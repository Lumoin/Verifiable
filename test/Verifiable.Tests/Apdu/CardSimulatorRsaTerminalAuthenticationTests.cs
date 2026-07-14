using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Eac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the real Terminal Authentication terminal (<see cref="TerminalAuthentication.AuthenticateAsync"/>)
/// against the stateful <see cref="CardSimulator"/> through the full EACv1 ordering — Basic Access Control,
/// then Chip Authentication, then Terminal Authentication over the re-keyed session — for a terminal whose
/// Terminal Authentication key is RSA (an <c>id-TA-RSA-v1-5-SHA-256</c> key). The certificate chain stays
/// elliptic-curve: the Country Verifying Certification Authority and the Document Verifier are P-256 and sign
/// with ECDSA, and the terminal certificate carries an RSA subject key but is itself signed by the Document
/// Verifier with ECDSA, so chain verification is unchanged and only the terminal's EXTERNAL AUTHENTICATE
/// possession proof is RSA (BSI TR-03110-3 Table 18). The keys and chain are minted with the framework's own
/// ECDSA and RSA; both sides are production code that agree only on the wire bytes.
/// </summary>
/// <remarks>
/// A 2048-bit RSA key makes the terminal certificate (a 256-byte modulus) and the EXTERNAL AUTHENTICATE
/// signature (a 256-byte signature) exceed the 255-byte short-Lc limit, so this test also exercises the
/// extended-length command path end to end: the protected PSO:Verify Certificate and EXTERNAL AUTHENTICATE
/// carry an extended Lc over Secure Messaging, and the chip parses it. The minted key material lives in the
/// framework <see cref="RSA"/> objects and pooled carriers, never naked buffers; the PKCS#1 private-key and
/// public-key exports are transient framework arrays consumed inline.
/// </remarks>
[TestClass]
internal sealed class CardSimulatorRsaTerminalAuthenticationTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";

    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";

    //brainpoolP256r1 private scalars reused from the Doc 9303 Appendix G.1 worked example (valid keys).
    private const string ChipStaticPrivateKey = "107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A";
    private const string TerminalEphemeralPrivateKey = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";

    private const string CvcaReference = "UTCVCA00001";
    private const string DocumentVerifierReference = "UTDVDE00001";
    private const string TerminalReference = "UTISDE00001";

    private static readonly DateOnly Effective = new(2024, 1, 1);
    private static readonly DateOnly Expiration = new(2026, 1, 1);
    private static readonly DateOnly WithinValidity = new(2025, 1, 1);


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task AuthenticatesWithAnRsaTerminalKeyAfterBasicAccessControlAndChipAuthentication()
    {
        //Minted with the framework RSA implementation: CardVerifiableCertificateMinter (an independent CVC
        //certificate factory) requires a framework RSA object for the subject key it embeds, and this same key
        //is exported below as the EXTERNAL AUTHENTICATE signer the chip verifies.
        using RSA terminalKey = RSA.Create(2048);

        bool accepted = await RunRsaTerminalAuthenticationAsync(certificateKey: terminalKey, signingKey: terminalKey);

        Assert.IsTrue(accepted, "The chip must accept a chain rooted in its trust anchor and an RSA EXTERNAL AUTHENTICATE signature with the terminal key the certificate carries, bound to the Chip Authentication ephemeral key.");
    }


    [TestMethod]
    public async Task RejectsAnRsaTerminalAuthenticationSignedWithTheWrongKey()
    {
        //Minted with the framework RSA implementation: CardVerifiableCertificateMinter (an independent CVC
        //certificate factory) requires a framework RSA object for the subject key it embeds.
        using RSA terminalKey = RSA.Create(2048);

        //A fresh, deliberately mismatched key minted on the spot for the negative case below.
        using RSA impostorKey = RSA.Create(2048);

        //The certificate carries the real RSA terminal key, but the terminal signs with a key it does not hold.
        bool accepted = await RunRsaTerminalAuthenticationAsync(certificateKey: terminalKey, signingKey: impostorKey);

        Assert.IsFalse(accepted, "The chip must reject an RSA EXTERNAL AUTHENTICATE signed with a key other than the terminal certificate's.");
    }


    [TestMethod]
    public async Task AuthenticatesAFullRsaCertificateChain()
    {
        //All three keys are minted with the framework RSA implementation: CardVerifiableCertificateMinter (an
        //independent CVC certificate factory) requires framework RSA objects for both the issuer signing key
        //and the embedded subject key at every link of the chain.
        using RSA cvcaKey = RSA.Create(2048);
        using RSA documentVerifierKey = RSA.Create(2048);
        using RSA terminalKey = RSA.Create(2048);

        //A wholly RSA chain: the CVCA the chip trusts, the Document Verifier, and the terminal are all RSA, so
        //the chip verifies each PSO:Verify Certificate through the RSA issuer path and the EXTERNAL AUTHENTICATE
        //through the RSA terminal path. Every certificate exceeds the short-Lc limit, exercising extended Lc.
        using CardVerifiableCertificate trustAnchor = CardVerifiableCertificateMinter.Mint(
            cvcaKey, cvcaKey, CvcaReference, CvcaReference, CardVerifiableCertificateMinter.CvcaRole, Effective, Expiration, BaseMemoryPool.Shared);
        using CardVerifiableCertificate documentVerifier = CardVerifiableCertificateMinter.Mint(
            cvcaKey, documentVerifierKey, CvcaReference, DocumentVerifierReference, CardVerifiableCertificateMinter.DocumentVerifierRole, Effective, Expiration, BaseMemoryPool.Shared);
        using CardVerifiableCertificate terminal = CardVerifiableCertificateMinter.Mint(
            documentVerifierKey, terminalKey, DocumentVerifierReference, TerminalReference, CardVerifiableCertificateMinter.TerminalRole, Effective, Expiration, BaseMemoryPool.Shared);

        bool accepted = await DriveTerminalAuthenticationAsync(trustAnchor, [documentVerifier, terminal], terminalKey.ExportRSAPrivateKey());

        Assert.IsTrue(accepted, "The chip must accept a full RSA chain rooted in its RSA trust anchor and an RSA EXTERNAL AUTHENTICATE signature.");
    }


    /// <summary>
    /// Mints a chip and an elliptic-curve certificate chain ending in a terminal certificate whose subject key
    /// is <paramref name="certificateKey"/> (RSA), then drives Basic Access Control, Chip Authentication, and
    /// Terminal Authentication, signing the EXTERNAL AUTHENTICATE with <paramref name="signingKey"/>'s RSA
    /// private key. Returns whether the chip accepted it.
    /// </summary>
    private async Task<bool> RunRsaTerminalAuthenticationAsync(RSA certificateKey, RSA signingKey)
    {
        //Minted with the framework ECDSA implementation: CardVerifiableCertificateMinter (an independent CVC
        //certificate factory) requires framework ECDsa objects for the issuer signing key at each link.
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using CardVerifiableCertificate trustAnchor = CardVerifiableCertificateMinter.Mint(
            cvcaKey, cvcaKey, CvcaReference, CvcaReference, CardVerifiableCertificateMinter.CvcaRole, includeDomainParameters: true, Effective, Expiration, inheritedCurve: null, BaseMemoryPool.Shared);
        Tag certificateCurve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using CardVerifiableCertificate documentVerifier = CardVerifiableCertificateMinter.Mint(
            cvcaKey, documentVerifierKey, CvcaReference, DocumentVerifierReference, CardVerifiableCertificateMinter.DocumentVerifierRole, includeDomainParameters: false, Effective, Expiration, certificateCurve, BaseMemoryPool.Shared);
        //The terminal certificate carries an RSA subject key but is signed by the Document Verifier with ECDSA.
        using CardVerifiableCertificate terminal = CardVerifiableCertificateMinter.Mint(
            documentVerifierKey, certificateKey, DocumentVerifierReference, TerminalReference, CardVerifiableCertificateMinter.TerminalRole, Effective, Expiration, BaseMemoryPool.Shared);

        return await DriveTerminalAuthenticationAsync(trustAnchor, [documentVerifier, terminal], signingKey.ExportRSAPrivateKey());
    }


    /// <summary>
    /// Personalises a chip holding <paramref name="trustAnchor"/> as its Terminal Authentication trust anchor,
    /// runs Basic Access Control then Chip Authentication against the simulator, and runs Terminal
    /// Authentication over the re-keyed session — presenting <paramref name="chain"/> and signing the EXTERNAL
    /// AUTHENTICATE with the RSA terminal private key <paramref name="terminalRsaPrivateKey"/>. The Chip
    /// Authentication stays elliptic-curve regardless of the certificate chain's key type. Returns whether the
    /// chip accepted the whole exchange.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The re-keyed session takes ownership of the Chip Authentication keys and is disposed via using; the Basic Access Control session and access keys are disposed in the using blocks.")]
    private async Task<bool> DriveTerminalAuthenticationAsync(
        CardVerifiableCertificate trustAnchor, CardVerifiableCertificate[] chain, ReadOnlyMemory<byte> terminalRsaPrivateKey)
    {
        Tag chipCurve = CryptoTags.BrainpoolP256r1ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> terminalEphemeralPrivateKey = Convert.FromHexString(TerminalEphemeralPrivateKey);

        using EncodedEcPoint chipStaticPublicKey = await multiplyGenerator(Convert.FromHexString(ChipStaticPrivateKey), chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);
        using EncodedEcPoint terminalEphemeralPublicKey = await multiplyGenerator(terminalEphemeralPrivateKey, chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);

        using ElementaryFile dataGroup14File = DataGroup14.Write(chipStaticPublicKey, ChipAuthenticationCipher.Aes128, version: 1, keyId: null, BaseMemoryPool.Shared);
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x6E], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using ChipAuthenticationKey chipKey = CreateChipKey(ChipStaticPrivateKey);

        using var card = new CardSimulator(
            "passport-rsa-terminal-auth",
            [efCom, dataGroup1, dataGroup14File],
            chipAuthenticationKeys: [chipKey],
            terminalAuthenticationTrustAnchor: trustAnchor,
            terminalAuthenticationDate: WithinValidity);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        (SecureMessagingSession bacSession, SymmetricKeyMemory accessEncryptionKey, SymmetricKeyMemory accessMacKey) =
            await EstablishBacAsync(device);
        using(accessEncryptionKey)
        using(accessMacKey)
        using(bacSession)
        {
            using DataGroup14 dataGroup14 = DataGroup14.Parse(dataGroup14File.AsReadOnlySpan(), BaseMemoryPool.Shared);
            ChipAuthenticationPublicKeyInfo chipKeyInfo = dataGroup14.ChipAuthenticationPublicKeyInfos[0];

            (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await ChipAuthentication.EstablishAsync(
                device, bacSession, chipKeyInfo.PublicKey, ChipAuthenticationCipher.Aes128, terminalEphemeralPrivateKey, chipKeyInfo.KeyId,
                BaseMemoryPool.Shared, TestContext.CancellationToken);

            using SecureMessagingSession reKeyed = new(encryptionKey, macKey, new byte[SecureMessagingProfile.Aes128.BlockSize], SecureMessagingProfile.Aes128, BaseMemoryPool.Shared);

            return await TerminalAuthentication.AuthenticateAsync(
                device, reKeyed, chain,
                terminalRsaPrivateKey,
                terminalEphemeralPublicKey.AsReadOnlyMemory(),
                Encoding.ASCII.GetBytes(TerminalAuthentication.ChipIdentifierForBasicAccessControl(DocumentNumber)),
                BaseMemoryPool.Shared, TestContext.CancellationToken);
        }
    }


    /// <summary>
    /// Runs the real terminal Basic Access Control against the card and returns the established session plus
    /// the borrowed access keys (the caller disposes all three).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the session and the access keys transfers to the caller, which disposes all three.")]
    private async Task<(SecureMessagingSession Session, SymmetricKeyMemory EncryptionKey, SymmetricKeyMemory MacKey)> EstablishBacAsync(ApduDevice device)
    {
        string mrzInformation = BasicAccessControl.BuildMrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry);
        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await BasicAccessControl.DeriveAccessKeysAsync(
            mrzInformation, BaseMemoryPool.Shared, TestContext.CancellationToken);

        SecureMessagingSession session = await BasicAccessControl.EstablishSessionAsync(
            device, encryptionKey, macKey, Convert.FromHexString("1122334455667788"), Convert.FromHexString("112233445566778899AABBCCDDEEFF00"),
            BaseMemoryPool.Shared, TestContext.CancellationToken);

        return (session, encryptionKey, macKey);
    }


    /// <summary>Mints a Chip Authentication private-key carrier from a hex scalar.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ChipAuthenticationKey, which the caller disposes.")]
    private static ChipAuthenticationKey CreateChipKey(string privateKeyHex)
    {
        ReadOnlySpan<byte> bytes = Convert.FromHexString(privateKeyHex);
        System.Buffers.IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new ChipAuthenticationKey(owner, keyId: null);
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
