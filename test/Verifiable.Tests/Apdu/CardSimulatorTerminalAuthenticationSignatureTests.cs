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
using Verifiable.Tests.TestDataProviders;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the real Terminal Authentication terminal (<see cref="TerminalAuthentication.AuthenticateAsync"/>)
/// against the stateful <see cref="CardSimulator"/> through the full EACv1 ordering: Basic Access Control,
/// then Chip Authentication, then Terminal Authentication over the re-keyed session. The chip verifies the
/// presented certificate chain against the Country Verifying Certification Authority it holds and then checks
/// the terminal's EXTERNAL AUTHENTICATE signature over <c>ID_IC || r_IC || Comp(PK_DH,IFD)</c>, deriving the
/// chip identifier from its own EF.DG1, the challenge it issued, and the terminal ephemeral key it retained
/// from Chip Authentication. The keys and chain are minted with the framework's own ECDSA; both sides are
/// production code that agree only on the wire bytes.
/// </summary>
[TestClass]
internal sealed class CardSimulatorTerminalAuthenticationSignatureTests
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
    public async Task AuthenticatesAfterBasicAccessControlAndChipAuthentication()
    {
        //CardVerifiableCertificateMinter is a test-side CVC certificate factory that requires a framework
        //ECDsa key; this key mints the terminal certificate and its exported scalar signs EXTERNAL AUTHENTICATE.
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] terminalPrivateKey = terminalKey.ExportParameters(includePrivateParameters: true).D!;

        bool accepted = await RunTerminalAuthenticationAsync(terminalKey, terminalPrivateKey, useRetainedEphemeralKey: true);

        Assert.IsTrue(accepted, "The chip must accept a chain rooted in its trust anchor and a signature with the matching terminal key bound to the Chip Authentication ephemeral key.");
    }


    [TestMethod]
    public async Task RejectsTerminalAuthenticationSignedWithTheWrongKey()
    {
        //CardVerifiableCertificateMinter is a test-side CVC certificate factory that requires a framework
        //ECDsa key; this key mints the terminal certificate.
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        //The chain carries the real terminal key, but the terminal signs with a key it does not hold; any
        //P-256 key distinct from the certificate's suffices, so the impostor key is ready-made test material
        //rather than a freshly minted framework key.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> impostorKeyMaterial = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory impostorPublicKey = impostorKeyMaterial.PublicKey;
        using PrivateKeyMemory impostorPrivateKey = impostorKeyMaterial.PrivateKey;

        bool accepted = await RunTerminalAuthenticationAsync(terminalKey, impostorPrivateKey.AsReadOnlyMemory(), useRetainedEphemeralKey: true);

        Assert.IsFalse(accepted, "The chip must reject an EXTERNAL AUTHENTICATE signed with a key other than the terminal certificate's.");
    }


    [TestMethod]
    public async Task RejectsTerminalAuthenticationBoundToADifferentEphemeralKey()
    {
        //CardVerifiableCertificateMinter is a test-side CVC certificate factory that requires a framework
        //ECDsa key; this key mints the terminal certificate and its exported scalar signs EXTERNAL AUTHENTICATE.
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] terminalPrivateKey = terminalKey.ExportParameters(includePrivateParameters: true).D!;

        //The terminal signs over a different ephemeral key than the one Chip Authentication established, so the
        //chip's Comp(PK_DH,IFD) differs and the channel binding fails.
        bool accepted = await RunTerminalAuthenticationAsync(terminalKey, terminalPrivateKey, useRetainedEphemeralKey: false);

        Assert.IsFalse(accepted, "The chip must reject a signature bound to an ephemeral key other than the one Chip Authentication established.");
    }


    /// <summary>
    /// Mints a chip and a certificate chain, runs Basic Access Control and Chip Authentication against the
    /// simulator, then runs Terminal Authentication over the re-keyed session, signing the EXTERNAL
    /// AUTHENTICATE with <paramref name="signingPrivateKey"/> and binding it either to the real Chip
    /// Authentication ephemeral key or a different one. Returns whether the chip accepted it.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The re-keyed session takes ownership of the Chip Authentication keys and is disposed via using; the Basic Access Control session and access keys are disposed in the using blocks.")]
    private async Task<bool> RunTerminalAuthenticationAsync(ECDsa terminalKey, ReadOnlyMemory<byte> signingPrivateKey, bool useRetainedEphemeralKey)
    {
        Tag chipCurve = CryptoTags.BrainpoolP256r1ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> chipStaticPrivateKey = Convert.FromHexString(ChipStaticPrivateKey);
        ReadOnlyMemory<byte> terminalEphemeralPrivateKey = Convert.FromHexString(TerminalEphemeralPrivateKey);

        //CardVerifiableCertificateMinter is a test-side CVC certificate factory that requires framework ECDsa
        //keys; cvcaKey self-signs the trust anchor and documentVerifierKey issues the terminal certificate.
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using CardVerifiableCertificate trustAnchor = CardVerifiableCertificateMinter.Mint(
            cvcaKey, cvcaKey, CvcaReference, CvcaReference, CardVerifiableCertificateMinter.CvcaRole, includeDomainParameters: true, Effective, Expiration, inheritedCurve: null, BaseMemoryPool.Shared);
        Tag certificateCurve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using CardVerifiableCertificate documentVerifier = CardVerifiableCertificateMinter.Mint(
            cvcaKey, documentVerifierKey, CvcaReference, DocumentVerifierReference, CardVerifiableCertificateMinter.DocumentVerifierRole, includeDomainParameters: false, Effective, Expiration, certificateCurve, BaseMemoryPool.Shared);
        using CardVerifiableCertificate terminal = CardVerifiableCertificateMinter.Mint(
            documentVerifierKey, terminalKey, DocumentVerifierReference, TerminalReference, CardVerifiableCertificateMinter.TerminalRole, includeDomainParameters: false, Effective, Expiration, certificateCurve, BaseMemoryPool.Shared);

        using EncodedEcPoint chipStaticPublicKey = await multiplyGenerator(chipStaticPrivateKey, chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);
        using EncodedEcPoint terminalEphemeralPublicKey = await multiplyGenerator(terminalEphemeralPrivateKey, chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);
        using EncodedEcPoint unrelatedPublicKey = await multiplyGenerator(chipStaticPrivateKey, chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);

        using ElementaryFile dataGroup14File = DataGroup14.Write(chipStaticPublicKey, ChipAuthenticationCipher.Aes128, version: 1, keyId: null, BaseMemoryPool.Shared);
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x6E], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using ChipAuthenticationKey chipKey = CreateChipKey(ChipStaticPrivateKey);

        using var card = new CardSimulator(
            "passport-terminal-auth-signature",
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

            byte[] chipIdentifier = Encoding.ASCII.GetBytes(TerminalAuthentication.ChipIdentifierForBasicAccessControl(DocumentNumber));
            ReadOnlyMemory<byte> boundEphemeralKey = useRetainedEphemeralKey
                ? terminalEphemeralPublicKey.AsReadOnlyMemory()
                : unrelatedPublicKey.AsReadOnlyMemory();

            return await TerminalAuthentication.AuthenticateAsync(
                device, reKeyed, [documentVerifier, terminal], signingPrivateKey, boundEphemeralKey, chipIdentifier,
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

        byte[] terminalNonce = Convert.FromHexString("1122334455667788");
        byte[] terminalKeyingMaterial = Convert.FromHexString("112233445566778899AABBCCDDEEFF00");

        SecureMessagingSession session = await BasicAccessControl.EstablishSessionAsync(
            device, encryptionKey, macKey, terminalNonce, terminalKeyingMaterial, BaseMemoryPool.Shared, TestContext.CancellationToken);

        return (session, encryptionKey, macKey);
    }


    /// <summary>Mints a Chip Authentication private-key carrier from a hex scalar.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ChipAuthenticationKey, which the caller disposes.")]
    private static ChipAuthenticationKey CreateChipKey(string privateKeyHex)
    {
        byte[] bytes = Convert.FromHexString(privateKeyHex);
        System.Buffers.IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new ChipAuthenticationKey(owner, keyId: null);
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
