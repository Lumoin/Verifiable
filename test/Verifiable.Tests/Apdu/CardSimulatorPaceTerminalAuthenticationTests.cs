using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Eac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.Pace;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the full EACv1 ordering over the PACE access path against the stateful <see cref="CardSimulator"/>:
/// PACE (Generic Mapping) establishes the session, Chip Authentication re-keys it, and Terminal Authentication
/// runs over the re-keyed session. After PACE the Terminal Authentication chip identifier <c>ID_IC</c> is no
/// longer the MRZ document number but <c>Comp()</c> of the chip's PACE ephemeral public key (BSI TR-03110-3
/// §A.2.2.3); the chip derives it from the key it retained from the PACE key-agreement round, and the terminal
/// from the key the chip returned over the wire. The positive run proves both sides agree on that identifier;
/// the negative run proves the chip rejects a terminal that signs the Basic Access Control identifier instead.
/// The keys and chain are minted with the framework's own ECDSA; both sides are production code that agree only
/// on the wire bytes.
/// </summary>
[TestClass]
internal sealed class CardSimulatorPaceTerminalAuthenticationTests
{
    private const string Td2MachineReadableZone =
        "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<" +
        "L898902C<3UTO6908061F9406236<<<<<<<8";

    private const string DocumentNumber = "L898902C<";
    private const string DateOfBirth = "690806";
    private const string DateOfExpiry = "940623";

    //The PACE-ECDH-GM-AES-CBC-CMAC-128 OID and the terminal's ephemeral private keys from Doc 9303 Appendix G.1.
    private const string PaceOid = "04007F00070202040202";
    private const string PaceMappingPrivateIfd = "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99";
    private const string PaceKeyAgreementPrivateIfd = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";

    //brainpoolP256r1 private scalars reused from the Doc 9303 Appendix G.1 worked example (valid keys).
    private const string ChipStaticPrivateKey = "107CF58696EF6155053340FD633392BA81909DF7B9706F226F32086C7AFF974A";
    private const string TerminalChipAuthenticationPrivateKey = "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595";

    private const string CvcaReference = "UTCVCA00001";
    private const string DocumentVerifierReference = "UTDVDE00001";
    private const string TerminalReference = "UTISDE00001";

    private static readonly DateOnly Effective = new(2024, 1, 1);
    private static readonly DateOnly Expiration = new(2026, 1, 1);
    private static readonly DateOnly WithinValidity = new(2025, 1, 1);


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task AuthenticatesAfterPaceUsingTheCompressedPaceEphemeralKeyAsTheIdentifier()
    {
        bool accepted = await RunPaceTerminalAuthenticationAsync(usePaceChipIdentifier: true);

        Assert.IsTrue(accepted, "The chip must accept Terminal Authentication whose ID_IC is Comp() of the chip's PACE ephemeral public key.");
    }


    [TestMethod]
    public async Task RejectsTerminalAuthenticationSignedWithTheBasicAccessControlIdentifierAfterPace()
    {
        //The terminal signs the Basic Access Control identifier (the MRZ document number) although PACE
        //established the session, so its ID_IC differs from the Comp() the chip derives from its PACE key.
        bool accepted = await RunPaceTerminalAuthenticationAsync(usePaceChipIdentifier: false);

        Assert.IsFalse(accepted, "The chip must reject a signature over the Basic Access Control identifier when PACE established the session.");
    }


    /// <summary>
    /// Mints a chip and a certificate chain, establishes PACE then Chip Authentication against the simulator,
    /// then runs Terminal Authentication over the re-keyed session. The chip identifier the terminal signs is
    /// either the PACE form (<c>Comp()</c> of the chip's PACE ephemeral public key, the correct one) or the
    /// Basic Access Control form (the MRZ document number), per <paramref name="usePaceChipIdentifier"/>.
    /// Returns whether the chip accepted it.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Each Secure Messaging session owns its keys and is disposed via using; the chip PACE ephemeral key and the certificates are disposed via using.")]
    private async Task<bool> RunPaceTerminalAuthenticationAsync(bool usePaceChipIdentifier)
    {
        Tag chipCurve = CryptoTags.BrainpoolP256r1ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> chipStaticPrivateKey = Convert.FromHexString(ChipStaticPrivateKey);
        ReadOnlyMemory<byte> terminalChipAuthenticationPrivateKey = Convert.FromHexString(TerminalChipAuthenticationPrivateKey);

        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] terminalPrivateKey = terminalKey.ExportParameters(includePrivateParameters: true).D!;

        using CardVerifiableCertificate trustAnchor = CardVerifiableCertificateMinter.Mint(
            cvcaKey, cvcaKey, CvcaReference, CvcaReference, CardVerifiableCertificateMinter.CvcaRole, includeDomainParameters: true, Effective, Expiration, inheritedCurve: null, BaseMemoryPool.Shared);
        Tag certificateCurve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using CardVerifiableCertificate documentVerifier = CardVerifiableCertificateMinter.Mint(
            cvcaKey, documentVerifierKey, CvcaReference, DocumentVerifierReference, CardVerifiableCertificateMinter.DocumentVerifierRole, includeDomainParameters: false, Effective, Expiration, certificateCurve, BaseMemoryPool.Shared);
        using CardVerifiableCertificate terminal = CardVerifiableCertificateMinter.Mint(
            documentVerifierKey, terminalKey, DocumentVerifierReference, TerminalReference, CardVerifiableCertificateMinter.TerminalRole, includeDomainParameters: false, Effective, Expiration, certificateCurve, BaseMemoryPool.Shared);

        using EncodedEcPoint chipStaticPublicKey = await multiplyGenerator(chipStaticPrivateKey, chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);
        using EncodedEcPoint terminalChipAuthenticationPublicKey = await multiplyGenerator(terminalChipAuthenticationPrivateKey, chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);

        using ElementaryFile dataGroup14File = DataGroup14.Write(chipStaticPublicKey, ChipAuthenticationCipher.Aes128, version: 1, keyId: null, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using ChipAuthenticationKey chipKey = CreateChipKey(ChipStaticPrivateKey);

        using var card = new CardSimulator(
            "passport-pace-terminal-auth",
            [dataGroup1, dataGroup14File],
            paceCurve: chipCurve,
            chipAuthenticationKeys: [chipKey],
            terminalAuthenticationTrustAnchor: trustAnchor,
            terminalAuthenticationDate: WithinValidity);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        //PACE establishes the access session and surfaces the chip's PACE ephemeral public key.
        (SecureMessagingSession paceSession, EncodedEcPoint chipPaceEphemeralPublicKey) = await EstablishPaceAsync(device);
        using(chipPaceEphemeralPublicKey)
        using(paceSession)
        {
            using DataGroup14 dataGroup14 = DataGroup14.Parse(dataGroup14File.AsReadOnlySpan(), BaseMemoryPool.Shared);
            ChipAuthenticationPublicKeyInfo chipKeyInfo = dataGroup14.ChipAuthenticationPublicKeyInfos[0];

            //Chip Authentication re-keys the session; PK_DH,IFD (terminalChipAuthenticationPublicKey) binds the
            //Terminal Authentication signature.
            (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await ChipAuthentication.EstablishAsync(
                device, paceSession, chipKeyInfo.PublicKey, ChipAuthenticationCipher.Aes128, terminalChipAuthenticationPrivateKey, chipKeyInfo.KeyId,
                BaseMemoryPool.Shared, TestContext.CancellationToken);

            using SecureMessagingSession reKeyed = new(encryptionKey, macKey, new byte[SecureMessagingProfile.Aes128.BlockSize], SecureMessagingProfile.Aes128, BaseMemoryPool.Shared);

            byte[] basicAccessControlIdentifier = Encoding.ASCII.GetBytes(TerminalAuthentication.ChipIdentifierForBasicAccessControl(DocumentNumber));
            ReadOnlyMemory<byte> chipIdentifier = usePaceChipIdentifier
                ? TerminalAuthentication.ChipIdentifierForPace(chipPaceEphemeralPublicKey)
                : basicAccessControlIdentifier;

            return await TerminalAuthentication.AuthenticateAsync(
                device, reKeyed, [documentVerifier, terminal], terminalPrivateKey, terminalChipAuthenticationPublicKey.AsReadOnlyMemory(), chipIdentifier,
                BaseMemoryPool.Shared, TestContext.CancellationToken);
        }
    }


    /// <summary>
    /// Runs the real PACE Generic Mapping terminal against the card and returns the established AES session plus
    /// the chip's PACE ephemeral public key (the caller disposes both).
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the session (which owns the session keys) and the chip ephemeral key transfers to the caller; the nonce key and password seed are disposed here.")]
    private async Task<(SecureMessagingSession Session, EncodedEcPoint ChipEphemeralPublicKey)> EstablishPaceAsync(ApduDevice device)
    {
        string mrzInformation = BasicAccessControl.BuildMrzInformation(DocumentNumber, DateOfBirth, DateOfExpiry);
        using DigestValue passwordSeed = await ComputeSha1Async(mrzInformation);
        using SymmetricKeyMemory nonceKey = await PaceKeyDerivation.DerivePasswordKeyAsync(
            passwordSeed.AsReadOnlyMemory(), BaseMemoryPool.Shared, TestContext.CancellationToken);

        (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey, EncodedEcPoint chipEphemeralPublicKey) = await PaceProtocol.EstablishAsync(
            device, nonceKey, Convert.FromHexString(PaceOid), passwordReference: 0x01,
            CryptoTags.BrainpoolP256r1ExchangePublicKey,
            Convert.FromHexString(PaceMappingPrivateIfd), Convert.FromHexString(PaceKeyAgreementPrivateIfd),
            BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken);

        SecureMessagingSession session = new(encryptionKey, macKey, new byte[SecureMessagingProfile.Aes128.BlockSize], SecureMessagingProfile.Aes128, BaseMemoryPool.Shared);

        return (session, chipEphemeralPublicKey);
    }


    /// <summary>
    /// Computes a SHA-1 digest of ASCII text through the registered <see cref="ComputeDigestDelegate"/> — the
    /// codebase's hash mechanism — for the PACE password seed K = SHA-1(MRZ information).
    /// </summary>
    private async Task<DigestValue> ComputeSha1Async(string text)
    {
        ComputeDigestDelegate digest = CryptographicKeyFactory.GetFunction<ComputeDigestDelegate>(typeof(ComputeDigestDelegate))
            ?? throw new InvalidOperationException("No ComputeDigestDelegate has been registered.");
        Tag sha1 = Tag.Create(HashAlgorithmName.SHA1).With(Purpose.Digest).With(EncodingScheme.Raw);

        (DigestValue value, _) = await digest(
            new ReadOnlySequence<byte>(Encoding.ASCII.GetBytes(text)), 20, sha1, BaseMemoryPool.Shared, null, TestContext.CancellationToken);

        return value;
    }


    /// <summary>Mints a Chip Authentication private-key carrier from a hex scalar.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned ChipAuthenticationKey, which the caller disposes.")]
    private static ChipAuthenticationKey CreateChipKey(string privateKeyHex)
    {
        byte[] bytes = Convert.FromHexString(privateKeyHex);
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new ChipAuthenticationKey(owner, keyId: null);
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");
}
