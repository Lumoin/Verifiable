using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Apdu;
using Verifiable.Apdu.Automata;
using Verifiable.Apdu.Bac;
using Verifiable.Apdu.Eac;
using Verifiable.Apdu.Lds;
using Verifiable.Apdu.SecureMessaging;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Drives the Extended Access Control effective-authorization gate (BSI TR-03110-3 §2.7) end to end against
/// the stateful <see cref="CardSimulator"/>: Basic Access Control, Chip Authentication, then Terminal
/// Authentication with an Inspection System certificate chain whose Certificate Holder Authorization
/// Templates carry the EF.DG3 (fingerprint) and EF.DG4 (iris) read-access bits. After Terminal Authentication
/// the chip grants the terminal the bitwise AND of the chain's relative authorizations and releases the
/// sensitive data groups only on the granted bits; a refused read returns <c>6982</c>. The chain and keys are
/// minted with the framework's own ECDSA; both sides are production code that agree only on the wire bytes.
/// </summary>
[TestClass]
internal sealed class CardSimulatorTerminalAuthenticationAccessControlTests
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

    /// <summary>A minimal finger record (EF.DG3): the ISO/IEC 19794-4 format identifier "FIR\0", a version, and filler. A read-only span over static data, not a heap array.</summary>
    private static ReadOnlySpan<byte> FingerRecord => [0x46, 0x49, 0x52, 0x00, 0x30, 0x31, 0x30, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];

    /// <summary>A minimal iris record (EF.DG4): the ISO/IEC 19794-6 format identifier "IIR\0", a version, and filler. A read-only span over static data, not a heap array.</summary>
    private static ReadOnlySpan<byte> IrisRecord => [0x49, 0x49, 0x52, 0x00, 0x30, 0x31, 0x30, 0x00, 0x11, 0x22, 0x33, 0x44];

    private static readonly DateOnly Effective = new(2024, 1, 1);
    private static readonly DateOnly Expiration = new(2026, 1, 1);
    private static readonly DateOnly WithinValidity = new(2025, 1, 1);

    private const byte CvcaRole = CardVerifiableCertificateMinter.CvcaRole;
    private const byte DocumentVerifierRole = CardVerifiableCertificateMinter.DocumentVerifierRole;
    private const byte TerminalRole = CardVerifiableCertificateMinter.TerminalRole;
    private const byte ReadDataGroup3 = CardVerifiableCertificateMinter.ReadDataGroup3;
    private const byte ReadDataGroup4 = CardVerifiableCertificateMinter.ReadDataGroup4;

    /// <summary>The maximum number of data octets a short READ BINARY can request (Le 0x00 means 256).</summary>
    private const int MaxShortReadLength = 256;


    public required TestContext TestContext { get; set; }


    [TestMethod]
    public async Task GrantsBothSensitiveGroupsToATerminalAuthorisedForBoth()
    {
        //Every certificate in the chain authorises reading both DG3 and DG4, and the terminal requests both.
        AccessControlOutcome outcome = await RunAccessControlAsync(
            cvcaAuthorization: CvcaRole | ReadDataGroup3 | ReadDataGroup4,
            documentVerifierAuthorization: DocumentVerifierRole | ReadDataGroup3 | ReadDataGroup4,
            terminalAuthorization: TerminalRole | ReadDataGroup3 | ReadDataGroup4,
            runTerminalAuthentication: true);

        Assert.IsTrue(outcome.TerminalAuthenticationAccepted, "The chip must accept the chain and the terminal's signature.");
        Assert.IsTrue(outcome.DataGroup3Status.IsSuccess, "EF.DG3 must be readable when the effective authorization grants the fingerprint bit.");
        Assert.IsTrue(outcome.DataGroup3Matches, "EF.DG3 must read back byte-for-byte over the Terminal-Authentication session.");
        Assert.IsTrue(outcome.DataGroup4Status.IsSuccess, "EF.DG4 must be readable when the effective authorization grants the iris bit.");
        Assert.IsTrue(outcome.DataGroup4Matches, "EF.DG4 must read back byte-for-byte over the Terminal-Authentication session.");
    }


    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The terminal PrivateKey takes ownership of the BouncyCastle private-key memory and is disposed by its using declaration; all other carriers are disposed by using declarations.")]
    public async Task GrantsAccessWhenTheTerminalSignsWithAnInjectedLibraryKey()
    {
        Tag chipCurve = CryptoTags.BrainpoolP256r1ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> terminalEphemeralPrivateKey = Convert.FromHexString(TerminalEphemeralPrivateKey);

        //The CVCA and Document Verifier keys are minted with the framework's own ECDSA — the independent signer
        //CardVerifiableCertificateMinter uses to build the CA/attestation chain (BSI TR-03110-3 §C.1) that the
        //library's Terminal Authentication chain verification then checks.
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using CardVerifiableCertificate trustAnchor = CardVerifiableCertificateMinter.Mint(
            cvcaKey, cvcaKey, CvcaReference, CvcaReference, (byte)(CvcaRole | ReadDataGroup3 | ReadDataGroup4), includeDomainParameters: true, Effective, Expiration, inheritedCurve: null, BaseMemoryPool.Shared, TerminalType.InspectionSystem);
        Tag certificateCurve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using CardVerifiableCertificate documentVerifier = CardVerifiableCertificateMinter.Mint(
            cvcaKey, documentVerifierKey, CvcaReference, DocumentVerifierReference, (byte)(DocumentVerifierRole | ReadDataGroup3 | ReadDataGroup4), includeDomainParameters: false, Effective, Expiration, certificateCurve, BaseMemoryPool.Shared, TerminalType.InspectionSystem);

        //The terminal key is created through the library on the cross-platform BouncyCastle backend (framework
        //ECDSA private-key export is unreliable on macOS) and never as a raw ECDsa: BouncyCastle mints the scalar,
        //the registered EC-multiply (a delegate passed the key bytes, with the curve and pool threaded as state,
        //no closure) derives its uncompressed public point, and the Document Verifier certifies that point. The
        //terminal then signs EXTERNAL AUTHENTICATE through the injected PrivateKey, the seam a TPM-held key uses.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> terminalKeys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using PublicKeyMemory unusedCompressedPublicKey = terminalKeys.PublicKey;
        using EncodedEcPoint terminalPublicPoint = await terminalKeys.PrivateKey.WithKeyBytesAsync(
            static (scalar, state) => state.Generator(scalar, state.Curve, state.Pool, state.Token),
            (Generator: multiplyGenerator, Curve: CryptoTags.P256ExchangePublicKey, Pool: (MemoryPool<byte>)BaseMemoryPool.Shared, Token: TestContext.CancellationToken));
        using PrivateKey terminalKey = CryptographicKeyFactory.CreatePrivateKey(terminalKeys.PrivateKey, "terminal-p256", terminalKeys.PrivateKey.Tag);
        using CardVerifiableCertificate terminal = CardVerifiableCertificateMinter.Mint(
            documentVerifierKey, terminalPublicPoint.AsReadOnlyMemory(), DocumentVerifierReference, TerminalReference, (byte)(TerminalRole | ReadDataGroup3 | ReadDataGroup4), Effective, Expiration, certificateCurve, BaseMemoryPool.Shared, TerminalType.InspectionSystem);

        using EncodedEcPoint chipStaticPublicKey = await multiplyGenerator(Convert.FromHexString(ChipStaticPrivateKey), chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);
        using EncodedEcPoint terminalEphemeralPublicKey = await multiplyGenerator(terminalEphemeralPrivateKey, chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);

        using ElementaryFile dataGroup14File = DataGroup14.Write(chipStaticPublicKey, ChipAuthenticationCipher.Aes128, version: 1, keyId: null, BaseMemoryPool.Shared);
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x6E], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup3 = DataGroup3.Write(FingerRecord, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup4 = DataGroup4.Write(IrisRecord, BaseMemoryPool.Shared);
        using ChipAuthenticationKey chipKey = CreateChipKey(ChipStaticPrivateKey);

        using var card = new CardSimulator(
            "passport-ta-injected-key", [efCom, dataGroup1, dataGroup14File, dataGroup3, dataGroup4],
            chipAuthenticationKeys: [chipKey], terminalAuthenticationTrustAnchor: trustAnchor, terminalAuthenticationDate: WithinValidity);
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
            bool accepted = await TerminalAuthentication.AuthenticateAsync(
                device, reKeyed, [documentVerifier, terminal], terminalKey, terminalEphemeralPublicKey.AsReadOnlyMemory(), chipIdentifier,
                BaseMemoryPool.Shared, TestContext.CancellationToken);

            (StatusWord dataGroup3Status, bool dataGroup3Matches) = await ReadSensitiveFileAsync(
                device, reKeyed, DataGroup3.FileIdentifier, dataGroup3.AsReadOnlyMemory(), TestContext.CancellationToken);
            (StatusWord dataGroup4Status, bool dataGroup4Matches) = await ReadSensitiveFileAsync(
                device, reKeyed, DataGroup4.FileIdentifier, dataGroup4.AsReadOnlyMemory(), TestContext.CancellationToken);

            Assert.IsTrue(accepted, "The chip must accept a terminal that signs EXTERNAL AUTHENTICATE with an injected library PrivateKey.");
            Assert.IsTrue(dataGroup3Status.IsSuccess, "EF.DG3 must be readable after injected-key Terminal Authentication.");
            Assert.IsTrue(dataGroup3Matches, "EF.DG3 must read back byte-for-byte.");
            Assert.IsTrue(dataGroup4Status.IsSuccess, "EF.DG4 must be readable after injected-key Terminal Authentication.");
            Assert.IsTrue(dataGroup4Matches, "EF.DG4 must read back byte-for-byte.");
        }
    }


    [TestMethod]
    public async Task GrantsOnlyTheFingerprintToATerminalAuthorisedForDataGroup3Only()
    {
        //The chain authorises both, but the terminal certificate requests only DG3, so the effective
        //authorization narrows to the fingerprint bit and DG4 stays refused.
        AccessControlOutcome outcome = await RunAccessControlAsync(
            cvcaAuthorization: CvcaRole | ReadDataGroup3 | ReadDataGroup4,
            documentVerifierAuthorization: DocumentVerifierRole | ReadDataGroup3 | ReadDataGroup4,
            terminalAuthorization: TerminalRole | ReadDataGroup3,
            runTerminalAuthentication: true);

        Assert.IsTrue(outcome.TerminalAuthenticationAccepted, "The chip must accept the chain and the terminal's signature.");
        Assert.IsTrue(outcome.DataGroup3Status.IsSuccess, "EF.DG3 must be readable when the terminal is authorised for the fingerprint.");
        Assert.IsTrue(outcome.DataGroup3Matches, "EF.DG3 must read back byte-for-byte.");
        Assert.IsTrue(outcome.DataGroup4Status.IsSecurityStatusNotSatisfied, "EF.DG4 must be refused (6982) when the terminal is not authorised for the iris.");
        Assert.IsFalse(outcome.DataGroup4Matches, "A refused EF.DG4 read must return no data.");
    }


    [TestMethod]
    public async Task CapsTheGrantToTheCountryVerifyingAuthoritysAuthorization()
    {
        //The terminal requests both groups, but the Country Verifying Certification Authority authorises only
        //DG3, so the bitwise AND caps the effective authorization to the fingerprint regardless of the
        //terminal certificate's broader request.
        AccessControlOutcome outcome = await RunAccessControlAsync(
            cvcaAuthorization: CvcaRole | ReadDataGroup3,
            documentVerifierAuthorization: DocumentVerifierRole | ReadDataGroup3 | ReadDataGroup4,
            terminalAuthorization: TerminalRole | ReadDataGroup3 | ReadDataGroup4,
            runTerminalAuthentication: true);

        Assert.IsTrue(outcome.TerminalAuthenticationAccepted, "The chip must accept the chain and the terminal's signature.");
        Assert.IsTrue(outcome.DataGroup3Status.IsSuccess, "EF.DG3 must be readable: every certificate in the chain authorises the fingerprint.");
        Assert.IsTrue(outcome.DataGroup3Matches, "EF.DG3 must read back byte-for-byte.");
        Assert.IsTrue(outcome.DataGroup4Status.IsSecurityStatusNotSatisfied, "EF.DG4 must be refused (6982): the CVCA caps the effective authorization to the fingerprint.");
        Assert.IsFalse(outcome.DataGroup4Matches, "A refused EF.DG4 read must return no data.");
    }


    [TestMethod]
    public async Task RefusesBothSensitiveGroupsWithoutTerminalAuthentication()
    {
        //The chain would authorise both groups, but Terminal Authentication is not run, so the chip grants no
        //sensitive-data access and refuses DG3 and DG4 even over the Chip-Authentication session.
        AccessControlOutcome outcome = await RunAccessControlAsync(
            cvcaAuthorization: CvcaRole | ReadDataGroup3 | ReadDataGroup4,
            documentVerifierAuthorization: DocumentVerifierRole | ReadDataGroup3 | ReadDataGroup4,
            terminalAuthorization: TerminalRole | ReadDataGroup3 | ReadDataGroup4,
            runTerminalAuthentication: false);

        Assert.IsFalse(outcome.TerminalAuthenticationAccepted, "Terminal Authentication was not run, so it is not accepted.");
        Assert.IsTrue(outcome.DataGroup3Status.IsSecurityStatusNotSatisfied, "EF.DG3 must be refused (6982) before Terminal Authentication grants access.");
        Assert.IsTrue(outcome.DataGroup4Status.IsSecurityStatusNotSatisfied, "EF.DG4 must be refused (6982) before Terminal Authentication grants access.");
        Assert.IsFalse(outcome.DataGroup3Matches, "A refused EF.DG3 read must return no data.");
        Assert.IsFalse(outcome.DataGroup4Matches, "A refused EF.DG4 read must return no data.");
    }


    /// <summary>
    /// Personalises a chip holding the trust anchor, EF.DG3, and EF.DG4, mints an Inspection System chain with
    /// the given relative authorizations, runs Basic Access Control then Chip Authentication, optionally runs
    /// Terminal Authentication, and reads EF.DG3 and EF.DG4 over the re-keyed session — returning each read's
    /// status word and whether its content matched the personalised file.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The re-keyed session takes ownership of the Chip Authentication keys and is disposed via using; the Basic Access Control session and access keys are disposed in the using blocks.")]
    private async Task<AccessControlOutcome> RunAccessControlAsync(
        int cvcaAuthorization, int documentVerifierAuthorization, int terminalAuthorization, bool runTerminalAuthentication)
    {
        Tag chipCurve = CryptoTags.BrainpoolP256r1ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> chipStaticPrivateKey = Convert.FromHexString(ChipStaticPrivateKey);
        ReadOnlyMemory<byte> terminalEphemeralPrivateKey = Convert.FromHexString(TerminalEphemeralPrivateKey);

        //The CVCA, Document Verifier, and terminal keys are minted with the framework's own ECDSA — the
        //independent signer CardVerifiableCertificateMinter uses to build the CA/attestation chain
        //(BSI TR-03110-3 §C.1) that the library's Terminal Authentication chain verification then checks.
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa terminalKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] terminalPrivateKey = terminalKey.ExportParameters(includePrivateParameters: true).D!;

        using CardVerifiableCertificate trustAnchor = CardVerifiableCertificateMinter.Mint(
            cvcaKey, cvcaKey, CvcaReference, CvcaReference, (byte)cvcaAuthorization, includeDomainParameters: true, Effective, Expiration, inheritedCurve: null, BaseMemoryPool.Shared, TerminalType.InspectionSystem);
        Tag certificateCurve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using CardVerifiableCertificate documentVerifier = CardVerifiableCertificateMinter.Mint(
            cvcaKey, documentVerifierKey, CvcaReference, DocumentVerifierReference, (byte)documentVerifierAuthorization, includeDomainParameters: false, Effective, Expiration, certificateCurve, BaseMemoryPool.Shared, TerminalType.InspectionSystem);
        using CardVerifiableCertificate terminal = CardVerifiableCertificateMinter.Mint(
            documentVerifierKey, terminalKey, DocumentVerifierReference, TerminalReference, (byte)terminalAuthorization, includeDomainParameters: false, Effective, Expiration, certificateCurve, BaseMemoryPool.Shared, TerminalType.InspectionSystem);

        using EncodedEcPoint chipStaticPublicKey = await multiplyGenerator(chipStaticPrivateKey, chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);
        using EncodedEcPoint terminalEphemeralPublicKey = await multiplyGenerator(terminalEphemeralPrivateKey, chipCurve, BaseMemoryPool.Shared, TestContext.CancellationToken);

        using ElementaryFile dataGroup14File = DataGroup14.Write(chipStaticPublicKey, ChipAuthenticationCipher.Aes128, version: 1, keyId: null, BaseMemoryPool.Shared);
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x6E], BaseMemoryPool.Shared);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup3 = DataGroup3.Write(FingerRecord, BaseMemoryPool.Shared);
        using ElementaryFile dataGroup4 = DataGroup4.Write(IrisRecord, BaseMemoryPool.Shared);
        using ChipAuthenticationKey chipKey = CreateChipKey(ChipStaticPrivateKey);

        using var card = new CardSimulator(
            "passport-terminal-auth-access",
            [efCom, dataGroup1, dataGroup14File, dataGroup3, dataGroup4],
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

            bool accepted = false;
            if(runTerminalAuthentication)
            {
                byte[] chipIdentifier = Encoding.ASCII.GetBytes(TerminalAuthentication.ChipIdentifierForBasicAccessControl(DocumentNumber));
                accepted = await TerminalAuthentication.AuthenticateAsync(
                    device, reKeyed, [documentVerifier, terminal], terminalPrivateKey, terminalEphemeralPublicKey.AsReadOnlyMemory(), chipIdentifier,
                    BaseMemoryPool.Shared, TestContext.CancellationToken);
            }

            (StatusWord dataGroup3Status, bool dataGroup3Matches) = await ReadSensitiveFileAsync(
                device, reKeyed, DataGroup3.FileIdentifier, dataGroup3.AsReadOnlyMemory(), TestContext.CancellationToken);
            (StatusWord dataGroup4Status, bool dataGroup4Matches) = await ReadSensitiveFileAsync(
                device, reKeyed, DataGroup4.FileIdentifier, dataGroup4.AsReadOnlyMemory(), TestContext.CancellationToken);

            return new AccessControlOutcome(accepted, dataGroup3Status, dataGroup3Matches, dataGroup4Status, dataGroup4Matches);
        }
    }


    /// <summary>
    /// Selects a transparent elementary file over the session and reads it whole with one READ BINARY,
    /// returning the read's status word and whether the returned bytes matched <paramref name="expectedContent"/>.
    /// A refused read leaves the data empty, so no content match is reported.
    /// </summary>
    private static async Task<(StatusWord Status, bool Matches)> ReadSensitiveFileAsync(
        ApduDevice device, SecureMessagingSession session, ushort fileId, ReadOnlyMemory<byte> expectedContent, CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> identifier = BaseMemoryPool.Shared.Rent(2);
        identifier.Memory.Span[0] = (byte)(fileId >> 8);
        identifier.Memory.Span[1] = (byte)fileId;
        using(SecureMessagingResponse select = await TransceiveAsync(
            device, session, InstructionCode.Select.Code, 0x02, 0x0C, identifier.Memory[..2], expectedResponseLength: null, cancellationToken))
        {
            if(!select.StatusWord.IsSuccess)
            {
                return (select.StatusWord, false);
            }
        }

        //The sample data groups are well under a short READ BINARY's 256-octet ceiling, so a single read with
        //Le 0x00 (the maximum) returns the whole file when access is granted.
        using SecureMessagingResponse read = await TransceiveAsync(
            device, session, InstructionCode.ReadBinary.Code, 0x00, 0x00, ReadOnlyMemory<byte>.Empty, MaxShortReadLength, cancellationToken);
        bool matches = read.StatusWord.IsSuccess && read.Data.SequenceEqual(expectedContent.Span);

        return (read.StatusWord, matches);
    }


    /// <summary>
    /// Protects a command over the session, transceives it, and unprotects the response — returning the inner
    /// (Secure-Messaging-recovered) response carrying the chip's status word and any data.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the unprotected response transfers to the caller, which disposes it via a using declaration.")]
    private static async Task<SecureMessagingResponse> TransceiveAsync(
        ApduDevice device, SecureMessagingSession session, byte instruction, byte p1, byte p2, ReadOnlyMemory<byte> data, int? expectedResponseLength, CancellationToken cancellationToken)
    {
        using ProtectedCommandApdu protectedCommand = await session.ProtectCommandAsync(
            0x00, instruction, p1, p2, data, expectedResponseLength, BaseMemoryPool.Shared, cancellationToken);

        ApduResult<ApduResponse> result = await ApduExecutor.ExecuteAsync(
            device, protectedCommand.AsReadOnlyMemory(), BaseMemoryPool.Shared, cancellationToken);
        if(result.IsTransportError)
        {
            throw new InvalidOperationException($"The Secure Messaging transceive failed with transport error 0x{result.TransportErrorCode:X8}.");
        }

        using ApduResponse response = result.Value;

        return await session.UnprotectResponseAsync(response.AsReadOnlyMemory(), BaseMemoryPool.Shared, cancellationToken);
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
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return new ChipAuthenticationKey(owner, keyId: null);
    }


    private static TDelegate Resolve<TDelegate>() where TDelegate: Delegate =>
        CryptographicKeyFactory.GetFunction<TDelegate>(typeof(TDelegate))
            ?? throw new InvalidOperationException($"No {typeof(TDelegate).Name} has been registered.");


    /// <summary>
    /// The observed outcome of an access-control run: whether Terminal Authentication was accepted and, for
    /// each sensitive data group, the read's status word and whether the returned content matched the file.
    /// </summary>
    /// <param name="TerminalAuthenticationAccepted">Whether the chip accepted the Terminal Authentication exchange (always <see langword="false"/> when it was not run).</param>
    /// <param name="DataGroup3Status">The status word the EF.DG3 read returned.</param>
    /// <param name="DataGroup3Matches">Whether the EF.DG3 read returned the personalised fingerprint file byte-for-byte.</param>
    /// <param name="DataGroup4Status">The status word the EF.DG4 read returned.</param>
    /// <param name="DataGroup4Matches">Whether the EF.DG4 read returned the personalised iris file byte-for-byte.</param>
    private sealed record AccessControlOutcome(
        bool TerminalAuthenticationAccepted,
        StatusWord DataGroup3Status,
        bool DataGroup3Matches,
        StatusWord DataGroup4Status,
        bool DataGroup4Matches);
}
