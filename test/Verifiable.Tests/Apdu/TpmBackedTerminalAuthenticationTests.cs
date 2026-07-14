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
using Verifiable.Apdu.SecureMessaging;
using Verifiable.Cryptography;
using Verifiable.Tests.Tpm;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// The TPM + APDU "extra secure" capstone slice where the eMRTD terminal's Terminal Authentication key is held
/// inside a TPM: <c>TPM2_CreatePrimary</c> generates the terminal's signing key, the Document Verifier certifies
/// the exported public point, and the terminal proves possession by signing EXTERNAL AUTHENTICATE through
/// <c>TPM2_Sign</c> — the private scalar never leaves the TPM. The whole flow (Basic Access Control, Chip
/// Authentication, then Terminal Authentication) runs entirely in-process against the in-house behavioural
/// <see cref="TpmSimulator"/> and the stateful <see cref="CardSimulator"/>, with no external assets; both are
/// production pushdown-automaton devices, and the two sides agree only on the wire bytes.
/// </summary>
[TestClass]
internal sealed class TpmBackedTerminalAuthenticationTests
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

    /// <summary>The width in bytes of a NIST P-256 coordinate.</summary>
    private const int P256ComponentSize = 32;

    private static readonly DateOnly Effective = new(2024, 1, 1);
    private static readonly DateOnly Expiration = new(2026, 1, 1);
    private static readonly DateOnly WithinValidity = new(2025, 1, 1);

    public required TestContext TestContext { get; set; }

    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "The terminal PrivateKey takes ownership of the TPM handle memory and is disposed by its using declaration; all other carriers are disposed by using declarations.")]
    public async Task GrantsAccessWhenTheTerminalSignsWithAnInHouseTpmHeldKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        Tag chipCurve = CryptoTags.BrainpoolP256r1ExchangePublicKey;
        EcMultiplyGeneratorDelegate multiplyGenerator = Resolve<EcMultiplyGeneratorDelegate>();
        ReadOnlyMemory<byte> terminalEphemeralPrivateKey = Convert.FromHexString(TerminalEphemeralPrivateKey);

        //Generate the terminal's Terminal Authentication key inside the in-house TPM and export only its public
        //point; TPM2_Sign produces the EXTERNAL AUTHENTICATE signature, so the private scalar never leaves it.
        TpmSimulator tpmSimulator = await CreateOperationalTpmAsync("passport-terminal-tpm", pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(tpmSimulator.SubmitAsync);
        TpmResponseRegistry tpmRegistry = new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> primaryResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, tpmRegistry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(primaryResult.IsSuccess, $"CreatePrimary (terminal TA key) failed: '{primaryResult.ResponseCode}'.");

        using CreatePrimaryResponse primary = primaryResult.Value;

        //Surface the TPM key as a first-class library PrivateKey: the private-key memory carries only the handle,
        //and the signing function is bound to TPM2_Sign with the device threaded through the per-call context.
        using EncodedEcPoint terminalPublicPoint = BuildUncompressedPoint(primary.OutPublic.PublicArea.Unique.Ecc!, pool);
        using var terminalKey = new PrivateKey(
            TpmCryptographicFunctions.CreateHandleKeyMemory(primary.ObjectHandle.Value, CryptoTags.P256PrivateKey, pool),
            "tpm-terminal-p256",
            TpmCryptographicFunctions.SignAsync,
            TpmCryptographicFunctions.CreateP256SigningContext(tpm));

        //Mint the Inspection System chain; the Document Verifier certifies the TPM-exported point as the terminal's.
        //The CVCA and Document Verifier keys stay framework ECDsa: CardVerifiableCertificateMinter, the test-side
        //certificate factory minting this CA/attestation chain, signs and exports through ECDsa's own API surface.
        using ECDsa cvcaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa documentVerifierKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        using CardVerifiableCertificate trustAnchor = CardVerifiableCertificateMinter.Mint(
            cvcaKey, cvcaKey, CvcaReference, CvcaReference, CardVerifiableCertificateMinter.CvcaRole, includeDomainParameters: true, Effective, Expiration, inheritedCurve: null, pool, TerminalType.InspectionSystem);
        Tag certificateCurve = trustAnchor.PublicKey.EllipticCurvePoint!.Tag;
        using CardVerifiableCertificate documentVerifier = CardVerifiableCertificateMinter.Mint(
            cvcaKey, documentVerifierKey, CvcaReference, DocumentVerifierReference, CardVerifiableCertificateMinter.DocumentVerifierRole, includeDomainParameters: false, Effective, Expiration, certificateCurve, pool, TerminalType.InspectionSystem);
        using CardVerifiableCertificate terminal = CardVerifiableCertificateMinter.Mint(
            documentVerifierKey, terminalPublicPoint.AsReadOnlyMemory(), DocumentVerifierReference, TerminalReference, CardVerifiableCertificateMinter.TerminalRole, Effective, Expiration, certificateCurve, pool, TerminalType.InspectionSystem);

        using EncodedEcPoint chipStaticPublicKey = await multiplyGenerator(Convert.FromHexString(ChipStaticPrivateKey), chipCurve, pool, TestContext.CancellationToken);
        using EncodedEcPoint terminalEphemeralPublicKey = await multiplyGenerator(terminalEphemeralPrivateKey, chipCurve, pool, TestContext.CancellationToken);

        using ElementaryFile dataGroup14File = DataGroup14.Write(chipStaticPublicKey, ChipAuthenticationCipher.Aes128, version: 1, keyId: null, pool);
        using ElementaryFile efCom = EfCom.Write("0106", "040000", [0x61, 0x6E], pool);
        using ElementaryFile dataGroup1 = DataGroup1.Write(Td2MachineReadableZone, pool);
        using ChipAuthenticationKey chipKey = CreateChipKey(ChipStaticPrivateKey);

        using var card = new CardSimulator(
            "passport-terminal-tpm-auth", [efCom, dataGroup1, dataGroup14File],
            chipAuthenticationKeys: [chipKey], terminalAuthenticationTrustAnchor: trustAnchor, terminalAuthenticationDate: WithinValidity);
        using ApduDevice device = ApduDevice.Create(card.TransceiveAsync);

        (SecureMessagingSession bacSession, SymmetricKeyMemory accessEncryptionKey, SymmetricKeyMemory accessMacKey) =
            await EstablishBacAsync(device);
        using(accessEncryptionKey)
        using(accessMacKey)
        using(bacSession)
        {
            using DataGroup14 dataGroup14 = DataGroup14.Parse(dataGroup14File.AsReadOnlySpan(), pool);
            ChipAuthenticationPublicKeyInfo chipKeyInfo = dataGroup14.ChipAuthenticationPublicKeyInfos[0];

            (SymmetricKeyMemory encryptionKey, SymmetricKeyMemory macKey) = await ChipAuthentication.EstablishAsync(
                device, bacSession, chipKeyInfo.PublicKey, ChipAuthenticationCipher.Aes128, terminalEphemeralPrivateKey, chipKeyInfo.KeyId,
                pool, TestContext.CancellationToken);

            using SecureMessagingSession reKeyed = new(encryptionKey, macKey, new byte[SecureMessagingProfile.Aes128.BlockSize], SecureMessagingProfile.Aes128, pool);

            byte[] chipIdentifier = Encoding.ASCII.GetBytes(TerminalAuthentication.ChipIdentifierForBasicAccessControl(DocumentNumber));
            bool accepted = await TerminalAuthentication.AuthenticateAsync(
                device, reKeyed, [documentVerifier, terminal], terminalKey, terminalEphemeralPublicKey.AsReadOnlyMemory(), chipIdentifier,
                pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(accepted, "The chip must accept a terminal that signs EXTERNAL AUTHENTICATE with a key held inside the in-house TPM.");
        }
    }

    /// <summary>
    /// Creates an in-house TPM with a signing backend and brings it through <c>_TPM_Init</c> and
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="tpmId">The simulated TPM's identifier.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalTpmAsync(string tpmId, MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator(tpmId, signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var startup = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + startup.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)startup.CommandCode);
        header.WriteTo(ref writer);
        startup.WriteHandles(ref writer);
        startup.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must report success.");

        return simulator;
    }

    /// <summary>
    /// Builds the SEC1 uncompressed public point (<c>0x04 || X || Y</c>) from a TPM-exported ECC point, padding
    /// each coordinate to the curve field width (the TPM may omit leading zero bytes).
    /// </summary>
    /// <param name="point">The TPM-exported public point.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The uncompressed point carrier.</returns>
    private static EncodedEcPoint BuildUncompressedPoint(TpmsEccPoint point, MemoryPool<byte> pool)
    {
        Span<byte> uncompressed = stackalloc byte[1 + (2 * P256ComponentSize)];
        uncompressed[0] = 0x04;
        LeftPadInto(point.X.AsReadOnlySpan(), uncompressed.Slice(1, P256ComponentSize));
        LeftPadInto(point.Y.AsReadOnlySpan(), uncompressed.Slice(1 + P256ComponentSize, P256ComponentSize));

        return EncodedEcPoint.FromBytes(uncompressed, CryptoTags.P256ExchangePublicKey, pool);
    }

    /// <summary>Left-pads a big-endian value into a fixed-width destination, zero-filling the leading bytes.</summary>
    /// <param name="value">The big-endian value (the TPM may omit leading zero bytes).</param>
    /// <param name="destination">The fixed-width destination span.</param>
    private static void LeftPadInto(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        destination.Clear();
        value.CopyTo(destination[(destination.Length - value.Length)..]);
    }

    /// <summary>
    /// Runs the real terminal Basic Access Control against the card and returns the established session plus the
    /// borrowed access keys (the caller disposes all three).
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
}
