using System.Buffers;
using System.Formats.Cbor;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Fido2;
using Verifiable.JCose;
using Verifiable.Microsoft;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.Tpm;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wave-4 PKG-A capstone: the FIDO2↔TPM rendezvous. A real <c>TPM2_Certify</c> — issued by the
/// in-house behavioural <see cref="TpmSimulator"/> over a freshly minted "credential" signing key,
/// through the same production command path (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="CertifyInput"/>/<see cref="CreatePrimaryInput"/> and response codecs) the other
/// <c>Tpm*</c> in-house simulator tests use — is CBOR-encoded into a <c>tpm</c> attStmt (via a
/// canonical <see cref="CborWriter"/>, the same encoding form <c>TpmAttestationStatementCborReader</c>
/// requires), then verified end to end through the SHIPPED <see cref="TpmAttestationStatementCborReader"/>,
/// <see cref="TpmAttestation"/> verifier, and <see cref="Fido2AttestationSelectors"/> format dispatch —
/// wire bytes in, a <see cref="CertifiedAttestationResult"/> out.
/// </summary>
/// <remarks>
/// <para>
/// <b>Capstone mode: live-minted, not a known-answer fallback.</b> The credential key and the AIK
/// are both minted as TPM primaries in the SAME simulator instance
/// (<c>TPM2_CreatePrimary()</c>, exactly as <c>TpmInHouseSimulatorAttestationLogTests</c> mints its
/// AK/EK), so both are genuinely loaded TPM objects with real Names and handles —
/// <c>TPM2_Certify()</c> can certify the credential key exactly as TPM 2.0 Part 3 §18.2 specifies,
/// with no import step needed. This sidesteps the one genuine gap this branch's TPM surface has:
/// <c>Verifiable.Tpm</c> implements <c>TPM2_Load()</c> (Part 3 §12.2 — loading a
/// <c>TPM2_Create()</c>-produced private blob under a parent) but not <c>TPM2_LoadExternal()</c>
/// (Part 3 §12.1 — importing a fully external public/private key pair with no parent-wrapped private
/// blob), so a credential key minted by a source OTHER than this TPM instance could not be certified
/// on this branch's surface. Because the credential key here is itself TPM-native from the start,
/// that gap is never exercised and does not block this capstone.
/// </para>
/// <para>
/// <c>pubArea</c> is <see cref="Tpm2bPublic.GetRawBytes"/> of the credential primary's exported
/// public area — already the bare TPMT_PUBLIC content the WebAuthn signing procedure requires (its
/// own TPM2B_PUBLIC length prefix stripped, per section 8.3's signing-procedure note). <c>certInfo</c>
/// is <see cref="Tpm2bAttest.GetRawBytes"/> of the TPM2_Certify response — the exact bytes the TPM
/// signed. <c>sig</c> is a hand-marshaled TPMT_SIGNATURE built from the parsed
/// <see cref="TpmuSignature"/>'s own <c>r</c>/<c>s</c> components — <c>Verifiable.Tpm</c> has no
/// TPMT_SIGNATURE writer of its own (nothing in the production TPM command surface re-serializes a
/// signature it just received), so this one small, spec-exact re-framing is test-only wire assembly,
/// not a duplicate of any production parser this wave's ruling 1 protects.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmAttestationCapstoneTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate/ECDSA component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Mints a credential key and an AIK as TPM primaries in the same simulator, certifies the
    /// credential key with the AIK over a genuine WebAuthn <c>attToBeSigned</c> transcript, CBOR-encodes
    /// the resulting <c>tpm</c> attStmt, and verifies it through the shipped reader/verifier/selector —
    /// asserting a <see cref="CertifiedAttestationResult"/> of type <see cref="AttestationType.AttestationCa"/>.
    /// </summary>
    [TestMethod]
    public async Task LiveMintedTpmCertifyRegistrationVerifiesFromWireBytes()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse credentialPrimary = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        try
        {
            using CreatePrimaryResponse aikPrimary = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
            try
            {
                //The WebAuthn side: a credential public key COSE-encoded from the TPM-minted credential
                //primary's real exported public point, embedded into a synthetic authenticatorData.
                Guid aaguid = Guid.NewGuid();
                (byte[] credentialX, byte[] credentialY) = ExportFixedEccPoint(credentialPrimary);
                var credentialPublicKey = new CoseKey(kty: CoseKeyTypes.Ec2, alg: WellKnownCoseAlgorithms.Es256, curve: CoseKeyCurves.P256, x: credentialX, y: credentialY);

                using DigestValue clientDataHash = Fido2AttestationTestVectors.ComputeClientDataHash([0x10, 0x20, 0x30], pool);
                using AuthenticatorData authenticatorData = Fido2AttestationTestVectors.BuildAuthenticatorData(aaguid, credentialPublicKey, out byte[] authDataBytes);
                byte[] attToBeSigned = Fido2AttestationTestVectors.BuildToBeSigned(authDataBytes, clientDataHash);

                //Independent oracle: this SHA-256 digest becomes the TPM2_Certify qualifyingData below, and
                //the shipped TpmAttestation verifier independently recomputes the same digest over the wire's
                //authenticatorData/clientDataHash and must match it against certInfo.extraData.
                byte[] extraData = SHA256.HashData(attToBeSigned);

                //The TPM side: a genuine TPM2_Certify over the credential primary, signed by the AIK
                //primary, through the real production command path.
                using CertifyResponse certifyResponse = await CertifyAsync(tpm, registry, pool, credentialPrimary.ObjectHandle, aikPrimary.ObjectHandle, extraData).ConfigureAwait(false);

                byte[] pubAreaBytes = credentialPrimary.OutPublic.GetRawBytes().ToArray();
                byte[] certInfoBytes = certifyResponse.CertifyInfo.GetRawBytes().ToArray();
                byte[] sigBytes = MarshalEcdsaSignature(certifyResponse.SignatureAlgorithm, certifyResponse.HashAlgorithm, certifyResponse.Signature);

                //The AIK certificate: a test root CA (independent of the TPM) issues a section
                //8.3.1-conformant AIK certificate over the AIK primary's REAL exported public key.
                (byte[] aikX, byte[] aikY) = ExportFixedEccPoint(aikPrimary);

                //Reconstructs the AIK's own real, TPM-derived public point (not swappable fixture
                //material — it must be the exact key exported from aikPrimary above) as an ECDsa
                //instance, the shape the certificate factory below requires.
                using ECDsa aikPublicKeyOnly = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = aikX, Y = aikY }
                });

                //A fresh root-CA signing key consumed directly by the CertificateRequest-based
                //certificate factory below (carve-out: test-side X.509 chain minting).
                using ECDsa rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                using X509Certificate2 rootCertificate = Fido2AttestationTestVectors.CreateSelfSignedCa("CN=Test TPM Vendor Root (Capstone)", rootKey);
                using X509Certificate2 aikCertificate = TpmAttestationTestVectors.CreateAikCertificate(rootCertificate, aikPublicKeyOnly, attachPrivateKey: false);

                using PkiCertificateMemory rootPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(rootCertificate.RawData);
                using PkiCertificateMemory aikPki = Fido2AttestationTestVectors.ToPkiCertificateMemory(aikCertificate.RawData);

                byte[] attStmtBytes = EncodeTpmAttStmt(WellKnownCoseAlgorithms.Es256, sigBytes, certInfoBytes, pubAreaBytes, [aikCertificate.RawData, rootCertificate.RawData]);

                SelectAttestationVerifierDelegate selectVerifier = Fido2AttestationSelectors.FromFormats(
                    (WellKnownWebAuthnAttestationFormats.Tpm, TpmAttestation.Build(
                        TpmAttestationStatementCborReader.Parse,
                        MicrosoftX509Functions.ValidateChainAsync,
                        MicrosoftX509Functions.ReadCertificateProfile,
                        MicrosoftX509Functions.ReadCertificateExtensionValue)));

                AttestationVerifyDelegate? verify = selectVerifier(WellKnownWebAuthnAttestationFormats.Tpm);
                Assert.IsNotNull(verify, "The tpm format must be registered in the shipped selector.");

                AttestationVerificationRequest request = Fido2AttestationTestVectors.CreateRequest(
                    authDataBytes, authenticatorData, clientDataHash, attStmtBytes, [rootPki], TestClock.CanonicalEpoch);

                AttestationResult result = await verify(request, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsInstanceOfType<CertifiedAttestationResult>(result, $"Expected a certified result; got {result}.");
                Assert.AreEqual(AttestationType.AttestationCa, ((CertifiedAttestationResult)result).Type);
            }
            finally
            {
                await FlushAsync(tpm, registry, aikPrimary.ObjectHandle.Value, pool).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushAsync(tpm, registry, credentialPrimary.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }


    /// <summary>Issues a genuine <c>TPM2_Certify</c> over <paramref name="objectHandle"/>, signed by <paramref name="signHandle"/>.</summary>
    /// <param name="tpm">The device the command is submitted through.</param>
    /// <param name="registry">The response codec registry resolving <c>TPM2_Certify</c>'s response.</param>
    /// <param name="pool">The pool command buffers and sessions rent from.</param>
    /// <param name="objectHandle">The handle of the object being certified (the credential primary).</param>
    /// <param name="signHandle">The handle of the signing key (the AIK primary).</param>
    /// <param name="qualifyingData">The <c>qualifyingData</c> the resulting <c>certInfo.extraData</c> must equal.</param>
    /// <returns>The successful <c>TPM2_Certify</c> response.</returns>
    private async Task<CertifyResponse> CertifyAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmiDhObject objectHandle, TpmiDhObject signHandle, byte[] qualifyingData)
    {
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(objectHandle, signHandle, qualifyingData, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Certify failed: '{result.ResponseCode}'.");

        return result.Value;
    }


    /// <summary>Marshals a TPMT_SIGNATURE from a parsed ECDSA <see cref="TpmuSignature"/> — test-only wire re-framing (see class remarks).</summary>
    /// <param name="signatureAlgorithm">The signature scheme selector; asserted to be <c>TPM_ALG_ECDSA</c>.</param>
    /// <param name="hashAlgorithm">The scheme's hash algorithm, carried alongside the ECDSA selector.</param>
    /// <param name="signature">The parsed signature union, whose ECDSA <c>r</c>/<c>s</c> components are re-marshaled.</param>
    /// <returns>The marshaled TPMT_SIGNATURE bytes.</returns>
    private static byte[] MarshalEcdsaSignature(TpmAlgIdConstants signatureAlgorithm, TpmAlgIdConstants hashAlgorithm, TpmuSignature signature)
    {
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, signatureAlgorithm, "The capstone's signing backend is expected to produce ECDSA signatures.");

        return TpmAttestationTestVectors.BuildEcdsaSignatureBytes(
            hashAlgorithm, signature.SignatureR!.AsReadOnlySpan(), signature.SignatureS!.AsReadOnlySpan());
    }


    /// <summary>Exports a TPM primary's ECC public point as two fixed-width (32-byte) big-endian coordinates.</summary>
    /// <param name="primary">The <c>TPM2_CreatePrimary</c> response whose public area carries the ECC point.</param>
    /// <returns>The fixed-width <c>X</c> and <c>Y</c> coordinates.</returns>
    private static (byte[] X, byte[] Y) ExportFixedEccPoint(CreatePrimaryResponse primary)
    {
        TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;

        return (ToFixed(point.X.AsReadOnlySpan(), P256ComponentSize), ToFixed(point.Y.AsReadOnlySpan(), P256ComponentSize));
    }


    /// <summary>Left-pads a big-endian value to a fixed width, as fixed-width coordinate encodings require.</summary>
    /// <param name="value">The big-endian value to pad or truncate.</param>
    /// <param name="length">The fixed output width, in bytes.</param>
    /// <returns>A <paramref name="length"/>-byte big-endian value.</returns>
    private static byte[] ToFixed(ReadOnlySpan<byte> value, int length)
    {
        byte[] result = new byte[length];
        if(value.Length <= length)
        {
            value.CopyTo(result.AsSpan(length - value.Length));
        }
        else
        {
            value[^length..].CopyTo(result);
        }

        return result;
    }


    /// <summary>
    /// Encodes a <c>tpm</c> attStmt CBOR map in CTAP2 canonical form — the shipped
    /// <see cref="TpmAttestationStatementCborReader"/>'s own input shape. No production TPM CBOR
    /// writer exists (this format is never emitted by the in-house CTAP authenticator simulator),
    /// so this hand-rolled encoder is test-only wire assembly.
    /// </summary>
    /// <param name="alg">The COSEAlgorithmIdentifier for the <c>alg</c> member.</param>
    /// <param name="sig">The marshaled TPMT_SIGNATURE bytes for the <c>sig</c> member.</param>
    /// <param name="certInfo">The marshaled TPMS_ATTEST bytes for the <c>certInfo</c> member.</param>
    /// <param name="pubArea">The marshaled TPMT_PUBLIC bytes for the <c>pubArea</c> member.</param>
    /// <param name="x5c">The AIK certificate chain, leaf first, for the <c>x5c</c> member.</param>
    /// <returns>The encoded <c>attStmt</c> CBOR bytes.</returns>
    private static byte[] EncodeTpmAttStmt(int alg, byte[] sig, byte[] certInfo, byte[] pubArea, IReadOnlyList<byte[]> x5c)
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(6);

        writer.WriteTextString("alg");
        writer.WriteInt32(alg);

        writer.WriteTextString("sig");
        writer.WriteByteString(sig);

        writer.WriteTextString("ver");
        writer.WriteTextString("2.0");

        writer.WriteTextString("x5c");
        writer.WriteStartArray(x5c.Count);
        foreach(byte[] certificate in x5c)
        {
            writer.WriteByteString(certificate);
        }

        writer.WriteEndArray();

        writer.WriteTextString("pubArea");
        writer.WriteByteString(pubArea);

        writer.WriteTextString("certInfo");
        writer.WriteByteString(certInfo);

        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>Creates a primary ECC P-256 signing key under the given hierarchy.</summary>
    /// <param name="tpm">The device the command is submitted through.</param>
    /// <param name="registry">The response codec registry resolving <c>TPM2_CreatePrimary</c>'s response.</param>
    /// <param name="pool">The pool command buffers and sessions rent from.</param>
    /// <param name="hierarchy">The hierarchy the primary is created under.</param>
    /// <returns>The successful <c>TPM2_CreatePrimary</c> response.</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }


    /// <summary>Creates a response codec registry covering the commands this capstone issues.</summary>
    /// <returns>A registry with <c>TPM2_CreatePrimary</c>, <c>TPM2_Certify</c>, and <c>TPM2_FlushContext</c> registered.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }


    /// <summary>Flushes a transient object handle, ignoring the result.</summary>
    /// <param name="tpm">The device the command is submitted through.</param>
    /// <param name="registry">The response codec registry resolving <c>TPM2_FlushContext</c>'s response.</param>
    /// <param name="handle">The transient object handle to flush.</param>
    /// <param name="pool">The pool command buffers rent from.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle, MemoryPool<byte> pool)
    {
        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and
    /// brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The pool the startup command buffer rents from.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-fido2-capstone", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }


    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator to move it into <see cref="TpmLifecyclePhase.Operational"/>.</summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The pool the startup command buffer rents from.</param>
    private async Task BringOperationalAsync(TpmSimulator simulator, MemoryPool<byte> pool)
    {
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code);
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);
    }
}
