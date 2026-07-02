using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_Certify()</c> (object attestation) against the in-house behavioural <see cref="TpmSimulator"/> —
/// entirely in-process, with no external assets — through the same production command path the production code
/// uses (<see cref="TpmCommandExecutor"/> with the real <see cref="CreatePrimaryInput"/>, <see cref="CertifyInput"/>,
/// and response codecs): <c>TPM2_CreatePrimary()</c> mints a subject signing key under the owner hierarchy and a
/// separate attestation key (AK) under the endorsement hierarchy, then the AK certifies the subject over a caller
/// nonce.
/// </summary>
/// <remarks>
/// <para>
/// The result is verified <b>off-TPM</b> from wire bytes only: the magic / type / nonce fields, that the attested
/// Name equals the subject's Name recomputed independently from its exported public area
/// (<c>nameAlg ‖ H(TPMT_PUBLIC)</c>), and the ECDSA signature over the raw attestation bytes against the AK's
/// exported public key reconstructed from <c>outPublic</c> alone. The verifier shares no in-memory state with the
/// signer beyond the wire bytes, so a divergence between what the simulator framed and what a genuine TPM would
/// attest and sign fails here. Distinct hierarchy seeds give the subject and the AK genuinely distinct keys, so
/// this is a real cross-key certification rather than a self-certify.
/// </para>
/// <para>
/// <c>TPM2_Certify()</c> authorizes two handles — the certified object and the signing key — so the executor
/// receives two authorization sessions in handle order; both are empty-auth password sessions (an attestation
/// carries no secret, so no HMAC/encrypt session is needed). The signing backend is injected so the production
/// <c>Verifiable.Tpm</c> assembly stays provider-agnostic.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCertifyTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.</summary>
    private static byte[] Nonce { get; } = "Certify nonce for the in-house TPM."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task EcdsaP256CertifyVerifiesAgainstInHouseSimulator()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The subject (certified) key under the owner hierarchy and the AK (signer) under the endorsement
        //hierarchy: distinct hierarchy seeds give genuinely distinct keys, so this is a real cross-key
        //certification rather than a self-certify.
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        //Certify the subject with the AK. objectHandle auth first, signHandle auth second; both empty-auth
        //password sessions (an attestation carries no secret, so no HMAC/encrypt session).
        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(certifyResult.IsSuccess, $"TPM2_Certify failed: '{certifyResult.ResponseCode}'.");

        using CertifyResponse certify = certifyResult.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, certify.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, certify.HashAlgorithm);

        //1. Attestation envelope: TPM-generated marker, certify type, and the nonce echoed verbatim.
        TpmsAttest attest = certify.CertifyInfo.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_CERTIFY, attest.Type);
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
        Assert.IsNotNull(attest.Attested.Certify);

        //2. Name binding: the attested Name must equal the subject's Name recomputed independently from its
        //exported public area (nameAlg || H(TPMT_PUBLIC)) — firewalled, not taken from the simulator's own
        //CreatePrimary name field.
        byte[] expectedName = await ComputeObjectNameAsync(subject.OutPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Certify!.Name.Span.SequenceEqual(expectedName),
            "The certified Name must equal the subject's Name recomputed from its exported public area.");

        //Cross-check: the recomputation matches the Name the simulator returned for the subject at creation.
        Assert.IsTrue(expectedName.AsSpan().SequenceEqual(subject.Name.Span),
            "The independently recomputed Name must match the simulator-reported subject Name.");

        //3. Signature: over the RAW attestation bytes, against the AK public key reconstructed from the
        //simulator's exported public area only.
        byte[] attestDigest = await ComputeSha256Async(certify.CertifyInfo.GetRawBytes().ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        TpmsEccPoint akPoint = ak.OutPublic.PublicArea.Unique.Ecc!;
        var ecParameters = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = ToFixed(akPoint.X.AsReadOnlySpan(), P256ComponentSize),
                Y = ToFixed(akPoint.Y.AsReadOnlySpan(), P256ComponentSize)
            }
        };

        //.NET's VerifyHash expects the raw IEEE P1363 r || s concatenation, each component fixed-width.
        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(certify.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(certify.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(
            ecdsa.VerifyHash(attestDigest, p1363Signature),
            "The certify signature must verify over the raw attestation bytes against the AK's exported public key.");
    }

    [TestMethod]
    public async Task CertifyWithUnknownObjectHandleReturnsHandle()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //No object was created, so the certified transient handle does not resolve (TPM 2.0 Part 3, clause 18.2).
        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase),
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase + 1),
            Nonce,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, certifyResult.ResponseCode);
    }

    [TestMethod]
    public async Task CertifyWithUnknownSignKeyReturnsHandle()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //A real, loaded subject but no loaded signing key, so the signHandle does not resolve (Part 3, clause 18.2).
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using CertifyInput certifyInput = CertifyInput.ForEcdsa(
            subject.ObjectHandle,
            TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase + 0x100u),
            Nonce,
            TpmAlgIdConstants.TPM_ALG_SHA256,
            pool);

        TpmResult<CertifyResponse> certifyResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
            tpm, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, certifyResult.ResponseCode);
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy and returns the response (the caller
    /// owns it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Recomputes a loaded object's Name from its exported public area: <c>nameAlg || H_nameAlg(TPMT_PUBLIC)</c>
    /// (TPM 2.0 Library Part 1, clause 16), through the registered digest seam. The test keys use a SHA-256 nameAlg.
    /// </summary>
    /// <param name="outPublic">The object's exported public area.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Name (2-byte nameAlg prefix + digest).</returns>
    private static async Task<byte[]> ComputeObjectNameAsync(Tpm2bPublic outPublic, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        TpmAlgIdConstants nameAlg = outPublic.PublicArea.NameAlg;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, nameAlg, "This test assumes a SHA-256 nameAlg.");

        byte[] marshaledPublic = MarshalPublicArea(outPublic, pool);
        byte[] digest = await ComputeSha256Async(marshaledPublic, pool, cancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Marshals the exported public area into its canonical TPMT_PUBLIC wire form (no TPM2B size prefix) — the
    /// hash input the object Name is computed over.
    /// </summary>
    /// <param name="outPublic">The exported public area.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The marshaled TPMT_PUBLIC bytes.</returns>
    private static byte[] MarshalPublicArea(Tpm2bPublic outPublic, MemoryPool<byte> pool)
    {
        int size = outPublic.PublicArea.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        outPublic.PublicArea.WriteTo(ref writer);

        return owner.Memory.Span[..size].ToArray();
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The ECC backend is required so the simulator services
    /// <c>TPM2_CreatePrimary()</c> (both keys) and signs the attestation for <c>TPM2_Certify()</c>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-certify", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
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

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);

        return registry;
    }

    /// <summary>
    /// Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        Tag tag = new(new Dictionary<Type, object>
        {
            [typeof(HashAlgorithmName)] = HashAlgorithmName.SHA256,
            [typeof(Purpose)] = Purpose.Digest,
            [typeof(EncodingScheme)] = EncodingScheme.Raw,
            [typeof(MaterialSemantics)] = MaterialSemantics.Direct
        });

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: P256ComponentSize,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Left-pads a big-endian integer to a fixed width, as the IEEE P1363 / ECPoint encodings require. The
    /// simulator returns TPM2B integers that may omit leading zero bytes.
    /// </summary>
    /// <param name="value">The big-endian value.</param>
    /// <param name="length">The fixed width to pad to.</param>
    /// <returns>A new array of exactly <paramref name="length"/> bytes.</returns>
    private static byte[] ToFixed(ReadOnlySpan<byte> value, int length)
    {
        byte[] result = new byte[length];
        if(value.Length <= length)
        {
            value.CopyTo(result.AsSpan(length - value.Length));
        }
        else
        {
            //Defensive: drop any leading zero padding the simulator may have included.
            value[^length..].CopyTo(result);
        }

        return result;
    }
}
