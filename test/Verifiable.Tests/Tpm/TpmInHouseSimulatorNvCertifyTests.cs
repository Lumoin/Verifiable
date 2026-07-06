using System;
using System.Buffers;
using System.Buffers.Binary;
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
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_NV_Certify()</c> (NV Index content attestation) against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="NvCertifyInput"/> and response codecs): <c>TPM2_NV_DefineSpace()</c>/<c>TPM2_NV_Write()</c>
/// provision and populate an NV Index, <c>TPM2_CreatePrimary()</c> mints an attestation key (AK) under the
/// endorsement hierarchy, then the AK certifies the Index's contents over a caller nonce.
/// </summary>
/// <remarks>
/// <para>
/// The result is verified <b>off-TPM</b> from wire bytes only: the magic / type / nonce fields, that the
/// attested indexName equals the Index's Name recomputed independently from its public-area fields, that the
/// attested nvContents equals the octets this test itself wrote, and the ECDSA/RSA signature over the raw
/// attestation bytes against the AK's exported public key reconstructed from <c>outPublic</c> alone. Only the
/// TPMS_NV_CERTIFY_INFO attestation form is modelled (TPM 2.0 Library Part 3, clause 31.16); the zero-size/offset
/// TPMS_NV_DIGEST_CERTIFY_INFO form is fail-closed rejected.
/// </para>
/// <para>
/// Both <c>@signHandle</c> and <c>@authHandle</c> require authorization (Table 238), so the executor is given two
/// password sessions in handle order: the AK's empty-auth session first, the Index's real authValue session
/// second.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorNvCertifyTests
{
    /// <summary>The number of bytes in a NIST P-256 coordinate or in an ECDSA r/s component.</summary>
    private const int P256ComponentSize = 32;

    /// <summary>The RSA modulus size in bits used by the RSA NV-certify tests.</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>An ordinary NV Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint NvIndexHandle = 0x0100_0002;

    /// <summary>Index attributes that authorize read/write with the Index authValue and are dictionary-attack protected (no TPMA_NV_NO_DA).</summary>
    private const TpmaNv DaProtectedAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE;

    /// <summary>The Index authorization value used by these tests.</summary>
    private static byte[] IndexAuth { get; } = [0x0A, 0x0B, 0x0C, 0x0D];

    /// <summary>A wrong Index authorization value, distinct from <see cref="IndexAuth"/>.</summary>
    private static byte[] WrongIndexAuth { get; } = [0x99, 0x99, 0x99, 0x99];

    /// <summary>The known octets written to the NV Index before certifying its contents.</summary>
    private static byte[] WrittenData { get; } = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

    /// <summary>The fixed caller nonce (qualifyingData) echoed into the attestation's extraData.</summary>
    private static byte[] Nonce { get; } = "NvCertify nonce for the in-house TPM."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies a full ECDSA P-256 NV-certify round trip: the attested indexName matches the Index's
    /// independently recomputed Name, the attested nvContents equals the octets this test wrote, qualifiedSigner
    /// is the AK's real (non-collapsed) Qualified Name, and the signature verifies against the AK's exported
    /// public key (TPM 2.0 Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task EcdsaP256NvCertifyVerifiesAgainstInHouseSimulator()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify failed: '{result.ResponseCode}'.");

        using NvCertifyResponse nvCertify = result.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, nvCertify.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, nvCertify.HashAlgorithm);

        await AssertNvCertifyAttestationAsync(nvCertify, WrittenData, offset: 0, ak, pool).ConfigureAwait(false);

        byte[] attestDigest = await ComputeSha256Async(nvCertify.CertifyInfo.GetRawBytes().ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);

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

        byte[] p1363Signature = new byte[2 * P256ComponentSize];
        ToFixed(nvCertify.Signature.SignatureR!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(0));
        ToFixed(nvCertify.Signature.SignatureS!.AsReadOnlySpan(), P256ComponentSize).CopyTo(p1363Signature.AsSpan(P256ComponentSize));

        using ECDsa ecdsa = ECDsa.Create(ecParameters);
        Assert.IsTrue(
            ecdsa.VerifyHash(attestDigest, p1363Signature),
            "The NV-certify signature must verify over the raw attestation bytes against the AK's exported public key.");
    }

    /// <summary>
    /// Verifies NV-certify with an RSA AK under both RSASSA and RSAPSS, mirroring the ECDSA assertions (TPM 2.0
    /// Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task RsaNvCertifyVerifiesAgainstInHouseSimulator()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        var rsaParameters = new RSAParameters
        {
            Modulus = ak.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray(),
            Exponent = [0x01, 0x00, 0x01]
        };

        await NvCertifyAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, usePss: false).ConfigureAwait(false);
        await NvCertifyAndVerifyRsaAsync(tpm, registry, pool, ak, rsaParameters, usePss: true).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that certifying a partial window (a non-zero offset) attests exactly that window, independently
    /// cross-checked against the written bytes at that offset (TPM 2.0 Library Part 2, clause 10.12.8).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOfPartialWindowAttestsRequestedOffsetAndSize()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        const ushort PartialOffset = 2;
        const ushort PartialSize = 4;

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, PartialSize, PartialOffset, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify failed: '{result.ResponseCode}'.");

        using NvCertifyResponse nvCertify = result.Value;
        byte[] expectedWindow = WrittenData.AsSpan(PartialOffset, PartialSize).ToArray();
        await AssertNvCertifyAttestationAsync(nvCertify, expectedWindow, PartialOffset, ak, pool).ConfigureAwait(false);
    }

    /// <summary>
    /// Verifies that certifying an unwritten Index (TPMA_NV_WRITTEN clear) is rejected: "If the NV Index has been
    /// defined but the TPMA_NV_WRITTEN attribute is CLEAR ... this command shall return TPM_RC_NV_UNINITIALIZED"
    /// (TPM 2.0 Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOfUnwrittenIndexReturnsNvUninitialized()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, result.ResponseCode);
    }

    /// <summary>
    /// Verifies that a wrong Index authorization value against a dictionary-attack-protected Index is an
    /// auth-failure, mirroring TPM2_NV_Read()'s equivalent negative (TPM 2.0 Library Part 1, clause 17.8.3).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithWrongIndexAuthReturnsAuthFail()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession wrongIndexAuth = TpmPasswordSession.Create(WrongIndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, wrongIndexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode);
    }

    /// <summary>
    /// Verifies that a storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) as the NV-certify's signHandle is
    /// rejected with <c>TPM_RC_KEY</c>: "If the sign attribute is not SET in the key referenced by signHandle then
    /// the TPM shall return TPM_RC_KEY" (TPM 2.0 Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithNonSigningKeyReturnsKey()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            parent.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, result.ResponseCode);
    }

    /// <summary>
    /// Verifies that requesting the unmodelled TPMS_NV_DIGEST_CERTIFY_INFO form (size and offset both zero) is
    /// rejected fail-closed rather than silently substituting the modelled TPMS_NV_CERTIFY_INFO form (TPM 2.0
    /// Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task NvCertifyWithDigestFormSelectedReturnsCommandCode()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, pool, DaProtectedAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
            ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, size: 0, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_COMMAND_CODE, result.ResponseCode);
    }

    /// <summary>
    /// Certifies the Index's contents with the RSA AK under the given scheme through the production command
    /// path, verifies the attestation off-TPM, and verifies the signature against the AK's exported modulus with
    /// an independent RSA verifier.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="ak">The RSA attestation key's CreatePrimary response.</param>
    /// <param name="rsaParameters">The public key reconstructed from the AK's exported modulus.</param>
    /// <param name="usePss">When <see langword="true"/>, certifies and verifies RSAPSS; otherwise RSASSA (PKCS#1 v1.5).</param>
    private async Task NvCertifyAndVerifyRsaAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, CreatePrimaryResponse ak, RSAParameters rsaParameters, bool usePss)
    {
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using NvCertifyInput nvCertifyInput = usePss
            ? NvCertifyInput.ForRsaPss(ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool)
            : NvCertifyInput.ForRsaSsa(ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            tpm, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        string schemeName = usePss ? "RSAPSS" : "RSASSA";
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Certify ({schemeName}) failed: '{result.ResponseCode}'.");

        using NvCertifyResponse nvCertify = result.Value;
        Assert.AreEqual(usePss ? TpmAlgIdConstants.TPM_ALG_RSAPSS : TpmAlgIdConstants.TPM_ALG_RSASSA, nvCertify.SignatureAlgorithm);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, nvCertify.HashAlgorithm);

        await AssertNvCertifyAttestationAsync(nvCertify, WrittenData, offset: 0, ak, pool).ConfigureAwait(false);

        byte[] attestDigest = await ComputeSha256Async(nvCertify.CertifyInfo.GetRawBytes().ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        RSASignaturePadding padding = usePss ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
        using RSA rsa = RSA.Create(rsaParameters);
        Assert.IsTrue(
            rsa.VerifyHash(attestDigest, nvCertify.Signature.RsaSignature.Buffer.ToArray(), HashAlgorithmName.SHA256, padding),
            $"The {schemeName} NV-certify signature must verify against the RSA AK's exported modulus.");
    }

    /// <summary>
    /// Asserts the envelope (magic/type/nonce), the attested indexName against an independent Name recomputation,
    /// the attested offset and nvContents against the expected written window, and qualifiedSigner against an
    /// independent (non-collapsed) Qualified Name recomputation.
    /// </summary>
    /// <param name="nvCertify">The parsed NV-certify response.</param>
    /// <param name="expectedWindow">The expected attested NV contents (the octets this test wrote at <paramref name="offset"/>).</param>
    /// <param name="offset">The expected attested offset.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task AssertNvCertifyAttestationAsync(NvCertifyResponse nvCertify, byte[] expectedWindow, ushort offset, CreatePrimaryResponse ak, MemoryPool<byte> pool)
    {
        TpmsAttest attest = nvCertify.CertifyInfo.AttestationData;
        Assert.AreEqual(TpmConstants32.TPM_GENERATED_VALUE, attest.Magic, "A genuine TPM attestation is stamped with TPM_GENERATED_VALUE.");
        Assert.AreEqual(TpmStConstants.TPM_ST_ATTEST_NV, attest.Type);
        Assert.IsTrue(attest.ExtraData.Span.SequenceEqual(Nonce), "extraData must echo the caller's qualifyingData nonce.");
        Assert.IsNotNull(attest.Attested.Nv);

        //The Index's Name is computed over its CURRENT attributes (TPM 2.0 Library Part 1, clause 16): by the
        //time NV_Certify() runs the Index has been written, so TPMA_NV_WRITTEN is folded in exactly as
        //TPM2_NV_Write() set it, distinct from the attributes this test originally defined the Index with.
        byte[] expectedIndexName = await ComputeNvIndexNameAsync(
            NvIndexHandle, DaProtectedAttributes | TpmaNv.TPMA_NV_WRITTEN, (ushort)WrittenData.Length, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.Attested.Nv!.IndexName.Span.SequenceEqual(expectedIndexName),
            "The attested indexName must equal the Index's Name recomputed from its public-area fields.");

        Assert.AreEqual(offset, attest.Attested.Nv!.Offset, "The attested offset must equal the requested offset.");
        Assert.IsTrue(
            attest.Attested.Nv!.NvContents.SequenceEqual(expectedWindow),
            "The attested nvContents must equal the octets this test wrote at the requested offset/size.");

        byte[] expectedSignerQn = await ComputeQualifiedNameAsync(
            (uint)TpmRh.TPM_RH_ENDORSEMENT, ak.Name.Span.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            attest.QualifiedSigner.Span.SequenceEqual(expectedSignerQn),
            "qualifiedSigner must equal the AK's independently recomputed Qualified Name.");
        Assert.IsFalse(
            attest.QualifiedSigner.Span.SequenceEqual(ak.Name.Span),
            "qualifiedSigner must not collapse to the AK's plain Name.");
    }

    /// <summary>
    /// Defines <see cref="NvIndexHandle"/> under the owner hierarchy (empty owner authorization, matching the
    /// simulator's default) with the given attributes and <see cref="IndexAuth"/>, sized for
    /// <see cref="WrittenData"/>, without writing it.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="attributes">The Index attributes.</param>
    private async Task DefineNvIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmaNv attributes)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(IndexAuth, pool);
        using var publicInfo = new TpmsNvPublic(NvIndexHandle, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize: (ushort)WrittenData.Length);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
    }

    /// <summary>
    /// Defines <see cref="NvIndexHandle"/> (via <see cref="DefineNvIndexAsync"/>) and then writes
    /// <see cref="WrittenData"/> to it in full, setting <c>TPMA_NV_WRITTEN</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="attributes">The Index attributes.</param>
    private async Task DefineAndWriteNvIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmaNv attributes)
    {
        await DefineNvIndexAsync(tpm, registry, pool, attributes).ConfigureAwait(false);

        using TpmPasswordSession writeAuth = TpmPasswordSession.Create(IndexAuth, pool);
        var writeInput = new NvWriteInput(NvIndexHandle, NvIndexHandle, new Tpm2bMaxBuffer(WrittenData), Offset: 0);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");
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
    /// Creates a primary RSA-2048 signing key under the given hierarchy and returns the response (the caller owns
    /// it).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            hierarchy, password: null, keyBits: Rsa2048KeyBits, TpmtRsaScheme.Null, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates an ECC storage parent (RESTRICTED|DECRYPT, no SIGN_ENCRYPT) under the given hierarchy and returns
    /// the response (the caller owns it) — a key that cannot sign, for the negative sign-attribute test.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the parent.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            hierarchy, authPassword: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC storage parent, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Recomputes an NV Index's Name independently: <c>nameAlg || H(nvIndex || nameAlg || attributes || emptyAuthPolicy || dataSize)</c>
    /// — the marshaled TPMS_NV_PUBLIC this test itself defined the Index with (TPM 2.0 Library Part 2, clause
    /// 13.6) — through the registered digest seam. This test never calls the production <c>TpmsNvPublic</c>/
    /// <c>TpmObjectName</c> types, matching the firewalled, off-TPM oracle style the Certify test file uses.
    /// </summary>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="attributes">The Index attributes this test defined the Index with.</param>
    /// <param name="dataSize">The Index's declared data size.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Name (2-byte nameAlg prefix + digest).</returns>
    private static async Task<byte[]> ComputeNvIndexNameAsync(uint nvIndex, TpmaNv attributes, ushort dataSize, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] marshaled = new byte[sizeof(uint) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + sizeof(ushort)];
        int offset = 0;
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset), nvIndex);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset), (uint)attributes);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), 0); //authPolicy: empty TPM2B_DIGEST.
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), dataSize);

        byte[] digest = await ComputeSha256Async(marshaled, pool, cancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        digest.CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Recomputes an object's Qualified Name independently: <c>nameAlg || H(hierarchyHandle || Name)</c> (TPM 2.0
    /// Library Part 1, clause 16), through the registered digest seam. Every object this simulator certifies is a
    /// primary created directly under a permanent hierarchy, so the hierarchy's own Qualified Name is its 4-octet
    /// big-endian handle value — this test never calls the production <c>TpmObjectName</c> helper, matching the
    /// firewalled, off-TPM oracle style the Certify test file uses.
    /// </summary>
    /// <param name="hierarchy">The permanent hierarchy handle the object was created under.</param>
    /// <param name="name">The object's own Name.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Qualified Name.</returns>
    private static async Task<byte[]> ComputeQualifiedNameAsync(uint hierarchy, ReadOnlyMemory<byte> name, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ushort nameAlg = BinaryPrimitives.ReadUInt16BigEndian(name.Span[..sizeof(ushort)]);
        Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_SHA256, nameAlg, "This test assumes a SHA-256 nameAlg.");

        byte[] message = new byte[sizeof(uint) + name.Length];
        BinaryPrimitives.WriteUInt32BigEndian(message, hierarchy);
        name.Span.CopyTo(message.AsSpan(sizeof(uint)));

        byte[] digest = await ComputeSha256Async(message, pool, cancellationToken).ConfigureAwait(false);

        byte[] qualifiedName = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(qualifiedName, nameAlg);
        digest.CopyTo(qualifiedName.AsSpan(sizeof(ushort)));

        return qualifiedName;
    }

    /// <summary>
    /// Creates a simulator with both the ECC (BouncyCastle) and RSA (framework) signing backends wired, powers it
    /// on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-nv-certify",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
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
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);

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
        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

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
