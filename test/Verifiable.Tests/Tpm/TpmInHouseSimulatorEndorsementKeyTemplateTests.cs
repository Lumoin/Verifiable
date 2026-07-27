using System;
using System.Buffers;
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
/// Verifies the standard ECC NIST P-256 endorsement key template (TCG EK Credential Profile, Annex B.3.4, Template
/// L-2) produced by <see cref="CreatePrimaryInput.ForEndorsementKey"/> against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production command
/// path the production code uses (<see cref="TpmCommandExecutor"/> with the real <see cref="CreatePrimaryInput"/>
/// and response codec).
/// </summary>
/// <remarks>
/// The Name is recomputed off-TPM from the wire-exported public area through the registered digest seam (TPM 2.0
/// Library Part 1, clause 16) — firewalled: the verifier never calls into the production <c>TpmObjectName</c>
/// helper, only an independent recomputation, matching the sibling nameAlg/Certify/Sign/Quote tests' oracle style.
/// A match proves the template's authPolicy is threaded end to end into both the exported public area and the Name.
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorEndorsementKeyTemplateTests
{
    /// <summary>The published endorsement authorization policy value ("PolicyA"), TCG EK Credential Profile, Annex B.6.2, Table 33.</summary>
    private static byte[] PolicyA { get; } = Convert.FromHexString("837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa");

    /// <summary>The RSA modulus size in bits used by the standard RSA endorsement key (TCG EK Credential Profile, Annex B.3.3, Template L-1).</summary>
    private const ushort Rsa2048KeyBits = 2048;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies the wire-exported standard-EK public area carries exactly the Template L-2 shape — the
    /// objectAttributes mask, the PolicyA authPolicy, AES-128-CFB, a NULL scheme, and the P-256 curve — and that
    /// the object's Name equals an independent off-TPM recomputation over that authPolicy-carrying public area.
    /// </summary>
    [TestMethod]
    public async Task EndorsementKeyTemplateMatchesTheStandardProfile()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput input = CreatePrimaryInput.ForEndorsementKey(TpmRh.TPM_RH_ENDORSEMENT, pool);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (standard EK) failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse ek = result.Value;
        try
        {
            TpmtPublic publicArea = ek.OutPublic.PublicArea;

            TpmaObject expectedAttributes =
                TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN |
                TpmaObject.ADMIN_WITH_POLICY | TpmaObject.RESTRICTED | TpmaObject.DECRYPT;
            Assert.AreEqual(expectedAttributes, publicArea.ObjectAttributes, "The exported EK must carry exactly the L-2 objectAttributes mask.");

            Assert.IsTrue(PolicyA.AsSpan().SequenceEqual(publicArea.AuthPolicy.AsReadOnlySpan()), "authPolicy must equal the published PolicyA digest.");

            Assert.IsNotNull(publicArea.Parameters.EccDetail, "The EK must carry ECC parameters.");
            TpmsEccParms eccParms = publicArea.Parameters.EccDetail!.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_AES, eccParms.Symmetric.Algorithm, "The EK's symmetric algorithm must be AES.");
            Assert.AreEqual((ushort)128, eccParms.Symmetric.KeyBits, "The EK's symmetric key size must be 128 bits.");
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_CFB, eccParms.Symmetric.Mode, "The EK's symmetric mode must be CFB.");
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_NULL, eccParms.Scheme.Scheme, "The EK's scheme must be NULL (a storage key, not a signing key).");
            Assert.AreEqual(TpmEccCurveConstants.TPM_ECC_NIST_P256, eccParms.CurveId, "The EK must be on the P-256 curve.");

            //Recompute the Name off-TPM, firewalled: marshal the exported public area and hash it through the
            //registered digest seam directly, never through the production TpmObjectName helper.
            byte[] marshaledPublic = MarshalPublicArea(ek.OutPublic, pool);
            byte[] expectedDigest = await ComputeDigestAsync(marshaledPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_SHA256, ek.Name.NameAlgorithm, "The Name must carry the SHA-256 nameAlg.");
            Assert.IsTrue(
                expectedDigest.AsSpan().SequenceEqual(ek.Name.Digest),
                "The Name digest must be H_SHA256(TPMT_PUBLIC) over the authPolicy-carrying public area, proving authPolicy is folded into the Name.");
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies the wire-exported standard RSA EK public area carries exactly the Template L-1 shape (TCG EK
    /// Credential Profile, Annex B.3.3) — the objectAttributes mask, the PolicyA authPolicy, AES-128-CFB, a NULL
    /// scheme, and RSA-2048 — that the exported public area carries a real, populated modulus rather than the
    /// all-zero template placeholder (proving the RSA storage-parent effect retained and exported it, R-8), and
    /// that the object's Name equals an independent off-TPM recomputation over that modulus-carrying public area.
    /// </summary>
    [TestMethod]
    public async Task RsaEndorsementKeyTemplateMatchesTheStandardProfile()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalWithRsaAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_ENDORSEMENT, pool);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (standard RSA EK) failed: '{result.ResponseCode}'.");

        using CreatePrimaryResponse ek = result.Value;
        try
        {
            TpmtPublic publicArea = ek.OutPublic.PublicArea;

            TpmaObject expectedAttributes =
                TpmaObject.FIXED_TPM | TpmaObject.FIXED_PARENT | TpmaObject.SENSITIVE_DATA_ORIGIN |
                TpmaObject.ADMIN_WITH_POLICY | TpmaObject.RESTRICTED | TpmaObject.DECRYPT;
            Assert.AreEqual(expectedAttributes, publicArea.ObjectAttributes, "The exported RSA EK must carry exactly the L-1 objectAttributes mask.");

            Assert.IsTrue(PolicyA.AsSpan().SequenceEqual(publicArea.AuthPolicy.AsReadOnlySpan()), "authPolicy must equal the published PolicyA digest.");

            Assert.IsNotNull(publicArea.Parameters.RsaDetail, "The RSA EK must carry RSA parameters.");
            TpmsRsaParms rsaParms = publicArea.Parameters.RsaDetail!.Value;
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_AES, rsaParms.Symmetric.Algorithm, "The RSA EK's symmetric algorithm must be AES.");
            Assert.AreEqual((ushort)128, rsaParms.Symmetric.KeyBits, "The RSA EK's symmetric key size must be 128 bits.");
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_CFB, rsaParms.Symmetric.Mode, "The RSA EK's symmetric mode must be CFB.");
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_NULL, rsaParms.Scheme.Scheme, "The RSA EK's scheme must be NULL (a storage key, not a signing key).");
            Assert.AreEqual(Rsa2048KeyBits, rsaParms.KeyBits, "The RSA EK must be RSA-2048.");

            //The generated modulus must be present, correctly sized, and populated — not the all-zero template
            //placeholder (TCG EK Credential Profile, Annex B.3.1) — proving BuildRsaStorageParentArtifacts (R-8)
            //retained and exported the real generated modulus rather than echoing the caller's template unique.
            byte[] modulus = publicArea.Unique.GetRsaModulus().ToArray();
            Assert.HasCount(Rsa2048KeyBits / 8, modulus, "The exported modulus must be 256 octets (RSA-2048).");
            Assert.IsFalse(modulus.AsSpan().SequenceEqual(new byte[Rsa2048KeyBits / 8]), "The exported modulus must be a real generated value, not the all-zero template placeholder.");

            //Recompute the Name off-TPM, firewalled: marshal the exported public area and hash it through the
            //registered digest seam directly, never through the production TpmObjectName helper.
            byte[] marshaledPublic = MarshalPublicArea(ek.OutPublic, pool);
            byte[] expectedDigest = await ComputeDigestAsync(marshaledPublic, pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((ushort)TpmAlgIdConstants.TPM_ALG_SHA256, ek.Name.NameAlgorithm, "The Name must carry the SHA-256 nameAlg.");
            Assert.IsTrue(
                expectedDigest.AsSpan().SequenceEqual(ek.Name.Digest),
                "The Name digest must be H_SHA256(TPMT_PUBLIC) over the modulus-carrying public area, proving the generated modulus is folded into the Name.");
        }
        finally
        {
            await FlushAsync(tpm, registry, ek.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies the standard RSA endorsement key's caller-supplied template (the <c>inPublic</c> a real caller
    /// would send, before <c>TPM2_CreatePrimary()</c> ever runs) marshals to the byte-exact TCG EK Credential
    /// Profile, Annex B.3.3, Table 2 wire form — including the 256-octet all-zero <c>unique</c> field (trap:
    /// never the empty-RSA convention). The expected bytes are hand-transcribed directly from the spec table,
    /// independent of the production <see cref="TpmtPublic.WriteTo"/> call this test exercises.
    /// </summary>
    [TestMethod]
    public void RsaEndorsementKeyTemplateMarshalsToTheStandardProfileKat()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        using Tpm2bPublic template = Tpm2bPublic.CreateRsaEndorsementKeyTemplate(TpmAlgIdConstants.TPM_ALG_SHA256, Rsa2048KeyBits, pool, PolicyA);

        byte[] marshaled = MarshalPublicArea(template, pool);
        byte[] expected = BuildExpectedRsaL1TemplateBytes();

        Assert.IsTrue(
            expected.AsSpan().SequenceEqual(marshaled),
            "The RSA EK template must marshal to the byte-exact TCG EK Credential Profile, Annex B.3.3, Table 2 wire form.");
    }

    /// <summary>
    /// Verifies Template L-1 (RSA) and Template L-2 (ECC) carry the byte-identical "PolicyA" digest (TCG EK
    /// Credential Profile, Annex B.3.1: PolicyA authorizes knowledge of the Endorsement Hierarchy's
    /// authorization, a property of the hierarchy, not of the protected key's algorithm) by creating both
    /// standard endorsement keys against one dual-backend simulator and comparing their exported authPolicy
    /// bytes directly, rather than only against the hardcoded <see cref="PolicyA"/> constant.
    /// </summary>
    [TestMethod]
    public async Task EndorsementKeyPolicyADigestIsByteIdenticalAcrossRsaAndEccTemplates()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalWithBothBackendsAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryInput eccInput = CreatePrimaryInput.ForEndorsementKey(TpmRh.TPM_RH_ENDORSEMENT, pool);
        using TpmPasswordSession eccAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> eccResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, eccInput, [eccAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(eccResult.IsSuccess, $"CreatePrimary (ECC EK) failed: '{eccResult.ResponseCode}'.");
        using CreatePrimaryResponse eccEk = eccResult.Value;

        using CreatePrimaryInput rsaInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_ENDORSEMENT, pool);
        using TpmPasswordSession rsaAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> rsaResult = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, rsaInput, [rsaAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rsaResult.IsSuccess, $"CreatePrimary (RSA EK) failed: '{rsaResult.ResponseCode}'.");
        using CreatePrimaryResponse rsaEk = rsaResult.Value;

        try
        {
            ReadOnlySpan<byte> eccPolicyA = eccEk.OutPublic.PublicArea.AuthPolicy.AsReadOnlySpan();
            ReadOnlySpan<byte> rsaPolicyA = rsaEk.OutPublic.PublicArea.AuthPolicy.AsReadOnlySpan();

            Assert.IsTrue(
                eccPolicyA.SequenceEqual(rsaPolicyA),
                "Template L-1 (RSA) and Template L-2 (ECC) must carry the byte-identical PolicyA digest.");
            Assert.IsTrue(eccPolicyA.SequenceEqual(PolicyA), "The ECC EK's authPolicy must equal the published PolicyA digest.");
        }
        finally
        {
            await FlushAsync(tpm, registry, rsaEk.ObjectHandle.Value, pool).ConfigureAwait(false);
            await FlushAsync(tpm, registry, eccEk.ObjectHandle.Value, pool).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Builds the expected marshaled bytes of the RSA L-1 template (TCG EK Credential Profile, Annex B.3.3,
    /// Table 2), hand-transcribed field-by-field from the spec table — independent of the production template
    /// factory the KAT test exercises.
    /// </summary>
    /// <returns>The expected 314-octet marshaled TPMT_PUBLIC.</returns>
    private static byte[] BuildExpectedRsaL1TemplateBytes()
    {
        byte[] header = Convert.FromHexString(
            "0001" +           //type: TPM_ALG_RSA.
            "000B" +           //nameAlg: TPM_ALG_SHA256.
            "000300B2" +       //objectAttributes: FIXED_TPM|FIXED_PARENT|SENSITIVE_DATA_ORIGIN|ADMIN_WITH_POLICY|RESTRICTED|DECRYPT.
            "0020" +           //authPolicy.size: 32.
            "837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa" + //authPolicy.buffer: PolicyA.
            "0006" +           //parameters.symmetric.algorithm: TPM_ALG_AES.
            "0080" +           //parameters.symmetric.keyBits: 128.
            "0043" +           //parameters.symmetric.mode: TPM_ALG_CFB.
            "0010" +           //parameters.scheme.scheme: TPM_ALG_NULL (no scheme parameters follow).
            "0800" +           //parameters.keyBits: 2048.
            "00000000" +       //parameters.exponent: 0 (TPM default 2^16+1 = 65537 wire convention).
            "0100");           //unique.size: 256.

        //unique.buffer: 256 zero octets — present and sized, never the empty-RSA convention (TCG EK Credential
        //Profile, Annex B.3.1's "buffer reserved for the public key of the EK is set to all zeros").
        byte[] expected = new byte[header.Length + 256];
        header.CopyTo(expected, 0);

        return expected;
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
    /// Computes SHA-256(<paramref name="message"/>) through the registered digest seam (not a direct framework
    /// hash), firewalled from the production <c>TpmObjectName</c> helper.
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-octet digest.</returns>
    private static async Task<byte[]> ComputeDigestAsync(ReadOnlyMemory<byte> message, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        Tag tag = Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message), 32, tag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The ECC backend is required so the simulator services
    /// <c>TPM2_CreatePrimary()</c> for the standard endorsement key.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-ek-template", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Creates a simulator with the RSA (framework-backed) signing backend wired, powers it on, and brings it
    /// through <c>TPM2_Startup(CLEAR)</c> into the operational phase. The RSA backend is required so the
    /// simulator services <c>TPM2_CreatePrimary()</c> for the standard RSA endorsement key; no ECC backend is
    /// wired, matching the ECC-only exemplar's minimal-wiring style.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalWithRsaAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-ek-template-rsa", rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Creates a simulator with both the ECC and RSA signing backends wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase — needed only by the cross-algorithm PolicyA
    /// comparison, which creates both standard endorsement keys against a single simulator instance.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalWithBothBackendsAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-ek-template-both",
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

    /// <summary>Creates a response codec registry covering the commands this test issues.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Flushes a transient object handle, ignoring the result.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="handle">The handle to flush.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle, MemoryPool<byte> pool)
    {
        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }
}
