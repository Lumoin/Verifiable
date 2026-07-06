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
