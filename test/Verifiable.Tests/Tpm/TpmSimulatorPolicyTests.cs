using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.TestInfrastructure.TpmSimulator;
using Verifiable.Tpm;
using Verifiable.Tpm.Extensions.Policy;
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
/// Acceptance tests for the TPM policy (enhanced authorization) command family against the TCG ms-tpm-20-ref
/// software TPM simulator. They confirm the production policy commands drive a session's policyDigest exactly
/// as the host predicts via <see cref="TpmPolicyDigest"/> — the foundation for binding objects to a policy.
/// </summary>
/// <remarks>
/// <para>
/// The tests are gated on a running simulator (start the container from
/// <c>test/Verifiable.Tests/TestInfrastructure/TpmSimulator/Dockerfile</c>, publishing ports 2321/2322); they
/// report <see cref="Assert.Inconclusive(string)"/> when none is reachable, so they are safe in any run.
/// </para>
/// </remarks>
[ConditionalTestClass]
[SkipIfNoTpmSimulator]
[DoNotParallelize]
[TestCategory("RequiresTpmSimulator")]
internal sealed class TpmSimulatorPolicyTests
{
    /// <summary>The connection to the simulator, established once for the class.</summary>
    private static MsTpmSimulatorConnection? Connection { get; set; }

    /// <summary>The TPM device created over the simulator connection.</summary>
    private static TpmDevice? Tpm { get; set; }

    /// <summary>Whether a simulator was reachable at class initialization.</summary>
    private static bool HasSimulator { get; set; }

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Connects to the simulator (if one is reachable) and brings up a TPM device for the class.
    /// </summary>
    /// <param name="context">The class-level test context.</param>
    [ClassInitialize]
    public static async Task ClassInit(TestContext context)
    {
        if(!MsTpmSimulatorConnection.IsAvailable("localhost", MsTpmSimulatorConnection.DefaultCommandPort, TimeSpan.FromSeconds(1)))
        {
            return;
        }

        Connection = await MsTpmSimulatorConnection.ConnectAsync(
            "localhost", MsTpmSimulatorConnection.DefaultCommandPort, context.CancellationToken).ConfigureAwait(false);
        Tpm = TpmDevice.Create(Connection.SubmitAsync);
        HasSimulator = true;
    }

    /// <summary>
    /// Releases the TPM device and simulator connection.
    /// </summary>
    [ClassCleanup]
    public static void ClassCleanup()
    {
        Tpm?.Dispose();
        Connection?.Dispose();
    }

    /// <summary>
    /// Skips the test when no simulator is reachable.
    /// </summary>
    [TestInitialize]
    public void TestInit()
    {
        if(!HasSimulator)
        {
            Assert.Inconclusive("No TPM simulator is reachable on localhost:2321/2322. Start the container from TestInfrastructure/TpmSimulator/Dockerfile.");
        }
    }

    [TestMethod]
    public async Task PolicyCommandCodeDrivesTheSessionPolicyDigestAsPredicted()
    {
        TpmDevice tpm = Tpm!;
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;

        //A trial session accumulates a policyDigest without authorizing anything, exactly as a real policy
        //session would, so its digest is what an object's authPolicy would be set to.
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicyCommandCodeResponse> policyResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Sign, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(policyResult.IsSuccess, $"PolicyCommandCode failed: '{policyResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            //Require the TPM's accumulated policyDigest to equal the host prediction: a fresh session starts at
            //all zeros, and PolicyCommandCode extends it by H(zeros || TPM_CC_PolicyCommandCode || TPM_CC_Sign).
            Assert.IsTrue(
                MatchesCommandCodePolicy(digest.PolicyDigest.AsReadOnlySpan(), TpmCcConstants.TPM_CC_Sign, PolicyHash),
                "The simulator's policyDigest after PolicyCommandCode must match the host-computed value.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicyAuthValueThenPolicyCommandCodeComposeAsPredicted()
    {
        TpmDevice tpm = Tpm!;
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_Sign, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            //Two assertions must chain: zeros -> H(zeros || PolicyAuthValue) -> H(that || PolicyCommandCode || Sign).
            Assert.IsTrue(
                MatchesAuthValueThenCommandCode(digest.PolicyDigest.AsReadOnlySpan(), TpmCcConstants.TPM_CC_Sign, PolicyHash),
                "The simulator's policyDigest after PolicyAuthValue + PolicyCommandCode must match the host-computed chain.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicyPcrDrivesTheSessionPolicyDigestAsPredicted()
    {
        TpmDevice tpm = Tpm!;
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;
        int[] pcrIndices = [0];

        //On a trial session the TPM uses the caller's pcrDigest verbatim, so the prediction does not depend on
        //live PCR contents — the test stays deterministic.
        byte[] pcrDigest = SHA256.HashData("policy-pcr-test"u8);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicyPcrResponse> pcrResult = await tpm.PolicyPcrAsync(
                sessionHandle, PcrBank, pcrIndices, pcrDigest, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(pcrResult.IsSuccess, $"PolicyPCR failed: '{pcrResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            Assert.IsTrue(
                MatchesPcrPolicy(digest.PolicyDigest.AsReadOnlySpan(), PcrBank, pcrIndices, pcrDigest, PolicyHash),
                "The simulator's policyDigest after PolicyPCR must match the host-computed value.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicySecretBindsToTheEndorsementKeyPolicy()
    {
        TpmDevice tpm = Tpm!;
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;

        //PolicySecret authorizes a hierarchy for real, so this uses a real policy session (not a trial one); the
        //resulting policyDigest is identical either way.
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret failed: '{secretResult.ResponseCode}'.");

            using(secretResult.Value)
            {
                TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

                using PolicyGetDigestResponse digest = digestResult.Value;

                //PolicySecret(TPM_RH_ENDORSEMENT) extends zeros by H(zeros || TPM_CC_PolicySecret || endorsementName)
                //followed by the (empty) policyRef hash.
                Assert.IsTrue(
                    MatchesEndorsementSecretPolicy(digest.PolicyDigest.AsReadOnlySpan(), PolicyHash),
                    "The simulator's policyDigest after PolicySecret(endorsement) must match the host-computed value.");

                //That value is the well-known TCG endorsement-key authorization policy.
                Assert.IsTrue(
                    digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(WellKnownEndorsementKeyPolicySha256),
                    "PolicySecret(endorsement) must yield the well-known EK authorization policy.");
            }
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    //The well-known TCG endorsement-key authorization policy for SHA-256:
    //H(0x00...00(32) || TPM_CC_PolicySecret || TPM_RH_ENDORSEMENT), empty policyRef (TCG EK Credential Profile).
    private static readonly byte[] WellKnownEndorsementKeyPolicySha256 =
    [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
        0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa
    ];

    /// <summary>
    /// Predicts the policyDigest of a fresh policy session after PolicySecret(TPM_RH_ENDORSEMENT) and compares it
    /// to <paramref name="actualDigest"/>. Kept synchronous so the stack buffers never span an await.
    /// </summary>
    /// <param name="actualDigest">The policyDigest reported by the TPM.</param>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    /// <returns><see langword="true"/> when the prediction matches.</returns>
    private static bool MatchesEndorsementSecretPolicy(ReadOnlySpan<byte> actualDigest, TpmAlgIdConstants policyHash)
    {
        int size = TpmPolicyDigest.Size(policyHash);
        Span<byte> current = stackalloc byte[size];
        current.Clear();

        //The Name of a permanent handle is its 4-byte handle value.
        Span<byte> endorsementName = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(endorsementName, (uint)TpmRh.TPM_RH_ENDORSEMENT);

        Span<byte> predicted = stackalloc byte[size];
        TpmPolicyDigest.ExtendForSecret(current, endorsementName, ReadOnlySpan<byte>.Empty, policyHash, predicted);

        return actualDigest.SequenceEqual(predicted);
    }

    [TestMethod]
    public async Task PolicyOrAuthorizesAMatchingBranchAndCollapsesToTheOrDigest()
    {
        TpmDevice tpm = Tpm!;
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        int size = TpmPolicyDigest.Size(PolicyHash);

        //PolicyOR's match check runs on a real session, so this uses one (not a trial session).
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            //Drive the session to a known digest so it equals one of the OR branches.
            TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

            byte[] matchingBranch = new byte[size];
            Span<byte> zero = stackalloc byte[size];
            zero.Clear();
            TpmPolicyDigest.ExtendForAuthValue(zero, PolicyHash, matchingBranch);

            byte[] otherBranch = new byte[size];
            Array.Fill(otherBranch, (byte)0x5A);

            var branches = new ReadOnlyMemory<byte>[] { matchingBranch, otherBranch };

            //The session's current digest equals matchingBranch, so PolicyOR authorizes and collapses to the OR digest.
            TpmResult<PolicyOrResponse> orResult = await tpm.PolicyOrAsync(
                sessionHandle, branches, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(orResult.IsSuccess, $"PolicyOR failed: '{orResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            byte[] predicted = new byte[size];
            TpmPolicyDigest.ExtendForOr(branches, PolicyHash, predicted);

            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "The simulator's policyDigest after PolicyOR must equal H(0 || TPM_CC_PolicyOR || branches).");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicyNvDrivesTheSessionPolicyDigestAsPredicted()
    {
        TpmDevice tpm = Tpm!;
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0012;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        int size = TpmPolicyDigest.Size(PolicyHash);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] operandB = [0x10, 0x20, 0x30, 0x40];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        //A trial session needs only the Index's Name, not its data, so the Index can stay unwritten.
        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                TpmResult<PolicyNvResponse> nvResult = await tpm.PolicyNvAsync(
                    NvIndex, NvIndex, sessionHandle, operandB, Offset, Operation, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(nvResult.IsSuccess, $"PolicyNV failed: '{nvResult.ResponseCode}'.");

                TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

                using PolicyGetDigestResponse digest = digestResult.Value;

                //policyDigest = H(zeros || TPM_CC_PolicyNV || H(operandB || offset || operation) || nvName).
                byte[] nvName = ComputeNvName(NvIndex, PolicyHash, attributes, DataSize, pool);
                byte[] predicted = new byte[size];
                Span<byte> zero = stackalloc byte[size];
                zero.Clear();
                TpmPolicyDigest.ExtendForNv(zero, operandB, Offset, (ushort)Operation, nvName, PolicyHash, predicted);

                Assert.IsTrue(
                    digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                    "The simulator's policyDigest after PolicyNV must match the host-computed value.");
            }
            finally
            {
                _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Defines a small NV Index authorized by its own (empty) auth value.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="attributes">The Index attributes.</param>
    /// <param name="dataSize">The data area size.</param>
    /// <returns>The NV_DefineSpace result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineNvAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint nvIndex, TpmaNv attributes, ushort dataSize)
    {
        using Tpm2bAuth indexAuth = Tpm2bAuth.CreateEmpty(pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, indexAuth, publicInfo);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Undefines an NV Index, returning the result for the caller to assert or ignore.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <returns>The NV_UndefineSpace result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineNvAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MemoryPool<byte> pool, uint nvIndex)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes an NV Index Name (<c>nameAlg || H(TPMS_NV_PUBLIC)</c>) from its public-area fields.
    /// </summary>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="nameAlg">The Name hash algorithm (SHA-256).</param>
    /// <param name="attributes">The Index attributes, exactly as stored (include TPMA_NV_WRITTEN once written).</param>
    /// <param name="dataSize">The data area size.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The Name bytes.</returns>
    private static byte[] ComputeNvName(uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ushort dataSize, MemoryPool<byte> pool)
    {
        using var nvPublic = new TpmsNvPublic(nvIndex, nameAlg, attributes, Tpm2bDigest.Empty, dataSize);
        int publicSize = nvPublic.SerializedSize;
        using IMemoryOwner<byte> owner = pool.Rent(publicSize);
        Span<byte> publicArea = owner.Memory.Span[..publicSize];
        var writer = new TpmWriter(publicArea);
        nvPublic.WriteTo(ref writer);

        byte[] name = new byte[sizeof(ushort) + 32];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        _ = SHA256.HashData(publicArea, name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Predicts the policyDigest of a fresh policy session restricted with a single PolicyCommandCode and
    /// compares it to <paramref name="actualDigest"/>. Kept synchronous so the stack buffers never span an await.
    /// </summary>
    /// <param name="actualDigest">The policyDigest reported by the TPM.</param>
    /// <param name="restrictedCommand">The command code the policy was restricted to.</param>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    /// <returns><see langword="true"/> when the prediction matches.</returns>
    private static bool MatchesCommandCodePolicy(ReadOnlySpan<byte> actualDigest, TpmCcConstants restrictedCommand, TpmAlgIdConstants policyHash)
    {
        int size = TpmPolicyDigest.Size(policyHash);

        //These buffers hold only non-secret public policy material (a policyDigest over public inputs) and are
        //test-local, so stack allocation is acceptable rather than the BaseMemoryPool containment used for
        //sensitive material. A fresh session's policyDigest is all zeros (stackalloc is zero-initialized).
        Span<byte> initial = stackalloc byte[size];
        Span<byte> expected = stackalloc byte[size];
        int expectedLength = TpmPolicyDigest.ExtendForCommandCode(initial, restrictedCommand, policyHash, expected);

        return actualDigest.SequenceEqual(expected[..expectedLength]);
    }

    /// <summary>
    /// Predicts the policyDigest of a fresh policy session after PolicyAuthValue then a PolicyCommandCode and
    /// compares it to <paramref name="actualDigest"/>. Kept synchronous so the stack buffers never span an await.
    /// </summary>
    /// <param name="actualDigest">The policyDigest reported by the TPM.</param>
    /// <param name="restrictedCommand">The command code the policy was restricted to.</param>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    /// <returns><see langword="true"/> when the prediction matches.</returns>
    private static bool MatchesAuthValueThenCommandCode(ReadOnlySpan<byte> actualDigest, TpmCcConstants restrictedCommand, TpmAlgIdConstants policyHash)
    {
        int size = TpmPolicyDigest.Size(policyHash);

        //Non-secret public policy material, test-local: stack allocation is acceptable rather than the
        //BaseMemoryPool containment used for sensitive material. Fresh session is all zeros (zero-initialized).
        Span<byte> afterAuthValue = stackalloc byte[size];
        int afterAuthValueLength = TpmPolicyDigest.ExtendForAuthValue(stackalloc byte[size], policyHash, afterAuthValue);

        Span<byte> expected = stackalloc byte[size];
        int expectedLength = TpmPolicyDigest.ExtendForCommandCode(afterAuthValue[..afterAuthValueLength], restrictedCommand, policyHash, expected);

        return actualDigest.SequenceEqual(expected[..expectedLength]);
    }

    /// <summary>
    /// Predicts the policyDigest of a fresh policy session after a single PolicyPCR and compares it to
    /// <paramref name="actualDigest"/>. Kept synchronous so the stack buffers never span an await.
    /// </summary>
    /// <param name="actualDigest">The policyDigest reported by the TPM.</param>
    /// <param name="pcrBank">The PCR bank selected.</param>
    /// <param name="pcrIndices">The PCR indices selected.</param>
    /// <param name="pcrDigest">The PCR digest the policy bound to.</param>
    /// <param name="policyHash">The session's policy hash algorithm.</param>
    /// <returns><see langword="true"/> when the prediction matches.</returns>
    private static bool MatchesPcrPolicy(ReadOnlySpan<byte> actualDigest, TpmAlgIdConstants pcrBank, int[] pcrIndices, ReadOnlySpan<byte> pcrDigest, TpmAlgIdConstants policyHash)
    {
        using TpmlPcrSelection pcrs = TpmlPcrSelection.Create(pcrBank, pcrIndices, BaseMemoryPool.Shared);

        //Non-secret public policy material (marshaled PCR selection and a policyDigest over public inputs) and
        //test-local, so stack allocation is acceptable rather than the BaseMemoryPool containment used for
        //sensitive material.
        Span<byte> marshaled = stackalloc byte[pcrs.GetSerializedSize()];
        var writer = new TpmWriter(marshaled);
        pcrs.WriteTo(ref writer);

        int size = TpmPolicyDigest.Size(policyHash);
        Span<byte> expected = stackalloc byte[size];
        int expectedLength = TpmPolicyDigest.ExtendForPcr(stackalloc byte[size], marshaled[..writer.Written], pcrDigest, policyHash, expected);

        return actualDigest.SequenceEqual(expected[..expectedLength]);
    }
}
