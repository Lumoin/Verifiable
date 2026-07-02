using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <see cref="TpmPolicyBuilder"/> / <see cref="TpmPolicy"/> against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets. Each test builds a policy once, then
/// confirms that <see cref="TpmPolicy.ComputeDigest"/> (the host prediction) and <see cref="TpmPolicy.ExecuteAsync"/>
/// (the on-device replay, through the production command path) agree on a live session, so the two duals — predict
/// and execute — cannot drift apart (TPM 2.0 Library Part 1, clause 19.7).
/// </summary>
/// <remarks>
/// The simulator advances the session's policyDigest by calling the same <see cref="TpmPolicyDigest"/> methods the
/// prediction uses, so the executed digest equalling the predicted one exercises the wire round-trip and assertion
/// composition end to end, not the raw spec formula (that is the role of <see cref="TpmPolicyDigest"/>'s unit tests).
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyBuilderTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task BuiltPolicyExecutesToItsComputedDigest()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;

        //One description: require the object's authValue, then restrict the session to TPM2_Sign.
        TpmPolicy policy = new TpmPolicyBuilder()
            .WithAuthValue()
            .WithCommandCode(TpmCcConstants.TPM_CC_Sign)
            .Build();

        byte[] predicted = new byte[TpmPolicyDigest.Size(PolicyHash)];
        _ = policy.ComputeDigest(PolicyHash, predicted);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<uint> executeResult = await policy.ExecuteAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(executeResult.IsSuccess, $"Policy execution failed: '{executeResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;
            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "The executed policy's digest must equal the host-computed digest from the same description.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task BuiltOrPolicyExecutesToItsComputedDigest()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        int size = TpmPolicyDigest.Size(PolicyHash);

        //Two alternative branches; the session will satisfy the first.
        byte[] branchA = new byte[size];
        _ = new TpmPolicyBuilder().WithAuthValue().Build().ComputeDigest(PolicyHash, branchA);

        byte[] branchB = new byte[size];
        _ = new TpmPolicyBuilder().WithCommandCode(TpmCcConstants.TPM_CC_Sign).Build().ComputeDigest(PolicyHash, branchB);

        var branches = new ReadOnlyMemory<byte>[] { branchA, branchB };

        //Satisfy branch A (PolicyAuthValue), then OR the alternatives — exactly what an "A or B" policy is.
        TpmPolicy policy = new TpmPolicyBuilder()
            .WithAuthValue()
            .WithOr(branches)
            .Build();

        byte[] predicted = new byte[size];
        _ = policy.ComputeDigest(PolicyHash, predicted);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (policy) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<uint> executeResult = await policy.ExecuteAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(executeResult.IsSuccess, $"OR policy execution failed: '{executeResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;
            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "The executed OR policy's digest must equal the host-computed digest from the same description.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The policy commands themselves need no signing
    /// backend, but the backend is wired for parity with the other in-house simulator tests.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(MemoryPool<byte> pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-policy-builder", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
}
