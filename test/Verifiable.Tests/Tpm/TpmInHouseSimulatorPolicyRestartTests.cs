using System;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicyRestart()</c> (TPM 2.0 Library Part 3, Section 11.2) against the in-house
/// <see cref="TpmSimulator"/> through the production command path: it returns a policy session's accumulated
/// context to its initial state without rolling its nonceTPM, so previously bound assertions can be replayed.
/// This class does not exercise the nonceTPM-preservation-across-<c>TPM2_PolicySecret()</c> claim, since proving
/// it needs a full authorization-ticket round trip; that facet is out of this class's scope.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyRestartTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies <c>TPM2_PolicyRestart()</c> clears a session's accumulated policyDigest back to the Zero Digest
    /// (Part 3, Section 11.2, Table 16), after a prior <c>TPM2_PolicyCommandCode()</c> assertion moved it away
    /// from zero.
    /// </summary>
    [TestMethod]
    public async Task PolicyRestartClearsTheAccumulatedDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-restart-clears", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] zeroDigest = new byte[size];

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCode failed: '{commandCodeResult.ResponseCode}'.");

            byte[] movedDigest = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);
            Assert.IsFalse(movedDigest.AsSpan().SequenceEqual(zeroDigest), "PolicyCommandCode must move the digest away from zero before the restart is proven.");

            TpmResult<PolicyRestartResponse> restartResult = await tpm.PolicyRestartAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(restartResult.IsSuccess, $"PolicyRestart failed: '{restartResult.ResponseCode}'.");

            byte[] restartedDigest = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);

            Assert.IsTrue(restartedDigest.AsSpan().SequenceEqual(zeroDigest), "PolicyRestart must clear the accumulated policyDigest to the Zero Digest.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a session may assert a DIFFERENT <c>TPM2_PolicyCommandCode()</c> restriction after
    /// <c>TPM2_PolicyRestart()</c>, folding fresh from the cleared digest (Part 3, Section 11.2: the command
    /// "does not reset the policy ID or the policy start time", but does clear the recorded commandCode
    /// restriction along with the digest).
    /// </summary>
    [TestMethod]
    public async Task PolicyRestartAllowsADifferentCommandCode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-restart-different-cc", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] predicted = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForCommandCode(zero, TpmCcConstants.TPM_CC_NV_Read, PolicySweepHarness.SessionAlg, predicted);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyCommandCodeResponse> firstAssertion = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_Unseal, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstAssertion.IsSuccess, $"PolicyCommandCode(Unseal) failed: '{firstAssertion.ResponseCode}'.");

            TpmResult<PolicyRestartResponse> restartResult = await tpm.PolicyRestartAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(restartResult.IsSuccess, $"PolicyRestart failed: '{restartResult.ResponseCode}'.");

            TpmResult<PolicyCommandCodeResponse> secondAssertion = await tpm.PolicyCommandCodeAsync(sessionHandle, TpmCcConstants.TPM_CC_NV_Read, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secondAssertion.IsSuccess, $"PolicyCommandCode(NV_Read) after PolicyRestart failed: '{secondAssertion.ResponseCode}'.");

            byte[] actual = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);

            Assert.IsTrue(actual.AsSpan().SequenceEqual(predicted), "The post-restart digest must fold ExtendForCommandCode(zero, TPM_CC_NV_Read), not carry over the pre-restart fold.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyRestart()</c> refuses a handle in the HMAC-session range that names no live policy
    /// session with <c>TPM_RC_HANDLE</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicyRestartRefusesANonPolicyHandle()
    {
        const uint HmacSessionRangeHandle = 0x02000000u;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-restart-non-policy-handle", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<PolicyRestartResponse> result = await tpm.PolicyRestartAsync(HmacSessionRangeHandle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A handle naming no live policy session must be refused.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode, "An HMAC-session-range handle with no live session must refuse TPM_RC_HANDLE.");
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyRestart()</c> refuses an unknown session handle with <c>TPM_RC_HANDLE</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicyRestartRefusesAnUnknownHandle()
    {
        const uint UnknownHandle = 0x03FFFFFFu;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-restart-unknown-handle", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<PolicyRestartResponse> result = await tpm.PolicyRestartAsync(UnknownHandle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "An unknown handle must be refused.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode, "An unknown handle must refuse TPM_RC_HANDLE.");
    }

    /// <summary>Starts a policy session with no assertions yet made against it.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <returns>The started policy session handle.</returns>
    private async Task<uint> StartSessionAsync(TpmDevice tpm)
    {
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(PolicySweepHarness.SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
        using StartAuthSessionResponse session = startResult.Value;

        return session.SessionHandle.Value;
    }

    /// <summary>Reads a policy session's current policyDigest into an owned array.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="sessionHandle">The policy session handle.</param>
    /// <returns>A copy of the policyDigest octets.</returns>
    private async Task<byte[]> GetDigestAsync(TpmDevice tpm, uint sessionHandle)
    {
        TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");
        using PolicyGetDigestResponse digest = digestResult.Value;

        return digest.PolicyDigest.AsReadOnlySpan().ToArray();
    }
}
