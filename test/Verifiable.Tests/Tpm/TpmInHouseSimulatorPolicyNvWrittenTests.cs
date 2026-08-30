using System;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicyNvWritten()</c> (TPM 2.0 Library Part 3, Section 23.20) against the in-house
/// <see cref="TpmSimulator"/> through the production command path: it binds a policy to the authorized NV
/// Index's <c>TPMA_NV_WRITTEN</c> state, deferring the actual check to use time. This class does not exercise
/// the write-once <c>TPM2_NV_ChangeAuth()</c> flow the deferred check ultimately guards in practice — that needs
/// the PIN/ADMIN policy composition elsewhere — so the only use-time facet claimed here is the reachable
/// no-NV-Index refusal against <c>TPM2_Unseal()</c>.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyNvWrittenTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies <c>TPM2_PolicyNvWritten()</c> folds a different digest for YES (<c>writtenSet</c> octet 0x01)
    /// than for NO (octet 0x00) (Part 3, Section 23.20), matching <see cref="TpmPolicyDigest.ExtendForNvWritten"/>
    /// from a fresh policyDigest.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWrittenFoldsYesAndNoDifferently()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-nvwritten-fold", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] predictedYes = new byte[size];
        byte[] predictedNo = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForNvWritten(zero, isWrittenSet: true, PolicySweepHarness.SessionAlg, predictedYes);
        _ = TpmPolicyDigest.ExtendForNvWritten(zero, isWrittenSet: false, PolicySweepHarness.SessionAlg, predictedNo);

        uint yesSession = 0;
        uint noSession = 0;
        try
        {
            yesSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyNvWrittenResponse> yesResult = await tpm.PolicyNvWrittenAsync(yesSession, isWrittenSet: true, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(yesResult.IsSuccess, $"PolicyNvWritten(true) failed: '{yesResult.ResponseCode}'.");
            byte[] actualYes = await GetDigestAsync(tpm, yesSession).ConfigureAwait(false);

            noSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyNvWrittenResponse> noResult = await tpm.PolicyNvWrittenAsync(noSession, isWrittenSet: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(noResult.IsSuccess, $"PolicyNvWritten(false) failed: '{noResult.ResponseCode}'.");
            byte[] actualNo = await GetDigestAsync(tpm, noSession).ConfigureAwait(false);

            Assert.IsTrue(actualYes.AsSpan().SequenceEqual(predictedYes), "PolicyNvWritten(true) must fold ExtendForNvWritten(zero, true).");
            Assert.IsTrue(actualNo.AsSpan().SequenceEqual(predictedNo), "PolicyNvWritten(false) must fold ExtendForNvWritten(zero, false).");
            Assert.IsFalse(actualYes.AsSpan().SequenceEqual(actualNo), "YES and NO must fold to different policyDigests.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, yesSession, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, noSession, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyNvWritten()</c> refuses a conflicting second assertion with <c>TPM_RC_VALUE</c>
    /// (Part 3, Section 23.20: "If policySession→checkNvWritten is SET, the TPM will return TPM_RC_VALUE if
    /// policySession→nvWrittenState and writtenSet are not the same"), while re-asserting the SAME value is
    /// accepted.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWrittenRefusesAConflictingSecondAssertion()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-nvwritten-conflict", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint conflictSession = 0;
        uint repeatSession = 0;
        try
        {
            conflictSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyNvWrittenResponse> firstAssertion = await tpm.PolicyNvWrittenAsync(conflictSession, isWrittenSet: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstAssertion.IsSuccess, $"PolicyNvWritten(false) failed: '{firstAssertion.ResponseCode}'.");

            TpmResult<PolicyNvWrittenResponse> conflicting = await tpm.PolicyNvWrittenAsync(conflictSession, isWrittenSet: true, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(conflicting.IsSuccess, "A conflicting second PolicyNvWritten assertion must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, conflicting.ResponseCode, "A conflicting writtenSet assertion must refuse TPM_RC_VALUE.");

            repeatSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyNvWrittenResponse> repeatFirst = await tpm.PolicyNvWrittenAsync(repeatSession, isWrittenSet: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(repeatFirst.IsSuccess, $"PolicyNvWritten(false) failed: '{repeatFirst.ResponseCode}'.");
            TpmResult<PolicyNvWrittenResponse> repeatSame = await tpm.PolicyNvWrittenAsync(repeatSession, isWrittenSet: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(repeatSame.IsSuccess, "The SAME writtenSet re-asserted must be accepted.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, conflictSession, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, repeatSession, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a session carrying an nvWritten check refuses <c>TPM2_Unseal()</c> with a bare
    /// <c>TPM_RC_POLICY_FAIL</c> when the authorized command has no NV Index at all (Part 3, Section 23.20: "If
    /// this is not an NV index, the policy makes no sense so fail it") — even though the accumulated
    /// policyDigest matches the sealed object's authPolicy.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWrittenAtUseFailsUnsealWithNoNvIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed-under-nvwritten-binding"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-nvwritten-no-index", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForNvWritten(zero, isWrittenSet: false, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyNvWrittenResponse> nvWrittenResult = await tpm.PolicyNvWrittenAsync(sessionHandle, isWrittenSet: false, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(nvWrittenResult.IsSuccess, $"PolicyNvWritten failed: '{nvWrittenResult.ResponseCode}'.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, PolicySweepHarness.SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess, "A session carrying an nvWritten check must never authorize an Unseal, which authorizes no NV Index.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY_FAIL, unsealResult.ResponseCode, "An nvWritten check with no NV Index authorized is a bare TPM_RC_POLICY_FAIL.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
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
