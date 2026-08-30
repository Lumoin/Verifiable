using System;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicyLocality()</c> (TPM 2.0 Library Part 3, Section 23.8; Part 2, Section 8.5, Table 39)
/// against the in-house <see cref="TpmSimulator"/> through the production command path: it restricts a policy
/// session's authority to a set of localities and, because this simulator always receives commands at locality
/// 0, a session narrowed away from <c>TPM_LOC_ZERO</c> can fold a valid digest yet never authorize anything.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyLocalityTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies <c>TPM2_PolicyLocality()</c> folds <c>H(policyDigest || TPM_CC_PolicyLocality || locality)</c>
    /// over the locality octet AS SENT (Part 3, Section 23.8), matching <see cref="TpmPolicyDigest.ExtendForLocality"/>.
    /// </summary>
    [TestMethod]
    public async Task PolicyLocalityFoldsTheOctetAsSent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-locality-fold", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] predicted = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForLocality(zero, TpmaLocality.TPM_LOC_ZERO, PolicySweepHarness.SessionAlg, predicted);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyLocalityResponse> localityResult = await tpm.PolicyLocalityAsync(sessionHandle, TpmaLocality.TPM_LOC_ZERO, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(localityResult.IsSuccess, $"PolicyLocality failed: '{localityResult.ResponseCode}'.");

            byte[] actual = await GetDigestAsync(tpm, sessionHandle).ConfigureAwait(false);

            Assert.IsTrue(actual.AsSpan().SequenceEqual(predicted), "PolicyLocality must fold H(policyDigest || TPM_CC_PolicyLocality || locality) over the octet as sent.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyLocality()</c> refuses a zero locality octet with <c>TPM_RC_RANGE</c> (Part 2,
    /// Section 8.5: a zero octet selects no locality at all).
    /// </summary>
    [TestMethod]
    public async Task PolicyLocalityRefusesAZeroOctet()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-locality-zero-octet", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);

            TpmResult<PolicyLocalityResponse> result = await tpm.PolicyLocalityAsync(sessionHandle, (TpmaLocality)0, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(result.IsSuccess, "A zero locality octet selects nothing and must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_RANGE, result.ResponseCode, "A zero locality octet must refuse TPM_RC_RANGE.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyLocality()</c> refuses with <c>TPM_RC_RANGE</c> when a second, narrower assertion
    /// ANDs against the prior setting to an empty set (Part 3, Section 23.8: normal localities intersect, and an
    /// empty result is refused, leaving the session unchanged).
    /// </summary>
    [TestMethod]
    public async Task PolicyLocalityRefusesWhenNarrowingToNothing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-locality-narrow-empty", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyLocalityResponse> first = await tpm.PolicyLocalityAsync(sessionHandle, TpmaLocality.TPM_LOC_ONE, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"PolicyLocality(TPM_LOC_ONE) failed: '{first.ResponseCode}'.");

            TpmResult<PolicyLocalityResponse> second = await tpm.PolicyLocalityAsync(sessionHandle, TpmaLocality.TPM_LOC_ZERO, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(second.IsSuccess, "Narrowing TPM_LOC_ONE with TPM_LOC_ZERO leaves no locality enabled and must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_RANGE, second.ResponseCode, "Narrowing to an empty set must refuse TPM_RC_RANGE.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyLocality()</c> refuses a normal locality after an extended one with
    /// <c>TPM_RC_RANGE</c> (Part 3, Section 23.8: a prior setting and the new request must both be normal or
    /// both be extended).
    /// </summary>
    [TestMethod]
    public async Task PolicyLocalityRefusesANormalAfterAnExtended()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-locality-extended-then-normal", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint sessionHandle = 0;
        try
        {
            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyLocalityResponse> extended = await tpm.PolicyLocalityAsync(sessionHandle, (TpmaLocality)0x20, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(extended.IsSuccess, $"PolicyLocality(extended) failed: '{extended.ResponseCode}'.");

            TpmResult<PolicyLocalityResponse> normal = await tpm.PolicyLocalityAsync(sessionHandle, TpmaLocality.TPM_LOC_ZERO, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(normal.IsSuccess, "A normal locality after an extended one must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_RANGE, normal.ResponseCode, "Mixing normal and extended localities must refuse TPM_RC_RANGE.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyLocality()</c> refuses a different extended locality with <c>TPM_RC_RANGE</c> (Part
    /// 3, Section 23.8: an extended request must equal any prior extended setting), while the SAME extended
    /// value re-asserted is accepted.
    /// </summary>
    [TestMethod]
    public async Task PolicyLocalityRefusesADifferentExtended()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-locality-extended-conflict", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        uint conflictSession = 0;
        uint repeatSession = 0;
        try
        {
            conflictSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyLocalityResponse> first = await tpm.PolicyLocalityAsync(conflictSession, (TpmaLocality)0x20, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"PolicyLocality(0x20) failed: '{first.ResponseCode}'.");

            TpmResult<PolicyLocalityResponse> conflicting = await tpm.PolicyLocalityAsync(conflictSession, (TpmaLocality)0x21, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(conflicting.IsSuccess, "A different extended locality must be refused.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_RANGE, conflicting.ResponseCode, "A conflicting extended locality must refuse TPM_RC_RANGE.");

            repeatSession = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyLocalityResponse> repeatFirst = await tpm.PolicyLocalityAsync(repeatSession, (TpmaLocality)0x20, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(repeatFirst.IsSuccess, $"PolicyLocality(0x20) failed: '{repeatFirst.ResponseCode}'.");
            TpmResult<PolicyLocalityResponse> repeatSame = await tpm.PolicyLocalityAsync(repeatSession, (TpmaLocality)0x20, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(repeatSame.IsSuccess, "The SAME extended locality re-asserted must be accepted.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, conflictSession, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, repeatSession, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a session narrowed to <c>TPM_LOC_ZERO</c> successfully unseals: this simulator receives every
    /// command at locality 0, which stays enabled, so the deferred locality check (Part 4
    /// <c>CheckPolicyAuthSession</c>) passes and the sealed secret comes back unchanged.
    /// </summary>
    [TestMethod]
    public async Task PolicyLocalityZeroEnabledSessionUnsealsAtLocalityZero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed-under-locality-zero"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-locality-zero-unseal", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForLocality(zero, TpmaLocality.TPM_LOC_ZERO, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyLocalityResponse> localityResult = await tpm.PolicyLocalityAsync(sessionHandle, TpmaLocality.TPM_LOC_ZERO, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(localityResult.IsSuccess, $"PolicyLocality failed: '{localityResult.ResponseCode}'.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, PolicySweepHarness.SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(unsealResult.IsSuccess, $"Unseal under a TPM_LOC_ZERO-enabled session failed: '{unsealResult.ResponseCode}'.");
            using UnsealResponse unsealed = unsealResult.Value;
            Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(secret), "The unsealed data must equal the sealed secret.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a session narrowed to ONLY <c>TPM_LOC_ONE</c> refuses <c>TPM2_Unseal()</c> with a bare
    /// <c>TPM_RC_LOCALITY</c>: this simulator receives every command at locality 0, which such a session never
    /// enables, so the deferred check (Part 4 <c>CheckPolicyAuthSession</c>) fails even though the accumulated
    /// policyDigest matches the sealed object's authPolicy.
    /// </summary>
    [TestMethod]
    public async Task PolicyLocalityOneOnlySessionFailsUnseal()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed-under-locality-one"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-locality-one-unseal", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForLocality(zero, TpmaLocality.TPM_LOC_ONE, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartSessionAsync(tpm).ConfigureAwait(false);
            TpmResult<PolicyLocalityResponse> localityResult = await tpm.PolicyLocalityAsync(sessionHandle, TpmaLocality.TPM_LOC_ONE, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(localityResult.IsSuccess, $"PolicyLocality failed: '{localityResult.ResponseCode}'.");

            using TpmPolicySession policySession = TpmPolicySession.ForSession(sessionHandle, PolicySweepHarness.SessionAlg, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess, "A session enabling only TPM_LOC_ONE must never authorize a command at locality 0.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_LOCALITY, unsealResult.ResponseCode, "Locality 0 not being enabled is a bare TPM_RC_LOCALITY.");
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
