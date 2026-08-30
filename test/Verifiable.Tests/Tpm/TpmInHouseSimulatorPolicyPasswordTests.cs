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
/// Drives <c>TPM2_PolicyPassword()</c> against the in-house <see cref="TpmSimulator"/> through the production
/// command path: it binds a policy to the authorized object's authValue presented as a cleartext password in the
/// session's <c>hmac</c> field (TPM 2.0 Library Part 3, Section 23.18), folding the same policyDigest value
/// <c>TPM2_PolicyAuthValue()</c> does.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyPasswordTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies <c>TPM2_PolicyPassword()</c> folds the identical policyDigest to <c>TPM2_PolicyAuthValue()</c>
    /// (Section 23.18: "This is the same extend value as used with TPM2_PolicyAuthValue()"), so one authPolicy
    /// serves either presentation.
    /// </summary>
    [TestMethod]
    public async Task PolicyPasswordFoldsTheSameDigestAsPolicyAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-password-fold", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] predicted = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForAuthValue(zero, PolicySweepHarness.SessionAlg, predicted);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(PolicySweepHarness.SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyPasswordResponse> passwordResult = await tpm.PolicyPasswordAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(passwordResult.IsSuccess, $"PolicyPassword failed: '{passwordResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");
            using PolicyGetDigestResponse digest = digestResult.Value;

            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "TPM2_PolicyPassword must fold the same policyDigest as TPM2_PolicyAuthValue.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Flagship flow: seals a secret whose authValue is a password, under the PolicyPassword/PolicyAuthValue
    /// policy, then unseals it with a policy session that asserted <c>TPM2_PolicyPassword()</c> and presents the
    /// password in the clear in its hmac field (Part 1, Section 16.6.16) — proving the item's authValue is checked
    /// at use as if the authorization were a password.
    /// </summary>
    [TestMethod]
    public async Task PolicyPasswordUnsealsWhenTheCorrectPasswordIsPresented()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed-under-policy-password"u8.ToArray();
        byte[] password = "the-item-authValue"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-password-unseal", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForAuthValue(zero, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, userAuth: password, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartPasswordPolicyAsync(tpm).ConfigureAwait(false);

            using TpmPolicySession policySession = TpmPolicySession.ForSessionWithPassword(sessionHandle, PolicySweepHarness.SessionAlg, password, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(unsealResult.IsSuccess, $"Unseal under PolicyPassword with the correct password failed: '{unsealResult.ResponseCode}'.");
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
    /// Verifies a wrong password refuses the unseal with <c>TPM_RC_BAD_AUTH</c> on the first session (the sealed
    /// item is dictionary-attack-exempt, so a mismatch never charges the lockout counter) — the password IS
    /// compared, not merely folded (Part 3, Section 23.18).
    /// </summary>
    [TestMethod]
    public async Task PolicyPasswordRefusesAWrongPassword()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed"u8.ToArray();
        byte[] password = "correct-horse"u8.ToArray();
        byte[] wrong = "battery-staple"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-password-wrong", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForAuthValue(zero, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, userAuth: password, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            sessionHandle = await StartPasswordPolicyAsync(tpm).ConfigureAwait(false);

            using TpmPolicySession policySession = TpmPolicySession.ForSessionWithPassword(sessionHandle, PolicySweepHarness.SessionAlg, wrong, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess, "A wrong PolicyPassword must refuse the unseal.");
            Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), unsealResult.ResponseCode, "A wrong password against a noDA item must refuse TPM_RC_BAD_AUTH on session 0.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies that when both assertions appear, the LAST one determines the presentation format (Part 1, Section
    /// 16.7.8: "The final instance of these commands determines the format"): a session that asserts
    /// <c>TPM2_PolicyAuthValue()</c> then <c>TPM2_PolicyPassword()</c> enforces the password at use, refusing a
    /// wrong one with <c>TPM_RC_BAD_AUTH</c> even though PolicyAuthValue ran first.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthValueThenPolicyPasswordEnforcesThePasswordFormat()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] secret = "sealed"u8.ToArray();
        byte[] password = "final-format-password"u8.ToArray();
        byte[] wrong = "not-the-password"u8.ToArray();

        using TpmSimulator simulator = await PolicySweepHarness.CreateOperationalAsync("policy-authvalue-then-password", pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = PolicySweepHarness.CreateRegistry();
        using CreatePrimaryResponse parent = await PolicySweepHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //Both assertions fold the same TPM_CC_PolicyAuthValue value, but a policy of TWO assertions folds the
        //digest twice — H(H(0 || CC) || CC) — so the sealed authPolicy is the double fold.
        int size = TpmPolicyDigest.Size(PolicySweepHarness.SessionAlg);
        byte[] authPolicy = new byte[size];
        Span<byte> zero = stackalloc byte[size];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForAuthValue(zero, PolicySweepHarness.SessionAlg, authPolicy);
        _ = TpmPolicyDigest.ExtendForAuthValue(authPolicy, PolicySweepHarness.SessionAlg, authPolicy);

        uint parentHandle = parent.ObjectHandle.Value;
        uint itemHandle = 0;
        uint sessionHandle = 0;
        try
        {
            (itemHandle, byte[] name) = await PolicySweepHarness.SealAndLoadAsync(
                tpm, registry, pool, parentHandle, secret, authPolicy, userAuth: password, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [name];

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(PolicySweepHarness.SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");
            TpmResult<PolicyPasswordResponse> passwordResult = await tpm.PolicyPasswordAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(passwordResult.IsSuccess, $"PolicyPassword failed: '{passwordResult.ResponseCode}'.");

            using TpmPolicySession policySession = TpmPolicySession.ForSessionWithPassword(sessionHandle, PolicySweepHarness.SessionAlg, wrong, pool);
            UnsealInput unsealInput = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
            TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                tpm, unsealInput, [policySession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(unsealResult.IsSuccess, "PolicyPassword last must enforce the password format, refusing a wrong password.");
            Assert.AreEqual(SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), unsealResult.ResponseCode, "The final PolicyPassword makes the wrong password TPM_RC_BAD_AUTH on session 0.");
        }
        finally
        {
            await PolicySweepHarness.FlushIfPresentAsync(tpm, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, itemHandle, TestContext.CancellationToken).ConfigureAwait(false);
            await PolicySweepHarness.FlushIfPresentAsync(tpm, parentHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Starts a policy session and asserts <c>TPM2_PolicyPassword()</c> on it, returning the handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <returns>The started, password-asserted policy session handle.</returns>
    private async Task<uint> StartPasswordPolicyAsync(TpmDevice tpm)
    {
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(PolicySweepHarness.SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySession failed: '{startResult.ResponseCode}'.");
        using StartAuthSessionResponse session = startResult.Value;
        uint handle = session.SessionHandle.Value;

        TpmResult<PolicyPasswordResponse> passwordResult = await tpm.PolicyPasswordAsync(handle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(passwordResult.IsSuccess, $"PolicyPassword failed: '{passwordResult.ResponseCode}'.");

        return handle;
    }

    /// <summary>The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): base code + TPM_RC_S + 0x100 * (index + 1).</summary>
    /// <param name="baseRc">The unencoded base response code.</param>
    /// <param name="sessionIndex">The offending session's zero-based index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));
}
