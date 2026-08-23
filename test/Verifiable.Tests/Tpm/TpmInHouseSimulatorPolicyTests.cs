using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the TPM policy (enhanced authorization) command family against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production command
/// path the production code uses (the <see cref="TpmDeviceExtensions"/> policy commands over
/// <see cref="TpmCommandExecutor"/> and the real command/response codecs). Each test starts a trial or policy
/// session, issues policy assertions, reads the accumulated policyDigest back via <c>TPM2_PolicyGetDigest()</c>,
/// and asserts it equals the host prediction the shipped <see cref="TpmPolicyDigest"/> computes for the same
/// assertions (TPM 2.0 Library Part 1, clause 17.7).
/// </summary>
/// <remarks>
/// <para>
/// The simulator advances each session's policyDigest by calling the SAME <see cref="TpmPolicyDigest"/> methods the
/// host prediction uses, so the on-device digest and the host prediction cannot diverge by construction. These
/// tests therefore exercise the wire round-trip, the production command path, and assertion composition; the raw
/// spec formula is the independent-oracle role of <see cref="TpmPolicyDigest"/>'s own unit tests.
/// </para>
/// <para>
/// The <c>PolicySecret(TPM_RH_ENDORSEMENT)</c> case additionally asserts the accumulated digest equals the
/// well-known endorsement-key authorization policy constant, a fixed public value independent of this codebase.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyTests
{
    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task PolicyCommandCodeDrivesTheSessionPolicyDigestAsPredicted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
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

            //Require the simulator's accumulated policyDigest to equal the host prediction: a fresh session starts
            //at all zeros, and PolicyCommandCode extends it by H(zeros || TPM_CC_PolicyCommandCode || TPM_CC_Sign).
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
    public async Task StartPolicySessionRejectsUnsupportedSha1PolicyHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        //The enhanced-authorization digest fold does not compute SHA-1, so a SHA-1 policy session must be refused
        //at StartAuthSession with TPM_RC_HASH rather than created and left to fault on its first assertion.
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA1, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(startResult.IsSuccess, "A SHA-1 policy session must be rejected.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, startResult.ResponseCode);
    }

    [TestMethod]
    public async Task PolicySecretRejectsNonPermanentAuthHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            //An NV Index handle is not a permanent hierarchy; PolicySecret over it would fold the raw handle as a
            //Name and skip the entity's authValue, so the simulator rejects it with TPM_RC_HANDLE rather than
            //advancing the policyDigest as if the entity's secret had been proven.
            const uint NvIndexHandle = 0x01000001u;
            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                NvIndexHandle, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(secretResult.IsSuccess, "PolicySecret over a non-permanent handle must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, secretResult.ResponseCode);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicySecretNullTicketTagSatisfiesIsPolicySecret()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            //Regression pin: TpmtTkAuth.IsPolicySecret()/IsPolicySigned() must reference the shared,
            //correct TpmStConstants.TPM_ST_AUTH_SECRET/TPM_ST_AUTH_SIGNED values (0x8023/0x8025), not the
            //previously-wrong private consts (0x8003/0x8002 — 0x8002 is actually TPM_ST_SESSIONS). A ticket parsed
            //back off the production wire from a genuine PolicySecret response must satisfy IsPolicySecret();
            //this failed under the old, incorrect private consts.
            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret failed: '{secretResult.ResponseCode}'.");

            using(secretResult.Value)
            {
                Assert.IsTrue(secretResult.Value.PolicyTicket.IsPolicySecret(), "A PolicySecret-produced ticket must satisfy IsPolicySecret().");
                Assert.IsFalse(secretResult.Value.PolicyTicket.IsPolicySigned(), "A PolicySecret-produced ticket must not satisfy IsPolicySigned().");
            }
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies the non-immediate <c>TPM2_PolicySecret()</c> form's own nonceTPM check: a mismatched non-empty
    /// caller nonce is rejected with <c>TPM_RC_VALUE</c>, the code the rule itself names — TPM 2.0 Library
    /// Part 3, clause 23.2.2, printed page 189, rule 1: "nonceTPM - If this parameter is not the Empty Buffer,
    /// and it does not match policySession&#8594;nonceTPM, then the TPM shall return TPM_RC_VALUE."
    /// </summary>
    [TestMethod]
    public async Task PolicySecretNonImmediateWithMismatchedCallerNonceReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            byte[] wrongNonce = new byte[session.NonceTPM.Size];
            Array.Fill(wrongNonce, (byte)0xAB);
            Assert.IsFalse(wrongNonce.AsSpan().SequenceEqual(session.NonceTPM.AsReadOnlySpan()), "Test setup: the wrong nonce must actually differ.");

            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, wrongNonce, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, 0, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(secretResult.IsSuccess, "A mismatched non-empty caller nonce must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, secretResult.ResponseCode);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a positive <c>expiration</c> whose absolute (empty-nonce) deadline has already passed is
    /// rejected with <c>TPM_RC_EXPIRED</c> (TPM 2.0 Library Part 3, Section 23.2.2), mirroring
    /// <c>PolicySignedWithExpiredDeadlineReturnsExpired</c> for the shared timeout math.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretNonImmediateWithExpiredDeadlineReturnsExpired()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, clockAdvanceQuantumMs: 5000).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            //Empty caller nonce: an absolute Time-base deadline of |expiration|*1000 ms, already exceeded because
            //StartAuthSession alone already advanced Time by the 5000ms quantum.
            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, 1, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(secretResult.IsSuccess, "An already-expired deadline must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_EXPIRED, secretResult.ResponseCode);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a non-empty <c>cpHashA</c> whose size does not equal the session's digest width is rejected with
    /// <c>TPM_RC_SIZE</c> (TPM 2.0 Library Part 3, Section 23.2.2).
    /// </summary>
    [TestMethod]
    public async Task PolicySecretNonImmediateWithWrongSizedCpHashAReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            byte[] wrongSizedCpHash = new byte[16];
            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, ReadOnlyMemory<byte>.Empty, wrongSizedCpHash, ReadOnlyMemory<byte>.Empty, 0, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(secretResult.IsSuccess, "A cpHashA of the wrong size must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, secretResult.ResponseCode);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies the session's cpHash latch is first-writer-wins for PolicySecret too (TPM 2.0 Library Part 3,
    /// Section 23.2.4): a first call latches <c>cpHashA</c>, and a second call on the same session with a
    /// different (but correctly sized) <c>cpHashA</c> is rejected with <c>TPM_RC_CPHASH</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretCpHashLatchConflictReturnsCpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        byte[] firstCpHash = new byte[32];
        Array.Fill(firstCpHash, (byte)0x11);
        byte[] secondCpHash = new byte[32];
        Array.Fill(secondCpHash, (byte)0x22);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicySecretResponse> firstResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, ReadOnlyMemory<byte>.Empty, firstCpHash, ReadOnlyMemory<byte>.Empty, 0, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstResult.IsSuccess, $"PolicySecret (latching cpHashA) failed: '{firstResult.ResponseCode}'.");
            firstResult.Value.Dispose();

            TpmResult<PolicySecretResponse> secondResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, ReadOnlyMemory<byte>.Empty, secondCpHash, ReadOnlyMemory<byte>.Empty, 0, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(secondResult.IsSuccess, "A cpHashA conflicting with the session's latch must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, secondResult.ResponseCode);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>authHandle</c>'s authorization is genuinely checked, not parsed and discarded: a wrong
    /// (non-empty) hierarchy authValue is rejected with <c>TPM_RC_BAD_AUTH</c>, and correct (empty, the
    /// hierarchy's actual authValue) auth on the same session then succeeds and folds. The production device
    /// verb always attaches an empty-auth password session, so this drives the raw command directly (through
    /// the same production <see cref="TpmCommandExecutor"/> path) to supply a caller-chosen, wrong authValue.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithWrongHierarchyAuthValueIsRejectedThenCorrectAuthSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            byte[] wrongAuth = [0x01, 0x02, 0x03];
            using PolicySecretInput wrongInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_OWNER, sessionHandle, pool);
            using TpmPasswordSession wrongAuthSession = TpmPasswordSession.Create(wrongAuth, pool);

            TpmResult<PolicySecretResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                tpm, wrongInput, [wrongAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(wrongResult.IsSuccess, "A wrong (non-empty) hierarchy authValue must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.ResponseCode);

            using PolicySecretInput correctInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_OWNER, sessionHandle, pool);
            using TpmPasswordSession correctAuthSession = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<PolicySecretResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                tpm, correctInput, [correctAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(correctResult.IsSuccess, $"PolicySecret with the correct (empty) authValue failed: '{correctResult.ResponseCode}'.");
            correctResult.Value.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// TPM_RH_LOCKOUT is the one permanent handle PolicySecret's authorization check is dictionary-attack gated
    /// for (TPM 2.0 Library Part 1, clause 17.8's own carve-out — every OTHER permanent handle is DA-exempt):
    /// a wrong lockoutAuth over <c>PolicySecret(TPM_RH_LOCKOUT)</c> is an auth-failure (<c>TPM_RC_AUTH_FAIL</c>,
    /// not <c>TPM_RC_BAD_AUTH</c>) that disables <c>lockoutAuth</c> independently of FailedTries/MaxTries —
    /// observable both through a subsequent <c>PolicySecret(TPM_RH_LOCKOUT)</c> refusal and through the
    /// established <c>TPM2_DictionaryAttackLockReset()</c> observable the dictionary-attack tests use — refuses
    /// every use of lockoutAuth (even the correct one) while disabled, and the correct auth succeeds again once
    /// lockoutAuth has self-healed.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithLockoutHandleIsDictionaryAttackGated()
    {
        const ulong QuantumMs = 1000UL;
        const uint LockoutRecoverySeconds = 5u;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, QuantumMs).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret);

        TpmResult<DictionaryAttackParametersResponse> setResult = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, TpmSimulatorState.DefaultMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            LockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(setResult.IsSuccess, $"Setting lockoutRecovery failed: '{setResult.ResponseCode}'.");

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            //A wrong lockoutAuth over PolicySecret(TPM_RH_LOCKOUT) must be TPM_RC_AUTH_FAIL (not TPM_RC_BAD_AUTH,
            //the code every other permanent handle's wrong authValue gets) and must disable LockoutAuthEnabled.
            byte[] wrongAuth = [0x0A];
            using PolicySecretInput wrongInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_LOCKOUT, sessionHandle, pool);
            using TpmPasswordSession wrongAuthSession = TpmPasswordSession.Create(wrongAuth, pool);
            TpmResult<PolicySecretResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                tpm, wrongInput, [wrongAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(wrongResult.IsSuccess, "A wrong lockoutAuth use must be an auth-failure — lockoutAuth is dictionary-attack protected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, wrongResult.ResponseCode);

            //Refused while disabled, proven through the established DictionaryAttackLockReset observable: even
            //the CORRECT lockoutAuth is rejected with TPM_RC_LOCKOUT.
            TpmResult<DictionaryAttackLockResetResponse> tooSoonResult = await tpm.DictionaryAttackLockResetAsync(
                ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_LOCKOUT, tooSoonResult.ResponseCode,
                "Even the CORRECT lockoutAuth must be rejected while lockoutAuth is disabled.");

            //And PolicySecret(TPM_RH_LOCKOUT) itself, with the CORRECT (empty) auth, is refused the same way
            //while disabled — the gate is TPM_RC_LOCKOUT-before-compare, not merely a failed compare.
            using PolicySecretInput stillDisabledInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_LOCKOUT, sessionHandle, pool);
            using TpmPasswordSession stillDisabledAuthSession = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<PolicySecretResponse> stillDisabledResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                tpm, stillDisabledInput, [stillDisabledAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(stillDisabledResult.IsSuccess, "PolicySecret(TPM_RH_LOCKOUT) with the correct auth must still be refused while lockoutAuth is disabled.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, stillDisabledResult.ResponseCode);

            //The two refused probes above plus these three quantum-advancing commands reach the five-second
            //lockoutRecovery boundary on the third PolicyGetDigest, whose self-heal check re-enables
            //lockoutAuth; the healed probe below then runs against the already-re-armed state.
            for(int i = 0; i < 3; i++)
            {
                TpmResult<PolicyGetDigestResponse> healQuantumResult = await tpm.PolicyGetDigestAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(healQuantumResult.IsSuccess, $"PolicyGetDigest (heal quantum) failed: '{healQuantumResult.ResponseCode}'.");
                healQuantumResult.Value.Dispose();
            }

            //Correct auth while enabled succeeds and folds the digest, exactly like any other permanent hierarchy.
            using PolicySecretInput healedInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_LOCKOUT, sessionHandle, pool);
            using TpmPasswordSession healedAuthSession = TpmPasswordSession.CreateEmpty(pool);
            TpmResult<PolicySecretResponse> healedResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                tpm, healedInput, [healedAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(healedResult.IsSuccess, $"PolicySecret(TPM_RH_LOCKOUT) with the correct auth must succeed once lockoutAuth has self-healed: '{healedResult.ResponseCode}'.");
            healedResult.Value.Dispose();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// PolicySecret over <c>TPM_RH_LOCKOUT</c> mints a ticket whose <c>hierarchy</c> field is LOCKOUT's OWNING
    /// hierarchy — <c>TPM_RH_OWNER</c> (TPM 2.0 Library Part 1, clause 12.5's <c>EntityGetHierarchy</c> mapping:
    /// every permanent handle other than Platform/Endorsement/Null belongs to Owner) — never the raw
    /// <c>TPM_RH_LOCKOUT</c> handle itself: <c>TPMT_TK_AUTH.hierarchy</c> is typed <c>TPMI_RH_HIERARCHY+</c>
    /// (Part 2, Table 111), whose legal set excludes <c>TPM_RH_LOCKOUT</c>. The minted ticket then replays
    /// successfully through <c>TPM2_PolicyTicket()</c> on a fresh session, proving the mapped hierarchy is also
    /// what the HMAC was actually keyed on, not merely what got framed onto the wire.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithLockoutHandleMintsATicketWhoseHierarchyIsTheOwningOwnerHierarchy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        byte[] authName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, (uint)TpmRh.TPM_RH_LOCKOUT);

        uint mintSessionHandle = 0;
        byte[] timeoutBytes;
        byte[] ticketDigestBytes;
        TpmStConstants ticketTag;
        TpmiRhHierarchy ticketHierarchy;
        try
        {
            TpmResult<StartAuthSessionResponse> mintStart = await tpm.StartPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(mintStart.IsSuccess, $"StartAuthSession (mint) failed: '{mintStart.ResponseCode}'.");

            using StartAuthSessionResponse mintSession = mintStart.Value;
            mintSessionHandle = mintSession.SessionHandle.Value;

            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_LOCKOUT, mintSessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, -3600, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret(TPM_RH_LOCKOUT) failed: '{secretResult.ResponseCode}'.");

            using PolicySecretResponse minted = secretResult.Value;
            Assert.IsFalse(minted.PolicyTicket.IsNull, "A negative expiration must mint a real ticket.");
            Assert.AreEqual(
                TpmiRhHierarchy.Owner, minted.PolicyTicket.Hierarchy,
                "TPM_RH_LOCKOUT's minted ticket must carry its OWNING hierarchy (Owner), never the raw TPM_RH_LOCKOUT handle.");

            timeoutBytes = minted.Timeout.ToArray();
            ticketDigestBytes = minted.PolicyTicket.Digest.ToArray();
            ticketTag = minted.PolicyTicket.Tag;
            ticketHierarchy = minted.PolicyTicket.Hierarchy;
        }
        finally
        {
            _ = await tpm.FlushContextAsync(mintSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        uint replaySessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> replayStart = await tpm.StartPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(replayStart.IsSuccess, $"StartAuthSession (replay) failed: '{replayStart.ResponseCode}'.");

            using StartAuthSessionResponse replaySession = replayStart.Value;
            replaySessionHandle = replaySession.SessionHandle.Value;

            using TpmtTkAuth ticket = TpmtTkAuth.Create(ticketTag, ticketHierarchy, ticketDigestBytes, pool);
            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                replaySessionHandle, timeoutBytes, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, authName, ticket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(ticketResult.IsSuccess, $"Replaying the TPM_RH_LOCKOUT-minted ticket must succeed: '{ticketResult.ResponseCode}'.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(replaySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a negative <c>expiration</c> mints a genuine <c>TPM_ST_AUTH_SECRET</c> ticket: the tag, the
    /// authorizing hierarchy, a non-empty digest, and an 8-byte timeout (TPM 2.0 Library Part 3, Section
    /// 23.2.5), mirroring PolicySigned's own real-ticket assertions.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithNegativeExpirationMintsARealAuthSecretTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, -3600, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret (negative expiration) failed: '{secretResult.ResponseCode}'.");

            using PolicySecretResponse minted = secretResult.Value;
            Assert.IsFalse(minted.PolicyTicket.IsNull, "A negative expiration must mint a real ticket, not a NULL ticket.");
            Assert.AreEqual(TpmStConstants.TPM_ST_AUTH_SECRET, minted.PolicyTicket.Tag, "The ticket tag must be TPM_ST_AUTH_SECRET.");
            Assert.AreEqual(TpmiRhHierarchy.Endorsement, minted.PolicyTicket.Hierarchy, "The ticket hierarchy must be the authorizing entity's own hierarchy.");
            int ticketDigestLength = minted.PolicyTicket.Digest.Length;
            int timeoutLength = minted.Timeout.Length;
            Assert.AreEqual(32, ticketDigestLength, "The ticket digest is a SHA-256 HMAC.");
            Assert.AreEqual(8, timeoutLength, "A real ticket's TPM2B_TIMEOUT is exactly 8 bytes.");
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// R-9 capstone: <c>TPM_RH_NULL</c> is a permanent handle, so PolicySecret over it is accepted and mints a
    /// ticket bound to the Null hierarchy's proof. A NULL-hierarchy ticket minted before a TPM Reset must NOT
    /// verify after one when replayed through <c>TPM2_PolicyTicket()</c>: this simulator's own mechanism for
    /// that cross-Reset invalidation is <c>TimeEpoch</c> regeneration on every completed <c>TPM2_Startup()</c>
    /// (equation 12's conditional <c>[timeEpoch]</c> term, TPM 2.0 Library Part 2, Section 10.7.5, Table 111) —
    /// the simulator's realization of the same defense Part 2 Table 107 attributes to the Null hierarchy's own
    /// proof changing on every Reset (here the per-hierarchy proof itself is seed-derived and stable; TimeEpoch
    /// regeneration is what carries the defense instead). A non-zero expiration is required to observe this:
    /// the <c>[timeEpoch]</c> term is omitted entirely when the ticket's timeout is zero.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretNullHierarchyTicketBecomesInvalidAfterATpmResetWhenReplayedViaPolicyTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        byte[] authName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, (uint)TpmRh.TPM_RH_NULL);

        uint mintSessionHandle = 0;
        byte[] timeoutBytes;
        byte[] ticketDigestBytes;
        try
        {
            TpmResult<StartAuthSessionResponse> mintStart = await tpm.StartPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(mintStart.IsSuccess, $"StartAuthSession (mint) failed: '{mintStart.ResponseCode}'.");

            using StartAuthSessionResponse mintSession = mintStart.Value;
            mintSessionHandle = mintSession.SessionHandle.Value;

            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_NULL, mintSessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, -1, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret(TPM_RH_NULL) failed: '{secretResult.ResponseCode}'.");

            using PolicySecretResponse minted = secretResult.Value;
            Assert.IsFalse(minted.PolicyTicket.IsNull, "A negative expiration must mint a real ticket.");
            timeoutBytes = minted.Timeout.ToArray();
            ticketDigestBytes = minted.PolicyTicket.Digest.ToArray();
        }
        finally
        {
            _ = await tpm.FlushContextAsync(mintSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }

        //A genuine TPM Reset: TpmSimulatorLifecycleTests.SecondStartupReturnsInitialize confirms a bare second
        //Startup WITHOUT a power cycle is instead rejected with TPM_RC_INITIALIZE, so a real power cycle
        //(PowerOnAsync again, with no orderly Shutdown() in between, so LastOrderlyShutdown stays null and the
        //next Startup(CLEAR) takes the Reset arm, not Restart) is required to actually regenerate TimeEpoch.
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        uint replaySessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> replayStart = await tpm.StartPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(replayStart.IsSuccess, $"StartAuthSession (replay) failed: '{replayStart.ResponseCode}'.");

            using StartAuthSessionResponse replaySession = replayStart.Value;
            replaySessionHandle = replaySession.SessionHandle.Value;

            using TpmtTkAuth ticket = TpmtTkAuth.Create(TpmStConstants.TPM_ST_AUTH_SECRET, TpmiRhHierarchy.Null, ticketDigestBytes, pool);
            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                replaySessionHandle, timeoutBytes, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, authName, ticket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(ticketResult.IsSuccess, "A NULL-hierarchy ticket minted before a TPM Reset must not verify after it.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_TICKET, ticketResult.ResponseCode);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(replaySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicyOrRejectsBranchCountBelowTwo()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            //TPM2_PolicyOR requires two to eight branches (Part 3, clause 23.6); a single-branch pHashList is a
            //malformed command the simulator must reject with TPM_RC_SIZE rather than fold silently.
            var oneBranch = new ReadOnlyMemory<byte>[] { new byte[32] };
            TpmResult<PolicyOrResponse> orResult = await tpm.PolicyOrAsync(
                sessionHandle, oneBranch, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(orResult.IsSuccess, "PolicyOR with fewer than two branches must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, orResult.ResponseCode);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    [TestMethod]
    public async Task PolicyAuthValueThenPolicyCommandCodeComposeAsPredicted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;
        int[] pcrIndices = [0];

        //On a trial session the TPM uses the caller's pcrDigest verbatim, so the prediction does not depend on
        //live PCR contents — the test stays deterministic. Computed through the registered digest seam (not a
        //direct framework hash), matching this file's ComputeNvNameAsync convention.
        using DigestValue pcrDigestValue = await CryptographicKeyEvents.ComputeDigestAsync(
            "policy-pcr-test"u8.ToArray(), 32, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        byte[] pcrDigest = pcrDigestValue.AsReadOnlySpan().ToArray();

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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
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

                //That value is the well-known endorsement-key authorization policy.
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

    //The well-known endorsement-key authorization policy for SHA-256:
    //H(0x00...00(32) || TPM_CC_PolicySecret || TPM_RH_ENDORSEMENT) with an empty policyRef — a fixed public value
    //independent of this codebase (TPM 2.0 endorsement-key authorization).
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
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
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0012;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        int size = TpmPolicyDigest.Size(PolicyHash);
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
                byte[] nvName = await ComputeNvNameAsync(NvIndex, PolicyHash, attributes, DataSize, pool, TestContext.CancellationToken).ConfigureAwait(false);
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
    /// TPM2_PolicyNV folds the Index's REAL Name, which is computed over the whole retained public area
    /// including <c>authPolicy</c> (TPM 2.0 Library Part 1, Section 14, Table 6 over the marshaled
    /// TPMS_NV_PUBLIC of Part 2, Section 13.6). An Index defined WITH an access policy therefore folds a
    /// different Name than the otherwise identical Index defined without one: this test predicts with the real,
    /// policy-carrying Name and additionally proves the empty-policy Name gives a different digest, so a model
    /// that computed the Name from a fixed empty policy cannot satisfy it.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvFoldsTheIndexNameComputedOverItsRetainedAuthPolicy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0019;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        int size = TpmPolicyDigest.Size(PolicyHash);
        byte[] operandB = [0x10, 0x20, 0x30, 0x40];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

        //A correctly-sized (32-octet, matching the SHA-256 nameAlg) access policy digest.
        byte[] authPolicy =
        [
            0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
            0xB0, 0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 0xBE, 0xBF
        ];

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize, authPolicy).ConfigureAwait(false);
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

                //Both Names are computed BEFORE the prediction buffers, so no stack-allocated span spans an await.
                byte[] policyName = await ComputeNvNameAsync(
                    NvIndex, PolicyHash, attributes, DataSize, pool, TestContext.CancellationToken, authPolicy).ConfigureAwait(false);
                byte[] emptyPolicyName = await ComputeNvNameAsync(
                    NvIndex, PolicyHash, attributes, DataSize, pool, TestContext.CancellationToken).ConfigureAwait(false);

                byte[] predicted = new byte[size];
                byte[] predictedFromEmptyPolicy = new byte[size];
                Span<byte> zero = stackalloc byte[size];
                zero.Clear();
                TpmPolicyDigest.ExtendForNv(zero, operandB, Offset, (ushort)Operation, policyName, PolicyHash, predicted);
                TpmPolicyDigest.ExtendForNv(zero, operandB, Offset, (ushort)Operation, emptyPolicyName, PolicyHash, predictedFromEmptyPolicy);

                Assert.IsTrue(
                    digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                    "The policyDigest after PolicyNV must fold the Name computed over the Index's own retained authPolicy.");

                Assert.IsFalse(
                    digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predictedFromEmptyPolicy),
                    "A Name computed as though the Index carried no access policy must NOT satisfy the folded digest.");
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
    /// Verifies that a REAL (non-trial) TPM2_PolicyNV session compares the retained Index data at the offset and,
    /// on a true comparison, authorizes and folds the digest exactly as the host predicts — closing the tracked
    /// gap where the simulator's PolicyNV always succeeded regardless of the Index's actual contents.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvLiveComparisonAcceptsATrueOperandOnAWrittenIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0013;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        int size = TpmPolicyDigest.Size(PolicyHash);
        byte[] writtenData = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            await WriteNvAsync(tpm, registry, pool, NvIndex, writtenData).ConfigureAwait(false);
            TpmaNv writtenAttributes = attributes | TpmaNv.TPMA_NV_WRITTEN;

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (real) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                //operandB equals the written data at offset 0, so TPM_EO_EQ must hold against the live Index.
                TpmResult<PolicyNvResponse> nvResult = await tpm.PolicyNvAsync(
                    NvIndex, NvIndex, sessionHandle, writtenData, Offset, Operation, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(nvResult.IsSuccess, $"PolicyNV (true comparison) failed: '{nvResult.ResponseCode}'.");

                TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

                using PolicyGetDigestResponse digest = digestResult.Value;

                byte[] nvName = await ComputeNvNameAsync(NvIndex, PolicyHash, writtenAttributes, DataSize, pool, TestContext.CancellationToken).ConfigureAwait(false);
                byte[] predicted = new byte[size];
                Span<byte> zero = stackalloc byte[size];
                zero.Clear();
                TpmPolicyDigest.ExtendForNv(zero, writtenData, Offset, (ushort)Operation, nvName, PolicyHash, predicted);

                Assert.IsTrue(
                    digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                    "The simulator's policyDigest after a live, true PolicyNV comparison must match the host-computed value.");
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
    /// Verifies that a REAL (non-trial) TPM2_PolicyNV session rejects with TPM_RC_POLICY when the retained Index
    /// data does not satisfy the comparison, and leaves the session's policyDigest untouched.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvLiveComparisonRejectsAFalseOperand()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0014;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        byte[] writtenData = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        byte[] mismatchingOperand = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            await WriteNvAsync(tpm, registry, pool, NvIndex, writtenData).ConfigureAwait(false);

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (real) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                TpmResult<PolicyNvResponse> nvResult = await tpm.PolicyNvAsync(
                    NvIndex, NvIndex, sessionHandle, mismatchingOperand, Offset, TpmEoConstants.TPM_EO_EQ, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(nvResult.IsSuccess, "PolicyNV must reject a false comparison against the live Index data.");
                Assert.AreEqual(TpmRcConstants.TPM_RC_POLICY, nvResult.ResponseCode, "A false PolicyNV comparison must reject with TPM_RC_POLICY.");
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
    /// Exploit-becomes-regression test: an undefined <c>TPM_EO</c> value (0x0100, outside the 12 Table 22 defines)
    /// on a REAL policy session must reject with <c>TPM_RC_VALUE</c> through the production wire path, not throw
    /// an unhandled exception out of <c>TpmSimulator.SubmitAsync</c> (TPM 2.0 Library Part 3, clause 5.1: an
    /// undefined selector is rejected at unmarshal).
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWithAnUndefinedOperationReturnsValueOnARealSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0015;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants UndefinedOperation = (TpmEoConstants)0x0100;
        byte[] writtenData = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_NO_DA;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            await WriteNvAsync(tpm, registry, pool, NvIndex, writtenData).ConfigureAwait(false);

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                PolicyHash, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (real) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                TpmResult<PolicyNvResponse> nvResult = await tpm.PolicyNvAsync(
                    NvIndex, NvIndex, sessionHandle, writtenData, Offset, UndefinedOperation, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(nvResult.IsSuccess, "An undefined TPM_EO must be rejected, not silently accepted.");
                Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, nvResult.ResponseCode, "An undefined TPM_EO must reject with TPM_RC_VALUE at unmarshal.");
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
    /// Verifies a TRIAL session rejects the same undefined <c>TPM_EO</c> identically to a REAL session (the FIX
    /// 1 uniformity requirement): the parse-time check runs before the trial/real branch, so the trial session's
    /// "skip the comparison, fold unconditionally" path never gets a chance to silently accept it.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWithAnUndefinedOperationReturnsValueOnATrialSessionToo()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const TpmAlgIdConstants PolicyHash = TpmAlgIdConstants.TPM_ALG_SHA256;
        const uint NvIndex = 0x0100_0016;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants UndefinedOperation = (TpmEoConstants)0x0100;
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
                    NvIndex, NvIndex, sessionHandle, operandB, Offset, UndefinedOperation, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(nvResult.IsSuccess, "A trial session must reject an undefined TPM_EO too, not silently fold it.");
                Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, nvResult.ResponseCode, "A trial session's undefined TPM_EO must also reject with TPM_RC_VALUE at unmarshal.");
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
    /// Verifies <c>TPM2_PolicyNV()</c>'s Index-authorization arm genuinely checks the supplied authValue against
    /// the Index's own retained value rather than parsing and discarding it (TPM 2.0 Library Part 3, clause
    /// 23.9's authHandle authorization; Part 1, clause 17.6.4.1): a correct password against a dictionary-attack
    /// protected, <c>AUTHWRITE|AUTHREAD</c> Index authorizes and folds the digest exactly as the predicted-digest
    /// tests above show; a wrong password is the NV family's own bare (never session-index encoded)
    /// <c>TPM_RC_AUTH_FAIL</c> (clause 17.8.7's charge rule) and charges the shared lockout counter by exactly
    /// one, observed through <c>TPM2_GetCapability</c>'s <c>TPM_PT_LOCKOUT_COUNTER</c> via
    /// <see cref="TpmDictionaryAttackExtensions.GetDictionaryAttackParametersAsync"/>.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvVerifiesTheIndexAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const uint NvIndex = 0x0100_0020;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        byte[] operandB = [0x10, 0x20, 0x30, 0x40];
        byte[] indexAuth = [0x0A, 0x0B, 0x0C, 0x0D];
        byte[] wrongIndexAuth = [0x99, 0x99, 0x99, 0x99];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyNV, TpmResponseCodec.PolicyNv);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(
            tpm, registry, pool, NvIndex, attributes, DataSize, authPolicy: default, indexAuth: indexAuth).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            //Correct index password, on its own trial session: only the Index's Name is needed, not its data, so
            //the Index can stay unwritten.
            TpmResult<StartAuthSessionResponse> correctStart = await tpm.StartTrialPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(correctStart.IsSuccess, $"StartAuthSession (correct) failed: '{correctStart.ResponseCode}'.");

            using StartAuthSessionResponse correctSession = correctStart.Value;
            uint correctSessionHandle = correctSession.SessionHandle.Value;
            try
            {
                using TpmPasswordSession correctAuthSession = TpmPasswordSession.Create(indexAuth, pool);
                var correctInput = new PolicyNvInput(NvIndex, NvIndex, correctSessionHandle, operandB, Offset, Operation);

                TpmResult<PolicyNvResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                    tpm, correctInput, [correctAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(correctResult.IsSuccess, $"PolicyNV with the correct index authValue must succeed: '{correctResult.ResponseCode}'.");
            }
            finally
            {
                _ = await tpm.FlushContextAsync(correctSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }

            TpmResult<TpmDictionaryAttackParameters> afterCorrect = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(before.Value.LockoutCounter, afterCorrect.Value.LockoutCounter, "A correctly-authorized PolicyNV must move no counter.");

            //Wrong index password, on a fresh trial session.
            TpmResult<StartAuthSessionResponse> wrongStart = await tpm.StartTrialPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(wrongStart.IsSuccess, $"StartAuthSession (wrong) failed: '{wrongStart.ResponseCode}'.");

            using StartAuthSessionResponse wrongSession = wrongStart.Value;
            uint wrongSessionHandle = wrongSession.SessionHandle.Value;
            try
            {
                using TpmPasswordSession wrongAuthSession = TpmPasswordSession.Create(wrongIndexAuth, pool);
                var wrongInput = new PolicyNvInput(NvIndex, NvIndex, wrongSessionHandle, operandB, Offset, Operation);

                TpmResult<PolicyNvResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                    tpm, wrongInput, [wrongAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTH_FAIL, wrongResult.ResponseCode,
                    "A wrong index authValue against a dictionary-attack protected Index must be a bare TPM_RC_AUTH_FAIL.");
            }
            finally
            {
                _ = await tpm.FlushContextAsync(wrongSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }

            TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                afterCorrect.Value.LockoutCounter + 1, afterWrong.Value.LockoutCounter,
                "A wrong index authValue against a dictionary-attack protected Index must charge the lockout counter exactly once.");
        }
        finally
        {
            _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies <c>TPM2_PolicyNV()</c>'s owner-authorized arm (<c>authHandle == TPM_RH_OWNER</c>, TPM 2.0 Library
    /// Part 3, clause 23.9's <c>authHandle</c> role mirroring <c>TPM2_NV_Read()</c>'s own owner arm) genuinely
    /// checks the supplied value against the owner hierarchy's own authValue: a wrong owner authValue is the
    /// bare (never session-index encoded) <c>TPM_RC_BAD_AUTH</c> permanent-entity authorization always answers
    /// (Part 1, clause 17.8.1 - owner authorization is dictionary-attack exempt, so the shared lockout counter
    /// moves not at all), and the correct, freshly-rotated owner authValue then authorizes on the very same
    /// session.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWithOwnerAuthorizationVerifiesTheOwnerAuthValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const uint NvIndex = 0x0100_0021;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        byte[] operandB = [0x10, 0x20, 0x30, 0x40];
        byte[] ownerAuth = [0x11, 0x22, 0x33, 0x44];
        byte[] wrongOwnerAuth = [0x55, 0x66, 0x77, 0x88];
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_NO_DA;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyNV, TpmResponseCodec.PolicyNv);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            TpmResult<HierarchyChangeAuthResponse> rotateResult = await tpm.ChangeHierarchyAuthWithPasswordAsync(
                TpmRh.TPM_RH_OWNER, ReadOnlyMemory<byte>.Empty, ownerAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(rotateResult.IsSuccess, $"HierarchyChangeAuth (owner) failed: '{rotateResult.ResponseCode}'.");

            TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                using TpmPasswordSession wrongOwnerSession = TpmPasswordSession.Create(wrongOwnerAuth, pool);
                var wrongInput = new PolicyNvInput((uint)TpmRh.TPM_RH_OWNER, NvIndex, sessionHandle, operandB, Offset, Operation);

                TpmResult<PolicyNvResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                    tpm, wrongInput, [wrongOwnerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.ResponseCode,
                    "A wrong owner authValue over PolicyNV's owner arm must be a bare TPM_RC_BAD_AUTH.");

                TpmResult<TpmDictionaryAttackParameters> afterWrong = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    before.Value.LockoutCounter, afterWrong.Value.LockoutCounter,
                    "Owner authorization is dictionary-attack exempt; a wrong owner authValue must move no counter.");

                using TpmPasswordSession correctOwnerSession = TpmPasswordSession.Create(ownerAuth, pool);
                var correctInput = new PolicyNvInput((uint)TpmRh.TPM_RH_OWNER, NvIndex, sessionHandle, operandB, Offset, Operation);

                TpmResult<PolicyNvResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                    tpm, correctInput, [correctOwnerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(correctResult.IsSuccess, $"PolicyNV with the correct owner authValue must succeed: '{correctResult.ResponseCode}'.");
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
    /// Verifies the owner arm's <c>TPMA_NV_OWNERREAD</c> availability gate runs BEFORE the owner authValue is even
    /// compared (TPM 2.0 Library Part 3, clause 23.9, mirroring <c>TPM2_NV_Read()</c>'s identical owner-arm gate):
    /// with the attribute clear, even the (default, correct) empty owner authValue is refused with
    /// <c>TPM_RC_NV_AUTHORIZATION</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWithoutOwnerReadIsRefused()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const uint NvIndex = 0x0100_0022;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        byte[] operandB = [0x10, 0x20, 0x30, 0x40];

        //Deliberately WITHOUT TPMA_NV_OWNERREAD: the owner arm's own compare must never even run.
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_AUTHREAD;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyNV, TpmResponseCodec.PolicyNv);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(tpm, registry, pool, NvIndex, attributes, DataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                using TpmPasswordSession ownerAuthSession = TpmPasswordSession.CreateEmpty(pool);
                var input = new PolicyNvInput((uint)TpmRh.TPM_RH_OWNER, NvIndex, sessionHandle, operandB, Offset, Operation);

                TpmResult<PolicyNvResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                    tpm, input, [ownerAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode,
                    "TPMA_NV_OWNERREAD clear must refuse the owner arm before the owner authValue is even compared.");
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
    /// Verifies the Index arm's <c>TPMA_NV_AUTHREAD</c> availability gate (TPM 2.0 Library Part 3, clause 5.6,
    /// check 7.2.2; Part 2, clause 13.4) refuses the assertion BEFORE the authValue compare: with the attribute
    /// clear the Index's own authValue can never authorize a read, so a correct password and a wrong password
    /// are refused with the identical <c>TPM_RC_AUTH_UNAVAILABLE</c>, and neither attempt moves the
    /// dictionary-attack counter of this DA-protected Index — the gate reveals nothing about the supplied value
    /// and charges nothing for it.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvWithAuthReadClearIsRefusedBeforeTheCompare()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const uint NvIndex = 0x0100_0024;
        const ushort Offset = 0;
        const ushort DataSize = 8;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        byte[] operandB = [0x10, 0x20, 0x30, 0x40];
        byte[] indexAuth = [0x0A, 0x0B, 0x0C, 0x0D];
        byte[] wrongIndexAuth = [0x99, 0x98, 0x97];

        //AUTHWRITE set (so the real authValue below is a valid definition) but AUTHREAD deliberately clear;
        //NO_DA left clear too, so the Index is DA-protected and an uncharged refusal is observable.
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHWRITE;

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyNV, TpmResponseCodec.PolicyNv);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(
            tpm, registry, pool, NvIndex, attributes, DataSize, authPolicy: default, indexAuth: indexAuth).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            uint sessionHandle = session.SessionHandle.Value;
            try
            {
                TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);

                using TpmPasswordSession correctAuthSession = TpmPasswordSession.Create(indexAuth, pool);
                var correctInput = new PolicyNvInput(NvIndex, NvIndex, sessionHandle, operandB, Offset, Operation);
                TpmResult<PolicyNvResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                    tpm, correctInput, [correctAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, correctResult.ResponseCode,
                    "TPMA_NV_AUTHREAD clear must refuse the assertion before the compare, even for a correct index authValue.");

                using TpmPasswordSession wrongAuthSession = TpmPasswordSession.Create(wrongIndexAuth, pool);
                var wrongInput = new PolicyNvInput(NvIndex, NvIndex, sessionHandle, operandB, Offset, Operation);
                TpmResult<PolicyNvResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                    tpm, wrongInput, [wrongAuthSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, wrongResult.ResponseCode,
                    "A wrong index authValue against an AUTHREAD-clear Index is refused identically, before the compare.");

                TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(pool, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    before.Value.LockoutCounter, after.Value.LockoutCounter,
                    "The pre-compare availability refusal must never charge the dictionary-attack counter (TPM 2.0 Library Part 3, clause 5.6, check 7.2.2).");
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
    /// Verifies a wrong password authorizing <c>TPM2_PolicyNV()</c> against a <c>TPM_NT_PIN_FAIL</c> Index
    /// applies the same localized pinCount outcome a wrong <c>TPM2_NV_Read()</c> would (TPM 2.0 Library Part 1,
    /// clause 37.2.6.6): with <c>pinLimit</c> set to one, a single wrong PolicyNV attempt drives
    /// <c>pinCount</c> to <c>pinLimit</c>, so a SUBSEQUENT attempt with the CORRECT PIN is refused with
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> before any comparison — the same throttle-exhaustion observable the
    /// NV_Read PIN Fail tests assert, reached here through PolicyNV instead of NV_Read. A PIN Fail Index is
    /// spec-mandated <c>TPMA_NV_NO_DA</c> (Part 2, clause 13.4), so the wrong attempt itself is the bare,
    /// NO_DA-exempt <c>TPM_RC_BAD_AUTH</c>, never <c>TPM_RC_AUTH_FAIL</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvAgainstAPinIndexAppliesThePinOutcome()
    {
        const uint PinLimit = 1;
        const ushort PinCounterParametersSize = 8;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        const uint NvIndex = 0x0100_0023;
        const ushort Offset = 0;
        const TpmEoConstants Operation = TpmEoConstants.TPM_EO_EQ;
        byte[] operandB = [0x10, 0x20, 0x30, 0x40];
        byte[] correctPin = [0x01, 0x02, 0x03, 0x04];
        byte[] wrongPin = [0x09, 0x09, 0x09, 0x09];

        //A PIN Fail Index: TPMA_NV_NO_DA is spec-mandated, TPMA_NV_AUTHWRITE is spec-forbidden, and
        //TPMA_NV_OWNERWRITE is the sole provisioning arm (TPM 2.0 Library Part 1, clause 37.2.6.1).
        TpmaNv attributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA
            | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyNV, TpmResponseCodec.PolicyNv);

        _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineNvAsync(
            tpm, registry, pool, NvIndex, attributes, PinCounterParametersSize, authPolicy: default, indexAuth: correctPin).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace (PIN Fail Index) failed: '{defineResult.ResponseCode}'.");
        try
        {
            //A PIN Index forbids its own authValue from authorizing writes, so pinCount/pinLimit are seeded
            //through the owner-authorized write arm (TPM 2.0 Library Part 1, clause 37.2.6.1).
            using(TpmPasswordSession ownerWriteAuth = TpmPasswordSession.CreateEmpty(pool))
            {
                using IMemoryOwner<byte> blobOwner = pool.Rent(PinCounterParametersSize);
                Memory<byte> blob = blobOwner.Memory[..PinCounterParametersSize];
                BinaryPrimitives.WriteUInt32BigEndian(blob.Span, 0u);
                BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], PinLimit);
                using Tpm2bMaxNvBuffer seedInputBuffer = Tpm2bMaxNvBuffer.Create(blob.Span, pool);
                var seedInput = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, NvIndex, seedInputBuffer, Offset: 0);

                TpmResult<NvWriteResponse> seedResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                    tpm, seedInput, [ownerWriteAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(seedResult.IsSuccess, $"Seeding pinCount/pinLimit failed: '{seedResult.ResponseCode}'.");
            }

            TpmResult<StartAuthSessionResponse> wrongStart = await tpm.StartTrialPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(wrongStart.IsSuccess, $"StartAuthSession (wrong) failed: '{wrongStart.ResponseCode}'.");

            using StartAuthSessionResponse wrongSession = wrongStart.Value;
            uint wrongSessionHandle = wrongSession.SessionHandle.Value;
            try
            {
                using TpmPasswordSession wrongPinSession = TpmPasswordSession.Create(wrongPin, pool);
                var wrongInput = new PolicyNvInput(NvIndex, NvIndex, wrongSessionHandle, operandB, Offset, Operation);

                TpmResult<PolicyNvResponse> wrongResult = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                    tpm, wrongInput, [wrongPinSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_BAD_AUTH, wrongResult.ResponseCode,
                    "A wrong PIN against a PIN Fail Index (TPMA_NV_NO_DA) must be a plain bad-authorization, never TPM_RC_AUTH_FAIL.");
            }
            finally
            {
                _ = await tpm.FlushContextAsync(wrongSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }

            //The single wrong PolicyNV attempt above must have advanced pinCount to pinLimit exactly as a wrong
            //TPM2_NV_Read() would, so even the CORRECT PIN is now refused before any comparison.
            TpmResult<StartAuthSessionResponse> correctStart = await tpm.StartTrialPolicySessionAsync(
                TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(correctStart.IsSuccess, $"StartAuthSession (correct) failed: '{correctStart.ResponseCode}'.");

            using StartAuthSessionResponse correctSession = correctStart.Value;
            uint correctSessionHandle = correctSession.SessionHandle.Value;
            try
            {
                using TpmPasswordSession correctPinSession = TpmPasswordSession.Create(correctPin, pool);
                var correctInput = new PolicyNvInput(NvIndex, NvIndex, correctSessionHandle, operandB, Offset, Operation);

                TpmResult<PolicyNvResponse> correctResult = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                    tpm, correctInput, [correctPinSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, correctResult.ResponseCode,
                    "Once the single wrong attempt has driven pinCount to pinLimit, even the CORRECT PIN must be refused.");
            }
            finally
            {
                _ = await tpm.FlushContextAsync(correctSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await UndefineNvAsync(tpm, registry, pool, NvIndex).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Writes <paramref name="data"/> in full to <paramref name="nvIndex"/>, authorized by the Index's own (empty)
    /// auth value, setting TPMA_NV_WRITTEN.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="data">The data to write.</param>
    private async Task WriteNvAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, byte[] data)
    {
        using TpmPasswordSession writeAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(data, pool);
        var writeInput = new NvWriteInput(nvIndex, nvIndex, writeInputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");
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
    /// <param name="authPolicy">The access policy digest to define with; empty (the default) for no policy.</param>
    /// <param name="indexAuth">The Index's own authorization value; empty (the default) for no authValue.</param>
    /// <returns>The NV_DefineSpace result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineNvAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, TpmaNv attributes, ushort dataSize,
        ReadOnlyMemory<byte> authPolicy = default, ReadOnlyMemory<byte> indexAuth = default)
    {
        using Tpm2bAuth definedAuth = indexAuth.IsEmpty ? Tpm2bAuth.CreateEmpty(pool) : Tpm2bAuth.Create(indexAuth.Span, pool);
        using var authPolicyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, authPolicyDigest, dataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, definedAuth, publicInfo);
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
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Computes an NV Index Name (<c>nameAlg || H(TPMS_NV_PUBLIC)</c>) from its public-area fields, through the
    /// registered digest seam (not a direct framework hash).
    /// </summary>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="nameAlg">The Name hash algorithm (SHA-256).</param>
    /// <param name="attributes">The Index attributes, exactly as stored (include TPMA_NV_WRITTEN once written).</param>
    /// <param name="dataSize">The data area size.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <param name="authPolicy">The access policy digest the Index was defined with; empty (the default) for no policy.</param>
    /// <returns>The Name bytes.</returns>
    private static async Task<byte[]> ComputeNvNameAsync(
        uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ushort dataSize, BaseMemoryPool pool, CancellationToken cancellationToken, ReadOnlyMemory<byte> authPolicy = default)
    {
        using var authPolicyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using var nvPublic = new TpmsNvPublic(nvIndex, nameAlg, attributes, authPolicyDigest, dataSize);
        int publicSize = nvPublic.SerializedSize;
        using IMemoryOwner<byte> owner = pool.Rent(publicSize);
        Span<byte> publicArea = owner.Memory.Span[..publicSize];
        var writer = new TpmWriter(publicArea);
        nvPublic.WriteTo(ref writer);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            owner.Memory[..publicSize], 32, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + 32];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.AsReadOnlySpan().CopyTo(name.AsSpan(sizeof(ushort)));

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

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase. The policy commands themselves need no signing
    /// backend, but the backend is wired for parity with the other in-house simulator tests.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="clockAdvanceQuantumMs">The fixed per-command clock advance, in milliseconds.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, ulong clockAdvanceQuantumMs = TpmSimulatorState.DefaultClockAdvanceQuantumMs)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-policy", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), clockAdvanceQuantumMs: clockAdvanceQuantumMs);
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
    private async Task BringOperationalAsync(TpmSimulator simulator, BaseMemoryPool pool)
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
