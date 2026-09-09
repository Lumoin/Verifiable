using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicySecret()</c>'s HMAC-session authorization arm (TPM 2.0 Library Part 3, clause 23.4.1:
/// "A password session, an HMAC session, or a policy session ... will satisfy this requirement") against the
/// in-house behavioural <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the
/// same production command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="PolicySecretInput"/>/<see cref="StartAuthSessionInput"/>/<see cref="TpmSession"/>, and the
/// secure-by-default <c>PolicySecretAsync</c>/<c>PolicySecretWithPasswordAsync</c> verbs).
/// </summary>
/// <remarks>
/// <para>
/// Covered here: the cpHash Name2 known-answer test (TPM 2.0 Library Part 1, clause 15.7 equation
/// 15; Table 9), lockout-over-HMAC (Part 1, clause 16.8.5), nonceTPM rolling and its replay consequence (Part 1,
/// clause 16.6.3.1), and the secure-by-default verb pair. The policy-session authorization arm (equations 26/27,
/// Part 1, clause 16.6.12) and <c>TPM_RC_MODE</c> (Part 3, clause 23.4.1) live in the sibling
/// <c>TpmInHouseSimulatorPolicySessionHmacTests</c>.
/// </para>
/// <para>
/// Every accepted-path test proves the session key/HMAC the simulator derived agrees with an independent
/// transcription or with what a genuine <see cref="TpmSession"/> both sent and verified; every negative test is
/// proven non-vacuous against a same-shaped positive.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSecureChannelTests
{
    /// <summary>The session/policy hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width, in octets, of <see cref="SessionAlg"/>.</summary>
    private const int DigestSize = 32;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task PolicySecretOverBoundHmacSessionAgainstEndorsementYieldsTheWellKnownPolicy()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<StartAuthSessionResponse> policyStart = await tpm.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStart.IsSuccess, $"StartAuthSession (policy) failed: '{policyStart.ResponseCode}'.");
        using StartAuthSessionResponse policySession = policyStart.Value;
        uint policySessionHandle = policySession.SessionHandle.Value;

        uint hmacSessionHandle = 0;
        try
        {
            (hmacSessionHandle, TpmSession authorizer, _, _) = await StartBoundHmacSessionAsync(
                tpm, registry, pool, (uint)TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
            using(authorizer)
            {
                try
                {
                    using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, policySessionHandle, pool);
                    TpmResult<PolicySecretResponse> secretResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                        tpm, input, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret over a bound HMAC session against the endorsement hierarchy failed: '{secretResult.ResponseCode}'.");
                    secretResult.Value.Dispose();
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, registry, hmacSessionHandle).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");
            using(digestResult.Value)
            {
                Assert.IsTrue(
                    MatchesEndorsementSecretPolicy(digestResult.Value.PolicyDigest.AsReadOnlySpan()),
                    "PolicySecret(endorsement) authorized over a bound HMAC session must yield the well-known EK authorization policy, exactly as the password arm does.");
            }

            _ = await tpm.FlushContextAsync(policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// PolicySecret's cpHash Name2 term is the <em>policySession parameter's</em> raw handle, never the
    /// authorizing HMAC session's own handle, even when the two differ (TPM 2.0 Library Part 1, clause 15.7
    /// equation 15; Table 9). Starts a policy session A (the parameter being extended) and a DISTINCT HMAC
    /// session B (the authorizer bound to <c>TPM_RH_ENDORSEMENT</c>), captures the wire command B actually sent,
    /// and independently recomputes the authHMAC twice: once with Name2 = A (the correct, accepted value) and
    /// once with Name2 = B (an easily-transposed wrong value) — the two must diverge, and the supplied HMAC must
    /// equal only the correct one.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretCpHashUsesThePolicySessionParameterHandleNotTheAuthorizingSessionHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[]? capturedCommand = null;
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            capturedCommand = command.ToArray();
            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<StartAuthSessionResponse> policyStart = await plainDevice.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStart.IsSuccess, $"StartAuthSession (policy A) failed: '{policyStart.ResponseCode}'.");
        using StartAuthSessionResponse policySessionA = policyStart.Value;
        uint policySessionHandleA = policySessionA.SessionHandle.Value;

        uint hmacSessionHandleB = 0;
        byte[] initialNonceCallerB = [];
        byte[] initialNonceTpmB = [];
        try
        {
            TpmSession authorizerB;
            (hmacSessionHandleB, authorizerB, initialNonceCallerB, initialNonceTpmB) =
                await StartBoundHmacSessionAsync(plainDevice, registry, pool, (uint)TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
            Assert.AreNotEqual(policySessionHandleA, hmacSessionHandleB, "Test setup: A and B must be genuinely distinct handles for the transposition to be observable.");

            using(authorizerB)
            {
                try
                {
                    using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, policySessionHandleA, pool);
                    TpmResult<PolicySecretResponse> secretResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                        capturingDevice, input, [authorizerB], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret with authHandle != policySession's authorizing session failed: '{secretResult.ResponseCode}'.");
                    secretResult.Value.Dispose();
                }
                finally
                {
                    await FlushIfPresentAsync(plainDevice, registry, hmacSessionHandleB).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(plainDevice, registry, policySessionHandleA).ConfigureAwait(false);
        }

        Assert.IsNotNull(capturedCommand, "The capturing wrapper must have observed the outgoing PolicySecret command.");
        ParsePolicySecretOverSessionCommand(
            capturedCommand!, out ReadOnlyMemory<byte> nonceCaller, out byte sessionAttributes,
            out ReadOnlyMemory<byte> suppliedHmac, out ReadOnlyMemory<byte> rawParameterArea);

        BaseMemoryPool oraclePool = BaseMemoryPool.Shared;
        using IMemoryOwner<byte> derivedSessionKey = await Kdfa.DeriveAsync(
            HashAlgorithmName.SHA256, ReadOnlyMemory<byte>.Empty, "ATH", initialNonceTpmB, initialNonceCallerB, DigestSize * 8, oraclePool, TestContext.CancellationToken).ConfigureAwait(false);
        ReadOnlyMemory<byte> sessionKey = derivedSessionKey.Memory[..DigestSize];

        using IMemoryOwner<byte> correctHmac = await ComputePolicySecretAuthHmacAsync(
            sessionKey, policySessionHandleA, nonceCaller, initialNonceTpmB, sessionAttributes, rawParameterArea, oraclePool, TestContext.CancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> transposedHmac = await ComputePolicySecretAuthHmacAsync(
            sessionKey, hmacSessionHandleB, nonceCaller, initialNonceTpmB, sessionAttributes, rawParameterArea, oraclePool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(
            correctHmac.Memory.Span[..DigestSize].SequenceEqual(transposedHmac.Memory.Span[..DigestSize]),
            "Test setup: Name2 = policySession and Name2 = authorizing session must produce genuinely different cpHash/HMAC values, or the transposition is not observable.");
        Assert.IsTrue(
            correctHmac.Memory.Span[..DigestSize].SequenceEqual(suppliedHmac.Span),
            "The accepted command HMAC must equal the transcription using Name2 = the policySession PARAMETER's handle.");
        Assert.IsFalse(
            transposedHmac.Memory.Span[..DigestSize].SequenceEqual(suppliedHmac.Span),
            "The accepted command HMAC must NOT equal the transcription using Name2 = the authorizing session's own handle (the transposition bug).");
    }

    [TestMethod]
    public async Task TamperedPolicySecretOverHmacSessionIsRejectedWithSessionEncodedBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<StartAuthSessionResponse> policyStart = await tpm.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStart.IsSuccess, $"StartAuthSession (policy) failed: '{policyStart.ResponseCode}'.");
        using StartAuthSessionResponse policySession = policyStart.Value;
        uint policySessionHandle = policySession.SessionHandle.Value;

        uint hmacSessionHandle = 0;
        try
        {
            (hmacSessionHandle, TpmSession authorizer, _, _) = await StartBoundHmacSessionAsync(
                tpm, registry, pool, (uint)TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
            using(authorizer)
            {
                try
                {
                    byte[]? lastCommand = null;
                    async ValueTask<TpmResult<TpmResponse>> TamperLastHmacByteAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
                    {
                        byte[] mutable = command.ToArray();
                        lastCommand = mutable;

                        //PolicySecret's trailing parameter octets (nonceTPM/cpHashA/policyRef/expiration) are all
                        //empty/zero in the immediate form, so the command's very last byte is deterministically the
                        //final octet of the session's hmac field.
                        mutable[^1] ^= 0xFF;

                        return await simulator.SubmitAsync(mutable, commandPool, ct).ConfigureAwait(false);
                    }

                    using TpmDevice tamperingDevice = TpmDevice.Create(TamperLastHmacByteAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
                    using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, policySessionHandle, pool);

                    TpmResult<PolicySecretResponse> secretResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                        tamperingDevice, input, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(secretResult.IsSuccess, "A tampered command HMAC must be rejected.");
                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), secretResult.ResponseCode,
                        "The endorsement hierarchy is never dictionary-attack protected, so a tampered HMAC must reject with the session-index-encoded TPM_RC_BAD_AUTH (no DA counter involved).");
                    Assert.IsNotNull(lastCommand, "The tampering wrapper must have observed the outgoing command.");
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, registry, hmacSessionHandle).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, policySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A session-HMAC mismatch authorizing <c>TPM_RH_LOCKOUT</c> is a one-strike disable of
    /// <see cref="TpmDictionaryAttackParameters"/>'s lockout-auth availability (TPM 2.0 Library Part 1, clause
    /// 16.8.5) — never a <see cref="TpmDictionaryAttackParameters.LockoutCounter"/> increment (that counter is
    /// the ordinary DA-protected-entity path, which lockoutAuth itself is exempt from). While disabled, EVERY
    /// further attempt — even with a correct HMAC — is refused with <c>TPM_RC_LOCKOUT</c> before any HMAC work;
    /// once <c>lockoutRecovery</c> seconds of simulated Time have elapsed, the very next command self-heals and,
    /// if it carries a correct HMAC, succeeds.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretHmacMismatchAgainstLockoutDisablesThenRefusesThenSelfHeals()
    {
        const ulong ClockAdvanceQuantumMs = 600UL;
        const uint LockoutRecoverySeconds = 1u;

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, ClockAdvanceQuantumMs).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowered = await tpm.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, TpmSimulatorState.DefaultMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            LockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowered.IsSuccess, $"Lowering lockoutRecovery failed: '{lowered.ResponseCode}'.");

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(before.IsSuccess);

        TpmResult<StartAuthSessionResponse> policyStart = await tpm.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStart.IsSuccess, $"StartAuthSession (policy) failed: '{policyStart.ResponseCode}'.");
        using StartAuthSessionResponse policySession = policyStart.Value;
        uint policySessionHandle = policySession.SessionHandle.Value;

        uint wrongHandle = 0;
        uint correctHandle = 0;
        try
        {
            //A genuinely wrong bind authValue: the sim derives its own session key from the REAL lockoutAuth
            //(empty by default), so this session's independently-derived key diverges — a real HMAC mismatch,
            //not a byte-tampered one.
            TpmSession wrongAuthorizer;
            TpmSession correctAuthorizer;
            (wrongHandle, wrongAuthorizer, _, _) = await StartBoundHmacSessionAsync(
                tpm, registry, pool, (uint)TpmRh.TPM_RH_LOCKOUT, bindAuthValueOverride: new byte[] { 0x01, 0x02, 0x03, 0x04 }).ConfigureAwait(false);
            (correctHandle, correctAuthorizer, _, _) = await StartBoundHmacSessionAsync(
                tpm, registry, pool, (uint)TpmRh.TPM_RH_LOCKOUT).ConfigureAwait(false);

            using(wrongAuthorizer)
            using(correctAuthorizer)
            {
                //Every command dispatched through the simulator (including the two GetCapability round trips
                //GetDictionaryAttackParametersAsync itself issues) advances simulated Time by one quantum, so the
                //"LockoutCounter never moved" check is deferred to the very end — right after this exact command
                //would perturb the quantum arithmetic the two timed probes below depend on.
                using(PolicySecretInput mismatchInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_LOCKOUT, policySessionHandle, pool))
                {
                    TpmResult<PolicySecretResponse> mismatchResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                        tpm, mismatchInput, [wrongAuthorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), mismatchResult.ResponseCode,
                        "A session-HMAC mismatch authorizing TPM_RH_LOCKOUT must answer the session-encoded TPM_RC_AUTH_FAIL.");
                }

                //Probe #1: elapsed since the failure is one quantum (600ms) < lockoutRecovery (1000ms) — still
                //disabled, refused BEFORE any HMAC work (even the CORRECT session is turned away).
                using(PolicySecretInput refusedInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_LOCKOUT, policySessionHandle, pool))
                {
                    TpmResult<PolicySecretResponse> refusedResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                        tpm, refusedInput, [correctAuthorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.AreEqual(
                        TpmRcConstants.TPM_RC_LOCKOUT, refusedResult.ResponseCode,
                        "While lockoutAuth is disabled, even a CORRECT session-authorized PolicySecret over TPM_RH_LOCKOUT must be refused before any HMAC is evaluated.");
                }

                //Probe #2: elapsed is now two quanta (1200ms) >= lockoutRecovery (1000ms) — the self-heal fires
                //before this command's own check, and the correct HMAC now authorizes.
                using(PolicySecretInput healedInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_LOCKOUT, policySessionHandle, pool))
                {
                    TpmResult<PolicySecretResponse> healedResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                        tpm, healedInput, [correctAuthorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(
                        healedResult.IsSuccess, $"Once lockoutRecovery seconds have elapsed, lockoutAuth must self-heal and a correct HMAC must succeed: '{healedResult.ResponseCode}'.");
                    healedResult.Value.Dispose();
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, wrongHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, correctHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, policySessionHandle).ConfigureAwait(false);
        }

        //Deferred to the very end (see the note above the mismatch command): the mismatch is the one-strike
        //Lockout disable, never the ordinary DA counter — LockoutCounter must be exactly what it was before any
        //of this test's commands ran, across the mismatch AND both successful/refused probes.
        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(after.IsSuccess);
        Assert.AreEqual(
            before.Value.LockoutCounter, after.Value.LockoutCounter,
            "A lockoutAuth-over-HMAC mismatch is the one-strike Lockout disable, never the ordinary DA counter.");
    }

    /// <summary>
    /// Sessions roll nonceTPM on each authorized use. A second genuine PolicySecret call over the same
    /// session succeeds (proving the session's own bookkeeping tracks the roll), while replaying the FIRST call's
    /// exact wire bytes directly against the simulator — after the second call has already advanced the session
    /// past it — fails, because the replay's HMAC was computed against a nonceTPM the session no longer holds.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretOverHmacSessionRollsNonceSoAReplayedFirstCommandIsRejectedAfterASecondSuccess()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<StartAuthSessionResponse> policyStart = await tpm.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStart.IsSuccess, $"StartAuthSession (policy) failed: '{policyStart.ResponseCode}'.");
        using StartAuthSessionResponse policySession = policyStart.Value;
        uint policySessionHandle = policySession.SessionHandle.Value;

        uint hmacSessionHandle = 0;
        try
        {
            byte[]? firstCommand = null;
            async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
            {
                firstCommand ??= command.ToArray();
                return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
            }

            using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

            //StartAuthSession runs over the PLAIN device: capturingDevice must observe ONLY the two PolicySecret
            //calls that follow, or "??=" would freeze firstCommand on the StartAuthSession bytes instead.
            (hmacSessionHandle, TpmSession authorizer, _, _) = await StartBoundHmacSessionAsync(
                tpm, registry, pool, (uint)TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);
            using(authorizer)
            {
                try
                {
                    using(PolicySecretInput firstInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, policySessionHandle, pool))
                    {
                        TpmResult<PolicySecretResponse> firstResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                            capturingDevice, firstInput, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                        Assert.IsTrue(firstResult.IsSuccess, $"The first (genuine) PolicySecret call must succeed: '{firstResult.ResponseCode}'.");
                        firstResult.Value.Dispose();
                    }

                    Assert.IsNotNull(firstCommand, "The capturing wrapper must have observed the first command.");

                    using(PolicySecretInput secondInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, policySessionHandle, pool))
                    {
                        TpmResult<PolicySecretResponse> secondResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                            capturingDevice, secondInput, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                        Assert.IsTrue(secondResult.IsSuccess, $"A second genuine PolicySecret call over the same, still-valid session must succeed (its own rolled nonceTPM is tracked automatically): '{secondResult.ResponseCode}'.");
                        secondResult.Value.Dispose();
                    }

                    //Resend the FIRST call's exact wire bytes directly against the simulator: the session's stored
                    //nonceTPM has since rolled twice (once per genuine call), so the replay's HMAC no longer
                    //matches.
                    TpmResult<TpmResponse> replayResult = await simulator.SubmitAsync(firstCommand!, pool, TestContext.CancellationToken).ConfigureAwait(false);
                    using(TpmResponse replayResponse = replayResult.Value)
                    {
                        var reader = new TpmReader(replayResponse.AsReadOnlySpan());
                        TpmHeader replayHeader = TpmHeader.Parse(ref reader);
                        var replayRc = (TpmRcConstants)replayHeader.Code;

                        Assert.AreEqual(
                            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), replayRc,
                            $"Replaying the first command's exact bytes after the session advanced twice must be rejected (got '{replayRc}').");
                    }
                }
                finally
                {
                    await FlushIfPresentAsync(tpm, registry, hmacSessionHandle).ConfigureAwait(false);
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, policySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>PolicySecretAsync</c> composes a bound, unsalted HMAC session against <c>authHandle</c>
    /// internally and drives the well-known EK PolicyA flow over it end to end, over the real production wire
    /// path (<see cref="TpmDevice"/> + <see cref="TpmCommandExecutor"/>): the captured wire command's
    /// authorization-area sessionHandle is never <c>TPM_RH_PW</c>, proving the secure default genuinely rides a
    /// session, not a password.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretAsyncDrivesTheEndorsementPolicyAFlowOverTheBoundChannelEndToEnd()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        var capturedCommands = new System.Collections.Generic.List<(TpmCcConstants Code, byte[] Bytes)>();
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            byte[] bytes = command.ToArray();
            capturedCommands.Add((ReadCommandCode(bytes), bytes));

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<StartAuthSessionResponse> policyStart = await capturingDevice.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStart.IsSuccess, $"StartAuthSession (policy) failed: '{policyStart.ResponseCode}'.");
        using StartAuthSessionResponse policySession = policyStart.Value;
        uint policySessionHandle = policySession.SessionHandle.Value;
        capturedCommands.Clear();

        try
        {
            TpmResult<PolicySecretResponse> secretResult = await capturingDevice.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecretAsync (secure default) failed: '{secretResult.ResponseCode}'.");
            secretResult.Value.Dispose();

            int policySecretCount = 0;
            foreach((TpmCcConstants code, byte[] bytes) in capturedCommands)
            {
                if(code == TpmCcConstants.TPM_CC_PolicySecret)
                {
                    policySecretCount++;
                    uint sessionHandle = ReadPolicySecretAuthorizingSessionHandle(bytes);
                    Assert.AreNotEqual(
                        (uint)TpmRh.TPM_RH_PW, sessionHandle,
                        "PolicySecretAsync's secure default must never send a TPM_RS_PW password session.");
                }
            }

            Assert.AreEqual(1, policySecretCount, "Exactly one PolicySecret command must have been sent.");
            Assert.IsTrue(
                capturedCommands.Exists(c => c.Code == TpmCcConstants.TPM_CC_StartAuthSession),
                "The composed HMAC session must have been started.");
            Assert.IsTrue(
                capturedCommands.Exists(c => c.Code == TpmCcConstants.TPM_CC_FlushContext),
                "The composed HMAC session must have been flushed after use.");
        }
        finally
        {
            using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

            TpmResult<PolicyGetDigestResponse> digestResult = await plainDevice.PolicyGetDigestAsync(
                policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");
            using(digestResult.Value)
            {
                Assert.IsTrue(
                    MatchesEndorsementSecretPolicy(digestResult.Value.PolicyDigest.AsReadOnlySpan()),
                    "PolicySecretAsync must still yield the well-known EK authorization policy over its secure default channel.");
            }

            _ = await plainDevice.FlushContextAsync(policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The explicit low-protection opt-out still authorizes correctly, and — unlike the secure default —
    /// genuinely sends a <c>TPM_RS_PW</c> password session (proving the two verbs are not accidentally identical
    /// on the wire).
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithPasswordAsyncStillWorksAsTheExplicitOptOut()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[]? capturedPolicySecretCommand = null;
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == TpmCcConstants.TPM_CC_PolicySecret)
            {
                capturedPolicySecretCommand = bytes;
            }

            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        TpmResult<StartAuthSessionResponse> policyStart = await capturingDevice.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(policyStart.IsSuccess, $"StartAuthSession (policy) failed: '{policyStart.ResponseCode}'.");
        using StartAuthSessionResponse policySession = policyStart.Value;
        uint policySessionHandle = policySession.SessionHandle.Value;

        try
        {
            TpmResult<PolicySecretResponse> secretResult = await capturingDevice.PolicySecretWithPasswordAsync(
                (uint)TpmRh.TPM_RH_ENDORSEMENT, policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecretWithPasswordAsync failed: '{secretResult.ResponseCode}'.");
            secretResult.Value.Dispose();

            Assert.IsNotNull(capturedPolicySecretCommand, "The capturing wrapper must have observed the PolicySecret command.");
            uint sessionHandle = ReadPolicySecretAuthorizingSessionHandle(capturedPolicySecretCommand!);
            Assert.AreEqual(
                (uint)TpmRh.TPM_RH_PW, sessionHandle,
                "The explicit low-protection opt-out must send a genuine TPM_RS_PW password session.");
        }
        finally
        {
            _ = await capturingDevice.FlushContextAsync(policySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — the test-side mirror of the production helper, transcribed independently since
    /// it is private.
    /// </summary>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>Reads a TPM command's header <c>code</c> field, leaving every other field unexamined.</summary>
    private static TpmCcConstants ReadCommandCode(byte[] command)
    {
        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmCcConstants)header.Code;
    }

    /// <summary>
    /// Reads a captured <c>TPM2_PolicySecret()</c> wire command's authorization area <c>sessionHandle</c> field
    /// (handle area: authHandle, policySession; then authorizationSize; then sessionHandle) — firewalled to the
    /// wire, no back-channel into simulator or session internals.
    /// </summary>
    private static uint ReadPolicySecretAuthorizingSessionHandle(byte[] command)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32(); //authHandle.
        _ = reader.ReadUInt32(); //policySession.
        _ = reader.ReadUInt32(); //authorizationSize.

        return reader.ReadUInt32(); //sessionHandle.
    }

    /// <summary>
    /// Parses a captured <c>TPM2_PolicySecret()</c>-over-session wire command back into its authorizing session's
    /// fields and the raw <c>nonceTPM ‖ cpHashA ‖ policyRef ‖ expiration</c> parameter bytes, firewalled to the
    /// wire (no back-channel into simulator or session internals). Mirrors TPMS_AUTH_COMMAND's own generic
    /// session-body shape (sessionHandle, nonceCaller, sessionAttributes, hmac; TPM 2.0 Library Part 2, clause
    /// 10.12.2, Table 156).
    /// </summary>
    private static void ParsePolicySecretOverSessionCommand(
        byte[] command, out ReadOnlyMemory<byte> nonceCaller, out byte sessionAttributes, out ReadOnlyMemory<byte> hmac, out ReadOnlyMemory<byte> rawParameterArea)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        _ = reader.ReadUInt32(); //authHandle.
        _ = reader.ReadUInt32(); //policySession.
        _ = reader.ReadUInt32(); //authorizationSize.
        _ = reader.ReadUInt32(); //sessionHandle (the authorizer).

        ushort nonceSize = reader.ReadUInt16();
        nonceCaller = reader.ReadBytes(nonceSize).ToArray();
        sessionAttributes = reader.ReadByte();

        ushort hmacSize = reader.ReadUInt16();
        hmac = reader.ReadBytes(hmacSize).ToArray();

        rawParameterArea = reader.ReadBytes(reader.Remaining).ToArray();
    }

    /// <summary>
    /// Independently recomputes PolicySecret's command authHMAC (TPM 2.0 Library Part 1, clause 15.7 equation 15;
    /// clause 16.6.5 equation 17): <c>cpHash = H(TPM_CC_PolicySecret ‖ Name(authHandle) ‖ Name2 ‖ parameters)</c>,
    /// then <c>authHMAC = HMAC(sessionKey, cpHash ‖ nonceCaller ‖ nonceTPM ‖ sessionAttributes)</c> — no authValue
    /// term (the session is bound directly to <c>TPM_RH_ENDORSEMENT</c>, so equation 22 (Part 1, clause 16.6.10)'s bind-omission applies)
    /// and no folded nonces (a single session in the authorization area, clause 16.6.3.4).
    /// </summary>
    private static async ValueTask<IMemoryOwner<byte>> ComputePolicySecretAuthHmacAsync(
        ReadOnlyMemory<byte> sessionKey, uint name2Handle, ReadOnlyMemory<byte> nonceCaller, ReadOnlyMemory<byte> nonceTpm,
        byte sessionAttributes, ReadOnlyMemory<byte> rawParameterArea, BaseMemoryPool pool, System.Threading.CancellationToken cancellationToken)
    {
        int cpHashInputLength = sizeof(uint) + sizeof(uint) + sizeof(uint) + rawParameterArea.Length;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        {
            var writer = new TpmWriter(cpHashInputOwner.Memory.Span[..cpHashInputLength]);
            writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_PolicySecret);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_ENDORSEMENT);
            writer.WriteUInt32(name2Handle);
            writer.WriteBytes(rawParameterArea.Span);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInputOwner.Memory[..cpHashInputLength], outputByteLength: DigestSize, tag: DigestTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        int hmacInputLength = cpHash.AsReadOnlySpan().Length + nonceCaller.Length + nonceTpm.Length + 1;
        using IMemoryOwner<byte> hmacInputOwner = pool.Rent(hmacInputLength);
        {
            var writer = new TpmWriter(hmacInputOwner.Memory.Span[..hmacInputLength]);
            writer.WriteBytes(cpHash.AsReadOnlySpan());
            writer.WriteBytes(nonceCaller.Span);
            writer.WriteBytes(nonceTpm.Span);
            writer.WriteByte(sessionAttributes);
        }

        using HmacValue expectedHmac = await CryptographicKeyEvents.ComputeHmacAsync(
            hmacInputOwner.Memory[..hmacInputLength], sessionKey, outputByteLength: DigestSize, tag: HmacTag(), pool: pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        IMemoryOwner<byte> owner = pool.Rent(DigestSize);
        try
        {
            expectedHmac.AsReadOnlySpan().CopyTo(owner.Memory.Span[..DigestSize]);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Builds the digest <see cref="Tag"/> exactly as <c>TpmCommandExecutor.BuildDigestTag</c> does: SHA-256
    /// digest, raw encoding, direct material.
    /// </summary>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>
    /// Builds the HMAC <see cref="Tag"/> exactly as <c>TpmSession.ComputeSessionHmacAsync</c> does: SHA-256 HMAC,
    /// raw encoding, direct material.
    /// </summary>
    private static Tag HmacTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Hmac).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

    /// <summary>
    /// Predicts the policyDigest of a fresh policy session after <c>PolicySecret(TPM_RH_ENDORSEMENT)</c> via the
    /// project's own <see cref="TpmPolicyDigest"/> (the single source of truth this simulator's own fold uses)
    /// and compares it to <paramref name="actualDigest"/>.
    /// </summary>
    private static bool MatchesEndorsementSecretPolicy(ReadOnlySpan<byte> actualDigest)
    {
        Span<byte> current = stackalloc byte[DigestSize];
        current.Clear();

        Span<byte> endorsementName = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(endorsementName, (uint)TpmRh.TPM_RH_ENDORSEMENT);

        Span<byte> predicted = stackalloc byte[DigestSize];
        TpmPolicyDigest.ExtendForSecret(current, endorsementName, ReadOnlySpan<byte>.Empty, SessionAlg, predicted, BaseMemoryPool.Shared);

        return actualDigest.SequenceEqual(predicted);
    }

    /// <summary>
    /// Starts a bound, unsalted HMAC session against <paramref name="bindHandle"/> through the production
    /// <c>TPM2_StartAuthSession()</c> path and wraps it as a <see cref="TpmSession"/>. Also returns copies of the
    /// two start nonces (captured before nonceTPM's ownership transfers into the session) for tests that need an
    /// independent oracle.
    /// </summary>
    /// <param name="bindAuthValueOverride">
    /// When supplied, the value the returned <see cref="TpmSession"/> derives its key from instead of the entity's
    /// real (resolved server-side) authorization value — used to construct a genuine, non-tampered command-HMAC
    /// mismatch for the negative tests.
    /// </param>
    private async Task<(uint SessionHandle, TpmSession Session, byte[] InitialNonceCaller, byte[] InitialNonceTpm)> StartBoundHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint bindHandle, ReadOnlyMemory<byte> bindAuthValueOverride = default)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(bindHandle, SessionAlg, TestEntropy.NewCounterStream(), pool);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound to 0x{bindHandle:X8}) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        byte[] initialNonceCaller = startInput.NonceCaller.ToArray();
        byte[] initialNonceTpm = startResponse.NonceTPM.AsReadOnlySpan().ToArray();

        TpmSession session = await TpmSession.CreateBoundAsync(
            new TpmHandle(startResponse.SessionHandle.Value), bindAuthValueOverride, startInput.NonceCaller,
            startResponse.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return (startResponse.SessionHandle.Value, session, initialNonceCaller, initialNonceTpm);
    }

    /// <summary>Flushes a transient session handle when one is present (non-zero), ignoring the result.</summary>
    private async Task FlushIfPresentAsync(TpmDevice tpm, TpmResponseRegistry registry, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        var flush = FlushContextInput.ForHandle(handle);
        _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flush, [], null, BaseMemoryPool.Shared, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a response codec registry covering the raw command paths these tests drive directly.</summary>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, ulong clockAdvanceQuantumMs = TpmSimulatorState.DefaultClockAdvanceQuantumMs)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-secure-channel", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), clockAdvanceQuantumMs: clockAdvanceQuantumMs, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire.
    /// </summary>
    private async Task IssueStartupClearAsync(TpmSimulator simulator, BaseMemoryPool pool)
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
    }
}
