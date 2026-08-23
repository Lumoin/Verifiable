using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicySecret()</c>'s POLICY-session authorization arm — equations 26/27 (TPM 2.0 Library Part
/// 1, clause 17.6.12) and the PolicySecret-scoped <c>TPM_RC_MODE</c> gate (Part 3, Section 23.4.1) — plus the
/// salted/bound POLICY session factories (Part 3, Section 11.1.1) against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the same production
/// command path the production code uses (<see cref="TpmCommandExecutor"/> with the real
/// <see cref="PolicySecretInput"/>/<see cref="StartAuthSessionInput"/>/<see cref="TpmSession"/>).
/// </summary>
/// <remarks>
/// <para>
/// Every POLICY session here authorizes <c>PolicySecret</c>'s own <c>authHandle</c> AND is itself the
/// <c>policySession</c> parameter being extended (self-referential — <c>ContinuePolicySecretOverSession</c>'s own
/// documented case for "a nested policy session that authorizes its OWN PolicySecret assertion"), keeping setup to
/// one session per test; the Name2-transposition risk (authorizer handle vs. policySession parameter handle) is
/// covered independently in the sibling <c>TpmInHouseSimulatorSecureChannelTests</c>, which uses two distinct
/// sessions specifically to make the transposition observable.
/// </para>
/// <para>
/// <b>A hierarchy must be given a policy before a POLICY session can authorize it at all.</b> "When the
/// authPolicy is empty, it cannot match any policyDigest value so the use of authPolicy is disabled" (TPM 2.0
/// Library Part 1, clause 11.2, Table 5), so every test here first installs one through
/// <c>TPM2_SetPrimaryPolicy</c> (Part 3, Section 24.3) — otherwise the authorizer is refused with
/// <c>TPM_RC_AUTH_UNAVAILABLE</c> before any of the mechanics below is reached. The digest installed is the one
/// the test's own session will accumulate: the <c>TPM2_PolicyAuthValue</c> fold for the tests that run it, and
/// the Zero Digest for the one that deliberately does not — a 32-octet value a fresh session already carries,
/// which is a legitimate policy and a different thing from the Empty Buffer that disables the path.
/// </para>
/// <para>
/// <b>eq. 26 vs. eq. 27.</b> Equation 26's key is <c>sessionKey ‖ authValue</c>; equation 27's is
/// <c>sessionKey</c> alone, and <c>isAuthValueNeeded</c> decides between them (Part 1, clause 17.6.12).
/// Equation 27 is unreachable for <c>PolicySecret</c> specifically: <c>TPM_RC_MODE</c> categorically refuses an
/// isAuthValueNeeded-CLEAR policy-session authorizer before any HMAC is ever evaluated (see
/// <see cref="PolicySecretOverPolicySessionWithoutPolicyAuthValueReturnsMode"/>), and no other command in this
/// codebase accepts a POLICY session as an authorizer. Equation 26 itself is exercised over a genuinely
/// non-empty authValue by
/// <see cref="Equation26FoldsANonEmptyHierarchyAuthorizationValueIntoThePolicySessionAuthHmac"/>, which rotates
/// the hierarchy's own value first, so the <c>sessionKey ‖ authValue</c> composition is proven by divergence
/// rather than by inspection;
/// <see cref="IndependentlyTranscribedEquation26AuthHmacMatchesWhatTheSimulatorAccepted"/> pins the same
/// equation byte-for-byte against an independent transcription over an unbound, unsalted session whose
/// <c>PolicySessionState.SessionKey</c> is itself the Empty Buffer (clause 17.6.9 — no bind entity, no salt, no
/// KDFa run at all). The salted E2E tests
/// (<see cref="SaltedUnboundPolicySessionAuthorizesPolicySecretRsa"/>,
/// <see cref="SaltedUnboundPolicySessionAuthorizesPolicySecretEcc"/>) are where a genuine, non-empty
/// KDFa-derived session key is exercised.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicySessionHmacTests
{
    /// <summary>The session/policy hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The digest width, in octets, of <see cref="SessionAlg"/>.</summary>
    private const int DigestSize = 32;

    /// <summary>Every RSA/ECC storage-parent-shaped template this simulator builds fixes nameAlg to SHA-256.</summary>
    private const TpmAlgIdConstants TpmKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA public exponent the framework RSA key generator uses (Table 215's "0" default).</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Part 3, Section 23.4.1 verbatim: "If a policy session is used and use of the authValue of authHandle is
    /// not required, the TPM will return TPM_RC_MODE." A fresh POLICY session's isAuthValueNeeded/isPasswordNeeded
    /// both default CLEAR (Part 1, clause 17.7.8), so authorizing PolicySecret with one before running
    /// <c>TPM2_PolicyAuthValue()</c> must be refused — before any HMAC is ever evaluated.
    /// </summary>
    /// <remarks>
    /// The policy installed on the endorsement hierarchy is the Zero Digest, which is exactly what a fresh
    /// session's policyDigest already is (Part 1, clause 17.7.1), so the session satisfies the hierarchy's policy
    /// and the refusal can only be the isAuthValueNeeded gate. Installing the <c>TPM2_PolicyAuthValue</c> digest
    /// instead would pre-empt it with <c>TPM_RC_POLICY_FAIL</c>, and installing nothing at all would pre-empt it
    /// with <c>TPM_RC_AUTH_UNAVAILABLE</c> — each a different rung of the same ladder.
    /// </remarks>
    [TestMethod]
    public async Task PolicySecretOverPolicySessionWithoutPolicyAuthValueReturnsMode()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await InstallEndorsementPolicyAsync(tpm, ZeroDigest()).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            (sessionHandle, TpmSession authorizer, _, _) = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(authorizer)
            {
                using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, pool);
                TpmResult<PolicySecretResponse> secretResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, input, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(secretResult.IsSuccess, "A POLICY session that never ran PolicyAuthValue must not authorize PolicySecret.");
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_MODE, secretResult.ResponseCode,
                    "isAuthValueNeeded and isPasswordNeeded both CLEAR on the authorizing POLICY session must answer TPM_RC_MODE (Part 3, Section 23.4.1), not a session-encoded auth failure.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The positive counterpart: once <c>TPM2_PolicyAuthValue()</c> SETs isAuthValueNeeded (Part 1, clause
    /// 17.7.7.6), the SAME session authorizing the SAME command now succeeds via equation 26 (TPM 2.0 Library Part
    /// 1, clause 17.6.12) — proving the flag
    /// genuinely gates <c>TPM_RC_MODE</c> rather than the command being unconditionally refused for a POLICY
    /// authorizer.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretOverPolicySessionAfterPolicyAuthValueAuthorizesViaEquation26()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await InstallEndorsementPolicyAsync(tpm, ComputePolicyAuthValueDigest()).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            (sessionHandle, TpmSession authorizer, _, _) = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(authorizer)
            {
                TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

                using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, pool);
                TpmResult<PolicySecretResponse> secretResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, input, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    secretResult.IsSuccess, $"A POLICY session with isAuthValueNeeded SET must authorize PolicySecret via equation 26: '{secretResult.ResponseCode}'.");
                secretResult.Value.Dispose();
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Equation 26 over a genuinely non-empty authorization value, which is where its key composition becomes
    /// observable rather than merely stated: <c>authHMAC = HMAC(sessionKey ‖ authValue, …)</c> (TPM 2.0 Library
    /// Part 1, clause 17.6.12). <c>TPM2_HierarchyChangeAuth</c> gives the endorsement hierarchy a real
    /// authorization value first (Part 3, Section 24.8.1), so the two candidate keys differ; the session that
    /// folds that value into its own key authorizes, and an otherwise identical session that folds nothing is
    /// refused with a session-encoded <c>TPM_RC_BAD_AUTH</c> - the endorsement hierarchy is a
    /// dictionary-attack-exempt permanent entity (Part 1, clause 17.8.1), so its mismatch moves no counter. An
    /// implementation that keyed a policy-session authorizer on the session key alone would accept both.
    /// </summary>
    [TestMethod]
    public async Task Equation26FoldsANonEmptyHierarchyAuthorizationValueIntoThePolicySessionAuthHmac()
    {
        byte[] endorsementAuth = [0x2A, 0x3B, 0x4C, 0x5D, 0x6E];

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The policy is installed while the hierarchy's authorization value is still empty, so this setup command
        //authorizes with the Empty Buffer; the rotation that follows is what the assertions below turn on.
        await InstallEndorsementPolicyAsync(tpm, ComputePolicyAuthValueDigest()).ConfigureAwait(false);

        TpmResult<HierarchyChangeAuthResponse> rotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, endorsementAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotation.IsSuccess, $"Giving the endorsement hierarchy a real authorization value failed: '{rotation.ResponseCode}'.");

        uint keyedHandle = 0;
        uint unkeyedHandle = 0;
        try
        {
            (keyedHandle, TpmSession keyedAuthorizer, _, _) = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(keyedAuthorizer)
            {
                TpmResult<PolicyAuthValueResponse> keyedFold = await tpm.PolicyAuthValueAsync(
                    keyedHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(keyedFold.IsSuccess, $"PolicyAuthValue failed: '{keyedFold.ResponseCode}'.");

                keyedAuthorizer.SetAuthValue(endorsementAuth, pool);

                using PolicySecretInput keyedInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, keyedHandle, pool);
                TpmResult<PolicySecretResponse> keyedResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, keyedInput, [keyedAuthorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    keyedResult.IsSuccess,
                    $"A session whose HMAC key folds the hierarchy's real authorization value must authorize: '{keyedResult.ResponseCode}'.");
                keyedResult.Value.Dispose();
            }

            (unkeyedHandle, TpmSession unkeyedAuthorizer, _, _) = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(unkeyedAuthorizer)
            {
                TpmResult<PolicyAuthValueResponse> unkeyedFold = await tpm.PolicyAuthValueAsync(
                    unkeyedHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(unkeyedFold.IsSuccess, $"PolicyAuthValue failed: '{unkeyedFold.ResponseCode}'.");

                using PolicySecretInput unkeyedInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, unkeyedHandle, pool);
                TpmResult<PolicySecretResponse> unkeyedResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, unkeyedInput, [unkeyedAuthorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(unkeyedResult.IsSuccess, "A session that folds no authValue must not authorize an entity whose authValue is non-empty.");
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_BAD_AUTH, unkeyedResult.BaseError,
                    "The endorsement hierarchy is dictionary-attack exempt, so its authorization mismatch is TPM_RC_BAD_AUTH rather than TPM_RC_AUTH_FAIL.");
                Assert.AreNotEqual(
                    TpmRcConstants.TPM_RC_BAD_AUTH, unkeyedResult.ResponseCode,
                    "The refusal names the offending session, so the raw wire code carries the session-index modifier.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, unkeyedHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, keyedHandle).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// The equation 26 (TPM 2.0 Library Part 1, clause 17.6.12) authValue term enters the session HMAC key with
    /// trailing zero octets removed (TPM 2.0
    /// Library Part 1, clause 17.6.4.3: "Trailing octets of zero are to be removed from any string before it is
    /// used as an authValue"; clause 17.6.5's Note applies the same rule to the HMAC computation). The hierarchy
    /// is rotated to a value ENDING in zero octets and the authorizing session receives that same zero-tailed
    /// form: the host session strips before keying, so the authorization succeeds only if the simulator strips
    /// its stored term identically — a simulator folding the raw stored bytes diverges and refuses.
    /// </summary>
    [TestMethod]
    public async Task Equation26StripsTrailingZeroOctetsFromTheHierarchyAuthorizationValue()
    {
        byte[] zeroTailedAuth = [0x2A, 0x3B, 0x4C, 0x00, 0x00];

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await InstallEndorsementPolicyAsync(tpm, ComputePolicyAuthValueDigest()).ConfigureAwait(false);

        TpmResult<HierarchyChangeAuthResponse> rotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, ReadOnlyMemory<byte>.Empty, zeroTailedAuth, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(rotation.IsSuccess, $"Rotating the endorsement hierarchy to a zero-tailed value failed: '{rotation.ResponseCode}'.");

        uint sessionHandle = 0;
        try
        {
            (sessionHandle, TpmSession authorizer, _, _) = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(authorizer)
            {
                TpmResult<PolicyAuthValueResponse> fold = await tpm.PolicyAuthValueAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(fold.IsSuccess, $"PolicyAuthValue failed: '{fold.ResponseCode}'.");

                authorizer.SetAuthValue(zeroTailedAuth, pool);

                using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, pool);
                TpmResult<PolicySecretResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, input, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(
                    result.IsSuccess,
                    $"Both sides must key equation 26 on the STRIPPED authorization value; a divergence refuses here: '{(result.IsTpmError ? result.ResponseCode : default)}'.");
                result.Value.Dispose();
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }

        //The password arm accepts the same secret in its zero-padded shape: both compare operands strip
        //(Part 1, clause 17.6.4.3), so whichever form the caller retained — padded or already stripped —
        //authorizes the next rotation.
        TpmResult<HierarchyChangeAuthResponse> paddedRotation = await tpm.ChangeHierarchyAuthWithPasswordAsync(
            TpmRh.TPM_RH_ENDORSEMENT, zeroTailedAuth, ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(
            paddedRotation.IsSuccess,
            $"Supplying the zero-padded form of the installed secret through the password arm must authorize: '{(paddedRotation.IsTpmError ? paddedRotation.ResponseCode : default)}'.");
    }

    /// <summary>
    /// A PolicySecret that fails AFTER its authorizer's command HMAC has already verified (here: a caller-supplied
    /// nonceTPM that does not match the target session's retained nonce, TPM 2.0 Library Part 3, Section 23.2.2)
    /// must leave the authorizing session's isAuthValueNeeded SET — the flag may only be CLEARed by successful use
    /// (Part 3, Section 23.2.4), never by a command that goes on to fail one of the parameter checks. Proven by a
    /// subsequent, otherwise-identical use of the SAME authorizer succeeding.
    /// </summary>
    [TestMethod]
    public async Task FailedPolicySecretAfterHmacVerificationLeavesAuthorizerFlagsSet()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await InstallEndorsementPolicyAsync(tpm, ComputePolicyAuthValueDigest()).ConfigureAwait(false);

        uint authorizerHandle = 0;
        uint targetHandle = 0;
        try
        {
            (authorizerHandle, TpmSession authorizer, _, _) = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(authorizer)
            {
                TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(
                    authorizerHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

                (targetHandle, TpmSession target, _, byte[] targetInitialNonceTpm) = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
                using(target)
                {
                    byte[] wrongNonceTpm = (byte[])targetInitialNonceTpm.Clone();
                    wrongNonceTpm[^1] ^= 0xFF;

                    using(PolicySecretInput badInput = PolicySecretInput.Create(
                        (uint)TpmRh.TPM_RH_ENDORSEMENT, targetHandle, wrongNonceTpm, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, 0, pool))
                    {
                        TpmResult<PolicySecretResponse> badResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                            tpm, badInput, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                        Assert.IsFalse(badResult.IsSuccess, "A caller-supplied nonceTPM that does not match the target session's retained nonce must fail.");
                        Assert.AreEqual(
                            TpmRcConstants.TPM_RC_VALUE, badResult.ResponseCode,
                            "The authorizer's command HMAC verifies first; the mismatch surfaces only at the later nonceTPM check, which answers TPM_RC_VALUE (Part 3, clause 23.2.2, printed page 189, rule 1).");
                    }

                    using PolicySecretInput goodInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, targetHandle, pool);
                    TpmResult<PolicySecretResponse> goodResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                        tpm, goodInput, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(
                        goodResult.IsSuccess,
                        $"The SAME authorizer must still succeed afterward — the earlier nonceTPM rejection must not have cleared its isAuthValueNeeded: '{goodResult.ResponseCode}'.");
                    goodResult.Value.Dispose();
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, targetHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, authorizerHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Successful use resets the authorizing POLICY session's context, not merely its two flags (TPM 2.0 Library
    /// Part 3, Section 23.2.4; the reference's <c>SessionResetPolicyData</c>/<c>SessionSetStartTime</c>, invoked
    /// unconditionally on every successful use of a policy session): a self-referential PolicySecret's own
    /// extension of its authorizer's policyDigest is wiped back to the Zero Digest by that same reset, and a
    /// second self-referential use over the same (now-reset) session is refused with TPM_RC_MODE exactly as a
    /// fresh session would be.
    /// </summary>
    /// <remarks>
    /// The second use names a DIFFERENT hierarchy, whose installed policy is the Zero Digest the reset restored,
    /// so the session still satisfies the entity's policy and the refusal is again the isAuthValueNeeded gate
    /// alone. Reusing the endorsement hierarchy would have been answered with <c>TPM_RC_POLICY_FAIL</c> - true,
    /// but a statement about the digest reset rather than about the flag reset, which is what this test is for.
    /// Both facts are asserted: the digest read-back below covers the first, this covers the second.
    /// </remarks>
    [TestMethod]
    public async Task SuccessfulSelfReferentialPolicySecretResetsAuthorizerPolicyDigest()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await InstallEndorsementPolicyAsync(tpm, ComputePolicyAuthValueDigest()).ConfigureAwait(false);
        await InstallHierarchyPolicyAsync(tpm, TpmRh.TPM_RH_OWNER, ZeroDigest()).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            (sessionHandle, TpmSession session, _, _) = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(session)
            {
                TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

                using PolicySecretInput firstInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, pool);
                TpmResult<PolicySecretResponse> firstResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, firstInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(firstResult.IsSuccess, $"The self-referential PolicySecret must succeed: '{firstResult.ResponseCode}'.");
                firstResult.Value.Dispose();

                TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");
                using(digestResult.Value)
                {
                    byte[] zeroDigest = new byte[DigestSize];
                    Assert.IsTrue(
                        digestResult.Value.PolicyDigest.AsReadOnlySpan().SequenceEqual(zeroDigest),
                        "A session that successfully authorized its own PolicySecret extension must have its policyDigest reset to the Zero Digest by that same use, not retain the fold.");
                }

                using PolicySecretInput secondInput = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_OWNER, sessionHandle, pool);
                TpmResult<PolicySecretResponse> secondResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, secondInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsFalse(secondResult.IsSuccess, "A session whose context was reset by its own successful use must not still authorize a second PolicySecret as if isAuthValueNeeded were still SET.");
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_MODE, secondResult.ResponseCode,
                    "isAuthValueNeeded must have been CLEARed by the successful-use reset, exactly as for a fresh session.");
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Independently transcribes equation 26's exact authHMAC (TPM 2.0 Library Part 1, clause 17.6.12: <c>authHMAC
    /// = HMAC(sessionKey ‖ authValue, cpHash ‖ nonceCaller ‖ nonceTPM ‖ sessionAttributes)</c>) over a genuine
    /// POLICY-table session — sessionKey is the Empty Buffer (clause 17.6.9: this session is unbound and
    /// unsalted, so no KDFa runs at all), cpHash and the HMAC itself via <c>CryptographicKeyEvents</c>'s
    /// registered digest/HMAC seam — from the raw wire bytes the session actually sent, proving the simulator's
    /// accept path against an independently-assembled transcription (see the class remarks for why authValue is
    /// also empty here).
    /// </summary>
    [TestMethod]
    public async Task IndependentlyTranscribedEquation26AuthHmacMatchesWhatTheSimulatorAccepted()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);

        byte[]? capturedCommand = null;
        async ValueTask<TpmResult<TpmResponse>> CaptureAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, System.Threading.CancellationToken ct)
        {
            capturedCommand = command.ToArray();
            return await simulator.SubmitAsync(command, commandPool, ct).ConfigureAwait(false);
        }

        using TpmDevice capturingDevice = TpmDevice.Create(CaptureAsync);
        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await InstallEndorsementPolicyAsync(plainDevice, ComputePolicyAuthValueDigest()).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            (sessionHandle, TpmSession authorizer, _, byte[] initialNonceTpm) =
                await StartUnboundPolicySessionAsync(plainDevice, registry, pool).ConfigureAwait(false);
            using(authorizer)
            {
                TpmResult<PolicyAuthValueResponse> authValueResult = await plainDevice.PolicyAuthValueAsync(
                    sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

                using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, pool);
                TpmResult<PolicySecretResponse> secretResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    capturingDevice, input, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret over a POLICY-session authorizer failed: '{secretResult.ResponseCode}'.");
                secretResult.Value.Dispose();
            }

            Assert.IsNotNull(capturedCommand, "The capturing wrapper must have observed the outgoing PolicySecret command.");
            ParsePolicySecretOverSessionCommand(
                capturedCommand!, out ReadOnlyMemory<byte> nonceCaller, out byte sessionAttributes,
                out ReadOnlyMemory<byte> suppliedHmac, out ReadOnlyMemory<byte> rawParameterArea);

            BaseMemoryPool oraclePool = BaseMemoryPool.Shared;

            //Part 1, clause 17.6.9: a session that is neither bound nor salted has sessionKey = an Empty Buffer —
            //no KDFa is run at all, unlike the bound/salted recipes (equations 20/23/25).
            ReadOnlyMemory<byte> sessionKey = ReadOnlyMemory<byte>.Empty;

            //cpHash = H(TPM_CC_PolicySecret ‖ Name(authHandle) ‖ Name(policySession) ‖ parameters) — self-referential,
            //so Name2 is this same session's own handle.
            int cpHashInputLength = sizeof(uint) + sizeof(uint) + sizeof(uint) + rawParameterArea.Length;
            using IMemoryOwner<byte> cpHashInputOwner = oraclePool.Rent(cpHashInputLength);
            {
                var writer = new TpmWriter(cpHashInputOwner.Memory.Span[..cpHashInputLength]);
                writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_PolicySecret);
                writer.WriteUInt32((uint)TpmRh.TPM_RH_ENDORSEMENT);
                writer.WriteUInt32(sessionHandle);
                writer.WriteBytes(rawParameterArea.Span);
            }

            using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
                cpHashInputOwner.Memory[..cpHashInputLength], outputByteLength: DigestSize, tag: DigestTag(), pool: oraclePool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            //Equation 26 (TPM 2.0 Library Part 1, clause 17.6.12): authHMAC = HMAC(sessionKey ‖ authValue, cpHash ‖ nonceCaller ‖ nonceTPM ‖
            //sessionAttributes). authValue is the endorsement hierarchy's own authorization value (empty, per the
            //class remarks) — the key reduces to sessionKey, but the KEY COMPOSITION itself (not merely its
            //accidental value) is what this transcription exercises.
            int hmacInputLength = cpHash.AsReadOnlySpan().Length + nonceCaller.Length + initialNonceTpm.Length + 1;
            using IMemoryOwner<byte> hmacInputOwner = oraclePool.Rent(hmacInputLength);
            {
                var writer = new TpmWriter(hmacInputOwner.Memory.Span[..hmacInputLength]);
                writer.WriteBytes(cpHash.AsReadOnlySpan());
                writer.WriteBytes(nonceCaller.Span);
                writer.WriteBytes(initialNonceTpm);
                writer.WriteByte(sessionAttributes);
            }

            ReadOnlyMemory<byte> authValue = ReadOnlyMemory<byte>.Empty;
            int keyLength = sessionKey.Length + authValue.Length;
            using IMemoryOwner<byte> keyOwner = oraclePool.Rent(Math.Max(keyLength, 1));
            sessionKey.CopyTo(keyOwner.Memory);
            authValue.CopyTo(keyOwner.Memory[sessionKey.Length..]);

            using HmacValue expectedHmac = await CryptographicKeyEvents.ComputeHmacAsync(
                hmacInputOwner.Memory[..hmacInputLength], keyOwner.Memory[..keyLength], outputByteLength: DigestSize, tag: HmacTag(), pool: oraclePool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(
                expectedHmac.AsReadOnlySpan().SequenceEqual(suppliedHmac.Span),
                "The independently transcribed equation 26 authHMAC must equal the hmac field the session actually sent and the simulator accepted.");
        }
        finally
        {
            await FlushIfPresentAsync(plainDevice, registry, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A salted, unbound POLICY session against an RSA tpmKey (TPM 2.0 Library Part 3, Section 11.1.1: sessionKey
    /// derivation is identical for every sessionType) authorizes PolicySecret end to end, proving the host and the
    /// simulator derived the same session key from the RSA-OAEP-recovered salt for the POLICY session table.
    /// </summary>
    [TestMethod]
    public async Task SaltedUnboundPolicySessionAuthorizesPolicySecretRsa()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;
        uint sessionHandle = 0;

        try
        {
            ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
            TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

            (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateSaltedPolicySession(
                tpmKeyHandle, modulus, DefaultRsaExponent, TpmKeyNameAlg, SessionAlg, rsaBackend.EncryptOaep, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using(salt)
            {
                TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                    tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted policy, RSA) failed: '{startResult.ResponseCode}'.");
                StartAuthSessionResponse startResponse = startResult.Value;
                sessionHandle = startResponse.SessionHandle.Value;

                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller, startResponse.NonceTPM,
                    SessionAlg, pool, salt: salt.Memory[..saltLength], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                await AuthorizeEndorsementSecretOverPolicySessionAsync(tpm, registry, pool, sessionHandle, session).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>The ECC sibling of <see cref="SaltedUnboundPolicySessionAuthorizesPolicySecretRsa"/> (ECDH+KDFe salt recovery).</summary>
    [TestMethod]
    public async Task SaltedUnboundPolicySessionAuthorizesPolicySecretEcc()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateEccDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;
        uint sessionHandle = 0;

        try
        {
            ReadOnlyMemory<byte> point = ExtractEccPoint(tpmKey);
            TpmEccSigningBackend eccBackend = BouncyCastleTpmEccSigningBackend.Create();

            (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateSaltedPolicySession(
                tpmKeyHandle, point, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmKeyNameAlg, SessionAlg,
                eccBackend.GenerateKey, eccBackend.ComputeSharedSecret, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using(salt)
            {
                TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                    tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (salted policy, ECC) failed: '{startResult.ResponseCode}'.");
                StartAuthSessionResponse startResponse = startResult.Value;
                sessionHandle = startResponse.SessionHandle.Value;

                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller, startResponse.NonceTPM,
                    SessionAlg, pool, salt: salt.Memory[..saltLength], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                await AuthorizeEndorsementSecretOverPolicySessionAsync(tpm, registry, pool, sessionHandle, session).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A salted AND bound POLICY session (RSA tpmKey, bound to the owner hierarchy) authorizes PolicySecret end to
    /// end: the distinction that the bind entity's authValue strengthens the KDFa sessionKey once, at
    /// establishment — Part 1, clause 17.6.12 equation 25 — and is never re-folded into the per-command authHMAC
    /// merely because the session is bound) is exercised structurally here since the bind entity (owner) and the
    /// authorized entity (endorsement) are DIFFERENT, so no bind-entity-omission question could arise even for an
    /// HMAC session; equation 26/27 alone (isAuthValueNeeded) decides the authValue fold, exactly as for the
    /// unbound cases above.
    /// </summary>
    [TestMethod]
    public async Task BoundAndSaltedPolicySessionAuthorizesPolicySecretRsa()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;
        uint sessionHandle = 0;

        try
        {
            ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
            TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

            (StartAuthSessionInput startInput, IMemoryOwner<byte> salt, int saltLength) = await StartAuthSessionInputExtensions.CreateBoundAndSaltedPolicySession(
                tpmKeyHandle, (uint)TpmRh.TPM_RH_OWNER, modulus, DefaultRsaExponent, TpmKeyNameAlg, SessionAlg, rsaBackend.EncryptOaep, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using(salt)
            {
                TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                    tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound-and-salted policy, RSA) failed: '{startResult.ResponseCode}'.");
                StartAuthSessionResponse startResponse = startResult.Value;
                sessionHandle = startResponse.SessionHandle.Value;

                //The bind entity (owner) carries empty auth by default in this simulator (see the class remarks).
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), ReadOnlyMemory<byte>.Empty, startInput.NonceCaller, startResponse.NonceTPM,
                    SessionAlg, pool, salt: salt.Memory[..saltLength], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                await AuthorizeEndorsementSecretOverPolicySessionAsync(tpm, registry, pool, sessionHandle, session).ConfigureAwait(false);
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, sessionHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, tpmKeyHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A TRIAL policy session presented as PolicySecret's authorizing session is refused before any HMAC or
    /// digest work: a trial session authorizes nothing, and a real TPM refuses ANY trial session presented in a
    /// command's session area (session-index-encoded TPM_RC_ATTRIBUTES) before any authorization processing. The
    /// target <c>policySession</c> being extended is a separate, non-trial session — isolating that only the
    /// AUTHORIZER is refused.
    /// </summary>
    [TestMethod]
    public async Task TrialPolicySessionCannotAuthorizePolicySecret()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint trialHandle = 0;
        uint targetHandle = 0;
        try
        {
            (trialHandle, TpmSession trial) = await StartTrialPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(trial)
            {
                TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(
                    trialHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue (trial) failed: '{authValueResult.ResponseCode}'.");

                (targetHandle, TpmSession target, _, _) = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
                using(target)
                {
                    using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, targetHandle, pool);
                    TpmResult<PolicySecretResponse> secretResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                        tpm, input, [trial], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsFalse(secretResult.IsSuccess, "A TRIAL session must never authorize PolicySecret's authHandle.");
                    Assert.AreEqual(
                        SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), secretResult.ResponseCode,
                        "A trial authorizer must be refused with the session-index-encoded TPM_RC_ATTRIBUTES.");
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, targetHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, trialHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The positive counterpart: a TRIAL session as the <c>policySession</c> PARAMETER being extended is still
    /// extendable, authorized by a separate, non-trial POLICY session — only the AUTHORIZER role is closed to a
    /// trial session, not the target of the assertion.
    /// </summary>
    [TestMethod]
    public async Task TrialTargetSessionIsStillExtendableViaNonTrialAuthorizer()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await InstallEndorsementPolicyAsync(tpm, ComputePolicyAuthValueDigest()).ConfigureAwait(false);

        uint authorizerHandle = 0;
        uint trialHandle = 0;
        try
        {
            (authorizerHandle, TpmSession authorizer, _, _) = await StartUnboundPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(authorizer)
            {
                TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(
                    authorizerHandle, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue (authorizer) failed: '{authValueResult.ResponseCode}'.");

                (trialHandle, TpmSession trial) = await StartTrialPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
                using(trial)
                {
                    using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, trialHandle, pool);
                    TpmResult<PolicySecretResponse> secretResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                        tpm, input, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                    Assert.IsTrue(
                        secretResult.IsSuccess, $"A non-trial authorizer must still be able to extend a TRIAL target session: '{secretResult.ResponseCode}'.");
                    secretResult.Value.Dispose();
                }
            }
        }
        finally
        {
            await FlushIfPresentAsync(tpm, registry, trialHandle).ConfigureAwait(false);
            await FlushIfPresentAsync(tpm, registry, authorizerHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// POLICY/TRIAL <c>TPM2_StartAuthSession()</c> now runs the same nonceCaller floor the HMAC path already
    /// enforced (TPM 2.0 Library Part 3, clause 11.1): a POLICY session start is not exempt.
    /// </summary>
    [TestMethod]
    public async Task ShortNonceCallerOnPolicySessionIsRejectedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg) with { NonceCaller = new byte[15] };

        TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, rc, "A 15-octet nonceCaller is one short of the fixed 16-octet floor, for a POLICY session exactly as for an HMAC session.");
    }

    /// <summary>
    /// POLICY/TRIAL <c>TPM2_StartAuthSession()</c> now runs the same tpmKey/encryptedSalt consistency check the
    /// HMAC path already enforced (TPM 2.0 Library Part 3, clause 11.1): a non-empty encryptedSalt naming an
    /// unsalted (<c>tpmKey = TPM_RH_NULL</c>) POLICY session is malformed.
    /// </summary>
    [TestMethod]
    public async Task EncryptedSaltWithNullTpmKeyOnPolicySessionIsRejectedWithValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg) with { EncryptedSalt = new byte[] { 0x01, 0x02, 0x03, 0x04 } };

        TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, rc, "An unsalted POLICY session request naming a non-empty encryptedSalt must be rejected, exactly as for an HMAC session.");
    }

    /// <summary>
    /// POLICY/TRIAL <c>TPM2_StartAuthSession()</c> now runs the same tpmKey-shape check the HMAC path already
    /// enforced (TPM 2.0 Library Part 3, clause 11.1): a permanent handle is never an asymmetric key, so naming
    /// one as tpmKey is TPM_RC_KEY, for a POLICY session exactly as for an HMAC session.
    /// </summary>
    [TestMethod]
    public async Task PermanentHandleAsTpmKeyOnPolicySessionIsRejectedWithKey()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg) with { TpmKey = (uint)TpmRh.TPM_RH_OWNER };

        TpmRcConstants rc = await AttemptStartAuthSessionAsync(tpm, registry, pool, startInput).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_KEY, rc, "A permanent handle named as tpmKey is never an asymmetric key, for a POLICY session exactly as for an HMAC session.");
    }

    /// <summary>
    /// Installs <paramref name="policyDigest"/> as the endorsement hierarchy's authorization policy through
    /// <c>TPM2_SetPrimaryPolicy</c> (TPM 2.0 Library Part 3, Section 24.3), the precondition every
    /// policy-session authorizer in this file needs: an entity whose authPolicy is the Empty Buffer is outside
    /// the policy path entirely (Part 1, clause 11.2, Table 5).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="policyDigest">The digest the authorizing session will accumulate.</param>
    private async Task InstallEndorsementPolicyAsync(TpmDevice tpm, ReadOnlyMemory<byte> policyDigest) =>
        await InstallHierarchyPolicyAsync(tpm, TpmRh.TPM_RH_ENDORSEMENT, policyDigest).ConfigureAwait(false);

    /// <summary>
    /// Installs <paramref name="policyDigest"/> as <paramref name="hierarchy"/>'s authorization policy over the
    /// plaintext arm, whose authorization is the hierarchy's own (still empty) value at this point in every test
    /// that calls it.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="hierarchy">The hierarchy whose policy is installed.</param>
    /// <param name="policyDigest">The digest the authorizing session will accumulate.</param>
    private async Task InstallHierarchyPolicyAsync(TpmDevice tpm, TpmRh hierarchy, ReadOnlyMemory<byte> policyDigest)
    {
        TpmResult<SetPrimaryPolicyResponse> result = await tpm.SetPrimaryPolicyWithPasswordAsync(
            hierarchy, ReadOnlyMemory<byte>.Empty, policyDigest, SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"Installing '{hierarchy}'s authorization policy failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Transcribes the policyDigest a session reaches by folding <c>TPM2_PolicyAuthValue()</c> alone:
    /// <c>policyDigest = H(ZeroDigest ‖ TPM_CC_PolicyAuthValue)</c> (TPM 2.0 Library Part 3, Section 23.11).
    /// </summary>
    /// <returns>The policy digest.</returns>
    private static byte[] ComputePolicyAuthValueDigest()
    {
        byte[] digest = new byte[DigestSize];
        Span<byte> zero = stackalloc byte[DigestSize];
        zero.Clear();
        _ = TpmPolicyDigest.ExtendForAuthValue(zero, SessionAlg, digest);

        return digest;
    }

    /// <summary>
    /// The Zero Digest a fresh policy session's policyDigest starts at (TPM 2.0 Library Part 1, clause 17.7.1) -
    /// a legitimate <see cref="DigestSize"/>-octet policy value, and a different thing from the Empty Buffer,
    /// which disables policy authorization altogether.
    /// </summary>
    /// <returns>The zero digest.</returns>
    private static byte[] ZeroDigest() => new byte[DigestSize];

    /// <summary>
    /// Installs the endorsement hierarchy's authorization policy, runs <c>TPM2_PolicyAuthValue()</c>, then a
    /// self-referential PolicySecret(endorsement) over <paramref name="session"/>, asserting success — the
    /// shared tail every salted-POLICY-session E2E test in this file reduces to once its session is established.
    /// </summary>
    /// <remarks>
    /// The policy is installed here rather than in each caller because the digest it must equal is fixed by the
    /// <c>TPM2_PolicyAuthValue</c> fold below and by nothing about the session's own establishment — salting and
    /// binding change the session KEY, never the accumulated policyDigest.
    /// </remarks>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The established policy session's handle.</param>
    /// <param name="session">The host-side session object that authorizes the command.</param>
    private async Task AuthorizeEndorsementSecretOverPolicySessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint sessionHandle, TpmSession session)
    {
        await InstallEndorsementPolicyAsync(tpm, ComputePolicyAuthValueDigest()).ConfigureAwait(false);

        TpmResult<PolicyAuthValueResponse> authValueResult = await tpm.PolicyAuthValueAsync(
            sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(authValueResult.IsSuccess, $"PolicyAuthValue failed: '{authValueResult.ResponseCode}'.");

        using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, pool);
        TpmResult<PolicySecretResponse> secretResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
            tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(
            secretResult.IsSuccess,
            $"PolicySecret over the established POLICY session failed: '{secretResult.ResponseCode}'. A failure means the host and the simulator derived different session keys.");
        secretResult.Value.Dispose();
    }

    /// <summary>
    /// Starts an unbound, unsalted POLICY session through the production <c>TPM2_StartAuthSession()</c> path and
    /// wraps it as a <see cref="TpmSession"/> via the plain constructor, whose sessionKey is the Empty Buffer
    /// (TPM 2.0 Library Part 1, clause 17.6.9) — no bind entity, no salt, so no KDFa runs. Also returns copies of
    /// the two start nonces (captured before nonceTPM's ownership transfers into the session) for tests that need
    /// an independent oracle.
    /// </summary>
    private async Task<(uint SessionHandle, TpmSession Session, byte[] InitialNonceCaller, byte[] InitialNonceTpm)> StartUnboundPolicySessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound policy) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        byte[] initialNonceCaller = startInput.NonceCaller.ToArray();
        byte[] initialNonceTpm = startResponse.NonceTPM.AsReadOnlySpan().ToArray();

        var session = new TpmSession(new TpmHandle(startResponse.SessionHandle.Value), startResponse.NonceTPM, SessionAlg, pool);

        return (startResponse.SessionHandle.Value, session, initialNonceCaller, initialNonceTpm);
    }

    /// <summary>
    /// Starts a TRIAL policy session through the production <c>TPM2_StartAuthSession()</c> path and wraps it as a
    /// <see cref="TpmSession"/> via the plain constructor — unbound and unsalted like
    /// <see cref="StartUnboundPolicySessionAsync"/>, so its sessionKey is likewise the Empty Buffer.
    /// </summary>
    private async Task<(uint SessionHandle, TpmSession Session)> StartTrialPolicySessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateTrialPolicySession(SessionAlg);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        var session = new TpmSession(new TpmHandle(startResponse.SessionHandle.Value), startResponse.NonceTPM, SessionAlg, pool);

        return (startResponse.SessionHandle.Value, session);
    }

    /// <summary>Issues <c>TPM2_StartAuthSession()</c> and returns its response code, disposing a success.</summary>
    private async Task<TpmRcConstants> AttemptStartAuthSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, StartAuthSessionInput startInput)
    {
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        if(startResult.IsSuccess)
        {
            startResult.Value.Dispose();
        }

        return startResult.ResponseCode;
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + TPM_RC_S +
    /// TPM_RC_n(0x100·(index+1)) — the test-side mirror of TpmLifecycleTransitions.SessionEncodedRc, transcribed
    /// independently rather than referencing the production internal.
    /// </summary>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Parses a captured <c>TPM2_PolicySecret()</c>-over-session wire command back into its authorizing session's
    /// fields and the raw <c>nonceTPM ‖ cpHashA ‖ policyRef ‖ expiration</c> parameter bytes, firewalled to the
    /// wire (no back-channel into simulator or session internals).
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

    /// <summary>Creates the standard RSA endorsement-key-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) used as a salted session's RSA tpmKey.</summary>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an ECC storage-parent-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) used as a salted session's ECC tpmKey.</summary>
    private async Task<CreatePrimaryResponse> CreateEccDecryptKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForEccStorageParent(TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC decrypt key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Extracts an ECC primary's exported public point, SEC1 uncompressed (<c>0x04 ‖ X ‖ Y</c>).</summary>
    private static ReadOnlyMemory<byte> ExtractEccPoint(CreatePrimaryResponse primary)
    {
        TpmsEccPoint point = primary.OutPublic.PublicArea.Unique.Ecc!;
        return EllipticCurveUtilities.CombineToUncompressedPoint(point.X.AsReadOnlySpan(), point.Y.AsReadOnlySpan());
    }

    /// <summary>Flushes a transient session or object handle when one is present (non-zero), ignoring the result.</summary>
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

    /// <summary>Creates a response codec registry covering every command these tests drive.</summary>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with BOTH the ECC (BouncyCastle) and RSA (framework key generation, BouncyCastle OAEP)
    /// signing backends wired, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase.
    /// </summary>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-policy-session-hmac", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an unauthorized command on the wire.</summary>
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
