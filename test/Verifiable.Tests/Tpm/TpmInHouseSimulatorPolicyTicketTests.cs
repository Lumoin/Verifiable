using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Hierarchy;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_PolicyTicket()</c> against the in-house behavioural <see cref="TpmSimulator"/> — entirely
/// in-process, with no external assets — through the same production command path the production code uses (the
/// <see cref="Verifiable.Tpm.Extensions.Policy.TpmDeviceExtensions"/> policy commands,
/// <see cref="TpmCommandExecutor"/>, and the real
/// command/response codecs). Every test mints a real ticket through <c>TPM2_PolicySigned()</c> or
/// <c>TPM2_PolicySecret()</c> (a negative <c>expiration</c>), flushes the minting session, and replays the
/// ticket into a fresh session via <c>TPM2_PolicyTicket()</c> (TPM 2.0 Library Part 3, clause 23.5).
/// </summary>
/// <remarks>
/// <para>
/// The two happy-path tests each assert the replayed digest equals the ORIGINAL command's own fold
/// (<see cref="TpmPolicyDigest.ExtendForSigned"/>/<see cref="TpmPolicyDigest.ExtendForSecret"/>) — proving
/// <c>PolicyUpdate()</c> is dispatched by the ticket's own tag, never by <c>TPM_CC_PolicyTicket</c> itself
/// (clause 23.5.1).
/// </para>
/// <para>
/// The negative tests isolate one rung of the check ladder (trial → timeout size → expiry → cpHashA →
/// ticket-digest recompute); everything past the isolated rung uses a placeholder/garbage ticket that is never
/// actually reached, mirroring the convention <c>TpmInHouseSimulatorPolicySignedTests</c> already uses for its
/// own placeholder-signature negatives.
/// </para>
/// <para>
/// <see cref="EquationTwelveTicketDigestIsAVerifiableHmacOfTheInjectedSeedAndTimeEpoch"/> is the independent,
/// oracle-free proof that the ticket digest really is
/// <c>HMAC(proof, tag || cpHash || policyRef || authName || timeout || timeEpoch || resetCount)</c> — equation
/// 12 (TPM 2.0 Library Part 2, clause 10.6.6, Table 114) — hand-assembled and HMAC'd in this file, not merely
/// re-invoking the implementation under test. It reproduces the simulator's own <c>TimeEpoch</c> derivation
/// (a one-time FNV-1a fold of the injected seed, then one well-known MurmurHash3 64-bit finalizer regeneration
/// per completed <c>TPM2_Startup()</c>) from those two algorithms' own public definitions, the same technique
/// <c>TpmInHouseSimulatorSignTests</c>/<c>TpmInHouseSimulatorVerifySignatureTests</c> already use to reproduce
/// the per-hierarchy proof (<c>SHA-256(seed || hierarchy)</c>) independently of the implementation.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyTicketTests
{
    /// <summary>The policy session hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The width, in bytes, of a SHA-256 digest or HMAC.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies a ticket minted by <c>TPM2_PolicySecret()</c> (tag <c>TPM_ST_AUTH_SECRET</c>), replayed on a
    /// FRESH session via <c>TPM2_PolicyTicket()</c>, folds the digest identically to the original command's own
    /// <see cref="TpmPolicyDigest.ExtendForSecret"/> — proving the replay is a true stand-in for the original
    /// authorization, not a distinct "used a ticket" branch of the policy tree (TPM 2.0 Library Part 1, clause
    /// 16.7.12).
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketReplaysAPolicySecretTicketAndFoldsIdenticallyToTheOriginalCommand()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] policyRef = "policyticket-secret-ref"u8.ToArray();
        byte[] authName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, (uint)TpmRh.TPM_RH_OWNER);

        uint mintSessionHandle = 0;
        byte[] timeoutBytes;
        byte[] ticketDigestBytes;
        TpmStConstants ticketTag;
        TpmiRhHierarchy ticketHierarchy;
        try
        {
            TpmResult<StartAuthSessionResponse> mintStart = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(mintStart.IsSuccess, $"StartAuthSession (mint) failed: '{mintStart.ResponseCode}'.");

            using StartAuthSessionResponse mintSession = mintStart.Value;
            mintSessionHandle = mintSession.SessionHandle.Value;

            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_OWNER, mintSessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, policyRef, -3600, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret (ticket mint) failed: '{secretResult.ResponseCode}'.");

            using PolicySecretResponse minted = secretResult.Value;
            Assert.IsFalse(minted.PolicyTicket.IsNull, "A negative expiration must mint a real ticket.");
            timeoutBytes = minted.Timeout.ToArray();
            ticketDigestBytes = minted.PolicyTicket.Digest.ToArray();
            ticketTag = minted.PolicyTicket.Tag;
            ticketHierarchy = minted.PolicyTicket.Hierarchy;
        }
        finally
        {
            await FlushIfPresentAsync(tpm, mintSessionHandle).ConfigureAwait(false);
        }

        uint replaySessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> replayStart = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(replayStart.IsSuccess, $"StartAuthSession (replay) failed: '{replayStart.ResponseCode}'.");

            using StartAuthSessionResponse replaySession = replayStart.Value;
            replaySessionHandle = replaySession.SessionHandle.Value;

            using TpmtTkAuth ticket = TpmtTkAuth.Create(ticketTag, ticketHierarchy, ticketDigestBytes, pool);
            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                replaySessionHandle, timeoutBytes, ReadOnlyMemory<byte>.Empty, policyRef, authName, ticket, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(ticketResult.IsSuccess, $"PolicyTicket (replay) failed: '{ticketResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                replaySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            int size = TpmPolicyDigest.Size(SessionAlg);
            byte[] predicted = new byte[size];
            Span<byte> zero = stackalloc byte[size];
            zero.Clear();
            TpmPolicyDigest.ExtendForSecret(zero, authName, policyRef, SessionAlg, predicted, pool);

            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "A replayed PolicySecret ticket must fold identically to TPM2_PolicySecret()'s own ExtendForSecret.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, replaySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Verifies a ticket minted by <c>TPM2_PolicySigned()</c> (tag <c>TPM_ST_AUTH_SIGNED</c>), replayed on a
    /// FRESH session via <c>TPM2_PolicyTicket()</c>, folds the digest identically to the original command's own
    /// <see cref="TpmPolicyDigest.ExtendForSigned"/>.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketReplaysAPolicySignedTicketAndFoldsIdenticallyToTheOriginalCommand()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;
        byte[] authorityName = authorityKey.Name.Span.ToArray();
        byte[] policyRef = "policyticket-signed-ref"u8.ToArray();

        uint mintSessionHandle = 0;
        byte[] timeoutBytes;
        byte[] ticketDigestBytes;
        TpmStConstants ticketTag;
        TpmiRhHierarchy ticketHierarchy;
        try
        {
            TpmResult<StartAuthSessionResponse> mintStart = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(mintStart.IsSuccess, $"StartAuthSession (mint) failed: '{mintStart.ResponseCode}'.");

            using StartAuthSessionResponse mintSession = mintStart.Value;
            mintSessionHandle = mintSession.SessionHandle.Value;

            byte[] aHash = await ComputeAHashAsync(
                ReadOnlyMemory<byte>.Empty, -3600, ReadOnlyMemory<byte>.Empty, policyRef, Sha256DigestSize, CryptoTags.Sha256Digest, pool, TestContext.CancellationToken).ConfigureAwait(false);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using SignInput signInput = SignInput.ForEcdsa(authorityKey.ObjectHandle, aHash, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
                tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authority) failed: '{signResult.ResponseCode}'.");

            using SignResponse signature = signResult.Value;
            using Signature p1363Signature = ConcatenateP1363(signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), pool);

            TpmResult<PolicySignedResponse> signedResult = await tpm.PolicySignedAsync(
                authorityHandle, mintSessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, policyRef, -3600, p1363Signature.AsReadOnlyMemory(),
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(signedResult.IsSuccess, $"PolicySigned (ticket mint) failed: '{signedResult.ResponseCode}'.");

            using PolicySignedResponse minted = signedResult.Value;
            Assert.IsFalse(minted.PolicyTicket.IsNull, "A negative expiration must mint a real ticket.");
            timeoutBytes = minted.Timeout.ToArray();
            ticketDigestBytes = minted.PolicyTicket.Digest.ToArray();
            ticketTag = minted.PolicyTicket.Tag;
            ticketHierarchy = minted.PolicyTicket.Hierarchy;
        }
        finally
        {
            await FlushIfPresentAsync(tpm, mintSessionHandle).ConfigureAwait(false);
        }

        uint replaySessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> replayStart = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(replayStart.IsSuccess, $"StartAuthSession (replay) failed: '{replayStart.ResponseCode}'.");

            using StartAuthSessionResponse replaySession = replayStart.Value;
            replaySessionHandle = replaySession.SessionHandle.Value;

            using TpmtTkAuth ticket = TpmtTkAuth.Create(ticketTag, ticketHierarchy, ticketDigestBytes, pool);
            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                replaySessionHandle, timeoutBytes, ReadOnlyMemory<byte>.Empty, policyRef, authorityName, ticket, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(ticketResult.IsSuccess, $"PolicyTicket (replay) failed: '{ticketResult.ResponseCode}'.");

            TpmResult<PolicyGetDigestResponse> digestResult = await tpm.PolicyGetDigestAsync(
                replaySessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(digestResult.IsSuccess, $"PolicyGetDigest failed: '{digestResult.ResponseCode}'.");

            using PolicyGetDigestResponse digest = digestResult.Value;

            int size = TpmPolicyDigest.Size(SessionAlg);
            byte[] predicted = new byte[size];
            Span<byte> zero = stackalloc byte[size];
            zero.Clear();
            TpmPolicyDigest.ExtendForSigned(zero, authorityName, policyRef, SessionAlg, predicted, pool);

            Assert.IsTrue(
                digest.PolicyDigest.AsReadOnlySpan().SequenceEqual(predicted),
                "A replayed PolicySigned ticket must fold identically to TPM2_PolicySigned()'s own ExtendForSigned.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, replaySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The single most direct observation of what <c>TPM2_Clear()</c> does, and the reason the hierarchy proofs
    /// are split at all: a clear "change[s] the storage primary seed (SPS) to a new value from the TPM's random
    /// number generator" and with it "shProof and ehProof" (TPM 2.0 Library Part 3, clause 24.6.1), while the
    /// platform proof appears nowhere on that list. A ticket is an HMAC keyed by its hierarchy's proof (Part 1,
    /// clause 11.5), and there is no invalidation pass over any list of outstanding tickets - "When the SPS is
    /// changed, shProof will change so that the saved contexts cannot be reloaded" is the whole mechanism. So an
    /// owner-hierarchy ticket minted before a clear must stop re-verifying afterwards (<c>TPM_RC_TICKET</c>, the
    /// recompute-and-compare failure) while a platform-hierarchy ticket minted in the same breath must still
    /// replay. Both are replayed once BEFORE the clear too, so a failure afterwards cannot be a ticket that never
    /// worked.
    /// </summary>
    /// <remarks>
    /// Both tickets are minted against the minting session's own retained <c>nonceTPM</c>, which makes the
    /// authorization session-bound rather than absolute and therefore leaves <c>expiresOnReset</c> CLEAR (Part 3,
    /// clause 23.2.2). That matters here: with it SET, equation 12 folds <c>resetCount</c> into the ticket
    /// digest (Part 2, clause 10.6.6, Table 114), and a clear sets <c>resetCount</c> to zero - so BOTH tickets
    /// would die and the proof split would be unobservable. Excluding that term isolates the proof.
    /// </remarks>
    [TestMethod]
    public async Task ClearRotatesTheStorageProofSoAnOwnerTicketStopsReplayingWhileAPlatformOneSurvives()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] ownerPolicyRef = "clear-owner-ticket-ref"u8.ToArray();
        byte[] platformPolicyRef = "clear-platform-ticket-ref"u8.ToArray();

        MintedTicket ownerTicket = await MintSessionBoundSecretTicketAsync(tpm, (uint)TpmRh.TPM_RH_OWNER, ownerPolicyRef).ConfigureAwait(false);
        MintedTicket platformTicket = await MintSessionBoundSecretTicketAsync(tpm, (uint)TpmRh.TPM_RH_PLATFORM, platformPolicyRef).ConfigureAwait(false);

        Assert.AreEqual(TpmiRhHierarchy.Owner, ownerTicket.Hierarchy, "A TPM_RH_OWNER-authorized ticket must carry the storage hierarchy.");
        Assert.AreEqual(TpmiRhHierarchy.Platform, platformTicket.Hierarchy, "A TPM_RH_PLATFORM-authorized ticket must carry the platform hierarchy.");

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, await ReplayTicketAsync(tpm, ownerTicket, ownerPolicyRef).ConfigureAwait(false),
            "The owner-hierarchy ticket must replay before the clear, or its later refusal would prove nothing.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, await ReplayTicketAsync(tpm, platformTicket, platformPolicyRef).ConfigureAwait(false),
            "The platform-hierarchy ticket must replay before the clear too.");

        TpmResult<ClearResponse> clearResult = await tpm.ClearAsync(ReadOnlyMemory<byte>.Empty, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(clearResult.IsSuccess, $"TPM2_Clear failed: '{clearResult.ResponseCode}'.");

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 4), await ReplayTicketAsync(tpm, ownerTicket, ownerPolicyRef).ConfigureAwait(false),
            "A rotated shProof stops an owner-hierarchy ticket from re-verifying at ticket, parameter 5 of Table 148 - structurally, with no revocation pass over any list.");
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, await ReplayTicketAsync(tpm, platformTicket, platformPolicyRef).ConfigureAwait(false),
            "The platform proof is not on clause 24.6.1's effect list, so a platform-hierarchy ticket must survive an owner change intact.");
    }

    /// <summary>
    /// A trial session rejects <c>TPM2_PolicyTicket()</c> outright with <c>TPM_RC_ATTRIBUTES</c> — a genuine,
    /// deliberate exception to clause 23.1's general "trial sessions always succeed" default, established only
    /// by the reference implementation's own explicit rejection (clause 23.5.1 itself says nothing about
    /// trial sessions: a trial session predicts a digest without holding real authorization material, and a
    /// ticket IS real authorization material, so "predicting" via a ticket is meaningless). Checked first,
    /// unconditionally, before even the timeout size is inspected.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketOnATrialSessionReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartTrialPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (trial) failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            byte[] garbageTimeout = new byte[8];
            using TpmtTkAuth garbageTicket = TpmtTkAuth.Create(TpmStConstants.TPM_ST_AUTH_SECRET, TpmiRhHierarchy.Null, new byte[Sha256DigestSize], pool);

            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                sessionHandle, garbageTimeout, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, garbageTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(ticketResult.IsSuccess, "A trial session must reject TPM2_PolicyTicket().");
            Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), ticketResult.ResponseCode, "Table 148: policySession is TPM2_PolicyTicket()'s sole handle (handle 1); a trial session is handle-encoded TPM_RC_ATTRIBUTES at index 0.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>timeout</c> whose wire length is not exactly 8 octets is rejected with <c>TPM_RC_SIZE</c> — a
    /// tighter rule than Part 2 Table 98's general "8 or less" for <c>TPM2B_TIMEOUT</c>, specific to this
    /// command because it must extract the expires-on-reset flag bit and reproduce the exact 64-bit value that
    /// was hashed into the original ticket. Part 4's <c>TPM2_PolicyTicket()</c> states the
    /// rule as <c>if(in-&gt;timeout.t.size != sizeof(UINT64)) return TPM_RCS_SIZE + RC_PolicyTicket_timeout;</c>.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithATimeoutNotEightBytesReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            byte[] wrongSizeTimeout = new byte[4];
            using TpmtTkAuth garbageTicket = TpmtTkAuth.Create(TpmStConstants.TPM_ST_AUTH_SECRET, TpmiRhHierarchy.Null, new byte[Sha256DigestSize], pool);

            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                sessionHandle, wrongSizeTimeout, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, garbageTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(ticketResult.IsSuccess, "A timeout that is not exactly 8 bytes must be rejected.");
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), ticketResult.ResponseCode, "Table 148: timeout is TPM2_PolicyTicket()'s first parameter (parameter 1); a timeout that is not exactly 8 bytes is parameter-encoded TPM_RC_SIZE at index 0.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>timeout</c> whose de-flagged value is already behind the TPM's live Time is rejected with
    /// <c>TPM_RC_EXPIRED</c> (TPM 2.0 Library Part 3, clause 23.2.2, shared with PolicySigned/PolicySecret).
    /// This isolates the check itself: the caller supplies the timeout wire value directly rather than
    /// replaying a genuinely minted one, exactly as the sibling PolicySigned negative tests isolate one ladder
    /// rung with placeholder values for everything downstream.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithAnExpiredTimeoutReturnsExpired()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            //A tiny (1ms), non-flagged deadline: the default per-command clock advance already moves Time past
            //it by the time this command's own dispatch evaluates the check (Startup + StartAuthSession alone
            //already advance Time to 2ms).
            byte[] tinyTimeout = new byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(tinyTimeout, 1UL);
            using TpmtTkAuth garbageTicket = TpmtTkAuth.Create(TpmStConstants.TPM_ST_AUTH_SECRET, TpmiRhHierarchy.Null, new byte[Sha256DigestSize], pool);

            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                sessionHandle, tinyTimeout, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, garbageTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(ticketResult.IsSuccess, "An already-expired timeout must be rejected.");
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_EXPIRED, 0), ticketResult.ResponseCode, "Table 148: timeout is TPM2_PolicyTicket()'s first parameter (parameter 1); an already-expired timeout is parameter-encoded TPM_RC_EXPIRED at index 0.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A non-empty <c>cpHashA</c> whose size does not equal the session's digest width is rejected with
    /// <c>TPM_RC_SIZE</c>. A zero <c>timeout</c> skips the expiry check entirely (clause 23.2.2's shared
    /// <c>PolicyParameterChecks</c> only evaluates expiry when the timeout is non-zero), isolating this rung.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithWrongSizedCpHashAReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            byte[] zeroTimeout = new byte[8];
            byte[] wrongSizedCpHash = new byte[16];
            using TpmtTkAuth garbageTicket = TpmtTkAuth.Create(TpmStConstants.TPM_ST_AUTH_SECRET, TpmiRhHierarchy.Null, new byte[Sha256DigestSize], pool);

            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                sessionHandle, zeroTimeout, wrongSizedCpHash, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, garbageTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(ticketResult.IsSuccess, "A cpHashA of the wrong size must be rejected.");
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), ticketResult.ResponseCode, "Table 148: cpHashA is TPM2_PolicyTicket()'s second parameter (parameter 2); a cpHashA of the wrong size is parameter-encoded TPM_RC_SIZE at index 1.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The session's cpHash latch is first-writer-wins for PolicyTicket too (TPM 2.0 Library Part 3, clause
    /// 23.2.4): a first, genuinely verified replay latches <c>cpHashA</c>, and a second replay on the same
    /// session with a different (but correctly sized) <c>cpHashA</c> is rejected with <c>TPM_RC_CPHASH</c>
    /// ahead of its own (garbage, never-reached) ticket-digest recompute.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketCpHashLatchConflictReturnsCpHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] firstCpHash = new byte[Sha256DigestSize];
        Array.Fill(firstCpHash, (byte)0x11);
        byte[] secondCpHash = new byte[Sha256DigestSize];
        Array.Fill(secondCpHash, (byte)0x22);
        byte[] authName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, (uint)TpmRh.TPM_RH_OWNER);

        uint mintSessionHandle = 0;
        byte[] timeoutBytes;
        byte[] ticketDigestBytes;
        TpmStConstants ticketTag;
        TpmiRhHierarchy ticketHierarchy;
        try
        {
            TpmResult<StartAuthSessionResponse> mintStart = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(mintStart.IsSuccess, $"StartAuthSession (mint) failed: '{mintStart.ResponseCode}'.");

            using StartAuthSessionResponse mintSession = mintStart.Value;
            mintSessionHandle = mintSession.SessionHandle.Value;

            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_OWNER, mintSessionHandle, ReadOnlyMemory<byte>.Empty, firstCpHash, ReadOnlyMemory<byte>.Empty, -3600, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret (ticket mint) failed: '{secretResult.ResponseCode}'.");

            using PolicySecretResponse minted = secretResult.Value;
            timeoutBytes = minted.Timeout.ToArray();
            ticketDigestBytes = minted.PolicyTicket.Digest.ToArray();
            ticketTag = minted.PolicyTicket.Tag;
            ticketHierarchy = minted.PolicyTicket.Hierarchy;
        }
        finally
        {
            await FlushIfPresentAsync(tpm, mintSessionHandle).ConfigureAwait(false);
        }

        uint replaySessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> replayStart = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(replayStart.IsSuccess, $"StartAuthSession (replay) failed: '{replayStart.ResponseCode}'.");

            using StartAuthSessionResponse replaySession = replayStart.Value;
            replaySessionHandle = replaySession.SessionHandle.Value;

            using TpmtTkAuth ticket = TpmtTkAuth.Create(ticketTag, ticketHierarchy, ticketDigestBytes, pool);

            //First replay: the genuine, correctly cpHash-bound ticket, so the session actually latches firstCpHash.
            TpmResult<PolicyTicketResponse> firstResult = await tpm.PolicyTicketAsync(
                replaySessionHandle, timeoutBytes, firstCpHash, ReadOnlyMemory<byte>.Empty, authName, ticket, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(firstResult.IsSuccess, $"PolicyTicket (latching cpHashA) failed: '{firstResult.ResponseCode}'.");

            //Second replay: a DIFFERENT cpHashA on the same session. The latch conflict is checked before the
            //ticket-digest recompute, so a garbage ticket is never actually reached.
            using TpmtTkAuth garbageTicket = TpmtTkAuth.Create(TpmStConstants.TPM_ST_AUTH_SECRET, TpmiRhHierarchy.Null, new byte[Sha256DigestSize], pool);
            TpmResult<PolicyTicketResponse> secondResult = await tpm.PolicyTicketAsync(
                replaySessionHandle, timeoutBytes, secondCpHash, ReadOnlyMemory<byte>.Empty, authName, garbageTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(secondResult.IsSuccess, "A cpHashA conflicting with the session's latch must be rejected.");
            Assert.AreEqual(TpmRcConstants.TPM_RC_CPHASH, secondResult.ResponseCode);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, replaySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A ticket that fails the HMAC recompute must NOT latch <c>cpHashA</c> onto the session (TPM 2.0 Library
    /// Part 3, clause 23.2.4's latch is part of a SUCCESSFUL <c>PolicyUpdate()</c>, not a pre-verification side
    /// effect of merely proposing a cpHashA): a first replay carrying a non-empty <c>cpHashA</c> and a tampered
    /// ticket digest is rejected with <c>TPM_RC_TICKET</c>, and a SECOND, genuinely successful assertion on the
    /// SAME session with a DIFFERENT <c>cpHashA</c> must then succeed — proving the failed first replay left the
    /// session's cpHash latch empty rather than poisoning it.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketFailedVerificationLeavesTheSessionCpHashLatchEmpty()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] policyRef = "policyticket-latch-empty-ref"u8.ToArray();
        byte[] authName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, (uint)TpmRh.TPM_RH_OWNER);
        byte[] firstCpHash = new byte[Sha256DigestSize];
        Array.Fill(firstCpHash, (byte)0x11);
        byte[] secondCpHash = new byte[Sha256DigestSize];
        Array.Fill(secondCpHash, (byte)0x22);

        (byte[] timeoutBytes, byte[] ticketDigestBytes, TpmStConstants ticketTag, TpmiRhHierarchy ticketHierarchy) minted =
            await MintPolicySecretTicketAsync(tpm, (uint)TpmRh.TPM_RH_OWNER, policyRef, pool).ConfigureAwait(false);

        byte[] tamperedDigest = (byte[])minted.ticketDigestBytes.Clone();
        tamperedDigest[^1] ^= 0xFF;

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            //First replay: a non-empty cpHashA, but a tampered ticket digest. Must fail WITHOUT latching
            //firstCpHash onto the session.
            using TpmtTkAuth tamperedTicket = TpmtTkAuth.Create(minted.ticketTag, minted.ticketHierarchy, tamperedDigest, pool);
            TpmResult<PolicyTicketResponse> firstResult = await tpm.PolicyTicketAsync(
                sessionHandle, minted.timeoutBytes, firstCpHash, policyRef, authName, tamperedTicket, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(firstResult.IsSuccess, "A tampered ticket digest must be rejected.");
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 4), firstResult.ResponseCode, "A tampered ticket digest must be refused with TPM_RC_TICKET at ticket, parameter 5 of Table 148.");

            //Second assertion, same session: a genuine PolicySecret authorization over a DIFFERENT cpHashA. If
            //the failed first replay had latched firstCpHash, this would be rejected with TPM_RC_CPHASH instead
            //of succeeding.
            TpmResult<PolicySecretResponse> secondResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_OWNER, sessionHandle, ReadOnlyMemory<byte>.Empty, secondCpHash, ReadOnlyMemory<byte>.Empty, 0, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(secondResult.IsSuccess, $"PolicySecret with a different cpHashA after a failed ticket replay must succeed: '{secondResult.ResponseCode}'.");
            secondResult.Value.Dispose();
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A ticket digest tampered by one flipped octet fails the HMAC recompute and is rejected with
    /// <c>TPM_RC_TICKET</c> (TPM 2.0 Library Part 3, clause 23.5.1, printed page 221: "If these tickets match,
    /// then the TPM will create a TPM2B_NAME (objectName) using authName and update the context of
    /// policySession") — the constant-time
    /// <c>CryptographicOperations.FixedTimeEquals</c> compare this simulator uses for every ticket check.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithATamperedTicketDigestReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] policyRef = "policyticket-tamper-ref"u8.ToArray();
        byte[] authName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, (uint)TpmRh.TPM_RH_OWNER);

        (byte[] timeoutBytes, byte[] ticketDigestBytes, TpmStConstants ticketTag, TpmiRhHierarchy ticketHierarchy) minted =
            await MintPolicySecretTicketAsync(tpm, (uint)TpmRh.TPM_RH_OWNER, policyRef, pool).ConfigureAwait(false);

        byte[] tamperedDigest = (byte[])minted.ticketDigestBytes.Clone();
        tamperedDigest[^1] ^= 0xFF;

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            using TpmtTkAuth tamperedTicket = TpmtTkAuth.Create(minted.ticketTag, minted.ticketHierarchy, tamperedDigest, pool);
            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                sessionHandle, minted.timeoutBytes, ReadOnlyMemory<byte>.Empty, policyRef, authName, tamperedTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(ticketResult.IsSuccess, "A tampered ticket digest must be rejected.");
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 4), ticketResult.ResponseCode, "A tampered ticket digest must be refused with TPM_RC_TICKET at ticket, parameter 5 of Table 148.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A ticket replayed with a DIFFERENT <c>hierarchy</c> than the one it was actually minted under fails the
    /// HMAC recompute (the caller-supplied hierarchy is used AS-IS to select the proof, never independently
    /// re-derived) and is rejected with the same <c>TPM_RC_TICKET</c> a tampered digest gets — not a distinct
    /// "wrong hierarchy" code (TPM 2.0 Library Part 3, clause 23.5.1, printed page 221; Part 4's
    /// <c>TPM2_PolicyTicket()</c> passes <c>in-&gt;ticket.hierarchy</c> straight into
    /// <c>TicketComputeAuth</c>).
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithAWrongHierarchyReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] policyRef = "policyticket-wronghierarchy-ref"u8.ToArray();
        byte[] authName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, (uint)TpmRh.TPM_RH_OWNER);

        (byte[] timeoutBytes, byte[] ticketDigestBytes, TpmStConstants ticketTag, TpmiRhHierarchy ticketHierarchy) minted =
            await MintPolicySecretTicketAsync(tpm, (uint)TpmRh.TPM_RH_OWNER, policyRef, pool).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            //The original digest bytes, unmodified, replayed against a DIFFERENT hierarchy constant.
            using TpmtTkAuth wrongHierarchyTicket = TpmtTkAuth.Create(minted.ticketTag, TpmiRhHierarchy.Endorsement, minted.ticketDigestBytes, pool);
            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                sessionHandle, minted.timeoutBytes, ReadOnlyMemory<byte>.Empty, policyRef, authName, wrongHierarchyTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(ticketResult.IsSuccess, "A ticket replayed against the wrong hierarchy must be rejected.");
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 4), ticketResult.ResponseCode, "A ticket replayed against the wrong hierarchy must be refused with TPM_RC_TICKET at ticket, parameter 5 of Table 148.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A genuine, untampered ticket replayed with a DIFFERENT <c>policyRef</c> than the one it was minted under
    /// fails the HMAC recompute — equation 12 (TPM 2.0 Library Part 2, Table 114) folds <c>policyRef</c> into
    /// the ticket digest — and is rejected with <c>TPM_RC_TICKET</c> (TPM 2.0 Library Part 3, clause 23.5.1):
    /// the digest and hierarchy are the ones actually minted; only the caller-supplied <c>policyRef</c> differs.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithAMismatchedPolicyRefReturnsTicket()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] mintedPolicyRef = "policyticket-mismatch-minted-ref"u8.ToArray();
        byte[] replayedPolicyRef = "policyticket-mismatch-replayed-ref"u8.ToArray();
        byte[] authName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, (uint)TpmRh.TPM_RH_OWNER);

        (byte[] timeoutBytes, byte[] ticketDigestBytes, TpmStConstants ticketTag, TpmiRhHierarchy ticketHierarchy) minted =
            await MintPolicySecretTicketAsync(tpm, (uint)TpmRh.TPM_RH_OWNER, mintedPolicyRef, pool).ConfigureAwait(false);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            //The original ticket octets and hierarchy, unmodified, replayed against a DIFFERENT policyRef.
            using TpmtTkAuth genuineTicket = TpmtTkAuth.Create(minted.ticketTag, minted.ticketHierarchy, minted.ticketDigestBytes, pool);
            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                sessionHandle, minted.timeoutBytes, ReadOnlyMemory<byte>.Empty, replayedPolicyRef, authName, genuineTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(ticketResult.IsSuccess, "A ticket replayed under a different policyRef must be rejected.");
            Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 4), ticketResult.ResponseCode, "A ticket replayed under a different policyRef must be refused with TPM_RC_TICKET at ticket, parameter 5 of Table 148.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An illegal <c>TPMT_TK_AUTH.tag</c> (neither <c>TPM_ST_AUTH_SIGNED</c> nor <c>TPM_ST_AUTH_SECRET</c>)
    /// is rejected with <c>TPM_RC_TAG</c> at the wire reader (Part 2, Table 114: "TPM_RC_TAG error returned when
    /// tag is not TPM_ST_AUTH_*") — the only place this constraint is actually enforced, since the
    /// re-verification recompute has no independent tag-legality check of its own (an illegal tag would still
    /// recompute a comparable, if forgery-resistant, HMAC).
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithAnIllegalTicketTagReturnsTag()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            byte[] zeroTimeout = new byte[8];
            using TpmtTkAuth illegalTicket = TpmtTkAuth.Create((TpmStConstants)0x1234, TpmiRhHierarchy.Null, new byte[Sha256DigestSize], pool);

            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                sessionHandle, zeroTimeout, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, illegalTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(ticketResult.IsSuccess, "An illegal ticket tag must be rejected.");
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TAG, 4), ticketResult.ResponseCode,
                "Table 148: ticket is TPM2_PolicyTicket()'s fifth parameter (index 4).");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPMT_TK_AUTH.hierarchy</c> is typed <c>TPMI_RH_HIERARCHY+</c> (TPM 2.0 Library Part 2, Table 114):
    /// its legal set is exactly <c>{TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT, TPM_RH_NULL}</c>. A
    /// ticket carrying a hierarchy value outside that set — for example a transient-object-range handle — is
    /// rejected with <c>TPM_RC_VALUE</c> at the wire reader, the same layer <c>TPMT_TK_AUTH.tag</c>'s own
    /// legality is enforced at, and for the identical reason: the re-verification recompute derives whatever
    /// proof the caller's hierarchy names with no legality check of its own.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithAnIllegalHierarchyReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            byte[] zeroTimeout = new byte[8];
            using TpmtTkAuth illegalHierarchyTicket = TpmtTkAuth.Create(TpmStConstants.TPM_ST_AUTH_SECRET, TpmiRhHierarchy.FromValue(TpmHcConstants.HR_TRANSIENT), new byte[Sha256DigestSize], pool);

            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                sessionHandle, zeroTimeout, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, illegalHierarchyTicket, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(ticketResult.IsSuccess, "A ticket hierarchy outside TPMI_RH_HIERARCHY+'s legal set must be rejected.");
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 4), ticketResult.ResponseCode,
                "Table 148: ticket is TPM2_PolicyTicket()'s fifth parameter (index 4).");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The independent equation 12 known-answer test: hand-assembles <c>tag || cpHash || policyRef || authName
    /// || timeout || timeEpoch || resetCount</c> (TPM 2.0 Library Part 2, clause 10.6.6, Table 114) and HMACs
    /// it with a proof and a TimeEpoch both reproduced from the injected seed's own public, well-known
    /// derivation algorithms (SHA-256(seed || hierarchy) for the proof; one FNV-1a fold plus one MurmurHash3
    /// 64-bit finalizer regeneration for TimeEpoch) — comparing the result against a production-minted ticket.
    /// A zero clock-advance quantum pins TimeEpoch's regeneration discriminant (the free-running Clock at the
    /// single completed <c>TPM2_Startup()</c>) at zero; a negative expiration with an empty caller nonceTPM
    /// makes both conditional equation-12 terms present (a non-zero timeout includes <c>[timeEpoch]</c>;
    /// expires-on-reset includes <c>[resetCount]</c>), exercising the full formula, not a truncated case.
    /// </summary>
    [TestMethod]
    public async Task EquationTwelveTicketDigestIsAVerifiableHmacOfTheInjectedSeedAndTimeEpoch()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        byte[] seed = Convert.FromHexString("A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90");

        using var simulator = new TpmSimulator("tpm-in-house-policyticket-kat", seed: seed, clockAdvanceQuantumMs: 0, rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] cpHash = await ComputeSha256Async("policyticket-kat-cphash"u8.ToArray(), pool, TestContext.CancellationToken).ConfigureAwait(false);
        byte[] policyRef = "policyticket-kat-ref"u8.ToArray();
        byte[] authName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, (uint)TpmRh.TPM_RH_OWNER);

        uint sessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

            using StartAuthSessionResponse session = startResult.Value;
            sessionHandle = session.SessionHandle.Value;

            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                (uint)TpmRh.TPM_RH_OWNER, sessionHandle, ReadOnlyMemory<byte>.Empty, cpHash, policyRef, -1, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret (ticket mint) failed: '{secretResult.ResponseCode}'.");

            byte[] actualDigest;
            byte[] timeoutWire;
            using(PolicySecretResponse minted = secretResult.Value)
            {
                Assert.AreEqual(TpmStConstants.TPM_ST_AUTH_SECRET, minted.PolicyTicket.Tag, "The ticket tag must be TPM_ST_AUTH_SECRET.");
                timeoutWire = minted.Timeout.ToArray();
                actualDigest = minted.PolicyTicket.Digest.ToArray();
            }

            ulong rawTimeout = BinaryPrimitives.ReadUInt64BigEndian(timeoutWire);
            Assert.AreNotEqual(0UL, rawTimeout & (1UL << 63), "An empty caller nonceTPM must set the expires-on-reset bit.");
            ulong timeout = rawTimeout & ~(1UL << 63);

            //Independent proof derivation: proof = SHA-256(seed || hierarchy).
            byte[] proof = await ComputeSha256Async(BuildProofInput(seed, (uint)TpmRh.TPM_RH_OWNER), pool, TestContext.CancellationToken).ConfigureAwait(false);

            //Independent TimeEpoch derivation: one FNV-1a fold of the seed at construction, then one
            //MurmurHash3-64 finalizer regeneration for the single completed TPM2_Startup() BringOperationalAsync
            //issued (a TPM Reset, since it is the very first Startup after power-on, TPM 2.0 Library Part 3,
            //clause 9.3) — the regeneration discriminant is zero because clockAdvanceQuantumMs is pinned to
            //zero above.
            uint timeEpoch = MixTimeEpoch(FnvFoldSeedToEpoch(seed), 0UL);

            //ResetCount: the very first Startup after power-on is unconditionally a TPM Reset, so ResetCount is
            //1 for every command in this test — a fixed fact about the command sequence, not a value that needs
            //reconstructing.
            const uint resetCount = 1u;

            byte[] message = BuildAuthTicketMessage((ushort)TpmStConstants.TPM_ST_AUTH_SECRET, cpHash, policyRef, authName, timeout, timeEpoch, resetCount);
            byte[] expectedDigest = await ComputeHmacSha256Async(message, proof, pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(
                expectedDigest.AsSpan().SequenceEqual(actualDigest),
                "The ticket digest must equal HMAC(proof, tag || cpHash || policyRef || authName || timeout || timeEpoch || resetCount) — equation 12.");
        }
        finally
        {
            await FlushIfPresentAsync(tpm, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Mints a real <c>TPM_ST_AUTH_SECRET</c> ticket via <c>TPM2_PolicySecret()</c> with an empty cpHashA/nonceTPM
    /// and a large negative expiration, on its own session (started and flushed within this call), returning the
    /// wire-copied timeout and ticket bytes for the caller to replay elsewhere.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="authHandle">The entity whose authorization the ticket binds to.</param>
    /// <param name="policyRef">The opaque policy qualifier the ticket is bound to.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The minted ticket's wire timeout, digest, tag, and hierarchy.</returns>
    private async Task<(byte[] TimeoutBytes, byte[] TicketDigestBytes, TpmStConstants TicketTag, TpmiRhHierarchy TicketHierarchy)> MintPolicySecretTicketAsync(
        TpmDevice tpm, uint authHandle, ReadOnlyMemory<byte> policyRef, BaseMemoryPool pool)
    {
        TpmResult<StartAuthSessionResponse> startResult = await tpm.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (mint) failed: '{startResult.ResponseCode}'.");

        using StartAuthSessionResponse session = startResult.Value;
        uint sessionHandle = session.SessionHandle.Value;
        try
        {
            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                authHandle, sessionHandle, ReadOnlyMemory<byte>.Empty, ReadOnlyMemory<byte>.Empty, policyRef, -3600, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret (ticket mint) failed: '{secretResult.ResponseCode}'.");

            using PolicySecretResponse minted = secretResult.Value;
            Assert.IsFalse(minted.PolicyTicket.IsNull, "A negative expiration must mint a real ticket.");

            return (minted.Timeout.ToArray(), minted.PolicyTicket.Digest.ToArray(), minted.PolicyTicket.Tag, minted.PolicyTicket.Hierarchy);
        }
        finally
        {
            _ = await tpm.FlushContextAsync(sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates an ECC P-256 ECDSA/SHA-256 signing key under the owner hierarchy, used as PolicySigned's authObject.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response for the authority key.</returns>
    private async Task<CreatePrimaryResponse> CreateEccAuthorityKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 authority key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Builds <c>aHash = H_authAlg(nonceTPM || expiration || cpHashA || policyRef)</c> (TPM 2.0 Library Part 3,
    /// clause 23.3, equation 13) through the registered async digest seam.
    /// </summary>
    private static async Task<byte[]> ComputeAHashAsync(
        ReadOnlyMemory<byte> nonceTpm, int expiration, ReadOnlyMemory<byte> cpHashA, ReadOnlyMemory<byte> policyRef,
        int hashLength, Tag hashTag, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] message = new byte[nonceTpm.Length + sizeof(int) + cpHashA.Length + policyRef.Length];
        var writer = new TpmWriter(message);
        writer.WriteBytes(nonceTpm.Span);
        writer.WriteInt32(expiration);
        writer.WriteBytes(cpHashA.Span);
        writer.WriteBytes(policyRef.Span);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            message, hashLength, hashTag, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Concatenates the ECDSA r and s components into the IEEE P1363 <c>r ‖ s</c> form, left-padding each to the
    /// P-256 field width (32 bytes).
    /// </summary>
    private static Signature ConcatenateP1363(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s, BaseMemoryPool pool)
    {
        const int P256ComponentSize = 32;
        IMemoryOwner<byte> owner = pool.Rent(2 * P256ComponentSize);
        Span<byte> destination = owner.Memory.Span[..(2 * P256ComponentSize)];
        destination.Clear();
        CopyFixed(r, destination[..P256ComponentSize]);
        CopyFixed(s, destination.Slice(P256ComponentSize, P256ComponentSize));

        return new Signature(owner, CryptoTags.P256Signature);

        static void CopyFixed(ReadOnlySpan<byte> value, Span<byte> destination)
        {
            if(value.Length <= destination.Length)
            {
                value.CopyTo(destination[^value.Length..]);
            }
            else
            {
                value[^destination.Length..].CopyTo(destination);
            }
        }
    }

    /// <summary>
    /// Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).
    /// </summary>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            message, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>Computes an HMAC-SHA256 through the registered HMAC seam.</summary>
    private static async Task<byte[]> ComputeHmacSha256Async(ReadOnlyMemory<byte> message, ReadOnlyMemory<byte> key, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        using HmacValue hmac = await CryptographicKeyEvents.ComputeHmacAsync(
            message, key, Sha256DigestSize, CryptoTags.HmacSha256Value, pool, cancellationToken: cancellationToken).ConfigureAwait(false);

        return hmac.AsReadOnlySpan().ToArray();
    }

    /// <summary>The proof-derivation hash input: the TPM seed followed by the hierarchy handle.</summary>
    private static byte[] BuildProofInput(byte[] seed, uint hierarchy)
    {
        byte[] input = new byte[seed.Length + sizeof(uint)];
        var writer = new TpmWriter(input);
        writer.WriteBytes(seed);
        writer.WriteUInt32(hierarchy);

        return input;
    }

    /// <summary>
    /// Equation 12's own field order, byte-for-byte (TPM 2.0 Library Part 2, clause 10.6.6, Table 114):
    /// <c>tag || cpHash || policyRef || authName || timeout || timeEpoch || resetCount</c>.
    /// </summary>
    private static byte[] BuildAuthTicketMessage(
        ushort tag, ReadOnlySpan<byte> cpHash, ReadOnlySpan<byte> policyRef, ReadOnlySpan<byte> authName,
        ulong timeout, uint timeEpoch, uint resetCount)
    {
        byte[] message = new byte[sizeof(ushort) + cpHash.Length + policyRef.Length + authName.Length + sizeof(ulong) + sizeof(uint) + sizeof(uint)];
        var writer = new TpmWriter(message);
        writer.WriteUInt16(tag);
        writer.WriteBytes(cpHash);
        writer.WriteBytes(policyRef);
        writer.WriteBytes(authName);
        writer.WriteUInt64(timeout);
        writer.WriteUInt32(timeEpoch);
        writer.WriteUInt32(resetCount);

        return message;
    }

    /// <summary>
    /// Reproduces the simulator's fold of the injected seed into TimeEpoch's initial value: the well-known,
    /// publicly specified FNV-1a hash (32-bit offset basis 2166136261, prime 16777619), independently
    /// implemented here from its public definition, not trusted from the implementation under test.
    /// </summary>
    private static uint FnvFoldSeedToEpoch(ReadOnlySpan<byte> seed)
    {
        const uint FnvOffsetBasis = 2166136261u;
        const uint FnvPrime = 16777619u;

        uint hash = FnvOffsetBasis;
        foreach(byte value in seed)
        {
            hash ^= value;
            hash *= FnvPrime;
        }

        return hash;
    }

    /// <summary>
    /// Reproduces the simulator's TimeEpoch regeneration on a completed <c>TPM2_Startup()</c>: the well-known
    /// MurmurHash3 64-bit finalizer bit-mixing <paramref name="currentEpoch"/> with a discriminant,
    /// independently implemented here from the finalizer's public definition.
    /// </summary>
    private static uint MixTimeEpoch(uint currentEpoch, ulong discriminant)
    {
        ulong mixed = ((ulong)currentEpoch << 32) ^ discriminant;
        mixed ^= mixed >> 33;
        mixed *= 0xff51afd7ed558ccdUL;
        mixed ^= mixed >> 33;
        mixed *= 0xc4ceb9fe1a85ec53UL;
        mixed ^= mixed >> 33;

        return (uint)mixed;
    }

    /// <summary>
    /// Mints a real <c>TPM_ST_AUTH_SECRET</c> ticket against <paramref name="authHandle"/> over a fresh policy
    /// session, supplying that session's own retained <c>nonceTPM</c> so the authorization is session-bound and
    /// <c>expiresOnReset</c> stays CLEAR (TPM 2.0 Library Part 3, clause 23.2.2), then flushes the minting
    /// session so the replay runs against a session that never saw the original command.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="authHandle">The permanent handle whose authorization the ticket stands in for.</param>
    /// <param name="policyRef">The opaque policy qualifier folded into the ticket and its digest.</param>
    /// <returns>The minted ticket's wire fields plus the authName the replay must present.</returns>
    private async Task<MintedTicket> MintSessionBoundSecretTicketAsync(TpmDevice tpm, uint authHandle, ReadOnlyMemory<byte> policyRef)
    {
        byte[] authName = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(authName, authHandle);

        uint mintSessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> mintStart = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(mintStart.IsSuccess, $"StartAuthSession (mint) failed: '{mintStart.ResponseCode}'.");

            using StartAuthSessionResponse mintSession = mintStart.Value;
            mintSessionHandle = mintSession.SessionHandle.Value;
            byte[] nonceTpm = mintSession.NonceTPM.AsReadOnlySpan().ToArray();

            TpmResult<PolicySecretResponse> secretResult = await tpm.PolicySecretAsync(
                authHandle, mintSessionHandle, nonceTpm, ReadOnlyMemory<byte>.Empty, policyRef, -3600, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(secretResult.IsSuccess, $"PolicySecret (ticket mint) failed: '{secretResult.ResponseCode}'.");

            using PolicySecretResponse minted = secretResult.Value;
            Assert.IsFalse(minted.PolicyTicket.IsNull, "A negative expiration must mint a real ticket.");

            return new MintedTicket(
                minted.Timeout.ToArray(), minted.PolicyTicket.Tag, minted.PolicyTicket.Hierarchy, minted.PolicyTicket.Digest.ToArray(), authName);
        }
        finally
        {
            await FlushIfPresentAsync(tpm, mintSessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Replays <paramref name="ticket"/> into a fresh policy session through <c>TPM2_PolicyTicket()</c> and
    /// returns the response code, so a caller can require the same replay to succeed before an event and to be
    /// refused after it.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="ticket">The minted ticket's wire fields.</param>
    /// <param name="policyRef">The opaque policy qualifier the ticket was minted with.</param>
    /// <returns>The response code <c>TPM2_PolicyTicket()</c> answered with.</returns>
    private async Task<TpmRcConstants> ReplayTicketAsync(TpmDevice tpm, MintedTicket ticket, ReadOnlyMemory<byte> policyRef)
    {
        uint replaySessionHandle = 0;
        try
        {
            TpmResult<StartAuthSessionResponse> replayStart = await tpm.StartPolicySessionAsync(
                SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(replayStart.IsSuccess, $"StartAuthSession (replay) failed: '{replayStart.ResponseCode}'.");

            using StartAuthSessionResponse replaySession = replayStart.Value;
            replaySessionHandle = replaySession.SessionHandle.Value;

            using TpmtTkAuth wireTicket = TpmtTkAuth.Create(ticket.Tag, ticket.Hierarchy, ticket.Digest, BaseMemoryPool.Shared);
            TpmResult<PolicyTicketResponse> ticketResult = await tpm.PolicyTicketAsync(
                replaySessionHandle, ticket.Timeout, ReadOnlyMemory<byte>.Empty, policyRef, ticket.AuthName, wireTicket, TestContext.CancellationToken).ConfigureAwait(false);

            //TpmResult exposes ResponseCode only for a TPM error, so an accepted replay names TPM_RC_SUCCESS
            //itself rather than reading a property that throws on exactly the outcome the pre-clear legs assert.
            return ticketResult.IsSuccess
                ? TpmRcConstants.TPM_RC_SUCCESS
                : ticketResult.ResponseCode;
        }
        finally
        {
            await FlushIfPresentAsync(tpm, replaySessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The wire fields of a minted <c>TPMT_TK_AUTH</c> plus the <c>authName</c> a replay must present, carried
    /// past the minting session's disposal so the replay depends on nothing still live.
    /// </summary>
    /// <param name="Timeout">The 8-octet <c>TPM2B_TIMEOUT</c> the mint returned.</param>
    /// <param name="Tag">The ticket's structure tag.</param>
    /// <param name="Hierarchy">The hierarchy whose proof keys the ticket.</param>
    /// <param name="Digest">The ticket's HMAC.</param>
    /// <param name="AuthName">The authorizing entity's Name - a permanent handle's own four octets.</param>
    private sealed record MintedTicket(byte[] Timeout, TpmStConstants Tag, TpmiRhHierarchy Hierarchy, byte[] Digest, byte[] AuthName);

    /// <summary>
    /// Creates a response codec registry covering the executor-driven commands these tests issue directly (the
    /// policy device verbs run through their own self-contained extension-method registries).
    /// </summary>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);

        return registry;
    }

    /// <summary>
    /// Flushes a transient session handle when one is present (non-zero), ignoring the result.
    /// </summary>
    private async Task FlushIfPresentAsync(TpmDevice tpm, uint handle)
    {
        if(handle == 0)
        {
            return;
        }

        _ = await tpm.FlushContextAsync(handle, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it
    /// through <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-policyticket", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
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
