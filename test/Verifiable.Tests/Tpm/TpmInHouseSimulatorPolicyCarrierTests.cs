using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves the pooled-carrier ownership of the enhanced-authorization state a policy session accumulates — the
/// policyDigest of TPM 2.0 Library Part 1, clause 16.7 and the latched cpHash of Part 3, clause 23.2.4 — and of
/// the wire parameters the assertion commands rent to feed them, against the in-house behavioural
/// <see cref="TpmSimulator"/>.
/// </summary>
/// <remarks>
/// <para>
/// The instrument is <see cref="MeteredHousePool"/>: a genuine <see cref="BaseMemoryPool"/> whose own rent and
/// return telemetry is observed, so nothing here depends on a seam in production code. Every digest and
/// qualifier driven through is deliberately NON-EMPTY, because an empty one parses to the shared dispose-immune
/// sentinel, which rents nothing and would make a balance assertion vacuous.
/// </para>
/// <para>
/// The commands are issued through <see cref="TpmCommandExecutor"/> with the metered pool rather than through
/// the <c>Extensions</c> verbs, because those compose their own <c>BaseMemoryPool.Shared</c> internally and the
/// simulator would then rent from a pool this instrument does not observe.
/// </para>
/// <para>
/// The invariant most of these read against is that a session holds exactly ONE live policyDigest no matter how
/// many assertions have run: each fold rents a fresh carrier and the install releases the superseded one, so a
/// chain of three assertions leaves the balance one above where the session started, never three.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorPolicyCarrierTests
{
    /// <summary>The policy session hash algorithm every session here is started with.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The width of the policyDigest a SHA-256 policy session carries.</summary>
    private const int DigestSize = 32;

    /// <summary>
    /// One octet wider than a <c>TPM2B_DIGEST</c> buffer may be (<c>{:sizeof(TPMU_HA)}</c>, TPM 2.0 Library
    /// Part 2, clause 10.3.2, Table 90) — the width the hand-framed parse-bound cases drive.
    /// </summary>
    private const int OverWideDigestSize = Tpm2bDigest.MaxSize + 1;

    /// <summary>
    /// One octet wider than a <c>TPM2B_TIMEOUT</c> buffer may be (<c>{:sizeof(UINT64)}</c>, TPM 2.0 Library
    /// Part 2, clause 10.3.10, Table 98).
    /// </summary>
    private const int OverWideTimeoutSize = Tpm2bTimeout.MaxSize + 1;

    /// <summary>The <c>TPMA_SESSION</c> octet a password slot carries: <c>continueSession</c> alone.</summary>
    private const byte ContinueSessionAttribute = 0x01;

    /// <summary>
    /// The policy qualifier the PolicySecret cases supply. Its 7-octet width keeps it clear of
    /// <see cref="DigestSize"/>, so a rent of the digest width is unambiguously a digest carrier.
    /// </summary>
    private static byte[] PolicyRef { get; } = [0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The Zero Digest a session's policyDigest starts at (TPM 2.0 Library Part 1, clause 16.7) is a shared
    /// instance per hash width that survives disposal: every unstarted and every just-reset session holds the
    /// same one at once, so one holder releasing it must leave it readable for all the others — the exemption the
    /// shared empty carriers already carry.
    /// </summary>
    [TestMethod]
    public void ZeroPolicyDigestSentinelSurvivesDisposalAndKeepsItsWidth()
    {
        using Tpm2bDigest zero = Tpm2bDigest.Zero(TpmiAlgHash.FromValue(SessionAlg));

        Assert.AreEqual(DigestSize, zero.Size, "The Zero Digest must carry the session hash's full digest width.");
        Assert.AreSequenceEqual(new byte[DigestSize], zero.AsReadOnlySpan().ToArray(), "The Zero Digest must be all zero octets.");

        zero.Dispose();
        zero.Dispose();

        Assert.AreEqual(DigestSize, zero.Size, "Disposal must not shrink the shared Zero Digest.");
        Assert.AreSequenceEqual(
            new byte[DigestSize], zero.AsReadOnlySpan().ToArray(),
            "A holder's disposal must leave the shared Zero Digest readable for every other holder.");
        Assert.AreSame(
            zero, Tpm2bDigest.Zero(TpmiAlgHash.FromValue(SessionAlg)),
            "The Zero Digest of one width is a single shared instance, not a fresh allocation per caller.");
    }

    /// <summary>
    /// The Zero Digest is width-specific and is NOT the empty carrier: an extension formula sizes its scratch
    /// from the current digest's own length (TPM 2.0 Library Part 1, clause 16.7), so folding over a zero-LENGTH
    /// digest would produce a different value than folding over a digest-width run of zeros.
    /// </summary>
    [TestMethod]
    public void ZeroPolicyDigestSentinelIsWidthSpecificAndDistinctFromTheEmptyCarrier()
    {
        Assert.AreEqual(
            TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA256), Tpm2bDigest.Zero(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA256)).Size,
            "The SHA-256 Zero Digest must be exactly the width the policyDigest formula sizes for SHA-256.");
        Assert.AreEqual(
            TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA384), Tpm2bDigest.Zero(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA384)).Size,
            "The SHA-384 Zero Digest must be exactly the width the policyDigest formula sizes for SHA-384.");
        Assert.AreEqual(
            TpmPolicyDigest.Size(TpmAlgIdConstants.TPM_ALG_SHA512), Tpm2bDigest.Zero(TpmiAlgHash.FromValue(TpmAlgIdConstants.TPM_ALG_SHA512)).Size,
            "The SHA-512 Zero Digest must be exactly the width the policyDigest formula sizes for SHA-512.");

        Assert.AreEqual(0, Tpm2bDigest.Empty.Size, "The empty carrier carries no octets at all, which is what makes it unusable as a starting policyDigest.");
    }

    /// <summary>
    /// A session's very first assertion folds over a Zero Digest of the session hash's width, not over an empty
    /// buffer (TPM 2.0 Library Part 1, clause 16.7): the value <c>TPM2_PolicyGetDigest()</c> reports after one
    /// <c>TPM2_PolicyCommandCode()</c> reproduces the host predictor's own
    /// <c>H(zeros ‖ TPM_CC_PolicyCommandCode ‖ code)</c> byte for byte.
    /// </summary>
    [TestMethod]
    public async Task FirstAssertionFoldsOverAZeroDigestOfTheSessionHashWidth()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, trackingPool.Pool, sessionHandle, TpmCcConstants.TPM_CC_Unseal).ConfigureAwait(false);

            byte[] expected = new byte[DigestSize];
            _ = TpmPolicyDigest.ExtendForCommandCode(new byte[DigestSize], TpmCcConstants.TPM_CC_Unseal, SessionAlg, expected, trackingPool.Pool);

            byte[] reported = await ReadPolicyDigestAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            Assert.AreSequenceEqual(
                expected, reported,
                "The first assertion must fold over a digest-width run of zeros, which is the only starting value the host predictor also assumes.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A chain of assertions on one session holds exactly ONE live policyDigest: each fold rents a fresh carrier
    /// at the session's digest width and the install releases the superseded one (TPM 2.0 Library Part 1, clause
    /// 16.7.3's wholesale replacement), so three assertions leave the balance one above the session's own start,
    /// never three above it.
    /// </summary>
    [TestMethod]
    public async Task PolicyAssertionChainHoldsExactlyOneLivePolicyDigest()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            await AssertPcrAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            Assert.AreEqual(
                baseline + 1, trackingPool.OutstandingCount,
                "The first assertion must leave exactly one live policyDigest — the Zero Digest it superseded rents nothing.");

            await AssertCommandCodeAsync(tpm, registry, trackingPool.Pool, sessionHandle, TpmCcConstants.TPM_CC_Unseal).ConfigureAwait(false);
            Assert.AreEqual(
                baseline + 1, trackingPool.OutstandingCount,
                "The second assertion must release the digest it superseded, so the session still holds exactly one.");

            await AssertAuthValueAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            Assert.AreEqual(
                baseline + 1, trackingPool.OutstandingCount,
                "Three assertions must still leave one live policyDigest, not three.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A refusal in the middle of a policy chain leaves the session exactly as it found it: a real (non-trial)
    /// <c>TPM2_PolicyPCR()</c> whose caller-supplied digest does not match the live composite is refused with
    /// <c>TPM_RC_VALUE</c> (TPM 2.0 Library Part 3, clause 23.7), and both the parse-rented digest carrier and the
    /// fold's own destination reach the pool again.
    /// </summary>
    [TestMethod]
    public async Task RefusedPolicyPcrMidChainLeavesExactlyTheSessionsOwnPolicyDigestOutstanding()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, trackingPool.Pool, sessionHandle, TpmCcConstants.TPM_CC_Unseal).ConfigureAwait(false);

            long baseline = trackingPool.OutstandingCount;

            //The client-side input and selection are scoped so their own rentals return before the balance is read.
            {
                using TpmlPcrSelection selection = TpmlPcrSelection.Create(SessionAlg, [0], trackingPool.Pool);
                using PolicyPcrInput input = PolicyPcrInput.Create(sessionHandle, DistinctDigest(0x70), selection, trackingPool.Pool);
                TpmResult<PolicyPcrResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyPcrResponse>(
                    tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_VALUE, result.ResponseCode,
                    "A real session binds to the live composite, so a mismatching caller digest is TPM_RC_VALUE.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusal must return the parse-rented pcrDigest carrier and leave the session's own policyDigest untouched.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_PolicyGetDigest()</c> BORROWS the session's own policyDigest carrier rather than taking it over
    /// (TPM 2.0 Library Part 3, clause 23.6 is a pure read), so framing the response must not release it: a
    /// further assertion on the same session still folds over the value, and the balance is unchanged by the read.
    /// </summary>
    [TestMethod]
    public async Task PolicyGetDigestBorrowsTheSessionDigestSoTheNextAssertionStillFoldsOverIt()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, trackingPool.Pool, sessionHandle, TpmCcConstants.TPM_CC_Unseal).ConfigureAwait(false);

            long baseline = trackingPool.OutstandingCount;
            byte[] afterFirst = await ReadPolicyDigestAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "Reading the digest must rent nothing that outlives the response and must release nothing the session owns.");

            await AssertAuthValueAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);

            byte[] expected = new byte[DigestSize];
            _ = TpmPolicyDigest.ExtendForAuthValue(afterFirst, SessionAlg, expected, trackingPool.Pool);

            byte[] afterSecond = await ReadPolicyDigestAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            Assert.AreSequenceEqual(
                expected, afterSecond,
                "The assertion after the read must fold over the same digest the read reported, which it could not if framing had released the carrier.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The first-writer-wins cpHash latch of TPM 2.0 Library Part 3, clause 23.2.4 is a conditional TRANSFER: an
    /// unlatched session takes over the carrier the parser rented, and a later assertion re-proposing the SAME
    /// value has its own carrier released instead of a second one accumulating on the session.
    /// </summary>
    [TestMethod]
    public async Task LatchingTheSameCpHashTwiceLeavesTheSessionHoldingExactlyOne()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            byte[] cpHash = DistinctDigest(0x30);
            long baseline = trackingPool.OutstandingCount;

            TpmResult<PolicySecretResponse> first = await AssertSecretAsync(
                tpm, registry, trackingPool.Pool, sessionHandle, cpHash, expiration: 0).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"PolicySecret against the owner hierarchy's empty authValue must succeed: '{first.ResponseCode}'.");
            first.Value.Dispose();

            long afterLatch = trackingPool.OutstandingCount;
            Assert.AreEqual(
                baseline + 2, afterLatch,
                "The latch must leave the session holding the transferred cpHash alongside its one live policyDigest.");

            TpmResult<PolicySecretResponse> second = await AssertSecretAsync(
                tpm, registry, trackingPool.Pool, sessionHandle, cpHash, expiration: 0).ConfigureAwait(false);
            Assert.IsTrue(second.IsSuccess, $"Re-proposing the latched cpHash must succeed: '{second.ResponseCode}'.");
            second.Value.Dispose();

            Assert.AreEqual(
                afterLatch, trackingPool.OutstandingCount,
                "An equal re-proposal must release its own cpHash carrier rather than accumulate a second one on the session.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A cpHash that differs from the one already latched is refused with <c>TPM_RC_CPHASH</c> (TPM 2.0 Library
    /// Part 3, clause 23.2.4's immutability rule), and the refusing arm returns both the rejected cpHash carrier
    /// and the qualifier the same request rented.
    /// </summary>
    [TestMethod]
    public async Task LatchingADifferentCpHashIsRefusedAndReturnsTheRejectedCarriers()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            TpmResult<PolicySecretResponse> first = await AssertSecretAsync(
                tpm, registry, trackingPool.Pool, sessionHandle, DistinctDigest(0x30), expiration: 0).ConfigureAwait(false);
            Assert.IsTrue(first.IsSuccess, $"The latching assertion must succeed: '{first.ResponseCode}'.");
            first.Value.Dispose();

            long afterLatch = trackingPool.OutstandingCount;

            TpmResult<PolicySecretResponse> second = await AssertSecretAsync(
                tpm, registry, trackingPool.Pool, sessionHandle, DistinctDigest(0x40), expiration: 0).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_CPHASH, second.ResponseCode,
                "A different, non-empty cpHash against a latched session is TPM_RC_CPHASH, never a silent replacement.");

            Assert.AreEqual(
                afterLatch, trackingPool.OutstandingCount,
                "The refusing arm must return the rejected cpHash and the qualifier it rented, leaving the latched carrier in place.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicySecret()</c> that requests a ticket (a negative expiration, TPM 2.0 Library Part 3,
    /// clause 23.4) folds inside the minting effect, so that effect owns the qualifier it consumed and returns
    /// the folded digest for the session to install — leaving one live policyDigest and the latched cpHash, and
    /// nothing else, once the response has been consumed. The digest it installed is the one the host predictor
    /// computes for <c>PolicySecret</c>'s own <c>PolicyUpdate</c> over the authorizing entity's Name and the
    /// qualifier, so the fold that moved into the effect is still the command's own formula.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithATicketReturnsEveryCarrierTheMintingEffectConsumed()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            TpmResult<PolicySecretResponse> result = await AssertSecretAsync(
                tpm, registry, trackingPool.Pool, sessionHandle, DistinctDigest(0x30), expiration: -60).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A ticket-requesting PolicySecret must succeed: '{result.ResponseCode}'.");
            result.Value.Dispose();

            Assert.AreEqual(
                baseline + 2, trackingPool.OutstandingCount,
                "The minting effect must leave exactly the session's own policyDigest and latched cpHash outstanding once the response is consumed.");

            byte[] expected = new byte[DigestSize];
            _ = TpmPolicyDigest.ExtendForSecret(new byte[DigestSize], PermanentHandleName(TpmRh.TPM_RH_OWNER), PolicyRef, SessionAlg, expected, trackingPool.Pool);

            byte[] reported = await ReadPolicyDigestAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            Assert.AreSequenceEqual(
                expected, reported,
                "The fold the minting effect performed must be PolicySecret's own PolicyUpdate, not another command's.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicySecret()</c> refused on its authorization (a wrong value against the owner hierarchy is a
    /// plain <c>TPM_RC_BAD_AUTH</c>, TPM 2.0 Library Part 1, clause 16.8.1) never reaches the fold, so the
    /// refusing arm is the terminal owner of both wire carriers the parser rented.
    /// </summary>
    [TestMethod]
    public async Task RefusedPolicySecretReturnsItsCpHashAndQualifierCarriers()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            //The client-side input and password session are scoped so their own rentals return before the balance
            //is read; what is left is only what the simulator kept.
            {
                using PolicySecretInput input = PolicySecretInput.Create(
                    (uint)TpmRh.TPM_RH_OWNER, sessionHandle, ReadOnlySpan<byte>.Empty, DistinctDigest(0x30), PolicyRef, expiration: 0, trackingPool.Pool);
                using TpmPasswordSession wrongOwnerAuth = TpmPasswordSession.Create(DistinctDigest(0x60), trackingPool.Pool);

                TpmResult<PolicySecretResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, input, [wrongOwnerAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode,
                    "The owner hierarchy is not dictionary-attack protected, so a wrong value is a plain bad authorization.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusing arm must return the parse-rented cpHash and qualifier carriers, and must fold nothing.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_PolicyOR()</c>'s <c>pHashList</c> rides an owned <c>TPML_DIGEST</c> (TPM 2.0 Library Part 2,
    /// clause 10.8.5, Table 126), so every branch carrier the parser rented reaches the pool again — on the
    /// accepted arm through the fold that consumed the list, and on the refused arm through the request's own
    /// disposal.
    /// </summary>
    [TestMethod]
    public async Task PolicyOrReturnsEveryBranchCarrierOnBothArms()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint trialSession = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        uint realSession = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            ReadOnlyMemory<byte>[] branches = [DistinctDigest(0x10), DistinctDigest(0x20)];

            long trialBaseline = trackingPool.OutstandingCount;
            var trialInput = new PolicyOrInput(trialSession, branches);
            TpmResult<PolicyOrResponse> trialResult = await TpmCommandExecutor.ExecuteAsync<PolicyOrResponse>(
                tpm, trialInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(trialResult.IsSuccess, $"A trial session skips the branch match: '{trialResult.ResponseCode}'.");
            Assert.AreEqual(
                trialBaseline + 1, trackingPool.OutstandingCount,
                "The fold must consume the whole branch list and leave only the session's own advanced policyDigest.");

            long realBaseline = trackingPool.OutstandingCount;
            var realInput = new PolicyOrInput(realSession, branches);
            TpmResult<PolicyOrResponse> realResult = await TpmCommandExecutor.ExecuteAsync<PolicyOrResponse>(
                tpm, realInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), realResult.ResponseCode,
                "A real session whose current digest matches no branch is TPM_RC_VALUE (Part 3, clause 23.6).");
            Assert.AreEqual(
                realBaseline, trackingPool.OutstandingCount,
                "The refusing arm must return every branch carrier the parser rented.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, realSession).ConfigureAwait(false);
            await FlushAsync(tpm, registry, trackingPool.Pool, trialSession).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Flushing a policy session is the ownership-end boundary for everything it accumulated (TPM 2.0 Library
    /// Part 1, clause 16.6.18's "clear all associated context"): the advanced policyDigest and the latched
    /// cpHash both reach the pool with the session's own key and nonce.
    /// </summary>
    [TestMethod]
    public async Task FlushingAPolicySessionReturnsItsPolicyDigestAndLatchedCpHash()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);

        TpmResult<PolicySecretResponse> result = await AssertSecretAsync(
            tpm, registry, trackingPool.Pool, sessionHandle, DistinctDigest(0x30), expiration: 0).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PolicySecret must succeed: '{result.ResponseCode}'.");
        result.Value.Dispose();

        Assert.AreEqual(
            baseline + 3, trackingPool.OutstandingCount,
            "A latched session holds three carriers the pool can see: its retained nonceTPM, its policyDigest, and its cpHash.");

        await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Eviction must release every carrier the session owned, the policyDigest and the cpHash included.");
    }

    /// <summary>
    /// A self-referential session-authorized <c>TPM2_PolicySecret()</c> — the POLICY session authorizing the call
    /// IS the one being extended — is NET ZERO on the pool: it folds a fresh policyDigest AND latches the
    /// caller's cpHash, and then, in the same command, the context reset of TPM 2.0 Library Part 3, clause
    /// 23.2.4 wipes that very digest back to the Zero Digest and unlatches that very cpHash, so both carriers are
    /// created and destroyed inside one command.
    /// </summary>
    /// <remarks>
    /// The reset is legitimate and is the reference's own behaviour: <c>UpdateInternalSession</c> fires for the
    /// authorization-area session on every successful use, regardless of what the command itself did to that
    /// session's digest. The hierarchy must carry an authorization policy first, or the POLICY authorizer is
    /// refused with <c>TPM_RC_AUTH_UNAVAILABLE</c> before any of this is reached (Part 1, clause 10.2, Table 8).
    /// </remarks>
    [TestMethod]
    public async Task SelfReferentialPolicySecretOverAPolicySessionIsNetZeroOnThePool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] authValueDigest = new byte[DigestSize];
        _ = TpmPolicyDigest.ExtendForAuthValue(new byte[DigestSize], SessionAlg, authValueDigest, trackingPool.Pool);
        await InstallEndorsementPolicyAsync(tpm, registry, trackingPool.Pool, authValueDigest).ConfigureAwait(false);

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound policy) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse startResponse = startResult.Value;
        uint sessionHandle = startResponse.SessionHandle.Value;
        using var authorizer = new TpmSession(new TpmHandle(sessionHandle), startResponse.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), trackingPool.Pool);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            await AssertAuthValueAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            Assert.AreEqual(
                baseline + 1, trackingPool.OutstandingCount,
                "The PolicyAuthValue fold must leave the session holding one live policyDigest.");

            {
                using PolicySecretInput input = PolicySecretInput.Create(
                    (uint)TpmRh.TPM_RH_ENDORSEMENT, sessionHandle, ReadOnlySpan<byte>.Empty, DistinctDigest(0x30), PolicyRef, expiration: 0, trackingPool.Pool);
                TpmResult<PolicySecretResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, input, [authorizer], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"A POLICY session with isAuthValueNeeded SET must authorize PolicySecret: '{result.ResponseCode}'.");
                result.Value.Dispose();
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The context reset must release both the digest this very command folded and the cpHash it latched, so the command is net zero on the pool.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyTicket()</c> whose <c>timeout</c> declares more octets than a <c>TPM2B_TIMEOUT</c> buffer
    /// may carry is refused with a <c>TPM_RC_SIZE</c>, parameter-encoded to the same index at the wire read — the <c>{:sizeof(UINT64)}</c> bound
    /// of TPM 2.0 Library Part 2, clause 10.3.10, Table 98, answered ahead of the command body exactly where
    /// the reference's own unmarshal answers it, so not even a TRIAL session's own outright rejection precedes
    /// it — and a parse refused there rents nothing at all.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithAnOverWideTimeoutIsRefusedAtTheParseWithoutRenting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            byte[] body = BuildPolicyTicketBody(
                sessionHandle, DistinctOctets(0x11, OverWideTimeoutSize), DistinctDigest(0x30), PolicyRef,
                DistinctOctets(0x41, sizeof(uint)), (ushort)TpmStConstants.TPM_ST_AUTH_SECRET, (uint)TpmRh.TPM_RH_OWNER, DistinctDigest(0x50));

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyTicket, body).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
                "Table 148: timeout is TPM2_PolicyTicket()'s first parameter (index 0); a width past sizeof(UINT64) is parameter-encoded TPM_RC_SIZE there, whatever the session is.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A parse refused on a wire bound must rent nothing, so the balance cannot move.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyTicket()</c> whose <c>timeout</c> is narrower than 8 octets but within
    /// <c>TPM2B_TIMEOUT</c>'s own bound passes the parse and reaches the command body, where a TRIAL session is
    /// rejected outright with <c>TPM_RC_ATTRIBUTES</c> before the command-specific "exactly 8 octets" rule is
    /// ever evaluated — the order Part 4's <c>TPM2_PolicyTicket()</c> gives, where
    /// <c>if(session-&gt;attributes.isTrialPolicy) return TPM_RCS_ATTRIBUTES + RC_PolicyTicket_policySession;</c>
    /// stands ahead of <c>if(in-&gt;timeout.t.size != sizeof(UINT64)) return TPM_RCS_SIZE +
    /// RC_PolicyTicket_timeout;</c>. This is the narrow delta that fixes where each of the two size rules lives.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithAShortTimeoutOnATrialSessionIsRefusedOnTheSessionAttributes()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            byte[] body = BuildPolicyTicketBody(
                sessionHandle, DistinctOctets(0x11, sizeof(uint)), DistinctDigest(0x30), PolicyRef,
                DistinctOctets(0x41, sizeof(uint)), (ushort)TpmStConstants.TPM_ST_AUTH_SECRET, (uint)TpmRh.TPM_RH_OWNER, DistinctDigest(0x50));

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyTicket, body).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 0), code,
                "A ticket replay against a trial session is refused on the session itself, ahead of the command's own exactly-8 timeout rule.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusing arm must return every carrier the parse rented for the accepted-width fields.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicySecret()</c> whose <c>cpHashA</c> declares more octets than a <c>TPM2B_DIGEST</c> buffer
    /// may carry (<c>{:sizeof(TPMU_HA)}</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90) is refused with a
    /// <c>TPM_RC_SIZE</c>, parameter-encoded to the same index at the wire read, ahead of the rental whose own factory would refuse the same
    /// bound by throwing — so the refused parse rents nothing.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithAnOverWideCpHashIsRefusedAtTheParseWithoutRenting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            byte[] body = BuildPolicySecretBody(
                (uint)TpmRh.TPM_RH_OWNER, sessionHandle, DistinctDigest(0x60), DistinctOctets(0x21, OverWideDigestSize), PolicyRef, expiration: 0);

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_PolicySecret, body).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), code,
                "Table 146: cpHashA is TPM2_PolicySecret()'s second parameter (index 1); a width past sizeof(TPMU_HA) is parameter-encoded TPM_RC_SIZE there.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A parse refused on a wire bound must rent nothing, so the balance cannot move.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicySigned()</c> whose <c>cpHashA</c> declares more octets than a <c>TPM2B_DIGEST</c> buffer
    /// may carry (<c>{:sizeof(TPMU_HA)}</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90) is refused with a
    /// <c>TPM_RC_SIZE</c>, parameter-encoded to the same index at the wire read, ahead of the rental and ahead of the signature the same frame
    /// carries — so the refused parse rents nothing.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithAnOverWideCpHashIsRefusedAtTheParseWithoutRenting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            byte[] body = BuildPolicySignedBody(
                authObject: 0x8000_0000, sessionHandle, DistinctDigest(0x60), DistinctOctets(0x21, OverWideDigestSize), PolicyRef,
                expiration: 0, DistinctDigest(0x70), DistinctDigest(0x80));

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicySigned, body).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), code,
                "cpHashA is TPM2_PolicySigned()'s second parameter (Table 144, index 1); one wider than sizeof(TPMU_HA) is parameter-encoded TPM_RC_SIZE, answered at the parse.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A parse refused on a wire bound must rent nothing, so the balance cannot move.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyTicket()</c> whose <c>cpHashA</c> declares more octets than a <c>TPM2B_DIGEST</c> buffer
    /// may carry (<c>{:sizeof(TPMU_HA)}</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90) is refused with a
    /// <c>TPM_RC_SIZE</c>, parameter-encoded to the same index at the wire read — after the timeout the same frame carries has already been
    /// admitted, so the refusal is this field's own and the parse still rents nothing.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithAnOverWideCpHashIsRefusedAtTheParseWithoutRenting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            byte[] body = BuildPolicyTicketBody(
                sessionHandle, DistinctOctets(0x11, Tpm2bTimeout.MaxSize), DistinctOctets(0x21, OverWideDigestSize), PolicyRef,
                DistinctOctets(0x41, sizeof(uint)), (ushort)TpmStConstants.TPM_ST_AUTH_SECRET, (uint)TpmRh.TPM_RH_OWNER, DistinctDigest(0x50));

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyTicket, body).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), code,
                "Table 148: cpHashA is TPM2_PolicyTicket()'s second parameter (index 1); a width past sizeof(TPMU_HA) is parameter-encoded TPM_RC_SIZE there.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A parse refused on a wire bound must rent nothing, so the balance cannot move.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyAuthorize()</c> whose <c>approvedPolicy</c> declares more octets than a
    /// <c>TPM2B_DIGEST</c> buffer may carry (<c>{:sizeof(TPMU_HA)}</c>, TPM 2.0 Library Part 2, clause 10.3.2,
    /// Table 90) is refused with a <c>TPM_RC_SIZE</c>, parameter-encoded to the same index at the wire read, ahead of the rental and ahead of
    /// the session's own digest comparison — so the refused parse rents nothing.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithAnOverWideApprovedPolicyIsRefusedAtTheParseWithoutRenting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            byte[] body = BuildPolicyAuthorizeBody(
                sessionHandle, DistinctOctets(0x21, OverWideDigestSize), PolicyRef, KeySignName(),
                (ushort)TpmStConstants.TPM_ST_VERIFIED, (uint)TpmRh.TPM_RH_OWNER, DistinctDigest(0x50));

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyAuthorize, body).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
                "Table 170: approvedPolicy is TPM2_PolicyAuthorize()'s first parameter (index 0); a width past sizeof(TPMU_HA) is parameter-encoded TPM_RC_SIZE there.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A parse refused on a wire bound must rent nothing, so the balance cannot move.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyAuthorize()</c> whose <c>checkTicket.digest</c> declares more octets than a
    /// <c>TPM2B_DIGEST</c> buffer may carry is refused with a <c>TPM_RC_SIZE</c>, parameter-encoded to the same index at the wire read: the
    /// ticket's digest field is a <c>TPM2B_DIGEST</c> in its own right (<c>TPMT_TK_VERIFIED</c>, TPM 2.0 Library
    /// Part 2, clause 10.6.5, Table 113), so it takes the <c>{:sizeof(TPMU_HA)}</c> bound of Table 90 too — and
    /// the refusal comes after three well-formed fields, whose carriers the parse has therefore not yet rented.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithAnOverWideCheckTicketDigestIsRefusedAtTheParseWithoutRenting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            byte[] body = BuildPolicyAuthorizeBody(
                sessionHandle, DistinctDigest(0x30), PolicyRef, KeySignName(),
                (ushort)TpmStConstants.TPM_ST_VERIFIED, (uint)TpmRh.TPM_RH_OWNER, DistinctOctets(0x21, OverWideDigestSize));

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyAuthorize, body).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 3), code,
                "Table 170: checkTicket is TPM2_PolicyAuthorize()'s fourth parameter (index 3); its digest field wider than sizeof(TPMU_HA) is parameter-encoded TPM_RC_SIZE there.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The three admitted fields ahead of it are rented only after every bound has passed, so nothing is outstanding.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyAuthorize()</c> whose <c>checkTicket</c> carries a tag outside the v185 admitted set is
    /// refused with a <c>TPM_RC_TAG</c>, parameter-encoded to the same index at the wire read. TPM 2.0 Library Part 3, clause 23.16, printed page
    /// 247 states the requirement: "The unmarshaling process requires that a proper TPMT_TK_VERIFIED be provided
    /// for checkTicket but it may be a NULL Ticket." Part 2, clause 10.6.5, Table 112 admits exactly three tags —
    /// <c>TPM_ST_VERIFIED</c> (<c>TPM2_VerifySignature()</c>), <c>TPM_ST_MESSAGE_VERIFIED</c>
    /// (<c>TPM2_VerifySequenceComplete()</c>), and <c>TPM_ST_DIGEST_VERIFIED</c>
    /// (<c>TPM2_VerifyDigestSignature()</c>, Part 3, clause 23.16.2's preferred producer) — and names <c>TPM_RC_TAG</c>
    /// for anything outside that set; the NULL Ticket carries one of those same three tags, so the gate admits it.
    /// <c>TPM_ST_AUTH_SIGNED</c> here stands in for any tag outside the set.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithACheckTicketTagOutsideTheAdmittedSetIsRefusedAtTheParseWithoutRenting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            byte[] body = BuildPolicyAuthorizeBody(
                sessionHandle, DistinctDigest(0x30), PolicyRef, KeySignName(),
                (ushort)TpmStConstants.TPM_ST_AUTH_SIGNED, (uint)TpmRh.TPM_RH_OWNER, DistinctDigest(0x50));

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyAuthorize, body).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TAG, 3), code,
                "Table 170: checkTicket is TPM2_PolicyAuthorize()'s fourth parameter (index 3); a tag outside Table 112's three-tag admitted set is parameter-encoded TPM_RC_TAG there.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The three admitted fields ahead of it are rented only after every wire check has passed, so nothing is outstanding.");

            //The identical frame carrying the tag the structure fixes reaches the command body instead, where
            //the ticket's own HMAC re-derivation refuses it — so only the tag accounts for the first refusal.
            byte[] taggedBody = BuildPolicyAuthorizeBody(
                sessionHandle, DistinctDigest(0x30), PolicyRef, KeySignName(),
                (ushort)TpmStConstants.TPM_ST_VERIFIED, (uint)TpmRh.TPM_RH_OWNER, DistinctDigest(0x50));

            TpmRcConstants taggedCode = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyAuthorize, taggedBody).ConfigureAwait(false);

            Assert.AreNotEqual(
                TpmRcConstants.TPM_RC_TAG, taggedCode,
                "The identical frame carrying TPM_ST_VERIFIED passes the tag rule, so only the tag refused the first one.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "Whatever the body then answers, every carrier the parse rented for the admitted frame is returned.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyAuthorize()</c> whose <c>checkTicket</c> claims a hierarchy outside
    /// <c>TPMI_RH_HIERARCHY</c>'s admitted set is refused with a <c>TPM_RC_VALUE</c>, parameter-encoded to the same index at the wire read.
    /// <c>TPMT_TK_VERIFIED.hierarchy</c> is typed <c>TPMI_RH_HIERARCHY+</c> (TPM 2.0 Library Part 2, clause
    /// 10.6.5, Table 113), whose own table names <c>TPM_RC_VALUE</c> for a value outside
    /// <c>{TPM_RH_OWNER, TPM_RH_PLATFORM, TPM_RH_ENDORSEMENT, TPM_RH_NULL}</c> (clause 9.13, Table 59) — the
    /// unmarshaling requirement Part 3, clause 23.16, printed page 247 states for this parameter.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithAnOutOfSetCheckTicketHierarchyIsRefusedAtTheParseWithoutRenting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            //TPM_RH_LOCKOUT is a permanent handle the caller may legitimately name elsewhere, and it is NOT a
            //hierarchy — so it separates "a handle the TPM knows" from "a hierarchy this field may carry".
            byte[] body = BuildPolicyAuthorizeBody(
                sessionHandle, DistinctDigest(0x30), PolicyRef, KeySignName(),
                (ushort)TpmStConstants.TPM_ST_VERIFIED, (uint)TpmRh.TPM_RH_LOCKOUT, DistinctDigest(0x50));

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyAuthorize, body).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 3), code,
                "Table 170: checkTicket is TPM2_PolicyAuthorize()'s fourth parameter (index 3); a hierarchy outside TPMI_RH_HIERARCHY is parameter-encoded TPM_RC_VALUE there (Part 2, Table 59).");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The three admitted fields ahead of it are rented only after every wire check has passed, so nothing is outstanding.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyOR()</c> whose SECOND <c>pHashList</c> branch declares more octets than a
    /// <c>TPM2B_DIGEST</c> buffer may carry (<c>{:sizeof(TPMU_HA)}</c>, TPM 2.0 Library Part 2, clause 10.3.2,
    /// Table 90, over the <c>TPML_DIGEST</c> of clause 10.8.5, Table 126) is refused with
    /// <c>TPM_RC_SIZE</c>, parameter-encoded to the same index — and the first branch, already read and admitted, leaves nothing orphaned, because
    /// the whole list is rented as one act only after every branch has passed its bound.
    /// </summary>
    [TestMethod]
    public async Task PolicyOrWithAnOverWideSecondBranchIsRefusedAtTheParseWithoutRenting()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            byte[] body = BuildPolicyOrBody(sessionHandle, [DistinctDigest(0x10), DistinctOctets(0x21, OverWideDigestSize)]);

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyOR, body).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
                "pHashList is TPM2_PolicyOR()'s sole parameter (Table 150, index 0), invariant regardless of which branch failed; one wider than sizeof(TPMU_HA) is parameter-encoded TPM_RC_SIZE, answered at the parse.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The admitted first branch must leave no rental behind when a later branch is refused.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyOR()</c> branch that is BOTH wider than a <c>TPM2B_DIGEST</c> buffer may carry
    /// (<c>{:sizeof(TPMU_HA)}</c>, TPM 2.0 Library Part 2, clause 10.3.2, Table 90) AND truncated — its declared
    /// size exceeds what actually follows it — answers the bound rather than the truncation: <c>TPM_RC_SIZE</c>,
    /// not <c>TPM_RC_INSUFFICIENT</c>, because the bound-first read checks the declared size against the branch's
    /// own bound before it ever compares that size to the octets remaining. This is branch 3 of a declared 4, so
    /// the two well-formed branches read ahead of it must leave no rental behind either.
    /// </summary>
    [TestMethod]
    public async Task PolicyOrWithAMidListOverBoundAndTruncatedBranchAnswersSizeNotInsufficientAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;

            List<byte> body = [];
            AppendUInt32(body, sessionHandle);
            AppendUInt32(body, 4);
            AppendTpm2b(body, DistinctDigest(0x10));
            AppendTpm2b(body, DistinctDigest(0x20));
            AppendUInt16(body, (ushort)OverWideDigestSize);
            body.AddRange(DistinctOctets(0x30, 5));

            TpmRcConstants code = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyOR, [.. body]).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
                "pHashList is TPM2_PolicyOR()'s sole parameter (Table 150, index 0), invariant regardless of which branch failed; a branch that is both over-bound and truncated is parameter-encoded TPM_RC_SIZE — the bound is checked before the remaining-buffer comparison.");
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The two well-formed branches read ahead of the refusal must leave no rental behind.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_PCR_Read()</c> and <c>TPM2_PolicyPCR()</c> both refuse a <c>TPML_PCR_SELECTION</c> naming more
    /// banks than the list admits — <c>HASH_COUNT</c> selections (TPM 2.0 Library Part 2, clause 10.8.7, Table
    /// 128, whose out-of-range count is <c>#TPM_RC_SIZE</c>) — with <c>TPM_RC_SIZE</c> at the parse, the same
    /// bound <c>TPM2_Create()</c>'s creationPCR path enforces.
    /// </summary>
    [TestMethod]
    public async Task PcrReadAndPolicyPcrRejectASelectionNamingMoreThanSixteenBanks()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        byte[] overBoundSelection = BuildPcrSelectionOctets(TpmlPcrSelection.MaxSelections + 1);

        long pcrReadBaseline = trackingPool.OutstandingCount;
        TpmRcConstants pcrReadCode = await SubmitFramedAsync(
            simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PCR_Read, overBoundSelection).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), pcrReadCode,
            "pcrSelectionIn is TPM2_PCR_Read()'s sole parameter (Table 134, index 0); a selection naming more than HASH_COUNT banks is parameter-encoded TPM_RC_SIZE (Part 2, clause 10.8.7, Table 128).");
        Assert.AreEqual(pcrReadBaseline, trackingPool.OutstandingCount, "The refused probe must rent nothing.");

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            long policyPcrBaseline = trackingPool.OutstandingCount;
            byte[] policyPcrBody = BuildPolicyPcrBody(sessionHandle, DistinctDigest(0x70), overBoundSelection);
            TpmRcConstants policyPcrCode = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyPCR, policyPcrBody).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), policyPcrCode,
                "pcrs is TPM2_PolicyPCR()'s second parameter (Table 152, index 1); the same count bound applies, parameter-encoded.");
            Assert.AreEqual(policyPcrBaseline, trackingPool.OutstandingCount, "The refused probe must rent nothing, including the already-read pcrDigest.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPMS_PCR_SELECTION</c> whose <c>sizeofSelect</c> lies outside <c>PCR_SELECT_MIN</c>..
    /// <c>PCR_SELECT_MAX</c> is <c>TPM_RC_VALUE</c> (TPM 2.0 Library Part 2, clause 10.5.2, Table 107), a bound
    /// <see cref="TpmlPcrSelection.Parse"/> enforces for both a too-narrow and a too-wide width.
    /// </summary>
    [TestMethod]
    public async Task PcrReadPreservesTheSizeofSelectValueBoundThroughTheCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        byte[] belowMin = BuildSinglePcrSelectionOctets(sizeofSelect: 2);
        byte[] aboveMax = BuildSinglePcrSelectionOctets(sizeofSelect: 33);

        long baselineBelow = trackingPool.OutstandingCount;
        TpmRcConstants belowMinCode = await SubmitFramedAsync(
            simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PCR_Read, belowMin).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), belowMinCode,
            "pcrSelectionIn is TPM2_PCR_Read()'s sole parameter (Table 134, index 0); sizeofSelect below PCR_SELECT_MIN (3) is parameter-encoded TPM_RC_VALUE (Part 2, clause 10.5.2, Table 107).");
        Assert.AreEqual(baselineBelow, trackingPool.OutstandingCount, "A refused sizeofSelect must rent nothing.");

        long baselineAbove = trackingPool.OutstandingCount;
        TpmRcConstants aboveMaxCode = await SubmitFramedAsync(
            simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PCR_Read, aboveMax).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 0), aboveMaxCode,
            "pcrSelectionIn is TPM2_PCR_Read()'s sole parameter (Table 134, index 0); sizeofSelect above PCR_SELECT_MAX (32) is parameter-encoded TPM_RC_VALUE (Part 2, clause 10.5.2, Table 107).");
        Assert.AreEqual(baselineAbove, trackingPool.OutstandingCount, "A refused sizeofSelect must rent nothing.");
    }

    /// <summary>
    /// A <c>TPML_PCR_SELECTION</c> that is BOTH over-bound (a declared count of 17, one more than
    /// <see cref="TpmlPcrSelection.MaxSelections"/>) AND truncated (far too few octets follow to walk even one
    /// entry) answers <c>TPM_RC_SIZE</c> rather than <c>TPM_RC_INSUFFICIENT</c> — the count bound is checked
    /// immediately after <c>count</c> is read, before any element is walked, so it wins over the truncation the
    /// element walk would otherwise report for PCR_Read and PolicyPCR alike.
    /// </summary>
    [TestMethod]
    public async Task PcrReadAndPolicyPcrAnswerSizeNotInsufficientForAnOverBoundAndTruncatedSelection()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        //count = 17, then two octets — nowhere near enough to walk even one TPMS_PCR_SELECTION entry (which
        //needs at least a UINT16 hash plus a BYTE sizeofSelect), let alone seventeen.
        byte[] overBoundAndTruncated = [0x00, 0x00, 0x00, 0x11, 0x00];

        long pcrReadBaseline = trackingPool.OutstandingCount;
        TpmRcConstants pcrReadCode = await SubmitFramedAsync(
            simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PCR_Read, overBoundAndTruncated).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), pcrReadCode,
            "pcrSelectionIn is TPM2_PCR_Read()'s sole parameter (Table 134, index 0); a list that is both over-bound and truncated answers the count bound before the truncation it would otherwise report, parameter-encoded.");
        Assert.AreEqual(pcrReadBaseline, trackingPool.OutstandingCount, "The refused probe must rent nothing.");

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            long policyPcrBaseline = trackingPool.OutstandingCount;
            byte[] policyPcrBody = BuildPolicyPcrBody(sessionHandle, DistinctDigest(0x70), overBoundAndTruncated);
            TpmRcConstants policyPcrCode = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyPCR, policyPcrBody).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), policyPcrCode,
                "pcrs is TPM2_PolicyPCR()'s second parameter (Table 152, index 1); the same precedence applies, parameter-encoded.");
            Assert.AreEqual(policyPcrBaseline, trackingPool.OutstandingCount, "The refused probe must rent nothing, including the already-read pcrDigest.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPM2_PCR_Read()</c>'s <c>pcrSelectionOut</c> marshals to exactly the octets the requested selection was
    /// built from: the response re-marshals the parsed <see cref="TpmlPcrSelection"/> through its own
    /// <c>WriteTo</c> rather than echoing a captured byte region, so byte-fidelity is proven against a
    /// hand-authored expected octet sequence rather than a second call to the same <c>WriteTo</c> the request
    /// itself was framed with.
    /// </summary>
    [TestMethod]
    public async Task PcrReadEchoesTheRequestedSelectionByteIdenticalAfterTheCarrierRoundTrip()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using TpmlPcrSelection requestSelection = TpmlPcrSelection.Create(SessionAlg, [0, 7, 23], pool);

        //TpmlPcrSelection.Create(SHA-256, [0, 7, 23]) marshals to exactly these octets (TPM 2.0 Library Part 2,
        //clause 10.8.7, Table 128; clause 10.5.2, Table 107 for the sizeofSelect-3 bitmap): count = 1, then one
        //TPMS_PCR_SELECTION of { SHA-256 (0x000B), sizeofSelect 3, PCR 0/7/23's bits 0x81 0x00 0x80 }. Authored
        //independently of TpmlPcrSelection.WriteTo so this test does not compare that call against itself.
        byte[] expectedOctets =
        [
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x0B, 0x03, 0x81, 0x00, 0x80
        ];

        using PcrReadInput input = PcrReadInput.FromSelection(requestSelection);
        TpmResult<PcrReadResponse> result = await TpmCommandExecutor.ExecuteAsync<PcrReadResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PCR_Read failed: '{result.ResponseCode}'.");

        using PcrReadResponse response = result.Value;
        byte[] echoedOctets = new byte[response.PcrSelectionOut.GetSerializedSize()];
        var echoedWriter = new TpmWriter(echoedOctets);
        response.PcrSelectionOut.WriteTo(ref echoedWriter);

        Assert.AreSequenceEqual(
            expectedOctets, echoedOctets,
            "pcrSelectionOut must marshal to exactly the octets the requested selection marshals to.");
    }

    /// <summary>
    /// <c>TPM2_PCR_Read()</c>'s <c>pcrSelectionOut</c> echoes a multi-bank <c>TPML_PCR_SELECTION</c> carrying a
    /// non-minimal <c>sizeofSelect</c> byte for byte — the shape a single-bank, <c>PCR_SELECT_MIN</c>-width
    /// request cannot exercise — against a hand-authored expected octet sequence, proving the count bound
    /// (<c>HASH_COUNT</c>, TPM 2.0 Library Part 2, clause 10.8.7, Table 128) and the <c>sizeofSelect</c> bound
    /// (<c>PCR_SELECT_MIN</c>..<c>PCR_SELECT_MAX</c>, clause 10.5.2, Table 107) both admit every shape the parser
    /// allows, not merely the minimal shape the typed command inputs can build.
    /// </summary>
    [TestMethod]
    public async Task PcrReadEchoesAMultiBankNonMinimalWidthSelectionByteIdentical()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        //Two banks: SHA-256 at the narrowest conformant width (PCR 0, 7 and 23), then SHA-384 at the widest
        //(PCR_SELECT_MAX, 32 octets) carrying a distinctive, non-repeating bitmap — the shape the typed command
        //inputs cannot express, so this is hand-framed straight to the simulator.
        List<byte> requestOctets = [];
        AppendUInt32(requestOctets, 2);
        AppendUInt16(requestOctets, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        requestOctets.Add(3);
        requestOctets.AddRange([0x81, 0x00, 0x80]);
        AppendUInt16(requestOctets, (ushort)TpmAlgIdConstants.TPM_ALG_SHA384);
        requestOctets.Add(32);
        requestOctets.AddRange(DistinctOctets(0x01, 32));
        byte[] requestBody = [.. requestOctets];

        int length = TpmHeader.HeaderSize + requestBody.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_PCR_Read);
        header.WriteTo(ref writer);
        writer.WriteBytes(requestBody);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed PCR_Read must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code,
            "A two-bank selection within both the count and sizeofSelect bounds must be read, not refused.");

        using PcrReadResponse parsedResponse = PcrReadResponse.Parse(ref reader, pool);
        byte[] echoedOctets = new byte[parsedResponse.PcrSelectionOut.GetSerializedSize()];
        var echoedWriter = new TpmWriter(echoedOctets);
        parsedResponse.PcrSelectionOut.WriteTo(ref echoedWriter);

        Assert.AreSequenceEqual(
            requestBody, echoedOctets,
            "pcrSelectionOut must marshal to exactly the multi-bank, non-minimal-width octets the caller sent, unfiltered.");
    }

    /// <summary>
    /// <c>TPM2_PolicyPCR()</c>'s fold on a trial session equals <c>H(0 || TPM_CC_PolicyPCR || pcrs ||
    /// pcrDigest)</c> (TPM 2.0 Library Part 3, clause 23.7), computed here through the same
    /// <see cref="TpmPolicyDigest.ExtendForPcr"/> formula the simulator's fold reaches — a formula spec-pinned
    /// against an independent SHA-256 transcription in <see cref="TpmPolicyDigestTests"/> — applied over the exact
    /// octets this test itself marshaled, so the reported policyDigest is proven to chain through a
    /// separately-verified formula over the caller's own selection octets, not asserted as a value the
    /// production carrier merely reproduces from itself. This proves the fold's marshal-then-hash mechanics;
    /// the clause's two shapes of the <c>pcrs</c> term for a selection naming unimplemented PCR — the trial
    /// fold's unmodified input parameter and the real fold's masked value — are proven by
    /// <see cref="PolicyPcrTrialFoldUsesThePcrsInputParameterWithoutModification"/> and
    /// <see cref="PolicyPcrRealFoldClearsUnimplementedPcrBitsInThePcrsTerm"/>.
    /// </summary>
    [TestMethod]
    public async Task PolicyPcrFoldMatchesTheSpecFormulaOverTheMarshaledSelectionOnATrialSession()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            using TpmlPcrSelection selection = TpmlPcrSelection.Create(SessionAlg, [0, 7, 23], trackingPool.Pool);
            byte[] marshaledSelection = new byte[selection.GetSerializedSize()];
            var writer = new TpmWriter(marshaledSelection);
            selection.WriteTo(ref writer);

            byte[] callerDigest = DistinctDigest(0x70);
            using PolicyPcrInput input = PolicyPcrInput.Create(sessionHandle, callerDigest, selection, trackingPool.Pool);
            TpmResult<PolicyPcrResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyPcrResponse>(
                tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"PolicyPCR (trial session) failed: '{result.ResponseCode}'.");

            byte[] expected = new byte[DigestSize];
            _ = TpmPolicyDigest.ExtendForPcr(new byte[DigestSize], marshaledSelection, callerDigest, SessionAlg, expected, trackingPool.Pool);

            byte[] reported = await ReadPolicyDigestAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            Assert.AreSequenceEqual(
                expected, reported,
                "PolicyPCR's fold must equal H(0 || TPM_CC_PolicyPCR || pcrs || pcrDigest) over the marshaled selection this test itself framed.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A TRIAL <c>TPM2_PolicyPCR()</c> folds the <c>pcrs</c> term as the caller sent it: "In this computation,
    /// pcrs is the input parameter without modification" (TPM 2.0 Library Part 3, clause 23.7) — the clause's
    /// own carve-out from the real-session mask, since a trial policy is routinely computed on a TPM whose PCR
    /// allocation differs from the target's. The selection here names PCR 30 (a register at or above this
    /// model's implemented count) and a SHA-384 bank (unallocated), and the expected digest is computed over
    /// exactly those raw octets through the spec-pinned <see cref="TpmPolicyDigest.ExtendForPcr"/> formula, so
    /// a trial fold that masked the selection would fail the comparison.
    /// <see cref="PolicyPcrRealFoldClearsUnimplementedPcrBitsInThePcrsTerm"/> proves the mask the real session
    /// applies to the same octets.
    /// </summary>
    [TestMethod]
    public async Task PolicyPcrTrialFoldUsesThePcrsInputParameterWithoutModification()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            //A SHA-256 entry four octets wide naming PCR 0 and PCR 30 (a register at or above the implemented
            //count of 24), then a SHA-384 entry naming PCR 5 (a bank the simulator has not allocated).
            byte[] rawSelection =
            [
                0x00, 0x00, 0x00, 0x02,
                0x00, 0x0B, 0x04, 0x01, 0x00, 0x00, 0x40,
                0x00, 0x0C, 0x03, 0x20, 0x00, 0x00
            ];

            byte[] callerDigest = DistinctDigest(0x72);
            byte[] policyPcrBody = BuildPolicyPcrBody(sessionHandle, callerDigest, rawSelection);
            TpmRcConstants responseCode = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyPCR, policyPcrBody).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SUCCESS, responseCode,
                "A trial session accepts a selection naming unimplemented PCR — it may target a differently configured TPM (Part 3, clause 23.7).");

            byte[] expected = new byte[DigestSize];
            _ = TpmPolicyDigest.ExtendForPcr(new byte[DigestSize], rawSelection, callerDigest, SessionAlg, expected, trackingPool.Pool);

            byte[] reported = await ReadPolicyDigestAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            Assert.AreSequenceEqual(
                expected, reported,
                "A trial fold's pcrs term is the input parameter without modification, never this model's masked value.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A REAL (non-trial) <c>TPM2_PolicyPCR()</c> folds the <c>pcrs</c> term with bits corresponding to
    /// unimplemented PCR CLEAR ("The TPM will modify the pcrs parameter so that bits that correspond to
    /// unimplemented PCR are CLEAR", TPM 2.0 Library Part 3, clause 23.7), the marshaled width unchanged: the
    /// bit naming PCR 30 folds cleared and the unallocated SHA-384 bank's entry folds retained with every bit
    /// cleared. The caller sends an empty <c>pcrDigest</c>, so the fold binds to the live composite — the
    /// digest of the selected implemented registers (here PCR 0 alone, at its all-zero reset value) — and the
    /// expected digest is computed over octets this test itself cleared per the clause, hand-authored wire
    /// literals rather than the production mask, so a fold over the caller's raw octets fails the comparison.
    /// </summary>
    [TestMethod]
    public async Task PolicyPcrRealFoldClearsUnimplementedPcrBitsInThePcrsTerm()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            //The same raw shape the trial test sends: PCR 0 and PCR 30 in a four-octet SHA-256 entry, PCR 5 in
            //an unallocated SHA-384 bank.
            byte[] rawSelection =
            [
                0x00, 0x00, 0x00, 0x02,
                0x00, 0x0B, 0x04, 0x01, 0x00, 0x00, 0x40,
                0x00, 0x0C, 0x03, 0x20, 0x00, 0x00
            ];

            //The clause's modification applied by hand: the count, entries and widths stand while PCR 30's bit
            //and the unallocated bank's every bit are CLEAR.
            byte[] expectedFoldedSelection =
            [
                0x00, 0x00, 0x00, 0x02,
                0x00, 0x0B, 0x04, 0x01, 0x00, 0x00, 0x00,
                0x00, 0x0C, 0x03, 0x00, 0x00, 0x00
            ];

            byte[] policyPcrBody = BuildPolicyPcrBody(sessionHandle, pcrDigest: [], rawSelection);
            TpmRcConstants responseCode = await SubmitFramedAsync(
                simulator, trackingPool.Pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicyPCR, policyPcrBody).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SUCCESS, responseCode,
                "An empty pcrDigest skips the live-composite comparison, so the real-session fold proceeds (Part 3, clause 23.7).");

            //The live composite over the MODIFIED selection: of the named registers only PCR 0 is implemented,
            //and it holds its 32-octet all-zero reset value, so digestTPM = H(PCR 0) through the registered
            //digest seam (Part 4, PCRComputeCurrentDigest).
            using DigestValue liveComposite = await CryptographicKeyEvents.ComputeDigestAsync(
                new byte[DigestSize], DigestSize, CryptoTags.Sha256Digest, trackingPool.Pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            byte[] expected = new byte[DigestSize];
            _ = TpmPolicyDigest.ExtendForPcr(new byte[DigestSize], expectedFoldedSelection, liveComposite.AsReadOnlySpan(), SessionAlg, expected, trackingPool.Pool);

            byte[] reported = await ReadPolicyDigestAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
            Assert.AreSequenceEqual(
                expected, reported,
                "A real fold's pcrs term must carry unimplemented-PCR bits cleared at unchanged width, not the caller's raw octets.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A genuinely signature-verified <c>TPM2_PolicySigned()</c> over an ECC authority key (TPM 2.0 Library
    /// Part 3, clause 23.3) folds inside the verification effect, so that effect returns the qualifier and the
    /// authority Name it consumed and hands back exactly one advanced policyDigest for the session to install:
    /// the session holds one live digest above where it started, and eviction returns even that.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedVerifiedOverAnEccAuthorityLeavesExactlyOneLivePolicyDigest()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;

        long beforeSession = trackingPool.OutstandingCount;
        StartedPolicySession started = await StartPolicySessionWithNonceAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        uint sessionHandle = started.Handle;

        byte[] signature = await SignPolicySignedAuthorizationAsync(
            tpm, registry, trackingPool.Pool, authorityKey.ObjectHandle, started.NonceTpm).ConfigureAwait(false);

        long sessionBaseline = trackingPool.OutstandingCount;

        //The command input's own rentals are scoped so only what the simulator kept is read below.
        {
            using PolicySignedInput input = PolicySignedInput.Create(
                authorityHandle, sessionHandle, started.NonceTpm, ReadOnlySpan<byte>.Empty, PolicyRef, expiration: 0, signature,
                TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

            TpmResult<PolicySignedResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicySignedResponse>(
                tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A genuinely signed PolicySigned must be authorized: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            sessionBaseline + 1, trackingPool.OutstandingCount,
            "The verifying effect must return every term it folded and leave exactly the advanced policyDigest the session now owns.");

        await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);

        Assert.AreEqual(
            beforeSession, trackingPool.OutstandingCount,
            "Evicting the session must return its policyDigest along with its own nonce, leaving nothing the assertion rented outstanding.");
    }

    /// <summary>
    /// A <c>TPM2_PolicySigned()</c> whose signature does not verify is refused with <c>TPM_RC_SIGNATURE</c>
    /// (TPM 2.0 Library Part 3, clause 23.3), and the refusing continuation is the terminal owner of every
    /// carrier the request and the effect had between them: the session is left exactly as the command found it.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedRefusedOnTheSignatureLeavesTheSessionsBalanceUntouched()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        uint authorityHandle = authorityKey.ObjectHandle.Value;

        StartedPolicySession started = await StartPolicySessionWithNonceAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        uint sessionHandle = started.Handle;
        try
        {
            byte[] signature = await SignPolicySignedAuthorizationAsync(
                tpm, registry, trackingPool.Pool, authorityKey.ObjectHandle, started.NonceTpm).ConfigureAwait(false);
            signature[^1] ^= 0xFF;

            long beforeCommand = trackingPool.OutstandingCount;

            {
                using PolicySignedInput input = PolicySignedInput.Create(
                    authorityHandle, sessionHandle, started.NonceTpm, ReadOnlySpan<byte>.Empty, PolicyRef, expiration: 0, signature,
                    TpmAlgIdConstants.TPM_ALG_ECDSA, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

                TpmResult<PolicySignedResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicySignedResponse>(
                    tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIGNATURE, 4), result.ResponseCode,
                    "A signature that does not verify against aHash is TPM_RC_SIGNATURE at auth, parameter 5 of Table 144.");
            }

            Assert.AreEqual(
                beforeCommand, trackingPool.OutstandingCount,
                "A refused verification folds nothing, so every carrier the request and the effect held must be back.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyTicket()</c> replaying a ticket a real <c>TPM2_PolicySecret()</c> minted (TPM 2.0 Library
    /// Part 3, clause 23.5) folds inside the re-verification effect, which is the terminal owner of the ticket
    /// digest, the qualifier and the Name it consumed: the replay session ends holding exactly one live
    /// policyDigest, and eviction returns it.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketReplayedAgainstItsOwnMintLeavesExactlyOneLivePolicyDigest()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        MintedAuthTicket ticket = await MintSessionBoundSecretTicketAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long beforeSession = trackingPool.OutstandingCount;
        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        long sessionBaseline = trackingPool.OutstandingCount;

        {
            using PolicyTicketInput input = PolicyTicketInput.Create(
                sessionHandle, ticket.Timeout, ReadOnlySpan<byte>.Empty, PolicyRef, ticket.AuthName, ticket.Tag, ticket.Hierarchy,
                ticket.Digest, trackingPool.Pool);

            TpmResult<PolicyTicketResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyTicketResponse>(
                tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A ticket replayed against its own mint must be authorized: '{result.ResponseCode}'.");
        }

        Assert.AreEqual(
            sessionBaseline + 1, trackingPool.OutstandingCount,
            "The re-verifying effect must return every term it consumed and leave exactly the advanced policyDigest the session now owns.");

        await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);

        Assert.AreEqual(
            beforeSession, trackingPool.OutstandingCount,
            "Evicting the replay session must return its policyDigest along with its own nonce.");
    }

    /// <summary>
    /// A <c>TPM2_PolicyTicket()</c> whose ticket digest does not reproduce the TPM's own recompute is refused
    /// with <c>TPM_RC_TICKET</c> (TPM 2.0 Library Part 3, clause 23.5), and the refusing continuation returns
    /// every carrier the request and the effect held: the session is left exactly as the command found it.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketRefusedOnTheTicketLeavesTheSessionsBalanceUntouched()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        MintedAuthTicket ticket = await MintSessionBoundSecretTicketAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        ticket.Digest[^1] ^= 0xFF;

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long beforeCommand = trackingPool.OutstandingCount;

            {
                using PolicyTicketInput input = PolicyTicketInput.Create(
                    sessionHandle, ticket.Timeout, ReadOnlySpan<byte>.Empty, PolicyRef, ticket.AuthName, ticket.Tag, ticket.Hierarchy,
                    ticket.Digest, trackingPool.Pool);

                TpmResult<PolicyTicketResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyTicketResponse>(
                    tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 4), result.ResponseCode,
                    "A ticket whose digest does not reproduce the TPM's recompute is TPM_RC_TICKET at ticket, parameter 5 of Table 148.");
            }

            Assert.AreEqual(
                beforeCommand, trackingPool.OutstandingCount,
                "A refused re-verification folds nothing, so every carrier the request and the effect held must be back.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A NON-trial <c>TPM2_PolicyAuthorize()</c> whose <c>checkTicket</c> genuinely re-verifies (TPM 2.0 Library
    /// Part 3, clause 23.16) folds inside the ticket-verification effect: the reset-and-refold replaces the
    /// session's digest wholesale, so the session still holds exactly ONE live policyDigest after the
    /// authorization, and eviction returns it.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeVerifiedAgainstARealTicketLeavesExactlyOneLivePolicyDigest()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();

        byte[] approvedPolicy = new byte[DigestSize];
        _ = TpmPolicyDigest.ExtendForCommandCode(new byte[DigestSize], TpmCcConstants.TPM_CC_Unseal, SessionAlg, approvedPolicy, trackingPool.Pool);

        VerifiedApproval approval = await ApproveWithAuthorityAsync(
            tpm, registry, trackingPool.Pool, authorityKey.ObjectHandle, approvedPolicy).ConfigureAwait(false);

        long beforeSession = trackingPool.OutstandingCount;
        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        long sessionBaseline = trackingPool.OutstandingCount;

        await AssertCommandCodeAsync(tpm, registry, trackingPool.Pool, sessionHandle, TpmCcConstants.TPM_CC_Unseal).ConfigureAwait(false);
        Assert.AreEqual(
            sessionBaseline + 1, trackingPool.OutstandingCount,
            "The sub-policy assertion must leave the session holding the digest the authority approved.");

        {
            using PolicyAuthorizeInput input = PolicyAuthorizeInput.Create(
                sessionHandle, approvedPolicy, PolicyRef, keySign, approval.TicketTag, approval.TicketHierarchy, approval.TicketMetadata, approval.TicketDigest, trackingPool.Pool);

            TpmResult<PolicyAuthorizeResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyAuthorizeResponse>(
                tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A genuinely ticketed PolicyAuthorize must be authorized: '{result.ResponseCode}'.");
        }

        Assert.AreEqual(
            sessionBaseline + 1, trackingPool.OutstandingCount,
            "The reset-and-refold replaces the digest wholesale, so the session must still hold exactly one, not two.");

        await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);

        Assert.AreEqual(
            beforeSession, trackingPool.OutstandingCount,
            "Evicting the session must return the refolded policyDigest along with its own nonce.");
    }

    /// <summary>
    /// The clause 23.16.2 conformance case: a <c>TPMT_TK_VERIFIED</c> tagged <c>TPM_ST_DIGEST_VERIFIED</c> —
    /// minted by <c>TPM2_VerifyDigestSignature()</c>, not <c>TPM2_VerifySignature()</c> — satisfies
    /// <c>TPM2_PolicyAuthorize()</c> over the real wire (<see cref="TpmCommandExecutor"/> end to end, not a
    /// hand-framed submit): TPM 2.0 Library Part 3, clause 23.16.2 names
    /// <c>TPM2_VerifyDigestSignature()</c>'s digest ticket as the preferred producer for this command, and
    /// Part 2, clause 10.6.5 restates that <c>TPM2_PolicyAuthorize()</c> is the ticket's consumer. Otherwise mirrors
    /// <see cref="PolicyAuthorizeVerifiedAgainstARealTicketLeavesExactlyOneLivePolicyDigest"/>'s VERIFIED-tag
    /// path, which stays covered unchanged by that test.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeAcceptsADigestVerifiedTicketFromVerifyDigestSignature()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();

        byte[] approvedPolicy = new byte[DigestSize];
        _ = TpmPolicyDigest.ExtendForCommandCode(new byte[DigestSize], TpmCcConstants.TPM_CC_Unseal, SessionAlg, approvedPolicy, trackingPool.Pool);

        VerifiedApproval approval = await ApproveWithAuthorityViaDigestSignatureAsync(
            tpm, registry, trackingPool.Pool, authorityKey.ObjectHandle, approvedPolicy).ConfigureAwait(false);
        Assert.AreEqual(
            (ushort)TpmStConstants.TPM_ST_DIGEST_VERIFIED, approval.TicketTag,
            "TPM2_VerifyDigestSignature() must mint its own TPM_ST_DIGEST_VERIFIED tag, not TPM_ST_VERIFIED.");

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, trackingPool.Pool, sessionHandle, TpmCcConstants.TPM_CC_Unseal).ConfigureAwait(false);

            using PolicyAuthorizeInput input = PolicyAuthorizeInput.Create(
                sessionHandle, approvedPolicy, PolicyRef, keySign, approval.TicketTag, approval.TicketHierarchy, approval.TicketMetadata, approval.TicketDigest, trackingPool.Pool);

            TpmResult<PolicyAuthorizeResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyAuthorizeResponse>(
                tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"A TPM_ST_DIGEST_VERIFIED-ticketed PolicyAuthorize must be authorized: '{result.ResponseCode}'.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A NON-trial <c>TPM2_PolicyAuthorize()</c> whose <c>checkTicket</c> does not reproduce the TPM's own
    /// recompute is refused with <c>TPM_RC_POLICY</c> — "If the ticket is not valid, the TPM shall return
    /// TPM_RC_POLICY" (TPM 2.0 Library Part 3, clause 23.16.1), distinct from the <c>approvedPolicy</c>
    /// mismatch's own <c>TPM_RC_VALUE</c> — but only after the verification effect has run, which is the arm
    /// where all four wire carriers have already travelled request to action to effect. The refusing
    /// continuation returns them, leaving the session's own digest in place and the balance exactly where the
    /// command found it.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeRefusedOnTheTicketLeavesTheSessionsBalanceUntouched()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authorityKey = await CreateEccAuthorityKeyAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);
        byte[] keySign = authorityKey.Name.Span.ToArray();

        byte[] approvedPolicy = new byte[DigestSize];
        _ = TpmPolicyDigest.ExtendForCommandCode(new byte[DigestSize], TpmCcConstants.TPM_CC_Unseal, SessionAlg, approvedPolicy, trackingPool.Pool);

        VerifiedApproval approval = await ApproveWithAuthorityAsync(
            tpm, registry, trackingPool.Pool, authorityKey.ObjectHandle, approvedPolicy).ConfigureAwait(false);
        approval.TicketDigest[^1] ^= 0xFF;

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            await AssertCommandCodeAsync(tpm, registry, trackingPool.Pool, sessionHandle, TpmCcConstants.TPM_CC_Unseal).ConfigureAwait(false);

            long beforeCommand = trackingPool.OutstandingCount;

            {
                using PolicyAuthorizeInput input = PolicyAuthorizeInput.Create(
                    sessionHandle, approvedPolicy, PolicyRef, keySign, approval.TicketTag, approval.TicketHierarchy, approval.TicketMetadata, approval.TicketDigest, trackingPool.Pool);

                TpmResult<PolicyAuthorizeResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyAuthorizeResponse>(
                    tpm, input, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_POLICY, result.ResponseCode,
                    "A checkTicket that does not reproduce the TPM's recompute is TPM_RC_POLICY (clause 23.16.1's ticket-invalid sentence), not TPM_RC_VALUE (which names only the approvedPolicy mismatch).");
            }

            Assert.AreEqual(
                beforeCommand, trackingPool.OutstandingCount,
                "A refused authorization folds nothing, so all four wire carriers must be back and the session's own digest untouched.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>Installs an authorization policy on the endorsement hierarchy over its still-empty password.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policyDigest">The digest the authorizing session will accumulate.</param>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented authPolicy digest transfers to the SetPrimaryPolicyInput, whose own using declaration releases it.")]
    private async Task InstallEndorsementPolicyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, byte[] policyDigest)
    {
        using var input = new SetPrimaryPolicyInput(TpmRh.TPM_RH_ENDORSEMENT, Tpm2bDigest.Create(policyDigest, pool), SessionAlg);
        using TpmPasswordSession endorsementAuth = TpmPasswordSession.Create(ReadOnlySpan<byte>.Empty, pool);

        TpmResult<SetPrimaryPolicyResponse> result = await TpmCommandExecutor.ExecuteAsync<SetPrimaryPolicyResponse>(
            tpm, input, [endorsementAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"SetPrimaryPolicy failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// The Name of a permanent handle, which is its 4-octet handle value in big-endian order (TPM 2.0 Library
    /// Part 1, clause 13, Table 9) — the term <c>PolicySecret</c>'s <c>PolicyUpdate</c> folds for a hierarchy.
    /// </summary>
    /// <param name="handle">The permanent handle.</param>
    /// <returns>The Name octets.</returns>
    private static byte[] PermanentHandleName(TpmRh handle)
    {
        byte[] name = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(name, (uint)handle);

        return name;
    }

    /// <summary>Builds a distinctive, non-empty digest-width value, so no balance assertion here is vacuous.</summary>
    /// <param name="seed">The first octet, which also offsets the rest.</param>
    /// <returns>The digest octets.</returns>
    private static byte[] DistinctDigest(byte seed) => DistinctOctets(seed, DigestSize);

    /// <summary>Builds a distinctive, non-empty run of octets of a caller-chosen width.</summary>
    /// <param name="seed">The first octet, which also offsets the rest.</param>
    /// <param name="length">How many octets to produce.</param>
    /// <returns>The octets.</returns>
    private static byte[] DistinctOctets(byte seed, int length)
    {
        byte[] octets = new byte[length];
        for(int i = 0; i < octets.Length; i++)
        {
            octets[i] = (byte)(seed + i);
        }

        return octets;
    }

    /// <summary>
    /// Builds a well-formed <c>TPM2B_NAME</c> for the hand-framed cases: the session hash's own algorithm
    /// identifier followed by a digest of that hash's width (TPM 2.0 Library Part 2, clause 10.4.3, Table 105).
    /// </summary>
    /// <returns>The Name octets.</returns>
    private static byte[] KeySignName()
    {
        byte[] name = new byte[sizeof(ushort) + DigestSize];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)SessionAlg);
        DistinctDigest(0x90).CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>Appends a big-endian <c>UINT16</c> to a hand-framed command body.</summary>
    /// <param name="body">The body under construction.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt16(List<byte> body, ushort value)
    {
        body.Add((byte)(value >> 8));
        body.Add((byte)value);
    }

    /// <summary>Appends a big-endian <c>UINT32</c> to a hand-framed command body.</summary>
    /// <param name="body">The body under construction.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt32(List<byte> body, uint value)
    {
        body.Add((byte)(value >> 24));
        body.Add((byte)(value >> 16));
        body.Add((byte)(value >> 8));
        body.Add((byte)value);
    }

    /// <summary>
    /// Appends a <c>TPM2B</c> — a big-endian <c>UINT16</c> size prefix then the octets themselves — to a
    /// hand-framed command body. The size is written from the octets supplied, which is what lets a caller
    /// declare a width the typed command inputs would refuse before it ever reached the wire.
    /// </summary>
    /// <param name="body">The body under construction.</param>
    /// <param name="value">The octets to append.</param>
    private static void AppendTpm2b(List<byte> body, byte[] value)
    {
        AppendUInt16(body, (ushort)value.Length);
        body.AddRange(value);
    }

    /// <summary>
    /// Frames a <c>TPM2_PolicyTicket()</c> body (TPM 2.0 Library Part 3, clause 23.5, Table 148): the policy
    /// session handle, then timeout, cpHashA, policyRef, authName and the <c>TPMT_TK_AUTH</c>.
    /// </summary>
    /// <param name="policySession">The policy session handle.</param>
    /// <param name="timeout">The <c>TPM2B_TIMEOUT</c> octets.</param>
    /// <param name="cpHashA">The <c>TPM2B_DIGEST</c> octets.</param>
    /// <param name="policyRef">The <c>TPM2B_NONCE</c> octets.</param>
    /// <param name="authName">The <c>TPM2B_NAME</c> octets.</param>
    /// <param name="ticketTag">The ticket's structure tag.</param>
    /// <param name="ticketHierarchy">The ticket's hierarchy.</param>
    /// <param name="ticketDigest">The ticket's own <c>TPM2B_DIGEST</c> octets.</param>
    /// <returns>The framed body.</returns>
    private static byte[] BuildPolicyTicketBody(
        uint policySession, byte[] timeout, byte[] cpHashA, byte[] policyRef, byte[] authName,
        ushort ticketTag, uint ticketHierarchy, byte[] ticketDigest)
    {
        List<byte> body = [];
        AppendUInt32(body, policySession);
        AppendTpm2b(body, timeout);
        AppendTpm2b(body, cpHashA);
        AppendTpm2b(body, policyRef);
        AppendTpm2b(body, authName);
        AppendUInt16(body, ticketTag);
        AppendUInt32(body, ticketHierarchy);
        AppendTpm2b(body, ticketDigest);

        return [.. body];
    }

    /// <summary>
    /// Frames a <c>TPM2_PolicySecret()</c> body (TPM 2.0 Library Part 3, clause 23.4): the two handles, a
    /// single <c>TPM_RS_PW</c> authorization slot, then nonceTPM, cpHashA, policyRef and expiration.
    /// </summary>
    /// <param name="authHandle">The entity whose authorization stands in for the assertion.</param>
    /// <param name="policySession">The policy session handle.</param>
    /// <param name="nonceTpm">The <c>TPM2B_NONCE</c> octets.</param>
    /// <param name="cpHashA">The <c>TPM2B_DIGEST</c> octets.</param>
    /// <param name="policyRef">The <c>TPM2B_NONCE</c> octets.</param>
    /// <param name="expiration">The requested expiration.</param>
    /// <returns>The framed body.</returns>
    private static byte[] BuildPolicySecretBody(
        uint authHandle, uint policySession, byte[] nonceTpm, byte[] cpHashA, byte[] policyRef, int expiration)
    {
        List<byte> authArea = [];
        AppendUInt32(authArea, (uint)TpmRh.TPM_RH_PW);
        AppendTpm2b(authArea, []);
        authArea.Add(ContinueSessionAttribute);
        AppendTpm2b(authArea, []);

        List<byte> body = [];
        AppendUInt32(body, authHandle);
        AppendUInt32(body, policySession);
        AppendUInt32(body, (uint)authArea.Count);
        body.AddRange(authArea);
        AppendTpm2b(body, nonceTpm);
        AppendTpm2b(body, cpHashA);
        AppendTpm2b(body, policyRef);
        AppendUInt32(body, (uint)expiration);

        return [.. body];
    }

    /// <summary>
    /// Frames a <c>TPM2_PolicySigned()</c> body (TPM 2.0 Library Part 3, clause 23.3, Table 144): the two
    /// handles, then nonceTPM, cpHashA, policyRef, expiration and an ECDSA <c>TPMT_SIGNATURE</c>.
    /// </summary>
    /// <param name="authObject">The key whose signature authorizes the assertion.</param>
    /// <param name="policySession">The policy session handle.</param>
    /// <param name="nonceTpm">The <c>TPM2B_NONCE</c> octets.</param>
    /// <param name="cpHashA">The <c>TPM2B_DIGEST</c> octets.</param>
    /// <param name="policyRef">The <c>TPM2B_NONCE</c> octets.</param>
    /// <param name="expiration">The requested expiration.</param>
    /// <param name="signatureR">The signature's r component.</param>
    /// <param name="signatureS">The signature's s component.</param>
    /// <returns>The framed body.</returns>
    private static byte[] BuildPolicySignedBody(
        uint authObject, uint policySession, byte[] nonceTpm, byte[] cpHashA, byte[] policyRef, int expiration,
        byte[] signatureR, byte[] signatureS)
    {
        List<byte> body = [];
        AppendUInt32(body, authObject);
        AppendUInt32(body, policySession);
        AppendTpm2b(body, nonceTpm);
        AppendTpm2b(body, cpHashA);
        AppendTpm2b(body, policyRef);
        AppendUInt32(body, (uint)expiration);
        AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_ECDSA);
        AppendUInt16(body, (ushort)SessionAlg);
        AppendTpm2b(body, signatureR);
        AppendTpm2b(body, signatureS);

        return [.. body];
    }

    /// <summary>
    /// Frames a <c>TPM2_PolicyAuthorize()</c> body (TPM 2.0 Library Part 3, clause 23.16, Table 170): the
    /// policy session handle, then approvedPolicy, policyRef, keySign and the <c>TPMT_TK_VERIFIED</c>.
    /// </summary>
    /// <param name="policySession">The policy session handle.</param>
    /// <param name="approvedPolicy">The <c>TPM2B_DIGEST</c> octets.</param>
    /// <param name="policyRef">The <c>TPM2B_NONCE</c> octets.</param>
    /// <param name="keySign">The <c>TPM2B_NAME</c> octets.</param>
    /// <param name="checkTicketTag">The ticket's structure tag.</param>
    /// <param name="checkTicketHierarchy">The ticket's hierarchy.</param>
    /// <param name="checkTicketDigest">The ticket's own <c>TPM2B_DIGEST</c> octets.</param>
    /// <returns>The framed body.</returns>
    private static byte[] BuildPolicyAuthorizeBody(
        uint policySession, byte[] approvedPolicy, byte[] policyRef, byte[] keySign,
        ushort checkTicketTag, uint checkTicketHierarchy, byte[] checkTicketDigest)
    {
        List<byte> body = [];
        AppendUInt32(body, policySession);
        AppendTpm2b(body, approvedPolicy);
        AppendTpm2b(body, policyRef);
        AppendTpm2b(body, keySign);
        AppendUInt16(body, checkTicketTag);
        AppendUInt32(body, checkTicketHierarchy);
        AppendTpm2b(body, checkTicketDigest);

        return [.. body];
    }

    /// <summary>
    /// Frames a <c>TPM2_PolicyOR()</c> body (TPM 2.0 Library Part 3, clause 23.6): the policy session handle,
    /// then the <c>TPML_DIGEST</c> count and its branches.
    /// </summary>
    /// <param name="policySession">The policy session handle.</param>
    /// <param name="branches">The branch digests, each framed as its own <c>TPM2B</c>.</param>
    /// <returns>The framed body.</returns>
    private static byte[] BuildPolicyOrBody(uint policySession, byte[][] branches)
    {
        List<byte> body = [];
        AppendUInt32(body, policySession);
        AppendUInt32(body, (uint)branches.Length);
        foreach(byte[] branch in branches)
        {
            AppendTpm2b(body, branch);
        }

        return [.. body];
    }

    /// <summary>
    /// Frames a <c>TPM2_PolicyPCR()</c> body (TPM 2.0 Library Part 3, clause 23.7): the policy session handle,
    /// then pcrDigest as a <c>TPM2B</c> and the already-marshaled <c>TPML_PCR_SELECTION</c> verbatim, since it
    /// is the command's own final parameter and never wrapped in a further <c>TPM2B</c>.
    /// </summary>
    /// <param name="policySession">The policy session handle.</param>
    /// <param name="pcrDigest">The <c>pcrDigest</c> octets, possibly empty.</param>
    /// <param name="pcrSelectionOctets">The already-marshaled <c>TPML_PCR_SELECTION</c>.</param>
    /// <returns>The framed body.</returns>
    private static byte[] BuildPolicyPcrBody(uint policySession, byte[] pcrDigest, byte[] pcrSelectionOctets)
    {
        List<byte> body = [];
        AppendUInt32(body, policySession);
        AppendTpm2b(body, pcrDigest);
        body.AddRange(pcrSelectionOctets);

        return [.. body];
    }

    /// <summary>
    /// Builds a <c>TPML_PCR_SELECTION</c> octet sequence naming <paramref name="selectionCount"/> banks, each
    /// selecting PCR 0 over the three octets that cover PCRs 0 to 23 — the shape the typed command inputs cannot
    /// express, used to drive the list's count bound.
    /// </summary>
    /// <param name="selectionCount">How many bank selections to name.</param>
    /// <returns>The marshaled selection octets.</returns>
    private static byte[] BuildPcrSelectionOctets(int selectionCount)
    {
        const int SelectionSize = sizeof(ushort) + sizeof(byte) + 3;
        byte[] octets = new byte[sizeof(uint) + (selectionCount * SelectionSize)];
        var writer = new TpmWriter(octets);
        writer.WriteUInt32((uint)selectionCount);
        for(int i = 0; i < selectionCount; i++)
        {
            writer.WriteUInt16((ushort)SessionAlg);
            writer.WriteByte(3);
            writer.WriteByte(0x01);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
        }

        return octets;
    }

    /// <summary>
    /// Builds a single-entry <c>TPML_PCR_SELECTION</c> octet sequence naming one bank with a caller-chosen
    /// <c>sizeofSelect</c> — the shape the typed command inputs cannot express, used to drive the member's own
    /// width bound (TPM 2.0 Library Part 2, clause 10.5.2, Table 107).
    /// </summary>
    /// <param name="sizeofSelect">The declared bitmap width.</param>
    /// <returns>The marshaled selection octets.</returns>
    private static byte[] BuildSinglePcrSelectionOctets(byte sizeofSelect)
    {
        byte[] octets = new byte[sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeofSelect];
        var writer = new TpmWriter(octets);
        writer.WriteUInt32(1);
        writer.WriteUInt16((ushort)SessionAlg);
        writer.WriteByte(sizeofSelect);
        for(int i = 0; i < sizeofSelect; i++)
        {
            writer.WriteByte(0x00);
        }

        return octets;
    }

    /// <summary>
    /// Submits a hand-framed command straight to the simulator and returns the response code its header
    /// carries. This is the only way to drive a wire value the typed command inputs refuse to build, which is
    /// exactly what a parse-time bound must be proved against.
    /// </summary>
    /// <param name="simulator">The simulator to submit to.</param>
    /// <param name="pool">The memory pool the command and response buffers are rented from.</param>
    /// <param name="tag">The command's structure tag.</param>
    /// <param name="commandCode">The command code.</param>
    /// <param name="body">The already-framed handle and parameter octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmStConstants tag, TpmCcConstants commandCode, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)tag, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "A framed command must always come back as a response buffer, never as a transport failure.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Creates an ECC P-256 ECDSA/SHA-256 signing key under the owner hierarchy, the authority whose signature
    /// a <c>TPM2_PolicySigned()</c> honours and whose Name is <c>keySign</c> for <c>TPM2_PolicyAuthorize()</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateEccAuthorityKeyAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(SessionAlg), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 authority key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Signs a <c>TPM2_PolicySigned()</c> authorization over the session's own retained nonceTPM through the
    /// production <c>TPM2_Sign()</c> wire path (<c>aHash = H(nonceTPM ‖ expiration ‖ cpHashA ‖ policyRef)</c>,
    /// TPM 2.0 Library Part 3, clause 23.3), and hands the octets back so every carrier the signing step
    /// rented is already returned before a balance is read.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authorityHandle">The authority key's handle.</param>
    /// <param name="nonceTpm">The session's retained nonceTPM, which the authorization binds to.</param>
    /// <returns>The IEEE P1363 <c>r ‖ s</c> signature octets.</returns>
    private async Task<byte[]> SignPolicySignedAuthorizationAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject authorityHandle, byte[] nonceTpm)
    {
        byte[] message = new byte[nonceTpm.Length + sizeof(int) + PolicyRef.Length];
        var writer = new TpmWriter(message);
        writer.WriteBytes(nonceTpm);
        writer.WriteInt32(0);
        writer.WriteBytes(PolicyRef);

        byte[] aHash = await ComputeSha256Async(message, pool).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(authorityHandle, aHash, SessionAlg, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authority over aHash) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        using Signature p1363Signature = ConcatenateP1363(
            signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), pool);

        return p1363Signature.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Has the authority key sign off on <paramref name="approvedPolicy"/> and turns that signature into the
    /// real <c>TPMT_TK_VERIFIED</c> <c>TPM2_PolicyAuthorize()</c> re-verifies (<c>aHash = H(approvedPolicy ‖
    /// policyRef)</c>, TPM 2.0 Library Part 3, clause 23.16), returning the ticket as plain octets so the
    /// response that carried it is already released before a balance is read.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authorityHandle">The authority key's handle.</param>
    /// <param name="approvedPolicy">The policy digest the authority approves.</param>
    /// <returns>The verified approval's ticket fields.</returns>
    private async Task<VerifiedApproval> ApproveWithAuthorityAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject authorityHandle, byte[] approvedPolicy)
    {
        byte[] message = new byte[approvedPolicy.Length + PolicyRef.Length];
        approvedPolicy.CopyTo(message.AsSpan());
        PolicyRef.CopyTo(message.AsSpan(approvedPolicy.Length));

        byte[] aHash = await ComputeSha256Async(message, pool).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(authorityHandle, aHash, SessionAlg, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authority over the approval aHash) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        using Signature p1363Signature = ConcatenateP1363(
            signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), pool);

        using VerifySignatureInput verifyInput = VerifySignatureInput.ForEcdsa(
            authorityHandle, aHash, p1363Signature.AsReadOnlySpan(), SessionAlg, pool);
        TpmResult<VerifySignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifySignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifySignature (authority ticket) failed: '{verifyResult.ResponseCode}'.");

        using VerifySignatureResponse verified = verifyResult.Value;
        Assert.IsFalse(verified.Validation.IsNull, "A real-hierarchy authority key must produce a usable (non-NULL) ticket.");

        return new VerifiedApproval(
            (ushort)verified.Validation.Tag, verified.Validation.Hierarchy.Value, verified.Validation.Metadata, verified.Validation.Hmac.ToArray());
    }

    /// <summary>
    /// The <c>TPM2_VerifyDigestSignature()</c> counterpart of <see cref="ApproveWithAuthorityAsync"/>: has the
    /// authority key sign off on <paramref name="approvedPolicy"/> and turns that signature into a real
    /// <c>TPM_ST_DIGEST_VERIFIED</c> <c>TPMT_TK_VERIFIED</c> via the digest-only verifier (TPM 2.0 Library Part
    /// 3, clause 23.16.2's preferred ticket producer for <c>TPM2_PolicyAuthorize()</c>), returning the ticket as
    /// plain octets so the response that carried it is already released before a balance is read.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="authorityHandle">The authority key's handle.</param>
    /// <param name="approvedPolicy">The policy digest the authority approves.</param>
    /// <returns>The verified approval's ticket fields, tagged <c>TPM_ST_DIGEST_VERIFIED</c> with metadata set.</returns>
    private async Task<VerifiedApproval> ApproveWithAuthorityViaDigestSignatureAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject authorityHandle, byte[] approvedPolicy)
    {
        byte[] message = new byte[approvedPolicy.Length + PolicyRef.Length];
        approvedPolicy.CopyTo(message.AsSpan());
        PolicyRef.CopyTo(message.AsSpan(approvedPolicy.Length));

        byte[] aHash = await ComputeSha256Async(message, pool).ConfigureAwait(false);

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using SignInput signInput = SignInput.ForEcdsa(authorityHandle, aHash, SessionAlg, pool);
        TpmResult<SignResponse> signResult = await TpmCommandExecutor.ExecuteAsync<SignResponse>(
            tpm, signInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(signResult.IsSuccess, $"TPM2_Sign (authority over the approval aHash) failed: '{signResult.ResponseCode}'.");

        using SignResponse signature = signResult.Value;
        using Signature p1363Signature = ConcatenateP1363(
            signature.Signature.SignatureR!.AsReadOnlySpan(), signature.Signature.SignatureS!.AsReadOnlySpan(), pool);

        using VerifyDigestSignatureInput verifyInput = VerifyDigestSignatureInput.ForEcdsa(
            authorityHandle, aHash, p1363Signature.AsReadOnlySpan(), SessionAlg, pool);
        TpmResult<VerifyDigestSignatureResponse> verifyResult = await TpmCommandExecutor.ExecuteAsync<VerifyDigestSignatureResponse>(
            tpm, verifyInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verifyResult.IsSuccess, $"TPM2_VerifyDigestSignature (authority ticket) failed: '{verifyResult.ResponseCode}'.");

        using VerifyDigestSignatureResponse verified = verifyResult.Value;
        Assert.IsFalse(verified.Validation.IsNull, "A real-hierarchy authority key must produce a usable (non-NULL) ticket.");
        Assert.IsTrue(verified.Validation.Metadata.HasValue, "A TPM_ST_DIGEST_VERIFIED ticket must carry metadata (Table 111's digestVerified arm).");

        return new VerifiedApproval(
            (ushort)verified.Validation.Tag, verified.Validation.Hierarchy.Value, verified.Validation.Metadata, verified.Validation.Hmac.ToArray());
    }

    /// <summary>
    /// Mints a real <c>TPM_ST_AUTH_SECRET</c> ticket against the owner hierarchy over a session-bound
    /// <c>TPM2_PolicySecret()</c> (a negative expiration, TPM 2.0 Library Part 3, clause 23.4), then flushes
    /// the minting session so the replay runs against a session that never saw the original command.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The minted ticket's wire fields plus the authName a replay must present.</returns>
    private async Task<MintedAuthTicket> MintSessionBoundSecretTicketAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartedPolicySession mintSession = await StartPolicySessionWithNonceAsync(tpm, registry, pool).ConfigureAwait(false);
        try
        {
            using PolicySecretInput input = PolicySecretInput.Create(
                (uint)TpmRh.TPM_RH_OWNER, mintSession.Handle, mintSession.NonceTpm, ReadOnlySpan<byte>.Empty, PolicyRef, expiration: -3600, pool);
            using TpmPasswordSession ownerAuth = TpmPasswordSession.Create(ReadOnlySpan<byte>.Empty, pool);

            TpmResult<PolicySecretResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"PolicySecret (ticket mint) failed: '{result.ResponseCode}'.");

            using PolicySecretResponse minted = result.Value;
            Assert.IsFalse(minted.PolicyTicket.IsNull, "A negative expiration must mint a real ticket.");

            return new MintedAuthTicket(
                minted.Timeout.ToArray(), (ushort)minted.PolicyTicket.Tag, minted.PolicyTicket.Hierarchy.Value,
                minted.PolicyTicket.Digest.ToArray(), PermanentHandleName(TpmRh.TPM_RH_OWNER));
        }
        finally
        {
            await FlushAsync(tpm, registry, pool, mintSession.Handle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Hashes a message through the project's own registered SHA-256 seam, so no test here reaches past the
    /// library for its oracle.
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The digest octets.</returns>
    private async Task<byte[]> ComputeSha256Async(byte[] message, BaseMemoryPool pool)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            message, DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Concatenates the ECDSA r and s components into the IEEE P1363 <c>r ‖ s</c> form, left-padding each to
    /// the P-256 field width.
    /// </summary>
    /// <param name="r">The signature's r component.</param>
    /// <param name="s">The signature's s component.</param>
    /// <param name="pool">The memory pool backing the returned signature.</param>
    /// <returns>The concatenated signature as a pooled carrier the caller disposes.</returns>
    private static Signature ConcatenateP1363(ReadOnlySpan<byte> r, ReadOnlySpan<byte> s, BaseMemoryPool pool)
    {
        const int P256ComponentSize = 32;
        IMemoryOwner<byte> owner = pool.Rent(2 * P256ComponentSize);
        Span<byte> destination = owner.Memory.Span[..(2 * P256ComponentSize)];
        destination.Clear();
        CopyFixed(r, destination[..P256ComponentSize]);
        CopyFixed(s, destination.Slice(P256ComponentSize, P256ComponentSize));

        return new Signature(owner, CryptoTags.P256Signature);

        //Copies a component right-aligned into the fixed field width, truncating leading octets when over-long.
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

    /// <summary>A started policy session's handle paired with the nonceTPM the start returned.</summary>
    /// <param name="Handle">The session handle.</param>
    /// <param name="NonceTpm">The session's retained nonceTPM, copied out so it outlives the start response.</param>
    private sealed record StartedPolicySession(uint Handle, byte[] NonceTpm);

    /// <summary>The wire fields of a minted <c>TPMT_TK_AUTH</c> plus the authName a replay must present.</summary>
    /// <param name="Timeout">The <c>TPM2B_TIMEOUT</c> octets the mint returned.</param>
    /// <param name="Tag">The ticket's structure tag.</param>
    /// <param name="Hierarchy">The hierarchy whose proof keys the ticket.</param>
    /// <param name="Digest">The ticket's HMAC octets.</param>
    /// <param name="AuthName">The authorizing entity's Name.</param>
    private sealed record MintedAuthTicket(byte[] Timeout, ushort Tag, uint Hierarchy, byte[] Digest, byte[] AuthName);

    /// <summary>The wire fields of the <c>TPMT_TK_VERIFIED</c> an authority's approval produced.</summary>
    /// <param name="TicketTag">The ticket's structure tag.</param>
    /// <param name="TicketHierarchy">The signing key's hierarchy.</param>
    /// <param name="TicketMetadata">The ticket's <c>[tag]metadata</c> field (Table 111); <see langword="null"/> under <c>TPM_ST_VERIFIED</c>, the verified digest's hash algorithm under <c>TPM_ST_DIGEST_VERIFIED</c>.</param>
    /// <param name="TicketDigest">The ticket's HMAC octets.</param>
    private sealed record VerifiedApproval(ushort TicketTag, uint TicketHierarchy, TpmiAlgHash? TicketMetadata, byte[] TicketDigest);

    /// <summary>Issues a <c>TPM2_PolicyCommandCode()</c> and asserts it succeeded.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session being extended.</param>
    /// <param name="restrictedCommand">The command code the policy is restricted to.</param>
    private async Task AssertCommandCodeAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint policySession, TpmCcConstants restrictedCommand)
    {
        PolicyCommandCodeInput input = PolicyCommandCodeInput.Create(policySession, restrictedCommand);
        TpmResult<PolicyCommandCodeResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyCommandCodeResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PolicyCommandCode failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues a <c>TPM2_PolicyAuthValue()</c> and asserts it succeeded.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session being extended.</param>
    private async Task AssertAuthValueAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint policySession)
    {
        PolicyAuthValueInput input = PolicyAuthValueInput.ForSession(policySession);
        TpmResult<PolicyAuthValueResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyAuthValueResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PolicyAuthValue failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues a <c>TPM2_PolicyPCR()</c> over a single selected register with a non-empty caller digest.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session being extended.</param>
    private async Task AssertPcrAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint policySession)
    {
        using TpmlPcrSelection selection = TpmlPcrSelection.Create(SessionAlg, [0], pool);
        using PolicyPcrInput input = PolicyPcrInput.Create(policySession, DistinctDigest(0x70), selection, pool);

        TpmResult<PolicyPcrResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyPcrResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PolicyPCR failed: '{result.ResponseCode}'.");
    }

    /// <summary>Issues a <c>TPM2_PolicySecret()</c> against the owner hierarchy's empty authorization value.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session being extended.</param>
    /// <param name="cpHashA">The command-parameter digest the authorization is limited to, always non-empty here so the carrier it drives is a real rental.</param>
    /// <param name="expiration">The requested expiration; negative requests a ticket.</param>
    /// <returns>The command result, not asserted for success.</returns>
    private async Task<TpmResult<PolicySecretResponse>> AssertSecretAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint policySession, byte[] cpHashA, int expiration)
    {
        using PolicySecretInput input = PolicySecretInput.Create(
            (uint)TpmRh.TPM_RH_OWNER, policySession, ReadOnlySpan<byte>.Empty, cpHashA, PolicyRef, expiration, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.Create(ReadOnlySpan<byte>.Empty, pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads a session's current policyDigest through <c>TPM2_PolicyGetDigest()</c>.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session to read.</param>
    /// <returns>The reported digest octets.</returns>
    private async Task<byte[]> ReadPolicyDigestAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint policySession)
    {
        PolicyGetDigestInput input = PolicyGetDigestInput.ForSession(policySession);
        TpmResult<PolicyGetDigestResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicyGetDigestResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PolicyGetDigest failed: '{result.ResponseCode}'.");

        using PolicyGetDigestResponse response = result.Value;

        return response.PolicyDigest.AsReadOnlySpan().ToArray();
    }

    /// <summary>Starts an unbound, unsalted policy or trial session and returns its handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="isTrial">Whether to start a trial session rather than one that authorizes.</param>
    /// <returns>The started session's handle.</returns>
    private async Task<uint> StartPolicySessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, bool isTrial)
    {
        StartAuthSessionInput input = isTrial
            ? StartAuthSessionInput.CreateTrialPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool)
            : StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool);

        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (policy) failed: '{result.ResponseCode}'.");

        using StartAuthSessionResponse response = result.Value;

        return response.SessionHandle.Value;
    }

    /// <summary>
    /// Starts an unbound, unsalted real policy session and carries its retained nonceTPM out as octets, which is
    /// what a <c>TPM2_PolicySigned()</c>/<c>TPM2_PolicySecret()</c> authorization binds itself to (TPM 2.0
    /// Library Part 3, clause 23.2.2).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The started session's handle and nonceTPM.</returns>
    private async Task<StartedPolicySession> StartPolicySessionWithNonceAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput input = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (policy) failed: '{result.ResponseCode}'.");

        using StartAuthSessionResponse response = result.Value;
        Assert.IsFalse(response.NonceTPM.IsEmpty, "A policy session's nonceTPM must be a real, non-placeholder value.");

        return new StartedPolicySession(response.SessionHandle.Value, response.NonceTPM.AsReadOnlySpan().ToArray());
    }

    /// <summary>Flushes a transient handle, asserting the command succeeded.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, FlushContextInput.ForHandle(handle), [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"FlushContext failed: '{result.ResponseCode}'.");
    }

    /// <summary>Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-policy-carriers", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await BringOperationalAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator to move it into the operational phase.</summary>
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

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyCommandCode, TpmResponseCodec.PolicyCommandCode);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyAuthValue, TpmResponseCodec.PolicyAuthValue);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyPCR, TpmResponseCodec.PolicyPcr);
        _ = registry.Register(TpmCcConstants.TPM_CC_PCR_Read, TpmResponseCodec.PcrRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyOR, TpmResponseCodec.PolicyOr);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyGetDigest, TpmResponseCodec.PolicyGetDigest);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySigned, TpmResponseCodec.PolicySigned);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyTicket, TpmResponseCodec.PolicyTicket);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyAuthorize, TpmResponseCodec.PolicyAuthorize);
        _ = registry.Register(TpmCcConstants.TPM_CC_SetPrimaryPolicy, TpmResponseCodec.SetPrimaryPolicy);
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Sign, TpmResponseCodec.Sign);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifySignature, TpmResponseCodec.VerifySignature);
        _ = registry.Register(TpmCcConstants.TPM_CC_VerifyDigestSignature, TpmResponseCodec.VerifyDigestSignature);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
