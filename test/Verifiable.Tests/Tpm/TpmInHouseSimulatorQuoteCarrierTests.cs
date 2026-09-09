using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves the pooled-carrier ownership of <c>TPM2_Quote()</c>'s wire parameters (TPM 2.0 Library Part 3, clause
/// 18.4, Table 101) against the in-house behavioural <see cref="TpmSimulator"/>: the <c>qualifyingData</c>
/// (<c>TPM2B_DATA</c>) and <c>PCRselect</c> (<c>TPML_PCR_SELECTION</c>) carriers the parser rents reach the pool
/// again on every path a command can leave by — refused at the entry transition, refused at the session
/// continuation, refused for a mismatched command HMAC, and attested successfully — and a frame the parser
/// itself refuses rents nothing at all.
/// </summary>
/// <remarks>
/// <para>
/// The instrument is <see cref="MeteredHousePool"/>: a genuine <see cref="BaseMemoryPool"/> whose own rent and
/// return telemetry is observed, so nothing here depends on a seam in production code. Every value driven
/// through a carrier under test is deliberately NON-EMPTY, because an empty one parses to the type's shared
/// dispose-immune sentinel, which rents nothing and would make a balance assertion vacuous.
/// </para>
/// <para>
/// Each measured region also pins that the simulator genuinely rented the qualifying-data carrier, by counting
/// rentals of exactly <see cref="CarrierProofNonce"/>'s width across the command: a balance that returns to its
/// baseline proves nothing unless something was handed out in between.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorQuoteCarrierTests
{
    /// <summary>The PCR bank the quotes here select from.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The hash algorithm for every real HMAC session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The signing key's authValue for the session-authorized fixtures.</summary>
    private const string SignKeyPassword = "quote-carrier-signing-key-auth";

    /// <summary>The PCRs the quotes cover; two PCRs exercise the composite-digest concatenation order.</summary>
    private static int[] PcrIndices { get; } = [0, 7];

    /// <summary>
    /// The caller nonce these tests drive as <c>qualifyingData</c>. Its 61-octet width is deliberately unlike
    /// any digest, key, or nonce width the surrounding machinery rents, so a rent of exactly this size across a
    /// command identifies the <c>TPM2B_DATA</c> carrier the parser created.
    /// </summary>
    private static byte[] CarrierProofNonce { get; } = "Quote carrier ownership proof nonce for the in-house TPM 2.0."u8.ToArray();

    /// <summary>The signing key's authValue in wire form — the UTF-8 octets of <see cref="SignKeyPassword"/>.</summary>
    private static byte[] SignKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SignKeyPassword);

    /// <summary>A wrong guess at the signing key's authValue, distinct from <see cref="SignKeyPasswordBytes"/>.</summary>
    private static byte[] WrongSignKeyPasswordBytes { get; } = [0x71, 0x72, 0x73, 0x74];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A <c>TPM2_Quote()</c> refused by the entry transition — the signHandle (the sole handle, index 0) is
    /// transient-range but resolves to no loaded object, so TPM 2.0 Library Part 3, clause 5.4 step 2.1 answers
    /// <c>TPM_RC_REFERENCE_H0</c> before any parameter is looked at — returns every carrier the parser rented:
    /// the sign slot's supplied password, the <c>TPM2B_DATA</c> qualifying data, and the
    /// <c>TPML_PCR_SELECTION</c>. The refusing arm reaches them through the request record's own
    /// <c>IDisposable.Dispose</c>, which is the only owner they ever had, because a handle refusal transfers
    /// nothing into an action.
    /// </summary>
    [TestMethod]
    public async Task RefusedQuoteAtTheEntryTransitionReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmPasswordSession keyAuth = TpmPasswordSession.Create(WrongSignKeyPasswordBytes, trackingPool.Pool);
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, trackingPool.Pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(
                TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase), CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, trackingPool.Pool);

            long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [keyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_REFERENCE_H0, result.ResponseCode,
                "A transient-range signHandle (the sole handle, index 0) that resolves to no loaded object is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");

            Assert.IsGreaterThan(
                qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
                "The parser must have rented the qualifying-data carrier before the transition refused, or the balance below proves nothing.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A handle refusal must return the parse-rented password, qualifying-data, and PCR-selection carriers to the pool.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_Quote()</c> refused by the continuation — the scheme hash algorithm is one
    /// the attest digest path does not implement, so <c>TPM_RC_HASH</c> is answered only AFTER the command HMAC
    /// has verified (TPM 2.0 Library Part 3, clause 5.6 orders authorization ahead of the parameter checks) —
    /// returns every carrier the parser rented. This is the arm that runs one step further than the entry
    /// refusal: the request has already travelled through the HMAC-verification action and back.
    /// </summary>
    [TestMethod]
    public async Task RefusedQuoteAtTheOverSessionContinuationReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<QuoteResponse> result = await QuoteOverRealSignSessionAsync(
            tpm, registry, trackingPool, ak, CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA1, SignKeyPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 1), result.ResponseCode,
            "A scheme hash the attest digest path does not implement is refused with TPM_RC_HASH after the command HMAC has verified.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A continuation refusal must return the parse-rented HMAC, qualifying-data, and PCR-selection carriers to the pool.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_Quote()</c> whose sign slot presents a command HMAC computed over the wrong
    /// authValue never reaches its continuation at all: the verification step terminates the command with the
    /// session-index-encoded <c>TPM_RC_AUTH_FAIL</c> (TPM 2.0 Library Part 2, clause 6.6.2). The queued request
    /// still owns every carrier the parser rented, and the mismatch path releases them before the rejection is
    /// framed.
    /// </summary>
    [TestMethod]
    public async Task QuoteOverSessionWithAMismatchedCommandHmacReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<QuoteResponse> result = await QuoteOverRealSignSessionAsync(
            tpm, registry, trackingPool, ak, CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA256, WrongSignKeyPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
            "A wrong authValue folded into the sign session's command HMAC must be a genuine authorization failure, or this path proves nothing about a mismatch.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A command-HMAC mismatch must return the parse-rented HMAC, qualifying-data, and PCR-selection carriers to the pool.");
    }

    /// <summary>
    /// A successful session-authorized <c>TPM2_Quote()</c> returns every carrier the parser rented once the
    /// response has been consumed: the qualifying data and the PCR selection transferred out of the request into
    /// the quote action, so it is the attesting effect — not the continuation — that is their terminal owner,
    /// and the attestation has copied their octets by the time it releases them (TPM 2.0 Library Part 3, clause
    /// 18.4; Part 1, clause 15.6.1 for the response entry).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulQuoteOverSessionReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);

        TpmResult<QuoteResponse> result = await QuoteOverRealSignSessionAsync(
            tpm, registry, trackingPool, ak, CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA256, SignKeyPasswordBytes).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The session-authorized quote must attest with the correct authValue: '{result.ResponseCode}'.");
        result.Value.Dispose();

        Assert.IsGreaterThan(
            qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
            "The parser must have rented the qualifying-data carrier for the successful command, or the balance below proves nothing.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful quote must return the parse-rented HMAC, qualifying-data, and PCR-selection carriers to the pool once the response is disposed.");
    }

    /// <summary>
    /// A <c>qualifyingData</c> wider than <c>TPM2B_DATA</c>'s declared bound — <c>sizeof(TPMT_HA)</c>, the
    /// 2-octet algorithm identifier plus the largest supported digest (TPM 2.0 Library Part 2, clause 10.3.3,
    /// Table 91) — is refused with <c>TPM_RC_SIZE</c> while the frame is still being parsed, so the parse rents
    /// nothing at all: the pool balance does not move, and the refusal is a response code rather than an
    /// exception escaping the command surface.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithQualifyingDataOverTheDataBoundIsRefusedAtParseAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        byte[] overBound = new byte[Tpm2bData.MaxSize + 1];
        overBound.AsSpan().Fill(0x5A);

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmPasswordSession keyAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, trackingPool.Pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(
                ak.ObjectHandle, overBound, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, trackingPool.Pool);

            long overBoundRentsBefore = trackingPool.RentedCountOfSize(overBound.Length);

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [keyAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), result.ResponseCode,
                "A qualifyingData wider than sizeof(TPMT_HA) is TPM_RC_SIZE at qualifyingData, parameter 1 of the Quote command table (TPM 2.0 Library Part 2, clause 10.3.3, Table 91).");

            Assert.AreEqual(
                overBoundRentsBefore, trackingPool.RentedCountOfSize(overBound.Length),
                "A frame the parser refuses must not have rented a carrier for the over-bound value it refused.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A parse-time refusal rents nothing, so the pool balance may not move across it.");
    }

    /// <summary>
    /// A <c>TPML_PCR_SELECTION</c> naming more banks than the list admits — its count field is bounded by
    /// HASH_COUNT selections (TPM 2.0 Library Part 2, clause 10.8.7, Table 128, whose out-of-range count is
    /// <c>#TPM_RC_SIZE</c>) — is refused with <c>TPM_RC_SIZE</c> while the frame is still being parsed, rather
    /// than being carried into the attestation. The frame is composed octet by octet because the typed command
    /// input cannot express a selection this shape.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithMoreSelectionsThanTheListAdmitsIsRefusedWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        byte[] admittedSelection = BuildSelectionOctets(TpmlPcrSelection.MaxSelections);
        byte[] overBoundSelection = BuildSelectionOctets(TpmlPcrSelection.MaxSelections + 1);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants admittedCode = await SubmitHandFramedQuoteAsync(
            simulator, trackingPool.Pool, ak.ObjectHandle, CarrierProofNonce, admittedSelection).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, admittedCode,
            "A selection naming exactly HASH_COUNT banks is inside the list's declared bound and must be attested.");

        TpmRcConstants overBoundCode = await SubmitHandFramedQuoteAsync(
            simulator, trackingPool.Pool, ak.ObjectHandle, CarrierProofNonce, overBoundSelection).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 2), overBoundCode,
            "PCRselect is TPM2_Quote()'s third parameter (Table 101, index 2); a selection naming more than HASH_COUNT banks is out of the list's declared bound and is parameter-encoded TPM_RC_SIZE (TPM 2.0 Library Part 2, clause 10.8.7, Table 128).");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Neither the admitted nor the refused selection may leave a carrier outstanding.");
    }

    /// <summary>
    /// A <c>TPML_PCR_SELECTION</c> that is BOTH over-bound (a declared count of 17, one more than
    /// <see cref="TpmlPcrSelection.MaxSelections"/>) AND truncated (far too few octets follow to walk even one
    /// entry) answers <c>TPM_RC_SIZE</c> rather than <c>TPM_RC_INSUFFICIENT</c>: the shared probe walker checks
    /// the count bound immediately after reading <c>count</c>, before any element is walked, so the bound wins
    /// over the truncation it would otherwise have reported further into the list. This is the compound case for
    /// every PCR-select reader that shares the walker, Quote included.
    /// </summary>
    [TestMethod]
    public async Task QuoteWithAnOverBoundAndTruncatedSelectionAnswersSizeNotInsufficient()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        //count = 17, then two octets — nowhere near enough to walk even one TPMS_PCR_SELECTION entry (which
        //needs at least a UINT16 hash plus a BYTE sizeofSelect), let alone seventeen.
        byte[] overBoundAndTruncated = [0x00, 0x00, 0x00, 0x11, 0x00];

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants code = await SubmitHandFramedQuoteAsync(
            simulator, trackingPool.Pool, ak.ObjectHandle, CarrierProofNonce, overBoundAndTruncated).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 2), code,
            "PCRselect is TPM2_Quote()'s third parameter (Table 101, index 2); a list that is both over-bound and truncated answers the count bound before the truncation it would otherwise report, parameter-encoded.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refused probe must rent nothing.");
    }

    /// <summary>
    /// The attested <c>TPMS_QUOTE_INFO.pcrSelect</c> reproduces the request's <c>TPML_PCR_SELECTION</c> octet for
    /// octet when every bit of that selection names a register the simulator actually holds: the selection
    /// travels through the simulator as a parsed structure, the filtering that clears unheld bits finds nothing
    /// to clear, and the structure marshals back to exactly the octets it was parsed from.
    /// </summary>
    /// <remarks>
    /// <c>pcrSelect</c> is "information on algID, PCR selected and digest" for the PCR the digest covers (TPM 2.0
    /// Library Part 2, clause 10.11.4, Table 146), so byte-identity with the request is the special case — the
    /// one where nothing was filtered — rather than the rule.
    /// <see cref="QuotedPcrSelectClearsBitsForABankTheModelDoesNotImplement"/> and
    /// <see cref="QuotedPcrSelectClearsBitsForPcrIndexesTheModelDoesNotHold"/> pin the general case.
    /// </remarks>
    [TestMethod]
    public async Task QuotedPcrSelectRoundTripsAnUnfilteredSelectionOctetForOctet()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        //One bank the simulator holds, selecting PCR 0, PCR 7, and PCR 23 — every one of them a register it
        //implements: count = 1, then { SHA-256, 3, 0x81 0x00 0x80 }.
        byte[] selectionOctets =
        [
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x0B, 0x03, 0x81, 0x00, 0x80
        ];

        using IMemoryOwner<byte> commandOwner = FrameQuoteCommand(pool, ak.ObjectHandle, CarrierProofNonce, selectionOctets, out int commandLength);
        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..commandLength], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed quote must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "The hand-framed quote must be attested.");

        using Tpm2bAttest attest = Tpm2bAttest.Parse(ref reader, pool);
        TpmsQuoteInfo? quoteInfo = attest.AttestationData.Attested.Quote;
        Assert.IsNotNull(quoteInfo, "A TPM_ST_ATTEST_QUOTE attestation carries a TPMS_QUOTE_INFO body.");
        Assert.HasCount(1, quoteInfo.PcrSelect.Selections, "The requested bank must survive into the attestation.");

        byte[] echoed = new byte[quoteInfo.PcrSelect.GetSerializedSize()];
        var echoWriter = new TpmWriter(echoed);
        quoteInfo.PcrSelect.WriteTo(ref echoWriter);

        Assert.AreSequenceEqual(
            selectionOctets, echoed,
            "A selection naming only implemented registers must marshal back to exactly the TPML_PCR_SELECTION octets the caller sent.");
    }

    /// <summary>
    /// A selection naming a bank the model has not allocated is attested with every bit of that bank's entry
    /// CLEARED, its entry retained: the attested <c>pcrSelect</c> tells a verifier which registers the digest
    /// covers, and a bank with no registers contributes none.
    /// </summary>
    /// <remarks>
    /// "If the required bank does not exist, clear input selection" is what the reference's <c>FilterPcr</c> does
    /// to the caller's list, and <c>PCRComputeCurrentDigest</c> is documented as modifying its selection argument
    /// so that only the implemented PCR keep their bits set; <c>TPM2_Quote()</c> then copies the MODIFIED list
    /// into <c>TPMS_QUOTE_INFO.pcrSelect</c> (TPM 2.0 Library Part 2, clause 10.11.4, Table 146). The entry is
    /// kept rather than dropped, so the marshaled width is unchanged and a verifier can see that the bank was
    /// asked for and yielded nothing.
    /// </remarks>
    [TestMethod]
    public async Task QuotedPcrSelectClearsBitsForABankTheModelDoesNotImplement()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        //Two banks: the SHA-256 bank the simulator holds, then SHA-384, which it has not allocated at all.
        byte[] selectionOctets =
        [
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x0B, 0x03, 0x01, 0x00, 0x00,
            0x00, 0x0C, 0x03, 0xFF, 0xFF, 0xFF
        ];
        byte[] expectedEchoOctets =
        [
            0x00, 0x00, 0x00, 0x02,
            0x00, 0x0B, 0x03, 0x01, 0x00, 0x00,
            0x00, 0x0C, 0x03, 0x00, 0x00, 0x00
        ];

        using IMemoryOwner<byte> commandOwner = FrameQuoteCommand(pool, ak.ObjectHandle, CarrierProofNonce, selectionOctets, out int commandLength);
        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..commandLength], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed quote must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "The hand-framed quote must be attested.");

        using Tpm2bAttest attest = Tpm2bAttest.Parse(ref reader, pool);
        TpmsQuoteInfo? quoteInfo = attest.AttestationData.Attested.Quote;
        Assert.IsNotNull(quoteInfo, "A TPM_ST_ATTEST_QUOTE attestation carries a TPMS_QUOTE_INFO body.");
        Assert.HasCount(2, quoteInfo.PcrSelect.Selections, "An unallocated bank's entry is kept with its bits cleared, never dropped.");

        byte[] echoed = new byte[quoteInfo.PcrSelect.GetSerializedSize()];
        var echoWriter = new TpmWriter(echoed);
        quoteInfo.PcrSelect.WriteTo(ref echoWriter);

        Assert.AreSequenceEqual(
            expectedEchoOctets, echoed,
            "Every bit of a bank the model has not allocated must be cleared in the attested selection, while the implemented bank's bits stand.");
    }

    /// <summary>
    /// A selection naming PCR indexes at or beyond the number of registers a bank holds is attested with those
    /// bits CLEARED: "if the TPM implements more PCR than there are bits in pcrSelect, the additional PCR are not
    /// selected" (TPM 2.0 Library Part 2, clause 10.5.1), and the converse is settled the same way — the bit is
    /// cleared rather than refused, exactly as the reference's <c>FilterPcr</c> masks the caller's bitmap against
    /// the bank's own allocation before <c>TPM2_Quote()</c> copies it into <c>TPMS_QUOTE_INFO.pcrSelect</c>
    /// (clause 10.11.4, Table 146).
    /// </summary>
    [TestMethod]
    public async Task QuotedPcrSelectClearsBitsForPcrIndexesTheModelDoesNotHold()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        //A four-octet bitmap over the implemented SHA-256 bank with every bit set: PCR 0 to 23 are held, PCR 24
        //to 31 are not, so the fourth octet must come back all zero.
        byte[] selectionOctets =
        [
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x0B, 0x04, 0xFF, 0xFF, 0xFF, 0xFF
        ];
        byte[] expectedEchoOctets =
        [
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x0B, 0x04, 0xFF, 0xFF, 0xFF, 0x00
        ];

        using IMemoryOwner<byte> commandOwner = FrameQuoteCommand(pool, ak.ObjectHandle, CarrierProofNonce, selectionOctets, out int commandLength);
        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..commandLength], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed quote must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "The hand-framed quote must be attested.");

        using Tpm2bAttest attest = Tpm2bAttest.Parse(ref reader, pool);
        TpmsQuoteInfo? quoteInfo = attest.AttestationData.Attested.Quote;
        Assert.IsNotNull(quoteInfo, "A TPM_ST_ATTEST_QUOTE attestation carries a TPMS_QUOTE_INFO body.");

        byte[] echoed = new byte[quoteInfo.PcrSelect.GetSerializedSize()];
        var echoWriter = new TpmWriter(echoed);
        quoteInfo.PcrSelect.WriteTo(ref echoWriter);

        Assert.AreSequenceEqual(
            expectedEchoOctets, echoed,
            "Bits naming registers beyond the bank's own count must be cleared in the attested selection, while the held registers' bits stand.");
    }

    /// <summary>
    /// A <c>TPMS_PCR_SELECTION</c> whose <c>sizeofSelect</c> is zero is refused with <c>TPM_RC_VALUE</c> while
    /// the frame is still being parsed, and the parse rents nothing at all.
    /// </summary>
    /// <remarks>
    /// The width is bounded on both sides — <c>sizeofSelect {PCR_SELECT_MIN:}</c> and
    /// <c>pcrSelect[sizeofSelect] {:PCR_SELECT_MAX}</c>, both carrying <c>#TPM_RC_VALUE</c> (TPM 2.0 Library Part
    /// 2, clause 10.5.2, Table 107; the widths themselves are clause 10.5.1's equations 1 and 2) — and the
    /// reference unmarshaler answers <c>TPM_RC_VALUE</c> for a width outside them, between reading
    /// <c>sizeofSelect</c> and reading the bitmap. A zero width additionally names a bitmap covering no PCR at
    /// all, which no conformant caller can mean.
    /// </remarks>
    [TestMethod]
    public async Task QuoteWithAZeroSizeofSelectIsRefusedWithValueAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, pool).ConfigureAwait(false);

        //count = 1, then { SHA-256, 0 } — a bitmap of no octets at all — and, for contrast, the narrowest
        //conformant width the same bank may carry.
        byte[] zeroWidthSelection = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, 0x00];
        byte[] admittedSelection = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0B, 0x03, 0x01, 0x00, 0x00];

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants admittedCode = await SubmitHandFramedQuoteAsync(
            simulator, pool, ak.ObjectHandle, CarrierProofNonce, admittedSelection).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, admittedCode,
            "A sizeofSelect of exactly PCR_SELECT_MIN octets is inside the member's declared range and must be attested.");

        TpmRcConstants zeroWidthCode = await SubmitHandFramedQuoteAsync(
            simulator, pool, ak.ObjectHandle, CarrierProofNonce, zeroWidthSelection).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_VALUE, 2), zeroWidthCode,
            "PCRselect is TPM2_Quote()'s third parameter (Table 101, index 2); a sizeofSelect below PCR_SELECT_MIN is out of the member's declared range and is parameter-encoded TPM_RC_VALUE (Part 2, clause 10.5.2, Table 107).");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A selection refused at parse must leave no carrier outstanding: the width is settled before the rental it sizes.");
    }

    /// <summary>
    /// Builds a <c>TPML_PCR_SELECTION</c> octet sequence naming <paramref name="selectionCount"/> banks, each
    /// selecting PCR 0 over the three octets that cover PCRs 0 to 23 — the shape the typed command input cannot
    /// express, used to drive the list's count bound.
    /// </summary>
    /// <param name="selectionCount">How many bank selections to name.</param>
    /// <returns>The marshaled selection octets.</returns>
    private static byte[] BuildSelectionOctets(int selectionCount)
    {
        const int SelectionSize = sizeof(ushort) + sizeof(byte) + 3;
        byte[] octets = new byte[sizeof(uint) + (selectionCount * SelectionSize)];
        var writer = new TpmWriter(octets);
        writer.WriteUInt32((uint)selectionCount);
        for(int i = 0; i < selectionCount; i++)
        {
            writer.WriteUInt16((ushort)PcrBank);
            writer.WriteByte(3);
            writer.WriteByte(0x01);
            writer.WriteByte(0x00);
            writer.WriteByte(0x00);
        }

        return octets;
    }

    /// <summary>
    /// Frames a <c>TPM2_Quote()</c> command carrying a caller-composed <c>TPML_PCR_SELECTION</c> octet sequence
    /// and a single empty-auth <c>TPM_RS_PW</c> slot, exactly as the executor lays one out (TPM 2.0 Library Part
    /// 3, clause 18.4, Table 101), for selection shapes <see cref="QuoteInput"/> cannot build.
    /// </summary>
    /// <param name="pool">The memory pool the command buffer is rented from.</param>
    /// <param name="signHandle">The signing key's handle.</param>
    /// <param name="qualifyingData">The caller nonce.</param>
    /// <param name="pcrSelectionOctets">The marshaled selection.</param>
    /// <param name="length">The number of valid octets in the returned buffer.</param>
    /// <returns>The command buffer; the caller disposes it.</returns>
    private static IMemoryOwner<byte> FrameQuoteCommand(
        BaseMemoryPool pool, TpmiDhObject signHandle, ReadOnlySpan<byte> qualifyingData, ReadOnlySpan<byte> pcrSelectionOctets, out int length)
    {
        const int PasswordSlotSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        length =
            TpmHeader.HeaderSize
            + sizeof(uint)                                       //Handle area: @signHandle.
            + sizeof(uint) + PasswordSlotSize                    //authorizationSize + the TPM_RS_PW slot.
            + sizeof(ushort) + qualifyingData.Length             //qualifyingData (TPM2B_DATA).
            + (2 * sizeof(ushort))                               //inScheme (TPMT_SIG_SCHEME).
            + pcrSelectionOctets.Length;                         //PCRselect (TPML_PCR_SELECTION).

        IMemoryOwner<byte> owner = pool.Rent(length);
        try
        {
            var writer = new TpmWriter(owner.Memory.Span[..length]);
            var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_Quote);
            header.WriteTo(ref writer);
            writer.WriteUInt32(signHandle.Value);
            writer.WriteUInt32(PasswordSlotSize);
            writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
            writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
            writer.WriteTpm2b(qualifyingData);
            writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_ECDSA);
            writer.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
            writer.WriteBytes(pcrSelectionOctets);

            return owner;
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Submits a hand-framed <c>TPM2_Quote()</c> straight to the simulator and yields the response code, so a
    /// selection shape the typed command input cannot build can still be judged by what the TPM answers.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="signHandle">The signing key's handle.</param>
    /// <param name="qualifyingData">The caller nonce.</param>
    /// <param name="pcrSelectionOctets">The marshaled selection.</param>
    /// <returns>The response code the simulator answered with.</returns>
    private async Task<TpmRcConstants> SubmitHandFramedQuoteAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmiDhObject signHandle, ReadOnlyMemory<byte> qualifyingData, ReadOnlyMemory<byte> pcrSelectionOctets)
    {
        using IMemoryOwner<byte> commandOwner = FrameQuoteCommand(pool, signHandle, qualifyingData.Span, pcrSelectionOctets.Span, out int commandLength);
        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(commandOwner.Memory[..commandLength], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed quote must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Quotes the fixed PCR selection with <paramref name="ak"/> over a fresh, real, unbound and unsalted HMAC
    /// sign session carrying <paramref name="signSlotAuthValue"/>, flushing the session on the way out. The
    /// session lives entirely inside this call, so the nonce carrier it adopts from the response (TPM 2.0
    /// Library Part 1, clause 15.6.1) is released before a caller reads the pool balance.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="trackingPool">The metered pool every carrier is rented from.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="qualifyingData">The caller nonce.</param>
    /// <param name="schemeHashAlg">The signing scheme's hash algorithm.</param>
    /// <param name="signSlotAuthValue">The authValue term folded into the sign session.</param>
    /// <returns>The Quote result, not asserted for success.</returns>
    private async Task<TpmResult<QuoteResponse>> QuoteOverRealSignSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MeteredHousePool trackingPool, CreatePrimaryResponse ak,
        ReadOnlyMemory<byte> qualifyingData, TpmAlgIdConstants schemeHashAlg, ReadOnlyMemory<byte> signSlotAuthValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), BaseMemoryPool.Shared);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), trackingPool.Pool);
            signSession.SetAuthValue(signSlotAuthValue.Span, trackingPool.Pool);

            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, trackingPool.Pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, qualifyingData.Span, schemeHashAlg, pcrSelection, trackingPool.Pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray()];

            return await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                tpm, quoteInput, [signSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the owner hierarchy with an empty authValue, for the
    /// password-arm fixtures.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a dictionary-attack-exempt primary ECC P-256 signing key under the endorsement hierarchy carrying
    /// the NON-EMPTY <see cref="SignKeyPassword"/> authValue — the fixture the session-authorized paths need so a
    /// wrong authValue is a plain <c>TPM_RC_BAD_AUTH</c> that moves no lockout counter.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateNoDaSigningPrimaryWithAuthAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT,
            password: SignKeyPassword,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (dictionary-attack-exempt ECC signing key with authValue) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a simulator with the ECC signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-quote-carriers",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
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

    /// <summary>Creates a response codec registry covering the commands the password-arm tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);

        return registry;
    }

    /// <summary>Extends <see cref="CreateRegistry"/> with the StartAuthSession and FlushContext codecs the session-arm tests need.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateHmacArmRegistry()
    {
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
