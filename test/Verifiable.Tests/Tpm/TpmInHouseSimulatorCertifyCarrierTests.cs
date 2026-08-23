using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves the pooled-carrier ownership of <c>TPM2_Certify()</c>'s <c>qualifyingData</c> parameter
/// (<c>TPM2B_DATA</c>, TPM 2.0 Library Part 2, clause 10.4.3, Table 93; the command is Part 3, clause 18.2,
/// Table 89) against the in-house behavioural <see cref="TpmSimulator"/>: the caller nonce rides a carrier the
/// parser rents, and it reaches the pool again on every path the command can leave by — refused at the entry
/// transition, refused at the session continuation, refused for a mismatched command HMAC at either of the two
/// authorization slots, and certified successfully — while a frame the parser itself refuses rents nothing at
/// all.
/// </summary>
/// <remarks>
/// <para>
/// The instrument is <see cref="MeteredHousePool"/>: a genuine <see cref="BaseMemoryPool"/> whose own rent and
/// return telemetry is observed, so nothing here depends on a seam in production code. Every value driven
/// through a carrier under test is deliberately NON-EMPTY, because an empty one parses to the type's shared
/// dispose-immune sentinel, which rents nothing and would make a balance assertion vacuous.
/// </para>
/// <para>
/// <c>TPM2_Certify()</c> is the two-slot member of the attest family — <c>@objectHandle</c> at session index 0
/// (ADMIN role) then <c>@signHandle</c> at session index 1 (USER role) — so it is also where a mismatch at the
/// SECOND queued slot can be exercised: the first slot's command HMAC verifies, the request is re-threaded
/// through the verification queue, and only then does the second slot fail (Part 3, clause 5.6 runs the slots'
/// ladders in session order). That arm proves the release happens on the queue's later round trip too, not only
/// on the first.
/// </para>
/// <para>
/// Every balance is taken with the client-side <see cref="TpmSession"/> already disposed, because a session
/// adopts the nonceTPM carrier its response entry carries (Part 1, clause 16.6.1) and holds it until the session
/// itself is released — a balance read while the session is alive is one rental high.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCertifyCarrierTests
{
    /// <summary>The hash algorithm for every real HMAC session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The certified object's authValue for the session-authorized fixtures. It stays inside the SHA-256
    /// nameAlg's 32-octet digest width, the bound an object's authValue may not exceed (TPM 2.0 Library Part 1,
    /// clause 17.6.4.2).
    /// </summary>
    private const string SubjectPassword = "certify-carrier-subject-auth";

    /// <summary>The signing key's authValue for the session-authorized fixtures, inside the same 32-octet bound.</summary>
    private const string SignKeyPassword = "certify-carrier-sign-auth";

    /// <summary>
    /// The caller nonce these tests drive as <c>qualifyingData</c>. Its 61-octet width is deliberately unlike
    /// any digest, key, or nonce width the surrounding machinery rents, so a rent of exactly this size across a
    /// command identifies the <c>TPM2B_DATA</c> carrier the parser created.
    /// </summary>
    private static byte[] CarrierProofNonce { get; } = "Certify carrier ownership proof nonce for the TPM 2.0 library"u8.ToArray();

    /// <summary>The certified object's authValue in wire form — the UTF-8 octets of <see cref="SubjectPassword"/>.</summary>
    private static byte[] SubjectPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SubjectPassword);

    /// <summary>The signing key's authValue in wire form — the UTF-8 octets of <see cref="SignKeyPassword"/>.</summary>
    private static byte[] SignKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SignKeyPassword);

    /// <summary>
    /// The <c>nonceCaller</c> the mixed-area case plants in the <c>TPM_RS_PW</c> slot. Its 47-octet width is
    /// unlike any digest, key, or nonce width the surrounding machinery rents, so a rent of exactly this size
    /// identifies the <c>TPM2B_NONCE</c> carrier the parser created for that slot.
    /// </summary>
    private static byte[] PasswordSlotNonce { get; } = "Password-slot nonceCaller proof octets, 47 long"u8.ToArray();

    /// <summary>A wrong guess at either slot's authValue, distinct from both real ones.</summary>
    private static byte[] WrongPasswordBytes { get; } = [0x61, 0x62, 0x63, 0x64];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A <c>TPM2_Certify()</c> refused by the entry transition — the objectHandle resolves to no loaded object,
    /// so TPM 2.0 Library Part 3, clause 18.2's handle check answers <c>TPM_RC_HANDLE</c> before either slot's
    /// credential is compared and before any parameter is looked at — returns every carrier the parser rented:
    /// both slots' supplied passwords and the qualifying data. The refusing arm reaches them through the request
    /// record's own <c>IDisposable.Dispose</c>, which is the only owner they ever had, because a handle refusal
    /// transfers nothing into an action.
    /// </summary>
    [TestMethod]
    public async Task RefusedCertifyAtTheEntryTransitionReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmPasswordSession objectAuth = TpmPasswordSession.Create(WrongPasswordBytes, trackingPool.Pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.Create(WrongPasswordBytes, trackingPool.Pool);
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase + 0x00FFFF00), ak.ObjectHandle, CarrierProofNonce,
                TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

            long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);

            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [objectAuth, signAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode,
                "An objectHandle that resolves to no loaded object is a bare TPM_RC_HANDLE (TPM 2.0 Library Part 3, clause 18.2).");

            Assert.IsGreaterThan(
                qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
                "The parser must have rented the qualifying-data carrier before the transition refused, or the balance below proves nothing.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A handle refusal must return the parse-rented password and qualifying-data carriers to the pool.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_Certify()</c> refused by the continuation — the scheme hash algorithm is one
    /// the attest digest path does not implement, so <c>TPM_RC_HASH</c> is answered only AFTER both queued
    /// command HMACs have verified (TPM 2.0 Library Part 3, clause 5.6 orders authorization ahead of the
    /// parameter checks) — returns every carrier the parser rented. This is the arm that runs one step further
    /// than the entry refusal: the request has already travelled through the HMAC-verification action and back
    /// for each of the two slots.
    /// </summary>
    [TestMethod]
    public async Task RefusedCertifyAtTheOverSessionContinuationReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, SubjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, SignKeyPassword).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<CertifyResponse> result = await CertifyOverTwoRealSessionsAsync(
            tpm, registry, trackingPool, subject, ak, TpmAlgIdConstants.TPM_ALG_SHA1, SubjectPasswordBytes, SignKeyPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HASH, result.ResponseCode,
            "A scheme hash the attest digest path does not implement is refused with TPM_RC_HASH after both command HMACs have verified.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A continuation refusal must return both parse-rented HMAC carriers and the qualifying-data carrier to the pool.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_Certify()</c> whose FIRST slot — <c>@objectHandle</c> at session index 0 —
    /// presents a command HMAC computed over the wrong authValue never reaches its continuation at all: the
    /// verification step terminates the command with an authorization failure (TPM 2.0 Library Part 2, clause
    /// 6.6.2). The queued request still owns every carrier the parser rented, and the mismatch path releases
    /// them before the rejection is framed.
    /// </summary>
    [TestMethod]
    public async Task CertifyOverSessionWithAMismatchedCommandHmacAtTheObjectSlotReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, SubjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, SignKeyPassword).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<CertifyResponse> result = await CertifyOverTwoRealSessionsAsync(
            tpm, registry, trackingPool, subject, ak, TpmAlgIdConstants.TPM_ALG_SHA256, WrongPasswordBytes, SignKeyPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
            "A wrong authValue folded into the object session's command HMAC is an uncharged authorization failure blamed on session index 0, or this path proves nothing about a first-slot mismatch.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A command-HMAC mismatch at the first slot must return both parse-rented HMAC carriers and the qualifying-data carrier to the pool.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_Certify()</c> whose SECOND slot — <c>@signHandle</c> at session index 1 —
    /// presents a command HMAC computed over the wrong authValue is refused only after the first slot's HMAC has
    /// already verified and the request has been re-threaded through the verification queue (TPM 2.0 Library
    /// Part 3, clause 5.6 runs the slots' ladders in session order). The carriers must reach the pool from that
    /// later round trip exactly as they do from the first, so the request stays owned across the whole queue.
    /// </summary>
    [TestMethod]
    public async Task CertifyOverSessionWithAMismatchedCommandHmacAtTheSignSlotReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, SubjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, SignKeyPassword).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<CertifyResponse> result = await CertifyOverTwoRealSessionsAsync(
            tpm, registry, trackingPool, subject, ak, TpmAlgIdConstants.TPM_ALG_SHA256, SubjectPasswordBytes, WrongPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), result.ResponseCode,
            "The refusal must be blamed on session index 1, which is only reachable once index 0's command HMAC has verified and the request has been re-threaded through the queue.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A command-HMAC mismatch at the second queued slot must return both parse-rented HMAC carriers and the qualifying-data carrier to the pool.");
    }

    /// <summary>
    /// A successful session-authorized <c>TPM2_Certify()</c> over two real HMAC sessions returns every carrier
    /// the parser rented once the response has been consumed: the qualifying data transferred out of the request
    /// into the certify action, so it is the attesting effect — not the continuation — that is its terminal
    /// owner, and the attestation has copied its octets into <c>extraData</c> by the time it releases them (TPM
    /// 2.0 Library Part 3, clause 18.2; Part 1, clause 16.6.1 for the response entries).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulCertifyOverSessionReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER, SubjectPassword).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, SignKeyPassword).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);

        TpmResult<CertifyResponse> result = await CertifyOverTwoRealSessionsAsync(
            tpm, registry, trackingPool, subject, ak, TpmAlgIdConstants.TPM_ALG_SHA256, SubjectPasswordBytes, SignKeyPasswordBytes).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The session-authorized certify must attest with the correct authValues: '{result.ResponseCode}'.");
        result.Value.Dispose();

        Assert.IsGreaterThan(
            qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
            "The parser must have rented the qualifying-data carrier for the successful command, or the balance below proves nothing.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful certify must return both parse-rented HMAC carriers and the qualifying-data carrier to the pool once the response is disposed.");
    }

    /// <summary>
    /// A <c>TPM2_Certify()</c> over a MIXED authorization area whose <c>TPM_RS_PW</c> object slot carries a
    /// non-empty <c>nonceCaller</c> on the wire is refused with <c>TPM_RC_NONCE</c> encoded to that slot while the
    /// slot is still being read, so the parse rents nothing at all and the pool balance does not move.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A password authorization has no nonce: the reference settles it while unmarshaling the session area — "the
    /// nonce size must be zero", answered <c>TPM_RCS_NONCE + errorIndex</c> — and the response side of the same
    /// fact is TPM 2.0 Library Part 1, clause 16.6.2.2, Table 11's "will be zero for a password authorization".
    /// The refusal is structural, so it precedes every authorization check (Part 3, clause 5.5 precedes clause
    /// 5.6) and the planted octets are never keyed into anything.
    /// </para>
    /// <para>
    /// The refusal is settled while the slot itself is being read, before the parse rents anything: a
    /// <c>TPMS_AUTH_COMMAND</c>'s layout is identical for both slot kinds, so the reader reaches the password
    /// slot's planted nonce on its own terms and answers there — the position the reference gives the rule in
    /// <c>RetrieveSessionData</c>, which tests each slot as it unmarshals it. The attest parsers rent their owned
    /// carriers as the parse's LAST act, so a frame refused at slot 0 creates none of them at all. On an ACCEPTED
    /// area a password slot's nonce is always the empty sentinel — this rule guarantees it — so the placeholder
    /// response entry's ownership of it is a defensive invariant rather than a live path.
    /// </para>
    /// <para>
    /// The host's own password session always writes a zero-length <c>nonceCaller</c>, so the non-empty one is
    /// planted by an intervening transport that rewrites the built command — the same technique the secure-channel
    /// tests use to set a session attribute the executor refuses to compose.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task CertifyOverAMixedAreaWithAPasswordSlotNonceIsRefusedAtParseAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, SignKeyPassword).ConfigureAwait(false);

        async ValueTask<TpmResult<TpmResponse>> PlantPasswordSlotNonceAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken cancellationToken)
        {
            if(ReadCommandCode(command.Span) != TpmCcConstants.TPM_CC_Certify)
            {
                return await simulator.SubmitAsync(command, commandPool, cancellationToken).ConfigureAwait(false);
            }

            return await simulator.SubmitAsync(
                WithPasswordSlotNonce(command.Span, handleCount: 2, PasswordSlotNonce), commandPool, cancellationToken).ConfigureAwait(false);
        }

        using TpmDevice plantingTpm = TpmDevice.Create(PlantPasswordSlotNonceAsync);

        long baseline = trackingPool.OutstandingCount;
        long nonceRentsBefore = trackingPool.RentedCountOfSize(PasswordSlotNonce.Length);

        TpmResult<CertifyResponse> result = await CertifyOverAMixedAreaAsync(tpm, plantingTpm, registry, trackingPool, subject, ak).ConfigureAwait(false);
        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NONCE, result.BaseError,
            "A password slot carries no nonce at all, so a non-empty nonceCaller there is a nonce error.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_NONCE, sessionIndex: 0), result.ResponseCode,
            "The refusal names the offending slot — the password object slot at index 0 — session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

        Assert.AreEqual(
            nonceRentsBefore, trackingPool.RentedCountOfSize(PasswordSlotNonce.Length),
            "The planted nonce is refused while its own slot is being read, so no carrier is ever rented for it.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A frame refused at slot 0 rents none of the parse's owned carriers, so the pool balance does not move.");
    }

    /// <summary>
    /// A <c>qualifyingData</c> wider than <c>TPM2B_DATA</c>'s declared bound — <c>sizeof(TPMT_HA)</c>, the
    /// 2-octet algorithm identifier plus the largest supported digest (TPM 2.0 Library Part 2, clause 10.4.3,
    /// Table 93) — is refused with <c>TPM_RC_SIZE</c> while the frame is still being parsed, so the parse rents
    /// nothing at all: the pool balance does not move, and the refusal is a response code rather than an
    /// exception escaping the command surface.
    /// </summary>
    [TestMethod]
    public async Task CertifyWithQualifyingDataOverTheDataBoundIsRefusedAtParseAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        byte[] atBound = new byte[Tpm2bData.MaxSize];
        atBound.AsSpan().Fill(0x3C);
        byte[] overBound = new byte[Tpm2bData.MaxSize + 1];
        overBound.AsSpan().Fill(0x3C);

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmPasswordSession atBoundObjectAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmPasswordSession atBoundSignAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using CertifyInput atBoundInput = CertifyInput.ForEcdsa(
                subject.ObjectHandle, ak.ObjectHandle, atBound, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

            TpmResult<CertifyResponse> atBoundResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, atBoundInput, [atBoundObjectAuth, atBoundSignAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                atBoundResult.IsSuccess,
                $"A qualifyingData of exactly sizeof(TPMT_HA) octets is inside the TPM2B_DATA bound and must be certified: '{atBoundResult.ResponseCode}'.");
            atBoundResult.Value.Dispose();

            using TpmPasswordSession overBoundObjectAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmPasswordSession overBoundSignAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using CertifyInput overBoundInput = CertifyInput.ForEcdsa(
                subject.ObjectHandle, ak.ObjectHandle, overBound, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

            long overBoundRentsBefore = trackingPool.RentedCountOfSize(overBound.Length);

            TpmResult<CertifyResponse> overBoundResult = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, overBoundInput, [overBoundObjectAuth, overBoundSignAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_SIZE, overBoundResult.ResponseCode,
                "A qualifyingData wider than sizeof(TPMT_HA) is TPM_RC_SIZE (TPM 2.0 Library Part 2, clause 10.4.3, Table 93).");

            Assert.AreEqual(
                overBoundRentsBefore, trackingPool.RentedCountOfSize(overBound.Length),
                "A frame the parser refuses must not have rented a carrier for the over-bound value it refused.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A parse-time refusal rents nothing, so the pool balance may not move across it.");
    }

    /// <summary>
    /// Certifies <paramref name="subject"/> with <paramref name="ak"/> over two fresh, real, unbound and
    /// unsalted HMAC sessions — one per authorization slot, in handle order — flushing both on the way out. The
    /// sessions live entirely inside this call, so the nonce carriers they adopt from the response entries (TPM
    /// 2.0 Library Part 1, clause 16.6.1) are released before a caller reads the pool balance.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="trackingPool">The metered pool every carrier is rented from.</param>
    /// <param name="subject">The certified object's CreatePrimary response.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="schemeHashAlg">The signing scheme's hash algorithm.</param>
    /// <param name="objectSlotAuthValue">The authValue term folded into the object slot's session.</param>
    /// <param name="signSlotAuthValue">The authValue term folded into the sign slot's session.</param>
    /// <returns>The certify result, not asserted for success.</returns>
    private async Task<TpmResult<CertifyResponse>> CertifyOverTwoRealSessionsAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MeteredHousePool trackingPool, CreatePrimaryResponse subject, CreatePrimaryResponse ak,
        TpmAlgIdConstants schemeHashAlg, ReadOnlyMemory<byte> objectSlotAuthValue, ReadOnlyMemory<byte> signSlotAuthValue)
    {
        StartAuthSessionResponse objectStarted = await StartHmacSessionAsync(tpm, registry, trackingPool).ConfigureAwait(false);
        uint objectSessionHandle = objectStarted.SessionHandle.Value;
        StartAuthSessionResponse signStarted = await StartHmacSessionAsync(tpm, registry, trackingPool).ConfigureAwait(false);
        uint signSessionHandle = signStarted.SessionHandle.Value;

        try
        {
            using TpmSession objectSession = new(new TpmHandle(objectSessionHandle), objectStarted.NonceTPM, HmacSessionAlg, trackingPool.Pool);
            objectSession.SetAuthValue(objectSlotAuthValue.Span, trackingPool.Pool);

            using TpmSession signSession = new(new TpmHandle(signSessionHandle), signStarted.NonceTPM, HmacSessionAlg, trackingPool.Pool);
            signSession.SetAuthValue(signSlotAuthValue.Span, trackingPool.Pool);

            using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                subject.ObjectHandle, ak.ObjectHandle, CarrierProofNonce, schemeHashAlg, trackingPool.Pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            return await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                tpm, certifyInput, [objectSession, signSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(objectSessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(signSessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Certifies <paramref name="subject"/> with <paramref name="ak"/> over a MIXED authorization area — a
    /// <c>TPM_RS_PW</c> object slot and one fresh, real, unbound and unsalted HMAC sign session — issuing the
    /// command through <paramref name="plantingTpm"/> so the password slot arrives carrying a non-empty
    /// <c>nonceCaller</c>, and flushing the session on the way out. The session lives entirely inside this call,
    /// so the nonce carrier it adopts from its response entry (TPM 2.0 Library Part 1, clause 16.6.1) is released
    /// before a caller reads the pool balance.
    /// </summary>
    /// <param name="plainTpm">The untouched TPM device, used for the session lifecycle commands.</param>
    /// <param name="plantingTpm">The TPM device whose transport plants the password slot's nonce.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="trackingPool">The metered pool every carrier is rented from.</param>
    /// <param name="subject">The certified object's CreatePrimary response; its empty authValue authorizes the password slot.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <returns>The certify result, not asserted for success.</returns>
    private async Task<TpmResult<CertifyResponse>> CertifyOverAMixedAreaAsync(
        TpmDevice plainTpm, TpmDevice plantingTpm, TpmResponseRegistry registry, MeteredHousePool trackingPool,
        CreatePrimaryResponse subject, CreatePrimaryResponse ak)
    {
        StartAuthSessionResponse signStarted = await StartHmacSessionAsync(plainTpm, registry, trackingPool).ConfigureAwait(false);
        uint signSessionHandle = signStarted.SessionHandle.Value;

        try
        {
            using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmSession signSession = new(new TpmHandle(signSessionHandle), signStarted.NonceTPM, HmacSessionAlg, trackingPool.Pool);
            signSession.SetAuthValue(SignKeyPasswordBytes, trackingPool.Pool);

            using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                subject.ObjectHandle, ak.ObjectHandle, CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            return await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                plantingTpm, certifyInput, [objectAuth, signSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                plainTpm, FlushContextInput.ForHandle(signSessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>Reads a built command's header <c>commandCode</c> field, leaving every other field unexamined.</summary>
    /// <param name="command">The built command bytes.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command)
    {
        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmCcConstants)header.Code;
    }

    /// <summary>
    /// Rewrites a built command so its first <c>TPM_RS_PW</c> authorization slot carries
    /// <paramref name="nonce"/> as its <c>nonceCaller</c>, growing the authorization area's size field and the
    /// header's <c>commandSize</c> to match. The handle and authorization areas are walked with a
    /// <see cref="TpmReader"/>, so the splice holds regardless of the surrounding slots' nonce and HMAC widths.
    /// </summary>
    /// <param name="command">The built command bytes, left untouched.</param>
    /// <param name="handleCount">The number of handles in the command's handle area.</param>
    /// <param name="nonce">The nonce octets to plant.</param>
    /// <returns>The rewritten command.</returns>
    private static byte[] WithPasswordSlotNonce(ReadOnlySpan<byte> command, int handleCount, ReadOnlySpan<byte> nonce)
    {
        var reader = new TpmReader(command);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < handleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        int authorizationSizeOffset = reader.Consumed;
        uint authorizationSize = reader.ReadUInt32();
        int sessionsStart = reader.Consumed;
        int nonceFieldOffset = -1;
        while(nonceFieldOffset < 0 && reader.Consumed - sessionsStart < authorizationSize)
        {
            uint sessionHandle = reader.ReadUInt32();
            int candidateOffset = reader.Consumed;
            reader.Skip(reader.ReadUInt16());
            _ = reader.ReadByte();
            reader.Skip(reader.ReadUInt16());

            if(sessionHandle == (uint)TpmRh.TPM_RH_PW)
            {
                nonceFieldOffset = candidateOffset;
            }
        }

        Assert.AreNotEqual(-1, nonceFieldOffset, "The command must carry a TPM_RS_PW slot for the mixed-area rewrite to have anything to plant a nonce in.");

        byte[] rewritten = new byte[command.Length + nonce.Length];
        command[..nonceFieldOffset].CopyTo(rewritten);
        BinaryPrimitives.WriteUInt16BigEndian(rewritten.AsSpan(nonceFieldOffset), (ushort)nonce.Length);
        nonce.CopyTo(rewritten.AsSpan(nonceFieldOffset + sizeof(ushort)));
        command[(nonceFieldOffset + sizeof(ushort))..].CopyTo(rewritten.AsSpan(nonceFieldOffset + sizeof(ushort) + nonce.Length));

        BinaryPrimitives.WriteUInt32BigEndian(rewritten.AsSpan(authorizationSizeOffset), authorizationSize + (uint)nonce.Length);
        BinaryPrimitives.WriteUInt32BigEndian(rewritten.AsSpan(sizeof(ushort)), (uint)rewritten.Length);

        return rewritten;
    }

    /// <summary>
    /// The format-one session-index encoding (TPM 2.0 Library Part 2, clause 6.6.2): RC + <c>TPM_RC_S</c> +
    /// <c>TPM_RC_n</c>(0x100·(index+1)) — a local mirror of the production session-index encoding, transcribed
    /// independently here since the production helper is private.
    /// </summary>
    /// <param name="baseRc">The base format-one response code.</param>
    /// <param name="sessionIndex">The zero-based session index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Starts one unbound, unsalted HMAC session and asserts it was created.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="trackingPool">The metered pool.</param>
    /// <returns>The StartAuthSession response.</returns>
    private async Task<StartAuthSessionResponse> StartHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, MeteredHousePool trackingPool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        return startResult.Value;
    }

    /// <summary>
    /// Creates a primary ECC P-256 signing key under the given hierarchy with an empty authValue, for the
    /// password-arm fixtures.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a dictionary-attack-exempt primary ECC P-256 signing key under the given hierarchy carrying a
    /// NON-EMPTY authValue — the fixture the session-authorized paths need so a wrong authValue is a plain
    /// <c>TPM_RC_BAD_AUTH</c> that moves no lockout counter (TPM 2.0 Library Part 1, clause 17.8.1).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The authValue the key carries.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateNoDaSigningPrimaryWithAuthAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            hierarchy,
            password,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (dictionary-attack-exempt ECC signing key with authValue, {hierarchy}) failed: '{result.ResponseCode}'.");

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
            "tpm-in-house-certify-carriers",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(),
            rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create());
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
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);

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
