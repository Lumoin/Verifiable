using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves the pooled-carrier ownership of <c>TPM2_NV_Certify()</c>'s parse-rented values — the two
/// authorization slots' supplied credentials and the <c>qualifyingData</c> parameter (<c>TPM2B_DATA</c>, TPM 2.0
/// Library Part 2, clause 10.4.3, Table 93; the command is Part 3, clause 31.16.2, Table 254) — against the
/// in-house behavioural <see cref="TpmSimulator"/>: each value rides a carrier the parser rents, and every
/// carrier reaches the pool again on every path the command can leave by — refused at the entry transition,
/// refused for a wrong Index password, refused at the session continuation, refused for a mismatched command
/// HMAC at either of the two authorization slots, and certified successfully on both the all-password and the
/// session arm — while a frame the parser itself refuses rents nothing at all.
/// </summary>
/// <remarks>
/// <para>
/// The instrument is <see cref="MeteredHousePool"/>: a genuine <see cref="BaseMemoryPool"/> whose own rent and
/// return telemetry is observed, so nothing here depends on a seam in production code. Every value driven
/// through a carrier under test is deliberately NON-EMPTY, because an empty one parses to the type's shared
/// dispose-immune sentinel, which rents nothing and would make a balance assertion vacuous.
/// </para>
/// <para>
/// <c>TPM2_NV_Certify()</c> is the only member of the attest family whose session-authorized request travels
/// through the Index-Name computation before its command HMACs are verified (Part 1, clause 16.7 equation 15
/// needs the Index's Name as a cpHash term), so its carriers must survive an extra effect round trip that the
/// other attest commands do not have. The session-arm cases below all cross that hop, and the two mismatch cases
/// additionally cross the verification queue's own round trips: the sign slot is queued at session index 0 and
/// the authorizing slot at index 1, so an index-1 mismatch is only reachable once index 0 has already verified.
/// </para>
/// <para>
/// Every balance is taken with the client-side <see cref="TpmSession"/> already disposed, because a session
/// adopts the nonceTPM carrier its response entry carries (Part 1, clause 16.6.1) and holds it until the session
/// itself is released — a balance read while the session is alive is one rental high.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorNvCertifyCarrierTests
{
    /// <summary>The hash algorithm for every real HMAC session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The Name algorithm every NV Index these tests define is created with.</summary>
    private const TpmAlgIdConstants DefaultNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The NV Index handle the all-password cases define and certify.</summary>
    private const uint PasswordArmNvIndexHandle = 0x0100_0021;

    /// <summary>The NV Index handle the session-authorized cases define and certify.</summary>
    private const uint SessionArmNvIndexHandle = 0x0100_0022;

    /// <summary>The NV Index handle the mixed-authorization-area case defines and certifies.</summary>
    private const uint MixedArmNvIndexHandle = 0x0100_0023;

    /// <summary>
    /// The attributes every Index here is defined with: readable and writable by its own authValue, and exempt
    /// from dictionary-attack protection (<c>TPMA_NV_NO_DA</c>), so a deliberately wrong credential is a plain
    /// <c>TPM_RC_BAD_AUTH</c> that moves no lockout counter (TPM 2.0 Library Part 1, clause 17.8.1).
    /// </summary>
    private const TpmaNv NoDaIndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The signing key's authValue for the all-password fixtures, inside the SHA-256 nameAlg's 32-octet bound (Part 1, clause 17.6.4.2).</summary>
    private const string SignKeyPassword = "nvcertify-carrier-sign-auth";

    /// <summary>
    /// The caller nonce these tests drive as <c>qualifyingData</c>. Its 61-octet width is deliberately unlike any
    /// digest, key, or nonce width the surrounding machinery rents, so a rent of exactly this size across a
    /// command identifies the <c>TPM2B_DATA</c> carrier the parser created.
    /// </summary>
    private static byte[] CarrierProofNonce { get; } = "NV_Certify carrier ownership proof nonce for the TPM library."u8.ToArray();

    /// <summary>The signing key's authValue in wire form — the UTF-8 octets of <see cref="SignKeyPassword"/>.</summary>
    private static byte[] SignKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SignKeyPassword);

    /// <summary>The authValue every NV Index here is defined with.</summary>
    private static byte[] IndexAuth { get; } = [0x0A, 0x0B, 0x0C, 0x0D];

    /// <summary>
    /// The <c>nonceCaller</c> the mixed-area case plants in the <c>TPM_RS_PW</c> slot. Its 47-octet width is
    /// unlike any digest, key, or nonce width the surrounding machinery rents, so a rent of exactly this size
    /// identifies the <c>TPM2B_NONCE</c> carrier the parser created for that slot.
    /// </summary>
    private static byte[] PasswordSlotNonce { get; } = "Password-slot nonceCaller proof octets, 47 long"u8.ToArray();

    /// <summary>A wrong guess at a credential, distinct from every real one these tests install.</summary>
    private static byte[] WrongAuthBytes { get; } = [0x99, 0x98, 0x97, 0x96];

    /// <summary>The octets written into every Index these tests define, and the full window they certify.</summary>
    private static byte[] WrittenData { get; } = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

    /// <summary>
    /// The width of an Index Name under <see cref="DefaultNameAlg"/>: the 2-octet nameAlg prefix plus a SHA-256
    /// digest (TPM 2.0 Library Part 1, clause 14, Table 6). The Index-Name hop is the only step in a session-authorized
    /// <c>TPM2_NV_Certify()</c> that rents a buffer of exactly this width — the signing key's Name was rented
    /// long before, and this file's own expected-Name recomputation frames its result on the managed heap — so a
    /// rent of this size across the command identifies the hop's <c>TPM2B_NAME</c> carrier.
    /// </summary>
    private const int IndexNameSize = sizeof(ushort) + 32;

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// An all-password <c>TPM2_NV_Certify()</c> refused by the entry transition — the signHandle resolves to no
    /// loaded object, so TPM 2.0 Library Part 3, clause 31.16's handle check answers <c>TPM_RC_HANDLE</c> before
    /// either slot's credential is compared and before any parameter is looked at — returns every carrier the
    /// parser rented: both slots' supplied passwords and the qualifying data. The refusing arm reaches them
    /// through the request record's own <c>IDisposable.Dispose</c>, which is the only owner they ever had,
    /// because a handle refusal transfers nothing into an action.
    /// </summary>
    [TestMethod]
    public async Task RefusedNvCertifyAtTheEntryTransitionReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, PasswordArmNvIndexHandle).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmPasswordSession signAuth = TpmPasswordSession.Create(WrongAuthBytes, trackingPool.Pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, trackingPool.Pool);
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase + 0x00FFFF00), PasswordArmNvIndexHandle, PasswordArmNvIndexHandle,
                CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, trackingPool.Pool);

            long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signAuth, indexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode,
                "A signHandle that resolves to no loaded object is a bare TPM_RC_HANDLE (TPM 2.0 Library Part 3, clause 31.16).");

            Assert.IsGreaterThan(
                qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
                "The parser must have rented the qualifying-data carrier before the transition refused, or the balance below proves nothing.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A handle refusal must return both parse-rented password carriers and the qualifying-data carrier to the pool.");
    }

    /// <summary>
    /// An all-password <c>TPM2_NV_Certify()</c> whose Index-slot password does not match the Index's own
    /// authValue is refused with <c>TPM_RC_BAD_AUTH</c> (the Index is <c>TPMA_NV_NO_DA</c>, so the mismatch moves
    /// no counter — TPM 2.0 Library Part 1, clause 17.8.1) on the one refusing arm whose rejection helper takes
    /// no in-flight input: it releases the request's carriers itself before framing. This is the arm that proves
    /// the Index slot's own supplied-password carrier is owned and returned, since it is the only path where the
    /// sign-slot compare has already succeeded and the Index compare is what fails.
    /// </summary>
    [TestMethod]
    public async Task RefusedNvCertifyWithAWrongIndexPasswordReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, PasswordArmNvIndexHandle).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, SignKeyPassword).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmPasswordSession signAuth = TpmPasswordSession.Create(SignKeyPasswordBytes, trackingPool.Pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(WrongAuthBytes, trackingPool.Pool);
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, PasswordArmNvIndexHandle, PasswordArmNvIndexHandle,
                CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, trackingPool.Pool);

            long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signAuth, indexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode,
                "A wrong authValue against a dictionary-attack-exempt Index is a plain TPM_RC_BAD_AUTH (TPM 2.0 Library Part 1, clause 17.8.1).");

            Assert.IsGreaterThan(
                qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
                "The parser must have rented the qualifying-data carrier for the refused command, or the balance below proves nothing.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "An Index-authValue mismatch must return both parse-rented password carriers and the qualifying-data carrier to the pool.");
    }

    /// <summary>
    /// A successful all-password <c>TPM2_NV_Certify()</c> returns every carrier the parser rented once the
    /// response has been consumed: the transition releases both slots' supplied passwords once their compares
    /// have consumed them, and the qualifying data transferred out of the request into the NV-certify action, so
    /// it is the attesting effect — not the transition — that is its terminal owner and releases it after the
    /// attestation has copied its octets into <c>extraData</c> (TPM 2.0 Library Part 3, clause 31.16).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulNvCertifyOverPasswordSlotsReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, PasswordArmNvIndexHandle).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, SignKeyPassword).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);
        {
            using TpmPasswordSession signAuth = TpmPasswordSession.Create(SignKeyPasswordBytes, trackingPool.Pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, trackingPool.Pool);
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, PasswordArmNvIndexHandle, PasswordArmNvIndexHandle,
                CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, trackingPool.Pool);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signAuth, indexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"The all-password NV certify must attest with the correct credentials: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.IsGreaterThan(
            qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
            "The parser must have rented the qualifying-data carrier for the successful command, or the balance below proves nothing.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful all-password NV certify must return both password carriers and the qualifying-data carrier to the pool once the response is disposed.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_NV_Certify()</c> refused by the continuation — the requested window runs past
    /// the Index's retained written extent, so <c>TPM_RC_NV_RANGE</c> (TPM 2.0 Library Part 3, clause 31.16) is
    /// answered only AFTER the Index's Name has been computed and both queued command HMACs have verified (clause
    /// 5.6 orders authorization ahead of the parameter checks) — returns every carrier the parser rented. This is
    /// the arm that runs furthest: the request has travelled through the Name-computation effect and back, then
    /// through the HMAC-verification action and back once per slot.
    /// </summary>
    [TestMethod]
    public async Task RefusedNvCertifyAtTheOverSessionContinuationReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, SessionArmNvIndexHandle).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvCertifyResponse> result = await CertifyOverTwoRealSessionsAsync(
            tpm, registry, trackingPool, ak, signSlotAuthValue: ReadOnlyMemory<byte>.Empty, indexSlotAuthValue: IndexAuth,
            size: (ushort)WrittenData.Length, offset: 4).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_RANGE, result.ResponseCode,
            "A window running past the Index's written extent is TPM_RC_NV_RANGE, answered after both command HMACs have verified.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A continuation refusal must return both parse-rented HMAC carriers and the qualifying-data carrier to the pool.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_NV_Certify()</c> whose FIRST queued slot — <c>@signHandle</c> at session index
    /// 0 — presents a command HMAC computed over the wrong authValue never reaches its continuation at all: the
    /// verification step terminates the command with an authorization failure (TPM 2.0 Library Part 2, clause
    /// 6.6.2). The queued request has already crossed the Index-Name hop by then and still owns every carrier the
    /// parser rented, so the mismatch path is what releases them before the rejection is framed.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverSessionWithAMismatchedCommandHmacAtTheSignSlotReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, SessionArmNvIndexHandle).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvCertifyResponse> result = await CertifyOverTwoRealSessionsAsync(
            tpm, registry, trackingPool, ak, signSlotAuthValue: WrongAuthBytes, indexSlotAuthValue: IndexAuth,
            size: (ushort)WrittenData.Length, offset: 0).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
            "A wrong authValue folded into the sign session's command HMAC is an uncharged authorization failure blamed on session index 0, or this path proves nothing about a first-slot mismatch.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A command-HMAC mismatch at the first queued slot must return both parse-rented HMAC carriers and the qualifying-data carrier to the pool.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_NV_Certify()</c> whose SECOND queued slot — <c>@authHandle</c> at session
    /// index 1 — presents a command HMAC computed over the wrong authValue is refused only after the first slot's
    /// HMAC has already verified and the request has been re-threaded through the verification queue (TPM 2.0
    /// Library Part 3, clause 5.6 runs the slots' ladders in session order). The carriers must reach the pool from
    /// that later round trip exactly as they do from the first, so the request stays owned across the whole queue.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverSessionWithAMismatchedCommandHmacAtTheAuthorizingSlotReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, SessionArmNvIndexHandle).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvCertifyResponse> result = await CertifyOverTwoRealSessionsAsync(
            tpm, registry, trackingPool, ak, signSlotAuthValue: ReadOnlyMemory<byte>.Empty, indexSlotAuthValue: WrongAuthBytes,
            size: (ushort)WrittenData.Length, offset: 0).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), result.ResponseCode,
            "The refusal must be blamed on session index 1, which is only reachable once index 0's command HMAC has verified and the request has been re-threaded through the queue.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A command-HMAC mismatch at the second queued slot must return both parse-rented HMAC carriers and the qualifying-data carrier to the pool.");
    }

    /// <summary>
    /// The Index-Name hop's own carrier is returned when the command it serves is refused. A session-authorized
    /// <c>TPM2_NV_Certify()</c> computes the Index's Name in an effect before either command HMAC is verified,
    /// because TPM 2.0 Library Part 1, clause 16.7 equation 15 needs that Name as a cpHash term; the computed
    /// Name rides an owned <c>TPM2B_NAME</c> carrier back through the effect feedback, and the resuming
    /// transition is its terminal owner on every arm — including the arm where the sign slot's command HMAC then
    /// fails and the command is abandoned (Part 2, clause 6.6.2). The rent of exactly the Index Name's width is
    /// asserted first, so the balance below is a proof about a carrier that genuinely existed rather than about
    /// a sentinel that rents nothing.
    /// </summary>
    [TestMethod]
    public async Task RefusedNvCertifyReturnsTheIndexNameHopCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, SessionArmNvIndexHandle).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        long indexNameRentsBefore = trackingPool.RentedCountOfSize(IndexNameSize);

        TpmResult<NvCertifyResponse> result = await CertifyOverTwoRealSessionsAsync(
            tpm, registry, trackingPool, ak, signSlotAuthValue: WrongAuthBytes, indexSlotAuthValue: IndexAuth,
            size: (ushort)WrittenData.Length, offset: 0).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 0), result.ResponseCode,
            "The refusal must be the sign slot's authorization failure, which is only reachable once the Index-Name hop has already run.");

        Assert.AreEqual(
            indexNameRentsBefore + 1, trackingPool.RentedCountOfSize(IndexNameSize),
            "The refused command must have rented exactly one Index-Name-width carrier at the hop, or the balance below proves nothing.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The resuming transition must return the hop's Name carrier to the pool even though the command it served was refused.");
    }

    /// <summary>
    /// A successful session-authorized <c>TPM2_NV_Certify()</c> over two real HMAC sessions returns every carrier
    /// the parser rented once the response has been consumed: the continuation releases both slots' supplied
    /// HMACs as their terminal owner, and the qualifying data transferred out of the request into the NV-certify
    /// action, so it is the attesting effect that releases it (TPM 2.0 Library Part 3, clause 31.16; Part 1,
    /// clause 16.6.1 for the response entries).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulNvCertifyOverSessionReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, SessionArmNvIndexHandle).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);

        TpmResult<NvCertifyResponse> result = await CertifyOverTwoRealSessionsAsync(
            tpm, registry, trackingPool, ak, signSlotAuthValue: ReadOnlyMemory<byte>.Empty, indexSlotAuthValue: IndexAuth,
            size: (ushort)WrittenData.Length, offset: 0).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The session-authorized NV certify must attest with the correct authValues: '{result.ResponseCode}'.");
        result.Value.Dispose();

        Assert.IsGreaterThan(
            qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
            "The parser must have rented the qualifying-data carrier for the successful command, or the balance below proves nothing.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful session-authorized NV certify must return both parse-rented HMAC carriers and the qualifying-data carrier to the pool once the response is disposed.");
    }

    /// <summary>
    /// A successful all-password <c>TPM2_NV_Certify()</c> whose attestation key is RSA returns every carrier the
    /// parser rented, exactly as the elliptic-curve path does: the signing key's type selects a different
    /// attesting effect (TPM 2.0 Library Part 3, clause 31.16 leaves what is attested untouched by the scheme),
    /// and that effect owes the same terminal-owner release of the qualifying data the transition transferred
    /// into its action.
    /// </summary>
    [TestMethod]
    public async Task SuccessfulNvCertifyOverAnRsaSigningKeyReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, PasswordArmNvIndexHandle).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateRsaSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);
        {
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, trackingPool.Pool);
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForRsaSsa(
                ak.ObjectHandle, PasswordArmNvIndexHandle, PasswordArmNvIndexHandle,
                CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, trackingPool.Pool);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signAuth, indexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"The RSA-signed NV certify must attest with the correct credentials: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.IsGreaterThan(
            qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
            "The parser must have rented the qualifying-data carrier for the successful command, or the balance below proves nothing.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful RSA-signed NV certify must return both password carriers and the qualifying-data carrier to the pool once the response is disposed.");
    }

    /// <summary>
    /// A <c>TPM2_NV_Certify()</c> over a MIXED authorization area whose <c>TPM_RS_PW</c> sign slot carries a
    /// non-empty <c>nonceCaller</c> on the wire is refused with <c>TPM_RC_NONCE</c> encoded to that slot while the
    /// slot is still being read, so the parse rents nothing at all and the pool balance does not move. This
    /// command would otherwise carry the whole area through the Index-Name hop before either slot is settled, so
    /// the structural refusal spares it an effect round trip as well as the rentals.
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
    public async Task NvCertifyOverAMixedAreaWithAPasswordSlotNonceIsRefusedAtParseAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, MixedArmNvIndexHandle).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);

        async ValueTask<TpmResult<TpmResponse>> PlantPasswordSlotNonceAsync(ReadOnlyMemory<byte> command, BaseMemoryPool commandPool, CancellationToken cancellationToken)
        {
            if(ReadCommandCode(command.Span) != TpmCcConstants.TPM_CC_NV_Certify)
            {
                return await simulator.SubmitAsync(command, commandPool, cancellationToken).ConfigureAwait(false);
            }

            return await simulator.SubmitAsync(
                WithPasswordSlotNonce(command.Span, handleCount: 3, PasswordSlotNonce), commandPool, cancellationToken).ConfigureAwait(false);
        }

        using TpmDevice plantingTpm = TpmDevice.Create(PlantPasswordSlotNonceAsync);

        long baseline = trackingPool.OutstandingCount;
        long nonceRentsBefore = trackingPool.RentedCountOfSize(PasswordSlotNonce.Length);

        TpmResult<NvCertifyResponse> result = await CertifyOverAMixedAreaAsync(tpm, plantingTpm, registry, trackingPool, ak).ConfigureAwait(false);
        if(result.IsSuccess)
        {
            result.Value.Dispose();
        }

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NONCE, result.BaseError,
            "A password slot carries no nonce at all, so a non-empty nonceCaller there is a nonce error.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_NONCE, sessionIndex: 0), result.ResponseCode,
            "The refusal names the offending slot — the password sign slot at index 0 — session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");

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
    public async Task NvCertifyWithQualifyingDataOverTheDataBoundIsRefusedAtParseAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        await DefineAndWriteNvIndexAsync(tpm, registry, trackingPool.Pool, PasswordArmNvIndexHandle).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(
            tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT, password: null).ConfigureAwait(false);

        byte[] atBound = new byte[Tpm2bData.MaxSize];
        atBound.AsSpan().Fill(0x3C);
        byte[] overBound = new byte[Tpm2bData.MaxSize + 1];
        overBound.AsSpan().Fill(0x3C);

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmPasswordSession atBoundSignAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmPasswordSession atBoundIndexAuth = TpmPasswordSession.Create(IndexAuth, trackingPool.Pool);
            using NvCertifyInput atBoundInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, PasswordArmNvIndexHandle, PasswordArmNvIndexHandle,
                atBound, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, trackingPool.Pool);

            TpmResult<NvCertifyResponse> atBoundResult = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, atBoundInput, [atBoundSignAuth, atBoundIndexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                atBoundResult.IsSuccess,
                $"A qualifyingData of exactly sizeof(TPMT_HA) octets is inside the TPM2B_DATA bound and must be certified: '{atBoundResult.ResponseCode}'.");
            atBoundResult.Value.Dispose();

            using TpmPasswordSession overBoundSignAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmPasswordSession overBoundIndexAuth = TpmPasswordSession.Create(IndexAuth, trackingPool.Pool);
            using NvCertifyInput overBoundInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, PasswordArmNvIndexHandle, PasswordArmNvIndexHandle,
                overBound, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, trackingPool.Pool);

            long overBoundRentsBefore = trackingPool.RentedCountOfSize(overBound.Length);

            TpmResult<NvCertifyResponse> overBoundResult = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, overBoundInput, [overBoundSignAuth, overBoundIndexAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
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
    /// Certifies <see cref="SessionArmNvIndexHandle"/> with <paramref name="ak"/> over two fresh, real, unbound
    /// and unsalted HMAC sessions — one per authorization slot, in handle order — flushing both on the way out.
    /// The sessions live entirely inside this call, so the nonce carriers they adopt from the response entries
    /// (TPM 2.0 Library Part 1, clause 16.6.1) are released before a caller reads the pool balance.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="trackingPool">The metered pool every carrier is rented from.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="signSlotAuthValue">The authValue term folded into the sign slot's session; empty matches the key's own empty authValue.</param>
    /// <param name="indexSlotAuthValue">The authValue term folded into the Index slot's session.</param>
    /// <param name="size">The number of octets to certify.</param>
    /// <param name="offset">The octet offset into the Index data area.</param>
    /// <returns>The NV-certify result, not asserted for success.</returns>
    private async Task<TpmResult<NvCertifyResponse>> CertifyOverTwoRealSessionsAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MeteredHousePool trackingPool, CreatePrimaryResponse ak,
        ReadOnlyMemory<byte> signSlotAuthValue, ReadOnlyMemory<byte> indexSlotAuthValue, ushort size, ushort offset)
    {
        StartAuthSessionResponse signStarted = await StartHmacSessionAsync(tpm, registry, trackingPool).ConfigureAwait(false);
        uint signSessionHandle = signStarted.SessionHandle.Value;
        StartAuthSessionResponse indexStarted = await StartHmacSessionAsync(tpm, registry, trackingPool).ConfigureAwait(false);
        uint indexSessionHandle = indexStarted.SessionHandle.Value;

        try
        {
            using TpmSession signSession = new(new TpmHandle(signSessionHandle), signStarted.NonceTPM, HmacSessionAlg, trackingPool.Pool);
            if(!signSlotAuthValue.IsEmpty)
            {
                signSession.SetAuthValue(signSlotAuthValue.Span, trackingPool.Pool);
            }

            using TpmSession indexSession = new(new TpmHandle(indexSessionHandle), indexStarted.NonceTPM, HmacSessionAlg, trackingPool.Pool);
            indexSession.SetAuthValue(indexSlotAuthValue.Span, trackingPool.Pool);

            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, SessionArmNvIndexHandle, SessionArmNvIndexHandle,
                CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA256, size, offset, trackingPool.Pool);

            byte[] indexName = await ComputeNvIndexNameAsync(
                SessionArmNvIndexHandle, DefaultNameAlg, NoDaIndexAttributes | TpmaNv.TPMA_NV_WRITTEN,
                (ushort)WrittenData.Length, trackingPool.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.AsReadOnlyMemory(), indexName, indexName];

            return await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                tpm, nvCertifyInput, [signSession, indexSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(signSessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(indexSessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Certifies <see cref="MixedArmNvIndexHandle"/> with <paramref name="ak"/> over a MIXED authorization area —
    /// a <c>TPM_RS_PW</c> sign slot and one fresh, real, unbound and unsalted HMAC session authorizing the Index —
    /// issuing the command through <paramref name="plantingTpm"/> so the password slot arrives carrying a
    /// non-empty <c>nonceCaller</c>, and flushing the session on the way out. The session lives entirely inside
    /// this call, so the nonce carrier it adopts from its response entry (TPM 2.0 Library Part 1, clause 16.6.1)
    /// is released before a caller reads the pool balance.
    /// </summary>
    /// <param name="plainTpm">The untouched TPM device, used for the session lifecycle commands.</param>
    /// <param name="plantingTpm">The TPM device whose transport plants the password slot's nonce.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="trackingPool">The metered pool every carrier is rented from.</param>
    /// <param name="ak">The attestation key's CreatePrimary response; its empty authValue authorizes the password sign slot.</param>
    /// <returns>The NV-certify result, not asserted for success.</returns>
    private async Task<TpmResult<NvCertifyResponse>> CertifyOverAMixedAreaAsync(
        TpmDevice plainTpm, TpmDevice plantingTpm, TpmResponseRegistry registry, MeteredHousePool trackingPool, CreatePrimaryResponse ak)
    {
        StartAuthSessionResponse indexStarted = await StartHmacSessionAsync(plainTpm, registry, trackingPool).ConfigureAwait(false);
        uint indexSessionHandle = indexStarted.SessionHandle.Value;

        try
        {
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using TpmSession indexSession = new(new TpmHandle(indexSessionHandle), indexStarted.NonceTPM, HmacSessionAlg, trackingPool.Pool);
            indexSession.SetAuthValue(IndexAuth, trackingPool.Pool);

            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, MixedArmNvIndexHandle, MixedArmNvIndexHandle,
                CarrierProofNonce, TpmAlgIdConstants.TPM_ALG_SHA256, (ushort)WrittenData.Length, offset: 0, trackingPool.Pool);

            byte[] indexName = await ComputeNvIndexNameAsync(
                MixedArmNvIndexHandle, DefaultNameAlg, NoDaIndexAttributes | TpmaNv.TPMA_NV_WRITTEN,
                (ushort)WrittenData.Length, trackingPool.Pool, TestContext.CancellationToken).ConfigureAwait(false);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.AsReadOnlyMemory(), indexName, indexName];

            return await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                plantingTpm, nvCertifyInput, [signAuth, indexSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                plainTpm, FlushContextInput.ForHandle(indexSessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
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
    /// Defines an NV Index under the owner hierarchy (empty owner authorization, matching the simulator's
    /// default) carrying <see cref="IndexAuth"/> as its own authorization value and sized for
    /// <see cref="WrittenData"/>, then writes those octets to it in full, setting <c>TPMA_NV_WRITTEN</c>.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    private async Task DefineAndWriteNvIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(IndexAuth, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, DefaultNameAlg, NoDaIndexAttributes, policyDigest, dataSize: (ushort)WrittenData.Length);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        using TpmPasswordSession writeAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(WrittenData, pool);
        var writeInput = new NvWriteInput(nvIndex, nvIndex, writeInputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// Creates a dictionary-attack-exempt primary ECC P-256 signing key under the given hierarchy, optionally
    /// carrying a non-empty authValue.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <param name="password">The authValue the key carries; <see langword="null"/> for an empty one.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy, string? password)
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
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Creates a dictionary-attack-exempt primary RSA 2048 signing key under the given hierarchy with an empty
    /// authValue — the fixture the RSA attesting effect's own carrier release is proven against.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateRsaSigningPrimaryAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmRh hierarchy)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForRsaSigningKey(
            hierarchy, password: null, keyBits: 2048, TpmtRsaScheme.Null, pool, noDa: true);

        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA 2048, {hierarchy}) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Recomputes an NV Index's Name independently: <c>nameAlg || H_nameAlg(nvIndex || nameAlg || attributes ||
    /// authPolicy || dataSize)</c> — the whole marshaled TPMS_NV_PUBLIC these tests defined the Index with (TPM
    /// 2.0 Library Part 2, clause 13.6) hashed per Part 1, clause 14, Table 6 — through the registered digest
    /// seam. Every Index here is defined with an empty access policy, so the policy field marshals as a
    /// zero-length TPM2B.
    /// </summary>
    /// <param name="nvIndex">The NV Index handle.</param>
    /// <param name="nameAlg">The Index's Name algorithm, which both prefixes the Name and selects the hash.</param>
    /// <param name="attributes">The Index attributes these tests defined the Index with.</param>
    /// <param name="dataSize">The Index's declared data size.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The recomputed Name (2-byte nameAlg prefix + digest).</returns>
    private static async Task<byte[]> ComputeNvIndexNameAsync(
        uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ushort dataSize, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        byte[] marshaled = new byte[sizeof(uint) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + sizeof(ushort)];
        int offset = 0;
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset), nvIndex);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), (ushort)nameAlg);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset), (uint)attributes);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), 0);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset), dataSize);

        byte[] digest = await ComputeSha256Async(marshaled, pool, cancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>
    /// Computes a SHA-256 digest through the registered digest seam (not a direct framework hash).
    /// </summary>
    /// <param name="message">The message to hash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The 32-byte digest.</returns>
    private static async Task<byte[]> ComputeSha256Async(ReadOnlyMemory<byte> message, BaseMemoryPool pool, CancellationToken cancellationToken)
    {
        Tag tag = Tag.Create(HashAlgorithmName.SHA256)
            .With(Purpose.Digest)
            .With(EncodingScheme.Raw)
            .With(MaterialSemantics.Direct);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            new ReadOnlySequence<byte>(message),
            outputByteLength: 32,
            tag: tag,
            pool: pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
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
            "tpm-in-house-nv-certify-carriers",
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

    /// <summary>Creates a response codec registry covering the commands the all-password cases issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);

        return registry;
    }

    /// <summary>Extends <see cref="CreateRegistry"/> with the StartAuthSession and FlushContext codecs the session cases need.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateHmacArmRegistry()
    {
        TpmResponseRegistry registry = CreateRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
