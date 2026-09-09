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
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves the pooled-carrier ownership of <c>TPM2_CertifyCreation()</c>'s wire parameters (TPM 2.0 Library Part
/// 3, clause 18.3, Table 99) against the in-house behavioural <see cref="TpmSimulator"/>: the
/// <c>qualifyingData</c> (<c>TPM2B_DATA</c>), the <c>creationHash</c> (<c>TPM2B_DIGEST</c>), and the creation
/// ticket's own digest each ride a carrier the parser rents, and each reaches the pool again on every path a
/// command can leave by — refused at the entry transition, refused at the session continuation, refused for a
/// mismatched command HMAC, refused inside the effect for a ticket that does not reproduce, and certified
/// successfully — while a frame the parser itself refuses rents nothing at all.
/// </summary>
/// <remarks>
/// <para>
/// The instrument is <see cref="MeteredHousePool"/>: a genuine <see cref="BaseMemoryPool"/> whose own rent and
/// return telemetry is observed, so nothing here depends on a seam in production code. Every value driven
/// through a carrier under test is deliberately NON-EMPTY, because an empty one parses to the type's shared
/// dispose-immune sentinel, which rents nothing and would make a balance assertion vacuous.
/// </para>
/// <para>
/// The ticket-mismatch path is the one this command has and its siblings do not: the re-verification needs the
/// asynchronous digest seam, so the refusal is decided inside the effect after the carriers have already
/// transferred into the action — the case that pins the effect's release as unconditional rather than
/// success-only.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorCertifyCreationCarrierTests
{
    /// <summary>The hash algorithm for every real HMAC session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// The signing key's authValue for the session-authorized fixtures. It stays inside the SHA-256 nameAlg's
    /// 32-octet digest width, the bound an object's authValue may not exceed (TPM 2.0 Library Part 1, clause
    /// 16.6.4.2).
    /// </summary>
    private const string SignKeyPassword = "certify-creation-carrier-auth";

    /// <summary>
    /// The caller nonce these tests drive as <c>qualifyingData</c>. Its 61-octet width is deliberately unlike
    /// any digest, key, or nonce width the surrounding machinery rents, so a rent of exactly this size across a
    /// command identifies the <c>TPM2B_DATA</c> carrier the parser created.
    /// </summary>
    private static byte[] CarrierProofNonce { get; } = "CertifyCreation carrier ownership proof nonce for the TPM 2.0"u8.ToArray();

    /// <summary>The signing key's authValue in wire form — the UTF-8 octets of <see cref="SignKeyPassword"/>.</summary>
    private static byte[] SignKeyPasswordBytes { get; } = System.Text.Encoding.UTF8.GetBytes(SignKeyPassword);

    /// <summary>A wrong guess at the signing key's authValue, distinct from <see cref="SignKeyPasswordBytes"/>.</summary>
    private static byte[] WrongSignKeyPasswordBytes { get; } = [0x61, 0x62, 0x63, 0x64];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A <c>TPM2_CertifyCreation()</c> refused by the entry transition — the signHandle (the 1st handle in the
    /// handle area, index 0) is transient-range but resolves to no loaded object, so TPM 2.0 Library Part 3,
    /// clause 5.4 step 2.1 answers <c>TPM_RC_REFERENCE_H0</c> before any parameter is looked at — returns every
    /// carrier the parser rented: the sign slot's supplied password, the qualifying data, the creation hash, and
    /// the ticket digest. The refusing arm reaches them through the request record's own
    /// <c>IDisposable.Dispose</c>, which is the only owner they ever had, because a handle refusal transfers
    /// nothing into an action.
    /// </summary>
    [TestMethod]
    public async Task RefusedCertifyCreationAtTheEntryTransitionReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmPasswordSession signAuth = TpmPasswordSession.Create(WrongSignKeyPasswordBytes, trackingPool.Pool);
            using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
                TpmiDhObject.FromValue(TpmSimulatorState.TransientHandleBase + 0x00FFFF00), subject.ObjectHandle, CarrierProofNonce,
                subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

            long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);

            TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, certifyCreationInput, [signAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_REFERENCE_H0, result.ResponseCode,
                "A transient-range signHandle (the 1st handle in the handle area) that resolves to no loaded object is TPM_RC_REFERENCE_H0 (TPM 2.0 Library Part 3, clause 5.4, step 2.1).");

            Assert.IsGreaterThan(
                qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
                "The parser must have rented the qualifying-data carrier before the transition refused, or the balance below proves nothing.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A handle refusal must return the parse-rented password, qualifying-data, creation-hash, and ticket-digest carriers to the pool.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_CertifyCreation()</c> refused by the continuation — the scheme hash
    /// algorithm is one the attest digest path does not implement, so <c>TPM_RC_HASH</c> is answered only AFTER
    /// the command HMAC has verified (TPM 2.0 Library Part 3, clause 5.6 orders authorization ahead of the
    /// parameter checks) — returns every carrier the parser rented. This is the arm that runs one step further
    /// than the entry refusal: the request has already travelled through the HMAC-verification action and back.
    /// </summary>
    [TestMethod]
    public async Task RefusedCertifyCreationAtTheOverSessionContinuationReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<CertifyCreationResponse> result = await CertifyCreationOverRealSignSessionAsync(
            tpm, registry, trackingPool, ak, subject, subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA1, SignKeyPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_HASH, 2), result.ResponseCode,
            "A scheme hash the attest digest path does not implement is refused with TPM_RC_HASH after the command HMAC has verified.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A continuation refusal must return the parse-rented HMAC, qualifying-data, creation-hash, and ticket-digest carriers to the pool.");
    }

    /// <summary>
    /// A session-authorized <c>TPM2_CertifyCreation()</c> whose sign slot presents a command HMAC computed over
    /// the wrong authValue never reaches its continuation at all: the verification step terminates the command
    /// with an authorization failure (TPM 2.0 Library Part 2, clause 6.6.2). The queued request still owns every
    /// carrier the parser rented, and the mismatch path releases them before the rejection is framed.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationOverSessionWithAMismatchedCommandHmacReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<CertifyCreationResponse> result = await CertifyCreationOverRealSignSessionAsync(
            tpm, registry, trackingPool, ak, subject, subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, WrongSignKeyPasswordBytes).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError,
            "A wrong authValue folded into the sign session's command HMAC must be a genuine authorization failure, or this path proves nothing about a mismatch.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A command-HMAC mismatch must return the parse-rented HMAC, qualifying-data, creation-hash, and ticket-digest carriers to the pool.");
    }

    /// <summary>
    /// A <c>TPM2_CertifyCreation()</c> whose creation ticket does not reproduce is refused with
    /// <c>TPM_RC_TICKET</c> from inside the effect (TPM 2.0 Library Part 3, clause 18.3: the re-derivation needs
    /// the asynchronous digest seam, so the outcome is decided there rather than in the transition), designated
    /// to <c>creationTicket</c>, Table 99's fourth parameter (index 3) — and still returns every carrier the
    /// request transferred into the action. This is the path that proves the effect releases them on its early
    /// return, not only after a successful attestation.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithATicketThatDoesNotReproduceReturnsTheTransferredCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmtTkCreation tamperedTicket = FlipTicketOctet(subject.CreationTicket, trackingPool.Pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, CarrierProofNonce,
                subject.CreationHash.AsReadOnlySpan(), tamperedTicket, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

            long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);

            TpmResult<CertifyCreationResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, certifyCreationInput, [signAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_TICKET, 3), result.ResponseCode,
                "A creation ticket that does not reproduce is TPM_RC_TICKET at creationTicket, parameter 4 of Table 99 (TPM 2.0 Library Part 3, clause 18.3).");

            Assert.IsGreaterThan(
                qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
                "The parser must have rented the qualifying-data carrier before the effect refused, or the balance below proves nothing.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A ticket that does not reproduce must still return the qualifying-data, creation-hash, and ticket-digest carriers the effect took ownership of.");
    }

    /// <summary>
    /// A successful session-authorized <c>TPM2_CertifyCreation()</c> returns every carrier the parser rented once
    /// the response has been consumed: the qualifying data, the creation hash, and the ticket digest transferred
    /// out of the request into the certify-creation action, so it is the attesting effect — not the continuation
    /// — that is their terminal owner, and the ticket comparison and the attestation have read their octets by
    /// the time it releases them (TPM 2.0 Library Part 3, clause 18.3; Part 1, clause 15.6.1 for the response
    /// entry).
    /// </summary>
    [TestMethod]
    public async Task SuccessfulCertifyCreationOverSessionReturnsTheParseRentedCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateHmacArmRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateNoDaSigningPrimaryWithAuthAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        long qualifyingRentsBefore = trackingPool.RentedCountOfSize(CarrierProofNonce.Length);

        TpmResult<CertifyCreationResponse> result = await CertifyCreationOverRealSignSessionAsync(
            tpm, registry, trackingPool, ak, subject, subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, SignKeyPasswordBytes).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The session-authorized certify-creation must attest with the correct authValue: '{result.ResponseCode}'.");
        result.Value.Dispose();

        Assert.IsGreaterThan(
            qualifyingRentsBefore, trackingPool.RentedCountOfSize(CarrierProofNonce.Length),
            "The parser must have rented the qualifying-data carrier for the successful command, or the balance below proves nothing.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A successful certify-creation must return the parse-rented HMAC, qualifying-data, creation-hash, and ticket-digest carriers to the pool once the response is disposed.");
    }

    /// <summary>
    /// A <c>qualifyingData</c> wider than <c>TPM2B_DATA</c>'s declared bound — <c>sizeof(TPMT_HA)</c>, the
    /// 2-octet algorithm identifier plus the largest supported digest (TPM 2.0 Library Part 2, clause 10.3.3,
    /// Table 91) — is refused with <c>TPM_RC_SIZE</c> while the frame is still being parsed, so the parse rents
    /// nothing at all: the pool balance does not move, and the refusal is a response code rather than an
    /// exception escaping the command surface.
    /// </summary>
    [TestMethod]
    public async Task CertifyCreationWithQualifyingDataOverTheDataBoundIsRefusedAtParseAndRentsNothing()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(tpm, registry, trackingPool.Pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        byte[] atBound = new byte[Tpm2bData.MaxSize];
        atBound.AsSpan().Fill(0x3C);
        byte[] overBound = new byte[Tpm2bData.MaxSize + 1];
        overBound.AsSpan().Fill(0x3C);

        long baseline = trackingPool.OutstandingCount;
        {
            using TpmPasswordSession atBoundAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using CertifyCreationInput atBoundInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, atBound,
                subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

            TpmResult<CertifyCreationResponse> atBoundResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, atBoundInput, [atBoundAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(
                atBoundResult.IsSuccess,
                $"A qualifyingData of exactly sizeof(TPMT_HA) octets is inside the TPM2B_DATA bound and must be certified: '{atBoundResult.ResponseCode}'.");
            atBoundResult.Value.Dispose();

            using TpmPasswordSession overBoundAuth = TpmPasswordSession.CreateEmpty(trackingPool.Pool);
            using CertifyCreationInput overBoundInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, overBound,
                subject.CreationHash.AsReadOnlySpan(), subject.CreationTicket, TpmAlgIdConstants.TPM_ALG_SHA256, trackingPool.Pool);

            long overBoundRentsBefore = trackingPool.RentedCountOfSize(overBound.Length);

            TpmResult<CertifyCreationResponse> overBoundResult = await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, overBoundInput, [overBoundAuth], null, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), overBoundResult.ResponseCode,
                "A qualifyingData wider than sizeof(TPMT_HA) is TPM_RC_SIZE at qualifyingData, parameter 1 of the CertifyCreation command table (TPM 2.0 Library Part 2, clause 10.3.3, Table 91).");

            Assert.AreEqual(
                overBoundRentsBefore, trackingPool.RentedCountOfSize(overBound.Length),
                "A frame the parser refuses must not have rented a carrier for the over-bound value it refused.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A parse-time refusal rents nothing, so the pool balance may not move across it.");
    }

    /// <summary>
    /// Rewrites a creation ticket with its last octet inverted, so the digest it carries cannot reproduce — the
    /// tampered fixture the ticket-mismatch path needs.
    /// </summary>
    /// <param name="ticket">The genuine ticket.</param>
    /// <param name="pool">The memory pool the rewritten ticket is parsed into.</param>
    /// <returns>The tampered ticket (the caller owns it).</returns>
    private static TpmtTkCreation FlipTicketOctet(TpmtTkCreation ticket, BaseMemoryPool pool)
    {
        int size = ticket.SerializedSize;
        byte[] wireBytes = new byte[size];
        var writer = new TpmWriter(wireBytes);
        ticket.WriteTo(ref writer);

        wireBytes[^1] ^= 0xFF;

        var reader = new TpmReader(wireBytes);

        return TpmtTkCreation.Parse(ref reader, pool);
    }

    /// <summary>
    /// Certifies <paramref name="subject"/>'s creation with <paramref name="ak"/> over a fresh, real, unbound and
    /// unsalted HMAC sign session carrying <paramref name="signSlotAuthValue"/>, flushing the session on the way
    /// out. The session lives entirely inside this call, so the nonce carrier it adopts from the response (TPM
    /// 2.0 Library Part 1, clause 15.6.1) is released before a caller reads the pool balance.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="trackingPool">The metered pool every carrier is rented from.</param>
    /// <param name="ak">The attestation key's CreatePrimary response.</param>
    /// <param name="subject">The certified object's CreatePrimary response.</param>
    /// <param name="creationTicket">The creation ticket to present.</param>
    /// <param name="schemeHashAlg">The signing scheme's hash algorithm.</param>
    /// <param name="signSlotAuthValue">The authValue term folded into the sign session.</param>
    /// <returns>The certify-creation result, not asserted for success.</returns>
    private async Task<TpmResult<CertifyCreationResponse>> CertifyCreationOverRealSignSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, MeteredHousePool trackingPool, CreatePrimaryResponse ak, CreatePrimaryResponse subject,
        TpmtTkCreation creationTicket, TpmAlgIdConstants schemeHashAlg, ReadOnlyMemory<byte> signSlotAuthValue)
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

            using CertifyCreationInput certifyCreationInput = CertifyCreationInput.ForEcdsa(
                ak.ObjectHandle, subject.ObjectHandle, CarrierProofNonce,
                subject.CreationHash.AsReadOnlySpan(), creationTicket, schemeHashAlg, trackingPool.Pool);
            ReadOnlyMemory<byte>[] handleNames = [ak.Name.Span.ToArray(), subject.Name.Span.ToArray()];

            return await TpmCommandExecutor.ExecuteAsync<CertifyCreationResponse>(
                tpm, certifyCreationInput, [signSession], handleNames, trackingPool.Pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                tpm, FlushContextInput.ForHandle(sessionHandle), [], null, trackingPool.Pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
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
            "tpm-in-house-certify-creation-carriers",
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
        _ = registry.Register(TpmCcConstants.TPM_CC_CertifyCreation, TpmResponseCodec.CertifyCreation);

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
