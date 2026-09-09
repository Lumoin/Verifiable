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
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives the attest family's THIRD kind of authorization slot against the in-house behavioural
/// <see cref="TpmSimulator"/>: a companion session that authorizes no entity and rides the area only to carry
/// <c>decrypt</c>, <c>encrypt</c>, or <c>audit</c> (TPM 2.0 Library Part 1, clause 15.6.1 — an authorization area
/// holds "at least one but no more than three" blocks — and Table 12, whose position after the authorization
/// sessions may be "encryption, decryption, or audit" only).
/// </summary>
/// <remarks>
/// <para>
/// Every companion here is planted on the WIRE rather than through the host session list, because the rules
/// under test are the area's structural ones: Part 3, clause 5.5's session-area consistency checks run strictly
/// before clause 5.6's authorization, so a companion carrying an arbitrary <c>hmac</c> is refused for its
/// attributes or its handle long before that <c>hmac</c> is looked at. Planting it on the wire is what lets each
/// test name exactly one rule and vary exactly one octet.
/// </para>
/// <para>
/// The attest arms admit such a slot structurally but transform neither the command's <c>qualifyingData</c> nor
/// the response's <c>TPM2B_ATTEST</c>, so every attribute a companion can legally carry is refused with
/// <c>TPM_RC_ATTRIBUTES</c> session-encoded to the claiming slot (Part 3, clause 5.7 for the encryption
/// attributes; the same fail-closed posture the audit attribute already had). What each test pins is therefore
/// WHICH rule answers and WHICH slot it blames, since the encoding is the only thing that distinguishes them.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorAttestCompanionSessionTests
{
    /// <summary>The hash algorithm for every real HMAC session these tests start.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The PCR bank <c>TPM2_Quote()</c> attests over.</summary>
    private const TpmAlgIdConstants PcrBank = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The command header's fixed width: tag (UINT16), commandSize (UINT32), commandCode (UINT32).</summary>
    private const int CommandHeaderSize = 10;

    /// <summary>The Name algorithm the NV Index the <c>TPM2_NV_Certify()</c> cases attest over is defined with.</summary>
    private const TpmAlgIdConstants IndexNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The NV Index handle the <c>TPM2_NV_Certify()</c> cases define, write, and attest over.</summary>
    private const uint NvIndexHandle = 0x0100_0031;

    /// <summary>
    /// The attributes that Index is defined with: readable and writable by its own authValue, and exempt from
    /// dictionary-attack protection (<c>TPMA_NV_NO_DA</c>), so nothing these tests do can move a lockout counter
    /// (TPM 2.0 Library Part 1, clause 16.8.1).
    /// </summary>
    private const TpmaNv NoDaIndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The PCR indices <c>TPM2_Quote()</c> attests over.</summary>
    private static int[] PcrIndices { get; } = [0, 7];

    /// <summary>The authValue the NV Index the <c>TPM2_NV_Certify()</c> cases define carries.</summary>
    private static byte[] IndexAuth { get; } = [0x0A, 0x0B, 0x0C, 0x0D];

    /// <summary>The octets written into that Index, and the full window the <c>TPM2_NV_Certify()</c> cases name.</summary>
    private static byte[] WrittenData { get; } = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];

    /// <summary>
    /// The caller nonce these tests drive as <c>qualifyingData</c>. Its 58-octet width is unlike any digest, key,
    /// or nonce width the surrounding machinery rents, so a rent of exactly this size identifies the
    /// <c>TPM2B_DATA</c> carrier the parser created.
    /// </summary>
    private static byte[] Nonce { get; } = "Companion-session proof nonce for the TPM 2.0 library area"u8.ToArray();

    /// <summary>
    /// The <c>nonceCaller</c> every planted companion presents. Its 44-octet width is unlike any other width the
    /// surrounding machinery rents, so a rent of exactly this size identifies the <c>TPM2B_NONCE</c> carrier the
    /// parser created for the companion slot.
    /// </summary>
    private static byte[] CompanionNonce { get; } = "Companion slot nonceCaller proof octets, 44."u8.ToArray();

    /// <summary>
    /// The <c>hmac</c> every planted companion presents. A companion owes a REAL command HMAC (Part 3, clause 5.6
    /// applies to every session in the area), but no test here reaches that check, so these octets stand in for
    /// one at the right width without any test depending on their value.
    /// </summary>
    private static byte[] CompanionHmac { get; } = "Companion slot hmac field proof octets, 40 lo"u8.ToArray()[..32];

    /// <summary>
    /// The <c>nonceCaller</c> the password-slot nonce case plants. A password authorization carries none at all,
    /// so any width refuses; this one is deliberately unlike every other width the surrounding machinery rents,
    /// so a rental of exactly this size would identify a carrier the parse created for it.
    /// </summary>
    private static byte[] PasswordSlotNonce { get; } = "Password-slot nonceCaller proof octets, 47 long"u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A companion slot that authorizes nothing and claims NONE of decrypt, encrypt, or audit is refused with
    /// <c>TPM_RC_ATTRIBUTES</c> encoded to its own index: "If a session is not being used for authorization, at
    /// least one of decrypt, encrypt, or audit must be SET" (TPM 2.0 Library Part 1, clause 15.6.4), blamed on
    /// the offending slot (Part 2, clause 6.6.2). The refusal is also what proves the parser READ the slot at
    /// all: an area whose trailing octets went unread would answer <c>TPM_RC_AUTHSIZE</c> instead.
    /// </summary>
    [TestMethod]
    public async Task QuoteCompanionSessionClaimingNoAttributeIsRefusedWithAttributesAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await QuoteWithPlantedCompanionAsync(
            trackingPool.Pool, TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, baseError,
            "A session authorizing no entity must claim at least one of decrypt, encrypt, or audit (Part 1, clause 15.6.4).");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "The refusal names the companion slot, so the wire code carries its session-index modifier.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_AUTHSIZE, responseCode,
            "TPM_RC_AUTHSIZE would mean the parser never read the companion slot, leaving its attributes unvalidated.");
    }

    /// <summary>
    /// A companion slot claiming <c>audit</c> is admitted as an attribute (TPM 2.0 Library Part 1, clause 17.1)
    /// and then owes a command HMAC of its own, exactly as a companion claiming <c>decrypt</c> or <c>encrypt</c>
    /// does — a slot planted on the wire with an arbitrary <c>hmac</c> is refused for THAT, never for the
    /// attribute.
    /// </summary>
    [TestMethod]
    public async Task QuoteCompanionSessionClaimingAuditOwesItsOwnCommandHmac()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await QuoteWithPlantedCompanionAsync(
            trackingPool.Pool, TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, baseError,
            "A companion carrying audit is admitted for the attribute and refused for the HMAC it could not supply.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), responseCode,
            "The refusal names the companion slot, so the wire code carries its session-index modifier.");
        Assert.AreNotEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "TPM_RC_ATTRIBUTES would mean the audit attribute itself was refused rather than admitted.");
    }

    /// <summary>
    /// A companion slot claiming <c>decrypt</c> is admitted as an attribute and then owes a command HMAC of its
    /// own, so a slot planted on the wire with an arbitrary <c>hmac</c> is refused for THAT — session-encoded to
    /// its own index — and never for the attribute. <c>qualifyingData</c> is an encryption-eligible first command
    /// parameter (TPM 2.0 Library Part 3, clause 18.4, Table 101; Part 1, clause 15.4: the first parameter and a
    /// TPM2B), and a session that authorizes no entity still presents a real HMAC keyed on its session key with
    /// no authValue term (Part 3, clause 5.6 applies to every session in the area).
    /// </summary>
    [TestMethod]
    public async Task QuoteCompanionSessionClaimingDecryptOwesItsOwnCommandHmac()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await QuoteWithPlantedCompanionAsync(
            trackingPool.Pool, TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, baseError,
            "A companion carrying decrypt is admitted for the attribute and refused for the HMAC it could not supply.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), responseCode,
            "The refusal names the companion slot, so the wire code carries its session-index modifier.");
        Assert.AreNotEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "TPM_RC_ATTRIBUTES would mean the decrypt attribute itself was refused on a parameter the command can protect.");
    }

    /// <summary>
    /// A companion slot claiming <c>encrypt</c> is admitted the same way and refused at the same index for the
    /// same reason as one claiming <c>decrypt</c>: <c>TPM2B_ATTEST</c> is an encryption-eligible first response
    /// parameter (TPM 2.0 Library Part 3, clause 18.4, Table 102), so the response-side gate admits the claim and
    /// what is left to fail is the companion's own command HMAC.
    /// </summary>
    [TestMethod]
    public async Task QuoteCompanionSessionClaimingEncryptOwesItsOwnCommandHmac()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await QuoteWithPlantedCompanionAsync(
            trackingPool.Pool, TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_BAD_AUTH, baseError,
            "A companion carrying encrypt is admitted for the attribute and refused for the HMAC it could not supply.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, sessionIndex: 1), responseCode,
            "The refusal names the companion slot, so the wire code carries its session-index modifier.");
        Assert.AreNotEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "TPM_RC_ATTRIBUTES would mean the encrypt attribute itself was refused on a parameter the command can protect.");
    }

    /// <summary>
    /// A companion slot claiming <c>decrypt</c> over a session that negotiated <c>TPM_ALG_NULL</c> is refused
    /// with <c>TPM_RC_SYMMETRIC</c>, not <c>TPM_RC_ATTRIBUTES</c>: "If the symmetric algorithm is TPM_ALG_NULL
    /// and encryption or decryption is specified, the TPM returns TPM_RC_SYMMETRIC" (TPM 2.0 Library Part 1,
    /// clause 18.1). The two codes are what separate a command that cannot encrypt the parameter at all from a
    /// session that negotiated no cipher to encrypt it with, so this test is the one that proves the command's
    /// own encryption gate is OPEN — with it closed, the attribute alone would answer first.
    /// </summary>
    [TestMethod]
    public async Task QuoteCompanionSessionClaimingDecryptWithNoNegotiatedSymmetricIsRefusedWithSymmetric()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await QuoteWithPlantedCompanionAsync(
            trackingPool.Pool, TpmtSymDef.Null, TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SYMMETRIC, baseError,
            "A decrypt claim over a session that negotiated TPM_ALG_NULL is TPM_RC_SYMMETRIC (Part 1, clause 18.1).");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, sessionIndex: 1), responseCode,
            "The refusal names the claiming slot, so the wire code carries its session-index modifier.");
    }

    /// <summary>
    /// A companion slot naming <c>TPM_RS_PW</c> and claiming <c>decrypt</c> is refused with
    /// <c>TPM_RC_ATTRIBUTES</c>, never <c>TPM_RC_SYMMETRIC</c>: a password authorization carries no session key
    /// and so can key no keystream, which is why <c>decrypt</c> is "required to be CLEAR in a password session"
    /// (TPM 2.0 Library Part 1, clause 15.6.4, Table 15). The error is about the attribute the slot may not carry,
    /// not about the cipher it never negotiated, and the difference is the whole point: a password slot has no
    /// negotiated symmetric either, so the two rules answer the same input with different codes.
    /// </summary>
    [TestMethod]
    public async Task QuotePasswordCompanionSlotClaimingDecryptIsRefusedWithAttributesNotSymmetric()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError) = await QuoteWithPlantedCompanionAsync(
            trackingPool.Pool, TpmtSymDef.Null, TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT,
            companionHandleOverride: (uint)TpmRh.TPM_RH_PW).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, baseError,
            "A password slot may carry none of decrypt, encrypt, or audit, so the attribute itself is the error.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "The refusal names the password companion slot, so the wire code carries its session-index modifier.");
        Assert.AreNotEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_SYMMETRIC, sessionIndex: 1), responseCode,
            "TPM_RC_SYMMETRIC would report a missing cipher negotiation for a slot that can never negotiate one.");
    }

    /// <summary>
    /// A companion slot whose handle REPEATS a real authorization slot's is refused with <c>TPM_RC_HANDLE</c>
    /// encoded to the companion's own index: "For a given command, the handle associated with a specific HMAC or
    /// policy session can occur only once in the Authorization Area" (TPM 2.0 Library Part 1, clause 15.6.3).
    /// Part 1 names no response code for the violation; the reference does, its <c>RetrieveSessionData</c>
    /// comparing each slot against every earlier one and answering <c>TPM_RCS_HANDLE + errorIndex</c>, so the
    /// repetition is reported as a handle error blamed on the second occurrence. Driven on
    /// <c>TPM2_Certify()</c>, whose two authorizing slots put the companion at index 2, and with the sign slot
    /// claiming <c>decrypt</c> so that the area is otherwise well formed and would be refused at a DIFFERENT
    /// index — index 1 — were the repetition not caught.
    /// </summary>
    [TestMethod]
    public async Task CertifyCompanionSessionRepeatingAnAuthorizingSlotHandleIsRefusedWithHandleAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using StartAuthSessionResponse started = await StartHmacSessionAsync(
            plainDevice, registry, pool, TpmtSymDef.Xor(HmacSessionAlg)).ConfigureAwait(false);
        uint signSessionHandle = started.SessionHandle.Value;

        try
        {
            //The sign slot claims decrypt on the wire and the companion repeats that slot's own handle. Both
            //rewrites happen after the executor framed the command, so the sign slot's HMAC no longer matches —
            //which is immaterial, since Part 3, clause 5.5's area checks precede clause 5.6's authorization.
            byte[] Rewrite(byte[] command)
            {
                SetSessionAttributeBit(command, handleCount: 2, sessionIndex: 1, TpmaSession.DECRYPT);

                return WithAppendedSession(command, handleCount: 2, signSessionHandle, TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT);
            }

            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Certify, Rewrite);

            using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmSession signSession = new(new TpmHandle(signSessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool)
            {
                SessionAttributes = TpmaSession.CONTINUE_SESSION
            };
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
            ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                rewritingDevice, certifyInput, [objectAuth, signSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE, result.BaseError,
                "A repeated real session handle in one authorization area is refused structurally as a handle error (Part 1, clause 15.6.3; the reference's RetrieveSessionData answers TPM_RCS_HANDLE).");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 2), result.ResponseCode,
                "The repetition is blamed on the SECOND occurrence — the companion at index 2 — not on the slot that named the handle first.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                plainDevice, FlushContextInput.ForHandle(signSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An authorization area carrying a FOURTH session is refused with <c>TPM_RC_AUTHSIZE</c> naming no slot: an
    /// area holds "at least one but no more than three" authorization/session blocks (TPM 2.0 Library Part 1,
    /// clause 16.6.1), so the fourth block's octets are surplus against the declared <c>authorizationSize</c> the
    /// parser brackets the area with. Driven on <c>TPM2_Certify()</c>, whose two authorizing slots plus one
    /// companion already fill the three the clause allows.
    /// </summary>
    [TestMethod]
    public async Task CertifyAreaCarryingAFourthSessionIsRefusedWithAuthSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        using StartAuthSessionResponse companion = await StartHmacSessionAsync(plainDevice, registry, pool, TpmtSymDef.Xor(HmacSessionAlg)).ConfigureAwait(false);
        uint companionHandle = companion.SessionHandle.Value;

        try
        {
            byte[] Rewrite(byte[] command)
            {
                byte[] withThird = WithAppendedSession(command, handleCount: 2, companionHandle, TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT);

                return WithAppendedSession(withThird, handleCount: 2, companionHandle, TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT);
            }

            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Certify, Rewrite);

            using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                rewritingDevice, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_AUTHSIZE, result.ResponseCode,
                "A fourth session's octets are surplus against the declared authorizationSize, so TPM_RC_AUTHSIZE names no slot.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                plainDevice, FlushContextInput.ForHandle(companionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A companion refused by the session-area check that a session authorizing nothing must claim at least one
    /// of decrypt, encrypt, or audit (TPM 2.0 Library Part 1, clause 15.6.4) returns the two carriers its slot
    /// made the parser rent — the companion's own <c>nonceCaller</c> (<c>TPM2B_NONCE</c>) and <c>hmac</c>
    /// (<c>TPM2B_AUTH</c>) — to the pool: the refusing arm reaches them through the request record's own
    /// <c>IDisposable.Dispose</c>, which is the only owner they ever had, because a session-area refusal
    /// transfers nothing into an action.
    /// </summary>
    [TestMethod]
    public async Task QuoteCompanionSessionRefusalReturnsTheParseRentedCompanionCarriersToPool()
    {
        using var trackingPool = new MeteredHousePool();
        long companionNonceRentsBefore = trackingPool.RentedCountOfSize(CompanionNonce.Length);
        long baseline = trackingPool.OutstandingCount;

        (TpmRcConstants responseCode, _) = await QuoteWithPlantedCompanionAsync(
            trackingPool.Pool, TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION).ConfigureAwait(false);

        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "The balance below proves nothing unless the command really was refused at the companion slot.");
        Assert.IsGreaterThan(
            companionNonceRentsBefore, trackingPool.RentedCountOfSize(CompanionNonce.Length),
            "The parser must have rented the companion's nonceCaller carrier before the transition refused, or the balance below proves nothing.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A session-area refusal must return the companion slot's parse-rented nonce and hmac carriers to the pool.");
    }


    /// <summary>
    /// A companion block naming handle <c>0x00000000</c> is refused with <c>TPM_RC_HANDLE</c> encoded to its own
    /// index, and every carrier its slot made the parser rent returns to the pool.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Zero is not a session handle: <c>TPMI_SH_AUTH_SESSION</c> admits an HMAC session handle, a policy session
    /// handle, or <c>TPM_RS_PW</c> and nothing else (TPM 2.0 Library Part 2, clause 9.8, Table 54), and Part 3,
    /// clause 5.5, step 4.1 answers exactly that case: "If the session handle is not a handle for an HMAC
    /// session, a handle for a policy session, or, TPM_RS_PW then the TPM shall return TPM_RC_HANDLE." It is a
    /// structural fact about the octets, so it is settled before the handle is looked up and before step 4.2's
    /// <c>TPM_RC_REFERENCE_S*</c> could apply.
    /// </para>
    /// <para>
    /// What makes zero worth a test of its own is that it is also the value a slot's handle field carries when
    /// the area holds NO such slot. Whether a block arrived is a structural fact of the wire — the octets left
    /// inside <c>authorizationSize</c> after the required slots — and never an inference from the handle value,
    /// so a block naming zero is a block the caller really sent: it is resolved, validated, and answered like any
    /// other, rather than silently vanishing between the parser and the transition.
    /// </para>
    /// </remarks>
    [TestMethod]
    public async Task QuoteCompanionSlotNamingHandleZeroIsRefusedWithHandleAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        long companionNonceRentsBefore = trackingPool.RentedCountOfSize(CompanionNonce.Length);
        long baseline = trackingPool.OutstandingCount;

        (TpmRcConstants responseCode, TpmRcConstants baseError) = await QuoteWithPlantedCompanionAsync(
            trackingPool.Pool, TpmtSymDef.Xor(HmacSessionAlg), TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT,
            companionHandleOverride: 0u).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HANDLE, baseError,
            "A slot naming something that is not a session handle at all is a handle error (Part 3, clause 5.5, step 4.1).");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1), responseCode,
            "The refusal names the offending slot — the companion at index 1 — session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        Assert.AreNotEqual(
            (TpmRcConstants)((uint)TpmRcConstants.TPM_RC_REFERENCE_S0 + 1u), responseCode,
            "TPM_RC_REFERENCE_S1 would report a well-typed handle naming no loaded session, which is step 4.2's case, not this one.");

        Assert.IsGreaterThan(
            companionNonceRentsBefore, trackingPool.RentedCountOfSize(CompanionNonce.Length),
            "The parser must have rented the companion's nonceCaller carrier before the transition refused, or the balance below proves nothing.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the companion slot's parse-rented nonce and hmac carriers to the pool.");
    }

    /// <summary>
    /// An area carrying TWO companion blocks whose FIRST names handle <c>0x00000000</c> and whose second names a
    /// live HMAC session is refused with <c>TPM_RC_HANDLE</c> at index 1 — the offending block — and leaves no
    /// carrier outstanding.
    /// </summary>
    /// <remarks>
    /// This is the shape that separates structural slot presence from inferred presence. A transition that read
    /// presence from the handle value would see the zero block as absent, slide the live session down into index
    /// 1, and then hold a slot array whose entries no longer line up with the wire: the attribute octets and the
    /// resolved sessions would be indexed apart, and the nonce fold would reach for a session at a position that
    /// holds none. Reading presence from the octet count instead keeps every array in wire order, so the zero
    /// block is answered as itself and the live session behind it is never mistaken for it.
    /// </remarks>
    [TestMethod]
    public async Task QuoteWithAHandleZeroBlockAheadOfARealCompanionIsRefusedWithHandleAtTheZeroBlocksIndex()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using StartAuthSessionResponse companion = await StartHmacSessionAsync(
            plainDevice, registry, pool, TpmtSymDef.Xor(HmacSessionAlg)).ConfigureAwait(false);
        uint companionHandle = companion.SessionHandle.Value;

        long baseline = trackingPool.OutstandingCount;

        try
        {
            {
                //Block 1 names no handle at all; block 2 names the live session. Appending in this order puts the
                //zero block at index 1 and the real one at index 2.
                byte[] Rewrite(byte[] command)
                {
                    byte[] withZeroBlock = WithAppendedSession(command, handleCount: 1, sessionHandle: 0u, TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT);

                    return WithAppendedSession(withZeroBlock, handleCount: 1, companionHandle, TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT);
                }

                using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Quote, Rewrite);

                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
                using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

                TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                    rewritingDevice, quoteInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                if(result.IsSuccess)
                {
                    result.Value.Dispose();
                }

                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_HANDLE, result.BaseError,
                    "The zero block is not a session handle, so the area is refused with a handle error rather than being carried into the attestation.");
                Assert.AreEqual(
                    SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1), result.ResponseCode,
                    "The refusal names the block that is wrong — index 1 — not the live session behind it at index 2.");
            }

            //The balance is read while the companion session is still LOADED: its retained nonceTPM carrier was
            //rented before the baseline, and the cleanup flush below returns it, so measuring across that flush
            //would read one below the baseline for a reason that has nothing to do with the refusal under test.
            //The inner block above ends first so the host-side carriers it rented (the password session, the PCR
            //selection, the input) are back in the pool before the count is read.
            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "Both planted blocks' parse-rented nonce and hmac carriers must reach the pool again across the refusal.");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                plainDevice, FlushContextInput.ForHandle(companionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// An AUTHORIZING slot naming a persistent-object handle is refused with <c>TPM_RC_HANDLE</c> encoded to that
    /// slot: the type check of TPM 2.0 Library Part 3, clause 5.5, step 4.1 governs every slot of the area, not
    /// only the companion positions, and a persistent object is a well-formed handle of entirely the wrong kind.
    /// </summary>
    /// <remarks>
    /// The distinction this pins is between step 4.1 and step 4.2. A handle whose type <c>TPMI_SH_AUTH_SESSION</c>
    /// does not admit at all is <c>TPM_RC_HANDLE</c>; a well-typed session handle naming nothing loaded is the
    /// warning <c>TPM_RC_REFERENCE_S0 + N</c>. Answering the first case with the second would tell a caller that a
    /// session had been flushed when the caller had never named a session.
    /// </remarks>
    [TestMethod]
    public async Task QuoteSignSlotNamingAPersistentObjectHandleIsRefusedWithHandleAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //The first persistent-object handle (TPM_HT_PERSISTENT, Part 2, clause 7.2, Table 33): a well-formed
        //handle of a kind no authorization slot may name.
        const uint PersistentObjectHandle = 0x81000000u;
        byte[] Rewrite(byte[] command) => WithSessionHandle(command, handleCount: 1, sessionIndex: 0, PersistentObjectHandle);

        //The command's own carriers live inside this block so every one of them is released before the balance
        //below is read; only the SIMULATOR's outstanding rentals are what the assertion is about.
        {
            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Quote, Rewrite);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                rewritingDevice, quoteInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE, result.BaseError,
                "A persistent-object handle is not one TPMI_SH_AUTH_SESSION admits, so the slot is a handle error.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 0), result.ResponseCode,
                "The refusal names the authorizing slot itself, session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
            Assert.AreNotEqual(
                TpmRcConstants.TPM_RC_REFERENCE_S0, result.ResponseCode,
                "TPM_RC_REFERENCE_S0 would claim a session had been flushed when no session was ever named.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return every parse-rented carrier of the refused area to the pool.");
    }

    /// <summary>
    /// A <c>TPM2_Certify()</c> companion block naming handle <c>0x00000000</c> is refused with
    /// <c>TPM_RC_HANDLE</c> at index 2 — the companion position of a command with two authorizing slots — so the
    /// rule is pinned at both companion positions the attest family admits.
    /// </summary>
    [TestMethod]
    public async Task CertifyCompanionSlotNamingHandleZeroIsRefusedWithHandleAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        byte[] Rewrite(byte[] command) => WithAppendedSession(command, handleCount: 2, sessionHandle: 0u, TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT);

        //The command's own carriers live inside this block so every one of them is released before the balance
        //below is read; only the SIMULATOR's outstanding rentals are what the assertion is about.
        {
            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Certify, Rewrite);

            using TpmPasswordSession objectAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);

            TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                rewritingDevice, certifyInput, [objectAuth, signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE, result.BaseError,
                "A slot naming something that is not a session handle at all is a handle error (Part 3, clause 5.5, step 4.1).");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 2), result.ResponseCode,
                "The refusal names the companion at index 2, the position Table 9 leaves free on a two-authorization command.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return the companion slot's parse-rented nonce and hmac carriers to the pool.");
    }

    /// <summary>
    /// A <c>TPM2_NV_Certify()</c> sign slot naming a persistent-object handle is refused with
    /// <c>TPM_RC_HANDLE</c> encoded to index 0: the handle-type check of TPM 2.0 Library Part 3, clause 5.5,
    /// step 4.1 governs the authorizing slots of a two-authorization command exactly as it governs a companion
    /// position.
    /// </summary>
    /// <remarks>
    /// This command is the attest family's only two-authorization member (Part 3, clause 31.16.2, Table 271 gives
    /// <c>@signHandle</c> Auth Index 1 and <c>@authHandle</c> Auth Index 2, both USER role), so it is where the
    /// rule has two authorizing slots to be pinned at rather than one. Answering a wrong-TYPE handle with
    /// <c>TPM_RC_REFERENCE_S0</c> would tell a caller a session had been flushed when no session was ever named.
    /// </remarks>
    [TestMethod]
    public async Task NvCertifySignSlotNamingAPersistentObjectHandleIsRefusedWithHandleAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        await DefineAndWriteNvIndexAsync(plainDevice, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //The first persistent-object handle (TPM_HT_PERSISTENT, Part 2, clause 7.2, Table 33): a well-formed
        //handle of a kind no authorization slot may name.
        const uint PersistentObjectHandle = 0x81000000u;
        byte[] Rewrite(byte[] command) => WithSessionHandle(command, handleCount: 3, sessionIndex: 0, PersistentObjectHandle);

        //The command's own carriers live inside this block so every one of them is released before the balance
        //below is read; only the SIMULATOR's outstanding rentals are what the assertion is about.
        {
            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_NV_Certify, Rewrite);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256,
                (ushort)WrittenData.Length, offset: 0, pool);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                rewritingDevice, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE, result.BaseError,
                "A persistent-object handle is not one TPMI_SH_AUTH_SESSION admits, so the slot is a handle error.");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 0), result.ResponseCode,
                "The refusal names the sign slot itself, session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
            Assert.AreNotEqual(
                TpmRcConstants.TPM_RC_REFERENCE_S0, result.ResponseCode,
                "TPM_RC_REFERENCE_S0 would claim a session had been flushed when no session was ever named.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return every parse-rented carrier of the refused area to the pool.");
    }

    /// <summary>
    /// A <c>TPM2_NV_Certify()</c> authorizing slot naming handle <c>0x00000000</c> is refused with
    /// <c>TPM_RC_HANDLE</c> encoded to index 1 — the second of the command's two authorization positions — so
    /// the rule is pinned at an authorizing slot that is neither the first nor a companion.
    /// </summary>
    /// <remarks>
    /// Zero is not a value <c>TPMI_SH_AUTH_SESSION</c> admits at all (Part 2, clause 9.8, Table 54), so the slot
    /// is answered on its handle's type before any session table is consulted and before either credential is
    /// compared (Part 3, clause 5.5 precedes clause 5.6). What the index pins is that the blame stays on the slot
    /// the caller got wrong rather than sliding to the sign slot ahead of it.
    /// </remarks>
    [TestMethod]
    public async Task NvCertifyAuthorizingSlotNamingHandleZeroIsRefusedWithHandleAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        await DefineAndWriteNvIndexAsync(plainDevice, registry, pool).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        byte[] Rewrite(byte[] command) => WithSessionHandle(command, handleCount: 3, sessionIndex: 1, sessionHandle: 0u);

        //The command's own carriers live inside this block so every one of them is released before the balance
        //below is read; only the SIMULATOR's outstanding rentals are what the assertion is about.
        {
            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_NV_Certify, Rewrite);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuth, pool);
            using NvCertifyInput nvCertifyInput = NvCertifyInput.ForEcdsa(
                ak.ObjectHandle, NvIndexHandle, NvIndexHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256,
                (ushort)WrittenData.Length, offset: 0, pool);

            TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                rewritingDevice, nvCertifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HANDLE, result.BaseError,
                "A slot naming something that is not a session handle at all is a handle error (Part 3, clause 5.5, step 4.1).");
            Assert.AreEqual(
                SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1), result.ResponseCode,
                "The refusal names the authorizing slot at index 1, not the sign slot ahead of it.");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return every parse-rented carrier of the refused area to the pool.");
    }

    /// <summary>
    /// Defines the NV Index the <c>TPM2_NV_Certify()</c> cases attest over — owner-authorized with an empty owner
    /// authValue, carrying <see cref="IndexAuth"/> as its own authorization value and sized for
    /// <see cref="WrittenData"/> — then writes those octets to it in full, setting <c>TPMA_NV_WRITTEN</c> so the
    /// Index has content to certify.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DefineAndWriteNvIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(IndexAuth, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using var publicInfo = new TpmsNvPublic(NvIndexHandle, IndexNameAlg, NoDaIndexAttributes, policyDigest, dataSize: (ushort)WrittenData.Length);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");

        using TpmPasswordSession writeAuth = TpmPasswordSession.Create(IndexAuth, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(WrittenData, pool);
        var writeInput = new NvWriteInput(NvIndexHandle, NvIndexHandle, writeInputBuffer, Offset: 0);

        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            tpm, writeInput, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// A lone <c>TPM_RS_PW</c> sign slot claiming <c>audit</c> is refused with <c>TPM_RC_ATTRIBUTES</c> encoded
    /// to its own index: audit "has no meaning for a password authorization and is required to be CLEAR" (TPM 2.0
    /// Library Part 1, clause 15.6.4, Table 15), because a password authorization keeps no session context in
    /// which an audit digest could live.
    /// </summary>
    /// <remarks>
    /// The rule is settled on the slot's wire shape alone, so it is answered while the slot is being read and
    /// before the command's arm is even chosen — the position the reference gives it in
    /// <c>RetrieveSessionData</c>, which tests each slot's attributes as it unmarshals it. An area refused there
    /// rents nothing, so the pool balance is what proves the refusal preceded every carrier the parse would
    /// otherwise have created.
    /// </remarks>
    [TestMethod]
    public async Task QuotePasswordSlotClaimingAuditIsRefusedWithAttributesAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError, long baseline, long outstanding) =
            await QuoteOverARewrittenPasswordSlotAsync(trackingPool, command =>
            {
                SetSessionAttributeBit(command, handleCount: 1, sessionIndex: 0, TpmaSession.AUDIT);

                return command;
            }).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, baseError,
            "A password slot may carry no attribute but continueSession, so audit there is an attribute error.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), responseCode,
            "The refusal names the offending slot, session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        Assert.AreEqual(
            baseline, outstanding,
            "A slot refused while it is being read leaves the parse with nothing rented, so the pool balance does not move.");
    }

    /// <summary>
    /// A lone <c>TPM_RS_PW</c> sign slot carrying a non-empty <c>nonceCaller</c> is refused with
    /// <c>TPM_RC_NONCE</c> encoded to its own index: a password authorization carries no nonce at all, which the
    /// reference states outright while unmarshaling the session area — "the nonce size must be zero", answered
    /// <c>TPM_RCS_NONCE + errorIndex</c> — and whose response side is TPM 2.0 Library Part 1, clause 15.6.2.2,
    /// Table 14's "will be zero for a password authorization".
    /// </summary>
    /// <remarks>
    /// This is the same rule the mixed-area cases pin at the attest family's other commands, here on the LONE
    /// password slot that would otherwise take the plain password arm: the two refusals a password slot owes are
    /// one rule applied at whatever index the slot occupies, not a property of the arm the area would have
    /// reached.
    /// </remarks>
    [TestMethod]
    public async Task QuotePasswordSlotCarryingANonceIsRefusedWithNonceAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError, long baseline, long outstanding) =
            await QuoteOverARewrittenPasswordSlotAsync(
                trackingPool, command => WithPasswordSlotNonce(command, handleCount: 1, PasswordSlotNonce)).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NONCE, baseError,
            "A password slot carries no nonce at all, so a non-empty nonceCaller there is a nonce error.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_NONCE, sessionIndex: 0), responseCode,
            "The refusal names the offending slot, session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        Assert.AreEqual(
            baseline, outstanding,
            "The planted nonce is refused while its own slot is being read, so no carrier is ever rented for it.");
    }

    /// <summary>
    /// A lone <c>TPM_RS_PW</c> sign slot whose attributes octet sets a bit in <c>TPMA_SESSION</c>'s reserved 4:3
    /// field is refused with <c>TPM_RC_ATTRIBUTES</c> encoded to its own index: an octet carrying a bit the table
    /// defines no meaning for is malformed before any attribute in it can be read (TPM 2.0 Library Part 2, clause
    /// 8.4, Table 38's reserved field "shall be CLEAR").
    /// </summary>
    /// <remarks>
    /// A password slot reaches this rule at the wire reader rather than at the session-area gate, so pinning it
    /// here is what keeps the two statements of the reserved field — the reader's and the session-area gate's —
    /// from drifting apart: both derive the reserved mask as the complement of the bits Table 38 names, so
    /// neither can admit a bit the other refuses.
    /// </remarks>
    [TestMethod]
    public async Task QuotePasswordSlotSettingAReservedAttributeBitIsRefusedWithAttributesAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError, long baseline, long outstanding) =
            await QuoteOverARewrittenPasswordSlotAsync(trackingPool, command =>
            {
                //Bit 3 of TPMA_SESSION, the low bit of the reserved 4:3 field, which the enumeration names no
                //member for precisely because the table defines none.
                SetSessionAttributeBit(command, handleCount: 1, sessionIndex: 0, (TpmaSession)0x08);

                return command;
            }).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, baseError,
            "A reserved TPMA_SESSION bit is an attribute error, not a value or a size one.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 0), responseCode,
            "The refusal names the offending slot, session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        Assert.AreEqual(
            baseline, outstanding,
            "A slot refused while it is being read leaves the parse with nothing rented, so the pool balance does not move.");
    }

    /// <summary>
    /// A <c>TPM2_Certify()</c> area whose slot at index 1 is a <c>TPM_RS_PW</c> authorization claiming
    /// <c>auditReset</c> is refused with <c>TPM_RC_ATTRIBUTES</c> encoded to index 1, with a REAL HMAC session
    /// occupying index 0: the password slot's rules hold at whatever index the slot occupies, and the blame stays
    /// on the slot that carries the attribute rather than on the session ahead of it.
    /// </summary>
    /// <remarks>
    /// <c>auditReset</c> is one of the three attributes Table 9 does not name for a password slot outright — it
    /// is a claim about an audit digest, "only allowed if the audit attribute is SET" (TPM 2.0 Library Part 2,
    /// clause 8.4, Table 38) — and a password authorization keeps no such digest, so the reference refuses all
    /// five of decrypt, encrypt, audit, auditExclusive, and auditReset together at the offending slot's own error
    /// index. Driving it at index 1 is what proves the rule is parameterised by the slot rather than pinned to
    /// index 0. This claim is one the audit-family gate would also catch, so
    /// <see cref="CertifyPasswordSlotAtIndexOneClaimingEncryptIsRefusedWithAttributesNotSymmetric"/> stands
    /// beside it as the case only the password rule can answer.
    /// </remarks>
    [TestMethod]
    public async Task CertifyPasswordSlotAtIndexOneClaimingAuditResetIsRefusedWithAttributesThere()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError, long baseline, long outstanding) =
            await CertifyOverAMixedAreaClaimingAsync(trackingPool, TpmaSession.AUDIT_RESET).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, baseError,
            "auditReset is a claim about an audit digest a password authorization never keeps, so it is an attribute error.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "The refusal names the password slot at index 1, not the real session at index 0.");
        Assert.AreEqual(
            baseline, outstanding,
            "A slot refused while it is being read leaves the parse with nothing rented, so the pool balance does not move.");
    }

    /// <summary>
    /// A <c>TPM2_Certify()</c> area whose slot at index 1 is a <c>TPM_RS_PW</c> authorization claiming
    /// <c>encrypt</c> is refused with <c>TPM_RC_ATTRIBUTES</c> encoded to index 1, never with
    /// <c>TPM_RC_SYMMETRIC</c>.
    /// </summary>
    /// <remarks>
    /// This is the discriminating case at a non-zero index. <c>encrypt</c> is "required to be CLEAR in a password
    /// session" because "there is no session key for the encrypt operation" (TPM 2.0 Library Part 1, clause
    /// 15.6.4, Table 15), and this command's first response parameter IS encryptable, so without that rule the
    /// per-attribute gate would reach the slot's symmetric definition — which a password slot never negotiated —
    /// and answer <c>TPM_RC_SYMMETRIC</c> about a cipher instead of <c>TPM_RC_ATTRIBUTES</c> about the attribute
    /// the slot may not carry. The two codes on the same input are what make this case, unlike the auditReset one
    /// beside it, provable only by the password rule.
    /// </remarks>
    [TestMethod]
    public async Task CertifyPasswordSlotAtIndexOneClaimingEncryptIsRefusedWithAttributesNotSymmetric()
    {
        using var trackingPool = new MeteredHousePool();
        (TpmRcConstants responseCode, TpmRcConstants baseError, long baseline, long outstanding) =
            await CertifyOverAMixedAreaClaimingAsync(trackingPool, TpmaSession.ENCRYPT).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, baseError,
            "The error is about the attribute a password slot may not carry, not about the cipher it never negotiated.");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_SYMMETRIC, baseError,
            "TPM_RC_SYMMETRIC would blame algorithm negotiation for a slot that can never negotiate one.");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, sessionIndex: 1), responseCode,
            "The refusal names the password slot at index 1, not the real session at index 0.");
        Assert.AreEqual(
            baseline, outstanding,
            "A slot refused while it is being read leaves the parse with nothing rented, so the pool balance does not move.");
    }

    /// <summary>
    /// Certifies over a MIXED authorization area — a real HMAC session at index 0, a <c>TPM_RS_PW</c>
    /// authorization at index 1 — with the given attribute bits planted in the password slot's octet on the
    /// wire, and returns what the simulator answered together with the pool balance before and after.
    /// </summary>
    /// <param name="trackingPool">The metered pool every carrier is rented from.</param>
    /// <param name="passwordSlotClaim">The attribute bits the password slot at index 1 is made to claim.</param>
    /// <returns>The response code, its base (session-modifier-free) form, and the outstanding-rental counts taken before the command and after every carrier it created was released.</returns>
    private async Task<(TpmRcConstants ResponseCode, TpmRcConstants BaseError, long Baseline, long Outstanding)> CertifyOverAMixedAreaClaimingAsync(
        MeteredHousePool trackingPool, TpmaSession passwordSlotClaim)
    {
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse subject = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_ENDORSEMENT).ConfigureAwait(false);

        StartAuthSessionResponse objectStarted = await StartHmacSessionAsync(
            plainDevice, registry, pool, TpmtSymDef.Xor(HmacSessionAlg)).ConfigureAwait(false);
        uint objectSessionHandle = objectStarted.SessionHandle.Value;

        try
        {
            //The client session adopts the started session's nonceTPM carrier (Part 1, clause 15.6.1) and holds
            //it for its own lifetime, so it is created BEFORE the baseline is taken: a balance read across that
            //adoption would move by the adopted rental rather than by anything the command did.
            using TpmSession objectSession = new(new TpmHandle(objectSessionHandle), objectStarted.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);

            long baseline = trackingPool.OutstandingCount;
            TpmRcConstants responseCode;
            TpmRcConstants baseError;

            byte[] Rewrite(byte[] command)
            {
                SetSessionAttributeBit(command, handleCount: 2, sessionIndex: 1, passwordSlotClaim);

                return command;
            }

            //The command's own carriers live inside this block so every one of them is released before the
            //balance below is read; only the SIMULATOR's outstanding rentals are what the assertion is about.
            {
                using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Certify, Rewrite);

                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using CertifyInput certifyInput = CertifyInput.ForEcdsa(
                    subject.ObjectHandle, ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pool);
                ReadOnlyMemory<byte>[] handleNames = [subject.Name.Span.ToArray(), ak.Name.Span.ToArray()];

                TpmResult<CertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<CertifyResponse>(
                    rewritingDevice, certifyInput, [objectSession, signAuth], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                if(result.IsSuccess)
                {
                    result.Value.Dispose();
                }

                responseCode = result.ResponseCode;
                baseError = result.BaseError;
            }

            return (responseCode, baseError, baseline, trackingPool.OutstandingCount);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                plainDevice, FlushContextInput.ForHandle(objectSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Quotes over a lone <c>TPM_RS_PW</c> sign slot whose wire block is rewritten on its way in, and returns
    /// what the simulator answered together with the pool balance before and after.
    /// </summary>
    /// <param name="trackingPool">The metered pool every carrier is rented from.</param>
    /// <param name="rewrite">The rewrite applied to the framed <c>TPM2_Quote()</c> command.</param>
    /// <returns>The response code, its base (session-modifier-free) form, and the outstanding-rental counts taken before the command and after every carrier it created was released.</returns>
    private async Task<(TpmRcConstants ResponseCode, TpmRcConstants BaseError, long Baseline, long Outstanding)> QuoteOverARewrittenPasswordSlotAsync(
        MeteredHousePool trackingPool, Func<byte[], byte[]> rewrite)
    {
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;
        TpmRcConstants responseCode;
        TpmRcConstants baseError;

        //The command's own carriers live inside this block so every one of them is released before the balance
        //below is read; only the SIMULATOR's outstanding rentals are what the caller's assertion is about.
        {
            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Quote, rewrite);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                rewritingDevice, quoteInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            responseCode = result.ResponseCode;
            baseError = result.BaseError;
        }

        return (responseCode, baseError, baseline, trackingPool.OutstandingCount);
    }

    /// <summary>
    /// Rewrites a framed command so its first <c>TPM_RS_PW</c> authorization slot carries
    /// <paramref name="nonce"/> as its <c>nonceCaller</c>, growing the authorization area's size field and the
    /// header's <c>commandSize</c> to match. The handle and authorization areas are walked with a
    /// <see cref="TpmReader"/>, so the splice holds regardless of the surrounding slots' nonce and HMAC widths.
    /// </summary>
    /// <param name="command">The framed command, left untouched.</param>
    /// <param name="handleCount">The command's handle count, which fixes where its authorization area starts.</param>
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

        Assert.AreNotEqual(-1, nonceFieldOffset, "The command must carry a TPM_RS_PW slot for the rewrite to have anything to plant a nonce in.");

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
    /// Rewrites one existing authorization slot's session-handle field in place, leaving every other octet of the
    /// framed command untouched.
    /// </summary>
    /// <param name="command">The framed command to rewrite.</param>
    /// <param name="handleCount">The command's handle count, which fixes where its authorization area starts.</param>
    /// <param name="sessionIndex">The zero-based slot whose handle field is rewritten.</param>
    /// <param name="sessionHandle">The handle to write.</param>
    /// <returns>A new framed command carrying the rewritten handle.</returns>
    private static byte[] WithSessionHandle(ReadOnlySpan<byte> command, int handleCount, int sessionIndex, uint sessionHandle)
    {
        byte[] rewritten = command.ToArray();
        int offset = CommandHeaderSize + (handleCount * sizeof(uint)) + sizeof(uint);
        for(int slot = 0; slot < sessionIndex; slot++)
        {
            offset += sizeof(uint);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(rewritten.AsSpan(offset, sizeof(ushort)));
            offset += sizeof(byte);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(rewritten.AsSpan(offset, sizeof(ushort)));
        }

        BinaryPrimitives.WriteUInt32BigEndian(rewritten.AsSpan(offset), sessionHandle);

        return rewritten;
    }

    /// <summary>
    /// Quotes over a <c>TPM_RS_PW</c> sign slot with a companion planted behind it on the wire, and returns what
    /// the simulator answered.
    /// </summary>
    /// <remarks>
    /// A LONE password slot would parse to the plain password form, so the planted companion is also what routes
    /// the command to the session-authorized arm — the shape Part 1, clause 15.6.1 describes when a caller adds a
    /// session "for the single purpose of decrypting a command parameter" to an otherwise password-authorized
    /// command.
    /// </remarks>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="companionSymmetric">The symmetric definition the companion's session negotiates at <c>TPM2_StartAuthSession()</c>.</param>
    /// <param name="companionAttributes">The attributes octet the planted companion presents.</param>
    /// <param name="companionHandleOverride">The handle the planted slot names in place of the started session's, for the cases that need a slot naming something other than a live HMAC session.</param>
    /// <returns>The response code the simulator answered and its base (session-modifier-free) form.</returns>
    private async Task<(TpmRcConstants ResponseCode, TpmRcConstants BaseError)> QuoteWithPlantedCompanionAsync(
        BaseMemoryPool pool, TpmtSymDef companionSymmetric, TpmaSession companionAttributes, uint? companionHandleOverride = null)
    {
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse ak = await CreateSigningPrimaryAsync(plainDevice, registry, pool, TpmRh.TPM_RH_OWNER).ConfigureAwait(false);

        using StartAuthSessionResponse companion = await StartHmacSessionAsync(plainDevice, registry, pool, companionSymmetric).ConfigureAwait(false);
        uint companionHandle = companion.SessionHandle.Value;

        try
        {
            uint plantedHandle = companionHandleOverride ?? companionHandle;
            byte[] Rewrite(byte[] command) => WithAppendedSession(command, handleCount: 1, plantedHandle, companionAttributes);

            using TpmDevice rewritingDevice = CreateRewritingDevice(simulator, TpmCcConstants.TPM_CC_Quote, Rewrite);

            using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
            using TpmlPcrSelection pcrSelection = TpmlPcrSelection.Create(PcrBank, PcrIndices, pool);
            using QuoteInput quoteInput = QuoteInput.ForEcdsa(ak.ObjectHandle, Nonce, TpmAlgIdConstants.TPM_ALG_SHA256, pcrSelection, pool);

            TpmResult<QuoteResponse> result = await TpmCommandExecutor.ExecuteAsync<QuoteResponse>(
                rewritingDevice, quoteInput, [signAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            return (result.ResponseCode, result.BaseError);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                plainDevice, FlushContextInput.ForHandle(companionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Wraps the simulator in a device that rewrites the wire bytes of exactly one command code on their way in,
    /// leaving every other command untouched.
    /// </summary>
    /// <param name="simulator">The simulator the rewritten command is submitted to.</param>
    /// <param name="commandCode">The command whose bytes are rewritten.</param>
    /// <param name="rewrite">The rewrite to apply.</param>
    /// <returns>The rewriting device; the caller owns it.</returns>
    private static TpmDevice CreateRewritingDevice(TpmSimulator simulator, TpmCcConstants commandCode, Func<byte[], byte[]> rewrite)
    {
        return TpmDevice.Create(async (command, commandPool, cancellationToken) =>
        {
            byte[] bytes = command.ToArray();
            if(ReadCommandCode(bytes) == commandCode)
            {
                bytes = rewrite(bytes);
            }

            return await simulator.SubmitAsync(bytes, commandPool, cancellationToken).ConfigureAwait(false);
        }, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
    }

    /// <summary>Reads a framed command's commandCode field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command) =>
        (TpmCcConstants)BinaryPrimitives.ReadUInt32BigEndian(command[6..CommandHeaderSize]);

    /// <summary>
    /// Appends one <c>TPMS_AUTH_COMMAND</c> block to a framed command's authorization area, growing both the
    /// area's declared <c>authorizationSize</c> and the header's <c>commandSize</c> to match.
    /// </summary>
    /// <param name="command">The framed command to extend.</param>
    /// <param name="handleCount">The command's handle count, which fixes where its authorization area starts.</param>
    /// <param name="sessionHandle">The appended slot's session handle.</param>
    /// <param name="sessionAttributes">The appended slot's attributes octet.</param>
    /// <returns>A new framed command carrying the extra slot.</returns>
    private static byte[] WithAppendedSession(ReadOnlySpan<byte> command, int handleCount, uint sessionHandle, TpmaSession sessionAttributes)
    {
        int authorizationSizeOffset = CommandHeaderSize + (handleCount * sizeof(uint));
        uint authorizationSize = BinaryPrimitives.ReadUInt32BigEndian(command.Slice(authorizationSizeOffset, sizeof(uint)));
        int insertAt = authorizationSizeOffset + sizeof(uint) + (int)authorizationSize;

        int blockLength = sizeof(uint) + sizeof(ushort) + CompanionNonce.Length + sizeof(byte) + sizeof(ushort) + CompanionHmac.Length;
        byte[] extended = new byte[command.Length + blockLength];
        command[..insertAt].CopyTo(extended);
        command[insertAt..].CopyTo(extended.AsSpan(insertAt + blockLength));

        Span<byte> block = extended.AsSpan(insertAt, blockLength);
        BinaryPrimitives.WriteUInt32BigEndian(block, sessionHandle);
        BinaryPrimitives.WriteUInt16BigEndian(block[sizeof(uint)..], (ushort)CompanionNonce.Length);
        CompanionNonce.CopyTo(block[(sizeof(uint) + sizeof(ushort))..]);
        int afterNonce = sizeof(uint) + sizeof(ushort) + CompanionNonce.Length;
        block[afterNonce] = (byte)sessionAttributes;
        BinaryPrimitives.WriteUInt16BigEndian(block[(afterNonce + sizeof(byte))..], (ushort)CompanionHmac.Length);
        CompanionHmac.CopyTo(block[(afterNonce + sizeof(byte) + sizeof(ushort))..]);

        BinaryPrimitives.WriteUInt32BigEndian(extended.AsSpan(authorizationSizeOffset), authorizationSize + (uint)blockLength);
        BinaryPrimitives.WriteUInt32BigEndian(extended.AsSpan(sizeof(ushort)), (uint)extended.Length);

        return extended;
    }

    /// <summary>
    /// Sets one attribute bit in an existing authorization slot's attributes octet, in place.
    /// </summary>
    /// <param name="command">The framed command to rewrite.</param>
    /// <param name="handleCount">The command's handle count, which fixes where its authorization area starts.</param>
    /// <param name="sessionIndex">The zero-based slot whose attributes octet is rewritten.</param>
    /// <param name="sessionAttributes">The attribute bits to set.</param>
    private static void SetSessionAttributeBit(byte[] command, int handleCount, int sessionIndex, TpmaSession sessionAttributes)
    {
        int offset = CommandHeaderSize + (handleCount * sizeof(uint)) + sizeof(uint);
        for(int slot = 0; slot < sessionIndex; slot++)
        {
            offset += sizeof(uint);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
            offset += sizeof(byte);
            offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
        }

        offset += sizeof(uint);
        offset += sizeof(ushort) + BinaryPrimitives.ReadUInt16BigEndian(command.AsSpan(offset, sizeof(ushort)));
        command[offset] |= (byte)sessionAttributes;
    }

    /// <summary>
    /// The session-index-encoded form of a response code: <c>base + TPM_RC_S + 0x100 * (index + 1)</c> (TPM 2.0
    /// Library Part 2, clause 6.6.2).
    /// </summary>
    /// <param name="baseRc">The base response code.</param>
    /// <param name="sessionIndex">The zero-based session index the code names.</param>
    /// <returns>The encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

    /// <summary>
    /// Starts a real, unbound and unsalted HMAC session negotiating the supplied symmetric definition.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="symmetric">The symmetric definition to negotiate.</param>
    /// <returns>The StartAuthSession response carrying the session's handle and initial nonceTPM; the caller owns it.</returns>
    private async Task<StartAuthSessionResponse> StartHmacSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmtSymDef symmetric)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool, symmetric);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        return startResult.Value;
    }

    /// <summary>Creates a primary ECC P-256 signing key with an empty authValue under the given hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="hierarchy">The hierarchy under which to create the key.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
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
    /// Creates a simulator with the ECC signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator; the caller owns it.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-attest-companion",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
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

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Quote, TpmResponseCodec.Quote);
        _ = registry.Register(TpmCcConstants.TPM_CC_Certify, TpmResponseCodec.Certify);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
