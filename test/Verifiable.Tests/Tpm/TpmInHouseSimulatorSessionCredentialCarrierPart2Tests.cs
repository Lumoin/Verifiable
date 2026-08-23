using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Policy;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// The pool accounting of the credential carriers a command authorization slot's <c>nonce</c> and <c>hmac</c>
/// are read into — the two fields of <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library Part 2, clause 10.13.2, Table
/// 153) — for the command families whose slots reach a RESPONSE-SESSION ENTRY or a session-start effect rather
/// than the single-slot NV and hierarchy framing, plus the width rule the two caller-supplied
/// <c>TPM2B_NONCE</c>/<c>TPM2B_ENCRYPTED_SECRET</c> command parameters of the session-start and policy families
/// carry. Every proof drives the real wire through the production command path and reads real pool telemetry
/// (<see cref="MeteredHousePool"/>), never an internal hook.
/// </summary>
/// <remarks>
/// <para>
/// The families here are the ones whose caller nonce is TRANSFERRED into a per-session response entry
/// (<c>TPM2_Create()</c>, <c>TPM2_Unseal()</c>, <c>TPM2_GetRandom()</c> over a session, <c>TPM2_PolicySecret()</c>)
/// or consumed by a session-start effect (<c>TPM2_StartAuthSession()</c>), so their accounting has a
/// CONDITIONAL shape the single-slot families do not: a branch that builds no entry for a slot must release that
/// slot's nonce at the arm. Three such branches are proved on their own — <c>TPM2_Unseal()</c>'s policy-only
/// exit, which builds no response session at all; <c>TPM2_Create()</c>'s placeholder branch, where session 0 is
/// not an HMAC session; and its second slot, which only yields an entry while that session is still loaded.
/// </para>
/// <para>
/// Every proof puts a NON-EMPTY value in each slot it measures. An empty credential is the shared dispose-immune
/// sentinel, which rents nothing, so a balance taken over one proves nothing at all.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSessionCredentialCarrierPart2Tests
{
    /// <summary>The session and Name hash algorithm every command here uses.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The number of random octets the <c>TPM2_GetRandom()</c> proofs ask for.</summary>
    private const ushort RandomByteCount = 16;

    /// <summary>A session handle in the HMAC range that no proof ever starts, so naming it is refused at the entry transition.</summary>
    private const uint UnstartedSessionHandle = 0x0200_00FE;

    /// <summary>The octets the sealed-object proofs place in <c>TPMS_SENSITIVE_CREATE.data</c>.</summary>
    private static byte[] SealedSecret { get; } = [0x73, 0x65, 0x61, 0x6C, 0x65, 0x64, 0x21, 0x21];

    /// <summary>
    /// A caller nonce of the session's own digest width whose every octet is non-zero, so the carrier a slot's
    /// nonce is read into is a real rental rather than the shared empty sentinel.
    /// </summary>
    private static byte[] PolicySlotNonce { get; } = FilledNonZero(32);

    /// <summary>
    /// A caller-supplied <c>nonceTPM</c> one octet past <c>sizeof(TPMU_HA)</c> — the smallest value no
    /// <c>TPM2B_NONCE</c> can carry (TPM 2.0 Library Part 2, clause 10.4.4, Table 94 over clause 10.4.2, Table 92).
    /// </summary>
    private static byte[] PastBoundNonce { get; } = FilledNonZero(Tpm2bNonce.MaxSize + 1);

    /// <summary>A caller-supplied <c>nonceTPM</c> of exactly the bound, which the same wire read admits.</summary>
    private static byte[] AdmissibleWidthNonce { get; } = FilledNonZero(Tpm2bNonce.MaxSize);

    /// <summary>
    /// An <c>encryptedSalt</c> one octet past <c>sizeof(TPMU_ENCRYPTED_SECRET)</c> — the smallest value no
    /// <c>TPM2B_ENCRYPTED_SECRET</c> can carry (TPM 2.0 Library Part 2, clause 11.4.3, Table 210, page 180).
    /// </summary>
    private static byte[] PastBoundEncryptedSalt { get; } = FilledNonZero(Tpm2bEncryptedSecret.MaxSize + 1);

    /// <summary>An <c>encryptedSalt</c> of exactly the bound, which the same wire read admits and the ladder then refuses on its own terms.</summary>
    private static byte[] AdmissibleWidthEncryptedSalt { get; } = FilledNonZero(Tpm2bEncryptedSecret.MaxSize);

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The credential carriers are rented as the parse's LAST act, so a <c>TPM2_GetRandom()</c> over a session
    /// refused on a trailing octet no parameter accounts for (TPM 2.0 Library Part 3, clause 5.2) leaves nothing
    /// outstanding at all.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverSessionRefusedAtTheParseRentsNoCredentialCarriers()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-getrandom-parse").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.Dispose();

        long baseline = trackingPool.OutstandingCount;

        var body = new List<byte>();
        AppendAuthorizationArea(body, sessionHandle, PolicySlotNonce, PolicySlotNonce.Length, PolicySlotNonce);
        AppendUInt16(body, RandomByteCount);
        body.Add(0xFF);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_GetRandom, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, code,
            "An octet no parameter accounts for is TPM_RC_SIZE at the wire read (Part 3, clause 5.2).");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Both credential carriers are rented as the parse's last act, so a parse refused on a later wire check must rent neither.");

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_GetRandom()</c> over a session with the <c>encrypt</c> attribute (TPM 2.0 Library Part 3, clause
    /// 16.1; Part 1, clause 19) returns both slot credentials on a refusal taken at the entry transition and on
    /// an accepted round trip: the accepting continuation is the hmac's terminal owner, and the caller nonce is
    /// transferred into the response-encryption step, whose effect releases it once the keystream and the
    /// response HMAC have keyed their nonceOlder term on it.
    /// </summary>
    [TestMethod]
    public async Task GetRandomOverSessionReturnsBothSlotCredentialsOnEveryPath()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-getrandom").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        (uint sessionHandle, TpmSession session) = await StartEncryptingSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                var body = new List<byte>();
                AppendAuthorizationArea(body, UnstartedSessionHandle, PolicySlotNonce, PolicySlotNonce.Length, PolicySlotNonce);
                AppendUInt16(body, RandomByteCount);

                TpmRcConstants code = await SubmitFramedAsync(
                    simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_GetRandom, [.. body]).ConfigureAwait(false);
                Assert.AreNotEqual(TpmRcConstants.TPM_RC_SUCCESS, code, "A session handle that names no loaded session must be refused.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A command refused at its entry transition releases both credentials through the request's own Dispose.");

            {
                var input = new GetRandomInput(RandomByteCount);
                TpmResult<GetRandomResponse> result = await TpmCommandExecutor.ExecuteAsync<GetRandomResponse>(
                    tpm, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_GetRandom over an encrypting session failed: '{result.ResponseCode}'.");
                result.Value.Dispose();
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "On the accepted path the continuation releases the hmac and the response-encryption effect releases the caller nonce it transferred into.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Create()</c> over one HMAC session (TPM 2.0 Library Part 3, clause 12.1) returns both slot
    /// credentials on a command-HMAC mismatch and on an accepted round trip, the accepted path transferring the
    /// slot's caller nonce into the response-session entry the sealing effect then releases.
    /// </summary>
    [TestMethod]
    public async Task CreateOverSessionsReturnsEverySlotCredentialOnEveryPath()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-create", withEccBackend: true).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] parentName = parent.Name.Span.ToArray();
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                byte[] wrongName = new byte[parentName.Length];
                parentName.CopyTo(wrongName, 0);
                wrongName[^1] ^= 0xFF;

                using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, pool);
                using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                TpmResult<CreateResponse> refused = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                    tpm, input, [session], [wrongName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "A command HMAC computed over the wrong parent Name must not authorize.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A command-HMAC mismatch releases every slot credential through the whole-request release the shared verification arm performs.");

            {
                using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, pool);
                using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                    tpm, input, [session], [parentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_Create over a session failed: '{result.ResponseCode}'.");
                result.Value.Dispose();
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "On the accepted path the continuation releases both hmacs and the sealing effect releases the caller nonce the resume transferred into its response-session entry.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Create()</c> over TWO sessions — the parent authorizer and a separate <c>decrypt</c> companion —
    /// accounts for all four slot credentials, and its second queued verification reads a live carrier: the
    /// request owns both slots' credentials for the whole queue, so session 1's HMAC is still verifiable after
    /// session 0's has been (TPM 2.0 Library Part 3, clause 5.6 applies to every session in the area).
    /// </summary>
    /// <remarks>
    /// A design that let the verification step release each session's credential as it consumed it would leave
    /// the second verification reading disposed memory; a design that copied per session would leave the balance
    /// short. Both are excluded by this one round trip.
    /// </remarks>
    [TestMethod]
    public async Task CreateOverTwoSessionsAccountsForEverySlotCredentialAndVerifiesTheSecondAgainstALiveCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-create2", withEccBackend: true).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] parentName = parent.Name.Span.ToArray();
        (uint authHandle, TpmSession authSession) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(authSession)
        {
            (uint decryptHandle, TpmSession decryptSession) = await StartDecryptingSessionAsync(tpm, registry, pool).ConfigureAwait(false);
            using(decryptSession)
            {
                long baseline = trackingPool.OutstandingCount;

                {
                    using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, pool);
                    using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                    using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                    TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                        tpm, input, [authSession, decryptSession], [parentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"TPM2_Create over an authorizing session and a decrypt companion failed: '{result.ResponseCode}'.");
                    result.Value.Dispose();
                }

                Assert.AreEqual(
                    baseline, trackingPool.OutstandingCount,
                    "Both slots' hmacs are released at the accepted continuation and both slots' caller nonces by the sealing effect that the resume transferred them into.");

                await FlushAsync(tpm, registry, pool, decryptHandle).ConfigureAwait(false);
            }
        }

        await FlushAsync(tpm, registry, pool, authHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Create()</c> whose parent-authorizing slot is <c>TPM_RS_PW</c> alongside a <c>decrypt</c>
    /// companion (TPM 2.0 Library Part 1, clause 16.6.4, Table 12 admits the attribute on a slot authorizing
    /// nothing) builds a PLACEHOLDER response entry for slot 0 rather than a real one, so nothing takes that
    /// slot's caller nonce and the resume is its terminal owner.
    /// </summary>
    /// <remarks>
    /// A password slot's caller nonce is structurally empty (Part 1, clause 16.6.4, Table 12) and therefore the
    /// dispose-immune sentinel, so what this proof measures on that slot is the credential rather than the
    /// nonce; the companion's own nonce is a real rental and still has to reach the sealing effect through its
    /// entry. Both are counted by the same balance.
    /// </remarks>
    [TestMethod]
    public async Task CreateOverAPasswordSlotWithADecryptCompanionAccountsForEverySlotCredential()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-createpw", withEccBackend: true).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        byte[] parentName = parent.Name.Span.ToArray();
        (uint decryptHandle, TpmSession decryptSession) = await StartDecryptingSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(decryptSession)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
                using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, pool);
                using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
                using CreateInput input = new(parent.ObjectHandle.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);

                TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                    tpm, input, [parentAuth, decryptSession], [parentName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_Create over a password slot and a decrypt companion failed: '{result.ResponseCode}'.");
                result.Value.Dispose();
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The placeholder branch builds no response-session entry for slot 0, so it must release that slot's caller nonce at the arm while the companion's travels on into its own entry.");

            await FlushAsync(tpm, registry, pool, decryptHandle).ConfigureAwait(false);
        }

        await FlushAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Unseal()</c> over one session that both authorizes the item and carries <c>encrypt</c> (TPM 2.0
    /// Library Part 3, clause 12.7) returns both slot credentials on a command-HMAC mismatch and on an accepted
    /// round trip: the caller nonce transfers into the response-session entry the framing effect releases, and
    /// the second slot — absent here — leaves only the dispose-immune sentinel behind.
    /// </summary>
    [TestMethod]
    public async Task UnsealOverAnEncryptingSessionReturnsEverySlotCredentialOnEveryPath()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-unseal", withEccBackend: true).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint itemHandle, byte[] itemName) = await SealAndLoadAsync(tpm, registry, pool, parent).ConfigureAwait(false);

        (uint sessionHandle, TpmSession session) = await StartEncryptingSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                byte[] wrongName = new byte[itemName.Length];
                itemName.CopyTo(wrongName, 0);
                wrongName[^1] ^= 0xFF;

                UnsealInput input = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
                TpmResult<UnsealResponse> refused = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, input, [session], [wrongName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "A command HMAC computed over the wrong item Name must not authorize.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A command-HMAC mismatch releases every slot credential through the whole-request release the shared verification arm performs.");

            {
                UnsealInput input = UnsealInput.ForItem(TpmiDhObject.FromValue(itemHandle));
                TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    tpm, input, [session], [itemName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_Unseal over an encrypting session failed: '{result.ResponseCode}'.");

                using UnsealResponse unsealed = result.Value;
                Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(SealedSecret), "The unseal must return the sealed octets.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "On the accepted path the continuation releases the hmac and the framing effect releases the caller nonce it transferred into.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, itemHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_Unseal()</c> authorized by a policy session alone builds NO response-session entry at all — the
    /// executor accepts a keyless policy session's no-sessions response (TPM 2.0 Library Part 1, clause 17.6) —
    /// so that exit is itself the terminal owner of the slot's caller nonce, which no entry ever takes.
    /// </summary>
    /// <remarks>
    /// The slot's nonce is deliberately the session's full digest width and non-zero, so it is a real rental: an
    /// exit that transferred nothing and released nothing would leave the balance one carrier high.
    /// </remarks>
    [TestMethod]
    public async Task UnsealAuthorizedByAPolicySessionAloneReleasesItsSlotNonceAtTheArm()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-unsealpolicy", withEccBackend: true).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint itemHandle, _) = await SealAndLoadAsync(tpm, registry, pool, parent).ConfigureAwait(false);
        uint policySessionHandle = await StartPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        var body = new List<byte>();
        AppendUInt32(body, itemHandle);
        AppendAuthorizationArea(body, policySessionHandle, PolicySlotNonce, declaredHmacSize: 0, hmacOctets: []);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_Unseal, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, code,
            "A policy session whose accumulated digest is not measured against an empty authPolicy authorizes the unseal (Part 1, clause 11.2, Table 5).");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The policy-authorized exit builds no response-session entry, so it must release the slot's caller nonce at the arm.");

        await FlushAsync(tpm, registry, pool, policySessionHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, itemHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c> authorized by an HMAC session (TPM 2.0 Library Part 3, Section 23.4.1) returns
    /// its slot credentials across a command-HMAC mismatch, an accepted call that mints no ticket, and an
    /// accepted call whose negative expiration mints a real <c>TPM_ST_AUTH_SECRET</c> ticket — the longest
    /// transfer chain these proofs drive, the caller nonce riding the authorizing-session entry through the fold
    /// and the ticket mint into the response framing that releases it.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretOverAnHmacSessionReturnsItsCredentialsAcrossTheTicketAndNoTicketArms()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-policysecret").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint policySessionHandle = await StartPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);
        (uint authorizerHandle, TpmSession authorizer) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(authorizer)
        {
            //A fresh policy session's policyDigest is the shared dispose-immune zero sentinel, which rents
            //nothing; the FIRST fold replaces it with a real pooled carrier the session then owns for good. That
            //one-time transition is a property of the digest, not of the credentials measured here, so the
            //baseline is taken past it.
            {
                using PolicySecretInput warmUp = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_OWNER, policySessionHandle, pool);
                TpmResult<PolicySecretResponse> warmUpResult = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, warmUp, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(warmUpResult.IsSuccess, $"TPM2_PolicySecret over an HMAC session failed: '{warmUpResult.ResponseCode}'.");
                warmUpResult.Value.Dispose();
            }

            long baseline = trackingPool.OutstandingCount;

            {
                using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_OWNER, policySessionHandle, pool);
                ReadOnlyMemory<byte>[] wrongNames = [HandleFormName((uint)TpmRh.TPM_RH_ENDORSEMENT), HandleFormName(policySessionHandle)];

                TpmResult<PolicySecretResponse> refused = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, input, [authorizer], wrongNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "A command HMAC computed over the wrong authHandle Name must not authorize.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A command-HMAC mismatch releases every slot credential through the whole-request release the shared verification arm performs.");

            {
                using PolicySecretInput input = PolicySecretInput.CreateImmediate((uint)TpmRh.TPM_RH_OWNER, policySessionHandle, pool);
                TpmResult<PolicySecretResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, input, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_PolicySecret over an HMAC session failed: '{result.ResponseCode}'.");
                result.Value.Dispose();
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The no-ticket arm still frames a session response, so the framing effect releases the caller nonce the continuation transferred into the authorizing-session entry.");

            {
                using PolicySecretInput ticketInput = PolicySecretInput.Create(
                    (uint)TpmRh.TPM_RH_OWNER, policySessionHandle, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, expiration: -60, pool);

                TpmResult<PolicySecretResponse> result = await TpmCommandExecutor.ExecuteAsync<PolicySecretResponse>(
                    tpm, ticketInput, [authorizer], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_PolicySecret requesting a ticket failed: '{result.ResponseCode}'.");
                result.Value.Dispose();
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The ticket arm adds a mint hop between the fold and the framing, and the caller nonce must survive it and be released exactly once at the end.");
        }

        await FlushAsync(tpm, registry, pool, authorizerHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, policySessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c>'s <c>nonceTPM</c> parameter is a <c>TPM2B_NONCE</c> (TPM 2.0 Library Part 3,
    /// Table 129), and a <c>TPM2B_NONCE</c>'s buffer is bounded by <c>sizeof(TPMU_HA)</c> (Part 2, clause 10.4.4,
    /// Table 94, which types it as a <c>TPM2B_DIGEST</c>, over clause 10.4.2, Table 92, whose implied check names
    /// <c>TPM_RC_SIZE</c>): a declared width past that is a marshalling refusal at the wire read, BARE because
    /// the octets belong to a command parameter rather than to a session.
    /// </summary>
    /// <remarks>
    /// The refusal lands ahead of the comparison against the session's retained nonce, so it is answered
    /// identically on a trial session, which runs no nonceTPM comparison at all. The paired rung declares exactly
    /// the bound and reaches that comparison, which answers <c>TPM_RC_VALUE</c> instead (clause 23.2.2, printed
    /// page 189, rule 1) — so only the declared width can account for the first refusal.
    /// </remarks>
    [TestMethod]
    public async Task PolicySecretWithACallerNonceTpmPastTheUnionBoundIsRefusedAtTheWireReadWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-policysecret-nonce").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint policySessionHandle = await StartPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants refused = await SubmitPolicySecretWithNonceTpmAsync(simulator, pool, policySessionHandle, PastBoundNonce).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, refused,
            "A nonceTPM parameter wider than sizeof(TPMU_HA) is TPM_RC_SIZE at the wire read (Part 2, clause 10.4.4, Table 94 over clause 10.4.2, Table 92).");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal lands ahead of every rental, so the refused frame leaves nothing outstanding.");

        TpmRcConstants admitted = await SubmitPolicySecretWithNonceTpmAsync(simulator, pool, policySessionHandle, AdmissibleWidthNonce).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_VALUE, admitted,
            "The identical frame one octet narrower passes the width rule and is judged by the session-nonce comparison instead, which answers TPM_RC_VALUE (Part 3, clause 23.2.2, printed page 189, rule 1), so only the declared width refused the first one.");

        //A trial session runs no nonceTPM comparison at all (Part 3, Section 23.4.1's carve-out is the
        //authorization check alone), so it is the arm on which a value the structure cannot hold would otherwise
        //travel through unexamined. The width rule is structural and refuses it there too.
        uint trialSessionHandle = await StartTrialPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmRcConstants trialRefused = await SubmitPolicySecretWithNonceTpmAsync(simulator, pool, trialSessionHandle, PastBoundNonce).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, trialRefused,
            "The width rule is a property of the structure, not of the session, so a trial session's own skipped comparison cannot admit a value no TPM2B_NONCE can hold.");

        TpmRcConstants trialAdmitted = await SubmitPolicySecretWithNonceTpmAsync(simulator, pool, trialSessionHandle, AdmissibleWidthNonce).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, trialAdmitted,
            "The identical frame one octet narrower is accepted by the trial session, so only the declared width refused the first one.");

        await FlushAsync(tpm, registry, pool, trialSessionHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, policySessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_PolicySigned()</c>'s <c>nonceTPM</c> parameter carries the same <c>TPM2B_NONCE</c> bound as
    /// <c>TPM2_PolicySecret()</c>'s (TPM 2.0 Library Part 3, Table 127; Part 2, clause 10.4.4, Table 94 over
    /// clause 10.4.2, Table 92) and is refused the same way at the wire read.
    /// </summary>
    [TestMethod]
    public async Task PolicySignedWithACallerNonceTpmPastTheUnionBoundIsRefusedAtTheWireReadWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-policysigned-nonce", withEccBackend: true).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint policySessionHandle = await StartPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants refused = await SubmitPolicySignedWithNonceTpmAsync(simulator, pool, policySessionHandle, PastBoundNonce).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, refused,
            "A nonceTPM parameter wider than sizeof(TPMU_HA) is TPM_RC_SIZE at the wire read, whichever policy assertion carries it.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal lands ahead of every rental, so the refused frame leaves nothing outstanding.");

        TpmRcConstants admitted = await SubmitPolicySignedWithNonceTpmAsync(simulator, pool, policySessionHandle, AdmissibleWidthNonce).ConfigureAwait(false);
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_SIZE, admitted,
            "The identical frame one octet narrower passes the width rule and is judged further down the ladder, so only the declared width refused the first one.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "That rung's nonceTPM IS a rental — it declared exactly the bound — so the arm that refuses it further down the ladder must release it with the rest of the request's parameter carriers.");

        await FlushAsync(tpm, registry, pool, policySessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// A trial-session <c>TPM2_PolicySigned()</c> carrying a NON-EMPTY <c>nonceTPM</c> returns that parameter's
    /// carrier to the pool: the trial arm folds the policyDigest without checking the signature or any parameter
    /// (TPM 2.0 Library Part 3, Section 23.3), so nothing downstream takes the nonce and the arm itself is its
    /// terminal owner.
    /// </summary>
    /// <remarks>
    /// The balance is taken after a FIRST assertion has already folded, because that first fold replaces the
    /// session's shared zero-digest sentinel — which rents nothing (Part 3, Section 23.2.3's all-zero initial
    /// policyDigest) — with a real pooled digest. From there each further fold disposes the superseded digest as
    /// it installs its replacement, so a second identical assertion must leave the count exactly where the first
    /// left it.
    /// </remarks>
    [TestMethod]
    public async Task PolicySignedOnATrialSessionReturnsItsCallerNonceTpmCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-policysigned-trial", withEccBackend: true).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse authObject = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint authObjectHandle = authObject.ObjectHandle.Value;
        uint trialSessionHandle = await StartTrialPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);

        TpmRcConstants firstFold = await SubmitPolicySignedWithNonceTpmAsync(
            simulator, pool, trialSessionHandle, PolicySlotNonce, authObjectHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, firstFold,
            "A trial session accepts the assertion without validating the signature, so the caller-supplied nonceTPM travels the accepting arm.");

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants secondFold = await SubmitPolicySignedWithNonceTpmAsync(
            simulator, pool, trialSessionHandle, PolicySlotNonce, authObjectHandle).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, secondFold,
            "The identical second assertion is accepted the same way, so the two folds differ only in the carriers they account for.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The trial arm inspects no parameter, so it is the terminal owner of the nonceTPM the parse rented for it, and the replacement digest it installs disposes the one it supersedes.");

        await FlushAsync(tpm, registry, pool, trialSessionHandle).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, authObjectHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_StartAuthSession()</c>'s <c>nonceCaller</c> is a <c>TPM2B_NONCE</c> (TPM 2.0 Library Part 3,
    /// Table 14), so a declared width past <c>sizeof(TPMU_HA)</c> is refused at the wire read with
    /// <c>TPM_RC_SIZE</c> — ahead of the clause 11.1.1 floor and ceiling, which are the session's own narrower
    /// rule rather than the structure's.
    /// </summary>
    [TestMethod]
    public async Task StartAuthSessionWithACallerNoncePastTheUnionBoundIsRefusedAtTheWireReadWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-start-nonce").ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants refused = await SubmitStartAuthSessionAsync(simulator, pool, PastBoundNonce, []).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, refused,
            "A nonceCaller wider than sizeof(TPMU_HA) is TPM_RC_SIZE at the wire read (Part 2, clause 10.4.4, Table 94 over clause 10.4.2, Table 92).");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal lands ahead of every rental, so the refused frame leaves nothing outstanding.");

        TpmRcConstants admitted = await SubmitStartAuthSessionAsync(simulator, pool, AdmissibleWidthNonce, []).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, admitted,
            "Exactly the structural bound still exceeds the SHA-256 session's own digest ceiling, so the identical frame is refused by clause 11.1.1's rule instead.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A start refused by the session's own ceiling releases both parse-rented carriers through the request's own Dispose.");

        //The structural width rule is a marshalling refusal, so it precedes every rule the command itself
        //applies — including the authHash gate, which this model answers with TPM_RC_HASH. The pair below fixes
        //that order: the same unsupported authHash answers HASH when the nonce is well formed and SIZE when it
        //is not.
        TpmRcConstants widthAheadOfHash = await SubmitStartAuthSessionAsync(
            simulator, pool, PastBoundNonce, [], TpmAlgIdConstants.TPM_ALG_SHA1).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, widthAheadOfHash,
            "An unmarshalling refusal precedes the command's own authHash gate (Part 3, clause 5.8.2: an unmarshalling error means no command processing occurs).");

        TpmRcConstants hashGate = await SubmitStartAuthSessionAsync(
            simulator, pool, FilledNonZero(32), [], TpmAlgIdConstants.TPM_ALG_SHA1).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HASH, hashGate,
            "The identical frame with a well-formed nonce reaches the authHash gate, so only the declared width moved the first answer.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Neither refusal leaves a carrier outstanding.");
    }

    /// <summary>
    /// <c>TPM2_StartAuthSession()</c>'s <c>encryptedSalt</c> is a <c>TPM2B_ENCRYPTED_SECRET</c>, whose secret is
    /// bounded by <c>sizeof(TPMU_ENCRYPTED_SECRET)</c> (TPM 2.0 Library Part 2, clause 11.4.3, Table 210, page
    /// 180) — the widest asymmetrically protected seed the union holds — so a declared width past that is a
    /// marshalling refusal at the wire read, ahead of the <c>tpmKey</c>/salt consistency ladder.
    /// </summary>
    /// <remarks>
    /// The paired rung declares exactly the bound with the same <c>TPM_RH_NULL</c> <c>tpmKey</c> and reaches
    /// that ladder, which answers <c>TPM_RC_VALUE</c> for an unsalted request naming a non-empty salt — so only
    /// the declared width can account for the first refusal.
    /// </remarks>
    [TestMethod]
    public async Task StartAuthSessionWithAnEncryptedSaltPastTheSecretBoundIsRefusedAtTheWireReadWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-start-salt").ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants refused = await SubmitStartAuthSessionAsync(simulator, pool, FilledNonZero(32), PastBoundEncryptedSalt).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, refused,
            "An encryptedSalt wider than sizeof(TPMU_ENCRYPTED_SECRET) is TPM_RC_SIZE at the wire read (Part 2, clause 11.4.3, Table 210).");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal lands ahead of every rental, so the refused frame leaves nothing outstanding.");

        TpmRcConstants admitted = await SubmitStartAuthSessionAsync(simulator, pool, FilledNonZero(32), AdmissibleWidthEncryptedSalt).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_VALUE,
            admitted,
            "The identical frame one octet narrower passes the width rule and is judged by the unsalted-request consistency rule instead, so only the declared width refused the first one.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A start refused by the salt-consistency ladder releases both parse-rented carriers through the request's own Dispose.");
    }

    /// <summary>
    /// A started, unbound, unsalted session leaves exactly ONE carrier outstanding — the nonceTPM it retains
    /// (TPM 2.0 Library Part 1, clause 17.6.5) — even though its parse rents a caller-nonce carrier as well: the
    /// session records no caller nonce at all, so the session-start effect is that carrier's terminal owner and
    /// releases it inside the command.
    /// </summary>
    [TestMethod]
    public async Task AStartedSessionLeavesOnlyItsRetainedNonceOutstanding()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential2-start-balance").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;

        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.Dispose();

        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "The start's own caller nonce is released by the session-start effect, so the retained nonceTPM is the only carrier such a session leaves behind.");

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Flushing the session returns the retained nonceTPM carrier to the pool.");
    }

    /// <summary>Renders a permanent entity's Name: its 4-octet big-endian handle value (Part 1, clause 14, Table 6).</summary>
    /// <param name="handle">The entity's handle.</param>
    /// <returns>The handle-form Name.</returns>
    private static byte[] HandleFormName(uint handle)
    {
        byte[] name = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(name, handle);

        return name;
    }

    /// <summary>Appends a big-endian <c>UINT32</c> to a command body under construction.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt32(List<byte> body, uint value)
    {
        Span<byte> octets = stackalloc byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(octets, value);
        body.AddRange(octets);
    }

    /// <summary>Appends a big-endian <c>UINT16</c> to a command body under construction.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="value">The value to append.</param>
    private static void AppendUInt16(List<byte> body, ushort value)
    {
        Span<byte> octets = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(octets, value);
        body.AddRange(octets);
    }

    /// <summary>Appends a TPM2B field: a big-endian <c>UINT16</c> size prefix followed by exactly those octets.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="octets">The field's octets; their count is the declared size.</param>
    private static void AppendTpm2b(List<byte> body, byte[] octets)
    {
        AppendUInt16(body, (ushort)octets.Length);
        body.AddRange(octets);
    }

    /// <summary>
    /// Appends a one-session authorization area whose <c>nonce</c> and <c>hmac</c> fields are written exactly as
    /// given, so a proof can present a slot no production session builder would produce (TPM 2.0 Library Part 2,
    /// clause 10.13.2, Table 153).
    /// </summary>
    /// <param name="body">The body being built.</param>
    /// <param name="sessionHandle">The session handle to name.</param>
    /// <param name="nonceOctets">The caller-nonce octets; their count is the declared size.</param>
    /// <param name="declaredHmacSize">The size to declare for the hmac field.</param>
    /// <param name="hmacOctets">The hmac octets actually written.</param>
    private static void AppendAuthorizationArea(
        List<byte> body, uint sessionHandle, byte[] nonceOctets, int declaredHmacSize, byte[] hmacOctets)
    {
        var area = new List<byte>();
        AppendUInt32(area, sessionHandle);
        AppendUInt16(area, (ushort)nonceOctets.Length);
        area.AddRange(nonceOctets);
        area.Add((byte)TpmaSession.CONTINUE_SESSION);
        AppendUInt16(area, (ushort)declaredHmacSize);
        area.AddRange(hmacOctets);

        AppendUInt32(body, (uint)area.Count);
        body.AddRange(area);
    }

    /// <summary>
    /// Hand-frames a password-authorized <c>TPM2_PolicySecret()</c> against the owner hierarchy whose
    /// <c>nonceTPM</c> parameter carries exactly the given octets, so a proof can declare a width no client-side
    /// factory would build.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session the assertion folds into.</param>
    /// <param name="nonceTpm">The caller-supplied nonceTPM octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitPolicySecretWithNonceTpmAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint policySession, byte[] nonceTpm)
    {
        var body = new List<byte>();
        AppendUInt32(body, (uint)TpmRh.TPM_RH_OWNER);
        AppendUInt32(body, policySession);
        AppendAuthorizationArea(body, (uint)TpmRh.TPM_RH_PW, nonceOctets: [], declaredHmacSize: 0, hmacOctets: []);
        AppendTpm2b(body, nonceTpm);
        AppendTpm2b(body, []);
        AppendTpm2b(body, []);
        AppendUInt32(body, 0);

        return await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_PolicySecret, [.. body]).ConfigureAwait(false);
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_PolicySigned()</c> whose <c>nonceTPM</c> parameter carries exactly the given octets;
    /// the command takes no authorization area at all (TPM 2.0 Library Part 3, Section 23.3).
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session the assertion folds into.</param>
    /// <param name="nonceTpm">The caller-supplied nonceTPM octets.</param>
    /// <param name="authObject">The handle of the key that validates the signature; the policy session's own handle when none is given, which the entry transition refuses as an object handle.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitPolicySignedWithNonceTpmAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint policySession, byte[] nonceTpm, uint? authObject = null)
    {
        var body = new List<byte>();
        AppendUInt32(body, authObject ?? policySession);
        AppendUInt32(body, policySession);
        AppendTpm2b(body, nonceTpm);
        AppendTpm2b(body, []);
        AppendTpm2b(body, []);
        AppendUInt32(body, 0);
        AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_ECDSA);
        AppendUInt16(body, (ushort)SessionAlg);
        AppendTpm2b(body, FilledNonZero(32));
        AppendTpm2b(body, FilledNonZero(32));

        return await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_PolicySigned, [.. body]).ConfigureAwait(false);
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_StartAuthSession()</c> for an unsalted, unbound HMAC session whose
    /// <c>nonceCaller</c> and <c>encryptedSalt</c> parameters carry exactly the given octets.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nonceCaller">The caller nonce octets.</param>
    /// <param name="encryptedSalt">The encrypted-salt octets.</param>
    /// <param name="authHash">The session hash algorithm the frame requests.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitStartAuthSessionAsync(
        TpmSimulator simulator, BaseMemoryPool pool, byte[] nonceCaller, byte[] encryptedSalt, TpmAlgIdConstants authHash = SessionAlg)
    {
        var body = new List<byte>();
        AppendUInt32(body, (uint)TpmRh.TPM_RH_NULL);
        AppendUInt32(body, (uint)TpmRh.TPM_RH_NULL);
        AppendTpm2b(body, nonceCaller);
        AppendTpm2b(body, encryptedSalt);
        body.Add((byte)TpmSeConstants.TPM_SE_HMAC);
        AppendUInt16(body, (ushort)TpmAlgIdConstants.TPM_ALG_NULL);
        AppendUInt16(body, (ushort)authHash);

        return await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_StartAuthSession, [.. body]).ConfigureAwait(false);
    }

    /// <summary>Submits a hand-framed command body and returns the response code alone.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="tag">The command tag.</param>
    /// <param name="commandCode">The command code.</param>
    /// <param name="body">Everything after the header.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitFramedAsync(
        TpmSimulator simulator, BaseMemoryPool pool, TpmStConstants tag, TpmCcConstants commandCode, byte[] body)
    {
        int length = TpmHeader.HeaderSize + body.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)tag, (uint)length, (uint)commandCode);
        header.WriteTo(ref writer);
        writer.WriteBytes(body);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The simulator must answer a malformed command rather than fault.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>Starts an unbound, unsalted HMAC session and returns its handle and the host-side session.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the host-side session object.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, pool)
        {
            SessionAttributes = TpmaSession.CONTINUE_SESSION
        };

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Starts an unbound, unsalted HMAC session negotiating XOR and sets its <c>encrypt</c> attribute.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the host-side session object.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartEncryptingSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool) =>
        await StartSymmetricSessionAsync(tpm, registry, pool, TpmaSession.CONTINUE_SESSION | TpmaSession.ENCRYPT).ConfigureAwait(false);

    /// <summary>Starts an unbound, unsalted HMAC session negotiating XOR and sets its <c>decrypt</c> attribute.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle and the host-side session object.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartDecryptingSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool) =>
        await StartSymmetricSessionAsync(tpm, registry, pool, TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT).ConfigureAwait(false);

    /// <summary>Starts an unbound, unsalted HMAC session negotiating XOR under the given command session attributes.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="attributes">The command session attributes the session presents.</param>
    /// <returns>The session handle and the host-side session object.</returns>
    private async Task<(uint SessionHandle, TpmSession Session)> StartSymmetricSessionAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmaSession attributes)
    {
        TpmtSymDef symmetric = TpmtSymDef.Xor(SessionAlg);
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, symmetric);

        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (symmetric) failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, SessionAlg, pool, symmetric)
        {
            SessionAttributes = attributes
        };

        return (started.SessionHandle.Value, session);
    }

    /// <summary>Starts a trial policy session, which accumulates a policyDigest but authorizes nothing (TPM 2.0 Library Part 1, clause 17.7).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle.</returns>
    private async Task<uint> StartTrialPolicySessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput input = StartAuthSessionInputExtensions.CreateTrialPolicySession(SessionAlg);

        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (trial policy) failed: '{result.ResponseCode}'.");

        using StartAuthSessionResponse started = result.Value;

        return started.SessionHandle.Value;
    }

    /// <summary>Starts an unbound, unsalted POLICY session (never a trial one, which authorizes nothing).</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The session handle.</returns>
    private async Task<uint> StartPolicySessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput input = StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg);

        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (policy) failed: '{result.ResponseCode}'.");

        using StartAuthSessionResponse started = result.Value;

        return started.SessionHandle.Value;
    }

    /// <summary>Flushes a transient object or session handle.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The handle to flush.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        var input = FlushContextInput.ForHandle(handle);
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_FlushContext failed: '{result.ResponseCode}'.");
    }

    /// <summary>Creates the ECC storage parent the sealed-object proofs create under; the caller owns and must dispose the response.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The created primary object.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Seals <see cref="SealedSecret"/> under the given parent over a password slot and loads it back.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parent">The loaded storage parent.</param>
    /// <returns>The loaded object's transient handle and Name.</returns>
    private async Task<(uint ItemHandle, byte[] ItemName)> SealAndLoadAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, CreatePrimaryResponse parent)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
        using CreateInput createInput = new(parent.ObjectHandle.Value, inSensitive, template, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"TPM2_Create (sealed object) failed: '{createResult.ResponseCode}'.");

        using CreateResponse created = createResult.Value;
        using LoadInput loadInput = new(parent.ObjectHandle.Value, created.OutPrivate, created.OutPublic);
        using TpmPasswordSession loadAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"TPM2_Load failed: '{loadResult.ResponseCode}'.");

        using LoadResponse loaded = loadResult.Value;

        return (loaded.ObjectHandle.Value, loaded.Name.Span.ToArray());
    }

    /// <summary>
    /// Builds a value of the given width whose every octet is non-zero, so no trailing-zero removal (TPM 2.0
    /// Library Part 1, clause 17.6.4.3) can shorten it and no carrier it is read into is the shared empty
    /// sentinel.
    /// </summary>
    /// <param name="length">The width in octets.</param>
    /// <returns>The value.</returns>
    private static byte[] FilledNonZero(int length)
    {
        byte[] value = new byte[length];
        for(int i = 0; i < length; i++)
        {
            value[i] = (byte)(0x11 + i);
        }

        return value;
    }

    /// <summary>Builds the response codec registry these proofs drive the executor with.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability);
        _ = registry.Register(TpmCcConstants.TPM_CC_GetRandom, TpmResponseCodec.GetRandom);
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicySecret, TpmResponseCodec.PolicySecret);

        return registry;
    }

    /// <summary>Creates a simulator, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool every command runs against.</param>
    /// <param name="tpmId">The simulated TPM's run identifier, unique per test so no meter is shared.</param>
    /// <param name="withEccBackend">Whether to supply the elliptic-curve backend key generation runs through, for the proofs that create a primary object; the proofs that create none never reach it.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string tpmId, bool withEccBackend = false)
    {
        var simulator = new TpmSimulator(tpmId, signingBackend: withEccBackend ? BouncyCastleTpmEccSigningBackend.Create() : null);
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

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
        result.Value.Dispose();
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);

        return simulator;
    }
}
