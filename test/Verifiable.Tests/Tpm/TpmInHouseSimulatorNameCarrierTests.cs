using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Cryptography;
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
/// Proves the pooled-carrier ownership of the <c>TPM2B_NAME</c> parameters three commands take on the wire —
/// <c>TPM2_PolicyAuthorize()</c>'s <c>keySign</c> (TPM 2.0 Library Part 3, Section 23.16, Table 153),
/// <c>TPM2_PolicyTicket()</c>'s <c>authName</c> (Section 23.5, Table 131), and
/// <c>TPM2_MakeCredential()</c>'s <c>objectName</c> (clause 12.6, Table 28) — against the in-house behavioural
/// <see cref="TpmSimulator"/>. Each Name rides a carrier the parser rents as its last act, and each reaches the
/// pool again on every path its command can leave by: refused before the command body runs, refused inside the
/// continuation that an effect fed, and consumed by the fold or the wrap that owned it last.
/// </summary>
/// <remarks>
/// <para>
/// The instrument is <see cref="MeteredHousePool"/>: a genuine <see cref="BaseMemoryPool"/> whose own rent and
/// return telemetry is observed, so nothing here depends on a seam in production code. Every Name driven through
/// is deliberately NON-EMPTY, because an empty one parses to <see cref="Tpm2bName.Empty"/> — the shared
/// dispose-immune sentinel, which rents nothing and would make a balance assertion vacuous.
/// </para>
/// <para>
/// The commands are issued through <see cref="TpmCommandExecutor"/> with the metered pool rather than through
/// the <c>Extensions</c> verbs, because those compose their own <c>BaseMemoryPool.Shared</c> internally and the
/// simulator would then rent from a pool this instrument does not observe.
/// </para>
/// <para>
/// Where a command is refused before its body runs, the exact number of Name-width rentals is asserted as well
/// as the balance: the command's input frames one such rental on the client side and the parser makes the
/// second, so a Name the parser left as a sentinel — or never rented at all — would show as one.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorNameCarrierTests
{
    /// <summary>The policy session hash algorithm every session here is started with.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The width of every Name these tests drive: a 2-octet nameAlg prefix plus a SHA-256 digest (TPM 2.0 Library Part 1, clause 14, Table 6).</summary>
    private const int NameSize = sizeof(ushort) + 32;

    /// <summary>A transient-range handle no test ever loads, so <c>TPM2_MakeCredential()</c> refuses it with <c>TPM_RC_HANDLE</c>.</summary>
    private const uint UnloadedObjectHandle = 0x8000_0010;

    /// <summary>
    /// The policy qualifier every case supplies. Its 7-octet width keeps every message buffer the effects rent
    /// clear of <see cref="NameSize"/>, so a rent of that size is unambiguously a Name carrier.
    /// </summary>
    private static byte[] PolicyRef { get; } = [0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57];

    /// <summary>The secret <c>TPM2_MakeCredential()</c> wraps, a <c>TPM2B_DIGEST</c>-shaped value.</summary>
    private static byte[] CredentialSecret { get; } =
        [0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF,
         0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A <c>TPM2_PolicyAuthorize()</c> whose <c>keySign</c> names a hash algorithm the TPM does not implement is
    /// refused with <c>TPM_RC_HASH</c> (TPM 2.0 Library Part 3, Section 23.16) before the session's digest is
    /// compared or any ticket is consulted — so the Name carrier the parser rented has no later owner and the
    /// refusing arm releases it through the request record's own disposal.
    /// </summary>
    [TestMethod]
    public async Task RefusedPolicyAuthorizeReturnsTheKeySignCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;
            long nameRentsBefore = trackingPool.RentedCountOfSize(NameSize);

            TpmResult<PolicyAuthorizeResponse> result = await AuthorizeAsync(
                tpm, registry, trackingPool.Pool, sessionHandle, ZeroDigest(), NameWithAlg(TpmAlgIdConstants.TPM_ALG_NULL)).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_HASH, result.ResponseCode,
                "A keySign whose first two octets name no implemented hash is TPM_RC_HASH, refused before the digest comparison.");

            Assert.AreEqual(
                nameRentsBefore + 2, trackingPool.RentedCountOfSize(NameSize),
                "The command's input and the parser must each have rented a Name-width carrier, or the balance below proves nothing.");

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusing arm must return the parse-rented keySign carrier to the pool.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyAuthorize()</c> on a TRIAL session skips the digest comparison and the ticket
    /// re-verification entirely and folds unconditionally (TPM 2.0 Library Part 3, Section 23.16: the digest "is
    /// extended as if the ticket is valid without actual verification"), so the parse-rented Name carrier
    /// transfers straight into the fold that writes it into the policyDigest — and that fold is its terminal
    /// owner. The session keeps exactly one carrier the assertion created: the advanced policyDigest itself,
    /// which it owns until the next assertion supersedes it or the session is evicted — so the balance the
    /// Name carrier's return is read against is that one live digest, not the pre-assertion count. The eviction
    /// that follows must then bring the count the whole way back past the session's own start, which is what
    /// proves that one-carrier relaxation is a live digest and not a leak.
    /// </summary>
    [TestMethod]
    public async Task TrialPolicyAuthorizeReturnsTheKeySignCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long beforeSession = trackingPool.OutstandingCount;
        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        long baseline = trackingPool.OutstandingCount;
        long nameRentsBefore = trackingPool.RentedCountOfSize(NameSize);

        TpmResult<PolicyAuthorizeResponse> result = await AuthorizeAsync(
            tpm, registry, trackingPool.Pool, sessionHandle, ZeroDigest(), NameWithAlg(SessionAlg)).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"PolicyAuthorize on a trial session must succeed: '{result.ResponseCode}'.");

        Assert.AreEqual(
            nameRentsBefore + 2, trackingPool.RentedCountOfSize(NameSize),
            "The command's input and the parser must each have rented a Name-width carrier, or the balance below proves nothing.");

        Assert.AreEqual(
            baseline + 1, trackingPool.OutstandingCount,
            "The trial fold must return the keySign carrier it consumed and leave exactly the advanced policyDigest the session now owns.");

        await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);

        Assert.AreEqual(
            beforeSession, trackingPool.OutstandingCount,
            "Evicting the session must return that one live policyDigest along with the session's own nonce, leaving nothing outstanding.");
    }

    /// <summary>
    /// A non-trial <c>TPM2_PolicyAuthorize()</c> whose <c>checkTicket</c> does not reproduce
    /// <c>HMAC(proof, TPM_ST_VERIFIED ‖ aHash ‖ keySign)</c> is refused with <c>TPM_RC_VALUE</c> (TPM 2.0
    /// Library Part 3, Section 23.16) — but only after the re-verification effect has run, which is the arm
    /// where the Name carrier has already travelled request → action → effect → feedback. The rejecting
    /// continuation is its terminal owner there, in place of the fold that would have consumed it.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeWithAMismatchedTicketReturnsTheKeySignCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;
            long nameRentsBefore = trackingPool.RentedCountOfSize(NameSize);

            //A fresh policy session's policyDigest is all zeros, so an all-zero approvedPolicy passes the
            //equality check (Section 23.16) and the command reaches the ticket re-verification effect.
            TpmResult<PolicyAuthorizeResponse> result = await AuthorizeAsync(
                tpm, registry, trackingPool.Pool, sessionHandle, ZeroDigest(), NameWithAlg(SessionAlg)).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_VALUE, result.ResponseCode,
                "A checkTicket that does not reproduce the expected verified-ticket HMAC is TPM_RC_VALUE, answered by the continuation the effect fed.");

            Assert.AreEqual(
                nameRentsBefore + 2, trackingPool.RentedCountOfSize(NameSize),
                "The command's input and the parser must each have rented a Name-width carrier, or the balance below proves nothing.");

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The rejecting continuation must return the keySign carrier the effect transferred to it.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyTicket()</c> against a TRIAL session is refused with <c>TPM_RC_ATTRIBUTES</c> (TPM 2.0
    /// Library Part 3, Section 23.5: a ticket IS the authorization material a trial session exists to predict
    /// without holding) before the timeout is even read, so the parse-rented <c>authName</c> carrier is released
    /// by the refusing arm through the request record's own disposal.
    /// </summary>
    [TestMethod]
    public async Task RefusedPolicyTicketReturnsTheAuthNameCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: true).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;
            long nameRentsBefore = trackingPool.RentedCountOfSize(NameSize);

            TpmResult<PolicyTicketResponse> result = await ReplayTicketAsync(
                tpm, registry, trackingPool.Pool, sessionHandle, NameWithAlg(SessionAlg)).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
                "A trial session cannot replay a ticket, and the refusal precedes every parameter check.");

            Assert.AreEqual(
                nameRentsBefore + 2, trackingPool.RentedCountOfSize(NameSize),
                "The command's input and the parser must each have rented a Name-width carrier, or the balance below proves nothing.");

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusing arm must return the parse-rented authName carrier to the pool.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_PolicyTicket()</c> whose ticket does not reproduce the equation-12 HMAC (TPM 2.0 Library Part 2,
    /// Section 10.7.5, Table 111) is refused with <c>TPM_RC_TICKET</c> only after the recompute effect has run,
    /// which is the arm where the Name carrier has already travelled request → action → effect → feedback. The
    /// rejecting continuation is its terminal owner there, in place of the fold that would have consumed it.
    /// </summary>
    [TestMethod]
    public async Task PolicyTicketWithAMismatchedTicketReturnsTheAuthNameCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint sessionHandle = await StartPolicySessionAsync(tpm, registry, trackingPool.Pool, isTrial: false).ConfigureAwait(false);
        try
        {
            long baseline = trackingPool.OutstandingCount;
            long nameRentsBefore = trackingPool.RentedCountOfSize(NameSize);

            TpmResult<PolicyTicketResponse> result = await ReplayTicketAsync(
                tpm, registry, trackingPool.Pool, sessionHandle, NameWithAlg(SessionAlg)).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_TICKET, result.ResponseCode,
                "A ticket digest that does not recompute is TPM_RC_TICKET, answered by the continuation the effect fed.");

            Assert.AreEqual(
                nameRentsBefore + 2, trackingPool.RentedCountOfSize(NameSize),
                "The command's input and the parser must each have rented a Name-width carrier, or the balance below proves nothing.");

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The rejecting continuation must return the authName carrier the effect transferred to it.");
        }
        finally
        {
            await FlushAsync(tpm, registry, trackingPool.Pool, sessionHandle).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_MakeCredential()</c> naming a credential key that is not loaded is refused with
    /// <c>TPM_RC_HANDLE</c> (TPM 2.0 Library Part 3, clause 12.6) before any wrap action is declared, so the
    /// parse-rented <c>objectName</c> carrier never transfers and the refusing arm releases it through the
    /// request record's own disposal.
    /// </summary>
    [TestMethod]
    public async Task RefusedMakeCredentialReturnsTheObjectNameCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        long baseline = trackingPool.OutstandingCount;
        long nameRentsBefore = trackingPool.RentedCountOfSize(NameSize);

        TpmResult<MakeCredentialResponse> result = await WrapCredentialAsync(
            tpm, registry, trackingPool.Pool, TpmiDhObject.FromValue(UnloadedObjectHandle), NameWithAlg(SessionAlg)).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode,
            "A credential key that is not loaded is TPM_RC_HANDLE, refused before the wrap action is declared.");

        Assert.AreEqual(
            nameRentsBefore + 2, trackingPool.RentedCountOfSize(NameSize),
            "The command's input and the parser must each have rented a Name-width carrier, or the balance below proves nothing.");

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusing arm must return the parse-rented objectName carrier to the pool.");
    }

    /// <summary>
    /// A successful <c>TPM2_MakeCredential()</c> transfers the parse-rented <c>objectName</c> carrier into the
    /// wrap action, whose effect binds the credential's symmetric and HMAC keys to that Name (TPM 2.0 Library
    /// Part 1, clause 24) and is its terminal owner — so the carrier reaches the pool once the response has been
    /// consumed, exactly as it does on the refusing arm.
    /// </summary>
    [TestMethod]
    public async Task SuccessfulMakeCredentialReturnsTheObjectNameCarrierToPool()
    {
        using var trackingPool = new MeteredHousePool();
        using TpmSimulator simulator = await CreateOperationalAsync(trackingPool.Pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse credentialKey = await CreateStorageParentAsync(tpm, registry, trackingPool.Pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<MakeCredentialResponse> result = await WrapCredentialAsync(
            tpm, registry, trackingPool.Pool, credentialKey.ObjectHandle, NameWithAlg(SessionAlg)).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"MakeCredential failed: '{result.ResponseCode}'.");
        result.Value.Dispose();

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The wrapping effect must return the objectName carrier transferred into its action to the pool.");
    }

    /// <summary>Builds a Name-shaped value: the given algorithm's 2-octet identifier followed by a distinctive 32-octet body.</summary>
    /// <param name="nameAlg">The algorithm identifier the Name's first two octets carry.</param>
    /// <returns>The Name octets.</returns>
    private static byte[] NameWithAlg(TpmAlgIdConstants nameAlg)
    {
        byte[] name = new byte[NameSize];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        for(int i = sizeof(ushort); i < name.Length; i++)
        {
            name[i] = (byte)(0xA0 + i);
        }

        return name;
    }

    /// <summary>Builds an all-zero digest of the policy session's own width — the value a freshly started session's policyDigest holds.</summary>
    /// <returns>The zero digest octets.</returns>
    private static byte[] ZeroDigest() => new byte[32];

    /// <summary>Issues a <c>TPM2_PolicyAuthorize()</c> carrying a placeholder <c>checkTicket</c> the trial arm ignores and the real arm cannot reproduce.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session being extended.</param>
    /// <param name="approvedPolicy">The approved policy digest.</param>
    /// <param name="keySign">The authority key's Name.</param>
    /// <returns>The command result, not asserted for success.</returns>
    private async Task<TpmResult<PolicyAuthorizeResponse>> AuthorizeAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint policySession, byte[] approvedPolicy, byte[] keySign)
    {
        using PolicyAuthorizeInput input = PolicyAuthorizeInput.Create(
            policySession, approvedPolicy, PolicyRef, keySign,
            (ushort)TpmStConstants.TPM_ST_VERIFIED, (uint)TpmRh.TPM_RH_OWNER, ZeroDigest(), pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicyAuthorizeResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a <c>TPM2_PolicyTicket()</c> carrying a zero timeout and a placeholder ticket the recompute cannot reproduce.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session being extended.</param>
    /// <param name="authName">The Name of the object that provided the original authorization.</param>
    /// <returns>The command result, not asserted for success.</returns>
    private async Task<TpmResult<PolicyTicketResponse>> ReplayTicketAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint policySession, byte[] authName)
    {
        byte[] timeout = new byte[sizeof(ulong)];

        using PolicyTicketInput input = PolicyTicketInput.Create(
            policySession, timeout, ReadOnlySpan<byte>.Empty, PolicyRef, authName,
            (ushort)TpmStConstants.TPM_ST_AUTH_SECRET, (uint)TpmRh.TPM_RH_OWNER, ZeroDigest(), pool);

        return await TpmCommandExecutor.ExecuteAsync<PolicyTicketResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a <c>TPM2_MakeCredential()</c> binding <see cref="CredentialSecret"/> to the given Name.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="keyHandle">The credential key.</param>
    /// <param name="objectName">The Name the credential is bound to.</param>
    /// <returns>The command result, not asserted for success.</returns>
    private async Task<TpmResult<MakeCredentialResponse>> WrapCredentialAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject keyHandle, byte[] objectName)
    {
        using MakeCredentialInput input = MakeCredentialInput.Create(keyHandle, CredentialSecret, objectName, pool);

        return await TpmCommandExecutor.ExecuteAsync<MakeCredentialResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
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
            ? StartAuthSessionInput.CreateTrialPolicySession(SessionAlg)
            : StartAuthSessionInput.CreateUnboundUnsaltedPolicySession(SessionAlg);

        TpmResult<StartAuthSessionResponse> result = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"StartAuthSession (policy) failed: '{result.ResponseCode}'.");

        using StartAuthSessionResponse started = result.Value;

        return started.SessionHandle.Value;
    }

    /// <summary>Creates the restricted-decrypt ECC storage primary <c>TPM2_MakeCredential()</c> wraps to.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC storage parent) failed: '{result.ResponseCode}'.");

        return result.Value;
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

    /// <summary>Creates a simulator with the ECC signing backend wired, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c>.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-name-carriers", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyAuthorize, TpmResponseCodec.PolicyAuthorize);
        _ = registry.Register(TpmCcConstants.TPM_CC_PolicyTicket, TpmResponseCodec.PolicyTicket);
        _ = registry.Register(TpmCcConstants.TPM_CC_MakeCredential, TpmResponseCodec.MakeCredential);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }
}
