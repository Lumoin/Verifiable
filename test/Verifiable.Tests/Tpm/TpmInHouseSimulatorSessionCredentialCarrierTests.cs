using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
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
/// The <c>sizeof(TPMU_HA)</c> width rule that every <c>TPM2B_AUTH</c> and <c>TPM2B_NONCE</c> on the wire carries,
/// and the pool accounting of the credential carriers a command authorization slot's <c>nonce</c> and <c>hmac</c>
/// are read into — the two fields of <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library Part 2, clause 10.13.2, Table
/// 153), held in the pooled <see cref="Tpm2bNonce"/> and <see cref="Tpm2bAuth"/> carriers the parse rents and the
/// request owns. Every proof drives the real wire through the production command path and reads real pool
/// telemetry (<see cref="MeteredHousePool"/>), never an internal hook.
/// </summary>
/// <remarks>
/// <para>
/// Three properties are separable and each is proved on its own here. The width rule for a SLOT CREDENTIAL: both
/// fields are <c>TPM2B_DIGEST</c>-typed, so a declared size past <c>sizeof(TPMU_HA)</c> is a marshalling refusal,
/// answered before the body-length check and before any authorization work, which is what keeps a malformed frame
/// away from the dictionary-attack counter. It is session-index-encoded, because the offending octets belong to a
/// numbered session.
/// </para>
/// <para>
/// The same width rule for a COMMAND PARAMETER: an <c>auth</c>, a <c>newAuth</c>, a <c>policyRef</c> or a nested
/// <c>TPMS_SENSITIVE_CREATE.userAuth</c> is the same structure with the same bound, so a declared size past it is
/// the same marshalling refusal — but BARE, because the octets belong to a parameter rather than to a session.
/// Each such gate is answered at the wire read, ahead of the rental whose carrier factory refuses the same bound
/// by throwing, so the rule holds at two layers; the command's own narrower per-entity rule (an authValue no
/// wider than the digest of the entity's Name algorithm, or of the context integrity digest for a hierarchy)
/// stays where it is, on the installing transition, and is a SECOND refusal that a value inside the structural
/// bound can still meet. The proofs pair each over-wide frame with an otherwise identical admissible one, so a
/// refusal can only be attributed to the width.
/// </para>
/// <para>
/// The accounting: the carriers are rented as the parse's LAST act, so a parse refused on a wire check rents
/// nothing at all, and every path out of the command — refused at entry, refused on an HMAC mismatch, refused at
/// the continuation, or accepted — returns both of them exactly once, the hmac at the accepting continuation and
/// the caller nonce through the response framing it transferred into.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSessionCredentialCarrierTests
{
    /// <summary>The session and Name hash algorithm every command here uses.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The Index the owner-authorized proofs read and write.</summary>
    private const uint OwnerIndexHandle = 0x0100_0081;

    /// <summary>The Index whose own authValue authorizes it, and which is dictionary-attack PROTECTED.</summary>
    private const uint DaProtectedIndexHandle = 0x0100_0082;

    /// <summary>The Index the counter proof increments.</summary>
    private const uint CounterIndexHandle = 0x0100_0083;

    /// <summary>The Index handle no proof ever defines, so naming it is refused at the entry transition.</summary>
    private const uint UndefinedIndexHandle = 0x0100_0089;

    /// <summary>The Index handle the parameter-width proofs define, so their admissible rung has an Index of its own.</summary>
    private const uint WidthProbeIndexHandle = 0x0100_008A;

    /// <summary>The declared data area width of every ordinary Index these proofs define.</summary>
    private const ushort IndexDataSize = 8;

    /// <summary>The declared data area width of a counter Index (Part 2, clause 13.2's 8-octet counter).</summary>
    private const ushort CounterDataSize = 8;

    /// <summary>A caller-authorized, dictionary-attack-PROTECTED Index: a failed authorization charges the counter.</summary>
    private const TpmaNv DaProtectedAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE;

    /// <summary>An Index the owner writes and the Index's OWN authValue reads, dictionary-attack exempt.</summary>
    private const TpmaNv OwnerAuthorizedAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>An owner-authorized, dictionary-attack-exempt counter Index.</summary>
    private const TpmaNv OwnerCounterAttributes =
        TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << 4);

    /// <summary>The octets every proof writes into an Index's data area.</summary>
    private static byte[] IndexData { get; } = [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48];

    /// <summary>The authorization value the password proof's Index carries, so its credential is a real rental rather than the shared empty carrier.</summary>
    private static byte[] IndexAuthValue { get; } = [0x91, 0x92, 0x93, 0x94, 0x95, 0x96];

    /// <summary>
    /// A well-formed but wrong session credential, wide enough that no proof relying on it can fall into the
    /// No-HMAC-Authorization case. Every octet is non-zero: trailing zeros are removed from any value used as an
    /// authorization secret (TPM 2.0 Library Part 1, clause 17.6.4.3), so an all-zero credential of this width
    /// strips to nothing and would stand in for the Empty Buffer rather than for a wrong value.
    /// </summary>
    private static byte[] WrongCredential { get; } = [
        0xA3, 0x5C, 0x17, 0xE9, 0x2B, 0x74, 0xC8, 0x61, 0x0D, 0xF2, 0x49, 0x86, 0xBD, 0x33, 0x7A, 0x15,
        0xCE, 0x68, 0x91, 0x22, 0xAF, 0x4D, 0x70, 0xEB, 0x59, 0x36, 0x82, 0xC4, 0x1B, 0xA7, 0x6F, 0xD0];

    /// <summary>
    /// An authorization value one octet past <c>sizeof(TPMU_HA)</c> — the smallest value no <c>TPM2B_AUTH</c> can
    /// carry at all, whatever entity it is offered to. Every octet is non-zero so that no trailing-zero removal
    /// (TPM 2.0 Library Part 1, clause 17.6.4.3) could shorten it.
    /// </summary>
    private static byte[] PastBoundAuthValue { get; } = FilledNonZero(Tpm2bAuth.MaxSize + 1);

    /// <summary>
    /// An authorization value the structural bound admits and every entity in these proofs admits too: exactly the
    /// SHA-256 digest width, which is both the Name algorithm's digest for every Index defined here and the
    /// context integrity digest a hierarchy's authorization value is bounded by (Part 1, clause 17.6.4.2).
    /// </summary>
    private static byte[] AdmissibleAuthValue { get; } = FilledNonZero(32);

    /// <summary>The count of leading non-zero octets the trailing-zero probe carries, chosen to survive both bounds once the zeros are removed.</summary>
    private const int TrailingZeroProbeSignificantLength = 24;

    /// <summary>The octets a trailing-zero removal would leave of <see cref="PastBoundAuthValueWithTrailingZeros"/>.</summary>
    private static byte[] TrailingZeroProbeSignificantOctets { get; } = FilledNonZero(TrailingZeroProbeSignificantLength);

    /// <summary>
    /// A declared authorization value past <c>sizeof(TPMU_HA)</c> whose trailing octets are zero: the leading 24
    /// are non-zero and the remaining 46 are zero, so a TPM that removed trailing zeros BEFORE bounding the
    /// declared size would see an admissible 24-octet value and accept it.
    /// </summary>
    private static byte[] PastBoundAuthValueWithTrailingZeros { get; } = BuildTrailingZeroProbe();

    /// <summary>The secret the sealed-object proofs place in <c>TPMS_SENSITIVE_CREATE.data</c>.</summary>
    private static byte[] SealedSecret { get; } = [0x73, 0x65, 0x61, 0x6C, 0x65, 0x64];

    /// <summary>A replacement authorization value wider than the context-integrity digest and with no trailing zeros to strip.</summary>
    private static byte[] OverWideHierarchyAuth { get; } = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The <c>hmac</c> field of a command authorization slot is a <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 2,
    /// clause 10.13.2, Table 153), which Table 95 types as a <c>TPM2B_DIGEST</c> and clause 10.4.2, Table 92
    /// bounds at <c>sizeof(TPMU_HA)</c> with the response code stated in the clause itself: "As with all sized
    /// buffers, the size is checked to see if it is within the prescribed range. If not, the response code is
    /// TPM_RC_SIZE". Three rungs prove both the bound and its ORDER against the body-length check: the bound
    /// itself is admitted and reaches the credential compare, one octet past it is <c>TPM_RC_SIZE</c> with the
    /// octets present, and one octet past it is STILL <c>TPM_RC_SIZE</c> — never <c>TPM_RC_INSUFFICIENT</c> —
    /// when the command cannot even carry them. The refusal is session-index-encoded (Part 2, clause 6.6.2),
    /// because the offending octets belong to a numbered session rather than to a command parameter.
    /// </summary>
    [TestMethod]
    public async Task AnOverWideSlotHmacIsRefusedAsASizeErrorAndChargesNoDictionaryAttackCounter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-hmacwidth").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        _ = await DefineIndexAsync(tpm, registry, pool, DaProtectedIndexHandle, DaProtectedAttributes, IndexData).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.Dispose();

        TpmResult<TpmDictionaryAttackParameters> before = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);

        //Rung 1: the bound itself. A 64-octet credential is a well-formed TPM2B_AUTH, so the frame passes the
        //width rule and the value is compared — and, being wrong, fails the session's command HMAC.
        TpmRcConstants atBound = await SubmitNvReadWithSlotAsync(
            simulator, pool, sessionHandle, DaProtectedIndexHandle,
            nonceOctets: [], declaredHmacSize: Tpm2bAuth.MaxSize, hmacOctets: new byte[Tpm2bAuth.MaxSize]).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), atBound,
            "A credential exactly at sizeof(TPMU_HA) is well formed, so it reaches the compare and fails there rather than at the wire read.");

        TpmResult<TpmDictionaryAttackParameters> afterCompare = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            before.Value.LockoutCounter + 1, afterCompare.Value.LockoutCounter,
            "A well-formed but wrong credential against a dictionary-attack-protected Index charges the counter once (Part 1, clause 17.8.1).");

        //Rung 2: one octet past the bound, with every declared octet actually present.
        TpmRcConstants pastBound = await SubmitNvReadWithSlotAsync(
            simulator, pool, sessionHandle, DaProtectedIndexHandle,
            nonceOctets: [], declaredHmacSize: Tpm2bAuth.MaxSize + 1, hmacOctets: new byte[Tpm2bAuth.MaxSize + 1]).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_SIZE, sessionIndex: 0), pastBound,
            "A declared hmac size past sizeof(TPMU_HA) is a marshalling refusal, session-index-encoded to the slot it names.");

        //Rung 3: one octet past the bound, with the body absent. The width rule runs FIRST, so this is still a
        //size error and never the truncation code the body-length check would answer.
        TpmRcConstants pastBoundTruncated = await SubmitNvReadWithSlotAsync(
            simulator, pool, sessionHandle, DaProtectedIndexHandle,
            nonceOctets: [], declaredHmacSize: Tpm2bAuth.MaxSize + 1, hmacOctets: new byte[4]).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_SIZE, sessionIndex: 0), pastBoundTruncated,
            "The width rule precedes the body-length check, so an over-wide size the command cannot carry is TPM_RC_SIZE, not TPM_RC_INSUFFICIENT.");

        TpmResult<TpmDictionaryAttackParameters> after = await tpm.GetDictionaryAttackParametersAsync(
            pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            afterCompare.Value.LockoutCounter, after.Value.LockoutCounter,
            "A malformed credential is refused at the wire read, so neither over-wide frame may reach an authorization outcome or move the failure counter.");

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The <c>nonce</c> field of the same slot is a <c>TPM2B_NONCE</c> (TPM 2.0 Library Part 2, clause 10.13.2,
    /// Table 153), which Table 94 types as a <c>TPM2B_DIGEST</c> and clause 10.4.2, Table 92 bounds at
    /// <c>sizeof(TPMU_HA)</c>, so it takes the identical three-rung rule and the identical session-index-encoded
    /// <c>TPM_RC_SIZE</c>.
    /// </summary>
    [TestMethod]
    public async Task AnOverWideSlotNonceIsRefusedAsASizeErrorAheadOfTheBodyLengthCheck()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-noncewidth").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        _ = await DefineIndexAsync(tpm, registry, pool, DaProtectedIndexHandle, DaProtectedAttributes, IndexData).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.Dispose();

        //The credential is deliberately non-empty: an empty session key, an empty entity authValue and an empty
        //credential together are the No-HMAC-Authorization case (TPM 2.0 Library Part 1, clause 17.6.6), which
        //authorizes rather than failing, and would prove nothing about the nonce's own width rule.
        TpmRcConstants atBound = await SubmitNvReadWithSlotAsync(
            simulator, pool, sessionHandle, DaProtectedIndexHandle,
            nonceOctets: new byte[Tpm2bNonce.MaxSize], declaredHmacSize: WrongCredential.Length, hmacOctets: WrongCredential).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, sessionIndex: 0), atBound,
            "A caller nonce exactly at sizeof(TPMU_HA) is well formed, so the frame reaches the credential compare.");

        TpmRcConstants pastBound = await SubmitNvReadWithSlotAsync(
            simulator, pool, sessionHandle, DaProtectedIndexHandle,
            nonceOctets: new byte[Tpm2bNonce.MaxSize + 1], declaredHmacSize: WrongCredential.Length, hmacOctets: WrongCredential).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_SIZE, sessionIndex: 0), pastBound,
            "A declared nonce size past sizeof(TPMU_HA) is a marshalling refusal, session-index-encoded to the slot it names.");

        TpmRcConstants pastBoundTruncated = await SubmitNvReadWithSlotAsync(
            simulator, pool, sessionHandle, DaProtectedIndexHandle,
            nonceOctets: new byte[Tpm2bNonce.MaxSize + 1], declaredHmacSize: WrongCredential.Length, hmacOctets: WrongCredential, truncateNonceBody: true).ConfigureAwait(false);
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_SIZE, sessionIndex: 0), pastBoundTruncated,
            "The width rule precedes the body-length check for the nonce exactly as it does for the hmac.");

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The credential carriers are rented as the parse's LAST act, after every wire check has passed, so a
    /// <c>TPM2_NV_Read()</c> refused on a trailing octet no parameter accounts for (TPM 2.0 Library Part 3,
    /// clause 5.2) leaves nothing outstanding at all.
    /// </summary>
    [TestMethod]
    public async Task NvReadOverSessionRefusedAtTheParseRentsNoCredentialCarriers()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-parse").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        _ = await DefineIndexAsync(tpm, registry, pool, DaProtectedIndexHandle, DaProtectedAttributes, IndexData).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        session.Dispose();

        long baseline = trackingPool.OutstandingCount;

        var body = new List<byte>();
        AppendUInt32(body, DaProtectedIndexHandle);
        AppendUInt32(body, DaProtectedIndexHandle);
        AppendAuthorizationArea(body, sessionHandle, nonceOctets: new byte[8], declaredHmacSize: 8, hmacOctets: new byte[8]);
        AppendUInt16(body, IndexDataSize);
        AppendUInt16(body, 0);
        body.Add(0xFF);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_Read, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, code,
            "An octet no parameter accounts for is TPM_RC_SIZE at the wire read (Part 3, clause 5.2).");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "Both credential carriers are rented as the parse's last act, so a parse refused on a later wire check must rent neither.");

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_NV_Read()</c> over an HMAC session returns both slot credentials on all three of its exit paths:
    /// refused at the entry transition (an Index that is not defined, <c>TPM_RC_HANDLE</c>), refused on a
    /// command-HMAC mismatch, and accepted — the accepting continuation being the hmac's terminal owner and the
    /// response framing the caller nonce's.
    /// </summary>
    [TestMethod]
    public async Task NvReadOverSessionReturnsBothSlotCredentialsOnEveryPath()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-nvread").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        byte[] indexName = await DefineIndexAsync(tpm, registry, pool, DaProtectedIndexHandle, DaProtectedAttributes, IndexData).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                var input = new NvReadInput(AuthHandle: UndefinedIndexHandle, NvIndex: UndefinedIndexHandle, Size: IndexDataSize, Offset: 0);
                TpmResult<NvReadResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    tpm, input, [session], [indexName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "Reading an Index that was never defined must be refused.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A command refused at its entry transition releases both credentials through the request's own Dispose.");

            {
                byte[] wrongName = new byte[indexName.Length];
                indexName.CopyTo(wrongName, 0);
                wrongName[^1] ^= 0xFF;

                var input = new NvReadInput(AuthHandle: DaProtectedIndexHandle, NvIndex: DaProtectedIndexHandle, Size: IndexDataSize, Offset: 0);
                TpmResult<NvReadResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    tpm, input, [session], [wrongName, wrongName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "A command HMAC computed over the wrong Name must not authorize.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A command-HMAC mismatch releases both credentials through the whole-request release the shared verification arm already performs.");

            {
                var input = new NvReadInput(AuthHandle: DaProtectedIndexHandle, NvIndex: DaProtectedIndexHandle, Size: IndexDataSize, Offset: 0);
                TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    tpm, input, [session], [indexName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Read over an HMAC session failed: '{result.ResponseCode}'.");
                result.Value.Dispose();
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "On the accepted path the continuation releases the hmac and the response framing releases the caller nonce it transferred into.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The remaining session-authorized NV arms — <c>TPM2_NV_Increment()</c> (Part 3, clause 31.8) and
    /// <c>TPM2_NV_UndefineSpace()</c> (clause 31.4) — return both slot credentials across a refusal taken at the
    /// entry transition and an accepted round trip, the undefine being the arm whose accepted path ends the
    /// Index's own lifetime as well.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementAndNvUndefineSpaceOverSessionsReturnBothSlotCredentials()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-nvcounter").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        byte[] ownerName = HandleFormName((uint)TpmRh.TPM_RH_OWNER);
        byte[] counterName = await DefineCounterAsync(tpm, registry, pool, CounterIndexHandle).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                var input = new NvIncrementInput((uint)TpmRh.TPM_RH_OWNER, UndefinedIndexHandle);
                TpmResult<NvIncrementResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
                    tpm, input, [session], [ownerName, ownerName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsFalse(refused.IsSuccess, "Incrementing an Index that was never defined must be refused.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "An increment refused at its entry transition releases both credentials through the request's own Dispose.");

            {
                var input = new NvIncrementInput((uint)TpmRh.TPM_RH_OWNER, CounterIndexHandle);
                TpmResult<NvIncrementResponse> result = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
                    tpm, input, [session], [ownerName, counterName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Increment over an HMAC session failed: '{result.ResponseCode}'.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The accepted increment releases the hmac at its continuation and the caller nonce through the response framing.");

            //The first increment SETs TPMA_NV_WRITTEN, which is part of the public area the Name digests (Part 1,
            //clause 35.2.6.3), so cpHash's Name2 term for the undefine is the POST-increment Name.
            counterName = await ReadNameAsync(tpm, registry, pool, CounterIndexHandle).ConfigureAwait(false);

            {
                var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, CounterIndexHandle);
                TpmResult<NvUndefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
                    tpm, input, [session], [ownerName, counterName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_NV_UndefineSpace over an HMAC session failed: '{result.ResponseCode}'.");
            }

            Assert.AreEqual(
                baseline - 1, trackingPool.OutstandingCount,
                "Undefining releases the Index's own authValue carrier as well as both slot credentials, so the count falls by exactly that one.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// The hierarchy family shares one authorization helper and one response framing, so
    /// <c>TPM2_HierarchyControl()</c> (TPM 2.0 Library Part 3, clause 24.2) and
    /// <c>TPM2_SetPrimaryPolicy()</c> (clause 24.3) stand for it here: both return their slot credentials across
    /// a refusal taken at the continuation AFTER the command HMAC has verified — the wrong authority for an
    /// enable, and a policy digest inconsistent with its algorithm — and across an accepted round trip.
    /// </summary>
    [TestMethod]
    public async Task HierarchyCommandsOverSessionsReturnBothSlotCredentials()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-hierarchy").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        byte[] ownerName = HandleFormName((uint)TpmRh.TPM_RH_OWNER);
        byte[] platformName = HandleFormName((uint)TpmRh.TPM_RH_PLATFORM);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                //The owner hierarchy may not write the platform enables (clause 24.2.1), and the refusal lands
                //at the continuation, after the command HMAC has already verified.
                var input = new HierarchyControlInput(TpmRh.TPM_RH_OWNER, TpmRh.TPM_RH_PLATFORM, TpmiYesNo.No);
                TpmResult<HierarchyControlResponse> refused = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
                    tpm, input, [session], [ownerName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_AUTH_TYPE, refused.ResponseCode,
                    "Only platformAuth may write a platform enable (Part 3, clause 24.2.1).");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A hierarchy command refused at its continuation releases both credentials through the request's own Dispose.");

            {
                var input = new HierarchyControlInput(TpmRh.TPM_RH_PLATFORM, TpmRh.TPM_RH_ENDORSEMENT, TpmiYesNo.No);
                TpmResult<HierarchyControlResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyControlResponse>(
                    tpm, input, [session], [platformName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyControl over an HMAC session failed: '{result.ResponseCode}'.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The accepted hierarchy control releases the hmac at its continuation and the caller nonce through the shared response framing.");

            {
                //A non-empty policy digest offered with TPM_ALG_NULL is inconsistent (clause 24.3.1), refused
                //at the continuation after the HMAC has verified.
                using Tpm2bDigest mismatched = Tpm2bDigest.Create(new byte[32], pool);
                using var input = new SetPrimaryPolicyInput(TpmRh.TPM_RH_PLATFORM, mismatched, TpmAlgIdConstants.TPM_ALG_NULL);
                TpmResult<SetPrimaryPolicyResponse> refused = await TpmCommandExecutor.ExecuteAsync<SetPrimaryPolicyResponse>(
                    tpm, input, [session], [platformName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SIZE, refused.ResponseCode,
                    "A policy digest whose size disagrees with hashAlg is TPM_RC_SIZE (Part 3, clause 24.3.1).");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A policy install refused at its continuation releases both credentials with the policy carrier it also owns.");

            {
                using Tpm2bDigest policy = Tpm2bDigest.Create(new byte[32], pool);
                using var input = new SetPrimaryPolicyInput(TpmRh.TPM_RH_PLATFORM, policy, SessionAlg);
                TpmResult<SetPrimaryPolicyResponse> result = await TpmCommandExecutor.ExecuteAsync<SetPrimaryPolicyResponse>(
                    tpm, input, [session], [platformName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_SetPrimaryPolicy over an HMAC session failed: '{result.ResponseCode}'.");
            }

            Assert.AreEqual(
                baseline + 1, trackingPool.OutstandingCount,
                "The accepted policy install transfers its policy digest into durable hierarchy state and releases both slot credentials.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPM2_HierarchyChangeAuth()</c> over an HMAC session (TPM 2.0 Library Part 3, clause 24.8) is the arm
    /// whose response HMAC is keyed on the NEW authorization value, so its caller nonce transfers into a
    /// response-session ENTRY rather than into the shared framing action; both credentials are still returned
    /// exactly once, across a refusal taken at the size gate and an accepted rotation.
    /// </summary>
    [TestMethod]
    public async Task HierarchyChangeAuthOverSessionReturnsBothSlotCredentials()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-changeauth").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        byte[] endorsementName = HandleFormName((uint)TpmRh.TPM_RH_ENDORSEMENT);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(tpm, registry, pool).ConfigureAwait(false);
        using(session)
        {
            long baseline = trackingPool.OutstandingCount;

            {
                //A hierarchy has no Name algorithm, so its authValue is bounded by the context-integrity digest
                //size (clause 17.6.4.2), and a longer one is refused after the HMAC has verified. The bound is
                //measured on the trailing-zero-STRIPPED value (clause 17.6.4.3), so the replacement carries no
                //trailing zeros: a padded one would strip back under the bound and be accepted.
                using Tpm2bAuth tooLong = Tpm2bAuth.Create(OverWideHierarchyAuth, pool);
                using var input = new HierarchyChangeAuthInput(TpmRh.TPM_RH_ENDORSEMENT, tooLong);
                TpmResult<HierarchyChangeAuthResponse> refused = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
                    tpm, input, [session], [endorsementName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(
                    TpmRcConstants.TPM_RC_SIZE, refused.ResponseCode,
                    "An authValue wider than the context-integrity digest is TPM_RC_SIZE (Part 3, clause 24.8.1).");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "A rotation refused at its size gate releases both credentials with the parsed replacement value.");

            {
                //The replacement is the Empty Buffer, which is what makes the accepted leg checkable from the
                //host at all: "The HMAC in the response shall use the new authorization value when computing the
                //response HMAC" (Part 3, clause 24.8.1), and a host that rotated to a value its session does not
                //carry could not verify the response it gets back.
                using var input = new HierarchyChangeAuthInput(TpmRh.TPM_RH_ENDORSEMENT, Tpm2bAuth.Empty);
                TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
                    tpm, input, [session], [endorsementName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(result.IsSuccess, $"TPM2_HierarchyChangeAuth over an HMAC session failed: '{result.ResponseCode}'.");
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The accepted rotation releases both slot credentials: the hmac at the completing tail and the caller nonce through the response entry it transferred into.");
        }

        await FlushAsync(tpm, registry, pool, sessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// A <c>TPM_RS_PW</c> slot carries its plaintext authorization value in the SAME <c>hmac</c> field a real
    /// session carries an HMAC in — "either an HMAC, a password, or an EmptyAuth" (TPM 2.0 Library Part 2,
    /// clause 10.13.2, Table 153) — so the password form rents the same kind of carrier and returns it on both
    /// a refused and an accepted round trip.
    /// </summary>
    [TestMethod]
    public async Task PasswordAuthorizedNvReadReturnsItsSuppliedCredentialCarrier()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-password").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        //The Index carries a real authValue, so the credential the parse rents is a genuine pooled rental rather
        //than the shared dispose-immune empty carrier a proof could not observe a leak through.
        _ = await DefineIndexAsync(tpm, registry, pool, OwnerIndexHandle, OwnerAuthorizedAttributes, IndexData, IndexAuthValue).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        {
            using TpmPasswordSession wrong = TpmPasswordSession.Create([0x01, 0x02, 0x03], pool);
            var input = new NvReadInput(AuthHandle: OwnerIndexHandle, NvIndex: OwnerIndexHandle, Size: IndexDataSize, Offset: 0);
            TpmResult<NvReadResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                tpm, input, [wrong], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(
                TpmRcConstants.TPM_RC_BAD_AUTH, refused.ResponseCode,
                "A wrong authValue against a dictionary-attack-EXEMPT Index is a plain bad-authorization (Part 1, clause 17.8.1).");
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "A password-authorized read refused on the compare releases the supplied credential through the request's own Dispose.");

        {
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(IndexAuthValue, pool);
            var input = new NvReadInput(AuthHandle: OwnerIndexHandle, NvIndex: OwnerIndexHandle, Size: IndexDataSize, Offset: 0);
            TpmResult<NvReadResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                tpm, input, [indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"Password-authorized TPM2_NV_Read failed: '{result.ResponseCode}'.");
            result.Value.Dispose();
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The authorizing transition is the supplied credential's terminal owner on the accepted path too.");
    }

    /// <summary>
    /// <c>TPM2_NV_DefineSpace()</c>'s <c>auth</c> parameter is a <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 3, clause
    /// 31.3.2, Table 235), which Table 95 types as a <c>TPM2B_DIGEST</c> and clause 10.4.2, Table 92 bounds at
    /// <c>sizeof(TPMU_HA)</c> with the response code the clause itself names: "As with all sized buffers, the size
    /// is checked to see if it is within the prescribed range. If not, the response code is TPM_RC_SIZE". One
    /// octet past the bound is that refusal, answered BARE because the octets belong to a command parameter rather
    /// than to a numbered session, and answered at the wire read — so no carrier is rented for the refused frame
    /// at all. The admissible rung is the same frame with a value the bound holds, which the command accepts, so
    /// the refusal above can be attributed to the declared width and to nothing else in the frame.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceWithAnIndexAuthPastTheUnionBoundIsRefusedAtTheWireReadWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-defineauthwidth").ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants refused = await SubmitNvDefineSpaceWithAuthAsync(
            simulator, pool, WidthProbeIndexHandle, PastBoundAuthValue).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, refused,
            "An auth parameter declaring a size past sizeof(TPMU_HA) is a marshalling refusal, answered bare because the octets belong to a parameter.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal precedes every rental this parse performs, so a frame refused on the width rents nothing at all.");

        TpmRcConstants accepted = await SubmitNvDefineSpaceWithAuthAsync(
            simulator, pool, WidthProbeIndexHandle, AdmissibleAuthValue).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, accepted,
            "The identical frame with an admissible auth value defines the Index, so only the declared width refused the first one.");
    }

    /// <summary>
    /// <c>TPM2_HierarchyChangeAuth()</c>'s <c>newAuth</c> parameter is a <c>TPM2B_AUTH</c> (TPM 2.0 Library Part 3,
    /// clause 24.8.2, Table 188) and carries the identical <c>sizeof(TPMU_HA)</c> bound and the identical bare
    /// <c>TPM_RC_SIZE</c> (Part 2, clause 10.4.5, Table 95 over clause 10.4.2, Table 92) on the plain password
    /// form. The admissible rung sends exactly the context integrity digest width the command's own per-entity
    /// rule allows a hierarchy (clause 24.8.1; Part 1, clause 17.6.4.2), which rotates — so the two refusals are
    /// separable: one is the structure's, one is the command's, and this proves the structure's own.
    /// </summary>
    [TestMethod]
    public async Task HierarchyChangeAuthWithAReplacementAuthPastTheUnionBoundIsRefusedAtTheWireReadWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-changeauthwidth").ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants refused = await SubmitHierarchyChangeAuthAsync(
            simulator, pool, currentAuth: [], newAuth: PastBoundAuthValue).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, refused,
            "A newAuth parameter declaring a size past sizeof(TPMU_HA) is a bare marshalling refusal.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal precedes every rental this parse performs, so a frame refused on the width rents nothing at all.");

        TpmRcConstants accepted = await SubmitHierarchyChangeAuthAsync(
            simulator, pool, currentAuth: [], newAuth: AdmissibleAuthValue).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, accepted,
            "The identical frame with a value the hierarchy's own bound admits rotates, so only the declared width refused the first one.");
    }

    /// <summary>
    /// The declared size is bounded BEFORE any trailing-zero removal, which is what keeps the strip from rescuing
    /// a structure no <c>TPM2B_AUTH</c> could hold. The reference bounds the declared size while unmarshalling the
    /// structure (<c>TPM2B_DIGEST_Unmarshal</c> compares the declared size against <c>sizeof(TPMU_HA)</c>) and
    /// removes trailing octets of zero only far later, in <c>MemoryRemoveTrailingZeros</c>, where the value is
    /// USED as an authorization secret (TPM 2.0 Library Part 1, clause 17.6.4.3). The probe makes the two orders
    /// answer differently: 70 declared octets
    /// whose trailing 46 are zero strip back to an admissible 24, so a TPM that stripped first would accept them —
    /// and the admissible rung sends exactly those 24 octets and IS accepted, so the refusal above is the declared
    /// width alone.
    /// </summary>
    [TestMethod]
    public async Task ADeclaredReplacementAuthPastTheBoundIsRefusedAheadOfAnyTrailingZeroRemoval()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-trailingzero").ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants refused = await SubmitHierarchyChangeAuthAsync(
            simulator, pool, currentAuth: [], newAuth: PastBoundAuthValueWithTrailingZeros).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, refused,
            "A declared size past sizeof(TPMU_HA) is refused as declared: the trailing zeros are not removed before the structure is bounded.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal precedes every rental this parse performs, so a frame refused on the width rents nothing at all.");

        TpmRcConstants accepted = await SubmitHierarchyChangeAuthAsync(
            simulator, pool, currentAuth: [], newAuth: TrailingZeroProbeSignificantOctets).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, accepted,
            "The very octets the strip would have left are accepted on their own, so the first frame was refused for its declared width and not for its content.");
    }

    /// <summary>
    /// <c>TPM2_PolicySecret()</c>'s <c>policyRef</c> parameter is a <c>TPM2B_NONCE</c> (TPM 2.0 Library Part 3,
    /// clause 23.4.2, Table 149), which Table 94 types as a <c>TPM2B_DIGEST</c> and clause 10.4.2, Table 92 bounds
    /// at <c>sizeof(TPMU_HA)</c>, so a declared size past the bound is the same bare <c>TPM_RC_SIZE</c> the
    /// authorization-value parameters answer. The assertion is driven over a TRIAL policy session, which computes
    /// the policy digest without authorizing anything, so the admissible rung folds a real assertion and returns
    /// success rather than depending on a satisfied policy elsewhere.
    /// </summary>
    [TestMethod]
    public async Task PolicySecretWithAPolicyReferencePastTheUnionBoundIsRefusedAtTheWireReadWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool, "tpm-credential-policyrefwidth").ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        uint trialSessionHandle = await StartTrialPolicySessionAsync(tpm, registry, pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants refused = await SubmitPolicySecretAsync(
            simulator, pool, trialSessionHandle, PastBoundAuthValue).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, refused,
            "A policyRef declaring a size past sizeof(TPMU_HA) is a bare marshalling refusal.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal precedes every rental this parse performs, so a frame refused on the width rents nothing at all.");

        TpmRcConstants accepted = await SubmitPolicySecretAsync(
            simulator, pool, trialSessionHandle, AdmissibleAuthValue).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, accepted,
            "The identical frame with a policyRef the bound holds folds the assertion, so only the declared width refused the first one.");

        await FlushAsync(tpm, registry, pool, trialSessionHandle).ConfigureAwait(false);
    }

    /// <summary>
    /// <c>TPMS_SENSITIVE_CREATE.userAuth</c> is a <c>TPM2B_AUTH</c> nested inside <c>TPM2_Create()</c>'s
    /// <c>inSensitive</c> parameter (TPM 2.0 Library Part 2, clause 11.1.15, Table 168, page 166), so it carries
    /// the same <c>sizeof(TPMU_HA)</c> bound and the same bare <c>TPM_RC_SIZE</c> — answered by the structure
    /// parser itself, whose only refusal channel is a throw the parse converts, since an unmarshalling error means
    /// no command processing occurs (Part 3, clause 5.8.2). The admissible rung sends the Name algorithm's own
    /// digest width, which the command's narrower per-entity rule also admits, and the object is created.
    /// </summary>
    [TestMethod]
    public async Task CreateWithASensitiveUserAuthPastTheUnionBoundIsRefusedAtTheWireReadWithSize()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(
            pool, "tpm-credential-userauthwidth", BouncyCastleTpmEccSigningBackend.Create()).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        uint parentHandle = parent.ObjectHandle.Value;

        long baseline = trackingPool.OutstandingCount;

        TpmRcConstants refused = await SubmitSealedCreateAsync(
            simulator, pool, parentHandle, PastBoundAuthValue).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SIZE, refused,
            "A nested userAuth declaring a size past sizeof(TPMU_HA) is a bare marshalling refusal.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal precedes every rental this parse performs, so a frame refused on the width rents nothing at all.");

        TpmRcConstants accepted = await SubmitSealedCreateAsync(
            simulator, pool, parentHandle, AdmissibleAuthValue).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS, accepted,
            "The identical frame with a userAuth the bound holds seals the object, so only the declared width refused the first one.");

        await FlushAsync(tpm, registry, pool, parentHandle).ConfigureAwait(false);
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

    /// <summary>Renders the session-index-encoded form of a format-one response code (Part 2, clause 6.6.2).</summary>
    /// <param name="baseRc">The bare response code.</param>
    /// <param name="sessionIndex">The offending session's zero-based index.</param>
    /// <returns>The session-index-encoded response code.</returns>
    private static TpmRcConstants SessionEncodedRc(TpmRcConstants baseRc, int sessionIndex) =>
        (TpmRcConstants)((uint)baseRc + (uint)TpmRcConstants.TPM_RC_S + (0x100u * (uint)(sessionIndex + 1)));

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

    /// <summary>
    /// Appends a one-session authorization area whose <c>nonce</c> and <c>hmac</c> fields are written exactly as
    /// given, so a proof can declare a size the octets do not match (TPM 2.0 Library Part 2, clause 10.13.2,
    /// Table 153).
    /// </summary>
    /// <param name="body">The body being built.</param>
    /// <param name="sessionHandle">The session handle to name.</param>
    /// <param name="nonceOctets">The caller-nonce octets to write; their count is the declared size unless <paramref name="truncateNonceBody"/> is set.</param>
    /// <param name="declaredHmacSize">The size to declare for the hmac field.</param>
    /// <param name="hmacOctets">The hmac octets actually written.</param>
    /// <param name="truncateNonceBody">Whether to declare <paramref name="nonceOctets"/>'s count but write only four octets.</param>
    private static void AppendAuthorizationArea(
        List<byte> body, uint sessionHandle, byte[] nonceOctets, int declaredHmacSize, byte[] hmacOctets, bool truncateNonceBody = false)
    {
        var area = new List<byte>();
        AppendUInt32(area, sessionHandle);
        AppendUInt16(area, (ushort)nonceOctets.Length);
        area.AddRange(truncateNonceBody ? new byte[4] : nonceOctets);
        area.Add((byte)TpmaSession.CONTINUE_SESSION);
        AppendUInt16(area, (ushort)declaredHmacSize);
        area.AddRange(hmacOctets);

        AppendUInt32(body, (uint)area.Count);
        body.AddRange(area);
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_NV_Read()</c> whose single authorization slot carries the given credential fields
    /// and submits it, so a proof can present a slot no production session builder would produce.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="sessionHandle">The authorizing session handle.</param>
    /// <param name="nvIndex">The Index to read (also the authorization handle).</param>
    /// <param name="nonceOctets">The caller-nonce octets.</param>
    /// <param name="declaredHmacSize">The size declared for the hmac field.</param>
    /// <param name="hmacOctets">The hmac octets actually written.</param>
    /// <param name="truncateNonceBody">Whether to declare the nonce's full width but write only four octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitNvReadWithSlotAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint sessionHandle, uint nvIndex,
        byte[] nonceOctets, int declaredHmacSize, byte[] hmacOctets, bool truncateNonceBody = false)
    {
        var body = new List<byte>();
        AppendUInt32(body, nvIndex);
        AppendUInt32(body, nvIndex);
        AppendAuthorizationArea(body, sessionHandle, nonceOctets, declaredHmacSize, hmacOctets, truncateNonceBody);
        AppendUInt16(body, IndexDataSize);
        AppendUInt16(body, 0);

        return await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_Read, [.. body]).ConfigureAwait(false);
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

    /// <summary>
    /// Defines an Index with the given attributes under empty owner authorization, optionally writes it, and
    /// returns its Name read back from the TPM (<c>TPMA_NV_WRITTEN</c> is part of the public area the Name
    /// digests, so a Name taken before the write would no longer name the Index).
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index attributes.</param>
    /// <param name="data">Octets to write into the Index, or <see langword="null"/> to leave it unwritten.</param>
    /// <param name="indexAuth">The authorization value to assign to the Index, or <see langword="null"/> for the Empty Buffer.</param>
    /// <returns>The defined Index's Name.</returns>
    private async Task<byte[]> DefineIndexAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex, TpmaNv attributes, byte[]? data, byte[]? indexAuth = null)
    {
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, attributes, policyDigest, IndexDataSize);
        using Tpm2bAuth assignedAuth = indexAuth is null ? Tpm2bAuth.Empty : Tpm2bAuth.Create(indexAuth, pool);

        {
            using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, assignedAuth, publicInfo);
            using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
                tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace failed: '{result.ResponseCode}'.");
        }

        if(data is not null)
        {
            bool isOwnerWrite = (attributes & TpmaNv.TPMA_NV_OWNERWRITE) != 0;
            using Tpm2bMaxNvBuffer inputBuffer = Tpm2bMaxNvBuffer.Create(data, pool);
            var input = new NvWriteInput(isOwnerWrite ? (uint)TpmRh.TPM_RH_OWNER : nvIndex, nvIndex, inputBuffer, Offset: 0);
            using TpmPasswordSession writeAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                tpm, input, [writeAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Write failed: '{result.ResponseCode}'.");
        }

        return await ReadNameAsync(tpm, registry, pool, nvIndex).ConfigureAwait(false);
    }

    /// <summary>
    /// Defines an owner-authorized counter Index (<c>TPM_NT_COUNTER</c>, TPM 2.0 Library Part 2, clause 13.2)
    /// and returns its Name.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <returns>The defined Index's Name.</returns>
    private async Task<byte[]> DefineCounterAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using TpmsNvPublic publicInfo = new(nvIndex, SessionAlg, OwnerCounterAttributes, policyDigest, CounterDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, Tpm2bAuth.Empty, publicInfo);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_DefineSpace (counter) failed: '{result.ResponseCode}'.");

        return await ReadNameAsync(tpm, registry, pool, nvIndex).ConfigureAwait(false);
    }

    /// <summary>Reads an Index's computed Name back from the TPM.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index whose Name is wanted.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ReadNameAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint nvIndex)
    {
        var readPublicInput = new NvReadPublicInput(nvIndex);
        TpmResult<NvReadPublicResponse> readPublic = await TpmCommandExecutor.ExecuteAsync<NvReadPublicResponse>(
            tpm, readPublicInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(readPublic.IsSuccess, $"TPM2_NV_ReadPublic failed: '{readPublic.ResponseCode}'.");

        using NvReadPublicResponse publicArea = readPublic.Value;

        return publicArea.NvName.Span.ToArray();
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

    /// <summary>Appends a TPM2B field: a big-endian <c>UINT16</c> size prefix followed by exactly those octets.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="octets">The field's octets; their count is the declared size.</param>
    private static void AppendTpm2b(List<byte> body, byte[] octets)
    {
        AppendUInt16(body, (ushort)octets.Length);
        body.AddRange(octets);
    }

    /// <summary>
    /// Appends an authorization area of exactly one <c>TPM_RS_PW</c> slot carrying the given plaintext
    /// authorization value in the <c>hmac</c> field, with the empty nonce and the <c>continueSession</c>
    /// attribute a password slot owes (TPM 2.0 Library Part 1, clause 16.6.4, Table 12).
    /// </summary>
    /// <param name="body">The body being built.</param>
    /// <param name="suppliedAuth">The authorization value the slot presents.</param>
    private static void AppendPasswordAuthorizationArea(List<byte> body, byte[] suppliedAuth)
    {
        AppendAuthorizationArea(body, (uint)TpmRh.TPM_RH_PW, nonceOctets: [], declaredHmacSize: suppliedAuth.Length, hmacOctets: suppliedAuth);
    }

    /// <summary>
    /// Appends a <c>TPM2B_NV_PUBLIC</c> wrapping a <c>TPMS_NV_PUBLIC</c> for an Index of
    /// <see cref="IndexDataSize"/> octets with no access policy (TPM 2.0 Library Part 2, clause 13.5, Table 234).
    /// </summary>
    /// <param name="body">The body being built.</param>
    /// <param name="nvIndex">The Index handle the public area names.</param>
    /// <param name="attributes">The Index attributes.</param>
    private static void AppendNvPublic(List<byte> body, uint nvIndex, TpmaNv attributes)
    {
        var publicArea = new List<byte>();
        AppendUInt32(publicArea, nvIndex);
        AppendUInt16(publicArea, (ushort)SessionAlg);
        AppendUInt32(publicArea, (uint)attributes);
        AppendUInt16(publicArea, 0);
        AppendUInt16(publicArea, IndexDataSize);

        AppendUInt16(body, (ushort)publicArea.Count);
        body.AddRange(publicArea);
    }

    /// <summary>Appends the sealed-data <c>TPM2B_PUBLIC</c> template these proofs create objects under, written by the production wire type itself.</summary>
    /// <param name="body">The body being built.</param>
    /// <param name="pool">The memory pool the marshalling scratch is rented from.</param>
    private static void AppendSealedDataTemplate(List<byte> body, BaseMemoryPool pool)
    {
        using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
        int length = template.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        template.WriteTo(ref writer);
        body.AddRange(owner.Memory.Span[..length]);
    }

    /// <summary>
    /// Hand-frames a password-authorized <c>TPM2_NV_DefineSpace()</c> whose <c>auth</c> parameter carries exactly
    /// the given octets and submits it, so a proof can declare a width no client-side factory would build.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="indexAuth">The authorization value assigned to the new Index.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitNvDefineSpaceWithAuthAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint nvIndex, byte[] indexAuth)
    {
        var body = new List<byte>();
        AppendUInt32(body, (uint)TpmRh.TPM_RH_OWNER);
        AppendPasswordAuthorizationArea(body, []);
        AppendTpm2b(body, indexAuth);
        AppendNvPublic(body, nvIndex, OwnerAuthorizedAttributes);

        return await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_DefineSpace, [.. body]).ConfigureAwait(false);
    }

    /// <summary>
    /// Hand-frames the plain password form of <c>TPM2_HierarchyChangeAuth()</c> for the endorsement hierarchy
    /// with a <c>newAuth</c> of exactly the given octets and submits it.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="currentAuth">The value the password slot presents as the hierarchy's current authorization value.</param>
    /// <param name="newAuth">The replacement value.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitHierarchyChangeAuthAsync(
        TpmSimulator simulator, BaseMemoryPool pool, byte[] currentAuth, byte[] newAuth)
    {
        var body = new List<byte>();
        AppendUInt32(body, (uint)TpmRh.TPM_RH_ENDORSEMENT);
        AppendPasswordAuthorizationArea(body, currentAuth);
        AppendTpm2b(body, newAuth);

        return await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_HierarchyChangeAuth, [.. body]).ConfigureAwait(false);
    }

    /// <summary>
    /// Hand-frames a <c>TPM2_PolicySecret()</c> against the owner hierarchy over a password slot, folding into the
    /// given policy session with a <c>policyRef</c> of exactly the given octets, and submits it.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="policySession">The policy session the assertion folds into.</param>
    /// <param name="policyRef">The policy reference octets.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitPolicySecretAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint policySession, byte[] policyRef)
    {
        var body = new List<byte>();
        AppendUInt32(body, (uint)TpmRh.TPM_RH_OWNER);
        AppendUInt32(body, policySession);
        AppendPasswordAuthorizationArea(body, []);
        AppendTpm2b(body, []);
        AppendTpm2b(body, []);
        AppendTpm2b(body, policyRef);
        AppendUInt32(body, 0);

        return await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_PolicySecret, [.. body]).ConfigureAwait(false);
    }

    /// <summary>
    /// Hand-frames the plain password form of <c>TPM2_Create()</c> sealing a fixed secret under a
    /// <c>userAuth</c> of exactly the given octets and submits it.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The loaded storage parent.</param>
    /// <param name="userAuth">The authorization value carried inside <c>inSensitive</c>.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSealedCreateAsync(
        TpmSimulator simulator, BaseMemoryPool pool, uint parentHandle, byte[] userAuth)
    {
        var sensitive = new List<byte>();
        AppendTpm2b(sensitive, userAuth);
        AppendTpm2b(sensitive, SealedSecret);

        var body = new List<byte>();
        AppendUInt32(body, parentHandle);
        AppendPasswordAuthorizationArea(body, []);
        AppendUInt16(body, (ushort)sensitive.Count);
        body.AddRange(sensitive);
        AppendSealedDataTemplate(body, pool);
        AppendUInt16(body, 0);
        AppendUInt32(body, 0);

        return await SubmitFramedAsync(simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_Create, [.. body]).ConfigureAwait(false);
    }

    /// <summary>Starts a trial policy session, which computes a policy digest without authorizing anything (TPM 2.0 Library Part 1, clause 17.7).</summary>
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

        return result.Value.SessionHandle.Value;
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

    /// <summary>
    /// Builds a value of the given width whose every octet is non-zero, so no trailing-zero removal (TPM 2.0
    /// Library Part 1, clause 17.6.4.3) can shorten it: the octets ascend from <c>0x11</c>, which stays clear of
    /// zero for every width these proofs use.
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

    /// <summary>
    /// Builds the trailing-zero probe: <see cref="TrailingZeroProbeSignificantLength"/> non-zero octets followed
    /// by zeros, declared six octets past <see cref="Tpm2bAuth.MaxSize"/> in total.
    /// </summary>
    /// <returns>The probe value.</returns>
    private static byte[] BuildTrailingZeroProbe()
    {
        byte[] value = new byte[Tpm2bAuth.MaxSize + 6];
        TrailingZeroProbeSignificantOctets.CopyTo(value, 0);

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
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_ReadPublic, TpmResponseCodec.NvReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement);
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyControl, TpmResponseCodec.HierarchyControl);
        _ = registry.Register(TpmCcConstants.TPM_CC_SetPrimaryPolicy, TpmResponseCodec.SetPrimaryPolicy);
        _ = registry.Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth);
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

        return registry;
    }

    /// <summary>Creates a simulator, powers it on, and brings it operational.</summary>
    /// <param name="pool">The memory pool every command runs against.</param>
    /// <param name="tpmId">The simulated TPM's run identifier, unique per test so no meter is shared.</param>
    /// <param name="signingBackend">The elliptic-curve backend key generation runs through, for the proofs that create a primary object; <see langword="null"/> for the proofs that create none, whose commands never reach it.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool, string tpmId, TpmEccSigningBackend? signingBackend = null)
    {
        var simulator = new TpmSimulator(tpmId, signingBackend: signingBackend);
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
