using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Extensions.Policy;
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
/// Drives the SECOND authorization slot of the four commands outside the attest family that admit one —
/// <c>TPM2_Create()</c>, <c>TPM2_Unseal()</c>, <c>TPM2_NV_ChangeAuth()</c>, and
/// <c>TPM2_HierarchyChangeAuth()</c> — against the in-house behavioural <see cref="TpmSimulator"/> with a block
/// that names handle <c>0x00000000</c>, a value <c>TPMI_SH_AUTH_SESSION</c> does not admit at all (TPM 2.0
/// Library Part 2, clause 9.8, Table 54).
/// </summary>
/// <remarks>
/// <para>
/// What each test pins is that slot PRESENCE is structural. The parser settles it from the octets left inside
/// <c>authorizationSize</c>, and the transition reads that fact rather than re-deriving it from the slot's handle
/// value: a block naming zero is a block the caller really did send, so it owes validation and a response entry
/// like any other (Part 3, clause 5.5, step 4 walks every unmarshaled session in turn). A transition that
/// inferred presence from the handle would read such a block as ABSENT — leaving it unvalidated, unverified, and
/// unanswered — and would misalign every later slot against the wire.
/// </para>
/// <para>
/// The answer is the handle-type refusal of clause 5.5, step 4.1, session-index-encoded to the offending slot
/// (Part 2, clause 6.6.2): the handle is examined for its TYPE before any session table is consulted, so the
/// refusal is neither the <c>TPM_RC_REFERENCE_S*</c> warning that would claim a session had been flushed nor a
/// bare code that would leave the caller guessing which block was wrong.
/// </para>
/// <para>
/// The instrument is <see cref="MeteredHousePool"/>: a genuine <see cref="BaseMemoryPool"/> whose own rent and
/// return telemetry is observed, so nothing here depends on a seam in production code. Two of these commands
/// rent an owned <c>newAuth</c> carrier at parse time, so the balance across each refusal is what proves the
/// refusing arm released what the parse created.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorSecondSlotPresenceTests
{
    /// <summary>The hash algorithm every session these tests start negotiates.</summary>
    private const TpmAlgIdConstants SessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The NV Index handle the <c>TPM2_NV_ChangeAuth()</c> case defines and rotates.</summary>
    private const uint NvIndexHandle = 0x0100_0041;

    /// <summary>The attributes that Index is defined with: writable and readable by its own authValue, dictionary-attack exempt.</summary>
    private const TpmaNv IndexAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The secret the <c>TPM2_Unseal()</c> case seals, so its sealed object has real content behind it.</summary>
    private static byte[] SealedSecret { get; } = "Second-slot presence proof secret."u8.ToArray();

    /// <summary>The sealed object's own authorization value, folded into the unsealing session's HMAC key.</summary>
    private static byte[] SealedUserAuth { get; } = [0x31, 0x32, 0x33, 0x34];

    /// <summary>The NV Index's own authorization value, and the value the rotation cases replace.</summary>
    private static byte[] IndexAuth { get; } = [0x41, 0x42, 0x43, 0x44];

    /// <summary>The replacement authorization value every rotation case sends as <c>newAuth</c>.</summary>
    private static byte[] ReplacementAuth { get; } = [0x51, 0x52, 0x53, 0x54, 0x55, 0x56];

    /// <summary>
    /// The <c>nonceCaller</c> every planted second block presents. Its 44-octet width is unlike any other width
    /// the surrounding machinery rents, so a rent of exactly this size identifies a carrier the parse created for
    /// the planted slot.
    /// </summary>
    private static byte[] PlantedNonce { get; } = "Planted second-slot nonceCaller octets, 44.."u8.ToArray();

    /// <summary>
    /// The <c>hmac</c> every planted second block presents. Such a block owes a REAL command HMAC (Part 3, clause
    /// 5.6 applies to every session in the area), but no test here reaches that check, so these octets stand in
    /// for one at the right width without any test depending on their value.
    /// </summary>
    private static byte[] PlantedHmac { get; } = "Planted second-slot hmac field octets, 40 lon"u8.ToArray()[..32];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A <c>TPM2_Create()</c> whose authorization area carries a second block naming handle <c>0x00000000</c>
    /// behind a <c>TPM_RS_PW</c> parent slot is refused with <c>TPM_RC_HANDLE</c> encoded to index 1.
    /// </summary>
    /// <remarks>
    /// The second slot of this command is the one that may carry <c>decrypt</c> to protect <c>inSensitive</c>
    /// (TPM 2.0 Library Part 1, clause 18.1), so a block read as absent would take the whole command down the
    /// unprotected path with the caller believing otherwise. Refusing on the handle's type keeps that
    /// disagreement impossible.
    /// </remarks>
    [TestMethod]
    public async Task CreateWithASecondSlotNamingHandleZeroIsRefusedWithHandleAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(plainDevice, registry, pool).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //The command's own carriers live inside this block so every one of them is released before the balance
        //below is read; only the SIMULATOR's outstanding rentals are what the assertion is about.
        {
            using TpmDevice rewritingDevice = CreateRewritingDevice(
                simulator, TpmCcConstants.TPM_CC_Create, command => WithAppendedSession(command, handleCount: 1));

            using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, SealedUserAuth, pool);
            using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
            using CreateInput createInput = new(parent.ObjectHandle.Value, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
            using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
                rewritingDevice, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            if(result.IsSuccess)
            {
                result.Value.Dispose();
            }

            AssertRefusedAtSlotOne(result.ResponseCode, result.BaseError);
        }

        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The refusal must return every carrier the parse rented for the refused area to the pool.");
    }

    /// <summary>
    /// A <c>TPM2_Unseal()</c> whose authorization area carries a second block naming handle <c>0x00000000</c>
    /// behind a real HMAC session is refused with <c>TPM_RC_HANDLE</c> encoded to index 1.
    /// </summary>
    /// <remarks>
    /// The second slot of this command is the one that may carry <c>encrypt</c> to protect the recovered
    /// <c>outData</c> (TPM 2.0 Library Part 1, clause 18.1). Reading such a block as absent would return the
    /// secret in the CLEAR while the host, seeing its own block in the area, decrypted what it received — a
    /// disagreement that corrupts the recovered value rather than announcing itself.
    /// </remarks>
    [TestMethod]
    public async Task UnsealWithASecondSlotNamingHandleZeroIsRefusedWithHandleAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        using CreatePrimaryResponse parent = await CreateStorageParentAsync(plainDevice, registry, pool).ConfigureAwait(false);
        using LoadResponse item = await SealAndLoadAsync(plainDevice, registry, pool, parent.ObjectHandle.Value).ConfigureAwait(false);

        StartAuthSessionResponse started = await StartUnboundHmacSessionAsync(plainDevice, registry, pool).ConfigureAwait(false);
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            //The client session adopts the started session's nonceTPM carrier (Part 1, clause 15.6.1) and holds
            //it for its own lifetime, so it is created BEFORE the baseline is taken: a balance read across that
            //adoption would move by the adopted rental rather than by anything the command did.
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);
            session.SetAuthValue(SealedUserAuth, pool);

            long baseline = trackingPool.OutstandingCount;

            //The command's own carriers live inside this block so every one of them is released before the
            //balance below is read; only the SIMULATOR's outstanding rentals are what the assertion is about.
            {
                using TpmDevice rewritingDevice = CreateRewritingDevice(
                    simulator, TpmCcConstants.TPM_CC_Unseal, command => WithAppendedSession(command, handleCount: 1));

                UnsealInput unsealInput = UnsealInput.ForItem(item.ObjectHandle);
                ReadOnlyMemory<byte>[] handleNames = [item.Name.Span.ToArray()];

                TpmResult<UnsealResponse> result = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
                    rewritingDevice, unsealInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                if(result.IsSuccess)
                {
                    result.Value.Dispose();
                }

                AssertRefusedAtSlotOne(result.ResponseCode, result.BaseError);
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusal must return every carrier the parse rented for the refused area to the pool.");
        }
        finally
        {
            _ = await plainDevice.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_NV_ChangeAuth()</c> whose authorization area carries a second block naming handle
    /// <c>0x00000000</c> behind the policy session that authorizes the Index is refused with
    /// <c>TPM_RC_HANDLE</c> encoded to index 1, and the <c>newAuth</c> carrier the parse rented reaches the pool
    /// again across the refusal.
    /// </summary>
    /// <remarks>
    /// The second slot of this command is the one that may carry <c>decrypt</c> to protect <c>newAuth</c> — the
    /// sole, and so the first, sized command parameter (TPM 2.0 Library Part 1, clause 18.1). A block read as
    /// absent would install as the Index's new authorization value whatever the host had encrypted, so the
    /// structural answer is what keeps a rotation from silently landing on ciphertext.
    /// </remarks>
    [TestMethod]
    public async Task NvChangeAuthWithASecondSlotNamingHandleZeroIsRefusedWithHandleAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        await DefineNvIndexAsync(plainDevice, registry, pool).ConfigureAwait(false);
        byte[] indexName = await ReadNvNameAsync(plainDevice).ConfigureAwait(false);

        TpmResult<StartAuthSessionResponse> startResult = await plainDevice.StartPolicySessionAsync(
            SessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartPolicySessionAsync failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            TpmResult<PolicyCommandCodeResponse> commandCodeResult = await plainDevice.PolicyCommandCodeAsync(
                sessionHandle, TpmCcConstants.TPM_CC_NV_ChangeAuth, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(commandCodeResult.IsSuccess, $"PolicyCommandCodeAsync failed: '{commandCodeResult.ResponseCode}'.");

            //The client session adopts the started session's nonceTPM carrier, so it is created BEFORE the
            //baseline is taken.
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

            long baseline = trackingPool.OutstandingCount;

            //The command's own carriers live inside this block so every one of them is released before the
            //balance below is read; only the SIMULATOR's outstanding rentals are what the assertion is about.
            {
                using TpmDevice rewritingDevice = CreateRewritingDevice(
                    simulator, TpmCcConstants.TPM_CC_NV_ChangeAuth, command => WithAppendedSession(command, handleCount: 1));

                using Tpm2bAuth newAuth = Tpm2bAuth.Create(ReplacementAuth, pool);
                using NvChangeAuthInput input = new(NvIndexHandle, newAuth);

                //A rotation response carries no pooled carrier of its own, so nothing here needs releasing
                //whichever way the command is answered.
                TpmResult<NvChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<NvChangeAuthResponse>(
                    rewritingDevice, input, [session], [indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                AssertRefusedAtSlotOne(result.ResponseCode, result.BaseError);
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusal must return the parse-rented newAuth carrier to the pool.");
        }
        finally
        {
            _ = await plainDevice.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// A <c>TPM2_HierarchyChangeAuth()</c> whose authorization area carries a second block naming handle
    /// <c>0x00000000</c> behind the HMAC session that authorizes the hierarchy is refused with
    /// <c>TPM_RC_HANDLE</c> encoded to index 1, and the <c>newAuth</c> carrier the parse rented reaches the pool
    /// again across the refusal.
    /// </summary>
    /// <remarks>
    /// This command's authorizing slot may not itself carry <c>decrypt</c> — an unbound, unsalted session of that
    /// shape would key its keystream on the very authValue being rotated away from (TPM 2.0 Library Part 1,
    /// clause 18.1's own Note) — so the second slot is the ONLY place a caller can put confidentiality for
    /// <c>newAuth</c>. Reading a block there as absent would rotate a hierarchy's authorization value to
    /// ciphertext, locking the caller out of it.
    /// </remarks>
    [TestMethod]
    public async Task HierarchyChangeAuthWithASecondSlotNamingHandleZeroIsRefusedWithHandleAtItsOwnIndex()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        TpmResponseRegistry registry = CreateRegistry();

        using TpmDevice plainDevice = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());

        StartAuthSessionResponse started = await StartUnboundHmacSessionAsync(plainDevice, registry, pool).ConfigureAwait(false);
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            //The client session adopts the started session's nonceTPM carrier, so it is created BEFORE the
            //baseline is taken.
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, SessionAlg, TestEntropy.NewCounterStream(), pool);

            long baseline = trackingPool.OutstandingCount;

            //The command's own carriers live inside this block so every one of them is released before the
            //balance below is read; only the SIMULATOR's outstanding rentals are what the assertion is about.
            {
                using TpmDevice rewritingDevice = CreateRewritingDevice(
                    simulator, TpmCcConstants.TPM_CC_HierarchyChangeAuth, command => WithAppendedSession(command, handleCount: 1));

                using Tpm2bAuth newAuth = Tpm2bAuth.Create(ReplacementAuth, pool);
                using HierarchyChangeAuthInput input = new(TpmRh.TPM_RH_OWNER, newAuth);

                //A rotation response carries no pooled carrier of its own, so nothing here needs releasing
                //whichever way the command is answered.
                TpmResult<HierarchyChangeAuthResponse> result = await TpmCommandExecutor.ExecuteAsync<HierarchyChangeAuthResponse>(
                    rewritingDevice, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                AssertRefusedAtSlotOne(result.ResponseCode, result.BaseError);
            }

            Assert.AreEqual(
                baseline, trackingPool.OutstandingCount,
                "The refusal must return the parse-rented newAuth carrier to the pool.");
        }
        finally
        {
            _ = await plainDevice.FlushContextAsync(sessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Asserts the one answer every case here expects: the handle-type refusal of TPM 2.0 Library Part 3, clause
    /// 5.5, step 4.1, session-index-encoded to the second slot.
    /// </summary>
    /// <param name="responseCode">The response code the simulator answered.</param>
    /// <param name="baseError">Its base (session-modifier-free) form.</param>
    private static void AssertRefusedAtSlotOne(TpmRcConstants responseCode, TpmRcConstants baseError)
    {
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HANDLE, baseError,
            "A slot naming something that is not a session handle at all is a handle error (Part 3, clause 5.5, step 4.1).");
        Assert.AreEqual(
            SessionEncodedRc(TpmRcConstants.TPM_RC_HANDLE, sessionIndex: 1), responseCode,
            "The refusal names the second slot, session-index-encoded (TPM 2.0 Library Part 2, clause 6.6.2).");
        Assert.AreNotEqual(
            TpmRcConstants.TPM_RC_AUTHSIZE, responseCode,
            "TPM_RC_AUTHSIZE would mean the parser never read the planted block, leaving it out of the area entirely.");
    }

    /// <summary>
    /// Appends one <c>TPMS_AUTH_COMMAND</c> naming handle <c>0x00000000</c> to a framed command's authorization
    /// area, growing both the area's declared <c>authorizationSize</c> and the header's <c>commandSize</c> to
    /// match — the wire shape of a caller who really did send a second block.
    /// </summary>
    /// <param name="command">The framed command to extend.</param>
    /// <param name="handleCount">The command's handle count, which fixes where its authorization area starts.</param>
    /// <returns>A new framed command carrying the extra slot.</returns>
    private static byte[] WithAppendedSession(ReadOnlySpan<byte> command, int handleCount)
    {
        const TpmaSession PlantedAttributes = TpmaSession.CONTINUE_SESSION | TpmaSession.DECRYPT;

        int authorizationSizeOffset = TpmHeader.HeaderSize + (handleCount * sizeof(uint));
        uint authorizationSize = BinaryPrimitives.ReadUInt32BigEndian(command.Slice(authorizationSizeOffset, sizeof(uint)));
        int insertAt = authorizationSizeOffset + sizeof(uint) + (int)authorizationSize;

        int blockLength = sizeof(uint) + sizeof(ushort) + PlantedNonce.Length + sizeof(byte) + sizeof(ushort) + PlantedHmac.Length;
        byte[] extended = new byte[command.Length + blockLength];
        command[..insertAt].CopyTo(extended);
        command[insertAt..].CopyTo(extended.AsSpan(insertAt + blockLength));

        Span<byte> block = extended.AsSpan(insertAt, blockLength);
        BinaryPrimitives.WriteUInt32BigEndian(block, 0u);
        BinaryPrimitives.WriteUInt16BigEndian(block[sizeof(uint)..], (ushort)PlantedNonce.Length);
        PlantedNonce.CopyTo(block[(sizeof(uint) + sizeof(ushort))..]);
        int afterNonce = sizeof(uint) + sizeof(ushort) + PlantedNonce.Length;
        block[afterNonce] = (byte)PlantedAttributes;
        BinaryPrimitives.WriteUInt16BigEndian(block[(afterNonce + sizeof(byte))..], (ushort)PlantedHmac.Length);
        PlantedHmac.CopyTo(block[(afterNonce + sizeof(byte) + sizeof(ushort))..]);

        BinaryPrimitives.WriteUInt32BigEndian(extended.AsSpan(authorizationSizeOffset), authorizationSize + (uint)blockLength);
        BinaryPrimitives.WriteUInt32BigEndian(extended.AsSpan(sizeof(ushort)), (uint)extended.Length);

        return extended;
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

    /// <summary>Reads a framed command's <c>commandCode</c> field (TPM 2.0 Library Part 1, clause 15.2.3's commandCode header field).</summary>
    /// <param name="command">The framed command.</param>
    /// <returns>The command code.</returns>
    private static TpmCcConstants ReadCommandCode(ReadOnlySpan<byte> command)
    {
        var reader = new TpmReader(command);
        TpmHeader header = TpmHeader.Parse(ref reader);

        return (TpmCcConstants)header.Code;
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

    /// <summary>Starts a real, unbound and unsalted HMAC session negotiating no symmetric definition.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The StartAuthSession response carrying the session's handle and initial nonceTPM.</returns>
    private async Task<StartAuthSessionResponse> StartUnboundHmacSessionAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(SessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (unbound HMAC) failed: '{startResult.ResponseCode}'.");

        return startResult.Value;
    }

    /// <summary>Creates the deterministic ECC storage parent under the owner hierarchy.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns it.</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>
    /// Seals <see cref="SealedSecret"/> under <see cref="SealedUserAuth"/> through the plain password-authorized
    /// <c>TPM2_Create()</c> form and loads the result, so the unseal case has a live sealed object to name.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The loaded storage parent.</param>
    /// <returns>The Load response carrying the loaded object's handle and Name; the caller owns it.</returns>
    private async Task<LoadResponse> SealAndLoadAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint parentHandle)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(SealedSecret, SealedUserAuth, pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(SessionAlg, pool, authPolicy: default, noDa: true);
        using CreateInput createInput = new(parentHandle, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession createParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreateResponse> createResult = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [createParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Create (seal) failed: '{createResult.ResponseCode}'.");

        using CreateResponse created = createResult.Value;
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(created.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(created.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle, inPrivate, inPublic);
        using TpmPasswordSession loadParentAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<LoadResponse> loadResult = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [loadParentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (sealed object) failed: '{loadResult.ResponseCode}'.");

        return loadResult.Value;
    }

    /// <summary>Reserializes a public area into a fresh <see cref="Tpm2bPublic"/>, the round trip a load takes.</summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cloned public area; the caller owns it.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>
    /// Defines the NV Index the rotation case names, under the owner hierarchy's empty authorization and
    /// carrying <see cref="IndexAuth"/> as its own authorization value.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task DefineNvIndexAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        using Tpm2bAuth auth = Tpm2bAuth.Create(IndexAuth, pool);
        using Tpm2bDigest policyDigest = Tpm2bDigest.Create(ReadOnlySpan<byte>.Empty, pool);
        using var publicInfo = new TpmsNvPublic(NvIndexHandle, SessionAlg, IndexAttributes, policyDigest, dataSize: 8);
        using var defineInput = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        TpmResult<NvDefineSpaceResponse> defineResult = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            tpm, defineInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"NV_DefineSpace failed: '{defineResult.ResponseCode}'.");
    }

    /// <summary>Reads the defined Index's Name back over <c>TPM2_NV_ReadPublic()</c>, for the cpHash handle area a session-authorized command needs.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ReadNvNameAsync(TpmDevice tpm)
    {
        TpmResult<NvReadPublicResponse> result = await tpm.NvReadPublicAsync(NvIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NvReadPublicAsync failed: '{result.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = result.Value;

        return indexPublic.NvName.Span.ToArray();
    }

    /// <summary>Creates a response codec registry covering every command these tests issue directly.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject)
            .Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load)
            .Register(TpmCcConstants.TPM_CC_Unseal, TpmResponseCodec.Unseal)
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_ChangeAuth, TpmResponseCodec.NvChangeAuth)
            .Register(TpmCcConstants.TPM_CC_HierarchyChangeAuth, TpmResponseCodec.HierarchyChangeAuth)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>
    /// Creates a simulator with the ECC signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator; the caller owns it.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator(
            "tpm-in-house-second-slot-presence",
            signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        await IssueStartupClearAsync(simulator, pool).ConfigureAwait(false);

        return simulator;
    }

    /// <summary>
    /// Issues <c>TPM2_Startup(CLEAR)</c> directly against the simulator, mirroring how the executor frames an
    /// unauthorized command on the wire, to move it into <see cref="TpmLifecyclePhase.Operational"/>.
    /// </summary>
    /// <param name="simulator">The simulator to bring operational.</param>
    /// <param name="pool">The memory pool.</param>
    private async Task IssueStartupClearAsync(TpmSimulator simulator, BaseMemoryPool pool)
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
