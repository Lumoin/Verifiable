using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;
using Microsoft.Extensions.Time.Testing;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives what the rest of the NV command set answers once <c>TPM2_NV_GlobalWriteLock()</c> has SET
/// <c>TPMA_NV_WRITELOCKED</c> on every Index electing <c>TPMA_NV_GLOBALLOCK</c>: the write family
/// (<c>TPM2_NV_Write()</c>, <c>TPM2_NV_Increment()</c>, <c>TPM2_NV_Extend()</c>, <c>TPM2_NV_SetBits()</c>) is
/// refused with <c>TPM_RC_NV_LOCKED</c> while the read side (<c>TPM2_NV_Read()</c>, <c>TPM2_NV_Certify()</c>,
/// <c>TPM2_NV_ReadLock()</c>) is untouched, <c>TPM2_NV_WriteLock()</c> answers the already-locked success even on
/// an Index carrying neither lockability attribute, authorization still precedes the lock gate, the Index remains
/// undefinable, and the two lock routes compose without doubling — against the in-house behavioural
/// <see cref="TpmSimulator"/>, entirely in-process with no external assets, through the same production command
/// path the production code uses (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM 2.0
/// Library Part 3, clauses 31.12, 31.11.1, 31.7.1, 31.8.1, 31.9.1, 31.10, 31.13.1, 31.14.1, 31.16 and 9.3;
/// Part 1, clauses 13 and 34.2.6.1.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvGlobalWriteLockInteractionTests
{
    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The Ordinary Index carrying <c>TPMA_NV_GLOBALLOCK</c> and neither lockability attribute.</summary>
    private const uint GlobalLockOnlyIndexHandle = 0x0100_00C0;

    /// <summary>The Ordinary Index carrying <c>TPMA_NV_GLOBALLOCK</c> together with <c>TPMA_NV_READ_STCLEAR</c>.</summary>
    private const uint GlobalLockReadStclearIndexHandle = 0x0100_00C4;

    /// <summary>The Ordinary Index carrying <c>TPMA_NV_GLOBALLOCK</c> together with <c>TPMA_NV_WRITE_STCLEAR</c>.</summary>
    private const uint GlobalLockWriteStclearIndexHandle = 0x0100_00C5;

    /// <summary>The hash algorithm for every HMAC-arm session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// Ordinary Index attributes carrying neither <c>TPMA_NV_WRITEDEFINE</c> nor <c>TPMA_NV_WRITE_STCLEAR</c>:
    /// readable and writable with the Index authValue, writable with owner authorization, dictionary-attack
    /// protected (<c>TPMA_NV_NO_DA</c> clear).
    /// </summary>
    private const TpmaNv PlainAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>Ordinary Index attributes electing <c>TPMA_NV_GLOBALLOCK</c> alone, with neither lockability attribute.</summary>
    private const TpmaNv GlobalLockOnlyAttributes = PlainAttributes | TpmaNv.TPMA_NV_GLOBALLOCK;

    /// <summary>Ordinary Index attributes electing <c>TPMA_NV_GLOBALLOCK</c> together with <c>TPMA_NV_WRITE_STCLEAR</c>.</summary>
    private const TpmaNv GlobalLockWriteStclearAttributes = GlobalLockOnlyAttributes | TpmaNv.TPMA_NV_WRITE_STCLEAR;

    /// <summary>Ordinary Index attributes electing <c>TPMA_NV_GLOBALLOCK</c> together with <c>TPMA_NV_READ_STCLEAR</c>.</summary>
    private const TpmaNv GlobalLockReadStclearAttributes = GlobalLockOnlyAttributes | TpmaNv.TPMA_NV_READ_STCLEAR;

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong Index authorization value, distinct from <see cref="CorrectAuth"/>.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The sixteen octets an Ordinary Index is populated with before it is globally locked.</summary>
    private static byte[] IndexData { get; } =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    /// <summary>A second sixteen-octet payload, written after a redefinition has produced a writable Index.</summary>
    private static byte[] SecondIndexData { get; } =
        [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F];

    /// <summary>
    /// A single-octet payload for a write attempt that a global lock must refuse; its content is immaterial
    /// since the write never reaches the Index's stored data.
    /// </summary>
    private static byte[] RefusedWriteAttempt { get; } = [0x00];

    /// <summary>The caller nonce (qualifyingData) the <c>TPM2_NV_Certify()</c> proof echoes into extraData.</summary>
    private static byte[] CertifyNonce { get; } = "NvGlobalWriteLock certify nonce."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// The order <c>TPM2_NV_WriteLock()</c> judges an Index in, made observable by a global lock: "If
    /// TPMA_NV_WRITELOCKED for the NV Index is already SET, the TPM shall return TPM_RC_SUCCESS if proper write
    /// authorization is provided" is answered ahead of "If neither TPMA_NV_WRITEDEFINE nor TPMA_NV_WRITE_STCLEAR
    /// of the NV Index is SET, then the TPM shall return TPM_RC_ATTRIBUTES". An Index carrying
    /// <c>TPMA_NV_GLOBALLOCK</c> alone is therefore <c>TPM_RC_ATTRIBUTES</c> while unlocked and
    /// <c>TPM_RC_SUCCESS</c> once <c>TPM2_NV_GlobalWriteLock()</c> has locked it — with its Name unchanged by the
    /// success, since nothing in the public area moves (Part 1, clause 13).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.11.1 and 31.12; Part 1, clause 13</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfGloballyLockedGlobalLockOnlyIndexReturnsSuccessWhileTheUnlockedIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> unlockedResult = await WriteLockAsync(
            device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(
            HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), unlockedResult.ResponseCode,
            "While unlocked, an Index carrying TPMA_NV_GLOBALLOCK alone has neither attribute clause 31.11.1 admits, so it is refused — nvIndex, handle 2 of Table 261.");

        TpmResult<NvGlobalWriteLockResponse> globalResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(globalResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{globalResult.ResponseCode}'.");

        byte[] nameAfterGlobalLock = await ReadIndexNameAsync(device, GlobalLockOnlyIndexHandle).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockedResult = await WriteLockAsync(
            device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyIndexHandle, CorrectAuth).ConfigureAwait(false);
        byte[] nameAfterWriteLock = await ReadIndexNameAsync(device, GlobalLockOnlyIndexHandle).ConfigureAwait(false);

        Assert.IsTrue(
            lockedResult.IsSuccess,
            $"Clause 31.11.1's already-locked success is judged before the lockability attributes, so a globally locked Index answers TPM_RC_SUCCESS: '{lockedResult.ResponseCode}'.");
        Assert.IsTrue(
            nameAfterGlobalLock.AsSpan().SequenceEqual(nameAfterWriteLock),
            "The already-locked success changes no attribute, so the Name the public area digests must be unchanged.");
    }

    /// <summary>
    /// "If the TPMA_NV_WRITELOCKED attribute is SET when an attempt is made to modify the Index, the TPM returns
    /// TPM_RC_NV_LOCKED" — the lock a global write lock SETs is the same lock clause 31.7.1 answers, proved on
    /// both session kinds: the password form on the Index arm and the owner arm over an HMAC session.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clauses 31.7.1 and 31.12</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfGloballyLockedIndexReturnsNvLockedOnBothSessionKinds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> globalResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(globalResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{globalResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> passwordResult = await WriteIndexAsync(
            device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);
        TpmResult<NvWriteResponse> sessionResult = await WriteIndexOverHmacOwnerArmAsync(
            device, pool, registry, GlobalLockOnlyIndexHandle, RefusedWriteAttempt).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, passwordResult.ResponseCode, "The password arm answers the global lock after authorization has succeeded.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, sessionResult.ResponseCode, "The HMAC-session continuation answers the same format-zero code once the command HMAC has verified.");
    }

    /// <summary>
    /// A global write lock inhibits writes only: clause 31.13.1 gates <c>TPM2_NV_Read()</c> on
    /// <c>TPMA_NV_READLOCKED</c>, never on <c>TPMA_NV_WRITELOCKED</c>, so a globally locked written Index still
    /// reads back its stored octets.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.12 and 31.13.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOfGloballyLockedIndexStillSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineAndWriteAsync(device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> globalResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(globalResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{globalResult.ResponseCode}'.");

        TpmResult<NvReadResponse> readResult = await ReadIndexAsync(
            device, pool, registry, GlobalLockOnlyIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"A globally locked Index must still be readable: '{readResult.ResponseCode}'.");

        using NvReadResponse read = readResult.Value;
        Assert.IsTrue(IndexData.AsSpan().SequenceEqual(read.Data), "The global write lock leaves the stored data intact and readable.");
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c> reads the Index's contents, so a global write lock leaves it alone as well: the
    /// read access checks answer <c>TPMA_NV_READLOCKED</c> only — a globally locked, written Index certifies
    /// successfully.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.16 and 31.12</see>.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOfGloballyLockedIndexSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(withEccSigningBackend: true).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSigningRegistry();

        await DefineAndWriteAsync(device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> globalResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(globalResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{globalResult.ResponseCode}'.");

        using CreatePrimaryResponse signingKey = await CreateSigningPrimaryAsync(device, registry, pool).ConfigureAwait(false);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(CorrectAuth, pool);
        using NvCertifyInput certifyInput = NvCertifyInput.ForEcdsa(
            signingKey.ObjectHandle, GlobalLockOnlyIndexHandle, GlobalLockOnlyIndexHandle, CertifyNonce, TpmAlgIdConstants.TPM_ALG_SHA256,
            OrdinaryDataSize, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            device, certifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A global write lock must not block TPM2_NV_Certify(): '{result.ResponseCode}'.");

        using NvCertifyResponse certified = result.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, certified.SignatureAlgorithm, "The attestation over a globally locked Index is signed with the key's ECDSA scheme.");
    }

    /// <summary>
    /// A write lock never blocks a read lock either: <c>TPM2_NV_ReadLock()</c> is gated on
    /// <c>TPMA_NV_READ_STCLEAR</c> ("Proper authorizations are required for this command as determined by
    /// TPMA_NV_PPREAD, TPMA_NV_OWNERREAD, TPMA_NV_AUTHREAD"), so a globally locked Index electing
    /// <c>TPMA_NV_READ_STCLEAR</c> still accepts the read lock and carries <c>TPMA_NV_READLOCKED</c> afterwards.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.14.1 and 31.12</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOfGloballyLockedReadStclearIndexSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockReadStclearIndexHandle, GlobalLockReadStclearAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> globalResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(globalResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{globalResult.ResponseCode}'.");

        TpmResult<NvReadLockResponse> readLockResult = await ReadLockAsync(
            device, pool, registry, GlobalLockReadStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(readLockResult.IsSuccess, $"A globally locked Index must still accept TPM2_NV_ReadLock(): '{readLockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockReadStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_READLOCKED, attributes & TpmaNv.TPMA_NV_READLOCKED, "The read lock SETs TPMA_NV_READLOCKED alongside the write lock the global command SET.");
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED, "The read lock leaves the global write lock standing.");
    }

    /// <summary>
    /// The order pin between authorization and the lock gate survives a global lock: "If authorization sessions
    /// are present, they are checked before checks to see if writes to the NV Index are locked" — a wrong Index
    /// authValue against a globally locked Index answers the auth-failure, not <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.7.1, 31.9.1 and 31.12</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfGloballyLockedIndexWithWrongAuthReturnsAuthFailNotNvLocked()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> globalResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(globalResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{globalResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> result = await WriteIndexAsync(
            device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyIndexHandle, WrongAuth, RefusedWriteAttempt).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), result.ResponseCode,
            "Authorization precedes the lock gate, so a wrong authValue answers the auth-failure rather than TPM_RC_NV_LOCKED.");
    }

    /// <summary>
    /// A global write lock is not a deletion barrier: <c>TPM2_NV_UndefineSpace()</c> carries no lock gate, and a
    /// redefinition at the same handle begins with <c>TPMA_NV_WRITELOCKED</c> CLEAR ("When the Index is created
    /// ... TPMA_NV_WRITELOCKED, TPMA_NV_READLOCKED, and TPMA_NV_WRITTEN shall all be CLEAR") and is writable,
    /// because "If an Index is defined with TPMA_NV_GLOBALLOCK SET, then the global lock does not apply until the
    /// next time this command is executed".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.4, 31.3.1 and 31.12.1; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOfGloballyLockedIndexAllowsAWritableRedefinition()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineAndWriteAsync(device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> globalResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(globalResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{globalResult.ResponseCode}'.");

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineIndexAsync(device, pool, registry, GlobalLockOnlyIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"TPM2_NV_UndefineSpace() of a globally locked Index must succeed: '{undefineResult.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(
            device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"The redefinition must succeed: '{redefineResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, GlobalLockOnlyIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A newly defined Index carries TPMA_NV_WRITELOCKED CLEAR even when it elects TPMA_NV_GLOBALLOCK.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, GlobalLockOnlyIndexHandle, GlobalLockOnlyIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"The redefined Index must be writable until the next global write lock: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// The two lock routes reach one bit, not two: an Index electing both <c>TPMA_NV_WRITE_STCLEAR</c> and
    /// <c>TPMA_NV_GLOBALLOCK</c> that <c>TPM2_NV_WriteLock()</c> has already locked answers a following
    /// <c>TPM2_NV_GlobalWriteLock()</c> with <c>TPM_RC_SUCCESS</c> and moves no Name — "The command will SET
    /// TPMA_NV_WRITELOCKED for all indexes that have their TPMA_NV_GLOBALLOCK attribute SET" is a SET of a bit
    /// that is already SET.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.12 and 31.11.1; Part 1, clause 13</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockAfterNvWriteLockOfTheSameIndexLeavesTheNameUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockWriteStclearIndexHandle, GlobalLockWriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> writeLockResult = await WriteLockAsync(
            device, pool, registry, GlobalLockWriteStclearIndexHandle, GlobalLockWriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(writeLockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{writeLockResult.ResponseCode}'.");
        byte[] nameAfterWriteLock = await ReadIndexNameAsync(device, GlobalLockWriteStclearIndexHandle).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> globalResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        byte[] nameAfterGlobalLock = await ReadIndexNameAsync(device, GlobalLockWriteStclearIndexHandle).ConfigureAwait(false);

        Assert.IsTrue(globalResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() over an already write-locked Index must succeed: '{globalResult.ResponseCode}'.");
        Assert.IsTrue(nameAfterWriteLock.AsSpan().SequenceEqual(nameAfterGlobalLock), "SETting a bit that is already SET moves no attribute, so the Name is unchanged.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, GlobalLockWriteStclearIndexHandle, GlobalLockWriteStclearIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, writeResult.ResponseCode, "One lock bit stands after both routes have run.");
    }

    /// <summary>
    /// The two routes are independent, which the startup pass makes visible: "If TPMA_NV_WRITEDEFINE is CLEAR,
    /// the TPMA_NV_WRITELOCKED attribute can be SET using TPM2_NV_WriteLock() if TPMA_NV_WRITE_STCLEAR is SET or
    /// TPM2_NV_GlobalWriteLock() if TPMA_NV_GLOBALLOCK is SET. In this case, TPMA_NV_WRITELOCKED will be CLEAR on
    /// the next TPM Reset or TPM Restart" — a global lock cleared by a TPM Reset leaves an Index that
    /// <c>TPM2_NV_WriteLock()</c> then locks again through its own <c>TPMA_NV_WRITE_STCLEAR</c> route.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clauses 9.3, 31.12 and 31.11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvGlobalWriteLockClearedByATpmResetAllowsNvWriteLockToLockAgain()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineAndWriteAsync(device, pool, registry, GlobalLockWriteStclearIndexHandle, GlobalLockWriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvGlobalWriteLockResponse> globalResult = await GlobalWriteLockAsync(device, pool, registry).ConfigureAwait(false);
        Assert.IsTrue(globalResult.IsSuccess, $"TPM2_NV_GlobalWriteLock() failed: '{globalResult.ResponseCode}'.");

        TpmaNv lockedAttributes = await ReadIndexAttributesAsync(device, GlobalLockWriteStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, lockedAttributes & TpmaNv.TPMA_NV_WRITELOCKED, "The global write lock SETs TPMA_NV_WRITELOCKED.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv clearedAttributes = await ReadIndexAttributesAsync(device, GlobalLockWriteStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), clearedAttributes & TpmaNv.TPMA_NV_WRITELOCKED, "A TPM Reset CLEARs a global write lock on an Index whose TPMA_NV_WRITEDEFINE is CLEAR.");

        TpmResult<NvWriteLockResponse> writeLockResult = await WriteLockAsync(
            device, pool, registry, GlobalLockWriteStclearIndexHandle, GlobalLockWriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(writeLockResult.IsSuccess, $"The TPMA_NV_WRITE_STCLEAR route must lock the Index again: '{writeLockResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, GlobalLockWriteStclearIndexHandle, GlobalLockWriteStclearIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, writeResult.ResponseCode, "The re-locked Index refuses a write with TPM_RC_NV_LOCKED.");
    }

    /// <summary>
    /// Defines <paramref name="nvIndex"/> and populates it with <see cref="IndexData"/>, asserting each step —
    /// the starting position of every proof that needs <c>TPMA_NV_WRITTEN</c> SET before the global write lock
    /// runs.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define and write.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    private async Task DefineAndWriteAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes)
    {
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(device, pool, registry, nvIndex, attributes).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"TPM2_NV_DefineSpace() failed: '{defineResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(device, pool, registry, nvIndex, nvIndex, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write() failed: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// Issues an owner-authorized <c>TPM2_NV_GlobalWriteLock()</c> over a password session carrying the factory
    /// ownerAuth. The command names one permanent handle and no Index, so no Name is supplied to the executor
    /// (TPM 2.0 Library Part 3, clause 31.12, Table 263).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <returns>The global-write-lock result.</returns>
    private async Task<TpmResult<NvGlobalWriteLockResponse>> GlobalWriteLockAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvGlobalWriteLockInput(TpmRh.TPM_RH_OWNER);

        return await TpmCommandExecutor.ExecuteAsync<NvGlobalWriteLockResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Starts an unbound, unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9) and composes the host
    /// session over it with <paramref name="authValue"/> as its authValue term.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authValue">The authValue the session proves.</param>
    /// <returns>The session handle (to flush) and the composed session (to dispose).</returns>
    private async Task<(uint Handle, TpmSession Session)> StartUnboundSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, ReadOnlyMemory<byte> authValue)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        session.SetAuthValue(authValue.Span, pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>The handle-form Name of a permanent handle: its four big-endian octets (TPM 2.0 Library Part 1, clause 13, Table 9).</summary>
    /// <param name="handle">The permanent handle.</param>
    /// <returns>The Name.</returns>
    private static byte[] HandleFormName(uint handle)
    {
        byte[] name = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(name, handle);

        return name;
    }

    /// <summary>
    /// Reads an Index's Name back from the TPM through <c>TPM2_NV_ReadPublic()</c> — the authoritative source of
    /// a session-authorized command's cpHash Name term, since the attribute word a lock changes is part of the
    /// public area the Name digests (TPM 2.0 Library Part 1, clause 13).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index whose Name is wanted.</param>
    /// <returns>The Index's Name.</returns>
    private async Task<byte[]> ReadIndexNameAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync failed: '{nameResult.ResponseCode}'.");

        using NvReadPublicResponse namePublic = nameResult.Value;

        return namePublic.NvName.Span.ToArray();
    }

    /// <summary>
    /// Reads an Index's <c>TPMA_NV</c> attribute word back through <c>TPM2_NV_ReadPublic()</c>, which is how the
    /// TPM-maintained lock bits are observable from outside (TPM 2.0 Library Part 3, clause 31.6).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index whose public area is wanted.</param>
    /// <returns>The Index's attribute word.</returns>
    private async Task<TpmaNv> ReadIndexAttributesAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"NvReadPublicAsync failed: '{publicResult.ResponseCode}'.");

        using NvReadPublicResponse indexPublic = publicResult.Value;

        return indexPublic.NvPublic.Attributes;
    }

    /// <summary>
    /// Creates the ECC P-256 signing primary the <c>TPM2_NV_Certify()</c> proof uses as its <c>signHandle</c>
    /// (TPM 2.0 Library Part 3, clause 31.16: the key referenced by signHandle must have <c>sign</c> SET).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response; the caller owns and must dispose it.</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT, password: null, TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession hierarchyAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, input, [hierarchyAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256 signing key) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates a response codec registry for the NV commands these tests drive.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateNvRegistry() =>
        new TpmResponseRegistry()
            .Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_UndefineSpace, TpmResponseCodec.NvUndefineSpace)
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement)
            .Register(TpmCcConstants.TPM_CC_NV_Extend, TpmResponseCodec.NvExtend)
            .Register(TpmCcConstants.TPM_CC_NV_SetBits, TpmResponseCodec.NvSetBits)
            .Register(TpmCcConstants.TPM_CC_NV_WriteLock, TpmResponseCodec.NvWriteLock)
            .Register(TpmCcConstants.TPM_CC_NV_ReadLock, TpmResponseCodec.NvReadLock)
            .Register(TpmCcConstants.TPM_CC_NV_GlobalWriteLock, TpmResponseCodec.NvGlobalWriteLock)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>Extends <see cref="CreateNvRegistry"/> with the codecs the <c>TPM2_NV_Certify()</c> proof needs.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateSigningRegistry() =>
        CreateNvRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <paramref name="nvIndex"/> with <see cref="CorrectAuth"/> as the
    /// Index authValue, authorized by the (empty) owner authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="dataSize">The declared data area size; defaults to the Ordinary Index width this file uses.</param>
    /// <returns>The define-space result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes, ushort dataSize = OrdinaryDataSize)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(CorrectAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an owner-authorized <c>TPM2_NV_UndefineSpace()</c> for <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to delete.</param>
    /// <returns>The undefine-space result.</returns>
    private async Task<TpmResult<NvUndefineSpaceResponse>> UndefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        var input = new NvUndefineSpaceInput(TpmRh.TPM_RH_OWNER, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvUndefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a password-authorized <c>TPM2_NV_WriteLock()</c> against <paramref name="nvIndex"/> authorized by <paramref name="authHandle"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle (the Index itself or the owner hierarchy).</param>
    /// <param name="nvIndex">The Index to lock for writing.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <returns>The write-lock result.</returns>
    private async Task<TpmResult<NvWriteLockResponse>> WriteLockAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvWriteLockInput(authHandle, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteLockResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an Index-arm, password-authorized <c>TPM2_NV_ReadLock()</c> against <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to lock for reading.</param>
    /// <param name="suppliedAuth">The authorization value supplied for the Index.</param>
    /// <returns>The read-lock result.</returns>
    private async Task<TpmResult<NvReadLockResponse>> ReadLockAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvReadLockInput(nvIndex, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvReadLockResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a password-authorized <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/> at offset zero.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="data">The octets to store.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth,
        ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var input = new NvWriteInput(authHandle, nvIndex, buffer, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues an owner-authorized <c>TPM2_NV_Write()</c> over an unbound, unsalted HMAC session — cpHash's Name1
    /// is the owner hierarchy's handle-form Name and Name2 the Index's Name as the command finds it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="data">The octets to store.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexOverHmacOwnerArmAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> data)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(session)
            {
                ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);
                ReadOnlyMemory<byte>[] handleNames = [HandleFormName((uint)TpmRh.TPM_RH_OWNER), indexName];

                using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
                var input = new NvWriteInput((uint)TpmRh.TPM_RH_OWNER, nvIndex, buffer, Offset: 0);

                return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                    device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>Issues <c>TPM2_NV_Read()</c> against <paramref name="nvIndex"/> from offset zero, authorized by the Index authValue over a password session.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="suppliedAuth">The authValue supplied for the Index.</param>
    /// <param name="size">The number of octets to read.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ushort size)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: size, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Completes an orderly shutdown, powers the simulator back on, and completes the startup, asserting each wire step.</summary>
    /// <param name="simulator">The simulator under test.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="shutdownType">The orderly shutdown type.</param>
    /// <param name="startupType">The startup type completing the cycle.</param>
    private async Task PowerCycleAsync(TpmSimulator simulator, BaseMemoryPool pool, TpmSuConstants shutdownType, TpmSuConstants startupType)
    {
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new ShutdownInput(shutdownType)).ConfigureAwait(false), "TPM2_Shutdown() must succeed.");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, await SubmitSessionlessAsync(simulator, pool, new StartupInput(startupType)).ConfigureAwait(false), "TPM2_Startup() must succeed.");
    }

    /// <summary>Frames a sessionless command directly to the simulator and returns its response code.</summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="input">The command input.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSessionlessAsync(TpmSimulator simulator, BaseMemoryPool pool, ITpmCommandInput input)
    {
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The transport itself must succeed.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());

        return (TpmRcConstants)TpmHeader.Parse(ref reader).Code;
    }

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the operational
    /// phase. When <paramref name="withEccSigningBackend"/> is set, the simulator is also wired with the ECC
    /// (BouncyCastle) signing backend <c>TPM2_CreatePrimary()</c> and <c>TPM2_NV_Certify()</c> need.
    /// </summary>
    /// <param name="withEccSigningBackend">When <see langword="true"/>, wires the ECC signing backend; otherwise the simulator carries none.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(bool withEccSigningBackend = false)
    {
        var simulator = withEccSigningBackend
            ? new TpmSimulator("tpm-in-house-nv-globalwritelock-interaction", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch))
            : new TpmSimulator("tpm-in-house-nv-globalwritelock-interaction", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitSessionlessAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
