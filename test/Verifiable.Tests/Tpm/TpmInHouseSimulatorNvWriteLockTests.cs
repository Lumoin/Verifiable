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
using Verifiable.Tpm.Extensions.Nv;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Drives <c>TPM2_NV_WriteLock()</c> — the write ladder on both arms over a password and over an HMAC session,
/// the <c>TPMA_NV_WRITEDEFINE</c>/<c>TPMA_NV_WRITE_STCLEAR</c> lockability rule, the already-locked success, the
/// Name movement a lock causes, the <c>TPMA_NV_WRITELOCKED</c> gate every write command answers with
/// <c>TPM_RC_NV_LOCKED</c>, and the <c>TPM2_Startup()</c> pass that CLEARs the lock on a TPM Reset or TPM Restart
/// unless <c>TPMA_NV_WRITEDEFINE</c> and <c>TPMA_NV_WRITTEN</c> are both SET — against the in-house behavioural
/// <see cref="TpmSimulator"/>, entirely in-process with no external assets, through the same production command
/// path the production code uses (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM 2.0
/// Library Part 3, clauses 31.11, 31.7.1, 31.8.1, 31.9.1, 31.10 and 9.3; Part 1, clauses 13 and 34.2.6.1.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvWriteLockTests
{
    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The declared data size clause 31.3.1's eight-octet rule fixes for a Counter and a Bit Field Index.</summary>
    private const ushort EightOctetDataSize = 8;

    /// <summary>The declared data size of the SHA-256 Extend Index — its nameAlg's digest width (clause 31.3.1).</summary>
    private const ushort Sha256DigestSize = 32;

    /// <summary>The Ordinary Index electing <c>TPMA_NV_WRITE_STCLEAR</c>, the volatile lockability attribute.</summary>
    private const uint WriteStclearIndexHandle = 0x0100_0070;

    /// <summary>The Ordinary Index electing <c>TPMA_NV_WRITEDEFINE</c>, the permanent lockability attribute.</summary>
    private const uint WriteDefineIndexHandle = 0x0100_0071;

    /// <summary>The Ordinary Index carrying neither lockability attribute.</summary>
    private const uint PlainIndexHandle = 0x0100_0072;

    /// <summary>The Ordinary Index carrying <c>TPMA_NV_GLOBALLOCK</c> alone.</summary>
    private const uint GlobalLockIndexHandle = 0x0100_0073;

    /// <summary>The Ordinary Index carrying <c>TPMA_NV_WRITEDEFINE</c> together with <c>TPMA_NV_CLEAR_STCLEAR</c>.</summary>
    private const uint WriteDefineClearStclearIndexHandle = 0x0100_0074;

    /// <summary>The Counter Index used to prove <c>TPM2_NV_Increment()</c>'s lock gate.</summary>
    private const uint CounterIndexHandle = 0x0100_0075;

    /// <summary>The Extend Index used to prove <c>TPM2_NV_Extend()</c>'s lock gate.</summary>
    private const uint ExtendIndexHandle = 0x0100_0076;

    /// <summary>The Bit Field Index used to prove <c>TPM2_NV_SetBits()</c>'s lock gate.</summary>
    private const uint BitsIndexHandle = 0x0100_0077;

    /// <summary>An <c>authHandle</c> that is neither the owner hierarchy nor any Index defined in this file.</summary>
    private const uint MismatchedAuthHandle = 0x0100_007F;

    /// <summary>The hash algorithm for every HMAC-arm session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// Ordinary Index attributes electing <c>TPMA_NV_WRITE_STCLEAR</c>: readable and writable with the Index
    /// authValue, writable with owner authorization, dictionary-attack protected (<c>TPMA_NV_NO_DA</c> clear).
    /// </summary>
    private const TpmaNv WriteStclearAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_WRITE_STCLEAR;

    /// <summary>The same <c>TPMA_NV_WRITE_STCLEAR</c> attributes, opted out of dictionary-attack protection.</summary>
    private const TpmaNv NonDaWriteStclearAttributes = WriteStclearAttributes | TpmaNv.TPMA_NV_NO_DA;

    /// <summary><c>TPMA_NV_WRITE_STCLEAR</c> attributes deliberately missing <c>TPMA_NV_OWNERWRITE</c>.</summary>
    private const TpmaNv WriteStclearWithoutOwnerWriteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_WRITE_STCLEAR;

    /// <summary><c>TPMA_NV_WRITE_STCLEAR</c> attributes deliberately missing <c>TPMA_NV_AUTHWRITE</c>.</summary>
    private const TpmaNv WriteStclearWithoutAuthWriteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_WRITE_STCLEAR;

    /// <summary>Ordinary Index attributes electing <c>TPMA_NV_WRITEDEFINE</c>, the permanent lock.</summary>
    private const TpmaNv WriteDefineAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_WRITEDEFINE;

    /// <summary>Ordinary Index attributes carrying neither <c>TPMA_NV_WRITEDEFINE</c> nor <c>TPMA_NV_WRITE_STCLEAR</c>.</summary>
    private const TpmaNv PlainAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>Ordinary Index attributes electing <c>TPMA_NV_GLOBALLOCK</c> and neither of the two lockability attributes.</summary>
    private const TpmaNv GlobalLockOnlyAttributes = PlainAttributes | TpmaNv.TPMA_NV_GLOBALLOCK;

    /// <summary>Ordinary Index attributes electing <c>TPMA_NV_WRITEDEFINE</c> together with <c>TPMA_NV_CLEAR_STCLEAR</c>.</summary>
    private const TpmaNv WriteDefineClearStclearAttributes = WriteDefineAttributes | TpmaNv.TPMA_NV_CLEAR_STCLEAR;

    /// <summary>Counter Index attributes electing <c>TPMA_NV_WRITE_STCLEAR</c> (the type rides bits 7:4 of TPMA_NV).</summary>
    private const TpmaNv CounterWriteStclearAttributes =
        WriteStclearAttributes | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Extend Index attributes electing <c>TPMA_NV_WRITE_STCLEAR</c>.</summary>
    private const TpmaNv ExtendWriteStclearAttributes =
        WriteStclearAttributes | (TpmaNv)((uint)TpmNt.TPM_NT_EXTEND << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Bit Field Index attributes electing <c>TPMA_NV_WRITE_STCLEAR</c>.</summary>
    private const TpmaNv BitsWriteStclearAttributes =
        WriteStclearAttributes | (TpmaNv)((uint)TpmNt.TPM_NT_BITS << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The <c>bits</c> value the <c>TPM2_NV_SetBits()</c> attempt a lock must refuse would OR in.</summary>
    private const ulong RefusedBits = 0x8000_0000_0000_0001ul;

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong Index authorization value, distinct from <see cref="CorrectAuth"/>.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>The sixteen octets an Ordinary Index is populated with before it is locked.</summary>
    private static byte[] IndexData { get; } =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    /// <summary>A second sixteen-octet payload, written after a lock has been cleared by a startup.</summary>
    private static byte[] SecondIndexData { get; } =
        [0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F];

    /// <summary>
    /// A single-octet payload for a write attempt that a lock must refuse; its content is immaterial since the
    /// write never reaches the Index's stored data.
    /// </summary>
    private static byte[] RefusedWriteAttempt { get; } = [0x00];

    /// <summary>Thirty-two octets of <c>data</c> for the <c>TPM2_NV_Extend()</c> attempt a lock must refuse.</summary>
    private static byte[] RefusedExtendAttempt { get; } = new byte[Sha256DigestSize];

    /// <summary>The caller nonce (qualifyingData) the <c>TPM2_NV_Certify()</c> proof echoes into extraData.</summary>
    private static byte[] CertifyNonce { get; } = "NvWriteLock certify nonce."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// <c>TPM2_NV_WriteLock()</c> names an existing NV Index, so an undefined handle is refused with
    /// <c>TPM_RC_HANDLE</c> before any authorization is evaluated.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.11; clause 5.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfUndefinedIndexReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvWriteLockResponse> result = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode);
    }

    /// <summary>
    /// "If the command is properly authorized and TPMA_NV_WRITE_STCLEAR or TPMA_NV_WRITEDEFINE is SET, then the
    /// TPM shall SET TPMA_NV_WRITELOCKED for the NV Index" — read back two ways on a <c>TPMA_NV_WRITE_STCLEAR</c>
    /// Index: the attribute word <c>TPM2_NV_ReadPublic()</c> returns carries <c>TPMA_NV_WRITELOCKED</c>, and the
    /// next <c>TPM2_NV_Write()</c> is refused with <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.11.1 and 31.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfWriteStclearIndexSetsWritelockedAndRefusesTheNextWrite()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A successful TPM2_NV_WriteLock() must SET TPMA_NV_WRITELOCKED in the public area.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, writeResult.ResponseCode, "A write-locked Index refuses TPM2_NV_Write() with TPM_RC_NV_LOCKED.");
    }

    /// <summary>
    /// The same lock through the other lockability attribute: "If the TPMA_NV_WRITEDEFINE or
    /// TPMA_NV_WRITE_STCLEAR attributes of an NV location are SET, then this command may be used to inhibit
    /// further writes of the NV Index" — a <c>TPMA_NV_WRITEDEFINE</c> Index locks, its attribute word carries
    /// <c>TPMA_NV_WRITELOCKED</c>, and the next write is <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.11.1 and 31.7.1; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfWriteDefineIndexSetsWritelockedAndRefusesTheNextWrite()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteDefineIndexHandle, WriteDefineAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteDefineIndexHandle, WriteDefineIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteDefineIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A TPMA_NV_WRITEDEFINE Index locks exactly as a TPMA_NV_WRITE_STCLEAR one does.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteDefineIndexHandle, WriteDefineIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, writeResult.ResponseCode, "A write-locked Index refuses TPM2_NV_Write() with TPM_RC_NV_LOCKED.");
    }

    /// <summary>
    /// "If neither TPMA_NV_WRITEDEFINE nor TPMA_NV_WRITE_STCLEAR of the NV Index is SET, then the TPM shall
    /// return TPM_RC_ATTRIBUTES" — and the refusal follows the authorization ("If authorization sessions are
    /// present, they are checked before checks to see if writes to the NV Index are locked"), so a wrong
    /// authValue answers the auth-failure instead.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.11.1 and 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfIndexWithNeitherLockAttributeReturnsAttributesUnderCorrectAuthAndAuthFailUnderWrongAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PlainIndexHandle, PlainAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> correctResult = await WriteLockAsync(
            device, pool, registry, PlainIndexHandle, PlainIndexHandle, CorrectAuth).ConfigureAwait(false);
        TpmResult<NvWriteLockResponse> wrongResult = await WriteLockAsync(
            device, pool, registry, PlainIndexHandle, PlainIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, correctResult.ResponseCode, "An Index carrying neither lockability attribute cannot be write-locked.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, wrongResult.BaseError, "The authorization is checked first, so a wrong authValue answers the auth-failure, not TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// <c>TPMA_NV_GLOBALLOCK</c> elects an Index for <c>TPM2_NV_GlobalWriteLock()</c>, not for this command:
    /// "If neither TPMA_NV_WRITEDEFINE nor TPMA_NV_WRITE_STCLEAR of the NV Index is SET, then the TPM shall
    /// return TPM_RC_ATTRIBUTES", so an Index carrying <c>TPMA_NV_GLOBALLOCK</c> alone is refused here.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.11.1 and 31.12.1; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfGlobalLockOnlyIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, GlobalLockIndexHandle, GlobalLockOnlyAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> result = await WriteLockAsync(
            device, pool, registry, GlobalLockIndexHandle, GlobalLockIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
            "TPMA_NV_GLOBALLOCK is not one of the two attributes clause 31.11.1 admits, so this command refuses the Index.");
    }

    /// <summary>
    /// "If TPMA_NV_WRITELOCKED for the NV Index is already SET, the TPM shall return TPM_RC_SUCCESS if proper
    /// write authorization is provided" — the repeat succeeds and changes nothing, which the Index's Name proves:
    /// the Name digests the attribute word (Part 1, clause 13), so an unchanged Name across the repeat is an
    /// unchanged public area.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.11.1; Part 1, clause 13</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfAlreadyLockedIndexReturnsSuccessWithTheNameUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> firstResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The first TPM2_NV_WriteLock() failed: '{firstResult.ResponseCode}'.");
        byte[] nameAfterFirst = await ReadIndexNameAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> secondResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        byte[] nameAfterSecond = await ReadIndexNameAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);

        Assert.IsTrue(secondResult.IsSuccess, $"An already write-locked Index must answer TPM_RC_SUCCESS: '{secondResult.ResponseCode}'.");
        Assert.IsTrue(nameAfterFirst.AsSpan().SequenceEqual(nameAfterSecond), "The repeat changes no attribute, so the Name the attribute word digests must be unchanged.");
    }

    /// <summary>
    /// The mandatory arm of the already-locked rule is conditioned on proper authorization ("the TPM shall
    /// return TPM_RC_SUCCESS if proper write authorization is provided"), and the permissive "can always return
    /// TPM_RC_SUCCESS" leaves a refusal admissible when authorization fails: a wrong Index authValue against an
    /// already-locked DA-protected Index is the auth-failure and charges <c>failedTries</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.11.1; Part 1, clauses 16.8.1 and 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfAlreadyLockedIndexWithWrongAuthReturnsAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> wrongResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, wrongResult.ResponseCode, "An already-locked Index still authorizes the command before answering it.");
        Assert.AreEqual(
            counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false),
            "A wrong DA-protected authValue charges failedTries whether or not the Index is already locked.");
    }

    /// <summary>
    /// "When an NV Index becomes locked (TPMA_NV_WRITELOCKED or TPMA_NV_READLOCKED is SET), the Name of the NV
    /// Index changes" — the Name digests the public area's attribute word, so
    /// <c>TPM2_NV_ReadPublic()</c> before and after the lock returns different Names.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 13; Part 3, clause 31.11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockChangesTheIndexName()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);
        byte[] nameBefore = await ReadIndexNameAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");
        byte[] nameAfter = await ReadIndexNameAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);

        Assert.IsFalse(nameBefore.AsSpan().SequenceEqual(nameAfter), "SETting TPMA_NV_WRITELOCKED moves the Name, which the Index's public area digests.");
    }

    /// <summary>
    /// The owner arm: "Proper write authorization is required for this command as determined by ...
    /// TPMA_NV_OWNERWRITE" — an owner-authorized lock under the (empty) owner authValue succeeds and the Index
    /// carries <c>TPMA_NV_WRITELOCKED</c> afterwards.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.11.1; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockByOwnerAuthorizationSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> result = await WriteLockAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, WriteStclearIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized lock must succeed: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED, "The owner arm SETs the same lock bit the Index arm does.");
    }

    /// <summary>
    /// The owner arm honours <c>TPMA_NV_OWNERWRITE</c> ahead of the compare: with the bit clear an
    /// owner-authorized lock is <c>TPM_RC_NV_AUTHORIZATION</c>, since owner authorization is not one of the
    /// write mechanisms this Index admits.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.4; Part 3, clause 31.11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockByOwnerWithoutOwnerWriteReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearWithoutOwnerWriteAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> result = await WriteLockAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, WriteStclearIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// "If authHandle is an NV Index, it must be the same as nvIndex (TPM_RC_NV_AUTHORIZATION)" — an
    /// <c>authHandle</c> that is neither the owner hierarchy nor the Index itself is refused with
    /// <c>TPM_RC_NV_AUTHORIZATION</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockWithMismatchedAuthHandleReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> result = await WriteLockAsync(
            device, pool, registry, MismatchedAuthHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// The Index arm honours <c>TPMA_NV_AUTHWRITE</c> ahead of the compare: with the bit clear the Index's own
    /// authValue is not an available mechanism for a write authorization at all, so a correct AND a wrong value
    /// are both refused with <c>TPM_RC_AUTH_UNAVAILABLE</c> and no comparison outcome leaks.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.11.1 and 5.6; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockWithoutAuthWriteReturnsAuthUnavailableForCorrectAndWrongValuesAlike()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearWithoutAuthWriteAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> correctResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        TpmResult<NvWriteLockResponse> wrongResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, correctResult.ResponseCode, "With TPMA_NV_AUTHWRITE clear the Index authValue cannot authorize the lock, even when it matches.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, wrongResult.ResponseCode, "The identical refusal for a wrong value, so the gate runs before the compare.");
    }

    /// <summary>
    /// A wrong Index authValue against a DA-protected Index is an auth-failure that charges <c>failedTries</c>:
    /// "All uses of a DA protected authValue receive DA protection", the lock command included — read back over
    /// <c>TPM_PT_LOCKOUT_COUNTER</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockWithWrongAuthOnDaProtectedIndexReturnsAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> result = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode);
        Assert.AreEqual(counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong DA-protected authValue must charge failedTries once.");
    }

    /// <summary>
    /// A wrong Index authValue against a <c>TPMA_NV_NO_DA</c> Index is a plain bad-authorization that leaves
    /// <c>failedTries</c> untouched — <c>TPMA_NV_NO_DA</c> applies uniformly, with no per-command carve-out.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockWithWrongAuthOnNoDaIndexReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, NonDaWriteStclearAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> result = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode);
        Assert.AreEqual(counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A NO_DA Index's wrong authValue must not move failedTries.");
    }

    /// <summary>
    /// "If the TPMA_NV_WRITELOCKED attribute of the NV Index is SET, then the TPM shall return
    /// TPM_RC_NV_LOCKED" — proved on both session kinds: the password form on the Index arm and the owner arm
    /// over an HMAC session, each refused with the same bare response code, since the refusal names the Index
    /// rather than a session.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.7.1; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfWriteLockedOrdinaryIndexReturnsNvLockedOnBothSessionKinds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> passwordResult = await WriteIndexAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);
        TpmResult<NvWriteResponse> sessionResult = await WriteIndexOverHmacOwnerArmAsync(
            device, pool, registry, WriteStclearIndexHandle, RefusedWriteAttempt).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, passwordResult.ResponseCode, "The password arm answers the lock after authorization has succeeded.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, sessionResult.ResponseCode, "The HMAC-session continuation answers the same bare code once the command HMAC has verified.");
    }

    /// <summary>
    /// "If TPMA_NV_WRITELOCKED is SET, the TPM shall return TPM_RC_NV_LOCKED" for <c>TPM2_NV_Increment()</c> —
    /// a locked Counter Index refuses the increment on the password arm and over an HMAC session alike.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOfWriteLockedCounterIndexReturnsNvLockedOnBothSessionKinds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterWriteStclearAttributes, EightOctetDataSize).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvIncrementResponse> passwordResult = await IncrementAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        TpmResult<NvIncrementResponse> sessionResult = await IncrementOverHmacAsync(
            device, pool, registry, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, passwordResult.ResponseCode);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, sessionResult.ResponseCode);
    }

    /// <summary>
    /// The same lock gate on <c>TPM2_NV_Extend()</c>: "If the TPMA_NV_WRITELOCKED attribute of the NV Index is
    /// SET, then the TPM shall return TPM_RC_NV_LOCKED" — a locked Extend Index refuses the extend on both session
    /// kinds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfWriteLockedExtendIndexReturnsNvLockedOnBothSessionKinds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendWriteStclearAttributes, Sha256DigestSize).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvExtendResponse> passwordResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, RefusedExtendAttempt).ConfigureAwait(false);
        TpmResult<NvExtendResponse> sessionResult = await ExtendOverHmacAsync(
            device, pool, registry, ExtendIndexHandle, CorrectAuth, RefusedExtendAttempt).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, passwordResult.ResponseCode);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, sessionResult.ResponseCode);
    }

    /// <summary>
    /// The fourth update command answers the lock too: "If the TPMA_NV_WRITELOCKED attribute is SET when an
    /// attempt is made to modify the Index, the TPM returns TPM_RC_NV_LOCKED" — a locked Bit Field Index refuses
    /// <c>TPM2_NV_SetBits()</c> on both session kinds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clause 31.10</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfWriteLockedBitsIndexReturnsNvLockedOnBothSessionKinds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsWriteStclearAttributes, EightOctetDataSize).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvSetBitsResponse> passwordResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, RefusedBits).ConfigureAwait(false);
        TpmResult<NvSetBitsResponse> sessionResult = await SetBitsOverHmacAsync(
            device, pool, registry, BitsIndexHandle, CorrectAuth, RefusedBits).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, passwordResult.ResponseCode);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, sessionResult.ResponseCode);
    }

    /// <summary>
    /// The order pin between the lock gate and the type gate: a write-locked COUNTER Index under
    /// <c>TPM2_NV_Write()</c> answers <c>TPM_RC_NV_LOCKED</c>, not the <c>TPM_RC_ATTRIBUTES</c> its type would
    /// earn — clause 31.7.1 states the lock sentence ahead of "If nvIndexType is TPM_NT_COUNTER, TPM_NT_BITS or
    /// TPM_NT_EXTEND, then the TPM shall return TPM_RC_ATTRIBUTES".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfWriteLockedCounterIndexReturnsNvLockedNotAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterWriteStclearAttributes, EightOctetDataSize).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> result = await WriteIndexAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth, RefusedWriteAttempt).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_LOCKED, result.ResponseCode,
            "The lock is answered ahead of the type, so a locked Counter Index is TPM_RC_NV_LOCKED rather than TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// The order pin between authorization and the lock gate: "If authorization sessions are present, they are
    /// checked before checks to see if writes to the NV Index are locked" — a wrong Index authValue against a
    /// write-locked Index answers the auth-failure, not <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.7.1 and 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfWriteLockedIndexWithWrongAuthReturnsAuthFailNotNvLocked()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> result = await WriteIndexAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, WrongAuth, RefusedWriteAttempt).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode,
            "Authorization precedes the lock gate, so a wrong authValue answers the auth-failure rather than TPM_RC_NV_LOCKED.");
    }

    /// <summary>
    /// A write lock inhibits writes only: clause 31.13.1 gates <c>TPM2_NV_Read()</c> on
    /// <c>TPMA_NV_READLOCKED</c>, never on <c>TPMA_NV_WRITELOCKED</c>, so a write-locked written Index still
    /// reads back its stored octets.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.11.1 and 31.13.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOfWriteLockedIndexStillSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write() failed: '{writeResult.ResponseCode}'.");

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvReadResponse> readResult = await ReadIndexAsync(
            device, pool, registry, WriteStclearIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"A write-locked Index must still be readable: '{readResult.ResponseCode}'.");

        using NvReadResponse read = readResult.Value;
        Assert.IsTrue(IndexData.AsSpan().SequenceEqual(read.Data), "The write lock leaves the stored data intact and readable.");
    }

    /// <summary>
    /// <c>TPM2_NV_Certify()</c> reads the Index's contents, so the write lock leaves it alone as well: Part 4's
    /// <c>NvReadAccessChecks</c> is what the command runs, and that check answers <c>TPMA_NV_READLOCKED</c>
    /// only — a write-locked, written Index certifies successfully.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.16 and 31.11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOfWriteLockedIndexSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(withEccSigningBackend: true).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateSigningRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write() failed: '{writeResult.ResponseCode}'.");

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        using CreatePrimaryResponse signingKey = await CreateSigningPrimaryAsync(device, registry, pool).ConfigureAwait(false);
        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(CorrectAuth, pool);
        using NvCertifyInput certifyInput = NvCertifyInput.ForEcdsa(
            signingKey.ObjectHandle, WriteStclearIndexHandle, WriteStclearIndexHandle, CertifyNonce, TpmAlgIdConstants.TPM_ALG_SHA256,
            OrdinaryDataSize, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            device, certifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"A write lock must not block TPM2_NV_Certify(): '{result.ResponseCode}'.");

        using NvCertifyResponse certified = result.Value;
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECDSA, certified.SignatureAlgorithm, "The attestation over a write-locked Index is signed with the key's ECDSA scheme.");
    }

    /// <summary>
    /// "TPMA_NV_WRITELOCKED will be clear on the next TPM2_Startup(TPM_SU_CLEAR) if either TPMA_NV_WRITEDEFINE
    /// is CLEAR or TPMA_NV_WRITTEN is CLEAR" — a <c>TPMA_NV_WRITE_STCLEAR</c> lock on a WRITTEN Index has
    /// <c>TPMA_NV_WRITEDEFINE</c> CLEAR, so a TPM Reset clears the lock: the attribute word loses
    /// <c>TPMA_NV_WRITELOCKED</c> and the Index accepts a write again.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.11.1 and 9.3; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfWriteStclearIndexClearsOnATpmReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndLockAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A TPM Reset must CLEAR TPMA_NV_WRITELOCKED on an Index whose TPMA_NV_WRITEDEFINE is CLEAR.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"The Index must be writable once the lock has cleared: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// Clause 9.3 lists the same bullet under TPM Restart — "For each NV index with TPMA_NV_WRITEDEFINE CLEAR
    /// or TPMA_NV_WRITTEN CLEAR, TPMA_NV_WRITELOCKED shall be CLEAR" — so a
    /// <c>Shutdown(TPM_SU_STATE)</c>/<c>Startup(TPM_SU_CLEAR)</c> cycle clears a <c>TPMA_NV_WRITE_STCLEAR</c>
    /// lock exactly as a Reset does.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 9.3; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfWriteStclearIndexClearsOnATpmRestart()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndLockAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A TPM Restart must CLEAR TPMA_NV_WRITELOCKED on an Index whose TPMA_NV_WRITEDEFINE is CLEAR.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"The Index must be writable once the lock has cleared: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// The unlock is a TPM Reset and TPM Restart act only: "TPMA_NV_WRITELOCKED will be CLEAR on the next TPM
    /// Reset or TPM Restart" names neither a Resume, and clause 9.3 lists the bullet under neither the Resume
    /// heading nor the every-Startup rules — so after a <c>Shutdown(TPM_SU_STATE)</c>/<c>Startup(TPM_SU_STATE)</c>
    /// cycle the lock stands and a write is still <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clauses 9.3 and 31.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfWriteStclearIndexSurvivesATpmResume()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndLockAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A TPM Resume runs no NV startup pass, so the lock must stand.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, writeResult.ResponseCode, "The Index is still write-locked after a TPM Resume.");
    }

    /// <summary>
    /// The permanent lock: "If the access control attribute TPMA_NV_WRITEDEFINE is SET, TPM2_NV_WriteLock() ...
    /// may be used to permanently disable modify access to the Index ... This attribute will remain SET until the
    /// Index is deleted" — with <c>TPMA_NV_WRITTEN</c> SET as well, clause 9.3's unlock bullet does not apply, so
    /// the lock survives a TPM Reset AND a TPM Restart.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clauses 9.3 and 31.11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfWrittenWriteDefineIndexSurvivesATpmResetAndATpmRestart()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndLockAsync(device, pool, registry, WriteDefineIndexHandle, WriteDefineAttributes).ConfigureAwait(false);

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv afterReset = await ReadIndexAttributesAsync(device, WriteDefineIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, afterReset & TpmaNv.TPMA_NV_WRITELOCKED, "A written TPMA_NV_WRITEDEFINE Index keeps its lock across a TPM Reset.");

        TpmResult<NvWriteResponse> afterResetWrite = await WriteIndexAsync(
            device, pool, registry, WriteDefineIndexHandle, WriteDefineIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, afterResetWrite.ResponseCode, "The permanent lock still refuses a write after a TPM Reset.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv afterRestart = await ReadIndexAttributesAsync(device, WriteDefineIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, afterRestart & TpmaNv.TPMA_NV_WRITELOCKED, "A written TPMA_NV_WRITEDEFINE Index keeps its lock across a TPM Restart too.");

        TpmResult<NvWriteResponse> afterRestartWrite = await WriteIndexAsync(
            device, pool, registry, WriteDefineIndexHandle, WriteDefineIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, afterRestartWrite.ResponseCode, "The permanent lock still refuses a write after a TPM Restart.");
    }

    /// <summary>
    /// "This attribute will remain SET until the Index is deleted (TPM2_NV_UndefineSpace())" — the deletion is
    /// the way out: <c>TPM2_NV_UndefineSpace()</c> carries no lock gate, and a redefinition at the same handle
    /// begins with <c>TPMA_NV_WRITELOCKED</c> CLEAR ("When the Index is created ... TPMA_NV_WRITELOCKED,
    /// TPMA_NV_READLOCKED, and TPMA_NV_WRITTEN shall all be CLEAR") and is writable.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 2, clause 13.4; Part 3, clauses 31.4 and 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvUndefineSpaceOfPermanentlyWriteLockedIndexAllowsAWritableRedefinition()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndLockAsync(device, pool, registry, WriteDefineIndexHandle, WriteDefineAttributes).ConfigureAwait(false);

        TpmResult<NvUndefineSpaceResponse> undefineResult = await UndefineIndexAsync(device, pool, registry, WriteDefineIndexHandle).ConfigureAwait(false);
        Assert.IsTrue(undefineResult.IsSuccess, $"TPM2_NV_UndefineSpace() of a permanently locked Index must succeed: '{undefineResult.ResponseCode}'.");

        TpmResult<NvDefineSpaceResponse> redefineResult = await DefineIndexAsync(
            device, pool, registry, WriteDefineIndexHandle, WriteDefineAttributes).ConfigureAwait(false);
        Assert.IsTrue(redefineResult.IsSuccess, $"The redefinition must succeed: '{redefineResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteDefineIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "A newly defined Index carries TPMA_NV_WRITELOCKED CLEAR.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteDefineIndexHandle, WriteDefineIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"The redefined Index must be writable: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// "If TPMA_NV_WRITELOCKED is SET, but TPMA_NV_WRITTEN is CLEAR, then TPMA_NV_WRITELOCKED is CLEAR by TPM
    /// Reset or TPM Restart. This is true even if the TPMA_NV_WRITEDEFINE attribute is set. It prevents an NV
    /// Index from being defined that can never be written" — an UNWRITTEN <c>TPMA_NV_WRITEDEFINE</c> Index locked
    /// before its first write is unlocked by a TPM Reset and then accepts that first write.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clauses 9.3 and 31.11.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfUnwrittenWriteDefineIndexClearsOnATpmResetAndTheIndexAcceptsItsFirstWrite()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteDefineIndexHandle, WriteDefineAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteDefineIndexHandle, WriteDefineIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"An unwritten Index may be locked: '{lockResult.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteDefineIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "TPMA_NV_WRITTEN CLEAR unlocks the Index even under TPMA_NV_WRITEDEFINE.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteDefineIndexHandle, WriteDefineIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"The Index must accept its first write once the lock has cleared: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// The two startup rules compose in the reference's order: the pass CLEARs <c>TPMA_NV_WRITTEN</c> first
    /// ("For each NV Index with TPMA_NV_CLEAR_STCLEAR SET, TPMA_NV_WRITTEN shall be CLEAR") and judges the
    /// WRITELOCKED unlock over the result ("For each NV Index with TPMA_NV_WRITEDEFINE CLEAR or TPMA_NV_WRITTEN
    /// CLEAR, TPMA_NV_WRITELOCKED shall be CLEAR"), which is what keeps a written-and-locked
    /// <c>TPMA_NV_WRITEDEFINE</c> + <c>TPMA_NV_CLEAR_STCLEAR</c> Index from becoming an Index that can never be
    /// written again.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 9.3; Part 1, clause 34.2.6.1; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOfWriteDefineClearStclearIndexClearsWithTheWrittenAttributeOnATpmReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineWriteAndLockAsync(device, pool, registry, WriteDefineClearStclearIndexHandle, WriteDefineClearStclearAttributes).ConfigureAwait(false);

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteDefineClearStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITTEN, "TPMA_NV_CLEAR_STCLEAR CLEARs TPMA_NV_WRITTEN on a TPM Reset.");
        Assert.AreEqual(default(TpmaNv), attributes & TpmaNv.TPMA_NV_WRITELOCKED, "The unlock is judged over the WRITTEN bit the same pass has just cleared.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteDefineClearStclearIndexHandle, WriteDefineClearStclearIndexHandle, CorrectAuth, SecondIndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"The Index must be writable again: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// The Index arm over an unbound, unsalted HMAC session: the command HMAC verifies against a cpHash whose
    /// Name terms are the Index's Name AS THE COMMAND FOUND IT — the pre-lock Name, since the lock moves the
    /// Name — and the Index carries <c>TPMA_NV_WRITELOCKED</c> afterwards.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15; clause 13; Part 3, clause 31.11</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOverHmacSessionAtTheIndexArmLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> result = await WriteLockOverHmacAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_WriteLock() over an HMAC session failed: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED, "The session arm SETs the same lock bit the password arm does.");
    }

    /// <summary>
    /// The owner arm over an HMAC session: cpHash's Name1 is the owner's raw handle (Part 1, Table 9: a
    /// permanent handle's Name IS its handle value) and Name2 the Index's computed Name; the empty owner
    /// authValue keys the HMAC alongside the empty session key, and the Index locks.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15; clause 13, Table 9; Part 3, clause 31.11</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOverHmacSessionAtTheOwnerArmLocks()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> result = await WriteLockOverHmacAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, WriteStclearIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized lock over an HMAC session failed: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);
        Assert.AreEqual(TpmaNv.TPMA_NV_WRITELOCKED, attributes & TpmaNv.TPMA_NV_WRITELOCKED, "The owner arm over a session locks the Index just as the password owner arm does.");
    }

    /// <summary>
    /// A wrong Index authValue proven over an HMAC session is the same auth-failure the password arm answers,
    /// session-encoded — the base error is <c>TPM_RC_AUTH_FAIL</c> and the raw wire code carries the
    /// session-index modifier — and it charges <c>failedTries</c> exactly once, mechanism-blind.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOverHmacSessionWithWrongAuthReturnsSessionEncodedAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> result = await WriteLockOverHmacAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError);
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode, "A command-HMAC mismatch names the offending session, so the raw wire code carries the session-index modifier.");
        Assert.AreEqual(counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong DA-protected authValue proven over a session must charge failedTries once.");
    }

    /// <summary>
    /// The stranger-authHandle answer survives on the HMAC arm exactly as on the password arm: an
    /// <c>authHandle</c> that is neither the owner hierarchy nor the Index itself is
    /// <c>TPM_RC_NV_AUTHORIZATION</c>, refused before any HMAC is evaluated.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOverHmacSessionWithMismatchedAuthHandleReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> result = await WriteLockOverHmacAsync(
            device, pool, registry, MismatchedAuthHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// <c>TPM2_NV_WriteLock()</c> carries no command parameters at all (Table 261), so a <c>decrypt</c>-attributed
    /// authorizing session has nothing to act on and the TPM fails closed with <c>TPM_RC_ATTRIBUTES</c> naming
    /// the session — proved hand-framed, since the executor's own client-side guard refuses this composition
    /// before any bytes reach the wire.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.7 and 31.11.2; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOverSessionWithDecryptAttributeReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmRcConstants rawCode = await WriteLockOverHmacHandFramedAsync(
            device, pool, registry, WriteStclearIndexHandle, CorrectAuth, TpmaSession.DECRYPT).ConfigureAwait(false);
        TpmResult<NvWriteLockResponse> result = TpmResult<NvWriteLockResponse>.TpmError(rawCode);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError, "A parameterless command has nothing to decrypt, so a decrypt-attributed session must fail closed.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");
    }

    /// <summary>
    /// The response side of the same rule: <c>TPM2_NV_WriteLock()</c>'s response is the header alone (Table
    /// 262), so an <c>encrypt</c>-attributed session has nothing to act on and is refused with
    /// <c>TPM_RC_ATTRIBUTES</c> naming the session.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.7 and 31.11.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOverSessionWithEncryptAttributeReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmRcConstants rawCode = await WriteLockOverHmacHandFramedAsync(
            device, pool, registry, WriteStclearIndexHandle, CorrectAuth, TpmaSession.ENCRYPT).ConfigureAwait(false);
        TpmResult<NvWriteLockResponse> result = TpmResult<NvWriteLockResponse>.TpmError(rawCode);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError, "A header-only response has nothing to encrypt, so an encrypt-attributed session must fail closed.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");
    }

    /// <summary>
    /// The <c>audit</c> attribute on the authorizing session fails closed with <c>TPM_RC_ATTRIBUTES</c> naming
    /// the session — no audit trail is modelled — proved the same hand-framed way as the encrypt half.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOverSessionWithAuditAttributeReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmRcConstants rawCode = await WriteLockOverHmacHandFramedAsync(
            device, pool, registry, WriteStclearIndexHandle, CorrectAuth, TpmaSession.AUDIT).ConfigureAwait(false);
        TpmResult<NvWriteLockResponse> result = TpmResult<NvWriteLockResponse>.TpmError(rawCode);

        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.BaseError, "No audit trail is modelled, so an audit-attributed session must fail closed.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");
    }

    /// <summary>
    /// "The caller should use its copy of the NV public area and calculate the Name before using it in an HMAC
    /// authorization calculation. Otherwise, an invalid authorization can trigger the dictionary attack
    /// protection" — end to end: after a <c>TPM2_NV_WriteLock()</c>, a <c>TPM2_NV_Read()</c> over an HMAC session
    /// whose handle Names carry the STALE pre-lock Name is refused with a session-encoded
    /// <c>TPM_RC_AUTH_FAIL</c> and charges <c>failedTries</c>, while the same read folding the fresh Name
    /// succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 13 and 15.7; Part 3, clause 31.13</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOverHmacSessionFoldingTheStaleNameAfterAWriteLockReturnsAuthFailWhileTheFreshNameSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write() failed: '{writeResult.ResponseCode}'.");

        byte[] staleName = await ReadIndexNameAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");

        byte[] freshName = await ReadIndexNameAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadResponse> staleResult = await ReadIndexOverHmacWithNamesAsync(
            device, pool, registry, WriteStclearIndexHandle, CorrectAuth, OrdinaryDataSize, [staleName, staleName]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, staleResult.BaseError, "A cpHash folding the pre-lock Name cannot match the one the TPM computes over the locked Index.");
        Assert.AreEqual(counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "The stale-Name authorization is an ordinary authorization failure and charges failedTries.");

        TpmResult<NvReadResponse> freshResult = await ReadIndexOverHmacWithNamesAsync(
            device, pool, registry, WriteStclearIndexHandle, CorrectAuth, OrdinaryDataSize, [freshName, freshName]).ConfigureAwait(false);
        Assert.IsTrue(freshResult.IsSuccess, $"The same read folding the fresh Name must succeed: '{freshResult.ResponseCode}'.");

        using NvReadResponse read = freshResult.Value;
        Assert.IsTrue(IndexData.AsSpan().SequenceEqual(read.Data), "The read returns the octets the Index holds.");
    }

    /// <summary>
    /// The password form returns every carrier its parse rented on each path: a refusal at the existence gate
    /// (before authorization), a refusal at the lockability gate (after authorization), and a success — the
    /// metered pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.11</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockReturnsItsCarriersAcrossRefusalsAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, PlainIndexHandle, PlainAttributes).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvWriteLockResponse> undefinedResult = await WriteLockAsync(
            device, pool, registry, WriteDefineIndexHandle, WriteDefineIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, undefinedResult.ResponseCode);
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal before authorization releases the supplied credential through the request's own Dispose.");

        TpmResult<NvWriteLockResponse> plainResult = await WriteLockAsync(
            device, pool, registry, PlainIndexHandle, PlainIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, plainResult.ResponseCode);
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal after authorization releases the supplied credential through the request's own Dispose.");

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(
            device, pool, registry, WriteStclearIndexHandle, WriteStclearIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The accepting transition is the credential's terminal owner and must release it.");
    }

    /// <summary>
    /// The HMAC-session form returns every carrier its parse rented — the raw parameter area, the slot
    /// credentials and the computed Index Name — across a refusal at the command HMAC and a success: the metered
    /// pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.11; Part 1, clause 15.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteLockOverHmacSessionReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WriteStclearIndexHandle, WriteStclearAttributes).ConfigureAwait(false);
        ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, WriteStclearIndexHandle).ConfigureAwait(false);
        ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

        (uint wrongSessionHandle, TpmSession wrongSession) = await StartUnboundSessionAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
        (uint correctSessionHandle, TpmSession correctSession) = await StartUnboundSessionAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        try
        {
            using(wrongSession)
            using(correctSession)
            {
                long baseline = trackingPool.OutstandingCount;

                var refusedInput = new NvWriteLockInput(WriteStclearIndexHandle, WriteStclearIndexHandle);
                TpmResult<NvWriteLockResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvWriteLockResponse>(
                    device, refusedInput, [wrongSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, refused.BaseError);
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A command refused at its command HMAC releases every carrier its parse rented.");

                var acceptedInput = new NvWriteLockInput(WriteStclearIndexHandle, WriteStclearIndexHandle);
                TpmResult<NvWriteLockResponse> accepted = await TpmCommandExecutor.ExecuteAsync<NvWriteLockResponse>(
                    device, acceptedInput, [correctSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                Assert.IsTrue(accepted.IsSuccess, $"TPM2_NV_WriteLock() over an HMAC session failed: '{accepted.ResponseCode}'.");
                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The accepting continuation and the response framing between them release every carrier.");
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(wrongSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(correctSessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Defines <paramref name="nvIndex"/>, populates it with <see cref="IndexData"/> and locks it for writing,
    /// asserting each step — the starting position of every startup-pass proof, which needs both
    /// <c>TPMA_NV_WRITTEN</c> and <c>TPMA_NV_WRITELOCKED</c> SET.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define, write and lock.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    private async Task DefineWriteAndLockAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes)
    {
        TpmResult<NvDefineSpaceResponse> defineResult = await DefineIndexAsync(device, pool, registry, nvIndex, attributes).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"TPM2_NV_DefineSpace() failed: '{defineResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(device, pool, registry, nvIndex, nvIndex, CorrectAuth, IndexData).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"TPM2_NV_Write() failed: '{writeResult.ResponseCode}'.");

        TpmResult<NvWriteLockResponse> lockResult = await WriteLockAsync(device, pool, registry, nvIndex, nvIndex, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_WriteLock() failed: '{lockResult.ResponseCode}'.");
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
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        var session = new TpmSession(new TpmHandle(started.SessionHandle.Value), started.NonceTPM, HmacSessionAlg, pool);
        session.SetAuthValue(authValue.Span, pool);

        return (started.SessionHandle.Value, session);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_WriteLock()</c> over an UNBOUND, unsalted HMAC session whose authValue is
    /// <paramref name="suppliedAuth"/>, on the Index arm (cpHash Names <c>[indexName, indexName]</c>) or the
    /// owner arm (<c>[ownerHandle, indexName]</c>). The Index Name is read back from the TPM before the command,
    /// which is the Name the TPM itself folds — the lock moves it only afterwards (Part 1, clause 13).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing handle: the Index itself, <c>TPM_RH_OWNER</c>, or a stranger.</param>
    /// <param name="nvIndex">The Index to lock.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <returns>The write-lock result.</returns>
    private async Task<TpmResult<NvWriteLockResponse>> WriteLockOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);
                ReadOnlyMemory<byte> authName = authHandle == nvIndex ? indexName : HandleFormName(authHandle);
                ReadOnlyMemory<byte>[] handleNames = [authName, indexName];
                var input = new NvWriteLockInput(authHandle, nvIndex);

                return await TpmCommandExecutor.ExecuteAsync<NvWriteLockResponse>(
                    device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The SIMULATOR-side proof for the session-attribute fail-closed gate: hand-frames a raw
    /// <c>TPM2_NV_WriteLock()</c> authorized by a single unbound, unsalted HMAC session whose
    /// <c>sessionAttributes</c> octet carries <paramref name="attribute"/>, and submits it directly to the
    /// transport — bypassing <see cref="TpmCommandExecutor"/>, whose own client-side guard would refuse this
    /// composition before any bytes reach the wire. The cpHash and command HMAC are the SAME production
    /// computation <see cref="TpmSession"/> performs for every other session-authorized test in this file; the
    /// command has no parameters, so equation (15)'s parameters term is EMPTY and cpHash folds the command code
    /// and the two Names alone.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own StartAuthSession/FlushContext lifecycle).</param>
    /// <param name="nvIndex">The Index to lock; also the authorizing handle.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test.</param>
    /// <returns>The raw wire response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> WriteLockOverHmacHandFramedAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, TpmaSession attribute)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, pool);
            session.SetAuthValue(suppliedAuth.Span, pool);
            session.SessionAttributes |= attribute;

            ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);

            //cpHash = H_SHA256(commandCode || Name(authHandle) || Name(nvIndex)) — TPM 2.0 Library Part 1, clause
            //15.7, equation 15, with an EMPTY parameters term because Table 261 defines no command parameters.
            //This arm's authHandle and nvIndex are the same Index, so both Name terms are identical.
            int cpHashInputLength = sizeof(uint) + indexName.Length + indexName.Length;
            using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
            Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
            {
                var cpHashWriter = new TpmWriter(cpHashInput.Span);
                cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_WriteLock);
                cpHashWriter.WriteBytes(indexName.Span);
                cpHashWriter.WriteBytes(indexName.Span);
            }

            using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
                cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.RollNonceCaller(pool);
            using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
                cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

            const int handlesSize = 2 * sizeof(uint);
            int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
            int totalSize = TpmHeader.HeaderSize + handlesSize + authAreaSize;

            using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
            Memory<byte> command = commandOwner.Memory[..totalSize];
            var writer = new TpmWriter(command.Span);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
            writer.WriteUInt32((uint)totalSize);
            writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_WriteLock);
            writer.WriteUInt32(nvIndex);
            writer.WriteUInt32(nvIndex);
            writer.WriteUInt32((uint)session.GetAuthCommandSize());
            session.WriteAuthCommand(ref writer, hmac);

            TpmResult<TpmResponse> transportResult = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(transportResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

            using TpmResponse response = transportResult.Value;
            var responseReader = new TpmReader(response.AsReadOnlySpan());
            TpmHeader responseHeader = TpmHeader.Parse(ref responseReader);

            return (TpmRcConstants)responseHeader.Code;
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Builds the digest <see cref="Tag"/> used to independently compute cpHash for
    /// <see cref="WriteLockOverHmacHandFramedAsync"/>: SHA-256 digest, raw encoding, direct material — the same
    /// shape <c>TpmCommandExecutor</c>'s own cpHash computation uses.
    /// </summary>
    /// <returns>The digest tag.</returns>
    private static Tag DigestTag() =>
        Tag.Create(HashAlgorithmName.SHA256).With(Purpose.Digest).With(EncodingScheme.Raw).With(MaterialSemantics.Direct);

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

    /// <summary>Reads <c>TPM_PT_LOCKOUT_COUNTER</c>, the live <c>failedTries</c> value, back over <c>TPM2_GetCapability()</c>.</summary>
    /// <param name="device">The device the capability is read through.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The reported counter value.</returns>
    private async Task<uint> ReadLockoutCounterAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        TpmResult<GetCapabilityResponse> result = await TpmCommandExecutor.ExecuteAsync<GetCapabilityResponse>(
            device, GetCapabilityInput.ForTpmProperties(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, count: 1), [], null, pool, registry,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"GetCapability(TPM_PT_LOCKOUT_COUNTER) failed: '{result.ResponseCode}'.");

        using GetCapabilityResponse properties = result.Value;
        var reported = properties.CapabilityData.TpmProperties;
        Assert.IsNotNull(reported);
        Assert.IsNotEmpty(reported);
        Assert.AreEqual(TpmPtConstants.TPM_PT_LOCKOUT_COUNTER, reported[0].Property);

        return reported[0].Value;
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
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
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
    /// <param name="authHandle">The authorization handle (the Index itself, the owner hierarchy, or a mismatched value).</param>
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

    /// <summary>Issues a password-authorized <c>TPM2_NV_Increment()</c> against <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle.</param>
    /// <param name="nvIndex">The Counter Index to increment.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <returns>The increment result.</returns>
    private async Task<TpmResult<NvIncrementResponse>> IncrementAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvIncrementInput(authHandle, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_Increment()</c> over an unbound, unsalted HMAC session.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Counter Index to increment.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <returns>The increment result.</returns>
    private async Task<TpmResult<NvIncrementResponse>> IncrementOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);
                ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];
                var input = new NvIncrementInput(nvIndex, nvIndex);

                return await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
                    device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>Issues a password-authorized <c>TPM2_NV_Extend()</c> against <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle.</param>
    /// <param name="nvIndex">The Extend Index to extend.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="data">The octets to fold in.</param>
    /// <returns>The extend result.</returns>
    private async Task<TpmResult<NvExtendResponse>> ExtendAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth,
        ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var input = new NvExtendInput(authHandle, nvIndex, buffer);

        return await TpmCommandExecutor.ExecuteAsync<NvExtendResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_Extend()</c> over an unbound, unsalted HMAC session.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Extend Index to extend.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="data">The octets to fold in.</param>
    /// <returns>The extend result.</returns>
    private async Task<TpmResult<NvExtendResponse>> ExtendOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> data)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);
                ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

                using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
                var input = new NvExtendInput(nvIndex, nvIndex, buffer);

                return await TpmCommandExecutor.ExecuteAsync<NvExtendResponse>(
                    device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>Issues a password-authorized <c>TPM2_NV_SetBits()</c> against <paramref name="nvIndex"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle.</param>
    /// <param name="nvIndex">The Bit Field Index whose bits are SET.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="bits">The value ORed into the Index's current contents.</param>
    /// <returns>The set-bits result.</returns>
    private async Task<TpmResult<NvSetBitsResponse>> SetBitsAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ulong bits)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvSetBitsInput(authHandle, nvIndex, bits);

        return await TpmCommandExecutor.ExecuteAsync<NvSetBitsResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues an Index-arm <c>TPM2_NV_SetBits()</c> over an unbound, unsalted HMAC session.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Bit Field Index whose bits are SET.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="bits">The value ORed into the Index's current contents.</param>
    /// <returns>The set-bits result.</returns>
    private async Task<TpmResult<NvSetBitsResponse>> SetBitsOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ulong bits)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);
                ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];
                var input = new NvSetBitsInput(nvIndex, nvIndex, bits);

                return await TpmCommandExecutor.ExecuteAsync<NvSetBitsResponse>(
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

    /// <summary>
    /// Issues an Index-arm <c>TPM2_NV_Read()</c> over an unbound, unsalted HMAC session whose cpHash folds
    /// <paramref name="handleNames"/> — supplied by the caller so a deliberately STALE Name can be proven.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="suppliedAuth">The authValue proven by the HMAC session.</param>
    /// <param name="size">The number of octets to read.</param>
    /// <param name="handleNames">The Name terms cpHash folds, in handle order.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexOverHmacWithNamesAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ushort size,
        ReadOnlyMemory<byte>[] handleNames)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                var input = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: size, Offset: 0);

                return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    device, input, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
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
            ? new TpmSimulator("tpm-in-house-nv-writelock", signingBackend: BouncyCastleTpmEccSigningBackend.Create())
            : new TpmSimulator("tpm-in-house-nv-writelock");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitSessionlessAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
