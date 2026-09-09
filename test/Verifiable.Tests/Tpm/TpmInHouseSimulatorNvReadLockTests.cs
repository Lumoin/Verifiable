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
/// Drives <c>TPM2_NV_ReadLock()</c> — its read authorization ladder on both arms over a password and over an
/// HMAC session, the <c>TPMA_NV_READ_STCLEAR</c> lockability rule, the <c>TPMA_NV_READLOCKED</c> bit it SETs and
/// the Name that bit moves, the gate that bit places on the whole read family
/// (<c>TPM2_NV_Read()</c>, <c>TPM2_NV_Certify()</c>, <c>TPM2_PolicyNV()</c> and
/// <c>TPM2_PolicyAuthorizeNV()</c>) while leaving every write command untouched, and the startup pass that
/// CLEARs the bit on a TPM Reset and a TPM Restart but not a TPM Resume — against the in-house behavioural
/// <see cref="TpmSimulator"/>, entirely in-process with no external assets, through the same production command
/// path the production code uses (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM
/// 2.0 Library Part 1, clauses 13, 34.2.5 and 34.2.6.6; Part 3, clauses 31.13.1, 31.14, 23.9, 23.22 and 9.3.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvReadLockTests
{
    /// <summary>The declared data size of every Ordinary Index this file defines.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>
    /// The declared data size of a Counter, Bit Field or PIN Index: "publicInfo→dataSize shall be set to eight
    /// (8)" (TPM 2.0 Library Part 3, clause 31.3.1).
    /// </summary>
    private const ushort EightOctetDataSize = 8;

    /// <summary>The SHA-256 digest width in octets — the cpHash width every session in this file folds.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>The primary read-lockable Ordinary Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint ReadLockIndexHandle = 0x0100_0080;

    /// <summary>A read-lockable Ordinary Index opted out of dictionary-attack protection.</summary>
    private const uint NonDaIndexHandle = 0x0100_0081;

    /// <summary>A read-lockable Ordinary Index deliberately missing <c>TPMA_NV_OWNERREAD</c>.</summary>
    private const uint WithoutOwnerReadIndexHandle = 0x0100_0082;

    /// <summary>A read-lockable Ordinary Index deliberately missing <c>TPMA_NV_AUTHREAD</c>.</summary>
    private const uint WithoutAuthReadIndexHandle = 0x0100_0083;

    /// <summary>An Ordinary Index deliberately missing <c>TPMA_NV_READ_STCLEAR</c>, so it cannot be read-locked at all.</summary>
    private const uint PlainIndexHandle = 0x0100_0084;

    /// <summary>A read-lockable Counter Index, proving a read lock never blocks <c>TPM2_NV_Increment()</c>.</summary>
    private const uint CounterIndexHandle = 0x0100_0085;

    /// <summary>A read-lockable Bit Field Index, proving a read lock never blocks <c>TPM2_NV_SetBits()</c>.</summary>
    private const uint BitsIndexHandle = 0x0100_0086;

    /// <summary>A read-lockable PIN Pass Index, whose pinCount a read lock's authorization consumes.</summary>
    private const uint PinPassIndexHandle = 0x0100_0087;

    /// <summary>A PIN Fail Index handle, whose own pinCount is the only throttle on a wrong PIN.</summary>
    private const uint PinFailIndexHandle = 0x0100_0088;

    /// <summary>An Index handle this file never defines, used for the undefined-handle and pre-authorization refusals.</summary>
    private const uint UndefinedIndexHandle = 0x0100_008E;

    /// <summary>An <c>authHandle</c> that is neither the owner hierarchy nor any Index defined in this file.</summary>
    private const uint MismatchedAuthHandle = 0x0100_008F;

    /// <summary>The hash algorithm for every HMAC-arm and policy session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The pinLimit provisioned into the PIN Pass Index whose pinCount a read lock consumes.</summary>
    private const uint PinLimit = 3;

    /// <summary>
    /// Ordinary Index attributes admitting both authorization arms for reads and writes and electing
    /// <c>TPMA_NV_READ_STCLEAR</c>, which is what makes <c>TPM2_NV_ReadLock()</c> usable at all: "If
    /// TPMA_NV_READ_STCLEAR is SET in an Index, then this command may be used to prevent further reads"
    /// (TPM 2.0 Library Part 3, clause 31.14.1). Dictionary-attack protected (<c>TPMA_NV_NO_DA</c> clear).
    /// </summary>
    private const TpmaNv ReadStclearAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_OWNERWRITE
        | TpmaNv.TPMA_NV_READ_STCLEAR;

    /// <summary>The same read-lockable attributes, opted out of dictionary-attack protection.</summary>
    private const TpmaNv NonDaReadStclearAttributes = ReadStclearAttributes | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>The same read-lockable attributes with <c>TPMA_NV_OWNERREAD</c> deliberately CLEAR.</summary>
    private const TpmaNv ReadStclearWithoutOwnerReadAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_READ_STCLEAR;

    /// <summary>The same read-lockable attributes with <c>TPMA_NV_AUTHREAD</c> deliberately CLEAR.</summary>
    private const TpmaNv ReadStclearWithoutAuthReadAttributes =
        TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_READ_STCLEAR;

    /// <summary>Ordinary Index attributes WITHOUT <c>TPMA_NV_READ_STCLEAR</c>, the fixture for clause 31.14.1's attribute refusal.</summary>
    private const TpmaNv PlainAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>Read-lockable Counter Index attributes (TPM_NT rides bits 7:4 of TPMA_NV, Part 2, clause 13.4).</summary>
    private const TpmaNv CounterReadStclearAttributes =
        ReadStclearAttributes | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Read-lockable Bit Field Index attributes.</summary>
    private const TpmaNv BitsReadStclearAttributes =
        ReadStclearAttributes | (TpmaNv)((uint)TpmNt.TPM_NT_BITS << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>
    /// Read-lockable PIN Pass Index attributes: <c>TPMA_NV_NO_DA</c> keeps the Index's own pinCount defence
    /// disjoint from the TPM-wide dictionary-attack mechanism, <c>TPMA_NV_AUTHWRITE</c> stays CLEAR because a PIN
    /// Index's own authValue authorizes reads only (TPM 2.0 Library Part 1, clause 34.2.6.1), and
    /// <c>TPMA_NV_OWNERWRITE</c>/<c>TPMA_NV_OWNERREAD</c> carry the owner-authorized provisioning and observation
    /// of <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c>.
    /// </summary>
    private const TpmaNv PinPassReadStclearAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA
        | TpmaNv.TPMA_NV_READ_STCLEAR | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_PASS << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>
    /// Read-lockable PIN Fail Index attributes — the same shape with <c>TPM_NT_PIN_FAIL</c>, whose
    /// <c>TPMA_NV_NO_DA</c> is mandatory ("If nvIndexType is TPM_NT_PIN_FAIL, then TPMA_NV_NO_DA shall be SET", TPM
    /// 2.0 Library Part 3, clause 31.3.1), so its own pinCount is the ONLY throttle on a wrong authValue.
    /// </summary>
    private const TpmaNv PinFailReadStclearAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERREAD | TpmaNv.TPMA_NV_OWNERWRITE | TpmaNv.TPMA_NV_NO_DA
        | TpmaNv.TPMA_NV_READ_STCLEAR | (TpmaNv)((uint)TpmNt.TPM_NT_PIN_FAIL << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong Index authorization value, distinct from <see cref="CorrectAuth"/>.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>A wrong owner authorization value; this simulator's owner authValue is empty, so any non-empty value is wrong.</summary>
    private static byte[] WrongOwnerAuth { get; } = [0x77, 0x77, 0x77, 0x77];

    /// <summary>The octets stored in an Ordinary Index before it is locked, so an unlocked read has something to answer.</summary>
    private static byte[] StoredData { get; } =
        [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];

    /// <summary>The octets an unwritten Index's first <c>TPM2_NV_Write()</c> stores after the Index has been read-locked.</summary>
    private static byte[] FirstWriteData { get; } = [0xA1, 0xA2, 0xA3, 0xA4];

    /// <summary>The comparand <c>TPM2_PolicyNV()</c> compares the Index contents against.</summary>
    private static byte[] PolicyOperand { get; } = [0x10, 0x11, 0x12, 0x13];

    /// <summary>The fixed caller nonce (qualifyingData) the <c>TPM2_NV_Certify()</c> proofs echo into extraData.</summary>
    private static byte[] CertifyNonce { get; } = "NvReadLock nonce for the in-house TPM."u8.ToArray();

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies <c>TPM2_NV_ReadLock()</c> against an undefined handle answers <c>TPM_RC_HANDLE</c>: "an Index
    /// exists that corresponds to the handle (TPM_RC_HANDLE)".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.14; clause 5.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOfUndefinedIndexReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvReadLockResponse> result = await ReadLockAsync(
            device, pool, registry, UndefinedIndexHandle, UndefinedIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode, "Table 267: nvIndex is TPM2_NV_ReadLock()'s second handle (handle 2); an undefined Index is handle-encoded TPM_RC_HANDLE at index 1.");
    }

    /// <summary>
    /// "If the command is properly authorized and TPMA_NV_READ_STCLEAR of the NV Index is SET, then the TPM shall
    /// SET TPMA_NV_READLOCKED for the NV Index" — read back through <c>TPM2_NV_ReadPublic()</c>'s attribute word —
    /// and thereafter "If TPMA_NV_READLOCKED of the NV Index is SET, then the TPM shall return TPM_RC_NV_LOCKED"
    /// on the Index arm of <c>TPM2_NV_Read()</c>, which succeeded on the very same window a moment earlier.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.14.1 and 31.13.1; Part 1, clause 34.2.5</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOfReadStclearIndexSetsReadLockedAndRefusesTheIndexArmRead()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadResponse> beforeResult = await ReadIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);
        Assert.IsTrue(beforeResult.IsSuccess, $"The read before the lock must succeed: '{beforeResult.ResponseCode}'.");
        using(NvReadResponse beforeRead = beforeResult.Value)
        {
            Assert.IsTrue(StoredData.AsSpan().SequenceEqual(beforeRead.Data), "The unlocked Index answers the octets a write stored.");
        }

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, ReadLockIndexHandle).ConfigureAwait(false);
        Assert.AreNotEqual((TpmaNv)0, attributes & TpmaNv.TPMA_NV_READLOCKED, "The lock must be visible in the Index's public attribute word.");

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, afterResult.ResponseCode);
    }

    /// <summary>
    /// The lock is a property of the Index, not of the authorization that set it: with <c>TPMA_NV_OWNERREAD</c>
    /// SET, an owner-authorized <c>TPM2_NV_Read()</c> of an Index locked through its own authValue is equally
    /// "TPM_RC_NV_LOCKED".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.13.1; Part 1, clause 34.2.5</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOfReadLockedIndexByOwnerAuthorizationReturnsNvLocked()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvReadResponse> ownerResult = await ReadIndexAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadLockIndexHandle, ReadOnlyMemory<byte>.Empty, OrdinaryDataSize).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, ownerResult.ResponseCode);
    }

    /// <summary>
    /// "If TPMA_NV_READ_STCLEAR of the NV Index is CLEAR, then the TPM shall return TPM_RC_ATTRIBUTES" — and the
    /// attribute gate runs AFTER the authorization ("If authorization sessions are present, they are checked
    /// before the read-lock status of the NV Index is checked", clause 31.13.1's twin rule), so the same Index
    /// under a WRONG authValue answers the auth-failure instead.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.13.1 and 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockWithoutReadStclearReturnsAttributesUnderCorrectAuthAndAuthFailUnderWrongAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PlainIndexHandle, PlainAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> correctResult = await ReadLockAsync(
            device, pool, registry, PlainIndexHandle, PlainIndexHandle, CorrectAuth).ConfigureAwait(false);
        TpmResult<NvReadLockResponse> wrongResult = await ReadLockAsync(
            device, pool, registry, PlainIndexHandle, PlainIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), correctResult.ResponseCode, "An Index without TPMA_NV_READ_STCLEAR cannot be read-locked at all.");
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode, "The authorization is resolved first, so a wrong authValue answers the auth-failure rather than the attribute refusal.");
    }

    /// <summary>
    /// "If TPMA_NV_READLOCKED for the NV Index is already SET: if proper read authorization is provided, the TPM
    /// shall return TPM_RC_SUCCESS" — and nothing changes, which the Index Name proves: the Name digests the
    /// attribute word (Part 1, clause 13), so a repeat lock that altered any bit would move it.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.14.1; Part 1, clause 13</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOfAlreadyLockedIndexReturnsSuccessWithTheNameUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> firstResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The first TPM2_NV_ReadLock() failed: '{firstResult.ResponseCode}'.");
        byte[] nameAfterFirst = await ReadIndexNameAsync(device, ReadLockIndexHandle).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> secondResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        byte[] nameAfterSecond = await ReadIndexNameAsync(device, ReadLockIndexHandle).ConfigureAwait(false);

        Assert.IsTrue(secondResult.IsSuccess, $"A properly authorized repeat of TPM2_NV_ReadLock() must succeed: '{secondResult.ResponseCode}'.");
        Assert.IsTrue(nameAfterFirst.AsSpan().SequenceEqual(nameAfterSecond), "An already-locked Index is left exactly as it is, so its Name must be stable across the repeat.");
    }

    /// <summary>
    /// The permissive half of the already-locked rule — "if proper read authorization is not provided, the TPM
    /// may return either TPM_RC_SUCCESS or an authorization error response" — is exercised as the authorization
    /// error: a wrong authValue against an already-locked, dictionary-attack protected Index is
    /// <c>TPM_RC_AUTH_FAIL</c> and charges <c>failedTries</c>, the lock never short-circuiting the compare.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.14.1; Part 1, clauses 16.8.1 and 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOfAlreadyLockedIndexWithWrongAuthReturnsAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> wrongResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode, "authHandle's authorizing session is session 1 of Table 267 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong authValue on an already-locked, DA-protected Index is session-encoded TPM_RC_AUTH_FAIL there.");
        Assert.AreEqual(counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong DA-protected authValue must charge failedTries once even against an already-locked Index.");
    }

    /// <summary>
    /// "An Index that had not been written may be locked for reading" — there is no <c>TPMA_NV_WRITTEN</c> gate on
    /// this command — and the lock binds reads alone, so the Index still accepts its very first
    /// <c>TPM2_NV_Write()</c> afterwards.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.14.1 and 31.7.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOfUnwrittenIndexSucceedsAndTheIndexStillAcceptsItsFirstWrite()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"An unwritten Index must be lockable for reading: '{lockResult.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, ReadLockIndexHandle).ConfigureAwait(false);
        Assert.AreNotEqual((TpmaNv)0, attributes & TpmaNv.TPMA_NV_READLOCKED, "The unwritten Index carries the lock in its public attribute word.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, FirstWriteData).ConfigureAwait(false);

        Assert.IsTrue(writeResult.IsSuccess, $"A read lock must not block the Index's first write: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// The read-lock refusal precedes the written-state refusal: a locked Index that has never been written
    /// answers <c>TPM_RC_NV_LOCKED</c>, not the <c>TPM_RC_NV_UNINITIALIZED</c> clause 31.13.1 gives an unwritten
    /// Index, since "If TPMA_NV_READLOCKED of the NV Index is SET, then the TPM shall return TPM_RC_NV_LOCKED"
    /// governs the whole read.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.13.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOfLockedUnwrittenIndexReturnsNvLockedNotUninitialized()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmResult<NvReadResponse> unlockedResult = await ReadIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, unlockedResult.ResponseCode, "Before the lock the unwritten Index answers the written-state refusal.");

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvReadResponse> lockedResult = await ReadIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, lockedResult.ResponseCode, "Once locked, the same unwritten Index answers the lock instead.");
    }

    /// <summary>
    /// The same order at <c>TPM2_PolicyAuthorizeNV()</c>: a read-locked Index that has never been written answers
    /// "If TPMA_NV_READLOCKED of the NV Index is SET, then the TPM shall return TPM_RC_NV_LOCKED" ahead of "If
    /// TPMA_NV_WRITTEN is not SET in the Index referenced by nvIndex, the TPM shall return
    /// TPM_RC_NV_UNINITIALIZED" — the lock is the first thing every read of an Index's data checks.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.22.1; clause 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvOfLockedUnwrittenIndexReturnsNvLockedNotUninitialized()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePolicyRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<StartAuthSessionResponse> realStart = await device.StartPolicySessionAsync(HmacSessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(realStart.IsSuccess, $"StartAuthSession (policy) failed: '{realStart.ResponseCode}'.");

        using StartAuthSessionResponse realSession = realStart.Value;
        uint realSessionHandle = realSession.SessionHandle.Value;
        try
        {
            TpmResult<PolicyAuthorizeNvResponse> realResult = await device.PolicyAuthorizeNvAsync(
                (uint)TpmRh.TPM_RH_OWNER, ReadLockIndexHandle, realSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, realResult.ResponseCode, "The lock answers ahead of the written state, so an unwritten locked Index is NV_LOCKED, not NV_UNINITIALIZED.");
        }
        finally
        {
            _ = await device.FlushContextAsync(realSessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "When an NV Index becomes locked (TPMA_NV_WRITELOCKED or TPMA_NV_READLOCKED is SET), the Name of the NV
    /// Index changes" — the Name digests the public area, attribute word included, so
    /// <c>TPM2_NV_ReadPublic()</c> answers a different Name before and after the lock.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 13; Part 3, clause 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockChangesTheIndexName()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        byte[] nameBefore = await ReadIndexNameAsync(device, ReadLockIndexHandle).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");
        byte[] nameAfter = await ReadIndexNameAsync(device, ReadLockIndexHandle).ConfigureAwait(false);

        Assert.IsFalse(nameBefore.AsSpan().SequenceEqual(nameAfter), "SETting TPMA_NV_READLOCKED changes the attribute word the Name digests, so the Name must change.");
    }

    /// <summary>
    /// "Proper authorizations are required for this command as determined by TPMA_NV_PPREAD,
    /// TPMA_NV_OWNERREAD, TPMA_NV_AUTHREAD" — with <c>TPMA_NV_OWNERREAD</c> SET the owner hierarchy's own
    /// (empty) authValue locks the Index, which its public attribute word then carries.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.14.1; Part 1, clause 34.2.5</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockByOwnerAuthorizationSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadLockIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized read lock must succeed: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, ReadLockIndexHandle).ConfigureAwait(false);

        Assert.AreNotEqual((TpmaNv)0, attributes & TpmaNv.TPMA_NV_READLOCKED, "The owner arm SETs the same lock bit the Index arm does.");
    }

    /// <summary>
    /// The owner arm honours <c>TPMA_NV_OWNERREAD</c> ahead of the compare: with the bit clear an owner-authorized
    /// read lock is <c>TPM_RC_NV_AUTHORIZATION</c> under a correct AND under a wrong owner authValue alike, so no
    /// comparison outcome leaks through the refusal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.4; Part 3, clauses 31.14.1 and 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockByOwnerWithoutOwnerReadReturnsNvAuthorizationRegardlessOfTheSuppliedOwnerAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WithoutOwnerReadIndexHandle, ReadStclearWithoutOwnerReadAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> correctResult = await ReadLockAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, WithoutOwnerReadIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        TpmResult<NvReadLockResponse> wrongResult = await ReadLockAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, WithoutOwnerReadIndexHandle, WrongOwnerAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, correctResult.ResponseCode, "With TPMA_NV_OWNERREAD clear the owner cannot read-lock, even under the correct owner authValue.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, wrongResult.ResponseCode, "The same refusal under a wrong owner authValue, so the gate runs before the compare.");
    }

    /// <summary>
    /// A wrong owner authValue on the owner arm is a plain <c>TPM_RC_BAD_AUTH</c>: "the authValue associated with
    /// a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA protection".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 3, clause 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockByOwnerWithWrongOwnerAuthReturnsBadAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadLockIndexHandle, WrongOwnerAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 267 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong owner authValue is session-encoded TPM_RC_BAD_AUTH there.");
        Assert.AreEqual(counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong owner authValue must not move failedTries.");
    }

    /// <summary>
    /// "If authHandle is an NV Index, it must be the same as nvIndex (TPM_RC_NV_AUTHORIZATION)" — an
    /// <c>authHandle</c> that is neither the owner hierarchy nor the Index itself is refused with
    /// <c>TPM_RC_NV_AUTHORIZATION</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockWithMismatchedAuthHandleReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockAsync(
            device, pool, registry, MismatchedAuthHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// The Index arm honours <c>TPMA_NV_AUTHREAD</c> ahead of the compare: with the bit clear the Index's own
    /// authValue is not an available mechanism for a read-role command at all, so a correct AND a wrong value are
    /// both refused with <c>TPM_RC_AUTH_UNAVAILABLE</c> (clause 5.6's check 7.2.2 precedes its value compare) and
    /// no comparison outcome leaks.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.5; Part 3, clauses 5.6 and 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockWithoutAuthReadReturnsAuthUnavailableForCorrectAndWrongValuesAlike()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WithoutAuthReadIndexHandle, ReadStclearWithoutAuthReadAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> correctResult = await ReadLockAsync(
            device, pool, registry, WithoutAuthReadIndexHandle, WithoutAuthReadIndexHandle, CorrectAuth).ConfigureAwait(false);
        TpmResult<NvReadLockResponse> wrongResult = await ReadLockAsync(
            device, pool, registry, WithoutAuthReadIndexHandle, WithoutAuthReadIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, correctResult.ResponseCode, "With TPMA_NV_AUTHREAD clear the Index authValue cannot authorize a read lock, even when it matches.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, wrongResult.ResponseCode, "The identical refusal for a wrong value, so the gate runs before the compare.");
    }

    /// <summary>
    /// A wrong Index authValue against a DA-protected Index is an auth-failure that charges <c>failedTries</c>:
    /// "All uses of a DA protected authValue receive DA protection" — read back over
    /// <c>TPM_PT_LOCKOUT_COUNTER</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockWithWrongAuthOnDaProtectedIndexReturnsAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 267 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong authValue on a DA-protected Index is session-encoded TPM_RC_AUTH_FAIL there.");
        Assert.AreEqual(counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong DA-protected authValue must charge failedTries once.");
    }

    /// <summary>
    /// A wrong Index authValue against a <c>TPMA_NV_NO_DA</c> Index is a plain bad-authorization that leaves
    /// <c>failedTries</c> untouched — <c>TPMA_NV_NO_DA</c> applies uniformly, with no command carve-out.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockWithWrongAuthOnNoDaIndexReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, NonDaIndexHandle, NonDaReadStclearAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockAsync(
            device, pool, registry, NonDaIndexHandle, NonDaIndexHandle, WrongAuth).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 267 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong authValue on a non-DA Index is session-encoded TPM_RC_BAD_AUTH there.");
        Assert.AreEqual(counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A NO_DA Index's wrong authValue must not move failedTries.");
    }

    /// <summary>
    /// "When the authValue of a PIN Index is used for authorization and the authorization succeeds, the pinCount
    /// field is set to zero if the Index is PIN Fail and incremented if the Index is PIN Pass" — a read lock is
    /// such a use, so one successful <c>TPM2_NV_ReadLock()</c> consumes exactly one pinCount step, observed
    /// through the owner-authorized read of <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> before and after. The read
    /// afterwards is taken across a TPM Reset, which "TPMA_NV_READLOCKED will be CLEAR on the next TPM Reset or
    /// TPM Restart" makes readable again while leaving the Index's data and written state alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 34.2.6.6 and 34.2.5; Part 3, clause 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOfPinPassIndexConsumesExactlyOnePinCountStep()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinPassIndexHandle, PinPassReadStclearAttributes, EightOctetDataSize).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinPassIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadResponse> beforeResult = await ReadIndexAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, PinPassIndexHandle, ReadOnlyMemory<byte>.Empty, EightOctetDataSize).ConfigureAwait(false);
        Assert.IsTrue(beforeResult.IsSuccess, $"The owner-authorized pinCount read before the lock failed: '{beforeResult.ResponseCode}'.");
        uint pinCountBefore;
        using(NvReadResponse before = beforeResult.Value)
        {
            pinCountBefore = ReadPinCount(before.Data);
        }

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, PinPassIndexHandle, PinPassIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"The PIN-authorized read lock must succeed below pinLimit: '{lockResult.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, PinPassIndexHandle, ReadOnlyMemory<byte>.Empty, EightOctetDataSize).ConfigureAwait(false);
        Assert.IsTrue(afterResult.IsSuccess, $"The owner-authorized pinCount read after the Reset failed: '{afterResult.ResponseCode}'.");
        using NvReadResponse after = afterResult.Value;

        Assert.AreEqual(0u, pinCountBefore, "The provisioning write leaves pinCount at zero.");
        Assert.AreEqual(pinCountBefore + 1u, ReadPinCount(after.Data), "A PIN Pass Index's pinCount increments by exactly one for the read lock's successful authorization.");
    }

    /// <summary>
    /// "If the authorization fails, pinCount is incremented for a PIN Fail Index" — one <c>TPM2_NV_ReadLock()</c>
    /// with a WRONG authValue on a PIN Fail Index answers <c>TPM_RC_BAD_AUTH</c> (its mandatory
    /// <c>TPMA_NV_NO_DA</c> keeps the TPM-wide counter out of it) and moves the Index's own pinCount from zero to
    /// one, observed through the owner-authorized read of <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c>; the refused
    /// command SETs no lock, so the read needs no Reset.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.6; Part 3, clauses 31.3.1 and 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOfPinFailIndexWithWrongAuthIncrementsPinCountByOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailReadStclearAttributes, EightOctetDataSize).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockAsync(
            device, pool, registry, PinFailIndexHandle, PinFailIndexHandle, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "A wrong PIN on a NO_DA PIN Fail Index is a plain bad-authorization.");

        Assert.AreEqual(1u, await ReadPinCountByOwnerAsync(device, pool, registry, PinFailIndexHandle).ConfigureAwait(false), "A failed PIN authorization increments a PIN Fail Index's pinCount by exactly one.");
    }

    /// <summary>
    /// "the pinCount field is set to zero if the Index is PIN Fail" on a successful authorization — a
    /// <c>TPM2_NV_ReadLock()</c> with the CORRECT authValue on a PIN Fail Index provisioned at pinCount one resets
    /// it to zero, read back across the TPM Reset that clears the lock the command SET.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 34.2.6.6 and 34.2.5; Part 3, clause 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOfPinFailIndexWithCorrectAuthResetsPinCountToZero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailReadStclearAttributes, EightOctetDataSize).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 1, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockAsync(
            device, pool, registry, PinFailIndexHandle, PinFailIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The PIN-authorized read lock must succeed below pinLimit: '{result.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        Assert.AreEqual(0u, await ReadPinCountByOwnerAsync(device, pool, registry, PinFailIndexHandle).ConfigureAwait(false), "A successful PIN authorization resets a PIN Fail Index's pinCount to zero.");
    }

    /// <summary>
    /// The failure-side rule over an HMAC session: the Index's own authValue keys the command HMAC, so a wrong
    /// value is a failed authorization of the PIN Index — session-encoded <c>TPM_RC_BAD_AUTH</c> under the
    /// mandatory <c>TPMA_NV_NO_DA</c> — and "pinCount is incremented for a PIN Fail Index" exactly as on the
    /// password form; without it the session form would be an unthrottled PIN oracle.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 34.2.6.6 and 16.6.5; Part 3, clauses 31.3.1 and 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOverHmacSessionOfPinFailIndexWithWrongAuthIncrementsPinCountByOne()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailReadStclearAttributes, EightOctetDataSize).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 0, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockOverHmacAsync(
            device, pool, registry, PinFailIndexHandle, PinFailIndexHandle, WrongAuth).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError, "A wrong PIN keying the command HMAC of a NO_DA PIN Fail Index is a session-encoded bad-authorization.");

        Assert.AreEqual(1u, await ReadPinCountByOwnerAsync(device, pool, registry, PinFailIndexHandle).ConfigureAwait(false), "A failed PIN authorization over a session increments a PIN Fail Index's pinCount by exactly one.");
    }

    /// <summary>
    /// The success-side rule over an HMAC session: a correct PIN keying the command HMAC resets a PIN Fail Index's
    /// pinCount to zero, read back across the TPM Reset that clears the lock the command SET.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 34.2.6.6, 34.2.5 and 16.6.5; Part 3, clause 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOverHmacSessionOfPinFailIndexWithCorrectAuthResetsPinCountToZero()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinFailIndexHandle, PinFailReadStclearAttributes, EightOctetDataSize).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinFailIndexHandle, pinCount: 1, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockOverHmacAsync(
            device, pool, registry, PinFailIndexHandle, PinFailIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The PIN-authorized read lock over a session must succeed below pinLimit: '{result.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        Assert.AreEqual(0u, await ReadPinCountByOwnerAsync(device, pool, registry, PinFailIndexHandle).ConfigureAwait(false), "A successful PIN authorization over a session resets a PIN Fail Index's pinCount to zero.");
    }

    /// <summary>
    /// "If the authValue of an PIN Index is used for authorization, then the authorization will fail if the
    /// pinCount field of the Index is not less than the pinLimit field" — a PIN Pass Index already at its limit
    /// refuses the read lock with <c>TPM_RC_AUTH_UNAVAILABLE</c>, before the authValue is compared at all.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.6; Part 3, clause 31.14.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOfPinPassIndexAtItsPinLimitReturnsAuthUnavailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, PinPassIndexHandle, PinPassReadStclearAttributes, EightOctetDataSize).ConfigureAwait(false);
        await WritePinCounterParametersAsync(device, pool, registry, PinPassIndexHandle, pinCount: PinLimit, PinLimit).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockAsync(
            device, pool, registry, PinPassIndexHandle, PinPassIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode, "At pinLimit the Index's own authValue is not an available authorization mechanism, even when it matches.");
    }

    /// <summary>
    /// "If authorization sessions are present, they are checked before the read-lock status of the NV Index is
    /// checked" — a <c>TPM2_NV_Read()</c> of a read-locked Index under a WRONG authValue answers the auth-failure
    /// rather than the lock, and charges <c>failedTries</c>, so the order is observable in both the code and the
    /// counter.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.13.1; Part 1, clause 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOfReadLockedIndexWithWrongAuthReturnsAuthFail()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadResponse> result = await ReadIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, WrongAuth, OrdinaryDataSize).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), result.ResponseCode, "Authorization is resolved before the read-lock status, so the wrong authValue answers first.");
        Assert.AreEqual(counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "The auth-failure charges failedTries, the very consequence the ordering carries.");
    }

    /// <summary>
    /// The read-lock gate binds the HMAC-session arm of <c>TPM2_NV_Read()</c> exactly as it binds the password
    /// arm, on the Index arm and on the owner arm alike: "If TPMA_NV_READLOCKED of the NV Index is SET, then the
    /// TPM shall return TPM_RC_NV_LOCKED", answered with no handle, session, or parameter designation after the
    /// command HMAC has verified against the post-lock Name (Part 1, clause 15.7, equation 15).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.13.1; Part 1, clauses 13 and 15.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOverHmacSessionOfReadLockedIndexReturnsNvLockedOnBothArms()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvReadResponse> indexArmResult = await ReadIndexOverHmacAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);
        TpmResult<NvReadResponse> ownerArmResult = await ReadIndexOverHmacAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadLockIndexHandle, ReadOnlyMemory<byte>.Empty, OrdinaryDataSize).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, indexArmResult.ResponseCode, "The Index arm over a session answers the lock.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, ownerArmResult.ResponseCode, "The owner arm over a session answers the same lock.");
    }

    /// <summary>
    /// A read lock binds every read of the Index data, <c>TPM2_NV_Certify()</c> included: "Read access to an NV
    /// Index is provided with TPM2_NV_Read(), TPM2_NV_Certify(), and TPM2_PolicyNV()", and clause 5.4's handle
    /// check states the consequence — "If the command requires read access to the index data, then
    /// TPMA_NV_READLOCKED is not SET (TPM_RC_NV_LOCKED)" — so an all-password certify of a locked, written Index
    /// is <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.5; Part 3, clauses 5.4 and 31.16</see>.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOfReadLockedIndexReturnsNvLocked()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(withSigningBackend: true).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateCertifyRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);
        using CreatePrimaryResponse signingKey = await CreateSigningPrimaryAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(CorrectAuth, pool);
        using NvCertifyInput certifyInput = NvCertifyInput.ForEcdsa(
            signingKey.ObjectHandle, ReadLockIndexHandle, ReadLockIndexHandle, CertifyNonce, TpmAlgIdConstants.TPM_ALG_SHA256,
            OrdinaryDataSize, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            device, certifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, result.ResponseCode);
    }

    /// <summary>
    /// The lock answers ahead of the written state at <c>TPM2_NV_Certify()</c> too: a read-locked Index that has
    /// never been written is <c>TPM_RC_NV_LOCKED</c>, not the "If the NV Index has been defined but the
    /// TPMA_NV_WRITTEN attribute is CLEAR, then this command shall return TPM_RC_NV_UNINITIALIZED" refusal — the
    /// same order every read of an Index's data applies, and a legal state since "An Index that had not been
    /// written may be locked for reading".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.4, 31.14.1 and 31.16.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOfReadLockedUnwrittenIndexReturnsNvLockedNotUninitialized()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(withSigningBackend: true).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateCertifyRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse signingKey = await CreateSigningPrimaryAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() of an unwritten Index failed: '{lockResult.ResponseCode}'.");

        using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
        using TpmPasswordSession indexAuth = TpmPasswordSession.Create(CorrectAuth, pool);
        using NvCertifyInput certifyInput = NvCertifyInput.ForEcdsa(
            signingKey.ObjectHandle, ReadLockIndexHandle, ReadLockIndexHandle, CertifyNonce, TpmAlgIdConstants.TPM_ALG_SHA256,
            OrdinaryDataSize, offset: 0, pool);

        TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
            device, certifyInput, [signAuth, indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, result.ResponseCode, "The lock answers ahead of the written state, so an unwritten locked Index is NV_LOCKED, not NV_UNINITIALIZED.");
    }

    /// <summary>
    /// The same certify refusal over the HMAC-session arm, where the Index's own slot is a real unbound session:
    /// the command HMAC verifies against the post-lock Name and the read of the Index data is still refused with
    /// <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.4 and 31.16; Part 1, clauses 13 and 15.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvCertifyOverHmacSessionOfReadLockedIndexReturnsNvLocked()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(withSigningBackend: true).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateCertifyRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);
        using CreatePrimaryResponse signingKey = await CreateSigningPrimaryAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        byte[] indexName = await ReadIndexNameAsync(device, ReadLockIndexHandle).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                using TpmPasswordSession signAuth = TpmPasswordSession.CreateEmpty(pool);
                using NvCertifyInput certifyInput = NvCertifyInput.ForEcdsa(
                    signingKey.ObjectHandle, ReadLockIndexHandle, ReadLockIndexHandle, CertifyNonce, TpmAlgIdConstants.TPM_ALG_SHA256,
                    OrdinaryDataSize, offset: 0, pool);
                ReadOnlyMemory<byte>[] handleNames = [signingKey.Name.Span.ToArray(), indexName, indexName];

                TpmResult<NvCertifyResponse> result = await TpmCommandExecutor.ExecuteAsync<NvCertifyResponse>(
                    device, certifyInput, [signAuth, session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, result.ResponseCode);
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If TPMA_NV_READLOCKED of the NV Index is SET, then the TPM shall return TPM_RC_NV_LOCKED" for
    /// <c>TPM2_PolicyNV()</c> as well — but only on a real policy session, since "The remainder of this general
    /// description would apply only if policySession is not a trial policy session": a trial session folds the
    /// assertion's digest without reading the Index at all and succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyNvOfReadLockedIndexReturnsNvLockedOnARealSessionAndSucceedsOnATrialSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePolicyRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<StartAuthSessionResponse> realStart = await device.StartPolicySessionAsync(HmacSessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(realStart.IsSuccess, $"StartAuthSession (policy) failed: '{realStart.ResponseCode}'.");

        using StartAuthSessionResponse realSession = realStart.Value;
        uint realSessionHandle = realSession.SessionHandle.Value;
        try
        {
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(CorrectAuth, pool);
            var realInput = new PolicyNvInput(ReadLockIndexHandle, ReadLockIndexHandle, realSessionHandle, PolicyOperand, Offset: 0, TpmEoConstants.TPM_EO_EQ);

            TpmResult<PolicyNvResponse> realResult = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                device, realInput, [indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, realResult.ResponseCode, "A real policy session reads the Index contents, so the lock refuses it.");
        }
        finally
        {
            _ = await device.FlushContextAsync(realSessionHandle, CancellationToken.None).ConfigureAwait(false);
        }

        TpmResult<StartAuthSessionResponse> trialStart = await device.StartTrialPolicySessionAsync(HmacSessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(trialStart.IsSuccess, $"StartAuthSession (trial) failed: '{trialStart.ResponseCode}'.");

        using StartAuthSessionResponse trialSession = trialStart.Value;
        uint trialSessionHandle = trialSession.SessionHandle.Value;
        try
        {
            using TpmPasswordSession indexAuth = TpmPasswordSession.Create(CorrectAuth, pool);
            var trialInput = new PolicyNvInput(ReadLockIndexHandle, ReadLockIndexHandle, trialSessionHandle, PolicyOperand, Offset: 0, TpmEoConstants.TPM_EO_EQ);

            TpmResult<PolicyNvResponse> trialResult = await TpmCommandExecutor.ExecuteAsync<PolicyNvResponse>(
                device, trialInput, [indexAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(trialResult.IsSuccess, $"A trial policy session performs no further validation, so the lock must not reach it: '{trialResult.ResponseCode}'.");
        }
        finally
        {
            _ = await device.FlushContextAsync(trialSessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The same split for <c>TPM2_PolicyAuthorizeNV()</c>: "If TPMA_NV_READLOCKED of the NV Index is SET, then the
    /// TPM shall return TPM_RC_NV_LOCKED" on a real policy session, while a trial session "will not perform any
    /// further validation" and succeeds on the authorization to read alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 23.22.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PolicyAuthorizeNvOfReadLockedIndexReturnsNvLockedOnARealSessionAndSucceedsOnATrialSession()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreatePolicyRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<StartAuthSessionResponse> realStart = await device.StartPolicySessionAsync(HmacSessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(realStart.IsSuccess, $"StartAuthSession (policy) failed: '{realStart.ResponseCode}'.");

        using StartAuthSessionResponse realSession = realStart.Value;
        uint realSessionHandle = realSession.SessionHandle.Value;
        try
        {
            TpmResult<PolicyAuthorizeNvResponse> realResult = await device.PolicyAuthorizeNvAsync(
                (uint)TpmRh.TPM_RH_OWNER, ReadLockIndexHandle, realSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, realResult.ResponseCode, "A real policy session reads the approved policy out of the Index, so the lock refuses it.");
        }
        finally
        {
            _ = await device.FlushContextAsync(realSessionHandle, CancellationToken.None).ConfigureAwait(false);
        }

        TpmResult<StartAuthSessionResponse> trialStart = await device.StartTrialPolicySessionAsync(HmacSessionAlg, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(trialStart.IsSuccess, $"StartAuthSession (trial) failed: '{trialStart.ResponseCode}'.");

        using StartAuthSessionResponse trialSession = trialStart.Value;
        uint trialSessionHandle = trialSession.SessionHandle.Value;
        try
        {
            TpmResult<PolicyAuthorizeNvResponse> trialResult = await device.PolicyAuthorizeNvAsync(
                (uint)TpmRh.TPM_RH_OWNER, ReadLockIndexHandle, trialSessionHandle, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(trialResult.IsSuccess, $"A trial policy session performs no further validation, so the lock must not reach it: '{trialResult.ResponseCode}'.");
        }
        finally
        {
            _ = await device.FlushContextAsync(trialSessionHandle, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// <c>TPMA_NV_READLOCKED</c> blocks reading alone: the write commands are gated by
    /// <c>TPMA_NV_WRITELOCKED</c> instead ("If the TPMA_NV_WRITELOCKED attribute of the NV Index is SET, then the
    /// TPM shall return TPM_RC_NV_LOCKED"), so a read-locked Ordinary Index still accepts <c>TPM2_NV_Write()</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.7.1; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfReadLockedOrdinaryIndexSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvWriteResponse> writeResult = await WriteIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, FirstWriteData).ConfigureAwait(false);

        Assert.IsTrue(writeResult.IsSuccess, $"A read lock must leave TPM2_NV_Write() untouched: '{writeResult.ResponseCode}'.");
    }

    /// <summary>
    /// The same one-sidedness on a Counter Index: <c>TPM2_NV_Increment()</c> is a write-role command, gated by
    /// <c>TPMA_NV_WRITELOCKED</c> alone, so a read-locked counter still advances.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.8.1; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOfReadLockedCounterIndexSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterReadStclearAttributes, EightOctetDataSize).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        using TpmPasswordSession session = TpmPasswordSession.Create(CorrectAuth, pool);
        var incrementInput = new NvIncrementInput(CounterIndexHandle, CounterIndexHandle);

        TpmResult<NvIncrementResponse> incrementResult = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, incrementInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(incrementResult.IsSuccess, $"A read lock must leave TPM2_NV_Increment() untouched: '{incrementResult.ResponseCode}'.");
    }

    /// <summary>
    /// The same one-sidedness on a Bit Field Index: <c>TPM2_NV_SetBits()</c> is a write-role command, so a
    /// read-locked Bit Field Index still takes its bits.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 1, clauses 34.2.6.1 and 34.2.6.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfReadLockedBitsIndexSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsReadStclearAttributes, EightOctetDataSize).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        using TpmPasswordSession session = TpmPasswordSession.Create(CorrectAuth, pool);
        var setBitsInput = new NvSetBitsInput(BitsIndexHandle, BitsIndexHandle, 0x8000_0000_0000_0001ul);

        TpmResult<NvSetBitsResponse> setBitsResult = await TpmCommandExecutor.ExecuteAsync<NvSetBitsResponse>(
            device, setBitsInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(setBitsResult.IsSuccess, $"A read lock must leave TPM2_NV_SetBits() untouched: '{setBitsResult.ResponseCode}'.");
    }

    /// <summary>
    /// "TPMA_NV_READLOCKED will be CLEAR by the next TPM2_Startup(TPM_SU_CLEAR)" — after a TPM Reset
    /// (<c>Shutdown(CLEAR)</c>/<c>Startup(CLEAR)</c>) the Index's public attribute word carries the bit CLEAR and
    /// the read that answered <c>TPM_RC_NV_LOCKED</c> succeeds again.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 31.14.1 and 9.3; Part 1, clause 34.2.5</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadLockedIndexBecomesReadableAgainAfterATpmReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        TpmResult<NvReadResponse> lockedResult = await ReadIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, lockedResult.ResponseCode, "The read is blocked while the lock stands.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, ReadLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual((TpmaNv)0, attributes & TpmaNv.TPMA_NV_READLOCKED, "A TPM Reset must CLEAR TPMA_NV_READLOCKED.");

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);
        Assert.IsTrue(afterResult.IsSuccess, $"The read must succeed once the Reset has cleared the lock: '{afterResult.ResponseCode}'.");

        using NvReadResponse read = afterResult.Value;
        Assert.IsTrue(StoredData.AsSpan().SequenceEqual(read.Data), "The Reset clears the lock without disturbing the stored octets.");
    }

    /// <summary>
    /// The same clearing on a TPM Restart (<c>Shutdown(STATE)</c>/<c>Startup(CLEAR)</c>): "TPMA_NV_READLOCKED will
    /// be CLEAR on the next TPM Reset or TPM Restart", and clause 9.3 lists the NV attribute pass under both.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.5; Part 3, clause 9.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadLockedIndexBecomesReadableAgainAfterATpmRestart()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, ReadLockIndexHandle).ConfigureAwait(false);
        Assert.AreEqual((TpmaNv)0, attributes & TpmaNv.TPMA_NV_READLOCKED, "A TPM Restart must CLEAR TPMA_NV_READLOCKED as a TPM Reset does.");

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);
        Assert.IsTrue(afterResult.IsSuccess, $"The read must succeed once the Restart has cleared the lock: '{afterResult.ResponseCode}'.");

        using NvReadResponse read = afterResult.Value;
        Assert.IsTrue(StoredData.AsSpan().SequenceEqual(read.Data), "The Restart clears the lock without disturbing the stored octets.");
    }

    /// <summary>
    /// A TPM Resume (<c>Shutdown(STATE)</c>/<c>Startup(STATE)</c>) is neither a TPM Reset nor a TPM Restart, so
    /// it runs no NV attribute pass at all: the Index stays read-locked and the read still answers
    /// <c>TPM_RC_NV_LOCKED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.5; Part 3, clauses 9.3 and 31.13.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ReadLockedIndexStaysLockedAcrossATpmResume()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> lockResult = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(lockResult.IsSuccess, $"TPM2_NV_ReadLock() failed: '{lockResult.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_STATE, TpmSuConstants.TPM_SU_STATE).ConfigureAwait(false);

        TpmaNv attributes = await ReadIndexAttributesAsync(device, ReadLockIndexHandle).ConfigureAwait(false);
        Assert.AreNotEqual((TpmaNv)0, attributes & TpmaNv.TPMA_NV_READLOCKED, "A TPM Resume runs no NV attribute pass, so the lock bit survives.");

        TpmResult<NvReadResponse> afterResult = await ReadIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, afterResult.ResponseCode, "The read stays blocked across a TPM Resume.");
    }

    /// <summary>
    /// The Index arm over an unbound, unsalted HMAC session: the command HMAC verifies against a cpHash whose
    /// Name terms are the Index's Name AS THE COMMAND FOUND IT — the lock then moves that Name (Part 1, clause 13)
    /// — and the Index comes back read-locked.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 13 and 15.7, equation 15; Part 3, clause 31.14</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOverHmacSessionAtTheIndexArmLocksTheIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await WriteIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, StoredData).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockOverHmacAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_ReadLock() over an HMAC session failed: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, ReadLockIndexHandle).ConfigureAwait(false);
        Assert.AreNotEqual((TpmaNv)0, attributes & TpmaNv.TPMA_NV_READLOCKED, "The session-authorized lock SETs the same bit the password arm does.");

        TpmResult<NvReadResponse> readResult = await ReadIndexAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth, OrdinaryDataSize).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_LOCKED, readResult.ResponseCode);
    }

    /// <summary>
    /// The owner arm over an HMAC session: cpHash's Name1 is the owner's raw handle (Part 1, Table 9: a permanent
    /// handle's Name IS its handle value) and Name2 the Index's computed Name; the empty owner authValue keys the
    /// HMAC alongside the empty session key, and the Index comes back read-locked.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 13, Table 9, and clause 15.7; Part 3, clause 31.14</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOverHmacSessionAtTheOwnerArmLocksTheIndex()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockOverHmacAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ReadLockIndexHandle, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized read lock over an HMAC session failed: '{result.ResponseCode}'.");

        TpmaNv attributes = await ReadIndexAttributesAsync(device, ReadLockIndexHandle).ConfigureAwait(false);

        Assert.AreNotEqual((TpmaNv)0, attributes & TpmaNv.TPMA_NV_READLOCKED, "The owner arm over a session SETs the lock bit too.");
    }

    /// <summary>
    /// A wrong Index authValue proven over an HMAC session is the same auth-failure the password arm answers,
    /// session-encoded — the base error is <c>TPM_RC_AUTH_FAIL</c> and the raw wire code carries the session-index
    /// modifier — and it charges <c>failedTries</c> exactly once, mechanism-blind.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOverHmacSessionWithWrongAuthReturnsSessionEncodedAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockOverHmacAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, WrongAuth).ConfigureAwait(false);

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
    public async Task NvReadLockOverHmacSessionWithMismatchedAuthHandleReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockOverHmacAsync(
            device, pool, registry, MismatchedAuthHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// The Index arm over an HMAC session honours <c>TPMA_NV_AUTHREAD</c> before any HMAC work: with the bit clear
    /// the Index's own authValue is not an available mechanism, so the read lock is
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> even under the correct value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.5; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOverHmacSessionWithoutAuthReadReturnsAuthUnavailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, WithoutAuthReadIndexHandle, ReadStclearWithoutAuthReadAttributes).ConfigureAwait(false);

        TpmResult<NvReadLockResponse> result = await ReadLockOverHmacAsync(
            device, pool, registry, WithoutAuthReadIndexHandle, WithoutAuthReadIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode);
    }

    /// <summary>
    /// Table 267 gives <c>TPM2_NV_ReadLock()</c> no command parameter, so a <c>decrypt</c>-attributed session names
    /// an operation with nothing to act on and fails closed with <c>TPM_RC_ATTRIBUTES</c> naming the session,
    /// while the identical session without the attribute succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.7 and 31.14.2, Table 267; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOverSessionWithDecryptAttributeReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmRcConstants rawDecryptCode = await ReadLockOverHmacHandFramedAsync(
            device, pool, registry, ReadLockIndexHandle, CorrectAuth, TpmaSession.DECRYPT).ConfigureAwait(false);
        TpmResult<NvReadLockResponse> decryptResult = TpmResult<NvReadLockResponse>.TpmError(rawDecryptCode);
        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, decryptResult.BaseError, "With no command parameter to encrypt, a decrypt-attributed session must fail closed.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, decryptResult.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<NvReadLockResponse> declinedResult = await ReadLockOverHmacAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.IsTrue(declinedResult.IsSuccess, $"The identical authValue over an otherwise identical session with decrypt left CLEAR must succeed: '{declinedResult.ResponseCode}'.");
    }

    /// <summary>
    /// Table 268 gives <c>TPM2_NV_ReadLock()</c> no response parameter either, so an <c>encrypt</c>-attributed
    /// session equally names an operation with nothing to act on and fails closed with
    /// <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clauses 5.7 and 31.14.2, Table 268</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOverSessionWithEncryptAttributeReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        TpmRcConstants rawEncryptCode = await ReadLockOverHmacHandFramedAsync(
            device, pool, registry, ReadLockIndexHandle, CorrectAuth, TpmaSession.ENCRYPT).ConfigureAwait(false);
        TpmResult<NvReadLockResponse> encryptResult = TpmResult<NvReadLockResponse>.TpmError(rawEncryptCode);
        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, encryptResult.BaseError, "TPM2_NV_ReadLock() has no response parameter, so an encrypt-attributed session must fail closed.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, encryptResult.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<NvReadLockResponse> declinedResult = await ReadLockOverHmacAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);

        Assert.IsTrue(declinedResult.IsSuccess, $"The identical authValue over an otherwise identical session with encrypt left CLEAR must succeed: '{declinedResult.ResponseCode}'.");
    }

    /// <summary>
    /// The <c>audit</c> attribute on the authorizing session is admitted (TPM 2.0 Library Part 1, clause 17.1)
    /// and the command succeeds, extending the session's audit digest to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its
    /// first use (equation 30) with the response echoing <c>audit</c> SET, <c>auditExclusive</c> SET and
    /// <c>auditReset</c> CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38) — proved by chaining cpHash/rpHash
    /// from the octets this test itself sent and read, then reading the session's digest back through
    /// <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOverSessionWithAuditAttributeSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);

        (byte[] response, uint sessionHandle, byte[] cpHash) = await ReadLockOverHmacHandFramedForAuditAsync(
            device, pool, registry, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        try
        {
            var responseReader = new TpmReader(response);
            TpmRcConstants rawAuditCode = (TpmRcConstants)TpmHeader.Parse(ref responseReader).Code;
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, rawAuditCode, "An audit-claiming session over an audited command succeeds (TPM 2.0 Library Part 1, clause 17.1).");

            byte auditedAttributes = ReadResponseSessionAttributes(response, outHandleCount: 0, sessionIndex: 0);
            Assert.AreEqual(
                (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                "The response echoes audit SET and auditExclusive SET (the session's first use as an audit session), with auditReset CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

            byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 0);
            byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_NV_ReadLock, responseParameters, pool).ConfigureAwait(false);
            byte[] expectedDigest = await ExtendAuditDigestAsync(priorDigest: null, cpHash, rpHash, pool).ConfigureAwait(false);

            using GetSessionAuditDigestInput auditDigestInput = GetSessionAuditDigestInput.ForNullSigner(TpmiShHmac.FromValue(sessionHandle), ReadOnlySpan<byte>.Empty, pool);
            using TpmPasswordSession endorsementForDigest = TpmPasswordSession.CreateEmpty(pool);
            using TpmPasswordSession nullSignerSlot = TpmPasswordSession.CreateEmpty(pool);

            TpmResult<GetSessionAuditDigestResponse> digestResult = await TpmCommandExecutor.ExecuteAsync<GetSessionAuditDigestResponse>(
                device, auditDigestInput, [endorsementForDigest, nullSignerSlot], handleNames: null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            using GetSessionAuditDigestResponse? auditDigestResponse = digestResult.IsSuccess ? digestResult.Value : null;

            Assert.IsTrue(digestResult.IsSuccess, $"TPM2_GetSessionAuditDigest() over the freshly audited session must succeed: '{digestResult.ResponseCode}'.");
            Assert.IsTrue(auditDigestResponse!.SessionAudit.ExclusiveSession.IsYes, "The session became the exclusive audit session on its first use (TPM 2.0 Library Part 1, clause 17.2).");
            Assert.IsTrue(
                expectedDigest.AsSpan().SequenceEqual(auditDigestResponse.SessionAudit.SessionDigest.AsReadOnlySpan()),
                "The session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from the NV_ReadLock exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The password form returns every carrier its parse rented on each path: a refusal at the existence gate
    /// (before authorization), a refusal at the <c>TPMA_NV_READ_STCLEAR</c> gate (after authorization), and a
    /// success — the metered pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.14</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockReturnsItsCarriersAcrossRefusalsAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, PlainIndexHandle, PlainAttributes).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvReadLockResponse> undefinedResult = await ReadLockAsync(
            device, pool, registry, UndefinedIndexHandle, UndefinedIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), undefinedResult.ResponseCode, "Table 267: nvIndex is TPM2_NV_ReadLock()'s second handle (handle 2); an undefined Index is handle-encoded TPM_RC_HANDLE at index 1.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal before authorization releases the slot credential through the request's own Dispose.");

        TpmResult<NvReadLockResponse> plainResult = await ReadLockAsync(
            device, pool, registry, PlainIndexHandle, PlainIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), plainResult.ResponseCode, "Table 267: nvIndex is TPM2_NV_ReadLock()'s second handle (handle 2); an Index whose TPMA_NV_READ_STCLEAR attribute is CLEAR is handle-encoded TPM_RC_ATTRIBUTES at index 1.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal after authorization releases the slot credential through the request's own Dispose.");

        TpmResult<NvReadLockResponse> result = await ReadLockAsync(
            device, pool, registry, ReadLockIndexHandle, ReadLockIndexHandle, CorrectAuth).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_ReadLock() failed: '{result.ResponseCode}'.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The accepting transition is the credential's terminal owner and must release it.");
    }

    /// <summary>
    /// The HMAC-session form returns every carrier its parse rented — the raw parameter area, the slot
    /// credentials and the computed Index Name — across a refusal at the command HMAC and a success: the metered
    /// pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.14; Part 1, clause 15.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadLockOverHmacSessionReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ReadLockIndexHandle, ReadStclearAttributes).ConfigureAwait(false);
        ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, ReadLockIndexHandle).ConfigureAwait(false);
        ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

        (uint wrongSessionHandle, TpmSession wrongSession) = await StartUnboundSessionAsync(device, pool, registry, WrongAuth).ConfigureAwait(false);
        (uint correctSessionHandle, TpmSession correctSession) = await StartUnboundSessionAsync(device, pool, registry, CorrectAuth).ConfigureAwait(false);
        try
        {
            using(wrongSession)
            using(correctSession)
            {
                long baseline = trackingPool.OutstandingCount;

                {
                    var input = new NvReadLockInput(ReadLockIndexHandle, ReadLockIndexHandle);
                    TpmResult<NvReadLockResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvReadLockResponse>(
                        device, input, [wrongSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, refused.BaseError);
                }

                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A command refused at its command HMAC releases every carrier its parse rented.");

                {
                    var input = new NvReadLockInput(ReadLockIndexHandle, ReadLockIndexHandle);
                    TpmResult<NvReadLockResponse> result = await TpmCommandExecutor.ExecuteAsync<NvReadLockResponse>(
                        device, input, [correctSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"TPM2_NV_ReadLock() over an HMAC session failed: '{result.ResponseCode}'.");
                }

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

    /// <summary>
    /// Issues a password-authorized <c>TPM2_NV_ReadLock()</c> against <paramref name="nvIndex"/> authorized by
    /// <paramref name="authHandle"/> (TPM 2.0 Library Part 3, clause 31.14.2, Table 267).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle (the Index itself, the owner hierarchy, or a mismatched value).</param>
    /// <param name="nvIndex">The Index to lock for reading.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <returns>The read-lock result.</returns>
    private async Task<TpmResult<NvReadLockResponse>> ReadLockAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var input = new NvReadLockInput(authHandle, nvIndex);

        return await TpmCommandExecutor.ExecuteAsync<NvReadLockResponse>(
            device, input, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_ReadLock()</c> against <paramref name="nvIndex"/> over an UNBOUND, unsalted HMAC session
    /// (TPM 2.0 Library Part 1, clause 16.6.9) whose authValue is <paramref name="suppliedAuth"/>, on the Index arm
    /// (cpHash Names <c>[indexName, indexName]</c>) or the owner arm (<c>[ownerHandle, indexName]</c>). The Name
    /// terms are the ones the command will FIND, read before it runs, since the lock moves the Name (Part 1,
    /// clause 13).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing handle: the Index itself, <c>TPM_RH_OWNER</c>, or a mismatched value.</param>
    /// <param name="nvIndex">The Index to lock for reading.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <returns>The read-lock result.</returns>
    private async Task<TpmResult<NvReadLockResponse>> ReadLockOverHmacAsync(
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
                var input = new NvReadLockInput(authHandle, nvIndex);

                return await TpmCommandExecutor.ExecuteAsync<NvReadLockResponse>(
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
    /// <c>TPM2_NV_ReadLock()</c> authorized by a single unbound, unsalted HMAC session whose
    /// <c>sessionAttributes</c> octet carries <paramref name="attribute"/>, and submits it directly to the
    /// transport — bypassing <see cref="TpmCommandExecutor"/>, whose own client-side guard would refuse this
    /// composition before any bytes reach the wire. The cpHash and command HMAC are the SAME production
    /// computation <see cref="TpmSession"/> performs for every other session-authorized test in this file;
    /// <c>TPM2_NV_ReadLock()</c> carries no parameters (Table 267), so cpHash's parameters term is empty
    /// (Part 1, clause 15.7, equation 15).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own StartAuthSession/FlushContext lifecycle).</param>
    /// <param name="nvIndex">The Index to lock; also the authorizing handle.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test: decrypt, encrypt or audit.</param>
    /// <returns>The raw wire response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> ReadLockOverHmacHandFramedAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, TpmaSession attribute)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
            session.SetAuthValue(suppliedAuth.Span, pool);
            session.SessionAttributes |= attribute;

            ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);

            //cpHash = H_SHA256(commandCode || Name(authHandle) || Name(nvIndex)) — TPM 2.0 Library Part 1, clause
            //15.7, equation 15, with no parameters term at all, since Part 3, Table 267 gives this command none. This
            //arm's authHandle and nvIndex are the same Index, so both Name terms are identical.
            int cpHashInputLength = sizeof(uint) + indexName.Length + indexName.Length;
            using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
            Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
            {
                var cpHashWriter = new TpmWriter(cpHashInput.Span);
                cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_ReadLock);
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
            writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_ReadLock);
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
    /// The audit twin of <see cref="ReadLockOverHmacHandFramedAsync"/>: hand-frames a raw <c>TPM2_NV_ReadLock()</c>
    /// authorized by a single unbound, unsalted HMAC session carrying <c>audit ‖ continueSession</c>, submits it
    /// directly to the transport, and returns the raw response octets, the session handle and the independently
    /// computed cpHash WITHOUT flushing the session — the caller keeps it loaded to read its audit digest back
    /// through <c>TPM2_GetSessionAuditDigest()</c>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own StartAuthSession lifecycle).</param>
    /// <param name="nvIndex">The Index to lock; also the authorizing handle.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <returns>The raw response octets, the session handle (unflushed) and cpHash.</returns>
    private async Task<(byte[] Response, uint SessionHandle, byte[] CpHash)> ReadLockOverHmacHandFramedForAuditAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth)
    {
        StartAuthSessionInput startInput = StartAuthSessionInput.CreateUnboundUnsaltedHmacSession(HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession failed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        using TpmSession session = new(new TpmHandle(sessionHandle), started.NonceTPM, HmacSessionAlg, TestEntropy.NewCounterStream(), pool);
        session.SetAuthValue(suppliedAuth.Span, pool);
        session.SessionAttributes |= TpmaSession.AUDIT;

        ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);

        int cpHashInputLength = sizeof(uint) + indexName.Length + indexName.Length;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_ReadLock);
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
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_ReadLock);
        writer.WriteUInt32(nvIndex);
        writer.WriteUInt32(nvIndex);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);

        TpmResult<TpmResponse> transportResult = await device.SubmitAsync(command, pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(transportResult.IsSuccess, "The transport itself must succeed even when the TPM refuses the command.");

        using TpmResponse response = transportResult.Value;

        return (response.AsReadOnlySpan().ToArray(), sessionHandle, cpHash.AsReadOnlySpan().ToArray());
    }

    /// <summary>
    /// Reads the response parameter area out of a captured raw response's octets — the bytes rpHash (TPM 2.0
    /// Library Part 1, clause 15.8, equation 16) is computed over, as actually returned on the wire, independent
    /// of whatever the codec parsed them into.
    /// </summary>
    /// <param name="responseBytes">The raw response octets, tagged <c>TPM_ST_SESSIONS</c>.</param>
    /// <param name="outHandleCount">The number of output handles the response carries before its parameter area.</param>
    /// <returns>The response parameter octets.</returns>
    private static byte[] ReadResponseParameters(byte[] responseBytes, int outHandleCount)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();

        return reader.ReadBytes((int)parameterSize).ToArray();
    }

    /// <summary>
    /// Reads one entry's <c>sessionAttributes</c> octet out of a captured raw response's authorization area — the
    /// octet Table 38's <c>audit</c>/<c>auditExclusive</c>/<c>auditReset</c> echo lands in and the response HMAC
    /// is computed over, walked directly off the wire rather than through any parsed session state.
    /// </summary>
    /// <param name="responseBytes">The raw response octets.</param>
    /// <param name="outHandleCount">The number of output handles preceding the parameter area.</param>
    /// <param name="sessionIndex">The zero-based position, in request order, of the session entry to read.</param>
    /// <returns>The entry's raw <c>sessionAttributes</c> octet.</returns>
    private static byte ReadResponseSessionAttributes(byte[] responseBytes, int outHandleCount, int sessionIndex)
    {
        var reader = new TpmReader(responseBytes);
        _ = TpmHeader.Parse(ref reader);
        for(int i = 0; i < outHandleCount; i++)
        {
            _ = reader.ReadUInt32();
        }

        uint parameterSize = reader.ReadUInt32();
        _ = reader.ReadBytes((int)parameterSize);

        byte attributes = 0;
        for(int i = 0; i <= sessionIndex; i++)
        {
            ushort nonceLength = reader.ReadUInt16();
            _ = reader.ReadBytes(nonceLength);
            attributes = reader.ReadByte();
            ushort hmacLength = reader.ReadUInt16();
            _ = reader.ReadBytes(hmacLength);
        }

        return attributes;
    }

    /// <summary>
    /// Computes <c>rpHash = H_sessionAlg(TPM_RC_SUCCESS ‖ commandCode ‖ parameters)</c> (TPM 2.0 Library Part 1,
    /// clause 15.8, equation 16) over the response parameter octets as actually read off the wire.
    /// </summary>
    /// <param name="commandCode">The command code.</param>
    /// <param name="responseParameters">The response parameter area as read.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The rpHash octets.</returns>
    private async Task<byte[]> ComputeRpHashAsync(TpmCcConstants commandCode, ReadOnlyMemory<byte> responseParameters, BaseMemoryPool pool)
    {
        byte[] input = new byte[sizeof(uint) + sizeof(uint) + responseParameters.Length];
        BinaryPrimitives.WriteUInt32BigEndian(input, (uint)TpmRcConstants.TPM_RC_SUCCESS);
        BinaryPrimitives.WriteUInt32BigEndian(input.AsSpan(sizeof(uint)), (uint)commandCode);
        responseParameters.Span.CopyTo(input.AsSpan(2 * sizeof(uint)));

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Extends an audit session digest by one round: <c>H(old ‖ cpHash ‖ rpHash)</c>, with the Zero Digest of the
    /// session's hash width standing in for <paramref name="priorDigest"/> on the session's first use as an audit
    /// session (TPM 2.0 Library Part 1, clause 17.1, equation 30).
    /// </summary>
    /// <param name="priorDigest">The digest before this extend, or <see langword="null"/> on first use.</param>
    /// <param name="cpHash">The audited command's cpHash.</param>
    /// <param name="rpHash">The audited command's rpHash.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The extended digest.</returns>
    private async Task<byte[]> ExtendAuditDigestAsync(byte[]? priorDigest, byte[] cpHash, byte[] rpHash, BaseMemoryPool pool)
    {
        byte[] old = priorDigest ?? new byte[Sha256DigestSize];
        byte[] input = new byte[old.Length + cpHash.Length + rpHash.Length];
        old.CopyTo(input, 0);
        cpHash.CopyTo(input, old.Length);
        rpHash.CopyTo(input, old.Length + cpHash.Length);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            input, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return digest.AsReadOnlySpan().ToArray();
    }

    /// <summary>
    /// Builds the digest <see cref="Tag"/> used to independently compute cpHash for
    /// <see cref="ReadLockOverHmacHandFramedAsync"/>: SHA-256 digest, raw encoding, direct material — the same
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

    /// <summary>Reads the pinCount field (the first four octets) of a PIN Index's <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> (TPM 2.0 Library Part 2, clause 13.3).</summary>
    /// <param name="data">The octets <see cref="NvReadResponse.Data"/> returned.</param>
    /// <returns>The pinCount value.</returns>
    private static uint ReadPinCount(ReadOnlySpan<byte> data) => BinaryPrimitives.ReadUInt32BigEndian(data);

    /// <summary>
    /// Reads a PIN Index's current pinCount through the OWNER-authorized <c>TPM2_NV_Read()</c> arm — the one path
    /// that observes <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> without consuming the Index's own authValue (pinCount
    /// moves only when the INDEX's authValue resolves the authorization, TPM 2.0 Library Part 1, clause 34.2.6.6).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The PIN Index to observe.</param>
    /// <returns>The pinCount value.</returns>
    private async Task<uint> ReadPinCountByOwnerAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex)
    {
        TpmResult<NvReadResponse> result = await ReadIndexAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, nvIndex, ReadOnlyMemory<byte>.Empty, EightOctetDataSize).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized pinCount read failed: '{result.ResponseCode}'.");

        using NvReadResponse read = result.Value;

        return ReadPinCount(read.Data);
    }

    /// <summary>
    /// Reads an Index's Name back from the TPM through <c>TPM2_NV_ReadPublic()</c> — the authoritative source of a
    /// session-authorized command's cpHash Name term, since the lock bits are part of the public area the Name
    /// digests (TPM 2.0 Library Part 1, clause 13, Table 9).
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
    /// Reads an Index's <c>TPMA_NV</c> attribute word back through <c>TPM2_NV_ReadPublic()</c>, the public view of
    /// the TPM-maintained lock bits (TPM 2.0 Library Part 2, clause 13.4; Part 3, clause 31.6).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="nvIndex">The Index whose attributes are wanted.</param>
    /// <returns>The Index's attribute word.</returns>
    private async Task<TpmaNv> ReadIndexAttributesAsync(TpmDevice device, uint nvIndex)
    {
        TpmResult<NvReadPublicResponse> result = await device.NvReadPublicAsync(nvIndex, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NvReadPublicAsync failed: '{result.ResponseCode}'.");

        using NvReadPublicResponse publicArea = result.Value;

        return publicArea.NvPublic.Attributes;
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

    /// <summary>Creates a primary ECC P-256 signing key under the endorsement hierarchy, the attestation key the certify proofs sign with.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateSigningPrimaryAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_ENDORSEMENT,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool,
            noDa: true);

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
            .Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead)
            .Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite)
            .Register(TpmCcConstants.TPM_CC_NV_Increment, TpmResponseCodec.NvIncrement)
            .Register(TpmCcConstants.TPM_CC_NV_SetBits, TpmResponseCodec.NvSetBits)
            .Register(TpmCcConstants.TPM_CC_NV_ReadLock, TpmResponseCodec.NvReadLock)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>Extends <see cref="CreateNvRegistry"/> with the codecs the <c>TPM2_NV_Certify()</c> proofs need.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateCertifyRegistry() =>
        CreateNvRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary)
            .Register(TpmCcConstants.TPM_CC_NV_Certify, TpmResponseCodec.NvCertify);

    /// <summary>Extends <see cref="CreateNvRegistry"/> with the <c>TPM2_PolicyNV()</c> codec the policy proofs need.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreatePolicyRegistry() =>
        CreateNvRegistry()
            .Register(TpmCcConstants.TPM_CC_PolicyNV, TpmResponseCodec.PolicyNv);

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

        TpmResult<NvDefineSpaceResponse> result = await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NV_DefineSpace failed: '{result.ResponseCode}'.");

        return result;
    }

    /// <summary>Issues <c>TPM2_NV_Read()</c> against <paramref name="nvIndex"/> authorized by <paramref name="authHandle"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle: the Index itself or the owner hierarchy.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="suppliedAuth">The authValue supplied for <paramref name="authHandle"/>.</param>
    /// <param name="size">The number of octets to read.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ushort size)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: authHandle, NvIndex: nvIndex, Size: size, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues <c>TPM2_NV_Read()</c> against <paramref name="nvIndex"/> over an UNBOUND, unsalted HMAC session
    /// authorized by <paramref name="authHandle"/>, with the Index Name read as the command will find it.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle: the Index itself or the owner hierarchy.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="suppliedAuth">The authValue proven by the HMAC session.</param>
    /// <param name="size">The number of octets to read.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ushort size)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, suppliedAuth).ConfigureAwait(false);
        try
        {
            using(session)
            {
                ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);
                ReadOnlyMemory<byte> authName = authHandle == nvIndex ? indexName : HandleFormName(authHandle);
                ReadOnlyMemory<byte>[] handleNames = [authName, indexName];
                var readInput = new NvReadInput(AuthHandle: authHandle, NvIndex: nvIndex, Size: size, Offset: 0);

                return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                    device, readInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>Issues <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/> at offset zero, authorized by <paramref name="authHandle"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle: the Index itself or the owner hierarchy.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="suppliedAuth">The authValue supplied for <paramref name="authHandle"/>.</param>
    /// <param name="data">The octets to write.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var writeInput = new NvWriteInput(authHandle, nvIndex, writeInputBuffer, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues an OWNER-authorized <c>TPM2_NV_Write()</c> storing <paramref name="pinCount"/> and
    /// <paramref name="pinLimit"/> as the eight-octet <c>TPMS_NV_PIN_COUNTER_PARAMETERS</c> blob (TPM 2.0 Library
    /// Part 2, clause 13.3). A PIN Index forbids <c>TPMA_NV_AUTHWRITE</c> (Part 1, clause 34.2.6.1), so the
    /// owner-authorized arm is the sole provisioning path.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The PIN Index to provision.</param>
    /// <param name="pinCount">The pinCount value to store.</param>
    /// <param name="pinLimit">The pinLimit value to store.</param>
    private async Task WritePinCounterParametersAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, uint pinCount, uint pinLimit)
    {
        using IMemoryOwner<byte> owner = pool.Rent(EightOctetDataSize);
        Memory<byte> blob = owner.Memory[..EightOctetDataSize];
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span, pinCount);
        BinaryPrimitives.WriteUInt32BigEndian(blob.Span[sizeof(uint)..], pinLimit);

        TpmResult<NvWriteResponse> result = await WriteIndexAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, nvIndex, ReadOnlyMemory<byte>.Empty, blob).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized PIN provisioning write failed: '{result.ResponseCode}'.");
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
    /// phase. When <paramref name="withSigningBackend"/> is set, the simulator is also wired with the ECC
    /// (BouncyCastle) signing backend <c>TPM2_CreatePrimary()</c> and <c>TPM2_NV_Certify()</c> need.
    /// </summary>
    /// <param name="withSigningBackend">When <see langword="true"/>, wires the ECC signing backend; otherwise the simulator carries none.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(bool withSigningBackend = false)
    {
        var simulator = withSigningBackend
            ? new TpmSimulator("tpm-in-house-nv-read-lock", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch))
            : new TpmSimulator("tpm-in-house-nv-read-lock", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitSessionlessAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
