using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Extensions.DictionaryAttack;
using Verifiable.Tpm.Extensions.Nv;
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
/// Drives the NV Bit Field Index machinery — <c>TPM2_NV_SetBits()</c>'s authorization ladder on both arms over a
/// password and over an HMAC session, the OR of <c>bits</c> into the eight big-endian octets the Index holds,
/// the <c>TPM_NT_BITS</c> type gate on <c>TPM2_NV_SetBits()</c>, <c>TPM2_NV_Write()</c>,
/// <c>TPM2_NV_Increment()</c> and <c>TPM2_NV_Extend()</c>, <c>TPM2_NV_DefineSpace()</c>'s eight-octet data size
/// rule, and the restart from all-zero bits across a TPM Reset that <c>TPMA_NV_CLEAR_STCLEAR</c> and
/// <c>TPMA_NV_ORDERLY</c> each cause — against the in-house behavioural <see cref="TpmSimulator"/>, entirely
/// in-process with no external assets, through the same production command path the production code uses
/// (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM 2.0 Library Part 1, clause
/// 34.2.6.4; Part 3, clauses 31.3.1, 31.7.1, 31.8.1, 31.9.1, 31.10, 31.13.1.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvSetBitsTests
{
    /// <summary>The data size of every Bit Field Index: "an 8-octet value to be used as a bit field" (TPM 2.0 Library Part 2, clause 13.2, Table 247).</summary>
    private const ushort BitFieldDataSize = 8;

    /// <summary>A data size that is not eight, used to prove clause 31.3.1's <c>TPM_RC_SIZE</c> rule from the refusing side.</summary>
    private const ushort OversizedBitFieldDataSize = 16;

    /// <summary>The declared data size of the Ordinary Index used to prove the type gate.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The declared data size of the Counter Index used to prove the type gate.</summary>
    private const ushort CounterDataSize = 8;

    /// <summary>The SHA-256 digest width in octets — the data size of the Extend Index and the cpHash width.</summary>
    private const ushort Sha256DigestSize = 32;

    /// <summary>The primary Bit Field Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint BitsIndexHandle = 0x0100_0060;

    /// <summary>A Bit Field Index handle that this file deliberately never defines.</summary>
    private const uint UndefinedIndexHandle = 0x0100_0061;

    /// <summary>An Ordinary Index handle, used to prove <c>TPM2_NV_SetBits()</c> refuses a non-Bit-Field type.</summary>
    private const uint OrdinaryIndexHandle = 0x0100_0062;

    /// <summary>A Counter Index handle, used to prove the type gate from the counter side.</summary>
    private const uint CounterIndexHandle = 0x0100_0063;

    /// <summary>An Extend Index handle, used to prove the type gate from the extend side.</summary>
    private const uint ExtendIndexHandle = 0x0100_0064;

    /// <summary>An <c>authHandle</c> that is neither the owner hierarchy nor any Index defined in this file.</summary>
    private const uint MismatchedAuthHandle = 0x0100_006F;

    /// <summary>The lowered <c>maxTries</c> used by the lockout tests to reach Lockout mode quickly.</summary>
    private const uint LoweredMaxTries = 2;

    /// <summary>The hash algorithm for every HMAC-arm session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA public exponent the framework RSA key generator uses (TPM 2.0 Library Part 2, Table 228).</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>The Name algorithm of the RSA endorsement-key-shaped decrypt key the salted-session test builds.</summary>
    private const TpmAlgIdConstants RsaKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The first <c>bits</c> value: the most significant and the least significant bit of the 64-bit field.</summary>
    private const ulong FirstBits = 0x8000_0000_0000_0001;

    /// <summary>The second <c>bits</c> value, disjoint from <see cref="FirstBits"/> so the OR is observable.</summary>
    private const ulong SecondBits = 0x0000_00FF_0000_0000;

    /// <summary>The value <see cref="FirstBits"/> then <see cref="SecondBits"/> leave in the Index: their OR.</summary>
    private const ulong OredBits = FirstBits | SecondBits;

    /// <summary>
    /// Bit Field attributes that authorize read/write with the Index authValue and write with owner
    /// authorization, dictionary-attack protected (<c>TPMA_NV_NO_DA</c> clear).
    /// </summary>
    private const TpmaNv BitsAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_BITS << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The same Bit Field attributes, opted out of dictionary-attack protection.</summary>
    private const TpmaNv NonDaBitsAttributes = BitsAttributes | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>Bit Field attributes deliberately missing <c>TPMA_NV_OWNERWRITE</c>.</summary>
    private const TpmaNv BitsWithoutOwnerWriteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_BITS << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Bit Field attributes deliberately missing <c>TPMA_NV_AUTHWRITE</c>.</summary>
    private const TpmaNv BitsWithoutAuthWriteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_BITS << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Bit Field attributes electing <c>TPMA_NV_CLEAR_STCLEAR</c>, so a TPM Reset CLEARs <c>TPMA_NV_WRITTEN</c>.</summary>
    private const TpmaNv ClearStclearBitsAttributes = BitsAttributes | TpmaNv.TPMA_NV_CLEAR_STCLEAR;

    /// <summary>Bit Field attributes electing <c>TPMA_NV_ORDERLY</c>, so a TPM Reset CLEARs <c>TPMA_NV_WRITTEN</c> through the orderly rule alone.</summary>
    private const TpmaNv OrderlyBitsAttributes = BitsAttributes | TpmaNv.TPMA_NV_ORDERLY;

    /// <summary>Ordinary Index attributes (TPM_NT_ORDINARY is the zero value, so no type shift is needed).</summary>
    private const TpmaNv OrdinaryAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>Counter Index attributes, used to prove the type gate from the counter side.</summary>
    private const TpmaNv CounterAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Extend Index attributes, used to prove the type gate from the extend side.</summary>
    private const TpmaNv ExtendAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_EXTEND << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong Index authorization value, distinct from <see cref="CorrectAuth"/>.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>
    /// A single-octet payload for a rejected-arm <c>TPM2_NV_Write()</c> or <c>TPM2_NV_Extend()</c> attempt; its
    /// content is immaterial since neither may reach a Bit Field Index's stored value.
    /// </summary>
    private static byte[] RejectedWriteAttempt { get; } = [0x00];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies <c>TPM2_NV_SetBits()</c> against an undefined handle answers <c>TPM_RC_HANDLE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10; clause 5.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfUndefinedIndexReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode, "Table 259: nvIndex is TPM2_NV_SetBits()'s second handle (handle 2); an undefined Index is handle-encoded TPM_RC_HANDLE at index 1.");
    }

    /// <summary>
    /// "When an NV Bit Field Index is created, it has no value and the TPMA_NV_WRITTEN attribute will be CLEAR",
    /// so a read before the first <c>TPM2_NV_SetBits()</c> answers <c>TPM_RC_NV_UNINITIALIZED</c> exactly as any
    /// other unwritten Index does.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.4; Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOfBitsIndexBeforeFirstSetBitsReturnsUninitialized()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvReadResponse> result = await ReadIndexAsync(device, pool, registry, BitsIndexHandle, CorrectAuth, BitFieldDataSize).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, result.ResponseCode);
    }

    /// <summary>
    /// "If TPMA_NV_WRITTEN is not SET, then, for the purposes of this command, the NV Index is considered to
    /// contain all zero bits and data is ORed with that value" — the first <c>TPM2_NV_SetBits()</c> of a fresh
    /// Index therefore stores exactly <c>bits</c>, which <c>TPM2_NV_Read()</c> returns as the eight big-endian
    /// octets of the 64-bit field written here by <see cref="BinaryPrimitives"/>, never by the code under test.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 1, clause 34.2.6.4; Part 2, clause 13.2, Table 247</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfUnwrittenIndexReadsBackAsTheBigEndianBits()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_SetBits() failed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, BitsIndexHandle, BigEndianOctets(FirstBits)).ConfigureAwait(false);
    }

    /// <summary>
    /// "The contents of bits are ORed with the current contents of the NV Index" and "the TPM will OR the bits
    /// parameter to the Index": a second <c>TPM2_NV_SetBits()</c> of a disjoint value leaves the union of both,
    /// never the second value alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 1, clause 34.2.6.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsTwiceReadsBackAsTheOrOfBothValues()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> firstResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The first TPM2_NV_SetBits() failed: '{firstResult.ResponseCode}'.");

        TpmResult<NvSetBitsResponse> secondResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, SecondBits).ConfigureAwait(false);
        Assert.IsTrue(secondResult.IsSuccess, $"The second TPM2_NV_SetBits() failed: '{secondResult.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, BitsIndexHandle, BigEndianOctets(OredBits)).ConfigureAwait(false);
    }

    /// <summary>
    /// The OR is idempotent: re-setting bits that are already SET leaves the stored value exactly as it was,
    /// since "the contents of bits are ORed with the current contents of the NV Index" and no bit can be
    /// CLEARed by this command.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 1, clause 34.2.6.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfAlreadySetBitsLeavesTheValueUnchanged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> firstResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The first TPM2_NV_SetBits() failed: '{firstResult.ResponseCode}'.");

        TpmResult<NvSetBitsResponse> repeatResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(repeatResult.IsSuccess, $"The repeated TPM2_NV_SetBits() failed: '{repeatResult.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, BitsIndexHandle, BigEndianOctets(FirstBits)).ConfigureAwait(false);
    }

    /// <summary>
    /// "Any number of bits from 0 to 64 may be SET" at the upper end: a <c>bits</c> of every bit SET leaves all
    /// eight octets of the field at <c>0xFF</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 2, clause 13.2, Table 247</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfAllSixtyFourBitsReadsBackAsEightAllOnesOctets()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, ulong.MaxValue).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_SetBits() of all 64 bits failed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(
            device, pool, registry, BitsIndexHandle, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]).ConfigureAwait(false);
    }

    /// <summary>
    /// "Any number of bits from 0 to 64 may be SET" at the lower end, with "After successful completion of this
    /// command, TPMA_NV_WRITTEN for the NV Index will be SET" and its Note "TPMA_NV_WRITTEN will be SET even if
    /// no bits were SET": a <c>bits</c> of zero on a fresh Index makes the read succeed, answering eight zero
    /// octets rather than <c>TPM_RC_NV_UNINITIALIZED</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 1, clause 34.2.6.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfZeroSetsWrittenAndReadsBackAsEightZeroOctets()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, 0ul).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_SetBits() of no bits at all must succeed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(
            device, pool, registry, BitsIndexHandle, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).ConfigureAwait(false);
    }

    /// <summary>
    /// "After successful completion of this command, TPMA_NV_WRITTEN for the NV Index will be SET" — and the
    /// attribute is part of the public area the Name digests (Part 1, clause 13, Table 9), so the Index Name read
    /// back through <c>TPM2_NV_ReadPublic()</c> changes across the FIRST <c>TPM2_NV_SetBits()</c> and not across
    /// the second, which touches the data area alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 1, clause 13, Table 9</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsChangesTheIndexNameOnTheFirstSetBitsOnly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);
        byte[] nameBefore = await ReadIndexNameAsync(device, BitsIndexHandle).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> firstResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The first TPM2_NV_SetBits() failed: '{firstResult.ResponseCode}'.");
        byte[] nameAfterFirst = await ReadIndexNameAsync(device, BitsIndexHandle).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> secondResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, SecondBits).ConfigureAwait(false);
        Assert.IsTrue(secondResult.IsSuccess, $"The second TPM2_NV_SetBits() failed: '{secondResult.ResponseCode}'.");
        byte[] nameAfterSecond = await ReadIndexNameAsync(device, BitsIndexHandle).ConfigureAwait(false);

        Assert.IsFalse(nameBefore.AsSpan().SequenceEqual(nameAfterFirst), "The first SetBits SETs TPMA_NV_WRITTEN, which the Name digests, so the Name must change.");
        Assert.IsTrue(nameAfterFirst.AsSpan().SequenceEqual(nameAfterSecond), "The second SetBits changes only the data area, which the Name does not cover, so the Name must be stable.");
    }

    /// <summary>
    /// "If nvIndexType is TPM_NT_COUNTER, TPM_NT_BITS, TPM_NT_PIN_FAIL, or TPM_NT_PIN_PASS, then
    /// publicInfo→dataSize shall be set to eight (8) or the TPM shall return TPM_RC_SIZE" — a Bit Field Index
    /// declared at sixteen octets is refused with <c>TPM_RC_SIZE</c>, the response the clause's Note names over
    /// the older reference code's <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfBitsIndexWithSixteenOctetDataSizeReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, BitsIndexHandle, BitsAttributes, OversizedBitFieldDataSize).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), result.ResponseCode,
            "A Bit Field Index whose dataSize is not eight octets is TPM_RC_SIZE, not TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// The admitting half of the clause 31.3.1 size rule, together with "If the implementation does not support
    /// TPM2_NV_SetBits(), the TPM shall return TPM_RC_ATTRIBUTES if nvIndexType is TPM_NT_BITS" read from the
    /// supporting side: an eight-octet Bit Field Index defines successfully and its bits can then be SET.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfBitsIndexWithEightOctetDataSizeSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"An eight-octet Bit Field Index must define: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// The same eight-octet rule over the HMAC-session arm of <c>TPM2_NV_DefineSpace()</c>: a Bit Field Index
    /// declared at sixteen octets is <c>TPM_RC_SIZE</c> there too, so both definition arms agree.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfBitsIndexOverHmacSessionWithSixteenOctetDataSizeReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineOverSessionAsync(
            device, pool, registry, BitsIndexHandle, BitsAttributes, OversizedBitFieldDataSize).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), result.ResponseCode, "The session arm applies the same eight-octet rule as the password arm.");
    }

    /// <summary>
    /// The admitting half of the eight-octet rule over the HMAC-session arm of <c>TPM2_NV_DefineSpace()</c>: an
    /// eight-octet Bit Field Index defines, and the Index then accepts a <c>TPM2_NV_SetBits()</c> that reads back.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfBitsIndexOverHmacSessionWithEightOctetDataSizeSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> defineResult = await DefineOverSessionAsync(
            device, pool, registry, BitsIndexHandle, BitsAttributes, BitFieldDataSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"An eight-octet Bit Field Index must define over a session: '{defineResult.ResponseCode}'.");

        TpmResult<NvSetBitsResponse> setBitsResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(setBitsResult.IsSuccess, $"TPM2_NV_SetBits() failed: '{setBitsResult.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, BitsIndexHandle, BigEndianOctets(FirstBits)).ConfigureAwait(false);
    }

    /// <summary>
    /// The owner arm: "Proper authorizations are required for this command as determined by ...
    /// TPMA_NV_OWNERWRITE" — an owner-authorized <c>TPM2_NV_SetBits()</c> under the (empty) owner authValue
    /// succeeds and the Index reads back under its own authValue.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsByOwnerAuthorizationSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, BitsIndexHandle, ReadOnlyMemory<byte>.Empty, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized TPM2_NV_SetBits() must succeed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, BitsIndexHandle, BigEndianOctets(FirstBits)).ConfigureAwait(false);
    }

    /// <summary>
    /// The owner arm honours <c>TPMA_NV_OWNERWRITE</c> ahead of the compare: with the bit clear an
    /// owner-authorized <c>TPM2_NV_SetBits()</c> is <c>TPM_RC_NV_AUTHORIZATION</c> under a correct AND under a
    /// wrong owner authValue alike, so no comparison outcome leaks through the refusal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.4; Part 3, clause 31.10.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsByOwnerWithoutOwnerWriteReturnsNvAuthorizationRegardlessOfTheSuppliedOwnerAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsWithoutOwnerWriteAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> correctResult = await SetBitsAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, BitsIndexHandle, ReadOnlyMemory<byte>.Empty, FirstBits).ConfigureAwait(false);
        TpmResult<NvSetBitsResponse> wrongResult = await SetBitsAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, BitsIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, correctResult.ResponseCode, "With TPMA_NV_OWNERWRITE clear the owner cannot SET bits, even under the correct owner authValue.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, wrongResult.ResponseCode, "The same refusal under a wrong owner authValue, so the gate runs before the compare.");
    }

    /// <summary>
    /// A wrong owner authValue on the owner arm is a plain <c>TPM_RC_BAD_AUTH</c> that moves no counter: "the
    /// authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA protection".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 3, clause 31.10.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsByOwnerWithWrongOwnerAuthReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, BitsIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 259 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong owner authValue is session-encoded TPM_RC_BAD_AUTH there.");
        Assert.AreEqual(counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong owner authValue must not move failedTries.");
    }

    /// <summary>
    /// "If authHandle is an NV Index, it must be the same as nvIndex (TPM_RC_NV_AUTHORIZATION)" — an
    /// <c>authHandle</c> that is neither the owner hierarchy nor the Index itself is refused with
    /// <c>TPM_RC_NV_AUTHORIZATION</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsWithMismatchedAuthHandleReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, MismatchedAuthHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// The Index arm honours <c>TPMA_NV_AUTHWRITE</c> ahead of the compare: with the bit clear the Index's own
    /// authValue is not an available mechanism for setting bits at all, so a correct AND a wrong value are both
    /// refused with <c>TPM_RC_AUTH_UNAVAILABLE</c> (Part 3, clause 5.6's check 7.2.2 precedes its check 9/10
    /// value compare) and no comparison outcome leaks.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsWithoutAuthWriteReturnsAuthUnavailableForCorrectAndWrongValuesAlike()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsWithoutAuthWriteAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> correctResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        TpmResult<NvSetBitsResponse> wrongResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, correctResult.ResponseCode, "With TPMA_NV_AUTHWRITE clear the Index authValue cannot authorize setting bits, even when it matches.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, wrongResult.ResponseCode, "The identical refusal for a wrong value, so the gate runs before the compare.");
    }

    /// <summary>
    /// A wrong Index authValue against a DA-protected Bit Field Index is an auth-failure that charges
    /// <c>failedTries</c>: "All uses of a DA protected authValue receive DA protection" — read back over
    /// <c>TPM_PT_LOCKOUT_COUNTER</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsWithWrongAuthOnDaProtectedIndexReturnsAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 259 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong authValue on a DA-protected Index is session-encoded TPM_RC_AUTH_FAIL there.");
        Assert.AreEqual(counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong DA-protected authValue must charge failedTries once.");
    }

    /// <summary>
    /// A wrong Index authValue against a <c>TPMA_NV_NO_DA</c> Bit Field Index is a plain bad-authorization that
    /// leaves <c>failedTries</c> untouched — <c>TPMA_NV_NO_DA</c> applies uniformly, with no type carve-out.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsWithWrongAuthOnNoDaIndexReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, NonDaBitsAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 259 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong authValue on a non-DA Index is session-encoded TPM_RC_BAD_AUTH there.");
        Assert.AreEqual(counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A NO_DA Index's wrong authValue must not move failedTries.");
    }

    /// <summary>
    /// Repeated wrong Index-arm attempts against a DA-protected Bit Field Index reach Lockout mode exactly at
    /// the (lowered) <c>maxTries</c>, after which even the correct authValue is refused with
    /// <c>TPM_RC_LOCKOUT</c> before any compare — while the owner arm stays available, since the clause 5.6
    /// lockout gate binds the entity whose authValue is compared, and on that arm it is the DA-exempt owner
    /// hierarchy.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsBruteForceReachesLockoutAndTheOwnerArmStaysAvailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<NvSetBitsResponse> wrongResult = await SetBitsAsync(
                device, pool, registry, BitsIndexHandle, BitsIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
                $"Attempt {attempt} of {LoweredMaxTries} must count as an auth-failure, not yet Lockout mode.");
        }

        TpmResult<NvSetBitsResponse> lockedResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, lockedResult.ResponseCode,
            "Once failedTries reaches maxTries, the Index arm must be refused with TPM_RC_LOCKOUT even with the correct authValue.");

        TpmResult<NvSetBitsResponse> ownerArmResult = await SetBitsAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, BitsIndexHandle, ReadOnlyMemory<byte>.Empty, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(
            ownerArmResult.IsSuccess,
            $"The owner-authorized administrative arm must stay available during lockout: '{ownerArmResult.ResponseCode}'.");
    }

    /// <summary>
    /// "If TPM_NT_BITS is not SET, then the TPM shall return TPM_RC_ATTRIBUTES" — and the gate runs AFTER
    /// authorization (the reference's own <c>NvWriteAccessChecks</c> runs before <c>IsNvBitsIndex</c>): an
    /// Ordinary Index answers <c>TPM_RC_ATTRIBUTES</c> under its correct authValue and the auth-failure under a
    /// wrong one.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfOrdinaryIndexReturnsAttributesUnderCorrectAuthAndAuthFailUnderWrongAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, OrdinaryIndexHandle, OrdinaryAttributes, OrdinaryDataSize).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> correctResult = await SetBitsAsync(
            device, pool, registry, OrdinaryIndexHandle, OrdinaryIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        TpmResult<NvSetBitsResponse> wrongResult = await SetBitsAsync(
            device, pool, registry, OrdinaryIndexHandle, OrdinaryIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), correctResult.ResponseCode, "TPM2_NV_SetBits() must refuse a non-Bit-Field Index once authorization has succeeded.");
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode, "The authorization is checked before the type, so a wrong authValue answers the auth-failure, not TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// The type gate from the Counter side: a Counter Index is refused with <c>TPM_RC_ATTRIBUTES</c> — the four
    /// update commands partition the NV Index types (Part 1, clause 34.2.6.1) — and only after authorization,
    /// so a wrong authValue answers the auth-failure instead.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfCounterIndexReturnsAttributesUnderCorrectAuthAndAuthFailUnderWrongAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes, CounterDataSize).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> correctResult = await SetBitsAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        TpmResult<NvSetBitsResponse> wrongResult = await SetBitsAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), correctResult.ResponseCode, "TPM2_NV_SetBits() must refuse a Counter Index once authorization has succeeded.");
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode, "The authorization is checked before the type, so a wrong authValue answers the auth-failure, not TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// The type gate from the Extend side: "The Index can only be modified using TPM2_NV_Extend()" (Part 2,
    /// Table 247), so <c>TPM2_NV_SetBits()</c> against an Extend Index is <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 2, clause 13.2, Table 247</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfExtendIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes, Sha256DigestSize).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode, "Table 259: nvIndex is TPM2_NV_SetBits()'s second handle (handle 2); an Index whose type is not TPM_NT_BITS is handle-encoded TPM_RC_ATTRIBUTES at index 1.");
    }

    /// <summary>
    /// "If nvIndexType is TPM_NT_COUNTER, TPM_NT_BITS or TPM_NT_EXTEND, then the TPM shall return
    /// TPM_RC_ATTRIBUTES" — <c>TPM2_NV_Write()</c> refuses a Bit Field Index, so only <c>TPM2_NV_SetBits()</c>
    /// can ever modify its eight-octet value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.7.1; Part 1, clause 34.2.6.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfBitsIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        using TpmPasswordSession session = TpmPasswordSession.Create(CorrectAuth, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(RejectedWriteAttempt, pool);
        var writeInput = new NvWriteInput(BitsIndexHandle, BitsIndexHandle, writeInputBuffer, Offset: 0);
        TpmResult<NvWriteResponse> result = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
            "TPM2_NV_Write() must refuse a Bit Field Index once authorization has already succeeded - only TPM2_NV_SetBits() may modify it.");
    }

    /// <summary>
    /// "If nvIndexType is not TPM_NT_COUNTER in the indicated NV Index, the TPM shall return TPM_RC_ATTRIBUTES"
    /// — <c>TPM2_NV_Increment()</c> refuses a Bit Field Index.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOfBitsIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        using TpmPasswordSession session = TpmPasswordSession.Create(CorrectAuth, pool);
        var incrementInput = new NvIncrementInput(BitsIndexHandle, BitsIndexHandle);
        TpmResult<NvIncrementResponse> result = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, incrementInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode, "Table 255: nvIndex is TPM2_NV_Increment()'s second handle (handle 2); an Index whose type is not TPM_NT_COUNTER is handle-encoded TPM_RC_ATTRIBUTES at index 1.");
    }

    /// <summary>
    /// "If nvIndexType is not TPM_NT_EXTEND, then the TPM shall return TPM_RC_ATTRIBUTES" —
    /// <c>TPM2_NV_Extend()</c> refuses a Bit Field Index, closing the last of the three sibling update commands
    /// on this type.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfBitsIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        using TpmPasswordSession session = TpmPasswordSession.Create(CorrectAuth, pool);
        using Tpm2bMaxNvBuffer extendInputBuffer = Tpm2bMaxNvBuffer.Create(RejectedWriteAttempt, pool);
        var extendInput = new NvExtendInput(BitsIndexHandle, BitsIndexHandle, extendInputBuffer);
        TpmResult<NvExtendResponse> result = await TpmCommandExecutor.ExecuteAsync<NvExtendResponse>(
            device, extendInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode, "Table 257: nvIndex is TPM2_NV_Extend()'s second handle (handle 2); an Index whose type is not TPM_NT_EXTEND is handle-encoded TPM_RC_ATTRIBUTES at index 1.");
    }

    /// <summary>
    /// "For an NV Index with the TPM_NT_COUNTER or TPM_NT_BITS attribute SET, the TPM may ignore the offset
    /// parameter and use an offset of 0" — a permission, not a requirement, and this TPM does not take it: a
    /// read at offset 4 for 4 octets answers the LOW half of the big-endian 64-bit field, the last four octets.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.13.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOfBitsIndexAtOffsetFourReturnsTheLowHalf()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> setBitsResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(setBitsResult.IsSuccess, $"TPM2_NV_SetBits() failed: '{setBitsResult.ResponseCode}'.");

        TpmResult<NvReadResponse> readResult = await ReadIndexAsync(
            device, pool, registry, BitsIndexHandle, CorrectAuth, size: 4, offset: 4).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"The half-field read failed: '{readResult.ResponseCode}'.");

        //The low four octets of 0x8000_0000_0000_0001 written big-endian, hand-written rather than derived.
        byte[] expected = [0x00, 0x00, 0x00, 0x01];
        using NvReadResponse read = readResult.Value;
        Assert.IsTrue(expected.AsSpan().SequenceEqual(read.Data), "The honoured offset must return the low four big-endian octets of the bit field.");
    }

    /// <summary>
    /// <c>TPMA_NV_CLEAR_STCLEAR</c>: "TPMA_NV_WRITTEN for the Index is CLEAR by TPM Reset or TPM Restart" — after
    /// <c>Shutdown(CLEAR)</c>/<c>Startup(CLEAR)</c>
    /// a CLEAR_STCLEAR Bit Field Index reads <c>TPM_RC_NV_UNINITIALIZED</c> again, and Part 1, clause 34.2.6.4's
    /// check is on the ATTRIBUTE: the next <c>TPM2_NV_SetBits()</c> restarts from all-zero bits rather than
    /// ORing over the octets the reserved area still holds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.1; Part 1, clause 34.2.6.4; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfClearStclearIndexRestartsFromZeroAfterATpmReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, ClearStclearBitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> firstResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The SetBits before the Reset failed: '{firstResult.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<NvReadResponse> readAfterReset = await ReadIndexAsync(device, pool, registry, BitsIndexHandle, CorrectAuth, BitFieldDataSize).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_UNINITIALIZED, readAfterReset.ResponseCode,
            "A TPM Reset must CLEAR TPMA_NV_WRITTEN on a CLEAR_STCLEAR Index, so the read must be refused.");

        TpmResult<NvSetBitsResponse> secondResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, SecondBits).ConfigureAwait(false);
        Assert.IsTrue(secondResult.IsSuccess, $"The SetBits after the Reset failed: '{secondResult.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, BitsIndexHandle, BigEndianOctets(SecondBits)).ConfigureAwait(false);
    }

    /// <summary>
    /// "If TPMA_NV_ORDERLY is SET, the RAM version of the Bit Field data is updated but it is not written to NV
    /// ... on TPM Reset, the TPMA_NV_WRITTEN attribute of the Index will be CLEAR" — the orderly rule alone,
    /// without <c>TPMA_NV_CLEAR_STCLEAR</c>: after <c>Shutdown(CLEAR)</c>/<c>Startup(CLEAR)</c> an ORDERLY Bit
    /// Field Index reads <c>TPM_RC_NV_UNINITIALIZED</c> and the next <c>TPM2_NV_SetBits()</c> restarts from
    /// all-zero bits.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.4; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOfOrderlyIndexRestartsFromZeroAfterATpmReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, OrderlyBitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> firstResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The SetBits before the Reset failed: '{firstResult.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<NvReadResponse> readAfterReset = await ReadIndexAsync(device, pool, registry, BitsIndexHandle, CorrectAuth, BitFieldDataSize).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_UNINITIALIZED, readAfterReset.ResponseCode,
            "A TPM Reset must CLEAR TPMA_NV_WRITTEN on an ORDERLY Index, so the read must be refused.");

        TpmResult<NvSetBitsResponse> secondResult = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, SecondBits).ConfigureAwait(false);
        Assert.IsTrue(secondResult.IsSuccess, $"The SetBits after the Reset failed: '{secondResult.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, BitsIndexHandle, BigEndianOctets(SecondBits)).ConfigureAwait(false);
    }

    /// <summary>
    /// The Index arm over an unbound, unsalted HMAC session: the command HMAC verifies against a cpHash whose
    /// Name terms are the Index's Name AS THE COMMAND FOUND IT — the first <c>TPM2_NV_SetBits()</c> SETs
    /// <c>TPMA_NV_WRITTEN</c>, so the Name the caller read before the command is the one cpHash must fold — and
    /// whose parameters term is the eight raw octets of <c>bits</c>; the Index then reads back as those octets.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15; clause 34.2.6.4; Part 3, clause 31.10</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverHmacSessionAtTheIndexArmSucceedsOnTheFirstSetBits()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsOverHmacAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_SetBits() over an HMAC session failed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, BitsIndexHandle, BigEndianOctets(FirstBits)).ConfigureAwait(false);
    }

    /// <summary>
    /// The owner arm over an HMAC session: cpHash's Name1 is the owner's raw handle (Part 1, Table 9: a
    /// permanent handle's Name IS its handle value) and Name2 the Index's computed Name; the empty owner
    /// authValue keys the HMAC alongside the empty session key.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15; clause 13, Table 9; Part 3, clause 31.10</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverHmacSessionAtTheOwnerArmSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsOverHmacAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, BitsIndexHandle, ReadOnlyMemory<byte>.Empty, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized TPM2_NV_SetBits() over an HMAC session failed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, BitsIndexHandle, BigEndianOctets(FirstBits)).ConfigureAwait(false);
    }

    /// <summary>
    /// A wrong Index authValue proven over an HMAC session is the same auth-failure the password arm answers,
    /// session-encoded — the base error is <c>TPM_RC_AUTH_FAIL</c> and the raw wire code carries the
    /// session-index modifier (Part 2, clause 6.6.2) — and it charges <c>failedTries</c> exactly once,
    /// mechanism-blind.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverHmacSessionWithWrongAuthReturnsSessionEncodedAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsOverHmacAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError);
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode, "A command-HMAC mismatch names the offending session, so the raw wire code carries the session-index modifier.");
        Assert.AreEqual(counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong DA-protected authValue proven over a session must charge failedTries once.");
    }

    /// <summary>
    /// The stranger-authHandle answer survives on the HMAC arm exactly as on the password arm: an
    /// <c>authHandle</c> that is neither the owner hierarchy nor the Index itself is
    /// <c>TPM_RC_NV_AUTHORIZATION</c> (Part 3, clause 31.1), refused before any HMAC is evaluated.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverHmacSessionWithMismatchedAuthHandleReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsOverHmacAsync(
            device, pool, registry, MismatchedAuthHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// The owner arm over an HMAC session honours <c>TPMA_NV_OWNERWRITE</c> before any HMAC work: with the bit
    /// clear the command is <c>TPM_RC_NV_AUTHORIZATION</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.4; Part 3, clause 31.10.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverHmacSessionByOwnerWithoutOwnerWriteReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsWithoutOwnerWriteAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsOverHmacAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, BitsIndexHandle, ReadOnlyMemory<byte>.Empty, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// The Index arm over an HMAC session honours <c>TPMA_NV_AUTHWRITE</c> before any HMAC work: with the bit
    /// clear the Index's own authValue is not an available mechanism, so the command is
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> even under the correct value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverHmacSessionWithoutAuthWriteReturnsAuthUnavailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsWithoutAuthWriteAttributes).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsOverHmacAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, result.ResponseCode);
    }

    /// <summary>
    /// Lockout mode refuses the HMAC arm exactly as the password arm: once wrong PASSWORD attempts have driven
    /// the TPM into Lockout mode, an HMAC-proven attempt with the CORRECT authValue is refused with
    /// <c>TPM_RC_LOCKOUT</c> before any HMAC is evaluated — the gate binds the DA-protected entity, not the
    /// mechanism used to present the authValue.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.3; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverHmacSessionInLockoutModeReturnsLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<NvSetBitsResponse> wrongResult = await SetBitsAsync(
                device, pool, registry, BitsIndexHandle, BitsIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode, $"Attempt {attempt} of {LoweredMaxTries} must count as an auth-failure while driving the TPM into Lockout mode.");
        }

        TpmResult<NvSetBitsResponse> lockedResult = await SetBitsOverHmacAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, lockedResult.ResponseCode, "The Index arm over a session must be refused while the TPM is in Lockout mode, even with the correct authValue.");
    }

    /// <summary>
    /// A wrong authValue proven over an HMAC session against a <c>TPMA_NV_NO_DA</c> Bit Field Index is a plain
    /// bad-authorization, session-encoded, that leaves <c>failedTries</c> untouched.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverHmacSessionWithWrongAuthOnNoDaIndexReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, NonDaBitsAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvSetBitsResponse> result = await SetBitsOverHmacAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, WrongAuth, FirstBits).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError);
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode, "A command-HMAC mismatch names the offending session, so the raw wire code carries the session-index modifier.");
        Assert.AreEqual(counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A NO_DA Index's wrong authValue must not move failedTries, whatever the mechanism.");
    }

    /// <summary>
    /// The SIMULATOR-side proof that parameter encryption has nothing to act on here: a hand-framed command
    /// whose authorizing session claims <c>decrypt</c> is refused with <c>TPM_RC_ATTRIBUTES</c> naming the
    /// session, while the identical session without the attribute succeeds. <c>bits</c> is a plain
    /// <c>UINT64</c>, not a sized TPM2B, and Part 1, clause 18.1 makes only a sized first parameter
    /// decrypt-eligible, so the refusal is the specification's own answer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.7; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverSessionWithDecryptAttributeReturnsAttributesWhileTheSameSessionWithoutItSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmRcConstants rawDecryptCode = await SetBitsOverHmacHandFramedAsync(
            device, pool, registry, BitsIndexHandle, CorrectAuth, FirstBits, TpmaSession.DECRYPT).ConfigureAwait(false);
        TpmResult<NvSetBitsResponse> decryptResult = TpmResult<NvSetBitsResponse>.TpmError(rawDecryptCode);
        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, decryptResult.BaseError, "bits is not a sized parameter, so the simulator must fail a decrypt-attributed session closed rather than silently ignoring it.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, decryptResult.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<NvSetBitsResponse> declinedResult = await SetBitsOverHmacAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(declinedResult.IsSuccess, $"The identical authValue over an otherwise identical session with decrypt left CLEAR must succeed: '{declinedResult.ResponseCode}'.");
    }

    /// <summary>
    /// The encrypt-attributed half: Table 260 gives <c>TPM2_NV_SetBits()</c> no response parameter, so an
    /// <c>encrypt</c>-attributed session names an operation with nothing to act on and fails closed with
    /// <c>TPM_RC_ATTRIBUTES</c> (Part 3, clause 5.7), proven the same hand-framed way alongside the declined
    /// case.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.7; clause 31.10.2, Table 260</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverSessionWithEncryptAttributeReturnsAttributesWhileTheSameSessionWithoutItSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        TpmRcConstants rawEncryptCode = await SetBitsOverHmacHandFramedAsync(
            device, pool, registry, BitsIndexHandle, CorrectAuth, FirstBits, TpmaSession.ENCRYPT).ConfigureAwait(false);
        TpmResult<NvSetBitsResponse> encryptResult = TpmResult<NvSetBitsResponse>.TpmError(rawEncryptCode);
        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, encryptResult.BaseError, "TPM2_NV_SetBits() has no response parameter, so the simulator must fail an encrypt-attributed session closed.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, encryptResult.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<NvSetBitsResponse> declinedResult = await SetBitsOverHmacAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(declinedResult.IsSuccess, $"The identical authValue over an otherwise identical session with encrypt left CLEAR must succeed: '{declinedResult.ResponseCode}'.");
    }

    /// <summary>
    /// The <c>audit</c> attribute on the authorizing session is admitted and the command succeeds, extending the
    /// session's audit digest to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its first use (TPM 2.0 Library Part 1, clause
    /// 17.1, equation 30) with the response echoing <c>audit</c> SET, <c>auditExclusive</c> SET and
    /// <c>auditReset</c> CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38) — proved by chaining cpHash/rpHash
    /// from the octets this test itself sent and read, then reading the session's digest back through
    /// <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer — and, as with a plain session, an identical
    /// session with the attribute left CLEAR also succeeds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverSessionWithAuditAttributeSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        (byte[] response, uint sessionHandle, byte[] cpHash) = await SetBitsOverHmacHandFramedForAuditAsync(
            device, pool, registry, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
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
            byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_NV_SetBits, responseParameters, pool).ConfigureAwait(false);
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
                "The session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from the NV_SetBits exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }

        TpmResult<NvSetBitsResponse> declinedResult = await SetBitsOverHmacAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(declinedResult.IsSuccess, $"The identical authValue over an otherwise identical session with audit left CLEAR must also succeed: '{declinedResult.ResponseCode}'.");
    }

    /// <summary>
    /// The client-side companion (decrypt half): the SAME decrypt-attributed session routed through the
    /// production <see cref="TpmCommandExecutor"/> never reaches the wire — the executor's own admissibility
    /// guard refuses it with <see cref="ArgumentException"/>, because <c>NvSetBitsInput</c> declares no
    /// encryptable first command parameter, so the host and the simulator agree.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverSessionWithDecryptAttributeIsRefusedByTheClientSideGuardBeforeReachingTheSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await SetBitsOverHmacAsync(
                device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits, TpmaSession.DECRYPT).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>
    /// The client-side companion (encrypt half): the executor refuses an encrypt-attributed session with
    /// <see cref="ArgumentException"/> before any bytes reach the wire, because the registered <c>NvSetBits</c>
    /// codec declares no encryptable first response parameter.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.2, Table 260</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverSessionWithEncryptAttributeIsRefusedByTheClientSideGuardBeforeReachingTheSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await SetBitsOverHmacAsync(
                device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits, TpmaSession.ENCRYPT).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>
    /// A SALTED HMAC session BOUND to the Bit Field Index itself: the Index's own authValue already feeds the
    /// session key's KDFa (equation 20), so the per-command HMAC key omits the authValue term when the session
    /// authorizes that SAME bound entity (equation 22) — the command succeeds even though the composing session
    /// never calls <c>SetAuthValue</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.10, equations 20 and 22</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverIndexBoundAndSaltedSessionForTheBoundEntityOmitsAuthValueAndSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(withRsaBackend: true).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSaltedSessionRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(device, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateBoundAndSaltedHmacSession(
            tpmKeyHandle, BitsIndexHandle, modulus, DefaultRsaExponent, RsaKeyNameAlg, HmacSessionAlg, rsaBackend.EncryptOaep, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, salted.Input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound-to-Index, salted) failed: '{startResult.ResponseCode}'.");

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                //Bound to BitsIndexHandle itself with CorrectAuth as the bind entity's own authValue: the
                //session key already carries it (equation 20), so SetAuthValue is deliberately never called.
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), CorrectAuth, salted.Input.NonceCaller, started.NonceTPM,
                    HmacSessionAlg, TestEntropy.NewCounterStream(), pool, salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, BitsIndexHandle).ConfigureAwait(false);
                ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

                var setBitsInput = new NvSetBitsInput(BitsIndexHandle, BitsIndexHandle, FirstBits);

                TpmResult<NvSetBitsResponse> result = await TpmCommandExecutor.ExecuteAsync<NvSetBitsResponse>(
                    device, setBitsInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

                Assert.IsTrue(result.IsSuccess, $"The bound-to-the-Index, salted HMAC session must authorize its own bound entity: '{result.ResponseCode}'.");
            }
            finally
            {
                _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                    device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
            }
        }
        finally
        {
            salted.Salt.Memory.Span[..salted.SaltLength].Clear();
            salted.Salt.Dispose();
        }
    }

    /// <summary>
    /// The password form returns every carrier its parse rented on each path: a refusal at the existence gate
    /// (before authorization), a refusal at the type gate (after authorization), and a success — the metered
    /// pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsReturnsItsCarriersAcrossRefusalsAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, OrdinaryIndexHandle, OrdinaryAttributes, OrdinaryDataSize).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvSetBitsResponse> undefinedResult = await SetBitsAsync(
            device, pool, registry, UndefinedIndexHandle, UndefinedIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), undefinedResult.ResponseCode, "Table 259: nvIndex is TPM2_NV_SetBits()'s second handle (handle 2); an undefined Index is handle-encoded TPM_RC_HANDLE at index 1.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal before authorization releases the slot credential through the request's own Dispose.");

        TpmResult<NvSetBitsResponse> ordinaryResult = await SetBitsAsync(
            device, pool, registry, OrdinaryIndexHandle, OrdinaryIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), ordinaryResult.ResponseCode, "Table 259: nvIndex is TPM2_NV_SetBits()'s second handle (handle 2); an ordinary (non-BITS) Index is handle-encoded TPM_RC_ATTRIBUTES at index 1.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal after authorization releases the slot credential through the request's own Dispose.");

        TpmResult<NvSetBitsResponse> result = await SetBitsAsync(
            device, pool, registry, BitsIndexHandle, BitsIndexHandle, CorrectAuth, FirstBits).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_SetBits() failed: '{result.ResponseCode}'.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The accepting transition is the slot credential's terminal owner and must release it.");
    }

    /// <summary>
    /// The HMAC-session form returns every carrier its parse rented — the raw parameter area, the slot
    /// credentials and the computed Index Name — across a refusal at the command HMAC and a success: the metered
    /// pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10; Part 1, clause 15.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsOverHmacSessionReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);
        ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, BitsIndexHandle).ConfigureAwait(false);
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
                    var input = new NvSetBitsInput(BitsIndexHandle, BitsIndexHandle, FirstBits);
                    TpmResult<NvSetBitsResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvSetBitsResponse>(
                        device, input, [wrongSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, refused.BaseError);
                }

                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A command refused at its command HMAC releases every carrier its parse rented.");

                {
                    var input = new NvSetBitsInput(BitsIndexHandle, BitsIndexHandle, FirstBits);
                    TpmResult<NvSetBitsResponse> result = await TpmCommandExecutor.ExecuteAsync<NvSetBitsResponse>(
                        device, input, [correctSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"TPM2_NV_SetBits() over an HMAC session failed: '{result.ResponseCode}'.");
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
    /// Table 259's <c>bits</c> is a <c>UINT64</c>, so a command body that leaves only SEVEN octets after the
    /// authorization area is a truncated integer: the wire read answers <c>TPM_RC_INSUFFICIENT</c>
    /// parameter-encoded to <c>bits</c>, parameter 1 of Table 259, before the command body's own rules are
    /// reached.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.2, Table 259; clause 5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsWithSevenOctetsOfBitsReturnsInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        //Handle area, a password authorization area, then one octet short of the UINT64 the table declares.
        var body = new List<byte>();
        AppendUInt32(body, BitsIndexHandle);
        AppendUInt32(body, BitsIndexHandle);
        AppendPasswordAuthorizationArea(body);
        body.AddRange(new byte[sizeof(ulong) - 1]);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_SetBits, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 259: bits is TPM2_NV_SetBits()'s sole parameter (index 0); a truncated UINT64 parameter is refused at the wire read with parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// <c>bits</c> is the command's only parameter (Table 259), so a ninth octet after it leaves the command
    /// buffer longer than the structures the command consumes: clause 5.2's "commandSize ... shall match" rule
    /// answers <c>TPM_RC_SIZE</c> with no handle, session, or parameter designated, the trailing-octet check
    /// naming no field in the command's own tables.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.2, Table 259; clause 5.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsWithATrailingOctetAfterBitsReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        //Handle area, a password authorization area, the eight octets of bits, then one octet too many.
        var body = new List<byte>();
        AppendUInt32(body, BitsIndexHandle);
        AppendUInt32(body, BitsIndexHandle);
        AppendPasswordAuthorizationArea(body);
        body.AddRange(BigEndianOctets(FirstBits));
        body.Add(0x00);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_SetBits, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, code, "No octet may follow the command's only parameter.");
    }

    /// <summary>
    /// Table 259 fixes the tag at <c>TPM_ST_SESSIONS</c>: a <c>TPM_ST_NO_SESSIONS</c> frame carrying no
    /// authorization area at all is refused with <c>TPM_RC_AUTH_MISSING</c>, since the command's
    /// <c>@authHandle</c> requires an authorization the frame does not carry.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.10.2, Table 259; clause 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvSetBitsWithoutAnAuthorizationAreaReturnsAuthMissing()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, BitsIndexHandle, BitsAttributes).ConfigureAwait(false);

        //Handle area and the parameter alone: the frame declares no sessions and carries no authorization area.
        var body = new List<byte>();
        AppendUInt32(body, BitsIndexHandle);
        AppendUInt32(body, BitsIndexHandle);
        body.AddRange(BigEndianOctets(FirstBits));

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_NO_SESSIONS, TpmCcConstants.TPM_CC_NV_SetBits, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_MISSING, code, "An authorized command sent without an authorization area is TPM_RC_AUTH_MISSING.");
    }

    /// <summary>
    /// The independent value oracle: the eight big-endian octets of a 64-bit field, written by
    /// <see cref="BinaryPrimitives"/> rather than by any helper of the code under test (TPM 2.0 Library Part 2,
    /// clause 13.2, Table 247).
    /// </summary>
    /// <param name="value">The bit-field value.</param>
    /// <returns>The eight octets the Index holds for that value.</returns>
    private static byte[] BigEndianOctets(ulong value)
    {
        byte[] octets = new byte[BitFieldDataSize];
        BinaryPrimitives.WriteUInt64BigEndian(octets, value);

        return octets;
    }

    /// <summary>
    /// Reads the Bit Field Index's whole eight-octet data area under its own authValue and asserts it equals
    /// <paramref name="expected"/> octet for octet.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Bit Field Index to read.</param>
    /// <param name="expected">The value the oracle predicts.</param>
    private async Task AssertReadsBackAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, byte[] expected)
    {
        TpmResult<NvReadResponse> readResult = await ReadIndexAsync(device, pool, registry, nvIndex, CorrectAuth, BitFieldDataSize).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"The read-back failed: '{readResult.ResponseCode}'.");

        using NvReadResponse read = readResult.Value;
        Assert.AreEqual(BitFieldDataSize, read.Data.Length, "A Bit Field Index holds exactly eight octets.");
        Assert.IsTrue(expected.AsSpan().SequenceEqual(read.Data), "The Index must read back as the big-endian octets of the ORed 64-bit field.");
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
    /// Issues an owner-authorized <c>TPM2_NV_DefineSpace()</c> over an unbound, unsalted HMAC session for
    /// <paramref name="nvIndex"/> with <see cref="CorrectAuth"/> as the Index authValue — cpHash's only Name
    /// term is the owner hierarchy's handle-form Name (Part 3, clause 31.3.2, Table 245).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="dataSize">The declared data area size.</param>
    /// <returns>The define-space result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineOverSessionAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes, ushort dataSize)
    {
        (uint sessionHandle, TpmSession session) = await StartUnboundSessionAsync(device, pool, registry, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        try
        {
            using(session)
            {
                using var auth = Tpm2bAuth.Create(CorrectAuth, pool);
                using var publicInfo = new TpmsNvPublic(nvIndex, TpmAlgIdConstants.TPM_ALG_SHA256, attributes, Tpm2bDigest.Empty, dataSize);
                using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);
                ReadOnlyMemory<byte>[] handleNames = [HandleFormName((uint)TpmRh.TPM_RH_OWNER)];

                return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
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
    /// Shared by this file's HMAC-arm tests: issues <c>TPM2_NV_SetBits()</c> against <paramref name="nvIndex"/>
    /// over an UNBOUND, unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9) whose authValue is
    /// <paramref name="suppliedAuth"/>, on the Index arm (cpHash Names <c>[indexName, indexName]</c>) or the
    /// owner arm (<c>[ownerHandle, indexName]</c>), optionally carrying
    /// <paramref name="extraSessionAttributes"/> for the parameter-encryption tests.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing handle: the Index itself or <c>TPM_RH_OWNER</c>.</param>
    /// <param name="nvIndex">The Bit Field Index whose bits are SET.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="bits">The 64-bit value ORed into the Index.</param>
    /// <param name="extraSessionAttributes">Additional <c>TPMA_SESSION</c> bits to set on the composed session.</param>
    /// <returns>The set-bits result.</returns>
    private async Task<TpmResult<NvSetBitsResponse>> SetBitsOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth,
        ulong bits, TpmaSession extraSessionAttributes = default)
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
            session.SessionAttributes |= extraSessionAttributes;

            ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, nvIndex).ConfigureAwait(false);
            ReadOnlyMemory<byte> authName = authHandle == nvIndex ? indexName : HandleFormName(authHandle);
            ReadOnlyMemory<byte>[] handleNames = [authName, indexName];

            var setBitsInput = new NvSetBitsInput(authHandle, nvIndex, bits);

            return await TpmCommandExecutor.ExecuteAsync<NvSetBitsResponse>(
                device, setBitsInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The SIMULATOR-side proof for the parameter-encryption fail-closed gate: hand-frames a raw
    /// <c>TPM2_NV_SetBits()</c> authorized by a single unbound, unsalted HMAC session whose
    /// <c>sessionAttributes</c> octet carries <paramref name="attribute"/>, and submits it directly to the
    /// transport — bypassing <see cref="TpmCommandExecutor"/>, whose own client-side guard would refuse this
    /// composition before any bytes reach the wire. The cpHash and command HMAC are the SAME production
    /// computation <see cref="TpmSession"/> performs for every other session-authorized test in this file; the
    /// parameters term is the eight raw octets of <c>bits</c>, with no size prefix, since Table 259 declares a
    /// bare <c>UINT64</c> (Part 1, clause 15.7, equation 15).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own StartAuthSession/FlushContext lifecycle).</param>
    /// <param name="nvIndex">The Bit Field Index whose bits are SET; also the authorizing handle.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="bits">The 64-bit value ORed into the Index.</param>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test: <see cref="TpmaSession.DECRYPT"/>, <see cref="TpmaSession.ENCRYPT"/> or <see cref="TpmaSession.AUDIT"/>.</param>
    /// <returns>The raw wire response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> SetBitsOverHmacHandFramedAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ulong bits, TpmaSession attribute)
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

            //cpHash = H_SHA256(commandCode || Name(authHandle) || Name(nvIndex) || bits) — TPM 2.0 Library Part 1,
            //clause 15.7, equation 15, the parameters term being the eight raw octets of the UINT64 with no size
            //prefix. This arm's authHandle and nvIndex are the same Index, so both Name terms are identical.
            const int parametersLength = sizeof(ulong);
            int cpHashInputLength = sizeof(uint) + indexName.Length + indexName.Length + parametersLength;
            using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
            Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
            {
                var cpHashWriter = new TpmWriter(cpHashInput.Span);
                cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_SetBits);
                cpHashWriter.WriteBytes(indexName.Span);
                cpHashWriter.WriteBytes(indexName.Span);
                cpHashWriter.WriteUInt64(bits);
            }

            using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
                cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            session.RollNonceCaller(pool);
            using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
                cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

            const int handlesSize = 2 * sizeof(uint);
            int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
            int totalSize = TpmHeader.HeaderSize + handlesSize + authAreaSize + parametersLength;

            using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
            Memory<byte> command = commandOwner.Memory[..totalSize];
            var writer = new TpmWriter(command.Span);
            writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
            writer.WriteUInt32((uint)totalSize);
            writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_SetBits);
            writer.WriteUInt32(nvIndex);
            writer.WriteUInt32(nvIndex);
            writer.WriteUInt32((uint)session.GetAuthCommandSize());
            session.WriteAuthCommand(ref writer, hmac);
            writer.WriteUInt64(bits);

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
    /// The audit twin of <see cref="SetBitsOverHmacHandFramedAsync"/>: hand-frames a raw <c>TPM2_NV_SetBits()</c>
    /// authorized by a single unbound, unsalted HMAC session carrying <c>audit ‖ continueSession</c>, submits it
    /// directly to the transport, and returns the raw response octets, the session handle and the independently
    /// computed cpHash WITHOUT flushing the session — the caller keeps it loaded to read its audit digest back
    /// through <c>TPM2_GetSessionAuditDigest()</c>.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own StartAuthSession lifecycle).</param>
    /// <param name="nvIndex">The Bit Field Index whose bits are SET; also the authorizing handle.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="bits">The 64-bit value ORed into the Index.</param>
    /// <returns>The raw response octets, the session handle (unflushed) and cpHash.</returns>
    private async Task<(byte[] Response, uint SessionHandle, byte[] CpHash)> SetBitsOverHmacHandFramedForAuditAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ulong bits)
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

        const int parametersLength = sizeof(ulong);
        int cpHashInputLength = sizeof(uint) + indexName.Length + indexName.Length + parametersLength;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_SetBits);
            cpHashWriter.WriteBytes(indexName.Span);
            cpHashWriter.WriteBytes(indexName.Span);
            cpHashWriter.WriteUInt64(bits);
        }

        using DigestValue cpHash = await CryptographicKeyEvents.ComputeDigestAsync(
            cpHashInput, outputByteLength: Sha256DigestSize, tag: DigestTag(), pool: pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        session.RollNonceCaller(pool);
        using Tpm2bAuth? hmac = await session.PrepareAuthHmacAsync(
            cpHash.AsReadOnlyMemory(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        const int handlesSize = 2 * sizeof(uint);
        int authAreaSize = sizeof(uint) + session.GetAuthCommandSize();
        int totalSize = TpmHeader.HeaderSize + handlesSize + authAreaSize + parametersLength;

        using IMemoryOwner<byte> commandOwner = pool.Rent(totalSize);
        Memory<byte> command = commandOwner.Memory[..totalSize];
        var writer = new TpmWriter(command.Span);
        writer.WriteUInt16((ushort)TpmStConstants.TPM_ST_SESSIONS);
        writer.WriteUInt32((uint)totalSize);
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_SetBits);
        writer.WriteUInt32(nvIndex);
        writer.WriteUInt32(nvIndex);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);
        writer.WriteUInt64(bits);

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
    /// <see cref="SetBitsOverHmacHandFramedAsync"/>: SHA-256 digest, raw encoding, direct material — the same
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
    /// a session-authorized command's cpHash Name term, since <c>TPMA_NV_WRITTEN</c> is part of the public area
    /// the Name digests (TPM 2.0 Library Part 1, clause 13, Table 9).
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

    /// <summary>Creates the RSA endorsement-key-shaped decrypt key (RESTRICTED+DECRYPT, SHA-256 nameAlg) used as a salted session's RSA tpmKey.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response.</returns>
    private async Task<CreatePrimaryResponse> CreateRsaDecryptKeyAsync(TpmDevice device, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput primaryInput = CreatePrimaryInput.ForRsaEndorsementKey(TpmRh.TPM_RH_OWNER, pool);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);

        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            device, primaryInput, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (RSA decrypt key) failed: '{result.ResponseCode}'.");

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
            .Register(TpmCcConstants.TPM_CC_NV_Extend, TpmResponseCodec.NvExtend)
            .Register(TpmCcConstants.TPM_CC_NV_SetBits, TpmResponseCodec.NvSetBits)
            .Register(TpmCcConstants.TPM_CC_GetCapability, TpmResponseCodec.GetCapability)
            .Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession)
            .Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

    /// <summary>Extends <see cref="CreateNvRegistry"/> with the CreatePrimary codec the salted-session test needs.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateSaltedSessionRegistry() =>
        CreateNvRegistry()
            .Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace()</c> for <paramref name="nvIndex"/> with <see cref="CorrectAuth"/> as the
    /// Index authValue, authorized by the (empty) owner authValue.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="attributes">The Index's TPMA_NV attributes.</param>
    /// <param name="dataSize">The declared data area size; defaults to the Bit Field width of eight octets.</param>
    /// <returns>The define-space result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes,
        ushort dataSize = BitFieldDataSize)
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

    /// <summary>Issues a password-authorized <c>TPM2_NV_SetBits()</c> against <paramref name="nvIndex"/> authorized by <paramref name="authHandle"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle (the Index itself, the owner hierarchy, or a mismatched value).</param>
    /// <param name="nvIndex">The Bit Field Index whose bits are SET.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="bits">The 64-bit value ORed into the Index.</param>
    /// <returns>The set-bits result.</returns>
    private async Task<TpmResult<NvSetBitsResponse>> SetBitsAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ulong bits)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var setBitsInput = new NvSetBitsInput(authHandle, nvIndex, bits);

        return await TpmCommandExecutor.ExecuteAsync<NvSetBitsResponse>(
            device, setBitsInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_NV_Read()</c> against <paramref name="nvIndex"/>, authorized by the Index authValue.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="suppliedAuth">The authValue supplied for the Index.</param>
    /// <param name="size">The number of octets to read.</param>
    /// <param name="offset">The octet offset the read starts at; zero reads the field from its most significant octet.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ushort size, ushort offset = 0)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: size, Offset: offset);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
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
    private static void AppendUInt16(List<byte> body, int value)
    {
        Span<byte> octets = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(octets, (ushort)value);
        body.AddRange(octets);
    }

    /// <summary>
    /// Appends a one-slot authorization area naming <c>TPM_RS_PW</c> with an empty nonce and an empty password —
    /// the password form of <c>TPMS_AUTH_COMMAND</c> (TPM 2.0 Library Part 1, clause 16.6.4.1) — which is enough
    /// for a parse-time proof, since the parse never evaluates the credential.
    /// </summary>
    /// <param name="body">The body being built.</param>
    private static void AppendPasswordAuthorizationArea(List<byte> body)
    {
        var area = new List<byte>();
        AppendUInt32(area, (uint)TpmRh.TPM_RH_PW);
        AppendUInt16(area, 0);
        area.Add((byte)TpmaSession.CONTINUE_SESSION);
        AppendUInt16(area, 0);

        AppendUInt32(body, (uint)area.Count);
        body.AddRange(area);
    }

    /// <summary>
    /// Creates a simulator, powers it on, and brings it through <c>TPM2_Startup(CLEAR)</c> into the
    /// operational phase. When <paramref name="withRsaBackend"/> is set, the simulator is also wired with the
    /// ECC (BouncyCastle) and RSA (framework) signing backends a salted HMAC session's RSA <c>tpmKey</c> needs
    /// from <c>TPM2_CreatePrimary()</c>.
    /// </summary>
    /// <param name="withRsaBackend">When <see langword="true"/>, wires the ECC and RSA signing backends; otherwise the simulator carries neither.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(bool withRsaBackend = false)
    {
        var simulator = withRsaBackend
            ? new TpmSimulator(
                "tpm-in-house-nv-setbits", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch))
            : new TpmSimulator("tpm-in-house-nv-setbits", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitSessionlessAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
