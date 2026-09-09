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
/// Drives the NV Extend Index machinery — <c>TPM2_NV_Extend()</c>'s authorization ladder on both arms over a
/// password and over an HMAC session, the <c>H_nameAlg(old ‖ data)</c> fold from the Zero Digest against the
/// framework's own hash as the oracle, the <c>TPM_NT_EXTEND</c> type gate on <c>TPM2_NV_Extend()</c>,
/// <c>TPM2_NV_Write()</c> and <c>TPM2_NV_Increment()</c>, <c>TPM2_NV_DefineSpace()</c>'s digest-width data size
/// rule, and the <c>TPMA_NV_CLEAR_STCLEAR</c> restart across a TPM Reset — against the in-house behavioural
/// <see cref="TpmSimulator"/>, entirely in-process with no external assets, through the same production command
/// path the production code uses (<see cref="TpmCommandExecutor"/> and the real command/response codecs). TPM
/// 2.0 Library Part 1, clause 34.2.6.5; Part 3, clauses 31.3.1, 31.7.1, 31.8.1, 31.9.
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorNvExtendTests
{
    /// <summary>The SHA-256 digest width in octets — the data size of every SHA-256 Extend Index this file defines.</summary>
    private const ushort Sha256DigestSize = 32;

    /// <summary>The SHA-384 digest width in octets — the data size of the SHA-384 Extend Index.</summary>
    private const ushort Sha384DigestSize = 48;

    /// <summary>The SHA-512 digest width in octets — the data size of the SHA-512 Extend Index.</summary>
    private const ushort Sha512DigestSize = 64;

    /// <summary>The declared data size of the Counter Index used to prove the type gate.</summary>
    private const ushort CounterDataSize = 8;

    /// <summary>The declared data size of the Ordinary Index used to prove the type gate.</summary>
    private const ushort OrdinaryDataSize = 16;

    /// <summary>The primary Extend Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint ExtendIndexHandle = 0x0100_0051;

    /// <summary>The SHA-384 Extend Index handle.</summary>
    private const uint Sha384ExtendIndexHandle = 0x0100_0053;

    /// <summary>The SHA-512 Extend Index handle.</summary>
    private const uint Sha512ExtendIndexHandle = 0x0100_0057;

    /// <summary>An Ordinary Index handle, used to prove <c>TPM2_NV_Extend()</c> refuses a non-Extend type.</summary>
    private const uint OrdinaryIndexHandle = 0x0100_0054;

    /// <summary>A Counter Index handle, used to prove <c>TPM2_NV_Extend()</c> refuses a non-Extend type.</summary>
    private const uint CounterIndexHandle = 0x0100_0055;

    /// <summary>An <c>authHandle</c> that is neither the owner hierarchy nor any Index defined in this file.</summary>
    private const uint MismatchedAuthHandle = 0x0100_0099;

    /// <summary>The lowered <c>maxTries</c> used by the lockout tests to reach Lockout mode quickly.</summary>
    private const uint LoweredMaxTries = 2;

    /// <summary>The hash algorithm for every HMAC-arm session these tests compose.</summary>
    private const TpmAlgIdConstants HmacSessionAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The RSA public exponent the framework RSA key generator uses (TPM 2.0 Library Part 2, Table 228).</summary>
    private const uint DefaultRsaExponent = 65537;

    /// <summary>The Name algorithm of the RSA endorsement-key-shaped decrypt key the salted-session test builds.</summary>
    private const TpmAlgIdConstants RsaKeyNameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>
    /// Extend attributes that authorize read/extend with the Index authValue and extend with owner
    /// authorization, dictionary-attack protected (<c>TPMA_NV_NO_DA</c> clear).
    /// </summary>
    private const TpmaNv ExtendAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_EXTEND << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The same Extend attributes, opted out of dictionary-attack protection.</summary>
    private const TpmaNv NonDaExtendAttributes = ExtendAttributes | TpmaNv.TPMA_NV_NO_DA;

    /// <summary>Extend attributes deliberately missing <c>TPMA_NV_OWNERWRITE</c>.</summary>
    private const TpmaNv ExtendWithoutOwnerWriteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_EXTEND << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Extend attributes deliberately missing <c>TPMA_NV_AUTHWRITE</c>.</summary>
    private const TpmaNv ExtendWithoutAuthWriteAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_OWNERWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_EXTEND << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>Extend attributes electing <c>TPMA_NV_CLEAR_STCLEAR</c>, so a TPM Reset CLEARs <c>TPMA_NV_WRITTEN</c>.</summary>
    private const TpmaNv ClearStclearExtendAttributes = ExtendAttributes | TpmaNv.TPMA_NV_CLEAR_STCLEAR;

    /// <summary>Extend attributes electing <c>TPMA_NV_ORDERLY</c>, so a TPM Reset CLEARs <c>TPMA_NV_WRITTEN</c> through the orderly rule alone.</summary>
    private const TpmaNv OrderlyExtendAttributes = ExtendAttributes | TpmaNv.TPMA_NV_ORDERLY;

    /// <summary>Ordinary Index attributes (TPM_NT_ORDINARY is the zero value, so no type shift is needed).</summary>
    private const TpmaNv OrdinaryAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE;

    /// <summary>Counter Index attributes, used to prove the type gate from the other side.</summary>
    private const TpmaNv CounterAttributes =
        TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE | TpmaNv.TPMA_NV_OWNERWRITE
        | (TpmaNv)((uint)TpmNt.TPM_NT_COUNTER << TpmaNvFields.TPM_NT_SHIFT);

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] CorrectAuth { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>A wrong Index authorization value, distinct from <see cref="CorrectAuth"/>.</summary>
    private static byte[] WrongAuth { get; } = [0x09, 0x09, 0x09, 0x09];

    /// <summary>Five octets of <c>data</c>, deliberately not the Index's size (clause 31.9.1's Note).</summary>
    private static byte[] FiveOctets { get; } = [0xA1, 0xA2, 0xA3, 0xA4, 0xA5];

    /// <summary>
    /// A single-octet payload for a rejected-arm <c>TPM2_NV_Write()</c> attempt; its content is immaterial
    /// since the write must never reach the Index's stored data.
    /// </summary>
    private static byte[] RejectedWriteAttempt { get; } = [0x00];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Verifies <c>TPM2_NV_Extend()</c> against an undefined handle answers <c>TPM_RC_HANDLE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9; clause 5.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfUndefinedIndexReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), result.ResponseCode, "Table 257: nvIndex is TPM2_NV_Extend()'s second handle (handle 2); an undefined Index is handle-encoded TPM_RC_HANDLE at index 1.");
    }

    /// <summary>
    /// "When an NV Extend Index is created, it has no value and the TPMA_NV_WRITTEN attribute will be CLEAR",
    /// so a read before the first extend answers <c>TPM_RC_NV_UNINITIALIZED</c> exactly as any other unwritten
    /// Index.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.5; Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvReadOfExtendIndexBeforeFirstExtendReturnsUninitialized()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        TpmResult<NvReadResponse> result = await ReadIndexAsync(device, pool, registry, ExtendIndexHandle, CorrectAuth, Sha256DigestSize).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, result.ResponseCode);
    }

    /// <summary>
    /// Equation (56): "nvIndex→data_new = nameAlg(nvIndex→data_old ‖ data.buffer)", with "If TPMA_NV_WRITTEN is
    /// CLEAR, then nvIndex→data_old is a Zero Digest" — the first extend of a fresh SHA-256 Index reads back
    /// as <c>SHA256(0³² ‖ data)</c> under the framework's own hash, and the extend SETs <c>TPMA_NV_WRITTEN</c>
    /// so the read succeeds at all.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.5, equation 56; Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfUnwrittenIndexReadsBackAsSha256OfZeroDigestAndData()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        byte[] data = RandomNumberGenerator.GetBytes(Sha256DigestSize);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, data).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Extend() failed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(new byte[Sha256DigestSize], data), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// Equation (56) with <c>TPMA_NV_WRITTEN</c> SET: the second extend folds over the stored value, so the
    /// Index reads back as <c>SHA256(SHA256(0³² ‖ data₁) ‖ data₂)</c> — the same chaining a PCR performs.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.5, equation 56; Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendTwiceChainsOverThePreviousValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        byte[] first = RandomNumberGenerator.GetBytes(Sha256DigestSize);
        byte[] second = RandomNumberGenerator.GetBytes(Sha256DigestSize);

        TpmResult<NvExtendResponse> firstResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, first).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The first TPM2_NV_Extend() failed: '{firstResult.ResponseCode}'.");

        TpmResult<NvExtendResponse> secondResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, second).ConfigureAwait(false);
        Assert.IsTrue(secondResult.IsSuccess, $"The second TPM2_NV_Extend() failed: '{secondResult.ResponseCode}'.");

        byte[] afterFirst = Sha256Extend(new byte[Sha256DigestSize], first);
        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(afterFirst, second), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// Clause 31.9.1's Note: "The data.buffer parameter does not have to be the defined size of the NV Index.
    /// It may be any size allowed by TPM2B_MAX_NV_BUFFER" — an empty <c>data</c> is admitted and the Index
    /// reads back as the digest of the Zero Digest alone.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendWithEmptyDataExtendsTheZeroDigestAlone()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Extend() with an empty data must succeed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(new byte[Sha256DigestSize], []), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// Clause 31.9.1's Note, the short side: five octets of <c>data</c> — shorter than the Index — fold in as
    /// they are, the digest input being <c>0³² ‖ data</c> with no padding.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendWithFiveOctetsOfDataReadsBackAsTheOracle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Extend() with five octets of data must succeed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(new byte[Sha256DigestSize], FiveOctets), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// Clause 31.9.1's Note, the long side: <c>data</c> exactly at the <c>TPM2B_MAX_NV_BUFFER</c> bound
    /// (Part 2, Table 97: <c>buffer[size]{:MAX_NV_BUFFER_SIZE}</c>, 2048 octets here) is admitted and folds in
    /// whole.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.1; Part 2, clause 10.3.9, Table 97</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendWithDataAtTheBufferBoundSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        byte[] data = RandomNumberGenerator.GetBytes(Tpm2bMaxNvBuffer.MaxSize);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, data).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Extend() with data at MAX_NV_BUFFER_SIZE must succeed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(new byte[Sha256DigestSize], data), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// A <c>data</c> whose declared size is one octet past <c>MAX_NV_BUFFER_SIZE</c> is refused at the wire
    /// read with <c>TPM_RC_SIZE</c> parameter-encoded to <c>data</c>, parameter 1 of Table 257 (the structure's
    /// own unmarshal answering it, Part 2, Table 97), ahead of any rental — proved by the metered pool's
    /// balance — so the command body's rules are never reached.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 10.3.9, Table 97; Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendRefusesDataWiderThanTheBufferBoundAtTheWireRead()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        //Handle area, a password authorization area, then data with a size field one octet past the bound.
        var body = new List<byte>();
        AppendUInt32(body, ExtendIndexHandle);
        AppendUInt32(body, ExtendIndexHandle);
        AppendPasswordAuthorizationArea(body);
        AppendUInt16(body, Tpm2bMaxNvBuffer.MaxSize + 1);
        body.AddRange(new byte[Tpm2bMaxNvBuffer.MaxSize + 1]);

        TpmRcConstants code = await SubmitFramedAsync(
            simulator, pool, TpmStConstants.TPM_ST_SESSIONS, TpmCcConstants.TPM_CC_NV_Extend, [.. body]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, parameterIndex: 0), code,
            "Table 257: data is TPM2_NV_Extend()'s sole parameter (index 0); a data parameter past MAX_NV_BUFFER_SIZE is refused at the wire read with TPM_RC_SIZE there.");
        Assert.AreEqual(
            baseline, trackingPool.OutstandingCount,
            "The bound is answered ahead of the rental, so a refused parse must rent nothing.");
    }

    /// <summary>
    /// "The extend will use the nameAlg of the Index" (Part 2, Table 247): a SHA-384 Extend Index, defined at
    /// the 48-octet width Part 3, clause 31.3.1 requires, reads back as <c>SHA384(0⁴⁸ ‖ data)</c> — the nameAlg
    /// drives both the Zero Digest's width and the hash.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.2, Table 247; Part 1, clause 34.2.6.5</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfSha384IndexReadsBackAsSha384OfZeroDigestAndData()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(
            device, pool, registry, Sha384ExtendIndexHandle, ExtendAttributes, Sha384DigestSize, TpmAlgIdConstants.TPM_ALG_SHA384).ConfigureAwait(false);
        byte[] data = RandomNumberGenerator.GetBytes(Sha384DigestSize);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, Sha384ExtendIndexHandle, Sha384ExtendIndexHandle, CorrectAuth, data).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Extend() of a SHA-384 Index failed: '{result.ResponseCode}'.");

        byte[] expected = SHA384.HashData([.. new byte[Sha384DigestSize], .. data]);
        await AssertReadsBackAsync(device, pool, registry, Sha384ExtendIndexHandle, expected, Sha384DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// "If nvIndexType is TPM_NT_EXTEND, then publicInfo→dataSize shall match the digest size of the
    /// publicInfo.nameAlg or the TPM shall return TPM_RC_SIZE" — a SHA-256 Extend Index declared at eight
    /// octets is refused with <c>TPM_RC_SIZE</c>, the corrected response the clause's Note names over the older
    /// reference code's <c>TPM_RC_ATTRIBUTES</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfExtendIndexWithMismatchedDataSizeReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, ExtendIndexHandle, ExtendAttributes, CounterDataSize).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), result.ResponseCode,
            "An Extend Index whose dataSize is not its nameAlg's digest width is TPM_RC_SIZE, not TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// The admitting half of the clause 31.3.1 size rule: a SHA-256 Extend Index declared at 32 octets
    /// defines successfully — <c>TPM_NT_EXTEND</c> is a supported type because <c>TPM2_NV_Extend()</c> is
    /// implemented, so the clause's unsupported-command gate does not fire.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfExtendIndexWithDigestSizedDataSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineIndexAsync(
            device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"A digest-sized Extend Index must define: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// The owner arm: "Proper write authorizations are required for this command as determined by ...
    /// TPMA_NV_OWNERWRITE" — an owner-authorized extend under the (empty) owner authValue succeeds and the
    /// Index reads back as the oracle under its own authValue.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.1; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendByOwnerAuthorizationSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ExtendIndexHandle, ReadOnlyMemory<byte>.Empty, FiveOctets).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized extend must succeed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(new byte[Sha256DigestSize], FiveOctets), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// The owner arm honours <c>TPMA_NV_OWNERWRITE</c> ahead of the compare: with the bit clear an
    /// owner-authorized extend is <c>TPM_RC_NV_AUTHORIZATION</c> under a correct AND under a wrong owner
    /// authValue alike, so no comparison outcome leaks through the refusal.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.4; Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendByOwnerWithoutOwnerWriteReturnsNvAuthorizationRegardlessOfTheSuppliedOwnerAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendWithoutOwnerWriteAttributes).ConfigureAwait(false);

        TpmResult<NvExtendResponse> correctResult = await ExtendAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ExtendIndexHandle, ReadOnlyMemory<byte>.Empty, FiveOctets).ConfigureAwait(false);
        TpmResult<NvExtendResponse> wrongResult = await ExtendAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ExtendIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, correctResult.ResponseCode, "With TPMA_NV_OWNERWRITE clear the owner cannot extend, even under the correct owner authValue.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, wrongResult.ResponseCode, "The same refusal under a wrong owner authValue, so the gate runs before the compare.");
    }

    /// <summary>
    /// A wrong owner authValue on the owner arm is a plain <c>TPM_RC_BAD_AUTH</c> that moves no counter: "the
    /// authValue associated with a permanent entity, other than TPM_RH_LOCKOUT, does not receive DA protection".
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendByOwnerWithWrongOwnerAuthReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ExtendIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 257 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong owner authValue is session-encoded TPM_RC_BAD_AUTH there.");
        Assert.AreEqual(counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong owner authValue must not move failedTries.");
    }

    /// <summary>
    /// "If authHandle is an NV Index, it must be the same as nvIndex (TPM_RC_NV_AUTHORIZATION)" — an
    /// <c>authHandle</c> that is neither the owner hierarchy nor the Index itself is refused with
    /// <c>TPM_RC_NV_AUTHORIZATION</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendWithMismatchedAuthHandleReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, MismatchedAuthHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// The Index arm honours <c>TPMA_NV_AUTHWRITE</c> ahead of the compare: with the bit clear the Index's own
    /// authValue is not an available mechanism for an extend at all, so a correct AND a wrong value are both
    /// refused with <c>TPM_RC_AUTH_UNAVAILABLE</c> (Part 3, clause 5.6's check 7.2.2 precedes its check 9/10
    /// value compare) and no comparison outcome leaks.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendWithoutAuthWriteReturnsAuthUnavailableForCorrectAndWrongValuesAlike()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendWithoutAuthWriteAttributes).ConfigureAwait(false);

        TpmResult<NvExtendResponse> correctResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        TpmResult<NvExtendResponse> wrongResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, correctResult.ResponseCode, "With TPMA_NV_AUTHWRITE clear the Index authValue cannot authorize an extend, even when it matches.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_UNAVAILABLE, wrongResult.ResponseCode, "The identical refusal for a wrong value, so the gate runs before the compare.");
    }

    /// <summary>
    /// A wrong Index authValue against a DA-protected Extend Index is an auth-failure that charges
    /// <c>failedTries</c>: "All uses of a DA protected authValue receive DA protection" — read back over
    /// <c>TPM_PT_LOCKOUT_COUNTER</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendWithWrongAuthOnDaProtectedIndexReturnsAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 257 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong authValue on a DA-protected Index is session-encoded TPM_RC_AUTH_FAIL there.");
        Assert.AreEqual(counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong DA-protected authValue must charge failedTries once.");
    }

    /// <summary>
    /// A wrong Index authValue against a <c>TPMA_NV_NO_DA</c> Extend Index is a plain bad-authorization that
    /// leaves <c>failedTries</c> untouched — <c>TPMA_NV_NO_DA</c> applies uniformly, with no type carve-out.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendWithWrongAuthOnNoDaIndexReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, NonDaExtendAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_BAD_AUTH, 0), result.ResponseCode, "authHandle's authorizing session is session 1 of Table 257 (TPM 2.0 Library Part 2, clause 6.6.2); a wrong authValue on a non-DA Index is session-encoded TPM_RC_BAD_AUTH there.");
        Assert.AreEqual(counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A NO_DA Index's wrong authValue must not move failedTries.");
    }

    /// <summary>
    /// Repeated wrong Index-arm extends against a DA-protected Extend Index reach Lockout mode exactly at the
    /// (lowered) <c>maxTries</c>, after which even the correct authValue is refused with
    /// <c>TPM_RC_LOCKOUT</c> before any compare — while the owner arm stays available, since the clause 5.6
    /// lockout gate binds the entity whose authValue is compared, and on that arm it is the DA-exempt owner
    /// hierarchy.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendBruteForceReachesLockoutAndTheOwnerArmStaysAvailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<NvExtendResponse> wrongResult = await ExtendAsync(
                device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);

            Assert.AreEqual(
                HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode,
                $"Attempt {attempt} of {LoweredMaxTries} must count as an auth-failure, not yet Lockout mode.");
        }

        TpmResult<NvExtendResponse> lockedResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_LOCKOUT, lockedResult.ResponseCode,
            "Once failedTries reaches maxTries, the Index arm must be refused with TPM_RC_LOCKOUT even with the correct authValue.");

        TpmResult<NvExtendResponse> ownerArmResult = await ExtendAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ExtendIndexHandle, ReadOnlyMemory<byte>.Empty, FiveOctets).ConfigureAwait(false);
        Assert.IsTrue(
            ownerArmResult.IsSuccess,
            $"The owner-authorized administrative arm must stay available during lockout: '{ownerArmResult.ResponseCode}'.");
    }

    /// <summary>
    /// "If nvIndexType is not TPM_NT_EXTEND, then the TPM shall return TPM_RC_ATTRIBUTES" — and the gate runs
    /// AFTER authorization (the reference's own <c>NvWriteAccessChecks</c> runs before <c>IsNvExtendIndex</c>):
    /// an Ordinary Index answers <c>TPM_RC_ATTRIBUTES</c> under its correct authValue and the auth-failure under
    /// a wrong one.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfOrdinaryIndexReturnsAttributesUnderCorrectAuthAndAuthFailUnderWrongAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, OrdinaryIndexHandle, OrdinaryAttributes, OrdinaryDataSize).ConfigureAwait(false);

        TpmResult<NvExtendResponse> correctResult = await ExtendAsync(
            device, pool, registry, OrdinaryIndexHandle, OrdinaryIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        TpmResult<NvExtendResponse> wrongResult = await ExtendAsync(
            device, pool, registry, OrdinaryIndexHandle, OrdinaryIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), correctResult.ResponseCode, "TPM2_NV_Extend() must refuse a non-Extend Index once authorization has succeeded.");
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode, "The authorization is checked before the type, so a wrong authValue answers the auth-failure, not TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// The type gate from the Counter side: a Counter Index is refused with <c>TPM_RC_ATTRIBUTES</c> — the four
    /// update commands partition the NV Index types (Part 1, clause 34.2.6.1) — and only after authorization,
    /// so a wrong authValue answers the auth-failure instead.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.1; Part 1, clause 34.2.6.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfCounterIndexReturnsAttributesUnderCorrectAuthAndAuthFailUnderWrongAuth()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, CounterIndexHandle, CounterAttributes, CounterDataSize).ConfigureAwait(false);

        TpmResult<NvExtendResponse> correctResult = await ExtendAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        TpmResult<NvExtendResponse> wrongResult = await ExtendAsync(
            device, pool, registry, CounterIndexHandle, CounterIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), correctResult.ResponseCode, "TPM2_NV_Extend() must refuse a Counter Index once authorization has succeeded.");
        Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode, "The authorization is checked before the type, so a wrong authValue answers the auth-failure, not TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// "If nvIndexType is TPM_NT_COUNTER, TPM_NT_BITS or TPM_NT_EXTEND, then the TPM shall return
    /// TPM_RC_ATTRIBUTES" — <c>TPM2_NV_Write()</c> refuses an Extend Index, so only the extend operation can
    /// ever modify its digest-sized value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.7.1; Part 1, clause 34.2.6.5</see>.
    /// </summary>
    [TestMethod]
    public async Task NvWriteOfExtendIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        TpmResult<NvWriteResponse> result = await WriteIndexAuthValueAsync(
            device, pool, registry, ExtendIndexHandle, CorrectAuth, RejectedWriteAttempt).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_ATTRIBUTES, result.ResponseCode,
            "TPM2_NV_Write() must refuse an Extend Index once authorization has already succeeded - only TPM2_NV_Extend() may modify it.");
    }

    /// <summary>
    /// "If nvIndexType is not TPM_NT_COUNTER ... the TPM shall return TPM_RC_ATTRIBUTES" — <c>TPM2_NV_Increment()</c>
    /// refuses an Extend Index.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvIncrementOfExtendIndexReturnsAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        using TpmPasswordSession session = TpmPasswordSession.Create(CorrectAuth, pool);
        var incrementInput = new NvIncrementInput(ExtendIndexHandle, ExtendIndexHandle);
        TpmResult<NvIncrementResponse> result = await TpmCommandExecutor.ExecuteAsync<NvIncrementResponse>(
            device, incrementInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode, "Table 255: nvIndex is TPM2_NV_Increment()'s second handle (handle 2); an Index whose type is not TPM_NT_COUNTER is handle-encoded TPM_RC_ATTRIBUTES at index 1.");
    }

    /// <summary>
    /// "After successful completion of this command, TPMA_NV_WRITTEN for the NV Index will be SET" — and the
    /// attribute is part of the public area the Name digests (Part 1, clause 13, Table 9), so the Index Name
    /// read back through <c>TPM2_NV_ReadPublic()</c> changes across the FIRST extend and not across the second.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.1; Part 1, clause 13, Table 9</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendChangesTheIndexNameOnTheFirstExtendOnly()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        byte[] nameBefore = await ReadIndexNameAsync(device, ExtendIndexHandle).ConfigureAwait(false);

        TpmResult<NvExtendResponse> firstResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The first TPM2_NV_Extend() failed: '{firstResult.ResponseCode}'.");
        byte[] nameAfterFirst = await ReadIndexNameAsync(device, ExtendIndexHandle).ConfigureAwait(false);

        TpmResult<NvExtendResponse> secondResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        Assert.IsTrue(secondResult.IsSuccess, $"The second TPM2_NV_Extend() failed: '{secondResult.ResponseCode}'.");
        byte[] nameAfterSecond = await ReadIndexNameAsync(device, ExtendIndexHandle).ConfigureAwait(false);

        Assert.IsFalse(nameBefore.AsSpan().SequenceEqual(nameAfterFirst), "The first extend SETs TPMA_NV_WRITTEN, which the Name digests, so the Name must change.");
        Assert.IsTrue(nameAfterFirst.AsSpan().SequenceEqual(nameAfterSecond), "The second extend changes only the data area, which the Name does not cover, so the Name must be stable.");
    }

    /// <summary>
    /// "Once SET, TPMA_NV_WRITTEN remains SET until the NV Index is undefined, unless the TPMA_NV_CLEAR_STCLEAR
    /// attribute is SET and a TPM Reset or TPM Restart occurs" — after <c>Shutdown(CLEAR)</c>/<c>Startup(CLEAR)</c>
    /// a CLEAR_STCLEAR Extend Index reads <c>TPM_RC_NV_UNINITIALIZED</c> again, and Part 1, clause 34.2.6.5's
    /// check is on the ATTRIBUTE: the next extend restarts from the Zero Digest rather than chaining over the
    /// octets the reserved area still holds.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.1; Part 1, clause 34.2.6.5; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfClearStclearIndexRestartsFromTheZeroDigestAfterATpmReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ClearStclearExtendAttributes).ConfigureAwait(false);
        byte[] first = RandomNumberGenerator.GetBytes(Sha256DigestSize);
        byte[] second = RandomNumberGenerator.GetBytes(Sha256DigestSize);

        TpmResult<NvExtendResponse> firstResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, first).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The extend before the Reset failed: '{firstResult.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<NvReadResponse> readAfterReset = await ReadIndexAsync(device, pool, registry, ExtendIndexHandle, CorrectAuth, Sha256DigestSize).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_UNINITIALIZED, readAfterReset.ResponseCode,
            "A TPM Reset must CLEAR TPMA_NV_WRITTEN on a CLEAR_STCLEAR Index, so the read must be refused.");

        TpmResult<NvExtendResponse> secondResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, second).ConfigureAwait(false);
        Assert.IsTrue(secondResult.IsSuccess, $"The extend after the Reset failed: '{secondResult.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(new byte[Sha256DigestSize], second), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// The Index arm over an unbound, unsalted HMAC session: the command HMAC verifies against a cpHash whose
    /// Name terms are the Index's Name AS THE COMMAND FOUND IT — the first extend SETs <c>TPMA_NV_WRITTEN</c>,
    /// so the Name the caller read before the command is the one cpHash must fold — and the Index reads back
    /// as the oracle.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15; clause 34.2.6.5; Part 3, clause 31.9</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverHmacSessionAtTheIndexArmSucceedsOnTheFirstExtend()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        byte[] data = RandomNumberGenerator.GetBytes(Sha256DigestSize);

        TpmResult<NvExtendResponse> result = await ExtendOverHmacAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, data).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Extend() over an HMAC session failed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(new byte[Sha256DigestSize], data), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// The owner arm over an HMAC session: cpHash's Name1 is the owner's raw handle (Part 1, Table 9: a
    /// permanent handle's Name IS its handle value) and Name2 the Index's computed Name; the empty owner
    /// authValue keys the HMAC alongside the empty session key.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 15.7, equation 15; clause 13, Table 9; Part 3, clause 31.9</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverHmacSessionAtTheOwnerArmSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendOverHmacAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ExtendIndexHandle, ReadOnlyMemory<byte>.Empty, FiveOctets).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"The owner-authorized extend over an HMAC session failed: '{result.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(new byte[Sha256DigestSize], FiveOctets), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// A wrong Index authValue proven over an HMAC session is the same auth-failure the password arm answers,
    /// session-encoded — the base error is <c>TPM_RC_AUTH_FAIL</c> and the raw wire code carries the session-index
    /// modifier (Part 2, clause 6.6.2) — and it charges <c>failedTries</c> exactly once, mechanism-blind.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clauses 16.8.1 and 16.8.3; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverHmacSessionWithWrongAuthReturnsSessionEncodedAuthFailAndChargesFailedTries()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendOverHmacAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.BaseError);
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, result.ResponseCode, "A command-HMAC mismatch names the offending session, so the raw wire code carries the session-index modifier.");
        Assert.AreEqual(counterBefore + 1u, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A wrong DA-protected authValue proven over a session must charge failedTries once.");
    }

    /// <summary>
    /// The stranger-authHandle answer survives on the HMAC arm exactly as on the password arm: an
    /// <c>authHandle</c> that is neither the owner hierarchy nor the Index itself is <c>TPM_RC_NV_AUTHORIZATION</c>
    /// (Part 3, clause 31.1), refused before any HMAC is evaluated.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverHmacSessionWithMismatchedAuthHandleReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendOverHmacAsync(
            device, pool, registry, MismatchedAuthHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// The owner arm over an HMAC session honours <c>TPMA_NV_OWNERWRITE</c> before any HMAC work: with the bit
    /// clear the extend is <c>TPM_RC_NV_AUTHORIZATION</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.4; Part 3, clause 31.9.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverHmacSessionByOwnerWithoutOwnerWriteReturnsNvAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendWithoutOwnerWriteAttributes).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendOverHmacAsync(
            device, pool, registry, (uint)TpmRh.TPM_RH_OWNER, ExtendIndexHandle, ReadOnlyMemory<byte>.Empty, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_AUTHORIZATION, result.ResponseCode);
    }

    /// <summary>
    /// The Index arm over an HMAC session honours <c>TPMA_NV_AUTHWRITE</c> before any HMAC work: with the bit
    /// clear the Index's own authValue is not an available mechanism, so the extend is
    /// <c>TPM_RC_AUTH_UNAVAILABLE</c> even under the correct value.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.1; Part 3, clause 5.6</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverHmacSessionWithoutAuthWriteReturnsAuthUnavailable()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendWithoutAuthWriteAttributes).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendOverHmacAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);

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
    public async Task NvExtendOverHmacSessionInLockoutModeReturnsLockout()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<DictionaryAttackParametersResponse> lowerResult = await device.DictionaryAttackParametersAsync(
            ReadOnlyMemory<byte>.Empty, LoweredMaxTries, TpmSimulatorState.DefaultRecoveryTimeSeconds,
            TpmSimulatorState.DefaultLockoutRecoverySeconds, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(lowerResult.IsSuccess, $"Lowering maxTries failed: '{lowerResult.ResponseCode}'.");

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        for(uint attempt = 1; attempt <= LoweredMaxTries; attempt++)
        {
            TpmResult<NvExtendResponse> wrongResult = await ExtendAsync(
                device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);
            Assert.AreEqual(HmacKeyHarness.SessionEncodedRc(TpmRcConstants.TPM_RC_AUTH_FAIL, 0), wrongResult.ResponseCode, $"Attempt {attempt} of {LoweredMaxTries} must count as an auth-failure while driving the TPM into Lockout mode.");
        }

        TpmResult<NvExtendResponse> lockedResult = await ExtendOverHmacAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_LOCKOUT, lockedResult.ResponseCode, "The Index arm over a session must be refused while the TPM is in Lockout mode, even with the correct authValue.");
    }

    /// <summary>
    /// A wrong authValue proven over an HMAC session against a <c>TPMA_NV_NO_DA</c> Extend Index is a plain
    /// bad-authorization, session-encoded, that leaves <c>failedTries</c> untouched.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.8.1; Part 2, clause 6.6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverHmacSessionWithWrongAuthOnNoDaIndexReturnsBadAuthUncharged()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, NonDaExtendAttributes).ConfigureAwait(false);
        uint counterBefore = await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false);

        TpmResult<NvExtendResponse> result = await ExtendOverHmacAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, WrongAuth, FiveOctets).ConfigureAwait(false);

        Assert.AreEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.BaseError);
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_BAD_AUTH, result.ResponseCode, "A command-HMAC mismatch names the offending session, so the raw wire code carries the session-index modifier.");
        Assert.AreEqual(counterBefore, await ReadLockoutCounterAsync(device, registry, pool).ConfigureAwait(false), "A NO_DA Index's wrong authValue must not move failedTries, whatever the mechanism.");
    }

    /// <summary>
    /// The <c>audit</c> attribute on the authorizing session is admitted and the command succeeds, extending the
    /// session's audit digest to <c>H(0…0 ‖ cpHash ‖ rpHash)</c> on its first use (TPM 2.0 Library Part 1, clause
    /// 17.1, equation 30) with the response echoing <c>audit</c> SET, <c>auditExclusive</c> SET and
    /// <c>auditReset</c> CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38) — proved by chaining cpHash/rpHash
    /// from the octets this test itself sent and read, then reading the session's digest back through
    /// <c>TPM2_GetSessionAuditDigest()</c> with the NULL signer.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 17.1; Part 2, clause 8.4, Table 38</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverSessionWithAuditAttributeSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_GetSessionAuditDigest, TpmResponseCodec.GetSessionAuditDigest);

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        (byte[] response, uint sessionHandle, byte[] cpHash) = await ExtendOverHmacHandFramedForAuditAsync(
            device, pool, registry, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        try
        {
            var responseReader = new TpmReader(response);
            TpmRcConstants rawAuditCode = (TpmRcConstants)TpmHeader.Parse(ref responseReader).Code;
            Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, rawAuditCode, "An audit-attributed session over an audited command succeeds (TPM 2.0 Library Part 1, clause 17.1).");

            byte auditedAttributes = ReadResponseSessionAttributes(response, outHandleCount: 0, sessionIndex: 0);
            Assert.AreEqual(
                (byte)(TpmaSession.CONTINUE_SESSION | TpmaSession.AUDIT | TpmaSession.AUDIT_EXCLUSIVE), auditedAttributes,
                "The response echoes audit SET and auditExclusive SET (the session's first use as an audit session), with auditReset CLEAR (TPM 2.0 Library Part 2, clause 8.4, Table 38).");

            byte[] responseParameters = ReadResponseParameters(response, outHandleCount: 0);
            byte[] rpHash = await ComputeRpHashAsync(TpmCcConstants.TPM_CC_NV_Extend, responseParameters, pool).ConfigureAwait(false);
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
                "The session's audit digest must equal H(0…0 ‖ cpHash ‖ rpHash) chained from the NV_Extend exchange's own wire octets (TPM 2.0 Library Part 1, clause 17.1, equation 30).");
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// "If nvIndexType is TPM_NT_EXTEND, then publicInfo→dataSize shall match the digest size of the
    /// publicInfo.nameAlg or the TPM shall return TPM_RC_SIZE" — the same rule over the HMAC-session arm of
    /// <c>TPM2_NV_DefineSpace()</c>: a SHA-256 Extend Index declared at eight octets is <c>TPM_RC_SIZE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfExtendIndexOverHmacSessionWithMismatchedDataSizeReturnsSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> result = await DefineOverSessionAsync(
            device, pool, registry, ExtendIndexHandle, ExtendAttributes, CounterDataSize).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 1), result.ResponseCode, "The session arm applies the same digest-width rule as the password arm.");
    }

    /// <summary>
    /// The admitting half of the clause 31.3.1 size rule over the HMAC-session arm of
    /// <c>TPM2_NV_DefineSpace()</c>: a SHA-256 Extend Index declared at 32 octets defines, and the Index then
    /// extends and reads back as the oracle.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.3.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceOfExtendIndexOverHmacSessionWithDigestSizedDataSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> defineResult = await DefineOverSessionAsync(
            device, pool, registry, ExtendIndexHandle, ExtendAttributes, Sha256DigestSize).ConfigureAwait(false);
        Assert.IsTrue(defineResult.IsSuccess, $"A digest-sized Extend Index must define over a session: '{defineResult.ResponseCode}'.");

        TpmResult<NvExtendResponse> extendResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        Assert.IsTrue(extendResult.IsSuccess, $"TPM2_NV_Extend() failed: '{extendResult.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(new byte[Sha256DigestSize], FiveOctets), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// "The extend will use the nameAlg of the Index" at the widest admitted width: a SHA-512 Extend Index,
    /// defined at the 64-octet width clause 31.3.1 requires, reads back as <c>SHA512(0⁶⁴ ‖ data)</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 13.2, Table 247; Part 1, clause 34.2.6.5</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfSha512IndexReadsBackAsSha512OfZeroDigestAndData()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(
            device, pool, registry, Sha512ExtendIndexHandle, ExtendAttributes, Sha512DigestSize, TpmAlgIdConstants.TPM_ALG_SHA512).ConfigureAwait(false);
        byte[] data = RandomNumberGenerator.GetBytes(Sha512DigestSize);

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, Sha512ExtendIndexHandle, Sha512ExtendIndexHandle, CorrectAuth, data).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Extend() of a SHA-512 Index failed: '{result.ResponseCode}'.");

        byte[] expected = SHA512.HashData([.. new byte[Sha512DigestSize], .. data]);
        await AssertReadsBackAsync(device, pool, registry, Sha512ExtendIndexHandle, expected, Sha512DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// "If TPMA_NV_ORDERLY is SET, the RAM version of the Index is updated but it is not written to NV ... on
    /// TPM Reset, the TPMA_NV_WRITTEN attribute of the Index will be CLEAR" — the orderly rule alone, without
    /// <c>TPMA_NV_CLEAR_STCLEAR</c>: after <c>Shutdown(CLEAR)</c>/<c>Startup(CLEAR)</c> an ORDERLY Extend Index
    /// reads <c>TPM_RC_NV_UNINITIALIZED</c> and the next extend restarts from the Zero Digest. This is the
    /// "NV Index as a PCR" shape the clause names.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 34.2.6.5; Part 2, clause 13.4</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOfOrderlyIndexRestartsFromTheZeroDigestAfterATpmReset()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, OrderlyExtendAttributes).ConfigureAwait(false);
        byte[] first = RandomNumberGenerator.GetBytes(Sha256DigestSize);
        byte[] second = RandomNumberGenerator.GetBytes(Sha256DigestSize);

        TpmResult<NvExtendResponse> firstResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, first).ConfigureAwait(false);
        Assert.IsTrue(firstResult.IsSuccess, $"The extend before the Reset failed: '{firstResult.ResponseCode}'.");

        await PowerCycleAsync(simulator, pool, TpmSuConstants.TPM_SU_CLEAR, TpmSuConstants.TPM_SU_CLEAR).ConfigureAwait(false);

        TpmResult<NvReadResponse> readAfterReset = await ReadIndexAsync(device, pool, registry, ExtendIndexHandle, CorrectAuth, Sha256DigestSize).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_NV_UNINITIALIZED, readAfterReset.ResponseCode,
            "A TPM Reset must CLEAR TPMA_NV_WRITTEN on an ORDERLY Index, so the read must be refused.");

        TpmResult<NvExtendResponse> secondResult = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, second).ConfigureAwait(false);
        Assert.IsTrue(secondResult.IsSuccess, $"The extend after the Reset failed: '{secondResult.ResponseCode}'.");

        await AssertReadsBackAsync(device, pool, registry, ExtendIndexHandle, Sha256Extend(new byte[Sha256DigestSize], second), Sha256DigestSize).ConfigureAwait(false);
    }

    /// <summary>
    /// The password form returns its <c>data</c> carrier on every path that holds one: a refusal at the
    /// existence gate (before authorization), a refusal at the type gate (after authorization), and a success
    /// whose carrier transfers onto the digest effect — the metered pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendReturnsItsDataCarrierAcrossRefusalsAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        await DefineIndexAsync(device, pool, registry, OrdinaryIndexHandle, OrdinaryAttributes, OrdinaryDataSize).ConfigureAwait(false);

        long baseline = trackingPool.OutstandingCount;

        TpmResult<NvExtendResponse> undefinedResult = await ExtendAsync(
            device, pool, registry, Sha384ExtendIndexHandle, Sha384ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_HANDLE, 1), undefinedResult.ResponseCode, "Table 257: nvIndex is TPM2_NV_Extend()'s second handle (handle 2); an undefined Index is handle-encoded TPM_RC_HANDLE at index 1.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal before authorization releases the data carrier through the request's own Dispose.");

        TpmResult<NvExtendResponse> ordinaryResult = await ExtendAsync(
            device, pool, registry, OrdinaryIndexHandle, OrdinaryIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        Assert.AreEqual(HmacKeyHarness.HandleEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), ordinaryResult.ResponseCode, "Table 257: nvIndex is TPM2_NV_Extend()'s second handle (handle 2); an Index whose type is not TPM_NT_EXTEND is handle-encoded TPM_RC_ATTRIBUTES at index 1.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A refusal after authorization releases the data carrier through the request's own Dispose.");

        TpmResult<NvExtendResponse> result = await ExtendAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Extend() failed: '{result.ResponseCode}'.");
        Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The digest effect is the transferred data carrier's terminal owner and must release it.");
    }

    /// <summary>
    /// The HMAC-session form returns every carrier its parse rented — the data, the raw parameter area, the slot
    /// credentials and the computed Index Name — across a refusal at the command HMAC and a success: the metered
    /// pool returns to its baseline after each.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9; Part 1, clause 15.7</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverHmacSessionReturnsItsCarriersAcrossARefusalAndASuccess()
    {
        using var trackingPool = new MeteredHousePool();
        BaseMemoryPool pool = trackingPool.Pool;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, ExtendIndexHandle).ConfigureAwait(false);
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
                    using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(FiveOctets, pool);
                    var input = new NvExtendInput(ExtendIndexHandle, ExtendIndexHandle, buffer);
                    TpmResult<NvExtendResponse> refused = await TpmCommandExecutor.ExecuteAsync<NvExtendResponse>(
                        device, input, [wrongSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.AreEqual(TpmRcConstants.TPM_RC_AUTH_FAIL, refused.BaseError);
                }

                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "A command refused at its command HMAC releases every carrier its parse rented, the data included.");

                {
                    using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(FiveOctets, pool);
                    var input = new NvExtendInput(ExtendIndexHandle, ExtendIndexHandle, buffer);
                    TpmResult<NvExtendResponse> result = await TpmCommandExecutor.ExecuteAsync<NvExtendResponse>(
                        device, input, [correctSession], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
                    Assert.IsTrue(result.IsSuccess, $"TPM2_NV_Extend() over an HMAC session failed: '{result.ResponseCode}'.");
                }

                Assert.AreEqual(baseline, trackingPool.OutstandingCount, "The accepting continuation, the digest effect and the response framing between them release every carrier.");
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
    /// The SIMULATOR-side proof that <c>data</c> parameter encryption is closed: a hand-framed command whose
    /// authorizing session claims <c>decrypt</c> is refused with <c>TPM_RC_ATTRIBUTES</c> naming the session,
    /// while the identical session without the attribute succeeds. The closure is deliberate — <c>data</c> IS
    /// a sized first parameter Part 1, clause 18.1 makes decrypt-eligible, and the NV family keeps it closed on
    /// both the host and the simulator so the two sides agree.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.7; Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverSessionWithDecryptAttributeReturnsAttributesWhileTheSameSessionWithoutItSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        TpmRcConstants rawDecryptCode = await ExtendOverHmacHandFramedAsync(
            device, pool, registry, ExtendIndexHandle, CorrectAuth, FiveOctets, TpmaSession.DECRYPT).ConfigureAwait(false);
        TpmResult<NvExtendResponse> decryptResult = TpmResult<NvExtendResponse>.TpmError(rawDecryptCode);
        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, decryptResult.BaseError, "The simulator must fail a decrypt-attributed session closed rather than silently ignoring it.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, decryptResult.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<NvExtendResponse> declinedResult = await ExtendOverHmacAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        Assert.IsTrue(declinedResult.IsSuccess, $"The identical authValue over an otherwise identical session with decrypt left CLEAR must succeed: '{declinedResult.ResponseCode}'.");
    }

    /// <summary>
    /// The encrypt-attributed half: Table 258 gives <c>TPM2_NV_Extend()</c> no response parameter, so an
    /// <c>encrypt</c>-attributed session names an operation with nothing to act on and fails closed with
    /// <c>TPM_RC_ATTRIBUTES</c> (Part 3, clause 5.7), proven the same hand-framed way alongside the declined case.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.7; clause 31.9.2, Table 258</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverSessionWithEncryptAttributeReturnsAttributesWhileTheSameSessionWithoutItSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        TpmRcConstants rawEncryptCode = await ExtendOverHmacHandFramedAsync(
            device, pool, registry, ExtendIndexHandle, CorrectAuth, FiveOctets, TpmaSession.ENCRYPT).ConfigureAwait(false);
        TpmResult<NvExtendResponse> encryptResult = TpmResult<NvExtendResponse>.TpmError(rawEncryptCode);
        Assert.AreEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, encryptResult.BaseError, "TPM2_NV_Extend() has no response parameter, so the simulator must fail an encrypt-attributed session closed.");
        Assert.AreNotEqual(TpmRcConstants.TPM_RC_ATTRIBUTES, encryptResult.ResponseCode, "The refusal names the offending session, so the raw wire code carries the session-index modifier (TPM 2.0 Library Part 2, clause 6.6.2).");

        TpmResult<NvExtendResponse> declinedResult = await ExtendOverHmacAsync(
            device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets).ConfigureAwait(false);
        Assert.IsTrue(declinedResult.IsSuccess, $"The identical authValue over an otherwise identical session with encrypt left CLEAR must succeed: '{declinedResult.ResponseCode}'.");
    }

    /// <summary>
    /// The client-side companion (decrypt half): the SAME decrypt-attributed session routed through the
    /// production <see cref="TpmCommandExecutor"/> never reaches the wire — the executor's own admissibility
    /// guard refuses it with <see cref="ArgumentException"/>, because <c>NvExtendInput</c> declares no
    /// encryptable first command parameter, so the host and the simulator agree.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 18.1</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverSessionWithDecryptAttributeIsRefusedByTheClientSideGuardBeforeReachingTheSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await ExtendOverHmacAsync(
                device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets, TpmaSession.DECRYPT).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>
    /// The client-side companion (encrypt half): the executor refuses an encrypt-attributed session with
    /// <see cref="ArgumentException"/> before any bytes reach the wire, because the registered <c>NvExtend</c>
    /// codec declares no encryptable first response parameter.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 31.9.2, Table 258</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverSessionWithEncryptAttributeIsRefusedByTheClientSideGuardBeforeReachingTheSimulator()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);

        await Assert.ThrowsExactlyAsync<ArgumentException>(async () =>
            await ExtendOverHmacAsync(
                device, pool, registry, ExtendIndexHandle, ExtendIndexHandle, CorrectAuth, FiveOctets, TpmaSession.ENCRYPT).ConfigureAwait(false)).ConfigureAwait(false);
    }

    /// <summary>
    /// A SALTED HMAC session BOUND to the Extend Index itself: the Index's own authValue already feeds the
    /// session key's KDFa (equation 20), so the per-command HMAC key omits the authValue term when the session
    /// authorizes that SAME bound entity (equation 22) — the extend succeeds even though the composing session
    /// never calls <c>SetAuthValue</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 1, clause 16.6.10, equations 20 and 22</see>.
    /// </summary>
    [TestMethod]
    public async Task NvExtendOverIndexBoundAndSaltedSessionForTheBoundEntityOmitsAuthValueAndSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(withRsaBackend: true).ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = CreateSaltedSessionRegistry();

        await DefineIndexAsync(device, pool, registry, ExtendIndexHandle, ExtendAttributes).ConfigureAwait(false);
        using CreatePrimaryResponse tpmKey = await CreateRsaDecryptKeyAsync(device, registry, pool).ConfigureAwait(false);
        uint tpmKeyHandle = tpmKey.ObjectHandle.Value;

        ReadOnlyMemory<byte> modulus = tpmKey.OutPublic.PublicArea.Unique.GetRsaModulus().ToArray();
        TpmRsaSigningBackend rsaBackend = MicrosoftTpmRsaSigningBackend.Create();

        (StartAuthSessionInput Input, IMemoryOwner<byte> Salt, int SaltLength) salted = await StartAuthSessionInput.CreateBoundAndSaltedHmacSession(
            tpmKeyHandle, ExtendIndexHandle, modulus, DefaultRsaExponent, RsaKeyNameAlg, HmacSessionAlg, rsaBackend.EncryptOaep, TestEntropy.NewCounterStream(), pool, TestContext.CancellationToken).ConfigureAwait(false);

        try
        {
            TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
                device, salted.Input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(startResult.IsSuccess, $"StartAuthSession (bound-to-Index, salted) failed: '{startResult.ResponseCode}'.");

            StartAuthSessionResponse started = startResult.Value;
            uint sessionHandle = started.SessionHandle.Value;

            try
            {
                //Bound to ExtendIndexHandle itself with CorrectAuth as the bind entity's own authValue: the
                //session key already carries it (equation 20), so SetAuthValue is deliberately never called.
                using TpmSession session = await TpmSession.CreateBoundAsync(
                    new TpmHandle(sessionHandle), CorrectAuth, salted.Input.NonceCaller, started.NonceTPM,
                    HmacSessionAlg, TestEntropy.NewCounterStream(), pool, salt: salted.Salt.Memory[..salted.SaltLength], cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

                ReadOnlyMemory<byte> indexName = await ReadIndexNameAsync(device, ExtendIndexHandle).ConfigureAwait(false);
                ReadOnlyMemory<byte>[] handleNames = [indexName, indexName];

                using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(FiveOctets, pool);
                var extendInput = new NvExtendInput(ExtendIndexHandle, ExtendIndexHandle, buffer);

                TpmResult<NvExtendResponse> result = await TpmCommandExecutor.ExecuteAsync<NvExtendResponse>(
                    device, extendInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

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
    /// The independent extend oracle: <c>SHA256(previous ‖ data)</c> under the framework's own hash, never the
    /// simulator's digest seam.
    /// </summary>
    /// <param name="previous">The Index's value before the extend — the Zero Digest for an unwritten Index.</param>
    /// <param name="data">The command's <c>data</c>.</param>
    /// <returns>The expected value after the extend.</returns>
    private static byte[] Sha256Extend(ReadOnlySpan<byte> previous, ReadOnlySpan<byte> data) =>
        SHA256.HashData([.. previous, .. data]);

    /// <summary>
    /// Reads the Index's whole data area under its own authValue and asserts it equals
    /// <paramref name="expected"/> octet for octet.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Extend Index to read.</param>
    /// <param name="expected">The value the oracle predicts.</param>
    /// <param name="dataSize">The Index's declared data size — the read window.</param>
    private async Task AssertReadsBackAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, byte[] expected, ushort dataSize)
    {
        TpmResult<NvReadResponse> readResult = await ReadIndexAsync(device, pool, registry, nvIndex, CorrectAuth, dataSize).ConfigureAwait(false);
        Assert.IsTrue(readResult.IsSuccess, $"The read-back failed: '{readResult.ResponseCode}'.");

        using NvReadResponse read = readResult.Value;
        Assert.AreEqual(dataSize, read.Data.Length, "The Index holds exactly one digest of its nameAlg's width.");
        Assert.IsTrue(expected.AsSpan().SequenceEqual(read.Data), "The Index must read back as H_nameAlg(old || data) under the framework's own hash.");
    }

    /// <summary>
    /// Shared by this file's HMAC-arm tests: issues <c>TPM2_NV_Extend()</c> against <paramref name="nvIndex"/>
    /// over an UNBOUND, unsalted HMAC session (TPM 2.0 Library Part 1, clause 16.6.9) whose authValue is
    /// <paramref name="suppliedAuth"/>, on the Index arm (cpHash Names <c>[indexName, indexName]</c>) or the
    /// owner arm (<c>[ownerHandle, indexName]</c>), optionally carrying <paramref name="extraSessionAttributes"/>
    /// for the parameter-encryption tests.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorizing handle: the Index itself or <c>TPM_RH_OWNER</c>.</param>
    /// <param name="nvIndex">The Extend Index to extend.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="data">The octets to extend.</param>
    /// <param name="extraSessionAttributes">Additional <c>TPMA_SESSION</c> bits to set on the composed session.</param>
    /// <returns>The extend result.</returns>
    private async Task<TpmResult<NvExtendResponse>> ExtendOverHmacAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth,
        ReadOnlyMemory<byte> data, TpmaSession extraSessionAttributes = default)
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

            using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
            var extendInput = new NvExtendInput(authHandle, nvIndex, buffer);

            return await TpmCommandExecutor.ExecuteAsync<NvExtendResponse>(
                device, extendInput, [session], handleNames, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, FlushContextInput.ForHandle(sessionHandle), [], null, pool, registry, CancellationToken.None).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// The SIMULATOR-side proof for the parameter-encryption fail-closed gate: hand-frames a raw
    /// <c>TPM2_NV_Extend()</c> authorized by a single unbound, unsalted HMAC session whose
    /// <c>sessionAttributes</c> octet carries <paramref name="attribute"/>, and submits it directly to the
    /// transport — bypassing <see cref="TpmCommandExecutor"/>, whose own client-side guard would refuse this
    /// composition before any bytes reach the wire. The cpHash and command HMAC are the SAME production
    /// computation <see cref="TpmSession"/> performs for every other session-authorized test in this file;
    /// unlike <c>TPM2_NV_Increment()</c>'s, this command's cpHash carries a parameters term — the
    /// <c>TPM2B_MAX_NV_BUFFER</c> <c>data</c> exactly as marshaled (Part 1, clause 15.7, equation 15).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own StartAuthSession/FlushContext lifecycle).</param>
    /// <param name="nvIndex">The Extend Index to extend; also the authorizing handle.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="data">The octets to extend.</param>
    /// <param name="attribute">The <c>TPMA_SESSION</c> bit under test: <see cref="TpmaSession.DECRYPT"/> or <see cref="TpmaSession.ENCRYPT"/>.</param>
    /// <returns>The raw wire response code, still carrying any session-index encoding.</returns>
    private async Task<TpmRcConstants> ExtendOverHmacHandFramedAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> data, TpmaSession attribute)
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

            //cpHash = H_SHA256(commandCode || Name(authHandle) || Name(nvIndex) || data) — TPM 2.0 Library Part 1,
            //clause 15.7, equation 15, the parameters term being the marshaled TPM2B_MAX_NV_BUFFER (size then
            //octets). This arm's authHandle and nvIndex are the same Index, so both Name terms are identical.
            int parametersLength = sizeof(ushort) + data.Length;
            int cpHashInputLength = sizeof(uint) + indexName.Length + indexName.Length + parametersLength;
            using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
            Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
            {
                var cpHashWriter = new TpmWriter(cpHashInput.Span);
                cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_Extend);
                cpHashWriter.WriteBytes(indexName.Span);
                cpHashWriter.WriteBytes(indexName.Span);
                cpHashWriter.WriteTpm2b(data.Span);
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
            writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_Extend);
            writer.WriteUInt32(nvIndex);
            writer.WriteUInt32(nvIndex);
            writer.WriteUInt32((uint)session.GetAuthCommandSize());
            session.WriteAuthCommand(ref writer, hmac);
            writer.WriteTpm2b(data.Span);

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
    /// The audit twin of <see cref="ExtendOverHmacHandFramedAsync"/>: hand-frames a raw <c>TPM2_NV_Extend()</c>
    /// authorized by a single unbound, unsalted HMAC session carrying <c>audit ‖ continueSession</c>, submits it
    /// directly to the transport, and returns the raw response octets, the session handle and the independently
    /// computed cpHash WITHOUT flushing the session — the caller keeps it loaded to read its audit digest back
    /// through <c>TPM2_GetSessionAuditDigest()</c>. The cpHash is the SAME independent computation
    /// <see cref="ExtendOverHmacHandFramedAsync"/> performs (TPM 2.0 Library Part 1, clause 15.7, equation 15).
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry (used only for the session's own StartAuthSession lifecycle).</param>
    /// <param name="nvIndex">The Extend Index to extend; also the authorizing handle.</param>
    /// <param name="suppliedAuth">The authorization value proven by the HMAC session.</param>
    /// <param name="data">The octets to extend.</param>
    /// <returns>The raw response octets, the session handle (unflushed) and cpHash.</returns>
    private async Task<(byte[] Response, uint SessionHandle, byte[] CpHash)> ExtendOverHmacHandFramedForAuditAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> data)
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

        int parametersLength = sizeof(ushort) + data.Length;
        int cpHashInputLength = sizeof(uint) + indexName.Length + indexName.Length + parametersLength;
        using IMemoryOwner<byte> cpHashInputOwner = pool.Rent(cpHashInputLength);
        Memory<byte> cpHashInput = cpHashInputOwner.Memory[..cpHashInputLength];
        {
            var cpHashWriter = new TpmWriter(cpHashInput.Span);
            cpHashWriter.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_Extend);
            cpHashWriter.WriteBytes(indexName.Span);
            cpHashWriter.WriteBytes(indexName.Span);
            cpHashWriter.WriteTpm2b(data.Span);
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
        writer.WriteUInt32((uint)TpmCcConstants.TPM_CC_NV_Extend);
        writer.WriteUInt32(nvIndex);
        writer.WriteUInt32(nvIndex);
        writer.WriteUInt32((uint)session.GetAuthCommandSize());
        session.WriteAuthCommand(ref writer, hmac);
        writer.WriteTpm2b(data.Span);

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
    /// <see cref="ExtendOverHmacHandFramedAsync"/>: SHA-256 digest, raw encoding, direct material — the same
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
    /// <param name="dataSize">The declared data area size; defaults to the SHA-256 digest width.</param>
    /// <param name="nameAlg">The Index's nameAlg; defaults to SHA-256.</param>
    /// <returns>The define-space result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> DefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmaNv attributes,
        ushort dataSize = Sha256DigestSize, TpmAlgIdConstants nameAlg = TpmAlgIdConstants.TPM_ALG_SHA256)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);

        //The input takes ownership of the auth value and public area and disposes them; the redundant using
        //locals satisfy CA2000 and are safe because both types have idempotent disposal.
        using var auth = Tpm2bAuth.Create(CorrectAuth, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, nameAlg, attributes, Tpm2bDigest.Empty, dataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues a password-authorized <c>TPM2_NV_Extend()</c> against <paramref name="nvIndex"/> authorized by <paramref name="authHandle"/>.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="authHandle">The authorization handle (the Index itself, the owner hierarchy, or a mismatched value).</param>
    /// <param name="nvIndex">The Extend Index to extend.</param>
    /// <param name="suppliedAuth">The authorization value supplied for <paramref name="authHandle"/>.</param>
    /// <param name="data">The octets to extend.</param>
    /// <returns>The extend result.</returns>
    private async Task<TpmResult<NvExtendResponse>> ExtendAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint authHandle, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer buffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var extendInput = new NvExtendInput(authHandle, nvIndex, buffer);

        return await TpmCommandExecutor.ExecuteAsync<NvExtendResponse>(
            device, extendInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Issues <c>TPM2_NV_Read()</c> against <paramref name="nvIndex"/> for its whole data area, authorized by the Index authValue.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to read.</param>
    /// <param name="suppliedAuth">The authValue supplied for the Index.</param>
    /// <param name="size">The number of octets to read — the Index's declared data size.</param>
    /// <returns>The read result; on success, the caller owns and must dispose <see cref="TpmResult{T}.Value"/>.</returns>
    private async Task<TpmResult<NvReadResponse>> ReadIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ushort size)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        var readInput = new NvReadInput(AuthHandle: nvIndex, NvIndex: nvIndex, Size: size, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Issues an index-authValue <c>TPM2_NV_Write()</c> against <paramref name="nvIndex"/>, used only to
    /// exercise the Extend-type rejection: the write must never reach the Index's stored data.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index to write.</param>
    /// <param name="suppliedAuth">The authValue supplied for the Index.</param>
    /// <param name="data">The octets to attempt to write.</param>
    /// <returns>The write result.</returns>
    private async Task<TpmResult<NvWriteResponse>> WriteIndexAuthValueAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> suppliedAuth, ReadOnlyMemory<byte> data)
    {
        using TpmPasswordSession session = TpmPasswordSession.Create(suppliedAuth.Span, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(data.Span, pool);
        var writeInput = new NvWriteInput(nvIndex, nvIndex, writeInputBuffer, Offset: 0);

        return await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [session], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
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
                "tpm-in-house-nv-extend", signingBackend: BouncyCastleTpmEccSigningBackend.Create(), rsaSigningBackend: MicrosoftTpmRsaSigningBackend.Create(), rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch))
            : new TpmSimulator("tpm-in-house-nv-extend", rng: TestEntropy.NewCounterStream(), timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch));
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(
            TpmRcConstants.TPM_RC_SUCCESS,
            await SubmitSessionlessAsync(simulator, BaseMemoryPool.Shared, new StartupInput(TpmSuConstants.TPM_SU_CLEAR)).ConfigureAwait(false),
            "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
