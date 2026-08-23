using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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
/// Drives <c>TPM2_NV_ReadPublic()</c> (TPM 2.0 Library Part 3, Section 31.6) against the in-house behavioural
/// <see cref="TpmSimulator"/> - entirely in-process, with no external assets - through the same production
/// command path production code uses (<see cref="TpmCommandExecutor"/> and
/// <see cref="TpmDeviceExtensions.NvReadPublicAsync(uint, System.Threading.CancellationToken)"/>).
/// </summary>
/// <remarks>
/// <para>
/// Every accepted-path test pins the returned Name against an INDEPENDENT in-test transcription of TPM 2.0
/// Library Part 1, Section 14, Table 6's recipe (<c>nameAlg ‖ H_nameAlg(TPMS_NV_PUBLIC)</c>, marshaled per Part
/// 2, Section 13.6, Table 235) - built here from <see cref="BinaryPrimitives"/> and the project's own registered
/// digest seam, never by calling <c>TpmObjectName</c> or any other production Name-computation type, so a bug
/// shared between the production recipe and this test's own oracle cannot pass silently.
/// </para>
/// <para>
/// The transcription uses a NON-EMPTY <c>authPolicy</c>: <c>TPMS_NV_PUBLIC.authPolicy</c> together with
/// <c>nameAlg</c> is retained on the Index's own state and folded into every Name computation this simulator
/// performs; an oracle built with an empty policy would pass even if that retention were silently broken back
/// into a hardcoded empty digest, since <c>Tpm2bDigest.Empty</c> looks identical either way.
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorNvReadPublicTests
{
    /// <summary>The Name hash algorithm used throughout.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width, in octets.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>An ordinary NV Index handle: its most-significant octet is TPM_HT_NV_INDEX (0x01).</summary>
    private const uint OrdinaryIndexHandle = 0x0100_0091;

    /// <summary>The declared data area size, in octets, of every Index this file defines.</summary>
    private const ushort OrdinaryIndexDataSize = 16;

    /// <summary>Ordinary (TPM_NT_ORDINARY, the zero index-type field) attributes: index-authValue read and write.</summary>
    private const TpmaNv OrdinaryAttributes = TpmaNv.TPMA_NV_AUTHREAD | TpmaNv.TPMA_NV_AUTHWRITE;

    /// <summary>The Index authorization value used throughout.</summary>
    private static byte[] IndexAuthValue { get; } = [0x01, 0x02, 0x03, 0x04];

    /// <summary>
    /// A non-empty, correctly-sized (32-octet, matching <see cref="NameAlg"/>) access policy digest - proves
    /// <c>authPolicy</c> retention: the Index's own state carries <c>nameAlg</c>/<c>authPolicy</c> forward from
    /// <c>TPM2_NV_DefineSpace()</c> rather than discarding them.
    /// </summary>
    private static byte[] NonEmptyAuthPolicy { get; } =
    [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    ];

    /// <summary>The first-write payload used by the WRITTEN-flip test.</summary>
    private static byte[] FirstWriteData { get; } = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99];

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// A defined Index's returned public area matches what was defined, and its Name matches an independent
    /// transcription of TPM 2.0 Library Part 1, Section 14, Table 6's recipe over a NON-EMPTY <c>authPolicy</c> -
    /// pinning the retention fix, not merely the recipe's shape.
    /// </summary>
    [TestMethod]
    public async Task NvReadPublicOfDefinedIndexReturnsAPublicAreaAndNameMatchingAnIndependentTranscription()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineOrdinaryIndexAsync(device, pool, registry, OrdinaryIndexHandle, NonEmptyAuthPolicy).ConfigureAwait(false);

        TpmResult<NvReadPublicResponse> result = await device.NvReadPublicAsync(OrdinaryIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NvReadPublicAsync failed: '{result.ResponseCode}'.");

        using NvReadPublicResponse response = result.Value;
        Assert.AreEqual(OrdinaryIndexHandle, response.NvPublic.NvIndex, "The returned public area's nvIndex must equal the defined handle.");
        Assert.AreEqual(NameAlg, response.NvPublic.NameAlg, "The returned public area's nameAlg must equal what was defined.");
        Assert.AreEqual(OrdinaryAttributes, response.NvPublic.Attributes, "The returned public area's attributes must equal what was defined (unwritten: no TPMA_NV_WRITTEN).");
        Assert.AreEqual(OrdinaryIndexDataSize, response.NvPublic.DataSize, "The returned public area's dataSize must equal what was defined.");
        Assert.AreSequenceEqual(NonEmptyAuthPolicy, response.NvPublic.AuthPolicy.AsReadOnlySpan().ToArray(), "The returned public area's authPolicy must equal what was defined - proving retention, not silent discard.");

        byte[] expectedName = await ComputeIndependentNvNameAsync(pool, OrdinaryIndexHandle, NameAlg, OrdinaryAttributes, NonEmptyAuthPolicy, OrdinaryIndexDataSize).ConfigureAwait(false);
        Assert.AreSequenceEqual(
            expectedName, response.NvName.Span.ToArray(),
            "The returned Name must equal nameAlg || H_nameAlg(TPMS_NV_PUBLIC) transcribed independently from Part 1, Section 14, Table 6 and Part 2, Section 13.6, Table 235.");
    }

    /// <summary>
    /// The Name changes the instant TPMA_NV_WRITTEN flips at the first write (TPM 2.0 Library Part 1, Section
    /// 14: "the Name will change to reflect that TPMA_NV_WRITTEN is SET for the Index") - the WRITTEN bit lives
    /// inside the hashed <c>attributes</c> field, so it is included in, never excluded from, the digest. Both
    /// the before- and after-write Names are independently pinned, not merely asserted unequal.
    /// </summary>
    [TestMethod]
    public async Task NvReadPublicNameChangesToMatchAFreshTranscriptionWhenTpmaNvWrittenFlipsAtTheFirstWrite()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineOrdinaryIndexAsync(device, pool, registry, OrdinaryIndexHandle, authPolicy: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        TpmResult<NvReadPublicResponse> beforeResult = await device.NvReadPublicAsync(OrdinaryIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(beforeResult.IsSuccess, $"NvReadPublicAsync (before the first write) failed: '{beforeResult.ResponseCode}'.");

        byte[] nameBeforeWrite;
        using(NvReadPublicResponse before = beforeResult.Value)
        {
            nameBeforeWrite = before.NvName.Span.ToArray();
            byte[] expectedBefore = await ComputeIndependentNvNameAsync(pool, OrdinaryIndexHandle, NameAlg, OrdinaryAttributes, ReadOnlyMemory<byte>.Empty, OrdinaryIndexDataSize).ConfigureAwait(false);
            Assert.AreSequenceEqual(expectedBefore, nameBeforeWrite, "Before the first write, the Name must match the transcription with TPMA_NV_WRITTEN clear.");
        }

        using TpmPasswordSession writeSession = TpmPasswordSession.Create(IndexAuthValue, pool);
        using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(FirstWriteData, pool);
        var writeInput = new NvWriteInput(OrdinaryIndexHandle, OrdinaryIndexHandle, writeInputBuffer, Offset: 0);
        TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
            device, writeInput, [writeSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");

        TpmResult<NvReadPublicResponse> afterResult = await device.NvReadPublicAsync(OrdinaryIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(afterResult.IsSuccess, $"NvReadPublicAsync (after the first write) failed: '{afterResult.ResponseCode}'.");

        using NvReadPublicResponse after = afterResult.Value;
        byte[] nameAfterWrite = after.NvName.Span.ToArray();
        byte[] expectedAfter = await ComputeIndependentNvNameAsync(
            pool, OrdinaryIndexHandle, NameAlg, OrdinaryAttributes | TpmaNv.TPMA_NV_WRITTEN, ReadOnlyMemory<byte>.Empty, OrdinaryIndexDataSize).ConfigureAwait(false);
        Assert.AreSequenceEqual(expectedAfter, nameAfterWrite, "After the first write, the Name must match the transcription with TPMA_NV_WRITTEN SET.");

        Assert.IsFalse(nameBeforeWrite.AsSpan().SequenceEqual(nameAfterWrite), "The Name before and after the first write must differ.");
    }

    /// <summary>An undefined handle (in-range, no Index present) is TPM_RC_HANDLE (TPM 2.0 Library Part 3, Section 5.4, clause 3.1).</summary>
    [TestMethod]
    public async Task NvReadPublicOfAnUndefinedHandleReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvReadPublicResponse> result = await device.NvReadPublicAsync(OrdinaryIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "An undefined handle must not succeed.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, result.ResponseCode);
    }

    /// <summary>
    /// A handle outside the NV-Index MSO range is TPM_RC_VALUE at unmarshal time (TPMI_RH_NV_INDEX's own
    /// interface-type check, TPM 2.0 Library Part 2, Section 9.25, Table 72) - never reaching the handle-
    /// existence gate at all.
    /// </summary>
    [TestMethod]
    public async Task NvReadPublicOfAnOutOfRangeHandleReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);

        TpmResult<NvReadPublicResponse> result = await device.NvReadPublicAsync((uint)TpmRh.TPM_RH_OWNER, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A permanent-handle-range value must not be accepted as an NV Index handle.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, result.ResponseCode);
    }

    /// <summary>
    /// NV_ReadPublic succeeds against a never-written Index, while the SAME Index's data-area read
    /// (TPM2_NV_Read) rejects with TPM_RC_NV_UNINITIALIZED - proving NV_ReadPublic is genuinely ungated on the
    /// data-access checks (TPM 2.0 Library Part 3, Section 5.4's lock-gate clauses condition on "the command
    /// requires read/write access to the index data", which NV_ReadPublic never requires since it reads only
    /// the public area). TPMA_NV_READLOCKED/WRITELOCKED specifically are never wire-reachable in this
    /// simulator (TPM2_NV_ReadLock()/TPM2_NV_WriteLock() are unmodelled, and TPM2_NV_DefineSpace() itself
    /// refuses a definition that arrives already claiming either bit) - the simulator's own NV_ReadPublic
    /// transition applies, by inspection, only the single generic existence check TPM 2.0 Library Part 3,
    /// Section 5.4 clause 3.1 describes, uniformly regardless of which status attribute would otherwise be at
    /// stake.
    /// </summary>
    [TestMethod]
    public async Task NvReadPublicOfANeverWrittenIndexSucceedsWhileNvReadRejectsWithUninitialized()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineOrdinaryIndexAsync(device, pool, registry, OrdinaryIndexHandle, authPolicy: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(OrdinaryIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(publicResult.IsSuccess, $"NvReadPublicAsync against a never-written Index must succeed: '{publicResult.ResponseCode}'.");
        publicResult.Value.Dispose();

        using TpmPasswordSession readSession = TpmPasswordSession.Create(IndexAuthValue, pool);
        var readInput = new NvReadInput(AuthHandle: OrdinaryIndexHandle, NvIndex: OrdinaryIndexHandle, Size: OrdinaryIndexDataSize, Offset: 0);
        TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
            device, readInput, [readSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(readResult.IsSuccess, "TPM2_NV_Read against the same never-written Index must not succeed.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_NV_UNINITIALIZED, readResult.ResponseCode);
    }

    /// <summary>
    /// A definition whose <c>nameAlg</c> is not a hash this TPM implements is refused with <c>TPM_RC_HASH</c>: on
    /// hardware the <c>TPMI_ALG_HASH</c> interface type refuses it while unmarshaling <c>publicInfo</c> (TPM 2.0
    /// Library Part 2, Section 9.27), so no Index can ever exist whose Name cannot be computed. The value is
    /// retained and drives every Name this model computes, so accepting it would strand the Index: its Name -
    /// needed by NV_ReadPublic, by cpHash on every session-authorized NV command, and by TPM2_PolicyNV - could
    /// never be produced.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceWithAnUnimplementedNameAlgIsRefusedWithHash()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        TpmResult<NvDefineSpaceResponse> defineResult = await TryDefineIndexAsync(
            device, pool, registry, OrdinaryIndexHandle, TpmAlgIdConstants.TPM_ALG_SM3_256, authPolicy: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        Assert.IsFalse(defineResult.IsSuccess, "An Index whose Name algorithm this TPM does not implement must never be defined.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_HASH, defineResult.ResponseCode);

        TpmResult<NvReadPublicResponse> publicResult = await device.NvReadPublicAsync(OrdinaryIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            TpmRcConstants.TPM_RC_HANDLE, publicResult.ResponseCode,
            "The refused definition must leave no Index behind for a later Name computation to stumble over.");
    }

    /// <summary>
    /// A definition whose <c>authPolicy</c> is present but not exactly the <c>nameAlg</c> digest size is refused
    /// with <c>TPM_RC_SIZE</c> (TPM 2.0 Library Part 3, Section 31.3.1's size condition on
    /// <c>publicInfo.authPolicy</c>; the reference's <c>NvDefineSpace</c> refuses any nonzero size differing from
    /// the digest size). The policy digest is hashed into the Index's Name, so an inconsistent one would give the
    /// Index a Name no hardware can produce.
    /// </summary>
    [TestMethod]
    public async Task NvDefineSpaceWithAnAuthPolicySizeInconsistentWithTheNameAlgIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        //A SHA-1-sized policy digest under a SHA-256 nameAlg: well-formed on the wire, inconsistent with the
        //Name algorithm it is supposed to belong to.
        byte[] undersizedAuthPolicy = new byte[20];
        TpmResult<NvDefineSpaceResponse> undersizedResult = await TryDefineIndexAsync(
            device, pool, registry, OrdinaryIndexHandle, NameAlg, undersizedAuthPolicy).ConfigureAwait(false);

        Assert.IsFalse(undersizedResult.IsSuccess, "An authPolicy shorter than the nameAlg digest size must not be accepted.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, undersizedResult.ResponseCode);

        byte[] oversizedAuthPolicy = new byte[Sha256DigestSize + 1];
        TpmResult<NvDefineSpaceResponse> oversizedResult = await TryDefineIndexAsync(
            device, pool, registry, OrdinaryIndexHandle, NameAlg, oversizedAuthPolicy).ConfigureAwait(false);

        Assert.IsFalse(oversizedResult.IsSuccess, "An authPolicy longer than the nameAlg digest size must not be accepted.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, oversizedResult.ResponseCode);
    }

    /// <summary>
    /// A session BOUND to the very Index it then authorizes omits that Index's authValue from the command and
    /// response HMAC keys (TPM 2.0 Library Part 1, Section 17.6.10, equation 22): binding already proved
    /// knowledge of the authValue through the session-key KDFa, so folding it in again is redundant. The caller
    /// therefore never sets an authorization value on the session, and the read must still succeed - a
    /// simulator that folded the authValue anyway would answer an authorization failure and charge the
    /// dictionary-attack counter for a perfectly honest command.
    /// </summary>
    /// <remarks>
    /// The Index is written BEFORE the session is bound: the first write flips TPMA_NV_WRITTEN and so changes
    /// the Index's Name, and a bind is tied to the Name the entity had when the session started.
    /// </remarks>
    [TestMethod]
    public async Task NvReadOverASessionBoundToTheSameIndexOmitsTheIndexAuthValueAndSucceeds()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync().ConfigureAwait(false);
        using TpmDevice device = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateNvRegistry();

        await DefineOrdinaryIndexAsync(device, pool, registry, OrdinaryIndexHandle, authPolicy: ReadOnlyMemory<byte>.Empty).ConfigureAwait(false);

        using(TpmPasswordSession writeSession = TpmPasswordSession.Create(IndexAuthValue, pool))
        {
            using Tpm2bMaxNvBuffer writeInputBuffer = Tpm2bMaxNvBuffer.Create(FirstWriteData, pool);
            var writeInput = new NvWriteInput(OrdinaryIndexHandle, OrdinaryIndexHandle, writeInputBuffer, Offset: 0);
            TpmResult<NvWriteResponse> writeResult = await TpmCommandExecutor.ExecuteAsync<NvWriteResponse>(
                device, writeInput, [writeSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(writeResult.IsSuccess, $"NV_Write failed: '{writeResult.ResponseCode}'.");
        }

        StartAuthSessionInput startInput = StartAuthSessionInput.CreateBoundUnsaltedHmacSession(OrdinaryIndexHandle, NameAlg);
        TpmResult<StartAuthSessionResponse> startResult = await TpmCommandExecutor.ExecuteAsync<StartAuthSessionResponse>(
            device, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"Binding a session to an ordinary NV Index must succeed: '{startResult.ResponseCode}'.");

        StartAuthSessionResponse started = startResult.Value;
        uint sessionHandle = started.SessionHandle.Value;

        try
        {
            using TpmSession boundSession = await TpmSession.CreateBoundAsync(
                new TpmHandle(sessionHandle), IndexAuthValue, startInput.NonceCaller, started.NonceTPM,
                NameAlg, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

            TpmResult<NvReadPublicResponse> nameResult = await device.NvReadPublicAsync(OrdinaryIndexHandle, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(nameResult.IsSuccess, $"NvReadPublicAsync failed: '{nameResult.ResponseCode}'.");

            using NvReadPublicResponse namePublic = nameResult.Value;
            ReadOnlyMemory<byte> indexName = namePublic.NvName.Span.ToArray();

            var readInput = new NvReadInput(AuthHandle: OrdinaryIndexHandle, NvIndex: OrdinaryIndexHandle, Size: OrdinaryIndexDataSize, Offset: 0);
            TpmResult<NvReadResponse> readResult = await TpmCommandExecutor.ExecuteAsync<NvReadResponse>(
                device, readInput, [boundSession], [indexName, indexName], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(
                readResult.IsSuccess,
                $"A session bound to the authorizing Index must authorize without the authValue term: '{readResult.ResponseCode}'.");

            using NvReadResponse response = readResult.Value;
            Assert.AreSequenceEqual(FirstWriteData, response.Data.ToArray(), "The bound-session read must return the written data area.");
        }
        finally
        {
            var flush = FlushContextInput.ForHandle(sessionHandle);
            _ = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
                device, flush, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Independently transcribes an NV Index's Name: <c>nameAlg ‖ H_nameAlg(nvIndex ‖ nameAlg ‖ attributes ‖
    /// authPolicy ‖ dataSize)</c>, the whole marshaled <c>TPMS_NV_PUBLIC</c> (TPM 2.0 Library Part 2, Section
    /// 13.6, Table 235) hashed per Part 1, Section 14, Table 6. Uses <see cref="BinaryPrimitives"/> directly and
    /// the project's own registered digest seam - never <c>TpmsNvPublic.WriteTo</c> or <c>TpmObjectName</c>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="nvIndex">The Index handle.</param>
    /// <param name="nameAlg">The Name hash algorithm.</param>
    /// <param name="attributes">The Index attributes to hash.</param>
    /// <param name="authPolicy">The access policy digest to hash.</param>
    /// <param name="dataSize">The declared data area size to hash.</param>
    /// <returns>The transcribed Name (nameAlg prefix followed by the digest).</returns>
    private async Task<byte[]> ComputeIndependentNvNameAsync(
        BaseMemoryPool pool, uint nvIndex, TpmAlgIdConstants nameAlg, TpmaNv attributes, ReadOnlyMemory<byte> authPolicy, ushort dataSize)
    {
        int marshaledLength = sizeof(uint) + sizeof(ushort) + sizeof(uint) + sizeof(ushort) + authPolicy.Length + sizeof(ushort);
        byte[] marshaled = new byte[marshaledLength];
        int offset = 0;

        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset, sizeof(uint)), nvIndex);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset, sizeof(ushort)), (ushort)nameAlg);
        offset += sizeof(ushort);
        BinaryPrimitives.WriteUInt32BigEndian(marshaled.AsSpan(offset, sizeof(uint)), (uint)attributes);
        offset += sizeof(uint);
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset, sizeof(ushort)), (ushort)authPolicy.Length);
        offset += sizeof(ushort);
        authPolicy.Span.CopyTo(marshaled.AsSpan(offset));
        offset += authPolicy.Length;
        BinaryPrimitives.WriteUInt16BigEndian(marshaled.AsSpan(offset, sizeof(ushort)), dataSize);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            marshaled, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        byte[] name = new byte[sizeof(ushort) + Sha256DigestSize];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)nameAlg);
        digest.AsReadOnlySpan().CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>Defines an ordinary (TPM_NT_ORDINARY) NV Index with <see cref="IndexAuthValue"/> as its own authValue, authorized by the (empty) owner authValue.</summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="authPolicy">The access policy digest to define with; empty for no policy.</param>
    private async Task DefineOrdinaryIndexAsync(TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, ReadOnlyMemory<byte> authPolicy)
    {
        TpmResult<NvDefineSpaceResponse> result = await TryDefineIndexAsync(device, pool, registry, nvIndex, NameAlg, authPolicy).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"NV_DefineSpace failed: '{result.ResponseCode}'.");
    }

    /// <summary>
    /// Issues <c>TPM2_NV_DefineSpace</c> for an ordinary Index with a caller-chosen Name algorithm and access
    /// policy and returns the raw result, so a rejection-path test can assert the response code the definition
    /// itself answers.
    /// </summary>
    /// <param name="device">The TPM device.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="nvIndex">The Index handle to define.</param>
    /// <param name="nameAlg">The Name algorithm to define with.</param>
    /// <param name="authPolicy">The access policy digest to define with; empty for no policy.</param>
    /// <returns>The definition's result.</returns>
    private async Task<TpmResult<NvDefineSpaceResponse>> TryDefineIndexAsync(
        TpmDevice device, BaseMemoryPool pool, TpmResponseRegistry registry, uint nvIndex, TpmAlgIdConstants nameAlg, ReadOnlyMemory<byte> authPolicy)
    {
        using TpmPasswordSession ownerSession = TpmPasswordSession.CreateEmpty(pool);
        using var auth = Tpm2bAuth.Create(IndexAuthValue, pool);
        using var authPolicyDigest = Tpm2bDigest.Create(authPolicy.Span, pool);
        using var publicInfo = new TpmsNvPublic(nvIndex, nameAlg, OrdinaryAttributes, authPolicyDigest, OrdinaryIndexDataSize);
        using var input = new NvDefineSpaceInput(TpmRh.TPM_RH_OWNER, auth, publicInfo);

        return await TpmCommandExecutor.ExecuteAsync<NvDefineSpaceResponse>(
            device, input, [ownerSession], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates a response codec registry for the NV commands and session handling these tests drive.</summary>
    private static TpmResponseRegistry CreateNvRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_DefineSpace, TpmResponseCodec.NvDefineSpace);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Read, TpmResponseCodec.NvRead);
        _ = registry.Register(TpmCcConstants.TPM_CC_NV_Write, TpmResponseCodec.NvWrite);
        _ = registry.Register(TpmCcConstants.TPM_CC_StartAuthSession, TpmResponseCodec.StartAuthSession);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);

        return registry;
    }

    /// <summary>Creates a simulator, powers it on, and brings it through TPM2_Startup(CLEAR) into the operational phase.</summary>
    private async Task<TpmSimulator> CreateOperationalAsync()
    {
        var simulator = new TpmSimulator("tpm-in-house-nv-readpublic");
        await simulator.PowerOnAsync(TestContext.CancellationToken).ConfigureAwait(false);

        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var input = new StartupInput(TpmSuConstants.TPM_SU_CLEAR);
        int length = TpmHeader.HeaderSize + input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_NO_SESSIONS, (uint)length, (uint)input.CommandCode);
        header.WriteTo(ref writer);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");

        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");

        return simulator;
    }
}
