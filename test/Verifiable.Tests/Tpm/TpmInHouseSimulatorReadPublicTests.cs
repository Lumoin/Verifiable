using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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
/// Drives <c>TPM2_ReadPublic()</c> (<see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM
/// 2.0 Library Specification</see>, Part 3: Commands, clause 12.4) against the in-house behavioural
/// <see cref="TpmSimulator"/> — entirely in-process, with no external assets — through the production command
/// path (<see cref="TpmCommandExecutor"/> with <see cref="ReadPublicInput"/> and
/// <see cref="TpmResponseCodec.ReadPublic"/>).
/// </summary>
/// <remarks>
/// <para>
/// Every accepted-path test pins the returned Name and Qualified Name against INDEPENDENT in-test
/// transcriptions of Part 1: Architecture — the Name as <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c> (clause 13,
/// Table 9) over the public area the response itself carries, the Qualified Name as
/// <c>H_nameAlg(QN_parent ‖ Name)</c> with a Primary Seed's QN being its handle (clause 23.5) — built here
/// from <see cref="BinaryPrimitives"/> and the project's own registered digest seam, never by calling
/// <c>TpmObjectName</c> or any other production Name-computation type, so a bug shared between the production
/// recipe and this test's own oracle cannot pass silently.
/// </para>
/// <para>
/// The refusal tests cover the command's own clause ("If objectHandle references a sequence object, the TPM
/// shall return TPM_RC_SEQUENCE", clause 12.4.1), the interface type's own range check (Part 2: Structures,
/// clause 9.3, Table 49, <c>#TPM_RC_VALUE</c>), and the generic handle-validation check for a handle nothing
/// is loaded at (Part 3, clause 5.4, <c>TPM_RC_HANDLE</c>).
/// </para>
/// </remarks>
[TestClass]
internal sealed class TpmInHouseSimulatorReadPublicTests
{
    /// <summary>The Name hash algorithm every object in this file is created under.</summary>
    private const TpmAlgIdConstants NameAlg = TpmAlgIdConstants.TPM_ALG_SHA256;

    /// <summary>The SHA-256 digest width, in octets.</summary>
    private const int Sha256DigestSize = 32;

    /// <summary>A transient handle value naming no loaded object in a freshly-brought-operational simulator.</summary>
    private const uint ArbitraryUnknownTransientHandle = 0x8000_0999;

    /// <summary>The persistent handle the persist test evicts a primary to (most-significant octet TPM_HT_PERSISTENT).</summary>
    private const uint PersistentHandle = 0x8100_0010;

    /// <summary>An NV-Index-range value (most-significant octet TPM_HT_NV_INDEX): outside TPMI_DH_OBJECT altogether.</summary>
    private const uint NvIndexRangeHandle = 0x0100_0091;

    /// <summary>The authorization value the no-authorization test creates its primary with.</summary>
    private const string ObjectPassword = "read-public-needs-no-auth";

    /// <summary>Gets or sets the per-test context (supplies the cancellation token).</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// "This command allows access to the public area of a loaded object" (Part 3, clause 12.4.1): a primary's
    /// <c>outPublic</c> comes back octet for octet as <c>TPM2_CreatePrimary()</c> exported it, its <c>name</c>
    /// matches both the creation response and an independent transcription of Part 1, clause 13, Table 9, and
    /// its <c>qualifiedName</c> matches an independent transcription of clause 23.5 with the owner hierarchy's
    /// handle as the Primary Seed's own Qualified Name.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOfAPrimaryReturnsItsPublicAreaNameAndQualifiedNameMatchingIndependentTranscriptions()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);

        TpmResult<ReadPublicResponse> result = await SubmitReadPublicAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadPublic() of a loaded primary failed: '{result.ResponseCode}'.");
        using ReadPublicResponse response = result.Value;

        byte[] createdPublicArea = primary.OutPublic.GetRawBytes().ToArray();
        Assert.AreSequenceEqual(createdPublicArea, response.PublicArea.GetRawBytes().ToArray(), "outPublic must be the marshaled TPMT_PUBLIC TPM2_CreatePrimary() exported, octet for octet.");
        Assert.AreSequenceEqual(primary.Name.Span.ToArray(), response.Name.Span.ToArray(), "name must equal the Name TPM2_CreatePrimary() returned.");

        byte[] expectedName = await ComputeIndependentNameAsync(pool, createdPublicArea).ConfigureAwait(false);
        Assert.AreSequenceEqual(expectedName, response.Name.Span.ToArray(), "name must equal nameAlg || H_nameAlg(TPMT_PUBLIC) transcribed independently from Part 1, clause 13, Table 9.");

        byte[] expectedQualifiedName = await ComputeIndependentQualifiedNameAsync(pool, HierarchyHandleQualifiedName(TpmRh.TPM_RH_OWNER), expectedName).ConfigureAwait(false);
        Assert.AreSequenceEqual(expectedQualifiedName, response.QualifiedName.Span.ToArray(), "qualifiedName must equal nameAlg || H_nameAlg(TPM_RH_OWNER || Name) transcribed independently from Part 1, clause 23.5.");
    }

    /// <summary>
    /// A loaded sealed object answers with the very <c>inPublic</c> that <c>TPM2_Load()</c> was given, the Name
    /// <c>TPM2_Load()</c> returned, and a Qualified Name chained from its Storage Parent's:
    /// <c>QN = H_nameAlg(QN_parent ‖ Name)</c> (Part 1, clause 23.5), the parent's own QN transcribed
    /// independently too — so the ancestry, not merely the hierarchy handle, is what the digest binds.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOfALoadedSealedObjectReturnsTheLoadedPublicAreaAndAQualifiedNameChainedFromTheParent()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse parent = await CreateStorageParentAsync(tpm, registry, pool).ConfigureAwait(false);
        using CreateResponse sealedObject = await CreateSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle).ConfigureAwait(false);
        (TpmiDhObject childHandle, byte[] loadedName) = await LoadSealedObjectAsync(tpm, registry, pool, parent.ObjectHandle, sealedObject).ConfigureAwait(false);

        TpmResult<ReadPublicResponse> result = await SubmitReadPublicAsync(tpm, registry, pool, childHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadPublic() of a loaded sealed object failed: '{result.ResponseCode}'.");
        using ReadPublicResponse response = result.Value;

        byte[] loadedPublicArea = sealedObject.OutPublic.GetRawBytes().ToArray();
        Assert.AreSequenceEqual(loadedPublicArea, response.PublicArea.GetRawBytes().ToArray(), "outPublic must be the marshaled TPMT_PUBLIC TPM2_Load() was given, octet for octet.");
        Assert.AreSequenceEqual(loadedName, response.Name.Span.ToArray(), "name must equal the Name TPM2_Load() returned.");

        byte[] expectedChildName = await ComputeIndependentNameAsync(pool, loadedPublicArea).ConfigureAwait(false);
        Assert.AreSequenceEqual(expectedChildName, response.Name.Span.ToArray(), "name must equal nameAlg || H_nameAlg(TPMT_PUBLIC) transcribed independently.");

        byte[] parentName = await ComputeIndependentNameAsync(pool, parent.OutPublic.GetRawBytes().ToArray()).ConfigureAwait(false);
        byte[] parentQualifiedName = await ComputeIndependentQualifiedNameAsync(pool, HierarchyHandleQualifiedName(TpmRh.TPM_RH_OWNER), parentName).ConfigureAwait(false);
        byte[] expectedChildQualifiedName = await ComputeIndependentQualifiedNameAsync(pool, parentQualifiedName, expectedChildName).ConfigureAwait(false);
        Assert.AreSequenceEqual(expectedChildQualifiedName, response.QualifiedName.Span.ToArray(), "qualifiedName must equal nameAlg || H_nameAlg(QN_parent || Name) with QN_parent = H(TPM_RH_OWNER || parent Name), transcribed independently from Part 1, clause 23.5.");
    }

    /// <summary>
    /// A persistent object is "a loaded object" too (Part 2, clause 9.3, Table 49 admits the persistent range
    /// in <c>TPMI_DH_OBJECT</c>): after <c>TPM2_EvictControl()</c> the persistent handle answers the identical
    /// public area, Name, and Qualified Name as the transient instance — persisting changes the handle, never
    /// the object's identity or ancestry (Part 1, clause 23.5) — and keeps answering after the transient is flushed.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOfAPersistentObjectAnswersTheSameTripleAsItsTransientInstanceAndSurvivesTheTransientFlush()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        await PersistAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);

        TpmResult<ReadPublicResponse> transientResult = await SubmitReadPublicAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsTrue(transientResult.IsSuccess, $"TPM2_ReadPublic() of the transient instance failed: '{transientResult.ResponseCode}'.");
        using ReadPublicResponse transientResponse = transientResult.Value;

        TpmResult<ReadPublicResponse> persistentResult = await SubmitReadPublicAsync(tpm, registry, pool, PersistentHandle).ConfigureAwait(false);
        Assert.IsTrue(persistentResult.IsSuccess, $"TPM2_ReadPublic() of the persistent instance failed: '{persistentResult.ResponseCode}'.");
        using ReadPublicResponse persistentResponse = persistentResult.Value;

        Assert.AreSequenceEqual(transientResponse.PublicArea.GetRawBytes().ToArray(), persistentResponse.PublicArea.GetRawBytes().ToArray(), "The persistent instance must answer the same public area.");
        Assert.AreSequenceEqual(transientResponse.Name.Span.ToArray(), persistentResponse.Name.Span.ToArray(), "The persistent instance must answer the same Name.");
        Assert.AreSequenceEqual(transientResponse.QualifiedName.Span.ToArray(), persistentResponse.QualifiedName.Span.ToArray(), "The persistent instance must answer the same Qualified Name.");

        await FlushAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);

        TpmResult<ReadPublicResponse> afterFlush = await SubmitReadPublicAsync(tpm, registry, pool, PersistentHandle).ConfigureAwait(false);
        Assert.IsTrue(afterFlush.IsSuccess, $"TPM2_ReadPublic() of the persistent instance after the transient flush failed: '{afterFlush.ResponseCode}'.");
        using ReadPublicResponse afterFlushResponse = afterFlush.Value;
        Assert.AreSequenceEqual(persistentResponse.Name.Span.ToArray(), afterFlushResponse.Name.Span.ToArray(), "The persistent instance owns its own carriers: flushing the transient must not change what it answers.");
    }

    /// <summary>
    /// "If objectHandle references a sequence object, the TPM shall return TPM_RC_SEQUENCE" (Part 3, clause
    /// 12.4.1; Part 1, clause 29.4.6: "the public portion of a sequence is not readable with TPM2_ReadPublic()").
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOfASequenceHandleReturnsSequence()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        using SignSequenceStartInput startInput = SignSequenceStartInput.Create(primary.ObjectHandle, [], pool);
        TpmResult<SignSequenceStartResponse> startResult = await TpmCommandExecutor.ExecuteAsync<SignSequenceStartResponse>(
            tpm, startInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(startResult.IsSuccess, $"TPM2_SignSequenceStart() failed: '{startResult.ResponseCode}'.");
        SignSequenceStartResponse started = startResult.Value;

        TpmResult<ReadPublicResponse> result = await SubmitReadPublicAsync(tpm, registry, pool, started.SequenceHandle.Value).ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess, "A sequence object's public portion must not be readable.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_SEQUENCE, result.ResponseCode);
    }

    /// <summary>
    /// An in-range handle nothing is loaded at is <c>TPM_RC_HANDLE</c> (Part 3, clause 5.4's handle-validation
    /// check) — both a never-assigned transient value and a primary's handle after <c>TPM2_FlushContext()</c>,
    /// which must stop answering the instant the object is gone.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOfAnUnloadedOrFlushedHandleReturnsHandle()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ReadPublicResponse> unknown = await SubmitReadPublicAsync(tpm, registry, pool, ArbitraryUnknownTransientHandle).ConfigureAwait(false);
        Assert.IsFalse(unknown.IsSuccess, "A transient handle nothing is loaded at must not answer.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, unknown.ResponseCode);

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);
        await FlushAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);

        TpmResult<ReadPublicResponse> flushed = await SubmitReadPublicAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);
        Assert.IsFalse(flushed.IsSuccess, "A flushed object's handle must not answer.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_HANDLE, flushed.ResponseCode);
    }

    /// <summary>
    /// A value outside the transient and persistent ranges is <c>TPM_RC_VALUE</c> at unmarshal time —
    /// <c>TPMI_DH_OBJECT</c>'s own interface-type check (Part 2, clause 9.3, Table 49, <c>#TPM_RC_VALUE</c>) —
    /// never reaching the handle-existence gate at all. <c>TPM_RH_NULL</c> is Table 49's conditional
    /// <c>+TPM_RH_NULL</c> value, and Part 3, Table 24 declares <c>objectHandle</c> without the <c>+</c>, so the
    /// NULL handle is out of range for this command exactly as an NV-Index-range value is.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOfAnOutOfRangeHandleReturnsValue()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        TpmResult<ReadPublicResponse> nullHandle = await SubmitReadPublicAsync(tpm, registry, pool, (uint)TpmRh.TPM_RH_NULL).ConfigureAwait(false);
        Assert.IsFalse(nullHandle.IsSuccess, "TPM_RH_NULL is not admitted by an objectHandle declared without the '+'.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, nullHandle.ResponseCode);

        TpmResult<ReadPublicResponse> nvRange = await SubmitReadPublicAsync(tpm, registry, pool, NvIndexRangeHandle).ConfigureAwait(false);
        Assert.IsFalse(nvRange.IsSuccess, "An NV-Index-range value must not be accepted as an object handle.");
        Assert.AreEqual(TpmRcConstants.TPM_RC_VALUE, nvRange.ResponseCode);
    }

    /// <summary>
    /// "Use of the objectHandle does not require authorization" (Part 3, clause 12.4.1; Table 24, Auth Index:
    /// None): a primary created WITH an authorization value answers a sessionless <c>TPM2_ReadPublic()</c> —
    /// no password, no session — with the same Name its creation returned.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicOfAnObjectWithAnAuthValueNeedsNoAuthorization()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, ObjectPassword).ConfigureAwait(false);

        TpmResult<ReadPublicResponse> result = await SubmitReadPublicAsync(tpm, registry, pool, primary.ObjectHandle.Value).ConfigureAwait(false);

        Assert.IsTrue(result.IsSuccess, $"TPM2_ReadPublic() of an object with an authValue, sent without any authorization, failed: '{result.ResponseCode}'.");
        using ReadPublicResponse response = result.Value;
        Assert.AreSequenceEqual(primary.Name.Span.ToArray(), response.Name.Span.ToArray(), "name must equal the Name TPM2_CreatePrimary() returned.");
    }

    /// <summary>
    /// Table 24's tag is <c>TPM_ST_SESSIONS</c> only "if an audit or encrypt session is present"; this simulator
    /// models neither on <c>outPublic</c>, so a session-tagged frame — a password authorization area appended to
    /// a command that has no authorization slot at all — leaves unparsed octets and is refused with
    /// <c>TPM_RC_SIZE</c> rather than silently accepted without the encryption the tag would promise.
    /// </summary>
    [TestMethod]
    public async Task ReadPublicWithASessionTaggedFrameIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await CreateOperationalAsync(pool).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync);
        TpmResponseRegistry registry = CreateRegistry();

        using CreatePrimaryResponse primary = await CreateEccSigningPrimaryAsync(tpm, registry, pool, password: null).ConfigureAwait(false);

        //Header ‖ objectHandle ‖ authorizationSize ‖ one TPM_RS_PW authorization (sessionHandle, empty nonce,
        //sessionAttributes 0, empty hmac) — the shape Part 3, clause 6.2 and Part 1, clause 15.6.1 give a
        //session-tagged command.
        const int AuthorizationAreaLength = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        int length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + AuthorizationAreaLength;
        using IMemoryOwner<byte> owner = pool.Rent(length);
        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_ReadPublic);
        header.WriteTo(ref writer);
        writer.WriteUInt32(primary.ObjectHandle.Value);
        writer.WriteUInt32(AuthorizationAreaLength);
        writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
        writer.WriteUInt16(0);
        writer.WriteByte(0);
        writer.WriteUInt16(0);

        TpmResult<TpmResponse> result = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, "The frame must be answered at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        Assert.AreEqual(TpmRcConstants.TPM_RC_SIZE, (TpmRcConstants)responseHeader.Code, "A session-tagged TPM2_ReadPublic() must fail closed on its unparsed authorization area.");
    }

    /// <summary>
    /// Independently transcribes an object's Name: <c>nameAlg ‖ H_nameAlg(TPMT_PUBLIC)</c> (Part 1, clause 13,
    /// Table 9) over the already-marshaled public-area octets, through the project's own registered digest
    /// seam — never <c>TpmObjectName</c>.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="marshaledPublicArea">The marshaled <c>TPMT_PUBLIC</c> octets (no size prefix).</param>
    /// <returns>The transcribed Name (nameAlg prefix followed by the digest).</returns>
    private async Task<byte[]> ComputeIndependentNameAsync(BaseMemoryPool pool, byte[] marshaledPublicArea)
    {
        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            marshaledPublicArea, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return FrameName(digest.AsReadOnlySpan());
    }

    /// <summary>
    /// Independently transcribes a Qualified Name: <c>nameAlg ‖ H_nameAlg(QN_parent ‖ Name)</c> (Part 1, clause
    /// 23.5), under the object's own Name algorithm, through the project's own registered digest seam.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentQualifiedName">The parent's Qualified Name octets — a hierarchy handle's 4 octets for a primary.</param>
    /// <param name="name">The object's Name octets (nameAlg prefix included, as the clause hashes the Name whole).</param>
    /// <returns>The transcribed Qualified Name (nameAlg prefix followed by the digest).</returns>
    private async Task<byte[]> ComputeIndependentQualifiedNameAsync(BaseMemoryPool pool, byte[] parentQualifiedName, byte[] name)
    {
        byte[] message = new byte[parentQualifiedName.Length + name.Length];
        parentQualifiedName.CopyTo(message, 0);
        name.CopyTo(message, parentQualifiedName.Length);

        using DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            message, Sha256DigestSize, CryptoTags.Sha256Digest, pool, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return FrameName(digest.AsReadOnlySpan());
    }

    /// <summary>
    /// "Both the Name and Qualified Name for a Primary Seed are the handle of the Primary Seed" (Part 1, clause
    /// 23.5): a hierarchy handle's 4-octet big-endian value stands as its own Qualified Name.
    /// </summary>
    /// <param name="hierarchy">The permanent hierarchy handle.</param>
    /// <returns>The handle's 4 octets.</returns>
    private static byte[] HierarchyHandleQualifiedName(TpmRh hierarchy)
    {
        byte[] handle = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(handle, (uint)hierarchy);

        return handle;
    }

    /// <summary>Frames a digest as a Name: the 2-octet big-endian nameAlg followed by the digest (Part 1, clause 13, Table 9).</summary>
    /// <param name="digest">The digest octets.</param>
    /// <returns>The framed Name.</returns>
    private static byte[] FrameName(ReadOnlySpan<byte> digest)
    {
        byte[] name = new byte[sizeof(ushort) + digest.Length];
        BinaryPrimitives.WriteUInt16BigEndian(name, (ushort)NameAlg);
        digest.CopyTo(name.AsSpan(sizeof(ushort)));

        return name;
    }

    /// <summary>Submits a sessionless <c>TPM2_ReadPublic()</c> for <paramref name="objectHandle"/> through the production executor and returns the raw result.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The raw handle value to read — deliberately unvalidated so the simulator's own range check is what a test exercises.</param>
    /// <returns>The command result.</returns>
    private async Task<TpmResult<ReadPublicResponse>> SubmitReadPublicAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle)
    {
        ReadPublicInput input = ReadPublicInput.ForHandle(TpmiDhObject.FromValue(objectHandle));

        return await TpmCommandExecutor.ExecuteAsync<ReadPublicResponse>(
            tpm, input, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
    }

    /// <summary>Creates an unrestricted ECC P-256 signing primary under the owner hierarchy with the given object password, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="password">The object's own authorization value, or <see langword="null"/> for an empty one.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateEccSigningPrimaryAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, string? password)
    {
        using CreatePrimaryInput input = CreatePrimaryInput.ForEccSigningKey(
            TpmRh.TPM_RH_OWNER, password, TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256), pool, noDa: true);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary (ECC P-256) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Creates an empty-password ECC storage parent under the owner hierarchy, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The CreatePrimary response (the caller owns it).</returns>
    private async Task<CreatePrimaryResponse> CreateStorageParentAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool)
    {
        using CreatePrimaryInput parentInput = CreatePrimaryInput.ForEccStorageParent(
            TpmRh.TPM_RH_OWNER, null, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, noDa: true);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreatePrimaryResponse> result = await TpmCommandExecutor.ExecuteAsync<CreatePrimaryResponse>(
            tpm, parentInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"CreatePrimary storage parent failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Seals a small datum under <paramref name="parentHandle"/> via <c>TPM2_Create()</c> — returned, not loaded — asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <returns>The Create response (the caller owns it).</returns>
    private async Task<CreateResponse> CreateSealedObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject parentHandle)
    {
        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData("read-public sealed datum"u8.ToArray(), pool);
        using Tpm2bPublic sealTemplate = Tpm2bPublic.CreateSealedDataTemplate(NameAlg, pool, noDa: true);
        using CreateInput createInput = new(parentHandle.Value, inSensitive, sealTemplate, Tpm2bData.Empty, TpmlPcrSelection.Empty);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, createInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"Create (seal) failed: '{result.ResponseCode}'.");

        return result.Value;
    }

    /// <summary>Loads <paramref name="sealedObject"/> under <paramref name="parentHandle"/> via <c>TPM2_Load()</c>, asserting success, and returns the loaded object's handle and the Name the response carried.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent.</param>
    /// <param name="sealedObject">The Create response carrying the blob to load.</param>
    /// <returns>The loaded object's handle and its Name as <c>TPM2_Load()</c> returned it.</returns>
    private async Task<(TpmiDhObject Handle, byte[] Name)> LoadSealedObjectAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmiDhObject parentHandle, CreateResponse sealedObject)
    {
        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Create(sealedObject.OutPrivate.Span, pool);
        using Tpm2bPublic inPublic = ClonePublic(sealedObject.OutPublic, pool);
        using LoadInput loadInput = new(parentHandle.Value, inPrivate, inPublic);
        using TpmPasswordSession parentAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<LoadResponse> result = await TpmCommandExecutor.ExecuteAsync<LoadResponse>(
            tpm, loadInput, [parentAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"TPM2_Load() failed: '{result.ResponseCode}'.");
        using LoadResponse loaded = result.Value;

        return (loaded.ObjectHandle, loaded.Name.Span.ToArray());
    }

    /// <summary>
    /// Persist-then-reload a public area through wire bytes only — the disk round-trip a real deployment
    /// performs — yielding an independently-owned copy rather than aliasing <paramref name="source"/>'s own storage.
    /// </summary>
    /// <param name="source">The public area to clone.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The cloned public area; the caller owns and disposes it.</returns>
    private static Tpm2bPublic ClonePublic(Tpm2bPublic source, BaseMemoryPool pool)
    {
        int size = source.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(size);
        var writer = new TpmWriter(owner.Memory.Span);
        source.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..size]);

        return Tpm2bPublic.Parse(ref reader, pool);
    }

    /// <summary>Persists a transient object to <see cref="PersistentHandle"/> under (empty) owner authorization, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="objectHandle">The transient handle to persist.</param>
    private async Task PersistAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint objectHandle)
    {
        var input = new EvictControlInput(TpmRh.TPM_RH_OWNER, objectHandle, PersistentHandle);
        using TpmPasswordSession ownerAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<EvictControlResponse> result = await TpmCommandExecutor.ExecuteAsync<EvictControlResponse>(
            tpm, input, [ownerAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"EvictControl (persist) failed: '{result.ResponseCode}'.");
    }

    /// <summary>Flushes <paramref name="handle"/> via <c>TPM2_FlushContext()</c>, asserting success.</summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="handle">The transient handle to flush.</param>
    private async Task FlushAsync(TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, uint handle)
    {
        FlushContextInput flushInput = FlushContextInput.ForHandle(handle);
        TpmResult<FlushContextResponse> result = await TpmCommandExecutor.ExecuteAsync<FlushContextResponse>(
            tpm, flushInput, [], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(result.IsSuccess, $"FlushContext failed: '{result.ResponseCode}'.");
    }

    /// <summary>Creates a response codec registry covering the commands these tests issue.</summary>
    /// <returns>The registry.</returns>
    private static TpmResponseRegistry CreateRegistry()
    {
        var registry = new TpmResponseRegistry();
        _ = registry.Register(TpmCcConstants.TPM_CC_CreatePrimary, TpmResponseCodec.CreatePrimary);
        _ = registry.Register(TpmCcConstants.TPM_CC_Create, TpmResponseCodec.CreateObject);
        _ = registry.Register(TpmCcConstants.TPM_CC_Load, TpmResponseCodec.Load);
        _ = registry.Register(TpmCcConstants.TPM_CC_ReadPublic, TpmResponseCodec.ReadPublic);
        _ = registry.Register(TpmCcConstants.TPM_CC_SignSequenceStart, TpmResponseCodec.SignSequenceStart);
        _ = registry.Register(TpmCcConstants.TPM_CC_FlushContext, TpmResponseCodec.FlushContext);
        _ = registry.Register(TpmCcConstants.TPM_CC_EvictControl, TpmResponseCodec.EvictControl);

        return registry;
    }

    /// <summary>
    /// Creates a simulator with the ECC (BouncyCastle) signing backend wired, powers it on, and brings it through
    /// <c>TPM2_Startup(CLEAR)</c> into the operational phase.
    /// </summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The operational simulator.</returns>
    private async Task<TpmSimulator> CreateOperationalAsync(BaseMemoryPool pool)
    {
        var simulator = new TpmSimulator("tpm-in-house-read-public", signingBackend: BouncyCastleTpmEccSigningBackend.Create());
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
        Assert.IsTrue(result.IsSuccess, "TPM2_Startup(CLEAR) must succeed at the transport level.");
        using TpmResponse response = result.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);
        Assert.AreEqual(TpmRcConstants.TPM_RC_SUCCESS, (TpmRcConstants)responseHeader.Code, "TPM2_Startup(CLEAR) must succeed.");
        Assert.AreEqual(TpmLifecyclePhase.Operational, simulator.CurrentPhase);

        return simulator;
    }
}
