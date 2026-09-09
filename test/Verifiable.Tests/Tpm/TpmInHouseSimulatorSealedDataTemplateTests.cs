using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Sessions;
using Verifiable.Tpm.Spec.Attributes;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Acceptance tests for the KEYEDHASH data-object rules a sealed data template is judged by at
/// <c>TPM2_Create()</c>: the <c>sensitiveDataOrigin</c> attribute a data object may never set, and the
/// <c>MAX_SYM_DATA</c> bound on the data it seals (TPM 2.0 Library Part 3, clause 12.1; Part 2, clauses 8.3.3.5,
/// 11.1.13 and 11.1.14, Tables 169 and 170).
/// </summary>
[TestClass]
internal sealed class TpmInHouseSimulatorSealedDataTemplateTests
{
    /// <summary>The MSTest-provided per-test context, its cancellation token observed across every exchange.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A short secret for the origin-rule cases.</summary>
    private static byte[] ShortSecret { get; } = "sealed"u8.ToArray();

    /// <summary>One octet past the <c>TPM2B_SENSITIVE_DATA</c> bound, the smallest width the seal must refuse.</summary>
    private const int OneOverBound = Tpm2bSensitiveData.MaxSize + 1;

    /// <summary>
    /// "The sensitiveDataOrigin attribute of inPublic shall be SET if inSensitive.data is an Empty Buffer and
    /// CLEAR if inSensitive.data is not an Empty Buffer or the TPM shall return TPM_RC_ATTRIBUTES": a data
    /// object template with <c>sensitiveDataOrigin</c> SET and data supplied is refused — a data object's
    /// sensitiveDataOrigin "is required to be CLEAR" (Part 2, clause 8.3.3.5).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.1.1; Part 2, clause 8.3.3.5</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateDataObjectWithSensitiveDataOriginAndDataIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(CreateDataObjectWithSensitiveDataOriginAndDataIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        TpmaObject sealedAttributes = SealedDataAttributes(pool);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(ShortSecret, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateKeyedHashTemplate(HmacKeyHarness.NameAlg, sealedAttributes | TpmaObject.SENSITIVE_DATA_ORIGIN, TpmsKeyedHashParms.SealedData, authPolicy: default, pool);
        TpmResult<CreateResponse> result = await HmacKeyHarness.CreateAsync(tpm, registry, pool, parent.ObjectHandle.Value, inSensitive, template, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode, "A data object template with sensitiveDataOrigin SET and data supplied must be refused with TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// "If inSensitive.sensitive.data is an Empty Buffer, and both sign and decrypt are CLEAR in the attributes
    /// of inPublic, the TPM shall return TPM_RC_ATTRIBUTES. This would be a data object with no data" (keyedHash
    /// rule 1): a data object template with <c>sensitiveDataOrigin</c> SET and no data is refused.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 12.1.1; Part 2, clause 8.3.3.5</see>.
    /// </summary>
    [TestMethod]
    public async Task CreateDataObjectWithSensitiveDataOriginAndNoDataIsRefusedWithAttributes()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(CreateDataObjectWithSensitiveDataOriginAndNoDataIsRefusedWithAttributes), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        TpmaObject sealedAttributes = SealedDataAttributes(pool);

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(ReadOnlySpan<byte>.Empty, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateKeyedHashTemplate(HmacKeyHarness.NameAlg, sealedAttributes | TpmaObject.SENSITIVE_DATA_ORIGIN, TpmsKeyedHashParms.SealedData, authPolicy: default, pool);
        TpmResult<CreateResponse> result = await HmacKeyHarness.CreateAsync(tpm, registry, pool, parent.ObjectHandle.Value, inSensitive, template, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_ATTRIBUTES, 1), result.ResponseCode, "A data object template with sensitiveDataOrigin SET and no data must be refused with TPM_RC_ATTRIBUTES.");
    }

    /// <summary>
    /// <c>TPM2B_SENSITIVE_DATA</c> is bounded by <c>sizeof(TPMU_SENSITIVE_CREATE)</c> = <c>MAX_SYM_DATA</c> (128
    /// octets): sealing 129 octets fails the unmarshal with <c>TPM_RC_SIZE</c>.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clauses 11.1.13 and 11.1.14, Tables 169 and 170; Part 3, clause 12.1.1</see>.
    /// </summary>
    [TestMethod]
    public async Task SealOf129OctetsIsRefusedWithSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SealOf129OctetsIsRefusedWithSize), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> data = Filled(OneOverBound, pool);

        TpmRcConstants code = await SubmitSealFramedAsync(simulator, pool, parent.ObjectHandle.Value, data.Memory[..OneOverBound]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
            "Table 18: inSensitive is TPM2_Create()'s first parameter (index 0); sealing 129 octets must be refused with parameter-encoded TPM_RC_SIZE there.");
    }

    /// <summary>
    /// The bound is inclusive: 128 octets — the largest <c>TPM2B_SENSITIVE_DATA</c> — seal, load, and unseal
    /// byte for byte ("Size of outData is limited to be no more than 128 octets", Table 31).
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.14, Table 170; Part 3, clause 12.7, Table 31</see>.
    /// </summary>
    [TestMethod]
    public async Task SealOf128OctetsSucceedsAndUnseals()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SealOf128OctetsSucceedsAndUnseals), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        using IMemoryOwner<byte> secretOwner = Filled(Tpm2bSensitiveData.MaxSize, pool);
        ReadOnlyMemory<byte> secret = secretOwner.Memory[..Tpm2bSensitiveData.MaxSize];

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.ForSealedData(secret.Span, pool);
        using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(HmacKeyHarness.NameAlg, pool, noDa: true);
        TpmResult<CreateResponse> createResult = await HmacKeyHarness.CreateAsync(tpm, registry, pool, parent.ObjectHandle.Value, inSensitive, template, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(createResult.IsSuccess, $"Sealing 128 octets failed: '{createResult.ResponseCode}'.");
        using CreateResponse created = createResult.Value;

        TpmResult<LoadResponse> loadResult = await HmacKeyHarness.LoadAsync(
            tpm, registry, pool, parent.ObjectHandle.Value, created.OutPrivate, created.OutPublic, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(loadResult.IsSuccess, $"Load (128-octet seal) failed: '{loadResult.ResponseCode}'.");
        using LoadResponse loaded = loadResult.Value;

        UnsealInput unsealInput = UnsealInput.ForItem(loaded.ObjectHandle);
        using TpmPasswordSession itemAuth = TpmPasswordSession.CreateEmpty(pool);
        TpmResult<UnsealResponse> unsealResult = await TpmCommandExecutor.ExecuteAsync<UnsealResponse>(
            tpm, unsealInput, [itemAuth], null, pool, registry, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(unsealResult.IsSuccess, $"Unseal (128-octet seal) failed: '{unsealResult.ResponseCode}'.");
        using UnsealResponse unsealed = unsealResult.Value;

        Assert.IsTrue(unsealed.OutData.AsReadOnlySpan().SequenceEqual(secret.Span), "The 128 sealed octets must unseal byte for byte.");
    }

    /// <summary>
    /// The session-authorized <c>TPM2_Create()</c> decodes <c>inSensitive</c> itself and applies the same
    /// <c>MAX_SYM_DATA</c> bound: sealing 129 octets over a bound HMAC session is a structural failure of
    /// <c>inSensitive</c> itself, TPM2_Create()'s first parameter (Table 18, index 0), so the answer is
    /// parameter-encoded <c>TPM_RC_SIZE</c>, exactly as the plain password form answers the same malformation.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 2, clause 11.1.14, Table 170; Part 3, clauses 5.8 and 12.1; Part 2, clause 6.6.2, Table 15</see>.
    /// </summary>
    [TestMethod]
    public async Task SealOf129OctetsOverAnHmacSessionIsRefusedWithParameterEncodedSize()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(SealOf129OctetsOverAnHmacSessionIsRefusedWithParameterEncodedSize), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);
        (uint sessionHandle, TpmSession session) = await HmacKeyHarness.StartBoundHmacSessionAsync(tpm, registry, pool, parent.ObjectHandle.Value, TestContext.CancellationToken).ConfigureAwait(false);
        try
        {
            using(session)
            {
                using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(HmacKeyHarness.NameAlg, pool, noDa: true);
                using IMemoryOwner<byte> data = Filled(OneOverBound, pool);
                TpmRcConstants code = await SubmitSealOverSessionFramedAsync(tpm, registry, pool, session, parent, template, data.Memory[..OneOverBound]).ConfigureAwait(false);

                Assert.AreEqual(
                    HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_SIZE, 0), code,
                    "Table 18: inSensitive is TPM2_Create()'s first parameter (index 0); sealing 129 octets over a session must be refused with parameter-encoded TPM_RC_SIZE there.");
            }
        }
        finally
        {
            await HmacKeyHarness.FlushIfPresentAsync(tpm, registry, pool, sessionHandle, TestContext.CancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Reads the attribute word the sealed-data template builder produces.</summary>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The sealed-data <c>TPMA_OBJECT</c> word.</returns>
    private static TpmaObject SealedDataAttributes(BaseMemoryPool pool)
    {
        using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(HmacKeyHarness.NameAlg, pool, noDa: true);

        return template.PublicArea.ObjectAttributes;
    }

    /// <summary>Rents a buffer whose first <paramref name="length"/> octets are 0x5a.</summary>
    /// <param name="length">The length.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The rented buffer; the caller disposes it.</returns>
    private static IMemoryOwner<byte> Filled(int length, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(length);
        owner.Memory.Span[..length].Fill(0x5a);

        return owner;
    }

    /// <summary>
    /// Hand-frames a password-authorized <c>TPM2_Create()</c> of a sealed data object whose <c>inSensitive.data</c>
    /// width the typed carrier refuses to build — the whole command, header and password session included, so
    /// the refusal is proven independently of the executor's framing — submits it on the raw transport, and
    /// returns the response code.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="data">The data to seal.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSealFramedAsync(TpmSimulator simulator, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> data)
    {
        using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(HmacKeyHarness.NameAlg, pool, noDa: true);
        int publicSize = template.GetSerializedSize();
        int size = HmacKeyHarness.SensitiveCreateSerializedSize(0, data.Length) + publicSize + sizeof(ushort) + sizeof(uint);
        using IMemoryOwner<byte> parameters = pool.Rent(size);

        var writer = new TpmWriter(parameters.Memory.Span[..size]);
        HmacKeyHarness.WriteSensitiveCreate(ref writer, ReadOnlySpan<byte>.Empty, data.Span);
        template.WriteTo(ref writer);
        writer.WriteUInt16(0);
        writer.WriteUInt32(0);

        return await SubmitCreateParametersAsync(simulator, pool, parentHandle, parameters.Memory[..size]).ConfigureAwait(false);
    }

    /// <summary>
    /// A <c>TPM2_Create()</c> whose <c>inSensitive.data</c> declares more octets than the frame carries is a
    /// truncated frame, refused at unmarshal with <c>TPM_RC_INSUFFICIENT</c> — an answer on the wire, never an
    /// escape from the simulator's response contract.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.8.2, Table 2; Part 2, clause 11.1.14, Table 170</see>.
    /// </summary>
    [TestMethod]
    public async Task ATruncatedInSensitiveIsRefusedWithInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ATruncatedInSensitiveIsRefusedWithInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //TPMS_SENSITIVE_CREATE declaring a 10-octet data field of which only two octets follow, and nothing after.
        const int DeclaredDataLength = 10;
        const int PresentDataLength = 2;
        int interior = (sizeof(ushort) + 0) + (sizeof(ushort) + DeclaredDataLength);
        int size = sizeof(ushort) + interior - (DeclaredDataLength - PresentDataLength);
        using IMemoryOwner<byte> parameters = pool.Rent(size);
        var writer = new TpmWriter(parameters.Memory.Span[..size]);
        writer.WriteUInt16((ushort)interior);
        writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
        writer.WriteUInt16(DeclaredDataLength);
        writer.WriteUInt16(0x5a5a);

        TpmRcConstants code = await SubmitCreateParametersAsync(simulator, pool, parent.ObjectHandle.Value, parameters.Memory[..size]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 0), code,
            "Table 18: inSensitive is TPM2_Create()'s first parameter (index 0); a truncated inSensitive must be refused with parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// A <c>TPM2_Create()</c> whose <c>inPublic</c> declares more octets than the frame carries is a truncated
    /// frame, refused at unmarshal with <c>TPM_RC_INSUFFICIENT</c> — an answer on the wire, never an escape from
    /// the simulator's response contract.
    /// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Part 3, clause 5.8.2, Table 2; Part 2, clause 12.2.3.5, Table 229</see>.
    /// </summary>
    [TestMethod]
    public async Task ATruncatedInPublicIsRefusedWithInsufficient()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        using TpmSimulator simulator = await HmacKeyHarness.CreateOperationalAsync(nameof(ATruncatedInPublicIsRefusedWithInsufficient), pool, TestContext.CancellationToken).ConfigureAwait(false);
        using TpmDevice tpm = TpmDevice.Create(simulator.SubmitAsync, BaseMemoryPool.Shared, TestEntropy.NewCounterStream());
        TpmResponseRegistry registry = HmacKeyHarness.CreateRegistry();

        using CreatePrimaryResponse parent = await HmacKeyHarness.CreateStorageParentAsync(tpm, registry, pool, TestContext.CancellationToken).ConfigureAwait(false);

        //A well-formed empty inSensitive, then a TPM2B_PUBLIC declaring eight octets more than its body carries.
        const int OverDeclaredOctets = 8;
        using Tpm2bPublic template = Tpm2bPublic.CreateSealedDataTemplate(HmacKeyHarness.NameAlg, pool, noDa: true);
        int publicSize = template.GetSerializedSize();
        using IMemoryOwner<byte> marshaledTemplate = pool.Rent(publicSize);
        var templateWriter = new TpmWriter(marshaledTemplate.Memory.Span[..publicSize]);
        template.WriteTo(ref templateWriter);

        int size = HmacKeyHarness.SensitiveCreateSerializedSize(0, 0) + publicSize;
        using IMemoryOwner<byte> parameters = pool.Rent(size);
        var writer = new TpmWriter(parameters.Memory.Span[..size]);
        HmacKeyHarness.WriteSensitiveCreate(ref writer, ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
        writer.WriteUInt16((ushort)(publicSize - sizeof(ushort) + OverDeclaredOctets));
        writer.WriteBytes(marshaledTemplate.Memory.Span[sizeof(ushort)..publicSize]);

        TpmRcConstants code = await SubmitCreateParametersAsync(simulator, pool, parent.ObjectHandle.Value, parameters.Memory[..size]).ConfigureAwait(false);

        Assert.AreEqual(
            HmacKeyHarness.ParameterEncodedRc(TpmRcConstants.TPM_RC_INSUFFICIENT, 1), code,
            "Table 18: inPublic is TPM2_Create()'s second parameter (index 1); a truncated inPublic must be refused with parameter-encoded TPM_RC_INSUFFICIENT there.");
    }

    /// <summary>
    /// Frames a password-authorized <c>TPM2_Create()</c> — header, <c>@parentHandle</c>, an empty
    /// <c>TPM_RS_PW</c> session block — around a caller-marshaled parameter area, submits it on the raw
    /// transport, and returns the response code; the header's size is the frame's true length, so any
    /// truncation the parameters carry is interior to the command.
    /// </summary>
    /// <param name="simulator">The simulator.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="parentHandle">The storage parent handle.</param>
    /// <param name="parameters">The marshaled parameter area.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitCreateParametersAsync(TpmSimulator simulator, BaseMemoryPool pool, uint parentHandle, ReadOnlyMemory<byte> parameters)
    {
        const int SessionBlockSize = sizeof(uint) + sizeof(ushort) + sizeof(byte) + sizeof(ushort);
        int length = TpmHeader.HeaderSize + sizeof(uint) + sizeof(uint) + SessionBlockSize + parameters.Length;
        using IMemoryOwner<byte> owner = pool.Rent(length);

        var writer = new TpmWriter(owner.Memory.Span[..length]);
        var header = new TpmHeader((ushort)TpmStConstants.TPM_ST_SESSIONS, (uint)length, (uint)TpmCcConstants.TPM_CC_Create);
        header.WriteTo(ref writer);
        writer.WriteUInt32(parentHandle);
        writer.WriteUInt32(SessionBlockSize);
        writer.WriteUInt32((uint)TpmRh.TPM_RH_PW);
        writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
        writer.WriteByte((byte)TpmaSession.CONTINUE_SESSION);
        writer.WriteTpm2b(ReadOnlySpan<byte>.Empty);
        writer.WriteBytes(parameters.Span);

        TpmResult<TpmResponse> submitResult = await simulator.SubmitAsync(owner.Memory[..length], pool, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(submitResult.IsSuccess, "The hand-framed TPM2_Create() must reach the simulator.");

        using TpmResponse response = submitResult.Value;
        var reader = new TpmReader(response.AsReadOnlySpan());
        TpmHeader responseHeader = TpmHeader.Parse(ref reader);

        return (TpmRcConstants)responseHeader.Code;
    }

    /// <summary>
    /// Submits a session-authorized <c>TPM2_Create()</c> of a sealed data object whose <c>inSensitive.data</c>
    /// width the typed carrier refuses to build, through the production executor with a hand-marshaled
    /// <c>inSensitive</c>, and returns the response code.
    /// </summary>
    /// <param name="tpm">The TPM device.</param>
    /// <param name="registry">The response codec registry.</param>
    /// <param name="pool">The memory pool.</param>
    /// <param name="session">The bound HMAC session authorizing the parent.</param>
    /// <param name="parent">The storage parent.</param>
    /// <param name="template">The sealed-data template.</param>
    /// <param name="data">The data to seal.</param>
    /// <returns>The response code.</returns>
    private async Task<TpmRcConstants> SubmitSealOverSessionFramedAsync(
        TpmDevice tpm, TpmResponseRegistry registry, BaseMemoryPool pool, TpmSession session, CreatePrimaryResponse parent, Tpm2bPublic template, ReadOnlyMemory<byte> data)
    {
        var input = new HmacKeyHarness.RawSensitiveCreateInput(parent.ObjectHandle.Value, ReadOnlyMemory<byte>.Empty, data, template);
        TpmResult<CreateResponse> result = await TpmCommandExecutor.ExecuteAsync<CreateResponse>(
            tpm, input, [session], [parent.Name.AsReadOnlyMemory()], pool, registry, TestContext.CancellationToken).ConfigureAwait(false);

        return result.ResponseCode;
    }
}
