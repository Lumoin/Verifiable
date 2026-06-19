using System;
using System.Buffers;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Commands;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Non-hardware wire-format coverage for the TPM2_Create / TPM2_Load command surface: the new
/// <see cref="Tpm2bPrivate"/> blob round-trips, the command inputs serialize the handle and parameter
/// areas the executor frames, and the responses parse back. The behavioral round-trip
/// (CreatePrimary parent -> Create -> Load -> Sign) is covered against real hardware in the HwTpm tests;
/// these assertions need no TPM.
/// </summary>
[TestClass]
internal sealed class TpmCreateLoadTests
{
    private const uint ParentHandle = 0x8000_0001;

    //A stand-in for the opaque parent-wrapped private blob TPM2_Create returns.
    private static byte[] SampleBlob { get; } =
        [0x00, 0x20, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public void Tpm2bPrivateRoundTripsThroughTheWire()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using Tpm2bPrivate original = Tpm2bPrivate.Create(SampleBlob, pool);
        Assert.AreEqual(SampleBlob.Length, original.Length);
        Assert.AreEqual(sizeof(ushort) + SampleBlob.Length, original.SerializedSize);

        using IMemoryOwner<byte> owner = pool.Rent(original.SerializedSize);
        var writer = new TpmWriter(owner.Memory.Span);
        original.WriteTo(ref writer);
        Assert.AreEqual(original.SerializedSize, writer.Written);

        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        using Tpm2bPrivate parsed = Tpm2bPrivate.Parse(ref reader, pool);

        Assert.AreEqual(0, reader.Remaining);
        Assert.IsTrue(parsed.Span.SequenceEqual(SampleBlob));
    }

    [TestMethod]
    public void EmptyTpm2bPrivateRoundTrips()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        Tpm2bPrivate empty = Tpm2bPrivate.Empty;
        Assert.IsTrue(empty.IsEmpty);
        Assert.AreEqual(sizeof(ushort), empty.SerializedSize);

        using IMemoryOwner<byte> owner = pool.Rent(empty.SerializedSize);
        var writer = new TpmWriter(owner.Memory.Span);
        empty.WriteTo(ref writer);

        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        Tpm2bPrivate parsed = Tpm2bPrivate.Parse(ref reader, pool);

        Assert.IsTrue(parsed.IsEmpty);
        Assert.AreEqual(0, reader.Remaining);
    }

    [TestMethod]
    public void CreateInputSerializesHandleAndParameters()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using var input = CreateInput.ForEccSigningChild(
            ParentHandle,
            password: null,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256),
            pool);

        Assert.AreEqual(TpmCcConstants.TPM_CC_Create, input.CommandCode);

        int total = input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(total);
        var writer = new TpmWriter(owner.Memory.Span);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);

        //The serialized size must exactly account for what the handle + parameter writers produce.
        Assert.AreEqual(total, writer.Written);

        //Re-parse the wire image through an independent decode path, so a transposed field or a size
        //miscount inside WriteParameters fails here rather than only on hardware: parentHandle, then
        //inSensitive, inPublic, outsideInfo, creationPCR in spec order (Part 3, 12.1).
        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        Assert.AreEqual(ParentHandle, reader.ReadUInt32());

        using Tpm2bSensitiveCreate inSensitive = Tpm2bSensitiveCreate.Parse(ref reader, pool);
        using Tpm2bPublic inPublic = Tpm2bPublic.Parse(ref reader, pool);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECC, inPublic.PublicArea.Type);
        using Tpm2bData outsideInfo = Tpm2bData.Parse(ref reader, pool);
        Assert.IsTrue(outsideInfo.IsEmpty);
        using TpmlPcrSelection creationPcr = TpmlPcrSelection.Parse(ref reader, pool);
        Assert.AreEqual(sizeof(uint), creationPcr.GetSerializedSize());

        Assert.AreEqual(0, reader.Remaining);
    }

    [TestMethod]
    public void LoadInputRoundTripsPrivateAndPublic()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //The input owns the blob and public area it is built with; the redundant using locals satisfy CA2000
        //and are safe via idempotent disposal.
        using Tpm2bPrivate seedPrivate = Tpm2bPrivate.Create(SampleBlob, pool);
        using Tpm2bPublic seedPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256,
            TpmaObject.SIGN_ENCRYPT,
            TpmEccCurveConstants.TPM_ECC_NIST_P256,
            TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256));
        using var input = new LoadInput(ParentHandle, seedPrivate, seedPublic);

        Assert.AreEqual(TpmCcConstants.TPM_CC_Load, input.CommandCode);

        int total = input.GetSerializedSize();
        using IMemoryOwner<byte> owner = pool.Rent(total);
        var writer = new TpmWriter(owner.Memory.Span);
        input.WriteHandles(ref writer);
        input.WriteParameters(ref writer);
        Assert.AreEqual(total, writer.Written);

        //Re-read the wire image: parentHandle, then inPrivate (TPM2B_PRIVATE) and inPublic (TPM2B_PUBLIC).
        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        Assert.AreEqual(ParentHandle, reader.ReadUInt32());

        using Tpm2bPrivate inPrivate = Tpm2bPrivate.Parse(ref reader, pool);
        Assert.IsTrue(inPrivate.Span.SequenceEqual(SampleBlob));

        using Tpm2bPublic inPublic = Tpm2bPublic.Parse(ref reader, pool);
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECC, inPublic.PublicArea.Type);
        Assert.AreEqual(0, reader.Remaining);
    }

    [TestMethod]
    public void CreateResponseParsesFieldsInSpecOrder()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //Build a TPM2_Create response parameter image by hand and confirm CreateResponse.Parse reads the
        //five fields in the Part 3, 12.1 order — outPrivate FIRST, then outPublic. Both are size-prefixed
        //blobs, so a transposed read would silently misparse rather than throw; this pins the order without
        //hardware (no behavioral simulator exists for TPM2_Create).
        using IMemoryOwner<byte> owner = pool.Rent(1024);
        var writer = new TpmWriter(owner.Memory.Span);

        using(Tpm2bPrivate outPrivate = Tpm2bPrivate.Create(SampleBlob, pool))
        {
            outPrivate.WriteTo(ref writer);
        }

        using(Tpm2bPublic outPublic = Tpm2bPublic.CreateEccSigningTemplate(
            TpmAlgIdConstants.TPM_ALG_SHA256, TpmaObject.SIGN_ENCRYPT,
            TpmEccCurveConstants.TPM_ECC_NIST_P256, TpmtEccScheme.Ecdsa(TpmAlgIdConstants.TPM_ALG_SHA256)))
        {
            outPublic.WriteTo(ref writer);
        }

        WriteMinimalCreationData(ref writer, pool);   //creationData (TPM2B_CREATION_DATA).
        writer.WriteUInt16(0);                         //creationHash (empty TPM2B_DIGEST).
        TpmtTkCreation.Null.WriteTo(ref writer);       //creationTicket.

        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        using CreateResponse response = CreateResponse.Parse(ref reader, pool);

        Assert.IsTrue(response.OutPrivate.Span.SequenceEqual(SampleBlob), "outPrivate must be read first.");
        Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_ECC, response.OutPublic.PublicArea.Type);
        Assert.AreEqual(0, reader.Remaining);
    }

    //Writes a minimal valid TPM2B_CREATION_DATA: TPMS_CREATION_DATA = pcrSelect (TPML_PCR_SELECTION) +
    //pcrDigest (TPM2B_DIGEST) + locality (BYTE) + parentNameAlg (TPM_ALG_ID) + parentName (TPM2B_NAME) +
    //parentQualifiedName (TPM2B_NAME) + outsideInfo (TPM2B_DATA), all empty, wrapped in the TPM2B size.
    private static void WriteMinimalCreationData(ref TpmWriter writer, MemoryPool<byte> pool)
    {
        using IMemoryOwner<byte> inner = pool.Rent(64);
        var innerWriter = new TpmWriter(inner.Memory.Span);
        TpmlPcrSelection.Empty.WriteTo(ref innerWriter);
        innerWriter.WriteUInt16(0);
        innerWriter.WriteByte(0);
        innerWriter.WriteUInt16((ushort)TpmAlgIdConstants.TPM_ALG_NULL);
        innerWriter.WriteUInt16(0);
        innerWriter.WriteUInt16(0);
        innerWriter.WriteUInt16(0);

        writer.WriteUInt16((ushort)innerWriter.Written);
        writer.WriteBytes(inner.Memory.Span[..innerWriter.Written]);
    }

    [TestMethod]
    public void LoadResponseParsesHandleAndName()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        const uint ObjectHandle = 0x8000_00AB;
        ReadOnlySpan<byte> nameBytes = [0x00, 0x0B, 0xDE, 0xAD, 0xBE, 0xEF];

        //The response parameter area is a single TPM2B_NAME (UINT16 size + name octets); the object handle
        //arrives separately from the response handle area.
        using IMemoryOwner<byte> owner = pool.Rent(sizeof(ushort) + nameBytes.Length);
        var writer = new TpmWriter(owner.Memory.Span);
        writer.WriteUInt16((ushort)nameBytes.Length);
        writer.WriteBytes(nameBytes);

        var reader = new TpmReader(owner.Memory.Span[..writer.Written]);
        using LoadResponse response = LoadResponse.Parse(ref reader, TpmiDhObject.FromValue(ObjectHandle), pool);

        Assert.AreEqual(ObjectHandle, response.ObjectHandle.Value);
        Assert.IsTrue(response.Name.Span.SequenceEqual(nameBytes));
        Assert.AreEqual(0, reader.Remaining);
    }

    [TestMethod]
    public void CreateAndLoadCodecsHaveExpectedHandleShape()
    {
        //TPM2_Create returns no handle; TPM2_Load returns one (the transient object handle).
        Assert.AreEqual(0, TpmResponseCodec.CreateObject.OutHandleCount);
        Assert.IsTrue(TpmResponseCodec.CreateObject.HasResponseParameters);

        Assert.AreEqual(1, TpmResponseCodec.Load.OutHandleCount);
        Assert.IsTrue(TpmResponseCodec.Load.HasResponseParameters);
    }
}
