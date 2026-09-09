using System;
using System.Buffers.Binary;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tests.Tpm;

/// <summary>
/// Proves the pool-custody contract for the ML-KEM/ML-DSA wire carriers: <see cref="Tpm2bPublicKeyMlKem"/>,
/// <see cref="Tpm2bPublicKeyMlDsa"/>, <see cref="Tpm2bSignatureMlDsa"/> and <see cref="TpmsSignatureHashMlDsa"/>
/// each rent their backing buffer from the <c>BaseMemoryPool</c> the caller passes to <c>Create</c>/<c>Parse</c> —
/// never a hidden default — and return it exactly once on disposal.
/// </summary>
[TestClass]
internal sealed class TpmMlKemMlDsaCarrierPoolCustodyTests
{
    /// <summary>A non-empty payload: a zero-length buffer resolves to a shared, dispose-immune sentinel that rents nothing, which would make a rent-count proof vacuous.</summary>
    private static byte[] Payload { get; } = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

    /// <summary>
    /// <see cref="Tpm2bPublicKeyMlKem.Create"/> rents from the passed pool and <see cref="Tpm2bPublicKeyMlKem.Dispose"/>
    /// returns it; <see cref="Tpm2bPublicKeyMlKem.Parse"/> over the written wire form does the same on its own rental.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyMlKemCreateAndParseRentFromThePassedPool()
    {
        using var trackingPool = new MeteredHousePool();

        using(Tpm2bPublicKeyMlKem created = Tpm2bPublicKeyMlKem.Create(Payload, trackingPool.Pool))
        {
            Assert.IsGreaterThan(0L, trackingPool.RentedCount, "Create must rent its backing buffer from the passed pool.");
            Assert.AreEqual(1L, trackingPool.OutstandingCount, "Exactly one carrier must be outstanding while it is held.");
        }

        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Disposing the created carrier must return its rental.");

        byte[] frame = new byte[sizeof(ushort) + Payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)Payload.Length);
        Payload.CopyTo(frame.AsSpan(sizeof(ushort)));

        long rentedBeforeParse = trackingPool.RentedCount;
        var reader = new TpmReader(frame);
        using(Tpm2bPublicKeyMlKem parsed = Tpm2bPublicKeyMlKem.Parse(ref reader, trackingPool.Pool))
        {
            Assert.IsGreaterThan(rentedBeforeParse, trackingPool.RentedCount, "Parse must rent its own backing buffer from the passed pool.");
            Assert.IsTrue(parsed.Buffer.SequenceEqual(Payload), "The parsed buffer must equal the written payload.");
        }

        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Disposing the parsed carrier must return its rental.");
    }

    /// <summary>
    /// <see cref="Tpm2bPublicKeyMlDsa.Create"/> rents from the passed pool and <see cref="Tpm2bPublicKeyMlDsa.Dispose"/>
    /// returns it; <see cref="Tpm2bPublicKeyMlDsa.Parse"/> over the written wire form does the same on its own rental.
    /// </summary>
    [TestMethod]
    public void Tpm2bPublicKeyMlDsaCreateAndParseRentFromThePassedPool()
    {
        using var trackingPool = new MeteredHousePool();

        using(Tpm2bPublicKeyMlDsa created = Tpm2bPublicKeyMlDsa.Create(Payload, trackingPool.Pool))
        {
            Assert.IsGreaterThan(0L, trackingPool.RentedCount, "Create must rent its backing buffer from the passed pool.");
            Assert.AreEqual(1L, trackingPool.OutstandingCount, "Exactly one carrier must be outstanding while it is held.");
        }

        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Disposing the created carrier must return its rental.");

        byte[] frame = new byte[sizeof(ushort) + Payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)Payload.Length);
        Payload.CopyTo(frame.AsSpan(sizeof(ushort)));

        long rentedBeforeParse = trackingPool.RentedCount;
        var reader = new TpmReader(frame);
        using(Tpm2bPublicKeyMlDsa parsed = Tpm2bPublicKeyMlDsa.Parse(ref reader, trackingPool.Pool))
        {
            Assert.IsGreaterThan(rentedBeforeParse, trackingPool.RentedCount, "Parse must rent its own backing buffer from the passed pool.");
            Assert.IsTrue(parsed.Buffer.SequenceEqual(Payload), "The parsed buffer must equal the written payload.");
        }

        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Disposing the parsed carrier must return its rental.");
    }

    /// <summary>
    /// <see cref="Tpm2bSignatureMlDsa.Create"/> rents from the passed pool and <see cref="Tpm2bSignatureMlDsa.Dispose"/>
    /// returns it; <see cref="Tpm2bSignatureMlDsa.Parse"/> over the written wire form does the same on its own rental.
    /// </summary>
    [TestMethod]
    public void Tpm2bSignatureMlDsaCreateAndParseRentFromThePassedPool()
    {
        using var trackingPool = new MeteredHousePool();

        using(Tpm2bSignatureMlDsa created = Tpm2bSignatureMlDsa.Create(Payload, trackingPool.Pool))
        {
            Assert.IsGreaterThan(0L, trackingPool.RentedCount, "Create must rent its backing buffer from the passed pool.");
            Assert.AreEqual(1L, trackingPool.OutstandingCount, "Exactly one carrier must be outstanding while it is held.");
        }

        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Disposing the created carrier must return its rental.");

        byte[] frame = new byte[sizeof(ushort) + Payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)Payload.Length);
        Payload.CopyTo(frame.AsSpan(sizeof(ushort)));

        long rentedBeforeParse = trackingPool.RentedCount;
        var reader = new TpmReader(frame);
        using(Tpm2bSignatureMlDsa parsed = Tpm2bSignatureMlDsa.Parse(ref reader, trackingPool.Pool))
        {
            Assert.IsGreaterThan(rentedBeforeParse, trackingPool.RentedCount, "Parse must rent its own backing buffer from the passed pool.");
            Assert.IsTrue(parsed.Buffer.SequenceEqual(Payload), "The parsed buffer must equal the written payload.");
        }

        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Disposing the parsed carrier must return its rental.");
    }

    /// <summary>
    /// <see cref="TpmsSignatureHashMlDsa.Parse"/> composes <see cref="Tpm2bSignatureMlDsa.Parse"/> internally, so
    /// its own carrier rents from the very same pool passed to it.
    /// </summary>
    [TestMethod]
    public void TpmsSignatureHashMlDsaParseRentsFromThePassedPool()
    {
        using var trackingPool = new MeteredHousePool();

        byte[] frame = new byte[sizeof(ushort) + sizeof(ushort) + Payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(frame, (ushort)TpmAlgIdConstants.TPM_ALG_SHA256);
        BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(sizeof(ushort)), (ushort)Payload.Length);
        Payload.CopyTo(frame.AsSpan(sizeof(ushort) + sizeof(ushort)));

        var reader = new TpmReader(frame);
        using(TpmsSignatureHashMlDsa parsed = TpmsSignatureHashMlDsa.Parse(ref reader, trackingPool.Pool))
        {
            Assert.IsGreaterThan(0L, trackingPool.RentedCount, "Parse must rent its composed signature carrier from the passed pool.");
            Assert.AreEqual(TpmAlgIdConstants.TPM_ALG_SHA256, parsed.HashAlg, "The pre-hash algorithm must round-trip.");
            Assert.IsTrue(parsed.Signature.Buffer.SequenceEqual(Payload), "The parsed signature bytes must equal the written payload.");
        }

        Assert.AreEqual(0L, trackingPool.OutstandingCount, "Disposing the parsed structure must return its composed carrier's rental.");
    }
}
