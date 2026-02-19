using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Cbor;
using Verifiable.Cbor.StatusList;
using Verifiable.Core.StatusList;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for the Status List CBOR converters.
/// </summary>
[TestClass]
internal sealed class StatusListCborConverterTests
{
    /// <summary>
    /// Gets the capacity used for small status lists in tests.
    /// </summary>
    private int SmallListCapacity { get; } = StatusListTestConstants.SmallListCapacity;
    
    /// <summary>
    /// Gets the default capacity for a medium-sized list used in status list tests.
    /// </summary>
    private int MediumListCapacity { get; } = StatusListTestConstants.MediumListCapacity;
    
    /// <summary>
    /// Gets the index of the suspended credential used for testing purposes.
    /// </summary>
    private int SuspendedCredentialIndex { get; } = StatusListTestConstants.SuspendedCredentialIndex;
    
    /// <summary>
    /// Gets the example subject value used for token generation in test scenarios.
    /// </summary>
    /// <remarks>This property is intended for use in testing contexts where a consistent token subject is
    /// required. It is not intended for use in production code.</remarks>
    private string ExampleTokenSubject { get; } = StatusListTestConstants.ExampleTokenSubject;
    
    /// <summary>
    /// Gets the hexadecimal CBOR encoding of a one-bit status list for testing purposes.
    /// </summary>
    private string OneBitCborHex { get; } = StatusListTestConstants.OneBitCborHex;
    
    /// <summary>
    /// Gets the hexadecimal string representation of the two-bit CBOR value used for testing.
    /// </summary>
    private string TwoBitCborHex { get; } = StatusListTestConstants.TwoBitCborHex;
    
    /// <summary>
    /// Represents the base time used for test status calculations.
    /// </summary>
    /// <remarks>This value is typically set to a constant defined for test scenarios and should not be
    /// modified at runtime.</remarks>
    private readonly DateTimeOffset BaseTime = StatusListTestConstants.BaseTime;

    /// <summary>
    /// Gets or sets the test context for the current test run.
    /// </summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>
    /// Gets a shared memory pool for managing buffers of bytes.
    /// </summary>
    /// <remarks>The returned memory pool is a singleton instance that can be used to efficiently rent and
    /// return byte buffers. Using the shared pool helps reduce memory allocations and improve performance in scenarios
    /// that require temporary buffers.</remarks>
    private static MemoryPool<byte> Pool => MemoryPool<byte>.Shared;

    /// <summary>
    /// Provides the default options for CBOR serialization.
    /// </summary>
    private static readonly CborSerializerOptions Options = CborSerializerOptions.Default;


    [TestMethod]
    public void OneBitSpecVectorDeserializesCorrectly()
    {
        byte[] specBytes = Convert.FromHexString(OneBitCborHex);

        var converter = new StatusListCborConverter(Pool);
        var reader = new CborReader(specBytes, CborConformanceMode.Lax);
        using var deserialized = converter.Read(ref reader, typeof(StatusListType), Options);

        Assert.AreEqual(StatusListBitSize.OneBit, deserialized.BitSize);
        Assert.AreEqual(StatusTypes.Invalid, deserialized[0]);
        Assert.AreEqual(StatusTypes.Valid, deserialized[1]);
        Assert.AreEqual(StatusTypes.Valid, deserialized[2]);
        Assert.AreEqual(StatusTypes.Invalid, deserialized[3]);
    }


    [TestMethod]
    public void OneBitCborRoundTrips()
    {
        using var original = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        original[0] = StatusTypes.Invalid;
        original[3] = StatusTypes.Invalid;
        original[7] = StatusTypes.Invalid;

        var converter = new StatusListCborConverter(Pool);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        converter.Write(writer, original, Options);
        byte[] encoded = writer.Encode();

        var reader = new CborReader(encoded, CborConformanceMode.Lax);
        using var restored = converter.Read(ref reader, typeof(StatusListType), Options);

        Assert.AreEqual(StatusListBitSize.OneBit, restored.BitSize);
        Assert.AreEqual(StatusTypes.Invalid, restored[0]);
        Assert.AreEqual(StatusTypes.Valid, restored[1]);
        Assert.AreEqual(StatusTypes.Invalid, restored[3]);
        Assert.AreEqual(StatusTypes.Invalid, restored[7]);
    }


    [TestMethod]
    public void TwoBitSpecVectorDeserializesCorrectly()
    {
        byte[] specBytes = Convert.FromHexString(TwoBitCborHex);

        var converter = new StatusListCborConverter(Pool);
        var reader = new CborReader(specBytes, CborConformanceMode.Lax);
        using var deserialized = converter.Read(ref reader, typeof(StatusListType), Options);

        Assert.AreEqual(StatusListBitSize.TwoBits, deserialized.BitSize);
        Assert.AreEqual(StatusTypes.Invalid, deserialized[0]);
        Assert.AreEqual(StatusTypes.Suspended, deserialized[1]);
        Assert.AreEqual(StatusTypes.Valid, deserialized[2]);
        Assert.AreEqual(StatusTypes.ApplicationSpecific03, deserialized[3]);
    }


    [TestMethod]
    public void StatusListReferenceRoundTrips()
    {
        var converter = new StatusListReferenceCborConverter();
        var original = new StatusListReference(SuspendedCredentialIndex, ExampleTokenSubject);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        converter.Write(writer, original, Options);
        byte[] encoded = writer.Encode();

        var reader = new CborReader(encoded, CborConformanceMode.Lax);
        var decoded = converter.Read(ref reader, typeof(StatusListReference), Options);

        Assert.AreEqual(original, decoded);
    }


    [TestMethod]
    public void StatusListTokenRoundTrips()
    {
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.TwoBits, Pool);
        list[0] = StatusTypes.Invalid;
        list[SuspendedCredentialIndex] = StatusTypes.Suspended;

        var expiration = BaseTime.AddHours(1);

        var original = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            ExpirationTime = expiration,
            TimeToLive = 3600
        };

        var converter = new StatusListTokenCborConverter(Pool);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        converter.Write(writer, original, Options);
        byte[] encoded = writer.Encode();

        var reader = new CborReader(encoded, CborConformanceMode.Lax);
        var decoded = converter.Read(ref reader, typeof(StatusListToken), Options);

        Assert.AreEqual(original.Subject, decoded.Subject);
        Assert.AreEqual(original.IssuedAt, decoded.IssuedAt);
        Assert.AreEqual(original.ExpirationTime, decoded.ExpirationTime);
        Assert.AreEqual(original.TimeToLive, decoded.TimeToLive);
        Assert.AreEqual(StatusTypes.Invalid, decoded.StatusList[0]);
        Assert.AreEqual(StatusTypes.Suspended, decoded.StatusList[SuspendedCredentialIndex]);

        decoded.StatusList.Dispose();
    }


    [TestMethod]
    public void StatusListTokenWithoutOptionalClaimsRoundTrips()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);

        var original = new StatusListToken(ExampleTokenSubject, BaseTime, list);

        var converter = new StatusListTokenCborConverter(Pool);
        var writer = new CborWriter(CborConformanceMode.Canonical);
        converter.Write(writer, original, Options);
        byte[] encoded = writer.Encode();

        var reader = new CborReader(encoded, CborConformanceMode.Lax);
        var decoded = converter.Read(ref reader, typeof(StatusListToken), Options);

        Assert.AreEqual(original.Subject, decoded.Subject);
        Assert.AreEqual(original.IssuedAt, decoded.IssuedAt);
        Assert.IsNull(decoded.ExpirationTime);
        Assert.IsNull(decoded.TimeToLive);

        decoded.StatusList.Dispose();
    }


    [TestMethod]
    public void StatusListMissingBitsThrowsCborContentException()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("lst");
        writer.WriteByteString([0x00]);
        writer.WriteEndMap();
        byte[] encoded = writer.Encode();

        var converter = new StatusListCborConverter(Pool);
        var reader = new CborReader(encoded, CborConformanceMode.Lax);

        Assert.ThrowsExactly<CborContentException>(() =>
            converter.Read(ref reader, typeof(StatusListType), Options));
    }


    [TestMethod]
    public void StatusListMissingLstThrowsCborContentException()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("bits");
        writer.WriteInt32(1);
        writer.WriteEndMap();
        byte[] encoded = writer.Encode();

        var converter = new StatusListCborConverter(Pool);
        var reader = new CborReader(encoded, CborConformanceMode.Lax);

        Assert.ThrowsExactly<CborContentException>(() =>
            converter.Read(ref reader, typeof(StatusListType), Options));
    }


    [TestMethod]
    public void ReferenceMissingIdxThrowsCborContentException()
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("uri");
        writer.WriteTextString(ExampleTokenSubject);
        writer.WriteEndMap();
        byte[] encoded = writer.Encode();

        var converter = new StatusListReferenceCborConverter();
        var reader = new CborReader(encoded, CborConformanceMode.Lax);

        Assert.ThrowsExactly<CborContentException>(() =>
            converter.Read(ref reader, typeof(StatusListReference), Options));
    }    
}