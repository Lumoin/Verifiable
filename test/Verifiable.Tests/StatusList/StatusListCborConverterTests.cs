using System.Buffers;
using Lumoin.Veritas.Cbor;
using Lumoin.Base;
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
    private DateTimeOffset BaseTime { get; } = StatusListTestConstants.BaseTime;

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
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    [TestMethod]
    public void OneBitSpecVectorDeserializesCorrectly()
    {
        byte[] specBytes = Convert.FromHexString(OneBitCborHex);

        var converter = new StatusListCborConverter(Pool);
        var reader = new CborReader(specBytes, CborOptions.Lax);
        using var deserialized = converter.Read(reader);

        Assert.AreEqual(StatusListBitSize.OneBit, deserialized.BitSize);
        Assert.AreEqual(StatusTypes.Invalid, deserialized[0]);
        Assert.AreEqual(StatusTypes.Valid, deserialized[1]);
        Assert.AreEqual(StatusTypes.Valid, deserialized[2]);
        Assert.AreEqual(StatusTypes.Invalid, deserialized[3]);
    }


    [TestMethod]
    public void OneBitCborRoundTrips()
    {
        using var original = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        original[0] = StatusTypes.Invalid;
        original[3] = StatusTypes.Invalid;
        original[7] = StatusTypes.Invalid;

        var converter = new StatusListCborConverter(Pool);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        converter.Write(writer, original);
        byte[] encoded = buffer.WrittenSpan.ToArray();

        var reader = new CborReader(encoded, CborOptions.Lax);
        using var restored = converter.Read(reader);

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
        var reader = new CborReader(specBytes, CborOptions.Lax);
        using var deserialized = converter.Read(reader);

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

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        converter.Write(writer, original);
        byte[] encoded = buffer.WrittenSpan.ToArray();

        var reader = new CborReader(encoded, CborOptions.Lax);
        var decoded = converter.Read(reader);

        Assert.AreEqual(original, decoded);
    }


    [TestMethod]
    public void StatusListTokenRoundTrips()
    {
        using var list = StatusListType.Create(MediumListCapacity, StatusListBitSize.TwoBits, Pool, BitOrder.LeastSignificantFirst);
        list[0] = StatusTypes.Invalid;
        list[SuspendedCredentialIndex] = StatusTypes.Suspended;

        var expiration = BaseTime.AddHours(1);

        var original = new StatusListToken(ExampleTokenSubject, BaseTime, list)
        {
            ExpirationTime = expiration,
            TimeToLive = 3600
        };

        var converter = new StatusListTokenCborConverter(Pool);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        converter.Write(writer, original);
        byte[] encoded = buffer.WrittenSpan.ToArray();

        var reader = new CborReader(encoded, CborOptions.Lax);
        var decoded = converter.Read(reader);

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
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        var original = new StatusListToken(ExampleTokenSubject, BaseTime, list);

        var converter = new StatusListTokenCborConverter(Pool);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        converter.Write(writer, original);
        byte[] encoded = buffer.WrittenSpan.ToArray();

        var reader = new CborReader(encoded, CborOptions.Lax);
        var decoded = converter.Read(reader);

        Assert.AreEqual(original.Subject, decoded.Subject);
        Assert.AreEqual(original.IssuedAt, decoded.IssuedAt);
        Assert.IsNull(decoded.ExpirationTime);
        Assert.IsNull(decoded.TimeToLive);

        decoded.StatusList.Dispose();
    }


    /// <summary>
    /// "ttl: RECOMMENDED. … The value of the claim MUST be a positive number encoded in JSON as a
    /// number." — the JSON tier's converter already refuses a non-positive <c>ttl</c> on read; the CWT
    /// tier's own read must refuse the same value for symmetry, rather than accepting on the wire what
    /// the model itself (since a non-positive <c>ttl</c> is refused at construction) could never have
    /// written.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public void StatusListTokenWithNonPositiveTimeToLiveThrowsCborContentException()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        byte[] compressed = list.Compress();

        //Map keys are written in ascending numeric order (2, 6, 65533, 65534), as
        //CborConformanceMode.RfcCanonical requires.
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(4);
        writer.WriteInt32(StatusListCborConstants.Subject);
        writer.WriteTextString(ExampleTokenSubject);
        writer.WriteInt32(StatusListCborConstants.IssuedAt);
        writer.WriteInt64(BaseTime.ToUnixTimeSeconds());
        writer.WriteInt32(StatusListCborConstants.StatusList);
        writer.WriteStartMap(2);
        writer.WriteTextString(StatusListCborConstants.Bits);
        writer.WriteInt32((int)StatusListBitSize.OneBit);
        writer.WriteTextString(StatusListCborConstants.List);
        writer.WriteByteString(compressed);
        writer.WriteEndMap();
        writer.WriteInt32(StatusListCborConstants.TimeToLive);
        writer.WriteInt64(0);
        writer.WriteEndMap();
        byte[] encoded = buffer.WrittenSpan.ToArray();

        var converter = new StatusListTokenCborConverter(Pool);
        var reader = new CborReader(encoded, CborOptions.Lax);

        Assert.ThrowsExactly<CborContentException>(() => converter.Read(reader));
    }


    [TestMethod]
    public void StatusListMissingBitsThrowsCborContentException()
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("lst");
        writer.WriteByteString([0x00]);
        writer.WriteEndMap();
        byte[] encoded = buffer.WrittenSpan.ToArray();

        var converter = new StatusListCborConverter(Pool);
        var reader = new CborReader(encoded, CborOptions.Lax);

        Assert.ThrowsExactly<CborContentException>(() =>
            converter.Read(reader));
    }


    [TestMethod]
    public void StatusListMissingLstThrowsCborContentException()
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("bits");
        writer.WriteInt32(1);
        writer.WriteEndMap();
        byte[] encoded = buffer.WrittenSpan.ToArray();

        var converter = new StatusListCborConverter(Pool);
        var reader = new CborReader(encoded, CborOptions.Lax);

        Assert.ThrowsExactly<CborContentException>(() =>
            converter.Read(reader));
    }


    [TestMethod]
    public void ReferenceMissingIdxThrowsCborContentException()
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);
        writer.WriteStartMap(1);
        writer.WriteTextString("uri");
        writer.WriteTextString(ExampleTokenSubject);
        writer.WriteEndMap();
        byte[] encoded = buffer.WrittenSpan.ToArray();

        var converter = new StatusListReferenceCborConverter();
        var reader = new CborReader(encoded, CborOptions.Lax);

        Assert.ThrowsExactly<CborContentException>(() =>
            converter.Read(reader));
    }


    /// <summary>
    /// "Each index identifies a contiguous block of bits in the byte array, with the blocks being
    /// packed into bytes from the least significant bit (&quot;0&quot;) to the most significant bit
    /// (&quot;7&quot;)." A <see cref="StatusListType"/> packed <see cref="BitOrder.MostSignificantFirst"/>
    /// (the W3C Bitstring Status List's order) is refused rather than written as a Section 4.3 CBOR
    /// map with its bytes copied as-is.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-4.1">Token Status List, Section 4.1</see>.
    /// </summary>
    [TestMethod]
    public void WritingRefusesAListPackedMostSignificantFirst()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        list[0] = StatusTypes.Invalid;

        var converter = new StatusListCborConverter(Pool);
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.RfcCanonical);

        var thrown = Assert.ThrowsExactly<ArgumentException>(() =>
            converter.Write(writer, list));

        Assert.AreEqual("value", thrown.ParamName, "The refusal must name the parameter carrying the wrongly ordered list.");
        Assert.Contains("section-4.1", thrown.Message, StringComparison.OrdinalIgnoreCase, "The refusal must anchor to Section 4.1.");
    }
}
