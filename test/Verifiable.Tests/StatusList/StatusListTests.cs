using System.Buffers;
using Verifiable.Core.StatusList;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusListType"/>.
/// </summary>
[TestClass]
internal sealed class StatusListTests
{
    /// <summary>
    /// Gets the default capacity for small status lists used in tests.
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
    /// Gets the example aggregation URI used for testing purposes.
    /// </summary>
    private string ExampleAggregationUri { get; } = StatusListTestConstants.ExampleAggregationUri;
    
    /// <summary>
    /// Gets the one-bit compressed hexadecimal string used for status list testing.
    /// </summary>
    private string OneBitCompressedHex { get; } = StatusListTestConstants.OneBitCompressedHex;
    
    /// <summary>
    /// Gets the two-bit compressed hexadecimal string used for status list testing.
    /// </summary>
    private string TwoBitCompressedHex { get; } = StatusListTestConstants.TwoBitCompressedHex;
    
    /// <summary>
    /// Gets a shared memory pool for efficient allocation and reuse of byte buffers.
    /// </summary>
    /// <remarks>The shared memory pool is thread-safe and intended for high-performance scenarios where
    /// frequent allocation and deallocation of byte arrays is required. Using the shared pool helps reduce memory
    /// fragmentation and improves application performance by reusing buffers.</remarks>
    private static MemoryPool<byte> Pool => MemoryPool<byte>.Shared;


    [TestMethod]
    public void CreateOneBitListSetsAndGetsCorrectly()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        list[0] = StatusTypes.Invalid;
        list[1] = StatusTypes.Valid;
        list[7] = StatusTypes.Invalid;

        Assert.AreEqual(StatusTypes.Invalid, list[0]);
        Assert.AreEqual(StatusTypes.Valid, list[1]);
        Assert.AreEqual(StatusTypes.Invalid, list[7]);
    }


    [TestMethod]
    public void CreateTwoBitListSetsAndGetsCorrectly()
    {
        using var list = StatusListType.Create(12, StatusListBitSize.TwoBits, Pool);
        list[0] = StatusTypes.Invalid;
        list[1] = StatusTypes.Suspended;
        list[2] = StatusTypes.Valid;
        list[3] = StatusTypes.ApplicationSpecific03;

        Assert.AreEqual(StatusTypes.Invalid, list[0]);
        Assert.AreEqual(StatusTypes.Suspended, list[1]);
        Assert.AreEqual(StatusTypes.Valid, list[2]);
        Assert.AreEqual(StatusTypes.ApplicationSpecific03, list[3]);
    }


    [TestMethod]
    public void CreateFourBitListSetsAndGetsCorrectly()
    {
        using var list = StatusListType.Create(8, StatusListBitSize.FourBits, Pool);
        list[0] = 0x0A;
        list[1] = 0x05;

        Assert.AreEqual((byte)0x0A, list[0]);
        Assert.AreEqual((byte)0x05, list[1]);
    }


    [TestMethod]
    public void CreateEightBitListSetsAndGetsCorrectly()
    {
        using var list = StatusListType.Create(4, StatusListBitSize.EightBits, Pool);
        list[0] = 0xFF;
        list[1] = (byte)SuspendedCredentialIndex;

        Assert.AreEqual((byte)0xFF, list[0]);
        Assert.AreEqual((byte)SuspendedCredentialIndex, list[1]);
    }


    [TestMethod]
    public void OneBitSpecVectorRawBytesMatchSpec()
    {
        //Section 4.1: status values [1,0,0,1,1,1,0,1, 1,1,0,0,0,1,0,1] = bytes [0xB9, 0xA3].
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        list[0] = 1; list[3] = 1; list[4] = 1; list[5] = 1; list[7] = 1;
        list[8] = 1; list[9] = 1; list[13] = 1; list[15] = 1;

        ReadOnlySpan<byte> raw = list.AsSpan();
        Assert.AreEqual((byte)0xB9, raw[0]);
        Assert.AreEqual((byte)0xA3, raw[1]);
    }


    [TestMethod]
    public void TwoBitSpecVectorRawBytesMatchSpec()
    {
        //Section 4.1: byte array [0xC9, 0x44, 0xF9].
        using var list = StatusListType.Create(12, StatusListBitSize.TwoBits, Pool);
        list[0] = StatusTypes.Invalid; list[1] = StatusTypes.Suspended;
        list[2] = StatusTypes.Valid; list[3] = StatusTypes.ApplicationSpecific03;
        list[4] = StatusTypes.Valid; list[5] = StatusTypes.Invalid;
        list[6] = StatusTypes.Valid; list[7] = StatusTypes.Invalid;
        list[8] = StatusTypes.Invalid; list[9] = StatusTypes.Suspended;
        list[10] = StatusTypes.ApplicationSpecific03; list[11] = StatusTypes.ApplicationSpecific03;

        ReadOnlySpan<byte> raw = list.AsSpan();
        Assert.AreEqual((byte)0xC9, raw[0]);
        Assert.AreEqual((byte)0x44, raw[1]);
        Assert.AreEqual((byte)0xF9, raw[2]);
    }


    [TestMethod]
    public void CompressDecompressRoundTripsOneBit()
    {
        using var original = StatusListType.Create(MediumListCapacity, StatusListBitSize.OneBit, Pool);
        original[0] = StatusTypes.Invalid;
        original[SuspendedCredentialIndex] = StatusTypes.Invalid;
        original[99] = StatusTypes.Invalid;

        byte[] compressed = original.Compress();
        using var restored = StatusListType.FromCompressed(compressed, StatusListBitSize.OneBit, Pool);

        Assert.AreEqual(original[0], restored[0]);
        Assert.AreEqual(original[SuspendedCredentialIndex], restored[SuspendedCredentialIndex]);
        Assert.AreEqual(original[99], restored[99]);
        Assert.AreEqual(original[50], restored[50]);
    }


    [TestMethod]
    public void DecodesSpecOneBitCompressedVector()
    {
        //Section 4.1: compressed form from the spec.
        byte[] specCompressed = Convert.FromHexString(OneBitCompressedHex);
        using var list = StatusListType.FromCompressed(specCompressed, StatusListBitSize.OneBit, Pool);

        Assert.AreEqual((byte)1, list[0]);
        Assert.AreEqual((byte)0, list[1]);
        Assert.AreEqual((byte)0, list[2]);
        Assert.AreEqual((byte)1, list[3]);
        Assert.AreEqual((byte)1, list[4]);
        Assert.AreEqual((byte)1, list[5]);
        Assert.AreEqual((byte)0, list[6]);
        Assert.AreEqual((byte)1, list[7]);
    }


    [TestMethod]
    public void DecodesSpecTwoBitCompressedVector()
    {
        //Section 4.1: compressed form from the spec.
        byte[] specCompressed = Convert.FromHexString(TwoBitCompressedHex);
        using var list = StatusListType.FromCompressed(specCompressed, StatusListBitSize.TwoBits, Pool);

        Assert.AreEqual(StatusTypes.Invalid, list[0]);
        Assert.AreEqual(StatusTypes.Suspended, list[1]);
        Assert.AreEqual(StatusTypes.Valid, list[2]);
        Assert.AreEqual(StatusTypes.ApplicationSpecific03, list[3]);
    }


    [TestMethod]
    public void FromRawCreatesListFromUncompressedBytes()
    {
        byte[] raw = [0xB9, 0xA3];
        using var list = StatusListType.FromRaw(raw, StatusListBitSize.OneBit, Pool);

        Assert.AreEqual((byte)1, list[0]);
        Assert.AreEqual((byte)0, list[1]);
        Assert.AreEqual(SmallListCapacity, list.Capacity);
    }


    [TestMethod]
    public void CapacityReflectsBitSize()
    {
        using var oneBit = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        using var twoBit = StatusListType.Create(SmallListCapacity, StatusListBitSize.TwoBits, Pool);
        using var fourBit = StatusListType.Create(SmallListCapacity, StatusListBitSize.FourBits, Pool);
        using var eightBit = StatusListType.Create(SmallListCapacity, StatusListBitSize.EightBits, Pool);

        Assert.AreEqual(SmallListCapacity, oneBit.Capacity);
        Assert.AreEqual(SmallListCapacity, twoBit.Capacity);
        Assert.AreEqual(SmallListCapacity, fourBit.Capacity);
        Assert.AreEqual(SmallListCapacity, eightBit.Capacity);
    }


    [TestMethod]
    public void IndexerGetThrowsForNegativeIndex()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = list[-1]);
    }


    [TestMethod]
    public void IndexerGetThrowsForOutOfBoundsIndex()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => _ = list[SmallListCapacity]);
    }


    [TestMethod]
    public void IndexerSetThrowsForValueExceedingBitSize()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => list[0] = 2);
    }


    [TestMethod]
    public void EqualityForIdenticalLists()
    {
        using var a = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        using var b = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        a[0] = StatusTypes.Invalid;
        b[0] = StatusTypes.Invalid;

        Assert.AreEqual(a, b);
        Assert.IsTrue(a == b);
    }


    [TestMethod]
    public void InequalityForDifferentData()
    {
        using var a = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        using var b = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        a[0] = StatusTypes.Invalid;
        b[0] = StatusTypes.Valid;

        Assert.AreNotEqual(a, b);
        Assert.IsTrue(a != b);
    }


    [TestMethod]
    public void InequalityForDifferentBitSize()
    {
        using var a = StatusListType.Create(8, StatusListBitSize.OneBit, Pool);
        using var b = StatusListType.Create(8, StatusListBitSize.TwoBits, Pool);

        Assert.AreNotEqual(a, b);
    }


    [TestMethod]
    public void DisposeReleasesMemory()
    {
        var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        list.Dispose();

        Assert.ThrowsExactly<ObjectDisposedException>(() => _ = list[0]);
    }


    [TestMethod]
    public void DoubleDisposeDoesNotThrow()
    {
        var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        list.Dispose();
        list.Dispose();
    }


    [TestMethod]
    public void AsSpanReturnsRawData()
    {
        using var list = StatusListType.FromRaw([0xB9, 0xA3], StatusListBitSize.OneBit, Pool);

        ReadOnlySpan<byte> span = list.AsSpan();

        Assert.AreEqual(2, span.Length);
        Assert.AreEqual((byte)0xB9, span[0]);
        Assert.AreEqual((byte)0xA3, span[1]);
    }


    [TestMethod]
    public void AggregationUriCanBeSet()
    {
        using var list = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        list.AggregationUri = ExampleAggregationUri;

        Assert.AreEqual(ExampleAggregationUri, list.AggregationUri);
    }


    [TestMethod]
    public void GetHashCodeConsistentForEqualLists()
    {
        using var a = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        using var b = StatusListType.Create(SmallListCapacity, StatusListBitSize.OneBit, Pool);
        a[5] = StatusTypes.Invalid;
        b[5] = StatusTypes.Invalid;

        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
    }   
}