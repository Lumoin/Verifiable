using System;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Contract tests for the shared status-list bit core that must hold identically under
/// both <see cref="BitOrder"/> values. The IETF Token Status List packs the first index at
/// the least-significant bit; the W3C Bitstring Status List packs it at the most-significant
/// (left-most) bit. Get/Set round-tripping, capacity and equality are bit-order-independent
/// and are exercised here under both orders, so the W3C (MSB) packing has direct core
/// coverage. The byte-exact, compressed spec vectors are inherently per-representation and
/// stay in the per-presentation suites; what is asserted here is only what the two orders
/// share, plus the two packing anchors and the cross-order distinctness.
/// </summary>
[TestClass]
internal sealed class StatusListBitOrderTests
{
    /// <summary>
    /// A capacity large enough that, for every bit size, entries span several bytes and the
    /// within-byte offset varies across the full range.
    /// </summary>
    private const int MultiByteCapacity = 40;


    [TestMethod]
    [DataRow(BitOrder.LeastSignificantFirst, StatusListBitSize.OneBit)]
    [DataRow(BitOrder.MostSignificantFirst, StatusListBitSize.OneBit)]
    [DataRow(BitOrder.LeastSignificantFirst, StatusListBitSize.TwoBits)]
    [DataRow(BitOrder.MostSignificantFirst, StatusListBitSize.TwoBits)]
    [DataRow(BitOrder.LeastSignificantFirst, StatusListBitSize.FourBits)]
    [DataRow(BitOrder.MostSignificantFirst, StatusListBitSize.FourBits)]
    [DataRow(BitOrder.LeastSignificantFirst, StatusListBitSize.EightBits)]
    [DataRow(BitOrder.MostSignificantFirst, StatusListBitSize.EightBits)]
    public void RoundTripsAcrossByteBoundariesUnderBothBitOrders(BitOrder bitOrder, StatusListBitSize bitSize)
    {
        using var list = StatusListType.Create(MultiByteCapacity, bitSize, BaseMemoryPool.Shared, bitOrder);
        int valueCount = 1 << (int)bitSize;

        //Walk every index so the within-byte offset cycles through all positions.
        for(int index = 0; index < MultiByteCapacity; index++)
        {
            list[index] = (byte)(index % valueCount);
        }

        for(int index = 0; index < MultiByteCapacity; index++)
        {
            Assert.AreEqual((byte)(index % valueCount), list[index]);
        }
    }


    [TestMethod]
    [DataRow(BitOrder.LeastSignificantFirst)]
    [DataRow(BitOrder.MostSignificantFirst)]
    public void CapacityIsIndependentOfBitOrder(BitOrder bitOrder)
    {
        using var list = StatusListType.Create(MultiByteCapacity, StatusListBitSize.TwoBits, BaseMemoryPool.Shared, bitOrder);

        Assert.AreEqual(MultiByteCapacity, list.Capacity);
    }


    [TestMethod]
    public void FirstIndexPacksAtLeastSignificantBitForIetfOrder()
    {
        using var list = StatusListType.Create(8, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.LeastSignificantFirst);
        list[0] = 1;

        Assert.AreEqual((byte)0x01, list.AsSpan()[0]);
    }


    [TestMethod]
    public void FirstIndexPacksAtMostSignificantBitForW3cOrder()
    {
        //W3C Bitstring Status List: "the first index, with a value of zero, is located at the left-most bit".
        using var list = StatusListType.Create(8, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.MostSignificantFirst);
        list[0] = 1;

        Assert.AreEqual((byte)0x80, list.AsSpan()[0]);
    }


    [TestMethod]
    public void SameLogicalStatusesDifferInRawBytesAcrossBitOrders()
    {
        using var ietf = StatusListType.Create(8, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.LeastSignificantFirst);
        using var w3c = StatusListType.Create(8, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.MostSignificantFirst);
        ietf[0] = 1; ietf[3] = 1;
        w3c[0] = 1; w3c[3] = 1;

        byte ietfByte = ietf.AsSpan()[0];
        byte w3cByte = w3c.AsSpan()[0];

        //LSB packs indices 0 and 3 as 0x01 | 0x08 = 0x09; MSB packs them as 0x80 | 0x10 = 0x90.
        Assert.AreEqual((byte)0x09, ietfByte);
        Assert.AreEqual((byte)0x90, w3cByte);
        Assert.AreNotEqual(ietfByte, w3cByte);
    }


    [TestMethod]
    public void ListsThatDifferOnlyInBitOrderAreNotEqual()
    {
        using var ietf = StatusListType.Create(MultiByteCapacity, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.LeastSignificantFirst);
        using var w3c = StatusListType.Create(MultiByteCapacity, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.MostSignificantFirst);

        Assert.AreNotEqual(ietf, w3c);
    }
}
