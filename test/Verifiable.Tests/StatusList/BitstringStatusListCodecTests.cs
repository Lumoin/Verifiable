using System;
using System.Buffers;
using System.IO;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="BitstringStatusListCodec"/>, the W3C Bitstring Status List
/// <c>encodedList</c> codec (GZIP + Multibase base64url, most-significant-first packing).
/// </summary>
[TestClass]
internal sealed class BitstringStatusListCodecTests
{
    /// <summary>
    /// The <c>encodedList</c> from W3C Bitstring Status List Example 5 (a revocation status list
    /// credential with no entries set): a GZIP-compressed, Multibase base64url-encoded all-zero
    /// 16 KB bitstring.
    /// </summary>
    private const string SpecExample5EncodedList =
        "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA";

    /// <summary>
    /// The index referenced by Example 4's revocable credential within Example 5's list.
    /// </summary>
    private const int Example4Index = 94567;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;


    [TestMethod]
    public void DecodesSpecExample5AsAllZeroMinimumLengthList()
    {
        using var list = BitstringStatusListCodec.DecodeList(SpecExample5EncodedList, StatusListBitSize.OneBit, Pool);

        //Reading the last minimum-length index proves the expanded list holds at least the
        //required 131,072 entries; every read of zero proves nothing is revoked.
        Assert.AreEqual((byte)0, list[0]);
        Assert.AreEqual((byte)0, list[Example4Index]);
        Assert.AreEqual((byte)0, list[BitstringStatusListCodec.MinimumEntries - 1]);
    }


    [TestMethod]
    public void EncodedListHasMultibaseBase64UrlPrefix()
    {
        using var list = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);

        string encoded = BitstringStatusListCodec.EncodeList(list);

        Assert.AreEqual('u', encoded[0]);
    }


    [TestMethod]
    public void RoundTripPreservesStatuses()
    {
        using var original = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        original[0] = 1;
        original[5] = 1;
        original[Example4Index] = 1;
        original[BitstringStatusListCodec.MinimumEntries - 1] = 1;

        string encoded = BitstringStatusListCodec.EncodeList(original);
        using var restored = BitstringStatusListCodec.DecodeList(encoded, StatusListBitSize.OneBit, Pool);

        Assert.AreEqual(original.Capacity, restored.Capacity);
        Assert.AreEqual((byte)1, restored[0]);
        Assert.AreEqual((byte)0, restored[1]);
        Assert.AreEqual((byte)1, restored[5]);
        Assert.AreEqual((byte)1, restored[Example4Index]);
        Assert.AreEqual((byte)1, restored[BitstringStatusListCodec.MinimumEntries - 1]);
    }


    [TestMethod]
    public void RoundTripPreservesMostSignificantFirstPacking()
    {
        using var original = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        original[0] = 1;

        string encoded = BitstringStatusListCodec.EncodeList(original);
        using var restored = BitstringStatusListCodec.DecodeList(encoded, StatusListBitSize.OneBit, Pool);

        //Index 0 set under most-significant-first packing occupies the left-most bit (0x80).
        Assert.AreEqual((byte)0x80, restored.AsSpan()[0]);
    }


    [TestMethod]
    public void RoundTripPreservesStatusSizeTwoEntries()
    {
        using var original = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.TwoBits, Pool, BitOrder.MostSignificantFirst);
        original[0] = 3;
        original[1] = 2;
        original[BitstringStatusListCodec.MinimumEntries - 1] = 1;

        string encoded = BitstringStatusListCodec.EncodeList(original);
        using var restored = BitstringStatusListCodec.DecodeList(encoded, StatusListBitSize.TwoBits, Pool);

        Assert.AreEqual((byte)3, restored[0]);
        Assert.AreEqual((byte)2, restored[1]);
        Assert.AreEqual((byte)1, restored[BitstringStatusListCodec.MinimumEntries - 1]);
    }


    [TestMethod]
    public void EncodeRejectsLeastSignificantFirstBitstring()
    {
        using var lsb = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        Assert.ThrowsExactly<ArgumentException>(() => BitstringStatusListCodec.EncodeList(lsb));
    }


    [TestMethod]
    public void EncodeRejectsBitstringBelowMinimumEntries()
    {
        using var tooSmall = StatusListType.Create(64, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);

        Assert.ThrowsExactly<ArgumentException>(() => BitstringStatusListCodec.EncodeList(tooSmall));
    }


    [TestMethod]
    public void DecodeRejectsValueWithoutMultibasePrefix()
    {
        //A base64url body lacking the leading 'u' Multibase prefix is not a conforming encodedList.
        Assert.ThrowsExactly<FormatException>(() => BitstringStatusListCodec.DecodeList("H4sIAAAAAAAAA", StatusListBitSize.OneBit, Pool));
    }


    [TestMethod]
    public void DecodeRejectsNonGzipPayload()
    {
        //Valid Multibase base64url ('u' + "AAAA" => 0x000000) but not GZIP-framed.
        Assert.ThrowsExactly<InvalidDataException>(() => BitstringStatusListCodec.DecodeList("uAAAA", StatusListBitSize.OneBit, Pool));
    }
}
