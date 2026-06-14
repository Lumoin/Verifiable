using System;
using System.Buffers;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="BitstringStatusListValidation"/>, the verifier-side status-reading portion
/// of the W3C Bitstring Status List Validate Algorithm (§3.2).
/// </summary>
[TestClass]
internal sealed class BitstringStatusListValidationTests
{
    private const int Example4Index = 94567;
    private static readonly DateTimeOffset Now = new(2024, 4, 6, 0, 0, 0, TimeSpan.Zero);
    private static readonly string[] RevocationPurposes = [BitstringStatusListConstants.RevocationPurpose];

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


    private static BitstringStatusListEntry RevocationEntry(int index) => new()
    {
        StatusPurpose = BitstringStatusListConstants.RevocationPurpose,
        StatusListIndex = index,
        StatusListCredential = "https://example.com/credentials/status/3"
    };


    [TestMethod]
    public void UnsetEntryReturnsValidThroughCodecRoundTrip()
    {
        using var list = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        string encoded = BitstringStatusListCodec.EncodeList(list);
        using var resolved = BitstringStatusListCodec.DecodeList(encoded, StatusListBitSize.OneBit, Pool);

        BitstringStatusListStatus result = BitstringStatusListValidation.GetStatus(RevocationEntry(Example4Index), resolved, RevocationPurposes, Now);

        Assert.IsTrue(result.IsValid);
        Assert.AreEqual((byte)0, result.Status);
        Assert.AreEqual(BitstringStatusListConstants.RevocationPurpose, result.Purpose);
    }


    [TestMethod]
    public void RevokedEntryReturnsInvalidThroughCodecRoundTrip()
    {
        using var list = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        list[Example4Index] = 1;
        string encoded = BitstringStatusListCodec.EncodeList(list);
        using var resolved = BitstringStatusListCodec.DecodeList(encoded, StatusListBitSize.OneBit, Pool);

        BitstringStatusListStatus result = BitstringStatusListValidation.GetStatus(RevocationEntry(Example4Index), resolved, RevocationPurposes, Now);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual((byte)1, result.Status);
    }


    [TestMethod]
    public void PurposeMismatchThrowsStatusVerification()
    {
        using var list = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        var entry = new BitstringStatusListEntry
        {
            StatusPurpose = BitstringStatusListConstants.SuspensionPurpose,
            StatusListIndex = Example4Index,
            StatusListCredential = "https://example.com/credentials/status/3"
        };

        var ex = Assert.ThrowsExactly<BitstringStatusListException>(() => BitstringStatusListValidation.GetStatus(entry, list, RevocationPurposes, Now));
        Assert.AreEqual(BitstringStatusListErrorType.StatusVerification, ex.ErrorType);
    }


    [TestMethod]
    public void ListBelowMinimumLengthThrowsStatusListLength()
    {
        //A 16-byte list holds only 128 one-bit entries, far below the 131,072 minimum.
        byte[] raw = new byte[16];
        using var shortList = StatusListType.FromRaw(raw, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);

        var ex = Assert.ThrowsExactly<BitstringStatusListException>(() => BitstringStatusListValidation.GetStatus(RevocationEntry(0), shortList, RevocationPurposes, Now));
        Assert.AreEqual(BitstringStatusListErrorType.StatusListLength, ex.ErrorType);
    }


    [TestMethod]
    public void IndexOutOfRangeThrowsRange()
    {
        using var list = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);

        var ex = Assert.ThrowsExactly<BitstringStatusListException>(() => BitstringStatusListValidation.GetStatus(RevocationEntry(list.Capacity), list, RevocationPurposes, Now));
        Assert.AreEqual(BitstringStatusListErrorType.Range, ex.ErrorType);
    }


    [TestMethod]
    public void ExpiredListThrowsStatusVerification()
    {
        using var list = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        DateTimeOffset validUntil = Now.AddDays(-1);

        var ex = Assert.ThrowsExactly<BitstringStatusListException>(() => BitstringStatusListValidation.GetStatus(RevocationEntry(Example4Index), list, RevocationPurposes, Now, validUntil: validUntil));
        Assert.AreEqual(BitstringStatusListErrorType.StatusVerification, ex.ErrorType);
    }


    [TestMethod]
    public void NotYetValidListThrowsStatusVerification()
    {
        using var list = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.OneBit, Pool, BitOrder.MostSignificantFirst);
        DateTimeOffset validFrom = Now.AddDays(1);

        var ex = Assert.ThrowsExactly<BitstringStatusListException>(() => BitstringStatusListValidation.GetStatus(RevocationEntry(Example4Index), list, RevocationPurposes, Now, validFrom: validFrom));
        Assert.AreEqual(BitstringStatusListErrorType.StatusVerification, ex.ErrorType);
    }


    [TestMethod]
    public void MessagePurposeResolvesMappedMessage()
    {
        using var list = StatusListType.Create(BitstringStatusListCodec.MinimumEntries, StatusListBitSize.TwoBits, Pool, BitOrder.MostSignificantFirst);
        list[0] = 2;
        var entry = new BitstringStatusListEntry
        {
            StatusPurpose = BitstringStatusListConstants.MessagePurpose,
            StatusListIndex = 0,
            StatusListCredential = "https://example.com/credentials/status/8",
            StatusSize = 2,
            StatusMessages =
            [
                new BitstringStatusMessage("0x0", "pending_review"),
                new BitstringStatusMessage("0x1", "accepted"),
                new BitstringStatusMessage("0x2", "rejected"),
                new BitstringStatusMessage("0x3", "withdrawn")
            ]
        };

        BitstringStatusListStatus result = BitstringStatusListValidation.GetStatus(entry, list, [BitstringStatusListConstants.MessagePurpose], Now);

        Assert.AreEqual((byte)2, result.Status);
        Assert.IsFalse(result.IsValid);
        Assert.AreEqual("rejected", result.Message);
    }
}
