using System;
using CsCheck;
using Verifiable.Apdu;

namespace Verifiable.Tests.Apdu;

/// <summary>
/// Property-based tests (CsCheck) for the BER-TLV reader that every eMRTD parser is built on. The invariant is the
/// robustness contract: walking arbitrary or near-valid chip bytes as a sequence of TLV elements either completes
/// or is rejected with the reader's documented <see cref="InvalidOperationException"/> — never another exception
/// type (an out-of-range slice or index, an overflow) and never a non-terminating walk. As with the CESR codec, the
/// generator mutates known-valid material one edit at a time as well as sampling blind bytes, because a reader of
/// this shape rejects most blind input at the first length while a near-valid neighbour reaches the size arithmetic
/// where the defects lived.
/// </summary>
[TestClass]
internal sealed class ApduTlvPropertyTests
{
    /// <summary>Known-valid TLV byte strings (a one-byte tag, a SEQUENCE, and a two-byte tag) used as mutation seeds.</summary>
    private static string[] ValidTlvSeeds { get; } =
    [
        "61035F0100",
        "30060201000401FF",
        "7F6103800100"
    ];

    /// <summary>A one-edit mutation (substitute, truncate, or append) of a known-valid TLV byte string.</summary>
    private static Gen<byte[]> GenMutatedTlv { get; } =
        from seed in Gen.Int[0, ValidTlvSeeds.Length - 1]
        from mutation in Gen.Int[0, 2]
        from position in Gen.Int[0, 8]
        from value in Gen.Byte
        select Mutate(Convert.FromHexString(ValidTlvSeeds[seed]), mutation, position, value);

    /// <summary>Blind arbitrary bytes crossed with the near-valid mutations.</summary>
    private static Gen<byte[]> GenTlvBytes { get; } = Gen.OneOf(Gen.Byte.Array[0, 24], GenMutatedTlv);


    /// <summary>
    /// Walking arbitrary or mutated bytes as a sequence of TLV elements either completes or throws a
    /// <see cref="InvalidOperationException"/>; any other escaping exception fails the property with its shrunk seed.
    /// The walk always advances by at least a tag and a length byte per element, so it cannot spin.
    /// </summary>
    [TestMethod]
    public void TlvWalkRejectsMalformedInputOnlyWithInvalidOperationException() =>
        GenTlvBytes.Sample(WalksOrThrowsInvalidOperation);


    //Runs the TLV walk and reports whether it completed or threw the documented exception; any other exception
    //propagates so CsCheck fails the property with the offending exception and its shrunk seed.
    private static bool WalksOrThrowsInvalidOperation(byte[] bytes)
    {
        try
        {
            WalkTlv(bytes);

            return true;
        }
        catch(InvalidOperationException)
        {
            return true;
        }
    }


    //Walks the buffer as consecutive TLV elements: tag, length, then the length's value bytes, until exhausted.
    private static void WalkTlv(byte[] bytes)
    {
        var reader = new ApduReader(bytes);
        while(!reader.IsEmpty)
        {
            _ = reader.ReadTag();
            int length = reader.ReadTlvLength();
            _ = reader.ReadBytes(length);
        }
    }


    //Applies a single edit to a known-valid byte string: substitute the byte at a position, truncate to a position,
    //or append a byte. A position past the end degenerates to an append.
    private static byte[] Mutate(byte[] data, int mutation, int position, byte value)
    {
        int clamped = Math.Min(position, data.Length);

        return mutation switch
        {
            0 when clamped < data.Length => Substitute(data, clamped, value),
            1 => data[..clamped],
            _ => [.. data, value]
        };
    }


    //Returns a copy of the data with the byte at the given index replaced.
    private static byte[] Substitute(byte[] data, int index, byte value)
    {
        byte[] copy = [.. data];
        copy[index] = value;

        return copy;
    }
}
