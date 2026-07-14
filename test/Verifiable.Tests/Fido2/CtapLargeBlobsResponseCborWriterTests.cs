using System;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness and round-trip tests for <see cref="CtapLargeBlobsResponseCborWriter"/>: the smallest
/// response shape this library ships — exactly one Required member, always written.
/// </summary>
[TestClass]
internal sealed class CtapLargeBlobsResponseCborWriterTests
{
    /// <summary>A non-empty <c>config</c> substring encodes to a single-entry map, byte-exact.</summary>
    [TestMethod]
    public void WriteEncodesConfigToExactCanonicalBytes()
    {
        var response = new CtapLargeBlobsResponse(Config: new byte[] { 0xDE, 0xAD, 0xBE });

        TaggedMemory<byte> result = CtapLargeBlobsResponseCborWriter.Write(response);

        byte[] expected = [0xA1, 0x01, 0x43, 0xDE, 0xAD, 0xBE]; //map(1): config(0x01) -> bstr(3)

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// A ZERO-LENGTH <c>config</c> substring (the <c>offset == stored length</c> success case, trap 8)
    /// still writes the Required member — an empty byte string, never an omitted map entry.
    /// </summary>
    [TestMethod]
    public void WriteEncodesEmptyConfigAsEmptyByteString()
    {
        var response = new CtapLargeBlobsResponse(Config: ReadOnlyMemory<byte>.Empty);

        TaggedMemory<byte> result = CtapLargeBlobsResponseCborWriter.Write(response);

        byte[] expected = [0xA1, 0x01, 0x40]; //map(1): config(0x01) -> bstr(0)

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>A <see langword="null"/> response is rejected.</summary>
    [TestMethod]
    public void ThrowsOnNullResponse()
    {
        Assert.ThrowsExactly<ArgumentNullException>(() => CtapLargeBlobsResponseCborWriter.Write(null!));
    }


    /// <summary>The written bytes round-trip through the paired test-side reader, recovering <c>config</c> exactly.</summary>
    [TestMethod]
    public void RoundTripsThroughTestSideReader()
    {
        var written = new CtapLargeBlobsResponse(Config: new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 });

        TaggedMemory<byte> encoded = CtapLargeBlobsResponseCborWriter.Write(written);
        CtapLargeBlobsResponse decoded = CtapLargeBlobsResponseCborReader.Read(encoded.Memory);

        CollectionAssert.AreEqual(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 }, decoded.Config.ToArray());
    }


    /// <summary>The test-side reader rejects a response missing the Required <c>config</c> member.</summary>
    [TestMethod]
    public void ReaderThrowsWhenConfigMemberIsMissing()
    {
        byte[] emptyMap = [0xA0]; //map(0)

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapLargeBlobsResponseCborReader.Read(emptyMap));
    }
}
