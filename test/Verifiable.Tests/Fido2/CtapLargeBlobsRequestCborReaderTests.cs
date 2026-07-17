using System;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapLargeBlobsRequestCborReader"/>: round-tripping against the paired test-side
/// writer, the byte-exact REVERSED <c>pinUvAuthParam</c>/<c>pinUvAuthProtocol</c> wire order (trap 1),
/// <c>offset</c>'s nullable-not-throwing absence (trap 6/7), unknown-key tolerance (section 8's
/// forward-compatibility rule), and malformed/wrong-type negatives.
/// </summary>
[TestClass]
internal sealed class CtapLargeBlobsRequestCborReaderTests
{
    /// <summary>A request carrying only <c>offset</c> round-trips with every other member <see langword="null"/>.</summary>
    [TestMethod]
    public void RoundTripsOffsetOnly()
    {
        var written = new CtapLargeBlobsRequest(Offset: 0);

        TaggedMemory<byte> encoded = CtapLargeBlobsRequestCborWriter.Write(written);
        CtapLargeBlobsRequest decoded = CtapLargeBlobsRequestCborReader.Read(encoded.Memory);

        Assert.AreEqual(0, decoded.Offset);
        Assert.IsNull(decoded.Get);
        Assert.IsNull(decoded.Set);
        Assert.IsNull(decoded.Length);
        Assert.IsNull(decoded.PinUvAuthParam);
        Assert.IsNull(decoded.PinUvAuthProtocol);
    }


    /// <summary>
    /// A <c>get</c>-shaped request (<c>get</c>, <c>offset</c>) round-trips with <c>set</c>/<c>length</c>/
    /// the pinUvAuth pair left <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public void RoundTripsGetShapedRequest()
    {
        var written = new CtapLargeBlobsRequest(Get: 960, Offset: 17);

        TaggedMemory<byte> encoded = CtapLargeBlobsRequestCborWriter.Write(written);
        CtapLargeBlobsRequest decoded = CtapLargeBlobsRequestCborReader.Read(encoded.Memory);

        Assert.AreEqual(960, decoded.Get);
        Assert.AreEqual(17, decoded.Offset);
        Assert.IsNull(decoded.Set);
        Assert.IsNull(decoded.Length);
        Assert.IsNull(decoded.PinUvAuthParam);
        Assert.IsNull(decoded.PinUvAuthProtocol);
    }


    /// <summary>A request carrying all six members round-trips every value, including the byte-string members.</summary>
    [TestMethod]
    public void RoundTripsAllSixMembers()
    {
        var written = new CtapLargeBlobsRequest(
            Get: 100,
            Set: new byte[] { 0xAA, 0xBB, 0xCC },
            Offset: 512,
            Length: 4096,
            PinUvAuthParam: new byte[] { 0x11, 0x22, 0x33 },
            PinUvAuthProtocol: 2);

        TaggedMemory<byte> encoded = CtapLargeBlobsRequestCborWriter.Write(written);
        CtapLargeBlobsRequest decoded = CtapLargeBlobsRequestCborReader.Read(encoded.Memory);

        Assert.AreEqual(written.Get, decoded.Get);
        CollectionAssert.AreEqual(new byte[] { 0xAA, 0xBB, 0xCC }, decoded.Set!.Value.ToArray());
        Assert.AreEqual(written.Offset, decoded.Offset);
        Assert.AreEqual(written.Length, decoded.Length);
        CollectionAssert.AreEqual(new byte[] { 0x11, 0x22, 0x33 }, decoded.PinUvAuthParam!.Value.ToArray());
        Assert.AreEqual(written.PinUvAuthProtocol, decoded.PinUvAuthProtocol);
    }


    /// <summary>
    /// Byte-exact KAT proving the REVERSED wire order (trap 1): <c>pinUvAuthParam</c> (<c>0x05</c>)
    /// precedes <c>pinUvAuthProtocol</c> (<c>0x06</c>) — the OPPOSITE of
    /// <c>WellKnownCtapAuthenticatorConfigRequestKeys</c>/<c>WellKnownCtapCredentialManagementRequestKeys</c>,
    /// both of which put <c>pinUvAuthProtocol</c> before <c>pinUvAuthParam</c>. A round-trip test alone
    /// cannot catch a reader/writer pair that swapped the two keys identically (self-consistently), so
    /// this test asserts the raw encoded bytes directly.
    /// </summary>
    [TestMethod]
    public void WriteOrdersPinUvAuthParamBeforePinUvAuthProtocol()
    {
        var written = new CtapLargeBlobsRequest(PinUvAuthParam: new byte[] { 0x11, 0x22, 0x33 }, PinUvAuthProtocol: 2);

        TaggedMemory<byte> encoded = CtapLargeBlobsRequestCborWriter.Write(written);

        byte[] expected = [0xA2, 0x05, 0x43, 0x11, 0x22, 0x33, 0x06, 0x02]; //map(2): pinUvAuthParam(0x05) -> bstr(3), pinUvAuthProtocol(0x06) -> 2

        Assert.IsTrue(encoded.Span.SequenceEqual(expected));

        CtapLargeBlobsRequest decoded = CtapLargeBlobsRequestCborReader.Read(encoded.Memory);
        CollectionAssert.AreEqual(new byte[] { 0x11, 0x22, 0x33 }, decoded.PinUvAuthParam!.Value.ToArray());
        Assert.AreEqual(2, decoded.PinUvAuthProtocol);
    }


    /// <summary>
    /// <c>offset</c>'s absence decodes cleanly to <see langword="null"/> WITHOUT throwing (trap 6/7):
    /// unlike <c>authenticatorConfig</c>/<c>authenticatorCredentialManagement</c>'s own Required
    /// <c>subCommand</c> member (whose absence throws <see cref="Fido2FormatException"/> at the decode
    /// boundary), <c>offset</c>'s Required-by-spec status is enforced by the PURE TRANSITION
    /// (<c>CTAP1_ERR_INVALID_PARAMETER</c>, line 7590), not the decoder.
    /// </summary>
    [TestMethod]
    public void OffsetAbsentDecodesToNullWithoutThrowing()
    {
        var written = new CtapLargeBlobsRequest(Get: 10);

        TaggedMemory<byte> encoded = CtapLargeBlobsRequestCborWriter.Write(written);
        CtapLargeBlobsRequest decoded = CtapLargeBlobsRequestCborReader.Read(encoded.Memory);

        Assert.IsNull(decoded.Offset);
        Assert.AreEqual(10, decoded.Get);
    }


    /// <summary>
    /// A request carrying an unrecognized top-level member key is decoded successfully with the unknown
    /// member ignored, per CTAP 2.3 section 8's forward-compatibility rule.
    /// </summary>
    [TestMethod]
    public void IgnoresUnrecognizedTopLevelMemberKey()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(WellKnownCtapLargeBlobsRequestKeys.Offset);
        writer.WriteInt32(3);
        writer.WriteInt32(0x07);
        writer.WriteUInt32(42);
        writer.WriteEndMap();

        CtapLargeBlobsRequest decoded = CtapLargeBlobsRequestCborReader.Read(writer.Encode());

        Assert.AreEqual(3, decoded.Offset);
    }


    /// <summary>Malformed (truncated) CBOR bytes are rejected as <see cref="Fido2FormatException"/>.</summary>
    [TestMethod]
    public void ThrowsOnMalformedCbor()
    {
        byte[] truncated = [0xA2, 0x03]; //map(2) claimed, but only one key with no value follows

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapLargeBlobsRequestCborReader.Read(truncated));
    }


    /// <summary>A wrong-type <c>offset</c> value (a byte string where an unsigned integer is expected) is rejected as <see cref="Fido2FormatException"/>.</summary>
    [TestMethod]
    public void ThrowsWhenOffsetHasWrongType()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(1);
        writer.WriteInt32(WellKnownCtapLargeBlobsRequestKeys.Offset);
        writer.WriteByteString(new byte[] { 0x01, 0x02 });
        writer.WriteEndMap();

        Assert.ThrowsExactly<Fido2FormatException>(() => CtapLargeBlobsRequestCborReader.Read(writer.Encode()));
    }
}
