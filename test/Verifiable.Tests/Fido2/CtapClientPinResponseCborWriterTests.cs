using System;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2.Ctap;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Byte-exactness tests for <see cref="CtapClientPinResponseCborWriter"/>.
/// </summary>
[TestClass]
internal sealed class CtapClientPinResponseCborWriterTests
{
    /// <summary>A response with no member present encodes to an empty map.</summary>
    [TestMethod]
    public void WriteEncodesEmptyResponseAsEmptyMap()
    {
        var response = new CtapClientPinResponse();

        TaggedMemory<byte> result = CtapClientPinResponseCborWriter.Write(response);

        Assert.IsTrue(result.Span.SequenceEqual(new byte[] { 0xA0 })); //map(0)
    }


    /// <summary><c>pinRetries</c> alone (key <c>0x03</c>) encodes to a single-entry map.</summary>
    [TestMethod]
    public void WriteEncodesPinRetriesOnlyToExactCanonicalBytes()
    {
        var response = new CtapClientPinResponse(PinRetries: 8);

        TaggedMemory<byte> result = CtapClientPinResponseCborWriter.Write(response);

        byte[] expected = [0xA1, 0x03, 0x08]; //map(1): key 3 (pinRetries) -> 8

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }


    /// <summary>
    /// <c>powerCycleState</c> (key <c>0x04</c>) writes before <c>uvRetries</c> (key <c>0x05</c>),
    /// preserving the outer map's ascending key order.
    /// </summary>
    [TestMethod]
    public void WriteOrdersPowerCycleStateBeforeUvRetries()
    {
        var response = new CtapClientPinResponse(PowerCycleState: true, UvRetries: 5);

        TaggedMemory<byte> result = CtapClientPinResponseCborWriter.Write(response);

        byte[] expected = [0xA2, 0x04, 0xF5, 0x05, 0x05]; //map(2): powerCycleState -> true, uvRetries -> 5

        Assert.IsTrue(result.Span.SequenceEqual(expected));
    }
}
