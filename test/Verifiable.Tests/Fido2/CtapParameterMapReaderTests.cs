using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using Verifiable.Cbor.Ctap;
using Verifiable.Fido2;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for <see cref="CtapParameterMapReader"/>, the command-agnostic top-level CBOR-map reader
/// every future CTAP2 command-parameter reader builds on.
/// </summary>
[TestClass]
internal sealed class CtapParameterMapReaderTests
{
    /// <summary>A synthetic multi-key map decodes with each key's still-encoded value recoverable independently.</summary>
    [TestMethod]
    public void ReadsMultipleTopLevelKeysInWireOrder()
    {
        byte[] clientDataHash = new byte[32];
        for(int i = 0; i < clientDataHash.Length; i++)
        {
            clientDataHash[i] = (byte)i;
        }

        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(2);
        writer.WriteInt32(1);
        writer.WriteByteString(clientDataHash);
        writer.WriteInt32(2);
        writer.WriteTextString("example.com");
        writer.WriteEndMap();

        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> result = CtapParameterMapReader.Read(writer.Encode());

        Assert.HasCount(2, result);

        var clientDataHashReader = new CborReader(result[1]);
        Assert.IsTrue(clientDataHashReader.ReadByteString().AsSpan().SequenceEqual(clientDataHash));

        var rpIdReader = new CborReader(result[2]);
        Assert.AreEqual("example.com", rpIdReader.ReadTextString());
    }


    /// <summary>A parameter map carrying the same top-level key twice is rejected.</summary>
    [TestMethod]
    public void ThrowsOnDuplicateTopLevelKey()
    {
        //Hand-built rather than produced by CborWriter: {1: 0, 1: 1} — structurally valid CBOR (two
        //equal, hence non-decreasing, keys) that Ctap2ParameterMapReader's own duplicate check must
        //catch regardless of whether the framework's own conformance-mode validation also flags it.
        byte[] duplicateKeyMap = [0xA2, 0x01, 0x00, 0x01, 0x01];

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => CtapParameterMapReader.Read(duplicateKeyMap));

        Assert.IsNotNull(exception);
    }


    /// <summary>An empty parameter map (a command with no parameters at all) decodes to an empty dictionary.</summary>
    [TestMethod]
    public void ReadsEmptyMap()
    {
        var writer = new CborWriter(CborConformanceMode.Ctap2Canonical);
        writer.WriteStartMap(0);
        writer.WriteEndMap();

        IReadOnlyDictionary<int, ReadOnlyMemory<byte>> result = CtapParameterMapReader.Read(writer.Encode());

        Assert.IsEmpty(result);
    }
}
