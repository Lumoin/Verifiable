using Lumoin.Veritas.Cbor;
using System.Buffers;
using Verifiable.Cbor;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Byte builders for COSE messages a test puts in front of a reader exactly as written, malformed shapes
/// among them. The library's own serializers refuse to write a message whose header maps repeat a label or
/// share one (<see href="https://www.rfc-editor.org/rfc/rfc9052#section-9">RFC 9052 Section 9</see>:
/// "Applications MUST NOT generate messages with the same label used twice as a key in a single map."), so a
/// test that needs such a message assembles its bytes here.
/// </summary>
internal static class CoseWireFixtures
{
    /// <summary>
    /// Assembles a tagged COSE_Sign1 from its four parts: the protected bucket and the payload and signature
    /// are written as byte strings, the unprotected bucket's encoded map is copied as given.
    /// </summary>
    /// <param name="protectedHeader">The serialized protected bucket.</param>
    /// <param name="unprotectedHeaderMap">The encoded unprotected bucket, a CBOR map.</param>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="signature">The signature bytes.</param>
    /// <returns>The COSE_Sign1 wire bytes.</returns>
    internal static byte[] ComposeCoseSign1(
        ReadOnlySpan<byte> protectedHeader, ReadOnlySpan<byte> unprotectedHeaderMap, ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborOptions.Lax);
        writer.WriteTag(new CborTag(CoseTags.Sign1));
        writer.WriteStartArray(4);
        writer.WriteByteString(protectedHeader);
        writer.WriteEncodedValue(unprotectedHeaderMap);
        writer.WriteByteString(payload);
        writer.WriteByteString(signature);
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// A <see cref="SerializeCoseSign1Delegate"/> that writes <paramref name="message"/> as given, its protected
    /// bucket unjudged, so a genuinely signed message whose header maps repeat a label reaches the wire.
    /// </summary>
    /// <param name="message">The signed message.</param>
    /// <param name="pool">Memory pool the returned wire form rents from.</param>
    /// <returns>The tagged COSE_Sign1 wire form; the caller disposes it.</returns>
    internal static EncodedCoseSign1 SerializeCoseSign1AsGiven(CoseSign1Message message, BaseMemoryPool pool)
    {
        var unprotectedBuffer = new ArrayBufferWriter<byte>();
        var unprotectedWriter = new CborWriter(unprotectedBuffer, CborOptions.Lax);
        IReadOnlyDictionary<int, object> unprotectedHeader = message.UnprotectedHeader ?? new Dictionary<int, object>();
        unprotectedWriter.WriteStartMap(unprotectedHeader.Count);
        foreach(KeyValuePair<int, object> entry in unprotectedHeader)
        {
            unprotectedWriter.WriteInt32(entry.Key);
            CborValueConverter.WriteValue(unprotectedWriter, entry.Value);
        }

        unprotectedWriter.WriteEndMap();

        byte[] wireBytes = ComposeCoseSign1(
            message.ProtectedHeader.AsReadOnlySpan(), unprotectedBuffer.WrittenSpan, message.Payload.Span, message.Signature.AsReadOnlySpan());
        IMemoryOwner<byte> owner = pool.Rent(wireBytes.Length);
        wireBytes.CopyTo(owner.Memory.Span);

        return new EncodedCoseSign1(owner, CryptoTags.CoseEncodedSign1);
    }


    /// <summary>
    /// Serializes <paramref name="header"/> and appends a second <c>kid</c> (the text <c>"x"</c>) to the map,
    /// raising the map's entry count by one, so the protected bucket carries <c>kid</c> twice.
    /// </summary>
    /// <param name="header">The protected header map; fewer than 23 entries, so the count is in the initial byte.</param>
    /// <returns>The serialized protected bucket with <c>kid</c> twice.</returns>
    internal static ReadOnlySpan<byte> CoseProtectedHeaderWithKidTwiceToCborBytes(IReadOnlyDictionary<int, object> header)
    {
        byte[] serialized = CoseSerialization.SerializeProtectedHeader(header);
        byte[] repeated = new byte[serialized.Length + 3];
        serialized.CopyTo(repeated, 0);
        repeated[0] = (byte)(serialized[0] + 1);
        repeated[^3] = CoseHeaderParameters.Kid;
        repeated[^2] = 0x61;
        repeated[^1] = (byte)'x';

        return repeated;
    }
}
