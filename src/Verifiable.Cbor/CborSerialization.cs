using System.Formats.Cbor;
using Verifiable.JCose;

namespace Verifiable.Cbor;

/// <summary>
/// CBOR serialization for COSE structures.
/// </summary>
/// <remarks>
/// <para>
/// This class provides the CBOR implementations for COSE serialization delegates
/// defined in <see cref="Verifiable.JCose"/>. It bridges the gap between the
/// format-agnostic <see cref="Cose"/> class and the actual CBOR encoding.
/// </para>
/// <para>
/// All methods use deterministic CBOR encoding per RFC 8949 §4.2.
/// </para>
/// </remarks>
public static class CoseSerialization
{
    /// <summary>
    /// Gets a delegate that builds the COSE Sig_structure for signing/verification.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The Sig_structure per RFC 9052 §4.4:
    /// </para>
    /// <code>
    /// Sig_structure = [
    ///     context : "Signature1",
    ///     body_protected : bstr,
    ///     external_aad : bstr,
    ///     payload : bstr
    /// ]
    /// </code>
    /// </remarks>
    public static BuildSigStructureDelegate BuildSigStructure { get; } = static (protectedHeader, payload, externalAad) =>
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(protectedHeader);
        writer.WriteByteString(externalAad);
        writer.WriteByteString(payload);
        writer.WriteEndArray();

        return writer.Encode();
    };


    /// <summary>
    /// Gets a delegate that serializes a COSE_Sign1 message to CBOR bytes.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The output includes CBOR tag(18) for COSE_Sign1.
    /// </para>
    /// </remarks>
    public static SerializeCoseSign1Delegate SerializeCoseSign1 { get; } = static message =>
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)CoseTags.Sign1);
        writer.WriteStartArray(4);

        //Protected header (already serialized).
        writer.WriteByteString(message.ProtectedHeaderBytes.Span);

        //Unprotected header.
        if(message.UnprotectedHeader is not null && message.UnprotectedHeader.Count > 0)
        {
            writer.WriteStartMap(message.UnprotectedHeader.Count);
            foreach(var kvp in message.UnprotectedHeader)
            {
                writer.WriteInt32(kvp.Key);
                CborValueConverter.WriteValue(writer, kvp.Value);
            }
            writer.WriteEndMap();
        }
        else
        {
            writer.WriteStartMap(0);
            writer.WriteEndMap();
        }

        //Payload.
        writer.WriteByteString(message.Payload.Span);

        //Signature.
        writer.WriteByteString(message.Signature.Span);

        writer.WriteEndArray();

        return writer.Encode();
    };


    /// <summary>
    /// Gets a delegate that parses COSE_Sign1 bytes into a message.
    /// </summary>
    public static ParseCoseSign1Delegate ParseCoseSign1 { get; } = static coseSign1Bytes =>
    {
        var reader = new CborReader(coseSign1Bytes, CborConformanceMode.Lax);

        //Read and validate tag.
        CborTag tag = reader.ReadTag();
        if((int)tag != CoseTags.Sign1)
        {
            throw new InvalidOperationException($"Expected COSE_Sign1 tag (18), got {(int)tag}.");
        }

        //Read array.
        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 4)
        {
            throw new InvalidOperationException($"COSE_Sign1 must have 4 elements, got {arrayLength}.");
        }

        //Protected header.
        byte[] protectedHeaderBytes = reader.ReadByteString();

        //Unprotected header.
        Dictionary<int, object>? unprotectedHeader = null;
        int? mapLength = reader.ReadStartMap();
        if(mapLength > 0)
        {
            unprotectedHeader = new Dictionary<int, object>();
            for(int i = 0; i < mapLength; i++)
            {
                int key = reader.ReadInt32();
                object? value = CborValueConverter.ReadValue(reader);
                if(value is not null)
                {
                    unprotectedHeader[key] = value;
                }
            }
        }
        reader.ReadEndMap();

        //Payload.
        byte[] payload = reader.ReadByteString();

        //Signature.
        byte[] signature = reader.ReadByteString();

        reader.ReadEndArray();

        return new CoseSign1Message(
            protectedHeaderBytes,
            unprotectedHeader,
            payload,
            signature);
    };


    /// <summary>
    /// Gets a delegate that serializes a protected header map to CBOR bytes.
    /// </summary>
    public static SerializeProtectedHeaderDelegate SerializeProtectedHeader { get; } = static header =>
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartMap(header.Count);

        foreach(var kvp in header.OrderBy(x => x.Key))
        {
            writer.WriteInt32(kvp.Key);
            CborValueConverter.WriteValue(writer, kvp.Value);
        }

        writer.WriteEndMap();

        return writer.Encode();
    };


    /// <summary>
    /// Gets a delegate that parses protected header bytes into a dictionary.
    /// </summary>
    public static ParseProtectedHeaderDelegate ParseProtectedHeader { get; } = static headerBytes =>
    {
        var reader = new CborReader(headerBytes.ToArray(), CborConformanceMode.Lax);
        var result = new Dictionary<int, object>();

        int? mapLength = reader.ReadStartMap();
        for(int i = 0; i < mapLength; i++)
        {
            int key = reader.ReadInt32();
            object? value = CborValueConverter.ReadValue(reader);
            if(value is not null)
            {
                result[key] = value;
            }
        }
        reader.ReadEndMap();

        return result;
    };
}