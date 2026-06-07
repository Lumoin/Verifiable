using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Cbor;
using System.Linq;
using Verifiable.Cryptography;
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
    public static SerializeCoseSign1Delegate SerializeCoseSign1 { get; } = static (message, pool) =>
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTag((CborTag)CoseTags.Sign1);
        writer.WriteStartArray(4);

        //Protected header (already serialized).
        writer.WriteByteString(message.ProtectedHeader.AsReadOnlySpan());

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
        writer.WriteByteString(message.Signature.AsReadOnlySpan());

        writer.WriteEndArray();

        //Route the encoded bytes through the pool so the wire form carries
        //CBOM provenance and OTel observes the allocation.
        int size = writer.BytesWritten;
        IMemoryOwner<byte> owner = pool.Rent(size);
        int written = writer.Encode(owner.Memory.Span);
        if(written != size)
        {
            owner.Dispose();
            throw new InvalidOperationException(
                $"CborWriter.Encode wrote {written} bytes, expected {size}.");
        }

        return new EncodedCoseSign1(owner, CryptoTags.CoseEncodedSign1);
    };


    /// <summary>
    /// Gets a delegate that parses COSE_Sign1 bytes into a message.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of protectedHeaderCarrier and signatureCarrier transfers to the returned CoseSign1Message; the caller disposes the message.")]
    public static ParseCoseSign1Delegate ParseCoseSign1 { get; } = static (coseSign1Bytes, pool) =>
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

        //Protected header — copy CborReader's heap byte[] into a pool-rented
        //buffer wrapped in the semantic carrier.
        byte[] protectedHeaderBytes = reader.ReadByteString();
        IMemoryOwner<byte> protectedHeaderOwner = pool.Rent(protectedHeaderBytes.Length);
        protectedHeaderBytes.CopyTo(protectedHeaderOwner.Memory.Span);
        EncodedCoseProtectedHeader protectedHeaderCarrier = new(protectedHeaderOwner, CryptoTags.CoseEncodedProtectedHeader);

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

        //Payload (borrowed; the message's lifetime brackets the caller's
        //use of this returned reference).
        byte[] payload = reader.ReadByteString();

        //Signature — route through pool into a Signature carrier. The
        //signature carries a tag the verifier inspects; reuse the signing
        //tag conventions where possible. Here we use a generic
        //"signature value" Tag composition.
        byte[] signature = reader.ReadByteString();
        IMemoryOwner<byte> signatureOwner = pool.Rent(signature.Length);
        signature.CopyTo(signatureOwner.Memory.Span);
        Signature signatureCarrier = new(signatureOwner, CryptoTags.AlgorithmAgnosticSignature);

        reader.ReadEndArray();

        return new CoseSign1Message(
            protectedHeaderCarrier,
            unprotectedHeader,
            payload,
            signatureCarrier);
    };


    /// <summary>
    /// Gets a delegate that parses a COSE_Sign1 whose payload slot may be the nil sentinel — the
    /// detached form ISO/IEC 18013-5 §9.1.3.4 uses for mdoc device signatures. The standard
    /// <see cref="ParseCoseSign1"/> rejects nil payloads (correct for SD-CWT, wrong for mdoc device
    /// auth), so this shares the <see cref="ParseCoseSign1Delegate"/> shape and the mdoc device
    /// verifier wires it as the parse seam. Routes protected-header + signature bytes through the
    /// pool; the returned message owns its carriers and the caller disposes it.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of protectedHeaderCarrier and signatureCarrier transfers to the returned CoseSign1Message; the caller disposes the message.")]
    public static ParseCoseSign1Delegate ParseCoseSign1AllowingNilPayload { get; } = static (coseSign1Bytes, pool) =>
    {
        var reader = new CborReader(coseSign1Bytes, CborConformanceMode.Lax);

        CborTag tag = reader.ReadTag();
        if((int)tag != CoseTags.Sign1)
        {
            throw new InvalidOperationException($"Expected COSE_Sign1 tag ({CoseTags.Sign1}), got {(int)tag}.");
        }

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 4)
        {
            throw new InvalidOperationException($"COSE_Sign1 must have 4 elements, got {arrayLength}.");
        }

        byte[] protectedHeader = reader.ReadByteString();
        IMemoryOwner<byte> protectedHeaderOwner = pool.Rent(protectedHeader.Length);
        protectedHeader.CopyTo(protectedHeaderOwner.Memory.Span);
        EncodedCoseProtectedHeader protectedHeaderCarrier = new(protectedHeaderOwner, CryptoTags.CoseEncodedProtectedHeader);

        //Unprotected header — read raw encoded value bytes; the verification math never touches it.
        Dictionary<int, object>? unprotectedHeader = null;
        if(reader.PeekState() == CborReaderState.StartMap)
        {
            int? mapEntries = reader.ReadStartMap();
            if(mapEntries is null || mapEntries.Value > 0)
            {
                unprotectedHeader = [];
                while(reader.PeekState() != CborReaderState.EndMap)
                {
                    int label = (int)reader.ReadInt64();
                    byte[] valueBytes = reader.ReadEncodedValue().ToArray();
                    unprotectedHeader[label] = valueBytes;
                }
            }
            reader.ReadEndMap();
        }

        //Payload: nil for the detached form, byte string for the attached form.
        ReadOnlyMemory<byte> payload = ReadOnlyMemory<byte>.Empty;
        if(reader.PeekState() == CborReaderState.Null)
        {
            reader.ReadNull();
        }
        else
        {
            payload = reader.ReadByteString();
        }

        byte[] signature = reader.ReadByteString();
        IMemoryOwner<byte> signatureOwner = pool.Rent(signature.Length);
        signature.CopyTo(signatureOwner.Memory.Span);
        Signature signatureCarrier = new(signatureOwner, CryptoTags.AlgorithmAgnosticSignature);

        reader.ReadEndArray();

        return new CoseSign1Message(
            protectedHeaderCarrier,
            unprotectedHeader,
            payload,
            signatureCarrier);
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
