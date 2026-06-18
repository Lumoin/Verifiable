using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.IO;
using System.Linq;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;

namespace Verifiable.Cbor;

/// <summary>
/// CBOR serialization and deserialization for bbs-2023 proof values.
/// </summary>
/// <remarks>
/// <para>
/// This class implements the CBOR encoding/decoding for bbs-2023 base and derived proofs
/// as specified in the W3C VC DI BBS specification.
/// </para>
/// <para>
/// The base proof header is <c>0xd9 0x5d 0x02</c> and the derived proof header is
/// <c>0xd9 0x5d 0x03</c>. The three header bytes are written literally; the CBOR array that
/// follows is untagged (the <c>0xd9 0x5d</c> prefix is itself tag 24029 over the array, emitted
/// as literal bytes, so the array must not be double-tagged).
/// </para>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#serializebaseproofvalue">serializeBaseProofValue</see>
/// and <see href="https://www.w3.org/TR/vc-di-bbs/#serializederivedproofvalue">serializeDerivedProofValue</see>.
/// </para>
/// </remarks>
public static class Bbs2023CborSerializer
{
    /// <summary>
    /// CBOR header bytes for baseline base proof values.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.w3.org/TR/vc-di-bbs/#serializebaseproofvalue">
    /// W3C VC DI BBS §3.3.1 serializeBaseProofValue</see>: the baseline base proof starts with
    /// the header bytes <c>0xd9</c>, <c>0x5d</c>, and <c>0x02</c>.
    /// </remarks>
    private static ReadOnlySpan<byte> BaseProofHeader => [0xd9, 0x5d, 0x02];

    /// <summary>
    /// CBOR header bytes for baseline derived proof values.
    /// </summary>
    /// <remarks>
    /// See <see href="https://www.w3.org/TR/vc-di-bbs/#serializederivedproofvalue">
    /// W3C VC DI BBS §3.3.6 serializeDerivedProofValue</see>: the baseline derived proof starts with
    /// the header bytes <c>0xd9</c>, <c>0x5d</c>, and <c>0x03</c>.
    /// </remarks>
    private static ReadOnlySpan<byte> DerivedProofHeader => [0xd9, 0x5d, 0x03];

    /// <summary>
    /// Prefix for canonical blank node identifiers from RDF canonicalization.
    /// </summary>
    private const string CanonicalBlankNodePrefix = "c14n";

    /// <summary>
    /// Prefix for shuffled blank node identifiers in the bbs-2023 label map.
    /// </summary>
    private const string ShuffledBlankNodePrefix = "b";


    /// <summary>
    /// Serializes a baseline base proof value to its multibase-encoded form.
    /// </summary>
    /// <param name="bbsSignature">The 80-byte BBS signature.</param>
    /// <param name="bbsHeader">The 64-byte BBS header (proofHash || mandatoryHash).</param>
    /// <param name="publicKey">The issuer BLS12-381 G2 multikey-encoded public key.</param>
    /// <param name="hmacKey">The 32-byte HMAC key.</param>
    /// <param name="mandatoryPointers">JSON pointers for mandatory claims.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <returns>The multibase-encoded proof value string starting with 'u'.</returns>
    public static string SerializeBaseProof(
        ReadOnlySpan<byte> bbsSignature,
        ReadOnlySpan<byte> bbsHeader,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> hmacKey,
        IReadOnlyList<string> mandatoryPointers,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(mandatoryPointers);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        byte[] proofBytes = SerializeBaseProofBytes(bbsSignature, bbsHeader, publicKey, hmacKey, mandatoryPointers);

        return $"{MultibaseAlgorithms.Base64Url}{base64UrlEncoder(proofBytes)}";
    }


    /// <summary>
    /// Serializes a baseline base proof value to raw bytes.
    /// </summary>
    /// <param name="bbsSignature">The 80-byte BBS signature.</param>
    /// <param name="bbsHeader">The 64-byte BBS header.</param>
    /// <param name="publicKey">The issuer BLS12-381 G2 multikey-encoded public key.</param>
    /// <param name="hmacKey">The 32-byte HMAC key.</param>
    /// <param name="mandatoryPointers">JSON pointers for mandatory claims.</param>
    /// <returns>The serialized proof bytes including the header.</returns>
    public static byte[] SerializeBaseProofBytes(
        ReadOnlySpan<byte> bbsSignature,
        ReadOnlySpan<byte> bbsHeader,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> hmacKey,
        IReadOnlyList<string> mandatoryPointers)
    {
        ArgumentNullException.ThrowIfNull(mandatoryPointers);

        using var stream = new MemoryStream();

        //The three header bytes are written literally; the array that follows is untagged.
        stream.Write(BaseProofHeader);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(5);
        writer.WriteByteString(bbsSignature);
        writer.WriteByteString(bbsHeader);
        writer.WriteByteString(publicKey);
        writer.WriteByteString(hmacKey);

        writer.WriteStartArray(mandatoryPointers.Count);
        foreach(string pointer in mandatoryPointers)
        {
            writer.WriteTextString(pointer);
        }

        writer.WriteEndArray();

        writer.WriteEndArray();

        byte[] cborBytes = writer.Encode();
        stream.Write(cborBytes);

        return stream.ToArray();
    }


    /// <summary>
    /// Parses a base proof value from its multibase-encoded form.
    /// </summary>
    /// <param name="proofValue">The multibase-encoded proof value string starting with 'u'.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url decoding.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <returns>The parsed base proof value components.</returns>
    /// <exception cref="FormatException">Thrown when the proof format is invalid.</exception>
    public static Bbs2023BaseProofValue ParseBaseProof(
        string proofValue,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentException.ThrowIfNullOrEmpty(proofValue);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(!proofValue.StartsWith(MultibaseAlgorithms.Base64Url))
        {
            throw new FormatException($"Base proof value must start with '{MultibaseAlgorithms.Base64Url}' indicating base64url-no-pad multibase encoding.");
        }

        using IMemoryOwner<byte> decodedOwner = base64UrlDecoder(proofValue.AsSpan()[1..], memoryPool);

        return ParseBaseProofBytes(decodedOwner.Memory.Span);
    }


    /// <summary>
    /// Parses a base proof value from raw bytes.
    /// </summary>
    /// <param name="proofBytes">The raw proof bytes including the header.</param>
    /// <returns>The parsed base proof value components.</returns>
    /// <exception cref="FormatException">Thrown when the proof format is invalid.</exception>
    public static Bbs2023BaseProofValue ParseBaseProofBytes(ReadOnlySpan<byte> proofBytes)
    {
        if(proofBytes.Length < 3)
        {
            throw new FormatException("Proof bytes too short to contain header.");
        }

        if(!proofBytes[..3].SequenceEqual(BaseProofHeader))
        {
            throw new FormatException("Invalid base proof header. Expected 0xd9 0x5d 0x02.");
        }

        var reader = new CborReader(proofBytes[3..].ToArray(), CborConformanceMode.Lax);

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 5)
        {
            throw new FormatException($"Base proof must contain exactly 5 elements, found {arrayLength}.");
        }

        byte[] bbsSignature = reader.ReadByteString();
        byte[] bbsHeader = reader.ReadByteString();
        byte[] publicKeyBytes = reader.ReadByteString();
        byte[] hmacKey = reader.ReadByteString();

        int? pointersLength = reader.ReadStartArray();
        var mandatoryPointers = new List<Verifiable.JsonPointer.JsonPointer>(pointersLength ?? 0);
        while(reader.PeekState() != CborReaderState.EndArray)
        {
            string pointerStr = reader.ReadTextString();
            mandatoryPointers.Add(Verifiable.JsonPointer.JsonPointer.Parse(pointerStr));
        }

        reader.ReadEndArray();

        reader.ReadEndArray();

        //The bbs-2023 base proof embeds the issuer's BLS12-381 G2 public key in its raw 96-byte CFRG
        //encoding (no multicodec header), per the W3C test vectors.
        return new Bbs2023BaseProofValue
        {
            BbsSignature = bbsSignature,
            BbsHeader = bbsHeader,
            PublicKey = publicKeyBytes,
            HmacKey = hmacKey,
            MandatoryPointers = mandatoryPointers
        };
    }


    /// <summary>
    /// Serializes a baseline derived proof value to its multibase-encoded form.
    /// </summary>
    /// <param name="bbsProof">The BBS proof bytes.</param>
    /// <param name="labelMap">Label map from canonical (<c>c14nN</c>) to shuffled (<c>bN</c>) identifiers.</param>
    /// <param name="mandatoryIndexes">Indexes of mandatory statements in the reveal document.</param>
    /// <param name="selectiveIndexes">Indexes of selectively disclosed statements relative to the non-mandatory list.</param>
    /// <param name="presentationHeader">The BBS presentation header bytes.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <returns>The multibase-encoded proof value string starting with 'u'.</returns>
    public static string SerializeDerivedProof(
        ReadOnlySpan<byte> bbsProof,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes,
        IReadOnlyList<int> selectiveIndexes,
        ReadOnlySpan<byte> presentationHeader,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(selectiveIndexes);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        byte[] proofBytes = SerializeDerivedProofBytes(bbsProof, labelMap, mandatoryIndexes, selectiveIndexes, presentationHeader);

        return $"{MultibaseAlgorithms.Base64Url}{base64UrlEncoder(proofBytes)}";
    }


    /// <summary>
    /// Serializes a baseline derived proof value to raw bytes.
    /// </summary>
    /// <param name="bbsProof">The BBS proof bytes.</param>
    /// <param name="labelMap">Label map from canonical (<c>c14nN</c>) to shuffled (<c>bN</c>) identifiers.</param>
    /// <param name="mandatoryIndexes">Indexes of mandatory statements in the reveal document.</param>
    /// <param name="selectiveIndexes">Indexes of selectively disclosed statements relative to the non-mandatory list.</param>
    /// <param name="presentationHeader">The BBS presentation header bytes.</param>
    /// <returns>The serialized proof bytes including the header.</returns>
    public static byte[] SerializeDerivedProofBytes(
        ReadOnlySpan<byte> bbsProof,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes,
        IReadOnlyList<int> selectiveIndexes,
        ReadOnlySpan<byte> presentationHeader)
    {
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(selectiveIndexes);

        using var stream = new MemoryStream();

        //The three header bytes are written literally; the array that follows is untagged.
        stream.Write(DerivedProofHeader);

        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(5);
        writer.WriteByteString(bbsProof);

        //The compressed label map is an int -> int map (c14n index -> b index), ordered by key.
        var compressedMap = CompressLabelMap(labelMap);
        writer.WriteStartMap(compressedMap.Count);
        foreach(var entry in compressedMap.OrderBy(e => e.Key))
        {
            writer.WriteInt32(entry.Key);
            writer.WriteInt32(entry.Value);
        }

        writer.WriteEndMap();

        writer.WriteStartArray(mandatoryIndexes.Count);
        foreach(int index in mandatoryIndexes)
        {
            writer.WriteInt32(index);
        }

        writer.WriteEndArray();

        writer.WriteStartArray(selectiveIndexes.Count);
        foreach(int index in selectiveIndexes)
        {
            writer.WriteInt32(index);
        }

        writer.WriteEndArray();

        writer.WriteByteString(presentationHeader);

        writer.WriteEndArray();

        byte[] cborBytes = writer.Encode();
        stream.Write(cborBytes);

        return stream.ToArray();
    }


    /// <summary>
    /// Parses a derived proof value from its multibase-encoded form.
    /// </summary>
    /// <param name="proofValue">The multibase-encoded proof value string starting with 'u'.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url decoding.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <returns>The parsed derived proof value components.</returns>
    /// <exception cref="FormatException">Thrown when the proof format is invalid.</exception>
    public static Bbs2023DerivedProofValue ParseDerivedProof(
        string proofValue,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentException.ThrowIfNullOrEmpty(proofValue);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(!proofValue.StartsWith(MultibaseAlgorithms.Base64Url))
        {
            throw new FormatException($"Derived proof value must start with '{MultibaseAlgorithms.Base64Url}' indicating base64url-no-pad multibase encoding.");
        }

        using IMemoryOwner<byte> decodedOwner = base64UrlDecoder(proofValue.AsSpan()[1..], memoryPool);

        return ParseDerivedProofBytes(decodedOwner.Memory.Span);
    }


    /// <summary>
    /// Parses a derived proof value from raw bytes.
    /// </summary>
    /// <param name="proofBytes">The raw proof bytes including the header.</param>
    /// <returns>The parsed derived proof value components.</returns>
    /// <exception cref="FormatException">Thrown when the proof format is invalid.</exception>
    public static Bbs2023DerivedProofValue ParseDerivedProofBytes(ReadOnlySpan<byte> proofBytes)
    {
        if(proofBytes.Length < 3)
        {
            throw new FormatException("Proof bytes too short to contain header.");
        }

        if(!proofBytes[..3].SequenceEqual(DerivedProofHeader))
        {
            throw new FormatException("Invalid derived proof header. Expected 0xd9 0x5d 0x03.");
        }

        var reader = new CborReader(proofBytes[3..].ToArray(), CborConformanceMode.Lax);

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 5)
        {
            throw new FormatException($"Derived proof must contain exactly 5 elements, found {arrayLength}.");
        }

        byte[] bbsProof = reader.ReadByteString();

        int? mapLength = reader.ReadStartMap();
        var compressedMap = new Dictionary<int, int>(mapLength ?? 0);
        while(reader.PeekState() != CborReaderState.EndMap)
        {
            int key = reader.ReadInt32();
            int value = reader.ReadInt32();
            compressedMap[key] = value;
        }

        reader.ReadEndMap();

        int? mandatoryLength = reader.ReadStartArray();
        var mandatoryIndexes = new List<int>(mandatoryLength ?? 0);
        while(reader.PeekState() != CborReaderState.EndArray)
        {
            mandatoryIndexes.Add(reader.ReadInt32());
        }

        reader.ReadEndArray();

        int? selectiveLength = reader.ReadStartArray();
        var selectiveIndexes = new List<int>(selectiveLength ?? 0);
        while(reader.PeekState() != CborReaderState.EndArray)
        {
            selectiveIndexes.Add(reader.ReadInt32());
        }

        reader.ReadEndArray();

        byte[] presentationHeader = reader.ReadByteString();

        reader.ReadEndArray();

        var labelMap = DecompressLabelMap(compressedMap);

        return new Bbs2023DerivedProofValue
        {
            BbsProof = bbsProof,
            LabelMap = labelMap,
            MandatoryIndexes = mandatoryIndexes,
            SelectiveIndexes = selectiveIndexes,
            PresentationHeader = presentationHeader
        };
    }


    /// <summary>
    /// Compresses a label map by converting string keys/values to integer keys and values.
    /// </summary>
    /// <remarks>
    /// Per <see href="https://www.w3.org/TR/vc-di-bbs/#compresslabelmap">W3C VC DI BBS §3.3.4 compressLabelMap</see>,
    /// the key is the integer following the <c>"c14n"</c> prefix and the value is the integer
    /// following the <c>"b"</c> prefix.
    /// </remarks>
    private static Dictionary<int, int> CompressLabelMap(IReadOnlyDictionary<string, string> labelMap)
    {
        var compressed = new Dictionary<int, int>(labelMap.Count);

        foreach(var entry in labelMap)
        {
            if(!entry.Key.StartsWith(CanonicalBlankNodePrefix, StringComparison.Ordinal))
            {
                throw new FormatException($"Label map key must start with '{CanonicalBlankNodePrefix}', got: {entry.Key}");
            }

            string keyDigits = entry.Key[CanonicalBlankNodePrefix.Length..];
            if(!int.TryParse(keyDigits, out int key))
            {
                throw new FormatException($"Label map key suffix must be an integer, got: {keyDigits}");
            }

            if(!entry.Value.StartsWith(ShuffledBlankNodePrefix, StringComparison.Ordinal))
            {
                throw new FormatException($"Label map value must start with '{ShuffledBlankNodePrefix}', got: {entry.Value}");
            }

            string valueDigits = entry.Value[ShuffledBlankNodePrefix.Length..];
            if(!int.TryParse(valueDigits, out int value))
            {
                throw new FormatException($"Label map value suffix must be an integer, got: {valueDigits}");
            }

            compressed[key] = value;
        }

        return compressed;
    }


    /// <summary>
    /// Decompresses a label map by converting integer keys and values back to string form.
    /// </summary>
    /// <remarks>
    /// Per <see href="https://www.w3.org/TR/vc-di-bbs/#decompresslabelmap">W3C VC DI BBS §3.3.5 decompressLabelMap</see>,
    /// the key adds the <c>"c14n"</c> prefix and the value adds the <c>"b"</c> prefix.
    /// </remarks>
    private static Dictionary<string, string> DecompressLabelMap(Dictionary<int, int> compressedMap)
    {
        var decompressed = new Dictionary<string, string>(compressedMap.Count, StringComparer.Ordinal);

        foreach(var entry in compressedMap)
        {
            string key = CanonicalBlankNodePrefix + entry.Key;
            string value = ShuffledBlankNodePrefix + entry.Value;
            decompressed[key] = value;
        }

        return decompressed;
    }
}
