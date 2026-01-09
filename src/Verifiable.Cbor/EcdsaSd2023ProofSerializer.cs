using System.Buffers;
using System.Formats.Cbor;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Cryptography;

namespace Verifiable.Cbor;

/// <summary>
/// CBOR serialization and deserialization for ecdsa-sd-2023 proof values.
/// </summary>
/// <remarks>
/// <para>
/// This class implements the CBOR encoding/decoding for ecdsa-sd-2023 base and derived proofs
/// as specified in the W3C VC DI ECDSA specification.
/// </para>
/// <para>
/// See <see href="https://w3c.github.io/vc-di-ecdsa/#serializebaseproofvalue">serializeBaseProofValue</see>
/// and <see href="https://w3c.github.io/vc-di-ecdsa/#serializederivedproofvalue">serializeDerivedProofValue</see>.
/// </para>
/// </remarks>
public static class EcdsaSd2023CborSerializer
{
    /// <summary>
    /// CBOR header bytes for base proof values.
    /// </summary>
    /// <remarks>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#serializebaseproofvalue">
    /// W3C VC DI ECDSA §3.3.13 serializeBaseProofValue</see>.
    /// </remarks>
    private static ReadOnlySpan<byte> BaseProofHeader => [0xd9, 0x5d, 0x00];

    /// <summary>
    /// CBOR header bytes for derived proof values.
    /// </summary>
    /// <remarks>
    /// See <see href="https://w3c.github.io/vc-di-ecdsa/#serializederivedproofvalue">
    /// W3C VC DI ECDSA §3.3.18 serializeDerivedProofValue</see>.
    /// </remarks>
    private static ReadOnlySpan<byte> DerivedProofHeader => [0xd9, 0x5d, 0x01];

    /// <summary>
    /// Prefix for canonical blank node identifiers from RDF canonicalization.
    /// </summary>
    private const string CanonicalBlankNodePrefix = "c14n";

    /// <summary>
    /// Prefix for HMAC-based blank node identifiers.
    /// </summary>
    private const string HmacBlankNodePrefix = "u";


    /// <summary>
    /// Serializes a base proof value to its multibase-encoded form.
    /// </summary>
    /// <param name="baseSignature">The 64-byte base signature.</param>
    /// <param name="publicKey">The multikey-encoded public key (35 bytes for P-256).</param>
    /// <param name="hmacKey">The 32-byte HMAC key.</param>
    /// <param name="signatures">Per-statement signatures.</param>
    /// <param name="mandatoryPointers">JSON pointers for mandatory claims.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <returns>The multibase-encoded proof value string starting with 'u'.</returns>
    public static string SerializeBaseProof(
        ReadOnlySpan<byte> baseSignature,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> hmacKey,
        IReadOnlyList<byte[]> signatures,
        IReadOnlyList<string> mandatoryPointers,
        EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        ArgumentNullException.ThrowIfNull(mandatoryPointers);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);

        byte[] proofBytes = SerializeBaseProofBytes(baseSignature, publicKey, hmacKey, signatures, mandatoryPointers);
        return $"{MultibaseAlgorithms.Base64Url}{base64UrlEncoder(proofBytes)}";
    }


    /// <summary>
    /// Serializes a base proof value to raw bytes.
    /// </summary>
    /// <param name="baseSignature">The 64-byte base signature.</param>
    /// <param name="publicKey">The multikey-encoded public key.</param>
    /// <param name="hmacKey">The 32-byte HMAC key.</param>
    /// <param name="signatures">Per-statement signatures.</param>
    /// <param name="mandatoryPointers">JSON pointers for mandatory claims.</param>
    /// <returns>The serialized proof bytes including the header.</returns>
    public static byte[] SerializeBaseProofBytes(
        ReadOnlySpan<byte> baseSignature,
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> hmacKey,
        IReadOnlyList<byte[]> signatures,
        IReadOnlyList<string> mandatoryPointers)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        ArgumentNullException.ThrowIfNull(mandatoryPointers);

        using var stream = new MemoryStream();

        //Write header bytes.
        stream.Write(BaseProofHeader);

        //Write CBOR-encoded components array.
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(5);
        writer.WriteByteString(baseSignature);
        writer.WriteByteString(publicKey);
        writer.WriteByteString(hmacKey);

        //Write signatures array.
        writer.WriteStartArray(signatures.Count);
        foreach(byte[] signature in signatures)
        {
            writer.WriteByteString(signature);
        }
        writer.WriteEndArray();

        //Write mandatory pointers array.
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
    public static BaseProofValue ParseBaseProof(
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
        return ParseBaseProofBytes(decodedOwner.Memory.Span, memoryPool);
    }


    /// <summary>
    /// Parses a base proof value from raw bytes.
    /// </summary>
    /// <param name="proofBytes">The raw proof bytes including the header.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <returns>The parsed base proof value components.</returns>
    /// <exception cref="FormatException">Thrown when the proof format is invalid.</exception>
    public static BaseProofValue ParseBaseProofBytes(ReadOnlySpan<byte> proofBytes, MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(proofBytes.Length < 3)
        {
            throw new FormatException("Proof bytes too short to contain header.");
        }

        //Verify header.
        if(!proofBytes[..3].SequenceEqual(BaseProofHeader))
        {
            throw new FormatException("Invalid base proof header. Expected 0xd9 0x5d 0x00.");
        }

        //Parse CBOR content.
        var reader = new CborReader(proofBytes[3..].ToArray(), CborConformanceMode.Lax);

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 5)
        {
            throw new FormatException($"Base proof must contain exactly 5 elements, found {arrayLength}.");
        }

        byte[] baseSignatureBytes = reader.ReadByteString();
        byte[] publicKeyBytes = reader.ReadByteString();
        byte[] hmacKey = reader.ReadByteString();

        //Read signatures array.
        int? signaturesLength = reader.ReadStartArray();
        var signatures = new List<Signature>(signaturesLength ?? 0);
        while(reader.PeekState() != CborReaderState.EndArray)
        {
            byte[] sigBytes = reader.ReadByteString();
            IMemoryOwner<byte> sigMemory = memoryPool.Rent(sigBytes.Length);
            sigBytes.CopyTo(sigMemory.Memory.Span);
            signatures.Add(new Signature(sigMemory, CryptoTags.P256Signature));
        }
        reader.ReadEndArray();

        //Read mandatory pointers array.
        int? pointersLength = reader.ReadStartArray();
        var mandatoryPointers = new List<Verifiable.JsonPointer.JsonPointer>(pointersLength ?? 0);
        while(reader.PeekState() != CborReaderState.EndArray)
        {
            string pointerStr = reader.ReadTextString();
            mandatoryPointers.Add(Verifiable.JsonPointer.JsonPointer.Parse(pointerStr));
        }
        reader.ReadEndArray();

        reader.ReadEndArray();

        //Create domain types.
        IMemoryOwner<byte> baseSignatureMemory = memoryPool.Rent(baseSignatureBytes.Length);
        baseSignatureBytes.CopyTo(baseSignatureMemory.Memory.Span);
        var baseSignature = new Signature(baseSignatureMemory, CryptoTags.P256Signature);

        //The stored public key includes multicodec header. Strip it to get raw key bytes.
        int headerLength = MulticodecHeaders.P256PublicKey.Length;
        int rawKeyLength = publicKeyBytes.Length - headerLength;
        IMemoryOwner<byte> publicKeyMemory = memoryPool.Rent(rawKeyLength);
        publicKeyBytes.AsSpan(headerLength).CopyTo(publicKeyMemory.Memory.Span);
        var ephemeralPublicKey = new PublicKeyMemory(publicKeyMemory, CryptoTags.P256PublicKey);

        return new BaseProofValue
        {
            BaseSignature = baseSignature,
            EphemeralPublicKey = ephemeralPublicKey,
            HmacKey = hmacKey,
            Signatures = signatures,
            MandatoryPointers = mandatoryPointers
        };
    }


    /// <summary>
    /// Serializes a derived proof value to its multibase-encoded form.
    /// </summary>
    /// <param name="baseSignature">The base signature bytes.</param>
    /// <param name="publicKey">The multikey-encoded public key.</param>
    /// <param name="signatures">Per-disclosed-statement signatures.</param>
    /// <param name="labelMap">Mapping from canonical to HMAC-derived blank node identifiers.</param>
    /// <param name="mandatoryIndexes">Indexes of mandatory statements.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url decoding.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <returns>The multibase-encoded proof value string starting with 'u'.</returns>
    public static string SerializeDerivedProof(
        ReadOnlySpan<byte> baseSignature,
        ReadOnlySpan<byte> publicKey,
        IReadOnlyList<byte[]> signatures,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes,
        EncodeDelegate base64UrlEncoder,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        byte[] proofBytes = SerializeDerivedProofBytes(baseSignature, publicKey, signatures, labelMap, mandatoryIndexes, base64UrlDecoder, memoryPool);
        return $"{MultibaseAlgorithms.Base64Url}{base64UrlEncoder(proofBytes)}";
    }


    /// <summary>
    /// Serializes a derived proof value to raw bytes.
    /// </summary>
    /// <param name="baseSignature">The base signature bytes.</param>
    /// <param name="publicKey">The multikey-encoded public key.</param>
    /// <param name="signatures">Per-disclosed-statement signatures.</param>
    /// <param name="labelMap">Mapping from canonical to HMAC-derived blank node identifiers.</param>
    /// <param name="mandatoryIndexes">Indexes of mandatory statements.</param>
    /// <param name="base64UrlDecoder">Delegate for base64url decoding.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <returns>The serialized proof bytes including the header.</returns>
    public static byte[] SerializeDerivedProofBytes(
        ReadOnlySpan<byte> baseSignature,
        ReadOnlySpan<byte> publicKey,
        IReadOnlyList<byte[]> signatures,
        IReadOnlyDictionary<string, string> labelMap,
        IReadOnlyList<int> mandatoryIndexes,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(signatures);
        ArgumentNullException.ThrowIfNull(labelMap);
        ArgumentNullException.ThrowIfNull(mandatoryIndexes);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        using var stream = new MemoryStream();

        //Write header bytes.
        stream.Write(DerivedProofHeader);

        //Write CBOR-encoded components array.
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteStartArray(5);
        writer.WriteByteString(baseSignature);
        writer.WriteByteString(publicKey);

        //Write signatures array.
        writer.WriteStartArray(signatures.Count);
        foreach(byte[] signature in signatures)
        {
            writer.WriteByteString(signature);
        }
        writer.WriteEndArray();

        //Write compressed label map (int -> bytes).
        var compressedMap = CompressLabelMap(labelMap, base64UrlDecoder, memoryPool);

        writer.WriteStartMap(compressedMap.Count);
        foreach(var entry in compressedMap.OrderBy(e => e.Key))
        {
            writer.WriteInt32(entry.Key);
            writer.WriteByteString(entry.Value);
        }
        writer.WriteEndMap();

        //Write mandatory indexes array.
        writer.WriteStartArray(mandatoryIndexes.Count);
        foreach(int index in mandatoryIndexes)
        {
            writer.WriteInt32(index);
        }
        writer.WriteEndArray();

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
    /// <param name="base64UrlEncoder">Delegate for base64url encoding (for label map decompression).</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <returns>The parsed derived proof value components.</returns>
    /// <exception cref="FormatException">Thrown when the proof format is invalid.</exception>
    public static DerivedProofValue ParseDerivedProof(
        string proofValue,
        DecodeDelegate base64UrlDecoder,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentException.ThrowIfNullOrEmpty(proofValue);
        ArgumentNullException.ThrowIfNull(base64UrlDecoder);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(!proofValue.StartsWith(MultibaseAlgorithms.Base64Url))
        {
            throw new FormatException($"Derived proof value must start with '{MultibaseAlgorithms.Base64Url}' indicating base64url-no-pad multibase encoding.");
        }

        using IMemoryOwner<byte> decodedOwner = base64UrlDecoder(proofValue.AsSpan()[1..], memoryPool);
        return ParseDerivedProofBytes(decodedOwner.Memory.Span, base64UrlEncoder, memoryPool);
    }


    /// <summary>
    /// Parses a derived proof value from raw bytes.
    /// </summary>
    /// <param name="proofBytes">The raw proof bytes including the header.</param>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding (for label map decompression).</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <returns>The parsed derived proof value components.</returns>
    /// <exception cref="FormatException">Thrown when the proof format is invalid.</exception>
    public static DerivedProofValue ParseDerivedProofBytes(
        ReadOnlySpan<byte> proofBytes,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> memoryPool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(memoryPool);

        if(proofBytes.Length < 3)
        {
            throw new FormatException("Proof bytes too short to contain header.");
        }

        //Verify header.
        if(!proofBytes[..3].SequenceEqual(DerivedProofHeader))
        {
            throw new FormatException("Invalid derived proof header. Expected 0xd9 0x5d 0x01.");
        }

        //Parse CBOR content.
        var reader = new CborReader(proofBytes[3..].ToArray(), CborConformanceMode.Lax);

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 5)
        {
            throw new FormatException($"Derived proof must contain exactly 5 elements, found {arrayLength}.");
        }

        byte[] baseSignatureBytes = reader.ReadByteString();
        byte[] publicKeyBytes = reader.ReadByteString();

        //Read signatures array.
        int? signaturesLength = reader.ReadStartArray();
        var signatures = new List<Signature>(signaturesLength ?? 0);
        while(reader.PeekState() != CborReaderState.EndArray)
        {
            byte[] sigBytes = reader.ReadByteString();
            IMemoryOwner<byte> sigMemory = memoryPool.Rent(sigBytes.Length);
            sigBytes.CopyTo(sigMemory.Memory.Span);
            signatures.Add(new Signature(sigMemory, CryptoTags.P256Signature));
        }
        reader.ReadEndArray();

        //Read compressed label map.
        int? mapLength = reader.ReadStartMap();
        var compressedMap = new Dictionary<int, byte[]>(mapLength ?? 0);
        while(reader.PeekState() != CborReaderState.EndMap)
        {
            int key = reader.ReadInt32();
            byte[] value = reader.ReadByteString();
            compressedMap[key] = value;
        }
        reader.ReadEndMap();

        //Read mandatory indexes array.
        int? indexesLength = reader.ReadStartArray();
        var mandatoryIndexes = new List<int>(indexesLength ?? 0);
        while(reader.PeekState() != CborReaderState.EndArray)
        {
            mandatoryIndexes.Add(reader.ReadInt32());
        }
        reader.ReadEndArray();

        reader.ReadEndArray();

        //Decompress label map.
        var labelMap = DecompressLabelMap(compressedMap, base64UrlEncoder);

        //Create domain types.
        IMemoryOwner<byte> baseSignatureMemory = memoryPool.Rent(baseSignatureBytes.Length);
        baseSignatureBytes.CopyTo(baseSignatureMemory.Memory.Span);
        var baseSignature = new Signature(baseSignatureMemory, CryptoTags.P256Signature);

        //The stored public key includes multicodec header. Strip it to get raw key bytes.
        int headerLength = MulticodecHeaders.P256PublicKey.Length;
        int rawKeyLength = publicKeyBytes.Length - headerLength;
        IMemoryOwner<byte> publicKeyMemory = memoryPool.Rent(rawKeyLength);
        publicKeyBytes.AsSpan(headerLength).CopyTo(publicKeyMemory.Memory.Span);
        var ephemeralPublicKey = new PublicKeyMemory(publicKeyMemory, CryptoTags.P256PublicKey);

        return new DerivedProofValue
        {
            BaseSignature = baseSignature,
            EphemeralPublicKey = ephemeralPublicKey,
            Signatures = signatures,
            LabelMap = labelMap,
            MandatoryIndexes = mandatoryIndexes
        };
    }


    /// <summary>
    /// Compresses a label map by converting string keys/values to integer keys and byte values.
    /// </summary>
    private static Dictionary<int, byte[]> CompressLabelMap(
        IReadOnlyDictionary<string, string> labelMap,
        DecodeDelegate base64UrlDecoder,
        MemoryPool<byte> memoryPool)
    {
        var compressed = new Dictionary<int, byte[]>(labelMap.Count);

        foreach(var entry in labelMap)
        {
            //Parse "c14nN" to integer N.
            if(!entry.Key.StartsWith(CanonicalBlankNodePrefix, StringComparison.Ordinal))
            {
                throw new FormatException($"Label map key must start with '{CanonicalBlankNodePrefix}', got: {entry.Key}");
            }

            string indexStr = entry.Key[CanonicalBlankNodePrefix.Length..];
            if(!int.TryParse(indexStr, out int index))
            {
                throw new FormatException($"Label map key suffix must be an integer, got: {indexStr}");
            }

            //Decode "uXXX" to bytes (remove 'u' prefix and base64url decode).
            if(!entry.Value.StartsWith(HmacBlankNodePrefix, StringComparison.Ordinal))
            {
                throw new FormatException($"Label map value must start with '{HmacBlankNodePrefix}', got: {entry.Value}");
            }

            using IMemoryOwner<byte> hmacBytesOwner = base64UrlDecoder(entry.Value.AsSpan()[1..], memoryPool);
            compressed[index] = hmacBytesOwner.Memory.ToArray();
        }

        return compressed;
    }


    /// <summary>
    /// Decompresses a label map by converting integer keys and byte values back to string form.
    /// </summary>
    private static Dictionary<string, string> DecompressLabelMap(
        Dictionary<int, byte[]> compressedMap,
        EncodeDelegate base64UrlEncoder)
    {
        var decompressed = new Dictionary<string, string>(compressedMap.Count);
        foreach(var entry in compressedMap)
        {
            string key = CanonicalBlankNodePrefix + entry.Key;
            string value = HmacBlankNodePrefix + base64UrlEncoder(entry.Value);

            decompressed[key] = value;
        }

        return decompressed;
    }
}