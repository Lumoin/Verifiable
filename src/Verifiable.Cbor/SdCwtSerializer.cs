using System.Formats.Cbor;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Sd;

namespace Verifiable.Cbor;

/// <summary>
/// CBOR serialization for SD-CWT disclosures and tokens.
/// </summary>
/// <remarks>
/// <para>
/// SD-CWT uses COSE_Sign1 structure with disclosures in the unprotected header,
/// as defined in draft-ietf-spice-sd-cwt. Key differences from SD-JWT:
/// </para>
/// <list type="bullet">
/// <item><description>Disclosures are CBOR arrays in the <c>sd_claims</c> unprotected header.</description></item>
/// <item><description>Salt is raw bytes (not Base64Url-encoded).</description></item>
/// <item><description>Key binding is REQUIRED and uses SD-KBT (Key Binding Token).</description></item>
/// <item><description>The SD-KBT includes the entire SD-CWT in its payload.</description></item>
/// </list>
/// <para>
/// <strong>Wire Format:</strong>
/// </para>
/// <code>
/// ┌─────────────────────────────────────────────────────────────────────────┐
/// │                        SD-CWT Wire Format                               │
/// ├─────────────────────────────────────────────────────────────────────────┤
/// │                                                                         │
/// │  SD-CWT = COSE_Sign1 [                                                  │
/// │      protected:   { typ: "application/sd-cwt", alg: ... }               │
/// │      unprotected: { sd_claims: [ disclosure1, disclosure2, ... ] }      │
/// │      payload:     { redacted_keys: [...], claims... }                   │
/// │      signature:   ...                                                   │
/// │  ]                                                                      │
/// │                                                                         │
/// │  Disclosure (map key):    [salt, key, value]                            │
/// │  Disclosure (array elem): [salt, value]                                 │
/// │                                                                         │
/// │  SD-KBT = COSE_Sign1 [                                                  │
/// │      protected:   { typ: "application/kb+cwt", alg: ... }               │
/// │      unprotected: { }                                                   │
/// │      payload:     { aud, nonce, iat, sd_cwt: &lt;SD-CWT&gt;, sd_hash: ... }   │
/// │      signature:   ...                                                   │
/// │  ]                                                                      │
/// │                                                                         │
/// └─────────────────────────────────────────────────────────────────────────┘
/// </code>
/// </remarks>
public static class SdCwtSerializer
{
    /// <summary>
    /// CWT claim key for redacted claim keys array.
    /// </summary>
    public const int RedactedKeysClaimKey = 12;

    /// <summary>
    /// Unprotected header key for selective disclosure claims.
    /// </summary>
    /// <remarks>
    /// This is a proposed IANA registration in draft-ietf-spice-sd-cwt.
    /// Also available as <see cref="CoseHeaderParameters.SdClaims"/>.
    /// </remarks>
    public const int SdClaimsHeaderKey = 17;

    /// <summary>
    /// Media type for SD-CWT.
    /// </summary>
    public const string SdCwtMediaType = "application/sd-cwt";

    /// <summary>
    /// Media type for KB-CWT (Key Binding CWT).
    /// </summary>
    public const string KbCwtMediaType = "application/kb+cwt";


    /// <summary>
    /// Serializes an SD-CWT message to COSE_Sign1 format.
    /// </summary>
    /// <param name="message">The SD-CWT message to serialize.</param>
    /// <param name="conformanceMode">CBOR conformance mode for deterministic encoding.</param>
    /// <returns>The CBOR-encoded COSE_Sign1 bytes.</returns>
    public static byte[] Serialize(
        SdCwtMessage message,
        CborConformanceMode conformanceMode = CborConformanceMode.Canonical)
    {
        ArgumentNullException.ThrowIfNull(message);

        var writer = new CborWriter(conformanceMode);

        //COSE_Sign1 = tag(18) [protected, unprotected, payload, signature].
        writer.WriteTag((CborTag)CoseTags.Sign1);
        writer.WriteStartArray(4);

        //Protected header (as bstr).
        writer.WriteByteString(message.ProtectedHeader.Span);

        //Unprotected header with sd_claims.
        writer.WriteStartMap(1);
        writer.WriteInt32(CoseHeaderParameters.SdClaims);
        writer.WriteStartArray(message.Disclosures.Count);
        foreach(SdDisclosure disclosure in message.Disclosures)
        {
            byte[] disclosureCbor = SerializeDisclosure(disclosure, conformanceMode);
            writer.WriteByteString(disclosureCbor);
        }
        writer.WriteEndArray();
        writer.WriteEndMap();

        //Payload.
        writer.WriteByteString(message.Payload.Span);

        //Signature.
        writer.WriteByteString(message.Signature.Span);

        writer.WriteEndArray();

        return writer.Encode();
    }


    /// <summary>
    /// Parses an SD-CWT message from COSE_Sign1 format.
    /// </summary>
    /// <param name="coseSign1">The CBOR-encoded COSE_Sign1 bytes.</param>
    /// <returns>The parsed SD-CWT message.</returns>
    /// <exception cref="CborContentException">Thrown when the format is invalid.</exception>
    public static SdCwtMessage Parse(ReadOnlyMemory<byte> coseSign1)
    {
        var reader = new CborReader(coseSign1, CborConformanceMode.Lax);

        //Read and validate COSE_Sign1 tag.
        CborTag tag = reader.ReadTag();
        if((int)tag != CoseTags.Sign1)
        {
            throw new CborContentException($"Expected COSE_Sign1 tag (18), got {(int)tag}.");
        }

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength != 4)
        {
            throw new CborContentException($"COSE_Sign1 must have 4 elements, got {arrayLength}.");
        }

        //Protected header.
        byte[] protectedHeader = reader.ReadByteString();

        //Unprotected header - extract sd_claims.
        var disclosures = new List<SdDisclosure>();
        reader.ReadStartMap();

        while(reader.PeekState() != CborReaderState.EndMap)
        {
            int label = reader.ReadInt32();
            if(label == CoseHeaderParameters.SdClaims)
            {
                //Read sd_claims array.
                reader.ReadStartArray();
                while(reader.PeekState() != CborReaderState.EndArray)
                {
                    byte[] disclosureCbor = reader.ReadByteString();
                    SdDisclosure disclosure = ParseDisclosure(disclosureCbor);
                    disclosures.Add(disclosure);
                }
                reader.ReadEndArray();
            }
            else
            {
                reader.SkipValue();
            }
        }
        reader.ReadEndMap();

        //Payload.
        byte[] payload = reader.ReadByteString();

        //Signature.
        byte[] signature = reader.ReadByteString();

        reader.ReadEndArray();

        return new SdCwtMessage(payload, protectedHeader, signature, disclosures);
    }


    /// <summary>
    /// Builds the Sig_structure for signing or verification.
    /// </summary>
    /// <param name="protectedHeader">The protected header bytes.</param>
    /// <param name="payload">The payload bytes.</param>
    /// <param name="externalAad">Optional external AAD (default empty).</param>
    /// <param name="conformanceMode">CBOR conformance mode for deterministic encoding.</param>
    /// <returns>The CBOR-encoded Sig_structure bytes.</returns>
    public static byte[] BuildSigStructure(
        ReadOnlySpan<byte> protectedHeader,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> externalAad = default,
        CborConformanceMode conformanceMode = CborConformanceMode.Canonical)
    {
        var writer = new CborWriter(conformanceMode);
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(protectedHeader);
        writer.WriteByteString(externalAad);
        writer.WriteByteString(payload);
        writer.WriteEndArray();

        return writer.Encode();
    }


    /// <summary>
    /// Builds a protected header with algorithm and type.
    /// </summary>
    /// <param name="algorithm">The COSE algorithm identifier.</param>
    /// <param name="mediaType">The content type (e.g., "application/sd-cwt").</param>
    /// <param name="conformanceMode">CBOR conformance mode for deterministic encoding.</param>
    /// <returns>The CBOR-encoded protected header bytes.</returns>
    public static byte[] BuildProtectedHeader(
        int algorithm,
        string? mediaType = null,
        CborConformanceMode conformanceMode = CborConformanceMode.Canonical)
    {
        var writer = new CborWriter(conformanceMode);

        int mapSize = mediaType is null ? 1 : 2;
        writer.WriteStartMap(mapSize);

        writer.WriteInt32(CoseHeaderParameters.Alg);
        writer.WriteInt32(algorithm);

        if(mediaType is not null)
        {
            writer.WriteInt32(CoseHeaderParameters.Typ);
            writer.WriteTextString(mediaType);
        }

        writer.WriteEndMap();

        return writer.Encode();
    }


    /// <summary>
    /// Serializes a disclosure to CBOR format.
    /// </summary>
    /// <param name="disclosure">The disclosure to serialize.</param>
    /// <param name="conformanceMode">CBOR conformance mode for deterministic encoding.</param>
    /// <returns>The CBOR-encoded disclosure bytes.</returns>
    public static byte[] SerializeDisclosure(
        SdDisclosure disclosure,
        CborConformanceMode conformanceMode = CborConformanceMode.Canonical)
    {
        ArgumentNullException.ThrowIfNull(disclosure);

        var writer = new CborWriter(conformanceMode);

        if(disclosure.ClaimName is not null)
        {
            //Property disclosure: [salt, name, value].
            writer.WriteStartArray(3);
            writer.WriteByteString(disclosure.Salt.Span);
            writer.WriteTextString(disclosure.ClaimName);
            CborValueConverter.WriteValue(writer, disclosure.ClaimValue);
            writer.WriteEndArray();
        }
        else
        {
            //Array element disclosure: [salt, value].
            writer.WriteStartArray(2);
            writer.WriteByteString(disclosure.Salt.Span);
            CborValueConverter.WriteValue(writer, disclosure.ClaimValue);
            writer.WriteEndArray();
        }

        return writer.Encode();
    }


    /// <summary>
    /// Parses a disclosure from CBOR format.
    /// </summary>
    /// <param name="disclosureCbor">The CBOR-encoded disclosure bytes.</param>
    /// <returns>The parsed disclosure.</returns>
    /// <exception cref="CborContentException">Thrown when the format is invalid.</exception>
    public static SdDisclosure ParseDisclosure(ReadOnlySpan<byte> disclosureCbor)
    {
        var reader = new CborReader(disclosureCbor.ToArray(), CborConformanceMode.Lax);

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength is not (2 or 3))
        {
            throw new CborContentException($"Disclosure must have 2 or 3 elements, got {arrayLength}.");
        }

        byte[] salt = reader.ReadByteString();

        if(arrayLength == 3)
        {
            //Property disclosure: [salt, name, value].
            string claimName = reader.ReadTextString();
            object? claimValue = CborValueConverter.ReadValue(reader);
            reader.ReadEndArray();

            return SdDisclosure.CreateProperty(salt, claimName, claimValue);
        }
        else
        {
            //Array element disclosure: [salt, value].
            object? claimValue = CborValueConverter.ReadValue(reader);
            reader.ReadEndArray();

            return SdDisclosure.CreateArrayElement(salt, claimValue);
        }
    }


    /// <summary>
    /// Writes a disclosure to a CBOR writer.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="disclosure">The disclosure to write.</param>
    public static void WriteDisclosure(CborWriter writer, SdDisclosure disclosure)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(disclosure);

        if(disclosure.ClaimName is not null)
        {
            writer.WriteStartArray(3);
            writer.WriteByteString(disclosure.Salt.Span);
            writer.WriteTextString(disclosure.ClaimName);
            CborValueConverter.WriteValue(writer, disclosure.ClaimValue);
            writer.WriteEndArray();
        }
        else
        {
            writer.WriteStartArray(2);
            writer.WriteByteString(disclosure.Salt.Span);
            CborValueConverter.WriteValue(writer, disclosure.ClaimValue);
            writer.WriteEndArray();
        }
    }


    /// <summary>
    /// Reads a disclosure from a CBOR reader.
    /// </summary>
    /// <param name="reader">The CBOR reader (passed by reference for efficiency).</param>
    /// <returns>The parsed disclosure.</returns>
    public static SdDisclosure ReadDisclosure(ref CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? arrayLength = reader.ReadStartArray();
        if(arrayLength is not (2 or 3))
        {
            throw new CborContentException($"Disclosure must have 2 or 3 elements, got {arrayLength}.");
        }

        byte[] salt = reader.ReadByteString();

        if(arrayLength == 3)
        {
            string claimName = reader.ReadTextString();
            object? claimValue = CborValueConverter.ReadValue(ref reader);
            reader.ReadEndArray();

            return SdDisclosure.CreateProperty(salt, claimName, claimValue);
        }
        else
        {
            object? claimValue = CborValueConverter.ReadValue(ref reader);
            reader.ReadEndArray();

            return SdDisclosure.CreateArrayElement(salt, claimValue);
        }
    }


    /// <summary>
    /// Reads the sd_claims array from the unprotected header.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the sd_claims array.</param>
    /// <returns>The list of disclosures.</returns>
    public static IReadOnlyList<SdDisclosure> ReadSdClaimsHeader(ref CborReader reader)
    {
        ArgumentNullException.ThrowIfNull(reader);
        int? count = reader.ReadStartArray();
        var disclosures = new List<SdDisclosure>(count ?? 4);

        while(reader.PeekState() != CborReaderState.EndArray)
        {
            SdDisclosure disclosure = ReadDisclosure(ref reader);
            disclosures.Add(disclosure);
        }

        reader.ReadEndArray();
        return disclosures;
    }


    /// <summary>
    /// Writes the sd_claims header entry to a CBOR writer.
    /// </summary>
    /// <param name="writer">The CBOR writer.</param>
    /// <param name="disclosures">The list of disclosures to write.</param>
    /// <remarks>
    /// <para>
    /// This writes the header key (<see cref="SdClaimsHeaderKey"/>) followed by an array
    /// of CBOR-encoded disclosures. The caller is responsible for starting and ending
    /// the containing map.
    /// </para>
    /// </remarks>
    public static void WriteSdClaimsHeader(CborWriter writer, IReadOnlyList<SdDisclosure> disclosures)
    {
        ArgumentNullException.ThrowIfNull(writer);
        ArgumentNullException.ThrowIfNull(disclosures);

        writer.WriteInt32(SdClaimsHeaderKey);
        writer.WriteStartArray(disclosures.Count);

        foreach(SdDisclosure disclosure in disclosures)
        {
            WriteDisclosure(writer, disclosure);
        }

        writer.WriteEndArray();
    }


    /// <summary>
    /// Computes the digest of a CBOR-encoded disclosure.
    /// </summary>
    /// <param name="disclosureCbor">The CBOR-encoded disclosure bytes.</param>
    /// <param name="algorithm">The hash algorithm name (e.g., "sha-256").</param>
    /// <returns>The hash digest bytes.</returns>
    /// <remarks>
    /// <para>
    /// Per draft-ietf-spice-sd-cwt, digests are computed over the CBOR-encoded
    /// disclosure bytes. This is used to create the redacted claim references
    /// in the payload.
    /// </para>
    /// </remarks>
    public static byte[] ComputeDisclosureDigest(ReadOnlySpan<byte> disclosureCbor, string algorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);

        using HashAlgorithm hasher = CreateHashAlgorithm(algorithm);
        byte[] hash = new byte[hasher.HashSize / 8];
        hasher.TryComputeHash(disclosureCbor, hash, out _);

        return hash;
    }


    /// <summary>
    /// Computes the digest of a CBOR-encoded disclosure.
    /// </summary>
    /// <param name="disclosureCbor">The CBOR-encoded disclosure bytes.</param>
    /// <param name="algorithm">The hash algorithm name (e.g., "sha-256").</param>
    /// <returns>The hash digest bytes.</returns>
    public static byte[] ComputeDisclosureDigest(byte[] disclosureCbor, string algorithm)
    {
        return ComputeDisclosureDigest(disclosureCbor.AsSpan(), algorithm);
    }


    /// <summary>
    /// Computes the SD hash for key binding.
    /// </summary>
    /// <param name="sdClaimsCbor">The CBOR-encoded sd_claims array.</param>
    /// <param name="algorithm">The hash algorithm name.</param>
    /// <returns>The hash digest bytes.</returns>
    /// <remarks>
    /// Per draft-ietf-spice-sd-cwt, the sd_hash is computed over the entire
    /// sd_claims array in the unprotected header.
    /// </remarks>
    public static byte[] ComputeSdHash(
        ReadOnlySpan<byte> sdClaimsCbor,
        string algorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);

        using HashAlgorithm hasher = CreateHashAlgorithm(algorithm);
        byte[] hash = new byte[hasher.HashSize / 8];
        hasher.TryComputeHash(sdClaimsCbor, hash, out _);

        return hash;
    }


    private static HashAlgorithm CreateHashAlgorithm(string algorithm)
    {
        if(WellKnownHashAlgorithms.IsSha256(algorithm))
        {
            return SHA256.Create();
        }

        if(WellKnownHashAlgorithms.IsSha384(algorithm))
        {
            return SHA384.Create();
        }

        if(WellKnownHashAlgorithms.IsSha512(algorithm))
        {
            return SHA512.Create();
        }

        throw new ArgumentException($"Unsupported hash algorithm: '{algorithm}'.", nameof(algorithm));
    }
}