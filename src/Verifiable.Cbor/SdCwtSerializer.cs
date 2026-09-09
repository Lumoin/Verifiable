using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Lumoin.Veritas.Cbor;
using System.Security.Cryptography;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Core.Model.SelectiveDisclosure;

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
        CborConformanceMode conformanceMode = CborConformanceMode.RfcCanonical)
    {
        ArgumentNullException.ThrowIfNull(message);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborSerializerOptions.Default(conformanceMode));

        //COSE_Sign1 = tag(18) [protected, unprotected, payload, signature].
        writer.WriteTag(new CborTag((ulong)CoseTags.Sign1));
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

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Parses an SD-CWT message from COSE_Sign1 format. Wire-decoded salt bytes from
    /// each contained disclosure are wrapped in <see cref="Salt"/> instances using the
    /// supplied <paramref name="saltTag"/>; the resulting message owns those salts via
    /// the held disclosures.
    /// </summary>
    /// <param name="coseSign1">The CBOR-encoded COSE_Sign1 bytes.</param>
    /// <param name="saltTag">The tag stamped on each wrapped <see cref="Salt"/>.</param>
    /// <param name="pool">Memory pool for allocating salt buffers.</param>
    /// <returns>The parsed SD-CWT message. Caller owns and disposes (which disposes
    /// every contained disclosure and salt).</returns>
    /// <exception cref="CborContentException">Thrown when the format is invalid.</exception>
    public static SdCwtMessage Parse(ReadOnlyMemory<byte> coseSign1, Tag saltTag, BaseMemoryPool pool) =>
        Parse(coseSign1, saltTag, pool, out _);


    /// <summary>
    /// Parses an SD-CWT message and additionally surfaces each disclosure's CBOR bytes exactly as
    /// the unprotected header carried them.
    /// </summary>
    /// <remarks>
    /// A disclosure's digest is a commitment to the bytes the Issuer hashed, so the binding is
    /// answered against those bytes and never against a re-encoding of the parsed value — this is
    /// the same rule <see cref="Verifiable.Json.Sd.SdJwtSerializer"/> follows for
    /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see> §4.2.3, and it keeps a
    /// validly encoded disclosure that this library would have written differently from failing
    /// to bind.
    /// </remarks>
    /// <param name="coseSign1">The CBOR-encoded COSE_Sign1 bytes.</param>
    /// <param name="saltTag">The tag stamped on each wrapped <see cref="Salt"/>.</param>
    /// <param name="pool">Memory pool for allocating salt buffers.</param>
    /// <param name="disclosureWireBytes">
    /// Each disclosure's CBOR bytes as they arrived, in the same order as the returned message's
    /// <see cref="SdCwtMessage.Disclosures"/>.
    /// </param>
    /// <returns>The parsed SD-CWT message. Caller owns and disposes it.</returns>
    /// <exception cref="CborContentException">Thrown when the format is invalid.</exception>
    internal static SdCwtMessage Parse(
        ReadOnlyMemory<byte> coseSign1,
        Tag saltTag,
        BaseMemoryPool pool,
        out IReadOnlyList<byte[]> disclosureWireBytes)
    {
        ArgumentNullException.ThrowIfNull(saltTag);
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new CborReader(coseSign1, CborOptions.Lax);

        //Read and validate COSE_Sign1 tag.
        CborTag tag = reader.ReadTag();
        if((int)tag.Value != CoseTags.Sign1)
        {
            throw new CborContentException($"Expected COSE_Sign1 tag (18), got {(int)tag.Value}.");
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
        var wireBytes = new List<byte[]>();
        reader.ReadStartMap();

        try
        {
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
                        SdDisclosure disclosure = ParseDisclosure(disclosureCbor, saltTag, pool);
                        disclosures.Add(disclosure);
                        wireBytes.Add(disclosureCbor);
                    }
                    reader.ReadEndArray();
                }
                else
                {
                    reader.SkipValue();
                }
            }
        }
        catch
        {
            //Mid-parse failure — dispose every disclosure already constructed.
            foreach(SdDisclosure d in disclosures)
            {
                d.Dispose();
            }
            throw;
        }

        reader.ReadEndMap();

        //Payload.
        byte[] payload = reader.ReadByteString();

        //Signature.
        byte[] signature = reader.ReadByteString();

        reader.ReadEndArray();

        disclosureWireBytes = wireBytes;

        return new SdCwtMessage(payload, protectedHeader, signature, disclosures);
    }


    /// <summary>
    /// Parses an SD-CWT message from COSE_Sign1 format into a structured
    /// <see cref="SdToken{TEnvelope}"/>. Computes <see cref="SdToken{TEnvelope}.DisclosurePaths"/>
    /// and <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> by walking the payload's digest
    /// tree, sharing the walker core with <see cref="SdCwtPathExtraction.ExtractPaths(SdCwtMessage, EncodeDelegate, BaseMemoryPool, string)"/>.
    /// </summary>
    /// <param name="coseSign1">The CBOR-encoded COSE_Sign1 bytes.</param>
    /// <param name="saltTag">The tag stamped on each wrapped <see cref="Salt"/>.</param>
    /// <param name="pool">Memory pool for allocating salt buffers.</param>
    /// <param name="encoder">Delegate for Base64Url encoding, used to compute disclosure digests.</param>
    /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
    /// <returns>The parsed token. Caller owns and disposes it (which disposes every contained
    /// disclosure and salt).</returns>
    /// <exception cref="CborContentException">Thrown when the COSE_Sign1 envelope is invalid.</exception>
    /// <exception cref="FormatException">
    /// Thrown when two disclosures carry the same salt bytes, when a same-level claim name
    /// collides, or when a disclosure is not referenced by any digest in the payload.
    /// </exception>
    public static SdToken<ReadOnlyMemory<byte>> ParseToken(
        ReadOnlyMemory<byte> coseSign1,
        Tag saltTag,
        BaseMemoryPool pool,
        EncodeDelegate encoder,
        string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana)
    {
        ArgumentNullException.ThrowIfNull(saltTag);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(encoder);

        SdCwtMessage message = Parse(coseSign1, saltTag, pool, out IReadOnlyList<byte[]> disclosureWireBytes);

        try
        {
            var digestToDisclosure = new Dictionary<string, SdDisclosure>(StringComparer.Ordinal);

            //draft-ietf-spice-sd-cwt follows RFC 9901 §9.3: the Issuer chooses an independent salt
            //per disclosure. SdDisclosure equality is its salt bytes, so this set detects a wire
            //form that carries two disclosures under one salt — a shape that would let a forged
            //disclosure ride a legitimate one's identity through the parse plumbing.
            var saltsSeen = new HashSet<SdDisclosure>();

            for(int i = 0; i < message.Disclosures.Count; i++)
            {
                SdDisclosure disclosure = message.Disclosures[i];

                if(!saltsSeen.Add(disclosure))
                {
                    throw new FormatException(
                        "draft-ietf-spice-sd-cwt (RFC 9901 §9.3): two Disclosures carry the same salt value; the Issuer must choose a new salt for each claim.");
                }

                //The digest is computed over the disclosure's bytes exactly as the unprotected
                //header carried them (RFC 9901 §4.2.3's rule), never a re-encoding of the parsed
                //value, which a validly encoded disclosure could legitimately differ from.
                byte[] digestBytes = ComputeDisclosureDigest(disclosureWireBytes[i], hashAlgorithm, pool);
                digestToDisclosure[encoder(digestBytes)] = disclosure;
            }

            SdCwtWalkResult walkResult = SdCwtPathExtraction.Walk(message.Payload, digestToDisclosure, encoder);

            //draft-ietf-spice-sd-cwt mirrors RFC 9901 §7.1 step 5: every Disclosure the wire
            //form carries must be referenced by some digest — one the walk could not place is a
            //parse failure, not silently dropped.
            foreach(SdDisclosure disclosure in message.Disclosures)
            {
                if(!walkResult.DisclosurePaths.ContainsKey(disclosure))
                {
                    throw new FormatException(
                        $"draft-ietf-spice-sd-cwt: the disclosure '{disclosure}' is not referenced by any digest in the issuer-signed payload.");
                }
            }

            return SdToken<ReadOnlyMemory<byte>>.CreateParsed(
                coseSign1.ToArray(),
                message.Disclosures,
                new SdDisclosurePaths(walkResult.DisclosurePaths),
                walkResult.IssuerSignedClaims,
                walkResult.DisclosureInteriorClaims);
        }
        catch
        {
            //The payload failed the digest-resolution rules — dispose every disclosure
            //already parsed before propagating. The token never came into existence.
            foreach(SdDisclosure d in message.Disclosures)
            {
                d.Dispose();
            }
            throw;
        }
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
        CborConformanceMode conformanceMode = CborConformanceMode.RfcCanonical)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborSerializerOptions.Default(conformanceMode));
        writer.WriteStartArray(4);
        writer.WriteTextString("Signature1");
        writer.WriteByteString(protectedHeader);
        writer.WriteByteString(externalAad);
        writer.WriteByteString(payload);
        writer.WriteEndArray();

        return buffer.WrittenSpan.ToArray();
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
        CborConformanceMode conformanceMode = CborConformanceMode.RfcCanonical)
    {
        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborSerializerOptions.Default(conformanceMode));

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

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Serializes a disclosure to CBOR format.
    /// </summary>
    /// <param name="disclosure">The disclosure to serialize.</param>
    /// <param name="conformanceMode">CBOR conformance mode for deterministic encoding.</param>
    /// <returns>The CBOR-encoded disclosure bytes.</returns>
    public static byte[] SerializeDisclosure(
        SdDisclosure disclosure,
        CborConformanceMode conformanceMode = CborConformanceMode.RfcCanonical)
    {
        ArgumentNullException.ThrowIfNull(disclosure);

        var buffer = new ArrayBufferWriter<byte>();
        var writer = new CborWriter(buffer, CborSerializerOptions.Default(conformanceMode));

        if(disclosure.ClaimName is not null)
        {
            //Property disclosure: [salt, name, value].
            writer.WriteStartArray(3);
            writer.WriteByteString(disclosure.Salt.AsReadOnlySpan());
            writer.WriteTextString(disclosure.ClaimName);
            CborValueConverter.WriteValue(writer, disclosure.ClaimValue);
            writer.WriteEndArray();
        }
        else
        {
            //Array element disclosure: [salt, value].
            writer.WriteStartArray(2);
            writer.WriteByteString(disclosure.Salt.AsReadOnlySpan());
            CborValueConverter.WriteValue(writer, disclosure.ClaimValue);
            writer.WriteEndArray();
        }

        return buffer.WrittenSpan.ToArray();
    }


    /// <summary>
    /// Parses a disclosure from CBOR format. The wire-decoded salt bytes are wrapped in
    /// a <see cref="Salt"/> with the supplied <paramref name="saltTag"/>; the resulting
    /// disclosure owns that salt and disposes it on disposal.
    /// </summary>
    /// <param name="disclosureCbor">The CBOR-encoded disclosure bytes.</param>
    /// <param name="saltTag">
    /// The tag stamped on the wrapped <see cref="Salt"/>. Should record that the bytes
    /// originated from a wire decode (no entropy operation in this process).
    /// </param>
    /// <param name="pool">Memory pool for allocating the salt buffer.</param>
    /// <returns>The parsed disclosure. Caller owns and must dispose.</returns>
    /// <exception cref="CborContentException">Thrown when the format is invalid.</exception>
    public static SdDisclosure ParseDisclosure(
        ReadOnlySpan<byte> disclosureCbor,
        Tag saltTag,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(saltTag);
        ArgumentNullException.ThrowIfNull(pool);

        var reader = new CborReader(disclosureCbor.ToArray(), CborOptions.Lax);
        return ReadDisclosure(ref reader, saltTag, pool);
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
            writer.WriteByteString(disclosure.Salt.AsReadOnlySpan());
            writer.WriteTextString(disclosure.ClaimName);
            CborValueConverter.WriteValue(writer, disclosure.ClaimValue);
            writer.WriteEndArray();
        }
        else
        {
            writer.WriteStartArray(2);
            writer.WriteByteString(disclosure.Salt.AsReadOnlySpan());
            CborValueConverter.WriteValue(writer, disclosure.ClaimValue);
            writer.WriteEndArray();
        }
    }


    /// <summary>
    /// Reads a disclosure from a CBOR reader. The wire-decoded salt bytes are wrapped
    /// in a <see cref="Salt"/> with the supplied <paramref name="saltTag"/>; the
    /// resulting disclosure owns that salt and disposes it on disposal.
    /// </summary>
    /// <param name="reader">The CBOR reader (passed by reference for efficiency).</param>
    /// <param name="saltTag">The tag stamped on the wrapped <see cref="Salt"/>.</param>
    /// <param name="pool">Memory pool for allocating the salt buffer.</param>
    /// <returns>The parsed disclosure. Caller owns and must dispose.</returns>
    [SuppressMessage(
        "Reliability", "CA2000",
        Justification =
            "The constructed Salt's ownership is transferred to the SdDisclosure via " +
            "CreateProperty/CreateArrayElement. Those factories dispose the salt on " +
            "construction failure. The remaining failure cases (mid-parse) explicitly " +
            "dispose `salt` before throwing. The analyzer cannot see this ownership " +
            "transfer through factory methods.")]
    public static SdDisclosure ReadDisclosure(ref CborReader reader, Tag saltTag, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(saltTag);
        ArgumentNullException.ThrowIfNull(pool);

        int? arrayLength = reader.ReadStartArray();
        if(arrayLength is not (2 or 3))
        {
            throw new CborContentException($"Disclosure must have 2 or 3 elements, got {arrayLength}.");
        }

        byte[] saltBytes = reader.ReadByteString();

        //Wrap the wire-decoded salt bytes in a Salt instance. Ownership of the
        //IMemoryOwner transfers into the Salt; the Salt then transfers into the
        //SdDisclosure via the factory below. If anything in the wrapping or
        //subsequent parsing fails, we explicitly dispose to release pool capacity.
        IMemoryOwner<byte> owner = pool.Rent(saltBytes.Length);
        Salt salt;
        try
        {
            saltBytes.AsSpan().CopyTo(owner.Memory.Span[..saltBytes.Length]);
            salt = new Salt(owner, saltTag, lifetime: null);
        }
        catch
        {
            owner.Dispose();
            throw;
        }

        //From here, ownership is with `salt`. CreateProperty/CreateArrayElement take
        //ownership of `salt` and dispose it on construction failure. Failures during
        //the rest of the parse (before the factory call) are caught here.
        try
        {
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
        catch
        {
            salt.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Reads the sd_claims array from the unprotected header.
    /// </summary>
    /// <param name="reader">The CBOR reader positioned at the sd_claims array.</param>
    /// <param name="saltTag">The tag stamped on each wrapped <see cref="Salt"/>.</param>
    /// <param name="pool">Memory pool for allocating salt buffers.</param>
    /// <returns>The list of disclosures. Caller owns and must dispose each.</returns>
    public static IReadOnlyList<SdDisclosure> ReadSdClaimsHeader(
        ref CborReader reader,
        Tag saltTag,
        BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(saltTag);
        ArgumentNullException.ThrowIfNull(pool);

        int? count = reader.ReadStartArray();
        var disclosures = new List<SdDisclosure>(count ?? 4);

        try
        {
            while(reader.PeekState() != CborReaderState.EndArray)
            {
                SdDisclosure disclosure = ReadDisclosure(ref reader, saltTag, pool);
                disclosures.Add(disclosure);
            }
        }
        catch
        {
            //Mid-read failure — dispose every disclosure already constructed.
            foreach(SdDisclosure d in disclosures)
            {
                d.Dispose();
            }
            throw;
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
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <returns>The hash digest bytes.</returns>
    /// <remarks>
    /// <para>
    /// Per draft-ietf-spice-sd-cwt, digests are computed over the CBOR-encoded
    /// disclosure bytes. This is used to create the redacted claim references
    /// in the payload.
    /// </para>
    /// </remarks>
    public static byte[] ComputeDisclosureDigest(ReadOnlySpan<byte> disclosureCbor, string algorithm, BaseMemoryPool pool)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);
        ArgumentNullException.ThrowIfNull(pool);

        (Tag tag, int length, string? qualifier) = ResolveDigestTag(algorithm);
        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(disclosureCbor, length, tag, pool, qualifier);

        //The pooled digest buffer may be larger than the requested length (pool implementations are free to
        //over-allocate); slice to the algorithm's exact output size before copying out.
        return digest.AsReadOnlySpan()[..length].ToArray();
    }


    /// <summary>
    /// Computes the digest of a CBOR-encoded disclosure.
    /// </summary>
    /// <param name="disclosureCbor">The CBOR-encoded disclosure bytes.</param>
    /// <param name="algorithm">The hash algorithm name (e.g., "sha-256").</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <returns>The hash digest bytes.</returns>
    public static byte[] ComputeDisclosureDigest(byte[] disclosureCbor, string algorithm, BaseMemoryPool pool)
    {
        return ComputeDisclosureDigest(disclosureCbor.AsSpan(), algorithm, pool);
    }


    /// <summary>
    /// Computes the SD hash for key binding.
    /// </summary>
    /// <param name="sdClaimsCbor">The CBOR-encoded sd_claims array.</param>
    /// <param name="algorithm">The hash algorithm name.</param>
    /// <param name="pool">The memory pool the digest is rented from.</param>
    /// <returns>The hash digest bytes.</returns>
    /// <remarks>
    /// Per draft-ietf-spice-sd-cwt, the sd_hash is computed over the entire
    /// sd_claims array in the unprotected header.
    /// </remarks>
    public static byte[] ComputeSdHash(
        ReadOnlySpan<byte> sdClaimsCbor,
        string algorithm,
        BaseMemoryPool pool)
    {
        ArgumentException.ThrowIfNullOrEmpty(algorithm);
        ArgumentNullException.ThrowIfNull(pool);

        (Tag tag, int length, string? qualifier) = ResolveDigestTag(algorithm);
        using DigestValue digest = CryptographicKeyEvents.ComputeDigest(sdClaimsCbor, length, tag, pool, qualifier);

        //The pooled digest buffer may be larger than the requested length (pool implementations are free to
        //over-allocate); slice to the algorithm's exact output size before copying out.
        return digest.AsReadOnlySpan()[..length].ToArray();
    }


    /// <summary>
    /// Maps an SD-CWT digest algorithm name (in any format <see cref="WellKnownHashAlgorithms"/> recognizes,
    /// e.g. the IANA <c>"sha-256"</c> spelling draft-ietf-spice-sd-cwt uses) to the registered digest seam's
    /// <see cref="Tag"/>, output byte length, and <see cref="CryptographicKeyEvents.ComputeDigest"/> qualifier.
    /// Fails closed with <see cref="ArgumentException"/> for an unrecognized algorithm rather than defaulting
    /// to SHA-256.
    /// </summary>
    /// <param name="algorithm">The hash algorithm name.</param>
    /// <returns>The digest <see cref="Tag"/>, output byte length, and seam qualifier for <paramref name="algorithm"/>.</returns>
    /// <exception cref="ArgumentException">Thrown for an unsupported algorithm name.</exception>
    private static (Tag Tag, int Length, string? Qualifier) ResolveDigestTag(string algorithm) => algorithm switch
    {
        _ when WellKnownHashAlgorithms.IsSha256(algorithm) => (CryptoTags.Sha256Digest, WellKnownHashAlgorithms.Sha256SizeBytes, null),
        _ when WellKnownHashAlgorithms.IsSha384(algorithm) => (CryptoTags.Sha384Digest, WellKnownHashAlgorithms.Sha384SizeBytes, nameof(HashAlgorithmName.SHA384)),
        _ when WellKnownHashAlgorithms.IsSha512(algorithm) => (CryptoTags.Sha512Digest, WellKnownHashAlgorithms.Sha512SizeBytes, nameof(HashAlgorithmName.SHA512)),
        _ => throw new ArgumentException($"Unsupported hash algorithm: '{algorithm}'.", nameof(algorithm))
    };
}
