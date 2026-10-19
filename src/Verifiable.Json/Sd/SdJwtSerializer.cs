using System.Buffers;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;

namespace Verifiable.Json.Sd;

/// <summary>
/// JSON serialization for SD-JWT disclosures and tokens.
/// </summary>
/// <remarks>
/// <para>
/// SD-JWT uses a compact serialization format:
/// <c>&lt;issuer-jwt&gt;~&lt;disclosure1&gt;~&lt;disclosure2&gt;~...~[kb-jwt]</c>
/// </para>
/// <para>
/// Disclosures are Base64Url-encoded JSON arrays: <c>[salt, name?, value]</c>.
/// </para>
/// </remarks>
public static class SdJwtSerializer
{
    /// <summary>
    /// Serializes a disclosure to its Base64Url-encoded form. A disclosure read from the wire keeps its salt's wire string
    /// (<see cref="SdDisclosure.EncodedSalt"/>), which is written as it was read; a disclosure created from salt bytes writes them
    /// base64url-encoded.
    /// </summary>
    /// <param name="disclosure">The disclosure to serialize.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <returns>The Base64Url-encoded disclosure string.</returns>
    public static string SerializeDisclosure(SdDisclosure disclosure, EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(disclosure);
        ArgumentNullException.ThrowIfNull(encoder);

        var saltString = disclosure.EncodedSalt ?? encoder(disclosure.Salt.AsReadOnlySpan());

        using var stream = new MemoryStream();
        using(var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartArray();
            writer.WriteStringValue(saltString);

            if(disclosure.ClaimName is not null)
            {
                writer.WriteStringValue(disclosure.ClaimName);
            }

            WriteClaimValue(writer, disclosure.ClaimValue);
            writer.WriteEndArray();
        }

        return encoder(stream.ToArray());
    }


    /// <summary>
    /// Reads a disclosure from its Base64Url-encoded form (RFC 9901 section 4.2). Its salt is a JSON string, kept as the wire
    /// wrote it (<see cref="SdDisclosure.EncodedSalt"/>); its bytes, the identity the disclosure is compared and committed to
    /// by, are those the string encodes when it is base64url text and its UTF-8 bytes otherwise. Its claim name, of a
    /// three-element disclosure, is any JSON string, the empty string among them. The disclosure owns a salt rented from
    /// <paramref name="pool"/> and disposes it on disposal.
    /// </summary>
    /// <param name="encoded">The Base64Url-encoded disclosure string.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="saltTag">
    /// The tag stamped on the wrapped <see cref="Salt"/>. Should record that the bytes
    /// originated from a wire decode (no entropy operation in this process). The
    /// application supplies a tag with appropriate <c>Purpose</c> and provenance entries.
    /// </param>
    /// <returns>
    /// The disclosure read (<see cref="SdDisclosureRead"/>), which the caller owns; or the refusal of a disclosure of no shape
    /// RFC 9901 section 4.2 defines (<see cref="SdDisclosureRefused"/>): text the decoder refuses as no base64url (its
    /// <see cref="FormatException"/>), decoded text that is not valid JSON, no JSON array of two or three elements, or a salt or
    /// claim name that is no JSON string. Any other failure of the decoder or of the allocator, cancellation among them, is
    /// theirs and surfaces as it is.
    /// </returns>
    public static SdDisclosureReading ParseDisclosure(string encoded, DecodeDelegate decoder, BaseMemoryPool pool, Tag saltTag)
    {
        ArgumentException.ThrowIfNullOrEmpty(encoded);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(saltTag);

        using var jsonBytes = DecodedWireText(encoded, decoder, pool);

        if(jsonBytes is null)
        {
            return new SdDisclosureRefused(SdJwtWireDefect.DisclosureNotBase64UrlText, "The disclosure is no base64url text (RFC 9901 section 4.2).");
        }

        using var document = JsonDocumentOrNone(jsonBytes.Memory);

        if(document is null)
        {
            return new SdDisclosureRefused(SdJwtWireDefect.DisclosureNotJson, "The disclosure is not valid JSON (RFC 9901 section 4.2).");
        }

        var root = document.RootElement;

        if(root.ValueKind != JsonValueKind.Array)
        {
            return new SdDisclosureRefused(SdJwtWireDefect.DisclosureNotAnArray, "A disclosure is a JSON array (RFC 9901 section 4.2).");
        }

        var length = root.GetArrayLength();

        if(length is < 2 or > 3)
        {
            return new SdDisclosureRefused(
                SdJwtWireDefect.DisclosureElementCount, $"A disclosure array has two or three elements (RFC 9901 section 4.2), this one {length}.");
        }

        //RFC 9901 section 4.2.1: the salt and the claim name are each a JSON string, and nothing more is required of either; the
        //names _sd and ... are reserved, which the digest resolution refuses where a disclosure is placed into an object.
        if(root[0].ValueKind != JsonValueKind.String || root[0].GetString() is not { } saltText)
        {
            return new SdDisclosureRefused(SdJwtWireDefect.SaltNotAString, "A disclosure's salt is a JSON string (RFC 9901 section 4.2.1).");
        }

        var claimName = length == 3 ? ClaimNameOrNone(root[1]) : null;

        if(length == 3 && claimName is null)
        {
            return new SdDisclosureRefused(SdJwtWireDefect.ClaimNameNotAString, "A disclosure's claim name is a JSON string (RFC 9901 section 4.2.1).");
        }

        var value = JsonElementConversion.Convert(root[length - 1]);

        //The salt's bytes are those its text encodes when it is base64url text, which RFC 9901 section 4.2.1 recommends, and the
        //text's own UTF-8 bytes otherwise; the text itself is kept as the wire wrote it.
        using var decodedSalt = IsBase64UrlText(saltText) ? DecodedWireText(saltText, decoder, pool) : null;

        var saltBytes = decodedSalt is not null ? decodedSalt.Memory.Span : Encoding.UTF8.GetBytes(saltText);

        return claimName is null
            ? new SdDisclosureRead(SdDisclosure.ReadArrayElement(saltBytes, saltText, saltTag, pool, value))
            : new SdDisclosureRead(SdDisclosure.ReadProperty(saltBytes, saltText, saltTag, pool, claimName, value));
    }


    /// <summary>The claim name a disclosure's second element states, or <see langword="null"/> when it is no JSON string.</summary>
    /// <param name="element">The element.</param>
    /// <returns>The claim name, the empty string among them, or <see langword="null"/>.</returns>
    private static string? ClaimNameOrNone(JsonElement element) =>
        element.ValueKind == JsonValueKind.String ? element.GetString() : null;


    /// <summary>
    /// The bytes a base64url text of the wire names, or <see langword="null"/> when the decoder refuses the text as no base64url,
    /// its <see cref="FormatException"/>; any other failure of the decoder or of the allocator, cancellation among them, is theirs
    /// and surfaces as it is.
    /// </summary>
    /// <param name="text">The base64url text.</param>
    /// <param name="decoder">The decoder.</param>
    /// <param name="pool">The pool the bytes are rented from.</param>
    /// <returns>The bytes, which the caller disposes, or <see langword="null"/>.</returns>
    internal static IMemoryOwner<byte>? DecodedWireText(string text, DecodeDelegate decoder, BaseMemoryPool pool)
    {
        try
        {
            return decoder(text, pool);
        }
        catch(FormatException)
        {
            return null;
        }
    }


    /// <summary>
    /// The JSON document a UTF-8 text is, or <see langword="null"/> when the text is not valid JSON, the reader's refusal, its
    /// <see cref="JsonException"/>.
    /// </summary>
    /// <param name="utf8Json">The UTF-8 text.</param>
    /// <returns>The document, which the caller disposes, or <see langword="null"/>.</returns>
    internal static JsonDocument? JsonDocumentOrNone(ReadOnlyMemory<byte> utf8Json)
    {
        try
        {
            return JsonDocument.Parse(utf8Json);
        }
        catch(JsonException)
        {
            return null;
        }
    }


    /// <summary>
    /// Serializes an SD-JWT token to its wire format.
    /// </summary>
    /// <param name="token">The token to serialize.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <returns>The serialized SD-JWT string.</returns>
    public static string SerializeToken(SdToken<string> token, EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(encoder);

        var builder = new StringBuilder();
        _ = builder.Append(token.IssuerSigned);
        _ = builder.Append(SdConstants.JwtSeparator);

        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            _ = builder.Append(SerializeDisclosure(disclosure, encoder));
            _ = builder.Append(SdConstants.JwtSeparator);
        }

        if(token.KeyBinding is not null)
        {
            builder.Length--;
            _ = builder.Append(SdConstants.JwtSeparator);
            _ = builder.Append(token.KeyBinding);
        }

        return builder.ToString();
    }


    /// <summary>
    /// Reads an SD-JWT token from its compact serialization by the grammar of RFC 9901 section 4: the Issuer-signed JWT, a
    /// <c>~</c>, each disclosure followed by its <c>~</c>, and then either nothing, which leaves the serialization's last
    /// component empty, or exactly one Key Binding JWT. Computes <see cref="SdToken{TEnvelope}.DisclosurePaths"/> and
    /// <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> by walking the issuer-signed payload's digest tree, sharing the walker
    /// core with <see cref="SdJwtPathExtraction.ExtractPaths"/>.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT string.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="encoder">Delegate for Base64Url encoding, used to compute disclosure digests.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="saltTag">
    /// The tag to stamp on each wire-decoded <see cref="Salt"/> (one per disclosure).
    /// </param>
    /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
    /// <returns>
    /// The token read (<see cref="SdJwtRead"/>), which the caller owns: disposing it disposes all contained disclosures and their
    /// salts. Or the refusal of the wire shape (<see cref="SdJwtRefused"/>): no separator, an empty component before the last, a
    /// compact JWS among the disclosures (a Key Binding JWT repeated or not final), a last component that is neither empty nor
    /// one compact JWS, an Issuer-signed JWT that is no compact JWS, a disclosure <see cref="ParseDisclosure"/> refuses, an
    /// issuer-signed payload that is no base64url text or not valid JSON, two disclosures under one salt string (RFC 9901
    /// section 9.3), a digest rule of RFC 9901 section 7.1 step 3.c or 4 broken, or a disclosure no digest references (step 5).
    /// A failure of the decoder beyond its refusal of text as no base64url, of the encoder, of the digest implementation or of
    /// the allocator, cancellation among them, is theirs and surfaces as it is.
    /// </returns>
    public static SdJwtReading ParseToken(
        string sdJwt,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        BaseMemoryPool pool,
        Tag saltTag,
        string hashAlgorithm)
    {
        ArgumentException.ThrowIfNullOrEmpty(sdJwt);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(saltTag);
        ArgumentException.ThrowIfNullOrEmpty(hashAlgorithm);

        var components = sdJwt.Split(SdConstants.JwtSeparator);

        if(components.Length < 2)
        {
            return new SdJwtRefused(SdJwtWireDefect.SeparatorMissing, "An SD-JWT carries the Issuer-signed JWT followed by a separator (RFC 9901 section 4).");
        }

        var issuerJwt = components[0];

        if(!IsCompactJws(issuerJwt))
        {
            return new SdJwtRefused(SdJwtWireDefect.IssuerJwtNotCompactJws, "The Issuer-signed JWT is no compact JWS of three base64url segments (RFC 7515 section 7.1).");
        }

        //RFC 9901 section 4: every disclosure is followed by its separator, so every component between the Issuer-signed JWT and
        //the last separator is one disclosure, never empty and never a JWT; the last component is empty, an SD-JWT's closing
        //separator having nothing after it, or the one Key Binding JWT of an SD-JWT+KB.
        var lastComponent = components[^1];

        if(lastComponent.Length > 0 && !IsCompactJws(lastComponent))
        {
            return new SdJwtRefused(
                SdJwtWireDefect.TerminatorMissing,
                "The last component of an SD-JWT is empty, after the separator closing its disclosures, or one Key Binding JWT (RFC 9901 section 4).");
        }

        for(var i = 1; i < components.Length - 1; i++)
        {
            if(components[i].Length == 0)
            {
                return new SdJwtRefused(SdJwtWireDefect.ComponentEmpty, "A disclosure of an SD-JWT is never empty: two separators do not follow each other (RFC 9901 section 4).");
            }

            if(IsCompactJws(components[i]))
            {
                return new SdJwtRefused(SdJwtWireDefect.KeyBindingJwtNotFinal, "A Key Binding JWT is the one final component of an SD-JWT+KB (RFC 9901 section 4).");
            }
        }

        var keyBindingJwt = lastComponent.Length > 0 ? lastComponent : null;

        var disclosures = new List<SdDisclosure>();
        var reading = ReadDisclosures(components, decoder, encoder, pool, saltTag, hashAlgorithm, disclosures);

        if(reading is SdJwtWalked walked)
        {
            //The reading takes the token's ownership and passes it to the caller with the answer it is carried in.
            var token = SdToken<string>.CreateParsed(
                issuerJwt,
                disclosures,
                new SdDisclosurePaths(walked.Result.DisclosurePaths),
                walked.Result.IssuerSignedClaims,
                walked.Result.DisclosureInteriorClaims,
                keyBindingJwt);

            try
            {
                var read = new SdJwtRead(token);
                token = null;

                return read;
            }
            finally
            {
                token?.Dispose();
            }
        }

        //The token never came into existence: every disclosure already read is released before the refusal is answered.
        foreach(SdDisclosure disclosure in disclosures)
        {
            disclosure.Dispose();
        }

        return reading is SdJwtWalkRefused refused
            ? new SdJwtRefused(refused.Defect, refused.Description)
            : throw new InvalidOperationException("The reading of the disclosures answered a reading it never answers.");
    }


    /// <summary>
    /// Reads the disclosures of a serialization whose grammar is checked, adding each to <paramref name="disclosures"/> as it is
    /// read so the caller releases every one on any refusal or fault, then walks the issuer-signed payload's digests over them.
    /// </summary>
    /// <param name="components">The serialization's components: the Issuer-signed JWT, the disclosures, the last component.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="encoder">Delegate for Base64Url encoding, used to compute disclosure digests.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="saltTag">The tag stamped on each disclosure's salt.</param>
    /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
    /// <param name="disclosures">Receives each disclosure read.</param>
    /// <returns>The walk of the payload (<see cref="SdJwtWalked"/>), or the refusal (<see cref="SdJwtWalkRefused"/>).</returns>
    private static SdJwtWalkReading ReadDisclosures(
        string[] components,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        BaseMemoryPool pool,
        Tag saltTag,
        string hashAlgorithm,
        List<SdDisclosure> disclosures)
    {
        var digestToDisclosure = new Dictionary<string, SdDisclosure>(StringComparer.Ordinal);

        //RFC 9901 section 9.3: "The Issuer MUST ensure that a new salt value is chosen for each claim, including when the same
        //claim name occurs at different places in the structure of the SD-JWT." A salt is the string the wire carries, so a
        //wire form carrying one salt string in two disclosures is refused; admitting it would let a forged disclosure ride a
        //legitimate one's identity through the parse plumbing.
        var saltsSeen = new HashSet<string>(StringComparer.Ordinal);

        try
        {
            for(var i = 1; i < components.Length - 1; i++)
            {
                var component = components[i];
                var disclosureReading = ParseDisclosure(component, decoder, pool, saltTag);

                if(disclosureReading is SdDisclosureRefused refused)
                {
                    return new SdJwtWalkRefused(refused.Defect, refused.Description);
                }

                if(disclosureReading is not SdDisclosureRead { Disclosure: var disclosure })
                {
                    throw new InvalidOperationException("The disclosure reading answered a reading it never answers.");
                }

                disclosures.Add(disclosure);

                var encodedSalt = disclosure.EncodedSalt ?? throw new InvalidOperationException("A disclosure read from the wire keeps its salt's wire string.");

                if(!saltsSeen.Add(encodedSalt))
                {
                    return new SdJwtWalkRefused(
                        SdJwtWireDefect.SaltRepeated,
                        "RFC 9901 section 9.3: two disclosures carry the same salt; the Issuer chooses a new salt for each claim.");
                }

                //The digest is computed over the disclosure exactly as it appeared on the wire (RFC 9901 section 4.2.3), the original
                //encoded text, never a re-serialization of the parsed value, which could legitimately differ byte for byte.
                digestToDisclosure[SdJwtPathExtraction.ComputeDisclosureDigest(component, hashAlgorithm, encoder, pool)] = disclosure;
            }

            var walk = SdJwtPathExtraction.Walk(components[0], digestToDisclosure, decoder, pool);

            if(walk is not SdJwtWalked walked)
            {
                return walk;
            }

            //RFC 9901 section 7.1 step 5: every disclosure the wire form carries is referenced by some digest, directly or
            //recursively through another disclosure; a disclosure the walk could not place is refused, never silently dropped.
            foreach(SdDisclosure disclosure in disclosures)
            {
                if(!walked.Result.DisclosurePaths.ContainsKey(disclosure))
                {
                    return new SdJwtWalkRefused(
                        SdJwtWireDefect.DisclosureUnreferenced,
                        $"RFC 9901 section 7.1 step 5: the disclosure '{disclosure}' is not referenced by any digest in the issuer-signed payload.");
                }
            }

            return walked;
        }
        catch
        {
            //A fault of a delegate composed here surfaces as it is; the disclosures already read are released first, since the
            //token that would own them never comes into existence.
            foreach(SdDisclosure disclosure in disclosures)
            {
                disclosure.Dispose();
            }

            disclosures.Clear();

            throw;
        }
    }


    /// <summary>
    /// Gets the SD-JWT string suitable for hashing (without key binding, with trailing tilde).
    /// </summary>
    /// <param name="token">The SD-JWT token.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <returns>The SD-JWT string for hashing.</returns>
    public static string GetSdJwtForHashing(SdToken<string> token, EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(token);
        ArgumentNullException.ThrowIfNull(encoder);

        var builder = new StringBuilder();
        _ = builder.Append(token.IssuerSigned);
        _ = builder.Append(SdConstants.JwtSeparator);

        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            _ = builder.Append(SerializeDisclosure(disclosure, encoder));
            _ = builder.Append(SdConstants.JwtSeparator);
        }

        return builder.ToString();
    }


    /// <summary>
    /// Checks if a string has compact JWS structure (RFC 7515 section 7.1): three dot-separated non-empty parts, each of the
    /// base64url alphabet and of a length some unpadded base64url text has (RFC 7515 section 2 and RFC 4648 section 5) - never a
    /// whole number of four-character quanta plus one character, which encodes no octets.
    /// </summary>
    /// <param name="value">The string to check.</param>
    /// <returns><c>true</c> if the string has compact JWS structure; otherwise, <c>false</c>.</returns>
    public static bool IsCompactJws(string value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        string[] parts = value.Split('.');
        if(parts.Length != 3)
        {
            return false;
        }

        foreach(string part in parts)
        {
            if(!IsBase64UrlText(part))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// Whether a text is unpadded base64url text (RFC 4648 section 5): not empty, every character of the base64url alphabet, and
    /// of a length some encoding has - never a whole number of four-character quanta plus one character, which encodes no octets.
    /// </summary>
    /// <param name="text">The text.</param>
    /// <returns><see langword="true"/> when the text is unpadded base64url text.</returns>
    private static bool IsBase64UrlText(string text) =>
        text.Length > 0 && text.Length % 4 != 1 && !text.AsSpan().ContainsAnyExcept(Base64UrlAlphabet);


    /// <summary>The base64url alphabet (RFC 4648 section 5).</summary>
    private static SearchValues<char> Base64UrlAlphabet { get; } = SearchValues.Create("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_");


    /// <summary>Writes a claim value as JSON.</summary>
    /// <param name="writer">The writer.</param>
    /// <param name="value">The value.</param>
    private static void WriteClaimValue(Utf8JsonWriter writer, object? value) =>
        ManualJsonWriter.WriteValue(writer, value);
}
