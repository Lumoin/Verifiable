using System.Buffers;
using System.Diagnostics.CodeAnalysis;
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
    /// Serializes a disclosure to its Base64Url-encoded form.
    /// </summary>
    /// <param name="disclosure">The disclosure to serialize.</param>
    /// <param name="encoder">Delegate for Base64Url encoding.</param>
    /// <returns>The Base64Url-encoded disclosure string.</returns>
    public static string SerializeDisclosure(SdDisclosure disclosure, EncodeDelegate encoder)
    {
        ArgumentNullException.ThrowIfNull(disclosure);
        ArgumentNullException.ThrowIfNull(encoder);

        string saltString = encoder(disclosure.Salt.AsReadOnlySpan());

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
    /// Parses a disclosure from its Base64Url-encoded form. The wire-decoded salt
    /// bytes are wrapped in a <see cref="Salt"/> with the supplied <paramref name="saltTag"/>;
    /// the resulting disclosure owns that salt and disposes it on disposal.
    /// </summary>
    /// <param name="encoded">The Base64Url-encoded disclosure string.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="saltTag">
    /// The tag stamped on the wrapped <see cref="Salt"/>. Should record that the bytes
    /// originated from a wire decode (no entropy operation in this process). The
    /// application supplies a tag with appropriate <c>Purpose</c> and provenance entries.
    /// </param>
    /// <returns>The parsed disclosure.</returns>
    /// <exception cref="SdJwtWireFormatException">
    /// The disclosure is not of the shape RFC 9901 section 4.2 defines: the decoder refuses it or its salt as no base64url text
    /// (its <see cref="FormatException"/>), it is no JSON array of two or three elements, or its salt or claim name is no JSON
    /// string or its claim name is empty. Any other failure of the decoder or of the allocator, cancellation among them, is
    /// theirs and surfaces as it is.
    /// </exception>
    [SuppressMessage(
        "Reliability", "CA2000",
        Justification =
            "The constructed Salt's ownership is transferred to the SdDisclosure via " +
            "CreateProperty/CreateArrayElement. Those factories dispose the salt on " +
            "construction failure. The remaining failure cases (claim-name validation) " +
            "explicitly dispose `salt` before throwing. The analyzer cannot see this " +
            "ownership transfer through factory methods.")]
    public static SdDisclosure ParseDisclosure(string encoded, DecodeDelegate decoder, BaseMemoryPool pool, Tag saltTag)
    {
        ArgumentException.ThrowIfNullOrEmpty(encoded);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(saltTag);

        using var jsonBytes = DecodedWireText(encoded, decoder, pool, "The disclosure is no base64url text (RFC 9901 section 4.2).");

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(jsonBytes.Memory);
        }
        catch(JsonException exception)
        {
            throw new SdJwtWireFormatException("The disclosure is not valid JSON (RFC 9901 section 4.2).", exception);
        }

        using(doc)
        {
            var root = doc.RootElement;

            if(root.ValueKind != JsonValueKind.Array)
            {
                throw new SdJwtWireFormatException("A disclosure is a JSON array (RFC 9901 section 4.2).");
            }

            var length = root.GetArrayLength();

            if(length is < 2 or > 3)
            {
                throw new SdJwtWireFormatException($"A disclosure array has two or three elements (RFC 9901 section 4.2), this one {length}.");
            }

            //RFC 9901 sections 4.2.1 and 4.2.2: the salt and the claim name are each a JSON string; an element of another kind is a
            //disclosure of no shape the section defines, refused here before any element is read as a string.
            if(root[0].ValueKind != JsonValueKind.String || root[0].GetString() is not { } saltText)
            {
                throw new SdJwtWireFormatException("A disclosure's salt is a JSON string (RFC 9901 section 4.2.1).");
            }

            var saltOwner = DecodedWireText(saltText, decoder, pool, "A disclosure's salt is base64url text (RFC 9901 section 4.2.1).");

            //Wrap the wire-decoded salt bytes in a Salt instance. Ownership of saltOwner
            //transfers into the Salt. The Salt then transfers into the SdDisclosure via
            //CreateProperty/CreateArrayElement; the disclosure disposes the Salt (and
            //therefore the IMemoryOwner) when the disclosure is disposed.
            //
            //If wrapping or factory construction fails before the disclosure exists,
            //we own the IMemoryOwner and must dispose it explicitly. The Salt instance
            //itself, once constructed, takes care of its own owner via Dispose.
            Salt salt;
            try
            {
                salt = new Salt(saltOwner, saltTag, lifetime: null);
            }
            catch
            {
                saltOwner.Dispose();
                throw;
            }

            //From here, ownership is with `salt`. CreateProperty/CreateArrayElement take ownership of
            //`salt` and dispose it on construction failure, so once one of them is reached, this method
            //disposes salt no further. Reading a value element below can itself throw before that
            //hand-off, at which point salt is still unowned.
            if(length == 2)
            {
                object? arrayValue;
                try
                {
                    arrayValue = JsonElementConversion.Convert(root[1]);
                }
                catch
                {
                    salt.Dispose();

                    throw;
                }

                return SdDisclosure.CreateArrayElement(salt, arrayValue);
            }

            if(root[1].ValueKind != JsonValueKind.String || root[1].GetString() is not { Length: > 0 } claimName)
            {
                salt.Dispose();

                throw new SdJwtWireFormatException("A disclosure's claim name is a non-empty JSON string (RFC 9901 section 4.2.1).");
            }

            object? propertyValue;
            try
            {
                propertyValue = JsonElementConversion.Convert(root[2]);
            }
            catch
            {
                salt.Dispose();

                throw;
            }

            return SdDisclosure.CreateProperty(salt, claimName, propertyValue);
        }
    }


    /// <summary>
    /// The bytes a base64url text of the wire names, the decoder's refusal of the text as no base64url, its
    /// <see cref="FormatException"/>, answered as the wire's refusal; any other failure of the decoder or of the allocator,
    /// cancellation among them, is theirs and surfaces as it is.
    /// </summary>
    /// <param name="text">The base64url text.</param>
    /// <param name="decoder">The decoder.</param>
    /// <param name="pool">The pool the bytes are rented from.</param>
    /// <param name="refusal">The description of the wire's refusal.</param>
    /// <returns>The bytes, which the caller disposes.</returns>
    /// <exception cref="SdJwtWireFormatException">The decoder refuses the text.</exception>
    internal static IMemoryOwner<byte> DecodedWireText(string text, DecodeDelegate decoder, BaseMemoryPool pool, string refusal)
    {
        try
        {
            return decoder(text, pool);
        }
        catch(FormatException exception)
        {
            throw new SdJwtWireFormatException(refusal, exception);
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
    /// Parses an SD-JWT token from its wire format. Computes <see cref="SdToken{TEnvelope}.DisclosurePaths"/>
    /// and <see cref="SdToken{TEnvelope}.IssuerSignedClaims"/> by walking the issuer-signed
    /// payload's digest tree, sharing the walker core with <see cref="SdJwtPathExtraction.ExtractPaths"/>.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT string.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="encoder">Delegate for Base64Url encoding, used to compute disclosure digests.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="saltTag">
    /// The tag to stamp on each wire-decoded <see cref="Salt"/> (one per disclosure).
    /// </param>
    /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
    /// <returns>The parsed token. Caller owns the returned token; disposing it disposes
    /// all contained disclosures and their salts.</returns>
    /// <exception cref="SdJwtWireFormatException">
    /// The wire shape is refused: the issuer JWT is no compact JWS, a disclosure is refused by
    /// <see cref="ParseDisclosure"/>, the issuer-signed payload is no base64url text or not valid JSON, two
    /// disclosures carry the same salt bytes (RFC 9901 §9.3), a digest rule of RFC 9901 §7.1 step 3.c or 4
    /// fails, or a disclosure is not referenced by any digest in the payload (RFC 9901 §7.1 step 5). A
    /// failure of the decoder beyond its refusal of text as no base64url, of the encoder, of the digest
    /// implementation or of the allocator, cancellation among them, is theirs and surfaces as it is.
    /// </exception>
    public static SdToken<string> ParseToken(
        string sdJwt,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        BaseMemoryPool pool,
        Tag saltTag,
        string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana)
    {
        ArgumentException.ThrowIfNullOrEmpty(sdJwt);
        ArgumentNullException.ThrowIfNull(decoder);
        ArgumentNullException.ThrowIfNull(encoder);
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(saltTag);

        string[] parts = sdJwt.Split(SdConstants.JwtSeparator);

        if(parts.Length < 2)
        {
            throw new SdJwtWireFormatException("An SD-JWT carries at least an issuer JWT and one separator (RFC 9901 section 4).");
        }

        string issuerJwt = parts[0];

        if(!IsCompactJws(issuerJwt))
        {
            throw new SdJwtWireFormatException("The Issuer-signed JWT is no compact JWS of three base64url segments (RFC 7515 section 7.1).");
        }

        var disclosures = new List<SdDisclosure>();
        var digestToDisclosure = new Dictionary<string, SdDisclosure>(StringComparer.Ordinal);

        //RFC 9901 §9.3: "The Issuer MUST ensure that a new salt value is chosen for each claim,
        //including when the same claim name occurs at different places in the structure of the
        //SD-JWT." SdDisclosure equality is its salt bytes, so this set is exactly a
        //salt-collision detector: a wire form carrying two disclosures under one salt is
        //malformed, and admitting it would let a forged disclosure ride a legitimate one's
        //identity through the parse plumbing.
        var saltsSeen = new HashSet<SdDisclosure>();
        string? keyBindingJwt = null;
        SdJwtWalkResult walkResult;

        try
        {
            for(int i = 1; i < parts.Length; i++)
            {
                string part = parts[i];

                if(string.IsNullOrEmpty(part))
                {
                    continue;
                }

                if(IsCompactJws(part))
                {
                    keyBindingJwt = part;
                }
                else
                {
                    SdDisclosure disclosure = ParseDisclosure(part, decoder, pool, saltTag);
                    disclosures.Add(disclosure);

                    if(!saltsSeen.Add(disclosure))
                    {
                        throw new SdJwtWireFormatException(
                            "RFC 9901 §9.3: two Disclosures carry the same salt value; the Issuer must choose a new salt for each claim.");
                    }

                    //The digest is computed over the disclosure exactly as it appeared on the
                    //wire (RFC 9901 §4.2.3) — the original encoded text, never a re-serialization
                    //of the parsed value, which could legitimately differ byte-for-byte.
                    string digest = SdJwtPathExtraction.ComputeDisclosureDigest(part, hashAlgorithm, encoder, pool);
                    digestToDisclosure[digest] = disclosure;
                }
            }

            walkResult = SdJwtPathExtraction.Walk(issuerJwt, digestToDisclosure, decoder, pool);

            //RFC 9901 §7.1 step 5: every Disclosure the wire form carries must be referenced by
            //some digest, directly or recursively via another Disclosure — a Disclosure Walk
            //could not place is a parse failure, not silently dropped.
            foreach(SdDisclosure disclosure in disclosures)
            {
                if(!walkResult.DisclosurePaths.ContainsKey(disclosure))
                {
                    throw new SdJwtWireFormatException(
                        $"RFC 9901 §7.1 step 5: the disclosure '{disclosure}' is not referenced by any digest in the issuer-signed payload.");
                }
            }
        }
        catch
        {
            //If any disclosure fails to parse, or the payload fails the digest-resolution
            //rules, dispose every disclosure already constructed before propagating. The
            //token never came into existence.
            foreach(SdDisclosure d in disclosures)
            {
                d.Dispose();
            }
            throw;
        }

        return SdToken<string>.CreateParsed(
            issuerJwt,
            disclosures,
            new SdDisclosurePaths(walkResult.DisclosurePaths),
            walkResult.IssuerSignedClaims,
            walkResult.DisclosureInteriorClaims,
            keyBindingJwt);
    }


    /// <summary>
    /// Attempts to parse an SD-JWT token.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT string.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="encoder">Delegate for Base64Url encoding, used to compute disclosure digests.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="saltTag">
    /// The tag to stamp on each wire-decoded <see cref="Salt"/>.
    /// </param>
    /// <param name="token">The parsed token if successful. Caller owns and disposes.</param>
    /// <param name="hashAlgorithm">The disclosure-digest hash algorithm in IANA format.</param>
    /// <returns>
    /// <c>true</c> if parsing succeeded; <c>false</c> when the wire shape is refused (<see cref="SdJwtWireFormatException"/>).
    /// Any other failure of a delegate supplied, cancellation among them, surfaces as it is.
    /// </returns>
    public static bool TryParseToken(
        string? sdJwt,
        DecodeDelegate decoder,
        EncodeDelegate encoder,
        BaseMemoryPool pool,
        Tag saltTag,
        out SdToken<string>? token,
        string hashAlgorithm = WellKnownHashAlgorithms.Sha256Iana)
    {
        token = null;

        if(string.IsNullOrEmpty(sdJwt))
        {
            return false;
        }

        try
        {
            token = ParseToken(sdJwt, decoder, encoder, pool, saltTag, hashAlgorithm);
            return true;
        }
        catch(SdJwtWireFormatException)
        {
            return false;
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
            if(string.IsNullOrEmpty(part) || part.Length % 4 == 1)
            {
                return false;
            }

            foreach(char c in part)
            {
                if(!IsBase64UrlChar(c))
                {
                    return false;
                }
            }
        }

        return true;
    }


    /// <summary>
    /// Tells whether <paramref name="c"/> is a member of the Base64URL alphabet
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4648#section-5">RFC 4648 section 5</see>). The
    /// boolean expression mirrors the alphabet's four character classes directly; a named predicate per
    /// class would only rename the citation, not simplify it.
    /// </summary>
    /// <param name="c">The character to classify.</param>
    /// <returns><see langword="true"/> when <paramref name="c"/> is in the Base64URL alphabet.</returns>
    private static bool IsBase64UrlChar(char c)
    {
        return c is (>= 'A' and <= 'Z') or
               (>= 'a' and <= 'z') or
               (>= '0' and <= '9') or
               '-' or
               '_';
    }


    private static void WriteClaimValue(Utf8JsonWriter writer, object? value) =>
        ManualJsonWriter.WriteValue(writer, value);
}
