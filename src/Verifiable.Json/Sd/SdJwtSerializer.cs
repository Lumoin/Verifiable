using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Core.Model.SelectiveDisclosure;

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
    /// <exception cref="FormatException">Thrown when the format is invalid.</exception>
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

        IMemoryOwner<byte> jsonBytes;
        try
        {
            jsonBytes = decoder(encoded, pool);
        }
        catch(Exception ex)
        {
            //decoder is a caller-supplied delegate whose implementation-specific exception vocabulary this
            //method cannot enumerate; every failure normalizes to the public FormatException contract.
            throw new FormatException("Invalid Base64Url encoding in disclosure.", ex);
        }

        using(jsonBytes)
        {
            JsonDocument doc;
            try
            {
                doc = JsonDocument.Parse(jsonBytes.Memory);
            }
            catch(JsonException exception)
            {
                throw new FormatException("Disclosure is not valid JSON.", exception);
            }

            using(doc)
            {
                JsonElement root = doc.RootElement;

                if(root.ValueKind != JsonValueKind.Array)
                {
                    throw new FormatException("Disclosure must be a JSON array.");
                }

                int length = root.GetArrayLength();

                if(length < 2 || length > 3)
                {
                    throw new FormatException($"Disclosure array must have 2 or 3 elements, got {length}.");
                }

                string saltString = root[0].GetString()
                    ?? throw new FormatException("Salt cannot be null.");

                IMemoryOwner<byte> saltOwner;
                try
                {
                    saltOwner = decoder(saltString, pool);
                }
                catch(Exception ex)
                {
                    //Same rationale as the disclosure decode above: decoder's exception vocabulary is not
                    //enumerable here, so every failure normalizes to the public FormatException contract.
                    throw new FormatException("Invalid Base64Url encoding in salt.", ex);
                }

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
                //`salt` and dispose it on construction failure (e.g. null/empty claim name), so once one
                //of them is reached, this method disposes salt no further. Reading the array's own
                //elements below can itself throw (a claim-name slot that is not a JSON string, a
                //malformed value element) before that hand-off, at which point salt is still unowned.
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

                string? claimName;
                try
                {
                    claimName = root[1].GetString();
                }
                catch
                {
                    salt.Dispose();

                    throw;
                }

                if(string.IsNullOrEmpty(claimName))
                {
                    salt.Dispose();
                    throw new FormatException("Claim name cannot be null.");
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
        builder.Append(token.IssuerSigned);
        builder.Append(SdConstants.JwtSeparator);

        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            builder.Append(SerializeDisclosure(disclosure, encoder));
            builder.Append(SdConstants.JwtSeparator);
        }

        if(token.KeyBinding is not null)
        {
            builder.Length--;
            builder.Append(SdConstants.JwtSeparator);
            builder.Append(token.KeyBinding);
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
    /// <exception cref="FormatException">
    /// Thrown when the format is invalid, when the issuer-signed payload is not valid JSON, when two
    /// disclosures carry the same salt bytes (RFC 9901 §9.3), when a same-level claim name collides
    /// (RFC 9901 §7.1 step 3.c.ii.3), or when a disclosure is not referenced by any digest in the
    /// payload (RFC 9901 §7.1 step 5).
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
            throw new FormatException("SD-JWT must have at least an issuer JWT and one separator.");
        }

        string issuerJwt = parts[0];

        if(!IsCompactJws(issuerJwt))
        {
            throw new FormatException("Invalid issuer JWT structure.");
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
                        throw new FormatException(
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
                    throw new FormatException(
                        $"RFC 9901 §7.1 step 5: the disclosure '{disclosure}' is not referenced by any digest in the issuer-signed payload.");
                }
            }
        }
        catch(JsonException exception)
        {
            //JsonDocument.Parse (inside SdJwtPathExtraction.Walk) throws its own JsonException for a
            //non-JSON issuer-signed payload; this method's public contract is FormatException for
            //every wire-shape rejection, so the leaf's own exception type is normalized here rather
            //than left to escape as System.Text.Json's.
            foreach(SdDisclosure d in disclosures)
            {
                d.Dispose();
            }
            throw new FormatException("The SD-JWT issuer-signed payload is not valid JSON.", exception);
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
    /// <returns><c>true</c> if parsing succeeded; otherwise, <c>false</c>.</returns>
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
        catch
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
        builder.Append(token.IssuerSigned);
        builder.Append(SdConstants.JwtSeparator);

        foreach(SdDisclosure disclosure in token.Disclosures)
        {
            builder.Append(SerializeDisclosure(disclosure, encoder));
            builder.Append(SdConstants.JwtSeparator);
        }

        return builder.ToString();
    }


    /// <summary>
    /// Checks if a string has compact JWS structure (three dot-separated non-empty Base64Url parts).
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
            if(string.IsNullOrEmpty(part))
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
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' ||
               c == '_';
    }


    private static void WriteClaimValue(Utf8JsonWriter writer, object? value) =>
        ManualJsonWriter.WriteValue(writer, value);
}
