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
    public static SdDisclosure ParseDisclosure(string encoded, DecodeDelegate decoder, MemoryPool<byte> pool, Tag saltTag)
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
            throw new FormatException("Invalid Base64Url encoding in disclosure.", ex);
        }

        using(jsonBytes)
        {
            using JsonDocument doc = JsonDocument.Parse(jsonBytes.Memory);
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

            //From here, ownership is with `salt`. CreateProperty/CreateArrayElement
            //take ownership of `salt` and dispose it on construction failure (e.g.,
            //null/empty claim name).
            if(length == 2)
            {
                object? value = JsonElementConversion.Convert(root[1]);
                return SdDisclosure.CreateArrayElement(salt, value);
            }
            else
            {
                //If GetString() throws or returns null, dispose `salt` before propagating.
                string? claimName = root[1].GetString();
                if(string.IsNullOrEmpty(claimName))
                {
                    salt.Dispose();
                    throw new FormatException("Claim name cannot be null.");
                }

                object? value = JsonElementConversion.Convert(root[2]);
                return SdDisclosure.CreateProperty(salt, claimName, value);
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
    /// Parses an SD-JWT token from its wire format.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT string.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="saltTag">
    /// The tag to stamp on each wire-decoded <see cref="Salt"/> (one per disclosure).
    /// </param>
    /// <returns>The parsed token. Caller owns the returned token; disposing it disposes
    /// all contained disclosures and their salts.</returns>
    /// <exception cref="FormatException">Thrown when the format is invalid.</exception>
    public static SdToken<string> ParseToken(string sdJwt, DecodeDelegate decoder, MemoryPool<byte> pool, Tag saltTag)
    {
        ArgumentException.ThrowIfNullOrEmpty(sdJwt);
        ArgumentNullException.ThrowIfNull(decoder);
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
        string? keyBindingJwt = null;

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
                }
            }
        }
        catch
        {
            //If any disclosure fails to parse, dispose every disclosure already
            //constructed before propagating. The token never came into existence.
            foreach(SdDisclosure d in disclosures)
            {
                d.Dispose();
            }
            throw;
        }

        return new SdToken<string>(issuerJwt, disclosures, keyBindingJwt);
    }


    /// <summary>
    /// Attempts to parse an SD-JWT token.
    /// </summary>
    /// <param name="sdJwt">The SD-JWT string.</param>
    /// <param name="decoder">Delegate for Base64Url decoding.</param>
    /// <param name="pool">Memory pool for allocations.</param>
    /// <param name="saltTag">
    /// The tag to stamp on each wire-decoded <see cref="Salt"/>.
    /// </param>
    /// <param name="token">The parsed token if successful. Caller owns and disposes.</param>
    /// <returns><c>true</c> if parsing succeeded; otherwise, <c>false</c>.</returns>
    public static bool TryParseToken(string? sdJwt, DecodeDelegate decoder, MemoryPool<byte> pool, Tag saltTag, out SdToken<string>? token)
    {
        token = null;

        if(string.IsNullOrEmpty(sdJwt))
        {
            return false;
        }

        try
        {
            token = ParseToken(sdJwt, decoder, pool, saltTag);
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
