using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> reader for a <see cref="RelatedOriginsDocument"/>'s wire JSON — the
/// document a relying party hosts at <see cref="WellKnownWebAuthnValues.RelatedOriginsWellKnownPath"/>, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">W3C Web Authentication Level 3,
/// section 5.11</see>. The JSON side lives here rather than in <c>Verifiable.Fido2</c>, mirroring
/// <see cref="ClientDataJsonReader"/>: the FIDO2 library takes no serializer dependency, and the
/// serialization firewall (<c>ValidateProjectReferences</c>) blocks it from referencing this project.
/// </summary>
/// <remarks>
/// <para>
/// Reads directly off a <see cref="Utf8JsonReader"/> positioned over the supplied bytes — no intermediate
/// <see cref="JsonDocument"/> buffering. A member other than <c>origins</c> is skipped via
/// <see cref="Utf8JsonReader.Skip"/> rather than rejected, since section 5.11 specifies only the
/// <c>origins</c> key; a repeated top-level member name, by contrast, has no single unambiguous value and
/// is rejected as malformed input, as is any content trailing the closing brace.
/// </para>
/// <para>
/// Section 5.11's "top-level JSON object MUST contain a key named <c>origins</c> whose value MUST be an
/// array of one or more strings" is enforced here, translated to this codebase's strict-parser idiom: a
/// missing, non-array, empty, or non-string-element <c>origins</c> member throws a
/// <see cref="Fido2FormatException"/> naming the violation, rather than the browser-only
/// <c>SecurityError</c> <c>DOMException</c> that
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-validating-relation-origin">section 5.11.1</see>,
/// step 2.iii, specifies for the client-run related origins validation procedure this library does not
/// implement.
/// </para>
/// </remarks>
public static class RelatedOriginsJsonReader
{
    /// <summary>The <c>origins</c> member name.</summary>
    private const string OriginsMember = "origins";


    /// <summary>
    /// Bounds JSON nesting depth for untrusted, hosted related-origins JSON. The document is a flat object
    /// carrying a single string array (section 5.11), so 8 is generous while still capping recursion depth
    /// at parse time.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 8 };


    /// <summary>
    /// Parses a related-origins JSON document into a <see cref="RelatedOriginsDocument"/>.
    /// </summary>
    /// <param name="relatedOriginsJson">The raw related-origins JSON bytes, exactly as hosted.</param>
    /// <returns>The parsed <see cref="RelatedOriginsDocument"/>.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="relatedOriginsJson"/> is not valid JSON, its top level is not an object, the
    /// <c>origins</c> member is missing, is not an array, is an empty array, contains a non-string element,
    /// a top-level member name repeats, or content trails the closing brace.
    /// </exception>
    public static RelatedOriginsDocument Read(ReadOnlyMemory<byte> relatedOriginsJson)
    {
        try
        {
            return ReadObject(relatedOriginsJson.Span);
        }
        catch(JsonException exception)
        {
            throw new Fido2FormatException("The related-origins document is not valid JSON.", exception);
        }
    }


    /// <summary>
    /// Reads the related-origins JSON object from <paramref name="relatedOriginsJson"/>. Any
    /// <see cref="JsonException"/> the underlying reader raises (malformed JSON, an unterminated token, a
    /// depth-bound violation) propagates to <see cref="Read"/>, which wraps it in a
    /// <see cref="Fido2FormatException"/>.
    /// </summary>
    private static RelatedOriginsDocument ReadObject(ReadOnlySpan<byte> relatedOriginsJson)
    {
        Utf8JsonReader reader = new(relatedOriginsJson, ReaderOptions);
        if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The related-origins document top level MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        List<string>? origins = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The related-origins document member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The related-origins document member '{memberName}' is truncated.");
            }

            if(string.Equals(memberName, OriginsMember, StringComparison.Ordinal))
            {
                origins = ReadOriginsArray(ref reader);
            }
            else
            {
                //Section 5.11 specifies only the "origins" member, so an unrecognised member is skipped
                //rather than rejected.
                reader.Skip();
            }
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The related-origins document object is not terminated.");
        }

        if(origins is null)
        {
            throw new Fido2FormatException("The related-origins document member 'origins' is required.");
        }

        if(reader.Read())
        {
            throw new Fido2FormatException("The related-origins document carries content trailing its closing brace.");
        }

        return new RelatedOriginsDocument { Origins = origins };
    }


    /// <summary>
    /// Reads the <c>origins</c> member's value as a non-empty array of strings, per section 5.11's "MUST be
    /// an array of one or more strings."
    /// </summary>
    private static List<string> ReadOriginsArray(ref Utf8JsonReader reader)
    {
        if(reader.TokenType != JsonTokenType.StartArray)
        {
            throw new Fido2FormatException("The related-origins document member 'origins' MUST be an array.");
        }

        List<string> origins = [];
        while(reader.Read() && reader.TokenType != JsonTokenType.EndArray)
        {
            if(reader.TokenType != JsonTokenType.String)
            {
                throw new Fido2FormatException("The related-origins document member 'origins' MUST contain only strings.");
            }

            origins.Add(reader.GetString()!);
        }

        if(reader.TokenType != JsonTokenType.EndArray)
        {
            throw new Fido2FormatException("The related-origins document member 'origins' array is not terminated.");
        }

        if(origins.Count == 0)
        {
            throw new Fido2FormatException("The related-origins document member 'origins' MUST contain one or more entries.");
        }

        return origins;
    }
}
