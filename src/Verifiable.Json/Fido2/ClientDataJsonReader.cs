using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> reader for the <c>clientDataJSON</c> wire bytes — the JSON side the
/// <c>Verifiable.Fido2</c> serialization firewall keeps out of the library. Its <see cref="Read"/> method
/// matches the <see cref="ParseClientDataDelegate"/> shape exactly, so it can be assigned directly:
/// <c>ParseClientDataDelegate d = ClientDataJsonReader.Read;</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3,
/// section 5.8.1: Client Data Used in WebAuthn Signatures</see> defines the <c>CollectedClientData</c>
/// members this reader extracts. This is a parse step only: it shapes the wire bytes into a
/// <see cref="ClientData"/> and does not compare <c>challenge</c> against the expected challenge or
/// <c>origin</c>/<c>topOrigin</c> against the relying party's origin — those are ceremony validation rules
/// carried out by the caller, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">section 7.1: Registering
/// a New Credential</see>, steps 5-11, and
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion">section 7.2: Verifying an
/// Authentication Assertion</see>, steps 8-14.
/// </para>
/// <para>
/// Reads directly off a <see cref="Utf8JsonReader"/> positioned over the supplied bytes — no intermediate
/// <see cref="JsonDocument"/> buffering. Section 5.8.1 notes that a client "MAY add additional keys" to
/// <c>CollectedClientData</c>, so a member this type does not recognise is skipped via
/// <see cref="Utf8JsonReader.Skip"/> rather than rejected. A repeated top-level member name, by contrast,
/// has no single unambiguous value and is rejected as malformed input, as is any content trailing the
/// closing brace.
/// </para>
/// </remarks>
public static class ClientDataJsonReader
{
    /// <summary>The <c>type</c> member name.</summary>
    private const string TypeMember = "type";

    /// <summary>The <c>challenge</c> member name.</summary>
    private const string ChallengeMember = "challenge";

    /// <summary>The <c>origin</c> member name.</summary>
    private const string OriginMember = "origin";

    /// <summary>The <c>crossOrigin</c> member name.</summary>
    private const string CrossOriginMember = "crossOrigin";

    /// <summary>The <c>topOrigin</c> member name.</summary>
    private const string TopOriginMember = "topOrigin";


    /// <summary>
    /// Bounds JSON nesting depth for untrusted, wire-received clientDataJSON. <c>CollectedClientData</c> is
    /// a flat object of string/boolean members (section 5.8.1), so 8 is generous while still capping
    /// recursion depth at parse time.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 8 };


    /// <summary>
    /// Parses <c>clientDataJSON</c> into a <see cref="ClientData"/>. Matches
    /// <see cref="ParseClientDataDelegate"/>.
    /// </summary>
    /// <param name="clientDataJson">The raw <c>clientDataJSON</c> bytes, exactly as received.</param>
    /// <returns>The parsed <see cref="ClientData"/>.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="clientDataJson"/> is not valid JSON, its top level is not an object, a required
    /// member (<c>type</c>, <c>challenge</c>, <c>origin</c>) is missing, <see langword="null"/>, or not a
    /// string, an optional member (<c>crossOrigin</c>, <c>topOrigin</c>) is present with the wrong JSON
    /// type, a top-level member name repeats, or content trails the closing brace.
    /// </exception>
    public static ClientData Read(ReadOnlyMemory<byte> clientDataJson)
    {
        try
        {
            return ReadObject(clientDataJson.Span);
        }
        catch(JsonException exception)
        {
            throw new Fido2FormatException("The clientDataJSON is not valid JSON.", exception);
        }
    }


    /// <summary>
    /// Reads the <c>CollectedClientData</c> JSON object from <paramref name="clientDataJson"/>. Any
    /// <see cref="JsonException"/> the underlying reader raises (malformed JSON, an unterminated token, an
    /// invalid UTF-8 sequence) propagates to <see cref="Read"/>, which wraps it in a
    /// <see cref="Fido2FormatException"/>.
    /// </summary>
    private static ClientData ReadObject(ReadOnlySpan<byte> clientDataJson)
    {
        Utf8JsonReader reader = new(clientDataJson, ReaderOptions);
        if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The clientDataJSON top level MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        string? type = null;
        string? challenge = null;
        string? origin = null;
        bool? crossOrigin = null;
        string? topOrigin = null;

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string memberName = reader.GetString()!;
            if(!seenMembers.Add(memberName))
            {
                throw new Fido2FormatException($"The clientDataJSON member '{memberName}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The clientDataJSON member '{memberName}' is truncated.");
            }

            if(string.Equals(memberName, TypeMember, StringComparison.Ordinal))
            {
                type = ReadStringMember(ref reader, memberName);
            }
            else if(string.Equals(memberName, ChallengeMember, StringComparison.Ordinal))
            {
                challenge = ReadStringMember(ref reader, memberName);
            }
            else if(string.Equals(memberName, OriginMember, StringComparison.Ordinal))
            {
                origin = ReadStringMember(ref reader, memberName);
            }
            else if(string.Equals(memberName, CrossOriginMember, StringComparison.Ordinal))
            {
                if(reader.TokenType != JsonTokenType.True && reader.TokenType != JsonTokenType.False)
                {
                    throw new Fido2FormatException("The clientDataJSON member 'crossOrigin' MUST be a boolean.");
                }

                crossOrigin = reader.GetBoolean();
            }
            else if(string.Equals(memberName, TopOriginMember, StringComparison.Ordinal))
            {
                topOrigin = ReadStringMember(ref reader, memberName);
            }
            else
            {
                //Section 5.8.1: a client MAY add additional members, so an unrecognised member is skipped
                //rather than rejected.
                reader.Skip();
            }
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The clientDataJSON object is not terminated.");
        }

        if(type is null)
        {
            throw new Fido2FormatException("The clientDataJSON member 'type' is required.");
        }

        if(challenge is null)
        {
            throw new Fido2FormatException("The clientDataJSON member 'challenge' is required.");
        }

        if(origin is null)
        {
            throw new Fido2FormatException("The clientDataJSON member 'origin' is required.");
        }

        if(reader.Read())
        {
            throw new Fido2FormatException("The clientDataJSON carries content trailing its closing brace.");
        }

        return new ClientData(type, challenge, origin, crossOrigin, topOrigin);
    }


    /// <summary>
    /// Reads the reader's current value as a string, naming <paramref name="memberName"/> in the rejection
    /// when the value is not string-shaped (including a JSON <see langword="null"/>, which is not a string
    /// token).
    /// </summary>
    private static string ReadStringMember(ref Utf8JsonReader reader, string memberName)
    {
        if(reader.TokenType != JsonTokenType.String)
        {
            throw new Fido2FormatException($"The clientDataJSON member '{memberName}' MUST be a string.");
        }

        return reader.GetString()!;
    }
}
