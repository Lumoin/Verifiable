using System;
using System.Collections.Generic;
using System.Text.Json;
using Verifiable.Fido2;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> reader for the <c>clientExtensionResults</c> wire bytes — the
/// JSON side the <c>Verifiable.Fido2</c> serialization firewall keeps out of the library.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">W3C Web Authentication Level 3,
/// section 9: WebAuthn Extensions</see>: "the client also augments the client data as specified by
/// each extension, by including the extension identifier and client extension output values" —
/// represented on the wire as a flat JSON object keyed by extension identifier
/// (<see href="https://www.w3.org/TR/webauthn-3/#sctn-client-extension-processing">the
/// <c>AuthenticationExtensionsClientOutputsJSON</c> dictionary</see>). This reader captures each
/// member's raw, still-encoded value slice rather than interpreting it — a registered
/// <see cref="ExtensionOutputProcessDelegate"/> decodes the value for the one extension identifier
/// it understands.
/// </para>
/// <para>
/// Reads directly off a <see cref="Utf8JsonReader"/> positioned over the supplied bytes — no
/// intermediate <see cref="JsonDocument"/> buffering, mirroring <see cref="ClientDataJsonReader"/>.
/// A repeated top-level member name has no single unambiguous value and is rejected as malformed
/// input, as is any content trailing the closing brace or a non-object top level.
/// </para>
/// </remarks>
public static class ClientExtensionOutputsJsonReader
{
    /// <summary>
    /// Bounds JSON nesting depth for untrusted, wire-received <c>clientExtensionResults</c>. An
    /// individual extension's client extension output can itself be a nested object (for example a
    /// public-key-credential-shaped output), so this is more generous than
    /// <see cref="ClientDataJsonReader"/>'s flat <c>CollectedClientData</c> bound while still
    /// capping recursion depth at parse time.
    /// </summary>
    private static JsonReaderOptions ReaderOptions { get; } = new() { MaxDepth = 8 };


    /// <summary>
    /// Parses <c>clientExtensionResults</c> into one <see cref="Fido2ExtensionOutput"/> per
    /// top-level member, in wire order. Values are not interpreted.
    /// </summary>
    /// <param name="clientExtensionOutputsJson">The raw <c>clientExtensionResults</c> bytes, exactly as received.</param>
    /// <returns>The decoded client extension outputs, one per top-level member.</returns>
    /// <exception cref="Fido2FormatException">
    /// <paramref name="clientExtensionOutputsJson"/> is not valid JSON, its top level is not an
    /// object, a top-level member name repeats, or content trails the closing brace.
    /// </exception>
    public static IReadOnlyList<Fido2ExtensionOutput> Read(ReadOnlyMemory<byte> clientExtensionOutputsJson)
    {
        try
        {
            return ReadObject(clientExtensionOutputsJson);
        }
        catch(JsonException exception)
        {
            throw new Fido2FormatException("The clientExtensionResults JSON is not valid JSON.", exception);
        }
    }


    /// <summary>
    /// Reads the <c>clientExtensionResults</c> JSON object from <paramref name="source"/>. Any
    /// <see cref="JsonException"/> the underlying reader raises (malformed JSON, an unterminated
    /// token, an invalid UTF-8 sequence) propagates to <see cref="Read"/>, which wraps it in a
    /// <see cref="Fido2FormatException"/>.
    /// </summary>
    private static List<Fido2ExtensionOutput> ReadObject(ReadOnlyMemory<byte> source)
    {
        Utf8JsonReader reader = new(source.Span, ReaderOptions);
        if(!reader.Read() || reader.TokenType != JsonTokenType.StartObject)
        {
            throw new Fido2FormatException("The clientExtensionResults top level MUST be a JSON object.");
        }

        HashSet<string> seenMembers = new(StringComparer.Ordinal);
        List<Fido2ExtensionOutput> outputs = [];

        while(reader.Read() && reader.TokenType != JsonTokenType.EndObject)
        {
            string identifier = reader.GetString()!;
            if(!seenMembers.Add(identifier))
            {
                throw new Fido2FormatException($"The clientExtensionResults member '{identifier}' is repeated.");
            }

            if(!reader.Read())
            {
                throw new Fido2FormatException($"The clientExtensionResults member '{identifier}' is truncated.");
            }

            long valueStart = reader.TokenStartIndex;
            if(reader.TokenType is JsonTokenType.StartObject or JsonTokenType.StartArray)
            {
                reader.Skip();
            }

            long valueEnd = reader.BytesConsumed;
            ReadOnlyMemory<byte> value = source[checked((int)valueStart)..checked((int)valueEnd)];
            outputs.Add(new Fido2ExtensionOutput(identifier, value));
        }

        if(reader.TokenType != JsonTokenType.EndObject)
        {
            throw new Fido2FormatException("The clientExtensionResults object is not terminated.");
        }

        if(reader.Read())
        {
            throw new Fido2FormatException("The clientExtensionResults carries content trailing its closing brace.");
        }

        return outputs;
    }
}
