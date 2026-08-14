using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.JCose;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Decodes a compact JWS Entity Statement into a typed
/// <see cref="FetchedEntityStatement"/> through the serialization-firewall
/// seams — the shared parse path used both by the inline trust chain
/// validator and the fetch transport, so neither hand-rolls JWS splitting
/// and JSON decoding.
/// </summary>
internal static class EntityStatementJwsReader
{
    /// <summary>
    /// Splits <paramref name="compactJws"/>, decodes its header and payload
    /// segments, and structurally parses the result into a
    /// <see cref="FetchedEntityStatement"/>. Returns <see langword="null"/>
    /// when the value is not a three-part compact JWS, a segment cannot be
    /// decoded, or the payload does not parse as an Entity Statement. This is
    /// structural parsing only — no signature is verified here.
    /// </summary>
    /// <param name="compactJws">The compact JWS Entity Statement.</param>
    /// <param name="headerDeserializer">Deserializes the protected-header segment bytes.</param>
    /// <param name="payloadDeserializer">Deserializes the payload segment bytes.</param>
    /// <param name="base64UrlDecoder">Decodes the base64url segments to bytes.</param>
    /// <param name="pool">Memory pool the transient segment buffers rent from.</param>
    /// <returns>The parsed statement, or <see langword="null"/> on any structural failure.</returns>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "The base64url decoder and deserializer seams are opaque app-provided delegates that throw arbitrary types on malformed input — including the JSON library's own parse exception, which the serialization firewall forbids this assembly from naming. TryRead processes untrusted chain entries and MUST fail closed (return null), never throw, on any decode/deserialize failure.")]
    internal static FetchedEntityStatement? TryRead(
        string compactJws,
        JwtHeaderDeserializer headerDeserializer,
        JwtPayloadDeserializer payloadDeserializer,
        DecodeDelegate base64UrlDecoder,
        BaseMemoryPool pool)
    {
        if(string.IsNullOrWhiteSpace(compactJws))
        {
            return null;
        }

        string[] parts = compactJws.Split('.');
        if(parts.Length != 3
            || parts[0].Length == 0
            || parts[1].Length == 0
            || parts[2].Length == 0)
        {
            return null;
        }

        UnverifiedJwtHeader header;
        UnverifiedJwtPayload payload;
        try
        {
            using IMemoryOwner<byte> headerBytes = base64UrlDecoder(parts[0], pool);
            using IMemoryOwner<byte> payloadBytes = base64UrlDecoder(parts[1], pool);
            header = new UnverifiedJwtHeader(headerDeserializer(headerBytes.Memory.Span));
            payload = new UnverifiedJwtPayload(payloadDeserializer(payloadBytes.Memory.Span));
        }
        catch(Exception)
        {
            //A malformed segment fails closed. The decoder/deserializer seams can throw arbitrary types
            //(base64 FormatException, the JSON library's own parse exception the firewall forbids naming here),
            //and a tampered chain entry is hostile input — so any decode/deserialize failure yields null, not a
            //thrown exception, matching this method's Try contract.
            return null;
        }

        EntityStatementParseResult parseResult = EntityStatementParser.Parse(header, payload);
        return parseResult.IsSuccess && parseResult.Statement is not null
            ? new FetchedEntityStatement(parseResult.Statement, header, compactJws)
            : null;
    }
}
