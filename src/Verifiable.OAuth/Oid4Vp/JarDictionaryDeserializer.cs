namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Deserialises a JWS header or payload byte span into an untyped property
/// dictionary. Used when parsing a JAR's protected header and payload back
/// into dictionaries before lifting individual claims into typed values via
/// <see cref="Verifiable.OAuth.JarClaimDeserializer{T}"/>.
/// </summary>
/// <remarks>
/// The byte span is the raw JSON content extracted from the JWS — the
/// application's deserializer (typically <c>System.Text.Json</c>-backed)
/// parses it into a generic property bag. The implementation is expected to
/// copy any data it returns out of the span; the span itself is not valid
/// after the call returns.
/// </remarks>
/// <param name="jsonBytes">The UTF-8 JSON bytes to deserialise.</param>
/// <returns>The parsed property dictionary.</returns>
public delegate IReadOnlyDictionary<string, object> JarDictionaryDeserializer(ReadOnlySpan<byte> jsonBytes);
