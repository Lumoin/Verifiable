namespace Verifiable.OAuth.ProtectedResource;

/// <summary>
/// Reads a complete protected resource metadata document from its original UTF-8 bytes, strictly: <see langword="null"/>
/// for a body that is not valid UTF-8, is not a JSON object, lacks <c>resource</c> or carries a known member of the wrong
/// type; a member the reading does not know is ignored
/// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see>: "any metadata
/// parameters that are not understood MUST be ignored"). The serialization adapter supplies the implementation;
/// Verifiable.Json provides <c>ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata</c> over the bytes.
/// Reading does not validate: <see cref="ProtectedResourceMetadataDocuments.ResolveFromChallengeAsync"/> applies the
/// Section 3.3 comparison to what this reads.
/// </summary>
/// <param name="document">The original response bytes, before any replacement decoding.</param>
/// <returns>The document as read, or <see langword="null"/> when the bytes hold no protected resource metadata document.</returns>
public delegate ProtectedResourceMetadata? ParseProtectedResourceMetadataDelegate(ReadOnlyMemory<byte> document);
