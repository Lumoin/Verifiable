using Verifiable.Core;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Decodes a complete UTF-8 JSON object into authorization server metadata. JSON strings must be
/// unescaped and all malformed input, including invalid UTF-8 and unpaired surrogates, must return
/// a typed error. The Verifiable.Json adapter supplies the System.Text.Json implementation.
/// </summary>
/// <param name="document">The original response bytes, before any replacement decoding.</param>
/// <returns>The metadata or the typed decoding failure.</returns>
public delegate Result<AuthorizationServerMetadata, AuthorizationServerMetadataParseError> ParseAuthorizationServerMetadataDelegate(
    ReadOnlyMemory<byte> document);
