using System;
using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// Deserializes the UTF-8 JSON bytes of a SET header or payload segment into a
/// claim dictionary. Supplied by the JSON layer (or test code) because
/// <see cref="Verifiable.Core"/> takes no JSON serializer dependency — the
/// serialization firewall keeps <c>System.Text.Json</c> out of the core.
/// </summary>
/// <param name="jsonBytes">The decoded (un-base64url) JSON bytes of one JWT segment.</param>
/// <returns>The parsed object, or <see langword="null"/> if the bytes are not a JSON object.</returns>
public delegate Dictionary<string, object>? SecurityEventTokenPartDeserializer(ReadOnlySpan<byte> jsonBytes);
