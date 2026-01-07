using System;
using System.Collections.Generic;

namespace Verifiable.JCose;

/// <summary>
/// Serializes a JWT header dictionary to UTF-8 bytes.
/// </summary>
/// <param name="header">The header dictionary containing alg, typ, kid, and other claims.</param>
/// <returns>The UTF-8 JSON bytes.</returns>
public delegate ReadOnlySpan<byte> JwtHeaderSerializer(Dictionary<string, object> header);

/// <summary>
/// Deserializes a JWT header from UTF-8 bytes.
/// </summary>
/// <param name="headerBytes">The UTF-8 JSON bytes.</param>
/// <returns>The deserialized header dictionary, or null if parsing fails.</returns>
public delegate Dictionary<string, object>? JwtHeaderDeserializer(ReadOnlySpan<byte> headerBytes);