using System;
using System.Collections.Generic;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Delegate for serializing a <see cref="VerifiableCredential"/> to JSON bytes.
/// </summary>
/// <param name="credential">The credential to serialize.</param>
/// <returns>The UTF-8 JSON bytes.</returns>
public delegate ReadOnlySpan<byte> CredentialToJsonBytesDelegate(VerifiableCredential credential);


/// <summary>
/// Delegate for deserializing a <see cref="VerifiableCredential"/> from JSON bytes.
/// </summary>
/// <param name="jsonBytes">The UTF-8 JSON bytes.</param>
/// <returns>The deserialized credential.</returns>
public delegate VerifiableCredential CredentialFromJsonBytesDelegate(ReadOnlySpan<byte> jsonBytes);


/// <summary>
/// Serializes a JWT header dictionary to bytes.
/// </summary>
/// <param name="header">The JWT header.</param>
/// <returns>UTF-8 JSON bytes of the header.</returns>
public delegate ReadOnlySpan<byte> JwtHeaderSerializer(Dictionary<string, object> header);


/// <summary>
/// Deserializes a JWT header from bytes.
/// </summary>
/// <param name="headerBytes">The UTF-8 JSON bytes.</param>
/// <returns>The deserialized header dictionary.</returns>
public delegate Dictionary<string, object>? JwtHeaderDeserializer(ReadOnlySpan<byte> headerBytes);