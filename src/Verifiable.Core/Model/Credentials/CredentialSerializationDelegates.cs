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
/// Serializes a claims object of type <typeparamref name="T"/> to UTF-8 JSON bytes for use as an
/// SD-JWT payload. The generic sibling of <see cref="CredentialToJsonBytesDelegate"/>, and the
/// JSON analog of <see cref="ToCborBytesDelegate{T}"/>; both exist because the issuance
/// orchestration lives in <c>Verifiable.Core</c>, which cannot reference a serialization library,
/// so the caller supplies the type-to-bytes conversion (wired to <c>System.Text.Json</c> here).
/// </summary>
/// <typeparam name="T">The claims type to serialize.</typeparam>
/// <param name="value">The claims object to serialize.</param>
/// <returns>The UTF-8 JSON-encoded claims bytes.</returns>
public delegate ReadOnlySpan<byte> ToJsonBytesDelegate<T>(T value);


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
