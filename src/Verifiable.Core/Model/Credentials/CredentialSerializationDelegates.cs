using System;

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