using System;
using System.Collections.Generic;

namespace Verifiable.Core.Model.Credentials;

/// <summary>
/// Serializes a <see cref="VerifiableCredential"/> to CBOR bytes for use as a COSE payload.
/// </summary>
/// <param name="credential">The credential to serialize.</param>
/// <returns>The CBOR-encoded credential bytes.</returns>
public delegate ReadOnlySpan<byte> CredentialToCborBytesDelegate(VerifiableCredential credential);

/// <summary>
/// Serializes a claims object of type <typeparamref name="T"/> to CBOR bytes for use as a COSE payload.
/// This is the generic sibling of <see cref="CredentialToCborBytesDelegate"/> and shares its
/// <see cref="ReadOnlySpan{T}"/> of <see cref="byte"/> return contract.
/// </summary>
/// <typeparam name="T">The claims type to serialize.</typeparam>
/// <param name="value">The claims object to serialize.</param>
/// <returns>The CBOR-encoded claims bytes.</returns>
public delegate ReadOnlySpan<byte> ToCborBytesDelegate<T>(T value);

/// <summary>
/// Serializes the COSE protected header map to CBOR bytes.
/// </summary>
/// <param name="header">The protected header parameters.</param>
/// <returns>The CBOR-encoded protected header bytes.</returns>
public delegate ReadOnlySpan<byte> CoseProtectedHeaderSerializer(IReadOnlyDictionary<int, object> header);
