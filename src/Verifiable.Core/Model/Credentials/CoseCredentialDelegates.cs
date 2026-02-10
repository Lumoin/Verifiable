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
/// Serializes the COSE protected header map to CBOR bytes.
/// </summary>
/// <param name="header">The protected header parameters.</param>
/// <returns>The CBOR-encoded protected header bytes.</returns>
public delegate ReadOnlySpan<byte> CoseProtectedHeaderSerializer(IReadOnlyDictionary<int, object> header);