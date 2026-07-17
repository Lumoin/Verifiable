using System;
using System.Buffers;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes an <c>authenticatorCredentialManagement</c> response's CTAP2-canonical CBOR payload into its
/// typed model — the RP/platform-side operation.
/// </summary>
/// <param name="payload">The CBOR-encoded response payload.</param>
/// <param name="pool">The memory pool the decoded <c>credentialID</c>/<c>user</c> carriers rent from.</param>
/// <returns>The decoded response model.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="DecodeCtapClientPinResponseDelegate"/>'s shape. The
/// shipped default, <c>Verifiable.Cbor.Ctap.CtapCredentialManagementResponseCborReader.Read</c>, is
/// method-group-compatible with this delegate. No authenticator-side production code consumes this
/// delegate — it exists for the platform-side test/real-wire harness that decodes
/// <c>authenticatorCredentialManagement</c> responses.
/// </remarks>
/// <exception cref="Fido2FormatException"><paramref name="payload"/> is not valid CTAP2 canonical CBOR.</exception>
public delegate CtapCredentialManagementResponse DecodeCtapCredentialManagementResponseDelegate(ReadOnlyMemory<byte> payload, MemoryPool<byte> pool);
