using System;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes an <c>authenticatorLargeBlobs</c> <c>get</c> response's CTAP2-canonical CBOR payload into its
/// typed model — the RP/platform-side operation.
/// </summary>
/// <param name="payload">The CBOR-encoded response payload.</param>
/// <returns>The decoded response model.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="DecodeCtapBioEnrollmentResponseDelegate"/>'s pool-less
/// shape: <c>config</c> is an opaque byte string, with no pooled <c>SensitiveMemory</c> carrier. The
/// shipped default, <c>Verifiable.Cbor.Ctap.CtapLargeBlobsResponseCborReader.Read</c>, is
/// method-group-compatible with this delegate. No authenticator-side production code consumes this
/// delegate — it exists for the platform-side test/real-wire harness that decodes
/// <c>authenticatorLargeBlobs</c> <c>get</c> responses. A <c>set</c> outcome carries no CBOR body at all,
/// so this delegate is never invoked for one.
/// </remarks>
/// <exception cref="Fido2FormatException"><paramref name="payload"/> is not valid CTAP2 canonical CBOR.</exception>
public delegate CtapLargeBlobsResponse DecodeCtapLargeBlobsResponseDelegate(ReadOnlyMemory<byte> payload);
