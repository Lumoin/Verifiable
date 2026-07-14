using System;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes the CTAP2-canonical CBOR payload of an <c>authenticatorLargeBlobs</c> request into its typed
/// model — the authenticator-side operation.
/// </summary>
/// <param name="parametersCbor">The CBOR-encoded request parameter map.</param>
/// <returns>The decoded request model.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="DecodeCtapAuthenticatorConfigRequestDelegate"/>'s
/// pool-less shape (no member this command decodes needs a pooled carrier). The shipped default,
/// <c>Verifiable.Cbor.Ctap.CtapLargeBlobsRequestCborReader.Read</c>, is method-group-compatible with this
/// delegate. A REQUIRED <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorSimulator"/> constructor
/// parameter: this authenticator advertises <c>largeBlobs:true</c> unconditionally, so an advertises-but-
/// cannot-decode configuration is unrepresentable, the same posture
/// <see cref="DecodeCtapCredentialManagementRequestDelegate"/> establishes for <c>credMgmt</c>.
/// </remarks>
/// <exception cref="Fido2FormatException"><paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR.</exception>
public delegate CtapLargeBlobsRequest DecodeCtapLargeBlobsRequestDelegate(ReadOnlyMemory<byte> parametersCbor);
