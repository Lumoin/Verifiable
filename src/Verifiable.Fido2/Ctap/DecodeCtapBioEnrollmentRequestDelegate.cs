using System;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Decodes the CTAP2-canonical CBOR payload of an <c>authenticatorBioEnrollment</c> request into its
/// typed model — the authenticator-side operation.
/// </summary>
/// <param name="parametersCbor">The CBOR-encoded request parameter map.</param>
/// <returns>The decoded request model.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="DecodeCtapClientPinRequestDelegate"/>'s shape, minus a
/// memory pool: every member this delegate decodes is a plain scalar or an opaque byte string/string
/// copied onto the heap, with no pooled <c>SensitiveMemory</c> carrier (<see cref="CtapBioEnrollmentRequest.TemplateId"/>
/// mirrors <see cref="CtapCredentialManagementRequest.RpIdHash"/>'s own unpooled <c>ReadOnlyMemory{Byte}</c>
/// shape). The shipped default, <c>Verifiable.Cbor.Ctap.CtapBioEnrollmentRequestCborReader.Read</c>, is
/// method-group-compatible with this delegate. A REQUIRED
/// <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorSimulator"/> constructor parameter: this
/// authenticator advertises <c>bioEnroll</c> present (true or false tri-state) unconditionally from
/// this wave on, so an advertises-but-cannot-decode configuration is unrepresentable — the exact
/// posture <see cref="DecodeCtapCredentialManagementRequestDelegate"/>'s own R1 precedent establishes.
/// </remarks>
/// <exception cref="Fido2FormatException"><paramref name="parametersCbor"/> is not valid CTAP2 canonical CBOR.</exception>
public delegate CtapBioEnrollmentRequest DecodeCtapBioEnrollmentRequestDelegate(ReadOnlyMemory<byte> parametersCbor);
