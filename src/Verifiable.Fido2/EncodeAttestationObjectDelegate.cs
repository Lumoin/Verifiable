namespace Verifiable.Fido2;

/// <summary>
/// Encodes a WebAuthn <c>attestationObject</c> from its three constituent parts into raw CBOR bytes —
/// the production counterpart to <see cref="ParseAttestationObjectDelegate"/>.
/// </summary>
/// <param name="format">The <c>fmt</c> value — an IANA-registered attestation statement format identifier.</param>
/// <param name="attestationStatement">
/// The already CBOR-encoded, format-specific <c>attStmt</c> bytes, spliced in verbatim.
/// </param>
/// <param name="authenticatorData">The raw <c>authData</c> bytes, wrapped in a CBOR byte string.</param>
/// <returns>
/// The encoded <c>attestationObject</c> bytes, wrapped in a <see cref="TaggedMemory{T}"/> so the
/// buffer's provenance travels with it without a defensive copy.
/// </returns>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-generating-an-attestation-object">W3C Web
/// Authentication Level 3, section 6.5.4: Generating an Attestation Object</see>: a CBOR map with
/// exactly the members <c>fmt</c>, <c>attStmt</c>, and <c>authData</c>.
/// </para>
/// <para>
/// The concrete CBOR codec is supplied at the composition edge, keeping <c>Verifiable.Fido2</c>
/// serialization-agnostic — mirrors <see cref="ParseAttestationObjectDelegate"/>'s own seam shape. The
/// shipped default, <c>Verifiable.Cbor.Fido2.AttestationObjectCborWriter.Write</c>, is
/// method-group-compatible with this delegate. A CTAP client's <c>authenticatorMakeCredential</c>
/// response translates into exactly this shape: the CTAP response's <c>fmt</c>/<c>authData</c>/
/// <c>attStmt</c> members carry straight across, and every CTAP-only response member (<c>epAtt</c>,
/// <c>largeBlobKey</c>, <c>unsignedExtensionOutputs</c>) is dropped, since the WebAuthn
/// <c>attestationObject</c> syntax has no room for them.
/// </para>
/// </remarks>
public delegate TaggedMemory<byte> EncodeAttestationObjectDelegate(
    string format, ReadOnlyMemory<byte> attestationStatement, ReadOnlyMemory<byte> authenticatorData);
