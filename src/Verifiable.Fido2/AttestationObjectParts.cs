using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The three constituents of a WebAuthn <c>attestationObject</c>, sliced from its raw CBOR bytes.
/// </summary>
/// <param name="Format">
/// The attestation statement format identifier (the CBOR <c>fmt</c> member) — one of the
/// <see cref="WellKnownWebAuthnAttestationFormats"/> values, or any other IANA-registered identifier
/// a caller's <see cref="SelectAttestationVerifierDelegate"/> recognises.
/// </param>
/// <param name="AttestationStatement">
/// The raw CBOR bytes of the <c>attStmt</c> member, aliasing the buffer supplied to
/// <see cref="ParseAttestationObjectDelegate"/> (wrap, don't copy) — opaque at this layer, exactly what
/// <see cref="AttestationVerificationRequest.AttestationStatement"/> expects. The format-specific
/// <c>ParseXxxAttestationStatementDelegate</c> resolved from <see cref="Format"/> decodes it.
/// </param>
/// <param name="AuthenticatorData">
/// The raw <c>authData</c> wire bytes — the CBOR <c>authData</c> member's byte-string contents,
/// aliasing the buffer supplied to <see cref="ParseAttestationObjectDelegate"/> (wrap, don't copy) —
/// exactly what <see cref="AttestationVerificationRequest.AuthenticatorDataBytes"/> expects and what
/// <see cref="AuthenticatorDataReader.Read"/> parses.
/// </param>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-generating-an-attestation-object">W3C Web
/// Authentication Level 3, section 6.5.4: Generating an Attestation Object</see> defines the
/// CBOR-encoded <c>attestationObject</c> as a map with exactly the members <c>authData</c>,
/// <c>fmt</c>, and <c>attStmt</c> (<c>attObj</c> / <c>attStmtTemplate</c> in that section's CDDL); the
/// Relying Party side of the same exchange,
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">section 7.1:
/// Registering a New Credential</see>, directs the Relying Party to "Perform CBOR decoding on the
/// attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation
/// statement format fmt, the authenticator data authData, and the attestation statement attStmt."
/// </para>
/// </remarks>
[DebuggerDisplay("AttestationObjectParts(Format={Format,nq}, AttestationStatement={AttestationStatement.Length} bytes, AuthenticatorData={AuthenticatorData.Length} bytes)")]
public sealed record AttestationObjectParts(string Format, ReadOnlyMemory<byte> AttestationStatement, ReadOnlyMemory<byte> AuthenticatorData);


/// <summary>
/// Decodes a WebAuthn <c>attestationObject</c>'s raw CBOR bytes into its constituent parts.
/// </summary>
/// <param name="attestationObject">The raw CBOR bytes of the <c>attestationObject</c>.</param>
/// <returns>The decoded, alias-sliced parts.</returns>
/// <remarks>
/// The concrete CBOR codec is supplied at the composition edge, keeping this library
/// serialization-agnostic — mirrors <see cref="ParsePackedAttestationStatementDelegate"/>.
/// </remarks>
/// <exception cref="Fido2FormatException">
/// Thrown when <paramref name="attestationObject"/> is not valid CBOR conforming to the
/// <c>attestationObject</c> syntax defined in
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-generating-an-attestation-object">W3C Web
/// Authentication Level 3, section 6.5.4</see>.
/// </exception>
public delegate AttestationObjectParts ParseAttestationObjectDelegate(ReadOnlyMemory<byte> attestationObject);
