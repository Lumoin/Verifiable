namespace Verifiable.Fido2;

/// <summary>
/// Verifies an attestation statement per a specific attestation statement format's verification
/// procedure.
/// </summary>
/// <param name="request">The verification inputs.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The <see cref="AttestationResult"/> — a none, self, certified, or rejected outcome.</returns>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-defined-attestation-formats">W3C Web Authentication Level 3, section 8: Defined Attestation Statement Formats.</see>
/// A verification failure that the attestation statement itself caused (a bad signature, an
/// untrusted chain, a non-conforming certificate) is a <see cref="RejectedAttestationResult"/>,
/// not a thrown exception; only a null request or an unexpected failure surfaces as an
/// exception.
/// </remarks>
public delegate ValueTask<AttestationResult> AttestationVerifyDelegate(AttestationVerificationRequest request, CancellationToken cancellationToken);


/// <summary>
/// Selects the <see cref="AttestationVerifyDelegate"/> registered for an attestation statement
/// format identifier.
/// </summary>
/// <param name="format">The <c>fmt</c> value from the attestation object.</param>
/// <returns>The registered <see cref="AttestationVerifyDelegate"/>, or <see langword="null"/> when <paramref name="format"/> is not registered.</returns>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential">W3C Web Authentication Level 3, section 7.1: Registering a New Credential.</see>
/// "Determine the attestation statement format by performing a USASCII case-sensitive match on
/// fmt against the set of supported WebAuthn Attestation Statement Format Identifier values."
/// </para>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attstn-fmt-ids">Section 8.1: Attestation Statement Format Identifiers</see>
/// restates the same rule generally: "Implementations MUST match WebAuthn attestation statement
/// format identifiers in a case-sensitive fashion." An implementation built with
/// <see cref="Fido2AttestationSelectors.FromFormats"/> satisfies this by dispatching through an
/// ordinal (case-sensitive) dictionary lookup.
/// </para>
/// </remarks>
public delegate AttestationVerifyDelegate? SelectAttestationVerifierDelegate(string format);
