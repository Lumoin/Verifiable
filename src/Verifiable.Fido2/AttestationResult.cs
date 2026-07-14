namespace Verifiable.Fido2;

/// <summary>
/// The result of a single attestation statement format's verification procedure.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-defined-attestation-formats">W3C Web Authentication Level 3, section 8: Defined Attestation Statement Formats.</see>
/// <para>
/// A closed sum: every <see cref="AttestationVerifyDelegate"/> returns exactly one of the four
/// sibling records declared alongside this base — <see cref="NoneAttestationResult"/>,
/// <see cref="SelfAttestationResult"/>, <see cref="CertifiedAttestationResult"/>, or
/// <see cref="RejectedAttestationResult"/> — and a caller consumes the result with an
/// exhaustive switch expression rather than a type test against an open hierarchy.
/// </para>
/// </remarks>
public abstract record AttestationResult
{
    /// <summary>
    /// Prevents this closed sum from being extended outside the sibling records declared
    /// alongside it.
    /// </summary>
    private protected AttestationResult()
    {
    }
}
