using System.Diagnostics;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// The outcome of validating a Self-Issued ID Token per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11.1">SIOPv2 §11.1</see>.
/// Produced by <see cref="SelfIssuedIdTokenValidation.ValidateAsync"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each §11.1 check surfaces as its own flag so the RP can distinguish failure modes;
/// <see cref="IsValid"/> is the conjunction. When <see cref="IsSelfIssued"/> is
/// <see langword="false"/> the token is an attester-signed ID Token and MUST be
/// processed per OpenID Connect Core §3.2.2.11 instead — none of the self-issued
/// checks were evaluated.
/// </para>
/// <para>
/// The §11.2 cross-device replay check — that the <c>nonce</c> is known to the RP and
/// was not used in a previous Authorization Response — requires the RP's nonce store
/// and stays with the caller; <see cref="Nonce"/> carries the value to check.
/// </para>
/// </remarks>
[DebuggerDisplay("SelfIssuedIdTokenValidationResult IsValid={IsValid} SubjectSyntaxType={SubjectSyntaxType}")]
public sealed record SelfIssuedIdTokenValidationResult
{
    /// <summary>
    /// Whether the token parsed as a three-part compact JWS with well-formed
    /// base64url-encoded JSON header and payload.
    /// </summary>
    public bool IsStructurallyValid { get; init; }

    /// <summary>
    /// Whether the <c>iss</c> and <c>sub</c> claims carry the same value — the §11.1
    /// definition of a Self-Issued ID Token.
    /// </summary>
    public bool IsSelfIssued { get; init; }

    /// <summary>
    /// The Subject Syntax Type identified from the URI of the <c>sub</c> claim (§11.1).
    /// </summary>
    public SiopSubjectSyntaxType SubjectSyntaxType { get; init; }

    /// <summary>
    /// Whether the <c>sub_jwk</c> claim obeys §8: present and a bare public key for the
    /// JWK Thumbprint Subject Syntax Type, absent for the Decentralized Identifier type.
    /// </summary>
    public bool IsSubJwkShapeValid { get; init; }

    /// <summary>
    /// Whether the JOSE header <c>alg</c> is one of the RP's allowed algorithms
    /// (as in <c>id_token_signing_alg_values_supported</c>).
    /// </summary>
    public bool IsAlgorithmAllowed { get; init; }

    /// <summary>
    /// Whether the JWS signature verified against the subject's key — the key in
    /// <c>sub_jwk</c> for the JWK Thumbprint type, the resolved DID Document key for
    /// the Decentralized Identifier type. Only evaluated under an allowed algorithm.
    /// </summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>
    /// Whether the <c>sub</c> claim value is bound to the verification key: for the JWK
    /// Thumbprint type, <c>sub</c> equals the RFC 7638 thumbprint of the key in
    /// <c>sub_jwk</c>; for the Decentralized Identifier type, the key was obtained from
    /// the DID Document resolved from <c>sub</c>.
    /// </summary>
    public bool IsSubjectConfirmed { get; init; }

    /// <summary>
    /// Whether the <c>aud</c> claim contains the Client ID the RP sent in the
    /// Authorization Request.
    /// </summary>
    public bool IsAudienceValid { get; init; }

    /// <summary>
    /// Whether a <c>nonce</c> claim is present and equals the value the RP sent in the
    /// Authorization Request.
    /// </summary>
    public bool IsNonceValid { get; init; }

    /// <summary>
    /// Whether the validation time is before the <c>exp</c> claim (within the
    /// configured leeway).
    /// </summary>
    public bool IsUnexpired { get; init; }

    /// <summary>The <c>iss</c> claim value, when present.</summary>
    public string? Issuer { get; init; }

    /// <summary>The <c>sub</c> claim value, when present.</summary>
    public string? Subject { get; init; }

    /// <summary>The <c>nonce</c> claim value, when present.</summary>
    public string? Nonce { get; init; }

    /// <summary>The <c>exp</c> claim instant, when present.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// The <c>iat</c> claim instant, when present. §11.1 leaves the acceptable
    /// issued-too-far-in-the-past range RP-specific, so the value is surfaced for the
    /// caller to police.
    /// </summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>
    /// Whether every §11.1 check passed: structurally valid, self-issued, a supported
    /// Subject Syntax Type, conformant <c>sub_jwk</c> shape, allowed algorithm, valid
    /// signature, confirmed subject binding, matching audience and nonce, and unexpired.
    /// </summary>
    public bool IsValid =>
        IsStructurallyValid
        && IsSelfIssued
        && SubjectSyntaxType != SiopSubjectSyntaxType.Unknown
        && IsSubJwkShapeValid
        && IsAlgorithmAllowed
        && IsSignatureValid
        && IsSubjectConfirmed
        && IsAudienceValid
        && IsNonceValid
        && IsUnexpired;
}
