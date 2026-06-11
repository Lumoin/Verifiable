using System.Diagnostics;

namespace Verifiable.OAuth.Jarm;

/// <summary>
/// The outcome of validating a JWT-secured authorization response per
/// <see href="https://openid.net/specs/oauth-v2-jarm-final.html#section-2.4">JARM §2.4</see>.
/// Produced by <see cref="JarmResponseValidation.ValidateAsync"/>.
/// </summary>
/// <remarks>
/// §2.4: the client MUST NOT process the grant-type-specific authorization response
/// parameters before all checks succeed — so <see cref="Parameters"/> is populated only
/// when <see cref="IsValid"/> holds. Error responses are themselves valid JARM
/// documents: a signed, issuer/audience/expiry-clean JWT whose parameters carry
/// <c>error</c> validates with <see cref="IsValid"/> <see langword="true"/> and the
/// error rides <see cref="Error"/>.
/// </remarks>
[DebuggerDisplay("JarmResponseValidationResult IsValid={IsValid}")]
public sealed record JarmResponseValidationResult
{
    /// <summary>
    /// Whether the response parsed as a three-part compact JWS with well-formed
    /// base64url-encoded JSON header and payload.
    /// </summary>
    public bool IsStructurallyValid { get; init; }

    /// <summary>
    /// Whether the <c>iss</c> claim identifies the expected issuer of the authorization
    /// process in examination (§2.4 step 2).
    /// </summary>
    public bool IsIssuerValid { get; init; }

    /// <summary>
    /// Whether the <c>aud</c> claim matches the client id the client used to identify
    /// itself in the corresponding authorization request (§2.4 step 3).
    /// </summary>
    public bool IsAudienceValid { get; init; }

    /// <summary>
    /// Whether the validation time is before the <c>exp</c> claim, within the
    /// configured leeway (§2.4 step 4).
    /// </summary>
    public bool IsUnexpired { get; init; }

    /// <summary>
    /// Whether the JWS <c>alg</c> is one of the client's allowed algorithms. The
    /// algorithm <c>none</c> is never accepted (§2.4 step 5).
    /// </summary>
    public bool IsAlgorithmAllowed { get; init; }

    /// <summary>
    /// Whether the JWT signature verified against the resolved Authorization Server
    /// key (§2.4 step 5). Only evaluated when the issuer matched — the §5.1 defence —
    /// and under an allowed algorithm.
    /// </summary>
    public bool IsSignatureValid { get; init; }

    /// <summary>
    /// The authorization endpoint response parameters carried in the JWT — every claim
    /// except the <c>iss</c>/<c>aud</c>/<c>exp</c> transmission-securing claims — or
    /// <see langword="null"/> unless every check passed (§2.4: parameters MUST NOT be
    /// processed before all checks succeed).
    /// </summary>
    public IReadOnlyDictionary<string, object>? Parameters { get; init; }

    /// <summary>The <c>code</c> response parameter, when present in <see cref="Parameters"/>.</summary>
    public string? Code => GetString("code");

    /// <summary>The <c>state</c> response parameter, when present in <see cref="Parameters"/>.</summary>
    public string? State => GetString("state");

    /// <summary>The <c>error</c> response parameter, when present in <see cref="Parameters"/>.</summary>
    public string? Error => GetString("error");

    /// <summary>
    /// Whether every §2.4 check passed: structurally valid, expected issuer, matching
    /// audience, unexpired, allowed algorithm, and a valid signature.
    /// </summary>
    public bool IsValid =>
        IsStructurallyValid
        && IsIssuerValid
        && IsAudienceValid
        && IsUnexpired
        && IsAlgorithmAllowed
        && IsSignatureValid;


    private string? GetString(string parameterName) =>
        Parameters is not null
            && Parameters.TryGetValue(parameterName, out object? value)
            && value is string text
            ? text
            : null;
}
