namespace Verifiable.OAuth.Validation;

/// <summary>
/// Context for all validation checks. Carries request fields, flow state, JWT
/// claims, JWE parameters, KB-JWT claims, credential verification results, and
/// expected values for comparison. Check functions read what they need and
/// ignore the rest.
/// </summary>
[System.Diagnostics.DebuggerDisplay("ValidationContext Now={Now}")]
public sealed record ValidationContext
{
    /// <summary>The request or callback parameters (form body, query string, or both).</summary>
    public IReadOnlyDictionary<string, string>? Fields { get; init; }

    /// <summary>The current flow state loaded from persistence.</summary>
    public OAuthFlowState? FlowState { get; init; }

    /// <summary>The parsed JWT payload claims.</summary>
    public IReadOnlyDictionary<string, object>? TokenClaims { get; init; }

    /// <summary>The expected issuer identifier for <c>iss</c> comparison.</summary>
    public string? ExpectedIssuer { get; init; }

    /// <summary>The expected client identifier for <c>aud</c> and KB-JWT <c>aud</c> comparison.</summary>
    public string? ExpectedClientId { get; init; }

    /// <summary>The expected nonce for KB-JWT <c>nonce</c> comparison.</summary>
    public string? ExpectedNonce { get; init; }

    /// <summary>The current time from the injected <see cref="TimeProvider"/>.</summary>
    public required DateTimeOffset Now { get; init; }

    /// <summary>The time provider for expiry checks that need the provider directly.</summary>
    public TimeProvider? TimeProvider { get; init; }

    /// <summary>Maximum acceptable clock skew for temporal checks.</summary>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Maximum acceptable age for KB-JWT <c>iat</c> or flow expiry.</summary>
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>Maximum acceptable token lifetime (exp - nbf/iat).</summary>
    public TimeSpan MaximumLifetime { get; init; } = TimeSpan.FromHours(1);

    /// <summary>The JWE <c>enc</c> header value.</summary>
    public string? JweEncAlgorithm { get; init; }

    /// <summary>The algorithms the Verifier advertised in <c>encrypted_response_enc_values_supported</c>.</summary>
    public IReadOnlyList<string>? AllowedEncAlgorithms { get; init; }

    /// <summary>The KB-JWT <c>nonce</c> claim.</summary>
    public string? KbJwtNonce { get; init; }

    /// <summary>The KB-JWT <c>aud</c> claim.</summary>
    public string? KbJwtAud { get; init; }

    /// <summary>The KB-JWT <c>iat</c> claim.</summary>
    public DateTimeOffset? KbJwtIat { get; init; }

    /// <summary>Whether the KB-JWT signature verification succeeded.</summary>
    public bool KbJwtSignatureValid { get; init; }

    /// <summary>Whether the issuer credential signature verification succeeded.</summary>
    public bool CredentialSignatureValid { get; init; }

    /// <summary>Whether the <c>sd_hash</c> matches the presentation.</summary>
    public bool SdHashValid { get; init; }

    /// <summary>Whether the session transcript matches (mdoc).</summary>
    public bool SessionTranscriptValid { get; init; }

    /// <summary>Previously seen <c>jti</c> values for replay detection.</summary>
    public IReadOnlySet<string>? SeenJtiValues { get; init; }

    /// <summary>The scope string from the original request for scope-expansion checking.</summary>
    public string? RequestedScope { get; init; }
}
