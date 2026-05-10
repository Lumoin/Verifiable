using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// Per-validation-check refined view. Composes
/// <see cref="RequestContext"/> via <see cref="Context"/> so checks can read
/// request-wide concerns (resolved policy, issuer, etc.) alongside their
/// check-specific typed fields. Each check function reads what it needs and
/// ignores the rest.
/// </summary>
/// <remarks>
/// <para>
/// One of four per-request context shapes that serve different lifecycles:
/// <see cref="RequestContext"/> (per-request bag, populated at dispatch entry
/// by the skin); <see cref="OAuthFlowState"/> (persistent cross-request
/// carrier for state-machine progress); <see cref="Verifiable.OAuth.IssuanceContext"/>
/// (per-token-endpoint-call refined view for the token producer / claim
/// contributor walk); and this <see cref="ValidationContext"/>
/// (per-validation-check refined view).
/// </para>
/// <para>
/// The pipeline-stage separation is real: each context's lifetime maps to a
/// stage of request processing. Per-request data lives on
/// <see cref="RequestContext"/> via typed extensions; stage-bounded data
/// lives on the appropriate stage-specific typed record; persistent
/// cross-request data lives on <see cref="OAuthFlowState"/>. Policy values
/// resolved at dispatch entry have per-request lifetime and consumers in all
/// three downstream contexts; pattern fit places them on
/// <see cref="RequestContext"/> via
/// <see cref="Verifiable.OAuth.Server.PolicyRequestContextExtensions"/>.
/// </para>
/// </remarks>
[System.Diagnostics.DebuggerDisplay("ValidationContext Now={Now}")]
public sealed record ValidationContext
{
    /// <summary>
    /// The per-request context bag. Validators read request-wide concerns
    /// (resolved policy via
    /// <see cref="Verifiable.OAuth.Server.PolicyRequestContextExtensions"/>,
    /// issuer URL, time provider snapshot) through this composition rather
    /// than via duplicated fields on this record. Required — every validator
    /// invocation in dispatched flows has a request context, and unit tests
    /// of individual validation checks construct an empty
    /// <see cref="RequestContext"/> when no resolution has happened.
    /// </summary>
    public required RequestContext Context { get; init; }

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

    /// <summary>
    /// Maximum acceptable clock skew for temporal checks. Defaults to five
    /// minutes for backwards-compatible validation behaviour.
    /// </summary>
    /// <remarks>
    /// Application code that owns the active
    /// <see cref="Verifiable.OAuth.Server.AuthorizationServer"/> should pass
    /// <c>server.Timings.ClockSkewTolerance</c> here so all validation sites
    /// in the deployment share one source of truth. See
    /// <see cref="Verifiable.OAuth.Server.TimingPolicy.ClockSkewTolerance"/>.
    /// </remarks>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum acceptable age for KB-JWT <c>iat</c> or flow expiry. Defaults to
    /// five minutes.
    /// </summary>
    /// <remarks>
    /// Application code that owns the active
    /// <see cref="Verifiable.OAuth.Server.AuthorizationServer"/> may pass
    /// <c>server.Timings.MaximumFlowLifetime</c> here when the validation is
    /// scoped to flow lifetime rather than KB-JWT freshness.
    /// </remarks>
    public TimeSpan MaxAge { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum acceptable token lifetime (exp - nbf/iat). Defaults to one hour.
    /// </summary>
    /// <remarks>
    /// Application code that owns the active
    /// <see cref="Verifiable.OAuth.Server.AuthorizationServer"/> may pass
    /// <c>server.Timings.AccessTokenLifetime</c> here when validating an
    /// access token, or <c>server.Timings.IdTokenLifetime</c> when validating
    /// an ID token, so the validator and the issuer share one source of truth.
    /// </remarks>
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
