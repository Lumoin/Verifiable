using System.Diagnostics;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Aggregates the delegate slots a resource server's request handler
/// composes to validate inbound access tokens and (optionally) DPoP
/// proofs. Parallel of
/// <see cref="Verifiable.OAuth.Server.AuthorizationServerIntegration"/>
/// on the consumption side; minimal — only what the validators need.
/// </summary>
/// <remarks>
/// The resource server has no flow state, no registration store, no
/// nonce challenge response — those are AS-side concerns. The RS only
/// validates inbound tokens and proofs against trusted-issuer
/// verification keys, then admits or rejects the request. Composition
/// happens at the handler level (e.g.,
/// <see cref="JwsAccessTokenValidator.ValidateAsync"/> chained with
/// <see cref="Dpop.DpopProofValidator.ValidateAsync"/> for DPoP-bound
/// tokens).
/// </remarks>
[DebuggerDisplay("ResourceServerIntegration ExpectedAudience={ExpectedAudience,nq}")]
public sealed class ResourceServerIntegration
{
    /// <summary>
    /// The trusted authorization server's issuer URI — compared against the
    /// access token's <c>iss</c> claim by ordinal equality. Required.
    /// </summary>
    public required Uri TrustedIssuer { get; init; }

    /// <summary>
    /// The expected <c>aud</c> claim value — this resource server's
    /// audience identifier. Required.
    /// </summary>
    public required string ExpectedAudience { get; init; }

    /// <summary>
    /// Resolves a public verification key by the access token header's
    /// <c>kid</c>. Required.
    /// </summary>
    public required ServerVerificationKeyResolverDelegate ResolveVerificationKeyAsync { get; init; }

    /// <summary>
    /// The time provider used for <c>exp</c>/<c>nbf</c>/<c>iat</c> checks
    /// and the DPoP freshness window. Defaults to
    /// <see cref="TimeProvider.System"/>.
    /// </summary>
    public TimeProvider TimeProvider { get; init; } = TimeProvider.System;

    /// <summary>
    /// Tolerance applied to a DPoP proof's <c>iat</c> claim per RFC 9449
    /// §11.1. Defaults to 60 seconds.
    /// </summary>
    public TimeSpan DpopFreshnessWindow { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Tolerance applied to an access token's <c>iat</c> claim for
    /// clock-skew rejection of future-dated tokens. Defaults to 60
    /// seconds.
    /// </summary>
    public TimeSpan AccessTokenIatSkew { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Replay tracker query for DPoP proof <c>jti</c> values. Required
    /// when the RS accepts DPoP-bound tokens; unused on Bearer-only
    /// deployments.
    /// </summary>
    public IsDpopProofJtiSeenDelegate? IsDpopProofJtiSeenAsync { get; init; }

    /// <summary>
    /// Persists a DPoP proof <c>jti</c> after a successful validation so
    /// subsequent presentations within the freshness window can be
    /// detected. Required alongside
    /// <see cref="IsDpopProofJtiSeenAsync"/> when the RS accepts
    /// DPoP-bound tokens.
    /// </summary>
    public PersistDpopProofJtiDelegate? PersistDpopProofJtiAsync { get; init; }
}
