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
/// The resource server has no flow state and no registration store. It
/// validates inbound tokens against trusted-issuer verification keys with
/// <see cref="JwsAccessTokenValidator.ValidateAsync"/>, then hands the
/// presentation to <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/>, the composition
/// of the RFC 9449 Section 7.1 checks over the slots below: the proof
/// validation, the resource's own nonces, the accepted algorithms and the
/// <c>jti</c> record, answering a permit or the exact refusal to send.
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
    /// <c>kid</c>, asked under
    /// <see cref="Verifiable.Cryptography.Context.KeyUsageContext.AccessTokenIssuance"/>
    /// by <see cref="JwsAccessTokenValidator.ValidateAsync"/>: the resource
    /// server has no other marker of the access-token key, since
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>
    /// "does not provide a mechanism for identifying a specific key as the
    /// one used to sign JWT access tokens". A resolver that keeps keys apart
    /// per kind answers <see langword="null"/> for a key it holds for another
    /// usage. Required.
    /// </summary>
    public required ServerVerificationKeyResolverDelegate ResolveVerificationKeyAsync { get; init; }

    /// <summary>
    /// The time provider used for <c>exp</c>/<c>nbf</c>/<c>iat</c> checks
    /// and the DPoP freshness window.
    /// </summary>
    public required TimeProvider TimeProvider { get; init; }

    /// <summary>
    /// The window <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/> holds a validated DPoP proof's
    /// <c>iat</c> claim to either way of the clock, the bounds included, whatever tolerance the proof validation wired
    /// into <see cref="ValidateDpopProofAsync"/> applies: the window a proof is accepted in
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "servers MUST only
    /// accept DPoP proofs for a limited time after their creation"), and so the time a proof's <c>jti</c> is recorded
    /// for beyond the later of the clock and its <c>iat</c>: <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/>
    /// records it through <see cref="PersistDpopProofJtiAsync"/> until the first instant after that window. A negative
    /// window names no time at all and is refused by <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/> as
    /// the caller's argument (<see cref="ArgumentException"/> naming the integration). Defaults to 60 seconds.
    /// </summary>
    public TimeSpan DpopFreshnessWindow { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Tolerance applied to an access token's <c>iat</c> claim for
    /// clock-skew rejection of future-dated tokens. Defaults to 60
    /// seconds.
    /// </summary>
    public TimeSpan AccessTokenIatSkew { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Replay tracker query for DPoP proof <c>jti</c> values presented to this resource server
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "HTTP requests to
    /// the same URI for which the jti value has been seen before would be declined.").
    /// <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/> calls it with no target URI, so the <c>jti</c> is
    /// looked up as the store keys it, not in the context of the target URI that section names; a <c>jti</c> that is
    /// empty, longer than <see cref="Server.JtiReplayGuard.MaxJtiLength"/> UTF-16 code units, or holding a character of
    /// general category Cc or an unpaired surrogate is refused before this slot is called. Required when the RS accepts
    /// DPoP-bound tokens; unused on Bearer-only deployments.
    /// </summary>
    public IsDpopProofJtiSeenDelegate? IsDpopProofJtiSeenAsync { get; init; }

    /// <summary>
    /// Persists an accepted DPoP proof <c>jti</c> so its every later presentation within the proof's acceptance window is
    /// refused (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449 Section 11.1</see>: "In the
    /// context of the target URI, servers can store the jti value of each DPoP proof for the time window in which the
    /// respective DPoP proof JWT would be accepted to prevent multiple uses of the same DPoP proof.").
    /// <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/> calls it with no target URI, so the <c>jti</c> is
    /// recorded as the store keys it, not in the context of the target URI, and with an expiry one tick past the later
    /// of the clock and the proof's <c>iat</c> plus <see cref="DpopFreshnessWindow"/>, the window it holds the
    /// <c>iat</c> to, so a store reading the expiry either as the last instant the entry counts or as the first instant
    /// it does not count refuses a replay at the window's last instant. A <c>jti</c> that is empty, longer than
    /// <see cref="Server.JtiReplayGuard.MaxJtiLength"/> UTF-16 code units, or holding a character of general category Cc
    /// or an unpaired surrogate is refused <c>invalid_dpop_proof</c> before this slot is called, the rule the library's
    /// resources hold a <c>jti</c> to wherever their replay guard reads it, which under
    /// <see cref="Server.JtiReplayPolicy.Disabled"/> it does not. Required alongside
    /// <see cref="IsDpopProofJtiSeenAsync"/> when the RS accepts DPoP-bound tokens.
    /// </summary>
    public PersistDpopProofJtiDelegate? PersistDpopProofJtiAsync { get; init; }

    /// <summary>
    /// Validates a DPoP proof presented with an access token at this resource server, every check of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see> ("To validate a DPoP
    /// proof, the receiving server MUST ensure the following") over the request's method, target URI, the presented
    /// token's hash and <see cref="AcceptedDpopProofAlgorithms"/>; for example
    /// <see cref="Dpop.DpopProofValidator"/>'s <c>ValidateAsync</c> over the application's verification function.
    /// <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/> holds a validated proof's <c>iat</c> to
    /// <see cref="DpopFreshnessWindow"/>: a narrower <c>iat</c> tolerance of the validation's own is its choice, and a
    /// wider one is cut to the window. Required when the resource server accepts DPoP-bound tokens; with it unwired a
    /// DPoP-bound token is answered <c>server_error</c>.
    /// </summary>
    public Dpop.ValidateDpopProofDelegate? ValidateDpopProofAsync { get; init; }

    /// <summary>
    /// Issues a fresh DPoP nonce for the target URI of the request it is provided on, the one endpoint it is accepted
    /// at (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "Resource servers can
    /// also choose to provide a nonce value to be included in DPoP proofs sent to them."); for example
    /// <see cref="Dpop.DefaultDpopNonceIssuance.IssueAsync"/> over the resource server's HMAC key set. At an application's
    /// resource <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/> calls it with the default
    /// <see cref="Verifiable.Core.TenantId"/> and the request's target URI as the audience, so a key set resolved by tenant answers its
    /// default tenant here. Required alongside <see cref="ValidateDpopNonceAsync"/> when the resource server accepts
    /// DPoP-bound tokens.
    /// </summary>
    public Dpop.IssueDpopNonceDelegate? IssueDpopNonceAsync { get; init; }

    /// <summary>
    /// Validates a DPoP nonce presented in a proof against the target URI it must have been issued for, the wire
    /// format <see cref="IssueDpopNonceAsync"/> writes; for example <see cref="Dpop.DefaultDpopNonceValidation.ValidateAsync"/>.
    /// At an application's resource <see cref="ProtectedResource.DpopResourceAccess.DecideAsync"/> calls it with the
    /// default <see cref="Verifiable.Core.TenantId"/> and the request's target URI as the audience, the pair it issues under.
    /// Required alongside <see cref="IssueDpopNonceAsync"/> when the resource server accepts DPoP-bound tokens.
    /// </summary>
    public Dpop.ValidateDpopNonceDelegate? ValidateDpopNonceAsync { get; init; }

    /// <summary>
    /// The JWS <c>alg</c> values this resource server accepts for a DPoP proof, held to every proof and written as the
    /// <c>algs</c> parameter of its <c>DPoP</c> challenges
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "An algs parameter
    /// SHOULD be included to signal to the client the JWS algorithms that are acceptable for the DPoP proof JWT.");
    /// <see langword="null"/> reads <see cref="Dpop.WellKnownDpopValues.SupportedSigningAlgorithms"/>. Each name is a
    /// registered JWS algorithm identifier, an RFC 9110 Section 5.6.2 token.
    /// </summary>
    public IReadOnlyList<string>? AcceptedDpopProofAlgorithms { get; init; }
}
