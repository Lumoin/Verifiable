using System.Diagnostics;
using Verifiable.Core;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// Per-validation-check refined view. Composes
/// <see cref="ExchangeContext"/> via <see cref="Context"/> so checks can read
/// request-wide concerns (resolved policy, issuer, etc.) alongside their
/// check-specific typed fields. Each check function reads what it needs and
/// ignores the rest.
/// </summary>
/// <remarks>
/// <para>
/// One of four per-request context shapes that serve different lifecycles:
/// <see cref="ExchangeContext"/> (per-request bag, populated at dispatch entry
/// by the skin); <see cref="FlowState"/> (persistent cross-request
/// carrier for state-machine progress); <see cref="Verifiable.OAuth.IssuanceContext"/>
/// (per-token-endpoint-call refined view for the token producer / claim
/// contributor walk); and this <see cref="ValidationContext"/>
/// (per-validation-check refined view).
/// </para>
/// <para>
/// The pipeline-stage separation is real: each context's lifetime maps to a
/// stage of request processing. Per-request data lives on
/// <see cref="ExchangeContext"/> via typed extensions; stage-bounded data
/// lives on the appropriate stage-specific typed record; persistent
/// cross-request data lives on <see cref="FlowState"/>. Policy values
/// resolved at dispatch entry have per-request lifetime and consumers in all
/// three downstream contexts; pattern fit places them on
/// <see cref="ExchangeContext"/> via
/// <see cref="Verifiable.OAuth.Server.PolicyExchangeContextExtensions"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("ValidationContext Now={Now}")]
public sealed record ValidationContext
{
    /// <summary>
    /// The per-request context bag. Validators read request-wide concerns
    /// (resolved policy via
    /// <see cref="Verifiable.OAuth.Server.PolicyExchangeContextExtensions"/>,
    /// issuer URL, time provider snapshot) through this composition rather
    /// than via duplicated fields on this record. Required — every validator
    /// invocation in dispatched flows has a request context, and unit tests
    /// of individual validation checks construct an empty
    /// <see cref="ExchangeContext"/> when no resolution has happened.
    /// </summary>
    public required ExchangeContext Context { get; init; }

    /// <summary>The request or callback parameters (form body, query string, or both).</summary>
    public IReadOnlyDictionary<string, string>? Fields { get; init; }

    /// <summary>The current flow state loaded from persistence.</summary>
    public FlowState? FlowState { get; init; }

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
    /// <see cref="Verifiable.OAuth.Server.EndpointServer"/> should pass
    /// <c>oauth.Timings.ClockSkewTolerance</c> here so all validation sites
    /// in the deployment share one source of truth. See
    /// <see cref="Verifiable.OAuth.Server.TimingPolicy.ClockSkewTolerance"/>.
    /// </remarks>
    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum acceptable age for the KB-JWT <c>iat</c> claim — the holder
    /// proof-of-possession freshness window. Defaults to five minutes.
    /// </summary>
    /// <remarks>
    /// The per-call fallback for the resolved
    /// <see cref="Verifiable.OAuth.Server.PolicyExchangeContextExtensions.KbJwtMaxAgeWindow"/>
    /// policy: the KB-JWT <c>iat</c> freshness check uses the policy window when
    /// set, otherwise this value. Application code owning the active
    /// <see cref="Verifiable.OAuth.Server.EndpointServer"/> aligns it with
    /// the deployment's KB-JWT freshness policy.
    /// </remarks>
    public TimeSpan KbJwtMaxAge { get; init; } = TimeSpan.FromMinutes(5);

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

    /// <summary>
    /// Whether the mdoc device signature verified against the verifier-
    /// reconstructed <c>SessionTranscript</c> per OID4VP 1.0 Appendix B.2.6.1.
    /// Computed by <see cref="Oid4Vp.Server.MdocVpTokenVerification"/>; the
    /// SD-JWT path has no transcript and reports <see langword="true"/>.
    /// </summary>
    public bool SessionTranscriptValid { get; init; }

    /// <summary>
    /// Whether the presentation satisfies the DCQL query — every claim the
    /// credential query requested is present in the disclosed/extracted claims.
    /// Derived in the verify step (the executor compares the query's requested
    /// leaf identifiers against the extracted claims, the verifier-side mirror
    /// of the wallet running the disclosure engine). Defaults to
    /// <see langword="true"/> so the axis is a no-op for validators that do not
    /// include <see cref="Oid4Vp.Server"/>'s DCQL-satisfaction rule.
    /// </summary>
    public bool DcqlSatisfied { get; init; } = true;

    /// <summary>
    /// Whether the presentation disclosed <em>more</em> claims than the DCQL
    /// query requested — i.e., a data-minimization violation (the inverse of
    /// <see cref="DcqlSatisfied"/>). Derived in the verify step: the executor
    /// flags any extracted/disclosed claim whose leaf identifier was not among
    /// the query's requested ones. Defaults to <see langword="false"/> (no
    /// over-disclosure) so the axis is a no-op for validators that do not include
    /// <see cref="Oid4Vp.Server"/>'s no-over-disclosure rule. Enforcement is
    /// policy-gated — see
    /// <see cref="Verifiable.OAuth.Server.PolicyExchangeContextExtensions.EnforceNoOverDisclosure"/>.
    /// </summary>
    public bool DcqlOverDisclosed { get; init; }

    /// <summary>
    /// The shortest disclosure salt length, in bytes, observed across the presentation's disclosures,
    /// or <see langword="null"/> when the format carries no disclosure salts (mdoc) or there were no
    /// disclosures. Captured in the verify step, which holds the parsed <c>SdToken</c> disclosures. The
    /// raw number flows through so the consumer can judge it against whatever threshold applies; the
    /// <see cref="Oid4Vp.Server"/> salt-length rule compares it against
    /// <see cref="Verifiable.Cryptography.Salt.RecommendedByteLength"/> and only fails when enforcement
    /// is opted in (<see cref="Verifiable.OAuth.Server.PolicyExchangeContextExtensions.EnforceMinimumSaltLength"/>),
    /// since RFC 9901 §9.3 RECOMMENDS rather than mandates the length.
    /// </summary>
    public int? MinimumDisclosureSaltLengthBytes { get; init; }

    /// <summary>
    /// Whether a disclosure salt in this presentation was already seen by the application's salt-reuse
    /// store (RFC 9901 §9.4 — unique salts; a repeat is a correlation/replay signal). Derived in the
    /// verify step, and only ever <see langword="true"/> when a salt-reuse seam was wired and a reuse was
    /// found, so it is opt-in like DPoP-JTI replay. Defaults to <see langword="false"/> (no reuse / no
    /// seam), a no-op for validators that do not include <see cref="Oid4Vp.Server"/>'s salt-reuse rule.
    /// </summary>
    public bool SaltReused { get; init; }

    /// <summary>
    /// The <c>transaction_data_hashes</c> array extracted from the KB-JWT, or
    /// <see langword="null"/> when the KB-JWT did not carry the claim. Compared
    /// against <see cref="ExpectedTransactionDataHashes"/> by the OID4VP 1.0
    /// §8.4 check.
    /// </summary>
    public IReadOnlyList<string>? KbJwtTransactionDataHashes { get; init; }

    /// <summary>
    /// The base64url-encoded hashes the verifier expects the Wallet to bind
    /// into the KB-JWT — the verifier's recomputation over the
    /// <c>transaction_data</c> array it sent in the Authorization Request.
    /// <see langword="null"/> when the request carried no <c>transaction_data</c>.
    /// </summary>
    public IReadOnlyList<string>? ExpectedTransactionDataHashes { get; init; }
}
