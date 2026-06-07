using System.Diagnostics;
using Verifiable.Core;
using Verifiable.OAuth.Oidc;
using Verifiable.OAuth.Server;

namespace Verifiable.OAuth;

/// <summary>
/// Discriminated target for claim contribution. Each
/// <see cref="Verifiable.Core.Assessment.ClaimDelegate{T}"/> registered on
/// <see cref="ServerConfiguration.ClaimIssuer"/> receives a target and
/// pattern-matches to decide whether to contribute claims for that
/// target.
/// </summary>
/// <remarks>
/// <para>
/// The closed hierarchy mirrors <c>Verifiable.OAuth.Validation</c>'s
/// <c>ValidationContext</c> family — one target type per claim-emitting
/// surface. Adding a new emission point in a future phase (federation
/// entity statement, OID4VCI credential, SIOPv2 self-issued ID Token,
/// logout token, IDA verified claims) is a single new sealed record
/// extending this base.
/// </para>
/// <para>
/// Targets that operate on <see cref="IssuanceContext"/>-rich state
/// (ID Token, access token) carry it directly. Targets that respond to
/// authenticated bearer-token requests (UserInfo, introspection)
/// carry just the subset they need.
/// </para>
/// </remarks>
[DebuggerDisplay("ClaimContributionTarget")]
public abstract record ClaimContributionTarget;


/// <summary>
/// Contribution target for an OIDC ID Token. Carries the per-issuance
/// state plus optional pre-resolved <see cref="OidcClaims"/>; the
/// walking site at the token endpoint resolves the user's OIDC claims
/// once before invoking the contributor walk and passes the result
/// through this property so per-rule contributors don't each re-issue
/// the resolver call.
/// </summary>
[DebuggerDisplay("IdTokenTarget Subject={Issuance.Subject,nq}")]
public sealed record IdTokenTarget(IssuanceContext Issuance) : ClaimContributionTarget
{
    /// <summary>
    /// The user's OIDC claims as resolved once by the walking site
    /// before the contributor walk. <see langword="null"/> means the
    /// walking site couldn't resolve (no resolver wired, or the resolver
    /// returned null); contributors treat absence as "no scope-driven
    /// claims to emit."
    /// </summary>
    public OidcClaims? ResolvedOidcClaims { get; init; }
}


/// <summary>
/// Contribution target for an OAuth 2.0 access token's JWT body
/// (RFC 9068 shape). Access tokens carry resource-server-oriented
/// claims, not OIDC profile claims, so the target doesn't include
/// <see cref="OidcClaims"/>.
/// </summary>
[DebuggerDisplay("AccessTokenTarget Subject={Issuance.Subject,nq}")]
public sealed record AccessTokenTarget(IssuanceContext Issuance) : ClaimContributionTarget;


/// <summary>
/// Contribution target for the OIDC UserInfo endpoint response
/// (OIDC Core §5.3). The endpoint authenticates with a bearer token,
/// derives the subject + scope from token introspection, and runs the
/// contributor walk to compose the response body.
/// </summary>
[DebuggerDisplay("UserInfoTarget Subject={Subject,nq}")]
public sealed record UserInfoTarget(
    ClientRecord Registration,
    string Subject,
    string Scope,
    ExchangeContext Context) : ClaimContributionTarget
{
    /// <summary>
    /// The user's OIDC claims as resolved once by the walking site
    /// before the contributor walk. Same role as the
    /// <see cref="IdTokenTarget.ResolvedOidcClaims"/> property; see its
    /// documentation for rationale.
    /// </summary>
    public OidcClaims? ResolvedOidcClaims { get; init; }
}


/// <summary>
/// Contribution target for an RFC 7662 introspection response body.
/// Introspection responses describe the presented token's state
/// (active, scope, sub, aud, expiry, jti) plus any application-
/// contributed fields; the contributor walk composes the latter.
/// </summary>
[DebuggerDisplay("IntrospectionTarget Jti={TokenJti,nq}")]
public sealed record IntrospectionTarget(
    ClientRecord Registration,
    string TokenJti,
    string Subject,
    string Scope,
    ExchangeContext Context) : ClaimContributionTarget;
