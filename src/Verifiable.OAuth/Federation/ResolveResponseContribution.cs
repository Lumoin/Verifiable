using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Application-supplied body of a Resolve Response served at the
/// <c>federation_resolve_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.3">Federation §8.3</see>.
/// The library produces the structural envelope claims (<c>iss</c> = the
/// resolver, <c>sub</c> = the resolved subject, <c>iat</c>, <c>exp</c>) and
/// signs the JWT with the resolver's federation signing key; the resolved
/// <c>metadata</c>, the <c>trust_chain</c>, and any <c>trust_marks</c> come
/// from the application's
/// <see cref="Server.AuthorizationServerIntegration.ResolveSubjectTrustChainAsync"/>
/// delegate.
/// </summary>
/// <remarks>
/// <para>
/// Resolving a subject — walking its authority hints to a Trust Anchor,
/// verifying every link, and applying the accumulated metadata policy — is
/// the resolver application's responsibility (the library ships the §6/§10
/// engines it can compose for that, but does not run them inside the
/// endpoint). This record is the <em>result</em> of that work, projected
/// onto the §8.3 wire claims.
/// </para>
/// <para>
/// <see cref="Metadata"/> is required: a Resolve Response with no resolved
/// metadata has nothing to convey. <see cref="TrustChain"/> and
/// <see cref="TrustMarks"/> are optional on this record so the library never
/// imposes a §8.3 REQUIRED/OPTIONAL policy of its own — the application
/// emits the chain and marks its profile mandates. The application returns
/// <see langword="null"/> from the delegate when the subject cannot be
/// resolved to the requested anchor; the endpoint then responds HTTP 404.
/// </para>
/// </remarks>
[DebuggerDisplay("ResolveResponseContribution")]
public sealed record ResolveResponseContribution
{
    /// <summary>
    /// The resolved <c>metadata</c> claim — the subject's effective,
    /// policy-applied per-entity-type metadata. Required.
    /// </summary>
    public required IReadOnlyDictionary<string, object> Metadata { get; init; }

    /// <summary>
    /// The <c>trust_chain</c> claim — the sequence of Entity Statement
    /// compact JWS strings forming the verified chain from the subject's
    /// Entity Configuration up to the Trust Anchor. Optional on this record;
    /// the application emits it when its §8.3 profile conveys the chain so a
    /// requester that does not trust the resolver blindly can re-verify.
    /// </summary>
    public IReadOnlyList<string>? TrustChain { get; init; }

    /// <summary>
    /// The <c>trust_marks</c> claim — the Trust Marks held by the subject,
    /// each a JSON object the application shapes per Federation §8.3 / §7
    /// (typically <c>{ "trust_mark_type": ..., "trust_mark": &lt;jwt&gt; }</c>).
    /// Optional.
    /// </summary>
    public IReadOnlyList<object>? TrustMarks { get; init; }

    /// <summary>
    /// Additional top-level claims to merge into the Resolve Response payload
    /// after the library's structural claims and the dedicated slots above.
    /// Keys that collide with library-emitted structural claims (<c>iss</c>,
    /// <c>sub</c>, <c>iat</c>, <c>exp</c>, <c>metadata</c>) are dropped — the
    /// library wins.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AdditionalClaims { get; init; }
}
