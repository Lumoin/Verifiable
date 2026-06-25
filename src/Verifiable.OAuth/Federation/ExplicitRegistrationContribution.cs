using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// Application-supplied body of an Explicit Registration Response served at
/// the <c>federation_registration_endpoint</c> per
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-12.2">Federation §12.2</see>.
/// The library produces the structural envelope (<c>iss</c> = the OP,
/// <c>sub</c> = <c>aud</c> = the RP, <c>iat</c>, <c>exp</c>) and signs the
/// JWT with the OP's federation signing key; the registered client
/// <c>metadata</c>, the selected <c>trust_anchor</c>, and any echoed
/// <c>jwks</c> come from the application's
/// <see cref="Server.AuthorizationServerIntegration.ResolveExplicitRegistrationAsync"/>
/// delegate.
/// </summary>
/// <remarks>
/// <para>
/// Verifying the RP's posted Entity Configuration signature, resolving and
/// validating its trust chain to a Trust Anchor the OP trusts (the library
/// ships <see cref="FederationAutomaticRegistration"/> for exactly that
/// composition), applying metadata policy, and minting any issued client
/// credentials are the OP application's work. This record is the
/// <em>result</em> projected onto the §12.2 response claims.
/// </para>
/// <para>
/// <see cref="Subject"/> and <see cref="Metadata"/> are required —
/// <see cref="Subject"/> becomes both the <c>sub</c> and the <c>aud</c>
/// claim (§3.1.5: the <c>aud</c> MUST be the Entity Identifier of the RP),
/// and <see cref="Metadata"/> is the registered client metadata the RP needs.
/// <see cref="TrustAnchor"/> and <see cref="AuthorityHint"/> are required by
/// the §12.2.3 requirements for a successful registration response; Jwks stays optional.
/// The application returns <see langword="null"/> from the delegate when the
/// RP cannot be registered; the endpoint then responds HTTP 400.
/// </para>
/// </remarks>
[DebuggerDisplay("ExplicitRegistrationContribution Subject={Subject}")]
public sealed record ExplicitRegistrationContribution
{
    /// <summary>
    /// The Relying Party's Entity Identifier. Becomes both the <c>sub</c> and
    /// the <c>aud</c> claim of the response per §3.1.5. Required.
    /// </summary>
    public required Uri Subject { get; init; }

    /// <summary>
    /// The registered client <c>metadata</c> claim — the RP's effective,
    /// policy-applied per-entity-type metadata plus any client credentials
    /// the OP issued. Required.
    /// </summary>
    public required IReadOnlyDictionary<string, object> Metadata { get; init; }

    /// <summary>
    /// The <c>trust_anchor</c> claim — the Entity Identifier of the Trust
    /// Anchor the OP selected to process the registration. REQUIRED in a
    /// successful Explicit Registration Response per §12.2.3.
    /// </summary>
    public required Uri TrustAnchor { get; init; }

    /// <summary>
    /// The RP's Immediate Superior in the Trust Chain the OP selected to
    /// process the request. Emitted as the <c>authority_hints</c> claim — a
    /// single-element array — which is REQUIRED in a successful Explicit
    /// Registration Response per §12.2.3.
    /// </summary>
    public required Uri AuthorityHint { get; init; }

    /// <summary>
    /// The optional <c>jwks</c> claim. OPTIONAL for a registration response
    /// per §3.1.5; supplied when the OP echoes keys (e.g. the RP's federation
    /// keys it bound the registration to).
    /// </summary>
    public IReadOnlyDictionary<string, object>? Jwks { get; init; }

    /// <summary>
    /// Additional top-level claims to merge into the response payload after
    /// the library's structural claims and the dedicated slots above. Keys
    /// that collide with library-emitted structural claims (<c>iss</c>,
    /// <c>sub</c>, <c>aud</c>, <c>iat</c>, <c>exp</c>, <c>metadata</c>,
    /// <c>trust_anchor</c>) are dropped — the library wins.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AdditionalClaims { get; init; }
}
