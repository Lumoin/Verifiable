using System.Collections.Frozen;
using System.Collections.Generic;
using System.Diagnostics;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Per-credential trust evidence a <see cref="TrustedAuthoritiesQuery"/> is matched against, per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
/// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: the concrete facts the three
/// registered types compare against a credential — every certificate chain AuthorityKeyIdentifier
/// (<c>aki</c>), every held ETSI Trusted List the chain is a member of (<c>etsi_tl</c>), and every
/// Entity Identifier on a validated OpenID Federation trust path (<c>openid_federation</c>).
/// </summary>
/// <remarks>
/// A sealed carrier of data only — computed ahead of query evaluation from the wallet's own
/// certificate chains, held Trusted Lists and validated federation trust paths, never from a value
/// named in the Verifier's request, per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">
/// Section 15.10</see>'s "Wallets SHOULD NOT access URLs included in a request from the Verifier ...
/// treated purely as identifiers and not actually retrieved by the Wallet upon receiving the
/// request." <see cref="TrustedAuthoritiesQuery.Matches(TrustedAuthorityEvidence)"/> reads this value
/// purely, performing no I/O of its own.
/// </remarks>
[DebuggerDisplay("Aki={AuthorityKeyIdentifiers.Count} EtsiTl={TrustedListMemberships.Count} Federation={FederationTrustPathEntities.Count}")]
public sealed record TrustedAuthorityEvidence
{
    /// <summary>The shared empty <see cref="AuthorityKeyIdentifiers"/> default.</summary>
    private static IReadOnlySet<AuthorityKeyIdentifier> EmptyAuthorityKeyIdentifiers { get; } = FrozenSet<AuthorityKeyIdentifier>.Empty;

    /// <summary>The shared empty <see cref="TrustedListMemberships"/> default.</summary>
    private static IReadOnlySet<TrustedListIdentifier> EmptyTrustedListMemberships { get; } = FrozenSet<TrustedListIdentifier>.Empty;

    /// <summary>The shared empty <see cref="FederationTrustPathEntities"/> default.</summary>
    private static IReadOnlySet<EntityIdentifier> EmptyFederationTrustPathEntities { get; } = FrozenSet<EntityIdentifier>.Empty;

    /// <summary>
    /// An evidence value carrying no fact of any kind — a credential with no certificate chain, no
    /// held-list membership and no validated federation trust path.
    /// </summary>
    public static TrustedAuthorityEvidence Empty { get; } = new();

    /// <summary>
    /// Every <see cref="AuthorityKeyIdentifier"/> present in the credential's certificate chain — the
    /// <c>aki</c> evidence
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">
    /// OID4VP 1.0 §6.1.1.1</see> compares against. Every chain certificate counts, not the leaf alone.
    /// </summary>
    public IReadOnlySet<AuthorityKeyIdentifier> AuthorityKeyIdentifiers { get; init; } = EmptyAuthorityKeyIdentifiers;

    /// <summary>
    /// Every ETSI Trusted List identifier the credential's certificate chain is a member of, cascades
    /// included — the <c>etsi_tl</c> evidence
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">
    /// OID4VP 1.0 §6.1.1.2</see> compares against.
    /// </summary>
    public IReadOnlySet<TrustedListIdentifier> TrustedListMemberships { get; init; } = EmptyTrustedListMemberships;

    /// <summary>
    /// Every statement subject's Entity Identifier on a validated OpenID Federation trust chain from
    /// the credential's issuer to a familiar trust anchor — the <c>openid_federation</c> evidence
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">
    /// OID4VP 1.0 §6.1.1.3</see> compares against.
    /// </summary>
    public IReadOnlySet<EntityIdentifier> FederationTrustPathEntities { get; init; } = EmptyFederationTrustPathEntities;

    /// <summary>Whether this evidence carries no fact of any kind.</summary>
    public bool IsEmpty =>
        AuthorityKeyIdentifiers.Count == 0
        && TrustedListMemberships.Count == 0
        && FederationTrustPathEntities.Count == 0;
}
