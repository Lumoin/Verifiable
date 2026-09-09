namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Reads the trust evidence a held credential already carries, for <see cref="TrustedAuthoritiesQuery"/>
/// matching. Synchronous: the evidence is data the wallet resolved and cached ahead of query
/// evaluation (certificate chain AuthorityKeyIdentifiers, held Trusted List memberships, validated
/// OpenID Federation trust paths) — per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">
/// OpenID for Verifiable Presentations 1.0, Section 15.10</see>, no fetch ever runs at query-evaluation
/// time.
/// </summary>
/// <typeparam name="TCredential">The credential type.</typeparam>
/// <param name="credential">The credential whose evidence is read.</param>
/// <returns>The credential's <see cref="TrustedAuthorityEvidence"/>, or <see langword="null"/> when the format or wiring surfaces none.</returns>
public delegate TrustedAuthorityEvidence? TrustedAuthorityEvidenceSource<TCredential>(TCredential credential);
