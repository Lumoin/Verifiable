using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Federation;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.OAuth.Federation;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Composes a <see cref="ResolveTrustedAuthorityEvidenceDelegate"/> over the shipped X.509, ETSI
/// Trusted List and OpenID Federation primitives, per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">
/// OpenID for Verifiable Presentations 1.0, Section 6.1.1</see>: the <c>aki</c> arm
/// (<see cref="X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers"/>), the <c>etsi_tl</c>
/// arm (<see cref="TrustedListMembership.Evaluate"/>) and, when the caller supplies one, the
/// <c>openid_federation</c> arm.
/// </summary>
public static class TrustedAuthorityEvidenceResolution
{
    /// <summary>
    /// Builds a <see cref="ResolveTrustedAuthorityEvidenceDelegate"/> that runs every supplied
    /// arm over its inputs and unions the result into one <see cref="TrustedAuthorityEvidence"/>.
    /// </summary>
    /// <param name="extractAuthorityKeyIdentifier">Reads one certificate's AuthorityKeyIdentifier — the <c>aki</c> arm's backend primitive.</param>
    /// <param name="readSubjectKeyIdentifier">Reads one certificate's SubjectKeyIdentifier — one <c>etsi_tl</c> entry-matching primitive.</param>
    /// <param name="readSubjectName">Renders one certificate's Subject as an RFC 4514 string — the other <c>etsi_tl</c> entry-matching primitive.</param>
    /// <param name="heldTrustedLists">Every ETSI Trusted List the wallet holds; the <c>etsi_tl</c> arm walks cascades among these only.</param>
    /// <param name="resolveFederationTrustPath">
    /// Optional <c>openid_federation</c> arm: resolves an issuer <see cref="EntityIdentifier"/> to the
    /// Entity Identifiers on its validated trust paths, per
    /// <see cref="FederationTrustPathEvidence.ResolveAsync"/>. <see langword="null"/> surfaces no
    /// federation evidence — the returned delegate's <paramref name="resolveFederationTrustPath"/>
    /// argument is skipped whenever the issuer identifier does not parse as an
    /// <see cref="EntityIdentifier"/> or this parameter is <see langword="null"/>.
    /// </param>
    /// <returns>
    /// A delegate returning the union of every arm's evidence, or <see langword="null"/> when the
    /// chain and issuer identifier together yield none.
    /// </returns>
    public static ResolveTrustedAuthorityEvidenceDelegate Build(
        ExtractAuthorityKeyIdentifierDelegate extractAuthorityKeyIdentifier,
        ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier,
        ReadCertificateSubjectNameDelegate readSubjectName,
        IReadOnlyList<TrustedList> heldTrustedLists,
        Func<EntityIdentifier, CancellationToken, ValueTask<IReadOnlySet<EntityIdentifier>>>? resolveFederationTrustPath)
    {
        ArgumentNullException.ThrowIfNull(extractAuthorityKeyIdentifier);
        ArgumentNullException.ThrowIfNull(readSubjectKeyIdentifier);
        ArgumentNullException.ThrowIfNull(readSubjectName);
        ArgumentNullException.ThrowIfNull(heldTrustedLists);

        return async (chain, issuerIdentifier, pool, cancellationToken) =>
        {
            ArgumentNullException.ThrowIfNull(chain);
            ArgumentNullException.ThrowIfNull(pool);

            IReadOnlySet<AuthorityKeyIdentifier> authorityKeyIdentifiers =
                X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers(chain, extractAuthorityKeyIdentifier);

            IReadOnlySet<TrustedListIdentifier> trustedListMemberships = TrustedListMembership.Evaluate(
                chain, heldTrustedLists, readSubjectKeyIdentifier, readSubjectName);

            IReadOnlySet<EntityIdentifier> federationTrustPathEntities = FrozenEmptyEntityIdentifiers;
            if(resolveFederationTrustPath is not null
                && EntityIdentifier.TryCreate(issuerIdentifier, out EntityIdentifier issuer))
            {
                federationTrustPathEntities = await resolveFederationTrustPath(issuer, cancellationToken)
                    .ConfigureAwait(false);
            }

            TrustedAuthorityEvidence evidence = new()
            {
                AuthorityKeyIdentifiers = authorityKeyIdentifiers,
                TrustedListMemberships = trustedListMemberships,
                FederationTrustPathEntities = federationTrustPathEntities
            };

            return evidence.IsEmpty ? null : evidence;
        };
    }


    /// <summary>The shared empty default when the <c>openid_federation</c> arm did not run.</summary>
    private static IReadOnlySet<EntityIdentifier> FrozenEmptyEntityIdentifiers { get; } = FrozenSet<EntityIdentifier>.Empty;
}
