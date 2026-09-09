using System;
using System.Collections.Generic;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Collects OID4VP 1.0 §6.1.1.1 <c>aki</c> evidence from an X.509 certificate chain.
/// </summary>
public static class X509TrustedAuthorityEvidence
{
    /// <summary>
    /// Reads every certificate in <paramref name="chain"/>'s AuthorityKeyIdentifier, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.1">OID4VP
    /// 1.0 §6.1.1.1</see>'s "the raw byte representation of this element MUST match with the
    /// AuthorityKeyIdentifier element of an X.509 certificate in the certificate chain" — every chain
    /// certificate counts, not only the leaf.
    /// </summary>
    /// <param name="chain">The certificate chain to read, in any order.</param>
    /// <param name="extractAuthorityKeyIdentifier">The backend delegate reading one certificate's AuthorityKeyIdentifier.</param>
    /// <returns>The distinct <see cref="AuthorityKeyIdentifier"/> values present in <paramref name="chain"/>; empty when none carry one.</returns>
    public static IReadOnlySet<AuthorityKeyIdentifier> CollectAuthorityKeyIdentifiers(
        IReadOnlyList<PkiCertificateMemory> chain,
        ExtractAuthorityKeyIdentifierDelegate extractAuthorityKeyIdentifier)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(extractAuthorityKeyIdentifier);

        HashSet<AuthorityKeyIdentifier> identifiers = [];
        foreach(PkiCertificateMemory certificate in chain)
        {
            AuthorityKeyIdentifier? identifier = extractAuthorityKeyIdentifier(certificate);
            if(identifier is { } value)
            {
                _ = identifiers.Add(value);
            }
        }

        return identifiers;
    }
}
