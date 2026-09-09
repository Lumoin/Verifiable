using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Evaluates whether an X.509 certificate chain is a member of one or more held ETSI Trusted Lists, per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.2">OID4VP 1.0
/// §6.1.1.2</see>: "The trust chain of a matching Credential MUST contain at least one X.509 Certificate that
/// matches one of the entries of the Trusted List or its cascading Trusted Lists."
/// </summary>
/// <remarks>
/// Pure and synchronous: it walks only the <see cref="TrustedList"/> object graphs the caller already holds
/// (parsed and signature-verified through <see cref="ParseTrustedListDelegate"/> /
/// <see cref="VerifyTrustedListSignatureDelegate"/>) and never fetches — the structural reading of OID4VP 1.0
/// §15.10's "Wallets SHOULD NOT access URLs included in a request from the Verifier ... treated purely as
/// identifiers and not actually retrieved by the Wallet upon receiving the request."
/// </remarks>
public static class TrustedListMembership
{
    /// <summary>
    /// Computes the set of Trusted List identifiers <paramref name="chain"/> is a member of, considering
    /// cascading pointers among <paramref name="heldLists"/>.
    /// </summary>
    /// <param name="chain">The credential's certificate chain to test, in any order.</param>
    /// <param name="heldLists">Every Trusted List the wallet holds — the walk considers cascading pointers only among these.</param>
    /// <param name="readSubjectKeyIdentifier">Reads a chain certificate's SubjectKeyIdentifier (RFC 5280 §4.2.1.2), for matching an <see cref="X509SubjectKeyIdentifierIdentity"/> entry.</param>
    /// <param name="readSubjectName">Reads a chain certificate's Subject as an RFC 4514 string, for matching an <see cref="X509SubjectNameIdentity"/> entry.</param>
    /// <returns>
    /// The identifiers (each list's own <see cref="TrustedListSchemeInformation.DistributionPoints"/>, parsed)
    /// of every held list whose service digital identities match a chain certificate, plus every held list that
    /// points — directly or transitively, through other held lists only — to one of those matching lists.
    /// Empty when no held list matches.
    /// </returns>
    public static IReadOnlySet<TrustedListIdentifier> Evaluate(
        IReadOnlyList<PkiCertificateMemory> chain,
        IReadOnlyList<TrustedList> heldLists,
        ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier,
        ReadCertificateSubjectNameDelegate readSubjectName)
    {
        ArgumentNullException.ThrowIfNull(chain);
        ArgumentNullException.ThrowIfNull(heldLists);
        ArgumentNullException.ThrowIfNull(readSubjectKeyIdentifier);
        ArgumentNullException.ThrowIfNull(readSubjectName);

        Dictionary<TrustedList, HashSet<TrustedListIdentifier>> identifiersByList = [];
        foreach(TrustedList list in heldLists)
        {
            identifiersByList[list] = ListIdentifiers(list);
        }

        Dictionary<TrustedList, List<TrustedList>> predecessorsByList = BuildPointerPredecessors(heldLists, identifiersByList);

        HashSet<TrustedListIdentifier> result = [];
        HashSet<TrustedList> visited = [];
        Queue<TrustedList> pending = new();
        foreach(TrustedList list in heldLists)
        {
            if(ListMatchesChain(list, chain, readSubjectKeyIdentifier, readSubjectName))
            {
                pending.Enqueue(list);
            }
        }

        while(pending.TryDequeue(out TrustedList? current))
        {
            if(!visited.Add(current))
            {
                continue;
            }

            result.UnionWith(identifiersByList[current]);
            if(predecessorsByList.TryGetValue(current, out List<TrustedList>? predecessors))
            {
                foreach(TrustedList predecessor in predecessors)
                {
                    pending.Enqueue(predecessor);
                }
            }
        }

        return result;
    }


    /// <summary>
    /// Parses a list's own identity — its <see cref="TrustedListSchemeInformation.DistributionPoints"/> — as
    /// <see cref="TrustedListIdentifier"/> values, silently skipping any distribution point that does not
    /// parse as one.
    /// </summary>
    /// <param name="list">The list to read.</param>
    /// <returns>The list's parseable distribution-point identifiers.</returns>
    private static HashSet<TrustedListIdentifier> ListIdentifiers(TrustedList list)
    {
        HashSet<TrustedListIdentifier> identifiers = [];
        foreach(string distributionPoint in list.SchemeInformation.DistributionPoints)
        {
            if(TrustedListIdentifier.TryCreate(distributionPoint, out TrustedListIdentifier identifier))
            {
                _ = identifiers.Add(identifier);
            }
        }

        return identifiers;
    }


    /// <summary>
    /// Builds the reverse-pointer index over <paramref name="heldLists"/>: for every pointer of a held list
    /// whose <see cref="OtherTrustedListPointer.TslLocation"/> is among another held list's identifiers, the
    /// pointed-to list's predecessor set gains the pointing list. A pointer to a target the caller does not
    /// hold contributes no edge — cascading follows held lists only.
    /// </summary>
    /// <param name="heldLists">Every Trusted List the wallet holds.</param>
    /// <param name="identifiersByList">Each held list's own parsed identifiers, from <see cref="ListIdentifiers(TrustedList)"/>.</param>
    /// <returns>A map from a held list to the held lists whose pointers name one of its identifiers.</returns>
    private static Dictionary<TrustedList, List<TrustedList>> BuildPointerPredecessors(
        IReadOnlyList<TrustedList> heldLists,
        Dictionary<TrustedList, HashSet<TrustedListIdentifier>> identifiersByList)
    {
        Dictionary<TrustedList, List<TrustedList>> predecessorsByList = [];
        foreach(TrustedList pointingList in heldLists)
        {
            foreach(OtherTrustedListPointer pointer in pointingList.SchemeInformation.PointersToOtherTrustedLists)
            {
                if(!TrustedListIdentifier.TryCreate(pointer.TslLocation.AbsoluteUri, out TrustedListIdentifier pointerIdentifier))
                {
                    continue;
                }

                foreach(TrustedList targetList in heldLists)
                {
                    if(!identifiersByList[targetList].Contains(pointerIdentifier))
                    {
                        continue;
                    }

                    if(!predecessorsByList.TryGetValue(targetList, out List<TrustedList>? predecessors))
                    {
                        predecessors = [];
                        predecessorsByList[targetList] = predecessors;
                    }

                    predecessors.Add(pointingList);
                }
            }
        }

        return predecessorsByList;
    }


    /// <summary>
    /// Reports whether any Trust Service Provider of <paramref name="list"/> operates a service whose current
    /// or historical digital identity recognises a certificate in <paramref name="chain"/>.
    /// </summary>
    /// <param name="list">The list to test.</param>
    /// <param name="chain">The certificate chain to test against.</param>
    /// <param name="readSubjectKeyIdentifier">Reads a chain certificate's SubjectKeyIdentifier.</param>
    /// <param name="readSubjectName">Reads a chain certificate's RFC 4514 Subject string.</param>
    /// <returns><see langword="true"/> when a service or history entry of <paramref name="list"/> matches; otherwise <see langword="false"/>.</returns>
    private static bool ListMatchesChain(
        TrustedList list,
        IReadOnlyList<PkiCertificateMemory> chain,
        ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier,
        ReadCertificateSubjectNameDelegate readSubjectName)
    {
        return list.TrustServiceProviders.Any(provider => provider.Services.Any(
            service => ServiceMatchesChain(service, chain, readSubjectKeyIdentifier, readSubjectName)));
    }


    /// <summary>
    /// Reports whether <paramref name="service"/>'s current digital identity, or that of any of its
    /// <see cref="TrustService.History"/> entries, matches a certificate in <paramref name="chain"/> — history
    /// counts for identification (the DCQL <c>etsi_tl</c> type only identifies the framework), never
    /// qualification.
    /// </summary>
    /// <param name="service">The service to test.</param>
    /// <param name="chain">The certificate chain to test against.</param>
    /// <param name="readSubjectKeyIdentifier">Reads a chain certificate's SubjectKeyIdentifier.</param>
    /// <param name="readSubjectName">Reads a chain certificate's RFC 4514 Subject string.</param>
    /// <returns><see langword="true"/> when the current or a historical digital identity matches; otherwise <see langword="false"/>.</returns>
    private static bool ServiceMatchesChain(
        TrustService service,
        IReadOnlyList<PkiCertificateMemory> chain,
        ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier,
        ReadCertificateSubjectNameDelegate readSubjectName)
    {
        return DigitalIdentityMatchesChain(service.DigitalIdentity, chain, readSubjectKeyIdentifier, readSubjectName)
            || service.History.Any(history => DigitalIdentityMatchesChain(history.DigitalIdentity, chain, readSubjectKeyIdentifier, readSubjectName));
    }


    /// <summary>
    /// Reports whether any entry of <paramref name="digitalIdentity"/> matches a certificate in
    /// <paramref name="chain"/>.
    /// </summary>
    /// <param name="digitalIdentity">The digital identity to test.</param>
    /// <param name="chain">The certificate chain to test against.</param>
    /// <param name="readSubjectKeyIdentifier">Reads a chain certificate's SubjectKeyIdentifier.</param>
    /// <param name="readSubjectName">Reads a chain certificate's RFC 4514 Subject string.</param>
    /// <returns><see langword="true"/> when any entry matches; otherwise <see langword="false"/>.</returns>
    private static bool DigitalIdentityMatchesChain(
        ServiceDigitalIdentity digitalIdentity,
        IReadOnlyList<PkiCertificateMemory> chain,
        ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier,
        ReadCertificateSubjectNameDelegate readSubjectName)
    {
        return digitalIdentity.Entries.Any(entry => EntryMatchesChain(entry, chain, readSubjectKeyIdentifier, readSubjectName));
    }


    /// <summary>
    /// Reports whether <paramref name="entry"/> matches a certificate in <paramref name="chain"/>, per ETSI TS
    /// 119 612 clause 5.5.3: an <see cref="X509CertificateIdentity"/> by DER equality
    /// (<see cref="PkiCertificateMemory.Equals(PkiCertificateMemory)"/>), an
    /// <see cref="X509SubjectKeyIdentifierIdentity"/> by its decoded bytes against
    /// <paramref name="readSubjectKeyIdentifier"/>'s result, an <see cref="X509SubjectNameIdentity"/> by
    /// ordinal equality of its text against <paramref name="readSubjectName"/>'s result, and an
    /// <see cref="OtherDigitalIdentity"/> never.
    /// </summary>
    /// <param name="entry">The digital identity entry to test.</param>
    /// <param name="chain">The certificate chain to test against.</param>
    /// <param name="readSubjectKeyIdentifier">Reads a chain certificate's SubjectKeyIdentifier.</param>
    /// <param name="readSubjectName">Reads a chain certificate's RFC 4514 Subject string.</param>
    /// <returns><see langword="true"/> when <paramref name="entry"/> matches; otherwise <see langword="false"/>.</returns>
    private static bool EntryMatchesChain(
        ServiceDigitalIdentityEntry entry,
        IReadOnlyList<PkiCertificateMemory> chain,
        ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier,
        ReadCertificateSubjectNameDelegate readSubjectName) => entry switch
        {
            X509CertificateIdentity certificateIdentity => chain.Any(certificate => certificate.Equals(certificateIdentity.Certificate)),
            X509SubjectKeyIdentifierIdentity subjectKeyIdentifierIdentity => MatchesSubjectKeyIdentifier(subjectKeyIdentifierIdentity, chain, readSubjectKeyIdentifier),
            X509SubjectNameIdentity subjectNameIdentity => chain.Any(certificate => string.Equals(readSubjectName(certificate), subjectNameIdentity.SubjectName, StringComparison.Ordinal)),
            OtherDigitalIdentity => false,
            _ => false
        };


    /// <summary>
    /// Decodes <paramref name="entry"/>'s standard-base64 <see cref="X509SubjectKeyIdentifierIdentity.SubjectKeyIdentifierBase64"/>
    /// (ETSI TS 119 612 clause 5.5.3's <c>base64Binary</c> encoding — distinct from base64url) and compares the
    /// decoded bytes against every certificate in <paramref name="chain"/>'s SubjectKeyIdentifier.
    /// </summary>
    /// <param name="entry">The entry to decode and match.</param>
    /// <param name="chain">The certificate chain to test against.</param>
    /// <param name="readSubjectKeyIdentifier">Reads a chain certificate's SubjectKeyIdentifier.</param>
    /// <returns><see langword="true"/> when the decoded bytes equal a chain certificate's SubjectKeyIdentifier; otherwise <see langword="false"/>.</returns>
    private static bool MatchesSubjectKeyIdentifier(
        X509SubjectKeyIdentifierIdentity entry,
        IReadOnlyList<PkiCertificateMemory> chain,
        ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier)
    {
        string base64 = entry.SubjectKeyIdentifierBase64;
        int maxDecodedLength = ((base64.Length + 3) / 4) * 3;
        byte[] rented = ArrayPool<byte>.Shared.Rent(maxDecodedLength);
        try
        {
            if(!Convert.TryFromBase64String(base64, rented, out int bytesWritten))
            {
                return false;
            }

            ReadOnlySpan<byte> decoded = rented.AsSpan(0, bytesWritten);
            foreach(PkiCertificateMemory certificate in chain)
            {
                if(readSubjectKeyIdentifier(certificate).Span.SequenceEqual(decoded))
                {
                    return true;
                }
            }

            return false;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented);
        }
    }
}
