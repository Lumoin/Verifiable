using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Pki;
using BouncyCastleX509 = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.BouncyCastle;

/// <summary>
/// An offline <see cref="CompleteCertificateChainAsyncDelegate"/> over a supplied set of CA certificates. It
/// completes a partial chain purely from the certificates it was given — it makes no network call and fetches no
/// Authority Information Access URL — the same offline posture <see cref="CrlRevocationChecker"/> takes for
/// revocation: the library ships the capability, not the fetcher.
/// </summary>
/// <remarks>
/// <para>
/// This is the "chain completion source" a caller configures and passes as the <c>completeChain</c> parameter of
/// <c>PackedAttestation.Build</c> (directly, or through a higher-level verifier). Because it is a configured
/// object holding the CA store, the caller supplies its data explicitly at construction rather than a closure
/// capturing it.
/// </para>
/// <para>
/// A store certificate is accepted as the issuer of the chain's current last certificate when its Subject
/// distinguished name matches the last certificate's Issuer distinguished name
/// (<see href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.4">RFC 5280 section 4.1.2.4</see>) and,
/// when both certificates carry the relevant extension, the store certificate's Subject Key Identifier
/// (<see href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2">RFC 5280 section 4.2.1.2</see>)
/// matches the last certificate's Authority Key Identifier
/// (<see href="https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1">RFC 5280 section 4.2.1.1</see>) —
/// the same ambiguous-issuer-safe matching a real path builder applies when several store certificates share a
/// subject name but hold different keys.
/// </para>
/// <para>
/// The completer walks the store repeatedly, appending one certificate per hop, until the chain reaches (or a
/// certificate in it already is) one of the supplied trust anchors, or the store is exhausted without a match, in
/// which case it throws. Each store certificate is used at most once per call, so the walk always terminates. The
/// completer holds a reference to the supplied store; it does not take ownership of it, so the caller keeps and
/// disposes it and constructs a new completer when the store is refreshed. Every certificate this instance
/// appends to a chain is an independent copy rented from the caller-supplied pool, not the store certificate
/// itself, so the returned "acquired" certificates are safe for the caller of <see cref="CompleteAsync"/> to
/// dispose without disturbing the store.
/// </para>
/// </remarks>
[DebuggerDisplay("CertificateChainCompleter(Store={CaCertificates.Count})")]
public sealed class CertificateChainCompleter
{
    /// <summary>The BouncyCastle certificate parser (stateless for the byte-array read used here).</summary>
    private static X509CertificateParser CertificateParser { get; } = new();

    /// <summary>The offline CA certificate store, referenced but not owned.</summary>
    private IReadOnlyList<PkiCertificateMemory> CaCertificates { get; }


    /// <summary>
    /// Initialises a new <see cref="CertificateChainCompleter"/> over a supplied set of CA certificates.
    /// </summary>
    /// <param name="caCertificates">
    /// The candidate intermediate CA certificates a partial chain may need, each a DER-encoded certificate carried
    /// as a <see cref="PkiCertificateMemory"/> tagged <see cref="PkiCertificateTags.X509Certificate"/>. Referenced,
    /// not owned: the caller keeps ownership and disposes them.
    /// </param>
    public CertificateChainCompleter(IReadOnlyList<PkiCertificateMemory> caCertificates)
    {
        ArgumentNullException.ThrowIfNull(caCertificates);

        CaCertificates = caCertificates;
    }


    /// <summary>
    /// Implements <see cref="CompleteCertificateChainAsyncDelegate"/>. Completes <paramref name="partialChain"/>
    /// from the configured CA store, fail-closed. Completes synchronously — no network call is made.
    /// </summary>
    /// <param name="partialChain">The certificate chain as supplied on the wire: leaf first, zero or more intermediates following.</param>
    /// <param name="trustAnchors">The trust anchor certificates the completed chain must reach.</param>
    /// <param name="pool">Memory pool for any acquired certificate's byte allocation.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// <paramref name="partialChain"/> unchanged when it already reaches a trust anchor; otherwise
    /// <paramref name="partialChain"/> with the acquired intermediate certificates appended.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="partialChain"/> is empty.</exception>
    /// <exception cref="SecurityException">
    /// Thrown when the CA store cannot complete the chain to any of the supplied trust anchors.
    /// </exception>
    public ValueTask<IReadOnlyList<PkiCertificateMemory>> CompleteAsync(
        IReadOnlyList<PkiCertificateMemory> partialChain,
        IReadOnlyList<PkiCertificateMemory> trustAnchors,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(partialChain);
        ArgumentNullException.ThrowIfNull(trustAnchors);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        if(partialChain.Count == 0)
        {
            throw new ArgumentException(
                "The partial certificate chain must contain at least one certificate.", nameof(partialChain));
        }

        var acquired = new List<PkiCertificateMemory>();
        var usedStoreIndices = new HashSet<int>();
        try
        {
            PkiCertificateMemory current = partialChain[^1];
            while(!ReachesTrustAnchor(current, trustAnchors))
            {
                cancellationToken.ThrowIfCancellationRequested();

                if(FindIssuerIndexInStore(current, usedStoreIndices) is not { } issuerIndex)
                {
                    throw new SecurityException(
                        "The certificate chain could not be completed: the offline CA store holds no certificate " +
                        "that issues the last certificate in the chain, and the chain does not reach a supplied trust anchor.");
                }

                usedStoreIndices.Add(issuerIndex);

                PkiCertificateMemory clonedIssuer = ClonePkiCertificate(CaCertificates[issuerIndex], pool);
                acquired.Add(clonedIssuer);
                current = clonedIssuer;
            }
        }
        catch
        {
            foreach(PkiCertificateMemory clonedCertificate in acquired)
            {
                clonedCertificate.Dispose();
            }

            throw;
        }

        if(acquired.Count == 0)
        {
            return ValueTask.FromResult(partialChain);
        }

        return ValueTask.FromResult<IReadOnlyList<PkiCertificateMemory>>([.. partialChain, .. acquired]);
    }


    /// <summary>
    /// Determines whether <paramref name="certificate"/> already reaches a trust anchor — either because it is
    /// itself byte-equal to one of <paramref name="trustAnchors"/>, or because its issuer matches one of them —
    /// in which case chain completion needs to go no further.
    /// </summary>
    private static bool ReachesTrustAnchor(PkiCertificateMemory certificate, IReadOnlyList<PkiCertificateMemory> trustAnchors)
    {
        if(trustAnchors.Contains(certificate))
        {
            return true;
        }

        BouncyCastleX509 parsedCertificate = CertificateParser.ReadCertificate(certificate.AsReadOnlyMemory().ToArray());
        foreach(PkiCertificateMemory anchor in trustAnchors)
        {
            BouncyCastleX509 parsedAnchor = CertificateParser.ReadCertificate(anchor.AsReadOnlyMemory().ToArray());
            if(IsMatchingIssuer(parsedCertificate, parsedAnchor))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Searches the configured CA store, skipping <paramref name="usedStoreIndices"/>, for a certificate that
    /// issues <paramref name="certificate"/>.
    /// </summary>
    /// <param name="certificate">The certificate to find an issuer for.</param>
    /// <param name="usedStoreIndices">The store indices already consumed earlier in the same completion walk.</param>
    /// <returns>The matching store certificate's index, or <see langword="null"/> when none matches.</returns>
    private int? FindIssuerIndexInStore(PkiCertificateMemory certificate, HashSet<int> usedStoreIndices)
    {
        BouncyCastleX509 parsedCertificate = CertificateParser.ReadCertificate(certificate.AsReadOnlyMemory().ToArray());
        for(int index = 0; index < CaCertificates.Count; index++)
        {
            if(usedStoreIndices.Contains(index))
            {
                continue;
            }

            BouncyCastleX509 candidate = CertificateParser.ReadCertificate(CaCertificates[index].AsReadOnlyMemory().ToArray());
            if(IsMatchingIssuer(parsedCertificate, candidate))
            {
                return index;
            }
        }

        return null;
    }


    /// <summary>
    /// Determines whether <paramref name="candidateIssuer"/> issued <paramref name="subjectCertificate"/>: its
    /// Subject distinguished name matches <paramref name="subjectCertificate"/>'s Issuer distinguished name, and,
    /// when both certificates carry the relevant key identifier extension, the Subject Key Identifier matches the
    /// Authority Key Identifier — disambiguating same-subject-name candidates that hold different keys.
    /// </summary>
    /// <param name="subjectCertificate">The certificate whose issuer is being sought.</param>
    /// <param name="candidateIssuer">The candidate certificate that may be the issuer.</param>
    /// <returns><see langword="true"/> when <paramref name="candidateIssuer"/> matches; otherwise <see langword="false"/>.</returns>
    private static bool IsMatchingIssuer(BouncyCastleX509 subjectCertificate, BouncyCastleX509 candidateIssuer)
    {
        if(!candidateIssuer.SubjectDN.Equivalent(subjectCertificate.IssuerDN))
        {
            return false;
        }

        byte[]? authorityKeyIdentifier = ReadAuthorityKeyIdentifier(subjectCertificate);
        byte[]? subjectKeyIdentifier = ReadSubjectKeyIdentifier(candidateIssuer);
        if(authorityKeyIdentifier is not null && subjectKeyIdentifier is not null)
        {
            return authorityKeyIdentifier.AsSpan().SequenceEqual(subjectKeyIdentifier);
        }

        return true;
    }


    /// <summary>Reads the <c>keyIdentifier</c> of <paramref name="certificate"/>'s Authority Key Identifier extension, if present.</summary>
    private static byte[]? ReadAuthorityKeyIdentifier(BouncyCastleX509 certificate)
    {
        Asn1OctetString? extensionValue = certificate.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
        if(extensionValue is null)
        {
            return null;
        }

        return AuthorityKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(extensionValue)).GetKeyIdentifier();
    }


    /// <summary>Reads the <c>keyIdentifier</c> of <paramref name="certificate"/>'s Subject Key Identifier extension, if present.</summary>
    private static byte[]? ReadSubjectKeyIdentifier(BouncyCastleX509 certificate)
    {
        Asn1OctetString? extensionValue = certificate.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
        if(extensionValue is null)
        {
            return null;
        }

        return SubjectKeyIdentifier.GetInstance(X509ExtensionUtilities.FromExtensionValue(extensionValue)).GetKeyIdentifier();
    }


    /// <summary>Copies <paramref name="source"/>'s DER bytes into a new pooled <see cref="PkiCertificateMemory"/> the caller owns.</summary>
    private static PkiCertificateMemory ClonePkiCertificate(PkiCertificateMemory source, MemoryPool<byte> pool)
    {
        ReadOnlyMemory<byte> sourceBytes = source.AsReadOnlyMemory();
        IMemoryOwner<byte> owner = pool.Rent(sourceBytes.Length);
        sourceBytes.CopyTo(owner.Memory);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }
}
