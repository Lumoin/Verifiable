using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography.Pki;
using BouncyCastleX509 = Org.BouncyCastle.X509.X509Certificate;

namespace Verifiable.BouncyCastle;

/// <summary>
/// An offline <see cref="CheckCertificateRevocationStatusAsyncDelegate"/> over a supplied set of Certificate
/// Revocation Lists (RFC 5280 §5). It answers a certificate's revocation status purely from the CRLs it was given —
/// it makes no network call — which is how eMRTD revocation actually works: the ICAO Public Key Directory and CSCA
/// Master List distribute CRLs that an inspection system pre-fetches and checks against, rather than making an OCSP
/// round-trip per document.
/// </summary>
/// <remarks>
/// <para>
/// This is the "revocation source" a caller configures and passes as the <c>checkRevocation</c> parameter of
/// <see cref="ValidateCertificateChainAsyncDelegate"/> (directly, or through a higher-level verifier such as eMRTD
/// Passive Authentication). Because it is a configured object holding the CRL set, the caller supplies its data
/// explicitly at construction rather than a closure capturing it.
/// </para>
/// <para>
/// A CRL is treated as authoritative only when, per RFC 5280 §6.3.3, it is issued by the certificate's issuer
/// (matching distinguished name), is signature-verified by a trusted issuer candidate that is authorised to sign
/// CRLs (the <c>cRLSign</c> key usage, when a Key Usage is asserted), and is within a defined validity window — a
/// not-yet-valid or stale CRL, and by default a CRL that omits <c>nextUpdate</c>, are all ignored. The result is
/// fail-closed: <see cref="CertificateRevocationStatus.Revoked"/> if any authoritative CRL lists the certificate's
/// serial, <see cref="CertificateRevocationStatus.Good"/> if at least one authoritative CRL covered the issuer and
/// none listed it, and <see cref="CertificateRevocationStatus.Unknown"/> when no authoritative CRL is available — so
/// a missing, stale, unverifiable, or malformed CRL denies rather than grants trust. Only the direct-CRL model (a
/// CRL signed by the certificate's own issuer) is handled; RFC 5280 indirect CRLs signed by a separate CRL issuer
/// are out of scope.
/// </para>
/// <para>
/// The checker answers only from the CRLs it is given: within that set a revocation is decisive (a revoking CRL is
/// never masked by a clean one), but it cannot detect a revocation published in a CRL that is absent from the set,
/// so keeping the CRL set current is the caller's responsibility. The checker holds a reference to the supplied
/// CRLs; it does not take ownership of them, so the caller keeps and disposes them and constructs a new checker when
/// the cache is refreshed.
/// </para>
/// </remarks>
public sealed class CrlRevocationChecker
{
    /// <summary>The BouncyCastle CRL parser (stateless for the byte-array read used here).</summary>
    private static X509CrlParser CrlParser { get; } = new();

    /// <summary>The BouncyCastle certificate parser (stateless for the byte-array read used here).</summary>
    private static X509CertificateParser CertificateParser { get; } = new();

    /// <summary>The supplied Certificate Revocation Lists, referenced but not owned.</summary>
    private IReadOnlyList<PkiCertificateMemory> CertificateRevocationLists { get; }

    /// <summary>Whether a CRL that omits <c>nextUpdate</c> is accepted as authoritative; secure default is <see langword="false"/>.</summary>
    private bool AllowCrlsWithoutNextUpdate { get; }


    /// <summary>
    /// Initialises a new <see cref="CrlRevocationChecker"/> over a supplied set of CRLs.
    /// </summary>
    /// <param name="certificateRevocationLists">
    /// The CRLs to check against, each a DER-encoded CRL carried as a <see cref="PkiCertificateMemory"/> tagged
    /// <see cref="PkiCertificateTags.X509Crl"/>. Referenced, not owned: the caller keeps ownership and disposes them.
    /// </param>
    /// <param name="allowCrlsWithoutNextUpdate">
    /// Whether a CRL that omits the optional <c>nextUpdate</c> field (RFC 5280 §5.1.2.5) is treated as authoritative.
    /// Defaults to <see langword="false"/>: such a CRL has no freshness bound and could mask a later revocation
    /// indefinitely, so the secure default treats it as non-authoritative. A deployment whose CA legitimately issues
    /// CRLs without <c>nextUpdate</c> and accepts that weaker assurance sets this to <see langword="true"/>.
    /// </param>
    public CrlRevocationChecker(IReadOnlyList<PkiCertificateMemory> certificateRevocationLists, bool allowCrlsWithoutNextUpdate = false)
    {
        ArgumentNullException.ThrowIfNull(certificateRevocationLists);

        CertificateRevocationLists = certificateRevocationLists;
        AllowCrlsWithoutNextUpdate = allowCrlsWithoutNextUpdate;
    }


    /// <summary>
    /// Implements <see cref="CheckCertificateRevocationStatusAsyncDelegate"/>. Reports <paramref name="certificate"/>'s
    /// revocation status from the configured CRLs, fail-closed. Completes synchronously — no network call is made.
    /// </summary>
    /// <param name="certificate">The certificate whose revocation status is being determined.</param>
    /// <param name="issuerCandidates">The certificates that may be the CRL's issuer (for eMRTD, the CSCA trust anchors).</param>
    /// <param name="validationTime">The UTC time at which the CRL validity window is evaluated.</param>
    /// <param name="pool">Unused; present to satisfy the delegate contract.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The certificate's <see cref="CertificateRevocationStatus"/>.</returns>
    public ValueTask<CertificateRevocationStatus> CheckAsync(
        PkiCertificateMemory certificate,
        IReadOnlyList<PkiCertificateMemory> issuerCandidates,
        DateTimeOffset validationTime,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuerCandidates);
        cancellationToken.ThrowIfCancellationRequested();

        BouncyCastleX509 target = CertificateParser.ReadCertificate(certificate.AsReadOnlyMemory().ToArray());
        DateTime instant = validationTime.UtcDateTime;

        bool foundAuthoritativeCrl = false;
        foreach(PkiCertificateMemory crlMemory in CertificateRevocationLists)
        {
            X509Crl? crl;
            try
            {
                crl = CrlParser.ReadCrl(crlMemory.AsReadOnlyMemory().ToArray());
            }
            catch(CrlException)
            {
                //A malformed CRL in the set is skipped rather than aborting the scan, so one bad entry can neither
                //deny-of-service the whole revocation check nor hide a valid revoking CRL behind it in the list.
                continue;
            }

            //RFC 5280 §5.1.2.3: the CRL must be issued by the certificate's issuer.
            if(crl is null || !crl.IssuerDN.Equivalent(target.IssuerDN))
            {
                continue;
            }

            //RFC 5280 §6.3.3(f): the CRL's signature must verify under a trusted issuer's key that is authorised to
            //sign CRLs — an unverifiable or unauthorised CRL is not authoritative and carries no weight.
            if(!IsSignedByAnyCandidate(crl, issuerCandidates))
            {
                continue;
            }

            //RFC 5280 §5.1.2.4/§5.1.2.5: a CRL is authoritative only within its validity window. A not-yet-valid CRL
            //is ignored; a stale one (past nextUpdate) is ignored; and a CRL that omits nextUpdate has no freshness
            //bound and could mask a later revocation indefinitely, so it is non-authoritative unless the deployment
            //has opted in.
            if(crl.ThisUpdate > instant)
            {
                continue;
            }

            if(crl.NextUpdate is { } nextUpdate)
            {
                if(nextUpdate < instant)
                {
                    continue;
                }
            }
            else if(!AllowCrlsWithoutNextUpdate)
            {
                continue;
            }

            foundAuthoritativeCrl = true;

            //A revocation in any authoritative CRL is decisive: a later CRL that lists the serial wins over an
            //earlier one that does not, so the checker fails closed toward Revoked.
            if(crl.GetRevokedCertificate(target.SerialNumber) is not null)
            {
                return ValueTask.FromResult(CertificateRevocationStatus.Revoked);
            }
        }

        //Good requires an authoritative CRL that covered the issuer and did not list the certificate; with no
        //authoritative CRL the status cannot be determined and a fail-closed policy treats Unknown as fatal.
        return ValueTask.FromResult(foundAuthoritativeCrl
            ? CertificateRevocationStatus.Good
            : CertificateRevocationStatus.Unknown);
    }


    /// <summary>
    /// Reports whether <paramref name="crl"/> is signed by any of the <paramref name="issuerCandidates"/> whose
    /// subject matches the CRL issuer — i.e. whether a trusted key authenticates the CRL.
    /// </summary>
    private static bool IsSignedByAnyCandidate(X509Crl crl, IReadOnlyList<PkiCertificateMemory> issuerCandidates)
    {
        foreach(PkiCertificateMemory candidate in issuerCandidates)
        {
            BouncyCastleX509 issuer = CertificateParser.ReadCertificate(candidate.AsReadOnlyMemory().ToArray());
            if(!issuer.SubjectDN.Equivalent(crl.IssuerDN))
            {
                continue;
            }

            //RFC 5280 §6.3.3(f): the key that validates a CRL must be authorised to sign CRLs. A candidate that
            //asserts a Key Usage without the cRLSign bit (index 6) is not authorised; one with no Key Usage extension
            //is unrestricted. GetKeyUsage may omit trailing zero bits, so the length is guarded before indexing.
            bool[]? keyUsage = issuer.GetKeyUsage();
            if(keyUsage is not null && (keyUsage.Length <= 6 || !keyUsage[6]))
            {
                continue;
            }

            try
            {
                crl.Verify(issuer.GetPublicKey());

                return true;
            }
            catch(GeneralSecurityException)
            {
                //This candidate's key does not authenticate the CRL (wrong key or bad signature); keep looking.
            }
        }

        return false;
    }
}
