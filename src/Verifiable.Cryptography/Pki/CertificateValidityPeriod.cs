using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// A certificate's own validity period — the <c>notBefore</c>/<c>notAfter</c> instants of
/// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5">RFC 5280 §4.1.2.5</see> — read straight
/// off its DER encoding.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The requirement this exists for.</strong> This is the whole of what
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> clause 6.3 additional requirement (d) — "the electronic time-stamp
/// encapsulated within <c>sigTst</c> shall be created before the signing certificate has been revoked or has
/// expired" (CB-6.3-d) — needs to know about the certificate itself: a time-stamp token's generation time is
/// compared against <see cref="NotBefore"/>/<see cref="NotAfter"/> for the "has expired" half. The "has been
/// revoked" half is a separate fact a revocation source states, not this record.
/// </para>
/// <para>
/// <strong>Reading never throws on what a signer's certificate happens to be.</strong> A signing certificate
/// arrives embedded in or referenced by a signature under validation, so it is attacker-reachable exactly as
/// every other certificate this library reads is: malformed DER answers <see langword="false"/> from
/// <see cref="TryRead"/> rather than an escaping <see cref="AsnContentException"/>, the same "state the fact,
/// never throw on hostile bytes" contract <see cref="EArkEvidenceSelfDescription"/>'s <c>TryDecodeValue</c>
/// keeps.
/// </para>
/// <para>
/// <strong>Reuse, not a fourth certificate walk.</strong> <see cref="TryRead"/> composes the internal
/// <see cref="ManagedCertificate.Parse"/> the managed CMS and OCSP verifiers already share, rather than
/// re-implementing the <c>Certificate</c>/<c>Validity</c> walk <see cref="QualifiedCertificateFactsExtractor"/>
/// and <see cref="RevocationSourceFactsExtractor"/> each carry their own copy of. No wider certificate surface
/// is exposed here than the two fields this reader states — <see cref="ManagedCertificate"/> itself stays
/// internal.
/// </para>
/// </remarks>
[DebuggerDisplay("CertificateValidityPeriod: {NotBefore} to {NotAfter}")]
public sealed record CertificateValidityPeriod
{
    /// <summary>
    /// Gets the certificate's <c>notBefore</c> validity instant
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5">RFC 5280 §4.1.2.5</see>) — the
    /// lower bound CB-6.3-d's window comparison checks a time-stamp token's generation time against.
    /// </summary>
    public required DateTimeOffset NotBefore { get; init; }

    /// <summary>
    /// Gets the certificate's <c>notAfter</c> validity instant
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5">RFC 5280 §4.1.2.5</see>) — the
    /// upper bound CB-6.3-d's window comparison checks a time-stamp token's generation time against.
    /// </summary>
    public required DateTimeOffset NotAfter { get; init; }


    /// <summary>
    /// Reads the validity period straight off a DER-encoded X.509 certificate.
    /// </summary>
    /// <param name="certificate">The certificate to read. The caller retains ownership.</param>
    /// <param name="validityPeriod">The read validity period, or <see langword="null"/> when the bytes do not parse as a certificate.</param>
    /// <returns><see langword="true"/> when the certificate's <c>notBefore</c>/<c>notAfter</c> were read.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="certificate"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">
    /// When <paramref name="certificate"/> does not carry an X.509 certificate — a caller composition error
    /// (the wrong <see cref="PkiObjectKind"/> was supplied), not an attacker-controlled shape, so it throws
    /// rather than answering <see langword="false"/>.
    /// </exception>
    public static bool TryRead(PkiCertificateMemory certificate, [NotNullWhen(true)] out CertificateValidityPeriod? validityPeriod)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if(!certificate.IsX509Certificate)
        {
            throw new ArgumentException("The carrier must hold an X.509 certificate.", nameof(certificate));
        }

        try
        {
            ManagedCertificate parsed = ManagedCertificate.Parse(certificate.AsReadOnlyMemory());
            validityPeriod = new CertificateValidityPeriod { NotBefore = parsed.NotBefore, NotAfter = parsed.NotAfter };

            return true;
        }
        catch(AsnContentException)
        {
            //A signing certificate is attacker-reachable; malformed DER is a fact about the input, never an
            //escaping exception (R-5's fail-closed parsing rule).
            validityPeriod = null;

            return false;
        }
    }
}
