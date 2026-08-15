using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Whether a CMS SignedData's embedded material (its certificates, its CRLs, and which certificate is the
/// signer's own) could be read from the structure's own bytes, and if not, why.
/// </summary>
/// <remarks>
/// <see cref="NotRead"/> occupies zero so a default-initialised status never reads as a successful parse —
/// the same convention <see cref="TimestampTokenInfoStatus"/> uses.
/// </remarks>
public enum CmsEmbeddedMaterialStatus
{
    /// <summary>No parse has been attempted. The value of an unset field, by design.</summary>
    NotRead = 0,

    /// <summary>The structure was well-formed <c>id-signedData</c> DER.</summary>
    Read = 1,

    /// <summary>The bytes were not a well-formed BER <c>SignedData</c>, or named a different content type.</summary>
    Malformed = 2
}


/// <summary>
/// The certificates and Certificate Revocation Lists a CMS SignedData structure carries in its own optional
/// <c>certificates</c> and <c>crls</c> fields
/// (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.1">IETF RFC 5652 §5.1</see>), read directly
/// from the structure's own BER encoding (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5">RFC 5652
/// §5</see> — CMS is BER; DER is a stricter subset a verifying backend may legitimately accept without this
/// re-parse rejecting it) — a pure parse, never a signature verification or a certificate-chain trust decision.
/// This is the single choke point <see cref="TimestampTokenInfo"/> composes to surface a time-stamp token's
/// embedded material regardless of which <see cref="VerifyCmsSignedDataDelegate"/> a host has registered for
/// the separate signature-verification concern: reading what a SignedData embeds is parsing, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119100_119199/11915201/01.01.01_60/ts_11915201v010101p.pdf">
/// ETSI TS 119 152-1 V1.1.1</see> clause 6.3 additional requirements (h)/(i), not a cryptographic operation a
/// verification backend should gate.
/// </summary>
/// <remarks>
/// <para>
/// A <c>CertificateChoices</c> (RFC 5652 §10.2.2) is a CHOICE between the untagged <c>Certificate</c>
/// alternative and four tagged alternatives this type never surfaces as one: <c>extendedCertificate [0]</c>,
/// <c>v1AttrCert [1]</c>, <c>v2AttrCert [2]</c> and <c>other [3]</c>. Only the untagged <c>Certificate</c>
/// alternative is surfaced through <see cref="Certificates"/>; the tagged alternatives are legal content that
/// is skipped, mirroring how the <c>RevocationInfoChoice</c> loop below treats <c>other [1]</c> — never misread
/// as a certificate, and never collapsed to <see cref="CmsEmbeddedMaterialStatus.Malformed"/> for merely being
/// present. A tag-valid untagged-<c>Certificate</c> member whose content still fails
/// <see cref="ManagedCertificate.Parse"/> keeps collapsing the whole read to
/// <see cref="CmsEmbeddedMaterialStatus.Malformed"/> — that member is genuinely broken, not legal alternative
/// content.
/// </para>
/// <para>
/// A <c>RevocationInfoChoice</c> (RFC 5652 §10.2.1) is a CHOICE between the untagged <c>CertificateList</c>
/// alternative — a Certificate Revocation List — and an <c>other [1] IMPLICIT OtherRevocationInfoFormat</c>
/// alternative (for example an embedded OCSP response, <see href="https://www.rfc-editor.org/rfc/rfc5940#section-2">
/// RFC 5940 §2</see>). Only the <c>CertificateList</c> alternative is surfaced through <see cref="Crls"/>; the
/// <c>other</c> alternative is skipped rather than misread as one.
/// </para>
/// <para>
/// <see cref="SignerCertificate"/> is identified by matching the structure's first <c>SignerInfo</c>'s
/// <c>sid</c> (<see href="https://www.rfc-editor.org/rfc/rfc5652#section-5.3">RFC 5652 §5.3</see>) — an
/// issuer-and-serial-number or a subject-key-identifier — against <see cref="Certificates"/>; it is
/// <see langword="null"/> when no embedded certificate matches, which RFC 5652 permits (a relying party may
/// hold the signer's certificate through other means). See the property's own remarks for the identity-match
/// (not cryptographic-binding) reading and the ownership caveat.
/// </para>
/// <para>
/// <strong>Residue: duplicate-sid decoys.</strong> RFC 5652 places no uniqueness requirement on the <c>sid</c>
/// across embedded certificates; when two or more share the identifier <see cref="SignerCertificate"/> matches
/// on, <see cref="ManagedCmsVerification.MatchSigner"/> returns the first one it encounters, not necessarily
/// the one the structure's own signature was produced with — this parse establishes no cryptographic binding
/// either way (see <see cref="SignerCertificate"/>). Hardening against a duplicate-sid decoy is a registered
/// residue, not currently resolved.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> This reads a structure that arrives inside a signature exactly
/// as <see cref="TimestampTokenInfo"/> treats one: every field of the outer CMS walk is read through
/// <see cref="AsnReader"/>'s bounds-checked cursors under <see cref="AsnEncodingRules.BER"/> — the re-parse
/// must never be stricter than what a verifying backend already accepted — while each individual certificate's
/// own bytes are re-parsed under <see cref="AsnEncodingRules.DER"/> by <see cref="ManagedCertificate.Parse"/>,
/// since RFC 5280 certificates are themselves DER regardless of the enclosing CMS's encoding. A malformed
/// structure yields <see cref="CmsEmbeddedMaterialStatus.Malformed"/> rather than an exception escaping to the
/// caller.
/// </para>
/// <para>
/// <strong>Ownership.</strong> A successful parse owns every carrier in <see cref="Certificates"/> and
/// <see cref="Crls"/>; the caller disposes the returned instance, which disposes them.
/// <see cref="SignerCertificate"/> is a reference into <see cref="Certificates"/>, never a separate
/// allocation, so it is not disposed twice.
/// </para>
/// </remarks>
public sealed class CmsEmbeddedMaterial: IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already run.</summary>
    private bool disposed;


    /// <summary>
    /// Initialises a new instance. Private: an instance only ever comes from <see cref="Parse"/>, so a status
    /// and the carriers that status implies cannot disagree.
    /// </summary>
    /// <param name="status">Whether the parse succeeded, and if not why.</param>
    /// <param name="certificates">The embedded certificates, owned, in the order the <c>certificates</c> field carried them.</param>
    /// <param name="crls">The embedded Certificate Revocation Lists, owned, in the order the <c>crls</c> field carried them.</param>
    /// <param name="signerCertificateIndex">The index within <paramref name="certificates"/> of the signer's own certificate, or a negative number when none matched.</param>
    /// <param name="signerIdentifier">The structure's first <c>SignerInfo</c>'s <c>sid</c>, meaningful only when <paramref name="status"/> is <see cref="CmsEmbeddedMaterialStatus.Read"/>.</param>
    private CmsEmbeddedMaterial(
        CmsEmbeddedMaterialStatus status,
        IReadOnlyList<PkiCertificateMemory> certificates,
        IReadOnlyList<PkiCertificateMemory> crls,
        int signerCertificateIndex,
        ManagedCmsVerification.SignerIdentifier signerIdentifier)
    {
        Status = status;
        Certificates = certificates;
        Crls = crls;
        SignerCertificateIndex = signerCertificateIndex;
        SignerIdentifierValue = signerIdentifier;
    }


    /// <summary>Gets whether the structure could be parsed, and if not, why.</summary>
    public CmsEmbeddedMaterialStatus Status { get; }

    /// <summary>Gets whether the structure was parsed; <see cref="Certificates"/> and <see cref="Crls"/> are meaningful regardless, but empty when this is <see langword="false"/>.</summary>
    public bool IsRead => Status == CmsEmbeddedMaterialStatus.Read;

    /// <summary>Gets the embedded certificates, owned by this instance, in the order the <c>certificates</c> field carried them.</summary>
    public IReadOnlyList<PkiCertificateMemory> Certificates { get; }

    /// <summary>Gets the embedded Certificate Revocation Lists, owned by this instance, in the order the <c>crls</c> field carried them.</summary>
    public IReadOnlyList<PkiCertificateMemory> Crls { get; }

    /// <summary>Gets the index within <see cref="Certificates"/> of the signer's own certificate, or a negative number when none matched.</summary>
    private int SignerCertificateIndex { get; }

    /// <summary>Gets the structure's first <c>SignerInfo</c>'s <c>sid</c>, meaningful only when <see cref="Status"/> is <see cref="CmsEmbeddedMaterialStatus.Read"/>.</summary>
    private ManagedCmsVerification.SignerIdentifier SignerIdentifierValue { get; }

    /// <summary>
    /// Gets the signer's own certificate among <see cref="Certificates"/>, identified by matching the
    /// structure's first <c>SignerInfo</c>'s <c>sid</c> against the embedded set; <see langword="null"/> when
    /// it is not among them.
    /// </summary>
    /// <remarks>
    /// This is an IDENTITY match (issuer-and-serial-number or subject-key-identifier, RFC 5652 §5.3), never a
    /// cryptographic binding to the signature this structure's <c>SignerInfo</c> actually produced —
    /// establishing that binding is the CMS signature-verification concern this type deliberately never
    /// performs. The returned instance is a non-owned alias into <see cref="Certificates"/>, never a separate
    /// rental: never dispose it directly — only disposing this <see cref="CmsEmbeddedMaterial"/> disposes the
    /// carrier it aliases, and disposing both is the double-dispose trap.
    /// </remarks>
    public PkiCertificateMemory? SignerCertificate => SignerCertificateIndex >= 0 ? Certificates[SignerCertificateIndex] : null;


    /// <summary>
    /// Determines whether <paramref name="certificateDer"/> identifies this structure's own signer — the SAME
    /// issuer-and-serial-number/subject-key-identifier identity comparison <see cref="SignerCertificate"/> runs
    /// against <see cref="Certificates"/> (RFC 5652 §5.3), run instead against a caller-supplied candidate this
    /// parse never saw (a signature's own <c>valData</c> certificate values, for instance).
    /// </summary>
    /// <param name="certificateDer">The candidate certificate's DER encoding.</param>
    /// <returns>
    /// <see langword="false"/> when this parse never reached a <c>SignerInfo</c> (<see cref="Status"/> is not
    /// <see cref="CmsEmbeddedMaterialStatus.Read"/>) or when <paramref name="certificateDer"/> does not itself
    /// parse as a certificate; otherwise whether its identity matches this structure's own signer identifier.
    /// </returns>
    /// <remarks>
    /// An identity comparison, never a cryptographic binding to the signature this structure's <c>SignerInfo</c>
    /// actually produced — the same reading <see cref="SignerCertificate"/>'s own remarks state.
    /// </remarks>
    public bool IsSignerCertificate(ReadOnlyMemory<byte> certificateDer)
    {
        if(Status != CmsEmbeddedMaterialStatus.Read)
        {
            return false;
        }

        ManagedCertificate candidate;
        try
        {
            candidate = ManagedCertificate.Parse(certificateDer);
        }
        catch(AsnContentException)
        {
            return false;
        }

        return ManagedCmsVerification.MatchSigner([candidate], SignerIdentifierValue) is not null;
    }


    /// <summary>
    /// Parses a CMS SignedData's <c>certificates</c> and <c>crls</c> fields and identifies the signer's own
    /// certificate among the former, without verifying any signature.
    /// </summary>
    /// <param name="signedData">The BER-encoded CMS SignedData, wrapped in its <c>ContentInfo</c>.</param>
    /// <param name="pool">The memory pool the certificate and CRL carriers are rented from.</param>
    /// <returns>The parsed facts. Check <see cref="Status"/>: only <see cref="CmsEmbeddedMaterialStatus.Read"/> means <see cref="Certificates"/> or <see cref="Crls"/> can be non-empty. The caller disposes the returned instance in every case.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="pool"/> is <see langword="null"/>.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every rented certificate and CRL carrier transfers to the returned CmsEmbeddedMaterial, which the caller disposes; a malformed or unexpectedly-failing parse disposes them here instead.")]
    public static CmsEmbeddedMaterial Parse(ReadOnlyMemory<byte> signedData, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        var certificates = new List<PkiCertificateMemory>();
        var crls = new List<PkiCertificateMemory>();
        try
        {
            var outer = new AsnReader(signedData, AsnEncodingRules.BER);
            AsnReader contentInfo = outer.ReadSequence();
            string contentType = contentInfo.ReadObjectIdentifier();
            if(!string.Equals(contentType, ManagedCmsVerification.SignedDataOid, StringComparison.Ordinal))
            {
                return new CmsEmbeddedMaterial(CmsEmbeddedMaterialStatus.Malformed, [], [], -1, default);
            }

            AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            AsnReader parsedSignedData = explicitContent.ReadSequence();

            _ = parsedSignedData.ReadInteger();                                  //version
            _ = parsedSignedData.ReadSetOf();                                    //digestAlgorithms

            AsnReader encapContentInfo = parsedSignedData.ReadSequence();
            _ = encapContentInfo.ReadObjectIdentifier();
            if(encapContentInfo.HasData)
            {
                _ = encapContentInfo.ReadEncodedValue();                         //eContent [0] EXPLICIT, unused here
            }

            var managedCertificates = new List<ManagedCertificate>();
            if(parsedSignedData.HasData && parsedSignedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true))
            {
                AsnReader certificateChoices = parsedSignedData.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 0));
                while(certificateChoices.HasData)
                {
                    if(certificateChoices.PeekTag() == new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true))
                    {
                        ReadOnlyMemory<byte> certificateDer = certificateChoices.ReadEncodedValue();
                        managedCertificates.Add(ManagedCertificate.Parse(certificateDer));
                        certificates.Add(ToPkiObject(certificateDer.Span, pool, PkiCertificateTags.X509Certificate));
                    }
                    else
                    {
                        //The extendedCertificate [0] / v1AttrCert [1] / v2AttrCert [2] / other [3] tagged
                        //alternatives — not a Certificate, consumed so the closing emptiness check stays exact
                        //but never surfaced as one.
                        _ = certificateChoices.ReadEncodedValue();
                    }
                }
            }

            if(parsedSignedData.HasData && parsedSignedData.PeekTag() == new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true))
            {
                AsnReader revocationInfoChoices = parsedSignedData.ReadSetOf(skipSortOrderValidation: true, new Asn1Tag(TagClass.ContextSpecific, 1));
                while(revocationInfoChoices.HasData)
                {
                    if(revocationInfoChoices.PeekTag() == new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true))
                    {
                        crls.Add(ToPkiObject(revocationInfoChoices.ReadEncodedValue().Span, pool, PkiCertificateTags.X509Crl));
                    }
                    else
                    {
                        //The other [1] IMPLICIT OtherRevocationInfoFormat alternative — not a CertificateList,
                        //consumed so the closing emptiness check stays exact but never surfaced as a CRL.
                        _ = revocationInfoChoices.ReadEncodedValue();
                    }
                }
            }

            AsnReader signerInfos = parsedSignedData.ReadSetOf();
            AsnReader firstSigner = signerInfos.ReadSequence();
            _ = firstSigner.ReadInteger();                                       //SignerInfo.version
            ManagedCmsVerification.SignerIdentifier signerIdentifier = ManagedCmsVerification.ParseSignerIdentifier(firstSigner);

            ManagedCertificate? matched = ManagedCmsVerification.MatchSigner(managedCertificates, signerIdentifier);
            int signerIndex = matched is null ? -1 : managedCertificates.IndexOf(matched);

            return new CmsEmbeddedMaterial(CmsEmbeddedMaterialStatus.Read, certificates, crls, signerIndex, signerIdentifier);
        }
        catch(AsnContentException)
        {
            DisposeAll(certificates, crls);

            return new CmsEmbeddedMaterial(CmsEmbeddedMaterialStatus.Malformed, [], [], -1, default);
        }
        catch
        {
            DisposeAll(certificates, crls);

            throw;
        }

        //Disposes every carrier collected so far on a parse that ends without producing a CmsEmbeddedMaterial to
        //own them. Takes both lists explicitly (no closure capture) even though every call site in this method
        //passes through the same enclosing locals, since a static local function cannot close over them.
        static void DisposeAll(List<PkiCertificateMemory> certificates, List<PkiCertificateMemory> crls)
        {
            foreach(PkiCertificateMemory certificate in certificates)
            {
                certificate.Dispose();
            }

            foreach(PkiCertificateMemory crl in crls)
            {
                crl.Dispose();
            }
        }

        //Copies a DER-encoded object's bytes into a pooled carrier under the given kind tag.
        static PkiCertificateMemory ToPkiObject(ReadOnlySpan<byte> der, BaseMemoryPool pool, Tag tag)
        {
            IMemoryOwner<byte> owner = pool.Rent(der.Length);
            der.CopyTo(owner.Memory.Span);

            return new PkiCertificateMemory(owner, tag);
        }
    }


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            foreach(PkiCertificateMemory certificate in Certificates)
            {
                certificate.Dispose();
            }

            foreach(PkiCertificateMemory crl in Crls)
            {
                crl.Dispose();
            }

            disposed = true;
        }
    }
}
