using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Formats.Asn1;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The revocation-source facts a certificate's Authority Information Access
/// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1">RFC 5280 §4.2.2.1</see>) and CRL
/// Distribution Points (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13">RFC 5280
/// §4.2.1.13</see>) extensions carry: the URIs an OCSP client or a CRL fetcher needs to locate the
/// certificate's revocation source. This record states only what a certificate declares; it makes no
/// revocation determination of its own.
/// </summary>
/// <remarks>
/// A URI is public routing metadata copied verbatim from the certificate's extension value — not a domain
/// value needing a carrier — so it is returned as a plain <see cref="string"/>, the same choice
/// <see cref="ExtractAuthorityKeyIdentifierDelegate"/> makes for the same reason.
/// </remarks>
[DebuggerDisplay("RevocationSourceFacts: OcspUris={OcspResponderUris.Count}, CaIssuerUris={CaIssuerUris.Count}, CrlUris={CrlDistributionPointUris.Count}")]
public sealed record RevocationSourceFacts
{
    /// <summary>
    /// Gets whether the certificate carries an Authority Information Access extension
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1">RFC 5280 §4.2.2.1</see>).
    /// </summary>
    public required bool HasAuthorityInfoAccessExtension { get; init; }

    /// <summary>
    /// Gets the <c>id-ad-ocsp</c> access location URIs, in certificate order; empty when the extension is
    /// absent or carries no <c>id-ad-ocsp</c> URI-form access location.
    /// </summary>
    public required IReadOnlyList<string> OcspResponderUris { get; init; }

    /// <summary>
    /// Gets the <c>id-ad-caIssuers</c> access location URIs, in certificate order; empty when the extension
    /// is absent or carries no <c>id-ad-caIssuers</c> URI-form access location.
    /// </summary>
    public required IReadOnlyList<string> CaIssuerUris { get; init; }

    /// <summary>
    /// Gets whether the certificate carries a CRL Distribution Points extension
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13">RFC 5280 §4.2.1.13</see>).
    /// </summary>
    public required bool HasCrlDistributionPointsExtension { get; init; }

    /// <summary>
    /// Gets the <c>fullName</c> URI entries of every distribution point, in certificate order; empty when the
    /// extension is absent or carries no URI-form <c>fullName</c> entry.
    /// </summary>
    public required IReadOnlyList<string> CrlDistributionPointUris { get; init; }
}


/// <summary>
/// Extracts <see cref="RevocationSourceFacts"/> straight off a DER-encoded X.509 certificate with
/// <see cref="System.Formats.Asn1"/> only, the same no-certificate-library approach as
/// <see cref="QualifiedCertificateFactsExtractor"/>.
/// </summary>
/// <remarks>
/// <strong>Attacker-reachable input.</strong> A certificate arrives from a signature or a network location
/// and its own signature is verified by the separate chain step, not here, so this extractor treats the
/// bytes as hostile exactly as <see cref="QualifiedCertificateFactsExtractor"/> does: every structure is read
/// with <see cref="AsnEncodingRules.DER"/> through <see cref="AsnReader"/>'s bounds-checked cursors, the walk
/// is straight-line loops with no recursion (a distinguished name and an extension list nest to fixed depth
/// by their ASN.1 definitions), and trailing data is rejected wherever the schema closes a structure this
/// extractor reads. Of duplicate extensions — an RFC 5280 §4.2 profile violation — the first occurrence is
/// read; a <c>GeneralName</c> in a form other than <c>uniformResourceIdentifier</c> is skipped rather than
/// aborting extraction, and likewise a <c>DistributionPointName</c> choosing
/// <c>nameRelativeToCRLIssuer</c> instead of <c>fullName</c> contributes no URI. Malformed content throws
/// <see cref="AsnContentException"/>.
/// </remarks>
public static class RevocationSourceFactsExtractor
{
    /// <summary>The GeneralName <c>uniformResourceIdentifier</c> choice tag: context-specific, primitive, number 6 (RFC 5280 §4.2.1.6).</summary>
    private static Asn1Tag UniformResourceIdentifierTag { get; } = new(TagClass.ContextSpecific, 6);


    /// <summary>
    /// Extracts the <see cref="RevocationSourceFacts"/> from a DER-encoded X.509 certificate.
    /// </summary>
    /// <param name="certificate">The certificate to read. The caller retains ownership.</param>
    /// <returns>The extracted facts.</returns>
    /// <exception cref="ArgumentException">When <paramref name="certificate"/> does not carry an X.509 certificate.</exception>
    /// <exception cref="AsnContentException">When the bytes are not a DER-encoded RFC 5280 certificate.</exception>
    public static RevocationSourceFacts Extract(PkiCertificateMemory certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);
        if(!certificate.IsX509Certificate)
        {
            throw new ArgumentException("The carrier must hold an X.509 certificate.", nameof(certificate));
        }

        //Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue } (RFC 5280 §4.1.1);
        //only tbsCertificate is read — the signature is the chain step's concern, not a fact.
        var reader = new AsnReader(certificate.AsReadOnlyMemory(), AsnEncodingRules.DER);
        AsnReader certificateSequence = reader.ReadSequence();
        reader.ThrowIfNotEmpty();
        AsnReader tbsCertificate = certificateSequence.ReadSequence();

        //version [0] EXPLICIT INTEGER DEFAULT v1 (RFC 5280 §4.1.2.1), present in practically every certificate.
        if(tbsCertificate.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            _ = tbsCertificate.ReadEncodedValue();
        }

        _ = tbsCertificate.ReadEncodedValue();                              //serialNumber.
        _ = tbsCertificate.ReadEncodedValue();                              //signature AlgorithmIdentifier.
        _ = tbsCertificate.ReadEncodedValue();                              //issuer Name.
        AsnReader validity = tbsCertificate.ReadSequence();
        _ = validity.ReadEncodedValue();                                    //notBefore, structurally validated only.
        _ = validity.ReadEncodedValue();                                    //notAfter, structurally validated only.
        validity.ThrowIfNotEmpty();
        _ = tbsCertificate.ReadEncodedValue();                              //subject Name.
        _ = tbsCertificate.ReadEncodedValue();                              //subjectPublicKeyInfo.

        RevocationSourceFacts facts = ReadExtensions(tbsCertificate);

        //signatureAlgorithm and signatureValue close the Certificate sequence (RFC 5280 §4.1.1); their
        //structure is this contract's concern, their content the chain step's.
        _ = certificateSequence.ReadSequence();
        if(!certificateSequence.TryReadPrimitiveBitString(out _, out _))
        {
            throw new AsnContentException("A Certificate must close with its signatureValue BIT STRING (RFC 5280 §4.1.1).");
        }

        certificateSequence.ThrowIfNotEmpty();

        return facts;
    }


    /// <summary>
    /// Skips the obsolete unique-identifier fields and walks the <c>extensions [3]</c> list per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.9">RFC 5280 §4.1.2.9</see>, reading
    /// the first occurrence of the Authority Information Access and CRL Distribution Points extensions.
    /// </summary>
    /// <param name="tbsCertificate">The reader positioned after <c>subjectPublicKeyInfo</c>.</param>
    /// <returns>The collected revocation-source facts.</returns>
    private static RevocationSourceFacts ReadExtensions(AsnReader tbsCertificate)
    {
        //issuerUniqueID [1] IMPLICIT and subjectUniqueID [2] IMPLICIT are obsolete but allowed before
        //extensions (RFC 5280 §4.1.2.8); IMPLICIT BIT STRING is a primitive tag, so only class and value
        //are compared.
        if(tbsCertificate.HasData && tbsCertificate.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            _ = tbsCertificate.ReadEncodedValue();
        }

        if(tbsCertificate.HasData && tbsCertificate.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
        {
            _ = tbsCertificate.ReadEncodedValue();
        }

        List<string>? ocspResponderUris = null;
        List<string>? caIssuerUris = null;
        List<string>? crlDistributionPointUris = null;
        bool hasAuthorityInfoAccess = false;
        bool hasCrlDistributionPoints = false;

        if(tbsCertificate.HasData && tbsCertificate.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 3)))
        {
            AsnReader extensionsWrapper = tbsCertificate.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 3));
            AsnReader extensions = extensionsWrapper.ReadSequence();
            while(extensions.HasData)
            {
                //Extension ::= SEQUENCE { extnID OID, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }.
                AsnReader extension = extensions.ReadSequence();
                string extensionId = extension.ReadObjectIdentifier();
                if(extension.PeekTag() == Asn1Tag.Boolean)
                {
                    _ = extension.ReadBoolean();
                }

                if(!extension.TryReadPrimitiveOctetString(out ReadOnlyMemory<byte> extensionValue))
                {
                    throw new AsnContentException("An extension value must be a primitive OCTET STRING in DER (RFC 5280 §4.1.2.9).");
                }

                switch(extensionId)
                {
                    case WellKnownOids.AuthorityInfoAccessExtension when !hasAuthorityInfoAccess:
                        hasAuthorityInfoAccess = true;
                        (ocspResponderUris, caIssuerUris) = ReadAuthorityInfoAccess(new AsnReader(extensionValue, AsnEncodingRules.DER));
                        break;

                    case WellKnownOids.CrlDistributionPointsExtension when !hasCrlDistributionPoints:
                        hasCrlDistributionPoints = true;
                        crlDistributionPointUris = ReadCrlDistributionPointUris(new AsnReader(extensionValue, AsnEncodingRules.DER));
                        break;

                    default:
                        break;
                }

                extension.ThrowIfNotEmpty();
            }

            extensionsWrapper.ThrowIfNotEmpty();
        }

        //Any to-be-signed content still unread here is not an RFC 5280 §4.1.2 field: malformed input is
        //rejected, never silently read as "no extensions".
        tbsCertificate.ThrowIfNotEmpty();

        return new RevocationSourceFacts
        {
            HasAuthorityInfoAccessExtension = hasAuthorityInfoAccess,
            OcspResponderUris = ocspResponderUris ?? [],
            CaIssuerUris = caIssuerUris ?? [],
            HasCrlDistributionPointsExtension = hasCrlDistributionPoints,
            CrlDistributionPointUris = crlDistributionPointUris ?? []
        };
    }


    /// <summary>
    /// Reads an Authority Information Access extension value — <c>AuthorityInfoAccessSyntax ::= SEQUENCE
    /// SIZE(1..MAX) OF AccessDescription</c>, <c>AccessDescription ::= SEQUENCE { accessMethod OID,
    /// accessLocation GeneralName }</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.2.1">RFC 5280 §4.2.2.1</see> — collecting
    /// the URI-form access locations for the OCSP and CA-issuers access methods.
    /// </summary>
    /// <param name="value">The reader positioned at the extension's inner value.</param>
    /// <returns>The OCSP responder and CA-issuer URIs, each in certificate order.</returns>
    private static (List<string> OcspResponderUris, List<string> CaIssuerUris) ReadAuthorityInfoAccess(AsnReader value)
    {
        List<string> ocspResponderUris = [];
        List<string> caIssuerUris = [];

        AsnReader accessDescriptions = value.ReadSequence();
        while(accessDescriptions.HasData)
        {
            AsnReader accessDescription = accessDescriptions.ReadSequence();
            string accessMethod = accessDescription.ReadObjectIdentifier();
            if(TryReadUniformResourceIdentifier(accessDescription, out string? uri))
            {
                switch(accessMethod)
                {
                    case WellKnownOids.AccessMethodOcsp:
                        ocspResponderUris.Add(uri!);
                        break;

                    case WellKnownOids.AccessMethodCaIssuers:
                        caIssuerUris.Add(uri!);
                        break;

                    default:
                        break;
                }
            }

            accessDescription.ThrowIfNotEmpty();
        }

        value.ThrowIfNotEmpty();

        return (ocspResponderUris, caIssuerUris);
    }


    /// <summary>
    /// Reads a CRL Distribution Points extension value — <c>CRLDistributionPoints ::= SEQUENCE SIZE(1..MAX)
    /// OF DistributionPoint</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13">RFC 5280 §4.2.1.13</see> —
    /// collecting the URI entries of every distribution point's <c>fullName</c> choice; a distribution point
    /// choosing <c>nameRelativeToCRLIssuer</c>, or omitting <c>distributionPoint</c> entirely, contributes no
    /// URI. The <c>reasons</c> and <c>cRLIssuer</c> fields are structurally skipped, not read as facts.
    /// </summary>
    /// <param name="value">The reader positioned at the extension's inner value.</param>
    /// <returns>The <c>fullName</c> URI entries, in certificate order.</returns>
    private static List<string> ReadCrlDistributionPointUris(AsnReader value)
    {
        List<string> uris = [];

        AsnReader distributionPoints = value.ReadSequence();
        while(distributionPoints.HasData)
        {
            //DistributionPoint ::= SEQUENCE { distributionPoint [0] EXPLICIT DistributionPointName OPTIONAL,
            //reasons [1] IMPLICIT ReasonFlags OPTIONAL, cRLIssuer [2] IMPLICIT GeneralNames OPTIONAL }.
            AsnReader distributionPoint = distributionPoints.ReadSequence();
            if(distributionPoint.HasData && distributionPoint.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                AsnReader distributionPointName = distributionPoint.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));

                //DistributionPointName ::= CHOICE { fullName [0] IMPLICIT GeneralNames, nameRelativeToCRLIssuer [1] IMPLICIT RDN }.
                if(distributionPointName.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    AsnReader fullName = distributionPointName.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
                    while(fullName.HasData)
                    {
                        if(TryReadUniformResourceIdentifier(fullName, out string? uri))
                        {
                            uris.Add(uri!);
                        }
                    }

                    fullName.ThrowIfNotEmpty();
                }
                else
                {
                    //nameRelativeToCRLIssuer — not a URI form; skipped without failing.
                    _ = distributionPointName.ReadEncodedValue();
                }

                distributionPointName.ThrowIfNotEmpty();
            }

            //reasons [1] and cRLIssuer [2] are not read facts; drain whatever remains so the walk stays
            //straight-line without needing to distinguish their tags.
            while(distributionPoint.HasData)
            {
                _ = distributionPoint.ReadEncodedValue();
            }
        }

        value.ThrowIfNotEmpty();

        return uris;
    }


    /// <summary>
    /// Reads a <c>GeneralName</c> as its <c>uniformResourceIdentifier [6] IMPLICIT IA5String</c> choice
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.6">RFC 5280 §4.2.1.6</see>), consuming
    /// and skipping any other choice so the walk continues.
    /// </summary>
    /// <param name="reader">The reader positioned at the <c>GeneralName</c>.</param>
    /// <param name="uri">The decoded URI, or <see langword="null"/> when the choice is not <c>uniformResourceIdentifier</c>.</param>
    /// <returns><see langword="true"/> when a URI was read.</returns>
    private static bool TryReadUniformResourceIdentifier(AsnReader reader, out string? uri)
    {
        if(reader.PeekTag().HasSameClassAndValue(UniformResourceIdentifierTag))
        {
            uri = reader.ReadCharacterString(UniversalTagNumber.IA5String, UniformResourceIdentifierTag);

            return true;
        }

        _ = reader.ReadEncodedValue();
        uri = null;

        return false;
    }
}
