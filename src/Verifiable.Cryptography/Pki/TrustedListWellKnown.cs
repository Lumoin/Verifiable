using System;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The kind of Trusted List a <see cref="TrustedList"/> document declares itself to be, read verbatim from
/// its <c>TSLType</c> element, per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.3.3</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is a wire-value wrapper (like <see cref="TrustServiceStatus"/> and its siblings below), NOT a closed
/// enum: the schema types <c>TSLType</c> as an unrestricted <c>NonEmptyURIType</c> (XSD anyURI), and only two
/// values (<see cref="Generic"/>, <see cref="ListOfTheLists"/>) are current EU-registered conventions — real
/// documents also carry a pre-2016 legacy URI shape, or a fictional third-country value under a Mutual
/// Recognition Agreement (TS 119 612's MRA mechanism explicitly covers non-EU lists that do not use the EU
/// convention at all). An earlier version of this parser hard-rejected the WHOLE document — real, structurally
/// complete lists included — whenever <c>TSLType</c> was not one of the two current values; that was wrong for
/// the same reason a hard <c>ServiceStatus</c> enum would be wrong, and is fixed by carrying whatever value the
/// document declares.
/// </para>
/// <para>
/// The XSD <c>anyURI</c> primitive type has a fixed <c>whiteSpace=collapse</c> facet (XML Schema Part 2 §3.2.17),
/// so a conformant reader trims/collapses the lexical value before comparison — a document whose
/// <c>TSLType</c> text carries incidental leading/trailing whitespace from pretty-printing is not thereby
/// carrying a different value.
/// </para>
/// </remarks>
public readonly record struct TrustedListKind(string Value)
{
    /// <summary>
    /// A Trusted List proper — a scheme operator's own list of trust services
    /// (<c>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric</c>).
    /// </summary>
    public static TrustedListKind Generic { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric");

    /// <summary>
    /// The EU List Of the Trusted Lists — a list of pointers to every member state's Trusted List
    /// (<c>http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists</c>), per
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
    /// ETSI TS 119 612 V2.4.1 clause 5.3.13</see>.
    /// </summary>
    public static TrustedListKind ListOfTheLists { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists");


    /// <summary>Returns <see langword="true"/> when this is <see cref="Generic"/>.</summary>
    public bool IsGeneric => string.Equals(Value, Generic.Value, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when this is <see cref="ListOfTheLists"/>.</summary>
    public bool IsListOfTheLists => string.Equals(Value, ListOfTheLists.Value, StringComparison.Ordinal);
}


/// <summary>
/// The status a Trust Service currently holds, or held at a point in its history, read from the
/// <c>ServiceStatus</c> element per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.4</see> (current) / clause 5.6.4 (history). The element is typed as an
/// unrestricted URI rather than a schema enumeration, so this is a wire-value wrapper (like
/// <see cref="Verifiable.OAuth.Trust.TrustMechanism"/>) carrying the raw URI plus <c>Is*</c> helpers for the
/// values the specification registers, rather than a closed enum that would reject a forward-compatible one.
/// </summary>
public readonly record struct TrustServiceStatus(string Value)
{
    /// <summary>The service is operating under the scheme's supervision/accreditation as declared.</summary>
    public static TrustServiceStatus Granted { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted");

    /// <summary>The service has been withdrawn from the scheme.</summary>
    public static TrustServiceStatus Withdrawn { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn");

    /// <summary>The service is under supervision.</summary>
    public static TrustServiceStatus UnderSupervision { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision");

    /// <summary>Supervision of the service is in the process of ceasing.</summary>
    public static TrustServiceStatus SupervisionInCessation { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation");

    /// <summary>Supervision of the service has ceased.</summary>
    public static TrustServiceStatus SupervisionCeased { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionceased");

    /// <summary>Supervision of the service has been revoked.</summary>
    public static TrustServiceStatus SupervisionRevoked { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionrevoked");

    /// <summary>The service is accredited.</summary>
    public static TrustServiceStatus Accredited { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited");

    /// <summary>Accreditation of the service has ceased.</summary>
    public static TrustServiceStatus AccreditationCeased { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationceased");

    /// <summary>Accreditation of the service has been revoked.</summary>
    public static TrustServiceStatus AccreditationRevoked { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accreditationrevoked");

    /// <summary>The service's status is set by national law rather than by the supervisory scheme.</summary>
    public static TrustServiceStatus SetByNationalLaw { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/setbynationallaw");

    /// <summary>The service is recognised at national level.</summary>
    public static TrustServiceStatus RecognisedAtNationalLevel { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/recognisedatnationallevel");

    /// <summary>The service's status has been deprecated at national level.</summary>
    public static TrustServiceStatus DeprecatedAtNationalLevel { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/deprecatedatnationallevel");


    /// <summary>Returns <see langword="true"/> when this status is <see cref="Granted"/>.</summary>
    public bool IsGranted => string.Equals(Value, Granted.Value, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when this status is <see cref="Withdrawn"/>.</summary>
    public bool IsWithdrawn => string.Equals(Value, Withdrawn.Value, StringComparison.Ordinal);
}


/// <summary>
/// The kind of Trust Service a <see cref="TrustService"/> provides, read from the
/// <c>ServiceTypeIdentifier</c> element per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.1</see>. The specification's registered service-type vocabulary is
/// open-ended (member states and future revisions add types), so this is a wire-value wrapper carrying the
/// raw URI plus <c>Is*</c> helpers for the types the certificate-qualification path in TS 119 615 cares
/// about — a service type this wrapper does not name is still represented, just without a helper.
/// </summary>
public readonly record struct TrustServiceTypeIdentifier(string Value)
{
    /// <summary>A Certification Authority issuing qualified certificates.</summary>
    public static TrustServiceTypeIdentifier CertificationAuthorityQualifiedCertificates { get; } = new("http://uri.etsi.org/TrstSvc/Svctype/CA/QC");

    /// <summary>A Certification Authority issuing non-qualified (public key) certificates.</summary>
    public static TrustServiceTypeIdentifier CertificationAuthorityPublicKeyCertificates { get; } = new("http://uri.etsi.org/TrstSvc/Svctype/CA/PKC");

    /// <summary>A Certification Authority issuing card-verifiable certificates.</summary>
    public static TrustServiceTypeIdentifier CertificationAuthorityCardVerifiableCertificates { get; } = new("http://uri.etsi.org/TrstSvc/Svctype/CA/CVC");

    /// <summary>An OCSP responder providing certificate status for qualified certificates.</summary>
    public static TrustServiceTypeIdentifier OcspQualifiedCertificates { get; } = new("http://uri.etsi.org/TrstSvc/Svctype/Certstatus/OCSP/QC");

    /// <summary>A CRL issuer providing revocation lists.</summary>
    public static TrustServiceTypeIdentifier Crl { get; } = new("http://uri.etsi.org/TrstSvc/Svctype/Certstatus/CRL");

    /// <summary>A Trust Service Authority issuing qualified electronic time stamps.</summary>
    public static TrustServiceTypeIdentifier QualifiedTimeStampAuthority { get; } = new("http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST");

    /// <summary>
    /// A time-stamping generation service not further qualified. Named alongside
    /// <see cref="QualifiedTimeStampAuthority"/> by ETSI TS 119 172-4 REQ-4.5-01 d) i), whose report
    /// information point covers the absence of a time-stamping trust anchor of either type from an EU
    /// Member State trusted list.
    /// </summary>
    public static TrustServiceTypeIdentifier TimeStampAuthority { get; } = new("http://uri.etsi.org/TrstSvc/Svctype/TSA");

    /// <summary>A Registration Authority.</summary>
    public static TrustServiceTypeIdentifier RegistrationAuthority { get; } = new("http://uri.etsi.org/TrstSvc/Svctype/RA");


    /// <summary>Returns <see langword="true"/> when this identifies a QC-issuing Certification Authority.</summary>
    public bool IsCertificationAuthorityQualifiedCertificates =>
        string.Equals(Value, CertificationAuthorityQualifiedCertificates.Value, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when this identifies a QC OCSP responder.</summary>
    public bool IsOcspQualifiedCertificates =>
        string.Equals(Value, OcspQualifiedCertificates.Value, StringComparison.Ordinal);
}


/// <summary>
/// An additional-service-information type asserted on a <see cref="TrustService"/> per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.9.1</see> — the registered <c>AdditionalServiceInformation</c> URIs
/// that narrow what a service (typically a <see cref="TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates"/>
/// CA) certifies for.
/// </summary>
[DebuggerDisplay("TrustServiceAdditionalInformationType")]
public readonly record struct TrustServiceAdditionalInformationType(string Value)
{
    /// <summary>The service issues certificates for electronic signatures.</summary>
    public static TrustServiceAdditionalInformationType ForElectronicSignatures { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures");

    /// <summary>The service issues certificates for electronic seals.</summary>
    public static TrustServiceAdditionalInformationType ForElectronicSeals { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals");

    /// <summary>The service issues certificates for website authentication.</summary>
    public static TrustServiceAdditionalInformationType ForWebSiteAuthentication { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication");

    /// <summary>The service is a root CA in a qualified certificate chain.</summary>
    public static TrustServiceAdditionalInformationType RootCertificationAuthorityQualifiedCertificates { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/RootCA-QC");


    /// <summary>Returns <see langword="true"/> when this is <see cref="ForElectronicSignatures"/>.</summary>
    public bool IsForElectronicSignatures => string.Equals(Value, ForElectronicSignatures.Value, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when this is <see cref="ForElectronicSeals"/>.</summary>
    public bool IsForElectronicSeals => string.Equals(Value, ForElectronicSeals.Value, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when this is <see cref="ForWebSiteAuthentication"/>.</summary>
    public bool IsForWebSiteAuthentication => string.Equals(Value, ForWebSiteAuthentication.Value, StringComparison.Ordinal);
}


/// <summary>
/// A service-qualifier value asserted by a <see cref="QualificationElement"/> per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5.5.9.2.3</see> — what a certificate matching the qualification element's
/// <see cref="QualifierCondition"/> tree is qualified as, overriding or clarifying what the certificate's
/// own QC statements assert.
/// </summary>
[DebuggerDisplay("ServiceQualifier")]
public readonly record struct ServiceQualifier(string Value)
{
    /// <summary>The certificate is for electronic signatures.</summary>
    public static ServiceQualifier ForElectronicSignature { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig");

    /// <summary>The certificate is for electronic seals.</summary>
    public static ServiceQualifier ForElectronicSeal { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal");

    /// <summary>The certificate is for website authentication.</summary>
    public static ServiceQualifier ForWebSiteAuthentication { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA");

    /// <summary>The certificate is issued to a legal person.</summary>
    public static ServiceQualifier ForLegalPerson { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson");

    /// <summary>The certificate is a qualified certificate (overriding an absent or ambiguous QC statement).</summary>
    public static ServiceQualifier QualifiedCertificateStatement { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement");

    /// <summary>The certificate is explicitly NOT qualified.</summary>
    public static ServiceQualifier NotQualified { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified");

    /// <summary>The private key is on a Qualified (Signature/Seal) Creation Device, as the certificate's own QC statement asserts.</summary>
    public static ServiceQualifier QscdStatusAsInCertificate { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert");

    /// <summary>The private key is on a QSCD (asserted by the Trusted List, independent of the certificate's own statement).</summary>
    public static ServiceQualifier WithQscd { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD");

    /// <summary>The private key is explicitly NOT on a QSCD.</summary>
    public static ServiceQualifier NoQscd { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD");

    /// <summary>The QSCD is managed on behalf of the signer/seal creator by a third party.</summary>
    public static ServiceQualifier QscdManagedOnBehalf { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf");

    /// <summary>The pre-TLv5 (SSCD-terminology) equivalent of <see cref="QscdStatusAsInCertificate"/>.</summary>
    public static ServiceQualifier SscdStatusAsInCertificate { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDStatusAsInCert");

    /// <summary>The pre-TLv5 (SSCD-terminology) equivalent of <see cref="WithQscd"/>.</summary>
    public static ServiceQualifier WithSscd { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD");

    /// <summary>The pre-TLv5 (SSCD-terminology) equivalent of <see cref="NoQscd"/>.</summary>
    public static ServiceQualifier NoSscd { get; } = new("http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoSSCD");


    /// <summary>Returns <see langword="true"/> when this qualifier is one of the QSCD-asserting values (<see cref="WithQscd"/> or its SSCD-terminology equivalent <see cref="WithSscd"/>).</summary>
    public bool AssertsQscd =>
        string.Equals(Value, WithQscd.Value, StringComparison.Ordinal) || string.Equals(Value, WithSscd.Value, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when this qualifier explicitly denies QSCD status (<see cref="NoQscd"/> or its SSCD-terminology equivalent <see cref="NoSscd"/>).</summary>
    public bool DeniesQscd =>
        string.Equals(Value, NoQscd.Value, StringComparison.Ordinal) || string.Equals(Value, NoSscd.Value, StringComparison.Ordinal);
}
