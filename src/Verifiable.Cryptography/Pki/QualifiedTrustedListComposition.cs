using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Composes the minimal <see cref="TrustedList"/> graph that
/// <see cref="TrustedListQualification.DetermineEuQualifiedCertificateAsync"/> resolves as Qualified for one
/// <see cref="EuQualifiedCertificateType"/> dimension, from a minted Certification Authority certificate and
/// the provider/territory identity a caller already holds. This is a composing helper, not a Trusted List
/// downloader or XML parser: it never fetches anything and produces exactly the one
/// <see cref="TrustServiceProvider"/> / <see cref="TrustService"/> / <see cref="QualificationElement"/> shape
/// the determination procedure needs.
/// </summary>
/// <remarks>
/// <para>
/// <strong>What is pinned by the certificate-qualification procedure, and wired accordingly:</strong> the
/// scheme territory, resolved with <see cref="TrustedListQualification.ResolveTrustedListTerritory"/> — the
/// same value the determination procedure re-derives from the certificate and compares against; the
/// provider's <see cref="TrustServiceProvider.Names"/>, matched against a certificate's issuer
/// <c>organizationName</c> under PRO-4.4.4-06's normalized comparison; a
/// <see cref="TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates"/> service carrying the
/// CA certificate as an <see cref="X509CertificateIdentity"/>; a <see cref="TrustServiceStatus.Granted"/>
/// state whose <see cref="TrustService.StatusStartingTime"/> is at or before the caller-supplied
/// <c>notBefore</c> (PRO-4.4.4-34's re-determination at the certificate's own <c>NotBefore</c> instant needs a
/// state that already covers that instant); the dimension's <see cref="TrustServiceAdditionalInformationType"/>
/// declared on the service (clause 4.4.4's <c>dimensionStates</c> selection); and one
/// <see cref="QualificationElement"/> carrying <see cref="ServiceQualifier.QualifiedCertificateStatement"/>
/// together with the dimension's own <see cref="ServiceQualifier"/> — Table 1/2/3's column 5, which confirms
/// the dimension unconditionally once both qualifiers apply.
/// </para>
/// <para>
/// <strong>What is a composed placeholder, not a procedure input:</strong> a <see cref="QualificationElement"/>
/// only contributes its qualifiers once its <see cref="QualificationElement.Condition"/> criteria tree
/// evaluates to <c>Matched</c> against the certificate under test (clause 5.5.9.2.2). Without a leaf
/// certificate to build criteria from, <see cref="DefaultIdentifyingCondition"/> asserts the one Key Usage
/// bit every certificate <see cref="QualifiedCertificateMinting.MintQualifiedCertificateAsync"/> mints carries
/// regardless of <see cref="EuQualifiedCertificateType"/> — <c>KeyUsage{nonRepudiation}</c> — so the default
/// graph is Qualified-yielding for any leaf minted by that surface under the composed CA. A caller composing a
/// list for a differently-shaped leaf supplies its own <c>identifyingCondition</c>. The remaining
/// <see cref="TrustedListSchemeInformation"/> fields the schema requires but this library's clause 4.3/4.4
/// procedures never read — only <see cref="TrustedListSchemeInformation.SchemeTerritory"/> feeds a
/// determination — are procedure-irrelevant placeholders, not schema-conformant values: TS 119 612 requires
/// at least one operator name and at least one scheme name, a cardinality this composed graph does not
/// attempt to satisfy because the determination procedure never reads either field.
/// </para>
/// </remarks>
public static class QualifiedTrustedListComposition
{
    /// <summary>The <c>StatusDeterminationApproach</c> URI naming the EU "appropriate" approach (schema clause 5.3.8).</summary>
    private const string EuAppropriateStatusDeterminationApproach = "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate";

    /// <summary>
    /// The default <see cref="QualificationElement.Condition"/>: a Key Usage <c>nonRepudiation</c> assertion
    /// (clause 5.5.9.2.2.1), matched by every certificate <see cref="QualifiedCertificateMinting.MintQualifiedCertificateAsync"/>
    /// mints — that surface always writes <c>KeyUsage{nonRepudiation}</c>, critical, independent of the
    /// declared <see cref="EuQualifiedCertificateType"/>.
    /// </summary>
    public static CriteriaListCondition DefaultIdentifyingCondition { get; } = new(
        QualifierAssertion.All,
        description: null,
        children: [new KeyUsageCondition([new KeyUsageBitAssertion(KeyUsageBitName.NonRepudiation, Asserted: true)])]);


    /// <summary>
    /// Composes a <see cref="TrustedList"/> whose single Certification Authority service confirms
    /// <paramref name="certificationAuthorityCertificate"/> as Granted for <paramref name="qualificationDimension"/>,
    /// from <paramref name="notBefore"/> on — see the type remarks for exactly which fields this wires from
    /// the procedure's own requirements versus filling with a minimal placeholder.
    /// </summary>
    /// <param name="certificationAuthorityCertificate">The minted CA certificate the service recognises. The caller retains ownership; its bytes are copied into the returned graph.</param>
    /// <param name="qualificationDimension">The certificate type dimension the composed service confirms (<see cref="EuQualifiedCertificateType.ElectronicSignature"/>, <see cref="EuQualifiedCertificateType.ElectronicSeal"/>, or <see cref="EuQualifiedCertificateType.WebsiteAuthentication"/>).</param>
    /// <param name="providerNames">The Trust Service Provider's legal name, one entry per language — matched against a certificate's issuer <c>organizationName</c> under PRO-4.4.4-06.</param>
    /// <param name="issuerCountryCode">The CA's own <c>countryName</c> attribute value, resolved to the scheme territory with <see cref="TrustedListQualification.ResolveTrustedListTerritory"/>.</param>
    /// <param name="notBefore">The instant the composed service's Granted state starts covering — typically a leaf certificate's own <c>notBefore</c>, so PRO-4.4.4-34's re-determination at that instant is covered.</param>
    /// <param name="pool">The memory pool the certificate copy is rented from.</param>
    /// <param name="identifyingCondition">The composed <see cref="QualificationElement"/>'s criteria, or <see langword="null"/> for <see cref="DefaultIdentifyingCondition"/>.</param>
    /// <returns>The composed trusted list. The caller owns it and disposes it, which disposes the copied certificate.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="certificationAuthorityCertificate"/>, <paramref name="providerNames"/>, <paramref name="issuerCountryCode"/>, or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentException">When <paramref name="providerNames"/> is empty (PRO-4.4.4-06 has no name to match the certificate's issuer against), or <paramref name="qualificationDimension"/> is <see cref="EuQualifiedCertificateType.None"/> (Table 1/2/3 has no row for it).</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the copied certificate transfers to the returned TrustedList's provider/service/digital-identity graph, disposed through TrustedList.Dispose.")]
    public static TrustedList ComposeQualifiedTrustedList(
        PkiCertificateMemory certificationAuthorityCertificate,
        EuQualifiedCertificateType qualificationDimension,
        IReadOnlyList<LocalizedText> providerNames,
        string issuerCountryCode,
        DateTimeOffset notBefore,
        BaseMemoryPool pool,
        CriteriaListCondition? identifyingCondition = null)
    {
        ArgumentNullException.ThrowIfNull(certificationAuthorityCertificate);
        ArgumentNullException.ThrowIfNull(providerNames);
        ArgumentNullException.ThrowIfNull(issuerCountryCode);
        ArgumentNullException.ThrowIfNull(pool);
        if(providerNames.Count == 0)
        {
            throw new ArgumentException("PRO-4.4.4-06: the composed provider needs at least one name to match a certificate's issuer organizationName against.", nameof(providerNames));
        }

        (TrustServiceAdditionalInformationType informationType, ServiceQualifier typeQualifier) = ResolveDimension(qualificationDimension);

        PkiCertificateMemory copiedCertificate = CAdESSignatureFacts.Copy(certificationAuthorityCertificate.AsReadOnlyMemory(), PkiCertificateTags.X509Certificate, pool);
        try
        {
            var service = new TrustService
            {
                ServiceTypeIdentifier = TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates,
                ServiceNames = [new LocalizedText("en", "Qualified certificate issuance service")],
                DigitalIdentity = new ServiceDigitalIdentity { Entries = [new X509CertificateIdentity(copiedCertificate)] },
                Status = TrustServiceStatus.Granted,
                StatusStartingTime = notBefore,
                AdditionalServiceInformation = [informationType],
                Qualifications =
                [
                    new QualificationElement
                    {
                        Qualifiers = [ServiceQualifier.QualifiedCertificateStatement, typeQualifier],
                        Condition = identifyingCondition ?? DefaultIdentifyingCondition,
                        IsCritical = false
                    }
                ]
            };

            var provider = new TrustServiceProvider
            {
                Names = providerNames,
                PostalAddresses = [],
                ElectronicAddresses = [],
                InformationUris = [],
                Services = [service]
            };

            return new TrustedList
            {
                SchemeInformation = new TrustedListSchemeInformation
                {
                    //TS 119 612 is not pulled; 6 matches the value this repo's own TS 119 612 V2.4.1-anchored
                    //fixtures (TrustedListQualificationTests, SignatureApplicabilityRulesTests,
                    //QualifiedCertificateFactsExtractorTests) already carry, pending a pulled-spec citation.
                    TslVersionIdentifier = 6,
                    TslSequenceNumber = 1,
                    TslType = TrustedListKind.Generic,
                    SchemeOperatorNames = [],
                    SchemeOperatorPostalAddresses = [],
                    SchemeOperatorElectronicAddresses = [],
                    SchemeNames = [],
                    SchemeInformationUris = [],
                    StatusDeterminationApproach = EuAppropriateStatusDeterminationApproach,
                    SchemeTerritory = TrustedListQualification.ResolveTrustedListTerritory(issuerCountryCode),
                    HistoricalInformationPeriodYears = 5,
                    ListIssueDateTime = notBefore
                },
                TrustServiceProviders = [provider]
            };
        }
        catch
        {
            copiedCertificate.Dispose();

            throw;
        }
    }


    /// <summary>Maps a dimension to the additional-service-information type and service qualifier Table 1/2/3 (clause 4.4.4) key its column selection on.</summary>
    private static (TrustServiceAdditionalInformationType InformationType, ServiceQualifier TypeQualifier) ResolveDimension(EuQualifiedCertificateType qualificationDimension) => qualificationDimension switch
    {
        EuQualifiedCertificateType.ElectronicSignature => (TrustServiceAdditionalInformationType.ForElectronicSignatures, ServiceQualifier.ForElectronicSignature),
        EuQualifiedCertificateType.ElectronicSeal => (TrustServiceAdditionalInformationType.ForElectronicSeals, ServiceQualifier.ForElectronicSeal),
        EuQualifiedCertificateType.WebsiteAuthentication => (TrustServiceAdditionalInformationType.ForWebSiteAuthentication, ServiceQualifier.ForWebSiteAuthentication),
        _ => throw new ArgumentException("Clause 4.4.4's Tables 1/2/3 have no row for EuQualifiedCertificateType.None.", nameof(qualificationDimension))
    };
}
