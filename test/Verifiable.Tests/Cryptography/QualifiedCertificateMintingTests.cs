using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Numerics;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.QualifiedCertificateMintingFixtures;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="QualifiedCertificateMinting"/>: the roundtrip spine — mint each chain
/// profile through the minter's own <see cref="AsnWriter"/>-and-registry path, then read it back with the
/// independent <see cref="QualifiedCertificateFactsExtractor"/> walk and assert the facts equal the mint
/// inputs field-exactly — and the refusing negative for every enforced issuance-profile rule the minter
/// checks at call time (see <see cref="QualifiedCertificateMinting"/>'s own remarks for the full
/// enforced-vs-unrepresentable split). Every subject/issuer key pair comes from
/// <see cref="QualifiedCertificateMintingFixtures.CreateP256KeyPair"/> — the project's own P-256 provider,
/// never <c>System.Security.Cryptography</c> directly — normalized to the uncompressed SEC1 point
/// <see cref="QualifiedCertificateMinting.MintCertificateAsync(CertificateMintRequest, PrivateKeyMemory, BaseMemoryPool, CancellationToken)"/>
/// writes into <c>subjectPublicKeyInfo</c> verbatim.
/// </summary>
[TestClass]
internal sealed class QualifiedCertificateMintingTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The root's validity start.</summary>
    private static DateTimeOffset RootNotBefore { get; } = new(2025, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The root's validity end.</summary>
    private static DateTimeOffset RootNotAfter { get; } = new(2035, 1, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The validity start every intermediate and leaf in this file mints under.</summary>
    private static DateTimeOffset LeafNotBefore { get; } = new(2025, 6, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>The validity end every intermediate and leaf in this file mints under.</summary>
    private static DateTimeOffset LeafNotAfter { get; } = new(2027, 6, 1, 0, 0, 0, TimeSpan.Zero);

    /// <summary>A clause 5.3 item c) policy identifier stand-in (QCP-n-qscd), for the esign leaf's CertificatePolicies extension.</summary>
    private const string NaturalPersonQscdPolicyOid = "0.4.0.194112.1.2";

    /// <summary>A clause 5.3 item d) policy identifier stand-in (QCP-l-qscd), for the eseal leaf's CertificatePolicies extension.</summary>
    private const string LegalPersonQscdPolicyOid = "0.4.0.194112.1.3";

    /// <summary>
    /// A clause 5.3 item e) policy identifier stand-in (QEVCP-w — clause 3.3's abbreviations note reads
    /// "Previous versions of the present document used the abbreviation QCP-w"), for the
    /// website-authentication leaf's CertificatePolicies extension.
    /// </summary>
    private const string WebsiteAuthenticationPolicyOid = "0.4.0.194112.1.4";

    /// <summary>
    /// A TSP-allocated policy identifier stand-in for the "OID as specified in EVCG [i.7], clause 7.1.6.1"
    /// GEN-6.6.1-05's [QEVCP-w] bullet requires alongside <see cref="WebsiteAuthenticationPolicyOid"/> (EVCG
    /// is not among this repository's pulled specs, so this is a placeholder OID, not the EVCG one itself).
    /// </summary>
    private const string WebsiteAuthenticationEvcgPolicyOid = "1.3.6.1.4.1.99999.1.1";

    /// <summary>An OID this library recognises as none of the seven clause 5.3 policy identifiers — a TSP-allocated stand-in for GEN-6.6.1-07's unconstrained case.</summary>
    private const string TspAllocatedOnlyPolicyOid = "1.3.6.1.4.1.99999.2.1";


    /// <summary>
    /// A minted self-signed root Certification Authority extracts field-exactly: its own name read back as
    /// both issuer and subject, the <c>notBefore</c> instant, and the critical
    /// <c>KeyUsage{keyCertSign, cRLSign}</c> bits <see cref="QualifiedCertificateMinting.MintRootCertificateAuthorityAsync"/>
    /// writes per <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.3">RFC 5280 §4.2.1.3</see>.
    /// No <c>qcStatements</c> or <c>CertificatePolicies</c> extension is written, so those facts read absent —
    /// the root is not itself a qualified certificate.
    /// </summary>
    [TestMethod]
    public async Task RootCertificateAuthorityFactsRoundTripFieldExactly()
    {
        const string CountryCode = "FI";
        const string OrganizationName = "Verifiable Root Provider";
        const string CommonName = "Verifiable Test Root CA";

        (PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = CreateP256KeyPair();
        IReadOnlyList<IReadOnlyList<DirectoryNameAttribute>> subjectName = CreateSubjectName(CountryCode, OrganizationName, CommonName);
        using PkiCertificateMemory root = await QualifiedCertificateMinting.MintRootCertificateAuthorityAsync(
            subjectName, RootNotBefore, RootNotAfter, publicKey, privateKey, pathLengthConstraint: 2, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        publicKey.Dispose();
        privateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(root);

        Assert.AreEqual(CountryCode, facts.IssuerCountryCode, "A self-signed root's issuer countryName equals its own subject countryName.");
        Assert.AreSequenceEqual([OrganizationName], facts.IssuerOrganizationNames);
        Assert.AreSequenceEqual([CommonName], facts.IssuerCommonNames);
        Assert.AreEqual(CountryCode, facts.SubjectCountryCode);
        Assert.AreSequenceEqual([OrganizationName], facts.SubjectOrganizationNames);
        Assert.AreEqual(RootNotBefore, facts.NotBefore, "The notBefore instant must round-trip exactly through UTCTime encoding.");
        Assert.IsFalse(facts.HasQcCompliance, "A root Certification Authority certificate is not itself a qualified certificate.");
        Assert.IsEmpty(facts.QcTypes);
        Assert.IsFalse(facts.HasCertificatePoliciesExtension, "MintRootCertificateAuthorityAsync writes no CertificatePolicies extension.");
        Assert.IsTrue(facts.HasKeyUsageExtension);
        Assert.AreSequenceEqual([KeyUsageBitName.KeyCertSign, KeyUsageBitName.CrlSign], facts.SetKeyUsageBits, "RFC 5280 §4.2.1.9's CA signing bits, ascending.");
        Assert.IsFalse(facts.HasExtendedKeyUsageExtension);
        Assert.AreSequenceEqual([WellKnownOids.CountryName, WellKnownOids.OrganizationName, WellKnownOids.CommonName], facts.SubjectAttributeTypeOids);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5">RFC 5280 §4.1.2.5</see>: "CAs
    /// conforming to this profile MUST always encode certificate validity dates through the year 2049 as
    /// UTCTime[.] Certificate validity dates in 2050 or later MUST be encoded as GeneralizedTime." A
    /// <c>notBefore</c> supplied with a non-UTC offset, whose UTC instant is still in 2049, still round-trips
    /// exactly through <see cref="QualifiedCertificateMinting"/>'s UTCTime branch.
    /// </summary>
    [TestMethod]
    public async Task RootCertificateAuthorityNotBeforeRoundTripsExactlyWhenSuppliedWithNonUtcOffsetInPivotYear()
    {
        DateTimeOffset notBefore = new(2049, 12, 31, 23, 0, 0, TimeSpan.FromHours(2));
        DateTimeOffset notAfter = notBefore.AddYears(1);

        (PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = CreateP256KeyPair();
        using PkiCertificateMemory root = await QualifiedCertificateMinting.MintRootCertificateAuthorityAsync(
            CreateSubjectName("FI", "Verifiable Root Provider", "Verifiable Test Root CA"), notBefore, notAfter,
            publicKey, privateKey, pathLengthConstraint: 2, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        publicKey.Dispose();
        privateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(root);

        Assert.AreEqual(notBefore, facts.NotBefore);
    }


    /// <summary>
    /// The same RFC 5280 §4.1.2.5 pivot, at the boundary that distinguishes a UTC-based decision from a
    /// local-offset-based one: the caller's own calendar date is already 2050-01-01, but the UTC instant it
    /// names is still 2049-12-31T23:00:00Z — one hour short of the GeneralizedTime pivot —
    /// <see cref="QualifiedCertificateMinting"/> pivots on <c>notBefore.ToUniversalTime().Year</c>, not the
    /// caller's own offset-relative calendar year, so this still round-trips through UTCTime.
    /// </summary>
    [TestMethod]
    public async Task RootCertificateAuthorityNotBeforeRoundTripsExactlyWhenLocalCalendarYearIsPastPivotButUtcInstantIsNot()
    {
        DateTimeOffset notBefore = new(2050, 1, 1, 1, 0, 0, TimeSpan.FromHours(2));
        DateTimeOffset notAfter = notBefore.AddYears(1);

        (PublicKeyMemory publicKey, PrivateKeyMemory privateKey) = CreateP256KeyPair();
        using PkiCertificateMemory root = await QualifiedCertificateMinting.MintRootCertificateAuthorityAsync(
            CreateSubjectName("FI", "Verifiable Root Provider", "Verifiable Test Root CA"), notBefore, notAfter,
            publicKey, privateKey, pathLengthConstraint: 2, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        publicKey.Dispose();
        privateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(root);

        Assert.AreEqual(notBefore, facts.NotBefore);
    }


    /// <summary>
    /// A minted intermediate Certification Authority extracts field-exactly: its issuer name equal to the
    /// root's own subject (RFC 5280 §4.1.2.4's issuer/subject chaining), its own subject name, and the
    /// critical <c>KeyUsage{keyCertSign, cRLSign}</c> bits <see cref="QualifiedCertificateMinting.MintIntermediateCertificateAuthorityAsync"/>
    /// writes — the same shape as the root, minus self-signature.
    /// </summary>
    [TestMethod]
    public async Task IntermediateCertificateAuthorityFactsRoundTripFieldExactly()
    {
        const string RootCountryCode = "FI";
        const string RootOrganizationName = "Verifiable Root Provider";
        const string RootCommonName = "Verifiable Test Root CA";
        const string IntermediateOrganizationName = "Verifiable Intermediate Provider";
        const string IntermediateCommonName = "Verifiable Test Intermediate CA";

        (PublicKeyMemory rootPublicKey, PrivateKeyMemory rootPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory root = await QualifiedCertificateMinting.MintRootCertificateAuthorityAsync(
            CreateSubjectName(RootCountryCode, RootOrganizationName, RootCommonName), RootNotBefore, RootNotAfter, rootPublicKey, rootPrivateKey,
            pathLengthConstraint: 2, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        rootPublicKey.Dispose();

        (PublicKeyMemory intermediatePublicKey, PrivateKeyMemory intermediatePrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory intermediate = await QualifiedCertificateMinting.MintIntermediateCertificateAuthorityAsync(
            root, CreateSubjectName(RootCountryCode, IntermediateOrganizationName, IntermediateCommonName), LeafNotBefore, LeafNotAfter,
            intermediatePublicKey, rootPrivateKey, pathLengthConstraint: 0, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        intermediatePublicKey.Dispose();
        rootPrivateKey.Dispose();
        intermediatePrivateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(intermediate);

        Assert.AreEqual(RootCountryCode, facts.IssuerCountryCode);
        Assert.AreSequenceEqual([RootOrganizationName], facts.IssuerOrganizationNames, "The issuer field is the root's own subject, copied verbatim.");
        Assert.AreSequenceEqual([RootCommonName], facts.IssuerCommonNames);
        Assert.AreEqual(RootCountryCode, facts.SubjectCountryCode);
        Assert.AreSequenceEqual([IntermediateOrganizationName], facts.SubjectOrganizationNames);
        Assert.AreEqual(LeafNotBefore, facts.NotBefore);
        Assert.IsFalse(facts.HasQcCompliance);
        Assert.IsFalse(facts.HasCertificatePoliciesExtension);
        Assert.IsTrue(facts.HasKeyUsageExtension);
        Assert.AreSequenceEqual([KeyUsageBitName.KeyCertSign, KeyUsageBitName.CrlSign], facts.SetKeyUsageBits);
        Assert.IsFalse(facts.HasExtendedKeyUsageExtension);
    }


    /// <summary>
    /// A minted electronic-signature qualified certificate extracts field-exactly across the full clause 4.3
    /// generic-statement house — <c>QcLimitValue</c> (clause 4.3.2, alphabetic <c>Iso4217CurrencyCode</c>
    /// alternative), <c>QcRetentionPeriod</c> (clause 4.3.3), <c>QcPDS</c> (clause 4.3.4, two locations),
    /// <c>QcIdentMethod</c> (clause 4.3.5) and <c>QcQSCDlegislation</c> (clause 4.2.5) — alongside the
    /// mandatory <c>QcCompliance</c>/<c>QcType</c> and the <c>QcSSCD</c> statement EN 319 411-2
    /// GEN-6.6.1-03 requires when the certificate is issued under a QSCD-flavoured policy.
    /// </summary>
    [TestMethod]
    public async Task ElectronicSignatureQualifiedCertificateFactsRoundTripFieldExactly()
    {
        (PkiCertificateMemory issuer, PrivateKeyMemory issuerKey) = await MintIssuingAuthorityAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory issuerCertificate = issuer;
        using PrivateKeyMemory issuerPrivateKey = issuerKey;

        const string LeafCountryCode = "FI";
        const string LeafOrganizationName = "Verifiable QC Provider";
        const string LeafCommonName = "Alice Esign";
        var limitValue = new QcMonetaryValue("EUR", null, 1000, 2);
        var pdsLocations = new List<PdsLocation> { new("https://pds.example/en", "en"), new("https://pds.example/fi", "fi") };
        var identificationMethod = EuIdentityVerificationMethod.Eidas1Ab;
        var qscdLegislationCountryCodes = new List<string> { "CH" };
        var additionalStatements = new QualifiedCertificateStatements
        {
            LimitValue = limitValue,
            RetentionPeriodYears = 10,
            PdsLocations = pdsLocations,
            IdentificationMethod = identificationMethod,
            QscdLegislationCountryCodes = qscdLegislationCountryCodes
        };

        (PublicKeyMemory leafPublicKey, PrivateKeyMemory leafPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory leaf = await QualifiedCertificateMinting.MintQualifiedCertificateAsync(
            issuerCertificate, CreateSubjectName(LeafCountryCode, LeafOrganizationName, LeafCommonName), LeafNotBefore, LeafNotAfter,
            leafPublicKey, issuerPrivateKey, EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: true,
            certificatePolicyOids: [NaturalPersonQscdPolicyOid], additionalStatements, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        leafPublicKey.Dispose();
        leafPrivateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(leaf);

        Assert.AreEqual(LeafCountryCode, facts.SubjectCountryCode);
        Assert.AreSequenceEqual([LeafOrganizationName], facts.SubjectOrganizationNames);
        Assert.AreEqual(LeafNotBefore, facts.NotBefore);
        Assert.IsTrue(facts.HasQcCompliance, "esi4-qcStatement-1 (QcCompliance) is always written.");
        Assert.AreSequenceEqual([EuQualifiedCertificateType.ElectronicSignature], facts.QcTypes);
        Assert.IsTrue(facts.HasQcSscdStatement, "GEN-6.6.1-03: a QCP-n-qscd certificate must carry QcSSCD.");
        Assert.AreEqual(limitValue, facts.QcLimitValue, "QcMonetaryValue is a value-equality record shared by the mint input model and the read-side facts.");
        Assert.AreEqual((BigInteger)10, facts.QcRetentionPeriodYears);
        Assert.AreSequenceEqual(pdsLocations, facts.QcPdsLocations);
        Assert.AreSequenceEqual([identificationMethod], facts.QcIdentityVerificationMethods);
        Assert.AreSequenceEqual(qscdLegislationCountryCodes, facts.QcQscdLegislationCountryCodes);
        Assert.IsEmpty(facts.QcCcLegislationCountryCodes, "QCS-4.2.1-01 a): QcCClegislation is never reachable alongside the always-written QcCompliance.");
        Assert.IsTrue(facts.HasCertificatePoliciesExtension);
        Assert.AreSequenceEqual([NaturalPersonQscdPolicyOid], facts.CertificatePolicyOids);
        Assert.IsTrue(facts.HasKeyUsageExtension);
        Assert.AreSequenceEqual([KeyUsageBitName.NonRepudiation], facts.SetKeyUsageBits);
        Assert.IsFalse(facts.HasExtendedKeyUsageExtension);
    }


    /// <summary>
    /// A minted electronic-seal qualified certificate extracts field-exactly, exercising the numeric
    /// <c>Iso4217CurrencyCode</c> CHOICE alternative of <c>QcLimitValue</c> (clause 4.3.2) and the single
    /// <c>QcIdentMethod</c> value <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
    /// ETSI EN 319 412-5 V2.6.1</see> Annex B's <c>QcIdentMethod ::= SEQUENCE SIZE (1) OF OBJECT IDENTIFIER</c>
    /// (clause 4.3.5.1) allows, alongside <c>QcSSCD</c> under a QCP-l-qscd policy.
    /// </summary>
    [TestMethod]
    public async Task ElectronicSealQualifiedCertificateFactsRoundTripFieldExactly()
    {
        (PkiCertificateMemory issuer, PrivateKeyMemory issuerKey) = await MintIssuingAuthorityAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory issuerCertificate = issuer;
        using PrivateKeyMemory issuerPrivateKey = issuerKey;

        const string LeafCountryCode = "FI";
        const string LeafOrganizationName = "Verifiable QC Provider";
        const string LeafCommonName = "Acme Seal";
        var limitValue = new QcMonetaryValue(null, 978, 500, 0);
        var identificationMethod = EuIdentityVerificationMethod.Eidas2Acd;
        var qscdLegislationCountryCodes = new List<string> { "CH", "US" };
        var additionalStatements = new QualifiedCertificateStatements
        {
            LimitValue = limitValue,
            IdentificationMethod = identificationMethod,
            QscdLegislationCountryCodes = qscdLegislationCountryCodes
        };

        (PublicKeyMemory leafPublicKey, PrivateKeyMemory leafPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory leaf = await QualifiedCertificateMinting.MintQualifiedCertificateAsync(
            issuerCertificate, CreateSubjectName(LeafCountryCode, LeafOrganizationName, LeafCommonName), LeafNotBefore, LeafNotAfter,
            leafPublicKey, issuerPrivateKey, EuQualifiedCertificateType.ElectronicSeal, requiresQualifiedSignatureCreationDevice: true,
            certificatePolicyOids: [LegalPersonQscdPolicyOid], additionalStatements, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        leafPublicKey.Dispose();
        leafPrivateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(leaf);

        Assert.AreSequenceEqual([EuQualifiedCertificateType.ElectronicSeal], facts.QcTypes);
        Assert.IsTrue(facts.HasQcSscdStatement);
        Assert.AreEqual(limitValue, facts.QcLimitValue, "The numeric Iso4217CurrencyCode alternative round-trips field-exactly.");
        Assert.IsNull(facts.QcRetentionPeriodYears, "QcRetentionPeriod was omitted from this leaf's additional statements.");
        Assert.IsEmpty(facts.QcPdsLocations);
        Assert.AreSequenceEqual([identificationMethod], facts.QcIdentityVerificationMethods);
        Assert.AreSequenceEqual(qscdLegislationCountryCodes, facts.QcQscdLegislationCountryCodes);
        Assert.AreSequenceEqual([LegalPersonQscdPolicyOid], facts.CertificatePolicyOids);
        Assert.AreSequenceEqual([KeyUsageBitName.NonRepudiation], facts.SetKeyUsageBits);
    }


    /// <summary>
    /// A minted website-authentication qualified certificate — the profile GEN-6.6.1-04 forbids from ever
    /// carrying <c>QcSSCD</c> — extracts field-exactly with no clause 4.3 generic statements at all: only the
    /// mandatory <c>QcCompliance</c>/<c>QcType</c> pair and a <c>CertificatePolicies</c> extension satisfying
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
    /// ETSI EN 319 411-2 V2.6.1</see> GEN-6.6.1-05's [QEVCP-w] conjunction — the clause 5.3 item e) identifier
    /// alongside a second, EVCG-placeholder policy OID, since <see cref="QualifiedCertificateMinting.WriteCertificatePoliciesExtension"/>
    /// refuses the clause 5.3 identifier standing alone.
    /// </summary>
    [TestMethod]
    public async Task WebsiteAuthenticationQualifiedCertificateFactsRoundTripFieldExactly()
    {
        (PkiCertificateMemory issuer, PrivateKeyMemory issuerKey) = await MintIssuingAuthorityAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory issuerCertificate = issuer;
        using PrivateKeyMemory issuerPrivateKey = issuerKey;

        const string LeafCommonName = "verifiable.example";

        (PublicKeyMemory leafPublicKey, PrivateKeyMemory leafPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory leaf = await QualifiedCertificateMinting.MintQualifiedCertificateAsync(
            issuerCertificate, CreateSubjectName("FI", "Verifiable QC Provider", LeafCommonName), LeafNotBefore, LeafNotAfter,
            leafPublicKey, issuerPrivateKey, EuQualifiedCertificateType.WebsiteAuthentication, requiresQualifiedSignatureCreationDevice: false,
            certificatePolicyOids: [WebsiteAuthenticationPolicyOid, WebsiteAuthenticationEvcgPolicyOid], additionalStatements: null, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        leafPublicKey.Dispose();
        leafPrivateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(leaf);

        Assert.AreSequenceEqual([WellKnownOids.CountryName, WellKnownOids.OrganizationName, WellKnownOids.CommonName], facts.SubjectAttributeTypeOids, "The commonName attribute (the DNS name) is recorded among the subject's attribute types; the record models no dedicated SubjectCommonNames fact.");
        Assert.IsTrue(facts.HasQcCompliance);
        Assert.AreSequenceEqual([EuQualifiedCertificateType.WebsiteAuthentication], facts.QcTypes);
        Assert.IsFalse(facts.HasQcSscdStatement, "GEN-6.6.1-04: website authentication has no QSCD-flavoured clause 5.3 policy.");
        Assert.IsNull(facts.QcLimitValue);
        Assert.IsNull(facts.QcRetentionPeriodYears);
        Assert.IsEmpty(facts.QcPdsLocations);
        Assert.IsEmpty(facts.QcIdentityVerificationMethods);
        Assert.IsEmpty(facts.QcQscdLegislationCountryCodes);
        Assert.AreSequenceEqual([WebsiteAuthenticationPolicyOid, WebsiteAuthenticationEvcgPolicyOid], facts.CertificatePolicyOids);
        Assert.AreSequenceEqual([KeyUsageBitName.NonRepudiation], facts.SetKeyUsageBits);
    }


    /// <summary>
    /// A minted Time-Stamping Authority certificate extracts field-exactly: <c>KeyUsage{digitalSignature,
    /// nonRepudiation}</c> critical and a critical <c>ExtendedKeyUsage</c> carrying only
    /// <c>id-kp-timeStamping</c> — the single-critical-EKU shape
    /// <see href="https://www.rfc-editor.org/rfc/rfc3161#section-2.3">RFC 3161 §2.3</see> requires of the
    /// certificate a time-stamp token's signature is verified with. No <c>qcStatements</c> or
    /// <c>CertificatePolicies</c> extension is written.
    /// </summary>
    [TestMethod]
    public async Task TimeStampingAuthorityCertificateFactsRoundTripFieldExactly()
    {
        (PkiCertificateMemory issuer, PrivateKeyMemory issuerKey) = await MintIssuingAuthorityAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory issuerCertificate = issuer;
        using PrivateKeyMemory issuerPrivateKey = issuerKey;

        const string LeafCommonName = "Verifiable Test TSA";

        (PublicKeyMemory leafPublicKey, PrivateKeyMemory leafPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory tsa = await QualifiedCertificateMinting.MintTimeStampingAuthorityCertificateAsync(
            issuerCertificate, CreateSubjectName("FI", "Verifiable TSA Provider", LeafCommonName), LeafNotBefore, LeafNotAfter,
            leafPublicKey, issuerPrivateKey, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        leafPublicKey.Dispose();
        leafPrivateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(tsa);

        Assert.IsFalse(facts.HasQcCompliance);
        Assert.IsFalse(facts.HasCertificatePoliciesExtension);
        Assert.IsTrue(facts.HasKeyUsageExtension);
        Assert.AreSequenceEqual([KeyUsageBitName.DigitalSignature, KeyUsageBitName.NonRepudiation], facts.SetKeyUsageBits);
        Assert.IsTrue(facts.HasExtendedKeyUsageExtension);
        Assert.AreSequenceEqual(["1.3.6.1.5.5.7.3.8"], facts.ExtendedKeyUsageOids, "id-kp-timeStamping, and only id-kp-timeStamping (RFC 3161 §2.3).");
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
    /// ETSI EN 319 412-5 V2.6.1</see> clause 4.2.3: "QcType::= SEQUENCE SIZE (1) OF OBJECT IDENTIFIER" declares
    /// that a certificate is issued as exactly one of electronic signature, electronic seal or website
    /// authentication; <see cref="EuQualifiedCertificateType.None"/> names none, so the writer refuses it.
    /// </summary>
    [TestMethod]
    public void WriteQcStatementsExtensionRefusesUndeclaredCertificateType()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.None, requiresQualifiedSignatureCreationDevice: false, additionalStatements: null, BaseMemoryPool.Shared));

        Assert.Contains("4.2.3", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
    /// ETSI EN 319 411-2 V2.6.1</see> GEN-6.6.1-04: "The qcStatement for QSCD (esi4-qcStatement-4) shall not
    /// be included in certificates that are not issued according to [QCP-n-qscd] or [QCP-l-qscd]
    /// requirements" — website authentication has no QSCD-flavoured clause 5.3 policy, so the combination is
    /// always refused regardless of the caller's intent.
    /// </summary>
    [TestMethod]
    public void WriteQcStatementsExtensionRefusesQscdOnWebsiteAuthentication()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.WebsiteAuthentication, requiresQualifiedSignatureCreationDevice: true, additionalStatements: null, BaseMemoryPool.Shared));

        Assert.Contains("GEN-6.6.1-04", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
    /// ETSI EN 319 412-5 V2.6.1</see> clause 4.3.2's <c>Iso4217CurrencyCode ::= CHOICE { alphabetic
    /// PrintableString (SIZE (3)), numeric INTEGER (1..999) }</c> is a CHOICE: exactly one alternative may be
    /// populated (QCS-4.1-04 gives Annex B's ASN.1 precedence over the body text). Neither alternative set is
    /// refused.
    /// </summary>
    [TestMethod]
    public void WriteQcStatementsExtensionRefusesAmbiguousMonetaryValueCurrencyChoice()
    {
        var statements = new QualifiedCertificateStatements { LimitValue = new QcMonetaryValue(null, null, 100, 0) };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: false, statements, BaseMemoryPool.Shared));

        Assert.Contains("4.3.2", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// The same clause 4.3.2 <c>Iso4217CurrencyCode</c> syntax, its alphabetic alternative's shape:
    /// <c>PrintableString (SIZE (3))</c> — a two- or four-character alphabetic currency code is refused.
    /// </summary>
    [TestMethod]
    [DataRow("US", DisplayName = "a two-character alphabetic currency code")]
    [DataRow("EURO", DisplayName = "a four-character alphabetic currency code")]
    public void WriteQcStatementsExtensionRefusesNonThreeCharacterAlphabeticCurrencyCode(string alphabeticCurrencyCode)
    {
        var statements = new QualifiedCertificateStatements { LimitValue = new QcMonetaryValue(alphabeticCurrencyCode, null, 100, 0) };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: false, statements, BaseMemoryPool.Shared));

        Assert.Contains("PrintableString (SIZE (3))", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// The same clause 4.3.2 <c>Iso4217CurrencyCode</c> syntax, its numeric alternative's range:
    /// <c>INTEGER (1..999)</c> — the value one below the lower bound and the value one above the upper bound
    /// are each refused.
    /// </summary>
    [TestMethod]
    [DataRow(0, DisplayName = "one below the INTEGER (1..999) lower bound")]
    [DataRow(1000, DisplayName = "one above the INTEGER (1..999) upper bound")]
    public void WriteQcStatementsExtensionRefusesOutOfRangeNumericCurrencyCode(int numericCurrencyCode)
    {
        var statements = new QualifiedCertificateStatements { LimitValue = new QcMonetaryValue(null, numericCurrencyCode, 100, 0) };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: false, statements, BaseMemoryPool.Shared));

        Assert.Contains("INTEGER (1..999)", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
    /// ETSI EN 319 412-5 V2.6.1</see> QCS-4.2.5-01: "CountryName shall not have as value any code identifying:
    /// a country of the European Union (EU); or a country of the European Economic Area (EEA); or a group of
    /// EU or EEA countries; or the value of 'EU'" — an EU member state code, an EEA (non-EU) member state
    /// code, the literal "EU", and an EU member state code compared case-insensitively are each refused with
    /// QCS-4.2.5-01, as is "EL" (the EU trusted-list territory code this library's own
    /// <see cref="TrustedListQualification.ResolveTrustedListTerritory"/> produces for Greece). A three-character
    /// code fails the clause 4.2.5 <c>CountryName ::= PrintableString (SIZE (2))</c> shape gate first, before
    /// QCS-4.2.5-01 is even reached.
    /// </summary>
    [TestMethod]
    [DataRow("FR", "QCS-4.2.5-01", DisplayName = "an EU member state code")]
    [DataRow("IS", "QCS-4.2.5-01", DisplayName = "an EEA (non-EU) member state code")]
    [DataRow("EU", "QCS-4.2.5-01", DisplayName = "the literal value 'EU'")]
    [DataRow("fr", "QCS-4.2.5-01", DisplayName = "an EU member state code, compared case-insensitively")]
    [DataRow("EL", "QCS-4.2.5-01", DisplayName = "the EU trusted-list territory code for Greece")]
    [DataRow("USA", "PrintableString (SIZE (2))", DisplayName = "a three-character code (clause 4.2.5's CountryName shape gate)")]
    public void WriteQcStatementsExtensionRefusesEuOrEeaQscdLegislationCountryCode(string countryCode, string expectedMessageSubstring)
    {
        var statements = new QualifiedCertificateStatements { QscdLegislationCountryCodes = [countryCode] };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: false, statements, BaseMemoryPool.Shared));

        Assert.Contains(expectedMessageSubstring, exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// QCS-4.3.4-01: "The language shall be the two character Set 1 code as defined in ISO 639" — a
    /// three-character language code is refused.
    /// </summary>
    [TestMethod]
    public void WriteQcStatementsExtensionRefusesNonTwoCharacterPdsLanguageCode()
    {
        var statements = new QualifiedCertificateStatements { PdsLocations = [new PdsLocation("https://pds.example/eng", "eng")] };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: false, statements, BaseMemoryPool.Shared));

        Assert.Contains("QCS-4.3.4-01", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// QCS-4.3.4-03: "As a minimum, a URL to a PDS provided in this statement shall use the 'https'
    /// (https://) scheme" — a plain <c>http://</c> location is refused.
    /// </summary>
    [TestMethod]
    public void WriteQcStatementsExtensionRefusesNonHttpsPdsUrl()
    {
        var statements = new QualifiedCertificateStatements { PdsLocations = [new PdsLocation("http://pds.example/en", "en")] };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: false, statements, BaseMemoryPool.Shared));

        Assert.Contains("QCS-4.3.4-03", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Table 2's <c>QcPDS</c> additional requirement condition a): "It shall provide at least one URL to a
    /// PDS in English" — a PDS location list with no English entry is refused.
    /// </summary>
    [TestMethod]
    public void WriteQcStatementsExtensionRefusesPdsLocationsWithoutEnglish()
    {
        var statements = new QualifiedCertificateStatements { PdsLocations = [new PdsLocation("https://pds.example/fi", "fi")] };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: false, statements, BaseMemoryPool.Shared));

        Assert.Contains("condition a)", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// Table 2's <c>QcPDS</c> additional requirement condition b): "It shall not reference more than one PDS
    /// per language" — two English-language locations are refused.
    /// </summary>
    [TestMethod]
    public void WriteQcStatementsExtensionRefusesDuplicateLanguagePdsLocations()
    {
        var statements = new QualifiedCertificateStatements
        {
            PdsLocations = [new PdsLocation("https://pds.example/en-1", "en"), new PdsLocation("https://pds.example/en-2", "en")]
        };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: false, statements, BaseMemoryPool.Shared));

        Assert.Contains("condition b)", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
    /// ETSI EN 319 411-2 V2.6.1</see> GEN-6.6.1-05: "The certificate shall include at least one of the
    /// following policy identifier [CHOICE]" — an empty policy identifier list is refused.
    /// </summary>
    [TestMethod]
    public void WriteCertificatePoliciesExtensionRefusesEmptyPolicyList()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteCertificatePoliciesExtension([], BaseMemoryPool.Shared));

        Assert.Contains("GEN-6.6.1-05", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
    /// ETSI EN 319 411-2 V2.6.1</see> GEN-6.6.1-05 [QEVCP-w]: "an OID as specified in EVCG [i.7], clause
    /// 7.1.6.1; and at least one of the following policy identifiers: as defined in clause 5.3 item e); and/or
    /// an OID allocated by the TSP" — the conjunction ("and") means the clause 5.3 item e) identifier
    /// (<see cref="WellKnownOids.QcpWeb"/>) alone, with no EVCG OID, does not satisfy [QEVCP-w].
    /// </summary>
    [TestMethod]
    public void WriteCertificatePoliciesExtensionRefusesQcpWebAlone()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteCertificatePoliciesExtension([WellKnownOids.QcpWeb], BaseMemoryPool.Shared));

        Assert.Contains("QEVCP-w", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
    /// ETSI EN 319 411-2 V2.6.1</see> GEN-6.6.1-05 [QNCP-w]: "an OID as specified in BRG [i.3], clause 1.2 or
    /// 7.1.6.1; and at least one of the following policy identifiers: as defined in clause 5.3 item f); and/or
    /// an OID allocated by the TSP" — the conjunction ("and") means the clause 5.3 item f) identifier
    /// (<see cref="WellKnownOids.QncpWeb"/>) alone, with no BRG OID, does not satisfy [QNCP-w].
    /// </summary>
    [TestMethod]
    public void WriteCertificatePoliciesExtensionRefusesQncpWebAlone()
    {
        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteCertificatePoliciesExtension([WellKnownOids.QncpWeb], BaseMemoryPool.Shared));

        Assert.Contains("QNCP-w", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">
    /// ETSI EN 319 412-5 V2.6.1</see> clause 4.3.5.1, QCS-4.3.5-02: "[CONDITIONAL] If this qcStatement is
    /// included in the certificate, it shall contain the OID value corresponding to the identification used
    /// for identity verification of the certificate" — a value naming none of the four EN 319 412-5
    /// identification methods is refused with the requirement key in the message, for an out-of-range value
    /// and for <see cref="EuIdentityVerificationMethod.None"/>.
    /// </summary>
    [TestMethod]
    [DataRow((EuIdentityVerificationMethod)99)]
    [DataRow(EuIdentityVerificationMethod.None)]
    public void WriteQcStatementsExtensionRefusesUndefinedIdentificationMethod(EuIdentityVerificationMethod undefinedMethod)
    {
        var statements = new QualifiedCertificateStatements { IdentificationMethod = undefinedMethod };

        ArgumentException exception = Assert.ThrowsExactly<ArgumentException>(
            () => QualifiedCertificateMinting.WriteQcStatementsExtension(
                EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: false, statements, BaseMemoryPool.Shared));

        Assert.Contains("QCS-4.3.5-02", exception.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
    /// ETSI EN 319 411-2 V2.6.1</see> GEN-6.6.1-03 [QCP-n-qscd] and [QCP-l-qscd]: "The certificate shall
    /// include the qcStatement for QSCD (esi4-qcStatement-4)" — a clause 5.3 item c) (QCP-n-qscd) policy
    /// identifier without <c>requiresQualifiedSignatureCreationDevice</c> set is refused by
    /// <see cref="QualifiedCertificateMinting.MintQualifiedCertificateAsync"/>'s own cross-check.
    /// </summary>
    [TestMethod]
    public async Task MintQualifiedCertificateAsyncRefusesQscdFlavouredPolicyWithoutDeviceFlag()
    {
        (PkiCertificateMemory issuer, PrivateKeyMemory issuerKey) = await MintIssuingAuthorityAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory issuerCertificate = issuer;
        using PrivateKeyMemory issuerPrivateKey = issuerKey;
        (PublicKeyMemory leafPublicKey, PrivateKeyMemory leafPrivateKey) = CreateP256KeyPair();
        try
        {
            ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
                QualifiedCertificateMinting.MintQualifiedCertificateAsync(
                    issuerCertificate, CreateSubjectName("FI", "Verifiable QC Provider", "Alice Esign"), LeafNotBefore, LeafNotAfter,
                    leafPublicKey, issuerPrivateKey, EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: false,
                    certificatePolicyOids: [NaturalPersonQscdPolicyOid], additionalStatements: null, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

            Assert.Contains("GEN-6.6.1-03", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            leafPublicKey.Dispose();
            leafPrivateKey.Dispose();
        }
    }


    /// <summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">
    /// ETSI EN 319 411-2 V2.6.1</see> GEN-6.6.1-04: "The qcStatement for QSCD (esi4-qcStatement-4) shall not
    /// be included in certificates that are not issued according to [QCP-n-qscd] or [QCP-l-qscd]
    /// requirements" — <c>requiresQualifiedSignatureCreationDevice</c> set alongside a clause 5.3 item a)
    /// (QCP-n, non-QSCD-flavoured) policy identifier is refused by
    /// <see cref="QualifiedCertificateMinting.MintQualifiedCertificateAsync"/>'s own cross-check.
    /// </summary>
    [TestMethod]
    public async Task MintQualifiedCertificateAsyncRefusesDeviceFlagUnderNonQscdFlavouredPolicy()
    {
        (PkiCertificateMemory issuer, PrivateKeyMemory issuerKey) = await MintIssuingAuthorityAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory issuerCertificate = issuer;
        using PrivateKeyMemory issuerPrivateKey = issuerKey;
        (PublicKeyMemory leafPublicKey, PrivateKeyMemory leafPrivateKey) = CreateP256KeyPair();
        try
        {
            ArgumentException exception = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
                QualifiedCertificateMinting.MintQualifiedCertificateAsync(
                    issuerCertificate, CreateSubjectName("FI", "Verifiable QC Provider", "Alice Esign"), LeafNotBefore, LeafNotAfter,
                    leafPublicKey, issuerPrivateKey, EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice: true,
                    certificatePolicyOids: [WellKnownOids.QcpNatural], additionalStatements: null, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).AsTask()).ConfigureAwait(false);

            Assert.Contains("GEN-6.6.1-04", exception.Message, StringComparison.Ordinal);
        }
        finally
        {
            leafPublicKey.Dispose();
            leafPrivateKey.Dispose();
        }
    }


    /// <summary>
    /// GEN-6.6.1-07 [CONDITIONAL]: "If the certificate contains only an OID allocated by the TSP, the
    /// referred certificate policy shall be built according to clause 7" — a policy set containing only a
    /// TSP-allocated identifier (one <see cref="QualifiedCertificateMinting"/> does not recognise as a clause
    /// 5.3 identifier) is unconstrained by the GEN-6.6.1-03/-04 cross-check: it mints under either device
    /// flag, and the resulting <c>QcSSCD</c> presence follows the flag exactly, not the policy set.
    /// </summary>
    [TestMethod]
    [DataRow(true, DisplayName = "requiresQualifiedSignatureCreationDevice = true")]
    [DataRow(false, DisplayName = "requiresQualifiedSignatureCreationDevice = false")]
    public async Task MintQualifiedCertificateAsyncMintsTspAllocatedOnlyPolicySetRegardlessOfDeviceFlag(bool requiresQualifiedSignatureCreationDevice)
    {
        (PkiCertificateMemory issuer, PrivateKeyMemory issuerKey) = await MintIssuingAuthorityAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using PkiCertificateMemory issuerCertificate = issuer;
        using PrivateKeyMemory issuerPrivateKey = issuerKey;

        (PublicKeyMemory leafPublicKey, PrivateKeyMemory leafPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory leaf = await QualifiedCertificateMinting.MintQualifiedCertificateAsync(
            issuerCertificate, CreateSubjectName("FI", "Verifiable QC Provider", "TSP Only"), LeafNotBefore, LeafNotAfter,
            leafPublicKey, issuerPrivateKey, EuQualifiedCertificateType.ElectronicSignature, requiresQualifiedSignatureCreationDevice,
            certificatePolicyOids: [TspAllocatedOnlyPolicyOid], additionalStatements: null, BaseMemoryPool.Shared, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        leafPublicKey.Dispose();
        leafPrivateKey.Dispose();

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(leaf);

        Assert.AreEqual(requiresQualifiedSignatureCreationDevice, facts.HasQcSscdStatement, "GEN-6.6.1-07: a TSP-allocated-only policy set is unconstrained by GEN-6.6.1-03/-04; QcSSCD presence follows the flag.");
        Assert.AreSequenceEqual([TspAllocatedOnlyPolicyOid], facts.CertificatePolicyOids);
    }


    /// <summary>Mints a root and an intermediate Certification Authority signed by it, for a leaf-minting test that needs an issuer.</summary>
    /// <returns>The intermediate's certificate and signing key. The caller owns and disposes both.</returns>
    private static async ValueTask<(PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey)> MintIssuingAuthorityAsync(CancellationToken cancellationToken)
    {
        (PublicKeyMemory rootPublicKey, PrivateKeyMemory rootPrivateKey) = CreateP256KeyPair();
        using PkiCertificateMemory root = await QualifiedCertificateMinting.MintRootCertificateAuthorityAsync(
            CreateSubjectName("FI", "Verifiable Root Provider", "Verifiable Test Root CA"), RootNotBefore, RootNotAfter,
            rootPublicKey, rootPrivateKey, pathLengthConstraint: 2, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);
        rootPublicKey.Dispose();

        (PublicKeyMemory intermediatePublicKey, PrivateKeyMemory intermediatePrivateKey) = CreateP256KeyPair();
        try
        {
            PkiCertificateMemory intermediate = await QualifiedCertificateMinting.MintIntermediateCertificateAuthorityAsync(
                root, CreateSubjectName("FI", "Verifiable Intermediate Provider", "Verifiable Test Intermediate CA"), LeafNotBefore, LeafNotAfter,
                intermediatePublicKey, rootPrivateKey, pathLengthConstraint: 0, BaseMemoryPool.Shared, cancellationToken: cancellationToken).ConfigureAwait(false);

            return (intermediate, intermediatePrivateKey);
        }
        finally
        {
            intermediatePublicKey.Dispose();
            rootPrivateKey.Dispose();
        }
    }
}
