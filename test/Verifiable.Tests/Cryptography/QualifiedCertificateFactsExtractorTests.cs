using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for <see cref="QualifiedCertificateFactsExtractor"/>, the shipped population of
/// <see cref="QualifiedCertificateFacts"/> from certificate DER. Minted certificates fix the expected
/// values by construction: names and qualified-certificate statements are encoded with
/// <see cref="AsnWriter"/> in exact DER order and the certificate is assembled and signed by the
/// platform's <see cref="CertificateRequest"/> encoder — a different code path from the extractor's
/// <see cref="AsnReader"/> walk. The capstone drives extracted facts through the shipped
/// <see cref="TrustedListQualification.DetermineEuQualifiedCertificateAsync"/> composition. Certificates
/// travel exclusively as <see cref="PkiCertificateMemory"/> carriers, minted into pooled memory and
/// disposed by each test.
/// </summary>
[TestClass]
internal sealed class QualifiedCertificateFactsExtractorTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The provider organization name shared by the minted issuer names and the trusted-list provider, so PRO-4.4.4-06 identifies the provider by <c>organizationName</c>.</summary>
    private const string ProviderOrganizationName = "Example Provider Oy";

    /// <summary>An example certificate policy identifier for policy-list extraction.</summary>
    private const string ExamplePolicyOid = "1.2.246.517.1.1";

    /// <summary>The <c>id-kp-clientAuth</c> extended key purpose per RFC 5280 §4.2.1.12.</summary>
    private const string ClientAuthenticationOid = "1.3.6.1.5.5.7.3.2";

    /// <summary>The <c>id-kp-emailProtection</c> extended key purpose per RFC 5280 §4.2.1.12.</summary>
    private const string EmailProtectionOid = "1.3.6.1.5.5.7.3.4";

    /// <summary>An identifier under the <c>id-etsi-qcs-QcType</c> arc that names no known certificate type.</summary>
    private const string UnknownQcTypeOid = "0.4.0.1862.1.6.99";

    /// <summary>An identifier under the <c>id-etsi-qcs-QcIdentMethod</c> arc that names no known identification method.</summary>
    private const string UnknownQcIdentMethodOid = "0.4.0.1862.1.8.99";

    /// <summary>An evaluation instant safely inside the Regulation regime.</summary>
    private static DateTimeOffset RegulationEvaluationTime { get; } = new(2024, 6, 1, 12, 0, 0, TimeSpan.Zero);

    /// <summary>The default minted validity start, safely inside the Regulation regime and before <see cref="RegulationEvaluationTime"/>.</summary>
    private static DateTimeOffset DefaultNotBefore { get; } = new(2020, 5, 4, 10, 30, 0, TimeSpan.Zero);

    /// <summary>The default minted validity end.</summary>
    private static DateTimeOffset DefaultNotAfter { get; } = new(2030, 5, 4, 10, 30, 0, TimeSpan.Zero);

    /// <summary>
    /// The PRO-4.3.4-03 check (ii) seam realised as byte equality against the identity's certificate
    /// entries — the "public key and subject name are identical" limb of the check, sufficient here because
    /// the service digital identity carries the minted certificate itself.
    /// </summary>
    private static MatchCertificateToTrustServiceAsyncDelegate ByteEqualityMatch { get; } = (certificate, serviceDigitalIdentity, validationTime, pool, cancellationToken) =>
    {
        foreach(ServiceDigitalIdentityEntry entry in serviceDigitalIdentity.Entries)
        {
            if(entry is X509CertificateIdentity certificateEntry
                && certificateEntry.Certificate.AsReadOnlySpan().SequenceEqual(certificate.AsReadOnlySpan()))
            {
                return ValueTask.FromResult(true);
            }
        }

        return ValueTask.FromResult(false);
    };


    /// <summary>
    /// A certificate carrying every fact the record models — a four-RDN issuer, a subject with a
    /// multi-valued RDN, and all four extensions — extracts field-exactly, every list in certificate order.
    /// </summary>
    [TestMethod]
    public void ExtractsEveryFactFromAMintedQualifiedCertificate()
    {
        //The two organization values inside the multi-valued RDN are equal-length, so their DER SET OF
        //sort order equals their content order and the expected certificate order is fixed by construction.
        X500DistinguishedName issuerName = CreateName(
            [Printable(WellKnownOids.CountryName, "FI")],
            [Utf8(WellKnownOids.OrganizationName, ProviderOrganizationName)],
            [Utf8(WellKnownOids.OrganizationName, "Example Provider Group Oy")],
            [Utf8(WellKnownOids.CommonName, "Example Provider QC CA")]);
        X500DistinguishedName subjectName = CreateName(
            [Printable(WellKnownOids.CountryName, "DE")],
            [Utf8(WellKnownOids.OrganizationName, "Aaa Unit Oy"), Utf8(WellKnownOids.OrganizationName, "Bbb Unit Oy")],
            [Utf8(WellKnownOids.OrganizationName, "Ccc Unit Oy")],
            [Utf8(WellKnownOids.CommonName, "Subject One")],
            [Utf8(WellKnownOids.OrganizationalUnitName, "Signing")]);

        using PkiCertificateMemory certificate = MintCertificate(issuerName, subjectName, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcCompliance),
                new QcStatementSpec(WellKnownOids.QcSscd),
                new QcStatementSpec(WellKnownOids.QcType, DeclaredTypeOids: [WellKnownOids.QcTypeElectronicSignature, WellKnownOids.QcTypeElectronicSeal])),
            CreateCertificatePoliciesExtension(WellKnownOids.QcpPublic, ExamplePolicyOid),
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation, critical: true),
            new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ClientAuthenticationOid), new Oid(EmailProtectionOid) }, critical: false)
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.AreEqual("FI", facts.IssuerCountryCode, "The issuer countryName must be read.");
        Assert.AreSequenceEqual([ProviderOrganizationName, "Example Provider Group Oy"], facts.IssuerOrganizationNames, "Both issuer organizationName values must be read in certificate order.");
        Assert.AreSequenceEqual(["Example Provider QC CA"], facts.IssuerCommonNames, "The issuer commonName must be read.");
        Assert.IsNull(facts.IssuerDistinguishedName, "The extractor leaves the optional PRO-4.4.4-06 (b) fallback rendering to the caller, who grafts one onto the record with a 'with' expression.");
        Assert.AreEqual("DE", facts.SubjectCountryCode, "The subject countryName must be read.");
        Assert.AreSequenceEqual(["Aaa Unit Oy", "Bbb Unit Oy", "Ccc Unit Oy"], facts.SubjectOrganizationNames, "All subject organizationName values must be read in certificate order, across and within relative distinguished names.");
        Assert.AreEqual(DefaultNotBefore, facts.NotBefore, "The notBefore instant must be read exactly.");
        Assert.IsTrue(facts.HasQcCompliance, "The QcCompliance statement must be recognised.");
        Assert.IsTrue(facts.HasQcSscdStatement, "The QcSSCD statement must be recognised.");
        Assert.AreSequenceEqual([EuQualifiedCertificateType.ElectronicSignature, EuQualifiedCertificateType.ElectronicSeal], facts.QcTypes, "The declared QcType values must be read in certificate order.");
        Assert.IsTrue(facts.HasCertificatePoliciesExtension, "The CertificatePolicies extension must be seen.");
        Assert.AreSequenceEqual([WellKnownOids.QcpPublic, ExamplePolicyOid], facts.CertificatePolicyOids, "The policy identifiers must be read in certificate order.");
        Assert.IsTrue(facts.HasKeyUsageExtension, "The KeyUsage extension must be seen.");
        Assert.AreSequenceEqual([KeyUsageBitName.DigitalSignature, KeyUsageBitName.NonRepudiation], facts.SetKeyUsageBits, "Exactly the asserted Key Usage bits must be read, in ascending bit order.");
        Assert.IsTrue(facts.HasExtendedKeyUsageExtension, "The ExtendedKeyUsage extension must be seen.");
        Assert.AreSequenceEqual([ClientAuthenticationOid, EmailProtectionOid], facts.ExtendedKeyUsageOids, "The key purpose identifiers must be read in certificate order.");
        Assert.AreSequenceEqual(
            [WellKnownOids.CountryName, WellKnownOids.OrganizationName, WellKnownOids.OrganizationName, WellKnownOids.OrganizationName, WellKnownOids.CommonName, WellKnownOids.OrganizationalUnitName],
            facts.SubjectAttributeTypeOids,
            "Every subject attribute type must be recorded in certificate order, duplicates included.");
    }


    /// <summary>
    /// A certificate with no extensions at all extracts with every presence flag
    /// <see langword="false"/> and every extension-derived list empty — the TS 119 612
    /// clause 5.5.9.2.2 criteria distinguish an absent extension from an empty one.
    /// </summary>
    [TestMethod]
    public void ExtractsAbsenceWhenTheCertificateCarriesNoExtensions()
    {
        X500DistinguishedName name = CreateName(
            [Printable(WellKnownOids.CountryName, "FI")],
            [Utf8(WellKnownOids.CommonName, "Bare Certificate")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter, []);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsFalse(facts.HasQcCompliance, "No QCStatements extension means no QcCompliance.");
        Assert.IsFalse(facts.HasQcSscdStatement, "No QCStatements extension means no QcSSCD.");
        Assert.IsEmpty(facts.QcTypes, "No QCStatements extension means no declared types.");
        Assert.IsFalse(facts.HasCertificatePoliciesExtension, "The CertificatePolicies extension is absent.");
        Assert.IsEmpty(facts.CertificatePolicyOids, "An absent CertificatePolicies extension contributes no identifiers.");
        Assert.IsFalse(facts.HasKeyUsageExtension, "The KeyUsage extension is absent.");
        Assert.IsEmpty(facts.SetKeyUsageBits, "An absent KeyUsage extension asserts no bits.");
        Assert.IsFalse(facts.HasExtendedKeyUsageExtension, "The ExtendedKeyUsage extension is absent.");
        Assert.IsEmpty(facts.ExtendedKeyUsageOids, "An absent ExtendedKeyUsage extension contributes no identifiers.");
        Assert.AreEqual("FI", facts.IssuerCountryCode, "The name facts are read independently of extensions.");
        Assert.AreEqual(DefaultNotBefore, facts.NotBefore, "The notBefore instant must still be read exactly.");
    }


    /// <summary>
    /// A validity start from 2050 on is DER-encoded as a <c>GeneralizedTime</c> per RFC 5280 §4.1.2.5 and
    /// must be read exactly, same as the <c>UTCTime</c> form the other tests exercise.
    /// </summary>
    [TestMethod]
    public void ReadsGeneralizedTimeNotBeforeBeyondTheUtcTimePivot()
    {
        DateTimeOffset notBefore = new(2052, 1, 2, 3, 4, 5, TimeSpan.Zero);
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Far Future")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, notBefore, notBefore.AddYears(1), []);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.AreEqual(notBefore, facts.NotBefore, "A GeneralizedTime notBefore must be read exactly.");
    }


    /// <summary>
    /// Unknown statements, unknown <c>QcType</c> identifiers, and a <c>QcType</c> statement without its
    /// info are tolerated: the known facts are still extracted and the unknowns contribute nothing.
    /// </summary>
    [TestMethod]
    public void SkipsUnknownQcStatementsAndTypeIdentifiers()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Odd Statements")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec("1.2.3.4", Utf8Payload: "An unknown statement with a payload."),
                new QcStatementSpec(WellKnownOids.QcType, DeclaredTypeOids: [UnknownQcTypeOid, WellKnownOids.QcTypeElectronicSignature]),
                new QcStatementSpec(WellKnownOids.QcType))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsFalse(facts.HasQcCompliance, "No QcCompliance statement was declared.");
        Assert.IsFalse(facts.HasQcSscdStatement, "No QcSSCD statement was declared.");
        Assert.AreSequenceEqual([EuQualifiedCertificateType.ElectronicSignature], facts.QcTypes, "Only the known declared type is extracted; the unknown identifier and the info-less statement contribute nothing.");
    }


    /// <summary>
    /// A name with no <c>countryName</c> leaves the country-code fact <see langword="null"/> — the
    /// PRO-4.4.4-01 territory resolution treats that as its own failure, not this extractor's.
    /// </summary>
    [TestMethod]
    public void LeavesCountryCodeNullWhenTheNameCarriesNone()
    {
        X500DistinguishedName issuerName = CreateName([Utf8(WellKnownOids.CommonName, "No Country CA")]);
        X500DistinguishedName subjectName = CreateName([Utf8(WellKnownOids.OrganizationName, "No Country Oy")]);
        using PkiCertificateMemory certificate = MintCertificate(issuerName, subjectName, DefaultNotBefore, DefaultNotAfter, []);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsNull(facts.IssuerCountryCode, "An issuer without countryName has no country-code fact.");
        Assert.IsNull(facts.SubjectCountryCode, "A subject without countryName has no country-code fact.");
        Assert.AreSequenceEqual([WellKnownOids.OrganizationName], facts.SubjectAttributeTypeOids, "The subject's only attribute type is still recorded.");
    }


    /// <summary>
    /// A carrier holding something other than an X.509 certificate is a composition error, rejected the
    /// same way the determination rejects a wrong-territory list.
    /// </summary>
    [TestMethod]
    public void RejectsANonCertificateCarrier()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Mistagged")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter, []);
        using PkiCertificateMemory mistagged = CloneCertificate(certificate, PkiCertificateTags.X509Crl);

        Assert.ThrowsExactly<ArgumentException>(() => QualifiedCertificateFactsExtractor.Extract(mistagged), "A CRL-tagged carrier must be rejected before any parsing.");
    }


    /// <summary>
    /// Bytes that are not a DER certificate — including a well-formed certificate followed by trailing
    /// data — throw <see cref="AsnContentException"/>; hostile input never extracts partially.
    /// </summary>
    [TestMethod]
    public void ThrowsOnMalformedDer()
    {
        IMemoryOwner<byte> garbageOwner = BaseMemoryPool.Shared.Rent(3);
        ReadOnlySpan<byte> garbageBytes = [0x01, 0x02, 0x03];
        garbageBytes.CopyTo(garbageOwner.Memory.Span);
        using PkiCertificateMemory garbage = new(garbageOwner, PkiCertificateTags.X509Certificate);
        Assert.ThrowsExactly<AsnContentException>(() => QualifiedCertificateFactsExtractor.Extract(garbage), "Garbage bytes must throw.");

        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Trailing Data")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter, []);
        IMemoryOwner<byte> trailingOwner = BaseMemoryPool.Shared.Rent(certificate.Length + 1);
        certificate.AsReadOnlySpan().CopyTo(trailingOwner.Memory.Span);
        trailingOwner.Memory.Span[certificate.Length] = 0x00;
        using PkiCertificateMemory trailing = new(trailingOwner, PkiCertificateTags.X509Certificate);
        Assert.ThrowsExactly<AsnContentException>(() => QualifiedCertificateFactsExtractor.Extract(trailing), "Trailing data after the Certificate sequence must throw.");
    }


    /// <summary>
    /// The capstone: a minted qualified certificate's extracted facts drive the shipped
    /// <see cref="TrustedListQualification.DetermineEuQualifiedCertificateAsync"/> composition to a
    /// qualified determination — real DER in, TS 119 615 Table 1 row 1 out, with no hand-written facts.
    /// </summary>
    [TestMethod]
    public async Task ExtractedFactsQualifyThroughTheShippedDetermination()
    {
        X500DistinguishedName issuerName = CreateName(
            [Printable(WellKnownOids.CountryName, "FI")],
            [Utf8(WellKnownOids.OrganizationName, ProviderOrganizationName)],
            [Utf8(WellKnownOids.CommonName, "Example Provider QC CA")]);
        X500DistinguishedName subjectName = CreateName(
            [Printable(WellKnownOids.CountryName, "FI")],
            [Utf8(WellKnownOids.OrganizationName, "Example Subject Oy")],
            [Utf8(WellKnownOids.CommonName, "Example Subject Signer")]);
        using PkiCertificateMemory certificate = MintCertificate(issuerName, subjectName, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcCompliance),
                new QcStatementSpec(WellKnownOids.QcType, DeclaredTypeOids: [WellKnownOids.QcTypeElectronicSignature])),
            CreateCertificatePoliciesExtension(ExamplePolicyOid),
            new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation, critical: true)
        ]);

        using TrustedList trustedList = CreateSingleServiceTrustedList(certificate, TrustServiceAdditionalInformationType.ForElectronicSignatures);
        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(TrustedListProcessStatus.Failed, result.Status, "The determination over extracted facts must not fail the process.");
        Assert.Contains(EuQualifiedCertificateIndication.QualifiedForESignature, result.Indications, "A granted for-eSignatures service recognising a QcCompliance + QcType-esign certificate determines qualified (Table 1 row 1).");
    }


    /// <summary>
    /// A name carrying several <c>countryName</c> attributes reads first-wins — the facts contract fixes
    /// the FIRST value, and PRO-4.4.4-01 territory resolution reads exactly one country.
    /// </summary>
    [TestMethod]
    public void ReadsTheFirstCountryNameWhenSeveralArePresent()
    {
        X500DistinguishedName issuerName = CreateName(
            [Printable(WellKnownOids.CountryName, "FI")],
            [Printable(WellKnownOids.CountryName, "SE")],
            [Utf8(WellKnownOids.CommonName, "Two Countries CA")]);
        X500DistinguishedName subjectName = CreateName(
            [Printable(WellKnownOids.CountryName, "DE")],
            [Printable(WellKnownOids.CountryName, "AT")],
            [Utf8(WellKnownOids.CommonName, "Two Countries Subject")]);
        using PkiCertificateMemory certificate = MintCertificate(issuerName, subjectName, DefaultNotBefore, DefaultNotAfter, []);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.AreEqual("FI", facts.IssuerCountryCode, "The first issuer countryName must win.");
        Assert.AreEqual("DE", facts.SubjectCountryCode, "The first subject countryName must win.");
        Assert.AreSequenceEqual(
            [WellKnownOids.CountryName, WellKnownOids.CountryName, WellKnownOids.CommonName],
            facts.SubjectAttributeTypeOids,
            "Both subject countryName attribute types are still recorded.");
    }


    /// <summary>
    /// Present-but-empty extensions report presence with empty contents — the TS 119 612
    /// clause 5.5.9.2.2 criteria require the extension to be present, not merely its values to be
    /// vacuously matched, so presence must never be derived from non-emptiness.
    /// </summary>
    [TestMethod]
    public void ReportsPresenceOfEmptyExtensions()
    {
        //A critical zero-bit KeyUsage and an empty-OidCollection ExtendedKeyUsage are shapes
        //CertificateRequest.Create() re-imports through the platform certificate store on decode,
        //so this degenerate pair is assembled directly instead, like the file's other RFC 5280
        //edge shapes.
        using PkiCertificateMemory certificate = MintSyntheticCertificate(
            extensions:
            [
                CreateCertificatePoliciesExtension(),
                new X509KeyUsageExtension(X509KeyUsageFlags.None, critical: true),
                new X509EnhancedKeyUsageExtension(new OidCollection(), critical: false)
            ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsTrue(facts.HasCertificatePoliciesExtension, "An empty CertificatePolicies extension is still present.");
        Assert.IsEmpty(facts.CertificatePolicyOids, "An empty CertificatePolicies extension carries no identifiers.");
        Assert.IsTrue(facts.HasKeyUsageExtension, "A zero-bit KeyUsage extension is still present.");
        Assert.IsEmpty(facts.SetKeyUsageBits, "A zero-bit KeyUsage extension asserts no bits.");
        Assert.IsTrue(facts.HasExtendedKeyUsageExtension, "An empty ExtendedKeyUsage extension is still present.");
        Assert.IsEmpty(facts.ExtendedKeyUsageOids, "An empty ExtendedKeyUsage extension carries no identifiers.");
    }


    /// <summary>
    /// The RFC 5280 §4.1.2.8 unique-identifier fields are skipped with the extensions still read, and of
    /// duplicate extensions — the §4.2 profile violation the extractor documents — the first occurrence
    /// wins. The platform factory can mint neither, so the certificate is assembled directly.
    /// </summary>
    [TestMethod]
    public void SkipsUniqueIdentifiersAndReadsTheFirstDuplicateExtension()
    {
        using PkiCertificateMemory certificate = MintSyntheticCertificate(
            withUniqueIdentifiers: true,
            extensions:
            [
                CreateQcStatementsExtension(new QcStatementSpec(WellKnownOids.QcCompliance)),
                CreateQcStatementsExtension(new QcStatementSpec(WellKnownOids.QcSscd))
            ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsTrue(facts.HasQcCompliance, "Extensions after the unique identifiers must still be read, from the first QCStatements occurrence.");
        Assert.IsFalse(facts.HasQcSscdStatement, "The duplicate QCStatements occurrence must be ignored — the first occurrence wins.");
        Assert.AreSequenceEqual(["Synthetic CA"], facts.IssuerCommonNames, "The name facts are unaffected by the unique identifiers.");
    }


    /// <summary>
    /// Malformed extension structures throw, never silently read as "no extensions": a mis-tagged element
    /// where <c>extensions [3]</c> belongs, an extensions block wrapping junk, and trailing content inside
    /// an extension value are each rejected.
    /// </summary>
    [TestMethod]
    public void ThrowsOnMalformedExtensionStructures()
    {
        using PkiCertificateMemory misTagged = MintSyntheticCertificate(
            extensions: [new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation, critical: true)],
            extensionsTagNumber: 4);
        Assert.ThrowsExactly<AsnContentException>(() => QualifiedCertificateFactsExtractor.Extract(misTagged), "A [4]-tagged element where extensions [3] belongs is not an RFC 5280 to-be-signed field and must throw.");

        using PkiCertificateMemory malformedContent = MintSyntheticCertificate(malformExtensionsContent: true);
        Assert.ThrowsExactly<AsnContentException>(() => QualifiedCertificateFactsExtractor.Extract(malformedContent), "An extensions block wrapping junk instead of the Extensions sequence must throw.");

        //A valid KeyUsage BIT STRING (nonRepudiation) followed by a trailing NULL inside the extnValue.
        using PkiCertificateMemory trailingValue = MintSyntheticCertificate(
            extensions: [new X509Extension(WellKnownOids.KeyUsageExtension, [0x03, 0x02, 0x06, 0x40, 0x05, 0x00], critical: false)]);
        Assert.ThrowsExactly<AsnContentException>(() => QualifiedCertificateFactsExtractor.Extract(trailingValue), "Trailing content after the value inside an extnValue must throw.");
    }


    /// <summary>
    /// The eSeal capstone: extracted facts of a QcCompliance + QcType-eseal certificate drive the shipped
    /// determination to qualified-for-eSeals (Table 2 row 1). Unlike the eSignature capstone, this one
    /// discriminates a QcTypes-emptying regression: Table 2's typeless-compliant column is NOT qualified,
    /// so losing the declared type flips the outcome.
    /// </summary>
    [TestMethod]
    public async Task ExtractedFactsQualifyForESealThroughTheShippedDetermination()
    {
        X500DistinguishedName issuerName = CreateName(
            [Printable(WellKnownOids.CountryName, "FI")],
            [Utf8(WellKnownOids.OrganizationName, ProviderOrganizationName)],
            [Utf8(WellKnownOids.CommonName, "Example Provider QC CA")]);
        X500DistinguishedName subjectName = CreateName(
            [Printable(WellKnownOids.CountryName, "FI")],
            [Utf8(WellKnownOids.OrganizationName, "Example Subject Oy")],
            [Utf8(WellKnownOids.CommonName, "Example Subject Seal")]);
        using PkiCertificateMemory certificate = MintCertificate(issuerName, subjectName, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcCompliance),
                new QcStatementSpec(WellKnownOids.QcType, DeclaredTypeOids: [WellKnownOids.QcTypeElectronicSeal])),
            CreateCertificatePoliciesExtension(ExamplePolicyOid),
            new X509KeyUsageExtension(X509KeyUsageFlags.NonRepudiation, critical: true)
        ]);

        using TrustedList trustedList = CreateSingleServiceTrustedList(certificate, TrustServiceAdditionalInformationType.ForElectronicSeals);
        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        EuQualifiedCertificateDeterminationResult result = await TrustedListQualification.DetermineEuQualifiedCertificateAsync(
            trustedList, certificate, facts, RegulationEvaluationTime, ByteEqualityMatch, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(TrustedListProcessStatus.Failed, result.Status, "The determination over extracted facts must not fail the process.");
        Assert.Contains(EuQualifiedCertificateIndication.QualifiedForESeal, result.Indications, "A granted for-eSeals service recognising a QcCompliance + QcType-eseal certificate determines qualified (Table 2 row 1).");
    }


    /// <summary>
    /// Clause 4.3.2's <c>MonetaryValue</c> extracts field-exactly through the <c>Iso4217CurrencyCode</c>
    /// CHOICE's alphabetic alternative: "value = amount * 10^exponent" (Annex B), with a negative exponent
    /// exercised so the sign survives the round trip.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.3.2.
    [TestMethod]
    public void ExtractsQcLimitValueWithTheAlphabeticCurrencyAlternative()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Limit Value Alphabetic")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcLimitValue, WriteInfo: WriteMonetaryValueInfo("EUR", null, 12345, -2)))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsNotNull(facts.QcLimitValue, "The QcLimitValue statement must be recognised.");
        Assert.AreEqual("EUR", facts.QcLimitValue.AlphabeticCurrencyCode, "The alphabetic currency code must be read.");
        Assert.IsNull(facts.QcLimitValue.NumericCurrencyCode, "Only one Iso4217CurrencyCode CHOICE alternative is populated.");
        Assert.AreEqual((BigInteger)12345, facts.QcLimitValue.Amount, "The amount must be read exactly.");
        Assert.AreEqual((BigInteger)(-2), facts.QcLimitValue.Exponent, "The exponent must be read exactly, negative sign included.");
    }


    /// <summary>
    /// Clause 4.3.2's <c>Iso4217CurrencyCode</c> CHOICE numeric alternative — "numeric INTEGER (1..999)" —
    /// extracts field-exactly, proving the reader honours both CHOICE arms even though
    /// QCS-4.3.2-02 recommends the alphabetic form.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.3.2 / Annex B.
    [TestMethod]
    public void ExtractsQcLimitValueWithTheNumericCurrencyAlternative()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Limit Value Numeric")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcLimitValue, WriteInfo: WriteMonetaryValueInfo(null, 978, 100, 0)))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsNotNull(facts.QcLimitValue, "The QcLimitValue statement must be recognised.");
        Assert.IsNull(facts.QcLimitValue.AlphabeticCurrencyCode, "Only one Iso4217CurrencyCode CHOICE alternative is populated.");
        Assert.AreEqual((BigInteger)978, facts.QcLimitValue.NumericCurrencyCode, "The numeric currency code must be read.");
        Assert.AreEqual((BigInteger)100, facts.QcLimitValue.Amount, "The amount must be read exactly.");
        Assert.AreEqual((BigInteger)0, facts.QcLimitValue.Exponent, "The exponent must be read exactly.");
    }


    /// <summary>
    /// A <c>MonetaryValue.currency</c> encoded in a tag outside the <c>Iso4217CurrencyCode</c> CHOICE —
    /// "CHOICE { alphabetic PrintableString (SIZE (3)), ... numeric INTEGER (1..999) }" — is a QCS-4.1-03
    /// ("The syntax of the defined statements shall comply with ASN.1") violation the reader tolerates by
    /// degrading the fact rather than aborting, per the clause 4.1 NOTE: "This extension is not processed as
    /// part of IETF RFC 5280 [i.9] path validation and there are no security implications with accepting a
    /// certificate in a system that cannot parse this extension." Minted alongside a well-formed
    /// <c>QcCompliance</c> statement so the sibling still extracts. Assembled with
    /// <see cref="MintSyntheticCertificate"/> so no platform encoder gets a chance to normalise the hostile
    /// tag.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.1, QCS-4.1-03; clause 4.3.2 / Annex B.
    [TestMethod]
    public void LeavesQcLimitValueAbsentWhenTheCurrencyIsNotAChoiceTag()
    {
        using PkiCertificateMemory certificate = MintSyntheticCertificate(
            extensions:
            [
                CreateQcStatementsExtension(
                    new QcStatementSpec(WellKnownOids.QcCompliance),
                    new QcStatementSpec(WellKnownOids.QcLimitValue, WriteInfo: WriteMonetaryValueInfoWithHostileCurrencyTag()))
            ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsTrue(facts.HasQcCompliance, "The sibling QcCompliance statement must still be read.");
        Assert.IsNull(facts.QcLimitValue, "A currency encoded as a UTF8String is neither the alphabetic PrintableString nor the numeric INTEGER CHOICE arm, so the QcLimitValue fact is left absent.");
    }


    /// <summary>
    /// Clause 4.3.3's <c>QcEuRetentionPeriod ::= INTEGER</c> extracts exactly, including a value beyond the
    /// CLR's 64-bit integer range, proving the BigInteger carrier records the retention period as read
    /// rather than truncating it.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.3.3: "This QCStatement declares a retention period for material information relevant to the use of and reliance on a certificate, expressed as a number of years after the expiry date of the certificate."
    [TestMethod]
    public void ExtractsQcRetentionPeriodBeyondLongRange()
    {
        BigInteger retentionYears = BigInteger.Parse("123456789012345678901234567890", CultureInfo.InvariantCulture);
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Retention Period")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcRetentionPeriod, WriteInfo: WriteIntegerInfo(retentionYears)))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.AreEqual(retentionYears, facts.QcRetentionPeriodYears, "A retention period beyond long range must be read exactly, unbounded by the CLR's 64-bit integer types.");
    }


    /// <summary>
    /// Clause 4.3.4's <c>PdsLocations ::= SEQUENCE SIZE (1..MAX) OF PdsLocation</c> extracts every entry's
    /// <c>url</c> and <c>language</c> in certificate order.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.3.4: "This QCStatement holds URLs to PKI Disclosure Statements (PDS) in accordance with Annex A of ETSI EN 319 411-1."
    [TestMethod]
    public void ExtractsMultiplePdsLocationsInCertificateOrder()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "PDS Locations")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcPds, WriteInfo: WritePdsLocationsInfo(
                    ("https://example.test/pds/en", "en"),
                    ("https://example.test/pds/de", "de"))))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.AreSequenceEqual(
            [new PdsLocation("https://example.test/pds/en", "en"), new PdsLocation("https://example.test/pds/de", "de")],
            facts.QcPdsLocations,
            "Every PdsLocation's url and language must be read in certificate order.");
    }


    /// <summary>
    /// Clause 4.2.4's <c>QcCClegislation ::= SEQUENCE OF CountryName</c> extracts the declared country codes
    /// in certificate order. The fixture uses non-EU/EEA codes because QCS-4.2.4-01 ("If the certificate is
    /// issued according to Directive 1999/93/EC [i.3] or Regulation (EU) No 910/2014 [i.8], this QCStatement
    /// shall not be present") makes an EU member state's code a profile violation here — a certificate
    /// qualified under Finnish or Swedish law is a Regulation certificate, so the fixture instead models one
    /// qualified under a third country's legal framework.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.2.4: "This QCStatement identifies the country or set of countries under the legislation of which the certificate is issued as a qualified certificate."; QCS-4.2.4-01.
    [TestMethod]
    public void ExtractsQcCcLegislationCountryCodesInCertificateOrder()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "CC Legislation")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcCcLegislation, WriteInfo: WriteCountryCodesInfo("CH", "JP")))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.AreSequenceEqual(["CH", "JP"], facts.QcCcLegislationCountryCodes, "The QcCClegislation country codes must be read in certificate order.");
    }


    /// <summary>
    /// Clause 4.3.5.3's four identification-method identifiers each map to their
    /// <see cref="EuIdentityVerificationMethod"/> member, while an identifier outside the four the
    /// extensible <c>QcIdentMethod ::= SEQUENCE SIZE (1) OF OBJECT IDENTIFIER (... | ...)</c> permits is
    /// omitted — mirroring the unknown-<c>QcType</c> tolerance.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.3.5.3 / Annex B.
    [TestMethod]
    public void MapsAllFourIdentificationMethodsAndOmitsAnUnknownOne()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Ident Methods")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcIdentMethod, WriteInfo: WriteIdentMethodsInfo(
                    WellKnownOids.QcIdentMethodEidas1Ab,
                    UnknownQcIdentMethodOid,
                    WellKnownOids.QcIdentMethodEidas1Cd,
                    WellKnownOids.QcIdentMethodEidas2Acd,
                    WellKnownOids.QcIdentMethodEidas2B)))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.AreSequenceEqual(
            [EuIdentityVerificationMethod.Eidas1Ab, EuIdentityVerificationMethod.Eidas1Cd, EuIdentityVerificationMethod.Eidas2Acd, EuIdentityVerificationMethod.Eidas2B],
            facts.QcIdentityVerificationMethods,
            "All four known identification methods must be read in certificate order; the unknown identifier contributes nothing.");
    }


    /// <summary>
    /// Clause 4.2.5's <c>QcQSCDlegislation ::= SEQUENCE SIZE (1..MAX) OF CountryName</c> extracts the
    /// declared country codes in certificate order. The identifier itself is <c>WellKnownOids.QcQscdLegislation</c>
    /// spelled per Annex B — QCS-4.1-04 ("Annex B takes precedence over the ASN.1 definitions provided in the
    /// body of the present document, in case of discrepancy") fixes the constant's name against the body's
    /// <c>id-etsi-qcs-QcQCSDlegislation</c> typo.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.2.5 / Annex B.
    [TestMethod]
    public void ExtractsQcQscdLegislationCountryCodesInCertificateOrder()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "QSCD Legislation")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcQscdLegislation, WriteInfo: WriteCountryCodesInfo("US", "GB")))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.AreSequenceEqual(["US", "GB"], facts.QcQscdLegislationCountryCodes, "The QcQSCDlegislation country codes must be read in certificate order.");
    }


    /// <summary>
    /// Mutation-proofs the ten EN 319 412-5 OID constants a typo'd dotted value would otherwise ship green
    /// for: the certificate's QCStatements extension is written entirely from dotted literals quoted from
    /// Annex B's object identifier block — no <see cref="WellKnownOids"/> constant appears on the minting
    /// side. The six content-bearing statement identifiers come from "id-etsi-qcs-QcLimitValue OBJECT
    /// IDENTIFIER ::= { id-etsi-qcs 2 }", "id-etsi-qcs-QcRetentionPeriod OBJECT IDENTIFIER ::= { id-etsi-qcs
    /// 3 }", "id-etsi-qcs-QcPDS OBJECT IDENTIFIER ::= { id-etsi-qcs 5 }", "id-etsi-qcs-QcCClegislation OBJECT
    /// IDENTIFIER ::= { id-etsi-qcs 7 }", "id-etsi-qcs-QcIdentMethod OBJECT IDENTIFIER ::= { id-etsi-qcs 8 }"
    /// and "id-etsi-qcs-QcQSCDlegislation OBJECT IDENTIFIER ::= { id-etsi-qcs 9 }", written as
    /// "0.4.0.1862.1.2", ".1.3", ".1.5", ".1.7", ".1.8" and ".1.9"; the <c>QcIdentMethod</c> info's four
    /// method identifiers come from "id-etsi-qct-eIDAS1-ab OBJECT IDENTIFIER ::= { id-etsi-qcs-QcIdentMethod
    /// 1 }" through "id-etsi-qct-eIDAS2-b OBJECT IDENTIFIER ::= { id-etsi-qcs-QcIdentMethod 4 }", written as
    /// "0.4.0.1862.1.8.1" through ".1.8.4". Recognition of every literal by the extractor's own
    /// <see cref="WellKnownOids"/>-keyed switch proves each constant states the Annex B arc: a typo'd
    /// constant that no longer matches its literal would surface as a null, unset or empty fact rather than
    /// passing silently.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> Annex B, object identifiers.
    [TestMethod]
    public void ExtractsFactsFromLiteralAnnexBObjectIdentifiers()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Literal Annex B OIDs")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec("0.4.0.1862.1.2", WriteInfo: WriteMonetaryValueInfo("EUR", null, 1, 0)),
                new QcStatementSpec("0.4.0.1862.1.3", WriteInfo: WriteIntegerInfo(1)),
                new QcStatementSpec("0.4.0.1862.1.5", WriteInfo: WritePdsLocationsInfo(("https://example.test/pds/en", "en"))),
                new QcStatementSpec("0.4.0.1862.1.7", WriteInfo: WriteCountryCodesInfo("CH")),
                new QcStatementSpec("0.4.0.1862.1.8", WriteInfo: WriteIdentMethodsInfo("0.4.0.1862.1.8.1", "0.4.0.1862.1.8.2", "0.4.0.1862.1.8.3", "0.4.0.1862.1.8.4")),
                new QcStatementSpec("0.4.0.1862.1.9", WriteInfo: WriteCountryCodesInfo("US", "GB")))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsNotNull(facts.QcLimitValue, "The literal '0.4.0.1862.1.2' statement id must be recognised as QcLimitValue.");
        Assert.AreEqual((BigInteger)1, facts.QcRetentionPeriodYears, "The literal '0.4.0.1862.1.3' statement id must be recognised as QcRetentionPeriod.");
        Assert.AreSequenceEqual([new PdsLocation("https://example.test/pds/en", "en")], facts.QcPdsLocations, "The literal '0.4.0.1862.1.5' statement id must be recognised as QcPDS.");
        Assert.AreSequenceEqual(["CH"], facts.QcCcLegislationCountryCodes, "The literal '0.4.0.1862.1.7' statement id must be recognised as QcCClegislation.");
        Assert.AreSequenceEqual(
            [EuIdentityVerificationMethod.Eidas1Ab, EuIdentityVerificationMethod.Eidas1Cd, EuIdentityVerificationMethod.Eidas2Acd, EuIdentityVerificationMethod.Eidas2B],
            facts.QcIdentityVerificationMethods,
            "The literal '0.4.0.1862.1.8' statement id must be recognised as QcIdentMethod, and each literal '.1.8.1' through '.1.8.4' method identifier must map to its EuIdentityVerificationMethod member in order.");
        Assert.AreSequenceEqual(["US", "GB"], facts.QcQscdLegislationCountryCodes, "The literal '0.4.0.1862.1.9' statement id must be recognised as QcQSCDlegislation.");
    }


    /// <summary>
    /// QCS-4.1-02A ("The qcStatements extension shall not include more than one instance of a particular
    /// qcStatement defined in the present document") is a profile violation the extractor tolerates rather
    /// than rejects: of two <c>QcRetentionPeriod</c> instances with different values, the first is the fact.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.1, QCS-4.1-02A.
    [TestMethod]
    public void ReadsTheFirstOfTwoDuplicateContentBearingStatements()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Duplicate Statement")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcRetentionPeriod, WriteInfo: WriteIntegerInfo(5)),
                new QcStatementSpec(WellKnownOids.QcRetentionPeriod, WriteInfo: WriteIntegerInfo(99)))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.AreEqual((BigInteger)5, facts.QcRetentionPeriodYears, "The first QcRetentionPeriod instance's value must win over the duplicate.");
    }


    /// <summary>
    /// QCS-4.1-02A forbids more than one instance of a statement, and the tolerance skips a second occurrence
    /// without parsing its <c>statementInfo</c> at all — not merely keeping the first value once both have
    /// been read. A second <c>QcRetentionPeriod</c> instance carrying malformed info (trailing data after its
    /// <c>QcEuRetentionPeriod ::= INTEGER</c> SYNTAX value, the same violation clause 4.1's QCS-4.1-03
    /// governs) proves the point: no exception escapes, because the duplicate is never parsed.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.1, QCS-4.1-02A.
    [TestMethod]
    public void KeepsTheFirstValueWhenTheDuplicateStatementInfoIsMalformed()
    {
        using PkiCertificateMemory certificate = MintSyntheticCertificate(
            extensions:
            [
                CreateQcStatementsExtension(
                    new QcStatementSpec(WellKnownOids.QcRetentionPeriod, WriteInfo: WriteIntegerInfo(5)),
                    new QcStatementSpec(WellKnownOids.QcRetentionPeriod, WriteInfo: WriteIntegerInfoWithTrailingData(99, 1)))
            ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.AreEqual((BigInteger)5, facts.QcRetentionPeriodYears, "The first QcRetentionPeriod value must survive even though the duplicate's info is malformed — the duplicate is skipped before its info is ever parsed.");
    }


    /// <summary>
    /// Annex B binds <c>SYNTAX QcEuRetentionPeriod</c> to <c>esi4-qcStatement-3</c> ("esi4-qcStatement-3
    /// QC-STATEMENT ::= { SYNTAX QcEuRetentionPeriod IDENTIFIED BY id-etsi-qcs-QcRetentionPeriod }"), so an
    /// instance minted without its <c>statementInfo</c> violates QCS-4.1-03 ("The syntax of the defined
    /// statements shall comply with ASN.1") — Table 2's 'O' for clause 4.3.3 governs the statement's
    /// presence, not the shape of a present instance. The reader tolerates the violation by leaving the fact
    /// at its absent default rather than aborting, mirroring the QcType-without-info leniency, and the
    /// sibling statement still extracts.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.1, QCS-4.1-03; clause 4.3.3 / Annex B, Table 2.
    [TestMethod]
    public void LeavesQcRetentionPeriodAbsentWhenInfoIsMissing()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Absent Retention Info")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateQcStatementsExtension(
                new QcStatementSpec(WellKnownOids.QcCompliance),
                new QcStatementSpec(WellKnownOids.QcRetentionPeriod))
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsTrue(facts.HasQcCompliance, "The sibling QcCompliance statement must still be read.");
        Assert.IsNull(facts.QcRetentionPeriodYears, "A QcRetentionPeriod statement minted without its info leaves the fact absent.");
    }


    /// <summary>
    /// A <c>QcEuRetentionPeriod ::= INTEGER</c> SYNTAX value (Annex B) permits exactly one INTEGER; trailing
    /// bytes after it violate QCS-4.1-03 ("The syntax of the defined statements shall comply with ASN.1"),
    /// which the reader tolerates by degrading the fact rather than aborting, per the clause 4.1 NOTE: "This
    /// extension is not processed as part of IETF RFC 5280 [i.9] path validation and there are no security
    /// implications with accepting a certificate in a system that cannot parse this extension." Minted
    /// alongside a well-formed <c>QcCompliance</c> statement so the sibling still extracts. Assembled with
    /// <see cref="MintSyntheticCertificate"/> so no platform encoder gets a chance to re-encode the hostile
    /// bytes.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.1, QCS-4.1-03; clause 4.3.3 / Annex B.
    [TestMethod]
    public void LeavesQcRetentionPeriodAbsentWhenTrailingDataFollowsItsSyntaxValue()
    {
        using PkiCertificateMemory certificate = MintSyntheticCertificate(
            extensions:
            [
                CreateQcStatementsExtension(
                    new QcStatementSpec(WellKnownOids.QcCompliance),
                    new QcStatementSpec(WellKnownOids.QcRetentionPeriod, WriteInfo: WriteIntegerInfoWithTrailingData(5, 0)))
            ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        Assert.IsTrue(facts.HasQcCompliance, "The sibling QcCompliance statement must still be read.");
        Assert.IsNull(facts.QcRetentionPeriodYears, "A second INTEGER after the QcEuRetentionPeriod SYNTAX value leaves the fact absent rather than aborting extraction.");
    }


    /// <summary>
    /// Clause 4.2.3's <c>QcType</c> statement info is a <c>SEQUENCE OF OBJECT IDENTIFIER</c>; trailing bytes
    /// after it inside the statement are a QCS-4.1-03 ("The syntax of the defined statements shall comply
    /// with ASN.1") violation the reader does not tolerate — unlike the six clause 4.2.4/4.2.5/4.3 statements
    /// above, <c>QcType</c> keeps the strict posture, because the TS 119 615 determination tables select
    /// rows directly by the declared types it carries. Assembled with <see cref="MintSyntheticCertificate"/>
    /// so no platform encoder gets a chance to re-encode the hostile bytes.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.1, QCS-4.1-03; clause 4.2.3.
    [TestMethod]
    public void ThrowsOnTrailingDataAfterTheQcTypeStatementInfo()
    {
        using PkiCertificateMemory certificate = MintSyntheticCertificate(
            extensions:
            [
                CreateQcStatementsExtension(
                    new QcStatementSpec(WellKnownOids.QcType, DeclaredTypeOids: [WellKnownOids.QcTypeElectronicSignature], WriteInfo: WriteTrailingNullAfterDeclaredTypes()))
            ]);

        Assert.ThrowsExactly<AsnContentException>(() => QualifiedCertificateFactsExtractor.Extract(certificate), "A NULL after the QcType declared-types SEQUENCE must be rejected as trailing data.");
    }


    /// <summary>
    /// EN 319 411-2 clause 5.3 defines seven EU qualified certificate policy identifiers under the
    /// <c>qualified-certificate-policies(194112)</c> arc; each <see cref="WellKnownOids"/> constant matches
    /// the dotted arc the clause spells out, and a certificate carrying all seven in its CertificatePolicies
    /// extension surfaces them through the existing <see cref="QualifiedCertificateFacts.CertificatePolicyOids"/>
    /// fact in certificate order.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941102/02.06.01_60/en_31941102v020601p.pdf">ETSI EN 319 411-2 V2.6.1</see> clause 5.3.
    [TestMethod]
    public void ExtractsAllSevenEnQualifiedCertificatePolicyIdentifiers()
    {
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "All Seven Policies")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
        [
            CreateCertificatePoliciesExtension(
                WellKnownOids.QcpNatural,
                WellKnownOids.QcpLegal,
                WellKnownOids.QcpNaturalQscd,
                WellKnownOids.QcpLegalQscd,
                WellKnownOids.QcpWeb,
                WellKnownOids.QncpWeb,
                WellKnownOids.QncpWebGen)
        ]);

        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificate);

        //The expected values are the dotted arcs clause 5.3 items a)-g) spell out — itu-t(0)
        //identified-organization(4) etsi(0) qualified-certificate-policies(194112) policy-identifiers(1)
        //qcp-natural(0) .. qncp-web-gen(6) — so the round trip through the minted extension proves each
        //WellKnownOids constant states the clause's arc, without a constant-versus-constant comparison.
        Assert.AreSequenceEqual(
            ["0.4.0.194112.1.0", "0.4.0.194112.1.1", "0.4.0.194112.1.2", "0.4.0.194112.1.3", "0.4.0.194112.1.4", "0.4.0.194112.1.5", "0.4.0.194112.1.6"],
            facts.CertificatePolicyOids,
            "All seven clause 5.3 policy identifiers must surface through CertificatePolicyOids in certificate order, at the exact dotted arcs items a)-g) define.");
    }


    /// <summary>
    /// <see cref="EuIdentityVerificationMethodMapping"/>'s <c>FromOid</c>/<c>ToOid</c> round-trip every
    /// clause 4.3.5.3 / Annex B identification-method identifier: the OID arc's four assigned last-numbers
    /// (<c>id-etsi-qcs-QcIdentMethod 1</c> through <c>4</c>) each map to their <see cref="EuIdentityVerificationMethod"/>
    /// member and back, mirroring <see cref="EuQualifiedCertificateTypeMapping"/>'s completeness shape.
    /// <c>ToOid</c> has no identifier to return for <see cref="EuIdentityVerificationMethod.None"/> or any
    /// other undefined value, so it throws <see cref="ArgumentOutOfRangeException"/> rather than default to
    /// one of the four known methods.
    /// </summary>
    /// <see href="https://www.etsi.org/deliver/etsi_en/319400_319499/31941205/02.06.01_60/en_31941205v020601p.pdf">ETSI EN 319 412-5 V2.6.1</see> clause 4.3.5.3 / Annex B.
    [TestMethod]
    public void RoundTripsEveryIdentificationMethodThroughItsMapping()
    {
        foreach(EuIdentityVerificationMethod method in new[]
        {
            EuIdentityVerificationMethod.Eidas1Ab,
            EuIdentityVerificationMethod.Eidas1Cd,
            EuIdentityVerificationMethod.Eidas2Acd,
            EuIdentityVerificationMethod.Eidas2B
        })
        {
            string oid = EuIdentityVerificationMethodMapping.ToOid(method);
            Assert.AreEqual(method, EuIdentityVerificationMethodMapping.FromOid(oid), $"{method} must map to an OID that maps back to itself.");
        }

        Assert.AreEqual(EuIdentityVerificationMethod.Eidas1Ab, EuIdentityVerificationMethodMapping.FromOid(WellKnownOids.QcIdentMethodEidas1Ab), "id-etsi-qct-eIDAS1-ab (arc value 1) must map to Eidas1Ab.");
        Assert.AreEqual(EuIdentityVerificationMethod.Eidas1Cd, EuIdentityVerificationMethodMapping.FromOid(WellKnownOids.QcIdentMethodEidas1Cd), "id-etsi-qct-eIDAS1-cd (arc value 2) must map to Eidas1Cd.");
        Assert.AreEqual(EuIdentityVerificationMethod.Eidas2Acd, EuIdentityVerificationMethodMapping.FromOid(WellKnownOids.QcIdentMethodEidas2Acd), "id-etsi-qct-eIDAS2-acd (arc value 3) must map to Eidas2Acd.");
        Assert.AreEqual(EuIdentityVerificationMethod.Eidas2B, EuIdentityVerificationMethodMapping.FromOid(WellKnownOids.QcIdentMethodEidas2B), "id-etsi-qct-eIDAS2-b (arc value 4) must map to Eidas2B.");
        Assert.IsNull(EuIdentityVerificationMethodMapping.FromOid(UnknownQcIdentMethodOid), "An identifier outside the four known methods must map to null.");
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => EuIdentityVerificationMethodMapping.ToOid(EuIdentityVerificationMethod.None), "ToOid must reject EuIdentityVerificationMethod.None; there is no identification-method OID for the CLR default.");
    }


    /// <summary>One <c>AttributeTypeAndValue</c> to encode into a minted name.</summary>
    /// <param name="TypeOid">The attribute type identifier.</param>
    /// <param name="Value">The attribute value text.</param>
    /// <param name="Encoding">The string form the value is encoded in.</param>
    private readonly record struct DirectoryAttribute(string TypeOid, string Value, UniversalTagNumber Encoding);


    /// <summary>One <c>QCStatement</c> to encode into a minted <c>QCStatements</c> extension, specified in domain terms so no encoded fragment travels between helpers.</summary>
    /// <param name="StatementId">The statement identifier.</param>
    /// <param name="DeclaredTypeOids">The <c>QcType</c> info's declared type identifiers in sequence order, or <see langword="null"/> for no info.</param>
    /// <param name="Utf8Payload">An arbitrary <c>UTF8String</c> info payload for an unknown statement, or <see langword="null"/> for none.</param>
    /// <param name="WriteInfo">Writes an arbitrary Annex B <c>statementInfo</c> shape directly with <see cref="AsnWriter"/> (well-formed or hostile alike), or <see langword="null"/> for no info.</param>
    private sealed record QcStatementSpec(string StatementId, IReadOnlyList<string>? DeclaredTypeOids = null, string? Utf8Payload = null, Action<AsnWriter>? WriteInfo = null);


    /// <summary>Writes a clause 4.3.2 <c>MonetaryValue</c> <c>statementInfo</c>: the <c>Iso4217CurrencyCode</c> CHOICE (exactly one alternative non-null), then <c>amount</c> and <c>exponent</c>.</summary>
    /// <param name="alphabeticCurrencyCode">The alphabetic CHOICE alternative, or <see langword="null"/> to use the numeric one.</param>
    /// <param name="numericCurrencyCode">The numeric CHOICE alternative; read only when <paramref name="alphabeticCurrencyCode"/> is <see langword="null"/>.</param>
    /// <param name="amount">The <c>MonetaryValue.amount</c>.</param>
    /// <param name="exponent">The <c>MonetaryValue.exponent</c>.</param>
    /// <returns>The info writer.</returns>
    private static Action<AsnWriter> WriteMonetaryValueInfo(string? alphabeticCurrencyCode, BigInteger? numericCurrencyCode, BigInteger amount, BigInteger exponent) => writer =>
    {
        using(writer.PushSequence())
        {
            if(alphabeticCurrencyCode is not null)
            {
                writer.WriteCharacterString(UniversalTagNumber.PrintableString, alphabeticCurrencyCode);
            }
            else
            {
                writer.WriteInteger(numericCurrencyCode!.Value);
            }

            writer.WriteInteger(amount);
            writer.WriteInteger(exponent);
        }
    };


    /// <summary>Writes a hostile clause 4.3.2 <c>MonetaryValue</c> <c>statementInfo</c> whose <c>currency</c> is a <c>UTF8String</c> — neither <c>Iso4217CurrencyCode</c> CHOICE arm.</summary>
    /// <returns>The info writer.</returns>
    private static Action<AsnWriter> WriteMonetaryValueInfoWithHostileCurrencyTag() => writer =>
    {
        using(writer.PushSequence())
        {
            writer.WriteCharacterString(UniversalTagNumber.UTF8String, "EUR");
            writer.WriteInteger(100);
            writer.WriteInteger(0);
        }
    };


    /// <summary>Writes a bare <c>INTEGER</c> <c>statementInfo</c>, the shape of a clause 4.3.3 <c>QcEuRetentionPeriod</c>.</summary>
    /// <param name="value">The integer value.</param>
    /// <returns>The info writer.</returns>
    private static Action<AsnWriter> WriteIntegerInfo(BigInteger value) => writer => writer.WriteInteger(value);


    /// <summary>Writes a bare <c>INTEGER</c> <c>statementInfo</c> followed by a second, hostile trailing <c>INTEGER</c> the SYNTAX value does not admit.</summary>
    /// <param name="value">The integer value the SYNTAX permits.</param>
    /// <param name="trailingValue">The hostile trailing integer written after it, inside the same statement.</param>
    /// <returns>The info writer.</returns>
    private static Action<AsnWriter> WriteIntegerInfoWithTrailingData(BigInteger value, BigInteger trailingValue) => writer =>
    {
        writer.WriteInteger(value);
        writer.WriteInteger(trailingValue);
    };


    /// <summary>Writes a hostile trailing <c>NULL</c> directly into a statement, appended after a <c>QcType</c> declared-types <c>SEQUENCE</c> the SYNTAX value does not admit.</summary>
    /// <returns>The info writer.</returns>
    private static Action<AsnWriter> WriteTrailingNullAfterDeclaredTypes() => writer => writer.WriteNull();


    /// <summary>Writes a clause 4.3.4 <c>PdsLocations ::= SEQUENCE SIZE (1..MAX) OF PdsLocation</c> <c>statementInfo</c>.</summary>
    /// <param name="locations">The URL and language pairs in sequence order.</param>
    /// <returns>The info writer.</returns>
    private static Action<AsnWriter> WritePdsLocationsInfo(params (string Url, string Language)[] locations) => writer =>
    {
        using(writer.PushSequence())
        {
            foreach((string url, string language) in locations)
            {
                using(writer.PushSequence())
                {
                    writer.WriteCharacterString(UniversalTagNumber.IA5String, url);
                    writer.WriteCharacterString(UniversalTagNumber.PrintableString, language);
                }
            }
        }
    };


    /// <summary>Writes a <c>SEQUENCE OF CountryName</c> <c>statementInfo</c>, the shape shared by clauses 4.2.4's <c>QcCClegislation</c> and 4.2.5's <c>QcQSCDlegislation</c>.</summary>
    /// <param name="countryCodes">The ISO 3166-1 alpha-2 country codes in sequence order.</param>
    /// <returns>The info writer.</returns>
    private static Action<AsnWriter> WriteCountryCodesInfo(params string[] countryCodes) => writer =>
    {
        using(writer.PushSequence())
        {
            foreach(string countryCode in countryCodes)
            {
                writer.WriteCharacterString(UniversalTagNumber.PrintableString, countryCode);
            }
        }
    };


    /// <summary>Writes a clause 4.3.5.3 <c>QcIdentMethod ::= SEQUENCE SIZE (1) OF OBJECT IDENTIFIER</c> <c>statementInfo</c>.</summary>
    /// <param name="identMethodOids">The identification method identifiers in sequence order.</param>
    /// <returns>The info writer.</returns>
    private static Action<AsnWriter> WriteIdentMethodsInfo(params string[] identMethodOids) => writer =>
    {
        using(writer.PushSequence())
        {
            foreach(string identMethodOid in identMethodOids)
            {
                writer.WriteObjectIdentifier(identMethodOid);
            }
        }
    };


    /// <summary>Creates a <c>PrintableString</c>-encoded name attribute.</summary>
    /// <param name="typeOid">The attribute type identifier.</param>
    /// <param name="value">The attribute value text.</param>
    /// <returns>The attribute.</returns>
    private static DirectoryAttribute Printable(string typeOid, string value) =>
        new(typeOid, value, UniversalTagNumber.PrintableString);


    /// <summary>Creates a <c>UTF8String</c>-encoded name attribute.</summary>
    /// <param name="typeOid">The attribute type identifier.</param>
    /// <param name="value">The attribute value text.</param>
    /// <returns>The attribute.</returns>
    private static DirectoryAttribute Utf8(string typeOid, string value) =>
        new(typeOid, value, UniversalTagNumber.UTF8String);


    /// <summary>
    /// Encodes a <c>Name</c> (an <c>RDNSequence</c>) per RFC 5280 §4.1.2.4 with <see cref="AsnWriter"/>,
    /// one inner array per relative distinguished name, so the expected DER order is fixed by construction.
    /// </summary>
    /// <param name="relativeNames">The relative distinguished names, each carrying its attributes.</param>
    /// <returns>The encoded name, passed to the certificate factory verbatim.</returns>
    private static X500DistinguishedName CreateName(params DirectoryAttribute[][] relativeNames)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            foreach(DirectoryAttribute[] relativeName in relativeNames)
            {
                using(writer.PushSetOf())
                {
                    foreach(DirectoryAttribute attribute in relativeName)
                    {
                        using(writer.PushSequence())
                        {
                            writer.WriteObjectIdentifier(attribute.TypeOid);
                            writer.WriteCharacterString(attribute.Encoding, attribute.Value);
                        }
                    }
                }
            }
        }

        return new X500DistinguishedName(writer.Encode());
    }


    /// <summary>
    /// Encodes a <c>QCStatements</c> extension per RFC 3739 §3.2.6 from the given statement specifications.
    /// </summary>
    /// <param name="statements">The statements in extension order.</param>
    /// <returns>The extension.</returns>
    private static X509Extension CreateQcStatementsExtension(params QcStatementSpec[] statements)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            foreach(QcStatementSpec statement in statements)
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(statement.StatementId);
                    if(statement.DeclaredTypeOids is not null)
                    {
                        using(writer.PushSequence())
                        {
                            foreach(string declaredTypeOid in statement.DeclaredTypeOids)
                            {
                                writer.WriteObjectIdentifier(declaredTypeOid);
                            }
                        }
                    }

                    if(statement.Utf8Payload is not null)
                    {
                        writer.WriteCharacterString(UniversalTagNumber.UTF8String, statement.Utf8Payload);
                    }

                    statement.WriteInfo?.Invoke(writer);
                }
            }
        }

        return new X509Extension(WellKnownOids.QcStatementsExtension, writer.Encode(), critical: false);
    }


    /// <summary>Encodes a <c>CertificatePolicies</c> extension per RFC 5280 §4.2.1.4 carrying the given policy identifiers.</summary>
    /// <param name="policyOids">The policy identifiers in extension order.</param>
    /// <returns>The extension.</returns>
    private static X509Extension CreateCertificatePoliciesExtension(params string[] policyOids)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())
        {
            foreach(string policyOid in policyOids)
            {
                using(writer.PushSequence())
                {
                    writer.WriteObjectIdentifier(policyOid);
                }
            }
        }

        return new X509Extension(WellKnownOids.CertificatePoliciesExtension, writer.Encode(), critical: false);
    }


    /// <summary>
    /// Mints a certificate with the given names, validity and extensions, signed by a throwaway issuer
    /// key, straight into a pooled carrier.
    /// </summary>
    /// <param name="issuerName">The issuer name, verbatim.</param>
    /// <param name="subjectName">The subject name, verbatim.</param>
    /// <param name="notBefore">The validity start.</param>
    /// <param name="notAfter">The validity end.</param>
    /// <param name="extensions">The extensions, in certificate order.</param>
    /// <returns>The certificate carrier; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned PkiCertificateMemory, which the caller disposes.")]
    private static PkiCertificateMemory MintCertificate(
        X500DistinguishedName issuerName,
        X500DistinguishedName subjectName,
        DateTimeOffset notBefore,
        DateTimeOffset notAfter,
        IReadOnlyList<X509Extension> extensions)
    {
        //X.509 cert-factory carve-out: CertificateRequest needs live framework signing keys.
        using ECDsa issuerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using ECDsa subjectKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        var request = new CertificateRequest(subjectName, subjectKey, HashAlgorithmName.SHA256);
        foreach(X509Extension extension in extensions)
        {
            request.CertificateExtensions.Add(extension);
        }

        using Salt serialNumber = X509ChainTestRing.CreateSerialNumber();
        using X509Certificate2 certificate = request.Create(
            issuerName,
            X509SignatureGenerator.CreateForECDsa(issuerKey),
            notBefore,
            notAfter,
            serialNumber.AsReadOnlySpan());

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.RawDataMemory.Length);
        certificate.RawDataMemory.Span.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Assembles a certificate DER structure directly with <see cref="AsnWriter"/>, for the RFC 5280 paths
    /// the platform factory cannot mint: the §4.1.2.8 unique identifiers, duplicate extensions, and a
    /// mis-tagged or malformed extensions block. The serial number and the signature fields are fixed
    /// structural stand-ins — the extractor validates their shape, never their content — in the same way
    /// the qualification procedure vectors use DER stand-in bytes.
    /// </summary>
    /// <param name="withUniqueIdentifiers">Whether the obsolete <c>issuerUniqueID [1]</c> and <c>subjectUniqueID [2]</c> fields are present.</param>
    /// <param name="extensions">The extensions in certificate order, duplicates permitted; <see langword="null"/> for no extensions block.</param>
    /// <param name="extensionsTagNumber">The context-specific tag number of the extensions block; 3 is the conformant value.</param>
    /// <param name="malformExtensionsContent">Whether the extensions block wraps junk instead of the <c>Extensions</c> sequence.</param>
    /// <returns>The certificate carrier; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned PkiCertificateMemory, which the caller disposes.")]
    private static PkiCertificateMemory MintSyntheticCertificate(
        bool withUniqueIdentifiers = false,
        IReadOnlyList<X509Extension>? extensions = null,
        int extensionsTagNumber = 3,
        bool malformExtensionsContent = false)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        using(writer.PushSequence())                                        //Certificate.
        {
            using(writer.PushSequence())                                    //tbsCertificate.
            {
                using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    writer.WriteInteger(2);                                 //version v3.
                }

                writer.WriteInteger(1);                                     //serialNumber stand-in.
                using(writer.PushSequence())                                //signature AlgorithmIdentifier stand-in.
                {
                    writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
                }

                writer.WriteEncodedValue(CreateName([Utf8(WellKnownOids.CommonName, "Synthetic CA")]).RawData);
                using(writer.PushSequence())                                //validity.
                {
                    writer.WriteUtcTime(DefaultNotBefore);
                    writer.WriteUtcTime(DefaultNotAfter);
                }

                writer.WriteEncodedValue(CreateName([Utf8(WellKnownOids.CommonName, "Synthetic Subject")]).RawData);
                using(writer.PushSequence())                                //subjectPublicKeyInfo stand-in, skipped whole by the extractor.
                {
                }

                if(withUniqueIdentifiers)
                {
                    writer.WriteBitString([0xA5], 0, new Asn1Tag(TagClass.ContextSpecific, 1));
                    writer.WriteBitString([0x5A], 0, new Asn1Tag(TagClass.ContextSpecific, 2));
                }

                if(extensions is not null || malformExtensionsContent)
                {
                    using(writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, extensionsTagNumber)))
                    {
                        if(malformExtensionsContent)
                        {
                            writer.WriteOctetString([0x01]);
                        }
                        else
                        {
                            using(writer.PushSequence())                    //Extensions.
                            {
                                foreach(X509Extension extension in extensions!)
                                {
                                    using(writer.PushSequence())            //Extension.
                                    {
                                        writer.WriteObjectIdentifier(extension.Oid!.Value!);
                                        if(extension.Critical)
                                        {
                                            writer.WriteBoolean(true);
                                        }

                                        writer.WriteOctetString(extension.RawData);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            using(writer.PushSequence())                                    //signatureAlgorithm stand-in.
            {
                writer.WriteObjectIdentifier(WellKnownOids.EcPublicKey);
            }

            writer.WriteBitString([]);                                      //signatureValue stand-in.
        }

        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(writer.GetEncodedLength());
        _ = writer.Encode(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>Clones a certificate carrier into fresh pooled memory, optionally under a different tag.</summary>
    /// <param name="certificate">The carrier to clone.</param>
    /// <param name="tag">The tag for the clone; the certificate tag when omitted.</param>
    /// <returns>The cloned carrier; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned PkiCertificateMemory, which the caller disposes.")]
    private static PkiCertificateMemory CloneCertificate(PkiCertificateMemory certificate, Tag? tag = null)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
        certificate.AsReadOnlySpan().CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, tag ?? PkiCertificateTags.X509Certificate);
    }


    /// <summary>Creates a trusted list with one FI provider carrying one granted CA/QC service of the given kind recognising the given certificate.</summary>
    /// <param name="certificate">The certificate the service's digital identity carries; cloned, the caller keeps ownership.</param>
    /// <param name="additionalInformationType">The service kind.</param>
    /// <returns>The trusted list; the caller disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the cloned certificate carrier transfers to the returned TrustedList, which the caller disposes.")]
    private static TrustedList CreateSingleServiceTrustedList(
        PkiCertificateMemory certificate,
        TrustServiceAdditionalInformationType additionalInformationType) => new()
    {
        SchemeInformation = new TrustedListSchemeInformation
        {
            TslVersionIdentifier = 6,
            TslSequenceNumber = 1,
            TslType = TrustedListKind.Generic,
            SchemeOperatorNames = [new LocalizedText("en", "Example Supervisory Body")],
            SchemeOperatorPostalAddresses = [],
            SchemeOperatorElectronicAddresses = [],
            SchemeNames = [new LocalizedText("en", "FI: Example Trusted List")],
            SchemeInformationUris = [],
            StatusDeterminationApproach = "http://uri.etsi.org/TrstSvc/TrustedList/StatusDetn/EUappropriate",
            SchemeTerritory = "FI",
            HistoricalInformationPeriodYears = 65535,
            ListIssueDateTime = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero)
        },
        TrustServiceProviders =
        [
            new TrustServiceProvider
            {
                Names = [new LocalizedText("en", ProviderOrganizationName)],
                TradeNames = [new LocalizedText("en", $"{ProviderOrganizationName} Trade")],
                PostalAddresses = [],
                ElectronicAddresses = [],
                InformationUris = [],
                Services =
                [
                    new TrustService
                    {
                        ServiceTypeIdentifier = TrustServiceTypeIdentifier.CertificationAuthorityQualifiedCertificates,
                        ServiceNames = [new LocalizedText("en", "Example CA")],
                        DigitalIdentity = new ServiceDigitalIdentity { Entries = [new X509CertificateIdentity(CloneCertificate(certificate))] },
                        Status = TrustServiceStatus.Granted,
                        StatusStartingTime = new DateTimeOffset(2017, 1, 1, 0, 0, 0, TimeSpan.Zero),
                        AdditionalServiceInformation = [additionalInformationType],
                        Qualifications = [],
                        History = []
                    }
                ]
            }
        ]
    };
}
