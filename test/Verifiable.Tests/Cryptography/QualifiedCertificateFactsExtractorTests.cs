using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using System.IO;
using System.Linq;
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
/// <see cref="AsnReader"/> walk — while the corpus test provides the fully independent cross-check,
/// comparing the extraction against the platform's own certificate decoder over every service certificate
/// of the real TL/LOTL corpus, bytes produced by heterogeneous real-world CA software. The capstone drives
/// extracted facts through the shipped
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
    /// Extracts facts from every service certificate of every valid fixture of the real TL/LOTL corpus and
    /// compares each extraction against the platform's own certificate decoder: the validity start and the
    /// presence and contents of the KeyUsage and ExtendedKeyUsage extensions must agree exactly, and the
    /// QCStatements and CertificatePolicies facts must be consistent with the platform's extension list.
    /// </summary>
    [TestMethod]
    public async Task ExtractsFactsFromEveryCorpusServiceCertificateConsistentlyWithThePlatformDecoder()
    {
        string? resourcesDirectory = TryFindDssTrustedListResourcesDirectory();
        if(resourcesDirectory is null)
        {
            Assert.Inconclusive("The local ETSI/eIDAS reference clone (tempdocs/etsi-ades-reference/dss) was not found; the DSS TL/LOTL corpus is optional local reference material.");
            return;
        }

        int certificateCount = 0;
        foreach(string filePath in Directory.EnumerateFiles(resourcesDirectory, "*.xml", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal))
        {
            string fileName = Path.GetFileName(filePath);
            using PooledMemory document = PooledMemory.FromBytes(
                await File.ReadAllBytesAsync(filePath, TestContext.CancellationToken).ConfigureAwait(false),
                BaseMemoryPool.Shared,
                TrustedListTags.Document);
            using TrustedListParseResult result = await TrustedListXmlParser.ParseAsync(document, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
            if(!result.IsValid)
            {
                //The corpus negatives are the parser fixture tests' concern, not this differential's.
                continue;
            }

            foreach(TrustServiceProvider provider in result.Document!.TrustServiceProviders)
            {
                foreach(TrustService service in provider.Services)
                {
                    foreach(ServiceDigitalIdentityEntry entry in service.DigitalIdentity.Entries)
                    {
                        if(entry is not X509CertificateIdentity certificateIdentity)
                        {
                            continue;
                        }

                        certificateCount++;
                        QualifiedCertificateFacts facts = QualifiedCertificateFactsExtractor.Extract(certificateIdentity.Certificate);
                        using X509Certificate2 oracle = X509CertificateLoader.LoadCertificate(certificateIdentity.Certificate.AsReadOnlySpan());

                        Assert.AreEqual(oracle.NotBefore.ToUniversalTime(), facts.NotBefore.UtcDateTime, $"{fileName}: the notBefore instant must match the platform decoder for '{oracle.Subject}'.");

                        HashSet<string> oracleExtensionOids = [.. oracle.Extensions.Select(extension => extension.Oid!.Value!)];
                        if(!oracleExtensionOids.Contains(WellKnownOids.QcStatementsExtension))
                        {
                            //The facts record carries no presence flag for QCStatements itself, so only the
                            //absence direction is assertable: no extension, no statement facts.
                            Assert.IsFalse(facts.HasQcCompliance, $"{fileName}: a certificate without QCStatements cannot declare QcCompliance ('{oracle.Subject}').");
                            Assert.IsFalse(facts.HasQcSscdStatement, $"{fileName}: a certificate without QCStatements cannot declare QcSSCD ('{oracle.Subject}').");
                            Assert.IsEmpty(facts.QcTypes, $"{fileName}: a certificate without QCStatements declares no types ('{oracle.Subject}').");
                        }

                        Assert.AreEqual(oracleExtensionOids.Contains(WellKnownOids.CertificatePoliciesExtension), facts.HasCertificatePoliciesExtension, $"{fileName}: CertificatePolicies presence must match the platform decoder for '{oracle.Subject}'.");
                        Assert.AreEqual(oracleExtensionOids.Contains(WellKnownOids.KeyUsageExtension), facts.HasKeyUsageExtension, $"{fileName}: KeyUsage presence must match the platform decoder for '{oracle.Subject}'.");
                        Assert.AreEqual(oracleExtensionOids.Contains(WellKnownOids.ExtendedKeyUsageExtension), facts.HasExtendedKeyUsageExtension, $"{fileName}: ExtendedKeyUsage presence must match the platform decoder for '{oracle.Subject}'.");

                        X509KeyUsageExtension? oracleKeyUsage = oracle.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
                        if(oracleKeyUsage is not null)
                        {
                            X509KeyUsageFlags extractedFlags = facts.SetKeyUsageBits.Aggregate(X509KeyUsageFlags.None, (flags, bit) => flags | ToKeyUsageFlag(bit));
                            Assert.AreEqual(oracleKeyUsage.KeyUsages, extractedFlags, $"{fileName}: the asserted Key Usage bits must match the platform decoder for '{oracle.Subject}'.");
                        }

                        X509EnhancedKeyUsageExtension? oracleExtendedKeyUsage = oracle.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
                        if(oracleExtendedKeyUsage is not null)
                        {
                            Assert.AreSequenceEqual(
                                oracleExtendedKeyUsage.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value!),
                                facts.ExtendedKeyUsageOids,
                                $"{fileName}: the key purpose identifiers must match the platform decoder for '{oracle.Subject}'.");
                        }
                    }
                }
            }
        }

        Assert.IsGreaterThan(0, certificateCount, "The corpus is expected to carry service certificates; none were found, so this differential no longer exercises anything.");
        TestContext.WriteLine($"Extracted and cross-checked {certificateCount} service certificates from the corpus.");
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
        X500DistinguishedName name = CreateName([Utf8(WellKnownOids.CommonName, "Empty Extensions")]);
        using PkiCertificateMemory certificate = MintCertificate(name, name, DefaultNotBefore, DefaultNotAfter,
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


    /// <summary>One <c>AttributeTypeAndValue</c> to encode into a minted name.</summary>
    /// <param name="TypeOid">The attribute type identifier.</param>
    /// <param name="Value">The attribute value text.</param>
    /// <param name="Encoding">The string form the value is encoded in.</param>
    private readonly record struct DirectoryAttribute(string TypeOid, string Value, UniversalTagNumber Encoding);


    /// <summary>One <c>QCStatement</c> to encode into a minted <c>QCStatements</c> extension, specified in domain terms so no encoded fragment travels between helpers.</summary>
    /// <param name="StatementId">The statement identifier.</param>
    /// <param name="DeclaredTypeOids">The <c>QcType</c> info's declared type identifiers in sequence order, or <see langword="null"/> for no info.</param>
    /// <param name="Utf8Payload">An arbitrary <c>UTF8String</c> info payload for an unknown statement, or <see langword="null"/> for none.</param>
    private sealed record QcStatementSpec(string StatementId, IReadOnlyList<string>? DeclaredTypeOids = null, string? Utf8Payload = null);


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


    /// <summary>Maps a <see cref="KeyUsageBitName"/> to the platform decoder's flag for the corpus differential.</summary>
    /// <param name="bit">The bit to map.</param>
    /// <returns>The platform flag.</returns>
    private static X509KeyUsageFlags ToKeyUsageFlag(KeyUsageBitName bit) => bit switch
    {
        KeyUsageBitName.DigitalSignature => X509KeyUsageFlags.DigitalSignature,
        KeyUsageBitName.NonRepudiation => X509KeyUsageFlags.NonRepudiation,
        KeyUsageBitName.KeyEncipherment => X509KeyUsageFlags.KeyEncipherment,
        KeyUsageBitName.DataEncipherment => X509KeyUsageFlags.DataEncipherment,
        KeyUsageBitName.KeyAgreement => X509KeyUsageFlags.KeyAgreement,
        KeyUsageBitName.KeyCertSign => X509KeyUsageFlags.KeyCertSign,
        KeyUsageBitName.CrlSign => X509KeyUsageFlags.CrlSign,
        KeyUsageBitName.EncipherOnly => X509KeyUsageFlags.EncipherOnly,
        KeyUsageBitName.DecipherOnly => X509KeyUsageFlags.DecipherOnly,
        _ => X509KeyUsageFlags.None
    };


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


    /// <summary>Locates the DSS trusted-list resources directory of the optional local reference clone, exactly as the parser fixture tests do.</summary>
    /// <returns>The resources directory, or <see langword="null"/> when the optional local clone is absent.</returns>
    private static string? TryFindDssTrustedListResourcesDirectory()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while(current is not null && !File.Exists(Path.Combine(current.FullName, "Verifiable.slnx")))
        {
            current = current.Parent;
        }

        if(current is null)
        {
            return null;
        }

        string candidate = Path.Combine(current.FullName, "tempdocs", "etsi-ades-reference", "dss", "dss-tsl-validation", "src", "test", "resources");

        return Directory.Exists(candidate) ? candidate : null;
    }
}
