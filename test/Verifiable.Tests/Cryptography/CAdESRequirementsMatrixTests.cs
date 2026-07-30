using System;
using System.Buffers;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.BouncyCastle;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// The RFC 2119 requirements matrix for the CAdES creation and long-term-availability surface built across
/// this wave: every row of Table 1 (clause 6.3, both parts) of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1</see>, its lettered requirements a)-t), the opt-in signed-attribute normative
/// content of clauses 5.2.5/5.2.6.1/5.2.7/5.2.8, the <c>ats-hash-index-v3</c>/<c>archive-time-stamp-v3</c>
/// normative terms of clauses 5.5.2/5.5.3 (including NOTE 4/NOTE 6's countersignature interaction), the
/// closed-set rules of Annex A.1.1.2/A.1.2.2, the deprecation rules of Annex A.2, clause 6.2.1's algorithm
/// rules, the clause-4 CMS dependencies this wave actually exercises, and TS 119 102-2 clause 4.4.7's
/// Proof-of-Existence provisioning this wave populates. Mirrors the DynamicData-rows-as-spec-cells shape of
/// <c>SignatureValidationRequirementsMatrixTests</c> (ETSI EN 319 102-1) and the 240-cell
/// <c>TrustedListQualificationTests</c> table (ETSI TS 119 615 clause 4).
/// </summary>
/// <remarks>
/// <para>
/// Every distinct normative statement of the in-scope clause range is one <see cref="RequirementMatrixRow"/>.
/// <see cref="RequirementMatrixTest"/> fails a row that is neither <see cref="RequirementCoverageStatus.Tested"/>
/// nor <see cref="RequirementCoverageStatus.OutOfScope"/> nor <see cref="RequirementCoverageStatus.KnownDefect"/>
/// — no silent gaps — and, for the first two dispositions, additionally resolves the cited evidence through
/// reflection over the compiled test assembly: a row citing a class or method that does not exist, or that is
/// not itself a <c>[TestMethod]</c>, fails. This goes beyond checking that an evidence string is merely
/// non-empty (an existence check on metadata) — it verifies the row's claim of "a real test drives this clause"
/// against the actual shipped test surface, so a renamed or deleted evidence method is caught here rather than
/// silently rotting into a stale citation.
/// </para>
/// <para>
/// Most rows cite the deep behavioural test that already exercises the clause through the shipped creation or
/// augmentation surface (stages 1-9 and the delta stages D1-D4 of this wave; every cited test itself calls
/// production code and asserts a real outcome — verified by reading each one before citing it here, not merely
/// by name). A handful of rows had no existing test anywhere in the suite; those are driven directly by new
/// tests in this class (<see cref="CoreSignedAttributesCarryTheRequiredValues"/>,
/// <see cref="EveryProducedSignatureCarriesExactlyOneSignerInfo"/>,
/// <see cref="NoAnnexAReferenceFamilyAttributeAppearsInAProducedBLtaSignature"/>,
/// <see cref="EveryAttributeOidGetterMatchesItsSpecificationValue"/>) which call the shipped
/// <see cref="CAdESSignatureCreation"/>/<see cref="CAdESSignatureAugmentation"/> surface themselves rather than
/// merely asserting the row's metadata. Several rows additionally cite
/// <c>CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation</c>
/// (delta stage D4) as SUPPLEMENTARY evidence that the same clause is witnessed again across a real socket —
/// added only where that flow genuinely exercises the clause (it uses OCSP, not CRL, revocation, and strategy 1
/// placement only, so rows specific to CRL placement or the legacy strategy-2 path are not so decorated).
/// </para>
/// <para>
/// <see cref="RequirementCoverageStatus.OutOfScope"/> rows carry the contract reason verbatim where one is
/// named (the wavelta contract's "Out" list, a stage's own recorded flag, or — where the reason is an
/// EN 319 102-1 engine concern this CAdES-specific matrix does not own — a note that AMENDMENT 2's narrow
/// engine change does not touch it). Delta stages D2/D3 built essentially every Table 1 <c>may</c>/<c>should</c>
/// signed attribute this matrix previously marked out of scope on "stage 4 flag 2" grounds (commitment-type-
/// indication, content-hints, mime-type, signer-location, content-reference, content-identifier,
/// signature-policy-identifier/-store, content-time-stamp, countersignature, signer-attributes-v2's
/// <c>claimedAttributes</c> arm) and requirement m) — those rows are <see cref="RequirementCoverageStatus.Tested"/>
/// now; only <c>signer-attributes-v2</c>'s <c>certifiedAttributesV2</c>/<c>signedAssertions</c> arms
/// (requirement n)'s row) remain a RECORDED deliberate pass, per <see cref="CAdESSignerAttributesV2"/>'s own
/// remarks (D3's exact reason: attribute-certificate infrastructure this library has nowhere, its own arc).
/// The <c>5.2.5-signerlocation-tagging</c> row — D3 found the shipped <c>signer-location</c> encoder tagged
/// <c>postalAddress</c> IMPLICIT where its own ASN.1 module (<c>DEFINITIONS EXPLICIT TAGS</c>) requires
/// EXPLICIT — is now <see cref="RequirementCoverageStatus.Tested"/> (fixed in FX3, defect D-C; its row pins the
/// exact EXPLICIT-TAGS DER to the octet). The <c>revocation-values</c> field tagging had the same defect
/// (D-D) and is likewise fixed and byte-decoded.
/// </para>
/// </remarks>
[TestClass]
internal sealed class CAdESRequirementsMatrixTests
{
    /// <summary>Whether a requirement row has been driven through a concrete test, is explicitly out of this wave's scope, or is implemented and unit-tested at the building-block level but not reachable through the shipped default composition because of an already-flagged, unfixed defect elsewhere in the pipeline.</summary>
    internal enum RequirementCoverageStatus
    {
        /// <summary>No disposition has been recorded. The value of an unset field, by design: a row must never silently pass as covered.</summary>
        Untested = 0,

        /// <summary>The requirement is driven by at least one concrete, named test that calls the shipped surface.</summary>
        Tested = 1,

        /// <summary>The requirement is explicitly out of this wave's scope, per the arc contract, the charter, or a stage's own recorded flag.</summary>
        OutOfScope = 2,

        /// <summary>The requirement's own building block implements and unit-tests it, but the shipped default composition cannot reach it because of an already-flagged, unfixed defect elsewhere in the pipeline.</summary>
        KnownDefect = 3
    }


    /// <summary>One row of the matrix: a clause identifier, a short digest of the requirement it names, its coverage disposition, and the evidence for that disposition.</summary>
    /// <param name="ClauseId">The clause and, where applicable, table/row/letter identifier the requirement comes from.</param>
    /// <param name="Requirement">A short digest of the normative statement, close enough to the specification's own wording to be checked against it.</param>
    /// <param name="Status">The coverage disposition.</param>
    /// <param name="Evidence">For <see cref="RequirementCoverageStatus.Tested"/>/<see cref="RequirementCoverageStatus.KnownDefect"/>, the asserting test's <c>ClassName.MethodName</c> (optionally followed by explanatory prose in parentheses) — the leading token is resolved through reflection; for <see cref="RequirementCoverageStatus.OutOfScope"/>, the contract or charter reason.</param>
    internal sealed record RequirementMatrixRow(string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence);


    /// <summary>The MSTest context, providing the cancellation token every asynchronous call threads.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The address the new behavioural tests' transport delegates are handed; no socket is opened for it.</summary>
    private const string TsaUri = "http://tsa.requirements-matrix.example.test/";

    /// <summary>An Annex A.1.3 attribute this wave never emits (<c>signer-attributes-v2</c> is not implemented), carried as a literal because no production getter names it — recognising an unimplemented attribute is a test-only concern.</summary>
    private const string AttributeCertificateReferencesAttributeOid = "1.2.840.113549.1.9.16.2.44";

    /// <summary>An Annex A.1.4 attribute this wave never emits, for the same reason as <see cref="AttributeCertificateReferencesAttributeOid"/>.</summary>
    private const string AttributeRevocationReferencesAttributeOid = "1.2.840.113549.1.9.16.2.45";

    /// <summary>The <c>id-data</c> content type (RFC 5652 §4) — requirement f)'s only legal <c>eContentType</c>.</summary>
    private const string IdDataOid = "1.2.840.113549.1.7.1";

    /// <summary>The minted certificates' validity start.</summary>
    private static DateTimeOffset NotBefore { get; } = TestClock.CanonicalEpoch.AddYears(-1);

    /// <summary>The minted certificates' validity end.</summary>
    private static DateTimeOffset NotAfter { get; } = TestClock.CanonicalEpoch.AddYears(9);

    /// <summary>The signing time every new test in this class signs with.</summary>
    private static DateTimeOffset SigningTime { get; } = TestClock.CanonicalEpoch;

    /// <summary>The generation time the signature time-stamp of the new behavioural tests' world states.</summary>
    private static DateTimeOffset SignatureTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(1);

    /// <summary>The generation time the archive time-stamp of the new behavioural tests' world states.</summary>
    private static DateTimeOffset ArchiveTimestampTime { get; } = TestClock.CanonicalEpoch.AddHours(2);

    /// <summary>The content every new test in this class signs.</summary>
    private static ReadOnlyMemory<byte> Content { get; } = new("the requirements-matrix content"u8.ToArray());


    /// <summary>The requirements matrix, one row per <c>object[]</c>.</summary>
    /// <returns>Every row.</returns>
    public static IEnumerable<object[]> Requirements()
    {
        foreach((string clauseId, string requirement, RequirementCoverageStatus status, string evidence) in RowData)
        {
            yield return [new RequirementMatrixRow(clauseId, requirement, status, evidence)];
        }
    }


    /// <summary>
    /// No row of the matrix may be left without a coverage disposition, and a <see cref="RequirementCoverageStatus.Tested"/>
    /// or <see cref="RequirementCoverageStatus.KnownDefect"/> row's evidence must resolve to a real, existing
    /// <c>[TestMethod]</c> in the compiled test assembly.
    /// </summary>
    /// <param name="row">The row under test.</param>
    [TestMethod]
    [DynamicData(nameof(Requirements))]
    public void RequirementMatrixTest(RequirementMatrixRow row)
    {
        Assert.AreNotEqual(RequirementCoverageStatus.Untested, row.Status, $"{row.ClauseId}: '{row.Requirement}' has no coverage disposition.");
        Assert.IsFalse(string.IsNullOrWhiteSpace(row.Evidence), $"{row.ClauseId}: '{row.Requirement}' needs a named test or a stated reason.");

        if(row.Status is RequirementCoverageStatus.Tested or RequirementCoverageStatus.KnownDefect)
        {
            AssertEvidenceNamesAShippedTestMethod(row);
        }
    }


    /// <summary>
    /// Every OID getter <see cref="CAdESSignatureFacts"/> exposes for this wave's attributes equals the value
    /// EN 319 122-1's Annex D (or, for the ATSv2 predecessor, ETSI TS 101 733, per the docstring's own citation
    /// note) actually specifies. This is a genuinely independent check: the tests that prove a deprecated or
    /// closed-set attribute is absent from a produced signature use the SAME getter as both the value under
    /// test and the oracle, so a wrong constant would pass them trivially. Re-deriving the expected value from
    /// the specification text here closes that self-reference.
    /// </summary>
    /// <param name="getterName">The <see cref="CAdESSignatureFacts"/> static property name.</param>
    /// <param name="expectedOid">The dotted-decimal object identifier the specification states.</param>
    [TestMethod]
    [DataRow(nameof(CAdESSignatureFacts.ContentTypeAttributeOid), "1.2.840.113549.1.9.3")]
    [DataRow(nameof(CAdESSignatureFacts.MessageDigestAttributeOid), "1.2.840.113549.1.9.4")]
    [DataRow(nameof(CAdESSignatureFacts.SigningTimeAttributeOid), "1.2.840.113549.1.9.5")]
    [DataRow(nameof(CAdESSignatureFacts.SigningCertificateAttributeOid), "1.2.840.113549.1.9.16.2.12")]
    [DataRow(nameof(CAdESSignatureFacts.SigningCertificateV2AttributeOid), "1.2.840.113549.1.9.16.2.47")]
    [DataRow(nameof(CAdESSignatureFacts.SignaturePolicyIdentifierAttributeOid), "1.2.840.113549.1.9.16.2.15")]
    [DataRow(nameof(CAdESSignatureFacts.ContentTimestampAttributeOid), "1.2.840.113549.1.9.16.2.20")]
    [DataRow(nameof(CAdESSignatureFacts.SignatureTimestampAttributeOid), "1.2.840.113549.1.9.16.2.14")]
    [DataRow(nameof(CAdESSignatureFacts.CompleteCertificateReferencesAttributeOid), "1.2.840.113549.1.9.16.2.21")]
    [DataRow(nameof(CAdESSignatureFacts.CompleteRevocationReferencesAttributeOid), "1.2.840.113549.1.9.16.2.22")]
    [DataRow(nameof(CAdESSignatureFacts.CertificateValuesAttributeOid), "1.2.840.113549.1.9.16.2.23")]
    [DataRow(nameof(CAdESSignatureFacts.RevocationValuesAttributeOid), "1.2.840.113549.1.9.16.2.24")]
    [DataRow(nameof(CAdESSignatureFacts.EscTimestampAttributeOid), "1.2.840.113549.1.9.16.2.25")]
    [DataRow(nameof(CAdESSignatureFacts.CertificateAndCrlTimestampAttributeOid), "1.2.840.113549.1.9.16.2.26")]
    [DataRow(nameof(CAdESSignatureFacts.ArchiveTimestampV2AttributeOid), "1.2.840.113549.1.9.16.2.48")]
    [DataRow(nameof(CAdESSignatureFacts.ArchiveTimestampV3AttributeOid), "0.4.0.1733.2.4")]
    [DataRow(nameof(CAdESSignatureFacts.AtsHashIndexV3AttributeOid), "0.4.0.19122.1.5")]
    [DataRow(nameof(CAdESSignatureFacts.LongTermValidationAttributeOid), "0.4.0.1733.2.2")]
    [DataRow(nameof(CAdESSignatureFacts.AtsHashIndexAttributeOid), "0.4.0.1733.2.5")]
    [DataRow(nameof(CAdESSignatureFacts.AtsHashIndexV2AttributeOid), "0.4.0.19122.1.4")]
    [DataRow(nameof(CAdESSignatureFacts.CommitmentTypeIndicationAttributeOid), "1.2.840.113549.1.9.16.2.16")]
    [DataRow(nameof(CAdESSignatureFacts.ContentHintsAttributeOid), "1.2.840.113549.1.9.16.2.4")]
    [DataRow(nameof(CAdESSignatureFacts.MimeTypeAttributeOid), "0.4.0.1733.2.1")]
    [DataRow(nameof(CAdESSignatureFacts.SignerLocationAttributeOid), "1.2.840.113549.1.9.16.2.17")]
    [DataRow(nameof(CAdESSignatureFacts.ContentReferenceAttributeOid), "1.2.840.113549.1.9.16.2.10")]
    [DataRow(nameof(CAdESSignatureFacts.ContentIdentifierAttributeOid), "1.2.840.113549.1.9.16.2.7")]
    [DataRow(nameof(CAdESSignatureFacts.SignaturePolicyStoreAttributeOid), "0.4.0.19122.1.3")]
    [DataRow(nameof(CAdESSignatureFacts.SignerAttributesV2AttributeOid), "0.4.0.19122.1.1")]
    [DataRow(nameof(CAdESSignatureFacts.CountersignatureAttributeOid), "1.2.840.113549.1.9.6")]
    public void EveryAttributeOidGetterMatchesItsSpecificationValue(string getterName, string expectedOid)
    {
        PropertyInfo? property = typeof(CAdESSignatureFacts).GetProperty(getterName, BindingFlags.Public | BindingFlags.Static);
        Assert.IsNotNull(property, $"{getterName} must exist on {nameof(CAdESSignatureFacts)}.");

        var actualOid = (string)property!.GetValue(null)!;
        Assert.AreEqual(expectedOid, actualOid, $"{getterName} must equal the specification's object identifier.");
    }


    /// <summary>
    /// Requirement f) (<c>content-type</c> shall have value <c>id-data</c>), Table 1's <c>message-digest</c>
    /// row (shall be present), and Table 1's <c>signing-time</c> row (shall be present, carrying the caller's
    /// instant) — read back from a freshly minted CAdES-B-B signature through two independent readers: a raw
    /// <see cref="AsnReader"/> walk for the encapsulated content type and the signed <c>content-type</c>
    /// attribute's own value, and the shipped <see cref="CAdESSignatureFacts"/> extractor for
    /// <c>message-digest</c>'s presence/scope and <c>signing-time</c>'s value.
    /// </summary>
    [TestMethod]
    public async Task CoreSignedAttributesCarryTheRequiredValues()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintSigner();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, null, null, includeCmsAlgorithmProtection: false,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            byte[] octets = signedData.AsReadOnlySpan().ToArray();

            var reader = new AsnReader(octets, AsnEncodingRules.DER);
            AsnReader contentInfo = reader.ReadSequence();
            _ = contentInfo.ReadObjectIdentifier();
            AsnReader explicitContent = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            AsnReader cmsSignedData = explicitContent.ReadSequence();
            _ = cmsSignedData.TryReadInt32(out _);
            _ = cmsSignedData.ReadSetOf();
            AsnReader encapContentInfo = cmsSignedData.ReadSequence();
            string eContentType = encapContentInfo.ReadObjectIdentifier();
            Assert.AreEqual(IdDataOid, eContentType, "Requirement f): SignedData.encapContentInfo.eContentType shall be id-data.");

            List<byte[]> contentTypeValues = SignedAttributeValues(octets, signerIndex: 0, CAdESSignatureFacts.ContentTypeAttributeOid);
            Assert.HasCount(1, contentTypeValues, "Table 1: content-type shall be present, cardinality 1.");
            string contentTypeAttributeValue = AsnDecoder.ReadObjectIdentifier(contentTypeValues[0], AsnEncodingRules.DER, out _);
            Assert.AreEqual(IdDataOid, contentTypeAttributeValue, "Requirement f): the content-type SIGNED ATTRIBUTE value shall also be id-data.");

            using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
                new SignatureFactsExtractionContext { SignedDataObject = signedData }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsTrue(facts.TryGetAttribute(CAdESSignatureFacts.MessageDigestAttributeOid, out SignatureAttributeFacts? messageDigest),
                "Table 1: message-digest shall be present.");
            Assert.AreEqual(SignatureAttributeScope.Signed, messageDigest!.Scope, "message-digest is a signed attribute (clause 5.1.2).");
            Assert.IsTrue(messageDigest.IsWellFormed, "The binding must be able to decode the attribute it just produced.");

            Assert.AreEqual(SigningTime, facts.ClaimedSigningTime, "Table 1: signing-time shall be present and carry the caller's instant.");
        }
    }


    /// <summary>
    /// Clause 4.6's degenerate-no-signer prohibition ("the degenerate case where there are no signers shall
    /// not be used"): every signature the shipped creation surface produces carries exactly one
    /// <c>SignerInfo</c>, read back through the platform <see cref="SignedCms"/> reader.
    /// </summary>
    [TestMethod]
    public async Task EveryProducedSignatureCarriesExactlyOneSignerInfo()
    {
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintSigner();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData signedData = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, null, null, includeCmsAlgorithmProtection: false,
                BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            var platformReader = new SignedCms();
            platformReader.Decode(signedData.AsReadOnlySpan().ToArray());

            Assert.HasCount(1, platformReader.SignerInfos,
                "Clause 4.6: the degenerate no-signer case cannot arise; this surface always writes exactly one SignerInfo.");
        }
    }


    /// <summary>
    /// Table 1 Part B marks <c>complete-certificate-references</c>, <c>complete-revocation-references</c>,
    /// <c>attribute-certificate-references</c>, <c>attribute-revocation-references</c>, <c>CAdES-C-timestamp</c>
    /// and <c>time-stamped-certs-crls-references</c> "shall not be present" at every baseline level. A
    /// signature raised all the way to B-LTA through the shipped creation and augmentation surfaces is walked
    /// through the shipped <see cref="CAdESSignatureFacts"/> extractor and none of the six is found.
    /// </summary>
    [TestMethod]
    public async Task NoAnnexAReferenceFamilyAttributeAppearsInAProducedBLtaSignature()
    {
        using CmsSignedData archived = await BuildBLtaSignatureAsync(TestContext.CancellationToken).ConfigureAwait(false);
        using SignatureFacts facts = await CAdESSignatureFacts.ExtractAsync(
            new SignatureFactsExtractionContext { SignedDataObject = archived }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        string[] referenceFamily =
        [
            CAdESSignatureFacts.CompleteCertificateReferencesAttributeOid,
            CAdESSignatureFacts.CompleteRevocationReferencesAttributeOid,
            AttributeCertificateReferencesAttributeOid,
            AttributeRevocationReferencesAttributeOid,
            CAdESSignatureFacts.EscTimestampAttributeOid,
            CAdESSignatureFacts.CertificateAndCrlTimestampAttributeOid
        ];

        for(int i = 0; i < referenceFamily.Length; ++i)
        {
            Assert.IsFalse(facts.TryGetAttribute(referenceFamily[i], out _),
                $"Table 1 Part B / EN 319 122-2 §2: '{referenceFamily[i]}' is a reference-family attribute this baseline surface must never emit.");
        }
    }


    /// <summary>
    /// Resolves an evidence citation's leading <c>ClassName.MethodName</c> token against the compiled test
    /// assembly and fails when the class, the method, or the <c>[TestMethod]</c> attribute on it does not
    /// exist — a genuine check of the shipped test surface, not a check that a string happens to be non-empty.
    /// </summary>
    /// <param name="row">The row whose evidence is resolved.</param>
    private static void AssertEvidenceNamesAShippedTestMethod(RequirementMatrixRow row)
    {
        string token = row.Evidence.Split([' ', '('], 2, StringSplitOptions.RemoveEmptyEntries)[0];
        int separatorIndex = token.LastIndexOf('.');
        Assert.IsGreaterThan(0, separatorIndex, $"{row.ClauseId}: evidence '{row.Evidence}' must lead with a Class.Method pair.");

        string className = token[..separatorIndex];
        string methodName = token[(separatorIndex + 1)..];
        Type? evidenceType = typeof(CAdESRequirementsMatrixTests).Assembly.GetTypes()
            .FirstOrDefault(candidate => string.Equals(candidate.Name, className, StringComparison.Ordinal));
        Assert.IsNotNull(evidenceType, $"{row.ClauseId}: evidence class '{className}' does not exist in the test assembly.");

        MethodInfo? evidenceMethod = evidenceType!.GetMethod(
            methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
        Assert.IsNotNull(evidenceMethod, $"{row.ClauseId}: evidence method '{className}.{methodName}' does not exist.");
        Assert.IsNotEmpty(evidenceMethod!.GetCustomAttributes(typeof(TestMethodAttribute), inherit: false),
            $"{row.ClauseId}: evidence '{className}.{methodName}' is not a [TestMethod] — the matrix must cite a real test.");
    }


    /// <summary>
    /// Mints a CAdES-B-LTA signature through the shipped surface end to end: <see cref="CAdESSignatureCreation.SignAsync(PkiCertificateMemory, PrivateKeyMemory, ReadOnlyMemory{byte}?, ReadOnlyMemory{byte}?, DateTimeOffset, IReadOnlyList{PkiCertificateMemory}?, CryptographicConstraints?, bool, MemoryPool{byte}, CancellationToken)"/>
    /// for B-B, <see cref="CAdESSignatureAugmentation.AddSignatureTimestampAsync"/> for B-T, and
    /// <see cref="CAdESSignatureAugmentation.AddArchiveTimestampAsync"/> for B-LTA, mirroring
    /// <see cref="CAdESSignatureTestFactory.AttachArchiveTimestampAsync"/>'s "no explicit B-LT step needed"
    /// shape (the archive time-stamp's own <see cref="CAdESValidationMaterial.None"/> precondition step covers
    /// requirement s) directly).
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The B-LTA signature. The caller disposes it.</returns>
    private static async ValueTask<CmsSignedData> BuildBLtaSignatureAsync(CancellationToken cancellationToken)
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using X509ChainTestRingNode root = X509ChainTestRing.CreateRootCa(timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        using X509ChainTestRingNode authority = X509ChainTestRing.CreateTimeStampingAuthority(root, timeProvider, notBefore: NotBefore, notAfter: NotAfter);
        (PkiCertificateMemory certificate, PrivateKeyMemory privateKey) = MintSigner();
        using(certificate)
        using(privateKey)
        {
            using CmsSignedData baseline = await CAdESSignatureCreation.SignAsync(
                certificate, privateKey, Content, null, SigningTime, null, null, includeCmsAlgorithmProtection: false,
                BaseMemoryPool.Shared, cancellationToken).ConfigureAwait(false);

            var signatureResponder = new MintingTimestampResponder(authority, [authority], SignatureTimestampTime);
            using CmsSignedData timestamped = await CAdESSignatureAugmentation.AddSignatureTimestampAsync(
                new CAdESSignatureTimestampContext
                {
                    SignedData = baseline,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = signatureResponder.FetchAsync,
                    SigningCertificate = certificate
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);

            var archiveResponder = new MintingTimestampResponder(authority, [authority], ArchiveTimestampTime);

            return await CAdESSignatureAugmentation.AddArchiveTimestampAsync(
                new CAdESArchiveTimestampContext
                {
                    SignedData = timestamped,
                    SignerIndex = 0,
                    MessageImprintAlgorithm = PkiDigestAlgorithm.Sha256,
                    TsaUri = TsaUri,
                    FetchResponse = archiveResponder.FetchAsync,
                    ValidationMaterial = CAdESValidationMaterial.None,
                    SigningCertificate = certificate
                },
                BaseMemoryPool.Shared,
                cancellationToken).ConfigureAwait(false);
        }
    }


    /// <summary>
    /// Returns the whole encoding of every value of every signed attribute of one attribute type, walked
    /// independently of the library's own reader through <see cref="CmsStructureOracle"/> — the signed-side
    /// counterpart of the unsigned-attribute walker <see cref="CAdESSignatureAugmentationTests"/> uses.
    /// </summary>
    /// <param name="signedData">The Signed Data Object octets.</param>
    /// <param name="signerIndex">The zero-based index of the signer.</param>
    /// <param name="attributeType">The attribute's object identifier.</param>
    /// <returns>The whole encodings of the matching values.</returns>
    private static List<byte[]> SignedAttributeValues(byte[] signedData, int signerIndex, string attributeType)
    {
        List<byte[]> values = [];
        List<CmsTlvBounds> signerFields = CmsStructureOracle.SignerFields(signedData, signerIndex);
        CmsTlvBounds signedAttrs = signerFields[3];
        List<CmsTlvBounds> attributes = CmsStructureOracle.Children(signedData, signedAttrs);
        for(int i = 0; i < attributes.Count; ++i)
        {
            List<CmsTlvBounds> parts = CmsStructureOracle.Children(signedData, attributes[i]);
            string oid = AsnDecoder.ReadObjectIdentifier(signedData.AsSpan()[parts[0].Start..parts[0].End], AsnEncodingRules.BER, out _);
            if(!string.Equals(oid, attributeType, StringComparison.Ordinal))
            {
                continue;
            }

            List<CmsTlvBounds> members = CmsStructureOracle.Children(signedData, parts[1]);
            for(int j = 0; j < members.Count; ++j)
            {
                values.Add(signedData[members[j].Start..members[j].End]);
            }
        }

        return values;
    }


    /// <summary>Copies DER bytes into a pooled carrier tagged as an X.509 certificate.</summary>
    /// <param name="certificate">The DER-encoded certificate.</param>
    /// <returns>The carrier; the caller disposes it.</returns>
    private static PkiCertificateMemory ToCertificateCarrier(byte[] certificate)
    {
        IMemoryOwner<byte> owner = BaseMemoryPool.Shared.Rent(certificate.Length);
        certificate.CopyTo(owner.Memory.Span);

        return new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate);
    }


    /// <summary>
    /// Mints a P-256 signer: key material through <see cref="BouncyCastleKeyMaterialCreator"/> (the repo's
    /// test-key convention), and a self-signed certificate over the exact same public point, minted through a
    /// platform <see cref="ECDsa"/> reconstructed from the BouncyCastle-produced coordinates — the certificate
    /// vehicle is platform code, the key material the library signs with is not.
    /// </summary>
    /// <returns>The certificate and the private key material, both owned by the caller.</returns>
    private static (PkiCertificateMemory Certificate, PrivateKeyMemory PrivateKey) MintSigner()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys = BouncyCastleKeyMaterialCreator.CreateP256Keys(BaseMemoryPool.Shared);
        using(keys.PublicKey)
        {
            byte[] uncompressedPoint = EllipticCurveUtilities.NormalizeToUncompressed(keys.PublicKey.AsReadOnlySpan(), EllipticCurveTypes.P256);
            var ecParameters = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                D = keys.PrivateKey.AsReadOnlySpan().ToArray(),
                Q = new ECPoint
                {
                    X = EllipticCurveUtilities.SliceXCoordinate(uncompressedPoint).ToArray(),
                    Y = EllipticCurveUtilities.SliceYCoordinate(uncompressedPoint).ToArray()
                }
            };

            using ECDsa platformKey = ECDsa.Create(ecParameters);
            using X509Certificate2 platformCertificate = CmsSignedDataTestFactory.MintSelfSignedCertificate(platformKey, NotBefore, NotAfter);

            return (ToCertificateCarrier(platformCertificate.RawData), keys.PrivateKey);
        }
    }


    /// <summary>
    /// Every row of the matrix, as a plain data table. Kept as one literal so a reviewer can scan the whole
    /// EN 319 122-1 creation/LT/LTA requirement surface — and its disposition — in one place. Rows are grouped
    /// to follow the specification's own structure: Table 1 Part A (clause 6.3), Table 1 Part B, the lettered
    /// requirements a)-t) (clause 6.3), the delta-stage D2/D3 opt-in signed-attribute normative content of
    /// clauses 5.2.5/5.2.6.1/5.2.7/5.2.8, the clause-4 CMS dependencies this wave exercises, clause 5.5.2's
    /// <c>ats-hash-index-v3</c> terms, clause 5.5.3's <c>archive-time-stamp-v3</c> terms (including NOTE 4/
    /// NOTE 6's countersignature interaction), Annex A.1.1.2/A.1.2.2's closed-set terms, Annex A.2's deprecation
    /// terms, clause 6.2.1's algorithm terms, Annex A.1.5's imprint definitions, TS 119 102-2 clause 4.4.7, and
    /// the attribute-identifier cross-check.
    /// </summary>
    private static (string ClauseId, string Requirement, RequirementCoverageStatus Status, string Evidence)[] RowData { get; } =
    [
        //---- Table 1 Part A (clause 6.3) ----
        ("6.3-table1a-certificates", "SignedData.certificates shall be present at every baseline level.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.AttachedEcdsaSignatureVerifiesUnderThePlatformCmsReader (the platform reader locates the signer certificate from this field)"),
        ("6.3-table1a-content-type", "content-type shall be present at every baseline level.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.CoreSignedAttributesCarryTheRequiredValues"),
        ("6.3-table1a-message-digest", "message-digest shall be present at every baseline level.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.CoreSignedAttributesCarryTheRequiredValues"),
        ("6.3-table1a-svc-cert-protection", "Service: protection of the signing certificate shall be provided at every baseline level.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.TheSigningCertificateV2AttributeOmitsIssuerSerialAndTheDefaultHashAlgorithm (the service is delivered via signing-certificate-v2)"),
        ("6.3-table1a-spo-signing-certificate", "SPO: ESS signing-certificate (v1) is conditioned presence, cardinality 0 or 1.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.RefusesSha1AsACreationDigest (structural: v1's only legitimate hash, SHA-1, is refused as a creation digest, so v1 is never reachable)"),
        ("6.3-table1a-spo-signing-certificate-v2", "SPO: ESS signing-certificate-v2 is conditioned presence, cardinality 0 or 1.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.TheSigningCertificateV2AttributeOmitsIssuerSerialAndTheDefaultHashAlgorithm"),
        ("6.3-table1a-signing-time", "signing-time shall be present at every baseline level.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.CoreSignedAttributesCarryTheRequiredValues"),
        ("6.3-table1a-commitment-type-indication", "commitment-type-indication may be present.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.CommitmentTypeIndicationRoundTripsAndTheEngineAcceptsTheSignature"),
        ("6.3-table1a-svc-signed-data-type", "Service: identifying the signed data type should be present.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.ContentHintsRoundTripsAndTheEngineAcceptsTheSignature (the service is delivered by content-hints/mime-type; duplicate of requirement t))"),
        ("6.3-table1a-spo-content-hints", "SPO: content-hints is conditioned presence.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.ContentHintsRoundTripsAndTheEngineAcceptsTheSignature"),
        ("6.3-table1a-spo-mime-type", "SPO: mime-type is conditioned presence.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.MimeTypeRoundTripsAndTheEngineAcceptsTheSignature"),
        ("6.3-table1a-signer-location", "signer-location may be present.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.SignerLocationRoundTripsEveryFieldAndTheEngineAcceptsTheSignature (cardinality/presence; the postalAddress field's own tagging correctness is tracked separately as 5.2.5-signerlocation-tagging)"),
        ("6.3-table1a-signer-attributes-v2", "signer-attributes-v2 may be present, cardinality 0 or 1.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.SignerAttributesV2CarriesTheClaimedAttributesArmAndTheEngineAcceptsTheSignature (D3: the claimedAttributes arm only; certifiedAttributesV2/signedAssertions remain a RECORDED deliberate pass per CAdESSignerAttributesV2's own remarks, see requirement n))"),
        ("6.3-table1a-countersignature", "countersignature may be present, cardinality >= 0.",
            RequirementCoverageStatus.Tested, "CAdESCountersignatureTests.ACountersignedBaselineSignatureVerifiesUnderTheShippedPathAndBothIndependentReaders (D3; cardinality >= 0 additionally shown by CAdESCountersignatureTests.SeveralCountersignaturesArriveAsSiblingAttributesOrAsSeveralValuesOfOneAttribute)"),
        ("6.3-table1a-content-time-stamp", "content-time-stamp may be present.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.ContentTimeStampUsesTheRawValueImprintConventionNotTheAtsv3TlvConvention"),
        ("6.3-table1a-signature-policy-identifier", "signature-policy-identifier may be present.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.SignaturePolicyIdentifierRoundTripsAndTheEngineAcceptsTheSignature"),
        ("6.3-table1a-signature-policy-store", "signature-policy-store is conditioned presence.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.SignaturePolicyStoreIsAddedWhenTheHashIsNonZeroAndRoundTrips (duplicate of requirement k), gated there)"),
        ("6.3-table1a-content-reference", "content-reference may be present.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.ContentReferenceRoundTripsAndTheEngineAcceptsTheSignature"),
        ("6.3-table1a-content-identifier", "content-identifier may be present.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.ContentIdentifierRoundTripsAndTheEngineAcceptsTheSignature"),
        ("6.3-table1a-cms-algorithm-protection", "cms-algorithm-protection may be present.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.TheCmsAlgorithmProtectionAttributeIsAddedOnlyWhenRequested"),
        ("6.3-table1a-signature-time-stamp", "signature-time-stamp shall be present (cardinality >= 1) at B-T, B-LT and B-LTA; should not be present at B-B.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.AddsASignatureTimestampTheIndependentOraclesAccept"),

        //---- Table 1 Part B (clause 6.3, corrected reproduction) ----
        ("6.3-table1b-certificate-values", "certificate-values shall not be present at B-LT/B-LTA (root SignerInfo.unsignedAttrs); at B-B/B-T it should not be present.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesMaterialInsideTheLatestArchiveTimestampTokenAndLeavesTheRootUntouched (the root SignerInfo never carries it; the strategy-2 exception places it inside the embedded TST's own SignerInfo, a different element)"),
        ("6.3-table1b-complete-certificate-references", "complete-certificate-references shall not be present at B-LT/B-LTA.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.NoAnnexAReferenceFamilyAttributeAppearsInAProducedBLtaSignature"),
        ("6.3-table1b-revocation-values", "revocation-values shall not be present at B-LT/B-LTA (root SignerInfo.unsignedAttrs).",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesMaterialInsideTheLatestArchiveTimestampTokenAndLeavesTheRootUntouched"),
        ("6.3-table1b-complete-revocation-references", "complete-revocation-references shall not be present at B-LT/B-LTA.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.NoAnnexAReferenceFamilyAttributeAppearsInAProducedBLtaSignature"),
        ("6.3-table1b-attribute-certificate-references", "attribute-certificate-references shall not be present at B-LT/B-LTA.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.NoAnnexAReferenceFamilyAttributeAppearsInAProducedBLtaSignature"),
        ("6.3-table1b-attribute-revocation-references", "attribute-revocation-references shall not be present at B-LT/B-LTA.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.NoAnnexAReferenceFamilyAttributeAppearsInAProducedBLtaSignature"),
        ("6.3-table1b-cades-c-timestamp", "CAdES-C-timestamp shall not be present at B-LT/B-LTA.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.NoAnnexAReferenceFamilyAttributeAppearsInAProducedBLtaSignature"),
        ("6.3-table1b-time-stamped-certs-crls-references", "time-stamped-certs-crls-references shall not be present at B-LT/B-LTA.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.NoAnnexAReferenceFamilyAttributeAppearsInAProducedBLtaSignature"),
        ("6.3-table1b-svc-revocation-values-ltv", "Service: revocation values in long-term validation shall be provided at B-LT/B-LTA.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem"),
        ("6.3-table1b-spo-crls-crl", "SPO: SignedData.crls.crl is conditioned presence at B-LT/B-LTA.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem"),
        ("6.3-table1b-spo-crls-other", "SPO: SignedData.crls.other is conditioned presence at B-LT/B-LTA.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem"),
        ("6.3-table1b-archive-time-stamp-v3", "archive-time-stamp-v3 shall be provided at B-LTA (cardinality >= 1).",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.AddsAnArchiveTimestampTheIndependentOracleAndTheCoverageComputationBothAgreeWith"),

        //---- Lettered requirements a)-t) (clause 6.3) ----
        ("6.3-req-a", "a) generator shall include the signing certificate in SignedData.certificates.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.AttachedEcdsaSignatureVerifiesUnderThePlatformCmsReader"),
        ("6.3-req-b", "b) should include all certificates needed for path-building that verifiers cannot obtain.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.AdditionalCertificatesAreIncludedAndExactDuplicatesAreSkipped (mechanism-level: the caller supplies additionalCertificates; which ones satisfy b) is a caller policy decision)"),
        ("6.3-req-c", "c) should include intermediary certificates up to the EU Trusted List CA when validated through a Trusted List.",
            RequirementCoverageStatus.OutOfScope, "EU Trusted List cross-referencing is W1's charter (TrustedListQualification, TS 119 615/612); the generic additionalCertificates mechanism (requirement b) is what a caller uses to satisfy this."),
        ("6.3-req-d", "d) generator shall include the full set of certificates used to validate the signature (signing cert, attribute certs, revocation-info certs, embedded TSA cert).",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem"),
        ("6.3-req-e", "e) duplication of certificate values should be avoided.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.AdditionalCertificatesAreIncludedAndExactDuplicatesAreSkipped"),
        ("6.3-req-f", "f) content-type shall have value id-data.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.CoreSignedAttributesCarryTheRequiredValues"),
        ("6.3-req-g", "g) issuerSerial should not be included in ESSCertID/ESSCertIDv2/OtherCertID.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.TheSigningCertificateV2AttributeOmitsIssuerSerialAndTheDefaultHashAlgorithm"),
        ("6.3-req-h", "h) ESS signing-certificate (v1) shall be used if SHA-1 is the hash algorithm.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.RefusesSha1AsACreationDigest (structural: SHA-1 is refused as a creation digest, so v1's only legitimate trigger never occurs)"),
        ("6.3-req-i", "i) ESS signing-certificate-v2 shall be used when a non-SHA-1 hash algorithm is used.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.TheSigningCertificateV2AttributeOmitsIssuerSerialAndTheDefaultHashAlgorithm"),
        ("6.3-req-j", "j) generator should migrate to signing-certificate-v2 in preference to v1.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.TheSigningCertificateV2AttributeOmitsIssuerSerialAndTheDefaultHashAlgorithm (v2 is always emitted, v1 never)"),
        ("6.3-req-k", "k) signature-policy-store may be incorporated only with signature-policy-identifier and a real digest present; otherwise shall not be incorporated.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.SignaturePolicyStoreIsAddedWhenTheHashIsNonZeroAndRoundTrips (the may path); CAdESOptionalAttributesTests.SignaturePolicyStoreIsRefusedWithoutASignaturePolicyIdentifier and .SignaturePolicyStoreIsRefusedWhenTheHashIsZero (the two shall-not paths)"),
        ("6.3-req-l", "l) generator shall DER-encode any signature-time-stamp attribute while preserving encoding of other attribute fields.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.TheSignatureTimestampAugmentationPreservesEveryOctetOutsideTheLengthChain (witnessed again over a real RFC 3161 wire round trip: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("6.3-req-m", "m) time-stamp tokens inside signature-time-stamp shall be created before the signing certificate has been revoked or expired.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.RequirementMRefusesASignatureTimestampTokenGeneratedBeforeTheCertificateWasValid (D2's EnsureRequirementMSatisfied; plus .RequirementMRefusesASignatureTimestampTokenGeneratedAfterTheCertificateExpired, .RequirementMRefusesATokenGeneratedAtOrAfterTheStatedRevocationInstant, .RequirementMCanBeExplicitlyOptedOut, .RequirementMRequiresACertificateWhenEnforcementIsOn, .RequirementMAppliesToTheArchiveTimestampAndCanBeOptedOut — the B-LTA extension is a delta-plan-directed widening beyond requirement m)'s literal B-T-only text, documented on both context records)"),
        ("6.3-req-n", "n) attribute-certificate-references/attribute-revocation-references may be used only when signer-attributes-v2 is present; otherwise they shall not be used.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.NoAnnexAReferenceFamilyAttributeAppearsInAProducedBLtaSignature (D3 implements signer-attributes-v2's claimedAttributes arm only; certifiedAttributesV2/signedAssertions — the only arms that would legitimize these two reference attributes — remain a recorded deliberate pass per CAdESSignerAttributesV2's own remarks, so the precondition still never holds and both reference attributes are verified absent)"),
        ("6.3-req-o", "o) generator shall include the full set of revocation data used in validating the signature, signing cert, attribute cert, revocation-info-signer cert and embedded TSA cert.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem (witnessed over the wire, including the Time-Stamping Authority's own certificate's revocation data: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("6.3-req-p", "p) duplication of revocation values should be avoided.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.AvoidsDuplicatingMaterialTheSignatureAlreadyCarries"),
        ("6.3-req-q", "q) when the revocation set contains CRLs, they shall be placed in SignedData.crls.crl.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem"),
        ("6.3-req-r", "r) when the revocation set contains OCSP responses, they shall be placed in SignedData.crls.other per RFC 5940.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem (the placement under RFC 5940 §2's id-ri-ocsp-response), with the write-then-read round trip closed by CAdESSignatureAugmentationTests.ARoundTripThroughTheRootPlacementSurfacesTheEmbeddedOcspResponseByteForByte (FX1: the shipped reader surfaces the exact member the shipped writer produced — the earlier id-pkix-ocsp-basic-only reader had silently dropped every self-produced response); witnessed over the wire live (CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation) and offline with the revocation decision read back out of the embedded member (CAdESMultiServerWireFlowTests.ARevocationDecisionIsMadeFromTheEmbeddedResponseWithNoLiveResponder)"),
        ("5.4.2.2-ocsp-reader-recognition", "An OCSP response embedded in SignedData.crls.other shall be recognised on extraction whether typed by RFC 5940 §2's id-ri-ocsp-response (a whole OCSPResponse) or by the pre-RFC-5940 id-pkix-ocsp-basic (a bare BasicOCSPResponse), and either surfaces as a whole OCSPResponse a consumer can verify.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.ARoundTripThroughTheRootPlacementSurfacesTheEmbeddedOcspResponseByteForByte and .ARoundTripThroughTheNestedPlacementSurfacesTheEmbeddedOcspResponseByteForByte (both id-ri-ocsp-response placements — root SignedData.crls and revocation-values.otherRevVals — surfaced verbatim by the shipped reader); the whole-OCSPResponse form the reader normalises both types to is the one OcspResponseVerification.VerifyAsync reads, exercised offline in CAdESMultiServerWireFlowTests.ARevocationDecisionIsMadeFromTheEmbeddedResponseWithNoLiveResponder and reachable-coverage in CAdESTimestampCoverageTests.AnOcspResponsePresentBeforeTheArchiveTimestampKeepsItsProofOfExistence"),
        ("6.3-req-s", "s) before generating/incorporating a new archive-time-stamp-v3, all validation material not already present shall be included, including material needed for a previous archive time-stamp.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.IncludesTheValidationMaterialBeforeGeneratingTheArchiveTimestamp"),
        ("6.3-req-t", "t) at least one of content-hints/mime-type should be present, and shall describe the signed data type when present.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.ContentHintsRoundTripsAndTheEngineAcceptsTheSignature (the SHOULD is a creation-time policy decision left to the caller — either, both or neither may be supplied, matching every other opt-in attribute's default; the SHALL is met structurally: each, when supplied, carries a contentType describing the signed data, per CAdESOptionalAttributesTests.MimeTypeRoundTripsAndTheEngineAcceptsTheSignature too)"),

        //---- Clause 5.2 opt-in signed-attribute normative content (D2/D3 new surface) ----
        ("5.2.5-signerlocation-tagging", "signer-location's postalAddress [2] field shall be tagged per its own ASN.1 module (DEFINITIONS EXPLICIT TAGS): [2] wraps PostalAddress's own SEQUENCE OF tag explicitly.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.SignerLocationRoundTripsEveryFieldAndTheEngineAcceptsTheSignature (fixed in FX3, defect D-C: BuildSignerLocationAttribute now writes postalAddress EXPLICIT — [2] { SEQUENCE { DirectoryString, ... } } — and the test pins the exact EXPLICIT-TAGS DER to the octet, so the writer and an independent reader cannot drift together)"),
        ("5.2.6.1-signerattributesv2-shalls", "signer-attributes-v2 shall carry exactly one AttributeValue of type SignerAttributeV2 identified by id-aa-ets-signerAttrV2; its claimedAttributes arm, when used, shall be a SEQUENCE OF Attribute; an empty signer-attributes-v2 shall not be created.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.SignerAttributesV2CarriesTheClaimedAttributesArmAndTheEngineAcceptsTheSignature (cardinality/type/OID/claimedAttributes content); CAdESOptionalAttributesTests.SignerAttributesV2RefusesAnEmptyClaimedAttributeSet (the empty-forbidden shall)"),
        ("5.2.7-countersignature-rfc5652-11.4", "Clause 5.2.7: countersignature shall be as defined in CMS (RFC 5652 §11.4) — no content-type in its signed attributes (item 1), message-digest present whenever other signed attributes are (item 2), and message-digest the digest of the countersigned SignerInfo.signature value octets, not the whole encoded field (item 3).",
            RequirementCoverageStatus.Tested, "CAdESCountersignatureTests.TheCountersignatureCarriesNoContentTypeAndItsMessageDigestIsTheCountersignedSignatureValue (items 1 and 3 directly; item 2 holds by construction — the countersignature's signed-attribute set is always message-digest + signing-time + signing-certificate-v2)"),
        ("5.2.8-content-timestamp-raw-imprint", "content-time-stamp's message imprint (§5.2.8) shall be the raw hash of the encapsulated content, without the ASN.1 tag and length octets clause 5.5.3's archive-time-stamp-v3 convention would add.",
            RequirementCoverageStatus.Tested, "CAdESOptionalAttributesTests.ContentTimeStampUsesTheRawValueImprintConventionNotTheAtsv3TlvConvention"),

        //---- Clause 4 dependencies this wave actually exercises ----
        ("4.1-cms-compliance", "CAdES signatures shall build on CMS (RFC 5652) and comply with its clauses 2-5.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.AttachedEcdsaSignatureVerifiesUnderThePlatformCmsReader"),
        ("4.4-version-rule", "SignedData.version and SignerInfo.version shall follow RFC 5652 §5.1's version-assignment cascade (clause 4.4 delegates to it): 1 for the id-data/IssuerAndSerialNumber/no-attribute-certificate/no-other-format combination the creation surface produces, and 5 once a B-LT validation-data placement embeds an OtherCertificateFormat certificate ([3]) or an OtherRevocationInfoFormat OCSP crls member ([1]).",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.AnOcspPlacementRaisesTheSignedDataVersionToFive (with ACrlOnlyPlacementLeavesTheSignedDataVersionAtOne for the crl-alternative version-1 case, AddingDataToASignatureThatAlreadyHasAnArchiveTimestampRaisesTheVersionYetTheArchiveTimestampStillValidates for the length-preserving raise past an existing archive-time-stamp-v3, and CAdESSignatureCreationTests.TheCmsAndSignerInfoVersionsAreBothOne for the created baseline's version 1)"),
        ("4.5-attached-detached", "EncapsulatedContentInfo.eContent should be present, or the signed data should be archived preserving its encoding, for long-term validation; both attached and detached signing are supported.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.ADetachedSignatureOmitsEContentAndVerifiesExternally"),
        ("4.6-no-degenerate-signerinfo", "The degenerate case where there are no signers shall not be used.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.EveryProducedSignatureCarriesExactlyOneSignerInfo"),
        ("4.7-der-signedattrs", "SignedData and signed attributes shall be DER-encoded (RFC 5652 §5.3); BER is permitted elsewhere only per X.690.",
            RequirementCoverageStatus.Tested, "CmsSignedAttributesEncodingTests.ProducesTheExactOctetsAnExistingSignatureWasComputedOver"),
        ("4.7.2-ats-computation-der-only", "Clause 4.7.2 permits BER generally, and CmsSignedDataAugmentation preserves indefinite-length BER framing rather than rejecting it (a third-party verifier may still need the original octets); this library's own ats-hash-index-v3/message-imprint computation is knowingly narrower and requires DER, so a signature left in legal indefinite-length BER form is not self-validatable by this library's own ATSv3 coverage computation (documented gap, recorded at ArchiveTimestampV3's ReadMaterial and CmsSignedDataAugmentation's class remarks).",
            RequirementCoverageStatus.KnownDefect, "ArchiveTimestampV3Tests.MapsAnIndefiniteLengthBerSignedDataObjectToNoCoverageAndRefusesItOnTheGeneratorSide (validation-side SignedDataMalformed and generator-side typed exception for the same indefinite-length input; the augmentation-side parity is CAdESSignatureAugmentationTests.RejectsAnUnreadableSignedDataObjectAsSignedDataMalformedInsteadOfLeakingARawParserException)"),
        ("4.8.1-tst-format", "The TimeStampToken type shall be as defined in RFC 3161 for every embedded time-stamp.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.AddsASignatureTimestampTheIndependentOraclesAccept"),
        ("4.8.1-esscertidv2", "RFC 3161 as updated by RFC 5816: the TSU's own certificate reference inside an embedded token shall use the algorithm-agile ESSCertIDv2 form.",
            RequirementCoverageStatus.OutOfScope, "The TSU certificate-reference form inside a token is TimestampTokenInfo's pre-existing read-side concern (shipped before this wave, unchanged); this wave requests/verifies-imprint/attaches tokens without parsing their internal ESS reference form."),
        ("4.9-signed-unsigned-split", "Signed attributes are covered by the signature and DER-encoded; unsigned attributes are added after signing and are not themselves signature-covered.",
            RequirementCoverageStatus.Tested, "CmsSignedDataAugmentationTests.PreservesTheOctetsOfUnsignedAttributesAlreadyPresent"),

        //---- Clause 5.5.2: ats-hash-index-v3 ----
        ("5.5.2-hashIndAlgorithm-identifies", "hashIndAlgorithm shall identify the hash algorithm used to compute certificatesHashIndex/crlsHashIndex/unsignedAttrValuesHashIndex.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.ComputesTheHashIndexTheIndependentOracleRecomputes (also witnessed end to end over a real RFC 3161 wire round trip reaching TOTAL_PASSED: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.2-hashIndAlgorithm-matches-tst", "hashIndAlgorithm shall be the same algorithm as the enveloping time-stamp token's own message imprint algorithm.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.RefusesAnIndexWhoseAlgorithmIsNotTheTokensMessageImprintAlgorithm (the matching case witnessed over the wire: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.2-certificatesHashIndex", "certificatesHashIndex shall contain a hash for every instance of CertificateChoices present when the archive time-stamp is requested, and no other hash value.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.ComputesTheHashIndexTheIndependentOracleRecomputes (also witnessed over the wire with the signer's, the Time-Stamping Authority's and the wire-retained OCSP certificates all indexed: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.2-crlsHashIndex", "crlsHashIndex shall contain a hash for every instance of RevocationInfoChoice present when the archive time-stamp is requested (covering both CRL and OCSP entries), and no other hash value.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.ComputesTheHashIndexTheIndependentOracleRecomputes (the OCSP entry indexed also witnessed over the wire: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.2-unsignedAttrValuesHashIndex", "unsignedAttrValuesHashIndex shall contain one octet string per AttributeValue instance of every unsignedAttrs Attribute present, and no other.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.IndexesEveryValueOfAMultiValuedUnsignedAttributeSeparately"),
        ("5.5.2-hash-input-tlv", "Each hash value shall be computed over the entire encoded component(s) including tag, length and value octets.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.ComputesTheHashIndexTheIndependentOracleRecomputes (the oracle hashes full TLV octets and matches the produced index; also witnessed over the wire: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.2-attribute-value-der", "The ats-hash-index-v3 attribute shall have exactly one AttributeValue, DER-encoded.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.RoundTripsAnEncodedIndexAndRefusesOctetsThatAreNotOne"),
        ("5.5.2-validation-step1-first", "When validating archive-time-stamp-v3, the contained ats-hash-index-v3 shall be validated first.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.AnIndexEntryWithNoMatchingMaterialMakesTheIndexInvalid (an invalid index states no coverage, gating the imprint statement)"),
        ("5.5.2-invalidity-asymmetric", "The index is invalid iff an index entry matches no current material; current material with no corresponding index entry is not an error.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.MaterialAddedAfterTheArchiveTimestampIsUncoveredAndNotAnError"),

        //---- Clause 5.5.3: archive-time-stamp-v3 ----
        ("5.5.3-imprint-concatenation", "The archive-time-stamp-v3 message imprint input shall be the four-part concatenation: eContentType, the signed-data hash, the named SignerInfo fields, and one ATSHashIndexV3.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.BuildsTheMessageImprintInputTheIndependentOracleAssembles (also witnessed end to end over the real wire: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.3-step2-hash-algorithm-match", "The signed-data hash (step 2) shall use the same algorithm as the archive time-stamp's own message imprint, re-hashing the signed content rather than reusing the message-digest attribute's value.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.BuildsTheMessageImprintInputTheIndependentOracleAssembles (also witnessed over the wire: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.3-digestAlgorithms-should", "The hash algorithm identifier should be included in SignedData.digestAlgorithms.",
            RequirementCoverageStatus.OutOfScope, "Not implemented this wave: AddArchiveTimestampAsync does not add the ATS's algorithm to the root SignedData.digestAlgorithms set (documented gap, a SHOULD-strength recommendation)."),
        ("5.5.3-single-ats-hash-index", "The archive-time-stamp-v3 shall include as an unsigned attribute a single ats-hash-index-v3 attribute.",
            RequirementCoverageStatus.Tested, "ArchiveTimestampV3Tests.ReadsTheHashIndexOutOfATokenAndReportsAbsenceWhenThereIsNone (the produced-and-graft case witnessed over the wire: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.3-precondition-extend", "Before incorporating a new archive-time-stamp-v3, SignedData shall be extended with any not-already-present validation material required to validate the signature, including material for a previous archive time-stamp.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.IncludesTheValidationMaterialBeforeGeneratingTheArchiveTimestamp (also witnessed over the wire, the B-LT material placed from a real OCSP round trip before the B-LTA round trip: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.3-delta-crl", "When the validation data contains a Delta CRL, the whole set of CRLs shall be included.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.RefusesADeltaCrlWithoutTheCompleteSetAndAcceptsItWithOne"),
        ("5.5.3-strategy1-root", "With no ATSv2/legacy archive-time-stamp/long-term-validation attribute present, new validation material shall be included within the root SignedData.certificates/.crls.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesCertificatesCrlsAndOcspResponsesWhereTableOneRequiresThem (also witnessed over the wire: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.3-strategy2-root-untouched", "With an ATSv2/legacy attribute present, the root SignedData.certificates and .crls shall not be modified.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesMaterialInsideTheLatestArchiveTimestampTokenAndLeavesTheRootUntouched"),
        ("5.5.3-strategy2-placement", "New validation material shall instead be provided within the TimeStampToken of the latest archive time-stamp, or within the latest long-term-validation attribute.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesMaterialInsideTheLatestArchiveTimestampTokenAndLeavesTheRootUntouched (the TST-nested method); CAdESSignatureAugmentationTests.RefusesToPlaceMaterialWhenTheLatestLegacyAttributeIsALongTermValidationAttribute (the long-term-validation method is refused, a typed rejection rather than a silent strategy-1 write)"),
        ("5.5.3-lockdown", "Once an ATSv2/legacy attribute is present, no attributes other than ATSv3 or Annex B attributes shall be added to unsignedAttrs.",
            RequirementCoverageStatus.Tested, "CAdESCountersignatureTests.ALegacyLongTermAvailabilityAttributeForbidsAddingACountersignature (also proves signature-policy-store refused over the same fixture); CAdESSignatureAugmentationTests.ALegacyLongTermAvailabilityAttributeForbidsAddingASignatureTimestampBeforeAnyAuthorityContact (D-E: the third write path, signature-time-stamp, was ungated — this test proves the SHALL for it too and, via the zero-call-count transport double, that the gate runs before any Time-Stamping Authority contact; all three write paths share the one DetectValidationDataPlacement detector, so the lockdown and the placement-strategy decision can never disagree about what \"legacy attribute present\" means)"),
        ("5.5.3-note4-countersignature-no-own-ats", "NOTE 4: a countersignature needs no archive time-stamp of its own — it is protected as an unsigned attribute value by the enclosing signature's own archive-time-stamp-v3.",
            RequirementCoverageStatus.Tested, "CAdESCountersignatureTests.MutatingACountersignatureTheArchiveTimestampProtectsBreaksTheArchiveTimestamp (the un-mutated countersignature's coverage by the enclosing ATSv3, with no separate archive time-stamp of its own, is the test's own precondition — exactly NOTE 4's content)"),
        ("5.5.3-note6-sibling-survives", "NOTE 6, first direction: adding a new countersignature after a signature is protected by an archive-time-stamp-v3, either as a sibling attribute or as an additional value of an existing countersignature attribute, does not invalidate that archive time-stamp.",
            RequirementCoverageStatus.Tested, "CAdESCountersignatureTests.ASiblingCountersignatureAddedAfterAnArchiveTimestampLeavesItValid (generalised over 1-3 siblings x one-splice/one-at-a-time by CAdESCountersignaturePropertyTests.SiblingCountersignaturesNeverInvalidateAnEarlierArchiveTimestamp)"),
        ("5.5.3-note6-mutation-invalidates", "NOTE 6, second direction: adding an unsigned attribute inside a countersignature that is itself protected by an archive-time-stamp-v3 breaks that archive time-stamp's protection, because it changes the hash of the countersignature attribute value the index names.",
            RequirementCoverageStatus.Tested, "CAdESCountersignatureTests.MutatingACountersignatureTheArchiveTimestampProtectsBreaksTheArchiveTimestamp (generalised over four unsigned attribute types x value sizes 0-300 by CAdESCountersignaturePropertyTests.AnyUnsignedAttributeAddedInsideAProtectedCountersignatureInvalidatesTheArchiveTimestamp)"),
        ("5.5.3-validate-then-ignore", "ATSv3/Annex-B attributes added after a legacy attribute shall be validated first, then ignored when validating the older archive time-stamp/long-term-validation attribute.",
            RequirementCoverageStatus.OutOfScope, "Multi-timestamp validation-order precedence is an EN 319 102-1 engine concern (clause 5.6), untouched by AMENDMENT 2's narrow POE-admission fix (ProofOfExistenceExtraction's three material loops only, never validation ordering across timestamps) — still an out-of-scope engine concern for this CAdES-specific matrix."),
        ("5.5.3-preservation", "Augmentation shall preserve the binary encoding of already-present unsigned attributes and any component contributing to the archive time-stamp's message imprint computation input.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.TheArchiveTimestampAugmentationPreservesEveryOctetOutsideTheLengthChain (preservation across two real, independently-minted TSA round trips witnessed over the wire: CAdESMultiServerWireFlowTests.CreatesAugmentsToBLtaAndReachesTotalPassedAcrossTwoKestrelHostsWithLiveOcspDrivenRevocation)"),
        ("5.5.3-new-attrs-should-der", "New attributes added after a signature is protected by an ATSv3 should be DER-encoded.",
            RequirementCoverageStatus.Tested, "CmsSignedAttributesEncodingTests.EncodesTheTwoFormsDifferingOnlyInTheTagOctet (structural: the whole surface authors new material through AsnWriter/CmsAttribute.Create only, so no BER-emission path exists)"),
        ("5.5.3-generation-der-preserving", "When generating a new attribute carrying validation data, it shall be DER-encoded while preserving the encoding of any signed field it references.",
            RequirementCoverageStatus.Tested, "CmsSignedAttributesEncodingTests.RebuildsAnExistingSignedAttributeSetOctetForOctetWhateverOrderTheAttributesArriveIn"),

        //---- Annex A.1.1.2 / A.1.2.2 closed-set rules ----
        ("a112-certvalues-closed-set", "certificate-values shall contain exactly the certificate values not already in SignedData.certificates that complete-certificate-references/attribute-certificate-references/signing-certificate-reference name; no other certificate shall be included.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.PlacesMaterialInsideTheLatestArchiveTimestampTokenAndLeavesTheRootUntouched (a certificate already carried by the token is offered again and only the missing one is found stated)"),
        ("a122-revocationvalues-closed-set", "revocation-values shall contain exactly the revocation elements not already in SignedData.crls that complete-revocation-references/attribute-revocation-references name; no other element shall be included.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.RevocationValuesTagsEveryFieldWithTheModulesExplicitTagsAndRoutesBothOcspFormsByType (each field is decoded against the offered DER and holds exactly the one stated element with no other — crlVals one CRL, ocspVals one BasicOCSPResponse, otherRevVals one whole OCSPResponse — and RevocationValues carries no field beyond those three; CAdESSignatureAugmentationTests.PlacesMaterialInsideTheLatestArchiveTimestampTokenAndLeavesTheRootUntouched leaves the root SignedData.crls byte-identical under the second placement)"),
        ("a122-ocsp-type-routing", "Within revocation-values, a BasicOCSPResponse shall be placed in ocspVals; a whole OCSPResponse shall instead be carried under otherRevVals tagged id-ri-ocsp-response.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.RevocationValuesTagsEveryFieldWithTheModulesExplicitTagsAndRoutesBothOcspFormsByType (both forms are offered in the same call; the BasicOCSPResponse is decoded out of ocspVals and the whole OCSPResponse out of otherRevVals under the id-ri-ocsp-response OID, each verbatim — the routing proven by field inspection, not by a presence count)"),

        //---- Annex A.2 deprecation rules ----
        ("a2.1-general", "Deprecated attributes shall not be added to a signature any more, except long-term-validation may still be added to a signature already containing one.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.TheAugmentationsEmitNoDeprecatedAttribute (the general shall-not); CAdESSignatureAugmentationTests.RefusesToPlaceMaterialWhenTheLatestLegacyAttributeIsALongTermValidationAttribute (the stated carve-out is a typed rejection this wave does not implement, per stage 5's recorded decision)"),
        ("a2.4-atsv2", "New ATSv2 (archive-time-stamp) attributes shall not be created.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.TheAugmentationsEmitNoDeprecatedAttribute"),
        ("a2.5-long-term-validation", "New long-term-validation attributes shall not be created.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.TheAugmentationsEmitNoDeprecatedAttribute"),
        ("a2.6-ats-hash-index", "ats-hash-index (pre-v3, v1/v2) is deprecated; ats-hash-index-v3 shall be used instead.",
            RequirementCoverageStatus.Tested, "CAdESSignatureAugmentationTests.TheAugmentationsEmitNoDeprecatedAttribute"),

        //---- Clause 6.2.1: algorithms ----
        ("6.2.1-md5", "MD5 shall not be used as a digest algorithm.",
            RequirementCoverageStatus.Tested, "CAdESSignatureCreationTests.RefusesMd5AsACreationDigest"),
        ("6.2.1-ts119312-should", "Algorithms/key lengths should be as specified in ETSI TS 119 312.",
            RequirementCoverageStatus.OutOfScope, "Contract 'Out' list: a TS 119 312 default algorithm table is a stated CBOM/PQC follow-up; this wave consults only a caller-supplied CryptographicConstraints table (R-8) plus the hard MD5/SHA-1 refusals."),

        //---- Annex A.1.5: imprint definitions (validation-side, recognised not emitted) ----
        ("a1.5.2-esc-timestamp-imprint", "The CAdES-C-timestamp (escTimeStamp) message imprint shall cover the signature value, signature-time-stamp, complete-certificate-references and complete-revocation-references attributes.",
            RequirementCoverageStatus.Tested, "CAdESTimestampCoverageTests.StatesWhatACadesCTimestampProtects"),
        ("a1.5.1-cert-crl-timestamp-imprint", "The time-stamped-certs-crls-references (certCRLTimestamp) message imprint shall cover complete-certificate-references and complete-revocation-references.",
            RequirementCoverageStatus.Tested, "CAdESTimestampCoverageTests.StatesWhatATimeStampOnCertificateAndRevocationReferencesProtects"),

        //---- Clause 5.5.3 step 3): signed-attribute coverage (content-time-stamp POE) ----
        ("5.5.3-signedattrs-content-timestamp-poe", "Step 3) of the archive-time-stamp-v3 imprint concatenates the whole signedAttrs TLV verbatim, so an archive-time-stamp-v3 protects a content-time-stamp (a signed attribute, §5.2.8) even though the ats-hash-index-v3 — which indexes certificates, revocation objects and unsigned attribute values alone — never names it; the CAdES binding's StateTimestampProtectsObject filter therefore grants it a proof of existence at the archive instant (D-F: the AMENDMENT-2 hash-index-only lookup wrongly denied it).",
            RequirementCoverageStatus.Tested, "CAdESTimestampCoverageTests.AContentTimestampGainsItsProofOfExistenceFromTheArchiveTimestamp (POE set names the content-time-stamp at the archive instant, plus the negative guard that the token is a signed attribute value the ats-hash-index-v3 never names — the exact pre-fix denial); CAdESCapstoneFirewalledFlowTests.FirewalledCapstoneAttributesAContentTimestampsProofToTheArchiveTimestamp (the report-level projection end to end: ProvidesProofOfExistenceFor lists it, from wire bytes to TOTAL-PASSED)"),

        //---- TS 119 102-2 clause 4.4.7 ----
        ("ts119102-2-4.4.7-poe", "The validation report shall populate ValidationObject.ProvidesProofOfExistenceFor from the accumulated proofs of existence, granting a proof only to material the archive time-stamp's own coverage genuinely protects — never to material merely appended after it (clause 5.6.3.1's class rule narrowed by the CAdES binding's own ats-hash-index-v3 coverage, AMENDMENT 2/D1).",
            RequirementCoverageStatus.Tested, "CAdESTimestampCoverageTests.MaterialAppendedAfterTheArchiveTimestampGainsNoProofOfExistenceFromIt (D1's regression test for the fix — a reachable false-POE admission this test pins shut: with the D1 filter reverted, this exact assertion fails, the other seven tests in the class still passing); AnnexAValidationReportFlowTests.Example2LongTermReportNamesWhatTheArchiveTimestampProvesTheExistenceOf (the report population itself); CAdESTimestampCoverageTests.AnOcspResponsePresentBeforeTheArchiveTimestampKeepsItsProofOfExistence (the over-filtering guard on the RFC 5940 member lookup)"),

        //---- Attribute-identifier cross-check ----
        ("cross-oid-identifiers", "Every attribute OID this wave recognises or emits equals the value EN 319 122-1 Annex D (or, for ATSv2, ETSI TS 101 733) specifies.",
            RequirementCoverageStatus.Tested, "CAdESRequirementsMatrixTests.EveryAttributeOidGetterMatchesItsSpecificationValue"),
    ];
}
