using System.Buffers;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Cbor.Mdoc;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;

namespace Verifiable.Tests.Mdoc;

/// <summary>
/// Tests for <see cref="MdocDcqlAdapter"/> — the bridge that lets the
/// existing <see cref="DcqlEvaluator"/> resolve queries against
/// <see cref="MdocDocument"/> credentials with the same shape it already
/// uses for SD-JWT VC.
/// </summary>
/// <remarks>
/// <para>
/// The headline test runs the full DCQL pipeline: build a DCQL query that
/// asks for two EUDI PID claims by namespace+identifier, build an mdoc
/// credential carrying those claims, run the evaluator with the adapter's
/// extractors, and assert that the credential matches with the expected
/// patterns. This is the integration check M.7 will lean on when wiring
/// the wallet client.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MdocDcqlAdapterTests
{
    private static readonly string PidDocType = EudiPid.AttestationType;
    private static readonly string PidNamespace = EudiPid.Mdoc.Namespace;


    [TestMethod]
    public void MetadataExtractorReportsMsoMdocFormatAndDocType()
    {
        using MdocDocument document = BuildSampleLogicalPid();

        DcqlCredentialMetadata metadata = MdocDcqlAdapter.MetadataExtractor(document);

        Assert.AreEqual(MdocDcqlAdapter.FormatIdentifier, metadata.Format);
        Assert.AreEqual(PidDocType, metadata.CredentialType);
        Assert.IsNotNull(metadata.AvailablePaths);
    }


    [TestMethod]
    public void MetadataExtractorEnumeratesEveryNamespaceElementAsAvailablePath()
    {
        using MdocDocument document = BuildSampleLogicalPid();

        DcqlCredentialMetadata metadata = MdocDcqlAdapter.MetadataExtractor(document);

        CredentialPath familyNamePath = ResolveMdocPath(PidNamespace, EudiPid.Mdoc.FamilyName);
        CredentialPath givenNamePath = ResolveMdocPath(PidNamespace, EudiPid.Mdoc.GivenName);

        IReadOnlySet<CredentialPath> availablePaths = metadata.AvailablePaths!;
        Assert.Contains(familyNamePath, availablePaths,
            "family_name path under the PID namespace must appear in AvailablePaths.");
        Assert.Contains(givenNamePath, availablePaths,
            "given_name path under the PID namespace must appear in AvailablePaths.");
    }


    [TestMethod]
    public void ClaimExtractorReturnsValueForPresentNamespaceElement()
    {
        using MdocDocument document = BuildSampleLogicalPid();

        DcqlClaimPattern pattern = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.FamilyName);
        bool found = MdocDcqlAdapter.ClaimExtractor(document, pattern, out object? value);

        Assert.IsTrue(found, "Extractor must locate the family_name claim in the sample PID.");
        Assert.AreEqual("Mustermann", value);
    }


    [TestMethod]
    public void ClaimExtractorReturnsFalseForUnknownNamespace()
    {
        using MdocDocument document = BuildSampleLogicalPid();

        DcqlClaimPattern pattern = DcqlClaimPattern.ForMdoc(
            "eu.europa.ec.eudi.pid.xx.1", EudiPid.Mdoc.FamilyName);

        bool found = MdocDcqlAdapter.ClaimExtractor(document, pattern, out object? value);

        Assert.IsFalse(found, "An unknown namespace must surface as 'not found'.");
        Assert.IsNull(value);
    }


    [TestMethod]
    public void ClaimExtractorReturnsFalseForUnknownElementInKnownNamespace()
    {
        using MdocDocument document = BuildSampleLogicalPid();

        DcqlClaimPattern pattern = DcqlClaimPattern.ForMdoc(PidNamespace, "no_such_element");

        Assert.IsFalse(MdocDcqlAdapter.ClaimExtractor(document, pattern, out _));
    }


    [TestMethod]
    public void ClaimExtractorReturnsFalseForNonTwoSegmentPattern()
    {
        //Single-segment / deeper / wildcard patterns are not mdoc-shaped.
        //The evaluator's wildcard expansion runs through DcqlPathResolver
        //before the extractor sees the pattern, so by the time we get here
        //we should only see concrete two-segment patterns.
        using MdocDocument document = BuildSampleLogicalPid();

        Assert.IsFalse(MdocDcqlAdapter.ClaimExtractor(
            document, DcqlClaimPattern.FromKeys("just_one"), out _));
        Assert.IsFalse(MdocDcqlAdapter.ClaimExtractor(
            document, DcqlClaimPattern.FromKeys("ns", "id", "extra"), out _));
    }


    [TestMethod]
    public void DcqlEvaluatorReturnsMatchForMdocCredentialUnderQuery()
    {
        //End-to-end: a DCQL query asking for family_name + given_name in the
        //PID namespace evaluates green against the sample PID credential.
        //This is the integration the wallet client (M.7) leans on.
        using MdocDocument document = BuildSampleLogicalPid();

        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = MdocDcqlAdapter.FormatIdentifier,
                    Claims =
                    [
                        new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.FamilyName) },
                        new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.GivenName) }
                    ]
                }
            ]
        };

        PreparedDcqlQuery prepared = DcqlPreparer.Prepare(query);

        List<DcqlMatch<MdocDocument>> matches = DcqlEvaluator.Evaluate(
            prepared,
            credentials: [document],
            metadataExtractor: MdocDcqlAdapter.MetadataExtractor,
            claimExtractor: MdocDcqlAdapter.ClaimExtractor).ToList();

        Assert.HasCount(1, matches);
        Assert.AreEqual("pid", matches[0].CredentialQueryId);
        Assert.HasCount(2, matches[0].MatchedPatterns);
    }


    [TestMethod]
    public void DcqlEvaluatorRejectsMdocCredentialWhenRequiredClaimMissing()
    {
        //The sample PID has family_name and given_name; ask for nationalities
        //(absent) and the query must not match.
        using MdocDocument document = BuildSampleLogicalPid();

        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = MdocDcqlAdapter.FormatIdentifier,
                    Claims =
                    [
                        new ClaimsQuery { Path = DcqlClaimPattern.ForMdoc(PidNamespace, EudiPid.Mdoc.Nationalities) }
                    ]
                }
            ]
        };

        List<DcqlMatch<MdocDocument>> matches = DcqlEvaluator.Evaluate(
            DcqlPreparer.Prepare(query),
            credentials: [document],
            metadataExtractor: MdocDcqlAdapter.MetadataExtractor,
            claimExtractor: MdocDcqlAdapter.ClaimExtractor).ToList();

        Assert.HasCount(0, matches);
    }


    [TestMethod]
    public void DcqlEvaluatorRejectsMdocCredentialOnFormatMismatch()
    {
        //An SD-JWT VC-formatted query must not match an mdoc credential.
        //This is the format gate inside DcqlEvaluator — the adapter's
        //metadata reports the right Format and DcqlEvaluator handles the
        //rest.
        using MdocDocument document = BuildSampleLogicalPid();

        var query = new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = "pid",
                    Format = "dc+sd-jwt",
                    Claims = [new ClaimsQuery { Path = DcqlClaimPattern.FromKeys("family_name") }]
                }
            ]
        };

        List<DcqlMatch<MdocDocument>> matches = DcqlEvaluator.Evaluate(
            DcqlPreparer.Prepare(query),
            credentials: [document],
            metadataExtractor: MdocDcqlAdapter.MetadataExtractor,
            claimExtractor: MdocDcqlAdapter.ClaimExtractor).ToList();

        Assert.HasCount(0, matches);
    }


    /// <summary>
    /// Builds a structurally-valid <see cref="MdocDocument"/> directly,
    /// without going through the signing pipeline. The adapter only reads
    /// <see cref="MdocDocument.DocType"/>,
    /// <see cref="MdocIssuerSigned.NameSpaces"/>, and per-item
    /// <see cref="MdocIssuerSignedItem.ElementIdentifier"/> /
    /// <see cref="MdocIssuerSignedItem.EncodedElementValue"/> — none of which
    /// depend on the signature being real, so synthetic IssuerAuth and
    /// placeholder WireBytes are sufficient.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage(
        "Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the Salt instances, items, and MdocIssuerSigned transfers through to the returned MdocDocument; the caller's `using` on the document disposes the whole cascade.")]
    private static MdocDocument BuildSampleLogicalPid()
    {
        Salt familySalt = MdocTestFixtures.ItemRandomSalt();
        Salt givenSalt = MdocTestFixtures.ItemRandomSalt();

        MdocIssuerSignedItem familyItem = new(
            digestId: 0,
            random: familySalt,
            elementIdentifier: EudiPid.Mdoc.FamilyName,
            encodedElementValue: MdocTestFixtures.CborText("Mustermann"),
            wireBytes: PlaceholderWireBytes);

        MdocIssuerSignedItem givenItem = new(
            digestId: 1,
            random: givenSalt,
            elementIdentifier: EudiPid.Mdoc.GivenName,
            encodedElementValue: MdocTestFixtures.CborText("Erika"),
            wireBytes: PlaceholderWireBytes);

        Dictionary<string, IReadOnlyList<MdocIssuerSignedItem>> nameSpaces = new(StringComparer.Ordinal)
        {
            [PidNamespace] = [familyItem, givenItem]
        };

        MdocMobileSecurityObject mso = new(
            version: MdocMsoWellKnownKeys.Version10,
            digestAlgorithm: MdocMsoWellKnownKeys.DigestAlgorithmSha256,
            valueDigests: new Dictionary<string, IReadOnlyDictionary<uint, ReadOnlyMemory<byte>>>(StringComparer.Ordinal),
            deviceKeyInfo: new MdocDeviceKeyInfo(new CoseKey(kty: CoseKeyTypes.Ec2, curve: CoseKeyCurves.P256)),
            docType: PidDocType,
            validityInfo: new MdocValidityInfo(
                signed: new DateTimeOffset(2026, 5, 25, 0, 0, 0, TimeSpan.Zero),
                validFrom: new DateTimeOffset(2026, 5, 25, 0, 0, 0, TimeSpan.Zero),
                validUntil: new DateTimeOffset(2027, 5, 25, 0, 0, 0, TimeSpan.Zero)));
        MdocIssuerAuth issuerAuth = new(mso, EncodedCoseSign1.FromBytes(new byte[] { 0x00 }, BaseMemoryPool.Shared));

        return new MdocDocument(PidDocType, new MdocIssuerSigned(nameSpaces, issuerAuth));
    }


    private static readonly byte[] PlaceholderWireBytes = [0xD8, 0x18, 0x40];


    private static CredentialPath ResolveMdocPath(string nameSpace, string elementIdentifier)
    {
        DcqlClaimPattern pattern = DcqlClaimPattern.ForMdoc(nameSpace, elementIdentifier);
        Assert.IsTrue(pattern.TryResolve(out CredentialPath path));

        return path;
    }
}
