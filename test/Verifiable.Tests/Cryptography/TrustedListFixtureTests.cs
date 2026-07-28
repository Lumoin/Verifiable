using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Xml.Linq;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Drives <see cref="TrustedListXmlParser"/> and <see cref="TrustedListXmlSignatureVerifier"/> — the staged
/// worked example of the two <c>Verifiable.Cryptography.Pki</c> Trusted List seams (contract R-3/R-4) —
/// against the real ETSI TS 119 612 TLv6/LOTL XML corpus vendored nowhere in this repository (contract R-5).
/// The fixtures are read directly from the local ETSI/eIDAS reference clone
/// (<see href="reference_etsi_eudi_cra_material.md">tempdocs/etsi-ades-reference/dss</see>) rather than
/// copied in, per the licence caveat that catalog already records; when the clone is not present (a fresh
/// checkout without that local reference material) every test in this class reports
/// <see cref="Assert.Inconclusive(string)"/> rather than failing, since the corpus is optional local
/// reference material, not a repository asset.
/// </summary>
[TestClass]
internal sealed class TrustedListFixtureTests
{
    /// <summary>
    /// Fixtures whose file name (without the country/version fragment) marks them as a deliberately invalid
    /// or structurally incomplete document, and the <see cref="TrustedListParseStatus"/> parsing them must
    /// fail with — this IS the negatives-fail-closed evidence for parsing (contract R-5).
    /// </summary>
    private static readonly Dictionary<string, TrustedListParseStatus> ExpectedParseFailures = new(StringComparer.OrdinalIgnoreCase)
    {
        //Structurally incomplete TLv6 documents (a required clause-5 element is genuinely absent — verified
        //directly against the fixture bytes, and cross-checked against DSS's own JUnit assertions for these
        //exact file names in TLValidationJobTest/LOTLParsingTaskTest). NOTE, a deliberate design choice: DSS
        //itself recovers a PARTIAL model from eu-lotl-no-tl-version.xml/tl-empty-with-identifier.xml (null
        //version, the rest populated) and from fi-v6-no-tsp-information.xml/fi-v6-no-service-information.xml
        //(the one incomplete TSP/service excluded, the rest of the document returned). This parser instead
        //fails the WHOLE document on any single missing required element — the strict-conformance-oracle
        //posture this codebase's other verifiers already take, not an oversight; a caller wanting DSS's
        //fault-tolerant partial recovery would need a different parser.
        ["eu-lotl-no-tl-version.xml"] = TrustedListParseStatus.MissingRequiredElement,
        ["tl-empty.xml"] = TrustedListParseStatus.MissingRequiredElement,
        ["tl-empty-with-identifier.xml"] = TrustedListParseStatus.MissingRequiredElement,
        ["fi-v6-no-tsp-information.xml"] = TrustedListParseStatus.MissingRequiredElement,
        ["fi-v6-no-service-information.xml"] = TrustedListParseStatus.MissingRequiredElement,
        //Deliberately tampered: SKCertificateTest's "altered" fixtures blank out one TSPInformation/
        //ServiceTypeIdentifier element (verified directly — the specific altered element is empty; other,
        //unaltered TSPs/services in the same document are untouched).
        ["sk-tl-altered-trust-service-with-time.xml"] = TrustedListParseStatus.MissingRequiredElement,
        ["sk-tl-altered-trust-service.xml"] = TrustedListParseStatus.MissingRequiredElement,
        ["sk-tl-altered-tsp.xml"] = TrustedListParseStatus.MissingRequiredElement,
        //Verified directly (lotlCache/CZ_not-compliant.xml): SchemeInformation goes straight from its opening
        //tag to TSLSequenceNumber — TSLVersionIdentifier (clause 5.3.1, mandatory) is genuinely absent. Its
        //TSLType text also carries incidental pretty-printing whitespace, which is a real but SEPARATE, no
        //longer fatal, issue this parser now trims per XSD anyURI's whiteSpace=collapse facet; the missing
        //TSLVersionIdentifier is the reason this fixture still fails, not the TSLType text.
        ["CZ_not-compliant.xml"] = TrustedListParseStatus.MissingRequiredElement,

        //Not well-formed XML at all (DSS's own XML-parser-robustness fixtures).
        ["eu-lotl-not-parseable.xml"] = TrustedListParseStatus.Malformed,
        ["CZ_empty.xml"] = TrustedListParseStatus.Malformed,
        ["CZ_not-conform.xml"] = TrustedListParseStatus.Malformed,
        ["CZ_not-parsable.xml"] = TrustedListParseStatus.Malformed,
        ["eu-lotl_not-parsable.xml"] = TrustedListParseStatus.Malformed,
        ["tl_pivot_191_mp_not-parsable.xml"] = TrustedListParseStatus.Malformed,
        ["tl_pivot_247_mp_empty.xml"] = TrustedListParseStatus.Malformed,
        ["tl_pivot_247_mp_not-parsable.xml"] = TrustedListParseStatus.Malformed,

        //Well-formed XML but not a Trusted List at all — DSS's own generic XML-canonicalization fixtures
        //(root element "hello"/"bye") that happen to share this resources directory.
        ["sample.xml"] = TrustedListParseStatus.Malformed,
        ["sample-bom.xml"] = TrustedListParseStatus.Malformed,
        ["sample-comment.xml"] = TrustedListParseStatus.Malformed,
        ["sample-diff.xml"] = TrustedListParseStatus.Malformed,
        ["sample-spaces.xml"] = TrustedListParseStatus.Malformed,
    };

    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Parses every real TL/LOTL XML fixture in the corpus and asserts: the whole 109-file corpus is
    /// accounted for, every fixture named in <see cref="ExpectedParseFailures"/> fails with exactly the
    /// expected status (negatives fail closed), and every other fixture parses to a well-formed
    /// <see cref="TrustedList"/>.
    /// </summary>
    [TestMethod]
    public async Task ParsesTheWholeDssTrustedListCorpusAndFailsExpectedNegativesClosed()
    {
        string? resourcesDirectory = TryFindDssTrustedListResourcesDirectory();
        if(resourcesDirectory is null)
        {
            Assert.Inconclusive("The local ETSI/eIDAS reference clone (tempdocs/etsi-ades-reference/dss) was not found; the DSS TL/LOTL corpus is optional local reference material.");
            return;
        }

        string[] xmlFiles = [.. Directory.EnumerateFiles(resourcesDirectory, "*.xml", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.Ordinal)];
        Assert.HasCount(109, xmlFiles, "The DSS TL/LOTL corpus is expected to carry exactly 109 XML fixtures; the corpus contents changed.");

        int parsedValid = 0;
        int parsedFailed = 0;
        List<string> unexpectedFailures = [];
        List<string> unexpectedSuccesses = [];

        foreach(string filePath in xmlFiles)
        {
            string fileName = Path.GetFileName(filePath);
            byte[] bytes = await File.ReadAllBytesAsync(filePath, TestContext.CancellationToken).ConfigureAwait(false);
            using PooledMemory document = PooledMemory.FromBytes(bytes, BaseMemoryPool.Shared, TrustedListTags.Document);

            using TrustedListParseResult result = await TrustedListXmlParser.ParseAsync(document, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

            if(ExpectedParseFailures.TryGetValue(fileName, out TrustedListParseStatus expectedStatus))
            {
                if(result.IsValid || result.Status != expectedStatus)
                {
                    unexpectedFailures.Add($"{fileName}: expected {expectedStatus} but got {(result.IsValid ? "Valid" : result.Status.ToString())}");
                }
                else
                {
                    parsedFailed++;
                }
            }
            else if(result.IsValid)
            {
                parsedValid++;
            }
            else
            {
                //A fixture not on the expected-negatives list failed to parse — every other DSS fixture is
                //expected to be a structurally well-formed TLv6/LOTL document (some deliberately carry a
                //broken or absent SIGNATURE, which is the signature verifier's negative, not the parser's).
                unexpectedSuccesses.Add($"{fileName}: unexpectedly failed to parse ({result.Status}: {result.FailureReason})");
            }
        }

        Assert.IsEmpty(unexpectedFailures, $"Fixtures that did not fail as expected: {string.Join("; ", unexpectedFailures)}");
        Assert.IsEmpty(unexpectedSuccesses, $"Fixtures that unexpectedly failed to parse: {string.Join("; ", unexpectedSuccesses)}");
        Assert.AreEqual(ExpectedParseFailures.Count, parsedFailed, "Every fixture named in ExpectedParseFailures must have been exercised.");
        Assert.AreEqual(xmlFiles.Length - ExpectedParseFailures.Count, parsedValid, "Every fixture not named in ExpectedParseFailures must parse successfully.");

        TestContext.WriteLine($"Parsed {parsedValid} fixtures successfully and {parsedFailed} expected negatives, out of {xmlFiles.Length} total.");
    }


    /// <summary>
    /// Parses the real EU List Of the Trusted Lists (<c>eu-lotl-250.xml</c>) and asserts its scheme
    /// information and pointer structure — the shape TS 119 615 qualification and any future LOTL/pivot
    /// cascade would consume.
    /// </summary>
    [TestMethod]
    public async Task ParsesTheRealEuListOfTheTrustedLists()
    {
        using TrustedListParseResult? result = await ParseFixtureAsync("eu-lotl-250.xml").ConfigureAwait(false);
        if(result is null)
        {
            return;
        }

        Assert.IsTrue(result.IsValid, $"eu-lotl-250.xml must parse: {result.FailureReason}");
        TrustedList document = result.Document!;

        Assert.AreEqual(TrustedListKind.ListOfTheLists, document.SchemeInformation.TslType, "eu-lotl-250.xml is the EU List Of the Trusted Lists.");
        Assert.AreEqual("EU", document.SchemeInformation.SchemeTerritory, "The EU LOTL's own scheme territory is EU.");
        Assert.AreEqual(250, document.SchemeInformation.TslSequenceNumber, "The fixture's own sequence number is 250.");
        Assert.IsGreaterThan(20, document.SchemeInformation.PointersToOtherTrustedLists.Count, "The EU LOTL must point at every member state's Trusted List — well over 20 pointers.");

        foreach(OtherTrustedListPointer pointer in document.SchemeInformation.PointersToOtherTrustedLists)
        {
            Assert.IsNotNull(pointer.TslLocation, "Every pointer must carry a resolvable location.");
        }
    }


    /// <summary>
    /// Parses a historical pivot LOTL (<c>eu-lotl-pivot.xml</c>) — a snapshot of the LOTL as it existed
    /// under an earlier certificate set. R-6's model-vs-cascade judgement: this proves the MODEL captures
    /// what a pivot cascade would need to walk (scheme sequence number, pointer set), while the cascade
    /// WALK itself is out of this wave's scope (see the wave report for the evidence-based reason).
    /// </summary>
    [TestMethod]
    public async Task ParsesAHistoricalPivotLotlAndSurfacesItsPointerSet()
    {
        using TrustedListParseResult? result = await ParseFixtureAsync("eu-lotl-pivot.xml").ConfigureAwait(false);
        if(result is null)
        {
            return;
        }

        Assert.IsTrue(result.IsValid, $"eu-lotl-pivot.xml must parse: {result.FailureReason}");
        TrustedList document = result.Document!;

        Assert.AreEqual(TrustedListKind.ListOfTheLists, document.SchemeInformation.TslType);
        Assert.IsNotEmpty(document.SchemeInformation.PointersToOtherTrustedLists, "A pivot LOTL still carries the pointer set that certificate set was valid for.");
    }


    /// <summary>
    /// Parses a fixture whose services carry real <c>Qualifications</c> (<c>sk-tl-sn-95.xml</c>) and asserts
    /// the qualifier-condition tree came through structurally: at least one service has qualification
    /// elements, and at least one of those has a non-empty criteria tree with the composite <c>assert</c>
    /// semantics preserved.
    /// </summary>
    [TestMethod]
    public async Task ParsesRealQualificationCriteriaTrees()
    {
        using TrustedListParseResult? result = await ParseFixtureAsync("sk-tl-sn-95.xml").ConfigureAwait(false);
        if(result is null)
        {
            return;
        }

        Assert.IsTrue(result.IsValid, $"sk-tl-sn-95.xml must parse: {result.FailureReason}");
        TrustedList document = result.Document!;

        List<QualificationElement> allQualificationElements = [.. document.TrustServiceProviders
            .SelectMany(provider => provider.Services)
            .SelectMany(service => service.Qualifications)];

        Assert.IsNotEmpty(allQualificationElements, "sk-tl-sn-95.xml is expected to carry real Qualifications extensions.");
        Assert.Contains(element => element.Qualifiers.Count > 0, allQualificationElements, "At least one qualification element must assert a qualifier.");
        Assert.Contains(element => element.Condition.Children.Count > 0, allQualificationElements, "At least one criteria tree must have children.");
    }


    /// <summary>
    /// Regression lock for a real defect an earlier version of this parser had: <c>tsl-pe.xml</c> (a real,
    /// structurally complete Peru Trusted List), <c>tl-ecdsa-brainpool.xml</c> (a real, structurally complete
    /// German list, 148 services), and <c>mra-zz-tl.xml</c> (a Mutual Recognition Agreement third-country
    /// fixture) were all wrongly rejected as <see cref="TrustedListParseStatus.MissingRequiredElement"/> —
    /// nothing in any of the three was actually missing; a <c>TSLType</c> value outside the two current
    /// EU-registered strings hard-failed the WHOLE parse. Each must now parse, and <see cref="TrustedListKind"/>
    /// must carry the document's own (non-registered) value rather than a rejection.
    /// </summary>
    [TestMethod]
    public async Task FixturesWithNonRegisteredButValidTslTypeValuesParse()
    {
        (string FileName, string ExpectedTslTypeValue)[] cases =
        [
            ("tsl-pe.xml", "http://uri.etsi.org/TrstSvc/eSigDir-1999-93-EC-TrustedList/TSLType/generic"),
            ("tl-ecdsa-brainpool.xml", "http://uri.etsi.org/TrstSvc/TSLtype/generic"),
            ("mra-zz-tl.xml", "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/ZZlist"),
        ];

        foreach((string fileName, string expectedTslTypeValue) in cases)
        {
            using TrustedListParseResult? result = await ParseFixtureAsync(fileName).ConfigureAwait(false);
            if(result is null)
            {
                return;
            }

            Assert.IsTrue(result.IsValid, $"{fileName} is structurally complete and must parse: {result.FailureReason}");
            Assert.AreEqual(expectedTslTypeValue, result.Document!.SchemeInformation.TslType.Value, $"{fileName}'s TSLType must be carried verbatim (whitespace-collapsed), not rejected.");
            Assert.IsNotEmpty(result.Document.TrustServiceProviders, $"{fileName} must carry its Trust Service Providers.");
        }
    }


    /// <summary>
    /// A document whose <c>ds:SignatureValue</c> has been tampered with (<c>eu-lotl-broken-sig.xml</c>) must
    /// fail closed as <see cref="TrustedListSignatureStatus.InvalidSignature"/> — the crypto check runs
    /// before trust-anchor membership is even considered, so this holds regardless of which anchors are
    /// supplied.
    /// </summary>
    [TestMethod]
    public async Task ABrokenSignatureFailsClosed()
    {
        byte[]? bytes = await TryReadFixtureBytesAsync("eu-lotl-broken-sig.xml").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        using PooledMemory document = PooledMemory.FromBytes(bytes, BaseMemoryPool.Shared, TrustedListTags.Document);
        TrustedListSignatureVerificationResult result = await TrustedListXmlSignatureVerifier.VerifyAsync(
            document, [], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid, "A tampered signature value must not verify.");
        Assert.AreEqual(TrustedListSignatureStatus.InvalidSignature, result.Status);
    }


    /// <summary>
    /// A document with no <c>ds:Signature</c> element at all (<c>eu-lotl-no-sig.xml</c>) must fail closed as
    /// <see cref="TrustedListSignatureStatus.MissingSignature"/>.
    /// </summary>
    [TestMethod]
    public async Task AMissingSignatureFailsClosed()
    {
        byte[]? bytes = await TryReadFixtureBytesAsync("eu-lotl-no-sig.xml").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        using PooledMemory document = PooledMemory.FromBytes(bytes, BaseMemoryPool.Shared, TrustedListTags.Document);
        TrustedListSignatureVerificationResult result = await TrustedListXmlSignatureVerifier.VerifyAsync(
            document, [], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(TrustedListSignatureStatus.MissingSignature, result.Status);
    }


    /// <summary>
    /// A cryptographically valid signature whose signer is not in the caller's trust-anchor set
    /// (<c>fi-v6.xml</c> verified against an empty anchor list) must fail closed as
    /// <see cref="TrustedListSignatureStatus.UntrustedSigner"/> — bootstrap trust, not PKIX discovery.
    /// </summary>
    [TestMethod]
    public async Task AnUntrustedSignerFailsClosedDespiteAValidSignature()
    {
        byte[]? bytes = await TryReadFixtureBytesAsync("fi-v6.xml").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        using PooledMemory document = PooledMemory.FromBytes(bytes, BaseMemoryPool.Shared, TrustedListTags.Document);
        TrustedListSignatureVerificationResult result = await TrustedListXmlSignatureVerifier.VerifyAsync(
            document, [], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(TrustedListSignatureStatus.UntrustedSigner, result.Status);
    }


    /// <summary>
    /// The positive path: <c>fi-v6.xml</c> verified against a trust-anchor set containing the certificate
    /// its own <c>ds:KeyInfo</c> carries — extracted INDEPENDENTLY of <see cref="TrustedListXmlSignatureVerifier"/>
    /// via a bare <see cref="System.Xml.Linq"/> read of the same document bytes, so this is not a tautological
    /// "the verifier trusts what it extracted itself" test — must verify.
    /// </summary>
    [TestMethod]
    public async Task AGenuineSignerInTheTrustAnchorSetVerifies()
    {
        byte[]? bytes = await TryReadFixtureBytesAsync("fi-v6.xml").ConfigureAwait(false);
        if(bytes is null)
        {
            return;
        }

        byte[] independentlyExtractedCertificateDer = ExtractEmbeddedSignerCertificateIndependently(bytes);

        using IMemoryOwner<byte> anchorOwner = BaseMemoryPool.Shared.Rent(independentlyExtractedCertificateDer.Length);
        independentlyExtractedCertificateDer.CopyTo(anchorOwner.Memory.Span);
        using var trustAnchor = new PkiCertificateMemory(anchorOwner, PkiCertificateTags.X509Certificate);

        using PooledMemory document = PooledMemory.FromBytes(bytes, BaseMemoryPool.Shared, TrustedListTags.Document);
        TrustedListSignatureVerificationResult result = await TrustedListXmlSignatureVerifier.VerifyAsync(
            document, [trustAnchor], BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"A genuine signer present in the trust-anchor set must verify: {result.FailureReason}");
        Assert.IsNotNull(result.SigningTime, "fi-v6.xml's SignedProperties carries a SigningTime.");
    }


    /// <summary>Independently (no dependency on the code under test) extracts the base64 DER bytes of the first <c>ds:X509Certificate</c> under <c>ds:KeyInfo</c>.</summary>
    /// <param name="documentBytes">The raw XML document bytes.</param>
    /// <returns>The decoded DER certificate bytes.</returns>
    private static byte[] ExtractEmbeddedSignerCertificateIndependently(byte[] documentBytes)
    {
        XNamespace ds = "http://www.w3.org/2000/09/xmldsig#";
        XDocument xml = XDocument.Load(new MemoryStream(documentBytes));
        XElement certificateElement = xml.Descendants(ds + "KeyInfo").Descendants(ds + "X509Certificate").First();

        return Convert.FromBase64String(certificateElement.Value.Trim());
    }


    /// <summary>Parses a named fixture, or returns <see langword="null"/> (having already reported <see cref="Assert.Inconclusive(string)"/>) when the corpus is not present locally.</summary>
    private async Task<TrustedListParseResult?> ParseFixtureAsync(string fileName)
    {
        byte[]? bytes = await TryReadFixtureBytesAsync(fileName).ConfigureAwait(false);
        if(bytes is null)
        {
            return null;
        }

        using PooledMemory document = PooledMemory.FromBytes(bytes, BaseMemoryPool.Shared, TrustedListTags.Document);

        return await TrustedListXmlParser.ParseAsync(document, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reads a named fixture's bytes, or reports <see cref="Assert.Inconclusive(string)"/> and returns <see langword="null"/> when the corpus is not present locally.</summary>
    private async Task<byte[]?> TryReadFixtureBytesAsync(string fileName)
    {
        string? resourcesDirectory = TryFindDssTrustedListResourcesDirectory();
        if(resourcesDirectory is null)
        {
            Assert.Inconclusive("The local ETSI/eIDAS reference clone (tempdocs/etsi-ades-reference/dss) was not found; the DSS TL/LOTL corpus is optional local reference material.");
            return null;
        }

        //Searched recursively (not just Path.Combine at the top level): some named fixtures this class asks
        //for by bare file name live under a subdirectory (for example CZ_not-compliant.xml is under
        //lotlCache/), same as the whole-corpus test's own recursive enumeration.
        string? filePath = Directory.EnumerateFiles(resourcesDirectory, fileName, SearchOption.AllDirectories).FirstOrDefault();
        if(filePath is null)
        {
            Assert.Inconclusive($"Fixture '{fileName}' was not found under the DSS TL/LOTL resources directory.");
            return null;
        }

        return await File.ReadAllBytesAsync(filePath, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Walks up from the test assembly's own output directory looking for the repository's solution file,
    /// then resolves the DSS TL/LOTL resources directory relative to it — the same "walk up from
    /// AppContext.BaseDirectory" shape <c>VerifiableCliTestHelpers.GetExecutablePath</c> already uses for
    /// locating the built CLI, generalised to a marker-file search since the test output nesting depth is
    /// not itself part of this project's contract.
    /// </summary>
    /// <returns>The resources directory's full path, or <see langword="null"/> when either the repository root or the resources directory could not be found.</returns>
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
