using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using System.Xml.Schema;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the METS serialisation seams — the shipped model and delegate shapes of
/// <see cref="MetsDocument"/>/<see cref="ParseMetsDelegate"/>/<see cref="EncodeMetsDelegate"/>, exercised through
/// the staged worked binding <see cref="MetsXmlBinding"/> — against the METS profile of
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// The strongest leg is <see cref="TheProducedDocumentValidatesAgainstTheAuthenticSchemas"/>: what the encode
/// seam writes is checked against the base METS schema and the profile's own extension schema, neither of which
/// anything in this repository wrote. <see cref="TheSchemaValidationRefusesADocumentTheGrammarDoesNotAdmit"/> is
/// its control — without it, a validator that accepted everything would make the first test vacuous. Everything
/// else is either the round trip through the model, a document written to break the parse, or a bound the limits
/// state.
/// </para>
/// <para>
/// Every digest is computed through the registered digest seam, every carrier is rented from the house pool, and
/// every instant is stated rather than read from a clock.
/// </para>
/// </remarks>
[TestClass]
internal sealed class MetsXmlBindingTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The METS namespace, whose <c>elementFormDefault="qualified"</c> puts every element of a document in it.</summary>
    private static XNamespace Mets { get; } = MetsWellKnown.MetsNamespace;

    /// <summary>The extension namespace the profile's own schema declares for its four attributes.</summary>
    private static XNamespace Csip { get; } = MetsWellKnown.CsipExtensionNamespace;

    /// <summary>The instant the fixture states as when the package was created.</summary>
    private static DateTimeOffset Created { get; } = new(2026, 7, 31, 9, 15, 0, TimeSpan.Zero);

    /// <summary>The instant the fixture states as when the package was last modified.</summary>
    private static DateTimeOffset Modified { get; } = new(2026, 7, 31, 11, 45, 30, TimeSpan.Zero);

    /// <summary>The identifier of the package the fixture describes, which is also what a child package references it by.</summary>
    private const string PackageIdentifier = "urn-uuid-a1b2c3d4-e5f6-4789-abcd-ef0123456789";

    /// <summary>The labels of the four divisions under the fixture's root division, in the package's own folder order.</summary>
    private static string[] FolderLabels { get; } = ["Metadata", "Documentation", "Schemas", "Representations"];

    /// <summary>The descriptive-metadata sections the fixture's representation file names.</summary>
    private static string[] RepresentationFileDescriptiveIds { get; } = ["dmd-1"];

    /// <summary>The administrative-metadata sections the fixture's representation file names.</summary>
    private static string[] RepresentationFileAdministrativeIds { get; } = ["digiprov-1", "rights-1"];


    /// <summary>
    /// A document written and read again is the document that was written: every particle the profile's catalogue
    /// names survives, down to the per-representation file group, the division tree's own order and the
    /// package-to-package pointer.
    /// </summary>
    [TestMethod]
    public async Task ADocumentRoundTripsThroughTheModel()
    {
        using MetsDocument original = await BuildDocumentAsync().ConfigureAwait(false);
        using MetsEncodeResult encoded = await EncodeAsync(original).ConfigureAwait(false);

        Assert.IsTrue(encoded.IsEncoded, encoded.FailureReason);

        using MetsParseResult parsed = await ParseAsync(encoded.Document!).ConfigureAwait(false);

        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);

        MetsDocument read = parsed.Document!;
        Assert.AreEqual(original.ObjectIdentifier, read.ObjectIdentifier);
        Assert.AreEqual(original.ContentCategory, read.ContentCategory);
        Assert.AreEqual(original.OtherContentCategory, read.OtherContentCategory);
        Assert.AreEqual(original.Profile, read.Profile);
        Assert.AreEqual(original.ContentInformationType, read.ContentInformationType);
        Assert.AreEqual(original.Header.CreateDate, read.Header.CreateDate);
        Assert.AreEqual(original.Header.LastModificationDate, read.Header.LastModificationDate);
        Assert.AreEqual(original.Header.OaisPackageType, read.Header.OaisPackageType);

        Assert.HasCount(1, read.Header.Agents);
        MetsAgent agent = read.Header.Agents[0];
        Assert.AreEqual(MetsWellKnown.CreatorAgentRole, agent.Role);
        Assert.AreEqual(MetsWellKnown.OtherAgentType, agent.Type);
        Assert.AreEqual(MetsWellKnown.SoftwareAgentOtherType, agent.OtherType);
        Assert.AreEqual("the package creating tool", agent.Name);
        Assert.HasCount(1, agent.Notes);
        Assert.AreEqual(MetsWellKnown.SoftwareVersionNoteType, agent.Notes[0].NoteType);

        Assert.HasCount(1, read.DescriptiveMetadataSections);
        MetsDescriptiveMetadataSection descriptive = read.DescriptiveMetadataSections[0];
        Assert.AreEqual("dmd-1", descriptive.Id);
        Assert.AreEqual(MetsWellKnown.CurrentStatus, descriptive.Status);
        Assert.AreEqual("metadata/descriptive/dc.xml", descriptive.Reference!.Href);
        Assert.AreEqual("DC", descriptive.Reference.MetadataType);

        Assert.HasCount(1, read.AdministrativeMetadata!.DigitalProvenanceSections);
        Assert.HasCount(1, read.AdministrativeMetadata.RightsSections);
        MetsMetadataReference provenance = read.AdministrativeMetadata.DigitalProvenanceSections[0].Reference!;
        Assert.AreEqual(MetsWellKnown.PremisMetadataType, provenance.MetadataType);
        Assert.AreEqual("3.0", provenance.MetadataTypeVersion);
        Assert.AreEqual(4096L, provenance.Size);

        Assert.HasCount(3, read.FileSection!.FileGroups);
        MetsFileGroup representation = read.FileSection.FileGroups[2];
        Assert.AreEqual("Representations/rep1", representation.Use);
        Assert.AreEqual("rep1", MetsWellKnown.RepresentationFolderFromLabel(representation.Use));
        Assert.AreEqual(MetsWellKnown.MixedContentInformationType, representation.ContentInformationType);
        Assert.HasCount(1, representation.Files);
        Assert.AreEqual("representations/rep1/data/record.xml", representation.Files[0].Locator.Href);
        Assert.AreSequenceEqual(RepresentationFileDescriptiveIds, representation.Files[0].DescriptiveMetadataIds);
        Assert.AreSequenceEqual(RepresentationFileAdministrativeIds, representation.Files[0].AdministrativeMetadataIds);

        Assert.HasCount(1, read.StructuralMaps);
        MetsStructuralMap map = read.StructuralMaps[0];
        Assert.AreEqual(MetsWellKnown.PhysicalStructuralMapType, map.Type);
        Assert.AreEqual(MetsWellKnown.CsipStructuralMapLabel, map.Label);
        Assert.AreSequenceEqual(
            FolderLabels,
            LabelsOf(map.RootDivision.Divisions),
            "The division tree keeps the order the model stated it in.");

        MetsDivision representations = map.RootDivision.Divisions[3];
        Assert.HasCount(1, representations.Divisions);
        Assert.HasCount(1, representations.Divisions[0].MetsPointers);
        Assert.AreEqual("representations/rep1/METS.xml", representations.Divisions[0].MetsPointers[0].Href);
        Assert.AreEqual("rep1", representations.Divisions[0].MetsPointers[0].Title);
    }


    /// <summary>
    /// Writing the document that was read produces the same octets, which is what lets a caller hold a model of a
    /// manifest a fixity value or an evidence record already commits to.
    /// </summary>
    [TestMethod]
    public async Task WritingTheDocumentThatWasReadProducesTheSameOctets()
    {
        using MetsDocument original = await BuildDocumentAsync().ConfigureAwait(false);
        using MetsEncodeResult first = await EncodeAsync(original).ConfigureAwait(false);
        using MetsParseResult parsed = await ParseAsync(first.Document!).ConfigureAwait(false);

        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);

        using MetsEncodeResult second = await EncodeAsync(parsed.Document!).ConfigureAwait(false);

        Assert.IsTrue(second.IsEncoded, second.FailureReason);
        Assert.AreSequenceEqual(first.Document!.AsReadOnlySpan().ToArray(), second.Document!.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// The produced document validates against the base METS schema and the profile's own extension schema —
    /// so what this library writes is checked against the specifications' own grammars rather than against this
    /// library's reading of them.
    /// </summary>
    [TestMethod]
    public async Task TheProducedDocumentValidatesAgainstTheAuthenticSchemas()
    {
        XmlSchemaSet? schemas = EArkSchemaOracle.TryBuildMetsSchemas();
        if(schemas is null)
        {
            Assert.Inconclusive(EArkSchemaOracle.MissingSchemaMessage);

            return;
        }

        using MetsDocument document = await BuildDocumentAsync().ConfigureAwait(false);
        using MetsEncodeResult encoded = await EncodeAsync(document).ConfigureAwait(false);

        Assert.IsTrue(encoded.IsEncoded, encoded.FailureReason);

        List<string> problems = EArkSchemaOracle.Validate(encoded.Document!.AsReadOnlySpan(), schemas);

        Assert.IsEmpty(problems, string.Join(Environment.NewLine, problems));
    }


    /// <summary>
    /// The schema validation refuses a document the grammar does not admit, which is what makes
    /// <see cref="TheProducedDocumentValidatesAgainstTheAuthenticSchemas"/> a statement about the document rather
    /// than about a validator that accepts anything: the particles here are legal ones put in an order the base
    /// schema's sequence forbids, and a checksum type outside its enumeration.
    /// </summary>
    [TestMethod]
    public void TheSchemaValidationRefusesADocumentTheGrammarDoesNotAdmit()
    {
        XmlSchemaSet? schemas = EArkSchemaOracle.TryBuildMetsSchemas();
        if(schemas is null)
        {
            Assert.Inconclusive(EArkSchemaOracle.MissingSchemaMessage);

            return;
        }

        const string OutOfOrder = """
            <mets xmlns="http://www.loc.gov/METS/" xmlns:csip="https://DILCIS.eu/XML/METS/CSIPExtensionMETS" OBJID="x" TYPE="OTHER">
              <structMap ID="sm-1" TYPE="PHYSICAL" LABEL="CSIP"><div ID="d-1"/></structMap>
              <metsHdr CREATEDATE="2026-07-31T09:15:00Z" csip:OAISPACKAGETYPE="AIP"/>
            </mets>
            """;

        Assert.IsNotEmpty(
            EArkSchemaOracle.Validate(Encoding.UTF8.GetBytes(OutOfOrder), schemas),
            "A document whose sections are in an order the sequence forbids is not schema-valid.");

        const string ForeignChecksumType = """
            <mets xmlns="http://www.loc.gov/METS/" xmlns:xlink="http://www.w3.org/1999/xlink" OBJID="x" TYPE="OTHER">
              <fileSec ID="fs-1"><fileGrp ID="fg-1" USE="Documentation">
                <file ID="f-1" MIMETYPE="text/plain" SIZE="1" CREATED="2026-07-31T09:15:00Z" CHECKSUM="00" CHECKSUMTYPE="BLAKE3">
                  <FLocat LOCTYPE="URL" xlink:type="simple" xlink:href="documentation/a.txt"/>
                </file>
              </fileGrp></fileSec>
              <structMap ID="sm-1" TYPE="PHYSICAL" LABEL="CSIP"><div ID="d-1"/></structMap>
            </mets>
            """;

        Assert.IsNotEmpty(
            EArkSchemaOracle.Validate(Encoding.UTF8.GetBytes(ForeignChecksumType), schemas),
            "A checksum type outside the enumeration is not schema-valid, whatever this library would do with it.");
    }


    /// <summary>
    /// The produced document carries the sections the base schema's sequence states, in that order, and the two
    /// administrative sub-sections in the order that sequence puts them — rights before provenance, which is the
    /// opposite of the order the requirement catalogue numbers them in.
    /// </summary>
    [TestMethod]
    public async Task TheProducedDocumentCarriesItsSectionsInTheOrderTheSchemaSequences()
    {
        using MetsDocument document = await BuildDocumentAsync().ConfigureAwait(false);
        using MetsEncodeResult encoded = await EncodeAsync(document).ConfigureAwait(false);

        XElement root = XDocument.Parse(Encoding.UTF8.GetString(encoded.Document!.AsReadOnlySpan())).Root!;

        Assert.AreEqual(Mets + "mets", root.Name);
        Assert.AreSequenceEqual(
            new[] { Mets + "metsHdr", Mets + "dmdSec", Mets + "amdSec", Mets + "fileSec", Mets + "structMap" },
            NamesOf(root.Elements()));

        Assert.AreSequenceEqual(
            new[] { Mets + "rightsMD", Mets + "digiprovMD" },
            NamesOf(root.Element(Mets + "amdSec")!.Elements()));

        Assert.AreEqual(MetsWellKnown.ArchivalPackageType, (string?)root.Element(Mets + "metsHdr")!.Attribute(Csip + "OAISPACKAGETYPE"));
        Assert.AreEqual(MetsWellKnown.CsipProfileUri, (string?)root.Attribute("PROFILE"));
    }


    /// <summary>
    /// A division's children are written in the order the model states them, because the division tree is the
    /// package's own folder order and a reader has no other source for it.
    /// </summary>
    [TestMethod]
    public async Task ADivisionsChildrenAreWrittenInTheOrderTheModelStatesThem()
    {
        using MetsDocument document = await BuildDocumentAsync().ConfigureAwait(false);
        using MetsEncodeResult encoded = await EncodeAsync(document).ConfigureAwait(false);

        XElement root = XDocument.Parse(Encoding.UTF8.GetString(encoded.Document!.AsReadOnlySpan())).Root!;
        XElement rootDivision = root.Element(Mets + "structMap")!.Element(Mets + "div")!;

        var labels = new List<string?>();
        foreach(XElement child in rootDivision.Elements(Mets + "div"))
        {
            labels.Add((string?)child.Attribute("LABEL"));
        }

        Assert.AreSequenceEqual(FolderLabels, labels);
    }


    /// <summary>
    /// A document written to break the parse is refused with the status that names what was wrong, never with an
    /// exception and never with a document built around the defect.
    /// </summary>
    /// <param name="document">The document to parse.</param>
    /// <param name="expected">The status that refuses it.</param>
    [TestMethod]
    [DataRow("not xml at all", MetsParseStatus.Malformed, DisplayName = "octets that are not XML")]
    [DataRow("<mets xmlns=\"http://www.loc.gov/METS/\">", MetsParseStatus.Malformed, DisplayName = "a truncated document")]
    [DataRow("<other xmlns=\"http://www.loc.gov/METS/\"/>", MetsParseStatus.Malformed, DisplayName = "a root element that is not mets")]
    [DataRow("<mets xmlns=\"urn:test:other\"/>", MetsParseStatus.Malformed, DisplayName = "the right local name in the wrong namespace")]
    [DataRow("<mets/>", MetsParseStatus.Malformed, DisplayName = "the right local name in no namespace at all")]
    [DataRow("<!DOCTYPE mets [<!ENTITY x \"y\">]><mets xmlns=\"http://www.loc.gov/METS/\"/>", MetsParseStatus.Malformed, DisplayName = "a document type definition, which entity expansion needs")]
    public async Task ADocumentWrittenToBreakTheParseIsRefusedWithTheStatusThatNamesIt(string document, MetsParseStatus expected)
    {
        using PooledMemory octets = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, EArkTags.MetsDocument);
        using MetsParseResult result = await ParseAsync(octets).ConfigureAwait(false);

        Assert.AreEqual(expected, result.Status);
        Assert.IsNull(result.Document);
        Assert.IsNotNull(result.FailureReason);
    }


    /// <summary>
    /// A document naming an external entity is refused rather than fetched: the parse prohibits document type
    /// definitions outright, so neither expansion nor an outbound request is reachable from a package this
    /// library did not produce.
    /// </summary>
    [TestMethod]
    public async Task ADocumentNamingAnExternalEntityIsRefusedRatherThanFetched()
    {
        const string External = """
            <!DOCTYPE mets [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <mets xmlns="http://www.loc.gov/METS/" OBJID="&xxe;" TYPE="OTHER" PROFILE="p"/>
            """;

        using PooledMemory octets = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(External), BaseMemoryPool.Shared, EArkTags.MetsDocument);
        using MetsParseResult result = await ParseAsync(octets).ConfigureAwait(false);

        Assert.AreEqual(MetsParseStatus.Malformed, result.Status);
        Assert.IsNull(result.Document);
    }


    /// <summary>
    /// Every particle the profile makes mandatory is required by the parse too: a document missing one is refused
    /// rather than completed with a default.
    /// </summary>
    /// <param name="attributes">The <c>mets</c> element's attributes.</param>
    /// <param name="body">The <c>mets</c> element's content.</param>
    [TestMethod]
    [DataRow("TYPE=\"OTHER\" PROFILE=\"p\"", ValidBody, DisplayName = "no mets/@OBJID (CSIP1)")]
    [DataRow("OBJID=\"o\" PROFILE=\"p\"", ValidBody, DisplayName = "no mets/@TYPE (CSIP2)")]
    [DataRow("OBJID=\"o\" TYPE=\"OTHER\"", ValidBody, DisplayName = "no mets/@PROFILE (CSIP6)")]
    [DataRow(AllAttributes, ValidStructMap, DisplayName = "no metsHdr (CSIP117)")]
    [DataRow(AllAttributes, "<metsHdr csip:OAISPACKAGETYPE=\"AIP\"/>" + ValidStructMap, DisplayName = "no metsHdr/@CREATEDATE (CSIP7)")]
    [DataRow(AllAttributes, "<metsHdr CREATEDATE=\"2026-07-31T09:15:00Z\"/>" + ValidStructMap, DisplayName = "no metsHdr/@csip:OAISPACKAGETYPE (CSIP9)")]
    [DataRow(AllAttributes, ValidHeader, DisplayName = "no structMap (CSIP80)")]
    [DataRow(AllAttributes, ValidHeader + "<structMap ID=\"sm-1\" TYPE=\"PHYSICAL\"/>", DisplayName = "a structMap with no @LABEL (CSIP82)")]
    [DataRow(AllAttributes, ValidHeader + "<structMap ID=\"sm-1\" TYPE=\"PHYSICAL\" LABEL=\"CSIP\"/>", DisplayName = "a structMap with no root div (CSIP84)")]
    public async Task EveryParticleTheProfileMakesMandatoryIsRequiredByTheParseToo(string attributes, string body)
    {
        using MetsParseResult result = await ParseDocumentAsync(attributes, body).ConfigureAwait(false);

        Assert.AreEqual(MetsParseStatus.MissingRequiredElement, result.Status);
        Assert.IsNull(result.Document);
    }


    /// <summary>
    /// A value that is present but not of its declared type is refused as malformed rather than as missing: the
    /// markup is well-formed and it is the producer's value that is being refused, which is a different thing to
    /// tell a caller.
    /// </summary>
    /// <param name="body">The <c>mets</c> element's content.</param>
    [TestMethod]
    [DataRow("<metsHdr CREATEDATE=\"the thirty-first of July\" csip:OAISPACKAGETYPE=\"AIP\"/>" + ValidStructMap, DisplayName = "a @CREATEDATE that is not an xsd:dateTime")]
    [DataRow("<metsHdr CREATEDATE=\"2026-07-31T09:15:00Z\" LASTMODDATE=\"later\" csip:OAISPACKAGETYPE=\"AIP\"/>" + ValidStructMap, DisplayName = "a @LASTMODDATE that is not an xsd:dateTime")]
    [DataRow(ValidHeader + "<structMap ID=\"1-sm\" TYPE=\"PHYSICAL\" LABEL=\"CSIP\"><div ID=\"d-1\"/></structMap>", DisplayName = "an @ID that is not an XML NCName")]
    [DataRow(ValidHeader + "<structMap ID=\"sm-1\" TYPE=\"PHYSICAL\" LABEL=\"CSIP\"><div ID=\"csip:d\"/></structMap>", DisplayName = "an @ID carrying a colon, which an NCName may not")]
    public async Task AValueThatIsNotOfItsDeclaredTypeIsRefusedAsMalformedRatherThanMissing(string body)
    {
        using MetsParseResult result = await ParseDocumentAsync(AllAttributes, body).ConfigureAwait(false);

        Assert.AreEqual(MetsParseStatus.MalformedValue, result.Status);
        Assert.IsNull(result.Document);
    }


    /// <summary>
    /// An instant stating no zone is read as though it stated Zulu, so the same octets parse to the same instant
    /// wherever the package is read — the alternative, the reading machine's local zone, is not something a
    /// preservation format can afford, and several reference packages state their instants that way.
    /// </summary>
    [TestMethod]
    public async Task AnInstantStatingNoZoneIsReadAsThoughItStatedZulu()
    {
        using MetsParseResult result = await ParseDocumentAsync(
            AllAttributes,
            "<metsHdr CREATEDATE=\"2026-07-31T09:15:00\" csip:OAISPACKAGETYPE=\"AIP\"/>" + ValidStructMap).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.FailureReason);
        Assert.AreEqual(new DateTimeOffset(2026, 7, 31, 9, 15, 0, TimeSpan.Zero), result.Document!.Header.CreateDate);
    }


    /// <summary>
    /// A fixity this library cannot recompute is carried through the parse with its reason rather than refusing
    /// the document — the deliberate asymmetry the profile forces, since its own reference packages state their
    /// fixity under MD5 and a reader that refused them would refuse most of the corpus it exists to read.
    /// </summary>
    [TestMethod]
    public async Task AFixityThisLibraryCannotRecomputeIsCarriedThroughTheParse()
    {
        const string WeakFixity = """
            <fileSec ID="fs-1"><fileGrp ID="fg-1" USE="Documentation">
              <file ID="f-1" MIMETYPE="application/pdf" SIZE="1024" CREATED="2026-07-31T09:15:00Z" CHECKSUM="d41d8cd98f00b204e9800998ecf8427e" CHECKSUMTYPE="MD5">
                <FLocat LOCTYPE="URL" xlink:type="simple" xlink:href="documentation/manual.pdf"/>
              </file>
            </fileGrp></fileSec>
            """;

        using MetsParseResult result = await ParseDocumentAsync(AllAttributes, ValidHeader + WeakFixity + ValidStructMap).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.FailureReason);

        EArkFixity fixity = result.Document!.FileSection!.FileGroups[0].Files[0].Fixity;
        Assert.AreEqual(EArkFixityStatus.WeakCryptographicAlgorithm, fixity.Status);

        var stated = Assert.IsInstanceOfType<EArkStatedFixity>(fixity);
        Assert.AreEqual("MD5", stated.ChecksumType);
        Assert.AreEqual("d41d8cd98f00b204e9800998ecf8427e", stated.Checksum,
            "The value is carried exactly as the document stated it; dropping it would leave a rule unable to say what the package met.");
    }


    /// <summary>
    /// Every bound the limits state is a refusal rather than a resource the document may spend.
    /// </summary>
    [TestMethod]
    public async Task EveryBoundTheLimitsStateIsARefusal()
    {
        using MetsDocument document = await BuildDocumentAsync().ConfigureAwait(false);
        using MetsEncodeResult encoded = await EncodeAsync(document).ConfigureAwait(false);

        foreach(MetsParseLimits limits in new[]
        {
            new MetsParseLimits { MaximumDocumentByteLength = 64 },
            new MetsParseLimits { MaximumMetadataSections = 0 },
            new MetsParseLimits { MaximumFileGroups = 2 },
            new MetsParseLimits { MaximumFiles = 2 },
            new MetsParseLimits { MaximumStructuralMaps = 0 },
            new MetsParseLimits { MaximumDivisions = 3 },
            new MetsParseLimits { MaximumAgents = 0 },
            new MetsParseLimits { MaximumTextLength = 8 }
        })
        {
            using MetsParseResult result = await MetsXmlBinding.ParseAsync(
                new MetsParseContext { Document = encoded.Document!, Limits = limits },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(MetsParseStatus.LimitExceeded, result.Status);
            Assert.IsNull(result.Document);
        }
    }


    /// <summary>
    /// A division tree that nests beyond the bound is refused rather than walked, and the walk itself is not
    /// recursive: a tree far deeper than any call stack would survive is refused by a counter rather than by an
    /// overflow.
    /// </summary>
    [TestMethod]
    public async Task ADivisionTreeThatNestsBeyondTheBoundIsRefusedRatherThanWalked()
    {
        const int Depth = 20_000;
        var deep = new StringBuilder();
        _ = deep.Append(CultureInfo.InvariantCulture, $"<structMap ID=\"sm-1\" TYPE=\"PHYSICAL\" LABEL=\"CSIP\">");
        for(int i = 0; i < Depth; ++i)
        {
            _ = deep.Append(CultureInfo.InvariantCulture, $"<div ID=\"d-{i}\">");
        }

        for(int i = 0; i < Depth; ++i)
        {
            _ = deep.Append("</div>");
        }

        _ = deep.Append("</structMap>");

        using MetsParseResult result = await ParseDocumentAsync(AllAttributes, ValidHeader + deep.ToString()).ConfigureAwait(false);

        Assert.AreEqual(MetsParseStatus.LimitExceeded, result.Status);
        Assert.IsNull(result.Document);
    }


    /// <summary>
    /// A division tree inside the bound is read whole, so the refusal above is the bound's doing rather than the
    /// walk's: a tree one level short of the limit reads, and its deepest division is reached.
    /// </summary>
    [TestMethod]
    public async Task ADivisionTreeInsideTheBoundIsReadWhole()
    {
        const int Depth = 16;
        var nested = new StringBuilder();
        _ = nested.Append("<structMap ID=\"sm-1\" TYPE=\"PHYSICAL\" LABEL=\"CSIP\">");
        for(int i = 0; i < Depth; ++i)
        {
            _ = nested.Append(CultureInfo.InvariantCulture, $"<div ID=\"d-{i}\">");
        }

        for(int i = 0; i < Depth; ++i)
        {
            _ = nested.Append("</div>");
        }

        _ = nested.Append("</structMap>");

        using MetsParseResult result = await ParseDocumentAsync(AllAttributes, ValidHeader + nested.ToString()).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.FailureReason);

        MetsDivision division = result.Document!.StructuralMaps[0].RootDivision;
        int reached = 1;
        while(division.Divisions.Count > 0)
        {
            division = division.Divisions[0];
            ++reached;
        }

        Assert.AreEqual(Depth, reached);
        Assert.AreEqual("d-15", division.Id);
    }


    /// <summary>
    /// A model that cannot become a conformant document is refused by the encoding with the status that names
    /// what was wrong: no structural map at all, an identifier that is not an XML <c>NCName</c>, and a fixity
    /// this library cannot recompute.
    /// </summary>
    [TestMethod]
    public async Task AModelThatCannotBecomeAConformantDocumentIsRefusedByTheEncoding()
    {
        using MetsDocument withoutMap = await BuildDocumentAsync(structuralMaps: []).ConfigureAwait(false);
        using MetsEncodeResult noMap = await EncodeAsync(withoutMap).ConfigureAwait(false);
        Assert.AreEqual(MetsEncodeStatus.NoStructuralMap, noMap.Status);
        Assert.IsNull(noMap.Document);

        using MetsDocument badIdentifier = await BuildDocumentAsync(fileSectionId: "1-filesec").ConfigureAwait(false);
        using MetsEncodeResult invalid = await EncodeAsync(badIdentifier).ConfigureAwait(false);
        Assert.AreEqual(MetsEncodeStatus.InvalidIdentifier, invalid.Status);
        Assert.IsNull(invalid.Document);

        using MetsDocument weakFixity = await BuildDocumentAsync(weakDocumentationFixity: true).ConfigureAwait(false);
        using MetsEncodeResult refused = await EncodeAsync(weakFixity).ConfigureAwait(false);
        Assert.AreEqual(MetsEncodeStatus.UnrecomputableFixity, refused.Status);
        Assert.IsNull(refused.Document);
    }


    /// <summary>
    /// The documented departure writes a fixity this library cannot recompute through as the text it was read as,
    /// which has exactly one honest use: writing back a document whose fixity somebody else asserted.
    /// </summary>
    [TestMethod]
    public async Task TheDocumentedDepartureWritesAnUnrecomputableFixityThrough()
    {
        using MetsDocument document = await BuildDocumentAsync(weakDocumentationFixity: true).ConfigureAwait(false);
        using MetsEncodeResult encoded = await MetsXmlBinding.EncodeAsync(
            new MetsEncodeContext { Document = document, AllowUnrecomputableFixity = true },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(encoded.IsEncoded, encoded.FailureReason);

        using MetsParseResult parsed = await ParseAsync(encoded.Document!).ConfigureAwait(false);

        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);

        EArkFixity fixity = parsed.Document!.FileSection!.FileGroups[0].Files[0].Fixity;
        var stated = Assert.IsInstanceOfType<EArkStatedFixity>(fixity);
        Assert.AreEqual(MetsWellKnown.Md5ChecksumType, stated.ChecksumType);
        Assert.AreEqual(EArkFixityStatus.WeakCryptographicAlgorithm, stated.Status);
    }


    /// <summary>
    /// The package-to-package pointer carries whatever the document stated — a location for a representation, and
    /// another package's own identifier for a parent or a child — because clause 5.1 states outright that a
    /// reference to another package uses that package's <c>mets/@OBJID</c>, which is not a location at all.
    /// </summary>
    [TestMethod]
    public async Task ThePackageToPackagePointerCarriesWhateverTheDocumentStated()
    {
        const string ChainedMap = """
            <structMap ID="sm-1" TYPE="PHYSICAL" LABEL="CSIP">
              <div ID="d-root" LABEL="root">
                <mptr LOCTYPE="URL" xlink:type="simple" xlink:href="urn-uuid-child-package" xlink:title="a child package"/>
                <mptr LOCTYPE="URL" xlink:type="simple" xlink:href="representations/rep1/METS.xml"/>
              </div>
            </structMap>
            """;

        using MetsParseResult result = await ParseDocumentAsync(AllAttributes, ValidHeader + ChainedMap).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.FailureReason);

        IReadOnlyList<MetsPointer> pointers = result.Document!.StructuralMaps[0].RootDivision.MetsPointers;
        Assert.HasCount(2, pointers);
        Assert.AreEqual("urn-uuid-child-package", pointers[0].Href);
        Assert.AreEqual("a child package", pointers[0].Title);
        Assert.IsNull(pointers[1].Title, "The title is optional and an absent one is not an empty one.");
    }


    /// <summary>
    /// Builds the fixture document: a package-level manifest carrying a header with the mandatory creator agent,
    /// one descriptive section, both administrative sections, the three mandated file groups plus one
    /// per-representation group, and the profile's structural map with a division per folder.
    /// </summary>
    /// <param name="structuralMaps">The structural maps to carry, or <see langword="null"/> for the fixture's own.</param>
    /// <param name="fileSectionId">The file section's identifier.</param>
    /// <param name="weakDocumentationFixity">Whether the documentation file states a fixity this library cannot recompute.</param>
    /// <returns>The document. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every fixity built here transfers to the returned document, which the caller disposes.")]
    private static async Task<MetsDocument> BuildDocumentAsync(
        IReadOnlyList<MetsStructuralMap>? structuralMaps = null,
        string fileSectionId = "filesec-1",
        bool weakDocumentationFixity = false)
    {
        EArkFixity documentationFixity = weakDocumentationFixity
            ? new EArkStatedFixity(MetsWellKnown.Md5ChecksumType, "d41d8cd98f00b204e9800998ecf8427e", EArkFixityStatus.WeakCryptographicAlgorithm)
            : await FixityAsync("the documentation"u8.ToArray()).ConfigureAwait(false);

        return new MetsDocument
        {
            ObjectIdentifier = PackageIdentifier,
            ContentCategory = "OTHER",
            OtherContentCategory = "a reference package",
            Profile = MetsWellKnown.CsipProfileUri,
            ContentInformationType = MetsWellKnown.MixedContentInformationType,
            Header = new MetsHeader
            {
                CreateDate = Created,
                LastModificationDate = Modified,
                OaisPackageType = MetsWellKnown.ArchivalPackageType,
                Agents =
                [
                    new MetsAgent
                    {
                        Role = MetsWellKnown.CreatorAgentRole,
                        Type = MetsWellKnown.OtherAgentType,
                        OtherType = MetsWellKnown.SoftwareAgentOtherType,
                        Name = "the package creating tool",
                        Notes = [new MetsAgentNote(MetsWellKnown.SoftwareVersionNoteType, "1.0.0")]
                    }
                ]
            },
            DescriptiveMetadataSections =
            [
                new MetsDescriptiveMetadataSection
                {
                    Id = "dmd-1",
                    Created = Created,
                    Status = MetsWellKnown.CurrentStatus,
                    Reference = await ReferenceAsync("metadata/descriptive/dc.xml", "DC", null, 512).ConfigureAwait(false)
                }
            ],
            AdministrativeMetadata = new MetsAdministrativeMetadata
            {
                DigitalProvenanceSections =
                [
                    new MetsAdministrativeMetadataSection
                    {
                        Id = "digiprov-1",
                        Status = MetsWellKnown.CurrentStatus,
                        Reference = await ReferenceAsync("metadata/preservation/premis.xml", MetsWellKnown.PremisMetadataType, "3.0", 4096).ConfigureAwait(false)
                    }
                ],
                RightsSections =
                [
                    new MetsAdministrativeMetadataSection
                    {
                        Id = "rights-1",
                        Status = MetsWellKnown.CurrentStatus,
                        Reference = await ReferenceAsync("metadata/rights/rights.xml", "METSRIGHTS", null, 256).ConfigureAwait(false)
                    }
                ]
            },
            FileSection = new MetsFileSection
            {
                Id = fileSectionId,
                FileGroups =
                [
                    new MetsFileGroup
                    {
                        Id = "grp-documentation",
                        Use = MetsWellKnown.DocumentationLabel,
                        AdministrativeMetadataIds = ["digiprov-1"],
                        Files =
                        [
                            new MetsFile
                            {
                                Id = "file-documentation-1",
                                MediaType = "application/pdf",
                                Size = 20_480,
                                Created = Created,
                                Fixity = documentationFixity,
                                Locator = new MetsFileLocator(MetsWellKnown.UrlLocatorType, MetsWellKnown.SimpleLinkType, "documentation/manual.pdf")
                            }
                        ]
                    },
                    new MetsFileGroup
                    {
                        Id = "grp-schemas",
                        Use = MetsWellKnown.SchemasLabel,
                        Files =
                        [
                            new MetsFile
                            {
                                Id = "file-schemas-1",
                                MediaType = "text/xml",
                                Size = 65_536,
                                Created = Created,
                                Fixity = await FixityAsync("the schema"u8.ToArray(), PkiDigestAlgorithm.Sha512).ConfigureAwait(false),
                                Locator = new MetsFileLocator(MetsWellKnown.UrlLocatorType, MetsWellKnown.SimpleLinkType, "schemas/mets.xsd")
                            }
                        ]
                    },
                    new MetsFileGroup
                    {
                        Id = "grp-representation-1",
                        Use = MetsWellKnown.RepresentationsPrefix + "rep1",
                        ContentInformationType = MetsWellKnown.MixedContentInformationType,
                        Files =
                        [
                            new MetsFile
                            {
                                Id = "file-representation-1",
                                MediaType = "text/xml",
                                Size = 1_024,
                                Created = Created,
                                Fixity = await FixityAsync("the record"u8.ToArray()).ConfigureAwait(false),
                                OwnerId = "record-0001",
                                DescriptiveMetadataIds = ["dmd-1"],
                                AdministrativeMetadataIds = ["digiprov-1", "rights-1"],
                                Locator = new MetsFileLocator(MetsWellKnown.UrlLocatorType, MetsWellKnown.SimpleLinkType, "representations/rep1/data/record.xml")
                            }
                        ]
                    }
                ]
            },
            StructuralMaps = structuralMaps ?? BuildStructuralMaps()
        };

        //Builds the profile's structural map: one division per folder the package carries, in folder order, with
        //the representation division pointing at the representation's own manifest.
        static IReadOnlyList<MetsStructuralMap> BuildStructuralMaps() =>
        [
            new MetsStructuralMap
            {
                Id = "structmap-1",
                Type = MetsWellKnown.PhysicalStructuralMapType,
                Label = MetsWellKnown.CsipStructuralMapLabel,
                RootDivision = new MetsDivision
                {
                    Id = "div-root",
                    Label = PackageIdentifier,
                    Divisions =
                    [
                        new MetsDivision
                        {
                            Id = "div-metadata",
                            Label = MetsWellKnown.MetadataLabel,
                            DescriptiveMetadataIds = ["dmd-1"],
                            AdministrativeMetadataIds = ["digiprov-1", "rights-1"]
                        },
                        new MetsDivision
                        {
                            Id = "div-documentation",
                            Label = MetsWellKnown.DocumentationLabel,
                            FilePointers = [new MetsFilePointer("grp-documentation")]
                        },
                        new MetsDivision
                        {
                            Id = "div-schemas",
                            Label = MetsWellKnown.SchemasLabel,
                            FilePointers = [new MetsFilePointer("grp-schemas")]
                        },
                        new MetsDivision
                        {
                            Id = "div-representations",
                            Label = MetsWellKnown.RepresentationsLabel,
                            Divisions =
                            [
                                new MetsDivision
                                {
                                    Id = "div-representation-1",
                                    Label = MetsWellKnown.RepresentationsPrefix + "rep1",
                                    FilePointers = [new MetsFilePointer("grp-representation-1")],
                                    MetsPointers =
                                    [
                                        new MetsPointer(
                                            "representations/rep1/METS.xml",
                                            MetsWellKnown.UrlLocatorType,
                                            MetsWellKnown.SimpleLinkType,
                                            "rep1")
                                    ]
                                }
                            ]
                        }
                    ]
                }
            }
        ];
    }


    /// <summary>
    /// Builds one metadata reference with a fixity computed through the registered digest seam.
    /// </summary>
    /// <param name="href">Where the referenced document sits.</param>
    /// <param name="metadataType">Which metadata vocabulary the referenced document speaks.</param>
    /// <param name="metadataTypeVersion">The vocabulary's version, or <see langword="null"/>.</param>
    /// <param name="size">The referenced document's size in octets.</param>
    /// <returns>The reference. Ownership transfers to whoever holds it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the fixity transfers to the returned reference, which the document that holds it disposes.")]
    private static async Task<MetsMetadataReference> ReferenceAsync(string href, string metadataType, string? metadataTypeVersion, long size) =>
        new()
        {
            LocatorType = MetsWellKnown.UrlLocatorType,
            LinkType = MetsWellKnown.SimpleLinkType,
            Href = href,
            MetadataType = metadataType,
            MetadataTypeVersion = metadataTypeVersion,
            MediaType = "text/xml",
            Size = size,
            Created = Created,
            Fixity = await FixityAsync(Encoding.UTF8.GetBytes(href)).ConfigureAwait(false)
        };


    /// <summary>
    /// Computes a fixity through the registered digest seam.
    /// </summary>
    /// <param name="content">The octets to hash.</param>
    /// <param name="algorithm">The algorithm to hash under.</param>
    /// <returns>The fixity. Ownership transfers to whoever holds it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the digest transfers to the returned fixity, which the document that holds it disposes.")]
    private static async Task<EArkFixity> FixityAsync(byte[] content, PkiDigestAlgorithm? algorithm = null)
    {
        PkiDigestAlgorithm resolved = algorithm ?? PkiDigestAlgorithm.Sha256;
        DigestValue digest = await CryptographicKeyEvents.ComputeDigestAsync(
            content,
            resolved.OutputByteLength,
            resolved.DigestTag,
            BaseMemoryPool.Shared).ConfigureAwait(false);

        return new EArkRecomputableFixity(resolved, digest);
    }


    /// <summary>The attributes a document states when nothing about them is what a test is checking.</summary>
    private const string AllAttributes = "OBJID=\"o\" TYPE=\"OTHER\" PROFILE=\"p\"";

    /// <summary>A conformant header, for tests whose subject is elsewhere.</summary>
    private const string ValidHeader = "<metsHdr CREATEDATE=\"2026-07-31T09:15:00Z\" csip:OAISPACKAGETYPE=\"AIP\"/>";

    /// <summary>A conformant structural map, for tests whose subject is elsewhere.</summary>
    private const string ValidStructMap = "<structMap ID=\"sm-1\" TYPE=\"PHYSICAL\" LABEL=\"CSIP\"><div ID=\"d-1\"/></structMap>";

    /// <summary>A conformant header and structural map together.</summary>
    private const string ValidBody = ValidHeader + ValidStructMap;


    /// <summary>
    /// Parses a document assembled from a root attribute list and a body.
    /// </summary>
    /// <param name="attributes">The <c>mets</c> element's attributes.</param>
    /// <param name="body">The <c>mets</c> element's content.</param>
    /// <returns>The parse result. The caller owns and disposes it.</returns>
    private async Task<MetsParseResult> ParseDocumentAsync(string attributes, string body)
    {
        string document = string.Create(
            CultureInfo.InvariantCulture,
            $"""<mets xmlns="{MetsWellKnown.MetsNamespace}" xmlns:csip="{MetsWellKnown.CsipExtensionNamespace}" xmlns:xlink="{MetsWellKnown.XLinkNamespace}" {attributes}>{body}</mets>""");

        using PooledMemory octets = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, EArkTags.MetsDocument);

        return await ParseAsync(octets).ConfigureAwait(false);
    }


    /// <summary>Encodes a document through the staged binding under the secure default fixity policy.</summary>
    /// <param name="document">The document to write.</param>
    /// <returns>The encoding result. The caller owns and disposes it.</returns>
    private ValueTask<MetsEncodeResult> EncodeAsync(MetsDocument document) =>
        MetsXmlBinding.EncodeAsync(new MetsEncodeContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken);


    /// <summary>Parses a document through the staged binding under the conformant limits.</summary>
    /// <param name="document">The document's octets.</param>
    /// <returns>The parse result. The caller owns and disposes it.</returns>
    private ValueTask<MetsParseResult> ParseAsync(PooledMemory document) =>
        MetsXmlBinding.ParseAsync(new MetsParseContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken);


    /// <summary>
    /// States the labels of a division list, so an ordering assertion reads as the folder order it is about.
    /// </summary>
    /// <param name="divisions">The divisions.</param>
    /// <returns>Each division's label.</returns>
    private static List<string?> LabelsOf(IReadOnlyList<MetsDivision> divisions)
    {
        List<string?> labels = [];
        foreach(MetsDivision division in divisions)
        {
            labels.Add(division.Label);
        }

        return labels;
    }


    /// <summary>
    /// States the names of an element sequence, so an ordering assertion reads as the sequence it is about.
    /// </summary>
    /// <param name="elements">The elements.</param>
    /// <returns>Each element's qualified name.</returns>
    private static List<XName> NamesOf(IEnumerable<XElement> elements)
    {
        List<XName> names = [];
        foreach(XElement element in elements)
        {
            names.Add(element.Name);
        }

        return names;
    }
}
