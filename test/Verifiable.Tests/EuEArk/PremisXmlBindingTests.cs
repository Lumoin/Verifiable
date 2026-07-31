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
/// Conformance tests for the preservation-metadata serialisation seams — the shipped model and delegate shapes of
/// <see cref="PremisDocument"/>/<see cref="ParsePremisDelegate"/>/<see cref="EncodePremisDelegate"/>, exercised
/// through the staged worked binding <see cref="PremisXmlBinding"/> — against
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> and the vocabulary it
/// constrains.
/// </summary>
/// <remarks>
/// <para>
/// Two independent grammars judge what the encode seam writes.
/// <see cref="TheProducedDocumentValidatesAgainstTheAuthenticSchema"/> uses the vocabulary's own version 3.0
/// schema, which the reference corpus' packages carry because the folder-structure requirements ask a package to
/// ship a copy of every schema its metadata is stated under;
/// <see cref="TheProducedDocumentValidatesAgainstTheCatalogueSubsetSchema"/> uses a schema written from the
/// requirement tables, which is a weaker claim about provenance and a stronger one about the catalogue, since the
/// vocabulary's own schema is looser than what the tables ask for.
/// </para>
/// <para>
/// Every digest is computed through the registered digest seam, every carrier is rented from the house pool, and
/// every instant is stated rather than read from a clock.
/// </para>
/// </remarks>
[TestClass]
internal sealed class PremisXmlBindingTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The preservation-metadata namespace, whose <c>elementFormDefault="qualified"</c> puts every element of a document in it.</summary>
    private static XNamespace Premis { get; } = PremisWellKnown.PremisNamespace;

    /// <summary>The XML Schema instance namespace, which carries the attribute an object states its category in.</summary>
    private static XNamespace SchemaInstance { get; } = PremisWellKnown.XmlSchemaInstanceNamespace;

    /// <summary>The instant the fixture's events state, in the extended form the vocabulary types them as.</summary>
    private const string EventInstant = "2026-07-31T09:15:00Z";

    /// <summary>The acts the fixture's rights statement grants.</summary>
    private static string[] GrantedActs { get; } = ["disseminate"];

    /// <summary>The two encode refusals a model that cannot become a conformant document reaches.</summary>
    private static PremisEncodeStatus[] EncodeRefusals { get; } =
        [PremisEncodeStatus.MissingIdentifier, PremisEncodeStatus.UnrecomputableFixity];


    /// <summary>
    /// A document written and read again is the document that was written: all four entities, the three object
    /// categories the fixture carries, the relationships between them, and the fixity each file states.
    /// </summary>
    [TestMethod]
    public async Task ADocumentRoundTripsThroughTheModel()
    {
        using PremisDocument original = await BuildDocumentAsync().ConfigureAwait(false);
        using PremisEncodeResult encoded = await EncodeAsync(original).ConfigureAwait(false);

        Assert.IsTrue(encoded.IsEncoded, encoded.FailureReason);

        using PremisParseResult parsed = await ParseAsync(encoded.Document!).ConfigureAwait(false);

        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);

        PremisDocument read = parsed.Document!;
        Assert.AreEqual(PremisWellKnown.PremisVersion, read.Version);
        Assert.HasCount(3, read.Objects);
        Assert.HasCount(1, read.Events);
        Assert.HasCount(1, read.Agents);
        Assert.HasCount(1, read.RightsStatements);

        PremisObject entity = read.Objects[0];
        Assert.AreEqual(PremisWellKnown.IntellectualEntityObjectCategory, entity.Category);
        Assert.AreEqual(PremisWellKnown.LocalIdentifierType, entity.Identifiers[0].Type);
        Assert.AreEqual("intellectual-entity-1", entity.Identifiers[0].Value);
        Assert.HasCount(1, entity.EnvironmentFunctions);
        Assert.AreEqual("render", entity.EnvironmentFunctions[0].Type);
        Assert.AreEqual("the rendering environment", entity.EnvironmentDesignation!.Value.Name);
        Assert.HasCount(1, entity.SignificantProperties);

        PremisObject representation = read.Objects[1];
        Assert.AreEqual(PremisWellKnown.RepresentationObjectCategory, representation.Category);
        Assert.HasCount(1, representation.Storage);
        Assert.AreEqual("representations/rep1", representation.Storage[0].ContentLocation!.Value.Value);
        Assert.AreEqual("magnetic tape", representation.Storage[0].Medium);
        Assert.HasCount(1, representation.Relationships);
        Assert.AreEqual("structural", representation.Relationships[0].Type);
        Assert.AreEqual("isIncludedIn", representation.Relationships[0].SubType);
        Assert.AreEqual("intellectual-entity-1", representation.Relationships[0].RelatedObjectIdentifiers[0].Value);
        Assert.AreEqual("event-1", representation.Relationships[0].RelatedEventIdentifiers[0].Value);

        PremisObject file = read.Objects[2];
        Assert.AreEqual(PremisWellKnown.FileObjectCategory, file.Category);
        Assert.AreEqual("the original file name", file.OriginalName);
        Assert.HasCount(1, file.Characteristics);
        Assert.HasCount(2, file.Characteristics[0].Fixities);
        Assert.AreEqual("XML", file.Characteristics[0].Format!.Value.Designation!.Value.Name);
        Assert.AreEqual("fmt/101", file.Characteristics[0].Format!.Value.Registry!.Value.Key);
        Assert.HasCount(1, file.Characteristics[0].CreatingApplications);
        Assert.AreSequenceEqual(
            new[] { EArkFixityStatus.Recomputable, EArkFixityStatus.Recomputable },
            StatusesOf(file.Characteristics[0].Fixities));

        PremisEvent preservationEvent = read.Events[0];
        Assert.AreEqual("migration", preservationEvent.Type);
        Assert.AreEqual(EventInstant, preservationEvent.EventDateTime);
        Assert.AreEqual("success", preservationEvent.Outcome);
        Assert.AreEqual("agent-1", preservationEvent.LinkingAgentIdentifiers[0].Value);
        Assert.AreEqual("file-1", preservationEvent.LinkingObjectIdentifiers[0].Value);

        PremisAgent agent = read.Agents[0];
        Assert.AreEqual("the migrating tool", agent.Name);
        Assert.AreEqual("software", agent.Type);
        Assert.AreEqual("1.0.0", agent.Version);
        Assert.AreEqual("the note", agent.Note);

        PremisRightsStatement rights = read.RightsStatements[0];
        Assert.AreEqual(PremisWellKnown.CopyrightRightsBasis, rights.Basis);
        Assert.AreEqual("copyrighted", rights.CopyrightInformation!.Status);
        Assert.AreEqual("FI", rights.CopyrightInformation.Jurisdiction);
        Assert.AreSequenceEqual(GrantedActs, rights.RightsGranted!.Acts);
        Assert.AreEqual("2026-07-31", rights.RightsGranted.TermOfGrant!.Value.StartDate);
        Assert.IsNull(rights.RightsGranted.TermOfGrant.Value.EndDate, "A grant that does not end states no end date, and an absent one is not an empty one.");
    }


    /// <summary>
    /// Writing the document that was read produces the same octets, which is what lets a caller hold a model of a
    /// document whose digest a package manifest already commits to.
    /// </summary>
    [TestMethod]
    public async Task WritingTheDocumentThatWasReadProducesTheSameOctets()
    {
        using PremisDocument original = await BuildDocumentAsync().ConfigureAwait(false);
        using PremisEncodeResult first = await EncodeAsync(original).ConfigureAwait(false);
        using PremisParseResult parsed = await ParseAsync(first.Document!).ConfigureAwait(false);

        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);

        using PremisEncodeResult second = await EncodeAsync(parsed.Document!).ConfigureAwait(false);

        Assert.IsTrue(second.IsEncoded, second.FailureReason);
        Assert.AreSequenceEqual(first.Document!.AsReadOnlySpan().ToArray(), second.Document!.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// The produced document validates against the vocabulary's own version 3.0 schema — the grammar every
    /// conformant reader of a package applies, which nothing in this repository wrote.
    /// </summary>
    /// <remarks>
    /// The fixture is what makes this pass, and what it has to satisfy is worth stating: that schema gives each
    /// object category a DIFFERENT child sequence — an intellectual entity admits the environment particles and
    /// neither characteristics nor storage, a representation admits neither characteristics nor environment
    /// particles, and a file requires at least one characteristics element carrying a format. The encode seam
    /// writes one fixed order, and this test is the proof that the order is a correct linearisation of all of
    /// them, which is exactly why the model declines to enforce the split itself.
    /// </remarks>
    [TestMethod]
    public async Task TheProducedDocumentValidatesAgainstTheAuthenticSchema()
    {
        XmlSchemaSet? schemas = EArkSchemaOracle.TryBuildAuthenticPremisSchemas();
        if(schemas is null)
        {
            Assert.Inconclusive(EArkSchemaOracle.MissingPremisSchemaMessage);

            return;
        }

        using PremisDocument document = await BuildDocumentAsync().ConfigureAwait(false);
        using PremisEncodeResult encoded = await EncodeAsync(document).ConfigureAwait(false);

        Assert.IsTrue(encoded.IsEncoded, encoded.FailureReason);

        List<string> problems = EArkSchemaOracle.Validate(encoded.Document!.AsReadOnlySpan(), schemas);

        Assert.IsEmpty(problems, string.Join(Environment.NewLine, problems));
    }


    /// <summary>
    /// The produced document also validates against a schema written from the requirement tables, which is the
    /// catalogue's own reading of the same vocabulary and is in several places narrower than the vocabulary's
    /// schema.
    /// </summary>
    [TestMethod]
    public async Task TheProducedDocumentValidatesAgainstTheCatalogueSubsetSchema()
    {
        XmlSchemaSet schemas = EArkSchemaOracle.BuildPremisSchemas();

        using PremisDocument document = await BuildDocumentAsync().ConfigureAwait(false);
        using PremisEncodeResult encoded = await EncodeAsync(document).ConfigureAwait(false);

        Assert.IsTrue(encoded.IsEncoded, encoded.FailureReason);

        List<string> problems = EArkSchemaOracle.Validate(encoded.Document!.AsReadOnlySpan(), schemas);

        Assert.IsEmpty(problems, string.Join(Environment.NewLine, problems));
    }


    /// <summary>
    /// Both schema validations refuse a document the grammar does not admit, which is what makes the two tests
    /// above statements about the document rather than about validators that accept anything.
    /// </summary>
    [TestMethod]
    public void TheSchemaValidationsRefuseADocumentTheGrammarDoesNotAdmit()
    {
        const string OutOfOrder = """
            <premis xmlns="http://www.loc.gov/premis/v3" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" version="3.0">
              <object xsi:type="representation">
                <significantProperties><significantPropertiesType>t</significantPropertiesType><significantPropertiesValue>v</significantPropertiesValue></significantProperties>
                <objectIdentifier><objectIdentifierType>local</objectIdentifierType><objectIdentifierValue>o-1</objectIdentifierValue></objectIdentifier>
              </object>
            </premis>
            """;

        Assert.IsNotEmpty(
            EArkSchemaOracle.Validate(Encoding.UTF8.GetBytes(OutOfOrder), EArkSchemaOracle.BuildPremisSchemas()),
            "An object stating its properties before its identifier is not schema-valid.");

        XmlSchemaSet? authentic = EArkSchemaOracle.TryBuildAuthenticPremisSchemas();
        if(authentic is null)
        {
            Assert.Inconclusive(EArkSchemaOracle.MissingPremisSchemaMessage);

            return;
        }

        Assert.IsNotEmpty(
            EArkSchemaOracle.Validate(Encoding.UTF8.GetBytes(OutOfOrder), authentic),
            "The vocabulary's own schema sequences an object's children too.");
    }


    /// <summary>
    /// The vocabulary's own schema settles a transcription discrepancy in the requirement tables: requirement
    /// <c>PM64</c> names the type element of a related-event reference with the RELATED-OBJECT prefix while its
    /// sibling <c>PM65</c> names the value element with the related-event one. The schema declares
    /// <c>relatedEventIdentifierType</c> beside <c>relatedEventIdentifierValue</c>, which is the reading the
    /// binding took from the rest of the catalogue before the schema was found.
    /// </summary>
    [TestMethod]
    public async Task TheVocabularysOwnSchemaSettlesTheRelatedEventIdentifierDiscrepancy()
    {
        using PremisDocument document = await BuildDocumentAsync().ConfigureAwait(false);
        using PremisEncodeResult encoded = await EncodeAsync(document).ConfigureAwait(false);

        XElement root = XDocument.Parse(Encoding.UTF8.GetString(encoded.Document!.AsReadOnlySpan())).Root!;
        XElement relationship = root.Elements(Premis + "object").ElementAt(1).Element(Premis + "relationship")!;
        XElement relatedEvent = relationship.Element(Premis + "relatedEventIdentifier")!;

        Assert.AreSequenceEqual(
            new[] { Premis + "relatedEventIdentifierType", Premis + "relatedEventIdentifierValue" },
            NamesOf(relatedEvent.Elements()));

        XmlSchemaSet? schemas = EArkSchemaOracle.TryBuildAuthenticPremisSchemas();
        if(schemas is null)
        {
            Assert.Inconclusive(EArkSchemaOracle.MissingPremisSchemaMessage);

            return;
        }

        Assert.IsEmpty(
            EArkSchemaOracle.Validate(encoded.Document.AsReadOnlySpan(), schemas),
            "The spelling the binding chose is the one the vocabulary's own schema declares.");
    }


    /// <summary>
    /// An object states its category as a qualified name, so the same category written with a prefix, written
    /// without one under a default declaration of this vocabulary's namespace, and written with a prefix bound
    /// somewhere else are three different statements — and only the first two name this vocabulary's category.
    /// </summary>
    /// <param name="declaration">The namespace declarations the root element carries.</param>
    /// <param name="category">The value of the category attribute.</param>
    /// <param name="expected">The category the model carries afterwards.</param>
    [TestMethod]
    [DataRow("", "file", "file", DisplayName = "no prefix, under the default declaration of this vocabulary")]
    [DataRow(" xmlns:p=\"http://www.loc.gov/premis/v3\"", "p:file", "file", DisplayName = "a prefix bound to this vocabulary")]
    [DataRow(" xmlns:q=\"urn:test:other\"", "q:file", "q:file", DisplayName = "a prefix bound somewhere else, which names some other type")]
    public async Task AnObjectStatesItsCategoryAsAQualifiedName(string declaration, string category, string expected)
    {
        string document = string.Create(
            CultureInfo.InvariantCulture,
            $"""
             <premis xmlns="{PremisWellKnown.PremisNamespace}" xmlns:xsi="{PremisWellKnown.XmlSchemaInstanceNamespace}"{declaration} version="3.0">
               <object xsi:type="{category}">
                 <objectIdentifier><objectIdentifierType>local</objectIdentifierType><objectIdentifierValue>o-1</objectIdentifierValue></objectIdentifier>
               </object>
             </premis>
             """);

        using PremisParseResult result = await ParseTextAsync(document).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.FailureReason);
        Assert.AreEqual(expected, result.Document!.Objects[0].Category);
        Assert.AreEqual(expected == "file", PremisWellKnown.IsObjectCategory(result.Document.Objects[0].Category));
    }


    /// <summary>
    /// A document written to break the parse is refused with the status that names what was wrong, never with an
    /// exception and never with a document built around the defect.
    /// </summary>
    /// <param name="document">The document to parse.</param>
    /// <param name="expected">The status that refuses it.</param>
    [TestMethod]
    [DataRow("not xml at all", PremisParseStatus.Malformed, DisplayName = "octets that are not XML")]
    [DataRow("<premis xmlns=\"http://www.loc.gov/premis/v3\">", PremisParseStatus.Malformed, DisplayName = "a truncated document")]
    [DataRow("<other xmlns=\"http://www.loc.gov/premis/v3\"/>", PremisParseStatus.Malformed, DisplayName = "a root element that is not premis")]
    [DataRow("<premis xmlns=\"urn:test:other\" version=\"3.0\"/>", PremisParseStatus.Malformed, DisplayName = "the right local name in the wrong namespace")]
    [DataRow("<object xmlns=\"http://www.loc.gov/premis/v3\"/>", PremisParseStatus.Malformed, DisplayName = "a bare object, which the vocabulary admits as a root and this seam does not")]
    [DataRow("<!DOCTYPE premis [<!ENTITY x \"y\">]><premis xmlns=\"http://www.loc.gov/premis/v3\" version=\"3.0\"/>", PremisParseStatus.Malformed, DisplayName = "a document type definition, which entity expansion needs")]
    [DataRow("<premis xmlns=\"http://www.loc.gov/premis/v3\"/>", PremisParseStatus.MissingRequiredElement, DisplayName = "no @version, which requirement PM1 makes mandatory")]
    public async Task ADocumentWrittenToBreakTheParseIsRefusedWithTheStatusThatNamesIt(string document, PremisParseStatus expected)
    {
        using PremisParseResult result = await ParseTextAsync(document).ConfigureAwait(false);

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
            <!DOCTYPE premis [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
            <premis xmlns="http://www.loc.gov/premis/v3" version="&xxe;"/>
            """;

        using PremisParseResult result = await ParseTextAsync(External).ConfigureAwait(false);

        Assert.AreEqual(PremisParseStatus.Malformed, result.Status);
        Assert.IsNull(result.Document);
    }


    /// <summary>
    /// Every particle the catalogue makes mandatory is required by the parse too: a document missing one is
    /// refused rather than completed with a default.
    /// </summary>
    /// <param name="body">The <c>premis</c> element's content.</param>
    [TestMethod]
    [DataRow("<object><objectIdentifier><objectIdentifierType>local</objectIdentifierType><objectIdentifierValue>o-1</objectIdentifierValue></objectIdentifier></object>", DisplayName = "an object stating no category (PM2, PM14, PM28)")]
    [DataRow("<object xsi:type=\"file\"><objectIdentifier><objectIdentifierValue>o-1</objectIdentifierValue></objectIdentifier></object>", DisplayName = "an identifier stating no type")]
    [DataRow("<object xsi:type=\"file\"><objectIdentifier><objectIdentifierType>local</objectIdentifierType></objectIdentifier></object>", DisplayName = "an identifier stating no value")]
    [DataRow("<event><eventIdentifier><eventIdentifierType>local</eventIdentifierType><eventIdentifierValue>e-1</eventIdentifierValue></eventIdentifier><eventDateTime>2026-07-31</eventDateTime></event>", DisplayName = "an event stating no type (PM84)")]
    [DataRow("<event><eventIdentifier><eventIdentifierType>local</eventIdentifierType><eventIdentifierValue>e-1</eventIdentifierValue></eventIdentifier><eventType>migration</eventType></event>", DisplayName = "an event stating no instant (PM85)")]
    [DataRow("<agent><agentIdentifier><agentIdentifierType>local</agentIdentifierType><agentIdentifierValue>a-1</agentIdentifierValue></agentIdentifier><agentType>software</agentType></agent>", DisplayName = "an agent stating no name (PM73)")]
    [DataRow("<agent><agentIdentifier><agentIdentifierType>local</agentIdentifierType><agentIdentifierValue>a-1</agentIdentifierValue></agentIdentifier><agentName>n</agentName></agent>", DisplayName = "an agent stating no type (PM74)")]
    [DataRow("<rights><rightsStatement><rightsStatementIdentifier><rightsStatementIdentifierType>local</rightsStatementIdentifierType><rightsStatementIdentifierValue>r-1</rightsStatementIdentifierValue></rightsStatementIdentifier></rightsStatement></rights>", DisplayName = "a rights statement stating no basis (PM98)")]
    [DataRow("<object xsi:type=\"file\"><objectIdentifier><objectIdentifierType>local</objectIdentifierType><objectIdentifierValue>o-1</objectIdentifierValue></objectIdentifier><relationship><relationshipType>structural</relationshipType></relationship></object>", DisplayName = "a relationship stating no subtype (PM23, PM59)")]
    [DataRow("<object xsi:type=\"file\"><objectIdentifier><objectIdentifierType>local</objectIdentifierType><objectIdentifierValue>o-1</objectIdentifierValue></objectIdentifier><storage><contentLocation><contentLocationType>t</contentLocationType></contentLocation></storage></object>", DisplayName = "a content location stating no value (PM55)")]
    [DataRow("<object xsi:type=\"intellectualEntity\"><objectIdentifier><objectIdentifierType>local</objectIdentifierType><objectIdentifierValue>o-1</objectIdentifierValue></objectIdentifier><environmentDesignation><environmentVersion>1</environmentVersion></environmentDesignation></object>", DisplayName = "an environment designation stating no name (PM10)")]
    public async Task EveryParticleTheCatalogueMakesMandatoryIsRequiredByTheParseToo(string body)
    {
        using PremisParseResult result = await ParseBodyAsync(body).ConfigureAwait(false);

        Assert.AreEqual(PremisParseStatus.MissingRequiredElement, result.Status);
        Assert.IsNull(result.Document);
    }


    /// <summary>
    /// A fixity this library cannot recompute is carried through the parse with its reason rather than refusing
    /// the document, the same asymmetry the package manifest's own fixity attributes are read under.
    /// </summary>
    [TestMethod]
    public async Task AFixityThisLibraryCannotRecomputeIsCarriedThroughTheParse()
    {
        const string WeakFixity = """
            <object xsi:type="file">
              <objectIdentifier><objectIdentifierType>local</objectIdentifierType><objectIdentifierValue>o-1</objectIdentifierValue></objectIdentifier>
              <objectCharacteristics>
                <fixity><messageDigestAlgorithm>MD5</messageDigestAlgorithm><messageDigest>d41d8cd98f00b204e9800998ecf8427e</messageDigest></fixity>
                <fixity><messageDigestAlgorithm>SHA-256</messageDigestAlgorithm><messageDigest>e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855</messageDigest></fixity>
              </objectCharacteristics>
            </object>
            """;

        using PremisParseResult result = await ParseBodyAsync(WeakFixity).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.FailureReason);

        IReadOnlyList<EArkFixity> fixities = result.Document!.Objects[0].Characteristics[0].Fixities;
        Assert.AreSequenceEqual(
            new[] { EArkFixityStatus.WeakCryptographicAlgorithm, EArkFixityStatus.Recomputable },
            StatusesOf(fixities),
            "Two fixities over one file, one of which this library can recompute and one of which it carries as text.");
    }


    /// <summary>
    /// Every bound the limits state is a refusal rather than a resource the document may spend.
    /// </summary>
    [TestMethod]
    public async Task EveryBoundTheLimitsStateIsARefusal()
    {
        using PremisDocument document = await BuildDocumentAsync().ConfigureAwait(false);
        using PremisEncodeResult encoded = await EncodeAsync(document).ConfigureAwait(false);

        foreach(PremisParseLimits limits in new[]
        {
            new PremisParseLimits { MaximumDocumentByteLength = 64 },
            new PremisParseLimits { MaximumObjects = 0 },
            new PremisParseLimits { MaximumEvents = 0 },
            new PremisParseLimits { MaximumAgents = 0 },
            new PremisParseLimits { MaximumRightsStatements = 0 },
            new PremisParseLimits { MaximumChildElements = 0 },
            new PremisParseLimits { MaximumTextLength = 4 }
        })
        {
            using PremisParseResult result = await PremisXmlBinding.ParseAsync(
                new PremisParseContext { Document = encoded.Document!, Limits = limits },
                BaseMemoryPool.Shared,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(PremisParseStatus.LimitExceeded, result.Status);
            Assert.IsNull(result.Document);
        }
    }


    /// <summary>
    /// A document nesting deeper than the bound is refused by a counter rather than by an exhausted call stack:
    /// the vocabulary's own particles sit at a fixed depth, so anything deeper is a document written to exhaust a
    /// reader rather than to say something.
    /// </summary>
    [TestMethod]
    public async Task ADocumentNestingBeyondTheBoundIsRefusedByACounter()
    {
        const int Depth = 20_000;
        var deep = new StringBuilder();
        for(int i = 0; i < Depth; ++i)
        {
            _ = deep.Append("<n>");
        }

        for(int i = 0; i < Depth; ++i)
        {
            _ = deep.Append("</n>");
        }

        using PremisParseResult result = await ParseBodyAsync(deep.ToString()).ConfigureAwait(false);

        Assert.AreEqual(PremisParseStatus.LimitExceeded, result.Status);
        Assert.IsNull(result.Document);
    }


    /// <summary>
    /// A model that cannot become a conformant document is refused by the encoding with the status that names
    /// what was wrong: an entity nothing can name, and a fixity this library cannot recompute.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Each document the loop builds is held by a using declaration scoped to one iteration, which disposes it before the next begins.")]
    public async Task AModelThatCannotBecomeAConformantDocumentIsRefusedByTheEncoding()
    {
        foreach(PremisEncodeStatus expected in EncodeRefusals)
        {
            using PremisDocument document = await BuildDocumentAsync(
                unidentifiedObject: expected == PremisEncodeStatus.MissingIdentifier,
                weakFileFixity: expected == PremisEncodeStatus.UnrecomputableFixity).ConfigureAwait(false);

            using PremisEncodeResult result = await EncodeAsync(document).ConfigureAwait(false);

            Assert.AreEqual(expected, result.Status);
            Assert.IsNull(result.Document);
        }
    }


    /// <summary>
    /// The documented departure writes a fixity this library cannot recompute through as the text it was read as,
    /// which has exactly one honest use: writing back a document whose fixity somebody else asserted.
    /// </summary>
    [TestMethod]
    public async Task TheDocumentedDepartureWritesAnUnrecomputableFixityThrough()
    {
        using PremisDocument document = await BuildDocumentAsync(weakFileFixity: true).ConfigureAwait(false);
        using PremisEncodeResult encoded = await PremisXmlBinding.EncodeAsync(
            new PremisEncodeContext { Document = document, AllowUnrecomputableFixity = true },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(encoded.IsEncoded, encoded.FailureReason);

        using PremisParseResult parsed = await ParseAsync(encoded.Document!).ConfigureAwait(false);

        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);

        EArkFixity fixity = parsed.Document!.Objects[2].Characteristics[0].Fixities[0];
        var stated = Assert.IsInstanceOfType<EArkStatedFixity>(fixity);
        Assert.AreEqual(MetsWellKnown.Md5ChecksumType, stated.ChecksumType);
    }


    /// <summary>
    /// A value from one of the externally hosted vocabularies is carried as stated and never mapped onto a closed
    /// set, because those vocabularies are open and a term added to one after this library was written is still
    /// conformant.
    /// </summary>
    [TestMethod]
    public async Task AValueFromAnOpenVocabularyIsCarriedAsStated()
    {
        const string ForeignTerms = """
            <event>
              <eventIdentifier><eventIdentifierType>a-locally-defined-scheme</eventIdentifierType><eventIdentifierValue>e-1</eventIdentifierValue></eventIdentifier>
              <eventType>a term nobody had thought of yet</eventType>
              <eventDateTime>2026-07/2026-08</eventDateTime>
              <eventOutcomeInformation><eventOutcome>a locally defined outcome</eventOutcome></eventOutcomeInformation>
            </event>
            """;

        using PremisParseResult result = await ParseBodyAsync(ForeignTerms).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, result.FailureReason);

        PremisEvent read = result.Document!.Events[0];
        Assert.AreEqual("a term nobody had thought of yet", read.Type);
        Assert.AreEqual("2026-07/2026-08", read.EventDateTime,
            "The instant is an extended date/time value admitting intervals, which no single instant can hold.");
        Assert.AreEqual("a locally defined outcome", read.Outcome);
        Assert.IsFalse(PremisWellKnown.IsLocalIdentifierType(read.Identifiers[0].Type));
    }


    /// <summary>
    /// Builds the fixture document: one object of each of the three categories the catalogue constrains, the
    /// preservation event that links them, the agent that carried it out, and one rights statement.
    /// </summary>
    /// <param name="unidentifiedObject">Whether the file object states no identifier.</param>
    /// <param name="weakFileFixity">Whether the file object states a fixity this library cannot recompute.</param>
    /// <returns>The document. The caller owns and disposes it.</returns>
    /// <remarks>
    /// Each object carries only what the vocabulary's own schema admits for its category, which is what
    /// <see cref="TheProducedDocumentValidatesAgainstTheAuthenticSchema"/> checks: the intellectual entity carries
    /// the environment particles, the representation carries storage, and the file carries the characteristics
    /// that schema makes mandatory for it.
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every fixity built here transfers to the returned document, which the caller disposes.")]
    private static async Task<PremisDocument> BuildDocumentAsync(bool unidentifiedObject = false, bool weakFileFixity = false)
    {
        EArkFixity first = weakFileFixity
            ? new EArkStatedFixity(MetsWellKnown.Md5ChecksumType, "d41d8cd98f00b204e9800998ecf8427e", EArkFixityStatus.WeakCryptographicAlgorithm)
            : await FixityAsync("the file"u8.ToArray()).ConfigureAwait(false);

        return new PremisDocument
        {
            Version = PremisWellKnown.PremisVersion,
            Objects =
            [
                new PremisObject
                {
                    Category = PremisWellKnown.IntellectualEntityObjectCategory,
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "intellectual-entity-1")],
                    SignificantProperties = [new PremisSignificantProperty("content", "the record's text")],
                    EnvironmentFunctions = [new PremisEnvironmentFunction("render", "1")],
                    EnvironmentDesignation = new PremisEnvironmentDesignation("the rendering environment", "2.0", "the supplier", "a note")
                },
                new PremisObject
                {
                    Category = PremisWellKnown.RepresentationObjectCategory,
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "representation-1")],
                    Storage = [new PremisStorage(new PremisContentLocation("URI", "representations/rep1"), "magnetic tape")],
                    Relationships =
                    [
                        new PremisRelationship
                        {
                            Type = "structural",
                            SubType = "isIncludedIn",
                            RelatedObjectIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "intellectual-entity-1")],
                            RelatedEventIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "event-1")]
                        }
                    ]
                },
                new PremisObject
                {
                    Category = PremisWellKnown.FileObjectCategory,
                    Identifiers = unidentifiedObject ? [] : [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "file-1")],
                    Characteristics =
                    [
                        new PremisObjectCharacteristics
                        {
                            Fixities =
                            [
                                first,
                                await FixityAsync("the file"u8.ToArray(), PkiDigestAlgorithm.Sha512).ConfigureAwait(false)
                            ],
                            Format = new PremisFormat(
                                new PremisFormatDesignation("XML", "1.0"),
                                new PremisFormatRegistry("a format registry", "fmt/101", "specification")),
                            CreatingApplications = [new PremisCreatingApplication("the creating tool", "1.0.0", "2026-07-30")]
                        }
                    ],
                    OriginalName = "the original file name",
                    Storage = [new PremisStorage(new PremisContentLocation("URI", "representations/rep1/data/record.xml"), "magnetic tape")],
                    RightsStatementIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "rights-statement-1")]
                }
            ],
            Events =
            [
                new PremisEvent
                {
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "event-1")],
                    Type = "migration",
                    EventDateTime = EventInstant,
                    Outcome = "success",
                    LinkingAgentIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "agent-1")],
                    LinkingObjectIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "file-1")]
                }
            ],
            Agents =
            [
                new PremisAgent
                {
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "agent-1")],
                    Name = "the migrating tool",
                    Type = "software",
                    Version = "1.0.0",
                    Note = "the note"
                }
            ],
            RightsStatements =
            [
                new PremisRightsStatement
                {
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "rights-statement-1")],
                    Basis = PremisWellKnown.CopyrightRightsBasis,
                    CopyrightInformation = new PremisCopyrightInformation
                    {
                        Status = "copyrighted",
                        Jurisdiction = "FI",
                        DocumentationIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "documentation-1")]
                    },
                    RightsGranted = new PremisRightsGranted
                    {
                        Acts = ["disseminate"],
                        TermOfGrant = new PremisTermOfGrant("2026-07-31", null),
                        Note = "a risk assessment"
                    }
                }
            ]
        };
    }


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


    /// <summary>
    /// Parses a document assembled from the content of a conformant root element.
    /// </summary>
    /// <param name="body">The <c>premis</c> element's content.</param>
    /// <returns>The parse result. The caller owns and disposes it.</returns>
    private Task<PremisParseResult> ParseBodyAsync(string body) =>
        ParseTextAsync(string.Create(
            CultureInfo.InvariantCulture,
            $"""<premis xmlns="{PremisWellKnown.PremisNamespace}" xmlns:xsi="{PremisWellKnown.XmlSchemaInstanceNamespace}" version="3.0">{body}</premis>"""));


    /// <summary>
    /// Parses a document from its text.
    /// </summary>
    /// <param name="document">The document.</param>
    /// <returns>The parse result. The caller owns and disposes it.</returns>
    private async Task<PremisParseResult> ParseTextAsync(string document)
    {
        using PooledMemory octets = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, EArkTags.PremisDocument);

        return await ParseAsync(octets).ConfigureAwait(false);
    }


    /// <summary>Encodes a document through the staged binding under the secure default fixity policy.</summary>
    /// <param name="document">The document to write.</param>
    /// <returns>The encoding result. The caller owns and disposes it.</returns>
    private ValueTask<PremisEncodeResult> EncodeAsync(PremisDocument document) =>
        PremisXmlBinding.EncodeAsync(new PremisEncodeContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken);


    /// <summary>Parses a document through the staged binding under the conformant limits.</summary>
    /// <param name="document">The document's octets.</param>
    /// <returns>The parse result. The caller owns and disposes it.</returns>
    private ValueTask<PremisParseResult> ParseAsync(PooledMemory document) =>
        PremisXmlBinding.ParseAsync(new PremisParseContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken);


    /// <summary>
    /// States the classifications of a fixity list, so an assertion about them reads as the ruling it is about.
    /// </summary>
    /// <param name="fixities">The fixities.</param>
    /// <returns>Each fixity's classification.</returns>
    private static List<EArkFixityStatus> StatusesOf(IReadOnlyList<EArkFixity> fixities)
    {
        List<EArkFixityStatus> statuses = [];
        foreach(EArkFixity fixity in fixities)
        {
            statuses.Add(fixity.Status);
        }

        return statuses;
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
