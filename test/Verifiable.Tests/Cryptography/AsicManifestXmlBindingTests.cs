using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Text;
using System.Threading.Tasks;
using System.Xml.Linq;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.Cryptography.Pki.Xml;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Cryptography;

/// <summary>
/// Conformance tests for the <c>ASiCManifest</c> serialisation seams — the shipped model and delegate shapes of
/// <see cref="AsicManifest"/>/<see cref="ParseAsicManifestDelegate"/>/<see cref="EncodeAsicManifestDelegate"/>,
/// exercised through the staged worked binding <see cref="AsicManifestXmlBinding"/> — against Annex A.4 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// The strongest leg is <see cref="TheProducedDocumentValidatesAgainstTheAuthenticSchema"/>: what this library
/// writes is checked against the schema attachment Annex A.3 makes normative, identified by the SHA-256 that
/// annex states rather than by where a file happens to sit. Locating and applying that schema is
/// <see cref="AsicManifestSchemaOracle"/>'s, so this class and the container-creation tests validate against
/// one schema set rather than against two copies of one. Everything else here is either the round trip through
/// the model or a document written to break the parse.
/// </para>
/// <para>
/// Every digest here is computed through the registered digest seam, and every carrier is rented from the
/// house pool and disposed.
/// </para>
/// </remarks>
[TestClass]
internal sealed class AsicManifestXmlBindingTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>The schema namespace Annex A.3 declares as its target.</summary>
    private static XNamespace Asic { get; } = "http://uri.etsi.org/02918/v1.2.1#";

    /// <summary>The XML Signature core namespace the ASiC schema imports.</summary>
    private static XNamespace DigitalSignature { get; } = XmlSignatureWellKnown.XmlSignatureNamespace;


    /// <summary>
    /// A manifest written and read again is the manifest that was written: every attribute the schema admits
    /// survives, including the two optional ones and the absent-versus-false distinction on <c>Rootfile</c>.
    /// </summary>
    [TestMethod]
    public async Task AManifestRoundTripsThroughTheModel()
    {
        using AsicManifest original = await BuildManifestAsync().ConfigureAwait(false);
        using AsicManifestEncodeResult encoded = await AsicManifestXmlBinding.EncodeAsync(
            new AsicManifestEncodeContext { Manifest = original }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(encoded.IsEncoded, encoded.FailureReason);

        using AsicManifestParseResult parsed = await AsicManifestXmlBinding.ParseAsync(
            new AsicManifestParseContext { Document = encoded.Document! }, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);

        AsicManifest read = parsed.Manifest!;
        Assert.AreEqual(original.SignatureReference.Uri, read.SignatureReference.Uri);
        Assert.AreEqual(original.SignatureReference.MimeType, read.SignatureReference.MimeType);
        Assert.HasCount(original.DataObjectReferences.Count, read.DataObjectReferences);

        for(int i = 0; i < original.DataObjectReferences.Count; ++i)
        {
            AsicDataObjectReference expected = original.DataObjectReferences[i];
            AsicDataObjectReference actual = read.DataObjectReferences[i];

            Assert.AreEqual(expected.Uri, actual.Uri);
            Assert.AreEqual(expected.MimeType, actual.MimeType);
            Assert.AreEqual(expected.IsRootFile, actual.IsRootFile);
            Assert.AreEqual(expected.DigestAlgorithm, actual.DigestAlgorithm);
            Assert.AreSequenceEqual(expected.Digest.AsReadOnlySpan().ToArray(), actual.Digest.AsReadOnlySpan().ToArray());
        }
    }


    /// <summary>
    /// Writing the manifest that was read produces the same octets, which is what lets a caller hold a model
    /// of a manifest a signature already commits to without having to keep the octets beside it for every
    /// purpose.
    /// </summary>
    [TestMethod]
    public async Task WritingTheManifestThatWasReadProducesTheSameOctets()
    {
        using AsicManifest original = await BuildManifestAsync().ConfigureAwait(false);
        using AsicManifestEncodeResult first = await EncodeAsync(original).ConfigureAwait(false);
        using AsicManifestParseResult parsed = await ParseAsync(first.Document!).ConfigureAwait(false);

        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);

        using AsicManifestEncodeResult second = await EncodeAsync(parsed.Manifest!).ConfigureAwait(false);

        Assert.IsTrue(second.IsEncoded, second.FailureReason);
        Assert.AreSequenceEqual(first.Document!.AsReadOnlySpan().ToArray(), second.Document!.AsReadOnlySpan().ToArray());
    }


    /// <summary>
    /// The produced document validates against the schema the Annex A.3 attachment carries, identified by the
    /// SHA-256 that annex states — so what this library writes is checked against the specification's own
    /// grammar rather than against this library's reading of it.
    /// </summary>
    [TestMethod]
    public async Task TheProducedDocumentValidatesAgainstTheAuthenticSchema()
    {
        string? schemaPath = await AsicManifestSchemaOracle.TryFindAuthenticSchemaAsync().ConfigureAwait(false);
        if(schemaPath is null)
        {
            Assert.Inconclusive(AsicManifestSchemaOracle.MissingSchemaMessage);

            return;
        }

        using AsicManifest manifest = await BuildManifestAsync(withExtensions: true).ConfigureAwait(false);
        using AsicManifestEncodeResult encoded = await EncodeAsync(manifest).ConfigureAwait(false);

        Assert.IsTrue(encoded.IsEncoded, encoded.FailureReason);

        List<string> problems = AsicManifestSchemaOracle.Validate(encoded.Document!.AsReadOnlySpan(), schemaPath);

        Assert.IsEmpty(problems, string.Join(Environment.NewLine, problems));
    }


    /// <summary>
    /// The schema validation refuses a document the grammar does not admit, which is what makes
    /// <see cref="TheProducedDocumentValidatesAgainstTheAuthenticSchema"/> a statement about the document
    /// rather than about a validator that accepts anything: the particles here are all legal ones, put in the
    /// order Annex A.4.2's sequence forbids.
    /// </summary>
    [TestMethod]
    public async Task TheSchemaValidationRefusesADocumentTheGrammarDoesNotAdmit()
    {
        string? schemaPath = await AsicManifestSchemaOracle.TryFindAuthenticSchemaAsync().ConfigureAwait(false);
        if(schemaPath is null)
        {
            Assert.Inconclusive(AsicManifestSchemaOracle.MissingSchemaMessage);

            return;
        }

        const string OutOfOrder = """
            <ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <DataObjectReference URI="file1.txt">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</ds:DigestValue>
              </DataObjectReference>
              <SigReference URI="META-INF/signature1.p7s"/>
            </ASiCManifest>
            """;

        List<string> problems = AsicManifestSchemaOracle.Validate(Encoding.UTF8.GetBytes(OutOfOrder), schemaPath);

        Assert.IsNotEmpty(problems, "A document whose particles are in an order the sequence forbids is not schema-valid.");
    }


    /// <summary>
    /// The produced document carries the elements Annex A.4.2's sequence states, in that order: one
    /// <c>SigReference</c>, then every <c>DataObjectReference</c> with its <c>ds:DigestMethod</c> before its
    /// <c>ds:DigestValue</c>, then the extensions list.
    /// </summary>
    [TestMethod]
    public async Task TheProducedDocumentCarriesTheElementsAnnexA42StatesInOrder()
    {
        using AsicManifest manifest = await BuildManifestAsync(withExtensions: true).ConfigureAwait(false);
        using AsicManifestEncodeResult encoded = await EncodeAsync(manifest).ConfigureAwait(false);

        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(encoded.Document!.AsReadOnlySpan()));
        XElement root = document.Root!;

        Assert.AreEqual(Asic + "ASiCManifest", root.Name);

        var childNames = new List<XName>();
        foreach(XElement child in root.Elements())
        {
            childNames.Add(child.Name);
        }

        Assert.AreSequenceEqual(
            new[] { Asic + "SigReference", Asic + "DataObjectReference", Asic + "DataObjectReference", Asic + "ASiCManifestExtensions" },
            childNames);

        XElement first = root.Element(Asic + "DataObjectReference")!;
        var referenceChildren = new List<XName>();
        foreach(XElement child in first.Elements())
        {
            referenceChildren.Add(child.Name);
        }

        Assert.AreSequenceEqual(
            new[] { DigitalSignature + "DigestMethod", DigitalSignature + "DigestValue" },
            referenceChildren);
    }


    /// <summary>
    /// An extension survives the round trip octet for octet, including the one that carries nothing but text,
    /// because the model carries the element as it was found rather than a reading of it.
    /// </summary>
    [TestMethod]
    public async Task AnExtensionRoundTripsOctetForOctet()
    {
        using AsicManifest original = await BuildManifestAsync(withExtensions: true).ConfigureAwait(false);
        using AsicManifestEncodeResult encoded = await EncodeAsync(original).ConfigureAwait(false);
        using AsicManifestParseResult parsed = await ParseAsync(encoded.Document!).ConfigureAwait(false);

        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);
        Assert.HasCount(original.Extensions.Count, parsed.Manifest!.Extensions);

        for(int i = 0; i < original.Extensions.Count; ++i)
        {
            AsicManifestExtension expected = original.Extensions[i];
            AsicManifestExtension actual = parsed.Manifest!.Extensions[i];

            Assert.AreEqual(expected.Critical, actual.Critical);
            Assert.AreEqual(expected.ElementName, actual.ElementName);
            Assert.AreEqual(expected.ElementNamespace, actual.ElementNamespace);
            Assert.AreSequenceEqual(expected.Content.AsReadOnlySpan().ToArray(), actual.Content.AsReadOnlySpan().ToArray());
        }
    }


    /// <summary>
    /// An unrecognised extension marked critical fails closed, which is this library's answer to an attribute
    /// Annex A.4.2 declares required and never gives a consumer obligation for; a recognised one is accepted,
    /// an unrecognised non-critical one is accepted, and the departure is a knob a caller has to state.
    /// </summary>
    [TestMethod]
    public async Task AnUnrecognisedCriticalExtensionFailsClosed()
    {
        using AsicManifest manifest = await BuildManifestAsync(withExtensions: true).ConfigureAwait(false);

        AsicManifestExtensionEvaluation strict = AsicManifestExtensionPolicy.Strict.Evaluate(manifest);
        Assert.AreEqual(AsicManifestExtensionStatus.UnrecognizedCriticalExtension, strict.Status);
        Assert.AreEqual(new AsicManifestExtensionName("urn:test:asic-extension", "Retention"), strict.RejectedExtension);

        var recognising = new AsicManifestExtensionPolicy
        {
            RecognizedExtensions = [new AsicManifestExtensionName("urn:test:asic-extension", "Retention")]
        };
        Assert.IsTrue(recognising.Evaluate(manifest).IsAccepted, "A critical extension the caller recognises is not a reason to stop.");

        var permissive = new AsicManifestExtensionPolicy { AcceptUnrecognizedCriticalExtensions = true };
        Assert.IsTrue(permissive.Evaluate(manifest).IsAccepted, "The documented departure accepts what the default refuses.");
    }


    /// <summary>
    /// A non-critical extension is never a reason to stop, whether the caller recognises it or not — that is
    /// what the attribute's other value means.
    /// </summary>
    [TestMethod]
    public void ANonCriticalExtensionIsNeverAReasonToStop()
    {
        //Ownership of the octets transfers to the extension, which the using disposes.
        using var extension = new AsicManifestExtension
        {
            Critical = false,
            ElementNamespace = "urn:test:asic-extension",
            ElementName = "Note",
            Content = PooledMemory.FromBytes(
                Encoding.UTF8.GetBytes("""<Extension xmlns="http://uri.etsi.org/02918/v1.2.1#" Critical="false"><Note xmlns="urn:test:asic-extension">informative</Note></Extension>"""),
                BaseMemoryPool.Shared,
                AsicTags.ManifestExtension)
        };

        Assert.IsTrue(AsicManifestExtensionPolicy.Strict.Evaluate([extension]).IsAccepted);
    }


    /// <summary>
    /// A document written to break the parse is refused with the status that names what was wrong, never with
    /// an exception and never with a manifest built around the defect.
    /// </summary>
    /// <param name="document">The document to parse.</param>
    /// <param name="expected">The status that refuses it.</param>
    [TestMethod]
    [DataRow("not xml at all", AsicManifestParseStatus.Malformed, DisplayName = "octets that are not XML")]
    [DataRow("<ASiCManifest xmlns=\"http://uri.etsi.org/02918/v1.2.1#\">", AsicManifestParseStatus.Malformed, DisplayName = "a truncated document")]
    [DataRow("<Other xmlns=\"http://uri.etsi.org/02918/v1.2.1#\"/>", AsicManifestParseStatus.Malformed, DisplayName = "a root element that is not ASiCManifest")]
    [DataRow("<ASiCManifest xmlns=\"urn:test:other\"/>", AsicManifestParseStatus.Malformed, DisplayName = "the right local name in the wrong namespace")]
    [DataRow("<!DOCTYPE ASiCManifest [<!ENTITY x \"y\">]><ASiCManifest xmlns=\"http://uri.etsi.org/02918/v1.2.1#\"/>", AsicManifestParseStatus.Malformed, DisplayName = "a document type definition, which entity expansion needs")]
    public async Task ADocumentWrittenToBreakTheParseIsRefusedWithTheStatusThatNamesIt(string document, AsicManifestParseStatus expected)
    {
        using PooledMemory octets = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, AsicTags.Manifest);
        using AsicManifestParseResult result = await ParseAsync(octets).ConfigureAwait(false);

        Assert.AreEqual(expected, result.Status);
        Assert.IsNull(result.Manifest);
        Assert.IsNotNull(result.FailureReason);
    }


    /// <summary>
    /// Every particle Annex A.4.2 requires is required by the parse too: a manifest missing one is refused
    /// rather than completed with a default.
    /// </summary>
    /// <param name="body">The content of the <c>ASiCManifest</c> element.</param>
    /// <param name="expected">The status that refuses it.</param>
    [TestMethod]
    [DataRow("", AsicManifestParseStatus.MissingRequiredElement, DisplayName = "no SigReference element")]
    [DataRow("<SigReference/>", AsicManifestParseStatus.MissingRequiredElement, DisplayName = "a SigReference with no URI attribute")]
    [DataRow("<SigReference URI=\"META-INF/signature1.p7s\"/>", AsicManifestParseStatus.MissingRequiredElement, DisplayName = "no DataObjectReference element")]
    public async Task EveryRequiredParticleIsRequiredByTheParseToo(string body, AsicManifestParseStatus expected)
    {
        using PooledMemory octets = PooledMemory.FromBytes(
            Encoding.UTF8.GetBytes($"<ASiCManifest xmlns=\"http://uri.etsi.org/02918/v1.2.1#\">{body}</ASiCManifest>"),
            BaseMemoryPool.Shared,
            AsicTags.Manifest);

        using AsicManifestParseResult result = await ParseAsync(octets).ConfigureAwait(false);

        Assert.AreEqual(expected, result.Status);
        Assert.IsNull(result.Manifest);
    }


    /// <summary>
    /// A <c>DataObjectReference</c> written to break the parse is refused with its own status: an algorithm
    /// this library will not compute, a digest that is not base64, a digest of the wrong length for the
    /// algorithm it is stated under, a reference naming something outside the container, and a missing child.
    /// </summary>
    /// <param name="algorithmUri">The <c>ds:DigestMethod</c> algorithm.</param>
    /// <param name="digestValue">The <c>ds:DigestValue</c> content.</param>
    /// <param name="uri">The <c>URI</c> attribute.</param>
    /// <param name="expected">The status that refuses it.</param>
    [TestMethod]
    [DataRow("http://www.w3.org/2000/09/xmldsig#sha1", "2jmj7l5rSw0yVb/vlWAYkK/YBwk=", "file1.txt", AsicManifestParseStatus.UnsupportedDigestAlgorithm, DisplayName = "SHA-1, which this library will not compute")]
    [DataRow("http://www.w3.org/2001/04/xmldsig-more#md5", "1B2M2Y8AsgTpgAmY7PhCfg==", "file1.txt", AsicManifestParseStatus.UnsupportedDigestAlgorithm, DisplayName = "MD5, refused unconditionally")]
    [DataRow("http://example.test/hash", "AAAA", "file1.txt", AsicManifestParseStatus.UnsupportedDigestAlgorithm, DisplayName = "an algorithm nobody registered")]
    [DataRow("http://www.w3.org/2001/04/xmlenc#sha256", "not base64!!", "file1.txt", AsicManifestParseStatus.DigestValueMalformed, DisplayName = "a digest that is not base64")]
    [DataRow("http://www.w3.org/2001/04/xmlenc#sha256", "AAAA", "file1.txt", AsicManifestParseStatus.DigestValueMalformed, DisplayName = "a digest too short for the algorithm it is stated under")]
    [DataRow("http://www.w3.org/2001/04/xmlenc#sha256", "", "file1.txt", AsicManifestParseStatus.DigestValueMalformed, DisplayName = "an empty digest")]
    [DataRow("http://www.w3.org/2001/04/xmlenc#sha256", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "../outside.txt", AsicManifestParseStatus.InvalidUriReference, DisplayName = "a reference climbing out of the container")]
    [DataRow("http://www.w3.org/2001/04/xmlenc#sha256", "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", "http://example.test/x", AsicManifestParseStatus.InvalidUriReference, DisplayName = "a reference naming a network location")]
    public async Task ADataObjectReferenceWrittenToBreakTheParseIsRefusedWithItsOwnStatus(
        string algorithmUri,
        string digestValue,
        string uri,
        AsicManifestParseStatus expected)
    {
        string document = string.Create(
            CultureInfo.InvariantCulture,
            $"""
             <ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
               <SigReference URI="META-INF/signature1.p7s"/>
               <DataObjectReference URI="{uri}">
                 <ds:DigestMethod Algorithm="{algorithmUri}"/>
                 <ds:DigestValue>{digestValue}</ds:DigestValue>
               </DataObjectReference>
             </ASiCManifest>
             """);

        using PooledMemory octets = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, AsicTags.Manifest);
        using AsicManifestParseResult result = await ParseAsync(octets).ConfigureAwait(false);

        Assert.AreEqual(expected, result.Status);
        Assert.IsNull(result.Manifest);
    }


    /// <summary>
    /// A <c>ds:DigestMethod</c> or <c>ds:DigestValue</c> the schema requires is required by the parse too.
    /// </summary>
    [TestMethod]
    public async Task ADataObjectReferenceMissingItsDigestIsRefused()
    {
        const string WithoutMethod = """
            <ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <SigReference URI="META-INF/signature1.p7s"/>
              <DataObjectReference URI="file1.txt"><ds:DigestValue>47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</ds:DigestValue></DataObjectReference>
            </ASiCManifest>
            """;

        const string WithoutValue = """
            <ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <SigReference URI="META-INF/signature1.p7s"/>
              <DataObjectReference URI="file1.txt"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></DataObjectReference>
            </ASiCManifest>
            """;

        foreach(string document in new[] { WithoutMethod, WithoutValue })
        {
            using PooledMemory octets = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, AsicTags.Manifest);
            using AsicManifestParseResult result = await ParseAsync(octets).ConfigureAwait(false);

            Assert.AreEqual(AsicManifestParseStatus.MissingRequiredElement, result.Status);
        }
    }


    /// <summary>
    /// An <c>Extension</c> without the <c>Critical</c> attribute Annex A.4.2 declares required is refused,
    /// because an extension whose criticality is unstated is one no policy can weigh.
    /// </summary>
    [TestMethod]
    public async Task AnExtensionWithoutItsCriticalAttributeIsRefused()
    {
        const string Document = """
            <ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <SigReference URI="META-INF/signature1.p7s"/>
              <DataObjectReference URI="file1.txt">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</ds:DigestValue>
              </DataObjectReference>
              <ASiCManifestExtensions><Extension><Anything/></Extension></ASiCManifestExtensions>
            </ASiCManifest>
            """;

        using PooledMemory octets = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(Document), BaseMemoryPool.Shared, AsicTags.Manifest);
        using AsicManifestParseResult result = await ParseAsync(octets).ConfigureAwait(false);

        Assert.AreEqual(AsicManifestParseStatus.MissingRequiredElement, result.Status);
    }


    /// <summary>
    /// Every bound the limits state is a refusal rather than a resource the document may spend: an oversized
    /// document, more references than admitted, and an extension nesting deeper than admitted.
    /// </summary>
    [TestMethod]
    public async Task EveryBoundTheLimitsStateIsARefusal()
    {
        using AsicManifest manifest = await BuildManifestAsync().ConfigureAwait(false);
        using AsicManifestEncodeResult encoded = await EncodeAsync(manifest).ConfigureAwait(false);

        using AsicManifestParseResult oversized = await AsicManifestXmlBinding.ParseAsync(
            new AsicManifestParseContext
            {
                Document = encoded.Document!,
                Limits = new AsicManifestParseLimits { MaximumDocumentByteLength = 16 }
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AsicManifestParseStatus.LimitExceeded, oversized.Status);

        using AsicManifestParseResult tooManyReferences = await AsicManifestXmlBinding.ParseAsync(
            new AsicManifestParseContext
            {
                Document = encoded.Document!,
                Limits = new AsicManifestParseLimits { MaximumDataObjectReferences = 1 }
            },
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AsicManifestParseStatus.LimitExceeded, tooManyReferences.Status);

        var deep = new StringBuilder();
        _ = deep.Append("""
            <ASiCManifest xmlns="http://uri.etsi.org/02918/v1.2.1#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <SigReference URI="META-INF/signature1.p7s"/>
              <DataObjectReference URI="file1.txt">
                <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ds:DigestValue>47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=</ds:DigestValue>
              </DataObjectReference>
              <ASiCManifestExtensions><Extension Critical="false">
            """);

        const int Depth = 256;
        for(int i = 0; i < Depth; ++i)
        {
            _ = deep.Append("<n>");
        }

        for(int i = 0; i < Depth; ++i)
        {
            _ = deep.Append("</n>");
        }

        _ = deep.Append("</Extension></ASiCManifestExtensions></ASiCManifest>");

        using PooledMemory deepOctets = PooledMemory.FromBytes(Encoding.UTF8.GetBytes(deep.ToString()), BaseMemoryPool.Shared, AsicTags.Manifest);
        using AsicManifestParseResult tooDeep = await ParseAsync(deepOctets).ConfigureAwait(false);
        Assert.AreEqual(AsicManifestParseStatus.LimitExceeded, tooDeep.Status);
    }


    /// <summary>
    /// A model that cannot become a conformant manifest is refused by the encoding with the status that names
    /// what was wrong: no data object reference at all, and a reference naming something outside the container.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each reference and of the digest it carries transfers to the manifest, which the using disposes.")]
    public async Task AModelThatCannotBecomeAConformantManifestIsRefusedByTheEncoding()
    {
        using AsicManifest empty = new()
        {
            SignatureReference = new AsicSignatureReference { Uri = "META-INF/signature1.p7s" },
            DataObjectReferences = []
        };

        using AsicManifestEncodeResult noReferences = await EncodeAsync(empty).ConfigureAwait(false);
        Assert.AreEqual(AsicManifestEncodeStatus.NoDataObjectReferences, noReferences.Status);
        Assert.IsNull(noReferences.Document);

        //Ownership of the digest transfers to the reference, which the manifest's using disposes.
        using AsicManifest escaping = new()
        {
            SignatureReference = new AsicSignatureReference { Uri = "META-INF/signature1.p7s" },
            DataObjectReferences =
            [
                new AsicDataObjectReference
                {
                    Uri = "../outside.txt",
                    DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                    Digest = await ComputeDigestAsync("outside"u8.ToArray()).ConfigureAwait(false)
                }
            ]
        };

        using AsicManifestEncodeResult escapingResult = await EncodeAsync(escaping).ConfigureAwait(false);
        Assert.AreEqual(AsicManifestEncodeStatus.InvalidUriReference, escapingResult.Status);
        Assert.IsNull(escapingResult.Document);
    }


    /// <summary>
    /// A digest of the wrong length for the algorithm it is stated under is refused by the encoding, so a
    /// manifest this library writes can never state a digest no recomputation could equal.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the reference and of the digest it carries transfers to the manifest, which the using disposes.")]
    public async Task ADigestOfTheWrongLengthIsRefusedByTheEncoding()
    {
        //A SHA-512 digest stated under SHA-256: 64 octets where the algorithm produces 32. Ownership of the
        //digest transfers to the reference, which the manifest's using disposes.
        using AsicManifest manifest = new()
        {
            SignatureReference = new AsicSignatureReference { Uri = "META-INF/signature1.p7s" },
            DataObjectReferences =
            [
                new AsicDataObjectReference
                {
                    Uri = "file1.txt",
                    DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                    Digest = await ComputeDigestAsync("content"u8.ToArray(), PkiDigestAlgorithm.Sha512).ConfigureAwait(false)
                }
            ]
        };

        using AsicManifestEncodeResult result = await EncodeAsync(manifest).ConfigureAwait(false);

        Assert.AreEqual(AsicManifestEncodeStatus.DigestValueMalformed, result.Status);
        Assert.IsNull(result.Document);
    }


    /// <summary>
    /// The role of a manifest is the file name's, not the document's: the same octets read under three
    /// different names carry three different roles, which is what makes
    /// <see cref="AsicManifestNaming.RoleFromEntryName"/> the dispatch and the content merely the payload.
    /// </summary>
    [TestMethod]
    public async Task TheSameOctetsCarryThreeRolesDependingOnTheNameTheyAreStoredUnder()
    {
        using AsicManifest manifest = await BuildManifestAsync().ConfigureAwait(false);
        using AsicManifestEncodeResult encoded = await EncodeAsync(manifest).ConfigureAwait(false);

        using AsicManifestParseResult parsed = await ParseAsync(encoded.Document!).ConfigureAwait(false);
        Assert.IsTrue(parsed.IsValid, parsed.FailureReason);

        Assert.AreEqual(AsicManifestRole.Signature, AsicManifestNaming.RoleFromEntryName("META-INF/ASiCManifest1.xml"));
        Assert.AreEqual(AsicManifestRole.Archive, AsicManifestNaming.RoleFromEntryName("META-INF/ASiCArchiveManifest.xml"));
        Assert.AreEqual(AsicManifestRole.EvidenceRecord, AsicManifestNaming.RoleFromEntryName("META-INF/ASiCEvidenceRecordManifest1.xml"));

        XDocument document = XDocument.Parse(Encoding.UTF8.GetString(encoded.Document!.AsReadOnlySpan()));
        Assert.AreEqual(Asic + "ASiCManifest", document.Root!.Name,
            "One element type serves all three roles; nothing in the document says which one it is.");
    }


    /// <summary>
    /// Builds a manifest with two data object references — one carrying both optional attributes and the
    /// <c>Rootfile</c> marker, one carrying neither — and optionally two extensions.
    /// </summary>
    /// <param name="withExtensions">Whether the manifest carries extensions.</param>
    /// <returns>The manifest. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every digest, reference and extension built here transfers to the returned manifest, which the caller disposes.")]
    private static async Task<AsicManifest> BuildManifestAsync(bool withExtensions = false)
    {
        DigestValue first = await ComputeDigestAsync("the first data object"u8.ToArray()).ConfigureAwait(false);
        DigestValue second = await ComputeDigestAsync("the second data object"u8.ToArray(), PkiDigestAlgorithm.Sha512).ConfigureAwait(false);

        List<AsicManifestExtension> extensions = [];
        if(withExtensions)
        {
            extensions.Add(BuildExtension(critical: true, """<Retention xmlns="urn:test:asic-extension">P10Y</Retention>"""));
            extensions.Add(BuildExtension(critical: false, """<Note xmlns="urn:test:asic-extension">informative</Note>"""));
        }

        return new AsicManifest
        {
            SignatureReference = new AsicSignatureReference
            {
                Uri = "META-INF/signature1.p7s",
                MimeType = "application/pkcs7-signature"
            },
            DataObjectReferences =
            [
                new AsicDataObjectReference
                {
                    Uri = "file1.txt",
                    DigestAlgorithm = PkiDigestAlgorithm.Sha256,
                    Digest = first,
                    MimeType = "text/plain",
                    IsRootFile = true
                },
                new AsicDataObjectReference
                {
                    Uri = "folder/file%202.bin",
                    DigestAlgorithm = PkiDigestAlgorithm.Sha512,
                    Digest = second
                }
            ],
            Extensions = extensions
        };

        //Builds one extension whose carried octets are the whole Extension element, which is what the model
        //holds and what the encoding writes back.
        static AsicManifestExtension BuildExtension(bool critical, string content)
        {
            string element = string.Create(
                CultureInfo.InvariantCulture,
                $"""<Extension xmlns="http://uri.etsi.org/02918/v1.2.1#" Critical="{(critical ? "true" : "false")}">{content}</Extension>""");

            XElement parsed = XElement.Parse(element);

            return new AsicManifestExtension
            {
                Critical = critical,
                ElementNamespace = "urn:test:asic-extension",
                ElementName = parsed.Elements().First().Name.LocalName,
                Content = PooledMemory.FromBytes(
                    Encoding.UTF8.GetBytes(parsed.ToString(SaveOptions.DisableFormatting)),
                    BaseMemoryPool.Shared,
                    AsicTags.ManifestExtension)
            };
        }
    }


    /// <summary>
    /// Computes a digest through the registered digest seam.
    /// </summary>
    /// <param name="content">The octets to hash.</param>
    /// <param name="algorithm">The algorithm to hash under.</param>
    /// <returns>The digest. The caller owns and disposes it.</returns>
    private static async Task<DigestValue> ComputeDigestAsync(byte[] content, PkiDigestAlgorithm? algorithm = null)
    {
        PkiDigestAlgorithm resolved = algorithm ?? PkiDigestAlgorithm.Sha256;

        return await CryptographicKeyEvents.ComputeDigestAsync(
            content,
            resolved.OutputByteLength,
            resolved.DigestTag,
            BaseMemoryPool.Shared).ConfigureAwait(false);
    }


    /// <summary>Encodes a manifest through the staged binding.</summary>
    /// <param name="manifest">The manifest to write.</param>
    /// <returns>The encoding result. The caller owns and disposes it.</returns>
    private ValueTask<AsicManifestEncodeResult> EncodeAsync(AsicManifest manifest) =>
        AsicManifestXmlBinding.EncodeAsync(new AsicManifestEncodeContext { Manifest = manifest }, BaseMemoryPool.Shared, TestContext.CancellationToken);


    /// <summary>Parses a manifest document through the staged binding under the conformant limits.</summary>
    /// <param name="document">The document's octets.</param>
    /// <returns>The parse result. The caller owns and disposes it.</returns>
    private ValueTask<AsicManifestParseResult> ParseAsync(PooledMemory document) =>
        AsicManifestXmlBinding.ParseAsync(new AsicManifestParseContext { Document = document }, BaseMemoryPool.Shared, TestContext.CancellationToken);


}
