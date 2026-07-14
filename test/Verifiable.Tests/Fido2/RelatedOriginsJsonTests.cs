using System.Buffers;
using System.Text;
using Verifiable.Fido2;
using Verifiable.Json;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Unit tests for <see cref="RelatedOriginsJsonReader"/> and <see cref="RelatedOriginsJsonWriter"/>: the
/// JSON codec for the document a relying party hosts at
/// <see cref="WellKnownWebAuthnValues.RelatedOriginsWellKnownPath"/>, per
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-related-origins">W3C Web Authentication Level 3,
/// section 5.11</see>. Every malformed-input rejection is a <see cref="Fido2FormatException"/> naming the
/// member or structural violation at fault; every writer rejection of an invalid
/// <see cref="RelatedOriginsDocument"/> is an <see cref="ArgumentException"/>.
/// </summary>
[TestClass]
internal sealed class RelatedOriginsJsonTests
{
    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A well-formed document carrying section 5.11's own worked example (the RP ID <c>example.com</c>'s
    /// ten related origins) parses to a <see cref="RelatedOriginsDocument"/> whose <see cref="RelatedOriginsDocument.Origins"/>
    /// preserves wire order.
    /// </summary>
    [TestMethod]
    public void CrWorkedExampleDocumentParsesEveryOriginInOrder()
    {
        const string json = """
            {
                "origins": [
                    "https://example.co.uk",
                    "https://example.de",
                    "https://example.sg",
                    "https://example.net",
                    "https://exampledelivery.com",
                    "https://exampledelivery.co.uk",
                    "https://exampledelivery.de",
                    "https://exampledelivery.sg",
                    "https://myexamplerewards.com",
                    "https://examplecars.com"
                ]
            }
            """;

        RelatedOriginsDocument document = RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json));

        string[] expectedOrigins =
        [
            "https://example.co.uk", "https://example.de", "https://example.sg", "https://example.net",
            "https://exampledelivery.com", "https://exampledelivery.co.uk", "https://exampledelivery.de",
            "https://exampledelivery.sg", "https://myexamplerewards.com", "https://examplecars.com"
        ];

        Assert.IsTrue(expectedOrigins.SequenceEqual(document.Origins));
    }


    /// <summary>An unrecognised top-level member is skipped; the recognised <c>origins</c> member still parses.</summary>
    [TestMethod]
    public void UnknownTopLevelMemberIsIgnored()
    {
        const string json = """{"origins":["https://a.example"],"extra":{"nested":[1,2,3]}}""";

        RelatedOriginsDocument document = RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json));

        Assert.HasCount(1, document.Origins);
        Assert.AreEqual("https://a.example", document.Origins[0]);
    }


    /// <summary>A document missing the required <c>origins</c> member is rejected.</summary>
    [TestMethod]
    public void MissingOriginsMemberIsRejected()
    {
        const string json = """{"other":"value"}""";

        Fido2FormatException exception = Assert.ThrowsExactly<Fido2FormatException>(
            () => RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json)));

        Assert.Contains("origins", exception.Message, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>An empty <c>origins</c> array violates section 5.11's "one or more strings" and is rejected.</summary>
    [TestMethod]
    public void EmptyOriginsArrayIsRejected()
    {
        const string json = """{"origins":[]}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>A non-string element inside <c>origins</c> is rejected.</summary>
    [TestMethod]
    public void NonStringOriginsElementIsRejected()
    {
        const string json = """{"origins":["https://a.example", 42]}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>An <c>origins</c> member carrying a JSON object rather than an array is rejected.</summary>
    [TestMethod]
    public void NonArrayOriginsMemberIsRejected()
    {
        const string json = """{"origins":{"a":"b"}}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>An <c>origins</c> member carrying a bare string rather than an array is rejected.</summary>
    [TestMethod]
    public void StringOriginsMemberIsRejected()
    {
        const string json = """{"origins":"https://a.example"}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>A duplicate top-level member (two <c>origins</c> members) is rejected.</summary>
    [TestMethod]
    public void DuplicateTopLevelMemberIsRejected()
    {
        const string json = """{"origins":["https://a.example"],"origins":["https://b.example"]}""";

        Assert.ThrowsExactly<Fido2FormatException>(() => RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>A top-level JSON array, rather than an object, is rejected.</summary>
    [TestMethod]
    public void TopLevelJsonArrayIsRejected()
    {
        const string json = """["https://a.example"]""";

        Assert.ThrowsExactly<Fido2FormatException>(() => RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>Malformed JSON bytes that do not parse at all are rejected.</summary>
    [TestMethod]
    public void MalformedJsonBytesAreRejected()
    {
        const string json = "{not json";

        Assert.ThrowsExactly<Fido2FormatException>(() => RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>Trailing content after an otherwise well-formed top-level object is rejected.</summary>
    [TestMethod]
    public void TrailingContentAfterTheObjectIsRejected()
    {
        const string json = """{"origins":["https://a.example"]} garbage""";

        Assert.ThrowsExactly<Fido2FormatException>(() => RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>
    /// An unrecognised member holding a deeply nested (70+ levels) array is rejected as malformed input
    /// rather than exhausting the call stack — <see cref="RelatedOriginsJsonReader"/> bounds
    /// <see cref="System.Text.Json.JsonReaderOptions.MaxDepth"/> at 8, mirroring
    /// <see cref="ClientDataJsonReader"/>'s depth bound.
    /// </summary>
    [TestMethod]
    public void DeeplyNestedUnknownMemberBeyondTheDepthBoundIsRejected()
    {
        string deeplyNestedArray = Fido2TestVectors.BuildDeeplyNestedArray(depth: 70);
        string json = "{\"origins\":[\"https://a.example\"],\"deep\":" + deeplyNestedArray + "}";

        Assert.ThrowsExactly<Fido2FormatException>(() => RelatedOriginsJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }


    /// <summary>
    /// Writing section 5.11's own worked example and reading it back yields an equal, order-preserved
    /// origins list.
    /// </summary>
    [TestMethod]
    public void WriterAndReaderRoundTripTheCrWorkedExample()
    {
        RelatedOriginsDocument original = new()
        {
            Origins =
            [
                "https://example.co.uk", "https://example.de", "https://example.sg", "https://example.net",
                "https://exampledelivery.com", "https://exampledelivery.co.uk", "https://exampledelivery.de",
                "https://exampledelivery.sg", "https://myexamplerewards.com", "https://examplecars.com"
            ]
        };

        ArrayBufferWriter<byte> buffer = new();
        RelatedOriginsJsonWriter.Write(original, buffer);
        RelatedOriginsDocument roundTripped = RelatedOriginsJsonReader.Read(buffer.WrittenMemory);

        Assert.IsTrue(original.Origins.SequenceEqual(roundTripped.Origins));
    }


    /// <summary>The writer refuses an empty <see cref="RelatedOriginsDocument.Origins"/> list.</summary>
    [TestMethod]
    public void WriterRejectsEmptyOriginsList()
    {
        RelatedOriginsDocument document = new() { Origins = [] };
        ArrayBufferWriter<byte> buffer = new();

        Assert.ThrowsExactly<ArgumentException>(() => RelatedOriginsJsonWriter.Write(document, buffer));
    }


    /// <summary>Each structurally invalid origin shape the writer must never emit.</summary>
    public static IEnumerable<object[]> InvalidOriginShapes =>
    [
        ["HttpScheme", "http://example.com"],
        ["PathBeyondRoot", "https://example.com/x"],
        ["Query", "https://example.com?x=1"],
        ["Fragment", "https://example.com#frag"],
        ["Userinfo", "https://user:pass@example.com"],
        ["BareHostWithoutScheme", "example.com"],
        ["RelativeStringCrossPlatformFileTrap", "/relative"]
    ];


    /// <summary>
    /// The writer refuses to emit a document carrying an entry <see cref="RelatedOrigins.IsValidOrigin"/>
    /// rejects — the secure default of never round-tripping an origin the reader (or the client's own
    /// validation procedure) would refuse.
    /// </summary>
    [TestMethod]
    [DynamicData(nameof(InvalidOriginShapes))]
    public void WriterRejectsEachInvalidOriginShape(string caseName, string invalidOrigin)
    {
        RelatedOriginsDocument document = new() { Origins = [invalidOrigin] };
        ArrayBufferWriter<byte> buffer = new();

        Assert.ThrowsExactly<ArgumentException>(() => RelatedOriginsJsonWriter.Write(document, buffer), caseName);
    }
}
