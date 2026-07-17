using System.Text;
using Verifiable.Fido2;
using Verifiable.Json;

using static Verifiable.Tests.Fido2.Fido2TestVectors;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Edge-case coverage for <see cref="ClientDataJsonReader"/> that <c>ClientDataJsonReaderTests</c>
/// (missing/duplicate/wrong-type members, top-level array, malformed JSON, trailing content) does not exercise:
/// a leading byte-order mark, JSON <c>\uXXXX</c> unescaping, non-ASCII origin serialization, a scope-blind
/// duplicate-key scanner, and untrusted-JSON depth bounding.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3,
/// section 5.8.1: Client Data Used in WebAuthn Signatures</see>.
/// </remarks>
[TestClass]
internal sealed class ClientDataJsonEdgeTests
{
    /// <summary>
    /// A single JSON backslash-<c>u</c> escape-sequence prefix, spelled through a regular (non-raw) C#
    /// string literal so the doubled backslash is unambiguous: <c>"\\u"</c> denotes exactly one backslash
    /// character followed by <c>u</c>, avoiding any doubt about how a raw string literal would render it.
    /// </summary>
    private const string BackslashU = "\\u";

    /// <summary>Gets or sets the test context, used by the MSTest runner to report per-test diagnostics.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A UTF-8 byte-order mark prefixed onto an otherwise well-formed <c>clientDataJSON</c> payload is
    /// rejected. WebAuthn clients serialize <c>CollectedClientData</c> as plain UTF-8 JSON text with no BOM,
    /// and <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.1">RFC 8259 section 8.1</see> forbids a
    /// JSON text producer from prepending one; a reader that silently tolerated a BOM would accept wire input
    /// no conformant client emits.
    /// </summary>
    [TestMethod]
    public void Utf8BomPrefixedClientDataJsonIsRejected()
    {
        byte[] withoutBom = Encoding.UTF8.GetBytes("""{"type":"webauthn.get","challenge":"c","origin":"o"}""");
        byte[] bom = [0xEF, 0xBB, 0xBF];
        byte[] withBom = [.. bom, .. withoutBom];

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientDataJsonReader.Read(withBom));
    }


    /// <summary>
    /// A <c>challenge</c> and an <c>origin</c> written with <c>\uXXXX</c> escapes parse to the exact same
    /// string as their unescaped equivalents. JSON string unescaping is standard, correct behavior per
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 section 7</see>, so a ceremony
    /// rule comparing the parsed value against a plain-text expected challenge or origin still matches — the
    /// escape is a wire-encoding detail the reader is required to normalize away, not a distinct value.
    /// </summary>
    [TestMethod]
    public void EscapedUnicodeChallengeAndOriginParseToTheUnescapedForm()
    {
        //The challenge below spells "abc1def-" using JSON backslash-u escapes for the digit
        //'1' (code point U+0031) and the hyphen '-' (code point U+002D). A non-interpolated raw
        //string literal does not itself interpret a backslash, so the JSON text the reader receives
        //genuinely carries these escapes rather than the plain characters.
        const string json = "{\"type\":\"webauthn.get\",\"challenge\":\"abc" + BackslashU + "0031def" + BackslashU + "002D\",\"origin\":\"https://rp.example\"}";

        ClientData clientData = ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json));

        Assert.AreEqual("abc1def-", clientData.Challenge);
        Assert.AreEqual("https://rp.example", clientData.Origin);
    }


    /// <summary>
    /// A <c>origin</c> member carrying a literal (non-ASCII) Unicode hostname does not ordinally match a
    /// relying party's expected origin serialized in its Punycode/IDNA ASCII form. Real browsers always
    /// serialize a Unicode domain name's origin using its ASCII (Punycode) form before writing
    /// <c>clientDataJSON</c>, so a relying party comparing against a Unicode-form expectation — or a client
    /// that (incorrectly) emitted the raw Unicode host — would fail the ordinal origin comparison
    /// <see cref="Fido2AssertionChecks.CheckAssertionOrigin"/> performs; this test documents that this reader
    /// performs no hostname normalization of its own, so any such mismatch surfaces at the ceremony-rule
    /// layer, not here.
    /// </summary>
    [TestMethod]
    public void NonAsciiOriginDoesNotOrdinallyMatchAPunycodeSerializedExpectedOrigin()
    {
        const string literalUnicodeOrigin = "https://café.example";
        const string punycodeSerializedOrigin = "https://xn--caf-dma.example";
        string json = "{\"type\":\"webauthn.get\",\"challenge\":\"c\",\"origin\":\"" + literalUnicodeOrigin + "\"}";

        ClientData clientData = ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json));

        Assert.AreEqual(literalUnicodeOrigin, clientData.Origin);
        Assert.AreNotEqual(punycodeSerializedOrigin, clientData.Origin);
    }


    /// <summary>
    /// A duplicate member name nested inside an unrecognised, skipped member does not shadow the top-level
    /// <c>type</c>/<c>challenge</c>/<c>origin</c> values. <see cref="ClientDataJsonReader"/> tracks seen
    /// member names only at the top level (section 5.8.1 permits a client to add extra members, so an
    /// unrecognised one is skipped via <see cref="System.Text.Json.Utf8JsonReader.Skip"/> rather than parsed);
    /// this guards against a scope-blind duplicate scanner that would otherwise be fooled by a repeated key
    /// several levels deep.
    /// </summary>
    [TestMethod]
    public void NestedDuplicateKeysInsideASkippedUnknownMemberDoNotShadowTopLevelValues()
    {
        const string json = """{"type":"webauthn.get","challenge":"c","origin":"o","unknownExtra":{"type":1,"type":2}}""";

        ClientData clientData = ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json));

        Assert.AreEqual(WellKnownClientDataTypes.Get, clientData.Type);
        Assert.AreEqual("c", clientData.Challenge);
        Assert.AreEqual("o", clientData.Origin);
    }


    /// <summary>
    /// An unrecognised member holding a deeply nested (70+ levels) array is rejected as malformed input
    /// rather than exhausting the call stack. <see cref="ClientDataJsonReader"/> bounds
    /// <see cref="System.Text.Json.JsonReaderOptions.MaxDepth"/> at 8 — <c>CollectedClientData</c> is a flat
    /// object of string/boolean members per section 5.8.1 — so untrusted wire input cannot force unbounded
    /// recursion even inside a member this reader otherwise ignores.
    /// </summary>
    [TestMethod]
    public void DeeplyNestedUnknownMemberBeyondTheDepthBoundIsRejected()
    {
        string deeplyNestedArray = Fido2TestVectors.BuildDeeplyNestedArray(depth: 70);
        string json = "{\"type\":\"webauthn.get\",\"challenge\":\"c\",\"origin\":\"o\",\"deep\":" + deeplyNestedArray + "}";

        Assert.ThrowsExactly<Fido2FormatException>(() => ClientDataJsonReader.Read(Encoding.UTF8.GetBytes(json)));
    }
}
