using System.Text;
using System.Text.Json;
using Verifiable.JCose;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests that <see cref="JwkJsonReader.ExtractStringValue"/> returns the JSON-DECODED
/// string value, not the raw escaped bytes. The motivating case: <c>System.Text.Json</c>'s
/// default encoder escapes <c>+</c> as a <c>+</c> sequence, so a conformant wallet
/// serializing a JOSE <c>typ</c> of <c>openid4vci-proof+jwt</c> with stock settings emits
/// the escaped form; a raw-bytes reader would reject it against the literal <c>+</c>
/// value. The reader must decode escapes so the comparison succeeds.
/// </summary>
/// <remarks>
/// The escaped inputs are produced by <see cref="JsonSerializer"/> with its default encoder
/// — i.e. exactly what a stock-.NET wallet emits — rather than hand-authored escape literals,
/// so the test proves the real interop round-trip without any source-literal ambiguity.
/// </remarks>
[TestClass]
internal sealed class JwkJsonReaderEscapeDecodingTests
{
    private static byte[] StockSerialized(string key, string value) =>
        Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(new Dictionary<string, object> { [key] = value }));


    [TestMethod]
    public void DecodesDefaultEncoderEscapedPlusInTyp()
    {
        byte[] json = StockSerialized("typ", "openid4vci-proof+jwt");

        //Guard: the default encoder really does escape '+', so this is a genuine case.
        Assert.Contains("\\u002B", Encoding.UTF8.GetString(json));

        string? typ = JwkJsonReader.ExtractStringValue(json, "typ"u8);

        Assert.AreEqual("openid4vci-proof+jwt", typ);
    }


    [TestMethod]
    public void DecodesNonAsciiEscape()
    {
        //The default encoder escapes non-ASCII (é) as é.
        byte[] json = StockSerialized("v", "café");

        Assert.Contains("\\u00E9", Encoding.UTF8.GetString(json));

        string? value = JwkJsonReader.ExtractStringValue(json, "v"u8);

        Assert.AreEqual("café", value);
    }


    [TestMethod]
    public void DecodesSurrogatePairEscape()
    {
        //😀 (U+1F600) is escaped as the surrogate pair 😀.
        byte[] json = StockSerialized("v", "x\U0001F600y");

        Assert.Contains("\\uD83D", Encoding.UTF8.GetString(json));

        string? value = JwkJsonReader.ExtractStringValue(json, "v"u8);

        Assert.AreEqual("x\U0001F600y", value);
    }


    [TestMethod]
    public void DecodesControlCharacterEscape()
    {
        byte[] json = StockSerialized("v", "a\tb");

        string? value = JwkJsonReader.ExtractStringValue(json, "v"u8);

        Assert.AreEqual("a\tb", value);
    }


    [TestMethod]
    public void UnescapedValueIsUnchangedFastPath()
    {
        //A literal value with no backslash takes the byte-identical fast path.
        string source = """{"typ":"openid4vci-proof+jwt"}""";
        string? typ = JwkJsonReader.ExtractStringValue(
            Encoding.UTF8.GetBytes(source), "typ"u8);

        Assert.AreEqual("openid4vci-proof+jwt", typ);
    }


    [TestMethod]
    public void Base64UrlValueIsUnchanged()
    {
        //base64url carries no backslash, so key material is never perturbed.
        const string coordinate = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
        string source = $$"""{"x":"{{coordinate}}"}""";
        string? x = JwkJsonReader.ExtractStringValue(
            Encoding.UTF8.GetBytes(source), "x"u8);

        Assert.AreEqual(coordinate, x);
    }
}
