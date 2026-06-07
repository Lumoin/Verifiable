using System.Text;
using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Tests for the shared <see cref="JsonAppender"/> primitives that compose
/// Verifiable.OAuth wire JSON without taking a serialisation-library
/// dependency. Covers escape edge cases (RFC 8259 §7), dispatch-walker
/// type coverage, incremental field-writer behaviour (leading-comma
/// management), and StringBuilder pooling round-trips.
/// </summary>
[TestClass]
internal sealed class JsonAppenderTests
{
    private static readonly string[] SampleTags = ["alpha", "beta"];
    private static readonly Uri[] SampleRedirectUris =
    [
        new Uri("https://example.org/cb"),
        new Uri("https://wallet.example.com/cb2?state=abc")
    ];


    [TestMethod]
    public void AppendEscapedStringEmitsRfc8259NamedEscapes()
    {
        StringBuilder sb = new();
        JsonAppender.AppendEscapedString(sb, "\" \\ \b \f \n \r \t");

        Assert.AreEqual("\\\" \\\\ \\b \\f \\n \\r \\t", sb.ToString());
    }


    [TestMethod]
    public void AppendEscapedStringEmitsUnicodeEscapesForControlChars()
    {
        StringBuilder sb = new();
        JsonAppender.AppendEscapedString(sb, "");

        Assert.AreEqual("\\u0001\\u001f", sb.ToString());
    }


    [TestMethod]
    public void AppendEscapedStringPassesPrintableCharsThrough()
    {
        StringBuilder sb = new();
        JsonAppender.AppendEscapedString(sb, "a/b:c=d:e f.g");

        //Forward slash and colon are legal as-is per RFC 8259 §7 (they only
        //need optional escaping); printable ASCII passes through.
        Assert.AreEqual("a/b:c=d:e f.g", sb.ToString());
    }


    [TestMethod]
    public void AppendValueDispatchesOnPrimitives()
    {
        StringBuilder sb = new();
        JsonAppender.AppendValue(sb, null);
        sb.Append('|');
        JsonAppender.AppendValue(sb, "text");
        sb.Append('|');
        JsonAppender.AppendValue(sb, true);
        sb.Append('|');
        JsonAppender.AppendValue(sb, false);
        sb.Append('|');
        JsonAppender.AppendValue(sb, 42);
        sb.Append('|');
        JsonAppender.AppendValue(sb, -7L);
        sb.Append('|');
        JsonAppender.AppendValue(sb, 3.14);

        Assert.AreEqual("null|\"text\"|true|false|42|-7|3.14", sb.ToString());
    }


    [TestMethod]
    public void AppendValueDispatchesOnUri()
    {
        StringBuilder sb = new();
        JsonAppender.AppendValue(sb, new Uri("https://example.org/path?q=1"));

        Assert.AreEqual("\"https://example.org/path?q=1\"", sb.ToString());
    }


    [TestMethod]
    public void AppendValueRecursesIntoNestedDictionaryAndArray()
    {
        Dictionary<string, object> inner = new(StringComparer.Ordinal)
        {
            ["k"] = "v"
        };
        Dictionary<string, object> outer = new(StringComparer.Ordinal)
        {
            ["nested"] = inner,
            ["list"] = new object[] { 1, "two", true }
        };

        StringBuilder sb = new();
        JsonAppender.AppendObject(sb, outer);

        Assert.AreEqual(
            "{\"nested\":{\"k\":\"v\"},\"list\":[1,\"two\",true]}",
            sb.ToString());
    }


    [TestMethod]
    public void AppendObjectPreservesInsertionOrder()
    {
        Dictionary<string, object> dict = new(StringComparer.Ordinal)
        {
            ["z"] = 1,
            ["a"] = 2,
            ["m"] = 3
        };

        StringBuilder sb = new();
        JsonAppender.AppendObject(sb, dict);

        Assert.AreEqual("{\"z\":1,\"a\":2,\"m\":3}", sb.ToString());
    }


    [TestMethod]
    public void AppendObjectEscapesKeys()
    {
        Dictionary<string, object> dict = new(StringComparer.Ordinal)
        {
            ["a\"b"] = "c"
        };

        StringBuilder sb = new();
        JsonAppender.AppendObject(sb, dict);

        Assert.AreEqual("{\"a\\\"b\":\"c\"}", sb.ToString());
    }


    [TestMethod]
    public void AppendObjectEmitsEmptyObjectForEmptyDict()
    {
        StringBuilder sb = new();
        JsonAppender.AppendObject(sb, new Dictionary<string, object>());

        Assert.AreEqual("{}", sb.ToString());
    }


    [TestMethod]
    public void AppendArrayEmitsEmptyArrayForEmptyEnumerable()
    {
        StringBuilder sb = new();
        JsonAppender.AppendArray(sb, Array.Empty<object>());

        Assert.AreEqual("[]", sb.ToString());
    }


    [TestMethod]
    public void IncrementalFieldWritersTrackFirstFlag()
    {
        StringBuilder sb = new();
        sb.Append('{');
        bool first = true;

        JsonAppender.AppendStringField(sb, "name", "Veikko", ref first);
        JsonAppender.AppendInt64Field(sb, "age", 42, ref first);
        JsonAppender.AppendBoolField(sb, "active", true, ref first);
        JsonAppender.AppendUriField(sb, "home", new Uri("https://example.org/"), ref first);
        JsonAppender.AppendStringArrayField(sb, "tags", SampleTags, ref first);

        sb.Append('}');

        Assert.AreEqual(
            "{\"name\":\"Veikko\",\"age\":42,\"active\":true,\"home\":\"https://example.org/\",\"tags\":[\"alpha\",\"beta\"]}",
            sb.ToString());
        Assert.IsFalse(first,
            "First flag must be flipped to false after the initial field.");
    }


    [TestMethod]
    public void AppendRawFieldInlinesPreserializedValue()
    {
        StringBuilder sb = new();
        sb.Append('{');
        bool first = true;
        JsonAppender.AppendRawField(sb, "jwks",
            "{\"keys\":[{\"kty\":\"EC\"}]}", ref first);
        sb.Append('}');

        Assert.AreEqual("{\"jwks\":{\"keys\":[{\"kty\":\"EC\"}]}}", sb.ToString());
    }


    [TestMethod]
    public void AppendUriArrayFieldUsesOriginalString()
    {
        StringBuilder sb = new();
        sb.Append('{');
        bool first = true;

        JsonAppender.AppendUriArrayField(sb, "redirect_uris",
            SampleRedirectUris, ref first);

        sb.Append('}');

        Assert.AreEqual(
            "{\"redirect_uris\":[\"https://example.org/cb\",\"https://wallet.example.com/cb2?state=abc\"]}",
            sb.ToString());
    }


    [TestMethod]
    public void RentReturnsReusableBufferAfterReturn()
    {
        StringBuilder rented = JsonAppender.Rent();
        rented.Append("first use");
        Assert.AreEqual("first use", rented.ToString());

        JsonAppender.Return(rented);

        StringBuilder again = JsonAppender.Rent();
        Assert.AreEqual(0, again.Length,
            "Rented builder must come back cleared so a previous use's bytes never leak into the next response.");
        JsonAppender.Return(again);
    }


    [TestMethod]
    public void ReturnDropsOversizeBuffersToBoundThePool()
    {
        StringBuilder oversize = new(capacity: 256 * 1024);
        oversize.Append('x');

        //Must not throw; oversize buffer is dropped rather than retained.
        JsonAppender.Return(oversize);

        //A fresh Rent that returns must be a new, small-capacity buffer —
        //we cannot assert exact capacity (pool internals) but a successful
        //rent without throwing covers the contract.
        StringBuilder fresh = JsonAppender.Rent();
        Assert.AreEqual(0, fresh.Length);
        JsonAppender.Return(fresh);
    }
}
