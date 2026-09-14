using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The raw-JSON-text inspector (<see cref="JsonScalarText"/>) the <c>Verifiable.OAuth</c>
/// serialization firewall uses to read one member's value carried verbatim in
/// <see cref="AuthorizationDetail.ExtensionData"/> without <c>System.Text.Json</c>: string
/// decoding, JSON-kind classification, and the array-of-strings predicate a strict RFC 9396
/// authorization details handler matches a field against.
/// </summary>
[TestClass]
internal sealed class JsonScalarTextTests
{
    /// <summary>A JSON string is decoded; a non-string yields <see langword="null"/>.</summary>
    [TestMethod]
    public void AsStringDecodesStringsOnly()
    {
        Assert.AreEqual("hello", JsonScalarText.AsString("\"hello\""));
        Assert.AreEqual("a/b\tc", JsonScalarText.AsString("\"a\\/b\\tc\""));
        Assert.IsNull(JsonScalarText.AsString("42"));
        Assert.IsNull(JsonScalarText.AsString("{\"k\":1}"));
        Assert.IsNull(JsonScalarText.AsString("[\"x\"]"));
    }


    /// <summary>
    /// Each JSON kind is classified from its leading text; malformed text classifies as
    /// <see cref="JsonValueShape.Malformed"/>.
    /// </summary>
    [TestMethod]
    public void ClassifyKindMapsEachJsonKind()
    {
        Assert.AreEqual(JsonValueShape.String, JsonScalarText.ClassifyKind("\"s\""));
        Assert.AreEqual(JsonValueShape.Number, JsonScalarText.ClassifyKind("-12.5"));
        Assert.AreEqual(JsonValueShape.Boolean, JsonScalarText.ClassifyKind("true"));
        Assert.AreEqual(JsonValueShape.Boolean, JsonScalarText.ClassifyKind("false"));
        Assert.AreEqual(JsonValueShape.Null, JsonScalarText.ClassifyKind("null"));
        Assert.AreEqual(JsonValueShape.Array, JsonScalarText.ClassifyKind("[1,2]"));
        Assert.AreEqual(JsonValueShape.Object, JsonScalarText.ClassifyKind("{\"k\":1}"));

        Assert.AreEqual(JsonValueShape.Malformed, JsonScalarText.ClassifyKind(""));
        Assert.AreEqual(JsonValueShape.Malformed, JsonScalarText.ClassifyKind("\"unterminated"));
        Assert.AreEqual(JsonValueShape.Malformed, JsonScalarText.ClassifyKind("tru"));
        Assert.AreEqual(JsonValueShape.Malformed, JsonScalarText.ClassifyKind("[1,2"));
    }


    /// <summary>
    /// An array of JSON strings (including the empty array and strings carrying escaped quotes
    /// and commas) satisfies the predicate; a non-array, or an array with a non-string element,
    /// does not.
    /// </summary>
    [TestMethod]
    public void IsArrayOfStringsAcceptsStringArraysOnly()
    {
        Assert.IsTrue(JsonScalarText.IsArrayOfStrings("[]"));
        Assert.IsTrue(JsonScalarText.IsArrayOfStrings("[\"a\",\"b\"]"));
        Assert.IsTrue(JsonScalarText.IsArrayOfStrings("[ \"a\" , \"b\" ]"));
        Assert.IsTrue(JsonScalarText.IsArrayOfStrings("[\"a,\\\"b\"]"));

        Assert.IsFalse(JsonScalarText.IsArrayOfStrings("\"a\""));
        Assert.IsFalse(JsonScalarText.IsArrayOfStrings("[\"a\",7]"));
        Assert.IsFalse(JsonScalarText.IsArrayOfStrings("[1,2]"));
        Assert.IsFalse(JsonScalarText.IsArrayOfStrings("[\"a\",]"));
        Assert.IsFalse(JsonScalarText.IsArrayOfStrings("{\"k\":1}"));
    }


    /// <summary>
    /// Each JSON scalar decodes to its CLR counterpart: a string to <see cref="string"/>, an
    /// integral number to <see cref="long"/>, a fractional number to <see cref="double"/>, the
    /// boolean literals to <see cref="bool"/>.
    /// </summary>
    [TestMethod]
    public void DecodeValueDecodesScalars()
    {
        Assert.AreEqual("hi\tthere", JsonScalarText.DecodeValue("\"hi\\tthere\""));
        Assert.AreEqual(42L, JsonScalarText.DecodeValue("42"));
        Assert.AreEqual(-7L, JsonScalarText.DecodeValue("-7"));
        Assert.AreEqual(1.5d, JsonScalarText.DecodeValue("1.5"));
        Assert.IsTrue((bool)JsonScalarText.DecodeValue("true")!);
        Assert.IsFalse((bool)JsonScalarText.DecodeValue("false")!);
        Assert.IsNull(JsonScalarText.DecodeValue("null"));
    }


    /// <summary>
    /// An array decodes to a <c>List&lt;object?&gt;</c> and an object to a
    /// <c>Dictionary&lt;string, object?&gt;</c>, recursively, preserving nested shape — the inverse
    /// of <see cref="JsonAppender.AppendValue"/>.
    /// </summary>
    [TestMethod]
    public void DecodeValueDecodesContainers()
    {
        object? array = JsonScalarText.DecodeValue("[\"a\",\"b\"]");
        List<object?> list = Assert.IsInstanceOfType<List<object?>>(array);
        Assert.HasCount(2, list);
        Assert.AreEqual("a", list[0]);
        Assert.AreEqual("b", list[1]);

        object? nested = JsonScalarText.DecodeValue(
            "{\"id\":\"x\",\"amounts\":[1,2],\"meta\":{\"ok\":true}}");
        Dictionary<string, object?> map = Assert.IsInstanceOfType<Dictionary<string, object?>>(nested);
        Assert.AreEqual("x", map["id"]);

        List<object?> amounts = Assert.IsInstanceOfType<List<object?>>(map["amounts"]);
        Assert.AreEqual(1L, amounts[0]);
        Assert.AreEqual(2L, amounts[1]);

        Dictionary<string, object?> meta = Assert.IsInstanceOfType<Dictionary<string, object?>>(map["meta"]);
        Assert.IsTrue((bool)meta["ok"]!);
    }


    /// <summary>Malformed or trailing-garbage text yields <see langword="null"/>.</summary>
    [TestMethod]
    public void DecodeValueRejectsMalformedText()
    {
        Assert.IsNull(JsonScalarText.DecodeValue("{\"k\":1"));
        Assert.IsNull(JsonScalarText.DecodeValue("[1,2"));
        Assert.IsNull(JsonScalarText.DecodeValue("\"unterminated"));
        Assert.IsNull(JsonScalarText.DecodeValue("tru"));
        Assert.IsNull(JsonScalarText.DecodeValue("42 garbage"));
        Assert.IsNull(JsonScalarText.DecodeValue(""));
    }
}
