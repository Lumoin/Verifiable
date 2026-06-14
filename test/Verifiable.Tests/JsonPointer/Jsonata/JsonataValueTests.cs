using System.Collections.Generic;
using Verifiable.JsonPointer.Jsonata;

namespace Verifiable.Tests.JsonPointer.Jsonata;

/// <summary>
/// Tests for the self-contained JSON value model (<see cref="JsonataValue"/>) the minimal in-repo
/// JSONata evaluator reads and constructs — the clean local model that keeps
/// <c>Verifiable.JsonPointer</c> free of <c>System.Text.Json</c>.
/// </summary>
[TestClass]
internal sealed class JsonataValueTests
{
    [TestMethod]
    public void FactoryMethodsSetKind()
    {
        Assert.AreEqual(JsonataValueKind.String, JsonataValue.FromString("x").Kind);
        Assert.AreEqual(JsonataValueKind.Integer, JsonataValue.FromInteger(1).Kind);
        Assert.AreEqual(JsonataValueKind.Number, JsonataValue.FromNumber(1.5).Kind);
        Assert.AreEqual(JsonataValueKind.Boolean, JsonataValue.FromBoolean(true).Kind);
        Assert.AreEqual(JsonataValueKind.Null, JsonataValue.Null.Kind);
    }


    [TestMethod]
    public void GetMemberOrNullReadsObjectMember()
    {
        var value = JsonataValue.FromObject(
            new Dictionary<string, JsonataValue>(StringComparer.Ordinal) { ["k"] = JsonataValue.FromString("v") });

        Assert.AreEqual("v", value.GetMemberOrNull("k").AsString());
    }


    [TestMethod]
    public void GetMemberOrNullReturnsNullForAbsentMember()
    {
        var value = JsonataValue.FromObject(new Dictionary<string, JsonataValue>(StringComparer.Ordinal));

        Assert.IsTrue(value.GetMemberOrNull("missing").IsNull);
    }


    [TestMethod]
    public void GetMemberOrNullReturnsNullForNonObject()
    {
        Assert.IsTrue(JsonataValue.FromString("x").GetMemberOrNull("k").IsNull);
    }


    [TestMethod]
    public void ScalarEqualityComparesByValue()
    {
        Assert.AreEqual(JsonataValue.FromString("a"), JsonataValue.FromString("a"));
        Assert.AreNotEqual(JsonataValue.FromString("a"), JsonataValue.FromString("b"));
        Assert.AreEqual(JsonataValue.FromInteger(7), JsonataValue.FromInteger(7));
        Assert.AreEqual(JsonataValue.FromBoolean(true), JsonataValue.True);
    }


    [TestMethod]
    public void AccessorThrowsOnWrongKind()
    {
        Assert.Throws<InvalidOperationException>(() => JsonataValue.FromString("x").AsInteger());
        Assert.Throws<InvalidOperationException>(() => JsonataValue.FromInteger(1).AsString());
    }
}
