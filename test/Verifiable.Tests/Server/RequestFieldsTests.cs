using Verifiable.Server;

namespace Verifiable.Tests.Server;

/// <summary>
/// Unit coverage for <see cref="RequestFields"/> — the multi-valued request
/// parameter model. Pins the fail-closed single-value read (RFC 6749 §3.1) and
/// the explicit multi-valued read.
/// </summary>
[TestClass]
internal sealed class RequestFieldsTests
{
    [TestMethod]
    public void SingleValueReadSucceedsForExactlyOne()
    {
        RequestFields fields = new();
        fields.Add("scope", "openid");

        Assert.IsTrue(fields.TryGetValue("scope", out string? value));
        Assert.AreEqual("openid", value);
    }


    [TestMethod]
    public void SingleValueReadFailsClosedForAbsentKey()
    {
        RequestFields fields = new();

        Assert.IsFalse(fields.TryGetValue("scope", out string? value));
        Assert.IsNull(value);
    }


    [TestMethod]
    public void SingleValueReadFailsClosedForRepeatedKey()
    {
        //RFC 6749 §3.1: a single-valued parameter that arrives more than once
        //must not silently resolve to one of the values.
        RequestFields fields = new();
        fields.Add("client_id", "a");
        fields.Add("client_id", "b");

        Assert.IsTrue(fields.ContainsKey("client_id"), "The key is present.");
        Assert.IsFalse(fields.TryGetValue("client_id", out string? value),
            "A repeated single-valued parameter must fail the exactly-one read.");
        Assert.IsNull(value);
    }


    [TestMethod]
    public void GetValuesReturnsEveryValueInOrder()
    {
        RequestFields fields = new();
        fields.Add("entity_type", "openid_relying_party");
        fields.Add("entity_type", "openid_provider");

        IReadOnlyList<string> values = fields.GetValues("entity_type");

        Assert.HasCount(2, values);
        Assert.AreEqual("openid_relying_party", values[0]);
        Assert.AreEqual("openid_provider", values[1]);
    }


    [TestMethod]
    public void GetValuesIsEmptyForAbsentKey()
    {
        RequestFields fields = new();

        Assert.IsEmpty(fields.GetValues("entity_type"));
    }


    [TestMethod]
    public void IndexerSetReplacesWithASingleValue()
    {
        RequestFields fields = new();
        fields.Add("scope", "a");
        fields["scope"] = "b";

        Assert.IsTrue(fields.TryGetValue("scope", out string? value));
        Assert.AreEqual("b", value);
    }
}
