using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Structural tests for <see cref="MetadataPolicyParser"/>.
/// </summary>
[TestClass]
internal sealed class MetadataPolicyParserTests
{
    [TestMethod]
    public void ParsesNestedShapeIntoTypedSnapshot()
    {
        IReadOnlyDictionary<string, object> payload = new Dictionary<string, object>
        {
            ["openid_relying_party"] = new Dictionary<string, object>
            {
                ["grant_types"] = new Dictionary<string, object>
                {
                    ["subset_of"] = new List<object> { "authorization_code", "refresh_token" }
                },
                ["id_token_signed_response_alg"] = new Dictionary<string, object>
                {
                    ["one_of"] = new List<object> { "ES256", "PS256" },
                    ["essential"] = true,
                },
            },
        };

        MetadataPolicyParseResult result = MetadataPolicyParser.Parse(payload);

        Assert.IsTrue(result.IsSuccess, $"Parser should accept the canonical shape. Reason: {result.FailureReason}");
        MetadataPolicySnapshot snapshot = result.Snapshot!;
        Assert.HasCount(1, snapshot.EntityTypes, "Snapshot should carry one entity-type block.");

        EntityTypeMetadataPolicy rpBlock = snapshot.EntityTypes[
            new EntityTypeIdentifier("openid_relying_party")];
        Assert.HasCount(2, rpBlock.ParameterPolicies, "RP block should carry two parameter policies.");

        ParameterPolicy idTokenAlg = rpBlock.ParameterPolicies["id_token_signed_response_alg"];
        Assert.HasCount(2, idTokenAlg.Operators, "id_token_signed_response_alg policy should carry two operators.");
        Assert.IsTrue(
            idTokenAlg.Operators.ContainsKey(WellKnownMetadataPolicyOperators.OneOf),
            "one_of operator should round-trip.");
        Assert.IsTrue(
            idTokenAlg.Operators.ContainsKey(WellKnownMetadataPolicyOperators.Essential),
            "essential operator should round-trip.");
    }


    [TestMethod]
    public void EmptyPolicyParsesToEmptySnapshot()
    {
        MetadataPolicyParseResult result = MetadataPolicyParser.Parse(
            new Dictionary<string, object>());

        Assert.IsTrue(result.IsSuccess, "Empty input should parse cleanly.");
        Assert.HasCount(0, result.Snapshot!.EntityTypes, "Snapshot should carry zero entity-type blocks.");
    }


    [TestMethod]
    public void EntityTypeBlockMustBeAnObject()
    {
        IReadOnlyDictionary<string, object> payload = new Dictionary<string, object>
        {
            //Not an object — Federation §6.1.2 says metadata_policy entries are objects.
            ["openid_relying_party"] = "not an object",
        };

        MetadataPolicyParseResult result = MetadataPolicyParser.Parse(payload);

        Assert.IsFalse(result.IsSuccess, "Non-object entity-type entry should be rejected.");
        Assert.IsNotNull(result.FailureReason, "Failure reason should be populated on rejection.");
        Assert.Contains("is not an object", result.FailureReason);
    }


    [TestMethod]
    public void ParameterEntryMustBeAnObject()
    {
        IReadOnlyDictionary<string, object> payload = new Dictionary<string, object>
        {
            ["openid_relying_party"] = new Dictionary<string, object>
            {
                ["grant_types"] = "not an object"
            },
        };

        MetadataPolicyParseResult result = MetadataPolicyParser.Parse(payload);

        Assert.IsFalse(result.IsSuccess, "Non-object parameter entry should be rejected.");
        Assert.Contains("grant_types", result.FailureReason!);
    }


    [TestMethod]
    public void EmptyEntityTypeKeyIsRejected()
    {
        IReadOnlyDictionary<string, object> payload = new Dictionary<string, object>
        {
            [""] = new Dictionary<string, object>(),
        };

        MetadataPolicyParseResult result = MetadataPolicyParser.Parse(payload);

        Assert.IsFalse(result.IsSuccess, "Empty entity-type key should be rejected.");
    }
}
