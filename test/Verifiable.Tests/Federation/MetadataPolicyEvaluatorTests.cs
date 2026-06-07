using Verifiable.Core.Assessment;
using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests for <see cref="MetadataPolicyEvaluator"/> against the
/// §6.1.3.1.8 operator-combination table.
/// </summary>
[TestClass]
internal sealed class MetadataPolicyEvaluatorTests
{
    private static readonly EntityTypeIdentifier RpType =
        WellKnownEntityTypeIdentifiers.OpenIdRelyingParty;


    [TestMethod]
    public void EmptyPolicyEvaluatesAsSuccess()
    {
        EntityTypeMetadataPolicy block = new()
        {
            EntityType = RpType,
            ParameterPolicies = new Dictionary<string, ParameterPolicy>(),
        };

        Claim claim = MetadataPolicyEvaluator.EvaluateOperatorCombinations(block);

        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
        Assert.AreEqual(
            WellKnownFederationClaimIds.MetadataPolicyOperatorCombinationLegal.Code,
            claim.Id.Code);
    }


    [TestMethod]
    public void SingleOperatorParameterEvaluatesAsSuccess()
    {
        EntityTypeMetadataPolicy block = MakeBlock(
            "grant_types",
            (WellKnownMetadataPolicyOperators.SubsetOf, new List<object> { "authorization_code", "refresh_token" }));

        Claim claim = MetadataPolicyEvaluator.EvaluateOperatorCombinations(block);

        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
    }


    [TestMethod]
    public void ValuePlusAddIsIllegal()
    {
        EntityTypeMetadataPolicy block = MakeBlock(
            "scope",
            (WellKnownMetadataPolicyOperators.Value, "openid"),
            (WellKnownMetadataPolicyOperators.Add, new List<object> { "profile" }));

        Claim claim = MetadataPolicyEvaluator.EvaluateOperatorCombinations(block);

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
        MetadataPolicyEvaluationContext ctx = (MetadataPolicyEvaluationContext)claim.Context;
        Assert.AreEqual("scope", ctx.ParameterName);
    }


    [TestMethod]
    public void OneOfPlusSubsetOfIsIllegal()
    {
        EntityTypeMetadataPolicy block = MakeBlock(
            "id_token_signed_response_alg",
            (WellKnownMetadataPolicyOperators.OneOf, new List<object> { "ES256", "PS256" }),
            (WellKnownMetadataPolicyOperators.SubsetOf, new List<object> { "ES256" }));

        Claim claim = MetadataPolicyEvaluator.EvaluateOperatorCombinations(block);

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
    }


    [TestMethod]
    public void EssentialCombinesWithEveryWellKnownOperator()
    {
        foreach(MetadataPolicyOperator other in WellKnownOperatorsExcept(WellKnownMetadataPolicyOperators.Essential))
        {
            EntityTypeMetadataPolicy block = MakeBlock(
                "grant_types",
                (WellKnownMetadataPolicyOperators.Essential, true),
                (other, OperatorValue(other)));

            Claim claim = MetadataPolicyEvaluator.EvaluateOperatorCombinations(block);

            Assert.AreEqual(ClaimOutcome.Success, claim.Outcome,
                $"essential+{other.Value} should be legal.");
        }
    }


    [TestMethod]
    public void DefaultCombinesWithRestrictionOperators()
    {
        //default + one_of, default + subset_of, default + superset_of are all legal.
        foreach(MetadataPolicyOperator restriction in new[]
        {
            WellKnownMetadataPolicyOperators.OneOf,
            WellKnownMetadataPolicyOperators.SubsetOf,
            WellKnownMetadataPolicyOperators.SupersetOf,
        })
        {
            EntityTypeMetadataPolicy block = MakeBlock(
                "scope",
                (WellKnownMetadataPolicyOperators.Default, OperatorValue(restriction)),
                (restriction, OperatorValue(restriction)));

            Claim claim = MetadataPolicyEvaluator.EvaluateOperatorCombinations(block);

            Assert.AreEqual(ClaimOutcome.Success, claim.Outcome,
                $"default+{restriction.Value} should be legal.");
        }
    }


    [TestMethod]
    public void SubsetOfCombinesWithSupersetOf()
    {
        EntityTypeMetadataPolicy block = MakeBlock(
            "scope",
            (WellKnownMetadataPolicyOperators.SubsetOf, new List<object> { "openid", "profile", "email" }),
            (WellKnownMetadataPolicyOperators.SupersetOf, new List<object> { "openid" }));

        Claim claim = MetadataPolicyEvaluator.EvaluateOperatorCombinations(block);

        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
    }


    [TestMethod]
    public void RawDictOverloadConvertsAndEvaluates()
    {
        IReadOnlyDictionary<string, object> rawBlock = new Dictionary<string, object>
        {
            ["scope"] = new Dictionary<string, object>
            {
                ["value"] = "openid",
                ["add"] = new List<object> { "profile" },
            },
        };

        Claim claim = MetadataPolicyEvaluator.EvaluateOperatorCombinations(rawBlock, RpType);

        Assert.AreEqual(ClaimOutcome.Failure, claim.Outcome);
    }


    [TestMethod]
    public void ExtensionOperatorPairIsConsideredLegal()
    {
        //Two extension operators combined: the library has no semantic knowledge
        //so it accepts the pair. Deployments wanting strict enforcement supply
        //their own evaluator.
        EntityTypeMetadataPolicy block = MakeBlock(
            "scope",
            (new MetadataPolicyOperator("urn:example:custom_op_a"), "value_a"),
            (new MetadataPolicyOperator("urn:example:custom_op_b"), "value_b"));

        Claim claim = MetadataPolicyEvaluator.EvaluateOperatorCombinations(block);

        Assert.AreEqual(ClaimOutcome.Success, claim.Outcome);
    }


    private static EntityTypeMetadataPolicy MakeBlock(
        string parameterName,
        params (MetadataPolicyOperator Operator, object Value)[] operators)
    {
        Dictionary<MetadataPolicyOperator, object> ops = new();
        foreach((MetadataPolicyOperator op, object val) in operators)
        {
            ops[op] = val;
        }

        return new EntityTypeMetadataPolicy
        {
            EntityType = RpType,
            ParameterPolicies = new Dictionary<string, ParameterPolicy>
            {
                [parameterName] = new ParameterPolicy
                {
                    ParameterName = parameterName,
                    Operators = ops,
                },
            },
        };
    }


    private static IEnumerable<MetadataPolicyOperator> WellKnownOperatorsExcept(MetadataPolicyOperator excluded)
    {
        MetadataPolicyOperator[] all =
        [
            WellKnownMetadataPolicyOperators.Value,
            WellKnownMetadataPolicyOperators.Add,
            WellKnownMetadataPolicyOperators.Default,
            WellKnownMetadataPolicyOperators.OneOf,
            WellKnownMetadataPolicyOperators.SubsetOf,
            WellKnownMetadataPolicyOperators.SupersetOf,
            WellKnownMetadataPolicyOperators.Essential,
        ];

        foreach(MetadataPolicyOperator op in all)
        {
            if(!op.Equals(excluded))
            {
                yield return op;
            }
        }
    }


    private static object OperatorValue(MetadataPolicyOperator op)
    {
        if(op.Equals(WellKnownMetadataPolicyOperators.Essential))
        {
            return true;
        }
        if(op.Equals(WellKnownMetadataPolicyOperators.Value))
        {
            return "openid";
        }
        //Default + the array-valued operators all accept arrays.
        return new List<object> { "openid", "profile" };
    }
}
