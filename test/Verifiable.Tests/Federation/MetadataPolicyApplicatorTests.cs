using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests for <see cref="MetadataPolicyApplicator"/> against the
/// §6.1.4.2 application order: value → add → default →
/// one_of/subset_of/superset_of constraints → essential.
/// </summary>
[TestClass]
internal sealed class MetadataPolicyApplicatorTests
{
    private static readonly EntityTypeIdentifier RpType =
        WellKnownEntityTypeIdentifiers.OpenIdRelyingParty;

    private static readonly string[] ExpectedAddedScope = ["openid", "profile", "email"];
    private static readonly string[] ExpectedDefaultScope = ["openid", "profile"];
    private static readonly string[] ExpectedTrimmedGrantTypes = ["authorization_code"];


    [TestMethod]
    public void EmptyPolicyReturnsDeclaredMetadataUnchanged()
    {
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>
        {
            ["scope"] = "openid",
        };
        EntityTypeMetadataPolicy policy = MakePolicy();

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("openid", result.EffectiveMetadata!["scope"]);
    }


    [TestMethod]
    public void ValueOperatorReplacesParameter()
    {
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>
        {
            ["scope"] = "openid",
        };
        EntityTypeMetadataPolicy policy = MakePolicy(
            ("scope", (WellKnownMetadataPolicyOperators.Value, (object)"openid profile email")));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("openid profile email", result.EffectiveMetadata!["scope"]);
    }


    [TestMethod]
    public void AddOperatorAppendsToDeclaredArray()
    {
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>
        {
            ["scope"] = new List<object> { "openid", "profile" },
        };
        EntityTypeMetadataPolicy policy = MakePolicy(
            ("scope", (WellKnownMetadataPolicyOperators.Add, (object)new List<object> { "email" })));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsTrue(result.IsSuccess);
        List<object> scope = (List<object>)result.EffectiveMetadata!["scope"];
        Assert.AreSequenceEqual(ExpectedAddedScope, scope, SequenceOrder.InAnyOrder);
    }


    [TestMethod]
    public void DefaultOperatorAppliesWhenParameterAbsent()
    {
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>();
        EntityTypeMetadataPolicy policy = MakePolicy(
            ("scope", (WellKnownMetadataPolicyOperators.Default, (object)new List<object> { "openid", "profile" })));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsTrue(result.IsSuccess);
        List<object> scope = (List<object>)result.EffectiveMetadata!["scope"];
        Assert.AreSequenceEqual(ExpectedDefaultScope, scope, SequenceOrder.InAnyOrder);
    }


    [TestMethod]
    public void DefaultOperatorSkippedWhenParameterPresent()
    {
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>
        {
            ["scope"] = "declared_value",
        };
        EntityTypeMetadataPolicy policy = MakePolicy(
            ("scope", (WellKnownMetadataPolicyOperators.Default, (object)"default_value")));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("declared_value", result.EffectiveMetadata!["scope"]);
    }


    [TestMethod]
    public void OneOfConstraintFailsForOutOfSetValue()
    {
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>
        {
            ["id_token_signed_response_alg"] = "HS256",
        };
        EntityTypeMetadataPolicy policy = MakePolicy(
            ("id_token_signed_response_alg",
                (WellKnownMetadataPolicyOperators.OneOf, (object)new List<object> { "ES256", "PS256" })));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsFalse(result.IsSuccess);
        Assert.Contains("one_of", result.FailureReason!);
    }


    [TestMethod]
    public void SubsetOfTrimsArrayToIntersection()
    {
        //§6.1.3.1.5 / Table 1: subset_of drops values outside the operator set rather
        //than failing. Input [authorization_code, implicit] ∩ [authorization_code,
        //refresh_token] = [authorization_code].
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>
        {
            ["grant_types"] = new List<object> { "authorization_code", "implicit" },
        };
        EntityTypeMetadataPolicy policy = MakePolicy(
            ("grant_types",
                (WellKnownMetadataPolicyOperators.SubsetOf, (object)new List<object> { "authorization_code", "refresh_token" })));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsTrue(result.IsSuccess);
        List<object> grantTypes = (List<object>)result.EffectiveMetadata!["grant_types"];
        Assert.AreSequenceEqual(ExpectedTrimmedGrantTypes, grantTypes);
    }


    [TestMethod]
    public void SubsetOfTrimsToEmptyArrayWhenDisjoint()
    {
        //§6.1.3.1.5 / Table 1: a disjoint intersection yields the empty array, not a failure.
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>
        {
            ["grant_types"] = new List<object> { "implicit" },
        };
        EntityTypeMetadataPolicy policy = MakePolicy(
            ("grant_types",
                (WellKnownMetadataPolicyOperators.SubsetOf, (object)new List<object> { "authorization_code", "refresh_token" })));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsTrue(result.IsSuccess);
        List<object> grantTypes = (List<object>)result.EffectiveMetadata!["grant_types"];
        Assert.IsEmpty(grantTypes);
    }


    [TestMethod]
    public void SupersetOfConstraintFailsForMissingRequiredValue()
    {
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>
        {
            ["scope"] = new List<object> { "profile" },
        };
        EntityTypeMetadataPolicy policy = MakePolicy(
            ("scope",
                (WellKnownMetadataPolicyOperators.SupersetOf, (object)new List<object> { "openid" })));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsFalse(result.IsSuccess);
        Assert.Contains("superset_of", result.FailureReason!);
    }


    [TestMethod]
    public void EssentialFailsWhenParameterAbsent()
    {
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>();
        EntityTypeMetadataPolicy policy = MakePolicy(
            ("scope", (WellKnownMetadataPolicyOperators.Essential, (object)true)));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsFalse(result.IsSuccess);
        Assert.Contains("Essential parameter", result.FailureReason!);
    }


    [TestMethod]
    public void EssentialWithNonBooleanValueFails()
    {
        //§6.1.3.1.7: essential's only mandatory operator value type is boolean. A string
        //"true" must be a policy error, not a silently-ignored (non-essential) parameter.
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>();
        EntityTypeMetadataPolicy policy = MakePolicy(
            ("scope", (WellKnownMetadataPolicyOperators.Essential, (object)"true")));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsFalse(result.IsSuccess);
        Assert.Contains("essential", result.FailureReason!);
    }


    [TestMethod]
    public void EssentialSucceedsWhenDefaultSuppliesValue()
    {
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>();
        EntityTypeMetadataPolicy policy = MakePolicyMulti(
            "scope",
            (WellKnownMetadataPolicyOperators.Default, "openid"),
            (WellKnownMetadataPolicyOperators.Essential, true));

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, policy);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("openid", result.EffectiveMetadata!["scope"]);
    }


    [TestMethod]
    public void RawDictOverloadParsesAndApplies()
    {
        IReadOnlyDictionary<string, object> declared = new Dictionary<string, object>
        {
            ["scope"] = "openid",
        };
        IReadOnlyDictionary<string, object> rawPolicy = new Dictionary<string, object>
        {
            ["scope"] = new Dictionary<string, object>
            {
                ["value"] = "openid profile",
            },
        };

        MetadataPolicyApplyResult result = MetadataPolicyApplicator.Apply(declared, rawPolicy, RpType);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("openid profile", result.EffectiveMetadata!["scope"]);
    }


    private static EntityTypeMetadataPolicy MakePolicy(
        params (string ParameterName, (MetadataPolicyOperator Operator, object Value) Operator)[] parameters)
    {
        Dictionary<string, ParameterPolicy> parameterPolicies = [];
        foreach((string name, (MetadataPolicyOperator op, object value)) in parameters)
        {
            parameterPolicies[name] = new ParameterPolicy
            {
                ParameterName = name,
                Operators = new Dictionary<MetadataPolicyOperator, object> { [op] = value },
            };
        }

        return new EntityTypeMetadataPolicy
        {
            EntityType = RpType,
            ParameterPolicies = parameterPolicies,
        };
    }


    private static EntityTypeMetadataPolicy MakePolicyMulti(
        string parameterName,
        params (MetadataPolicyOperator Operator, object Value)[] operators)
    {
        Dictionary<MetadataPolicyOperator, object> ops = [];
        foreach((MetadataPolicyOperator op, object value) in operators)
        {
            ops[op] = value;
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
}
