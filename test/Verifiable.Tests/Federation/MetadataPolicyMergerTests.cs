using Verifiable.OAuth.Federation;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests for <see cref="MetadataPolicyMerger"/> against the
/// §6.1.4.1 per-operator merge rules.
/// </summary>
[TestClass]
internal sealed class MetadataPolicyMergerTests
{
    private static readonly EntityTypeIdentifier RpType =
        WellKnownEntityTypeIdentifiers.OpenIdRelyingParty;

    private static readonly string[] ProfileEmail = ["profile", "email"];
    private static readonly string[] OpenIdProfile = ["openid", "profile"];


    [TestMethod]
    public void MergingEmptyWithEmptyYieldsEmpty()
    {
        EntityTypeMetadataPolicy upstream = MakeBlock();
        EntityTypeMetadataPolicy downstream = MakeBlock();

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsTrue(result.IsSuccess);
        Assert.HasCount(0, result.MergedBlock!.ParameterPolicies);
    }


    [TestMethod]
    public void NonOverlappingParametersBothCarryThrough()
    {
        EntityTypeMetadataPolicy upstream = MakeBlock(
            ("grant_types",
                (WellKnownMetadataPolicyOperators.SubsetOf, (object)new List<object> { "authorization_code" })));
        EntityTypeMetadataPolicy downstream = MakeBlock(
            ("id_token_signed_response_alg",
                (WellKnownMetadataPolicyOperators.OneOf, (object)new List<object> { "ES256" })));

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsTrue(result.IsSuccess);
        Assert.HasCount(2, result.MergedBlock!.ParameterPolicies);
    }


    [TestMethod]
    public void SubsetOfMergesViaIntersection()
    {
        EntityTypeMetadataPolicy upstream = MakeBlock(
            ("scope",
                (WellKnownMetadataPolicyOperators.SubsetOf, (object)new List<object> { "openid", "profile", "email" })));
        EntityTypeMetadataPolicy downstream = MakeBlock(
            ("scope",
                (WellKnownMetadataPolicyOperators.SubsetOf, (object)new List<object> { "profile", "email", "address" })));

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsTrue(result.IsSuccess);
        ParameterPolicy merged = result.MergedBlock!.ParameterPolicies["scope"];
        List<object> subsetOf = (List<object>)merged.Operators[WellKnownMetadataPolicyOperators.SubsetOf];
        CollectionAssert.AreEquivalent(ProfileEmail, subsetOf);
    }


    [TestMethod]
    public void SubsetOfEmptyIntersectionIsConflict()
    {
        EntityTypeMetadataPolicy upstream = MakeBlock(
            ("scope",
                (WellKnownMetadataPolicyOperators.SubsetOf, (object)new List<object> { "openid" })));
        EntityTypeMetadataPolicy downstream = MakeBlock(
            ("scope",
                (WellKnownMetadataPolicyOperators.SubsetOf, (object)new List<object> { "profile" })));

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsFalse(result.IsSuccess);
        Assert.Contains("Intersection", result.FailureReason!);
    }


    [TestMethod]
    public void AddMergesViaUnion()
    {
        EntityTypeMetadataPolicy upstream = MakeBlock(
            ("scope",
                (WellKnownMetadataPolicyOperators.Add, (object)new List<object> { "openid" })));
        EntityTypeMetadataPolicy downstream = MakeBlock(
            ("scope",
                (WellKnownMetadataPolicyOperators.Add, (object)new List<object> { "profile" })));

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsTrue(result.IsSuccess);
        ParameterPolicy merged = result.MergedBlock!.ParameterPolicies["scope"];
        List<object> add = (List<object>)merged.Operators[WellKnownMetadataPolicyOperators.Add];
        CollectionAssert.AreEquivalent(OpenIdProfile, add);
    }


    [TestMethod]
    public void EssentialMergesViaLogicalOr()
    {
        EntityTypeMetadataPolicy upstream = MakeBlock(
            ("scope", (WellKnownMetadataPolicyOperators.Essential, (object)false)));
        EntityTypeMetadataPolicy downstream = MakeBlock(
            ("scope", (WellKnownMetadataPolicyOperators.Essential, (object)true)));

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsTrue(result.IsSuccess);
        ParameterPolicy merged = result.MergedBlock!.ParameterPolicies["scope"];
        Assert.IsTrue((bool)merged.Operators[WellKnownMetadataPolicyOperators.Essential]);
    }


    [TestMethod]
    public void ValueConflictRejects()
    {
        EntityTypeMetadataPolicy upstream = MakeBlock(
            ("scope", (WellKnownMetadataPolicyOperators.Value, (object)"openid")));
        EntityTypeMetadataPolicy downstream = MakeBlock(
            ("scope", (WellKnownMetadataPolicyOperators.Value, (object)"profile")));

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsFalse(result.IsSuccess);
        Assert.Contains("Conflicting 'value'", result.FailureReason!);
    }


    [TestMethod]
    public void ValueEqualOnBothSidesMerges()
    {
        EntityTypeMetadataPolicy upstream = MakeBlock(
            ("scope", (WellKnownMetadataPolicyOperators.Value, (object)"openid")));
        EntityTypeMetadataPolicy downstream = MakeBlock(
            ("scope", (WellKnownMetadataPolicyOperators.Value, (object)"openid")));

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsTrue(result.IsSuccess);
        Assert.AreEqual("openid", result.MergedBlock!.ParameterPolicies["scope"].Operators[WellKnownMetadataPolicyOperators.Value]);
    }


    [TestMethod]
    public void IncompatibleResultingOperatorCombinationRejects()
    {
        //Upstream has subset_of, downstream has value: merged would have both,
        //which the §6.1.3.1.8 table forbids. Merge rejects with the
        //post-merge combination check.
        EntityTypeMetadataPolicy upstream = MakeBlock(
            ("scope",
                (WellKnownMetadataPolicyOperators.SubsetOf, (object)new List<object> { "openid", "profile" })));
        EntityTypeMetadataPolicy downstream = MakeBlock(
            ("scope", (WellKnownMetadataPolicyOperators.Value, (object)"openid")));

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsFalse(result.IsSuccess);
        Assert.Contains("incompatible operators", result.FailureReason!);
    }


    [TestMethod]
    public void MismatchedEntityTypesRejects()
    {
        EntityTypeMetadataPolicy upstream = new()
        {
            EntityType = WellKnownEntityTypeIdentifiers.OpenIdRelyingParty,
            ParameterPolicies = new Dictionary<string, ParameterPolicy>(),
        };
        EntityTypeMetadataPolicy downstream = new()
        {
            EntityType = WellKnownEntityTypeIdentifiers.OpenIdProvider,
            ParameterPolicies = new Dictionary<string, ParameterPolicy>(),
        };

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsFalse(result.IsSuccess);
        Assert.Contains("different entity types", result.FailureReason!);
    }


    [TestMethod]
    public void SnapshotLevelMergeCombinesAcrossEntityTypes()
    {
        MetadataPolicySnapshot upstream = new()
        {
            EntityTypes = new Dictionary<EntityTypeIdentifier, EntityTypeMetadataPolicy>
            {
                [WellKnownEntityTypeIdentifiers.OpenIdRelyingParty] = MakeBlock(
                    ("scope",
                        (WellKnownMetadataPolicyOperators.SubsetOf, (object)new List<object> { "openid", "profile" }))),
            },
        };
        MetadataPolicySnapshot downstream = new()
        {
            EntityTypes = new Dictionary<EntityTypeIdentifier, EntityTypeMetadataPolicy>
            {
                [WellKnownEntityTypeIdentifiers.OpenIdProvider] = MakeBlock(
                    ("scope",
                        (WellKnownMetadataPolicyOperators.SubsetOf, (object)new List<object> { "openid" })))
                with
                {
                    EntityType = WellKnownEntityTypeIdentifiers.OpenIdProvider,
                },
            },
        };

        MetadataPolicyMergeResult result = MetadataPolicyMerger.Merge(upstream, downstream);

        Assert.IsTrue(result.IsSuccess);
        Assert.HasCount(2, result.MergedSnapshot!.EntityTypes);
    }


    private static EntityTypeMetadataPolicy MakeBlock(
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
}
