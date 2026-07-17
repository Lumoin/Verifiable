using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests for <see cref="FederationEffectiveMetadataResolver"/>.
/// </summary>
[TestClass]
internal sealed class FederationEffectiveMetadataResolverTests
{
    public TestContext TestContext { get; set; } = null!;

    private static readonly EntityTypeIdentifier RpType =
        WellKnownEntityTypeIdentifiers.OpenIdRelyingParty;

    private static readonly string[] ExpectedOverriddenGrantTypes = ["authorization_code", "refresh_token"];
    private static readonly string[] ExpectedTrimmedToAuthCode = ["authorization_code"];


    [TestMethod]
    public async Task ReturnsNullWhenSubjectDoesNotDeclareEntityType()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://subject.example.com"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://anchor.example.com"));

        //Subject EC has no metadata claim at all.
        MintedChain chain = await FederationTestRing.BuildDirectChainAsync(
            subject, anchor, now, now.AddHours(1),
            TestContext.CancellationToken).ConfigureAwait(false);

        MetadataPolicyApplyResult? result = await FederationEffectiveMetadataResolver.ResolveAsync(
            chain.Chain,
            RpType,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(result, "Resolver returns null when subject doesn't declare metadata for the type.");
    }


    [TestMethod]
    public async Task ReturnsDeclaredMetadataWhenNoPolicyInChain()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://subject.example.com"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://anchor.example.com"));

        Dictionary<string, object> rpMetadata = new(StringComparer.Ordinal)
        {
            ["jwks"] = new Dictionary<string, object>(StringComparer.Ordinal) { ["keys"] = new List<object>() },
            ["scope"] = "openid profile",
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [RpType.Value] = rpMetadata,
                },
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        MetadataPolicyApplyResult? result = await FederationEffectiveMetadataResolver.ResolveAsync(
            chain,
            RpType,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result);
        Assert.IsTrue(result.IsSuccess, $"Apply must succeed with empty policy. Reason: {result.FailureReason}");
        Assert.AreEqual("openid profile", result.EffectiveMetadata!["scope"],
            "Effective metadata == declared metadata when no policy in chain.");
    }


    [TestMethod]
    public async Task AnchorPolicyConstrainsDeclaredMetadataCleanly()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://subject.example.com"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://anchor.example.com"));

        Dictionary<string, object> rpMetadata = new(StringComparer.Ordinal)
        {
            ["grant_types"] = new List<object> { "authorization_code" },
        };

        Dictionary<string, object> anchorPolicy = new(StringComparer.Ordinal)
        {
            [RpType.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["grant_types"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["subset_of"] = new List<object> { "authorization_code", "refresh_token" },
                },
            },
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [RpType.Value] = rpMetadata,
                },
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.MetadataPolicy] = anchorPolicy,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        MetadataPolicyApplyResult? result = await FederationEffectiveMetadataResolver.ResolveAsync(
            chain,
            RpType,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result);
        Assert.IsTrue(result.IsSuccess);
        Assert.IsNotNull(result.EffectiveMetadata);
        Assert.IsTrue(result.EffectiveMetadata!.ContainsKey("grant_types"));
    }


    [TestMethod]
    public async Task ConstraintViolationReturnsFailure()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://subject.example.com"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://anchor.example.com"));

        //Subject declares grant_types=[authorization_code]; anchor's superset_of requires
        //refresh_token, which the subject lacks. Apply must fail (§6.1.3.1.6).
        Dictionary<string, object> rpMetadata = new(StringComparer.Ordinal)
        {
            ["grant_types"] = new List<object> { "authorization_code" },
        };

        Dictionary<string, object> anchorPolicy = new(StringComparer.Ordinal)
        {
            [RpType.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["grant_types"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["superset_of"] = new List<object> { "authorization_code", "refresh_token" },
                },
            },
        };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [RpType.Value] = rpMetadata,
                },
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.MetadataPolicy] = anchorPolicy,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustChain chain = new()
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };

        MetadataPolicyApplyResult? result = await FederationEffectiveMetadataResolver.ResolveAsync(
            chain,
            RpType,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(result);
        Assert.IsFalse(result.IsSuccess, "Constraint violation must surface as a failure.");
        Assert.IsNotNull(result.FailureReason);
    }


    [TestMethod]
    public async Task RemovesEntityTypeNotInAllowedEntityTypesConstraint()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        //Subject declares openid_relying_party, but the anchor's allowed_entity_types
        //permits only openid_provider — the RP type must be removed (§6.2.3).
        TrustChain chain = await BuildChainAsync(
            DeclareMetadata(RpType.Value),
            AllowedEntityTypesConstraint("openid_provider"),
            now).ConfigureAwait(false);

        MetadataPolicyApplyResult? result = await ResolveAsync(chain, RpType).ConfigureAwait(false);

        Assert.IsNull(result,
            "An entity type absent from allowed_entity_types must be removed (resolves to null).");
    }


    [TestMethod]
    public async Task KeepsEntityTypeListedInAllowedEntityTypesConstraint()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        TrustChain chain = await BuildChainAsync(
            DeclareMetadata(RpType.Value),
            AllowedEntityTypesConstraint("openid_relying_party"),
            now).ConfigureAwait(false);

        MetadataPolicyApplyResult? result = await ResolveAsync(chain, RpType).ConfigureAwait(false);

        Assert.IsNotNull(result, "An entity type listed in allowed_entity_types must be retained.");
        Assert.IsTrue(result.IsSuccess);
    }


    [TestMethod]
    public async Task NeverRemovesFederationEntityEvenWhenNotListed()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        //allowed_entity_types lists only openid_provider, yet federation_entity is always
        //allowed and MUST NOT be removed (§6.2.3).
        TrustChain chain = await BuildChainAsync(
            DeclareMetadata(WellKnownEntityTypeIdentifiers.FederationEntity.Value),
            AllowedEntityTypesConstraint("openid_provider"),
            now).ConfigureAwait(false);

        MetadataPolicyApplyResult? result = await ResolveAsync(
            chain, WellKnownEntityTypeIdentifiers.FederationEntity).ConfigureAwait(false);

        Assert.IsNotNull(result, "federation_entity is always allowed and must never be removed.");
        Assert.IsTrue(result.IsSuccess);
    }


    [TestMethod]
    public async Task EmptyAllowedEntityTypesRemovesEveryNonFederationType()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        //An empty array means only federation_entity is allowed (§6.2.3).
        TrustChain chain = await BuildChainAsync(
            DeclareMetadata(RpType.Value),
            AllowedEntityTypesConstraint(),
            now).ConfigureAwait(false);

        MetadataPolicyApplyResult? result = await ResolveAsync(chain, RpType).ConfigureAwait(false);

        Assert.IsNull(result,
            "An empty allowed_entity_types array removes every entity type except federation_entity.");
    }


    [TestMethod]
    public async Task ImmediateSuperiorMetadataOverridesSubjectDeclaration()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        //Subject declares grant_types=[authorization_code]; the immediate superior's
        //Subordinate Statement supplies grant_types=[authorization_code, refresh_token],
        //which overrides the subject's value (§3.1.1). No metadata_policy in the chain.
        Dictionary<string, object> subjectMetadata = new(StringComparer.Ordinal)
        {
            [RpType.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["grant_types"] = new List<object> { "authorization_code" },
            },
        };
        Dictionary<string, object> superiorClaims = new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [RpType.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["grant_types"] = new List<object> { "authorization_code", "refresh_token" },
                },
            },
        };

        TrustChain chain = await BuildChainAsync(subjectMetadata, superiorClaims, now).ConfigureAwait(false);
        MetadataPolicyApplyResult? result = await ResolveAsync(chain, RpType).ConfigureAwait(false);

        Assert.IsNotNull(result);
        Assert.IsTrue(result.IsSuccess, result.FailureReason);
        List<object> grantTypes = (List<object>)result.EffectiveMetadata!["grant_types"];
        CollectionAssert.AreEquivalent(ExpectedOverriddenGrantTypes, grantTypes);
    }


    [TestMethod]
    public async Task ImmediateSuperiorMetadataIsAppliedBeforePolicy()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        //Subject declares grant_types=[implicit] which subset_of alone would trim to the
        //empty array. The immediate superior overrides it with [authorization_code]; the
        //anchor's subset_of then keeps authorization_code — proving the metadata override
        //is applied before the policy (§6.1.4.2).
        Dictionary<string, object> subjectMetadata = new(StringComparer.Ordinal)
        {
            [RpType.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["grant_types"] = new List<object> { "implicit" },
            },
        };
        Dictionary<string, object> superiorClaims = new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [RpType.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["grant_types"] = new List<object> { "authorization_code" },
                },
            },
            [WellKnownFederationClaimNames.MetadataPolicy] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [RpType.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["grant_types"] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["subset_of"] = new List<object> { "authorization_code", "refresh_token" },
                    },
                },
            },
        };

        TrustChain chain = await BuildChainAsync(subjectMetadata, superiorClaims, now).ConfigureAwait(false);
        MetadataPolicyApplyResult? result = await ResolveAsync(chain, RpType).ConfigureAwait(false);

        Assert.IsNotNull(result);
        Assert.IsTrue(result.IsSuccess, result.FailureReason);
        List<object> grantTypes = (List<object>)result.EffectiveMetadata!["grant_types"];
        CollectionAssert.AreEqual(ExpectedTrimmedToAuthCode, grantTypes);
    }


    /// <summary>
    /// Builds a direct chain whose subject declares the given metadata-by-type and whose
    /// anchor Subordinate Statement carries the given extra claims (e.g. constraints).
    /// </summary>
    private async ValueTask<TrustChain> BuildChainAsync(
        Dictionary<string, object> subjectMetadataByType,
        Dictionary<string, object>? subordinateStatementExtraClaims,
        DateTimeOffset now)
    {
        using FederationTestRingNode subject = FederationTestRing.CreateNode(
            new EntityIdentifier("https://subject.example.com"));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(
            new EntityIdentifier("https://anchor.example.com"));

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subject, now, now.AddHours(1),
            extraClaims: new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.Metadata] = subjectMetadataByType,
            },
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, subject, now, now.AddHours(1),
            subordinateStatementExtraClaims,
            TestContext.CancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, now, now.AddHours(1),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        return new TrustChain
        {
            Statements = [subjectEc.Statement, anchorAboutSubject.Statement, anchorEc.Statement],
        };
    }


    /// <summary>
    /// Builds a subject metadata claim declaring a minimal block for one entity type.
    /// </summary>
    private static Dictionary<string, object> DeclareMetadata(string entityType) =>
        new(StringComparer.Ordinal)
        {
            [entityType] = new Dictionary<string, object>(StringComparer.Ordinal) { ["scope"] = "openid" },
        };


    /// <summary>
    /// Builds a constraints claim carrying <c>allowed_entity_types</c> with the given
    /// entity types.
    /// </summary>
    private static Dictionary<string, object> AllowedEntityTypesConstraint(params string[] types) =>
        new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.Constraints] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.AllowedEntityTypes] = new List<object>(types),
            },
        };


    private ValueTask<MetadataPolicyApplyResult?> ResolveAsync(TrustChain chain, EntityTypeIdentifier entityType) =>
        FederationEffectiveMetadataResolver.ResolveAsync(
            chain,
            entityType,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            TestContext.CancellationToken);
}
