using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.OAuth.Federation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Tests for <see cref="FederationAutomaticRegistration"/> — the OpenID
/// Federation 1.0 §12.1 automatic-registration engine. Each test builds a
/// real signed trust chain via <see cref="FederationTestRing"/>, validates it
/// through the production <see cref="InlineTrustChainValidationDriver"/>
/// (parse + per-link signature verify + <see cref="TrustChainValidator"/>),
/// and asserts the engine's admit/refuse decision and derived metadata.
/// </summary>
[TestClass]
internal sealed class FederationAutomaticRegistrationTests
{
    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly EntityTypeIdentifier RpType =
        WellKnownEntityTypeIdentifiers.OpenIdRelyingParty;

    private static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);


    [TestMethod]
    public async Task AdmitsRelyingPartyAndDerivesEffectiveMetadata()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        Dictionary<string, object> rpMetadata = new(StringComparer.Ordinal)
        {
            ["redirect_uris"] = new List<object> { "https://rp.example.com/cb" },
            ["scope"] = "openid profile",
            ["jwks"] = new Dictionary<string, object>(StringComparer.Ordinal) { ["keys"] = new List<object>() },
        };

        using ChainFixture fixture = await BuildChainAsync(
            new EntityIdentifier("https://rp.example.com"),
            new EntityIdentifier("https://anchor.example.com"),
            now,
            subjectMetadata: rpMetadata,
            anchorPolicy: null).ConfigureAwait(false);

        FederationAutomaticRegistrationResult result = await FederationAutomaticRegistration.ResolveAsync(
            fixture.CompactJwsByPosition,
            fixture.Subject,
            RpType,
            [fixture.Anchor],
            now,
            ClockSkew,
            fixture.ValidateChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsRegistered,
            $"A valid chain with declared RP metadata must register. Reason: {result.RejectionReason}");
        Assert.IsNull(result.RejectionReason);
        Assert.IsNotNull(result.EffectiveMetadata);
        Assert.AreEqual("openid profile", result.EffectiveMetadata!["scope"],
            "Effective metadata must carry the declared RP scope.");
        Assert.IsTrue(result.EffectiveMetadata.ContainsKey("redirect_uris"),
            "Effective metadata must carry the declared redirect_uris.");
        Assert.IsNotNull(result.Chain);
        Assert.IsNotNull(result.Assessment);
        Assert.IsTrue(result.Assessment!.IsTrusted);
        Assert.IsNotNull(result.ValidUntil,
            "The party-trust freshness assessor bounds validity to the chain's earliest exp.");
    }


    [TestMethod]
    public async Task RefusesWhenSubjectDoesNotMatchClientId()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        Dictionary<string, object> rpMetadata = new(StringComparer.Ordinal)
        {
            ["scope"] = "openid",
        };

        using ChainFixture fixture = await BuildChainAsync(
            new EntityIdentifier("https://rp.example.com"),
            new EntityIdentifier("https://anchor.example.com"),
            now,
            subjectMetadata: rpMetadata,
            anchorPolicy: null).ConfigureAwait(false);

        //Assert a client_id that is NOT the chain's subject.
        EntityIdentifier wrongClientId = new("https://attacker.example.com");

        FederationAutomaticRegistrationResult result = await FederationAutomaticRegistration.ResolveAsync(
            fixture.CompactJwsByPosition,
            wrongClientId,
            RpType,
            [fixture.Anchor],
            now,
            ClockSkew,
            fixture.ValidateChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsRegistered,
            "A chain whose subject differs from the asserted client_id must be refused.");
        Assert.IsNotNull(result.RejectionReason);
        Assert.Contains("does not match", result.RejectionReason!);
    }


    [TestMethod]
    public async Task RefusesWhenSubjectDeclaresNoRelyingPartyMetadata()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        using ChainFixture fixture = await BuildChainAsync(
            new EntityIdentifier("https://rp.example.com"),
            new EntityIdentifier("https://anchor.example.com"),
            now,
            subjectMetadata: null,
            anchorPolicy: null).ConfigureAwait(false);

        FederationAutomaticRegistrationResult result = await FederationAutomaticRegistration.ResolveAsync(
            fixture.CompactJwsByPosition,
            fixture.Subject,
            RpType,
            [fixture.Anchor],
            now,
            ClockSkew,
            fixture.ValidateChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsRegistered,
            "Automatic registration requires the RP to declare openid_relying_party metadata.");
        Assert.IsNotNull(result.RejectionReason);
        Assert.Contains("did not declare", result.RejectionReason!);
    }


    [TestMethod]
    public async Task RefusesWhenAnchorPolicyExcludesDeclaredMetadata()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        //Subject declares grant_types=[authorization_code]; the anchor's superset_of
        //policy requires refresh_token, which the subject lacks → policy application
        //fails (§6.1.3.1.6).
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

        using ChainFixture fixture = await BuildChainAsync(
            new EntityIdentifier("https://rp.example.com"),
            new EntityIdentifier("https://anchor.example.com"),
            now,
            subjectMetadata: rpMetadata,
            anchorPolicy: anchorPolicy).ConfigureAwait(false);

        FederationAutomaticRegistrationResult result = await FederationAutomaticRegistration.ResolveAsync(
            fixture.CompactJwsByPosition,
            fixture.Subject,
            RpType,
            [fixture.Anchor],
            now,
            ClockSkew,
            fixture.ValidateChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsRegistered,
            "A metadata-policy constraint violation must refuse automatic registration.");
        Assert.IsNotNull(result.RejectionReason);
    }


    [TestMethod]
    public async Task RefusesReversedChain()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        using ChainFixture fixture = await BuildChainAsync(
            new EntityIdentifier("https://rp.example.com"),
            new EntityIdentifier("https://anchor.example.com"),
            now,
            subjectMetadata: new Dictionary<string, object>(StringComparer.Ordinal) { ["scope"] = "openid" },
            anchorPolicy: null).ConfigureAwait(false);

        //Reversing the chain order means position 0 is no longer the subject's
        //Entity Configuration — the chain no longer starts at the subject and
        //its links no longer verify. Automatic registration must refuse.
        List<string> reversed = [.. fixture.CompactJwsByPosition];
        reversed.Reverse();

        FederationAutomaticRegistrationResult result = await FederationAutomaticRegistration.ResolveAsync(
            reversed,
            fixture.Subject,
            RpType,
            [fixture.Anchor],
            now,
            ClockSkew,
            fixture.ValidateChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsRegistered, "A reversed trust chain must be refused.");
        Assert.IsNotNull(result.RejectionReason);
    }


    [TestMethod]
    public async Task RefusesTruncatedChain()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        using ChainFixture fixture = await BuildChainAsync(
            new EntityIdentifier("https://rp.example.com"),
            new EntityIdentifier("https://anchor.example.com"),
            now,
            subjectMetadata: new Dictionary<string, object>(StringComparer.Ordinal) { ["scope"] = "openid" },
            anchorPolicy: null).ConfigureAwait(false);

        //Dropping the subject's Entity Configuration (keeping only the tail) breaks
        //the chain — it no longer starts at the subject. Must be refused.
        List<string> truncated = [.. fixture.CompactJwsByPosition.Skip(1)];

        FederationAutomaticRegistrationResult result = await FederationAutomaticRegistration.ResolveAsync(
            truncated,
            fixture.Subject,
            RpType,
            [fixture.Anchor],
            now,
            ClockSkew,
            fixture.ValidateChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsRegistered, "A truncated trust chain must be refused.");
        Assert.IsNotNull(result.RejectionReason);
    }


    [TestMethod]
    public async Task RefusesWhenTerminalAnchorNotTrusted()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        using ChainFixture fixture = await BuildChainAsync(
            new EntityIdentifier("https://rp.example.com"),
            new EntityIdentifier("https://anchor.example.com"),
            now,
            subjectMetadata: new Dictionary<string, object>(StringComparer.Ordinal) { ["scope"] = "openid" },
            anchorPolicy: null).ConfigureAwait(false);

        //A valid chain, but validated against a trust-anchor set that does NOT
        //include the chain's terminal anchor. The chain must not be trusted —
        //anchor scoping is the federation's outermost gate.
        EntityIdentifier unrelatedAnchor = new("https://other-anchor.example.com");

        FederationAutomaticRegistrationResult result = await FederationAutomaticRegistration.ResolveAsync(
            fixture.CompactJwsByPosition,
            fixture.Subject,
            RpType,
            [unrelatedAnchor],
            now,
            ClockSkew,
            fixture.ValidateChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsRegistered,
            "A chain terminating at an anchor outside the trust-anchor allow-list must be refused.");
        Assert.IsNotNull(result.RejectionReason);
    }


    [TestMethod]
    public async Task AdmitsThroughIntermediateWithStackedMetadataPolicy()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        //Leaf declares grant_types = [authorization_code]. The intermediate
        //and the anchor each tighten via subset_of; the merged policy still
        //admits authorization_code, so registration succeeds — proving the
        //engine resolves effective metadata through a real intermediate, not
        //just the direct chain.
        Dictionary<string, object> rpMetadata = new(StringComparer.Ordinal)
        {
            ["grant_types"] = new List<object> { "authorization_code" },
        };

        using LongChainFixture fixture = await BuildLongChainAsync(
            now,
            rpMetadata,
            WellKnownMetadataPolicyOperators.SubsetOf.Value,
            intermediatePolicyGrantTypes: ["authorization_code", "refresh_token", "implicit"],
            anchorPolicyGrantTypes: ["authorization_code", "refresh_token"]).ConfigureAwait(false);

        FederationAutomaticRegistrationResult result = await FederationAutomaticRegistration.ResolveAsync(
            fixture.CompactJwsByPosition,
            fixture.Subject,
            RpType,
            [fixture.Anchor],
            now,
            ClockSkew,
            fixture.ValidateChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsRegistered,
            $"A 5-element chain whose stacked policy still admits the declared grant must register. Reason: {result.RejectionReason}");
        Assert.IsNotNull(result.EffectiveMetadata);
        Assert.IsTrue(result.EffectiveMetadata!.ContainsKey("grant_types"),
            "Effective metadata must carry the policy-applied grant_types.");
    }


    [TestMethod]
    public async Task RefusesWhenAnchorPolicyDeeperInChainRequiresMissingGrant()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;

        //Leaf declares grant_types=[authorization_code]. The INTERMEDIATE superset_of
        //requires only authorization_code (satisfiable), but the ANCHOR superset_of (the
        //outer link of the longer chain) additionally requires refresh_token, which the
        //leaf lacks — so the merged policy fails application. This is the case the direct
        //(no-intermediate) chain cannot express: it proves the full chain's stacked policy
        //binds through §12.1.
        Dictionary<string, object> rpMetadata = new(StringComparer.Ordinal)
        {
            ["grant_types"] = new List<object> { "authorization_code" },
        };

        using LongChainFixture fixture = await BuildLongChainAsync(
            now,
            rpMetadata,
            WellKnownMetadataPolicyOperators.SupersetOf.Value,
            intermediatePolicyGrantTypes: ["authorization_code"],
            anchorPolicyGrantTypes: ["authorization_code", "refresh_token"]).ConfigureAwait(false);

        FederationAutomaticRegistrationResult result = await FederationAutomaticRegistration.ResolveAsync(
            fixture.CompactJwsByPosition,
            fixture.Subject,
            RpType,
            [fixture.Anchor],
            now,
            ClockSkew,
            fixture.ValidateChain,
            FederationDefaultHooks.EvaluateMetadataPolicy,
            FederationDefaultHooks.ApplyMetadataPolicy,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsRegistered,
            "The anchor's policy, deeper in the longer chain, must still bind and refuse the excluded grant.");
        Assert.IsNotNull(result.RejectionReason);
    }


    /// <summary>
    /// Builds a subject → intermediate → anchor (5-element) chain with the
    /// subject's <c>openid_relying_party</c> metadata and a <c>grant_types</c>
    /// policy using <paramref name="policyOperator"/> on BOTH the intermediate's
    /// and the anchor's Subordinate Statements, and wires a real
    /// <see cref="ValidateTrustChainAsyncDelegate"/> over it.
    /// </summary>
    private static async ValueTask<LongChainFixture> BuildLongChainAsync(
        DateTimeOffset now,
        IReadOnlyDictionary<string, object> subjectMetadata,
        string policyOperator,
        IReadOnlyList<string> intermediatePolicyGrantTypes,
        IReadOnlyList<string> anchorPolicyGrantTypes)
    {
        FederationTestRingNode subjectNode =
            FederationTestRing.CreateNode(new EntityIdentifier("https://rp.example.com"));
        FederationTestRingNode intermediateNode =
            FederationTestRing.CreateNode(new EntityIdentifier("https://intermediate.example.com"));
        FederationTestRingNode anchorNode =
            FederationTestRing.CreateNode(new EntityIdentifier("https://anchor.example.com"));

        IReadOnlyDictionary<string, object> subjectExtras = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [RpType.Value] = subjectMetadata,
            },
        };

        MintedChain chain = await FederationTestRing.BuildChainWithIntermediateAsync(
            subjectNode,
            intermediateNode,
            anchorNode,
            now,
            now.AddHours(1),
            subjectExtraClaims: subjectExtras,
            intermediateAboutSubjectExtraClaims: GrantTypesPolicy(policyOperator, intermediatePolicyGrantTypes),
            anchorAboutIntermediateExtraClaims: GrantTypesPolicy(policyOperator, anchorPolicyGrantTypes)).ConfigureAwait(false);

        ValidateTrustChainAsyncDelegate validateChain = InlineTrustChainValidationDriver.Build(
            async (position, jws, ct) => position switch
            {
                0 => await FederationTestRing.VerifyAsync(subjectNode, jws, ct).ConfigureAwait(false),
                1 or 2 => await FederationTestRing.VerifyAsync(intermediateNode, jws, ct).ConfigureAwait(false),
                _ => await FederationTestRing.VerifyAsync(anchorNode, jws, ct).ConfigureAwait(false),
            });

        return new LongChainFixture(
            subjectNode, intermediateNode, anchorNode,
            subjectNode.Identifier, anchorNode.Identifier,
            chain.CompactJwsByPosition, validateChain);
    }


    private static Dictionary<string, object> GrantTypesPolicy(string policyOperator, IReadOnlyList<string> values) =>
        new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.MetadataPolicy] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [RpType.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["grant_types"] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [policyOperator] = new List<object>(values),
                    },
                },
            },
        };


    private sealed class LongChainFixture(
        FederationTestRingNode subjectNode,
        FederationTestRingNode intermediateNode,
        FederationTestRingNode anchorNode,
        EntityIdentifier subject,
        EntityIdentifier anchor,
        IReadOnlyList<string> compactJwsByPosition,
        ValidateTrustChainAsyncDelegate validateChain): IDisposable
    {
        public EntityIdentifier Subject { get; } = subject;

        public EntityIdentifier Anchor { get; } = anchor;

        public IReadOnlyList<string> CompactJwsByPosition { get; } = compactJwsByPosition;

        public ValidateTrustChainAsyncDelegate ValidateChain { get; } = validateChain;

        public void Dispose()
        {
            subjectNode.Dispose();
            intermediateNode.Dispose();
            anchorNode.Dispose();
        }
    }


    /// <summary>
    /// Builds a subject → anchor direct chain (subject EC + anchor's
    /// subordinate statement + anchor EC), optionally injecting the subject's
    /// <c>openid_relying_party</c> metadata and the anchor's metadata policy,
    /// and wires a real <see cref="ValidateTrustChainAsyncDelegate"/> over it.
    /// </summary>
    private static async ValueTask<ChainFixture> BuildChainAsync(
        EntityIdentifier subjectId,
        EntityIdentifier anchorId,
        DateTimeOffset now,
        IReadOnlyDictionary<string, object>? subjectMetadata,
        IReadOnlyDictionary<string, object>? anchorPolicy)
    {
        FederationTestRingNode subjectNode = FederationTestRing.CreateNode(subjectId);
        FederationTestRingNode anchorNode = FederationTestRing.CreateNode(anchorId);

        IReadOnlyDictionary<string, object>? subjectExtras = subjectMetadata is null
            ? null
            : new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [RpType.Value] = subjectMetadata,
                },
            };

        IReadOnlyDictionary<string, object>? anchorAboutSubjectExtras = anchorPolicy is null
            ? null
            : new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownFederationClaimNames.MetadataPolicy] = anchorPolicy,
            };

        MintedStatement subjectEc = await FederationTestRing.MintEntityConfigurationAsync(
            subjectNode, now, now.AddHours(1), subjectExtras).ConfigureAwait(false);
        MintedStatement anchorAboutSubject = await FederationTestRing.MintSubordinateStatementAsync(
            anchorNode, subjectNode, now, now.AddHours(1), anchorAboutSubjectExtras).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchorNode, now, now.AddHours(1)).ConfigureAwait(false);

        List<string> compactJwsByPosition =
            [subjectEc.CompactJws, anchorAboutSubject.CompactJws, anchorEc.CompactJws];

        ValidateTrustChainAsyncDelegate validateChain = InlineTrustChainValidationDriver.Build(
            async (position, jws, ct) => position == 0
                ? await FederationTestRing.VerifyAsync(subjectNode, jws, ct).ConfigureAwait(false)
                : await FederationTestRing.VerifyAsync(anchorNode, jws, ct).ConfigureAwait(false));

        return new ChainFixture(subjectNode, anchorNode, subjectId, anchorId, compactJwsByPosition, validateChain);
    }


    private sealed class ChainFixture(
        FederationTestRingNode subjectNode,
        FederationTestRingNode anchorNode,
        EntityIdentifier subject,
        EntityIdentifier anchor,
        IReadOnlyList<string> compactJwsByPosition,
        ValidateTrustChainAsyncDelegate validateChain): IDisposable
    {
        public EntityIdentifier Subject { get; } = subject;

        public EntityIdentifier Anchor { get; } = anchor;

        public IReadOnlyList<string> CompactJwsByPosition { get; } = compactJwsByPosition;

        public ValidateTrustChainAsyncDelegate ValidateChain { get; } = validateChain;

        public void Dispose()
        {
            subjectNode.Dispose();
            anchorNode.Dispose();
        }
    }
}
