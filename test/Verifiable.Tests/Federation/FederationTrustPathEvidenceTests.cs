using Microsoft.Extensions.Time.Testing;
using System.Collections.Generic;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Model.Dcql;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.Federation;

/// <summary>
/// Proves the <c>openid_federation</c> evidence arm — <see cref="FederationTrustPathEvidence.ResolveAsync"/>
/// and its composition through <see cref="TrustedAuthorityEvidenceResolution.Build"/> — realises the
/// matching rule of
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">OpenID
/// for Verifiable Presentations 1.0, Section 6.1.1.3</see>: "A valid trust path, including the given Entity
/// Identifier, must be constructible from a matching credential", and does so purely over the wallet's own
/// familiar Trust Anchors so no Verifier-supplied URL is ever dereferenced, per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">Section
/// 15.10</see>. The federation graphs are minted in-process by <see cref="FederationTestRing"/> and the
/// certificate chains by <see cref="X509ChainTestRing"/>; the expected subject identifiers are derived from
/// each chain's own topology, never read back through the resolver under test.
/// </summary>
[TestClass]
internal sealed class FederationTrustPathEvidenceTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The Entity Identifier of the credential issuer at the leaf of the minted trust path.</summary>
    private const string LeafId = "https://leaf.example.com";

    /// <summary>The Entity Identifier of the intermediate on the minted trust path.</summary>
    private const string IntermediateId = "https://intermediate.example.com";

    /// <summary>The Entity Identifier of the Trust Anchor terminating the minted trust path.</summary>
    private const string AnchorId = "https://anchor.example.com";

    /// <summary>An Entity Identifier the leaf never chains to — a familiar anchor with no valid path from the leaf.</summary>
    private const string StrangerAnchorId = "https://stranger-anchor.example.com";

    /// <summary>The intermediate's <c>federation_fetch_endpoint</c>, from which its Subordinate Statements are retrieved.</summary>
    private const string IntermediateFetch = "https://intermediate.example.com/fetch";

    /// <summary>The anchor's <c>federation_fetch_endpoint</c>, from which its Subordinate Statements are retrieved.</summary>
    private const string AnchorFetch = "https://anchor.example.com/fetch";

    /// <summary>The Microsoft-backend name selecting <see cref="MicrosoftX509Functions"/>'s certificate readers.</summary>
    private const string MicrosoftBackend = "Microsoft";

    /// <summary>The BouncyCastle-backend name selecting <see cref="BouncyCastleX509Functions"/>'s certificate readers.</summary>
    private const string BouncyCastleBackend = "BouncyCastle";


    /// <summary>Deserializes a compact JWS header segment for <see cref="TrustChainValidation.BuildInlineValidator"/>.</summary>
    private static JwtHeaderDeserializer HeaderDeserializer { get; } = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Header JSON parsed to null.");

    /// <summary>Deserializes a compact JWS payload segment for <see cref="TrustChainValidation.BuildInlineValidator"/>.</summary>
    private static JwtPayloadDeserializer PayloadDeserializer { get; } = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Payload JSON parsed to null.");


    /// <summary>
    /// Proves
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.3</see>'s "A valid trust path, including the given
    /// Entity Identifier, must be constructible from a matching credential": for a leaf &#8594; intermediate
    /// &#8594; anchor chain whose anchor is a familiar Trust Anchor, the resolved evidence is exactly the set
    /// of every Entity Identifier on the validated path — the leaf's, the intermediate's and the anchor's.
    /// </summary>
    [TestMethod]
    public async Task ResolveReturnsEveryEntityIdentifierOnAValidatedPathThroughAnIntermediate()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        FederationGraph graph = await BuildLeafIntermediateAnchorGraphAsync(
            now, forgeIntermediateSubordinate: false, TestContext.CancellationToken).ConfigureAwait(false);

        FetchCounters counters = new();
        (FetchEntityConfigurationDelegate fetchConfiguration, FetchEntityStatementDelegate fetchSubordinate) =
            BuildFetchDelegates(graph, counters);

        IReadOnlySet<EntityIdentifier> entities = await FederationTrustPathEvidence.ResolveAsync(
            graph.Leaf,
            [graph.Anchor],
            fetchConfiguration,
            fetchSubordinate,
            BuildValidator(),
            new ExchangeContext(),
            maxChainLength: 5,
            validationTime: now,
            clockSkew: TimeSpan.FromMinutes(5),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, entities,
            "§6.1.1.3: the resolved evidence is every subject on the validated path — leaf, intermediate and anchor.");
        Assert.Contains(graph.Leaf, entities,
            "§6.1.1.3: the leaf issuer's Entity Identifier is a subject on the validated path and must be present.");
        Assert.Contains(graph.Intermediate, entities,
            "§6.1.1.3: the intermediate's Entity Identifier is a subject on the validated path and must be present.");
        Assert.Contains(graph.Anchor, entities,
            "§6.1.1.3: the anchor's Entity Identifier is a subject on the validated path and must be present.");
    }


    /// <summary>
    /// Proves
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">OpenID
    /// for Verifiable Presentations 1.0, Section 15.10</see>'s "Wallets SHOULD NOT access URLs included in a
    /// request from the Verifier if those URLs are unfamiliar ... treated purely as identifiers and not
    /// actually retrieved by the Wallet upon receiving the request": with an empty familiar-anchor set the
    /// resolver both yields nothing and never invokes either fetch delegate — resolution is bounded entirely
    /// by the wallet's own anchors.
    /// </summary>
    [TestMethod]
    public async Task EmptyFamiliarAnchorSetResolvesToEmptyWithoutAnyFetch()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        FederationGraph graph = await BuildLeafIntermediateAnchorGraphAsync(
            now, forgeIntermediateSubordinate: false, TestContext.CancellationToken).ConfigureAwait(false);

        FetchCounters counters = new();
        (FetchEntityConfigurationDelegate fetchConfiguration, FetchEntityStatementDelegate fetchSubordinate) =
            BuildFetchDelegates(graph, counters);

        IReadOnlySet<EntityIdentifier> entities = await FederationTrustPathEvidence.ResolveAsync(
            graph.Leaf,
            [],
            fetchConfiguration,
            fetchSubordinate,
            BuildValidator(),
            new ExchangeContext(),
            maxChainLength: 5,
            validationTime: now,
            clockSkew: TimeSpan.FromMinutes(5),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(0, entities,
            "§6.1.1.3: with no familiar anchor there is no path to any of them, so the evidence is empty.");
        Assert.AreEqual(0, counters.ConfigurationFetches,
            "§15.10: with no familiar anchor the resolver must dereference no Entity Configuration URL.");
        Assert.AreEqual(0, counters.SubordinateFetches,
            "§15.10: with no familiar anchor the resolver must dereference no Subordinate Statement URL.");
    }


    /// <summary>
    /// Proves
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.3</see>'s "A valid trust path, including the given
    /// Entity Identifier, must be constructible from a matching credential": a familiar anchor the leaf does
    /// not chain to yields no evidence — the path cannot be constructed to it.
    /// </summary>
    [TestMethod]
    public async Task AnUnreachableFamiliarAnchorResolvesToEmpty()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        FederationGraph graph = await BuildLeafIntermediateAnchorGraphAsync(
            now, forgeIntermediateSubordinate: false, TestContext.CancellationToken).ConfigureAwait(false);

        FetchCounters counters = new();
        (FetchEntityConfigurationDelegate fetchConfiguration, FetchEntityStatementDelegate fetchSubordinate) =
            BuildFetchDelegates(graph, counters);

        IReadOnlySet<EntityIdentifier> entities = await FederationTrustPathEvidence.ResolveAsync(
            graph.Leaf,
            [new EntityIdentifier(StrangerAnchorId)],
            fetchConfiguration,
            fetchSubordinate,
            BuildValidator(),
            new ExchangeContext(),
            maxChainLength: 5,
            validationTime: now,
            clockSkew: TimeSpan.FromMinutes(5),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(0, entities,
            "§6.1.1.3: no valid path reaches the stranger anchor, so no Entity Identifier is contributed.");
    }


    /// <summary>
    /// Proves
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.3</see>'s "A <em>valid</em> trust path ... must be
    /// constructible": a chain whose intermediate-issued Subordinate Statement is signed by a foreign key is
    /// rejected by the shipped
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-10.2">OpenID Federation 1.0,
    /// Section 10.2</see> validation, so the assembled-but-invalid chain contributes no Entity Identifiers.
    /// </summary>
    [TestMethod]
    public async Task AForgedSubordinateSignatureContributesNoEntities()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        FederationGraph graph = await BuildLeafIntermediateAnchorGraphAsync(
            now, forgeIntermediateSubordinate: true, TestContext.CancellationToken).ConfigureAwait(false);

        FetchCounters counters = new();
        (FetchEntityConfigurationDelegate fetchConfiguration, FetchEntityStatementDelegate fetchSubordinate) =
            BuildFetchDelegates(graph, counters);

        IReadOnlySet<EntityIdentifier> entities = await FederationTrustPathEvidence.ResolveAsync(
            graph.Leaf,
            [graph.Anchor],
            fetchConfiguration,
            fetchSubordinate,
            BuildValidator(),
            new ExchangeContext(),
            maxChainLength: 5,
            validationTime: now,
            clockSkew: TimeSpan.FromMinutes(5),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(0, entities,
            "Federation §10.2: a chain carrying a forged Subordinate Statement signature is not valid, so it contributes no entities.");
    }


    /// <summary>
    /// Proves
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.3</see>'s "A valid trust path ... must be
    /// constructible": a familiar anchor whose bounded path length is too short to reach it from the leaf
    /// yields no evidence — the path is not constructible within the caller's <c>maxChainLength</c> bound.
    /// </summary>
    [TestMethod]
    public async Task AMaxChainLengthTooShortForThePathResolvesToEmpty()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        FederationGraph graph = await BuildLeafIntermediateAnchorGraphAsync(
            now, forgeIntermediateSubordinate: false, TestContext.CancellationToken).ConfigureAwait(false);

        FetchCounters counters = new();
        (FetchEntityConfigurationDelegate fetchConfiguration, FetchEntityStatementDelegate fetchSubordinate) =
            BuildFetchDelegates(graph, counters);

        //Two entities is one short of the leaf -> intermediate -> anchor path's three, so the walk backtracks
        //without reaching the anchor and no chain is assembled.
        IReadOnlySet<EntityIdentifier> entities = await FederationTrustPathEvidence.ResolveAsync(
            graph.Leaf,
            [graph.Anchor],
            fetchConfiguration,
            fetchSubordinate,
            BuildValidator(),
            new ExchangeContext(),
            maxChainLength: 2,
            validationTime: now,
            clockSkew: TimeSpan.FromMinutes(5),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(0, entities,
            "§6.1.1.3: a path that cannot be constructed within the bound contributes no Entity Identifiers.");
    }


    /// <summary>
    /// Proves
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1.3">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1.3</see>'s "A valid trust path ... must be
    /// constructible" over a set of familiar anchors: given two familiar anchors of which only one is
    /// reachable, exactly the reachable path's subjects are resolved — the unreachable anchor adds nothing.
    /// </summary>
    [TestMethod]
    public async Task OnlyTheReachableAnchorsPathContributesSubjects()
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        FederationGraph graph = await BuildLeafIntermediateAnchorGraphAsync(
            now, forgeIntermediateSubordinate: false, TestContext.CancellationToken).ConfigureAwait(false);

        FetchCounters counters = new();
        (FetchEntityConfigurationDelegate fetchConfiguration, FetchEntityStatementDelegate fetchSubordinate) =
            BuildFetchDelegates(graph, counters);

        IReadOnlySet<EntityIdentifier> entities = await FederationTrustPathEvidence.ResolveAsync(
            graph.Leaf,
            [graph.Anchor, new EntityIdentifier(StrangerAnchorId)],
            fetchConfiguration,
            fetchSubordinate,
            BuildValidator(),
            new ExchangeContext(),
            maxChainLength: 5,
            validationTime: now,
            clockSkew: TimeSpan.FromMinutes(5),
            BaseMemoryPool.Shared,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(3, entities,
            "§6.1.1.3: only the reachable anchor's path contributes subjects; the unreachable anchor adds none.");
        Assert.Contains(graph.Leaf, entities,
            "§6.1.1.3: the leaf's Entity Identifier is a subject on the one reachable path.");
        Assert.Contains(graph.Intermediate, entities,
            "§6.1.1.3: the intermediate's Entity Identifier is a subject on the one reachable path.");
        Assert.Contains(graph.Anchor, entities,
            "§6.1.1.3: the reachable anchor's Entity Identifier is a subject on its own validated path.");
    }


    /// <summary>
    /// Proves
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.1.1">OpenID
    /// for Verifiable Presentations 1.0, Section 6.1.1</see>'s composition of the registered types: when
    /// <see cref="TrustedAuthorityEvidenceResolution.Build"/> is given an <c>openid_federation</c> arm over a
    /// reachable path and a certificate chain for the <c>aki</c> arm, the resolved evidence carries exactly
    /// the federation resolver's subject set in <see cref="TrustedAuthorityEvidence.FederationTrustPathEntities"/>
    /// and every chain certificate's AuthorityKeyIdentifier in
    /// <see cref="TrustedAuthorityEvidence.AuthorityKeyIdentifiers"/>.
    /// </summary>
    /// <param name="backend">The X.509 backend whose AuthorityKeyIdentifier reader the <c>aki</c> arm exercises.</param>
    [TestMethod]
    [DataRow(MicrosoftBackend)]
    [DataRow(BouncyCastleBackend)]
    public async Task BuildComposesFederationEntitiesAndChainAuthorityKeyIdentifiers(string backend)
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        FederationGraph graph = await BuildLeafIntermediateAnchorGraphAsync(
            now, forgeIntermediateSubordinate: false, TestContext.CancellationToken).ConfigureAwait(false);

        FetchCounters counters = new();
        (FetchEntityConfigurationDelegate fetchConfiguration, FetchEntityStatementDelegate fetchSubordinate) =
            BuildFetchDelegates(graph, counters);

        (ExtractAuthorityKeyIdentifierDelegate extractAuthorityKeyIdentifier,
            ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier,
            ReadCertificateSubjectNameDelegate readSubjectName) = BackendReaders(backend);

        ResolveTrustedAuthorityEvidenceDelegate resolve = TrustedAuthorityEvidenceResolution.Build(
            extractAuthorityKeyIdentifier,
            readSubjectKeyIdentifier,
            readSubjectName,
            heldTrustedLists: [],
            resolveFederationTrustPath: (issuer, ct) => FederationTrustPathEvidence.ResolveAsync(
                issuer,
                [graph.Anchor],
                fetchConfiguration,
                fetchSubordinate,
                BuildValidator(),
                new ExchangeContext(),
                maxChainLength: 5,
                validationTime: now,
                clockSkew: TimeSpan.FromMinutes(5),
                BaseMemoryPool.Shared,
                ct));

        var timeProvider = new FakeTimeProvider(now);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("federation-aki.example.test", timeProvider);
        using PkiCertificateMemory leafCertificate = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediateCertificate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory rootCertificate = TrustedListFixtures.ToCertificateCarrier(ring.Root.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leafCertificate, intermediateCertificate, rootCertificate];

        TrustedAuthorityEvidence? evidence = await resolve(
            chain, graph.Leaf.Value, BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(evidence,
            "§6.1.1: a chain with AuthorityKeyIdentifiers and a validated federation path yields non-empty evidence.");

        IReadOnlySet<EntityIdentifier> expectedFederationEntities = new HashSet<EntityIdentifier>
        {
            graph.Leaf,
            graph.Intermediate,
            graph.Anchor
        };
        Assert.IsTrue(evidence.FederationTrustPathEntities.SetEquals(expectedFederationEntities),
            "§6.1.1.3: the composed evidence's federation entities must equal the resolver's validated-path subject set.");

        IReadOnlySet<AuthorityKeyIdentifier> expectedAuthorityKeyIdentifiers =
            X509TrustedAuthorityEvidence.CollectAuthorityKeyIdentifiers(chain, extractAuthorityKeyIdentifier);
        Assert.IsNotEmpty(expectedAuthorityKeyIdentifiers,
            "§6.1.1.1: the minted three-level chain carries AuthorityKeyIdentifiers to compose.");
        Assert.IsTrue(evidence.AuthorityKeyIdentifiers.SetEquals(expectedAuthorityKeyIdentifiers),
            "§6.1.1.1: the composed evidence's AuthorityKeyIdentifiers must come from the supplied certificate chain.");
    }


    /// <summary>
    /// Proves
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-15.10">OpenID
    /// for Verifiable Presentations 1.0, Section 15.10</see>'s "URLs ... treated purely as identifiers and
    /// not actually retrieved" through the composition seam: an issuer identifier that is not an https Entity
    /// Identifier is never parsed into a federation lookup, so
    /// <see cref="TrustedAuthorityEvidence.FederationTrustPathEntities"/> stays empty and neither fetch
    /// delegate is ever invoked.
    /// </summary>
    /// <param name="backend">The X.509 backend whose AuthorityKeyIdentifier reader keeps the evidence non-empty for inspection.</param>
    [TestMethod]
    [DataRow(MicrosoftBackend)]
    [DataRow(BouncyCastleBackend)]
    public async Task BuildSkipsTheFederationArmAndFetchesNothingForANonHttpsIssuer(string backend)
    {
        DateTimeOffset now = TestClock.CanonicalEpoch;
        FederationGraph graph = await BuildLeafIntermediateAnchorGraphAsync(
            now, forgeIntermediateSubordinate: false, TestContext.CancellationToken).ConfigureAwait(false);

        FetchCounters counters = new();
        (FetchEntityConfigurationDelegate fetchConfiguration, FetchEntityStatementDelegate fetchSubordinate) =
            BuildFetchDelegates(graph, counters);
        int federationArmInvocations = 0;

        (ExtractAuthorityKeyIdentifierDelegate extractAuthorityKeyIdentifier,
            ReadCertificateSubjectKeyIdentifierDelegate readSubjectKeyIdentifier,
            ReadCertificateSubjectNameDelegate readSubjectName) = BackendReaders(backend);

        ResolveTrustedAuthorityEvidenceDelegate resolve = TrustedAuthorityEvidenceResolution.Build(
            extractAuthorityKeyIdentifier,
            readSubjectKeyIdentifier,
            readSubjectName,
            heldTrustedLists: [],
            resolveFederationTrustPath: (issuer, ct) =>
            {
                federationArmInvocations++;

                return FederationTrustPathEvidence.ResolveAsync(
                    issuer,
                    [graph.Anchor],
                    fetchConfiguration,
                    fetchSubordinate,
                    BuildValidator(),
                    new ExchangeContext(),
                    maxChainLength: 5,
                    validationTime: now,
                    clockSkew: TimeSpan.FromMinutes(5),
                    BaseMemoryPool.Shared,
                    ct);
            });

        var timeProvider = new FakeTimeProvider(now);
        using X509ChainTestRingChain ring = X509ChainTestRing.BuildThreeLevelChain("non-https-issuer.example.test", timeProvider);
        using PkiCertificateMemory leafCertificate = TrustedListFixtures.ToCertificateCarrier(ring.Leaf.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory intermediateCertificate = TrustedListFixtures.ToCertificateCarrier(ring.Intermediate.Certificate, BaseMemoryPool.Shared);
        using PkiCertificateMemory rootCertificate = TrustedListFixtures.ToCertificateCarrier(ring.Root.Certificate, BaseMemoryPool.Shared);
        IReadOnlyList<PkiCertificateMemory> chain = [leafCertificate, intermediateCertificate, rootCertificate];

        //An http (non-https) absolute URL fails the Entity Identifier shape check, so the federation arm is
        //skipped entirely rather than dereferenced.
        TrustedAuthorityEvidence? evidence = await resolve(
            chain, "http://issuer.example.com", BaseMemoryPool.Shared, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(evidence,
            "§6.1.1.1: the certificate chain's AuthorityKeyIdentifiers keep the evidence non-empty for inspection.");
        Assert.HasCount(0, evidence.FederationTrustPathEntities,
            "§6.1.1.3: a non-https issuer identifier is no Entity Identifier, so the federation set stays empty.");
        Assert.AreEqual(0, federationArmInvocations,
            "§15.10: a value that is not an https identifier must not enter the federation resolution arm.");
        Assert.AreEqual(0, counters.ConfigurationFetches,
            "§15.10: the skipped federation arm must dereference no Entity Configuration URL.");
        Assert.AreEqual(0, counters.SubordinateFetches,
            "§15.10: the skipped federation arm must dereference no Subordinate Statement URL.");
    }


    /// <summary>
    /// Mints a leaf &#8594; intermediate &#8594; anchor federation graph through <see cref="FederationTestRing"/>
    /// and returns the fetch-lookup tables plus the three Entity Identifiers. When
    /// <paramref name="forgeIntermediateSubordinate"/> is <see langword="true"/>, the intermediate's
    /// Subordinate Statement about the leaf is signed by a foreign key carrying the same Entity Identifier, so
    /// the assembled chain fails <see href="https://openid.net/specs/openid-federation-1_0.html#section-10.2">
    /// Federation §10.2</see> signature validation while remaining structurally walkable.
    /// </summary>
    /// <param name="issuedAt">The instant the minted statements are issued at.</param>
    /// <param name="forgeIntermediateSubordinate">Whether to sign the intermediate-issued Subordinate Statement with a foreign key.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The lookup tables and Entity Identifiers describing the minted graph.</returns>
    private static async Task<FederationGraph> BuildLeafIntermediateAnchorGraphAsync(
        DateTimeOffset issuedAt,
        bool forgeIntermediateSubordinate,
        CancellationToken cancellationToken)
    {
        DateTimeOffset expiresAt = issuedAt.AddHours(1);

        using FederationTestRingNode leaf = FederationTestRing.CreateNode(new EntityIdentifier(LeafId));
        using FederationTestRingNode intermediate = FederationTestRing.CreateNode(new EntityIdentifier(IntermediateId));
        using FederationTestRingNode anchor = FederationTestRing.CreateNode(new EntityIdentifier(AnchorId));

        MintedStatement leafEc = await FederationTestRing.MintEntityConfigurationAsync(
            leaf, issuedAt, expiresAt,
            extraClaims: AuthorityHints(IntermediateId),
            cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement intermediateEc = await FederationTestRing.MintEntityConfigurationAsync(
            intermediate, issuedAt, expiresAt,
            extraClaims: Merge(AuthorityHints(AnchorId), FetchEndpoint(IntermediateFetch)),
            cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement anchorEc = await FederationTestRing.MintEntityConfigurationAsync(
            anchor, issuedAt, expiresAt,
            extraClaims: FetchEndpoint(AnchorFetch),
            cancellationToken: cancellationToken).ConfigureAwait(false);
        MintedStatement anchorAboutIntermediate = await FederationTestRing.MintSubordinateStatementAsync(
            anchor, intermediate, issuedAt, expiresAt,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        MintedStatement intermediateAboutLeaf;
        if(forgeIntermediateSubordinate)
        {
            //A foreign node with the intermediate's identifier but a fresh, unrelated key: the Subordinate
            //Statement it signs carries the correct iss/sub claims yet a signature the intermediate's real
            //published key (in anchorAboutIntermediate's jwks) cannot verify.
            using FederationTestRingNode foreignIntermediate = FederationTestRing.CreateNode(new EntityIdentifier(IntermediateId));
            intermediateAboutLeaf = await FederationTestRing.MintSubordinateStatementAsync(
                foreignIntermediate, leaf, issuedAt, expiresAt,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        else
        {
            intermediateAboutLeaf = await FederationTestRing.MintSubordinateStatementAsync(
                intermediate, leaf, issuedAt, expiresAt,
                cancellationToken: cancellationToken).ConfigureAwait(false);
        }

        Dictionary<string, string> configByEntity = new(StringComparer.Ordinal)
        {
            [LeafId] = leafEc.CompactJws,
            [IntermediateId] = intermediateEc.CompactJws,
            [AnchorId] = anchorEc.CompactJws,
        };
        Dictionary<string, string> endpointToIssuer = new(StringComparer.Ordinal)
        {
            [IntermediateFetch] = IntermediateId,
            [AnchorFetch] = AnchorId,
        };
        Dictionary<string, string> subordinateByIssuerSubject = new(StringComparer.Ordinal)
        {
            [SubordinateKey(IntermediateId, LeafId)] = intermediateAboutLeaf.CompactJws,
            [SubordinateKey(AnchorId, IntermediateId)] = anchorAboutIntermediate.CompactJws,
        };

        return new FederationGraph(
            configByEntity,
            endpointToIssuer,
            subordinateByIssuerSubject,
            new EntityIdentifier(LeafId),
            new EntityIdentifier(IntermediateId),
            new EntityIdentifier(AnchorId));
    }


    /// <summary>
    /// Builds the in-memory fetch delegates over a <see cref="FederationGraph"/>'s lookup tables, counting
    /// every invocation into <paramref name="counters"/> so a test can prove the resolver did or did not
    /// dereference any URL.
    /// </summary>
    /// <param name="graph">The minted graph whose lookup tables the delegates read.</param>
    /// <param name="counters">The per-test invocation counters the delegates increment.</param>
    /// <returns>The Entity Configuration and Subordinate Statement fetch delegates.</returns>
    private static (FetchEntityConfigurationDelegate FetchConfiguration, FetchEntityStatementDelegate FetchSubordinate) BuildFetchDelegates(
        FederationGraph graph,
        FetchCounters counters)
    {
        FetchEntityConfigurationDelegate fetchConfiguration = (entity, context, cancellationToken) =>
        {
            counters.ConfigurationFetches++;

            return ValueTask.FromResult(graph.ConfigByEntity.TryGetValue(entity.Value, out string? jws)
                ? FederationHttpClientTransport.TryParseFetchedStatement(jws)
                : null);
        };

        FetchEntityStatementDelegate fetchSubordinate = (subject, fetchEndpoint, context, cancellationToken) =>
        {
            counters.SubordinateFetches++;

            return ValueTask.FromResult(
                graph.EndpointToIssuer.TryGetValue(fetchEndpoint.ToString(), out string? issuer)
                && graph.SubordinateByIssuerSubject.TryGetValue(SubordinateKey(issuer, subject.Value), out string? jws)
                    ? FederationHttpClientTransport.TryParseFetchedStatement(jws)
                    : null);
        };

        return (fetchConfiguration, fetchSubordinate);
    }


    /// <summary>
    /// Builds the production inline trust-chain validator — build (§10.1) then verify (§10.2) — over the ring's
    /// compact-JWS statements, keyed by the in-chain key resolver.
    /// </summary>
    /// <returns>The validator delegate <see cref="FederationTrustPathEvidence.ResolveAsync"/> applies to each assembled chain.</returns>
    private static ValidateTrustChainAsyncDelegate BuildValidator()
    {
        return TrustChainValidation.BuildInlineValidator(
            HeaderDeserializer,
            PayloadDeserializer,
            TestSetup.Base64UrlDecoder,
            FederationKeyResolver.BuildInChainResolver(TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared));
    }


    /// <summary>
    /// Selects the certificate readers implemented by the named X.509 backend so the <c>aki</c> composition
    /// runs against both <see cref="MicrosoftX509Functions"/> and <see cref="BouncyCastleX509Functions"/>.
    /// </summary>
    /// <param name="backend">The backend name from the test's <c>DataRow</c>.</param>
    /// <returns>The backend's AuthorityKeyIdentifier, SubjectKeyIdentifier and Subject readers.</returns>
    private static (ExtractAuthorityKeyIdentifierDelegate ExtractAuthorityKeyIdentifier,
        ReadCertificateSubjectKeyIdentifierDelegate ReadSubjectKeyIdentifier,
        ReadCertificateSubjectNameDelegate ReadSubjectName) BackendReaders(string backend) => backend switch
    {
        MicrosoftBackend => (
            MicrosoftX509Functions.GetAuthorityKeyIdentifier,
            MicrosoftX509Functions.GetSubjectKeyIdentifier,
            MicrosoftX509Functions.GetSubjectName),
        BouncyCastleBackend => (
            BouncyCastleX509Functions.GetAuthorityKeyIdentifier,
            BouncyCastleX509Functions.GetSubjectKeyIdentifier,
            BouncyCastleX509Functions.GetSubjectName),
        _ => throw new ArgumentOutOfRangeException(nameof(backend), backend, "Unknown X.509 backend name.")
    };


    /// <summary>Builds an extra-claims bag carrying an <c>authority_hints</c> array.</summary>
    /// <param name="hints">The superior Entity Identifiers the entity points up to.</param>
    /// <returns>The extra-claims bag.</returns>
    private static Dictionary<string, object> AuthorityHints(params string[] hints) =>
        new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.AuthorityHints] = new List<object>(hints),
        };


    /// <summary>Builds an extra-claims bag carrying a <c>federation_entity.federation_fetch_endpoint</c>.</summary>
    /// <param name="endpoint">The federation fetch endpoint URL.</param>
    /// <returns>The extra-claims bag.</returns>
    private static Dictionary<string, object> FetchEndpoint(string endpoint) =>
        new(StringComparer.Ordinal)
        {
            [WellKnownFederationClaimNames.Metadata] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownEntityTypeIdentifiers.FederationEntity.Value] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [FederationMetadataParameterNames.FetchEndpoint] = endpoint,
                },
            },
        };


    /// <summary>Merges two extra-claims bags, the right winning on key collisions.</summary>
    /// <param name="left">The base bag.</param>
    /// <param name="right">The overriding bag.</param>
    /// <returns>The merged bag.</returns>
    private static Dictionary<string, object> Merge(
        Dictionary<string, object> left, Dictionary<string, object> right)
    {
        Dictionary<string, object> result = new(left, StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> entry in right)
        {
            result[entry.Key] = entry.Value;
        }

        return result;
    }


    /// <summary>Builds the composite key for the (issuer, subject) Subordinate Statement lookup.</summary>
    /// <param name="issuer">The issuing entity's identifier.</param>
    /// <param name="subject">The subject entity's identifier.</param>
    /// <returns>The composite lookup key.</returns>
    private static string SubordinateKey(string issuer, string subject) => $"{issuer}\n{subject}";


    /// <summary>
    /// The in-memory fetch-lookup tables and Entity Identifiers describing one minted leaf &#8594; intermediate
    /// &#8594; anchor federation graph.
    /// </summary>
    /// <param name="ConfigByEntity">Entity Identifier to its self-issued Entity Configuration compact JWS.</param>
    /// <param name="EndpointToIssuer">Federation fetch endpoint URL to the issuer whose statements it serves.</param>
    /// <param name="SubordinateByIssuerSubject">The (issuer, subject) key to the Subordinate Statement compact JWS.</param>
    /// <param name="Leaf">The leaf credential issuer's Entity Identifier.</param>
    /// <param name="Intermediate">The intermediate's Entity Identifier.</param>
    /// <param name="Anchor">The Trust Anchor's Entity Identifier.</param>
    private sealed record FederationGraph(
        IReadOnlyDictionary<string, string> ConfigByEntity,
        IReadOnlyDictionary<string, string> EndpointToIssuer,
        IReadOnlyDictionary<string, string> SubordinateByIssuerSubject,
        EntityIdentifier Leaf,
        EntityIdentifier Intermediate,
        EntityIdentifier Anchor);


    /// <summary>Per-test counters of how many times each fetch delegate was invoked.</summary>
    private sealed class FetchCounters
    {
        /// <summary>The number of Entity Configuration fetch invocations observed.</summary>
        public int ConfigurationFetches { get; set; }

        /// <summary>The number of Subordinate Statement fetch invocations observed.</summary>
        public int SubordinateFetches { get; set; }
    }
}
