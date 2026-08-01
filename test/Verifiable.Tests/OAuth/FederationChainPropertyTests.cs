using CsCheck;
using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Core.Assessment;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Server;
using Verifiable.Tests.Federation;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Property-based tests for the OpenID Federation 1.0 trust-chain surface
/// running across three Kestrel listeners — subject (verifier) +
/// intermediate + trust anchor. The intermediate signs Subordinate
/// Statements about the verifier; the anchor signs Subordinate Statements
/// about the intermediate. All five chain elements travel over HTTP from
/// their respective hosts.
/// </summary>
/// <remarks>
/// <para>
/// Composes §3a (multi-host), §3e (well-known EC), and §8.1
/// (federation_fetch_endpoint). The deterministic three-server federation
/// shape is set up once at class-init and shared across samples to keep
/// per-sample cost low; CsCheck generators vary the inputs to each
/// property — tamper positions, anchor allow-lists, queried subjects.
/// </para>
/// <para>
/// Three properties:
/// </para>
/// <list type="bullet">
///   <item><description>
///     <strong>Chain liveness</strong>: assembling and validating the
///     chain repeatedly produces the same valid outcome.
///   </description></item>
///   <item><description>
///     <strong>Tamper rejection</strong>: any single-byte mutation to any
///     chain element causes validation to fail.
///   </description></item>
///   <item><description>
///     <strong>Anchor scoping</strong>: validating the chain against any
///     trust-anchor set that excludes the chain's terminal anchor causes
///     validation to fail.
///   </description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class FederationChainPropertyTests
{
    public TestContext TestContext { get; set; } = null!;

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    //Class-level fixture. Set up once, shared across all samples in all
    //tests. ClassCleanup tears it down.
    private static FederationTopologyFixture? sharedFixture;

    private static FederationTopologyFixture Fixture =>
        sharedFixture
        ?? throw new InvalidOperationException("Fixture not initialised; ClassInitialize did not run.");


    [ClassInitialize]
    public static async Task ClassInitializeAsync(TestContext _)
    {
        sharedFixture = await FederationTopologyFixture.BuildAsync().ConfigureAwait(false);
    }


    [ClassCleanup]
    public static async Task ClassCleanupAsync()
    {
        if(sharedFixture is not null)
        {
            await sharedFixture.DisposeAsync().ConfigureAwait(false);
            sharedFixture = null;
        }
    }


    /// <summary>
    /// For any number of fresh fetches the chain validates cleanly. This
    /// catches non-determinism in the wire path — caching bugs, time-
    /// dependent state, signature regeneration mismatches — by re-running
    /// the fetch + validate cycle independently on each sample.
    /// </summary>
    [TestMethod]
    public void ChainAssembledOverWireValidatesOnEveryFetch()
    {
        //Gen.Int gives CsCheck a knob it can shrink; each sample re-fetches
        //the chain freshly. The seed value isn't otherwise consumed.
        Gen.Int[0, 1000].Sample(_ =>
        {
            string[] chain = Fixture.FetchChainAsync(TestContext.CancellationToken)
                .GetAwaiter().GetResult();

            TrustChainValidationOutcome outcome = Fixture.ValidateChainAsync(
                    chain,
                    [Fixture.AnchorNode.Identifier],
                    TestContext.CancellationToken)
                .GetAwaiter().GetResult();

            Assert.IsTrue(outcome.IsValid,
                $"Chain validation must succeed every fetch. Reason: {outcome.FailureReason}");
        }, iter: 25);
    }


    /// <summary>
    /// Mutating any single byte of any chain element must cause validation
    /// to fail. CsCheck generates a (chain-element index, byte offset, XOR
    /// mask) tuple and asserts the rejection. Tampered segments that no
    /// longer decode are rejected at parse time; mutations that survive
    /// decoding break the JWS signature and are rejected at signature
    /// verification.
    /// </summary>
    [TestMethod]
    public void TamperingAnyByteRejectsTheChain()
    {
        string[] validChain = Fixture.FetchChainAsync(TestContext.CancellationToken)
            .GetAwaiter().GetResult();

        Gen<(int Element, int ByteOffset, byte XorMask)> tamperGen =
            Gen.Int[0, validChain.Length - 1].SelectMany(elementIndex =>
                Gen.Int[0, validChain[elementIndex].Length - 1].SelectMany(byteOffset =>
                    Gen.Byte[1, 255].Select(xorMask =>
                        (elementIndex, byteOffset, xorMask))));

        tamperGen.Sample(tuple =>
        {
            string[] tamperedChain = (string[])validChain.Clone();
            char[] mutated = tamperedChain[tuple.Element].ToCharArray();
            //XOR the low byte of the chosen char by the mask. The XOR
            //mask is in [1, 255] so the resulting char always differs
            //from the original.
            mutated[tuple.ByteOffset] = (char)(mutated[tuple.ByteOffset] ^ tuple.XorMask);
            tamperedChain[tuple.Element] = new string(mutated);

            TrustChainValidationOutcome outcome = Fixture.ValidateChainAsync(
                    tamperedChain,
                    [Fixture.AnchorNode.Identifier],
                    TestContext.CancellationToken)
                .GetAwaiter().GetResult();

            Assert.IsFalse(outcome.IsValid,
                $"Tampering element {tuple.Element} at byte {tuple.ByteOffset} (XOR {tuple.XorMask:X2}) must reject. " +
                $"Original: '{validChain[tuple.Element]}', Tampered: '{tamperedChain[tuple.Element]}'.");
        }, iter: 50);
    }


    /// <summary>
    /// Validating the chain against any anchor allow-list that does not
    /// include the chain's terminal anchor identifier must fail. CsCheck
    /// generates "wrong-anchor" entity identifiers (URLs distinct from the
    /// real anchor's identifier) and asserts the rejection.
    /// </summary>
    [TestMethod]
    public void AnchorAllowListExcludingChainTerminalRejectsChain()
    {
        string[] validChain = Fixture.FetchChainAsync(TestContext.CancellationToken)
            .GetAwaiter().GetResult();
        string realAnchorId = Fixture.AnchorNode.Identifier.Value;

        Gen<EntityIdentifier[]> wrongAnchorsGen =
            Gen.Int[0, 3].SelectMany(count =>
                Gen.String[Gen.Char.AlphaNumeric, 4, 16]
                    .Where(s => !string.Equals($"https://{s}.example.com", realAnchorId, StringComparison.Ordinal))
                    .Array[count]
                    .Select(names => names
                        .Select(n => new EntityIdentifier($"https://{n}.example.com"))
                        .ToArray()));

        wrongAnchorsGen.Sample(wrongAnchors =>
        {
            TrustChainValidationOutcome outcome = Fixture.ValidateChainAsync(
                    validChain,
                    wrongAnchors,
                    TestContext.CancellationToken)
                .GetAwaiter().GetResult();

            Assert.IsFalse(outcome.IsValid,
                $"Validation against anchor set [{string.Join(',', wrongAnchors.Select(a => a.Value))}] " +
                "must reject — none of these are the chain's terminal anchor.");
        }, iter: 30);
    }


    /// <summary>
    /// A trust mark the anchor signs and authorizes is admitted by <see cref="FederationTrustMarkResolver"/>
    /// running over the chain fetched across the three live hosts. The chain travels over HTTP and validates
    /// through the production validator; the resolver then resolves the anchor's key FROM THAT VERIFIED CHAIN and
    /// verifies the mark's real ES256 signature against that resolved key via the production
    /// <c>Jws.VerifyAsync</c> — the same key-from-verified-source path a deployment runs, with no test-side
    /// signature shortcut — before admitting it on the §6.2 issuer-authorization pathway. The end-to-end
    /// multi-server proof for the §7 trust-mark verifier.
    /// </summary>
    [TestMethod]
    public async Task TrustMarkIsAdmittedOverChainFetchedFromMultipleServers()
    {
        //Fetch + validate the five-element chain over HTTP; the validated outcome carries the parsed TrustChain.
        string[] chain = await Fixture.FetchChainAsync(TestContext.CancellationToken).ConfigureAwait(false);
        TrustChainValidationOutcome outcome = await Fixture.ValidateChainAsync(
            chain, [Fixture.AnchorNode.Identifier], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsValid, outcome.FailureReason);
        Assert.IsNotNull(outcome.Chain);

        //The anchor issues a mark about the verifier, signed with its real federation key. Federation §7 makes
        //the kid header a MUST on Trust Mark JWTs and the in-chain resolver key-pins on it (no first-key
        //fallback), so the mark references the kid the anchor actually published in its Entity Configuration —
        //read here from the wire-fetched, verified chain, exactly as a deployment's resolver would match it.
        DateTimeOffset now = TestClock.CanonicalEpoch;
        string anchorPublishedKid = ReadFirstPublishedKid(outcome.Chain!.Statements[^1]);
        MintedTrustMark minted = await FederationTestRing.MintTrustMarkAsync(
            Fixture.AnchorNode, Fixture.VerifierNode, FederationTopologyFixture.TrustMarkId, now, now.AddHours(1),
            kidOverride: anchorPublishedKid, cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        TrustMarkCandidate candidate = new() { Mark = minted.Mark, Header = minted.Header, CompactJws = minted.CompactJws };

        //Production verification: the resolver hands the key it resolved FROM THE VERIFIED CHAIN to this delegate,
        //which runs the library's real Jws.VerifyAsync against it (the same overload the chain validator uses).
        VerifyCompactJwsDelegate verify = (compactJws, key, cancellationToken) =>
            Jws.VerifyAsync(compactJws, TestSetup.Base64UrlDecoder, Pool, key, cancellationToken);

        IReadOnlyList<TrustMarkVerdict> verdicts = await FederationTrustMarkResolver.ResolveVerifiedAsync(
            outcome.Chain!, [candidate], verify, TestSetup.Base64UrlDecoder, Pool,
            timeProvider: new FakeTimeProvider(TestClock.CanonicalEpoch), TimeSpan.FromMinutes(5), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(verdicts[0].SignatureVerified,
            "The mark signature must verify against the anchor key resolved from the wire-fetched, verified chain.");
        Assert.AreEqual(ClaimOutcome.Success, verdicts[0].IssuerAuthorization.Outcome);
        Assert.IsTrue(verdicts[0].Admitted,
            "A mark the anchor signs and authorizes must be admitted over the multi-server fetched chain.");
    }


    /// <summary>
    /// Reads the <c>kid</c> of the first key an entity statement publishes in its <c>jwks</c> claim — the id a
    /// deployment's in-chain resolver key-pins on when matching a statement or mark header.
    /// </summary>
    /// <param name="statement">The entity statement whose published jwks is read.</param>
    /// <returns>The first published key's <c>kid</c>.</returns>
    private static string ReadFirstPublishedKid(EntityStatement statement)
    {
        Assert.IsTrue(statement.Payload.TryGetValue(WellKnownFederationClaimNames.Jwks, out object? jwksObj),
            "The anchor's Entity Configuration must publish a jwks.");
        IReadOnlyDictionary<string, object> jwks = (IReadOnlyDictionary<string, object>)jwksObj!;
        IEnumerable<object> keys = (IEnumerable<object>)jwks[WellKnownJwkMemberNames.Keys];
        IReadOnlyDictionary<string, object> firstKey = (IReadOnlyDictionary<string, object>)keys.First();
        return (string)firstKey[WellKnownJwkMemberNames.Kid];
    }
}


/// <summary>
/// Three-host federation fixture: a verifier subject on the default host,
/// an intermediate on its own Kestrel, and a trust anchor on its own
/// Kestrel. Owns the registrations, the federation signing keys, and the
/// per-link chain-fetch + chain-validation helpers used by the property
/// tests.
/// </summary>
internal sealed class FederationTopologyFixture: IAsyncDisposable
{
    private readonly TestHostShell host;
    private readonly Uri verifierEntityId;
    private readonly Uri intermediateEntityId;
    private readonly Uri anchorEntityId;
    private readonly string verifierSegment;
    private readonly string intermediateSegment;
    private readonly string anchorSegment;
    private readonly PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierFederationKeys;
    private readonly PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> intermediateFederationKeys;
    private readonly PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorFederationKeys;
    private readonly VerifierKeyMaterial verifierKeys;
    private readonly VerifierKeyMaterial intermediateKeys;
    private readonly VerifierKeyMaterial anchorKeys;

    /// <summary>Header deserializer mirroring the authorization server's wiring.</summary>
    private static readonly JwtHeaderDeserializer HeaderDeserializer = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Header JSON parsed to null.");

    /// <summary>Payload deserializer mirroring the authorization server's wiring.</summary>
    private static readonly JwtPayloadDeserializer PayloadDeserializer = static bytes =>
        JsonSerializerExtensions.Deserialize<Dictionary<string, object>>(
            bytes, TestSetup.DefaultSerializationOptions)
        ?? throw new FormatException("Payload JSON parsed to null.");

    /// <summary>The trust-mark type the anchor authorizes itself to issue (declared in its EC's trust_mark_issuers).</summary>
    public const string TrustMarkId = "https://anchor.example.com/trust-mark/membership";

    /// <summary>The anchor ring node — supplies its Entity Identifier for the trust-anchor allow-list and signs trust marks.</summary>
    public FederationTestRingNode AnchorNode { get; }

    /// <summary>The verifier (leaf) ring node, keyed by the same federation key its EC publishes — the trust-mark subject.</summary>
    public FederationTestRingNode VerifierNode { get; }


    private FederationTopologyFixture(
        TestHostShell host,
        Uri verifierEntityId, Uri intermediateEntityId, Uri anchorEntityId,
        string verifierSegment, string intermediateSegment, string anchorSegment,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierFederationKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> intermediateFederationKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorFederationKeys,
        VerifierKeyMaterial verifierKeys, VerifierKeyMaterial intermediateKeys, VerifierKeyMaterial anchorKeys,
        FederationTestRingNode anchorNode,
        FederationTestRingNode verifierNode)
    {
        this.host = host;
        this.verifierEntityId = verifierEntityId;
        this.intermediateEntityId = intermediateEntityId;
        this.anchorEntityId = anchorEntityId;
        this.verifierSegment = verifierSegment;
        this.intermediateSegment = intermediateSegment;
        this.anchorSegment = anchorSegment;
        this.verifierFederationKeys = verifierFederationKeys;
        this.intermediateFederationKeys = intermediateFederationKeys;
        this.anchorFederationKeys = anchorFederationKeys;
        this.verifierKeys = verifierKeys;
        this.intermediateKeys = intermediateKeys;
        this.anchorKeys = anchorKeys;
        AnchorNode = anchorNode;
        VerifierNode = verifierNode;
    }


    public static async ValueTask<FederationTopologyFixture> BuildAsync()
    {
        FakeTimeProvider timeProvider = new();
        TestHostShell host = new(timeProvider);
        host.AddHost("intermediate");
        host.AddHost("anchor");

        await host.StartHttpHostAsync("default", default).ConfigureAwait(false);
        await host.StartHttpHostAsync("intermediate", default).ConfigureAwait(false);
        await host.StartHttpHostAsync("anchor", default).ConfigureAwait(false);

        Uri verifierEntityId = new("https://verifier.example.com");
        Uri intermediateEntityId = new("https://intermediate.example.com");
        Uri anchorEntityId = new("https://anchor.example.com");

        //Each entity owns its federation signing keypair. Subjects' public
        //sides flow into their EC's jwks (via the §3e endpoint) and into
        //their superior's SS jwks (via the §8.1 federation_fetch handler).
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierFederationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> intermediateFederationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorFederationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        //Verifier (leaf): EC only, no subordinates.
        VerifierKeyMaterial verifierKeys = host.RegisterFederationCapableClient(
            clientId: "https://verifier.example.com",
            baseUri: verifierEntityId,
            federationEntityId: verifierEntityId,
            federationSigningKeyPair: verifierFederationKeys,
            baseCapabilities: ImmutableHashSet<CapabilityIdentifier>.Empty);

        //Intermediate: EC + SS issuer.
        VerifierKeyMaterial intermediateKeys = host.RegisterFederationCapableClientOnHost(
            hostName: "intermediate",
            clientId: intermediateEntityId.ToString(),
            baseUri: intermediateEntityId,
            federationEntityId: intermediateEntityId,
            federationSigningKeyPair: intermediateFederationKeys,
            baseCapabilities: ImmutableHashSet.Create(
                WellKnownFederationCapabilityIdentifiers.PublishSubordinateStatement));

        //Anchor: EC + SS issuer.
        VerifierKeyMaterial anchorKeys = host.RegisterFederationCapableClientOnHost(
            hostName: "anchor",
            clientId: anchorEntityId.ToString(),
            baseUri: anchorEntityId,
            federationEntityId: anchorEntityId,
            federationSigningKeyPair: anchorFederationKeys,
            baseCapabilities: ImmutableHashSet.Create(
                WellKnownFederationCapabilityIdentifiers.PublishSubordinateStatement));

        //Align intermediate + anchor to their own Kestrel bases so EC URLs
        //and federation_fetch URLs resolve against the right authority.
        //The verifier on default is aligned via the wallet factory in
        //tests that build wallets; this fixture isn't a wallet host, so
        //align it explicitly too.
        verifierKeys.Registration = host.AlignRegistrationToHostHttpBase("default", verifierKeys.Registration);
        intermediateKeys.Registration = host.AlignRegistrationToHostHttpBase("intermediate", intermediateKeys.Registration);
        anchorKeys.Registration = host.AlignRegistrationToHostHttpBase("anchor", anchorKeys.Registration);

        string verifierSegment = verifierKeys.Registration.TenantId.Value;
        string intermediateSegment = intermediateKeys.Registration.TenantId.Value;
        string anchorSegment = anchorKeys.Registration.TenantId.Value;

        HostedAuthorizationServer intermediateHost = host.Host("intermediate");
        HostedAuthorizationServer anchorHost = host.Host("anchor");

        //Intermediate publishes its federation_fetch URL in its EC's
        //metadata.federation_entity (the wire shape a real wallet parses).
        Uri intermediateFetchUrl = new(intermediateHost.HttpBaseAddress!,
            $"/connect/{intermediateSegment}/federation_fetch");
        intermediateHost.Server.OAuth().ContributeFederationMetadataAsync = (_, _, _) =>
            ValueTask.FromResult(new FederationEntityConfigurationContribution
            {
                Metadata = new Dictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>>
                {
                    [WellKnownEntityTypeIdentifiers.FederationEntity] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["federation_fetch_endpoint"] = intermediateFetchUrl.ToString()
                    }
                }
            });

        Dictionary<string, object> verifierSubjectJwks = OAuthJwksFixtures.BuildSingleEcKeyJwks(verifierFederationKeys.PublicKey);
        intermediateHost.Server.OAuth().ResolveSubordinateStatementAsync = (subject, _, _, _) =>
        {
            if(!string.Equals(subject.Value, verifierEntityId.ToString(), StringComparison.Ordinal))
            {
                return ValueTask.FromResult<SubordinateStatementContribution?>(null);
            }

            return ValueTask.FromResult<SubordinateStatementContribution?>(
                new SubordinateStatementContribution { Jwks = verifierSubjectJwks });
        };

        //Anchor publishes its federation_fetch URL and serves SS about
        //the intermediate.
        Uri anchorFetchUrl = new(anchorHost.HttpBaseAddress!,
            $"/connect/{anchorSegment}/federation_fetch");
        anchorHost.Server.OAuth().ContributeFederationMetadataAsync = (_, _, _) =>
            ValueTask.FromResult(new FederationEntityConfigurationContribution
            {
                Metadata = new Dictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>>
                {
                    [WellKnownEntityTypeIdentifiers.FederationEntity] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["federation_fetch_endpoint"] = anchorFetchUrl.ToString()
                    }
                },
                //The Trust Anchor authorizes itself as a trust-mark issuer for TrustMarkId (§6.2), so a mark it
                //signs is admitted by the trust-mark resolver over the fetched chain.
                AdditionalClaims = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [WellKnownFederationClaimNames.TrustMarkIssuers] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        [TrustMarkId] = new List<object> { anchorEntityId.ToString() }
                    }
                }
            });

        Dictionary<string, object> intermediateSubjectJwks = OAuthJwksFixtures.BuildSingleEcKeyJwks(intermediateFederationKeys.PublicKey);
        anchorHost.Server.OAuth().ResolveSubordinateStatementAsync = (subject, _, _, _) =>
        {
            if(!string.Equals(subject.Value, intermediateEntityId.ToString(), StringComparison.Ordinal))
            {
                return ValueTask.FromResult<SubordinateStatementContribution?>(null);
            }

            return ValueTask.FromResult<SubordinateStatementContribution?>(
                new SubordinateStatementContribution { Jwks = intermediateSubjectJwks });
        };

        //The anchor's ring node supplies its EntityIdentifier for the
        //trust-anchor allow-list the property tests pass to
        //ValidateChainAsync. Per-link signature verification no longer
        //dispatches through ring nodes by chain position — the production
        //validator resolves each link's verification key from the chain's
        //own jwks (see ValidateChainAsync below), so no verifier- or
        //intermediate-keyed ring node is needed here.
        FederationTestRingNode anchorNode = FederationTestRing.CreateNodeFromKey(
            new EntityIdentifier(anchorEntityId.ToString()), anchorFederationKeys.PrivateKey);

        //The verifier ring node is keyed by the same federation private key its EC publishes, so it can stand in
        //as the trust-mark subject; the anchor signs marks about it over the wire-fetched chain.
        FederationTestRingNode verifierNode = FederationTestRing.CreateNodeFromKey(
            new EntityIdentifier(verifierEntityId.ToString()), verifierFederationKeys.PrivateKey);

        return new FederationTopologyFixture(
            host,
            verifierEntityId, intermediateEntityId, anchorEntityId,
            verifierSegment, intermediateSegment, anchorSegment,
            verifierFederationKeys, intermediateFederationKeys, anchorFederationKeys,
            verifierKeys, intermediateKeys, anchorKeys,
            anchorNode,
            verifierNode);
    }


    /// <summary>
    /// Fetches the full chain over HTTP from the three hosts. Returns the
    /// five compact JWS strings in chain order:
    /// [verifierEC, intermediateSSaboutVerifier, intermediateEC,
    ///  anchorSSaboutIntermediate, anchorEC].
    /// </summary>
    public async Task<string[]> FetchChainAsync(CancellationToken cancellationToken)
    {
        HostedAuthorizationServer defaultHost = host.Host("default");
        HostedAuthorizationServer intermediateHost = host.Host("intermediate");
        HostedAuthorizationServer anchorHost = host.Host("anchor");

        Uri verifierEcUrl = new(defaultHost.HttpBaseAddress!,
            $"/connect/{verifierSegment}/.well-known/openid-federation");
        Uri intermediateEcUrl = new(intermediateHost.HttpBaseAddress!,
            $"/connect/{intermediateSegment}/.well-known/openid-federation");
        Uri anchorEcUrl = new(anchorHost.HttpBaseAddress!,
            $"/connect/{anchorSegment}/.well-known/openid-federation");
        Uri intermediateSsUrl = new(intermediateHost.HttpBaseAddress!,
            $"/connect/{intermediateSegment}/federation_fetch?sub={Uri.EscapeDataString(verifierEntityId.ToString())}");
        Uri anchorSsUrl = new(anchorHost.HttpBaseAddress!,
            $"/connect/{anchorSegment}/federation_fetch?sub={Uri.EscapeDataString(intermediateEntityId.ToString())}");

        string verifierEc = await FetchAsync(defaultHost.SharedHttpClient!, verifierEcUrl, cancellationToken).ConfigureAwait(false);
        string intermediateSsAboutVerifier = await FetchAsync(intermediateHost.SharedHttpClient!, intermediateSsUrl, cancellationToken).ConfigureAwait(false);
        string intermediateEc = await FetchAsync(intermediateHost.SharedHttpClient!, intermediateEcUrl, cancellationToken).ConfigureAwait(false);
        string anchorSsAboutIntermediate = await FetchAsync(anchorHost.SharedHttpClient!, anchorSsUrl, cancellationToken).ConfigureAwait(false);
        string anchorEc = await FetchAsync(anchorHost.SharedHttpClient!, anchorEcUrl, cancellationToken).ConfigureAwait(false);

        return [verifierEc, intermediateSsAboutVerifier, intermediateEc, anchorSsAboutIntermediate, anchorEc];
    }


    /// <summary>
    /// Runs the supplied chain through the production
    /// <see cref="TrustChainValidation.BuildInlineValidator"/>, wired with
    /// <see cref="FederationKeyResolver.BuildInChainResolver"/> — the same
    /// composition a deployment wires. Every verification key is resolved
    /// from the chain's own <c>jwks</c> claims; there is no test-side
    /// signature shortcut keyed by chain position.
    /// </summary>
    public async Task<TrustChainValidationOutcome> ValidateChainAsync(
        IReadOnlyList<string> chain,
        IReadOnlyCollection<EntityIdentifier> trustAnchors,
        CancellationToken cancellationToken)
    {
        ValidateTrustChainAsyncDelegate validateChain = TrustChainValidation.BuildInlineValidator(
            HeaderDeserializer,
            PayloadDeserializer,
            TestSetup.Base64UrlDecoder,
            FederationKeyResolver.BuildInChainResolver(TestSetup.Base64UrlDecoder, BaseMemoryPool.Shared));

        return await validateChain(
            chain,
            trustAnchors,
            host.Time.GetUtcNow(),
            TimeSpan.FromMinutes(5),
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);
    }


    private static async Task<string> FetchAsync(
        System.Net.Http.HttpClient client, Uri url, CancellationToken cancellationToken)
    {
        using System.Net.Http.HttpResponseMessage response =
            await client.GetAsync(url, cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
    }


    public async ValueTask DisposeAsync()
    {
        AnchorNode.Dispose();
        VerifierNode.Dispose();
        verifierKeys.Dispose();
        intermediateKeys.Dispose();
        anchorKeys.Dispose();
        await host.DisposeAsync().ConfigureAwait(false);
    }
}
