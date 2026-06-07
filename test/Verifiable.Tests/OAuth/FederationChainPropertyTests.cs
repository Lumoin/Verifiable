using CsCheck;
using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
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

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

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

    public FederationTestRingNode VerifierNode { get; }
    public FederationTestRingNode IntermediateNode { get; }
    public FederationTestRingNode AnchorNode { get; }


    private FederationTopologyFixture(
        TestHostShell host,
        Uri verifierEntityId, Uri intermediateEntityId, Uri anchorEntityId,
        string verifierSegment, string intermediateSegment, string anchorSegment,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> verifierFederationKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> intermediateFederationKeys,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorFederationKeys,
        VerifierKeyMaterial verifierKeys, VerifierKeyMaterial intermediateKeys, VerifierKeyMaterial anchorKeys,
        FederationTestRingNode verifierNode, FederationTestRingNode intermediateNode, FederationTestRingNode anchorNode)
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
        VerifierNode = verifierNode;
        IntermediateNode = intermediateNode;
        AnchorNode = anchorNode;
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
        intermediateHost.Server.Integration.ContributeFederationMetadataAsync = (_, _, _) =>
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

        Dictionary<string, object> verifierSubjectJwks = BuildSingleEcKeyJwks(verifierFederationKeys.PublicKey);
        intermediateHost.Server.Integration.ResolveSubordinateStatementAsync = (subject, _, _, _) =>
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
        anchorHost.Server.Integration.ContributeFederationMetadataAsync = (_, _, _) =>
            ValueTask.FromResult(new FederationEntityConfigurationContribution
            {
                Metadata = new Dictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>>
                {
                    [WellKnownEntityTypeIdentifiers.FederationEntity] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["federation_fetch_endpoint"] = anchorFetchUrl.ToString()
                    }
                }
            });

        Dictionary<string, object> intermediateSubjectJwks = BuildSingleEcKeyJwks(intermediateFederationKeys.PublicKey);
        anchorHost.Server.Integration.ResolveSubordinateStatementAsync = (subject, _, _, _) =>
        {
            if(!string.Equals(subject.Value, intermediateEntityId.ToString(), StringComparison.Ordinal))
            {
                return ValueTask.FromResult<SubordinateStatementContribution?>(null);
            }

            return ValueTask.FromResult<SubordinateStatementContribution?>(
                new SubordinateStatementContribution { Jwks = intermediateSubjectJwks });
        };

        //Ring nodes drive per-link signature verification. Each uses the
        //same P-256 scalar as the corresponding AS-side federation signing
        //key so signatures produced on the wire verify under the node.
        FederationTestRingNode verifierNode = FederationTestRing.CreateNodeFromKey(
            new EntityIdentifier(verifierEntityId.ToString()), verifierFederationKeys.PrivateKey);
        FederationTestRingNode intermediateNode = FederationTestRing.CreateNodeFromKey(
            new EntityIdentifier(intermediateEntityId.ToString()), intermediateFederationKeys.PrivateKey);
        FederationTestRingNode anchorNode = FederationTestRing.CreateNodeFromKey(
            new EntityIdentifier(anchorEntityId.ToString()), anchorFederationKeys.PrivateKey);

        return new FederationTopologyFixture(
            host,
            verifierEntityId, intermediateEntityId, anchorEntityId,
            verifierSegment, intermediateSegment, anchorSegment,
            verifierFederationKeys, intermediateFederationKeys, anchorFederationKeys,
            verifierKeys, intermediateKeys, anchorKeys,
            verifierNode, intermediateNode, anchorNode);
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
    /// Runs the supplied chain through the production TrustChainValidator
    /// via the test-side <see cref="InlineTrustChainValidationDriver"/>.
    /// Per-link signature verification dispatches by position:
    /// 0 = verifier EC (verifier key), 1+2 = intermediate's SS and EC
    /// (intermediate key), 3+4 = anchor's SS and EC (anchor key).
    /// </summary>
    public async Task<TrustChainValidationOutcome> ValidateChainAsync(
        IReadOnlyList<string> chain,
        IReadOnlyCollection<EntityIdentifier> trustAnchors,
        CancellationToken cancellationToken)
    {
        //Tampered chains can carry malformed base64url segments — verifying
        //such input via Jws.VerifyAsync throws a FormatException at decode
        //time. The validator's per-link verifier delegate contract is to
        //return false on any verification failure, not to throw, so the
        //fixture wraps verification in try/catch and treats any exception
        //(decode error, signature mismatch, malformed JWS structure) as
        //"link did not verify". A real wallet's per-link verifier must do
        //the same — hostile inputs are part of the threat surface.
        ValidateTrustChainAsyncDelegate validateChain =
            InlineTrustChainValidationDriver.Build(
                async (position, compactJws, ct) =>
                {
                    try
                    {
                        return position switch
                        {
                            0 => await FederationTestRing.VerifyAsync(VerifierNode, compactJws, ct).ConfigureAwait(false),
                            1 or 2 => await FederationTestRing.VerifyAsync(IntermediateNode, compactJws, ct).ConfigureAwait(false),
                            _ => await FederationTestRing.VerifyAsync(AnchorNode, compactJws, ct).ConfigureAwait(false),
                        };
                    }
                    catch
                    {
                        return false;
                    }
                });

        return await validateChain(
            chain,
            trustAnchors,
            host.Time.GetUtcNow(),
            TimeSpan.FromMinutes(5),
            SensitiveMemoryPool<byte>.Shared,
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


    private static Dictionary<string, object> BuildSingleEcKeyJwks(PublicKeyMemory publicKey)
    {
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            publicKey.Tag.Get<CryptoAlgorithm>(),
            publicKey.Tag.Get<Purpose>(),
            publicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);
        jwk.Use = WellKnownJwkValues.UseSig;

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["keys"] = new List<object> { jwk }
        };
    }


    public async ValueTask DisposeAsync()
    {
        VerifierNode.Dispose();
        IntermediateNode.Dispose();
        AnchorNode.Dispose();
        verifierKeys.Dispose();
        intermediateKeys.Dispose();
        anchorKeys.Dispose();
        await host.DisposeAsync().ConfigureAwait(false);
    }
}
