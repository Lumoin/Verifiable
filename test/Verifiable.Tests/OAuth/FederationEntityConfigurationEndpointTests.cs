using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end tests for the OpenID Federation 1.0 §9 Entity Configuration
/// endpoint exposed by <see cref="FederationEndpoints"/>. Covers two scopes:
/// </summary>
/// <list type="bullet">
///   <item><description>
///     <strong>Full configuration</strong>: a single registration carrying
///     OAuth, OIDC discovery, JWKS, OID4VP, and federation capabilities
///     simultaneously. The four well-known surfaces all serve correctly at
///     once and the federation EC parses into a structurally-correct
///     <see cref="EntityStatement"/>.
///   </description></item>
///   <item><description>
///     <strong>Per-tenant federation</strong>: two registrations on one
///     authorization server, each with its own federation entity identifier
///     and signing keypair. Each tenant's EC is independent — the
///     <c>iss</c>/<c>sub</c> equals that tenant's
///     <see cref="ClientRecord.FederationEntityId"/> and the JWKS publishes
///     only that tenant's federation signing keys.
///   </description></item>
/// </list>
[TestClass]
internal sealed class FederationEntityConfigurationEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// Serves an entity configuration alongside the registration's other metadata endpoints.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-9.2">Federation §9.2</see>.
    /// </summary>
    [TestMethod]
    public async Task FullConfigurationServesAllWellKnownsSideBySide()
    {
        await using TestHostShell app = new(TimeProvider);

        //One registration carries OAuth, OIDC, OID4VP, AND federation
        //capabilities simultaneously. All four well-knowns must serve from
        //the same tenant URL prefix without one path stomping another.
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri federationEntityId = new("https://verifier.example.com");
        const string ClientId = "https://verifier.example.com";
        Uri verifierBaseUri = new("https://verifier.example.com");

        using VerifierKeyMaterial verifierKeys = await app.RegisterFederationCapableClientAsync(
            ClientId,
            verifierBaseUri,
            federationEntityId,
            federationKeys,
            capabilities).ConfigureAwait(false);

        //Wire the federation-metadata contribution: publish an
        //openid_relying_party metadata block that lists the verifier's JAR
        //signing key. A real deployment would source this from durable
        //configuration; the test pulls the JAR signing public key off the
        //already-registered VerifierKeyMaterial so chain validation paths
        //downstream can use it.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeFederationMetadataAsync = (_, _, _) =>
            {
                Dictionary<string, object> openIdRelyingPartyMetadata = new(StringComparer.Ordinal)
                {
                    ["jwks"] = BuildJwksWithSingleEcKey(
                        verifierKeys.SigningPublicKey,
                        verifierKeys.SigningKeyId.Value),
                    ["client_name"] = "Full-configuration verifier"
                };

                return ValueTask.FromResult(new FederationEntityConfigurationContribution
                {
                    Metadata = new Dictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>>
                    {
                        [WellKnownEntityTypeIdentifiers.OpenIdRelyingParty] = openIdRelyingPartyMetadata
                    }
                });
            };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = verifierKeys.Registration.TenantId.Value;

        //Each of the four well-known endpoints serves a 200 response at its
        //own path under the tenant's segment.
        _ = await AssertEndpointReturnsAsync(host,
            $"/connect/{segment}/jwks",
            expectedContentType: WellKnownMediaTypes.Application.Json).ConfigureAwait(false);

        _ = await AssertEndpointReturnsAsync(host,
            $"/connect/{segment}/.well-known/openid-configuration",
            expectedContentType: WellKnownMediaTypes.Application.Json).ConfigureAwait(false);

        string compactEntityConfiguration = await AssertEndpointReturnsAsync(host,
            $"/connect/{segment}/.well-known/openid-federation",
            expectedContentType: WellKnownMediaTypes.Application.EntityStatementJwt).ConfigureAwait(false);

        //Parse the federation EC. The structural claims must match what the
        //library emitted from the registration; the openid_relying_party
        //metadata block must be present.
        EntityStatement statement = ParseEntityConfiguration(compactEntityConfiguration);

        Assert.AreEqual(federationEntityId.ToString(), statement.Issuer.Value,
            "EC iss must equal the registration's FederationEntityId.");
        Assert.AreEqual(federationEntityId.ToString(), statement.Subject.Value,
            "EC sub must equal iss for a self-signed Entity Configuration per Federation §3.1.");
        Assert.IsGreaterThan(statement.IssuedAt, statement.ExpiresAt,
            "EC exp must be strictly after iat.");
        IReadOnlyDictionary<string, object> metadataClaim = ExtractMetadataClaim(statement);
        Assert.IsTrue(metadataClaim.ContainsKey(WellKnownEntityTypeIdentifiers.OpenIdRelyingParty.Value),
            "EC metadata must include the openid_relying_party block the application contributed.");
    }


    /// <summary>
    /// Regression: the Entity Configuration signing path in
    /// <see cref="FederationEndpoints"/> must rent its signing-input and signature
    /// buffers from a pool that grants EXACT-length rentals. P-384 raw ECDSA
    /// signatures are 96 bytes (<c>2 * <see cref="EllipticCurveConstants.P384"/>.PointArrayLength</c>)
    /// — not a power of two — so a pool that rounds rentals up to the next
    /// power-of-two bucket (<c>System.Buffers.MemoryPool&lt;byte&gt;.Shared</c>) over-rents to
    /// 128 bytes. Because <see cref="Signature.Length"/> derives from the rented owner's
    /// <c>Memory.Length</c> without slicing, an over-rent silently produces a 128-byte wire
    /// signature that no verifier can validate against the 96-byte value the signing
    /// algorithm actually produced. Before the fix this test failed both assertions
    /// (a 128-byte signature segment, and a verification failure); after the fix
    /// (<see cref="BaseMemoryPool"/> at every <c>Jws.SignAsync</c> call site in
    /// <see cref="FederationEndpoints"/>) both pass.
    /// </summary>
    [TestMethod]
    public async Task EntityConfigurationSignatureIsExactLengthForNonPowerOfTwoAlgorithm()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP384KeyMaterial();

        Uri federationEntityId = new("https://p384-verifier.example.com");
        const string ClientId = "https://p384-verifier.example.com";
        Uri baseUri = new("https://p384-verifier.example.com");

        using VerifierKeyMaterial keys = await app.RegisterFederationCapableClientAsync(
            ClientId,
            baseUri,
            federationEntityId,
            federationKeys,
            ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode)).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = keys.Registration.TenantId.Value;

        string compactEc = await AssertEndpointReturnsAsync(host,
            $"/connect/{segment}/.well-known/openid-federation",
            expectedContentType: WellKnownMediaTypes.Application.EntityStatementJwt).ConfigureAwait(false);

        string[] parts = compactEc.Split('.');
        Assert.HasCount(3, parts, "EC must be a JWS compact serialization with three segments.");

        int expectedSignatureLength = 2 * EllipticCurveConstants.P384.PointArrayLength;
        using(IMemoryOwner<byte> signatureBytes = TestSetup.Base64UrlDecoder(parts[2], Pool))
        {
            Assert.HasCount(expectedSignatureLength, signatureBytes.Memory.ToArray(),
                $"P-384 JWS signature must be exactly {expectedSignatureLength} raw bytes (r||s); " +
                "a longer value means the signing pool over-rented and Signature.Length trusted " +
                "the rented buffer instead of the algorithm's actual output.");
        }

        bool verified = await VerifyEcAsync(
            compactEc, federationKeys.PublicKey, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified, "EC must verify under the P-384 federation public key.");
    }


    [TestMethod]
    public async Task EntityConfigurationAdvertisesSupportedClientRegistrationTypes()
    {
        await using TestHostShell app = new(TimeProvider);

        //The OP opts into BOTH automatic (§12.1) and explicit (§12.2) federation
        //registration. The library must advertise both in the published EC without
        //any application metadata contribution — derived from the capabilities alone.
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownFederationCapabilityIdentifiers.RegisterClientsAutomatically,
            WellKnownFederationCapabilityIdentifiers.RegisterClientsExplicitly);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri federationEntityId = new("https://op.example.com");
        const string ClientId = "https://op.example.com";
        Uri baseUri = new("https://op.example.com");

        using VerifierKeyMaterial keys = await app.RegisterFederationCapableClientAsync(
            ClientId, baseUri, federationEntityId, federationKeys, capabilities).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = keys.Registration.TenantId.Value;

        string compactEc = await AssertEndpointReturnsAsync(host,
            $"/connect/{segment}/.well-known/openid-federation",
            expectedContentType: WellKnownMediaTypes.Application.EntityStatementJwt).ConfigureAwait(false);

        EntityStatement statement = ParseEntityConfiguration(compactEc);
        List<string> advertised = ExtractClientRegistrationTypes(statement);

        Assert.HasCount(2, advertised,
            "Both registration types must be advertised when both capabilities are enabled.");
        Assert.Contains(WellKnownFederationRegistrationTypeValues.Automatic, advertised,
            "automatic must be advertised (RegisterClientsAutomatically is enabled).");
        Assert.Contains(WellKnownFederationRegistrationTypeValues.Explicit, advertised,
            "explicit must be advertised (RegisterClientsExplicitly is enabled).");
    }


    /// <summary>
    /// Preserves application-contributed client registration types in provider metadata.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.1.3">Federation §5.1.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ApplicationContributedRegistrationTypesAreNotOverwritten()
    {
        await using TestHostShell app = new(TimeProvider);

        //Capabilities enable both, but the application contributes an explicit-only
        //openid_provider value. The application's choice must win — the library
        //never overwrites a contributed client_registration_types_supported.
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownFederationCapabilityIdentifiers.RegisterClientsAutomatically,
            WellKnownFederationCapabilityIdentifiers.RegisterClientsExplicitly);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri federationEntityId = new("https://op2.example.com");
        const string ClientId = "https://op2.example.com";
        Uri baseUri = new("https://op2.example.com");

        using VerifierKeyMaterial keys = await app.RegisterFederationCapableClientAsync(
            ClientId, baseUri, federationEntityId, federationKeys, capabilities).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeFederationMetadataAsync = (_, _, _) =>
            {
                Dictionary<string, object> openIdProviderMetadata = new(StringComparer.Ordinal)
                {
                    [WellKnownFederationClaimNames.ClientRegistrationTypesSupported] =
                        new List<object> { WellKnownFederationRegistrationTypeValues.Explicit }
                };

                return ValueTask.FromResult(new FederationEntityConfigurationContribution
                {
                    Metadata = new Dictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>>
                    {
                        [WellKnownEntityTypeIdentifiers.OpenIdProvider] = openIdProviderMetadata
                    }
                });
            };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = keys.Registration.TenantId.Value;

        string compactEc = await AssertEndpointReturnsAsync(host,
            $"/connect/{segment}/.well-known/openid-federation",
            expectedContentType: WellKnownMediaTypes.Application.EntityStatementJwt).ConfigureAwait(false);

        EntityStatement statement = ParseEntityConfiguration(compactEc);
        List<string> advertised = ExtractClientRegistrationTypes(statement);

        Assert.HasCount(1, advertised,
            "The application contributed exactly one registration type; the library must not append.");
        Assert.Contains(WellKnownFederationRegistrationTypeValues.Explicit, advertised,
            "The application's explicit-only value must be preserved verbatim.");
    }


    /// <summary>
    /// The verification-key resolver's documented contract, a contract of this library: every
    /// resolution states the <see cref="KeyUsageContext"/> the key is expected under, and a publishing
    /// site names the set it publishes. The design follows
    /// <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.2">RFC 7517 §4.2</see>: "The "use"
    /// (public key use) parameter identifies the intended use of the public key." The Entity
    /// Configuration fetched over the wire is answered 200, and the resolver is asked for each key the
    /// registration publishes for federation entity signatures exactly once, under
    /// <see cref="KeyUsageContext.FederationEntitySignature"/>.
    /// </summary>
    [TestMethod]
    public async Task EntityConfigurationResolvesPublishedKeysUnderFederationEntitySignatureAsync()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri federationEntityId = new("https://usage-verifier.example.com");
        const string ClientId = "https://usage-verifier.example.com";
        Uri baseUri = new("https://usage-verifier.example.com");

        using VerifierKeyMaterial keys = await app.RegisterFederationCapableClientAsync(
            ClientId,
            baseUri,
            federationEntityId,
            federationKeys,
            ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode)).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = keys.Registration.TenantId.Value;
        List<KeyId> publishedKeyIds = [.. keys.Registration.SigningKeys[KeyUsageContext.FederationEntitySignature].PublishedKeys];
        Assert.IsNotEmpty(publishedKeyIds, "The registration publishes a federation entity signing key.");

        host.VerificationKeyResolutions.Clear();

        _ = await AssertEndpointReturnsAsync(host,
            $"/connect/{segment}/.well-known/openid-federation",
            expectedContentType: WellKnownMediaTypes.Application.EntityStatementJwt).ConfigureAwait(false);

        foreach(KeyId publishedKeyId in publishedKeyIds)
        {
            VerificationKeyResolution resolution = Assert.ContainsSingle(host.ResolutionsOf(publishedKeyId));
            Assert.AreEqual(KeyUsageContext.FederationEntitySignature, resolution.Usage);
        }
    }


    /// <summary>
    /// A client registration type the library lists from a capability is left out of
    /// <c>client_registration_types_supported</c> when the capability is outside the capabilities the Entity
    /// Configuration request is served under, in two forms: the application's materialization answers a
    /// registration without it with the capability added, which the dispatcher's bound withholds, or the
    /// application's capability resolution withholds it from a registration that allows it. The types are
    /// <c>automatic</c> and <c>explicit</c> of
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-5.1.3">OpenID Federation 1.0 section
    /// 5.1.3</see>. The Entity Configuration fetched over the wire is a signed statement, so its complete decoded
    /// claims are compared: the status, every header field and the decoded claims are the same as those of a
    /// registration that never held the capability, the time claims read from the one injected clock, and in the
    /// <c>jwks</c> claim only the values each registration generates afresh replaced, its key identifier and its
    /// public key's coordinates, each asserted well-formed. A materialization narrows what the server serves and never
    /// widens it, and a capability the resolution withholds is not served, which is this library's rule:
    /// <see href="../../../documents/AuthorizationServerDesign.md#23-per-endpoint-loop-stage">Server design</see>.
    /// </summary>
    /// <param name="registrationType"><c>automatic</c> or <c>explicit</c>.</param>
    /// <param name="form">
    /// <c>materializationAdds</c> or <c>resolutionWithholds</c>, as <see cref="CapabilityBounds"/> names them.
    /// </param>
    [TestMethod]
    [DataRow("automatic", "materializationAdds", DisplayName = "automatic, the materialization adds the capability")]
    [DataRow("automatic", "resolutionWithholds", DisplayName = "automatic, the capability resolution withholds the capability")]
    [DataRow("explicit", "materializationAdds", DisplayName = "explicit, the materialization adds the capability")]
    [DataRow("explicit", "resolutionWithholds", DisplayName = "explicit, the capability resolution withholds the capability")]
    public async Task ARegistrationTypeOutsideTheServedCapabilitiesIsNotListedAsync(string registrationType, string form)
    {
        CapabilityIdentifier capability = registrationType switch
        {
            "automatic" => WellKnownFederationCapabilityIdentifiers.RegisterClientsAutomatically,
            "explicit" => WellKnownFederationCapabilityIdentifiers.RegisterClientsExplicitly,
            _ => throw new ArgumentOutOfRangeException(nameof(registrationType), registrationType, "Unknown registration type.")
        };
        ImmutableHashSet<CapabilityIdentifier> neverHeld = ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthAuthorizationCode);

        (string underTheBound, string claims) = await GetEntityConfigurationUnderTheBoundAsync(
            CapabilityBounds.Registered(form, neverHeld, capability),
            CapabilityBounds.Wire(form, capability)).ConfigureAwait(false);
        (string neverHeldAnswer, _) = await GetEntityConfigurationUnderTheBoundAsync(neverHeld, bound: null).ConfigureAwait(false);

        Assert.AreEqual(neverHeldAnswer, underTheBound);
        Assert.StartsWith("200\n", underTheBound);
        Assert.DoesNotContain("client_registration_types_supported", claims);
    }


    /// <summary>
    /// Registers a federation-capable client with <paramref name="capabilities"/> and a fresh P-256 federation
    /// signing key under the entity identifier <c>https://bounded-op.example.com</c>, applies <paramref name="bound"/>
    /// to the server's integration when given, then fetches the Entity Configuration over the listener.
    /// </summary>
    /// <param name="capabilities">The capabilities the loaded registration allows besides publishing.</param>
    /// <param name="bound">
    /// The wiring that sets the capabilities the request is served under, from <see cref="CapabilityBounds.Wire"/>,
    /// or <see langword="null"/> for none.
    /// </param>
    /// <returns>
    /// The answer as <see cref="OAuthTestTransport.ProjectWireAnswer"/> projects it with the complete decoded claims,
    /// the values <see cref="ReplaceGeneratedKeyValues"/> names replaced, in place of the compact statement, and those
    /// claims as JSON text.
    /// </returns>
    private async Task<(string WireAnswer, string Claims)> GetEntityConfigurationUnderTheBoundAsync(
        ImmutableHashSet<CapabilityIdentifier> capabilities, Action<AuthorizationServerIntegration>? bound)
    {
        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> federationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using VerifierKeyMaterial keys = await app.RegisterFederationCapableClientAsync(
            "https://bounded-op.example.com",
            new Uri("https://bounded-op.example.com"),
            new Uri("https://bounded-op.example.com"),
            federationKeys,
            capabilities).ConfigureAwait(false);
        if(bound is not null)
        {
            await TestHostShell.AlterAsync(app.Server, bound).ConfigureAwait(false);
        }

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri url = new(host.HttpBaseAddress!, $"/connect/{keys.Registration.TenantId.Value}/.well-known/openid-federation");

        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string[] parts = body.Split('.');
        Assert.HasCount(3, parts, $"The Entity Configuration is a compact JWS. Body: {body}");
        using IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool);
        JsonObject claims = JsonNode.Parse(payloadBytes.Memory.Span)!.AsObject();
        ReplaceGeneratedKeyValues(claims);
        string claimsText = claims.ToJsonString();

        return (OAuthTestTransport.ProjectWireAnswer(response, claimsText), claimsText);
    }


    /// <summary>
    /// Replaces, in each JSON Web Key of the <c>jwks</c> claim of <paramref name="claims"/>, the values a registration
    /// generates afresh, each asserted well-formed first, and nothing else: the key identifier, a
    /// <c>urn:uuid:</c> URN of a UUID the fixture draws per registration, by <c>{kid}</c>, and the public key's
    /// coordinates <c>x</c> and <c>y</c>, each the base64url encoding of 32 octets of a fresh P-256 signing key, by
    /// <c>{x}</c> and <c>{y}</c>. Every other member of the claim, and the claim itself, is compared.
    /// </summary>
    /// <param name="claims">The decoded claims of the Entity Configuration, changed in place.</param>
    private static void ReplaceGeneratedKeyValues(JsonObject claims)
    {
        JsonArray jsonWebKeys = claims["jwks"]![WellKnownJwkMemberNames.Keys]!.AsArray();
        Assert.IsNotEmpty(jsonWebKeys, "The Entity Configuration publishes its signing key.");
        foreach(JsonNode? jsonWebKey in jsonWebKeys)
        {
            JsonObject jwk = jsonWebKey!.AsObject();
            string kid = jwk[WellKnownJwkMemberNames.Kid]!.GetValue<string>();
            Assert.IsTrue(
                kid.StartsWith("urn:uuid:", StringComparison.Ordinal) && Guid.TryParse(kid["urn:uuid:".Length..], out _), kid);
            jwk[WellKnownJwkMemberNames.Kid] = "{kid}";
            jwk[WellKnownJwkMemberNames.X] = ReplaceCoordinate(jwk[WellKnownJwkMemberNames.X]!.GetValue<string>(), "{x}");
            jwk[WellKnownJwkMemberNames.Y] = ReplaceCoordinate(jwk[WellKnownJwkMemberNames.Y]!.GetValue<string>(), "{y}");
        }
    }


    /// <summary>
    /// Asserts that <paramref name="coordinate"/> is the base64url encoding of the 32 octets of a P-256 coordinate and
    /// answers <paramref name="placeholder"/> in its place.
    /// </summary>
    /// <param name="coordinate">The coordinate as the JSON Web Key publishes it.</param>
    /// <param name="placeholder">The text that stands for it in the compared claims.</param>
    /// <returns><paramref name="placeholder"/>.</returns>
    private static string ReplaceCoordinate(string coordinate, string placeholder)
    {
        using IMemoryOwner<byte> octets = TestSetup.Base64UrlDecoder(coordinate, Pool);
        Assert.HasCount(32, octets.Memory.ToArray(), coordinate);

        return placeholder;
    }


    //Reads metadata.openid_provider.client_registration_types_supported out of a
    //parsed Entity Configuration as a list of string tokens.
    private static List<string> ExtractClientRegistrationTypes(EntityStatement statement)
    {
        IReadOnlyDictionary<string, object> metadata = ExtractMetadataClaim(statement);

        Assert.IsTrue(
            metadata.TryGetValue(WellKnownEntityTypeIdentifiers.OpenIdProvider.Value, out object? openIdProviderObj)
            && openIdProviderObj is IReadOnlyDictionary<string, object>,
            "EC metadata must include an openid_provider block.");

        Assert.IsTrue(
            ((IReadOnlyDictionary<string, object>)openIdProviderObj).TryGetValue(
                WellKnownFederationClaimNames.ClientRegistrationTypesSupported, out object? typesObj)
            && typesObj is IReadOnlyList<object>,
            "openid_provider must advertise client_registration_types_supported.");

        List<string> values = [];
        foreach(object item in (IReadOnlyList<object>)typesObj)
        {
            values.Add((string)item);
        }

        return values;
    }


    /// <summary>
    /// Emits each tenant's entity identity and verifies its configuration with that tenant's key.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1.1">Federation §3.1.1</see>.
    /// </summary>
    [TestMethod]
    public async Task PerTenantFederationConfigurationsAreIndependent()
    {
        await using TestHostShell app = new(TimeProvider);

        ImmutableHashSet<CapabilityIdentifier> baselineCapabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation);

        //Two distinct tenants — each with its own federation entity id and
        //its own federation signing keypair. Both registered on the SAME
        //authorization server.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> aliceFederationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> bobFederationKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        Uri aliceEntityId = new("https://alice.example.com");
        Uri bobEntityId = new("https://bob.example.com");

        using VerifierKeyMaterial aliceKeys = await app.RegisterFederationCapableClientAsync(
            clientId: "https://alice.example.com",
            baseUri: new Uri("https://alice.example.com"),
            federationEntityId: aliceEntityId,
            federationSigningKeyPair: aliceFederationKeys,
            baseCapabilities: baselineCapabilities).ConfigureAwait(false);

        using VerifierKeyMaterial bobKeys = await app.RegisterFederationCapableClientAsync(
            clientId: "https://bob.example.com",
            baseUri: new Uri("https://bob.example.com"),
            federationEntityId: bobEntityId,
            federationSigningKeyPair: bobFederationKeys,
            baseCapabilities: baselineCapabilities).ConfigureAwait(false);

        //Per-tenant metadata contribution dispatches on the requested
        //registration — Alice and Bob get different organization_name
        //claims. This proves queries flow through the AS pipeline at
        //request time and that mutation is per-call.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeFederationMetadataAsync = (registration, _, _) =>
            {
                string organizationName = string.Equals(
                    registration.FederationEntityId?.ToString(),
                    aliceEntityId.ToString(),
                    StringComparison.Ordinal)
                        ? "Alice Verifier Co."
                        : "Bob Verifier Inc.";

                Dictionary<string, object> federationEntityMetadata = new(StringComparer.Ordinal)
                {
                    ["organization_name"] = organizationName
                };

                return ValueTask.FromResult(new FederationEntityConfigurationContribution
                {
                    Metadata = new Dictionary<EntityTypeIdentifier, IReadOnlyDictionary<string, object>>
                    {
                        [WellKnownEntityTypeIdentifiers.FederationEntity] = federationEntityMetadata
                    }
                });
            };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        //Alice's EC.
        string aliceCompactEc = await AssertEndpointReturnsAsync(host,
            $"/connect/{aliceKeys.Registration.TenantId.Value}/.well-known/openid-federation",
            expectedContentType: WellKnownMediaTypes.Application.EntityStatementJwt).ConfigureAwait(false);
        EntityStatement aliceStatement = ParseEntityConfiguration(aliceCompactEc);
        Assert.AreEqual(aliceEntityId.ToString(), aliceStatement.Issuer.Value);
        IReadOnlyDictionary<string, object> aliceMetadata = ExtractMetadataClaim(aliceStatement);
        IReadOnlyDictionary<string, object> aliceFederationMetadata =
            (IReadOnlyDictionary<string, object>)aliceMetadata[WellKnownEntityTypeIdentifiers.FederationEntity.Value];
        Assert.AreEqual("Alice Verifier Co.", aliceFederationMetadata["organization_name"]);

        //Bob's EC.
        string bobCompactEc = await AssertEndpointReturnsAsync(host,
            $"/connect/{bobKeys.Registration.TenantId.Value}/.well-known/openid-federation",
            expectedContentType: WellKnownMediaTypes.Application.EntityStatementJwt).ConfigureAwait(false);
        EntityStatement bobStatement = ParseEntityConfiguration(bobCompactEc);
        Assert.AreEqual(bobEntityId.ToString(), bobStatement.Issuer.Value);
        IReadOnlyDictionary<string, object> bobMetadata = ExtractMetadataClaim(bobStatement);
        IReadOnlyDictionary<string, object> bobFederationMetadata =
            (IReadOnlyDictionary<string, object>)bobMetadata[WellKnownEntityTypeIdentifiers.FederationEntity.Value];
        Assert.AreEqual("Bob Verifier Inc.", bobFederationMetadata["organization_name"]);

        //Alice's EC must be signed with Alice's federation key — Bob's
        //public key must fail to verify Alice's EC and vice versa. This
        //asserts the per-tenant key isolation at the wire layer.
        bool aliceUnderAliceKey = await VerifyEcAsync(
            aliceCompactEc, aliceFederationKeys.PublicKey, TestContext.CancellationToken).ConfigureAwait(false);
        bool aliceUnderBobKey = await VerifyEcAsync(
            aliceCompactEc, bobFederationKeys.PublicKey, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(aliceUnderAliceKey,
            "Alice's EC must verify under Alice's federation public key.");
        Assert.IsFalse(aliceUnderBobKey,
            "Alice's EC must NOT verify under Bob's federation public key.");
    }


    private static Dictionary<string, object> BuildJwksWithSingleEcKey(
        PublicKeyMemory publicKey,
        string kid)
    {
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            publicKey.Tag.Get<CryptoAlgorithm>(),
            publicKey.Tag.Get<Purpose>(),
            publicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);
        jwk.Kid = kid;
        jwk.Use = WellKnownJwkValues.UseSig;

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            ["keys"] = new List<object> { jwk }
        };
    }


    private async ValueTask<string> AssertEndpointReturnsAsync(
        HostedAuthorizationServer host,
        string absolutePath,
        string expectedContentType)
    {
        Uri url = new(host.HttpBaseAddress!, absolutePath);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            $"GET {absolutePath} must return 200. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");

        string? actualContentType = response.Content.Headers.ContentType?.MediaType;
        Assert.AreEqual(expectedContentType, actualContentType,
            $"GET {absolutePath} must serve {expectedContentType}.");

        return await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Pulls the <c>metadata</c> claim out of an
    /// <see cref="EntityStatement"/>'s carried payload. The library's
    /// <see cref="EntityStatement"/> intentionally does not pre-deserialise
    /// nested-object claims; consumers read them from
    /// <see cref="EntityStatement.Payload"/> on demand. STJ deserialises
    /// the nested object into <see cref="JsonElement"/>; this helper
    /// projects it back into the plain
    /// <see cref="IReadOnlyDictionary{TKey, TValue}"/> shape the contributor
    /// supplied.
    /// </summary>
    private static IReadOnlyDictionary<string, object> ExtractMetadataClaim(EntityStatement statement)
    {
        Assert.IsTrue(statement.Payload.TryGetValue("metadata", out object? metadataObj),
            "EC payload must carry the contributed metadata claim.");

        return metadataObj switch
        {
            IReadOnlyDictionary<string, object> dict => dict,
            JsonElement element when element.ValueKind == JsonValueKind.Object => MaterializeJsonObject(element),
            _ => throw new InvalidOperationException(
                $"Unexpected metadata claim CLR type '{metadataObj.GetType().FullName}'.")
        };
    }


    /// <summary>
    /// Recursively materialises an STJ <see cref="JsonElement"/> object
    /// into the same <see cref="Dictionary{TKey, TValue}"/> /
    /// <see cref="List{T}"/> / primitive tree the federation contributor
    /// supplied. Used after STJ-based EC payload parsing so the test reads
    /// metadata blocks back in their original CLR shape.
    /// </summary>
    private static Dictionary<string, object> MaterializeJsonObject(JsonElement element)
    {
        Dictionary<string, object> result = new(StringComparer.Ordinal);
        foreach(JsonProperty property in element.EnumerateObject())
        {
            object? value = MaterializeJsonValue(property.Value);
            if(value is not null)
            {
                result[property.Name] = value;
            }
        }

        return result;
    }


    private static object? MaterializeJsonValue(JsonElement element) => element.ValueKind switch
    {
        JsonValueKind.String => element.GetString(),
        JsonValueKind.Number when element.TryGetInt64(out long l) => l,
        JsonValueKind.Number => element.GetDouble(),
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Null => null,
        JsonValueKind.Object => MaterializeJsonObject(element),
        JsonValueKind.Array => MaterializeJsonArray(element),
        JsonValueKind.Undefined => null,
        _ => null
    };


    private static List<object> MaterializeJsonArray(JsonElement element)
    {
        List<object> result = [];
        foreach(JsonElement item in element.EnumerateArray())
        {
            object? value = MaterializeJsonValue(item);
            if(value is not null)
            {
                result.Add(value);
            }
        }

        return result;
    }


    private static EntityStatement ParseEntityConfiguration(string compactJws)
    {
        string[] parts = compactJws.Split('.');
        Assert.HasCount(3, parts,
            "EC must be a JWS compact serialization with three segments.");

        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], Pool);
        using IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool);

        Dictionary<string, object> headerDict = JsonSerializer.Deserialize<Dictionary<string, object>>(
            headerBytes.Memory.Span, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("EC header parsed to null.");
        Dictionary<string, object> payloadDict = JsonSerializer.Deserialize<Dictionary<string, object>>(
            payloadBytes.Memory.Span, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("EC payload parsed to null.");

        UnverifiedJwtHeader header = new(headerDict);
        UnverifiedJwtPayload payload = new(payloadDict);
        EntityStatementParseResult result = EntityStatementParser.Parse(header, payload);
        Assert.IsNotNull(result.Statement,
            $"EC must parse as an EntityStatement. Failure: {result.FailureReason}");

        return result.Statement;
    }


    private static async ValueTask<bool> VerifyEcAsync(
        string compactJws, PublicKeyMemory publicKey, CancellationToken cancellationToken)
    {
        return await Jws.VerifyAsync(
            compactJws,
            TestSetup.Base64UrlDecoder,
            Pool,
            publicKey,
            cancellationToken).ConfigureAwait(false);
    }
}
