using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
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

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider();

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;


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

        using VerifierKeyMaterial verifierKeys = app.RegisterFederationCapableClient(
            ClientId,
            verifierBaseUri,
            federationEntityId,
            federationKeys,
            capabilities);

        //Wire the federation-metadata contribution: publish an
        //openid_relying_party metadata block that lists the verifier's JAR
        //signing key. A real deployment would source this from durable
        //configuration; the test pulls the JAR signing public key off the
        //already-registered VerifierKeyMaterial so chain validation paths
        //downstream can use it.
        app.Server.OAuth().ContributeFederationMetadataAsync = (_, _, _) =>
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

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");

        string segment = verifierKeys.Registration.TenantId.Value;

        //Each of the four well-known endpoints serves a 200 response at its
        //own path under the tenant's segment.
        await AssertEndpointReturnsAsync(host,
            $"/connect/{segment}/jwks",
            expectedContentType: WellKnownMediaTypes.Application.Json).ConfigureAwait(false);

        await AssertEndpointReturnsAsync(host,
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

        using VerifierKeyMaterial keys = app.RegisterFederationCapableClient(
            ClientId, baseUri, federationEntityId, federationKeys, capabilities);

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

        using VerifierKeyMaterial keys = app.RegisterFederationCapableClient(
            ClientId, baseUri, federationEntityId, federationKeys, capabilities);

        app.Server.OAuth().ContributeFederationMetadataAsync = (_, _, _) =>
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


    //Reads metadata.openid_provider.client_registration_types_supported out of a
    //parsed Entity Configuration as a list of string tokens.
    private static List<string> ExtractClientRegistrationTypes(EntityStatement statement)
    {
        IReadOnlyDictionary<string, object> metadata = ExtractMetadataClaim(statement);

        Assert.IsTrue(
            metadata.TryGetValue(WellKnownEntityTypeIdentifiers.OpenIdProvider.Value, out object? openIdProviderObj)
            && openIdProviderObj is IReadOnlyDictionary<string, object> openIdProviderBlock,
            "EC metadata must include an openid_provider block.");

        Assert.IsTrue(
            ((IReadOnlyDictionary<string, object>)openIdProviderObj!).TryGetValue(
                WellKnownFederationClaimNames.ClientRegistrationTypesSupported, out object? typesObj)
            && typesObj is IReadOnlyList<object> typeItems,
            "openid_provider must advertise client_registration_types_supported.");

        List<string> values = [];
        foreach(object item in (IReadOnlyList<object>)typesObj!)
        {
            values.Add((string)item);
        }

        return values;
    }


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

        using VerifierKeyMaterial aliceKeys = app.RegisterFederationCapableClient(
            clientId: "https://alice.example.com",
            baseUri: new Uri("https://alice.example.com"),
            federationEntityId: aliceEntityId,
            federationSigningKeyPair: aliceFederationKeys,
            baseCapabilities: baselineCapabilities);

        using VerifierKeyMaterial bobKeys = app.RegisterFederationCapableClient(
            clientId: "https://bob.example.com",
            baseUri: new Uri("https://bob.example.com"),
            federationEntityId: bobEntityId,
            federationSigningKeyPair: bobFederationKeys,
            baseCapabilities: baselineCapabilities);

        //Per-tenant metadata contribution dispatches on the requested
        //registration — Alice and Bob get different organization_name
        //claims. This proves queries flow through the AS pipeline at
        //request time and that mutation is per-call.
        app.Server.OAuth().ContributeFederationMetadataAsync = (registration, _, _) =>
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

        return result.Statement!;
    }


    private static async ValueTask<bool> VerifyEcAsync(
        string compactJws, PublicKeyMemory publicKey, CancellationToken cancellationToken)
    {
        return await Jws.VerifyAsync(
            compactJws,
            TestSetup.Base64UrlDecoder,
            static bytes => JsonSerializer.Deserialize<Dictionary<string, object>>(
                bytes, TestSetup.DefaultSerializationOptions)
                ?? throw new FormatException("Header parsed to null."),
            Pool,
            publicKey,
            cancellationToken).ConfigureAwait(false);
    }
}
