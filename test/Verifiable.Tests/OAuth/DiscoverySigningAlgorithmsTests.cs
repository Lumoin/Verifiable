using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Introspection;
using Verifiable.OAuth.Jarm;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Pins the host-supplied, per-usage signing-algorithm input at both discovery mounts.
/// </summary>
[TestClass]
internal sealed class DiscoverySigningAlgorithmsTests
{
    /// <summary>The runner's cancellation and diagnostic context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The fixture clock.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The registered consumer identifier.</summary>
    private const string ClientId = "https://discovery-algorithms.client.test";

    /// <summary>The registered consumer's base URI.</summary>
    private static Uri ClientBaseUri { get; } = new(ClientId);

    /// <summary>The existing discovery members and the protocol usages they describe.</summary>
    private static IReadOnlyList<(string Field, KeyUsageContext Usage)> AlgorithmMembers { get; } =
    [
        (OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported, KeyUsageContext.IdTokenIssuance),
        (JarmServerMetadataParameterNames.AuthorizationSigningAlgValuesSupported, KeyUsageContext.AuthorizationResponseSigning),
        (IntrospectionServerMetadataParameterNames.IntrospectionSigningAlgValuesSupported, KeyUsageContext.IntrospectionResponseSigning),
        (AuthorizationServerMetadataParameterNames.DpopSigningAlgValuesSupported, KeyUsageContext.DpopProof),
        (AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported, KeyUsageContext.ClientAssertion)
    ];


    /// <summary>
    /// A host holding RSA and P-256 material supplies both ID-token algorithms even when
    /// the registration's default key set names only its P-256 key.
    /// </summary>
    /// <param name="oauthMetadata">Whether to request the RFC 8414 mount.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task DiscoveryUsesHostSuppliedIdTokenAlgorithms(bool oauthMetadata)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> rsa = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using PublicKeyMemory rsaPublicKey = rsa.PublicKey;
        using PrivateKeyMemory rsaPrivateKey = rsa.PrivateKey;
        string[] supported =
        [
            CryptoFormatConversions.DefaultTagToJwaConverter(rsaPublicKey.Tag),
            CryptoFormatConversions.DefaultTagToJwaConverter(material.SigningPublicKey.Tag)
        ];
        List<KeyUsageContext> requestedUsages = [];

        await TestHostShell.AlterAsync(host.Server, integration =>
        {
            integration.Cryptography.ResolveSupportedSigningAlgorithmsAsync = (registration, usage, context, ct) =>
            {
                Assert.AreEqual(material.Registration.TenantId, registration.TenantId);
                Assert.AreSame(registration, context.ClientRegistration);
                Assert.AreEqual(TestContext.CancellationToken, ct);
                requestedUsages.Add(usage);
                return ValueTask.FromResult<IReadOnlyList<string>>(
                    usage == KeyUsageContext.IdTokenIssuance ? supported : []);
            };
        }).ConfigureAwait(false);

        host.Host("default").VerificationKeyResolutions.Clear();
        using JsonDocument document = await ReadDiscoveryAsync(host, material, oauthMetadata).ConfigureAwait(false);

        AssertAlgorithms(document, OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported, supported);
        Assert.Contains(KeyUsageContext.IdTokenIssuance, requestedUsages);
        Assert.IsEmpty(host.Host("default").VerificationKeyResolutions,
            "Supplying the algorithms must bypass the metadata composer's key resolution.");
    }


    /// <summary>
    /// Leaving the delegate unset retains every existing signing-algorithm declaration:
    /// current-key tags for server signatures and the accepted-client-signature defaults.
    /// </summary>
    /// <param name="oauthMetadata">Whether to request the RFC 8414 mount.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task DiscoveryWithoutAlgorithmDelegatePreservesExistingLists(bool oauthMetadata)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllAlgorithmMembersAsync(host).ConfigureAwait(false);
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(material.SigningPublicKey.Tag);

        using JsonDocument document = await ReadDiscoveryAsync(host, material, oauthMetadata).ConfigureAwait(false);

        AssertAlgorithms(document, OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported, [algorithm]);
        AssertAlgorithms(document, JarmServerMetadataParameterNames.AuthorizationSigningAlgValuesSupported, [algorithm]);
        AssertAlgorithms(document, IntrospectionServerMetadataParameterNames.IntrospectionSigningAlgValuesSupported, [algorithm]);
        AssertAlgorithms(document, AuthorizationServerMetadataParameterNames.DpopSigningAlgValuesSupported,
            WellKnownDpopValues.SupportedSigningAlgorithms);
        AssertAlgorithms(document, AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported, [algorithm]);
    }


    /// <summary>
    /// Supplying the single current key's algorithm leaves the whole document unchanged;
    /// the host can explicitly delegate its other usages to the public default helper.
    /// </summary>
    /// <param name="oauthMetadata">Whether to request the RFC 8414 mount.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task DiscoverySuppliedSingleKeyAlgorithmMatchesDefault(bool oauthMetadata)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllAlgorithmMembersAsync(host).ConfigureAwait(false);
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(material.SigningPublicKey.Tag);
        using JsonDocument defaultDocument = await ReadDiscoveryAsync(host, material, oauthMetadata).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, integration =>
        {
            integration.Cryptography.ResolveSupportedSigningAlgorithmsAsync = (registration, usage, context, ct) =>
                usage == KeyUsageContext.IdTokenIssuance
                    ? ValueTask.FromResult<IReadOnlyList<string>>([algorithm])
                    : DefaultSupportedSigningAlgorithms.ResolveAsync(
                        context.RequestServer!.OAuth(), registration, usage, context, ct);
        }).ConfigureAwait(false);

        using JsonDocument suppliedDocument = await ReadDiscoveryAsync(host, material, oauthMetadata).ConfigureAwait(false);

        Assert.AreEqual(defaultDocument.RootElement.GetRawText(), suppliedDocument.RootElement.GetRawText(),
            "A supplied singleton matching the current key must preserve the default document.");
    }


    /// <summary>
    /// Distinct per-usage lists reach every signing-algorithm member at both mounts,
    /// without merging key-derived or accepted-client-signature defaults into them.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryUsesOneInputForEverySigningAlgorithmMemberAtBothMounts()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllAlgorithmMembersAsync(host).ConfigureAwait(false);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> rsa = TestKeyMaterialProvider.CreateRsa2048KeyMaterial();
        using PublicKeyMemory rsaPublicKey = rsa.PublicKey;
        using PrivateKeyMemory rsaPrivateKey = rsa.PrivateKey;
        string rsaAlgorithm = CryptoFormatConversions.DefaultTagToJwaConverter(rsaPublicKey.Tag);
        string ecAlgorithm = CryptoFormatConversions.DefaultTagToJwaConverter(material.SigningPublicKey.Tag);
        Dictionary<KeyUsageContext, IReadOnlyList<string>> supported =
            new()
            {
                [KeyUsageContext.IdTokenIssuance] = [rsaAlgorithm, ecAlgorithm],
                [KeyUsageContext.AuthorizationResponseSigning] = [ecAlgorithm, rsaAlgorithm],
                [KeyUsageContext.IntrospectionResponseSigning] = [rsaAlgorithm],
                [KeyUsageContext.DpopProof] = [ecAlgorithm],
                [KeyUsageContext.ClientAssertion] = [rsaAlgorithm]
            };
        List<KeyUsageContext> requestedUsages = [];

        await TestHostShell.AlterAsync(host.Server, integration =>
        {
            integration.Cryptography.ResolveSupportedSigningAlgorithmsAsync = (_, usage, _, _) =>
            {
                requestedUsages.Add(usage);
                return ValueTask.FromResult(supported[usage]);
            };
        }).ConfigureAwait(false);

        host.Host("default").VerificationKeyResolutions.Clear();
        using JsonDocument oidc = await ReadDiscoveryAsync(host, material, false).ConfigureAwait(false);
        using JsonDocument oauth = await ReadDiscoveryAsync(host, material, true).ConfigureAwait(false);

        Assert.AreEqual(oidc.RootElement.GetRawText(), oauth.RootElement.GetRawText());
        foreach((string field, KeyUsageContext usage) in AlgorithmMembers)
        {
            AssertAlgorithms(oidc, field, supported[usage]);
            AssertAlgorithms(oauth, field, supported[usage]);
            Assert.AreEqual(2, requestedUsages.Count(requested => requested == usage),
                $"Each document must obtain {field} from its own usage input once.");
        }
        Assert.HasCount(2 * AlgorithmMembers.Count, requestedUsages);
        Assert.IsEmpty(host.Host("default").VerificationKeyResolutions);
    }


    /// <summary>
    /// An explicitly empty host input omits every algorithm member, even with keys and
    /// validation declarations present. Only an absent delegate selects the default.
    /// </summary>
    /// <param name="oauthMetadata">Whether to request the RFC 8414 mount.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task DiscoveryEmptySuppliedListsDoNotFallBackToDefaults(bool oauthMetadata)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterAllAlgorithmMembersAsync(host).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, integration =>
        {
            integration.Cryptography.ResolveSupportedSigningAlgorithmsAsync = static (_, _, _, _) =>
                ValueTask.FromResult<IReadOnlyList<string>>([]);
        }).ConfigureAwait(false);

        using JsonDocument document = await ReadDiscoveryAsync(host, material, oauthMetadata).ConfigureAwait(false);

        foreach((string field, KeyUsageContext _) in AlgorithmMembers)
        {
            Assert.IsFalse(document.RootElement.TryGetProperty(field, out _),
                $"An empty supplied list must omit {field} without deriving a replacement.");
        }
        Assert.IsFalse(document.RootElement.TryGetProperty(AuthorizationServerMetadataParameterNames.ResponseModesSupported, out _),
            "JARM modes require declared authorization-response signing support.");
    }


    /// <summary>
    /// A discovery-only registration cannot gain gated signing members from a nonempty
    /// input, and neither a JAR key nor the delegate invents a request-object member.
    /// </summary>
    /// <param name="oauthMetadata">Whether to request the RFC 8414 mount.</param>
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task DiscoveryDoesNotInventMembersOrBypassEndpointGates(bool oauthMetadata)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce,
            capabilities: ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint)).ConfigureAwait(false);
        await host.UpdateSigningKeysAsync(material.Registration.TenantId.Value,
            material.Registration.SigningKeys.ToImmutableDictionary().SetItem(
                KeyUsageContext.JarSigning, new SigningKeySet { Current = [material.SigningKeyId] })).ConfigureAwait(false);
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(material.SigningPublicKey.Tag);
        List<KeyUsageContext> requestedUsages = [];

        await TestHostShell.AlterAsync(host.Server, integration =>
        {
            integration.Cryptography.ResolveSupportedSigningAlgorithmsAsync = (_, usage, _, _) =>
            {
                requestedUsages.Add(usage);
                return ValueTask.FromResult<IReadOnlyList<string>>([algorithm]);
            };
        }).ConfigureAwait(false);

        using JsonDocument document = await ReadDiscoveryAsync(host, material, oauthMetadata).ConfigureAwait(false);

        Assert.AreEqual(KeyUsageContext.IdTokenIssuance, Assert.ContainsSingle(requestedUsages));
        AssertAlgorithms(document, OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported, [algorithm]);
        foreach((string field, KeyUsageContext usage) in AlgorithmMembers)
        {
            if(usage != KeyUsageContext.IdTokenIssuance)
            {
                Assert.IsFalse(document.RootElement.TryGetProperty(field, out _),
                    $"Supplying algorithms cannot enable the gated member {field}.");
            }
        }
        Assert.IsFalse(document.RootElement.TryGetProperty(
            AuthorizationServerMetadataParameterNames.RequestObjectSigningAlgValuesSupported, out _),
            "The composer did not previously emit request-object signing algorithms.");
    }


    /// <summary>
    /// The default resolves only current keys under the advertised usage, skips unresolved
    /// keys and deduplicates tags without including keys from other rotation slots.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryDefaultUsesOnlyDistinctResolvedCurrentKeyAlgorithms()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce).ConfigureAwait(false);
        KeyId secondCurrentKey = host.AllocateSigningKey();
        KeyId unresolvedKey = new("discovery-unresolved-key");
        KeyId otherSlotKey = new("discovery-other-slot-key");
        KeyId[] currentKeys = [material.SigningKeyId, unresolvedKey, secondCurrentKey];
        List<KeyId> resolutions = [];
        await host.UpdateSigningKeysAsync(material.Registration.TenantId.Value,
            material.Registration.SigningKeys.ToImmutableDictionary().SetItem(
                KeyUsageContext.IdTokenIssuance, new SigningKeySet
                {
                    Current = [.. currentKeys],
                    Incoming = [otherSlotKey],
                    Retiring = [otherSlotKey],
                    Historical = [otherSlotKey]
                })).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, integration =>
        {
            integration.Cryptography.VerificationKeyResolver = (keyId, usage, tenantId, context, ct) =>
            {
                Assert.AreEqual(KeyUsageContext.IdTokenIssuance, usage);
                Assert.AreEqual(material.Registration.TenantId, tenantId);
                Assert.AreEqual(TestContext.CancellationToken, ct);
                resolutions.Add(keyId);
                return ValueTask.FromResult<PublicKeyMemory?>(keyId == unresolvedKey ? null : material.SigningPublicKey);
            };
        }).ConfigureAwait(false);

        using JsonDocument document = await ReadDiscoveryAsync(host, material, false).ConfigureAwait(false);

        AssertAlgorithms(document, OpenIdProviderMetadataParameterNames.IdTokenSigningAlgValuesSupported,
            [CryptoFormatConversions.DefaultTagToJwaConverter(material.SigningPublicKey.Tag)]);
        Assert.AreSequenceEqual(currentKeys, resolutions);
    }


    /// <summary>Registers a host with every currently composed algorithm member enabled.</summary>
    /// <param name="host">The host whose registration and wiring are populated.</param>
    /// <returns>The caller-owned registration key material.</returns>
    private static async Task<VerifierKeyMaterial> RegisterAllAlgorithmMembersAsync(TestHostShell host)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthTokenIntrospection);
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: capabilities).ConfigureAwait(false);
        await host.UpdateSigningKeysAsync(material.Registration.TenantId.Value,
            material.Registration.SigningKeys.ToImmutableDictionary()
                .SetItem(KeyUsageContext.AuthorizationResponseSigning, new SigningKeySet { Current = [material.SigningKeyId] })
                .SetItem(KeyUsageContext.IntrospectionResponseSigning, new SigningKeySet { Current = [material.SigningKeyId] }))
            .ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, integration =>
        {
            integration.ValidateClientCredentialsAsync = static (_, _, _, _) => ValueTask.FromResult(true);
            integration.IntrospectTokenAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(new TokenIntrospectionResult { IsActive = false });
            integration.ClientAssertionSigningAlgorithmsSupported =
                [CryptoFormatConversions.DefaultTagToJwaConverter(material.SigningPublicKey.Tag)];
        }).ConfigureAwait(false);

        return material;
    }


    /// <summary>Dispatches a discovery request through the fixture's in-process pipeline.</summary>
    /// <param name="host">The host to dispatch to.</param>
    /// <param name="material">The registration whose discovery document is requested.</param>
    /// <param name="oauthMetadata">Whether to request the RFC 8414 mount.</param>
    /// <returns>The caller-owned parsed discovery document.</returns>
    private async Task<JsonDocument> ReadDiscoveryAsync(
        TestHostShell host, VerifierKeyMaterial material, bool oauthMetadata)
    {
        string endpointName = oauthMetadata
            ? WellKnownEndpointNames.MetadataOAuthAuthorizationServer
            : WellKnownEndpointNames.MetadataDiscovery;
        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value, endpointName, WellKnownHttpMethods.Get,
            new RequestFields(), [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, response.StatusCode, response.Body);

        return JsonDocument.Parse(response.Body);
    }


    /// <summary>Checks the complete ordered algorithm list emitted for a member.</summary>
    /// <param name="document">The served discovery document.</param>
    /// <param name="field">The well-known member name.</param>
    /// <param name="expected">The complete expected list.</param>
    private static void AssertAlgorithms(JsonDocument document, string field, IReadOnlyList<string> expected)
    {
        Assert.IsTrue(document.RootElement.TryGetProperty(field, out JsonElement algorithms),
            $"Discovery must advertise {field}.");
        Assert.AreEqual(JsonValueKind.Array, algorithms.ValueKind);
        string[] actual = algorithms.EnumerateArray().Select(static value => value.GetString()!).ToArray();
        Assert.AreSequenceEqual(expected, actual, field);
    }
}
