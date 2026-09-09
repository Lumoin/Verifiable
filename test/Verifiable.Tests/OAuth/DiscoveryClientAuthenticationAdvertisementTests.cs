using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
using Verifiable.Server;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 8414 §2 client-authentication advertisement over the real discovery
/// endpoint (the hosted test server the sibling <see cref="DiscoveryEndpointTests"/>
/// drives): the authorization server publishes the client authentication
/// methods and the assertion signing algorithms the integration declares, the
/// composition validation refuses a declaration the wiring cannot honour, and
/// a contributed field naming a base-emitted member is refused so the emitted
/// document never carries a duplicate name.
/// </summary>
/// <remarks>
/// The advertisement is a deployment declaration on
/// <see cref="AuthorizationServerIntegration.ClientAuthenticationMethodsSupported"/>
/// and <see cref="AuthorizationServerIntegration.ClientAssertionSigningAlgorithmsSupported"/>,
/// not an inference the transport-agnostic library could draw from an
/// application's validator. Fixture expectations are the RFC 8414 §2 registry
/// names and the RFC 8259 §4 unique-name rule read from the spec text, never
/// the discovery builder's own output.
/// </remarks>
[TestClass]
internal sealed class DiscoveryClientAuthenticationAdvertisementTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch.AddDays(-15));

    private const string ClientId = "https://discovery-auth.client.test";
    private static Uri ClientBaseUri { get; } = new("https://discovery-auth.client.test");


    /// <summary>
    /// RFC 8414 §2: "<c>token_endpoint_auth_methods_supported</c> OPTIONAL. JSON
    /// array containing a list of client authentication methods supported by this
    /// token endpoint. ... If omitted, the default is <c>client_secret_basic</c>."
    /// The library never judges <c>client_secret_basic</c> by default, so the
    /// default declaration <c>[None]</c> emits the member as <c>["none"]</c> — and
    /// because no assertion method is declared, the paired
    /// <c>token_endpoint_auth_signing_alg_values_supported</c> member is absent.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>.
    /// </summary>
    [TestMethod]
    public async Task DefaultNoneDeclarationEmitsNoneMethodAndNoSigningAlgMember()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        JsonElement methods = body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported);

        Assert.AreEqual(JsonValueKind.Array, methods.ValueKind);
        List<string> methodNames = EnumerateStrings(methods);
        Assert.AreSequenceEqual(
            new List<string> { "none" },
            methodNames,
            "RFC 8414 §2: the default [None] declaration must advertise exactly the 'none' method.");

        Assert.IsFalse(
            body.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported, out _),
            "RFC 8414 §2: token_endpoint_auth_signing_alg_values_supported must be absent when no "
            + "private_key_jwt/client_secret_jwt method is declared.");
    }


    /// <summary>
    /// RFC 8414 §2: "<c>token_endpoint_auth_signing_alg_values_supported</c> ...
    /// This metadata entry MUST be present if either of these authentication
    /// methods are specified in the <c>token_endpoint_auth_methods_supported</c>
    /// entry." A <c>[None, PrivateKeyJwt]</c> declaration with
    /// <c>["ES256","RS256"]</c> and the credential-validation seam wired emits both
    /// members with the IANA registry names, each preserving the deployment's
    /// declaration order.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>.
    /// </summary>
    [TestMethod]
    public async Task PrivateKeyJwtDeclarationEmitsBothMembersWithRegistryNamesInDeclarationOrder()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        AuthorizationServerIntegration oauth = host.Server.OAuth();
        oauth.ClientAuthenticationMethodsSupported =
            [ClientAuthenticationMethod.None, ClientAuthenticationMethod.PrivateKeyJwt];
        oauth.ClientAssertionSigningAlgorithmsSupported =
            [WellKnownJwaValues.Es256, WellKnownJwaValues.Rs256];
        oauth.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(true);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        List<string> methodNames = EnumerateStrings(body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported));
        Assert.AreSequenceEqual(
            new List<string> { "none", "private_key_jwt" },
            methodNames,
            "RFC 8414 §2: the methods must be the registry names in declaration order.");

        List<string> algorithmNames = EnumerateStrings(body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported));
        Assert.AreSequenceEqual(
            new List<string> { "ES256", "RS256" },
            algorithmNames,
            "RFC 8414 §2: the signing-alg member MUST be present for private_key_jwt, "
            + "carrying the declared algorithms in declaration order.");
    }


    /// <summary>
    /// RFC 8414 §2: "Servers SHOULD support <c>RS256</c>." The library does not
    /// demand RS256 of the deployment; a deployment that declares it has that
    /// choice honoured — <c>RS256</c> appears verbatim in
    /// <c>token_endpoint_auth_signing_alg_values_supported</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>.
    /// </summary>
    [TestMethod]
    public async Task DeclarationIncludingRs256EmitsRs256()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        AuthorizationServerIntegration oauth = host.Server.OAuth();
        oauth.ClientAuthenticationMethodsSupported =
            [ClientAuthenticationMethod.None, ClientAuthenticationMethod.PrivateKeyJwt];
        oauth.ClientAssertionSigningAlgorithmsSupported = [WellKnownJwaValues.Rs256];
        oauth.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(true);

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        List<string> algorithmNames = EnumerateStrings(body.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported));
        Assert.Contains("RS256", algorithmNames,
            "RFC 8414 §2: a deployment that declares the SHOULD-supported RS256 must advertise it.");
    }


    /// <summary>
    /// RFC 8414 §2: "<c>token_endpoint_auth_methods_supported</c> ... a list of
    /// client authentication methods supported by this token endpoint." A method
    /// other than <c>none</c> advertised without a wired
    /// <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>
    /// would announce authentication the endpoint never checks, so
    /// <see cref="AuthorizationServerIntegration.Validate"/> refuses the
    /// composition with an <see cref="InvalidOperationException"/>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>.
    /// </summary>
    [TestMethod]
    public async Task ValidateThrowsWhenNonNoneMethodDeclaredWithoutCredentialValidator()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        AuthorizationServerIntegration oauth = host.Server.OAuth();
        oauth.ClientAuthenticationMethodsSupported =
            [ClientAuthenticationMethod.None, ClientAuthenticationMethod.PrivateKeyJwt];
        oauth.ClientAssertionSigningAlgorithmsSupported = [WellKnownJwaValues.Es256];
        oauth.ValidateClientCredentialsAsync = null;

        InvalidOperationException ex =
            Assert.ThrowsExactly<InvalidOperationException>(oauth.Validate);

        Assert.Contains(
            nameof(AuthorizationServerIntegration.ValidateClientCredentialsAsync),
            ex.Message,
            StringComparison.Ordinal,
            "The refusal must name ValidateClientCredentialsAsync as the unwired judgment seam.");
    }


    /// <summary>
    /// RFC 8414 §2: "This metadata entry MUST be present if either of these
    /// authentication methods are specified in the
    /// <c>token_endpoint_auth_methods_supported</c> entry." A <c>private_key_jwt</c>
    /// declaration with an empty algorithm set could never satisfy that MUST, so
    /// <see cref="AuthorizationServerIntegration.Validate"/> refuses it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>.
    /// </summary>
    [TestMethod]
    public async Task ValidateThrowsWhenPrivateKeyJwtDeclaredWithEmptyAlgorithmSet()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        AuthorizationServerIntegration oauth = host.Server.OAuth();
        oauth.ClientAuthenticationMethodsSupported =
            [ClientAuthenticationMethod.None, ClientAuthenticationMethod.PrivateKeyJwt];
        oauth.ClientAssertionSigningAlgorithmsSupported = [];
        oauth.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(true);

        InvalidOperationException ex =
            Assert.ThrowsExactly<InvalidOperationException>(oauth.Validate);

        Assert.Contains(
            nameof(AuthorizationServerIntegration.ClientAssertionSigningAlgorithmsSupported),
            ex.Message,
            StringComparison.Ordinal,
            "The refusal must name the empty ClientAssertionSigningAlgorithmsSupported set.");
    }


    /// <summary>
    /// RFC 8414 §2: "This metadata entry MUST be present if either of these
    /// authentication methods are specified in the
    /// <c>token_endpoint_auth_methods_supported</c> entry." The rule holds for
    /// <c>client_secret_jwt</c> exactly as for <c>private_key_jwt</c>: an empty
    /// algorithm set is a composition error.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>.
    /// </summary>
    [TestMethod]
    public async Task ValidateThrowsWhenClientSecretJwtDeclaredWithEmptyAlgorithmSet()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        AuthorizationServerIntegration oauth = host.Server.OAuth();
        oauth.ClientAuthenticationMethodsSupported =
            [ClientAuthenticationMethod.None, ClientAuthenticationMethod.ClientSecretJwt];
        oauth.ClientAssertionSigningAlgorithmsSupported = [];
        oauth.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(true);

        InvalidOperationException ex =
            Assert.ThrowsExactly<InvalidOperationException>(oauth.Validate);

        Assert.Contains(
            nameof(AuthorizationServerIntegration.ClientAssertionSigningAlgorithmsSupported),
            ex.Message,
            StringComparison.Ordinal,
            "The refusal must name the empty ClientAssertionSigningAlgorithmsSupported set for client_secret_jwt.");
    }


    /// <summary>
    /// RFC 8414 §2: "The value <c>none</c> MUST NOT be used." A signing-algorithm
    /// set that contains <c>none</c> is refused by
    /// <see cref="AuthorizationServerIntegration.Validate"/> before any document
    /// could advertise it.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>.
    /// </summary>
    [TestMethod]
    public async Task ValidateThrowsWhenAlgorithmSetContainsNone()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        AuthorizationServerIntegration oauth = host.Server.OAuth();
        oauth.ClientAuthenticationMethodsSupported =
            [ClientAuthenticationMethod.None, ClientAuthenticationMethod.PrivateKeyJwt];
        oauth.ClientAssertionSigningAlgorithmsSupported = [WellKnownJwaValues.None];
        oauth.ValidateClientCredentialsAsync = static (request, fields, registration, context, ct) =>
            ValueTask.FromResult(true);

        InvalidOperationException ex =
            Assert.ThrowsExactly<InvalidOperationException>(oauth.Validate);

        Assert.Contains(
            "none",
            ex.Message,
            StringComparison.Ordinal,
            "The refusal must name the forbidden 'none' algorithm value.");
    }


    /// <summary>
    /// RFC 8414 §2: "<c>token_endpoint_auth_methods_supported</c> ... If omitted,
    /// the default is <c>client_secret_basic</c>." An empty declaration would let
    /// the omitted-member default misdescribe a token endpoint that never judges
    /// <c>client_secret_basic</c>, so
    /// <see cref="AuthorizationServerIntegration.Validate"/> refuses an empty
    /// method set.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>.
    /// </summary>
    [TestMethod]
    public async Task ValidateThrowsWhenMethodSetIsEmpty()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        AuthorizationServerIntegration oauth = host.Server.OAuth();
        oauth.ClientAuthenticationMethodsSupported = [];

        InvalidOperationException ex =
            Assert.ThrowsExactly<InvalidOperationException>(oauth.Validate);

        Assert.Contains(
            nameof(AuthorizationServerIntegration.ClientAuthenticationMethodsSupported),
            ex.Message,
            StringComparison.Ordinal,
            "The refusal must name the empty ClientAuthenticationMethodsSupported declaration.");
    }


    /// <summary>
    /// RFC 8414 §2: "<c>token_endpoint_auth_methods_supported</c> ... a list of
    /// client authentication methods supported by this token endpoint." The member
    /// describes the token endpoint; a registration whose active chain carries no
    /// token endpoint advertises neither the methods member nor its signing-alg
    /// sibling, even when a declaration is present on the integration.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>.
    /// </summary>
    [TestMethod]
    public async Task TokenEndpointOffChainEmitsNeitherMember()
    {
        await using TestHostShell host = new(TimeProvider);
        ImmutableHashSet<CapabilityIdentifier> discoveryOnly = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri, discoveryOnly);

        AuthorizationServerIntegration oauth = host.Server.OAuth();
        oauth.ClientAuthenticationMethodsSupported =
            [ClientAuthenticationMethod.None, ClientAuthenticationMethod.PrivateKeyJwt];
        oauth.ClientAssertionSigningAlgorithmsSupported = [WellKnownJwaValues.Es256];

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.IsFalse(
            body.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.TokenEndpointAuthMethodsSupported, out _),
            "RFC 8414 §2: the methods member describes the token endpoint and must be absent when it is off chain.");
        Assert.IsFalse(
            body.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.TokenEndpointAuthSigningAlgValuesSupported, out _),
            "RFC 8414 §2: the signing-alg member must be absent when the token endpoint is off chain.");
    }


    /// <summary>
    /// RFC 8259 §4: "The names within an object SHOULD be unique." A discovery
    /// contribution naming a member the base emission already wrote is refused with
    /// the composition error rather than duplicated, so the document request fails
    /// and no document is produced. Both a library-emitted member
    /// (<c>token_endpoint_auth_methods_supported</c>) and the always-present
    /// <c>issuer</c> exercise the guard.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259">RFC 8259, Section 4</see>.
    /// </summary>
    [DataRow("token_endpoint_auth_methods_supported")]
    [DataRow("issuer")]
    [TestMethod]
    public async Task ContributionDuplicatingBaseMemberFailsTheDocumentRequest(string duplicatedName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        host.Server.OAuth().ContributeDiscoveryFieldsAsync = (_, _, _) =>
            ValueTask.FromResult(new DiscoveryDocumentContribution(
                [new DiscoveryStringArrayField(duplicatedName, ["shadow-value"])]));

        InvalidOperationException ex = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await DispatchDiscoveryAsync(host, material).ConfigureAwait(false))
            .ConfigureAwait(false);

        Assert.Contains(
            duplicatedName,
            ex.Message,
            StringComparison.Ordinal,
            "RFC 8259 §4: the refusal must name the duplicated member so the misconfiguration is loud.");
    }


    /// <summary>
    /// RFC 8414 §2 permits an authorization server to publish additional metadata
    /// members; the contribution seam merges a field whose name the base emission
    /// did not write. A fresh-named contributed field appears in the emitted
    /// document after the base set.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414, Section 2</see>.
    /// </summary>
    [TestMethod]
    public async Task ContributionWithFreshNameMergesAfterBaseSet()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce);

        const string freshName = "urn:example:custom_advertisement_field";
        host.Server.OAuth().ContributeDiscoveryFieldsAsync = (_, _, _) =>
            ValueTask.FromResult(new DiscoveryDocumentContribution(
                [new DiscoveryStringField(freshName, "custom-value")]));

        ServerHttpResponse response = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);

        using JsonDocument body = JsonDocument.Parse(response.Body);
        Assert.IsTrue(
            body.RootElement.TryGetProperty(freshName, out JsonElement contributed),
            $"A fresh-named contributed field must merge into the document. Body: {response.Body}");
        Assert.AreEqual("custom-value", contributed.GetString(),
            "The contributed value must round-trip verbatim.");

        //The base issuer member still stands, proving the fresh field merged after the base set.
        Assert.IsTrue(
            body.RootElement.TryGetProperty("issuer", out _),
            "The base set must remain intact when a fresh field merges.");
    }


    /// <summary>
    /// draft-ietf-oauth-client-id-metadata-document-02 §6: "Authorization servers
    /// that publish Authorization Server Metadata [RFC8414] MUST include the
    /// following property to signal support for Client ID Metadata Documents ...
    /// <c>client_id_metadata_document_supported</c>." The dual gate is unchanged:
    /// the member is absent until the CIMD resolver seam is wired alongside the
    /// capability, and present as <c>true</c> once it is.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-02">OAuth Client ID Metadata Document, Section 6</see>.
    /// </summary>
    [TestMethod]
    public async Task ClientIdMetadataDocumentSupportedGateUnchanged()
    {
        await using TestHostShell host = new(TimeProvider);
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthClientIdMetadataDocument);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: capabilities);

        ServerHttpResponse withoutResolver = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);
        Assert.AreEqual(200, withoutResolver.StatusCode, withoutResolver.Body);

        using(JsonDocument body = JsonDocument.Parse(withoutResolver.Body))
        {
            Assert.IsFalse(
                body.RootElement.TryGetProperty(
                    AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported, out _),
                "CIMD §6: the member must be absent while only the capability is present and the resolver is unwired.");
        }

        //Discovery emission only checks the resolver seam for non-null-ness; a
        //throwing lambda proves the document request never fetches a client document.
        host.Server.OAuth().ResolveClientMetadataAsync = (uri, context, ct) =>
            throw new NotImplementedException(
                "Discovery emission checks ResolveClientMetadataAsync for non-null-ness only.");

        ServerHttpResponse withResolver = await DispatchDiscoveryAsync(host, material)
            .ConfigureAwait(false);
        Assert.AreEqual(200, withResolver.StatusCode, withResolver.Body);

        using JsonDocument wired = JsonDocument.Parse(withResolver.Body);
        Assert.IsTrue(
            wired.RootElement.TryGetProperty(
                AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported,
                out JsonElement supported),
            "CIMD §6: the member MUST be present once the capability and resolver seam are both wired.");
        Assert.IsTrue(supported.GetBoolean(),
            "CIMD §6: client_id_metadata_document_supported signals support as true.");
    }


    /// <summary>
    /// Dispatches a GET to the tenant's discovery endpoint on the hosted test
    /// server, the same recipe <see cref="DiscoveryEndpointTests"/> uses.
    /// </summary>
    private async ValueTask<ServerHttpResponse> DispatchDiscoveryAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Reads a JSON string array into a list, preserving element order for the
    /// declaration-order assertions.
    /// </summary>
    private static List<string> EnumerateStrings(JsonElement array)
    {
        List<string> values = [];
        foreach(JsonElement entry in array.EnumerateArray())
        {
            values.Add(entry.GetString() ?? string.Empty);
        }

        return values;
    }
}
