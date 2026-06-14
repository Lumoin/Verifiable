using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Server.Routing;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OID4VCI 1.0 §8.2 scope↔credential_configuration_id binding and §12.2.4 batch ceiling,
/// enforced at the Credential Endpoint off the issuer metadata contribution. The gate runs
/// BEFORE the issuance seam, so a token scoped for one configuration cannot draw another and a
/// request cannot exceed (or assume unadvertised) batch issuance.
/// </summary>
[TestClass]
internal sealed class Oid4VciConfigurationConstraintsTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private const string ClientId = "https://wallet.client.test";
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");
    private const string OfferSubject = "urn:uuid:end-user-42";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string ConfigurationScope = "UniversityDegree";
    private const string IssuedCredential = "eyJhbGciOiJFUzI1NiJ9.body.sig";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly ImmutableHashSet<CapabilityIdentifier> IssuanceCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);


    [TestMethod]
    public async Task ScopeMatchingConfigurationIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIssuer(host);
        WireCatalog(host, configurationScope: ConfigurationScope, batchSize: null);

        //The token is granted exactly the configuration's scope.
        string accessToken = await MintAccessTokenAsync(host, material, credentialScope:ConfigurationScope)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
    }


    [TestMethod]
    public async Task ScopeNotMatchingConfigurationIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIssuer(host);
        WireCatalog(host, configurationScope: ConfigurationScope, batchSize: null);

        //The token is granted a DIFFERENT scope than the requested configuration declares.
        string accessToken = await MintAccessTokenAsync(host, material, credentialScope:"SomeOtherCredential")
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, response.Body);
    }


    [TestMethod]
    public async Task BatchWithinAdvertisedSizeIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIssuer(host);
        WireCatalog(host, configurationScope: ConfigurationScope, batchSize: 3);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope:ConfigurationScope)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1", "proof-2", "proof-3"))
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
    }


    [TestMethod]
    public async Task BatchOverAdvertisedSizeIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIssuer(host);
        WireCatalog(host, configurationScope: ConfigurationScope, batchSize: 2);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope:ConfigurationScope)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1", "proof-2", "proof-3"))
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
    }


    [TestMethod]
    public async Task MultipleProofsWithoutBatchSupportAreRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = RegisterIssuer(host);
        //No batch_credential_issuance advertised.
        WireCatalog(host, configurationScope: ConfigurationScope, batchSize: null);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope:ConfigurationScope)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1", "proof-2"))
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
    }


    private static VerifierKeyMaterial RegisterIssuer(TestHostShell host)
    {
        VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities);
        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();
        host.Server.OAuth().IssueCredentialAsync = static (_, _, _, _, _) =>
            ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));

        return material;
    }


    /// <summary>
    /// Wires the metadata contribution with one configuration declaring <paramref name="configurationScope"/>
    /// and, when <paramref name="batchSize"/> is set, batch issuance advertised at that size.
    /// </summary>
    private static void WireCatalog(TestHostShell host, string configurationScope, int? batchSize)
    {
        host.Server.OAuth().ContributeCredentialIssuerMetadataAsync = (_, _, _) =>
        {
            CredentialIssuerMetadataContribution contribution = new()
            {
                CredentialConfigurationsSupported = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    [ConfigurationId] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["format"] = "dc+sd-jwt",
                        ["scope"] = configurationScope
                    }
                },
                BatchCredentialIssuance = batchSize is int size
                    ? new Dictionary<string, object>(StringComparer.Ordinal) { ["batch_size"] = size }
                    : null
            };

            return ValueTask.FromResult(contribution);
        };
    }


    private static string CredentialRequestBody(params string[] proofs)
    {
        string proofArray = string.Join(",", proofs.Select(p => "\"" + p + "\""));

        return "{\"credential_configuration_id\":\"" + ConfigurationId + "\","
            + "\"proofs\":{\"jwt\":[" + proofArray + "]}}";
    }


    private static RequestHeaders BearerHeaders(string accessToken) =>
        new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = ["Bearer " + accessToken]
        });


    private async Task<ServerHttpResponse> DispatchCredentialAsync(
        TestHostShell host, VerifierKeyMaterial material, string accessToken, string jsonBody)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredential,
            "POST",
            new RequestFields(),
            BearerHeaders(accessToken),
            jsonBody,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private async Task<string> MintAccessTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string credentialScope)
    {
        //openid keeps the RFC 9068 audience resolvable (ScopeToAudience maps it); the credential
        //scope rides alongside it and is what the §8.2 binding matches against.
        string grantedScope = $"{WellKnownScopes.OpenId} {credentialScope}";
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, grantedScope));

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypePreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }
}
