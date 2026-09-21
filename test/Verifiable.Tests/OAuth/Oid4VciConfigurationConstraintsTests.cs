using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Text.Json;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
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

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://wallet.client.test";
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");
    private const string OfferSubject = "urn:uuid:end-user-42";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string ConfigurationScope = "UniversityDegree";
    private const string IssuedCredential = "eyJhbGciOiJFUzI1NiJ9.body.sig";

    private static ImmutableHashSet<CapabilityIdentifier> IssuanceCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);


    [TestMethod]
    public async Task ScopeMatchingConfigurationIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        //The token is granted exactly the configuration's scope.
        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
    }


    [TestMethod]
    public async Task ScopeNotMatchingConfigurationIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        //The token is granted a DIFFERENT scope than the requested configuration declares.
        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: "SomeOtherCredential")
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, response.Body);
    }


    /// <summary>
    /// OID4VCI 1.0 §8.2: "The corresponding object in the <c>credential_configurations_supported</c>
    /// map MUST contain one of the value(s) used in the <c>scope</c> parameter in the Authorization
    /// Request" — §8.2 scopes that requirement to the path where <c>credential_configuration_id</c>
    /// is used because no <c>credential_identifiers</c> were granted by <c>authorization_details</c>.
    /// A token carrying an unrelated scope but an <see cref="AuthorizationDetailsTypeValues.OpenIdCredential"/>
    /// grant naming the requested configuration is served — the §5.1.1 grant is this request's
    /// authorization, not the scope.
    /// </summary>
    [TestMethod]
    public async Task TokenWithUnrelatedScopeAndAGrantingDetailIsServed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        string accessToken = await MintAccessTokenWithAuthorizationDetailsAsync(
            host, material, credentialScope: "SomeOtherCredential", grantedConfigurationId: ConfigurationId)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
    }


    /// <summary>
    /// A token's <c>authorization_details</c> grant naming Configuration A does not authorize a
    /// Credential Request for Configuration B — the grant binds to the exact
    /// <c>credential_configuration_id</c> it names, and B's scope is missing from the token, so §8.2
    /// still refuses.
    /// </summary>
    [TestMethod]
    public async Task DetailGrantingConfigurationAIsStillRefusedForConfigurationBWhenScopeMissing()
    {
        const string OtherConfigurationId = "OtherConfiguration_dc_sd_jwt";
        const string OtherConfigurationScope = "OtherCredential";

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            ContributeCredentialIssuerMetadataDelegate wired = candidateIntegration.ContributeCredentialIssuerMetadataAsync!;
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = async (registration, context, ct) =>
            {
                CredentialIssuerMetadataContribution baseContribution =
                    await wired(registration, context, ct).ConfigureAwait(false);

                Dictionary<string, object> configurations = new(
                    baseContribution.CredentialConfigurationsSupported!, StringComparer.Ordinal)
                {
                    [OtherConfigurationId] = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["format"] = "dc+sd-jwt",
                        ["scope"] = OtherConfigurationScope
                    }
                };

                return baseContribution with { CredentialConfigurationsSupported = configurations };
            };
        }).ConfigureAwait(false);

        //The grant names Configuration A (ConfigurationId); the token's scope names neither
        //configuration's declared scope.
        string accessToken = await MintAccessTokenWithAuthorizationDetailsAsync(
            host, material, credentialScope: "SomeOtherCredential", grantedConfigurationId: ConfigurationId)
            .ConfigureAwait(false);

        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, OtherConfigurationRequestBody(OtherConfigurationId, "proof-1"))
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, response.Body);
    }


    [TestMethod]
    public async Task BatchWithinAdvertisedSizeIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: 3).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
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
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: 2).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
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
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        //No batch_credential_issuance advertised.
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1", "proof-2"))
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
    }


    /// <summary>
    /// Registers an issuer with the test capabilities and installs its issuance delegates.
    /// </summary>
    private static async Task<VerifierKeyMaterial> RegisterIssuerAsync(TestHostShell host)
    {
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);

        return material;
    }


    /// <summary>
    /// Wires the metadata contribution with one configuration declaring <paramref name="configurationScope"/>
    /// and, when <paramref name="batchSize"/> is set, batch issuance advertised at that size.
    /// </summary>
    private static async Task WireCatalogAsync(TestHostShell host, string configurationScope, int? batchSize)
    {
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (_, _, _) =>
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
        }).ConfigureAwait(false);
    }


    private static string CredentialRequestBody(params string[] proofs) =>
        OtherConfigurationRequestBody(ConfigurationId, proofs);


    private static string OtherConfigurationRequestBody(string configurationId, params string[] proofs)
    {
        string proofArray = string.Join(",", proofs.Select(p => "\"" + p + "\""));

        return "{\"credential_configuration_id\":\"" + configurationId + "\","
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
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Completes the fixture token exchange and returns an access token for the credential endpoint request.
    /// </summary>
    private async Task<string> MintAccessTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string credentialScope)
    {
        //openid keeps the RFC 9068 audience resolvable (ScopeToAudience maps it); the credential
        //scope rides alongside it and is what the §8.2 binding matches against.
        string grantedScope = $"{WellKnownScopes.OpenId} {credentialScope}";
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, grantedScope));
        }).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    /// <summary>
    /// Mints a Bearer access token through the OID4VCI Pre-Authorized Code grant carrying
    /// <paramref name="credentialScope"/> as its granted scope AND an RFC 9396 §9.1
    /// <c>authorization_details</c> claim whose sole <c>openid_credential</c> detail grants
    /// <paramref name="grantedConfigurationId"/> — the §5.1.1 grant the §8.2 scope binding must
    /// treat as this request's authorization.
    /// </summary>
    private async Task<string> MintAccessTokenWithAuthorizationDetailsAsync(
        TestHostShell host, VerifierKeyMaterial material, string credentialScope, string grantedConfigurationId)
    {
        string grantedScope = $"{WellKnownScopes.OpenId} {credentialScope}";
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();

            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, grantedScope));

            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                    ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                    [
                        new GrantedCredentialAuthorization
                        {
                            CredentialConfigurationId = grantedConfigurationId,
                            CredentialIdentifiers = ["dataset-1"]
                        }
                    ]));
        }).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA",
                [OAuthRequestParameterNames.AuthorizationDetails] =
                    "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\""
                    + grantedConfigurationId + "\"}]"
            },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }
}
