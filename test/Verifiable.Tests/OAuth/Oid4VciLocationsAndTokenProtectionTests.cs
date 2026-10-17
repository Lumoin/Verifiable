using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Two OID4VCI 1.0 conformance MUSTs enforced at the token-issuing endpoints:
/// <list type="bullet">
///   <item><description>
///     §5.1.1 / §6.1.1 — when the Credential Issuer metadata declares an
///     <c>authorization_servers</c> parameter, every <c>openid_credential</c> authorization
///     details object MUST carry the Credential Issuer Identifier in its <c>locations</c> element.
///   </description></item>
///   <item><description>
///     §13.10 — a long-lived Access Token giving access to Credentials MUST NOT be issued unless
///     sender-constrained (DPoP / <c>cnf.jkt</c>).
///   </description></item>
/// </list>
/// </summary>
[TestClass]
internal sealed class Oid4VciLocationsAndTokenProtectionTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://wallet.client.test";
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");
    private const string SubjectId = "urn:uuid:end-user-42";
    private const string DegreeConfigurationId = "UniversityDegree_dc_sd_jwt";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static ImmutableHashSet<CapabilityIdentifier> AuthCodeCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization);


    /// <summary>
    /// Under Credential Issuer metadata declaring <c>authorization_servers</c>, an authorization code
    /// Token Request whose <c>authorization_details</c> carries no <c>locations</c> is refused 400
    /// <c>invalid_authorization_details</c> after a correctly located object was pushed and authorized,
    /// and the credential authorization decision seam is not consulted for the refused request.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1">OID4VCI 1.0 Section 6.1</see>:
    /// "If the Token Request contains an authorization_details parameter (as defined by [RFC9396]) of
    /// type openid_credential and the Credential Issuer's metadata contains an authorization_servers
    /// parameter, the authorization_details object MUST contain the Credential Issuer's identifier in
    /// the locations element."
    /// </summary>
    [TestMethod]
    public async Task LocationsOmittedWithAuthorizationServersIsRejectedAtToken()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        bool seamCalled = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                {
                    seamCalled = true;

                    return ValueTask.FromResult(GrantAllRequested(details));
                };
        }).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        await ConfigureAuthorizationServersMetadataAsync(host).ConfigureAwait(false);

        string issuerLocation = material.Registration.IssuerUri!.OriginalString;
        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: DetailWithLocations(DegreeConfigurationId, issuerLocation),
            tokenRequestDetails: DetailWithoutLocations(DegreeConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, tokenResponse.Body);
        Assert.IsFalse(seamCalled,
            "A token-request detail missing locations must be refused before the decision seam.");
    }


    /// <summary>
    /// Under Credential Issuer metadata declaring <c>authorization_servers</c>, an
    /// <c>openid_credential</c> object whose <c>locations</c> names the Credential Issuer Identifier is
    /// accepted at the pushed authorization request and redeemed at the token endpoint, which answers
    /// 200 with the granted <c>authorization_details</c> naming the configuration.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.1">OID4VCI 1.0 Section 5.1.1</see>:
    /// "If the Credential Issuer metadata contains an authorization_servers parameter, the
    /// authorization detail's locations common data field MUST be set to the Credential Issuer
    /// Identifier value."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1">OID4VCI 1.0 Section 6.1</see>:
    /// "If the Token Request contains an authorization_details parameter (as defined by [RFC9396]) of
    /// type openid_credential and the Credential Issuer's metadata contains an authorization_servers
    /// parameter, the authorization_details object MUST contain the Credential Issuer's identifier in
    /// the locations element."
    /// </summary>
    [TestMethod]
    public async Task LocationsNamingTheIssuerWithAuthorizationServersSucceeds()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                    ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);
        //§13.10: keep the plain-bearer credential token within the long-lived threshold.
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        await ConfigureAuthorizationServersMetadataAsync(host).ConfigureAwait(false);

        string issuerLocation = material.Registration.IssuerUri!.OriginalString;
        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: DetailWithLocations(DegreeConfigurationId, issuerLocation)).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);
        JsonElement details = doc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(DegreeConfigurationId,
            details[0].GetProperty("credential_configuration_id").GetString());
    }


    /// <summary>
    /// §5.1.1: the requirement is conditioned on "If the Credential Issuer metadata contains an
    /// authorization_servers parameter" — the common single-issuer deployment (AS == issuer)
    /// declares no such parameter, so an openid_credential detail WITHOUT locations is accepted
    /// end to end. This is the unchanged behavior the existing tests rely on.
    /// </summary>
    [TestMethod]
    public async Task LocationsAbsentWithoutAuthorizationServersStillSucceeds()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        //No authorization_servers metadata is contributed: the AS is the issuer.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                    ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: DetailWithoutLocations(DegreeConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
    }


    /// <summary>
    /// Under Credential Issuer metadata declaring two <c>authorization_servers</c>, the
    /// <c>locations</c> rule is held over the real wire: a pushed <c>openid_credential</c> object
    /// without <c>locations</c>, or with a <c>locations</c> naming another issuer, is refused 400
    /// <c>invalid_authorization_details</c> naming the Credential Issuer Identifier; one whose
    /// <c>locations</c> names that identifier is accepted 201; and a Pre-Authorized Code Token Request
    /// whose <c>authorization_details</c> carries no <c>locations</c> is refused 400
    /// <c>invalid_authorization_details</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.1">OID4VCI 1.0 Section 5.1.1</see>:
    /// "If the Credential Issuer metadata contains an authorization_servers parameter, the
    /// authorization detail's locations common data field MUST be set to the Credential Issuer
    /// Identifier value."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1">OID4VCI 1.0 Section 6.1</see>:
    /// "If the Token Request contains an authorization_details parameter (as defined by [RFC9396]) of
    /// type openid_credential and the Credential Issuer's metadata contains an authorization_servers
    /// parameter, the authorization_details object MUST contain the Credential Issuer's identifier in
    /// the locations element."
    /// </summary>
    /// <param name="caseName">The request and its <c>locations</c>: <c>pushed-without-locations</c>, <c>pushed-naming-another-issuer</c>, <c>pushed-naming-the-issuer</c> or <c>pre-authorized-token-without-locations</c>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("pushed-without-locations")]
    [DataRow("pushed-naming-another-issuer")]
    [DataRow("pushed-naming-the-issuer")]
    [DataRow("pre-authorized-token-without-locations")]
    public async Task LocationsAreHeldOverTheWireAsync(string caseName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            AuthCodeCapabilities.Add(WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant)).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                static (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                static (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(SubjectId));
            candidateIntegration.ContributeCredentialIssuerMetadataAsync =
                static (registration, context, ct) => ValueTask.FromResult(
                    new CredentialIssuerMetadataContribution
                    {
                        AuthorizationServers = ["https://as.example.com", "https://as-two.example.com"]
                    });
        }).ConfigureAwait(false);

        //OID4VCI 1.0 Section 13.10: a plain bearer Credential token stays within five minutes.
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;
        string issuerIdentifier = material.Registration.IssuerUri!.OriginalString;
        string expectedDescription = "The Credential Issuer metadata declares authorization_servers, so each "
            + "openid_credential authorization details object MUST set its locations element to the Credential "
            + $"Issuer Identifier '{issuerIdentifier}'.";

        (int statusCode, string body) = caseName switch
        {
            "pushed-without-locations" => await PushOverTheWireAsync(
                host, segment, DetailWithoutLocations(DegreeConfigurationId)).ConfigureAwait(false),
            "pushed-naming-another-issuer" => await PushOverTheWireAsync(
                host, segment, DetailWithLocations(DegreeConfigurationId, "https://not-this-issuer.example.com")).ConfigureAwait(false),
            "pushed-naming-the-issuer" => await PushOverTheWireAsync(
                host, segment, DetailWithLocations(DegreeConfigurationId, issuerIdentifier)).ConfigureAwait(false),
            "pre-authorized-token-without-locations" => await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host,
                segment,
                new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                    [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA",
                    [OAuthRequestParameterNames.AuthorizationDetails] = DetailWithoutLocations(DegreeConfigurationId)
                },
                TestContext.CancellationToken).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(caseName), caseName, "No such case.")
        };

        if(string.Equals(caseName, "pushed-naming-the-issuer", StringComparison.Ordinal))
        {
            Assert.AreEqual(201, statusCode, body);
            Assert.Contains("\"request_uri\":", body, StringComparison.Ordinal, body);
        }
        else
        {
            DpopCodeBindingWire.AssertError(statusCode, body, 400, OAuthErrors.InvalidAuthorizationDetails, expectedDescription);
        }
    }


    /// <summary>
    /// OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
    /// issued unless sender-constrained. Access Tokens with lifetimes longer than 5 minutes are,
    /// in general, considered long lived." A plain bearer credential token whose lifetime exceeds
    /// the threshold is refused with invalid_request rather than issued.
    /// </summary>
    [TestMethod]
    public async Task LongLivedPlainBearerCredentialTokenIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        bool seamCalled = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                {
                    seamCalled = true;

                    return ValueTask.FromResult(GrantAllRequested(details));
                };
        }).ConfigureAwait(false);
        //Longer than the §13.10 five-minute threshold and NOT sender-constrained.
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(10)).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: DetailWithoutLocations(DegreeConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.Contains(OAuthErrors.InvalidRequest, tokenResponse.Body);
        Assert.IsTrue(seamCalled,
            "The grant is resolved (the token gives access to Credentials), then §13.10 refuses the long-lived bearer token.");
    }


    /// <summary>
    /// §13.10: "Access Tokens with lifetimes longer than 5 minutes are, in general, considered
    /// long lived." A short-lived (within-threshold) plain bearer credential token is permitted —
    /// the guard only refuses tokens that outlive the threshold.
    /// </summary>
    [TestMethod]
    public async Task ShortLivedPlainBearerCredentialTokenIsIssued()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                    ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);
        //Exactly the §13.10 threshold — not "longer than 5 minutes", so it is not long lived.
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: DetailWithoutLocations(DegreeConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer,
            doc.RootElement.GetProperty("token_type").GetString(),
            "A short-lived credential token may be a plain bearer token.");
    }


    /// <summary>
    /// §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be issued unless
    /// sender-constrained." A long-lived (default one-hour) credential token IS issued when it is
    /// DPoP-bound: the response carries token_type=DPoP and the access-token JWT carries cnf.jkt
    /// (RFC 9449 §5 / §6.1), so the §13.10 sender-constraint condition is met.
    /// </summary>
    [TestMethod]
    public async Task LongLivedDpopBoundCredentialTokenIsIssued()
    {
        await using TestHostShell host = new(TimeProvider);
        //Default HAIP profile — DPoP is required and the default access-token lifetime is one
        //hour, which is long lived per §13.10. The token issues because it is sender-constrained.
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();


            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                    ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);

        using DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration,
            RedirectUri.OriginalString,
            TestContext.CancellationToken).ConfigureAwait(false);

        //Push authorization_details so the issued token gives access to Credentials.
        OAuthFormEncodedFields parFields = new(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.AuthorizationDetails] = DetailWithoutLocations(DegreeConfigurationId),
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        });

        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, parFields,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];
        string requestUri = parCompleted.Par.RequestUri.ToString();

        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeAuthorize,
            WellKnownHttpMethods.Get,
            new RequestFields
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RequestUri] = requestUri
            },
            authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);

        (string code, string? iss) = ParseAuthorizeRedirect(authorizeResponse.Location!);
        Dictionary<string, string> callbackFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.State] = flowId
        };
        if(iss is not null)
        {
            callbackFields[OAuthRequestParameterNames.Iss] = iss;
        }

        AuthCodeFlowEndpointResult callbackResult = await fixture.Client.AuthCode.HandleCallbackAsync(
            fixture.Registration,
            new OAuthFormEncodedFields(callbackFields),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed. ErrorCode={callbackResult.ErrorCode} ErrorDescription={callbackResult.ErrorDescription}");

        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"A long-lived but DPoP-bound credential token must issue. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");
        Assert.IsNotNull(tokenResult.Body);

        Assert.IsTrue(tokenResult.Body!.TryGetValue(OAuthRequestParameterNames.TokenType, out object? tokenTypeObj));
        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, (string)tokenTypeObj!,
            "A sender-constrained credential token is bound under DPoP (RFC 9449 §5).");

        string accessToken = (string)tokenResult.Body[OAuthRequestParameterNames.AccessToken]!;
        Assert.IsTrue(JwtPayloadReader.HasCnfClaim(accessToken),
            "The sender-constrained token carries cnf.jkt (RFC 9449 §6.1), satisfying §13.10.");
    }


    /// <summary>
    /// Wires the §12.2.4 Credential Issuer Metadata contribution to declare an
    /// <c>authorization_servers</c> parameter, the deployment fact that activates the §5.1.1 /
    /// §6.1.1 <c>locations</c> requirement.
    /// </summary>
    private static async Task ConfigureAuthorizationServersMetadataAsync(TestHostShell host)
    {
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync =
                (registration, context, ct) => ValueTask.FromResult(
                    new CredentialIssuerMetadataContribution
                    {
                        AuthorizationServers = ["https://as.example.com"]
                    });
        }).ConfigureAwait(false);
    }


    private static CredentialAuthorizationDecision GrantAllRequested(
        IReadOnlyList<CredentialAuthorizationDetail> details)
    {
        List<GrantedCredentialAuthorization> granted = [];
        foreach(CredentialAuthorizationDetail detail in details)
        {
            granted.Add(new GrantedCredentialAuthorization
            {
                CredentialConfigurationId = detail.CredentialConfigurationId!,
                CredentialIdentifiers = [$"{detail.CredentialConfigurationId}-dataset-1"]
            });
        }

        return CredentialAuthorizationDecision.Grant(granted);
    }


    private static string DetailWithoutLocations(string configurationId) =>
        "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + configurationId + "\"}]";


    private static string DetailWithLocations(string configurationId, string location) =>
        "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + configurationId
        + "\",\"locations\":[\"" + location + "\"]}]";


    /// <summary>
    /// Sends a pushed authorization request over the real wire carrying
    /// <paramref name="authorizationDetails"/> beside the <c>code</c> response type, an S256 PKCE
    /// challenge, the registered redirect URI and the <c>openid</c> scope, starting the listener on
    /// first use.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="authorizationDetails">The <c>authorization_details</c> value, sent verbatim.</param>
    /// <returns>The pushed authorization request endpoint's status code and body.</returns>
    private async Task<(int StatusCode, string Body)> PushOverTheWireAsync(
        TestHostShell host, string segment, string authorizationDetails)
    {
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        List<KeyValuePair<string, string>> fields = RawAuthCodeWirePushers.BuildParFields(
            ClientId, pkce, RedirectUri.OriginalString, WellKnownScopes.OpenId);
        fields.Add(new(OAuthRequestParameterNames.AuthorizationDetails, authorizationDetails));

        return await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, fields, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives PAR → authorize → token via raw dispatch (no DPoP), pushing
    /// <paramref name="parDetails"/> at PAR and an optional <paramref name="tokenRequestDetails"/>
    /// at the token request.
    /// </summary>
    private async ValueTask<ServerHttpResponse> RunAuthCodeFlowAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string parDetails,
        string? tokenRequestDetails = null)
    {
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.AuthorizationDetails] = parDetails
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            new RequestFields
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RequestUri] = requestUri
            },
            authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        string code = ExtractCode(authorizeResponse.Location!);

        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        if(tokenRequestDetails is not null)
        {
            tokenFields[OAuthRequestParameterNames.AuthorizationDetails] = tokenRequestDetails;
        }

        return await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static (string Code, string? Iss) ParseAuthorizeRedirect(string location)
    {
        int queryStart = location.IndexOf('?', StringComparison.Ordinal);
        Dictionary<string, string> parsed = new(StringComparer.Ordinal);
        foreach(string pair in location[(queryStart + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq <= 0)
            {
                continue;
            }

            parsed[pair[..eq]] = Uri.UnescapeDataString(pair[(eq + 1)..]);
        }

        _ = parsed.TryGetValue(OAuthRequestParameterNames.Code, out string? code);
        _ = parsed.TryGetValue(OAuthRequestParameterNames.Iss, out string? iss);

        return (code!, iss);
    }


    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(property).GetString()!;
    }


    private static string ExtractCode(string location)
    {
        int q = location.IndexOf('?', StringComparison.Ordinal);
        foreach(string pair in location[(q + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq > 0 && string.Equals(
                pair[..eq], OAuthRequestParameterNames.Code, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        throw new InvalidOperationException("No code parameter on the authorize redirect.");
    }
}
