using System.Buffers;
using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Json;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OID4VCI 1.0 Authorization-Endpoint request parameters on the shared OAuth authorization /
/// PAR surface: the §5.1.3 <c>issuer_state</c> the Wallet echoes from a Credential Offer, the
/// §5.1.2 precedence between a <c>scope</c> and an <c>authorization_details</c>
/// <c>openid_credential</c> object that name the same Credential type, and the §5.1.2 / RFC 8707
/// <c>resource</c> indicator. Driven through the real dispatch pipeline.
/// </summary>
[TestClass]
internal sealed class Oid4VciAuthorizationRequestParamsTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The Wallet client identifier registered for these tests.</summary>
    private const string ClientId = "https://wallet.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static readonly Uri ClientBaseUri = new("https://wallet.client.test");

    /// <summary>The registered redirect URI the fixture's clients use.</summary>
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");

    /// <summary>The authenticated End-User established at the authorize step.</summary>
    private const string SubjectId = "urn:uuid:end-user-42";

    /// <summary>The Credential Configurations the tests request.</summary>
    private const string DegreeConfigurationId = "UniversityDegree_dc_sd_jwt";

    /// <summary>The opaque issuer_state the issuer minted into the Credential Offer.</summary>
    private const string OfferIssuerState = "eyJhbGciOiJSU0Et...FYUaBy";

    /// <summary>The Credential Issuer Identifier the Wallet sends as the RFC 8707 resource.</summary>
    private const string IssuerResource = "https://credential-issuer.example.com";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>The capabilities the Authorization Code flow tests need.</summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> AuthCodeCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization);


    /// <summary>
    /// §5.1.3: "This request parameter is used to pass the issuer_state value back to the
    /// Credential Issuer." An <c>issuer_state</c> pushed at PAR reaches the application's
    /// authorization-decision seam verbatim — the §5.1.3 Note requires the issuer to treat it as
    /// possibly attacker-injected, so the library surfaces it untrusted and the application
    /// correlates it.
    /// </summary>
    [TestMethod]
    public async Task IssuerStateReachesTheAuthorizationDecisionSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);

        string? seenIssuerState = "<unset>";
        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            (evaluation, registration, context, ct) =>
            {
                seenIssuerState = evaluation.RequestedIssuerState;

                return ValueTask.FromResult(AuthorizationRequestDecision.Permit);
            };

        ServerHttpResponse authorizeResponse = await RunToAuthorizeAsync(
            host, material, issuerState: OfferIssuerState).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.AreEqual(OfferIssuerState, seenIssuerState,
            "The pushed issuer_state must reach the authorization-decision seam verbatim.");
    }


    /// <summary>
    /// §5.1.3: <c>issuer_state</c> is OPTIONAL — a request that omits it still completes, and the
    /// seam observes <see langword="null"/> rather than an empty placeholder.
    /// </summary>
    [TestMethod]
    public async Task AuthorizeWithoutIssuerStateStillSucceeds()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);

        string? seenIssuerState = "<unset>";
        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            (evaluation, registration, context, ct) =>
            {
                seenIssuerState = evaluation.RequestedIssuerState;

                return ValueTask.FromResult(AuthorizationRequestDecision.Permit);
            };

        ServerHttpResponse authorizeResponse = await RunToAuthorizeAsync(
            host, material, issuerState: null).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.IsNull(seenIssuerState, "An absent issuer_state must surface as null at the seam.");
    }


    /// <summary>
    /// §5.1.3 untrusted handling: "the Credential Issuer MUST take into account that the
    /// issuer_state is not guaranteed to originate from this Credential Issuer ... It could have
    /// been injected by an attacker." The library validates nothing about the value — when the
    /// application cannot correlate it to an Offer it created, it refuses at the seam and the
    /// library maps the denial to the OAuth error.
    /// </summary>
    [TestMethod]
    public async Task IssuerStateThatTheApplicationCannotCorrelateIsDeniedAtTheSeam()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);

        //The application owns the Offer store; only an issuer_state it minted correlates. A value
        //it does not recognise — possibly attacker-injected — is denied.
        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            (evaluation, registration, context, ct) =>
                ValueTask.FromResult(
                    string.Equals(evaluation.RequestedIssuerState, OfferIssuerState, StringComparison.Ordinal)
                        ? AuthorizationRequestDecision.Permit
                        : AuthorizationRequestDecision.Deny(
                            AuthorizationDenialReason.AccessDenied,
                            "issuer_state does not correlate to a known Credential Offer."));

        ServerHttpResponse permitted = await RunToAuthorizeAsync(
            host, material, issuerState: OfferIssuerState).ConfigureAwait(false);
        Assert.AreEqual(302, permitted.StatusCode, permitted.Body);

        ServerHttpResponse refused = await RunToAuthorizeAsync(
            host, material, issuerState: "attacker-injected-state").ConfigureAwait(false);
        Assert.AreEqual(302, refused.StatusCode, refused.Body);
        Assert.Contains(OAuthErrors.AccessDenied, refused.Location!,
            "An uncorrelated issuer_state must be refused via the seam's denial.");
    }


    /// <summary>
    /// §5.1.2 precedence: "if both [a scope and an authorization_details openid_credential object]
    /// request the same Credential type, then the Credential Issuer MUST follow the request as
    /// given by the authorization details object." The §6.2 token response carries the Credential
    /// type ONCE, with the details-derived grant — not double-granted.
    /// </summary>
    [TestMethod]
    public async Task ScopeAndDetailsForTheSameTypeAreGrantedOnce()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        //The seam models the §5.1.2 collision: the request carried both a scope that maps to
        //DegreeConfigurationId and an authorization_details object for the same configuration, so
        //a naive issuer would grant the type twice (one scope-derived, one details-derived). The
        //library collapses the duplicate so the §6.2 response names the type once.
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) =>
                ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                [
                    new GrantedCredentialAuthorization
                    {
                        CredentialConfigurationId = DegreeConfigurationId,
                        CredentialIdentifiers = ["CivilEngineeringDegree-2026"]
                    },
                    //The scope-derived grant for the SAME Credential type — the details object
                    //takes precedence, so this duplicate must not appear in the response.
                    new GrantedCredentialAuthorization
                    {
                        CredentialConfigurationId = DegreeConfigurationId,
                        CredentialIdentifiers = ["ScopeDerivedDuplicate-2026"]
                    }
                ]));

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            scope: $"{WellKnownScopes.OpenId} {DegreeConfigurationId}",
            parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);
        JsonElement details = doc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(1, details.GetArrayLength(),
            "The Credential type must be granted ONCE — the authorization_details object takes precedence over the scope.");
        Assert.AreEqual(DegreeConfigurationId,
            details[0].GetProperty("credential_configuration_id").GetString());
        //The details-derived grant is the one kept (it was first); the scope-derived duplicate is dropped.
        JsonElement identifiers = details[0].GetProperty("credential_identifiers");
        Assert.AreEqual(1, identifiers.GetArrayLength());
        Assert.AreEqual("CivilEngineeringDegree-2026", identifiers[0].GetString(),
            "The details-derived grant must win; the scope-derived duplicate identifiers must not appear.");
    }


    /// <summary>
    /// §5.1.2 / RFC 8707: "it is RECOMMENDED to use a resource parameter [RFC8707] whose value is
    /// the Credential Issuer's identifier value to allow the Authorization Server to differentiate
    /// Credential Issuers." A single <c>resource</c> value is read and surfaced to the
    /// authorization-decision seam.
    /// </summary>
    [TestMethod]
    public async Task SingleResourceIndicatorIsReadAndSurfaced()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);

        IReadOnlyList<string>? seenResource = null;
        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            (evaluation, registration, context, ct) =>
            {
                seenResource = evaluation.RequestedResource;

                return ValueTask.FromResult(AuthorizationRequestDecision.Permit);
            };

        ServerHttpResponse authorizeResponse = await RunToAuthorizeAsync(
            host, material, resource: IssuerResource).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.IsNotNull(seenResource);
        Assert.HasCount(1, seenResource!);
        Assert.AreEqual(IssuerResource, seenResource![0]);
    }


    /// <summary>
    /// RFC 8707 §2: the <c>resource</c> parameter "MAY appear multiple times." Multiple indicators
    /// (collapsed space-delimited by the skin, as for <c>scope</c>) are read and surfaced as the
    /// parsed list; an absent parameter surfaces as <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public async Task MultipleResourceIndicatorsAreReadAndSurfaced()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);

        IReadOnlyList<string>? seenResource = null;
        host.Server.OAuth().EvaluateAuthorizationRequestAsync =
            (evaluation, registration, context, ct) =>
            {
                seenResource = evaluation.RequestedResource;

                return ValueTask.FromResult(AuthorizationRequestDecision.Permit);
            };

        const string secondResource = "https://other-issuer.example.com";
        ServerHttpResponse multi = await RunToAuthorizeAsync(
            host, material, resource: $"{IssuerResource} {secondResource}").ConfigureAwait(false);
        Assert.AreEqual(302, multi.StatusCode, multi.Body);
        Assert.IsNotNull(seenResource);
        Assert.HasCount(2, seenResource!);
        Assert.AreEqual(IssuerResource, seenResource![0]);
        Assert.AreEqual(secondResource, seenResource![1]);

        seenResource = null;
        ServerHttpResponse none = await RunToAuthorizeAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(302, none.StatusCode, none.Body);
        Assert.IsNull(seenResource, "An absent resource parameter must surface as null at the seam.");
    }


    private static string SingleDetail(string configurationId) =>
        "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + configurationId + "\"}]";


    /// <summary>
    /// Drives PAR → authorize and returns the authorize response (a 302 on success), pushing the
    /// optional <paramref name="issuerState"/> and <paramref name="resource"/> so the
    /// authorization-decision seam observes them.
    /// </summary>
    private async ValueTask<ServerHttpResponse> RunToAuthorizeAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string? issuerState = null,
        string? resource = null)
    {
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        if(issuerState is not null)
        {
            parFields[OAuthRequestParameterNames.IssuerState] = issuerState;
        }

        if(resource is not null)
        {
            parFields[OAuthRequestParameterNames.Resource] = resource;
        }

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };

        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);

        return await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the full PAR → authorize → token flow, pushing the given <paramref name="scope"/>
    /// and <paramref name="parDetails"/>, and returns the token response.
    /// </summary>
    private async ValueTask<ServerHttpResponse> RunAuthCodeFlowAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string scope,
        string parDetails)
    {
        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = scope,
            [OAuthRequestParameterNames.AuthorizationDetails] = parDetails
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
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

        return await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
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
