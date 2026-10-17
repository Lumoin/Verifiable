using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
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
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The Wallet client identifier registered for these tests.</summary>
    private const string ClientId = "https://wallet.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");

    /// <summary>The registered redirect URI the fixture's clients use.</summary>
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    /// <summary>The authenticated End-User established at the authorize step.</summary>
    private const string SubjectId = "urn:uuid:end-user-42";

    /// <summary>The Credential Configurations the tests request.</summary>
    private const string DegreeConfigurationId = "UniversityDegree_dc_sd_jwt";

    /// <summary>The opaque issuer_state the issuer minted into the Credential Offer.</summary>
    private const string OfferIssuerState = "eyJhbGciOiJSU0Et...FYUaBy";

    /// <summary>The Credential Issuer Identifier the Wallet sends as the RFC 8707 resource.</summary>
    private const string IssuerResource = "https://credential-issuer.example.com";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The capabilities the Authorization Code flow tests need.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> AuthCodeCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization);


    /// <summary>
    /// §5.1.3: <c>issuer_state</c> is OPTIONAL — a request that omits it still completes, and the
    /// seam observes <see langword="null"/> rather than an empty placeholder.
    /// </summary>
    [TestMethod]
    public async Task AuthorizeWithoutIssuerStateStillSucceeds()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        string? seenIssuerState = "<unset>";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (evaluation, registration, context, ct) =>
                {
                    seenIssuerState = evaluation.RequestedIssuerState;

                    return ValueTask.FromResult(AuthorizationRequestDecision.Permit());
                };
        }).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await RunToAuthorizeAsync(
            host, material, issuerState: null).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.IsNull(seenIssuerState, "An absent issuer_state must surface as null at the seam.");
    }


    /// <summary>
    /// An <c>issuer_state</c> pushed over the real wire reaches the application's
    /// authorization-decision seam byte for byte, whatever its origin: the value the Credential
    /// Offer carried is permitted and the authorize response redirects with a <c>code</c>; a value
    /// the application cannot correlate to an offer, as an attacker would inject, is denied at the
    /// seam and the authorize response redirects with <c>error=access_denied</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.3">OID4VCI 1.0 Section 5.1.3</see>:
    /// "issuer_state: OPTIONAL. String value identifying a certain processing context at the
    /// Credential Issuer. ... This request parameter is used to pass the issuer_state value back to
    /// the Credential Issuer." and "Note: When processing the Authorization Request, the Credential
    /// Issuer MUST take into account that the issuer_state is not guaranteed to originate from this
    /// Credential Issuer in all circumstances. It could have been injected by an attacker."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.3">OID4VCI 1.0 Section 5.3</see>:
    /// "The Authorization Error Response MUST be made as defined in [RFC6749]." The denied row's
    /// redirect carries the RFC 6749 <c>error</c> parameter with the value <c>access_denied</c>.
    /// </summary>
    /// <param name="issuerState">The <c>issuer_state</c> pushed.</param>
    /// <param name="isCorrelated">Whether the application correlates the value to an offer it created.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(OfferIssuerState, true)]
    [DataRow("attacker-injected-state", false)]
    public async Task IssuerStateReachesTheDecisionSeamOverTheWireAsync(string issuerState, bool isCorrelated)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        string? seenIssuerState = "<unset>";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (evaluation, registration, context, ct) =>
                {
                    seenIssuerState = evaluation.RequestedIssuerState;

                    return ValueTask.FromResult(
                        string.Equals(evaluation.RequestedIssuerState, OfferIssuerState, StringComparison.Ordinal)
                            ? AuthorizationRequestDecision.Permit()
                            : AuthorizationRequestDecision.Deny(
                                AuthorizationDenialReason.AccessDenied,
                                "issuer_state does not correlate to a known Credential Offer."));
                };
        }).ConfigureAwait(false);

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        List<KeyValuePair<string, string>> pushedFields = RawAuthCodeWirePushers.BuildParFields(ClientId, pkce, RedirectUri.OriginalString, WellKnownScopes.OpenId);
        pushedFields.Add(new(OAuthRequestParameterNames.IssuerState, issuerState));
        (int parStatusCode, string parBody, Uri? location, int authorizeStatusCode) = await RawAuthCodeWirePushers.PushParAndAuthorizeAsync(
            host, material.Registration.TenantId.Value, ClientId, SubjectId, pushedFields, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, parStatusCode, parBody);
        Assert.AreEqual(issuerState, seenIssuerState,
            "The pushed issuer_state must reach the authorization-decision seam byte for byte.");
        Assert.AreEqual(302, authorizeStatusCode, "The authorization endpoint answers with a redirect.");
        Assert.IsNotNull(location, "The redirect carries a Location.");
        if(isCorrelated)
        {
            Assert.IsNotNull(TestBrowser.ExtractQueryParam(location.ToString(), OAuthRequestParameterNames.Code),
                $"A correlated issuer_state is permitted and the redirect carries a code: '{location}'.");
        }
        else
        {
            Assert.AreEqual(OAuthErrors.AccessDenied, TestBrowser.ExtractQueryParam(location.ToString(), OAuthRequestParameterNames.Error),
                $"An uncorrelated issuer_state is denied at the seam: '{location}'.");
        }
    }


    /// <summary>
    /// A pushed authorization request sent over the real wire whose <c>scope</c> and
    /// <c>openid_credential</c> object request the same Credential type yields a Token Response
    /// granting that type once, with the identifiers of the authorization details object.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.2">OID4VCI 1.0 Section 5.1.2</see>:
    /// "If a scope value related to Credential issuance and the authorization_details request
    /// parameter containing objects of type openid_credential are both present in a single request,
    /// the Credential Issuer MUST interpret these individually. However, if both request the same
    /// Credential type, then the Credential Issuer MUST follow the request as given by the
    /// authorization details object."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "authorization_details: REQUIRED when the authorization_details parameter, as defined in
    /// Section 5.1.1, is used in either the Authorization Request or Token Request." and
    /// "credential_identifiers: REQUIRED. A non-empty array of strings, each uniquely identifying a
    /// Credential Dataset that can be issued using the Access Token returned in this response."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ScopeAndDetailsForTheSameTypeAreGrantedOnceOverTheWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        //The seam answers a details-derived grant and a scope-derived grant for the same Credential
        //type, the details-derived grant first.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                static (details, subject, registration, context, ct) =>
                    ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                    [
                        new GrantedCredentialAuthorization
                        {
                            CredentialConfigurationId = DegreeConfigurationId,
                            CredentialIdentifiers = ["CivilEngineeringDegree-2026"]
                        },
                        new GrantedCredentialAuthorization
                        {
                            CredentialConfigurationId = DegreeConfigurationId,
                            CredentialIdentifiers = ["ScopeDerivedDuplicate-2026"]
                        }
                    ]));
        }).ConfigureAwait(false);

        //OID4VCI 1.0 Section 13.10: a plain bearer Credential token stays within five minutes.
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        List<KeyValuePair<string, string>> pushedFields = RawAuthCodeWirePushers.BuildParFields(ClientId, pkce, RedirectUri.OriginalString, $"{WellKnownScopes.OpenId} {DegreeConfigurationId}");
        pushedFields.Add(new(OAuthRequestParameterNames.AuthorizationDetails, SingleDetail(DegreeConfigurationId)));
        (int parStatusCode, string parBody, Uri? location, int authorizeStatusCode) = await RawAuthCodeWirePushers.PushParAndAuthorizeAsync(
            host, segment, ClientId, SubjectId, pushedFields, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parStatusCode, parBody);
        string code = DpopCodeBindingWire.ReadCode(authorizeStatusCode, location);

        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkce.EncodedVerifier, RedirectUri.OriginalString),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, body);
        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement granted = document.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(1, granted.GetArrayLength(),
            "The Credential type is granted once, as the authorization details object requests it.");
        Assert.AreEqual(DegreeConfigurationId, granted[0].GetProperty("credential_configuration_id").GetString(), body);
        Assert.AreSequenceEqual(
            ["CivilEngineeringDegree-2026"],
            granted[0].GetProperty("credential_identifiers").EnumerateArray().Select(static identifier => identifier.GetString()).ToArray(),
            "The identifiers granted are those of the authorization details object.");
    }


    /// <summary>
    /// A request carrying a parameter this specification does not define is served over the real
    /// wire as if the parameter were absent: a pushed authorization request carrying
    /// <c>x_vendor=1</c> is answered 201 with a <c>request_uri</c>, and a Pre-Authorized Code Token
    /// Request carrying <c>x_vendor=1</c> is answered 200 with an <c>access_token</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.3">OID4VCI 1.0 Section 5.1.3</see>:
    /// "Additional Authorization Request parameters MAY be defined and used, as described in [RFC6749].
    /// The Authorization Server MUST ignore any unrecognized parameters."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.1">OID4VCI 1.0 Section 6.1</see>:
    /// "Additional Token Request parameters MAY be defined and used, as described in [RFC6749]. The
    /// Authorization Server MUST ignore any unrecognized parameters."
    /// </summary>
    /// <param name="requestName">The request carrying the parameter: <c>pushed-authorization-request</c> or <c>pre-authorized-token-request</c>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("pushed-authorization-request")]
    [DataRow("pre-authorized-token-request")]
    public async Task UnrecognizedParametersAreIgnoredOverTheWireAsync(string requestName)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            AuthCodeCapabilities.Add(WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant)).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                static (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(SubjectId, DegreeConfigurationId));
        }).ConfigureAwait(false);

        //OID4VCI 1.0 Section 13.10: a plain bearer Credential token stays within five minutes.
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);
        List<KeyValuePair<string, string>> pushedFields = RawAuthCodeWirePushers.BuildParFields(ClientId, pkce, RedirectUri.OriginalString, WellKnownScopes.OpenId);
        pushedFields.Add(new("x_vendor", "1"));
        List<KeyValuePair<string, string>> tokenFields =
        [
            new(OAuthRequestParameterNames.GrantType, WellKnownGrantTypes.PreAuthorizedCode),
            new(OAuthRequestParameterNames.PreAuthorizedCode, "SplxlOBeZQQYbYS6WxSbIA"),
            new("x_vendor", "1")
        ];

        (int expectedStatusCode, string expectedMember, (int statusCode, string body)) = requestName switch
        {
            "pushed-authorization-request" => (201, "\"request_uri\":", await RawAuthCodeWirePushers.PushRawParFieldsAsync(
                host, segment, pushedFields, TestContext.CancellationToken).ConfigureAwait(false)),
            "pre-authorized-token-request" => (200, "\"access_token\":", await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, tokenFields, TestContext.CancellationToken).ConfigureAwait(false)),
            _ => throw new ArgumentOutOfRangeException(nameof(requestName), requestName, "No such request.")
        };

        Assert.AreEqual(expectedStatusCode, statusCode, body);
        Assert.Contains(expectedMember, body, StringComparison.Ordinal, body);
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
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        IReadOnlyList<string>? seenResource = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (evaluation, registration, context, ct) =>
                {
                    seenResource = evaluation.RequestedResource;

                    return ValueTask.FromResult(AuthorizationRequestDecision.Permit());
                };
        }).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await RunToAuthorizeAsync(
            host, material, resource: IssuerResource).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.IsNotNull(seenResource);
        Assert.HasCount(1, seenResource);
        Assert.AreEqual(IssuerResource, seenResource[0]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8707#section-2">RFC 8707 §2</see>: "Multiple
    /// 'resource' parameters MAY be used to indicate that the requested token is intended to be
    /// used at multiple resources" — the genuine multi-resource wire form is the REPEATED
    /// parameter, not several URIs packed into one occurrence separated by spaces. Every repeated
    /// occurrence is read and surfaced as the parsed list; an absent parameter surfaces as
    /// <see langword="null"/>.
    /// </summary>
    [TestMethod]
    public async Task MultipleResourceIndicatorsAreReadAndSurfaced()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        IReadOnlyList<string>? seenResource = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (evaluation, registration, context, ct) =>
                {
                    seenResource = evaluation.RequestedResource;

                    return ValueTask.FromResult(AuthorizationRequestDecision.Permit());
                };
        }).ConfigureAwait(false);

        const string secondResource = "https://other-issuer.example.com";
        ServerHttpResponse multi = await RunToAuthorizeAsync(
            host, material, issuerState: null, resources: [IssuerResource, secondResource]).ConfigureAwait(false);
        Assert.AreEqual(302, multi.StatusCode, multi.Body);
        Assert.IsNotNull(seenResource);
        Assert.HasCount(2, seenResource);
        Assert.AreEqual(IssuerResource, seenResource[0]);
        Assert.AreEqual(secondResource, seenResource[1]);

        seenResource = null;
        ServerHttpResponse none = await RunToAuthorizeAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(302, none.StatusCode, none.Body);
        Assert.IsNull(seenResource, "An absent resource parameter must surface as null at the seam.");
    }


    /// <summary>
    /// RFC 9396 §2 defines <c>authorization_details</c> as a JSON array of objects; the decision
    /// seam's <see cref="AuthorizationRequestEvaluation.RequestedAuthorizationDetailObjects"/>
    /// carries the SAME request's details parsed through the wired
    /// <c>ParseAuthorizationDetailsAsync</c> seam, beside the still-unchanged verbatim
    /// <see cref="AuthorizationRequestEvaluation.RequestedAuthorizationDetails"/> string, so an
    /// application correlating <c>issuer_state</c> to the requested
    /// <c>credential_configuration_id</c> reads the parsed value instead of re-parsing the string
    /// itself.
    /// </summary>
    [TestMethod]
    public async Task RequestedAuthorizationDetailsReachTheDecisionSeamParsed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        //The composition-time pairing check requires ResolveCredentialAuthorizationAsync alongside
        //the parser (no further authorization details type is registered here). This test never
        //reaches the token grant — it stops at the authorize response — so invoking the decision
        //seam fails the test rather than merely going unobserved.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                static (details, subject, registration, context, ct) =>
                {
                    Assert.Fail("This test never reaches the token grant; the credential decision seam must not be consulted.");

                    return ValueTask.FromResult(
                        CredentialAuthorizationDecision.Deny(CredentialAuthorizationDenialReason.AuthorizationDenied));
                };
        }).ConfigureAwait(false);

        string? seenVerbatim = "<unset>";
        IReadOnlyList<AuthorizationDetail>? seenParsed = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (evaluation, registration, context, ct) =>
                {
                    seenVerbatim = evaluation.RequestedAuthorizationDetails;
                    seenParsed = evaluation.RequestedAuthorizationDetailObjects;

                    return ValueTask.FromResult(AuthorizationRequestDecision.Permit());
                };
        }).ConfigureAwait(false);

        string verbatimDetails = SingleDetail(DegreeConfigurationId);
        ServerHttpResponse authorizeResponse = await RunToAuthorizeWithDetailsAsync(
            host, material, verbatimDetails).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.AreEqual(verbatimDetails, seenVerbatim,
            "The verbatim authorization_details string must reach the seam unchanged.");
        Assert.IsNotNull(seenParsed);
        Assert.HasCount(1, seenParsed);
        Assert.AreEqual(AuthorizationDetailsTypeValues.OpenIdCredential, seenParsed[0].Type);
        Assert.Contains(DegreeConfigurationId,
            seenParsed[0].ExtensionData[Oid4VciCredentialParameterNames.CredentialConfigurationId],
            StringComparison.Ordinal);
    }


    /// <summary>
    /// A request that carries no <c>authorization_details</c> observes
    /// <see langword="null"/> for both the verbatim string and the parsed list — there is nothing
    /// to parse.
    /// </summary>
    [TestMethod]
    public async Task RequestWithoutAuthorizationDetailsObservesNullParsedList()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        //The composition-time pairing check requires ResolveCredentialAuthorizationAsync alongside
        //the parser (no further authorization details type is registered here). This test never
        //reaches the token grant — it stops at the authorize response — so invoking the decision
        //seam fails the test rather than merely going unobserved.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                static (details, subject, registration, context, ct) =>
                {
                    Assert.Fail("This test never reaches the token grant; the credential decision seam must not be consulted.");

                    return ValueTask.FromResult(
                        CredentialAuthorizationDecision.Deny(CredentialAuthorizationDenialReason.AuthorizationDenied));
                };
        }).ConfigureAwait(false);

        IReadOnlyList<AuthorizationDetail>? seenParsed = [];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EvaluateAuthorizationRequestAsync =
                (evaluation, registration, context, ct) =>
                {
                    seenParsed = evaluation.RequestedAuthorizationDetailObjects;

                    return ValueTask.FromResult(AuthorizationRequestDecision.Permit());
                };
        }).ConfigureAwait(false);

        ServerHttpResponse authorizeResponse = await RunToAuthorizeAsync(host, material).ConfigureAwait(false);

        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        Assert.IsNull(seenParsed, "A request without authorization_details must observe a null parsed list.");
    }


    /// <summary>
    /// Drives PAR → authorize with <paramref name="authorizationDetails"/> pushed verbatim, and
    /// returns the authorize response, so the decision seam observes both the verbatim string and
    /// its parsed projection.
    /// </summary>
    private async ValueTask<ServerHttpResponse> RunToAuthorizeWithDetailsAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string authorizationDetails)
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
            [OAuthRequestParameterNames.AuthorizationDetails] = authorizationDetails
        };

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };

        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(SubjectId);

        return await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string SingleDetail(string configurationId) =>
        "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + configurationId + "\"}]";


    /// <summary>
    /// Drives PAR → authorize and returns the authorize response (a 302 on success), pushing the
    /// optional <paramref name="issuerState"/> and <paramref name="resource"/> so the
    /// authorization-decision seam observes them.
    /// </summary>
    private ValueTask<ServerHttpResponse> RunToAuthorizeAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string? issuerState = null,
        string? resource = null) =>
        RunToAuthorizeAsync(host, material, issuerState, resource is null ? null : [resource]);


    /// <summary>
    /// Drives PAR → authorize and returns the authorize response (a 302 on success), pushing the
    /// optional <paramref name="issuerState"/> and <paramref name="resources"/> so the
    /// authorization-decision seam observes them. Each entry of <paramref name="resources"/>
    /// becomes its OWN repeated <c>resource</c> field occurrence (<see cref="RequestFields.Add"/>)
    /// — RFC 8707 §2's actual multi-resource wire form.
    /// </summary>
    private async ValueTask<ServerHttpResponse> RunToAuthorizeAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string? issuerState,
        IReadOnlyList<string>? resources)
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
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        if(issuerState is not null)
        {
            parFields[OAuthRequestParameterNames.IssuerState] = issuerState;
        }

        if(resources is not null)
        {
            foreach(string resource in resources)
            {
                parFields.Add(OAuthRequestParameterNames.Resource, resource);
            }
        }

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };

        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(SubjectId);

        return await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(property).GetString()!;
    }
}
