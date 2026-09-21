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
/// RFC 9396 <c>authorization_details</c> of type <c>openid_credential</c> (OID4VCI 1.0 §5.1.1 /
/// §6.1.1 / §6.2), driven through the real dispatch pipeline. The pushed value is authoritative
/// through PAR → authorize → token (a front-channel duplicate is ignored), a token-request value
/// may narrow it to an authorized subset, and the application's
/// <see cref="ResolveCredentialAuthorizationDelegate"/> seam mints the §6.2
/// <c>credential_identifiers</c> the token response advertises. All refusals map to the RFC 9396
/// §5 <c>invalid_authorization_details</c> error.
/// </summary>
[TestClass]
internal sealed class Oid4VciAuthorizationDetailsTests
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

    /// <summary>The two Credential Configurations the tests request.</summary>
    private const string DegreeConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string LicenseConfigurationId = "org.iso.18013.5.1.mDL";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The capabilities the Authorization Code flow tests need.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> AuthCodeCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization);


    /// <summary>
    /// §5.1.1/§6.2 happy path: authorization_details pushed at PAR ride the flow to the token
    /// endpoint, the seam receives the parsed details and the authenticated subject, and the
    /// token response carries the granted details enriched with <c>credential_identifiers</c>.
    /// </summary>
    [TestMethod]
    public async Task AuthCodeFlowGrantsCredentialIdentifiersFromThePushedDetails()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        //Both authorization-details seams are coupled changes and are published together in ONE
        //alteration (EndpointServer.RequestAlterationAsync's own doc): a candidate wiring only the
        //parser is itself a half-wired server the composition-time pairing check now refuses.
        IReadOnlyList<CredentialAuthorizationDetail>? seenDetails = null;
        string? seenSubject = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                {
                    seenDetails = details;
                    seenSubject = subject;

                    return ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                    [
                        new GrantedCredentialAuthorization
                        {
                            CredentialConfigurationId = details[0].CredentialConfigurationId!,
                            CredentialIdentifiers = ["CivilEngineeringDegree-2026", "ElectricalEngineeringDegree-2026"]
                        }
                    ]));
                };
        }).ConfigureAwait(false);

        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." This plain-bearer credential flow stays within the
        //§13.10 long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);
        JsonElement details = doc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(JsonValueKind.Array, details.ValueKind);
        Assert.AreEqual(1, details.GetArrayLength());
        Assert.AreEqual("openid_credential", details[0].GetProperty("type").GetString());
        Assert.AreEqual(DegreeConfigurationId,
            details[0].GetProperty("credential_configuration_id").GetString());
        JsonElement identifiers = details[0].GetProperty("credential_identifiers");
        Assert.AreEqual(2, identifiers.GetArrayLength());
        Assert.AreEqual("CivilEngineeringDegree-2026", identifiers[0].GetString());

        //The seam received the parsed pushed details and the authorize-time subject.
        Assert.AreEqual(SubjectId, seenSubject);
        Assert.IsNotNull(seenDetails);
        Assert.HasCount(1, seenDetails!);
        Assert.AreEqual(DegreeConfigurationId, seenDetails![0].CredentialConfigurationId);

        //RFC 9396 §9.1: the minted RFC 9068 JWT access token carries the granted
        //authorization_details as a top-level claim, matching the token-response echo (the §6.2
        //enriched objects with credential_identifiers).
        string accessToken = ExtractFromBody(tokenResponse.Body, "access_token");
        using JsonDocument tokenPayload = JwtPayloadReader.ParsePayloadJson(accessToken);
        JsonElement claim = tokenPayload.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(JsonValueKind.Array, claim.ValueKind);
        Assert.AreEqual(1, claim.GetArrayLength());
        Assert.AreEqual("openid_credential", claim[0].GetProperty("type").GetString());
        Assert.AreEqual(DegreeConfigurationId,
            claim[0].GetProperty("credential_configuration_id").GetString());
        JsonElement claimIdentifiers = claim[0].GetProperty("credential_identifiers");
        Assert.AreEqual(JsonValueKind.Array, claimIdentifiers.ValueKind);
        Assert.AreEqual(2, claimIdentifiers.GetArrayLength());
        Assert.AreEqual("CivilEngineeringDegree-2026", claimIdentifiers[0].GetString());
        Assert.AreEqual("ElectricalEngineeringDegree-2026", claimIdentifiers[1].GetString());
    }


    /// <summary>
    /// RFC 9396 §9.1 is conditional on the grant carrying authorization_details: an Authorization
    /// Code grant with no <c>authorization_details</c> mints a JWT access token that carries no
    /// <c>authorization_details</c> claim.
    /// </summary>
    [TestMethod]
    public async Task AccessTokenCarriesNoAuthorizationDetailsClaimWithoutAGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
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
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [], TestContext.CancellationToken).ConfigureAwait(false);
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
            authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        string code = ExtractCode(authorizeResponse.Location!);

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeToken, "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
            },
            [], TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.IsFalse(seamCalled, "No grant carried authorization_details, so the decision seam is never consulted.");
        Assert.DoesNotContain("authorization_details", tokenResponse.Body,
            "The token response carries no authorization_details when the grant had none.");

        string accessToken = ExtractFromBody(tokenResponse.Body, "access_token");
        using JsonDocument tokenPayload = JwtPayloadReader.ParsePayloadJson(accessToken);
        Assert.IsFalse(tokenPayload.RootElement.TryGetProperty("authorization_details", out _),
            "RFC 9396 §9.1 is conditional: no granted authorization_details, no claim.");
    }


    /// <summary>
    /// RFC 9101 §6.3 via RFC 9126 §4: the pushed authorization_details is authoritative — a
    /// different value injected on the front-channel authorize request is ignored, and the
    /// token grant resolves against the pushed value.
    /// </summary>
    [TestMethod]
    public async Task FrontChannelAuthorizationDetailsTamperingIsIgnored()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        IReadOnlyList<CredentialAuthorizationDetail>? seenDetails = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                {
                    seenDetails = details;

                    return ValueTask.FromResult(GrantAllRequested(details));
                };
        }).ConfigureAwait(false);

        //§13.10: keep the plain-bearer credential token within the long-lived threshold.
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: SingleDetail(DegreeConfigurationId),
            frontChannelDetails: SingleDetail(LicenseConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.IsNotNull(seenDetails);
        Assert.HasCount(1, seenDetails);
        Assert.AreEqual(DegreeConfigurationId, seenDetails[0].CredentialConfigurationId,
            "The pushed authorization_details must govern; the front-channel value is ignored.");
    }


    /// <summary>
    /// §6.1.1: the token request may narrow the authorized details to a subset of the pushed
    /// configurations — the seam then receives only the narrowed set.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestMayNarrowToAnAuthorizedSubset()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        IReadOnlyList<CredentialAuthorizationDetail>? seenDetails = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                {
                    seenDetails = details;

                    return ValueTask.FromResult(GrantAllRequested(details));
                };
        }).ConfigureAwait(false);

        //§13.10: keep the plain-bearer credential token within the long-lived threshold.
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: TwoDetails(DegreeConfigurationId, LicenseConfigurationId),
            tokenRequestDetails: SingleDetail(LicenseConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.IsNotNull(seenDetails);
        Assert.HasCount(1, seenDetails);
        Assert.AreEqual(LicenseConfigurationId, seenDetails[0].CredentialConfigurationId);

        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);
        JsonElement details = doc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(1, details.GetArrayLength());
        Assert.AreEqual(LicenseConfigurationId,
            details[0].GetProperty("credential_configuration_id").GetString());
    }


    /// <summary>
    /// §6.1.1: a token-request configuration outside the authorized set is refused with
    /// <c>invalid_authorization_details</c> before the seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestBeyondTheAuthorizedSetIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
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

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: SingleDetail(DegreeConfigurationId),
            tokenRequestDetails: SingleDetail(LicenseConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, tokenResponse.Body);
        Assert.IsFalse(seamCalled, "The seam must not be consulted when the narrowing rule is violated.");

        //Discriminator: a healthy grant of the same shape, narrowed to its OWN authorized
        //configuration, still succeeds and reaches the seam.
        ServerHttpResponse healthyResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: SingleDetail(DegreeConfigurationId),
            tokenRequestDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(200, healthyResponse.StatusCode, healthyResponse.Body);
        Assert.IsTrue(seamCalled, "A narrowing request naming an authorized configuration must reach the seam.");
    }


    /// <summary>
    /// §5.1.1 shape enforcement at PAR receipt: malformed JSON, an unsupported authorization
    /// details type, and a missing <c>credential_configuration_id</c> are each refused with
    /// <c>invalid_authorization_details</c>.
    /// </summary>
    [TestMethod]
    public async Task MalformedShapesAreRejectedAtPar()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        //The composition-time pairing check requires ResolveCredentialAuthorizationAsync alongside
        //the parser (no further authorization details type is registered here). This test never
        //reaches the token grant — every case is refused at PAR shape validation — so invoking the
        //decision seam fails the test rather than merely going unobserved.
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

        await AssertParRejectsAsync(host, material, "{ not json").ConfigureAwait(false);
        await AssertParRejectsAsync(host, material,
            "[{\"type\":\"payment_initiation\",\"credential_configuration_id\":\"x\"}]").ConfigureAwait(false);
        await AssertParRejectsAsync(host, material,
            "[{\"type\":\"openid_credential\"}]").ConfigureAwait(false);
        await AssertParRejectsAsync(host, material, "[]").ConfigureAwait(false);
    }


    /// <summary>
    /// Fail-closed: a PAR request carrying authorization_details while the parse seam is
    /// unwired is refused — the server does not support the parameter (RFC 9396 §5).
    /// </summary>
    [TestMethod]
    public async Task DetailsWithoutTheParseSeamAreRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        await AssertParRejectsAsync(host, material, SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
    }


    /// <summary>
    /// Fail-closed: when the grant carries authorization_details but the decision seam is
    /// unwired, the token request is refused with <c>invalid_authorization_details</c> — the
    /// library cannot mint <c>credential_identifiers</c>.
    /// </summary>
    [TestMethod]
    public async Task DetailsWithoutTheResolveSeamAreRejectedAtToken()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        //A deployment wiring the parser for the built-in openid_credential type ALONE, with no
        //decision seam, is a composition the AS refuses at Validate() (an issuance-capable
        //integration whose grant can never mint credential_identifiers). This test's own subject —
        //the wire-level fail-closed refusal when the seam is genuinely unwired — remains reachable
        //for a deployment that also registers a further authorization details type (a RAR-style
        //use of the parameter for something other than credential issuance): the composition-time
        //check stays silent for it (RegisteredTypes.Count > 1), and ResolveCredentialAuthorizationAsync
        //stays unwired for the openid_credential grant this test carries.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
        }).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, tokenResponse.Body);

        //Discriminator: wiring the resolve seam afterward, a healthy grant of the same shape
        //still succeeds and mints credential_identifiers.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);
        ServerHttpResponse healthyResponse = await RunAuthCodeFlowAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(200, healthyResponse.StatusCode, healthyResponse.Body);
    }


    /// <summary>
    /// Each seam refusal maps to <c>invalid_authorization_details</c> (RFC 9396 §5), with the
    /// reason-specific default description distinguishing the cases.
    /// </summary>
    [TestMethod]
    public async Task SeamDenialsMapToInvalidAuthorizationDetails()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();


            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(
                    CredentialAuthorizationDecision.Deny(
                        CredentialAuthorizationDenialReason.UnknownCredentialConfiguration));
        }).ConfigureAwait(false);

        ServerHttpResponse unknownResponse = await RunAuthCodeFlowAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(400, unknownResponse.StatusCode, unknownResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, unknownResponse.Body);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(
                    CredentialAuthorizationDecision.Deny(
                        CredentialAuthorizationDenialReason.AuthorizationDenied));
        }).ConfigureAwait(false);

        ServerHttpResponse deniedResponse = await RunAuthCodeFlowAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(400, deniedResponse.StatusCode, deniedResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, deniedResponse.Body);

        //Discriminator: wiring a granting decision afterward, a healthy grant of the same shape
        //still succeeds.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);
        ServerHttpResponse grantedResponse = await RunAuthCodeFlowAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(200, grantedResponse.StatusCode, grantedResponse.Body);
    }


    /// <summary>
    /// §6.1.1 in the Pre-Authorized Code Flow: the Wallet presents authorization_details
    /// directly in the token request (there is no authorize step), the seam receives them with
    /// the grant-resolved subject, and the response carries the granted details.
    /// </summary>
    [TestMethod]
    public async Task PreAuthorizedFlowResolvesDetailsFromTheTokenRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant)).ConfigureAwait(false);
        IReadOnlyList<CredentialAuthorizationDetail>? seenDetails = null;
        string? seenSubject = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                {
                    seenDetails = details;
                    seenSubject = subject;

                    return ValueTask.FromResult(GrantAllRequested(details));
                };
        }).ConfigureAwait(false);

        //§13.10: the Pre-Authorized Code grant mints a plain-bearer credential token; keep it
        //within the long-lived threshold so it is not refused as an unconstrained long-lived token.
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(SubjectId));
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA",
                [OAuthRequestParameterNames.AuthorizationDetails] = SingleDetail(DegreeConfigurationId)
            },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(SubjectId, seenSubject, "The seam must receive the grant-resolved subject.");
        Assert.IsNotNull(seenDetails);
        Assert.AreEqual(DegreeConfigurationId, seenDetails[0].CredentialConfigurationId);

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement details = doc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(DegreeConfigurationId,
            details[0].GetProperty("credential_configuration_id").GetString());
        Assert.IsGreaterThan(0, details[0].GetProperty("credential_identifiers").GetArrayLength());
    }


    /// <summary>
    /// RFC 9396 §10: <c>authorization_details_types_supported</c> advertises
    /// <c>openid_credential</c> exactly when the decision seam is wired — absent otherwise, so
    /// the advertisement never invites requests the server would refuse.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryAdvertisesAuthorizationDetailsTypesOnlyWhenWired()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        //Registering a second authorization details type alongside the parser, in ONE
        //alteration, keeps RegisteredTypes.Count above 1 throughout — the composition-time
        //pairing check only refuses a candidate wiring the parser for the built-in
        //openid_credential type alone. ResolveCredentialAuthorizationAsync stays exactly as
        //unwired as before, which is what this test's "unwired" observation needs; the discovery
        //gate itself reads only ResolveCredentialAuthorizationAsync's nullity (MetadataEndpoints),
        //never RegisteredTypes.Count, so the observation is unaffected.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
        }).ConfigureAwait(false);

        ServerHttpResponse unwired = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, unwired.StatusCode, unwired.Body);
        Assert.DoesNotContain("authorization_details_types_supported", unwired.Body,
            "An unwired decision seam must not advertise authorization details support.");

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);

        ServerHttpResponse wired = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, wired.StatusCode, wired.Body);
        Assert.Contains("authorization_details_types_supported", wired.Body);
        Assert.Contains("openid_credential", wired.Body);
    }


    /// <summary>
    /// RFC 9396 §10: the advertised <c>authorization_details_types_supported</c> is derived from
    /// the registry — a second handler registered for a further type is advertised alongside the
    /// built-in <c>openid_credential</c>.
    /// </summary>
    [TestMethod]
    public async Task DiscoveryAdvertisesEveryRegisteredAuthorizationDetailsType()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(
            ClientId, ClientBaseUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint)).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();


            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizationDetailTypes.Register(new AuthorizationDetailHandler
            {
                Type = "payment_initiation",
                ValidateShape = (detail, validation) => null
            });
        }).ConfigureAwait(false);

        ServerHttpResponse discovery = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, discovery.StatusCode, discovery.Body);

        using JsonDocument doc = JsonDocument.Parse(discovery.Body);
        JsonElement types = doc.RootElement.GetProperty("authorization_details_types_supported");
        Assert.AreEqual(2, types.GetArrayLength());
        Assert.AreEqual("openid_credential", types[0].GetString());
        Assert.AreEqual("payment_initiation", types[1].GetString());
    }


    /// <summary>
    /// RFC 9396 §7 / §9.1 / §11.2 ("This should work with any grant type, especially
    /// authorization_code and refresh_token"): a refresh of a grant that carried
    /// <c>authorization_details</c> re-emits the §7 token-response echo with freshly minted
    /// <c>credential_identifiers</c> (§6.2) and the refreshed access token carries the §9.1
    /// <c>authorization_details</c> claim.
    /// </summary>
    [TestMethod]
    public async Task RefreshReEmitsGrantedAuthorizationDetailsWithFreshCredentialIdentifiers()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        int resolveCount = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                {
                    resolveCount++;
                    string identifierSuffix = resolveCount.ToString(System.Globalization.CultureInfo.InvariantCulture);

                    return ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                    [
                        new GrantedCredentialAuthorization
                        {
                            CredentialConfigurationId = details[0].CredentialConfigurationId!,
                            CredentialIdentifiers = [$"{details[0].CredentialConfigurationId}-dataset-{identifierSuffix}"]
                        }
                    ]));
                };
        }).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        (ServerHttpResponse tokenResponse, string refreshToken) = await RunAuthCodeFlowCapturingRefreshAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        //The initial token exchange minted dataset-1; the refresh re-runs the seam and mints a
        //fresh credential_identifiers set (dataset-2), proving §6.2 freshness on refresh.
        ServerHttpResponse refreshResponse = await DispatchRefreshAsync(host, material, refreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, refreshResponse.StatusCode, refreshResponse.Body);
        Assert.AreEqual(2, resolveCount, "The decision seam re-runs on refresh to re-mint credential_identifiers.");

        using JsonDocument doc = JsonDocument.Parse(refreshResponse.Body);
        JsonElement details = doc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(1, details.GetArrayLength());
        Assert.AreEqual("openid_credential", details[0].GetProperty("type").GetString());
        Assert.AreEqual(DegreeConfigurationId, details[0].GetProperty("credential_configuration_id").GetString());
        JsonElement identifiers = details[0].GetProperty("credential_identifiers");
        Assert.AreEqual(1, identifiers.GetArrayLength());
        Assert.AreEqual($"{DegreeConfigurationId}-dataset-2", identifiers[0].GetString(),
            "The refresh response advertises freshly minted credential_identifiers.");

        //RFC 9396 §9.1: the refreshed RFC 9068 JWT access token carries the granted
        //authorization_details claim, matching the refresh-response echo.
        string refreshedAccessToken = ExtractFromBody(refreshResponse.Body, "access_token");
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(refreshedAccessToken);
        JsonElement claim = payload.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(1, claim.GetArrayLength());
        Assert.AreEqual(DegreeConfigurationId, claim[0].GetProperty("credential_configuration_id").GetString());
        Assert.AreEqual($"{DegreeConfigurationId}-dataset-2",
            claim[0].GetProperty("credential_identifiers")[0].GetString());
    }


    /// <summary>
    /// RFC 9396 §6.1 ("upon refreshing a token, the client can ask for a new access token with
    /// fewer permissions"): a refresh request narrowing the grant to an authorized subset gets
    /// the subset, and a refresh request asking for a configuration outside the grant is refused
    /// with <c>invalid_authorization_details</c>.
    /// </summary>
    [TestMethod]
    public async Task RefreshHonoursSubsetNarrowingAndRejectsConfigurationsOutsideTheGrant()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        (ServerHttpResponse tokenResponse, string refreshToken) = await RunAuthCodeFlowCapturingRefreshAsync(
            host, material, parDetails: TwoDetails(DegreeConfigurationId, LicenseConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        //§6.1 narrowing: ask for only the licence on refresh — the response carries just that one.
        ServerHttpResponse narrowed = await DispatchRefreshAsync(
            host, material, refreshToken, SingleDetail(LicenseConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(200, narrowed.StatusCode, narrowed.Body);
        using JsonDocument narrowedDoc = JsonDocument.Parse(narrowed.Body);
        JsonElement narrowedDetails = narrowedDoc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(1, narrowedDetails.GetArrayLength());
        Assert.AreEqual(LicenseConfigurationId,
            narrowedDetails[0].GetProperty("credential_configuration_id").GetString());

        //A refresh asking for a configuration the grant never authorized is refused. The narrowing
        //refresh above rotated the token, so drive a fresh issuance to test the rejection cleanly.
        (_, string secondRefreshToken) = await RunAuthCodeFlowCapturingRefreshAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
        ServerHttpResponse rejected = await DispatchRefreshAsync(
            host, material, secondRefreshToken, SingleDetail(LicenseConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(400, rejected.StatusCode, rejected.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, rejected.Body);

        //Discriminator: the narrowing refusal did not consume the refresh token — a subsequent
        //refresh naming the grant's own authorized configuration still succeeds.
        ServerHttpResponse recovered = await DispatchRefreshAsync(
            host, material, secondRefreshToken, SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(200, recovered.StatusCode, recovered.Body);
    }


    /// <summary>
    /// RFC 9396 §6.1 across rotation (RFC 9700 §2.2.2): the granted authorization_details survive
    /// a refresh-token rotation, so a second refresh using the rotated token still re-emits them.
    /// </summary>
    [TestMethod]
    public async Task GrantedAuthorizationDetailsSurviveRefreshTokenRotation()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        (_, string firstRefreshToken) = await RunAuthCodeFlowCapturingRefreshAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);

        //First refresh — rotates the token and must still carry the details.
        ServerHttpResponse firstRefresh = await DispatchRefreshAsync(host, material, firstRefreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, firstRefresh.StatusCode, firstRefresh.Body);
        string secondRefreshToken = ExtractFromBody(firstRefresh.Body, "refresh_token");
        Assert.AreNotEqual(firstRefreshToken, secondRefreshToken, "The refresh token must rotate.");

        //Second refresh using the rotated token — the details survived rotation.
        ServerHttpResponse secondRefresh = await DispatchRefreshAsync(host, material, secondRefreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, secondRefresh.StatusCode, secondRefresh.Body);
        using JsonDocument doc = JsonDocument.Parse(secondRefresh.Body);
        JsonElement details = doc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(DegreeConfigurationId, details[0].GetProperty("credential_configuration_id").GetString());
    }


    /// <summary>
    /// RFC 9396 §6.1: "The requested access token will convey the reduced permissions, but the
    /// resource owner's previous authorization is unchanged by such requests." A narrowing
    /// refresh reduces only the access token it mints; a later refresh of the rotated token
    /// without a narrowing request receives the full originally authorized details again.
    /// </summary>
    [TestMethod]
    public async Task NarrowingRefreshLeavesTheResourceOwnersAuthorizationUnchanged()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));
        }).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        (_, string refreshToken) = await RunAuthCodeFlowCapturingRefreshAsync(
            host, material, parDetails: TwoDetails(DegreeConfigurationId, LicenseConfigurationId)).ConfigureAwait(false);

        //§6.1 narrowing: the minted token conveys only the licence.
        ServerHttpResponse narrowed = await DispatchRefreshAsync(
            host, material, refreshToken, SingleDetail(LicenseConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(200, narrowed.StatusCode, narrowed.Body);
        using JsonDocument narrowedDoc = JsonDocument.Parse(narrowed.Body);
        Assert.AreEqual(1, narrowedDoc.RootElement.GetProperty("authorization_details").GetArrayLength());
        string rotatedRefreshToken = ExtractFromBody(narrowed.Body, "refresh_token");

        //The narrowing reduced the token, not the authorization: a refresh of the rotated token
        //without a narrowing request receives the full originally authorized details again.
        ServerHttpResponse full = await DispatchRefreshAsync(host, material, rotatedRefreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, full.StatusCode, full.Body);
        using JsonDocument fullDoc = JsonDocument.Parse(full.Body);
        JsonElement fullDetails = fullDoc.RootElement.GetProperty("authorization_details");
        Assert.AreEqual(2, fullDetails.GetArrayLength());
    }


    /// <summary>
    /// A refresh of a grant that carried no authorization_details (and a refresh request carrying
    /// none) yields a response with no <c>authorization_details</c> member and no §9.1
    /// access-token claim.
    /// </summary>
    [TestMethod]
    public async Task RefreshOfADetailLessGrantCarriesNoAuthorizationDetails()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
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
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [], TestContext.CancellationToken).ConfigureAwait(false);
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
            authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        string code = ExtractCode(authorizeResponse.Location!);

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeToken, "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
            },
            [], TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        string refreshToken = ExtractFromBody(tokenResponse.Body, "refresh_token");

        ServerHttpResponse refreshResponse = await DispatchRefreshAsync(host, material, refreshToken).ConfigureAwait(false);
        Assert.AreEqual(200, refreshResponse.StatusCode, refreshResponse.Body);
        Assert.IsFalse(seamCalled, "A detail-less grant never consults the decision seam on refresh.");
        Assert.DoesNotContain("authorization_details", refreshResponse.Body,
            "A refresh of a detail-less grant carries no authorization_details member.");

        string refreshedAccessToken = ExtractFromBody(refreshResponse.Body, "access_token");
        using JsonDocument payload = JwtPayloadReader.ParsePayloadJson(refreshedAccessToken);
        Assert.IsFalse(payload.RootElement.TryGetProperty("authorization_details", out _),
            "RFC 9396 §9.1 is conditional: no granted details, no claim on the refreshed token.");
    }


    /// <summary>A strict, registry-validated authorization details type used in these tests.</summary>
    private const string PaymentInitiationType = "payment_initiation";


    /// <summary>
    /// RFC 9396 §5 strict per-type validation end to end at PAR receipt: a registered strict
    /// handler refuses an unknown field, a wrong-typed field, and an invalid field value, each
    /// mapping to <c>invalid_authorization_details</c>; a conforming object is accepted.
    /// </summary>
    [TestMethod]
    public async Task StrictTypeEnforcesEverySectionFiveAbortCauseAtPar()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        //Registering the strict second type alongside the parser, in ONE alteration, keeps
        //RegisteredTypes.Count above 1 throughout — the composition-time pairing check only
        //refuses a candidate wiring the parser for the built-in openid_credential type alone.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
        }).ConfigureAwait(false);

        //RFC 9396 §5: "is an object of known type but containing unknown fields."
        await AssertParRejectsAsync(host, material,
            """[{"type":"payment_initiation","instructedAmount":{"amount":"1.00"},"rogue":"x"}]""").ConfigureAwait(false);

        //RFC 9396 §5: "contains fields of the wrong type" — a type-specific field of the wrong shape.
        await AssertParRejectsAsync(host, material,
            """[{"type":"payment_initiation","instructedAmount":"not-an-object"}]""").ConfigureAwait(false);

        //RFC 9396 §5: "contains fields of the wrong type" — a §2.2 common field of the wrong shape.
        await AssertParRejectsAsync(host, material,
            """[{"type":"payment_initiation","instructedAmount":{"amount":"1.00"},"locations":"https://rs.example"}]""").ConfigureAwait(false);

        //RFC 9396 §5: "contains fields with invalid values for the authorization details type."
        await AssertParRejectsAsync(host, material,
            """[{"type":"payment_initiation","instructedAmount":{"amount":"1.00"},"currency":"XYZ"}]""").ConfigureAwait(false);

        //RFC 9396 §5: "is missing required fields for the authorization details type."
        await AssertParRejectsAsync(host, material,
            """[{"type":"payment_initiation"}]""").ConfigureAwait(false);

        //A conforming object is accepted at PAR.
        await AssertParAcceptsAsync(host, material,
            """[{"type":"payment_initiation","instructedAmount":{"amount":"1.00"},"currency":"EUR"}]""").ConfigureAwait(false);
    }


    /// <summary>
    /// The lenient <c>openid_credential</c> profile (OID4VCI 1.0 §5.1.1, never invalid due to
    /// unknown fields) keeps accepting an object carrying an unknown member at PAR, even while a
    /// strict second type is registered — the strictness framework does not change the profile.
    /// </summary>
    [TestMethod]
    public async Task OpenIdCredentialStaysLenientForUnknownFieldsAtPar()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        //Registering the strict second type alongside the parser, in ONE alteration, keeps
        //RegisteredTypes.Count above 1 throughout — the composition-time pairing check only
        //refuses a candidate wiring the parser for the built-in openid_credential type alone.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
        }).ConfigureAwait(false);

        await AssertParAcceptsAsync(host, material,
            """[{"type":"openid_credential","credential_configuration_id":"UniversityDegree_dc_sd_jwt","vendor_extension":{"anything":true}}]""").ConfigureAwait(false);
    }


    /// <summary>
    /// RFC 9396 §10: a client that registered an <c>authorization_details_types</c> allowlist may
    /// use a registered type that is within the allowlist (here <c>openid_credential</c>) but is
    /// refused at PAR with <c>invalid_authorization_details</c> for a server-supported type that is
    /// outside the client's allowlist (here <c>payment_initiation</c>) — the AS entitles the client
    /// to certain authorization details types (§11.1).
    /// </summary>
    [TestMethod]
    public async Task ClientRestrictedToATypeEnforcesItsAuthorizationDetailsTypesAllowlistAtPar()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        //The server supports payment_initiation, but the client registered only openid_credential.
        //Registering the second type alongside the parser, in ONE alteration, keeps
        //RegisteredTypes.Count above 1 throughout — the composition-time pairing check only
        //refuses a candidate wiring the parser for the built-in openid_credential type alone.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
        }).ConfigureAwait(false);
        await host.SetAllowedAuthorizationDetailsTypesAsync(
            material, ImmutableHashSet.Create(AuthorizationDetailsTypeValues.OpenIdCredential)).ConfigureAwait(false);

        //An allowlisted type passes shape validation.
        await AssertParAcceptsAsync(host, material, SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);

        //A server-supported type the client did NOT register is refused with invalid_authorization_details.
        await AssertParRejectsAsync(host, material,
            """[{"type":"payment_initiation","instructedAmount":{"amount":"1.00"},"currency":"EUR"}]""").ConfigureAwait(false);
    }


    /// <summary>
    /// RFC 9396 §10: the per-client <c>authorization_details_types</c> allowlist is enforced on the
    /// token request as well — a Pre-Authorized Code token request carrying a server-supported type
    /// outside the client's allowlist is refused with <c>invalid_authorization_details</c> before
    /// the decision seam is consulted.
    /// </summary>
    [TestMethod]
    public async Task ClientAuthorizationDetailsTypesAllowlistIsEnforcedAtTheTokenRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant)).ConfigureAwait(false);
        //Registering the second type alongside the parser, in ONE alteration, keeps
        //RegisteredTypes.Count above 1 throughout — the composition-time pairing check only
        //refuses a candidate wiring the parser for the built-in openid_credential type alone.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
        }).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        await host.SetAllowedAuthorizationDetailsTypesAsync(
            material, ImmutableHashSet.Create(AuthorizationDetailsTypeValues.OpenIdCredential)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(SubjectId));
        }).ConfigureAwait(false);

        bool seamCalled = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                {
                    seamCalled = true;

                    return ValueTask.FromResult(GrantAllRequested(details));
                };
        }).ConfigureAwait(false);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA",
                [OAuthRequestParameterNames.AuthorizationDetails] =
                    """[{"type":"payment_initiation","instructedAmount":{"amount":"1.00"},"currency":"EUR"}]"""
            },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, response.Body);
        Assert.IsFalse(seamCalled, "The allowlist gate must refuse before the decision seam is consulted.");
    }


    /// <summary>
    /// RFC 9396 §10 absent-metadata default: a client that registered no
    /// <c>authorization_details_types</c> restriction may use any server-supported type — the
    /// metadata's absence is advisory ("MAY indicate"), not a prohibition. A
    /// <c>payment_initiation</c> request passes shape validation at PAR even though the client
    /// registered no allowlist.
    /// </summary>
    [TestMethod]
    public async Task ClientWithNoAllowlistMayUseAnySupportedAuthorizationDetailsType()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

        //Registering the strict second type alongside the parser, in ONE alteration, keeps
        //RegisteredTypes.Count above 1 throughout — the composition-time pairing check only
        //refuses a candidate wiring the parser for the built-in openid_credential type alone.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
        }).ConfigureAwait(false);

        Assert.IsNull(material.Registration.AllowedAuthorizationDetailsTypes,
            "The fixture client registers no authorization_details_types restriction.");

        await AssertParAcceptsAsync(host, material,
            """[{"type":"payment_initiation","instructedAmount":{"amount":"1.00"},"currency":"EUR"}]""").ConfigureAwait(false);
        await AssertParAcceptsAsync(host, material, SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
    }


    /// <summary>
    /// A strict <c>payment_initiation</c> handler with a required object field and an optional
    /// string field whose value is checked against a closed currency set — the fixture driving
    /// every §5 abort category through the endpoints.
    /// </summary>
    private static AuthorizationDetailHandler StrictPaymentInitiationHandler()
    {
        return new AuthorizationDetailHandler
        {
            Type = PaymentInitiationType,
            ValidateShape = AuthorizationDetailStrictFieldValidation.ForFields(
                new AuthorizationDetailFieldRule
                {
                    Name = "instructedAmount",
                    IsRequired = true,
                    Shape = AuthorizationDetailFieldShape.Object
                },
                new AuthorizationDetailFieldRule
                {
                    Name = "currency",
                    Shape = AuthorizationDetailFieldShape.String,
                    ValidateValue = rawValue =>
                        string.Equals(JsonScalarText.AsString(rawValue), "EUR", StringComparison.Ordinal)
                            ? null
                            : "The field 'currency' must be 'EUR'."
                })
        };
    }


    /// <summary>
    /// A grant covering every requested configuration, with deterministic per-configuration
    /// dataset identifiers.
    /// </summary>
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


    private static string SingleDetail(string configurationId) =>
        "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + configurationId + "\"}]";


    private static string TwoDetails(string firstConfigurationId, string secondConfigurationId) =>
        "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + firstConfigurationId
        + "\"},{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + secondConfigurationId + "\"}]";


    /// <summary>
    /// Drives the full PAR → authorize → token flow with the given authorization_details at
    /// each leg: <paramref name="parDetails"/> is pushed, an optional
    /// <paramref name="frontChannelDetails"/> is injected on the authorize query (tampering),
    /// and an optional <paramref name="tokenRequestDetails"/> rides the token request
    /// (§6.1.1 narrowing).
    /// </summary>
    private async ValueTask<ServerHttpResponse> RunAuthCodeFlowAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string parDetails,
        string? frontChannelDetails = null,
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

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        if(frontChannelDetails is not null)
        {
            authorizeFields[OAuthRequestParameterNames.AuthorizationDetails] = frontChannelDetails;
        }

        ExchangeContext authorizeContext = [];
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
        if(tokenRequestDetails is not null)
        {
            tokenFields[OAuthRequestParameterNames.AuthorizationDetails] = tokenRequestDetails;
        }

        return await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the full PAR → authorize → token flow exactly as <see cref="RunAuthCodeFlowAsync"/>
    /// but also returns the issued <c>refresh_token</c> so a refresh exchange can be driven against
    /// the same grant.
    /// </summary>
    private async ValueTask<(ServerHttpResponse TokenResponse, string RefreshToken)> RunAuthCodeFlowCapturingRefreshAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string parDetails)
    {
        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(host, material, parDetails).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        return (tokenResponse, ExtractFromBody(tokenResponse.Body, "refresh_token"));
    }


    /// <summary>
    /// Dispatches a refresh-token grant request, optionally carrying an
    /// <paramref name="refreshRequestDetails"/> authorization_details value (the §6.1 narrowing
    /// request).
    /// </summary>
    private async ValueTask<ServerHttpResponse> DispatchRefreshAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string refreshToken,
        string? refreshRequestDetails = null)
    {
        RequestFields refreshFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = refreshToken,
            [OAuthRequestParameterNames.ClientId] = ClientId
        };
        if(refreshRequestDetails is not null)
        {
            refreshFields[OAuthRequestParameterNames.AuthorizationDetails] = refreshRequestDetails;
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodeToken, "POST",
            refreshFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Dispatches a PAR request carrying the given <paramref name="authorizationDetails"/> and
    /// asserts the <c>invalid_authorization_details</c> refusal.
    /// </summary>
    private async ValueTask AssertParRejectsAsync(
        TestHostShell host, VerifierKeyMaterial material, string authorizationDetails)
    {
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
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, parResponse.StatusCode, parResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, parResponse.Body);
    }


    /// <summary>
    /// Dispatches a PAR request carrying the given <paramref name="authorizationDetails"/> and
    /// asserts the shape is accepted (the PAR receipt issues a <c>request_uri</c>).
    /// </summary>
    private async ValueTask AssertParAcceptsAsync(
        TestHostShell host, VerifierKeyMaterial material, string authorizationDetails)
    {
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
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
    }


    private async ValueTask<ServerHttpResponse> DispatchDiscoveryAsync(
        TestHostShell host, VerifierKeyMaterial material)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.MetadataDiscovery,
            WellKnownHttpMethods.Get,
            new RequestFields(),
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>The RFC 9396 §2 type value the permitted-but-unresolvable tests register.</summary>
    private const string CustomDetailsType = "urn:verifiable-tests:custom-authorization-detail";

    /// <summary>A shape-valid authorization_details value of <see cref="CustomDetailsType"/>.</summary>
    private const string CustomDetail = "[{\"type\":\"" + CustomDetailsType + "\"}]";

    /// <summary>An authorization_details value that fails to parse as JSON at all.</summary>
    private const string MalformedDetail = "[{\"type\":not-valid-json]";


    /// <summary>
    /// The STEPLESS overload of
    /// <c>ResolveRequiredAuthorizationDetailsLocationAsync</c> (PAR's own path, through
    /// <c>ValidateAuthorizationDetailsShapeAsync</c>) must keep its ORIGINAL metadata-first
    /// short-circuit — no issuer resolution at all when the Credential Issuer metadata contributor
    /// is absent, or is present but its <c>authorization_servers</c> is EMPTY. Compares the
    /// per-request <c>ResolveIssuerAsync</c> count for an otherwise-identical PAR request with and
    /// without a shape-valid <c>authorization_details</c> value: the two counts are EQUAL — an
    /// overload that resolved the issuer before its short-circuit would show as one more call
    /// for the authorization_details-bearing request — under BOTH an absent contributor and a
    /// present-but-empty one.
    /// </summary>
    [TestMethod]
    public async Task StepwiseAuthorizationDetailsLocationDoesNotAddAnIssuerResolutionAtParAsync()
    {
        foreach(bool contributorWired in new[] { false, true })
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);

            int resolveIssuerCount = 0;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
                candidateIntegration.AuthorizationDetailTypes.Register(new AuthorizationDetailHandler
                {
                    Type = CustomDetailsType,
                    ValidateShape = (_, _) => null
                });
                candidateIntegration.ResolveIssuerAsync = (reg, ctx, ct) =>
                {
                    resolveIssuerCount++;

                    return ValueTask.FromResult<Uri?>(((ClientRecord)reg).IssuerUri);
                };
                if(contributorWired)
                {
                    //A PRESENT contributor whose authorization_servers is EMPTY — the other half
                    //of the metadata-first short-circuit S1 protects.
                    candidateIntegration.ContributeCredentialIssuerMetadataAsync =
                        (reg, ctx, ct) => ValueTask.FromResult(CredentialIssuerMetadataContribution.Empty);
                }
            }).ConfigureAwait(false);

            resolveIssuerCount = 0;
            ServerHttpResponse withoutDetails = await PushParAsync(host, material, authorizationDetails: null).ConfigureAwait(false);
            Assert.AreEqual(201, withoutDetails.StatusCode, withoutDetails.Body);
            int baselineCount = resolveIssuerCount;

            resolveIssuerCount = 0;
            ServerHttpResponse withDetails = await PushParAsync(host, material, CustomDetail).ConfigureAwait(false);
            Assert.AreEqual(201, withDetails.StatusCode, withDetails.Body);

            Assert.AreEqual(baselineCount, resolveIssuerCount,
                contributorWired
                    ? "A present contributor with an empty authorization_servers must add no extra issuer resolution at PAR."
                    : "An absent metadata contributor must add no extra issuer resolution at PAR.");
        }
    }


    /// <summary>
    /// The <c>client_credentials</c> twin of <see cref="StepwiseAuthorizationDetailsLocationDoesNotAddAnIssuerResolutionAtParAsync"/>
    /// — the shape validation client_credentials shares with PAR reaches the same stepless
    /// overload.
    /// </summary>
    [TestMethod]
    public async Task StepwiseAuthorizationDetailsLocationDoesNotAddAnIssuerResolutionAtClientCredentialsAsync()
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthClientCredentials);
        const string ClientSecret = "s3cret-for-authorization-details-count";

        //Every request below carries the SAME shape-valid custom-type detail and reaches the SAME
        //final refusal ("does not issue authorization-details-bound access tokens") — the custom
        //handler accepts unconditionally, so ONLY whether ResolveRequiredAuthorizationDetailsLocationAsync
        //itself resolves an issuer can differ between the three metadata shapes. Comparing against a
        //"no authorization_details at all" baseline is unsound here (a SUCCESSFUL client_credentials
        //response mints a token, which resolves the issuer again for the JWT `iss` claim — a resolve
        //this refusal path never reaches, for a reason unrelated to S1); comparing the three SAME-shaped
        //refusals to each other isolates exactly the resolver count the fix protects.
        async Task<int> CountResolvesForAsync(Action<AuthorizationServerIntegration>? configureContributor)
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, capabilities).ConfigureAwait(false);

            int resolveIssuerCount = 0;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidateClientCredentialsAsync = static (_, fields, _, _, _) =>
                    ValueTask.FromResult(
                        fields.TryGetValue(OAuthRequestParameterNames.ClientSecret, out string? secret)
                        && string.Equals(secret, ClientSecret, StringComparison.Ordinal));
                _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
                candidateIntegration.AuthorizationDetailTypes.Register(new AuthorizationDetailHandler
                {
                    Type = CustomDetailsType,
                    ValidateShape = (_, _) => null
                });
                candidateIntegration.ResolveIssuerAsync = (reg, ctx, ct) =>
                {
                    resolveIssuerCount++;

                    return ValueTask.FromResult<Uri?>(((ClientRecord)reg).IssuerUri);
                };
                configureContributor?.Invoke(candidateIntegration);
            }).ConfigureAwait(false);

            RequestFields fields = new()
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.ClientCredentials,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.ClientSecret] = ClientSecret,
                [OAuthRequestParameterNames.AuthorizationDetails] = CustomDetail
            };
            ServerHttpResponse response = await host.DispatchAtEndpointAsync(
                material.Registration.TenantId.Value, WellKnownEndpointNames.ClientCredentialsToken, "POST",
                fields, [], TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(400, response.StatusCode, response.Body);
            Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, response.Body);

            return resolveIssuerCount;
        }

        int absentContributorCount = await CountResolvesForAsync(configureContributor: null).ConfigureAwait(false);
        int emptyContributorCount = await CountResolvesForAsync(candidateIntegration =>
            candidateIntegration.ContributeCredentialIssuerMetadataAsync =
                (reg, ctx, ct) => ValueTask.FromResult(CredentialIssuerMetadataContribution.Empty))
            .ConfigureAwait(false);
        int nonEmptyContributorCount = await CountResolvesForAsync(candidateIntegration =>
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (reg, ctx, ct) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution { AuthorizationServers = ["https://as.example.test/"] }))
            .ConfigureAwait(false);

        Assert.AreEqual(absentContributorCount, emptyContributorCount,
            "An absent contributor and a present-but-empty authorization_servers must resolve the issuer the same number of times.");
        Assert.AreEqual(absentContributorCount + 1, nonEmptyContributorCount,
            "A present, non-empty authorization_servers must resolve the issuer exactly ONE more time than an absent or empty one — RED on the unfixed tree, where the stepless overload resolved unconditionally and all three counts were equal.");
    }


    /// <summary>
    /// The Pre-Authorized Code twin of <see cref="StepwiseAuthorizationDetailsLocationDoesNotAddAnIssuerResolutionAtParAsync"/>
    /// — the grant reaches the stepless overload AFTER <c>ValidatePreAuthorizedCodeAsync</c>
    /// may have consumed the code and outside its own resolver-fault catch, so an added
    /// resolution there would fail a redemption after consumption.
    /// </summary>
    [TestMethod]
    public async Task StepwiseAuthorizationDetailsLocationDoesNotAddAnIssuerResolutionAtPreAuthorizedCodeAsync()
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);

        //Same rationale as the client_credentials twin: every request below carries the SAME
        //shape-valid custom-type detail and reaches the SAME final answer, so comparing the three
        //metadata shapes to each other (rather than against a "no authorization_details" baseline,
        //which mints a token and resolves the issuer AGAIN for its `iss` claim on a path this one
        //never reaches) isolates exactly the resolver count the fix protects.
        async Task<int> CountResolvesForAsync(Action<AuthorizationServerIntegration>? configureContributor)
        {
            await using TestHostShell host = new(TimeProvider);
            using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
                ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, capabilities).ConfigureAwait(false);
            //OID4VCI 1.0 §13.10: stay within the long-lived threshold for the plain-bearer token a
            //granted response would mint.
            await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

            int resolveIssuerCount = 0;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.ValidatePreAuthorizedCodeAsync =
                    (code, txCode, clientId, registration, context, ct) =>
                        ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(SubjectId, "credential-scope"));
                candidateIntegration.ResolveCredentialAuthorizationAsync =
                    (details, subject, reg, ctx, ct) => ValueTask.FromResult(CredentialAuthorizationDecision.Grant([]));
                _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
                candidateIntegration.AuthorizationDetailTypes.Register(new AuthorizationDetailHandler
                {
                    Type = CustomDetailsType,
                    ValidateShape = (_, _) => null
                });
                candidateIntegration.ResolveIssuerAsync = (reg, ctx, ct) =>
                {
                    resolveIssuerCount++;

                    return ValueTask.FromResult<Uri?>(((ClientRecord)reg).IssuerUri);
                };
                configureContributor?.Invoke(candidateIntegration);
            }).ConfigureAwait(false);

            RequestFields fields = new()
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = $"pre-authorized-code-{Guid.NewGuid():N}",
                [OAuthRequestParameterNames.AuthorizationDetails] = CustomDetail
            };
            _ = await host.DispatchAtEndpointAsync(
                material.Registration.TenantId.Value, WellKnownEndpointNames.Oid4VciPreAuthorizedToken, "POST",
                fields, [], TestContext.CancellationToken).ConfigureAwait(false);

            return resolveIssuerCount;
        }

        int absentContributorCount = await CountResolvesForAsync(configureContributor: null).ConfigureAwait(false);
        int emptyContributorCount = await CountResolvesForAsync(candidateIntegration =>
            candidateIntegration.ContributeCredentialIssuerMetadataAsync =
                (reg, ctx, ct) => ValueTask.FromResult(CredentialIssuerMetadataContribution.Empty))
            .ConfigureAwait(false);
        int nonEmptyContributorCount = await CountResolvesForAsync(candidateIntegration =>
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (reg, ctx, ct) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution { AuthorizationServers = ["https://as.example.test/"] }))
            .ConfigureAwait(false);

        Assert.AreEqual(absentContributorCount, emptyContributorCount,
            "An absent contributor and a present-but-empty authorization_servers must resolve the issuer the same number of times at the pre-authorized code grant.");
        Assert.AreEqual(absentContributorCount + 1, nonEmptyContributorCount,
            "A present, non-empty authorization_servers must resolve the issuer exactly ONE more time than an absent or empty one — RED on the unfixed tree, where the stepless overload resolved unconditionally and all three counts were equal.");
    }


    /// <summary>Pushes PAR, optionally carrying <paramref name="authorizationDetails"/>.</summary>
    private async Task<ServerHttpResponse> PushParAsync(
        TestHostShell host, VerifierKeyMaterial material, string? authorizationDetails)
    {
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
        if(authorizationDetails is not null)
        {
            parFields[OAuthRequestParameterNames.AuthorizationDetails] = authorizationDetails;
        }

        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A PERMITTED deployment shape — a custom
    /// authorization_details type registered, its parser wired, but NO credential-authorization
    /// resolver wired (RFC 9396 §6's policy-cannot-allow refusal) — answers the SAME
    /// <c>invalid_authorization_details</c> body for an unknown code and a live, still-unconsumed
    /// one, touching no grant-store operation on the refusal, at CODE REDEMPTION.
    /// </summary>
    [TestMethod]
    public async Task PermittedCustomAuthorizationDetailsTypeWithNoResolverIsRefusedAtCodeRedemptionAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.AuthorizationDetailTypes.Register(new AuthorizationDetailHandler
            {
                Type = CustomDetailsType,
                ValidateShape = (_, _) => null
            });
        }).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        (string code, string verifier) = await PushAuthorizeWithoutDetailsAsync(host, material).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        int beforeLive = hosted.StorageObservations.Count;
        ServerHttpResponse liveResponse = await DispatchTokenAsync(host, segment, code, verifier, CustomDetail).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeLive,
            "a permitted custom authorization_details type with no resolver, live code");

        int beforeUnknown = hosted.StorageObservations.Count;
        ServerHttpResponse unknownResponse = await DispatchTokenAsync(
            host, segment, "code-never-issued-by-this-host", verifier, CustomDetail).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeUnknown,
            "a permitted custom authorization_details type with no resolver, unknown code");

        Assert.AreEqual(400, liveResponse.StatusCode, liveResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, liveResponse.Body);
        Assert.AreEqual(unknownResponse.StatusCode, liveResponse.StatusCode);
        Assert.AreEqual(unknownResponse.Body, liveResponse.Body,
            "A live code's existence must not be discoverable from a permitted-but-unresolvable authorization_details refusal.");

        ServerHttpResponse successfulRedemption = await DispatchTokenAsync(
            host, segment, code, verifier, authorizationDetails: null).ConfigureAwait(false);
        Assert.AreEqual(200, successfulRedemption.StatusCode, successfulRedemption.Body);
    }


    /// <summary>
    /// The REFRESH twin of <see cref="PermittedCustomAuthorizationDetailsTypeWithNoResolverIsRefusedAtCodeRedemptionAsync"/>.
    /// </summary>
    [TestMethod]
    public async Task PermittedCustomAuthorizationDetailsTypeWithNoResolverIsRefusedAtRefreshAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.AuthorizationDetailTypes.Register(new AuthorizationDetailHandler
            {
                Type = CustomDetailsType,
                ValidateShape = (_, _) => null
            });
        }).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        (string code, string verifier) = await PushAuthorizeWithoutDetailsAsync(host, material).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await DispatchTokenAsync(
            host, material.Registration.TenantId.Value, code, verifier, authorizationDetails: null).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        string refreshToken = ExtractFromBody(tokenResponse.Body, "refresh_token");

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        int beforeLive = hosted.StorageObservations.Count;
        ServerHttpResponse liveResponse = await DispatchRefreshAsync(host, material, refreshToken, CustomDetail).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeLive,
            "a permitted custom authorization_details type with no resolver, live refresh token");

        int beforeUnknown = hosted.StorageObservations.Count;
        ServerHttpResponse unknownResponse = await DispatchRefreshAsync(
            host, material, "refresh-token-never-issued-by-this-host", CustomDetail).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeUnknown,
            "a permitted custom authorization_details type with no resolver, unknown refresh token");

        Assert.AreEqual(400, liveResponse.StatusCode, liveResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, liveResponse.Body);
        Assert.AreEqual(unknownResponse.StatusCode, liveResponse.StatusCode);
        Assert.AreEqual(unknownResponse.Body, liveResponse.Body,
            "A live refresh token's existence must not be discoverable from a permitted-but-unresolvable authorization_details refusal.");

        ServerHttpResponse successfulRefresh = await DispatchRefreshAsync(
            host, material, refreshToken, refreshRequestDetails: null).ConfigureAwait(false);
        Assert.AreEqual(200, successfulRefresh.StatusCode, successfulRefresh.Body);
    }


    /// <summary>
    /// The MALFORMED-value case: a token-request <c>authorization_details</c>
    /// value that fails to parse as JSON answers the SAME <c>invalid_authorization_details</c>
    /// body for an unknown code and a live, still-unconsumed one, touching no grant-store
    /// operation on the refusal, at CODE REDEMPTION.
    /// </summary>
    [TestMethod]
    public async Task MalformedAuthorizationDetailsValueIsRefusedAtCodeRedemptionAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            //Composition requires a resolver seam once the built-in openid_credential type is
            //wired with no further type registered; a malformed value never reaches it.
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, reg, ctx, ct) => ValueTask.FromResult(CredentialAuthorizationDecision.Grant([]));
        }).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        (string code, string verifier) = await PushAuthorizeWithoutDetailsAsync(host, material).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        int beforeLive = hosted.StorageObservations.Count;
        ServerHttpResponse liveResponse = await DispatchTokenAsync(host, segment, code, verifier, MalformedDetail).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeLive, "a malformed authorization_details value, live code");

        int beforeUnknown = hosted.StorageObservations.Count;
        ServerHttpResponse unknownResponse = await DispatchTokenAsync(
            host, segment, "code-never-issued-by-this-host", verifier, MalformedDetail).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeUnknown, "a malformed authorization_details value, unknown code");

        Assert.AreEqual(400, liveResponse.StatusCode, liveResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, liveResponse.Body);
        Assert.AreEqual(unknownResponse.StatusCode, liveResponse.StatusCode);
        Assert.AreEqual(unknownResponse.Body, liveResponse.Body,
            "A live code's existence must not be discoverable from a malformed authorization_details refusal.");

        ServerHttpResponse successfulRedemption = await DispatchTokenAsync(
            host, segment, code, verifier, authorizationDetails: null).ConfigureAwait(false);
        Assert.AreEqual(200, successfulRedemption.StatusCode, successfulRedemption.Body);
    }


    /// <summary>
    /// The REFRESH twin of <see cref="MalformedAuthorizationDetailsValueIsRefusedAtCodeRedemptionAsync"/>.
    /// </summary>
    [TestMethod]
    public async Task MalformedAuthorizationDetailsValueIsRefusedAtRefreshAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            //Composition requires a resolver seam once the built-in openid_credential type is
            //wired with no further type registered; a malformed value never reaches it.
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, reg, ctx, ct) => ValueTask.FromResult(CredentialAuthorizationDecision.Grant([]));
        }).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        (string code, string verifier) = await PushAuthorizeWithoutDetailsAsync(host, material).ConfigureAwait(false);
        ServerHttpResponse tokenResponse = await DispatchTokenAsync(
            host, material.Registration.TenantId.Value, code, verifier, authorizationDetails: null).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        string refreshToken = ExtractFromBody(tokenResponse.Body, "refresh_token");

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);

        int beforeLive = hosted.StorageObservations.Count;
        ServerHttpResponse liveResponse = await DispatchRefreshAsync(host, material, refreshToken, MalformedDetail).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeLive, "a malformed authorization_details value, live refresh token");

        int beforeUnknown = hosted.StorageObservations.Count;
        ServerHttpResponse unknownResponse = await DispatchRefreshAsync(
            host, material, "refresh-token-never-issued-by-this-host", MalformedDetail).ConfigureAwait(false);
        hosted.AssertNoFlowStateStoreOperationTouched(beforeUnknown, "a malformed authorization_details value, unknown refresh token");

        Assert.AreEqual(400, liveResponse.StatusCode, liveResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, liveResponse.Body);
        Assert.AreEqual(unknownResponse.StatusCode, liveResponse.StatusCode);
        Assert.AreEqual(unknownResponse.Body, liveResponse.Body,
            "A live refresh token's existence must not be discoverable from a malformed authorization_details refusal.");

        ServerHttpResponse successfulRefresh = await DispatchRefreshAsync(
            host, material, refreshToken, refreshRequestDetails: null).ConfigureAwait(false);
        Assert.AreEqual(200, successfulRefresh.StatusCode, successfulRefresh.Body);
    }


    /// <summary>Drives PAR + authorize with NO authorization_details and returns (code, PKCE verifier).</summary>
    private async Task<(string Code, string Verifier)> PushAuthorizeWithoutDetailsAsync(
        TestHostShell host, VerifierKeyMaterial material)
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
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);

        return (ExtractCode(authorizeResponse.Location!), pkce.EncodedVerifier);
    }


    /// <summary>Redeems <paramref name="code"/>, optionally carrying <paramref name="authorizationDetails"/>.</summary>
    private async Task<ServerHttpResponse> DispatchTokenAsync(
        TestHostShell host, string segment, string code, string verifier, string? authorizationDetails)
    {
        RequestFields tokenFields = new()
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = verifier,
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
        };
        if(authorizationDetails is not null)
        {
            tokenFields[OAuthRequestParameterNames.AuthorizationDetails] = authorizationDetails;
        }

        return await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeToken, "POST",
            tokenFields, [],
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
