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

    /// <summary>The two Credential Configurations the tests request.</summary>
    private const string DegreeConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string LicenseConfigurationId = "org.iso.18013.5.1.mDL";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>The capabilities the Authorization Code flow tests need.</summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> AuthCodeCapabilities =
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." This plain-bearer credential flow stays within the
        //§13.10 long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        IReadOnlyList<CredentialAuthorizationDetail>? seenDetails = null;
        string? seenSubject = null;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        bool seamCalled = false;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) =>
            {
                seamCalled = true;

                return ValueTask.FromResult(GrantAllRequested(details));
            };

        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        ExchangeContext authorizeContext = new();
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
                [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeAuthorizationCode,
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
            },
            new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        //§13.10: keep the plain-bearer credential token within the long-lived threshold.
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        IReadOnlyList<CredentialAuthorizationDetail>? seenDetails = null;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) =>
            {
                seenDetails = details;

                return ValueTask.FromResult(GrantAllRequested(details));
            };

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: SingleDetail(DegreeConfigurationId),
            frontChannelDetails: SingleDetail(LicenseConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.IsNotNull(seenDetails);
        Assert.HasCount(1, seenDetails!);
        Assert.AreEqual(DegreeConfigurationId, seenDetails![0].CredentialConfigurationId,
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        //§13.10: keep the plain-bearer credential token within the long-lived threshold.
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        IReadOnlyList<CredentialAuthorizationDetail>? seenDetails = null;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) =>
            {
                seenDetails = details;

                return ValueTask.FromResult(GrantAllRequested(details));
            };

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: TwoDetails(DegreeConfigurationId, LicenseConfigurationId),
            tokenRequestDetails: SingleDetail(LicenseConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.IsNotNull(seenDetails);
        Assert.HasCount(1, seenDetails!);
        Assert.AreEqual(LicenseConfigurationId, seenDetails![0].CredentialConfigurationId);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        bool seamCalled = false;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) =>
            {
                seamCalled = true;

                return ValueTask.FromResult(GrantAllRequested(details));
            };

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material,
            parDetails: SingleDetail(DegreeConfigurationId),
            tokenRequestDetails: SingleDetail(LicenseConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, tokenResponse.Body);
        Assert.IsFalse(seamCalled, "The seam must not be consulted when the narrowing rule is violated.");
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        ServerHttpResponse tokenResponse = await RunAuthCodeFlowAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);

        Assert.AreEqual(400, tokenResponse.StatusCode, tokenResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, tokenResponse.Body);
    }


    /// <summary>
    /// Each seam refusal maps to <c>invalid_authorization_details</c> (RFC 9396 §5), with the
    /// reason-specific default description distinguishing the cases.
    /// </summary>
    [TestMethod]
    public async Task SeamDenialsMapToInvalidAuthorizationDetails()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) => ValueTask.FromResult(
                CredentialAuthorizationDecision.Deny(
                    CredentialAuthorizationDenialReason.UnknownCredentialConfiguration));

        ServerHttpResponse unknownResponse = await RunAuthCodeFlowAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(400, unknownResponse.StatusCode, unknownResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, unknownResponse.Body);

        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) => ValueTask.FromResult(
                CredentialAuthorizationDecision.Deny(
                    CredentialAuthorizationDenialReason.AuthorizationDenied));

        ServerHttpResponse deniedResponse = await RunAuthCodeFlowAsync(
            host, material, parDetails: SingleDetail(DegreeConfigurationId)).ConfigureAwait(false);
        Assert.AreEqual(400, deniedResponse.StatusCode, deniedResponse.Body);
        Assert.Contains(OAuthErrors.InvalidAuthorizationDetails, deniedResponse.Body);
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant));
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        //§13.10: the Pre-Authorized Code grant mints a plain-bearer credential token; keep it
        //within the long-lived threshold so it is not refused as an unconstrained long-lived token.
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(SubjectId));

        IReadOnlyList<CredentialAuthorizationDetail>? seenDetails = null;
        string? seenSubject = null;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) =>
            {
                seenDetails = details;
                seenSubject = subject;

                return ValueTask.FromResult(GrantAllRequested(details));
            };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypePreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA",
                [OAuthRequestParameterNames.AuthorizationDetails] = SingleDetail(DegreeConfigurationId)
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode, response.Body);
        Assert.AreEqual(SubjectId, seenSubject, "The seam must receive the grant-resolved subject.");
        Assert.IsNotNull(seenDetails);
        Assert.AreEqual(DegreeConfigurationId, seenDetails![0].CredentialConfigurationId);

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
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        ServerHttpResponse unwired = await DispatchDiscoveryAsync(host, material).ConfigureAwait(false);
        Assert.AreEqual(200, unwired.StatusCode, unwired.Body);
        Assert.DoesNotContain("authorization_details_types_supported", unwired.Body,
            "An unwired decision seam must not advertise authorization details support.");

        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));

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
        using VerifierKeyMaterial material = host.RegisterClient(
            ClientId, ClientBaseUri,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                WellKnownCapabilityIdentifiers.OAuthJwksEndpoint));
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));

        host.Server.OAuth().AuthorizationDetailTypes.Register(new AuthorizationDetailHandler
        {
            Type = "payment_initiation",
            ValidateShape = (detail, validation) => null
        });

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        int resolveCount = 0;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));

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
    }


    /// <summary>
    /// RFC 9396 §6.1 across rotation (RFC 9700 §2.2.2): the granted authorization_details survive
    /// a refresh-token rotation, so a second refresh using the rotated token still re-emits them.
    /// </summary>
    [TestMethod]
    public async Task GrantedAuthorizationDetailsSurviveRefreshTokenRotation()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) => ValueTask.FromResult(GrantAllRequested(details));

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        bool seamCalled = false;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) =>
            {
                seamCalled = true;

                return ValueTask.FromResult(GrantAllRequested(details));
            };

        string segment = material.Registration.TenantId.Value;
        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        ExchangeContext authorizeContext = new();
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
                [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeAuthorizationCode,
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
            },
            new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        host.Server.OAuth().AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        host.Server.OAuth().AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        //The server supports payment_initiation, but the client registered only openid_credential.
        host.Server.OAuth().AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());
        host.SetAllowedAuthorizationDetailsTypes(
            material, ImmutableHashSet.Create(AuthorizationDetailsTypeValues.OpenIdCredential));

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
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce,
            ImmutableHashSet.Create(
                WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant));
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));

        host.Server.OAuth().AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());
        host.SetAllowedAuthorizationDetailsTypes(
            material, ImmutableHashSet.Create(AuthorizationDetailsTypeValues.OpenIdCredential));

        host.Server.OAuth().ValidatePreAuthorizedCodeAsync =
            (code, txCode, clientId, registration, context, ct) =>
                ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(SubjectId));

        bool seamCalled = false;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) =>
            {
                seamCalled = true;

                return ValueTask.FromResult(GrantAllRequested(details));
            };

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypePreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA",
                [OAuthRequestParameterNames.AuthorizationDetails] =
                    """[{"type":"payment_initiation","instructedAmount":{"amount":"1.00"},"currency":"EUR"}]"""
            },
            new ExchangeContext(),
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
        using VerifierKeyMaterial material = host.RegisterDpopClient(ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, AuthCodeCapabilities);
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();
        host.Server.OAuth().AuthorizationDetailTypes.Register(StrictPaymentInitiationHandler());

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
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
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
        if(frontChannelDetails is not null)
        {
            authorizeFields[OAuthRequestParameterNames.AuthorizationDetails] = frontChannelDetails;
        }

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
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeAuthorizationCode,
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
            tokenFields, new ExchangeContext(),
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
            [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeRefreshToken,
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
            refreshFields, new ExchangeContext(),
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
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.AuthorizationDetails] = authorizationDetails
        };

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
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
            [OAuthRequestParameterNames.ClientId] = ClientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId,
            [OAuthRequestParameterNames.AuthorizationDetails] = authorizationDetails
        };

        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(),
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
            new ExchangeContext(),
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
