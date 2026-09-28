using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// RFC 9449 §7.1 sender constraint at the OID4VCI Credential Endpoint, end to end over real
/// HTTP: a DPoP-bound Access Token (minted by the auth-code + DPoP token flow, carrying
/// <c>cnf.jkt</c>) must be presented under the <c>DPoP</c> scheme with a DPoP proof bound to the
/// same key. The credential endpoint verifies the proof-of-possession the token endpoint
/// established rather than accepting the token as a plain bearer.
/// </summary>
[TestClass]
internal sealed class Oid4VciDpopCredentialEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private static DateTimeOffset NowInstant { get; } = TestClock.CanonicalEpoch;
    private FakeTimeProvider TimeProvider { get; } = new(NowInstant);

    private const string ClientId = "https://wallet.client.test";
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");
    //RegisterDpopClient registers exactly this callback as the client's redirect URI.
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");
    private const string TestSubject = "subject-1";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string IssuedCredential = "eyJhbGciOiJFUzI1NiJ9.body.sig";

    private static ImmutableHashSet<CapabilityIdentifier> Capabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 §7.1</see>: "For such an
    /// access token, a resource server MUST check that a DPoP proof was also received in the DPoP header
    /// field of the HTTP request, check the DPoP proof according to the rules in Section 4.3, and check
    /// that the public key of the DPoP proof matches the public key to which the access token is bound
    /// per Section 6." A DPoP-bound access token presented at the Credential Endpoint over the wire
    /// under the <c>DPoP</c> scheme with a proof signed by the bound key and carrying the nonce the
    /// endpoint provided is served: 200.
    /// </summary>
    [TestMethod]
    public async Task DpopBoundTokenWithValidProofIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        string nonce = await ObtainResourceNonceAsync(ctx).ConfigureAwait(false);
        string proof = await BuildCredentialProofAsync(ctx, freshKey: null, nonce).ConfigureAwait(false);
        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, proof).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 §9</see>: "Resource servers
    /// use an HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and
    /// DPoP-Nonce value to accomplish this." A DPoP-bound access token presented at the Credential
    /// Endpoint over the wire under the <c>DPoP</c> scheme with no proof is answered 401, one challenge
    /// <c>DPoP error="use_dpop_nonce", algs="…"</c>, <c>use_dpop_nonce</c> in the body and a
    /// <c>DPoP-Nonce</c>.
    /// </summary>
    [TestMethod]
    public async Task DpopBoundTokenWithoutProofChallengesForNonce()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        //DPoP scheme, but no DPoP proof header.
        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, dpopProof: null)
            .ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 9449 §9: the nonce challenge carries a WWW-Authenticate: DPoP value.");
        Assert.AreEqual(DpopChallenge("use_dpop_nonce"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("use_dpop_nonce", document.RootElement.GetProperty("error").GetString());
        Assert.IsFalse(string.IsNullOrEmpty(ResourceDpopProofs.ReadNonce(response)),
            "A nonce challenge must carry a fresh DPoP-Nonce header.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "such a
    /// protected resource MUST reject a DPoP-bound access token received as a bearer token per
    /// [RFC6750]." and <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>:
    /// "If the protected resource request does not include authentication credentials or does not
    /// contain an access token that enables access to the protected resource, the resource server MUST
    /// include the HTTP "WWW-Authenticate" response header field". A DPoP-bound access token presented
    /// at the Credential Endpoint over the wire under the <c>Bearer</c> scheme is refused with 401
    /// <c>invalid_token</c> and the single challenge <c>Bearer error="invalid_token"</c>.
    /// </summary>
    [TestMethod]
    public async Task DpopBoundTokenUnderBearerSchemeIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        string proof = await BuildCredentialProofAsync(ctx, freshKey: null, nonce: null).ConfigureAwait(false);
        //Present the sender-constrained token under the Bearer scheme — a downgrade.
        using HttpResponseMessage response = await PostCredentialAsync(
            ctx, ctx.AccessToken, proof, scheme: WellKnownAuthenticationSchemes.Bearer).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual("Bearer error=\"invalid_token\"", challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 §4.3</see> item 12:
    /// "confirm that the public key to which the access token is bound matches the public key from the
    /// DPoP proof". A DPoP-bound access token presented at the Credential Endpoint over the wire with a
    /// structurally valid proof signed by a key other than the bound one is refused with 401 and the
    /// <c>DPoP error="invalid_token"</c> challenge of §7.1's Figure 16 ("Invalid DPoP key binding").
    /// </summary>
    [TestMethod]
    public async Task DpopProofWithWrongKeyIsRejected()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        //A structurally valid proof signed by a DIFFERENT key than the token was bound to.
        var otherKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey otherKey = new(otherKeys, WellKnownJwaValues.Es256);
        string nonce = await ObtainResourceNonceAsync(ctx).ConfigureAwait(false);
        string proof = await BuildCredentialProofAsync(ctx, freshKey: otherKey, nonce).ConfigureAwait(false);

        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, proof).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges));
        Assert.AreEqual(DpopChallenge("invalid_token"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information (e.g., the client was unaware that authentication
    /// is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." A Credential Request sent over the
    /// wire with no <c>Authorization</c> header is refused with 401 and exactly one challenge that
    /// names both schemes the endpoint accepts and no error: a <c>Bearer</c> challenge whose
    /// <c>realm</c> is the issuer's absolute URI, then <c>DPoP algs="…"</c>.
    /// </summary>
    [TestMethod]
    public async Task CredentialEndpointChallengesARequestWithoutCredentialsForBothSchemesAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        using StringContent content = new(
            "{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage request = new(HttpMethod.Post, ctx.CredentialUrl) { Content = content };
        using HttpResponseMessage response = await ctx.Http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //The header is read as sent: the client's typed view splits one field value into its challenges.
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.NonValidated.TryGetValues("WWW-Authenticate", out HeaderStringValues challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        string challenge = Assert.ContainsSingle(challenges);
        const string RealmPrefix = "Bearer realm=\"";
        string dpopPart = $"\", DPoP algs=\"{AcceptedProofAlgorithms}\"";
        Assert.StartsWith(RealmPrefix, challenge, challenge);
        Assert.EndsWith(dpopPart, challenge, challenge);
        string realm = challenge[RealmPrefix.Length..^dpopPart.Length];
        Assert.IsTrue(Uri.TryCreate(realm, UriKind.Absolute, out _), $"The realm names the issuer: {realm}");
        Assert.DoesNotContain("error=", challenge, "No error information is sent to a request without credentials.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "If the
    /// mechanism used to attempt authentication could be established unambiguously, then the
    /// corresponding challenge SHOULD be used to deliver error information". A DPoP-bound access token
    /// whose signature does not verify, presented at the Credential Endpoint over the wire under the
    /// <c>DPoP</c> scheme, is refused with 401 <c>invalid_token</c> and the single challenge
    /// <c>DPoP error="invalid_token", algs="…"</c>, never a <c>Bearer</c> one.
    /// </summary>
    [TestMethod]
    public async Task CredentialEndpointAnswersARefusedDpopPresentationWithADpopChallengeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        int signatureStart = ctx.AccessToken.LastIndexOf('.', StringComparison.Ordinal) + 1;
        int tamperIndex = signatureStart + ((ctx.AccessToken.Length - signatureStart) / 2);
        char flipped = ctx.AccessToken[tamperIndex] == 'A' ? 'B' : 'A';
        string tampered = string.Concat(
            ctx.AccessToken.AsSpan(0, tamperIndex), flipped.ToString(), ctx.AccessToken.AsSpan(tamperIndex + 1));

        using HttpResponseMessage response = await PostCredentialAsync(ctx, tampered, dpopProof: null).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(DpopChallenge("invalid_token"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>The <c>algs</c> value of every <c>DPoP</c> challenge the Credential Endpoint answers with.</summary>
    private const string AcceptedProofAlgorithms = "ES256 ES384 ES512 RS256 RS384 RS512 PS256 PS384 PS512 EdDSA";


    /// <summary>The <c>DPoP</c> challenge carrying <paramref name="error"/>.</summary>
    /// <param name="error">The challenge's <c>error</c>.</param>
    /// <returns>The literal <c>WWW-Authenticate</c> value.</returns>
    private static string DpopChallenge(string error) => $"DPoP error=\"{error}\", algs=\"{AcceptedProofAlgorithms}\"";


    /// <summary>
    /// Presents the bound token at the Credential Endpoint over the wire with no proof and returns the
    /// nonce its RFC 9449 §9 challenge provides.
    /// </summary>
    /// <param name="ctx">The bound-token context.</param>
    /// <returns>The nonce the endpoint provided.</returns>
    private async Task<string> ObtainResourceNonceAsync(BoundTokenContext ctx)
    {
        using HttpResponseMessage challenge = await PostCredentialAsync(ctx, ctx.AccessToken, dpopProof: null)
            .ConfigureAwait(false);

        return ResourceDpopProofs.ReadNonce(challenge);
    }


    /// <summary>
    /// A proof-bound access token cannot authorize credential issuance when proof validation is unavailable.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7">RFC 9449 §7</see>.
    /// </summary>
    [TestMethod]
    public async Task DpopBoundTokenWithUnwiredValidationSeamFailsClosed()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        //Unwire the proof-validation seam AFTER the bound token was minted: a bound token must
        //never silently fall back to bearer, so the credential endpoint fails loud.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateDpopProofAsync = null;
        }).ConfigureAwait(false);

        string proof = await BuildCredentialProofAsync(ctx, freshKey: null, nonce: null).ConfigureAwait(false);
        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, proof).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.InternalServerError, response.StatusCode, body);
        Assert.Contains(OAuthErrors.ServerError, body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see>: "If the
    /// protected resource request does not include authentication credentials or does not contain an
    /// access token that enables access to the protected resource, the resource server MUST include the
    /// HTTP "WWW-Authenticate" response header field", and "If the protected resource request included
    /// an access token and failed authentication, the resource server SHOULD include the "error"
    /// attribute". An access token presented at the Credential Endpoint under the <c>Bearer</c> scheme
    /// whose signature does not verify is refused over the wire with 401 and a <c>Bearer</c> challenge
    /// carrying <c>error="invalid_token"</c>.
    /// </summary>
    [TestMethod]
    public async Task CredentialEndpointRefusalOfAnAccessTokenCarriesABearerChallengeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        //Flip a middle character of the signature segment: it stays base64url-valid, so the token
        //parses and its signature deterministically fails to verify.
        int signatureStart = ctx.AccessToken.LastIndexOf('.', StringComparison.Ordinal) + 1;
        int tamperIndex = signatureStart + ((ctx.AccessToken.Length - signatureStart) / 2);
        char flipped = ctx.AccessToken[tamperIndex] == 'A' ? 'B' : 'A';
        string tampered = string.Concat(
            ctx.AccessToken.AsSpan(0, tamperIndex), flipped.ToString(), ctx.AccessToken.AsSpan(tamperIndex + 1));

        using HttpResponseMessage response = await PostCredentialAsync(
            ctx, tampered, dpopProof: null, scheme: WellKnownAuthenticationSchemes.Bearer).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual("Bearer error=\"invalid_token\"", challenges.Single());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>:
    /// "invalid_token The access token provided is expired, revoked, malformed, or invalid for other
    /// reasons. The resource SHOULD respond with the HTTP 401 (Unauthorized) status code." An access
    /// token whose protected header's <c>kid</c> is a single space names no key and is malformed: it is
    /// refused at the Credential Endpoint over the wire with 401 <c>invalid_token</c> and the challenge
    /// <c>Bearer error="invalid_token"</c>, never a server error.
    /// </summary>
    [TestMethod]
    public async Task CredentialEndpointRefusesAnAccessTokenWhoseKidIsWhitespaceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        string whitespaceKidToken = await CompactJwsResigning.ResignWithHeaderAsync(
            host, ctx.AccessToken, ctx.SigningKeyId, " ", "at+jwt").ConfigureAwait(false);

        using HttpResponseMessage response = await PostCredentialAsync(
            ctx, whitespaceKidToken, dpopProof: null, scheme: WellKnownAuthenticationSchemes.Bearer).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 §3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual("Bearer error=\"invalid_token\"", challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("Access token header is missing kid.", document.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// Carries the live host, fixture, minted bound token and the key the registration signs access
    /// tokens under through a credential-request variation.
    /// </summary>
    private sealed record BoundTokenContext(
        TestHostShell Host, DpopClientFixture Fixture, string AccessToken, Uri CredentialUrl, HttpClient Http, KeyId SigningKeyId);


    /// <summary>
    /// Registers a DPoP issuer, drives the full PAR → Authorize → callback → token DPoP flow to
    /// mint a <c>cnf.jkt</c>-bound Access Token, and wires the credential issuance seam.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The host's key stores own and dispose the registration's key material; the returned " +
        "VerifierKeyMaterial is a handle to those same instances, released when the host is disposed.")]
    private async Task<BoundTokenContext> AcquireAsync(TestHostShell host)
    {
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, Capabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
        }).ConfigureAwait(false);

        DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string segment = material.Registration.TenantId.Value;

        //Step 1 — PAR.
        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFields.Empty, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect. {parResult.ErrorCode} {parResult.ErrorDescription}");

        string flowId = fixture.ClientFlowStore.Keys.Single();
        ParCompletedState parCompleted = (ParCompletedState)fixture.ClientFlowStore[flowId];

        //Step 2 — Authorize (user-agent GET replicated in-process with a pre-authenticated subject).
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(TestSubject);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            new RequestFields
            {
                [OAuthRequestParameterNames.ClientId] = ClientId,
                [OAuthRequestParameterNames.RequestUri] = parCompleted.Par.RequestUri.ToString()
            },
            authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);

        (string code, string? iss) = ParseAuthorizeRedirect(authorizeResponse.Location!);
        Assert.IsNotNull(iss);

        //Step 3 — callback.
        AuthCodeFlowEndpointResult callbackResult = await fixture.Client.AuthCode.HandleCallbackAsync(
            fixture.Registration,
            new OAuthFormEncodedFields(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.State] = flowId,
                [OAuthRequestParameterNames.Iss] = iss!
            }),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed. {callbackResult.ErrorCode} {callbackResult.ErrorDescription}");

        //Step 4 — token (DPoP nonce challenge + retry handled by the client).
        AuthCodeFlowEndpointResult tokenResult = await fixture.Client.AuthCode.ExchangeTokenAsync(
            fixture.Registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token must issue. {tokenResult.ErrorCode} {tokenResult.ErrorDescription}");
        Assert.IsTrue(tokenResult.Body!.TryGetValue(OAuthRequestParameterNames.AccessToken, out object? tokenObj));
        string accessToken = (string)tokenObj!;

        Uri credentialUrl = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VciCredential, segment));

        return new BoundTokenContext(
            host, fixture, accessToken, credentialUrl, host.Host("default").SharedHttpClient!, material.SigningKeyId);
    }


    /// <summary>
    /// Builds a fresh DPoP proof for the credential POST: htm=POST, htu=the credential URL,
    /// ath bound to the access token, the resource <paramref name="nonce"/> when given, signed by the
    /// token's key (or <paramref name="freshKey"/> to forge a thumbprint mismatch).
    /// </summary>
    /// <param name="ctx">The bound-token context.</param>
    /// <param name="freshKey">A key other than the bound one, or <see langword="null"/> for the bound key.</param>
    /// <param name="nonce">The resource nonce, or <see langword="null"/> to carry none.</param>
    /// <returns>The DPoP proof JWT.</returns>
    private Task<string> BuildCredentialProofAsync(BoundTokenContext ctx, DpopKey? freshKey, string? nonce) =>
        ResourceDpopProofs.BuildAsync(
            freshKey ?? ctx.Fixture.DpopKey, WellKnownHttpMethods.Post, ctx.CredentialUrl.ToString(), ctx.AccessToken,
            nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken);


    private async Task<HttpResponseMessage> PostCredentialAsync(
        BoundTokenContext ctx, string accessToken, string? dpopProof,
        string scheme = "DPoP")
    {
        using StringContent content = new(
            "{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage request = new(HttpMethod.Post, ctx.CredentialUrl) { Content = content };
        _ = request.Headers.TryAddWithoutValidation(
            WellKnownHttpHeaderNames.Authorization, $"{scheme} {accessToken}");
        if(dpopProof is not null)
        {
            _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.DPoP, dpopProof);
        }

        return await ctx.Http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static (string Code, string? Iss) ParseAuthorizeRedirect(string location)
    {
        Uri uri = new(location);
        string query = uri.Query.TrimStart('?');
        string? code = null;
        string? iss = null;
        foreach(string pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq <= 0)
            {
                continue;
            }

            string key = pair[..eq];
            string value = Uri.UnescapeDataString(pair[(eq + 1)..]);
            if(string.Equals(key, OAuthRequestParameterNames.Code, StringComparison.Ordinal)) { code = value; }
            else if(string.Equals(key, OAuthRequestParameterNames.Iss, StringComparison.Ordinal)) { iss = value; }
        }

        return (code ?? throw new AssertFailedException($"No code in redirect: {location}"), iss);
    }
}
