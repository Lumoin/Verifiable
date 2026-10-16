using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Metadata;
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
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint);


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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-11.1">RFC 9449, Section 11.1</see>: "In order to
    /// guard against memory exhaustion attacks, a server that is tracking jti values should reject DPoP proof JWTs
    /// with unnecessarily large jti values or store only a hash thereof." Beside that length rule, this library
    /// refuses a <c>jti</c> holding a character of the Unicode general category Cc before the replay store is read
    /// or written, since the application's store may not hold such a character; the character rule is this
    /// library's policy, not a rule of the text. A DPoP-bound access token presented at the Credential Endpoint
    /// over the wire with a proof signed with the key pair the token is bound to, carrying the endpoint's nonce and
    /// a <c>jti</c> holding U+0000, is refused with 401, the single challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", algs="..."</c>, <c>invalid_dpop_proof</c> and the description that names
    /// both causes, and the store observation records no flow-state store call. A proof with an ordinary
    /// <c>jti</c> is then served with 200, and the observation sees the replay guard read, save, read back and claim
    /// its record.
    /// </summary>
    [TestMethod]
    public async Task ADpopProofWhoseJtiCarriesAControlCharacterIsRefusedBeforeAnyStoreCallAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;
        HostedAuthorizationServer hosted = host.Host("default");
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            hosted.InstallObservedStorage(candidateIntegration, hosted);
        }).ConfigureAwait(false);
        string nonce = await ObtainResourceNonceAsync(ctx).ConfigureAwait(false);

        string refusedProof = await BuildCredentialProofAsync(
            ctx, freshKey: null, nonce, jti: string.Concat("jti-", ((char)0x0000).ToString(), "-value")).ConfigureAwait(false);
        int beforeRefusal = hosted.StorageObservations.Count;
        using HttpResponseMessage refused = await PostCredentialAsync(ctx, ctx.AccessToken, refusedProof).ConfigureAwait(false);
        List<string> refusalOperations = [.. hosted.StorageObservations.Skip(beforeRefusal).Select(static entry => entry.Operation)];
        string refusedBody = await refused.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(hosted.ConsumeHttpFaults(), "The proof is refused without a server fault.");
        Assert.AreEqual(HttpStatusCode.Unauthorized, refused.StatusCode, refusedBody);
        Assert.IsTrue(refused.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "The refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(CredentialDpopChallenge(ctx, "invalid_dpop_proof"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(refusedBody);
        Assert.AreEqual("invalid_dpop_proof", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual(
            "DPoP proof jti is empty, too long or carries a character the replay guard cannot store.",
            document.RootElement.GetProperty("error_description").GetString());
        Assert.IsEmpty(refusalOperations,
            $"The refused jti must never reach the store; it observed: {string.Join(", ", refusalOperations)}.");

        string acceptedProof = await BuildCredentialProofAsync(ctx, freshKey: null, nonce).ConfigureAwait(false);
        int beforeAcceptance = hosted.StorageObservations.Count;
        using HttpResponseMessage accepted = await PostCredentialAsync(ctx, ctx.AccessToken, acceptedProof).ConfigureAwait(false);
        List<string> acceptanceOperations = [.. hosted.StorageObservations.Skip(beforeAcceptance).Select(static entry => entry.Operation)];
        string acceptedBody = await accepted.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(hosted.ConsumeHttpFaults(), "The proof is accepted without a server fault.");
        Assert.AreEqual(HttpStatusCode.OK, accepted.StatusCode, acceptedBody);
        Assert.IsTrue(HostedAuthorizationServer.IsReplayGuardFirstUseObserved(acceptanceOperations),
            $"The store observation must see the replay guard's read, save, read-back and claim; it observed: {string.Join(", ", acceptanceOperations)}.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 §9</see>: "Resource servers
    /// use an HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and
    /// DPoP-Nonce value to accomplish this." A DPoP-bound access token presented at the Credential
    /// Endpoint over the wire under the <c>DPoP</c> scheme with no proof is answered 401, one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", algs="..."</c>, <c>use_dpop_nonce</c> in the body and a
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
        Assert.AreEqual(CredentialDpopChallenge(ctx, "use_dpop_nonce"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("use_dpop_nonce", document.RootElement.GetProperty("error").GetString());
        Assert.IsFalse(string.IsNullOrEmpty(ResourceDpopProofs.ReadNonce(response)),
            "A nonce challenge must carry a fresh DPoP-Nonce header.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "Note that the nonces
    /// provided by an authorization server and a resource server are different and should not be confused with one
    /// another since nonces will be only accepted by the server that issued them. Likewise, should a client use multiple
    /// authorization servers and/or resource servers, a nonce issued by any of them should be used only at the issuing
    /// server." The token endpoint's challenge to a token request whose proof carries no <c>nonce</c> supplies a nonce;
    /// a proof by the bound DPoP key carrying that nonce is presented with the DPoP-bound access token at the Credential
    /// Endpoint over the wire and is refused: 401, the one challenge <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", algs="..."</c>,
    /// <c>use_dpop_nonce</c> in the body with the description that names the nonce's audience as another endpoint's,
    /// and a <c>DPoP-Nonce</c> field supplying a nonce other than the one presented.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CredentialEndpointRefusesTheTokenEndpointNonceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;
        string tokenEndpointNonce = await RawAuthCodeWirePushers.ObtainTokenEndpointDpopNonceAsync(
            host, ctx.Segment, ClientId, fixture.DpopKey, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        string proof = await BuildCredentialProofAsync(ctx, freshKey: null, tokenEndpointNonce).ConfigureAwait(false);
        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, proof).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "The refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(CredentialDpopChallenge(ctx, "use_dpop_nonce"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("use_dpop_nonce", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("DPoP nonce invalid: AudienceMismatch.", document.RootElement.GetProperty("error_description").GetString());
        string resourceNonce = ResourceDpopProofs.ReadNonce(response);
        Assert.IsFalse(string.IsNullOrEmpty(resourceNonce), "The refusal supplies a nonce.");
        Assert.AreNotEqual(tokenEndpointNonce, resourceNonce, "The Credential Endpoint supplies a nonce of its own.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "Note that the nonces
    /// provided by an authorization server and a resource server are different and should not be confused with one
    /// another since nonces will be only accepted by the server that issued them. Likewise, should a client use multiple
    /// authorization servers and/or resource servers, a nonce issued by any of them should be used only at the issuing
    /// server." The Credential Endpoint's challenge to a request that carries no proof supplies a nonce; a proof by the
    /// bound DPoP key carrying that nonce, its <c>htm</c>, <c>htu</c> and <c>ath</c> those of a Notification Request,
    /// is presented with the same DPoP-bound access token at the Notification Endpoint over the wire and is refused:
    /// 401, the one challenge <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", algs="..."</c>, <c>use_dpop_nonce</c> in the body with
    /// the description that names the nonce's audience as another endpoint's, and a <c>DPoP-Nonce</c> field supplying
    /// a nonce other than the one presented.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task NotificationEndpointRefusesTheCredentialEndpointNonceAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;
        string credentialEndpointNonce = await ObtainResourceNonceAsync(ctx).ConfigureAwait(false);

        Uri notificationUrl = new(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VciNotification, ctx.Segment));
        string proof = await ResourceDpopProofs.BuildAsync(
            ctx.Fixture.DpopKey, WellKnownHttpMethods.Post, notificationUrl.ToString(), ctx.AccessToken,
            credentialEndpointNonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);
        using StringContent content = new(
            "{\"notification_id\":\"3fwe98js\",\"event\":\"credential_accepted\"}", Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage request = new(HttpMethod.Post, notificationUrl) { Content = content };
        _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, "DPoP " + ctx.AccessToken);
        _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.DPoP, proof);
        using HttpResponseMessage response = await ctx.Http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "The refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(CredentialDpopChallenge(ctx, "use_dpop_nonce"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("use_dpop_nonce", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("DPoP nonce invalid: AudienceMismatch.", document.RootElement.GetProperty("error_description").GetString());
        string notificationNonce = ResourceDpopProofs.ReadNonce(response);
        Assert.IsFalse(string.IsNullOrEmpty(notificationNonce), "The refusal supplies a nonce.");
        Assert.AreNotEqual(credentialEndpointNonce, notificationNonce, "The Notification Endpoint supplies a nonce of its own.");
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>:
    /// "dpop_bound_access_tokens_required OPTIONAL. Boolean value specifying whether the protected resource always
    /// requires the use of DPoP-bound access tokens [RFC9449]."; <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC
    /// 9449 Section 7.1</see>: "Upon receipt of a request to a protected resource within the protection space requiring
    /// DPoP authentication, the server can respond with a challenge to the client to provide DPoP authentication
    /// information"; and <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "If
    /// the request lacks any authentication information (e.g., the client was unaware that authentication is necessary
    /// or attempted using an unsupported authentication method), the resource server SHOULD NOT include an error code or
    /// other error information." At a server whose resources require DPoP-bound access tokens, an access token presented
    /// at the Credential Endpoint over a raw TLS connection under the <c>Bearer</c> scheme is refused before the token is
    /// judged: 401, an empty body, the one challenge <c>DPoP realm="&lt;issuer&gt;", algs="..."</c> with no
    /// <c>error</c>, no <c>scope</c> and no <c>Bearer</c> challenge, and the one field line
    /// <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CredentialEndpointRequiringDpopBoundAccessTokensRefusesABearerPresentationAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;
        await TestHostShell.AlterAsync(host.Server, static candidateIntegration =>
            candidateIntegration.IsDpopBoundAccessTokenRequiredAtResources = true).ConfigureAwait(false);

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, ctx.CredentialUrl,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json),
                new(WellKnownHttpHeaderNames.Authorization, "Bearer " + ctx.AccessToken)
            ],
            Encoding.UTF8.GetBytes("{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The presentation is refused without a server fault.");
        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            CredentialDpopChallenge(ctx, error: null),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields,
            Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        Assert.AreEqual(string.Empty, response.Body, "No error code or other error information.");
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
        Assert.AreEqual(CredentialDpopChallenge(ctx, "invalid_token"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see>: "If the
    /// request lacks any authentication information (e.g., the client was unaware that authentication
    /// is necessary or attempted using an unsupported authentication method), the resource server
    /// SHOULD NOT include an error code or other error information." A Credential Request sent over the
    /// wire with no <c>Authorization</c> header is refused with 401, an empty body and exactly one
    /// challenge that names both schemes the endpoint accepts and no error: a <c>Bearer</c> challenge
    /// whose <c>realm</c> is the issuer the host serves the endpoint under, then <c>DPoP realm="&lt;issuer&gt;", algs="..."</c>.
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
        Assert.AreEqual(
            $"Bearer realm=\"{IssuerOf(ctx)}\", {ResourceDpopProofs.DpopChallenge(IssuerOf(ctx), error: null)}",
            Assert.ContainsSingle(challenges));
        Assert.AreEqual(string.Empty, body, "RFC 6750 §3.1: no error code or other error information.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 Section 3</see>: "All challenges defined by
    /// this specification MUST use the auth-scheme value "Bearer". This scheme MUST be followed by one or more auth-param
    /// values.", and <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>:
    /// "The 500 (Internal Server Error) status code indicates that the server encountered an unexpected condition that
    /// prevented it from fulfilling the request." The Credential Endpoint requires no single scope, so the <c>Bearer</c>
    /// challenge of its answer to a request without credentials carries the realm, the issuer; at a server whose issuer
    /// does not resolve it has no auth-param to carry. A Credential Request sent over the wire with no
    /// <c>Authorization</c> field there is answered 500 with exactly the body
    /// <c>{"error":"server_error","error_description":"The server is not ready to serve this request."}</c>, no
    /// challenge and no <c>Access-Control-Expose-Headers</c> field. The rows: the registration's issuer replaced by one the default issuer resolver refuses (<c>http</c>
    /// scheme); an application issuer resolver that answers nothing.
    /// </summary>
    /// <param name="row">Which part of the wiring fails: <see cref="IssuerUnresolvableRow"/> or <see cref="IssuerResolverAnswersNothingRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(IssuerUnresolvableRow)]
    [DataRow(IssuerResolverAnswersNothingRow)]
    public async Task CredentialEndpointAnswersANoCredentialRequestWhoseIssuerDoesNotResolveAsServerErrorAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;
        Action<AuthorizationServerIntegration>? alteration = row switch
        {
            IssuerResolverAnswersNothingRow => static candidateIntegration =>
                candidateIntegration.ResolveIssuerAsync = static (_, _, _) => ValueTask.FromResult<Uri?>(null),
            IssuerUnresolvableRow => null,
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown wiring row.")
        };
        if(alteration is not null)
        {
            await TestHostShell.AlterAsync(host.Server, alteration).ConfigureAwait(false);
        }
        else
        {
            HostedAuthorizationServer served = host.Host("default");
            ClientRecord replaced = served.Registrations[ctx.Segment] with { IssuerUri = new Uri("http://issuer.test/" + ctx.Segment) };
            served.Registrations[replaced.TenantId.Value] = replaced;
            served.Registrations[replaced.ClientId] = replaced;
        }

        using StringContent content = new(
            "{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}",
            Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage request = new(HttpMethod.Post, ctx.CredentialUrl) { Content = content };
        using HttpResponseMessage response = await ctx.Http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(HttpStatusCode.InternalServerError, response.StatusCode, body);
        Assert.AreEqual(
            /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"The server is not ready to serve this request.\"}", body);
        Assert.IsFalse(response.Headers.Contains("WWW-Authenticate"), "A fault of the server carries no challenge.");
        Assert.IsEmpty(
            response.Headers.NonValidated.Where(static field => string.Equals(field.Key, "Access-Control-Expose-Headers", StringComparison.OrdinalIgnoreCase)),
            "A fault of the server carries no exposure field.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18).", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed.  The resource
    /// server SHOULD respond with the HTTP 400 (Bad Request) status code." A Credential Request sent over a raw TLS
    /// connection with two <c>Authorization: Bearer</c> field lines (<c>Authorization = credentials</c> is no list,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.2">RFC 9110 Section 11.6.2</see>) attempts the
    /// <c>Bearer</c> mechanism alone: it is refused with 400 <c>invalid_request</c> and the one challenge
    /// <c>Bearer realm="&lt;issuer&gt;", error="invalid_request"</c>, the realm the issuer the host serves the endpoint
    /// under, and no <c>DPoP</c> challenge.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CredentialEndpointRefusesTwoBearerAuthorizationLinesWithTheBearerChallengeAloneAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, ctx.CredentialUrl,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json),
                new(WellKnownHttpHeaderNames.Authorization, "Bearer " + ctx.AccessToken),
                new(WellKnownHttpHeaderNames.Authorization, "Bearer " + ctx.AccessToken)
            ],
            Encoding.UTF8.GetBytes("{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"Bearer realm=\"{IssuerOf(ctx)}\", error=\"invalid_request\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "credentials = "DPoP"
    /// 1*SP token68", and <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>:
    /// "credentials = "Bearer" 1*SP b64token"; a credential outside that form is malformed,
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 Section 3.1</see>: "invalid_request The
    /// request is missing a required parameter, includes an unsupported parameter or parameter value, repeats the same
    /// parameter, uses more than one method for including an access token, or is otherwise malformed. The resource server
    /// SHOULD respond with the HTTP 400 (Bad Request) status code.", and the mechanism it attempts is named,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18)." A Credential Request sent over a raw TLS connection whose one
    /// <c>Authorization</c> field line names a scheme with the credentials <c>abc def</c>, no token68, is answered 400
    /// with the body
    /// <c>{"error":"invalid_request","error_description":"The Authorization header credentials are not a token68."}</c>.
    /// The rows: the <c>DPoP</c> scheme, the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_request", algs="..."</c>
    /// and the one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>; the <c>Bearer</c>
    /// scheme, the one challenge <c>Bearer realm="&lt;issuer&gt;", error="invalid_request"</c> and no
    /// <c>Access-Control-Expose-Headers</c> field.
    /// </summary>
    /// <param name="scheme">The scheme the field line names.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("DPoP")]
    [DataRow("Bearer")]
    public async Task CredentialEndpointAnswersACredentialOutsideToken68WithInvalidRequestAsync(string scheme)
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, ctx.CredentialUrl,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json),
                new(WellKnownHttpHeaderNames.Authorization, $"{scheme} abc def")
            ],
            Encoding.UTF8.GetBytes("{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(host.Host("default").ConsumeHttpFaults(), "The request is answered without a server fault.");
        Assert.AreEqual(400, response.StatusCode, response.Body);
        bool isDpopScheme = string.Equals(scheme, "DPoP", StringComparison.Ordinal);
        Assert.AreEqual(
            isDpopScheme ? CredentialDpopChallenge(ctx, "invalid_request") : $"Bearer realm=\"{IssuerOf(ctx)}\", error=\"invalid_request\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        IReadOnlyList<string> exposureFields = response.Headers.Headers.GetValues("Access-Control-Expose-Headers");
        if(isDpopScheme)
        {
            Assert.AreEqual(ResourceDpopProofs.ExposedDpopResponseFields, Assert.ContainsSingle(exposureFields));
        }
        else
        {
            Assert.IsEmpty(exposureFields, "A Bearer challenge alone exposes no field.");
        }

        Assert.AreEqual(
            "{\"error\":\"invalid_request\",\"error_description\":\"The Authorization header credentials are not a token68.\"}",
            response.Body);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 Section 7.2</see>: "If the mechanism used
    /// to attempt authentication could be established unambiguously, then the corresponding challenge SHOULD be used to
    /// deliver error information (Figure 18)." A Credential Request sent over a raw TLS connection with two
    /// <c>Authorization: DPoP</c> field lines attempts the <c>DPoP</c> mechanism alone: it is refused with 400,
    /// <c>invalid_request</c> in the body, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_request", algs="..."</c>, no <c>scope</c> and no <c>Bearer</c>
    /// challenge, and the one field line <c>Access-Control-Expose-Headers: WWW-Authenticate, DPoP-Nonce</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "including WWW-Authenticate in
    /// the Access-Control-Expose-Headers response header list value").
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CredentialEndpointAnswersTwoDpopAuthorizationLinesWithTheDpopChallengeAloneAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, ctx.CredentialUrl,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json),
                new(WellKnownHttpHeaderNames.Authorization, "DPoP " + ctx.AccessToken),
                new(WellKnownHttpHeaderNames.Authorization, "DPoP " + ctx.AccessToken)
            ],
            Encoding.UTF8.GetBytes("{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, response.StatusCode, response.Body);
        Assert.AreEqual(
            CredentialDpopChallenge(ctx, "invalid_request"),
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        Assert.AreEqual(
            ResourceDpopProofs.ExposedDpopResponseFields,
            Assert.ContainsSingle(response.Headers.Headers.GetValues("Access-Control-Expose-Headers")));
        using JsonDocument document = JsonDocument.Parse(response.Body);
        Assert.AreEqual("invalid_request", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.2">RFC 9449 §7.2</see>: "If the
    /// mechanism used to attempt authentication could be established unambiguously, then the
    /// corresponding challenge SHOULD be used to deliver error information". A DPoP-bound access token
    /// whose signature does not verify, presented at the Credential Endpoint over the wire under the
    /// <c>DPoP</c> scheme, is refused with 401 <c>invalid_token</c> and the single challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_token", algs="..."</c>, never a <c>Bearer</c> one.
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
        Assert.AreEqual(CredentialDpopChallenge(ctx, "invalid_token"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>, of the <c>DPoP</c>
    /// challenge: "The authentication parameter realm MAY be included to indicate the scope of protection in the manner
    /// described in [RFC9110], Section 11.5." and "A scope authentication parameter MAY be included as defined in
    /// [RFC6750], Section 3." The Credential Endpoint names the realm of the protection space it serves, the issuer, in
    /// every <c>DPoP</c> challenge, and no <c>scope</c>, since it requires no single scope when it refuses a
    /// presentation. The one field line received over a raw TLS connection is, for a DPoP-bound token whose signature
    /// does not verify, <c>DPoP realm="&lt;issuer&gt;", error="invalid_token", algs="..."</c>, and for a DPoP-bound token
    /// presented with no proof <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", algs="..."</c> with one
    /// <c>DPoP-Nonce</c> field line.
    /// </summary>
    /// <param name="row">Which refusal the request meets: <see cref="TamperedTokenRow"/> or <see cref="NonceChallengeRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(TamperedTokenRow)]
    [DataRow(NonceChallengeRow)]
    public async Task CredentialEndpointDpopChallengeCarriesTheRealmAndNoScopeAsync(string row)
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        (string presentedToken, string error) = row switch
        {
            TamperedTokenRow => (TamperSignature(ctx.AccessToken), "invalid_token"),
            NonceChallengeRow => (ctx.AccessToken, "use_dpop_nonce"),
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown challenge row.")
        };
        HttpResponseData response = await RawHttpsRequest.SendAsync(
            host, WellKnownHttpMethods.Post, ctx.CredentialUrl,
            [
                new(WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json),
                new(WellKnownHttpHeaderNames.Authorization, "DPoP " + presentedToken)
            ],
            Encoding.UTF8.GetBytes("{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}"),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, response.StatusCode, response.Body);
        Assert.AreEqual(
            $"DPoP realm=\"{IssuerOf(ctx)}\", error=\"{error}\", algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"",
            Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.WwwAuthenticate)));
        if(row == NonceChallengeRow)
        {
            Assert.IsFalse(string.IsNullOrEmpty(Assert.ContainsSingle(response.Headers.Headers.GetValues(WellKnownHttpHeaderNames.DPoPNonce))),
                "The nonce challenge carries one DPoP-Nonce field line.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.3">RFC 9449 Section 4.3</see>, check 5: "The alg JOSE
    /// Header Parameter indicates a registered asymmetric digital signature algorithm [IANA.JOSE.ALGS], is not none, is
    /// supported by the application, and is acceptable per local policy.", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">Section 7.1</see>: "An algs parameter SHOULD be
    /// included to signal to the client the JWS algorithms that are acceptable for the DPoP proof JWT." A host whose
    /// signing-algorithm resolver answers <c>["ES384"]</c> for DPoP proofs, after the token was issued and the endpoint's
    /// nonce provided, holds the Credential Endpoint to that list: an ES256 proof presented with its DPoP-bound token over
    /// the wire, carrying that nonce and correct in every other claim, is refused with 401, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="invalid_dpop_proof", algs="ES384"</c> and the description "DPoP proof
    /// validation failed: InvalidAlg.".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task CredentialEndpointRefusesAProofOutsideTheAcceptedAlgorithmsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;
        string nonce = await ObtainResourceNonceAsync(ctx).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, static candidateIntegration =>
            candidateIntegration.Cryptography.ResolveSupportedSigningAlgorithmsAsync = static (registration, usage, context, cancellationToken) =>
                usage == KeyUsageContext.DpopProof
                    ? ValueTask.FromResult<IReadOnlyList<string>>([WellKnownJwaValues.Es384])
                    : DefaultSupportedSigningAlgorithms.ResolveAsync(
                        context.RequestServer!.OAuth(), registration, usage, context, cancellationToken)).ConfigureAwait(false);

        string proof = await BuildCredentialProofAsync(ctx, freshKey: null, nonce).ConfigureAwait(false);
        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "The refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual($"DPoP realm=\"{IssuerOf(ctx)}\", error=\"invalid_dpop_proof\", algs=\"ES384\"", challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_dpop_proof", document.RootElement.GetProperty("error").GetString());
        Assert.AreEqual("DPoP proof validation failed: InvalidAlg.", document.RootElement.GetProperty("error_description").GetString());
    }


    /// <summary>
    /// Flips one character in the middle of a compact JWS's signature segment; it stays base64url, so the token parses
    /// and its signature deterministically fails to verify.
    /// </summary>
    /// <param name="compactJws">The token to tamper.</param>
    /// <returns>The token with a signature that does not verify.</returns>
    private static string TamperSignature(string compactJws)
    {
        int signatureStart = compactJws.LastIndexOf('.', StringComparison.Ordinal) + 1;
        int tamperIndex = signatureStart + ((compactJws.Length - signatureStart) / 2);
        char flipped = compactJws[tamperIndex] == 'A' ? 'B' : 'A';

        return string.Concat(compactJws.AsSpan(0, tamperIndex), flipped.ToString(), compactJws.AsSpan(tamperIndex + 1));
    }


    /// <summary>
    /// Presents the bound token at the Credential Endpoint over the wire with no proof, asserts the
    /// RFC 9449 §9 nonce challenge it is answered with (401, the one challenge
    /// <c>DPoP realm="&lt;issuer&gt;", error="use_dpop_nonce", algs="..."</c> and <c>use_dpop_nonce</c> in the body), and returns
    /// the nonce its <c>DPoP-Nonce</c> header provides.
    /// </summary>
    /// <param name="ctx">The bound-token context.</param>
    /// <returns>The nonce the endpoint provided.</returns>
    private async Task<string> ObtainResourceNonceAsync(BoundTokenContext ctx)
    {
        using HttpResponseMessage challenge = await PostCredentialAsync(ctx, ctx.AccessToken, dpopProof: null)
            .ConfigureAwait(false);
        string body = await challenge.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, challenge.StatusCode, body);
        Assert.IsTrue(challenge.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges));
        Assert.AreEqual(CredentialDpopChallenge(ctx, "use_dpop_nonce"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("use_dpop_nonce", document.RootElement.GetProperty("error").GetString());

        return ResourceDpopProofs.ReadNonce(challenge);
    }


    /// <summary>The issuer the host serves the registration under, the realm of the endpoints' challenges.</summary>
    /// <param name="ctx">The bound-token context.</param>
    /// <returns>The issuer, as written.</returns>
    private static string IssuerOf(BoundTokenContext ctx) => ctx.Fixture.Registration.AuthorizationServerIssuer.OriginalString;


    /// <summary>
    /// The <c>DPoP</c> challenge the Credential, Deferred Credential and Notification endpoints answer a refused DPoP
    /// presentation with, written out: <c>DPoP realm="&lt;issuer&gt;", error="&lt;error&gt;", algs="..."</c>, no
    /// <c>scope</c>, since these endpoints require no single scope when they refuse a presentation.
    /// </summary>
    /// <param name="ctx">The bound-token context.</param>
    /// <param name="error">The challenge's <c>error</c>, or <see langword="null"/> for a challenge carrying none.</param>
    /// <returns>The <c>WWW-Authenticate</c> value.</returns>
    private static string CredentialDpopChallenge(BoundTokenContext ctx, string? error) =>
        ResourceDpopProofs.DpopChallenge(IssuerOf(ctx), error);


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

        //Unwire proof validation AFTER the bound token was minted, the slot unassigned and no parser for the
        //library default: a bound token must never silently fall back to bearer, so the credential endpoint
        //fails loud.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidateDpopProofAsync = null;
            candidateIntegration.Codecs.DpopProofParser = null;
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>: "The JWT access
    /// token MUST be rejected if "aud" does not contain a resource indicator of the current resource server as a
    /// valid audience." and "Please note that this requirement does not prevent JWT access tokens from using
    /// authentication schemes other than "Bearer"." The Credential, the Deferred Credential and the Notification
    /// endpoint are resources of this Authorization Server, whose identifier is the issuer. A DPoP-bound access
    /// token signed again under the registration's access-token key with its <c>aud</c> naming another resource
    /// alone, presented over the wire under the <c>DPoP</c> scheme with a well-formed request body and a proof from
    /// the bound key carrying the nonce the server provided, at the endpoint a row addresses, is refused with 401,
    /// <c>invalid_token</c> and the one challenge <c>DPoP realm="&lt;issuer&gt;", error="invalid_token", algs="..."</c>.
    /// </summary>
    /// <param name="endpointName">The protected endpoint addressed: <see cref="CredentialEndpointRow"/>, <see cref="DeferredEndpointRow"/> or <see cref="NotificationEndpointRow"/>.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(CredentialEndpointRow)]
    [DataRow(DeferredEndpointRow)]
    [DataRow(NotificationEndpointRow)]
    public async Task AProtectedEndpointRefusesADpopBoundTokenAudiencedAtAnotherResourceAsync(string endpointName)
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;
        string nonce = await ObtainResourceNonceAsync(ctx).ConfigureAwait(false);

        string otherAudienceToken = await CompactJwsResigning.ResignWithAlteredPayloadAsync(
            host, ctx.AccessToken, ctx.SigningKeyId,
            static payload => payload["aud"] = new JsonArray(OtherResourceAudience)).ConfigureAwait(false);
        (string endpointWireName, string requestBody) = endpointName switch
        {
            CredentialEndpointRow => (WellKnownEndpointNames.Oid4VciCredential,
                "{\"credential_configuration_id\":\"" + ConfigurationId + "\",\"proofs\":{\"jwt\":[\"p\"]}}"),
            DeferredEndpointRow => (WellKnownEndpointNames.Oid4VciDeferredCredential, "{\"transaction_id\":\"8xLOxBtZp8\"}"),
            NotificationEndpointRow => (WellKnownEndpointNames.Oid4VciNotification,
                "{\"notification_id\":\"3fwe98js\",\"event\":\"credential_accepted\"}"),
            _ => throw new ArgumentOutOfRangeException(nameof(endpointName), endpointName, "Unknown endpoint row.")
        };
        Uri endpointUrl = new(host.Host("default").HttpBaseAddress!, TestHostShell.ComposeEndpointPath(endpointWireName, ctx.Segment));
        string proof = await ResourceDpopProofs.BuildAsync(
            ctx.Fixture.DpopKey, WellKnownHttpMethods.Post, endpointUrl.ToString(), otherAudienceToken,
            nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken).ConfigureAwait(false);

        using StringContent content = new(requestBody, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        using HttpRequestMessage request = new(HttpMethod.Post, endpointUrl) { Content = content };
        _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, "DPoP " + otherAudienceToken);
        _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.DPoP, proof);
        using HttpResponseMessage response = await ctx.Http.SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode, body);
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "RFC 6750 Section 3: the refusal carries a WWW-Authenticate challenge.");
        Assert.AreEqual(CredentialDpopChallenge(ctx, "invalid_token"), challenges.Single());
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.AreEqual("invalid_token", document.RootElement.GetProperty("error").GetString());
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.2">OpenID
    /// for Verifiable Credential Issuance 1.0 Section 5.1.2</see>: "If the Credential Issuer metadata contains an
    /// authorization_servers property, it is RECOMMENDED to use a resource parameter [RFC8707] whose value is the
    /// Credential Issuer's identifier value to allow the Authorization Server to differentiate Credential
    /// Issuers." and <see href="https://www.rfc-editor.org/rfc/rfc9068#section-3">RFC 9068 Section 3</see>: "If
    /// the request includes a "resource" parameter (as defined in [RFC8707]), the resulting JWT access token
    /// "aud" claim SHOULD have the same value as the "resource" parameter in the request." The authorization-code
    /// flow over the wire whose pushed request names the Credential Issuer's identifier, the issuer, as its
    /// <c>resource</c> issues a DPoP-bound access token whose <c>aud</c> is <c>["&lt;issuer&gt;"]</c>; presented at
    /// the Credential Endpoint over the wire under the <c>DPoP</c> scheme with a proof from the bound key carrying
    /// the nonce the endpoint provided, it is served 200.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ATokenRequestedForTheCredentialIssuerIsServedAtTheCredentialEndpointAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        BoundTokenContext ctx = await AcquireAsync(host, isIssuerRequestedAsResource: true).ConfigureAwait(false);
        using DpopClientFixture fixture = ctx.Fixture;

        using JsonDocument payload = JsonDocument.Parse(
            SecurityEventTestJson.DecodeSegment(ctx.AccessToken.Split('.')[1], BaseMemoryPool.Shared));
        Assert.AreEqual(
            $"[\"{ctx.Fixture.Registration.AuthorizationServerIssuer.OriginalString}\"]",
            payload.RootElement.GetProperty("aud").GetRawText(),
            "The requested resource, the Credential Issuer's identifier, is the token's audience.");

        string nonce = await ObtainResourceNonceAsync(ctx).ConfigureAwait(false);
        string proof = await BuildCredentialProofAsync(ctx, freshKey: null, nonce).ConfigureAwait(false);
        using HttpResponseMessage response = await PostCredentialAsync(ctx, ctx.AccessToken, proof).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode, body);
    }


    /// <summary>The identifier of a resource other than this Authorization Server.</summary>
    private static string OtherResourceAudience { get; } = "https://rs.example.com";

    /// <summary>The wiring row whose registration names an issuer the default resolver refuses.</summary>
    private const string IssuerUnresolvableRow = "issuer-unresolvable";

    /// <summary>The wiring row whose application issuer resolver answers nothing.</summary>
    private const string IssuerResolverAnswersNothingRow = "issuer-resolver-answers-nothing";

    /// <summary>The challenge row whose access token's signature does not verify.</summary>
    private const string TamperedTokenRow = "tampered-token";

    /// <summary>The challenge row whose DPoP-bound token is presented with no proof.</summary>
    private const string NonceChallengeRow = "nonce-challenge";

    /// <summary>The row addressing the Credential Endpoint.</summary>
    private const string CredentialEndpointRow = "oid4vci-credential";

    /// <summary>The row addressing the Deferred Credential Endpoint.</summary>
    private const string DeferredEndpointRow = "oid4vci-deferred-credential";

    /// <summary>The row addressing the Notification Endpoint.</summary>
    private const string NotificationEndpointRow = "oid4vci-notification";


    /// <summary>
    /// Carries the live host, fixture, minted bound token, the registration's path segment and the key the
    /// registration signs access tokens under through a credential-request variation.
    /// </summary>
    /// <param name="Host">The live host the issuer is registered on.</param>
    /// <param name="Fixture">The DPoP client fixture whose public key the access token is bound to.</param>
    /// <param name="AccessToken">The minted <c>cnf.jkt</c>-bound access token.</param>
    /// <param name="CredentialUrl">The Credential Endpoint's address on the host's loopback listener.</param>
    /// <param name="Http">The client that sends the requests over the loopback listener.</param>
    /// <param name="SigningKeyId">The identifier of the signing key the registration signs access tokens under.</param>
    /// <param name="Segment">The registration's tenant segment of the endpoint paths.</param>
    private sealed record BoundTokenContext(
        TestHostShell Host, DpopClientFixture Fixture, string AccessToken, Uri CredentialUrl, HttpClient Http, KeyId SigningKeyId, string Segment);


    /// <summary>
    /// Registers a DPoP issuer, drives the full PAR → Authorize → callback → token DPoP flow to
    /// mint a <c>cnf.jkt</c>-bound Access Token, and wires the credential issuance seam.
    /// </summary>
    /// <param name="host">The host the issuer is registered on.</param>
    /// <param name="isIssuerRequestedAsResource">
    /// Whether the pushed authorization request names the registration's issuer, the Credential Issuer's
    /// identifier, as its <c>resource</c>; otherwise it names none.
    /// </param>
    /// <returns>The bound-token context.</returns>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The host's key stores own and dispose the registration's key material; the returned " +
        "VerifierKeyMaterial is a handle to those same instances, released when the host is disposed.")]
    private async Task<BoundTokenContext> AcquireAsync(TestHostShell host, bool isIssuerRequestedAsResource = false)
    {
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, Capabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            candidateIntegration.ResolveDeferredCredentialAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(DeferredCredentialDecision.Defer(60));
            candidateIntegration.ProcessCredentialNotificationAsync = static (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialNotificationDecision.Accept);
        }).ConfigureAwait(false);

        DpopClientFixture fixture = await host.CreateDpopEnabledOAuthClientAsync(
            material.Registration, RedirectUri.OriginalString, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string segment = material.Registration.TenantId.Value;

        //Step 1 — PAR.
        IReadOnlyList<string>? resource = isIssuerRequestedAsResource
            ? [fixture.Registration.AuthorizationServerIssuer.OriginalString]
            : null;
        AuthCodeFlowEndpointResult parResult = await fixture.Client.AuthCode.StartParAsync(
            fixture.Registration, RedirectUri, OAuthFormEncodedFieldsFixtures.OpenIdScope, [], resource, TestContext.CancellationToken)
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
            host, fixture, accessToken, credentialUrl, host.Host("default").SharedHttpClient!, material.SigningKeyId, segment);
    }


    /// <summary>
    /// Builds a fresh DPoP proof for the credential POST: htm=POST, htu=the credential URL,
    /// ath bound to the access token, the resource <paramref name="nonce"/> when given, signed by the
    /// token's key (or <paramref name="freshKey"/> to forge a thumbprint mismatch).
    /// </summary>
    /// <param name="ctx">The bound-token context.</param>
    /// <param name="freshKey">A key other than the bound one, or <see langword="null"/> for the bound key.</param>
    /// <param name="nonce">The resource nonce, or <see langword="null"/> to carry none.</param>
    /// <param name="jti">The <c>jti</c> value, or <see langword="null"/> for a fresh unique one.</param>
    /// <returns>The DPoP proof JWT.</returns>
    private Task<string> BuildCredentialProofAsync(BoundTokenContext ctx, DpopKey? freshKey, string? nonce, string? jti = null) =>
        ResourceDpopProofs.BuildAsync(
            freshKey ?? ctx.Fixture.DpopKey, WellKnownHttpMethods.Post, ctx.CredentialUrl.ToString(), ctx.AccessToken,
            nonce, TimeProvider.GetUtcNow(), TestContext.CancellationToken, jti);


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
