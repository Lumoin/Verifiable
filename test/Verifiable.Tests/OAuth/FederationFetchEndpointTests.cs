using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Federation;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end + specification-conformance tests for the OpenID Federation 1.0
/// §8.1 <c>federation_fetch_endpoint</c> exposed by
/// <see cref="FederationEndpoints"/>: a positive case (serve + validate a
/// signed Subordinate Statement) and the two §8.1 / §3 negatives — an unknown
/// subordinate, and a <c>sub</c> equal to the issuing entity (a Subordinate
/// Statement is never self-issued).
/// </summary>
[TestClass]
internal sealed class FederationFetchEndpointTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string AnchorEntityId = "https://anchor.example.com";
    private const string SubordinateEntityId = "https://subordinate.example.com";


    /// <summary>
    /// Serves the requested subordinate statement signed by its issuing entity.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.1.2">Federation §8.1.2</see>.
    /// </summary>
    [TestMethod]
    public async Task FetchEndpointServesSignedSubordinateStatement()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = await RegisterAnchorAsync(app, anchorKeys).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubordinateStatementAsync = (subject, _, _, _) =>
            {
                if(!string.Equals(subject.Value, SubordinateEntityId, StringComparison.Ordinal))
                {

                    return ValueTask.FromResult<SubordinateStatementContribution?>(null);
                }

                return ValueTask.FromResult<SubordinateStatementContribution?>(
                    new SubordinateStatementContribution
                    {
                        Jwks = new Dictionary<string, object>(StringComparer.Ordinal)
                        {
                            ["keys"] = new List<object>(),
                        },
                    });
            };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        string compact = await GetAsync(
            host,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString(SubordinateEntityId)}",
            expectedStatus: 200,
            expectedContentType: WellKnownMediaTypes.Application.EntityStatementJwt).ConfigureAwait(false);

        //A Subordinate Statement is iss != sub, carries the subject's jwks, and
        //is signed by the issuing anchor's federation key.
        Dictionary<string, object> header = DecodeSegment(compact, 0);
        Assert.AreEqual(
            WellKnownFederationMediaTypes.EntityStatementJwt,
            (string)header[WellKnownJoseHeaderNames.Typ]);

        Dictionary<string, object> payload = DecodeSegment(compact, 1);
        Assert.AreEqual(new Uri(AnchorEntityId).ToString(), (string)payload["iss"],
            "iss must be the issuing anchor.");
        Assert.AreEqual(new Uri(SubordinateEntityId).ToString(), (string)payload["sub"],
            "sub must be the queried subordinate.");
        Assert.AreNotEqual((string)payload["iss"], (string)payload["sub"],
            "A Subordinate Statement is never self-issued (iss != sub).");
        Assert.IsTrue(payload.ContainsKey("jwks"),
            "A Subordinate Statement carries the subject's jwks per §3.1.");

        bool verified = await Jws.VerifyAsync(
            compact,
            TestSetup.Base64UrlDecoder,
            Pool,
            anchorKeys.PublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(verified, "The Subordinate Statement must verify under the anchor's federation key.");
    }


    /// <summary>
    /// The library's own rule for a lifetime it issues: the library writes a Subordinate Statement's <c>iat</c> and
    /// <c>exp</c> (<see href="https://openid.net/specs/openid-federation-1_0.html#section-3.1.1">OpenID Federation 1.0
    /// Section 3.1.1</see>) as whole-second NumericDates, and every lifetime the server's <see cref="TimingPolicy"/>
    /// holds is its whole seconds, so a <see cref="TimingPolicy.FederationEntityConfigurationLifetime"/> of 90.7
    /// seconds issues a Subordinate Statement, fetched over the real wire half a second past a whole second, whose
    /// <c>exp</c> is 90 seconds after its <c>iat</c>.
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task ASubordinateStatementUnderAFractionalLifetimeLivesItsWholeSecondsAsync()
    {
        await using TestHostShell app = new(TimeProvider);
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using VerifierKeyMaterial anchor = await RegisterAnchorAsync(app, anchorKeys).ConfigureAwait(false);
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubordinateStatementAsync = static (subject, _, _, _) =>
                ValueTask.FromResult<SubordinateStatementContribution?>(new SubordinateStatementContribution
                {
                    Jwks = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["keys"] = new List<object>()
                    }
                });
            candidateIntegration.Timings = TimingPolicy.Default with
            {
                FederationEntityConfigurationLifetime = TimeSpan.FromTicks(907_000_000L)
            };
        }).ConfigureAwait(false);
        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        TimeProvider.Advance(TimeSpan.FromTicks(TimeSpan.TicksPerSecond / 2));

        string compact = await GetAsync(
            host,
            $"/connect/{anchor.Registration.TenantId.Value}/federation_fetch?sub={Uri.EscapeDataString(SubordinateEntityId)}",
            expectedStatus: 200,
            expectedContentType: WellKnownMediaTypes.Application.EntityStatementJwt).ConfigureAwait(false);
        Dictionary<string, object> payload = DecodeSegment(compact, 1);

        Assert.AreEqual(
            90L,
            Convert.ToInt64(payload["exp"], CultureInfo.InvariantCulture)
                - Convert.ToInt64(payload["iat"], CultureInfo.InvariantCulture),
            compact);
    }


    /// <summary>
    /// Returns not_found when the requested subordinate has no statement.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">Federation §8.9</see>.
    /// </summary>
    [TestMethod]
    public async Task FetchEndpointReturns404ForUnknownSubordinate()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = await RegisterAnchorAsync(app, anchorKeys).ConfigureAwait(false);

        //The anchor knows no subordinates → every sub resolves to null.
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubordinateStatementAsync =
                (_, _, _, _) => ValueTask.FromResult<SubordinateStatementContribution?>(null);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString("https://unknown.example.com")}");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(404, (int)response.StatusCode,
            "Federation §8.1: a fetch for a subject the entity does not vouch for yields HTTP 404.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            "Federation §8.9: the error response must be an application/json object.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.NotFound}\"", body, StringComparison.Ordinal,
            $"Federation §8.9: an unknown subject must carry the not_found error code. Got: {body}");
    }


    /// <summary>
    /// Rejects a fetch that would make a subordinate statement self-issued.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-3">Federation §3</see>.
    /// </summary>
    [TestMethod]
    public async Task FetchEndpointRejectsSubEqualToIssuer()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = await RegisterAnchorAsync(app, anchorKeys).ConfigureAwait(false);

        bool delegateInvoked = false;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubordinateStatementAsync = (_, _, _, _) =>
            {
                delegateInvoked = true;

                return ValueTask.FromResult<SubordinateStatementContribution?>(null);
            };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        //Query the anchor about ITSELF — a Subordinate Statement cannot be
        //self-issued (Federation §3).
        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString(AnchorEntityId)}");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "Federation §3: sub == the issuing entity is a malformed request (a Subordinate Statement is never self-issued) — 400.");
        Assert.IsFalse(delegateInvoked,
            "The self-issued guard must reject before consulting the application resolver.");
    }


    /// <summary>
    /// Rejects failed client authentication before resolving a subordinate statement:
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.8">Federation Section 8.8</see>. The
    /// requester used no <c>Authorization</c> field and the server advertises no <c>client_secret_basic</c>, so the
    /// answer is 400 <c>invalid_client</c>, since no 401 is sent without a challenge
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>).
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">OpenID Federation 1.0 Section
    /// 8.9</see> defines <c>invalid_client</c> as "The Client cannot be authorized or is not a valid participant of
    /// the federation." and continues "The HTTP response status code SHOULD be 401 (Unauthorized)." The 400 is a
    /// named deviation from that SHOULD: for a request that did not use the <c>Authorization</c> field, a server
    /// without <c>client_secret_basic</c> has no challenge applicable to the endpoint to send with a 401.
    /// </summary>
    [TestMethod]
    public async Task FetchEndpointRejectsWhenClientAuthenticationFails()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = await RegisterAnchorAsync(app, anchorKeys).ConfigureAwait(false);

        //§8.8: the deployment requires client authentication at this endpoint and
        //the requester fails it. The gate must reject with invalid_client before the
        //subordinate-statement resolver is consulted: 400, since the request used no Authorization
        //field and the server advertises no client_secret_basic, so no challenge is sent.
        bool resolverInvoked = false;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubordinateStatementAsync = (_, _, _, _) =>
            {
                resolverInvoked = true;

                return ValueTask.FromResult<SubordinateStatementContribution?>(null);
            };

            candidateIntegration.AuthenticateFederationClientAsync = (_, _, _, _, _) =>
                ValueTask.FromResult<FederationClientAuthenticationResult?>(
                    FederationClientAuthenticationResult.Rejected("No client authentication was presented."));
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString(SubordinateEntityId)}");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "Section 8.8: a failed client authentication without an Authorization field and without client_secret_basic advertised yields HTTP 400 invalid_client.");
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidClient}\"", body, StringComparison.Ordinal,
            $"The refusal must carry the invalid_client error code. Got: {body}");
        Assert.IsFalse(resolverInvoked,
            "The client-authentication gate must run before the endpoint's own resolver.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>: "If the
    /// client attempted to authenticate via the "Authorization" request header field, the authorization
    /// server MUST respond with an HTTP 401 (Unauthorized) status code and include the "WWW-Authenticate"
    /// response header field matching the authentication scheme used by the client." A fetch request sent
    /// over the wire with <c>Authorization: Basic</c> that the deployment's federation client
    /// authentication refuses is answered 401 <c>invalid_client</c> with the one challenge
    /// <c>Basic realm="https://federation-realm.issuer.test/"</c>, the issuer the request is served under.
    /// </summary>
    [TestMethod]
    public async Task FetchEndpointChallengesAFailedBasicAttemptWithItsRealm()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = await RegisterAnchorAsync(app, anchorKeys).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubordinateStatementAsync = (_, _, _, _) =>
                ValueTask.FromResult<SubordinateStatementContribution?>(null);
            candidateIntegration.AuthenticateFederationClientAsync = (_, _, _, _, _) =>
                ValueTask.FromResult<FederationClientAuthenticationResult?>(
                    FederationClientAuthenticationResult.Rejected("The presented credential is not accepted."));
        }).ConfigureAwait(false);
        await TestHostShell.NameIssuerAsync(app.Server, new Uri("https://federation-realm.issuer.test/")).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString(SubordinateEntityId)}");
        using System.Net.Http.HttpRequestMessage request = new(System.Net.Http.HttpMethod.Get, url);
        _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, "Basic Y2xpZW50OnNlY3JldA==");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .SendAsync(request, TestContext.CancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        Assert.Contains($"\"error\":\"{OAuthErrors.InvalidClient}\"", body, StringComparison.Ordinal);
        Assert.IsTrue(response.Headers.TryGetValues(WellKnownHttpHeaderNames.WwwAuthenticate, out IEnumerable<string>? challenges),
            "RFC 9110 Section 15.5.2: the 401 carries a challenge.");
        Assert.AreEqual("Basic realm=\"https://federation-realm.issuer.test/\"", challenges.Single());
    }


    /// <summary>
    /// Serves the fetch when application policy does not require client authentication.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.8">Federation §8.8</see>.
    /// </summary>
    [TestMethod]
    public async Task FetchEndpointProceedsWhenClientAuthenticationIsNotRequired()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = await RegisterAnchorAsync(app, anchorKeys).ConfigureAwait(false);

        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubordinateStatementAsync = (subject, _, _, _) =>
                string.Equals(subject.Value, SubordinateEntityId, StringComparison.Ordinal)
                    ? ValueTask.FromResult<SubordinateStatementContribution?>(
                        new SubordinateStatementContribution
                        {
                            Jwks = new Dictionary<string, object>(StringComparer.Ordinal) { ["keys"] = new List<object>() },
                        })
                    : ValueTask.FromResult<SubordinateStatementContribution?>(null);


            //A null result means client authentication is not required at this
            //endpoint — the request proceeds and is served normally.

            candidateIntegration.AuthenticateFederationClientAsync = (_, _, _, _, _) =>
                ValueTask.FromResult<FederationClientAuthenticationResult?>(null);
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        Uri url = new(host.HttpBaseAddress!,
            $"/connect/{segment}/federation_fetch?sub={Uri.EscapeDataString(SubordinateEntityId)}");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, (int)response.StatusCode,
            "A null client-authentication result means not required — the request proceeds.");
    }


    /// <summary>
    /// A fetch request POSTed over the wire with a <c>client_assertion</c> whose <c>iat</c> lies 61 seconds after
    /// the clock, one second beyond the skew of 60 seconds the deployment's gate applies through
    /// <see cref="FederationClientAuthentication.Validate"/>, is refused: the gate records the description "The
    /// client assertion iat is in the future beyond the skew tolerance." and the answer is 400 with the body
    /// <c>{"error":"invalid_client","error_description":"The client assertion iat is in the future beyond the skew
    /// tolerance."}</c>; the subordinate-statement resolver is never consulted. The refusal is this library's
    /// policy, the one its <c>private_key_jwt</c> client authentication applies.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see>: "In order to issue
    /// an access token response as described in OAuth 2.0 [RFC6749] or to rely on a JWT for client
    /// authentication, the authorization server MUST validate the JWT according to the criteria below.
    /// Application of additional restrictions and policy are at the discretion of the authorization server."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">RFC 7519 Section 4.1.6</see>: "The "iat"
    /// (issued at) claim identifies the time at which the JWT was issued."
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.9">OpenID Federation 1.0 Section
    /// 8.9</see> defines <c>invalid_client</c> as "The Client cannot be authorized or is not a valid participant of
    /// the federation." and continues "The HTTP response status code SHOULD be 401 (Unauthorized)." The 400 is a
    /// named deviation from that SHOULD: the request used no <c>Authorization</c> field and the server advertises
    /// no <c>client_secret_basic</c>, so the server has no challenge applicable to the endpoint to send with a 401
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.5.2">RFC 9110 Section 15.5.2</see>).
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task FetchEndpointRefusesAClientAssertionIssuedBeyondTheSkew()
    {
        (int statusCode, string body, FederationClientAuthenticationResult? recorded, bool isResolverInvoked, _) =
            await FetchWithClientAssertionAsync(TimeProvider.GetUtcNow().AddSeconds(61)).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode, body);
        Assert.AreEqual(
            "{\"error\":\"invalid_client\",\"error_description\":\"The client assertion iat is in the future beyond the skew tolerance.\"}",
            body);
        Assert.IsNotNull(recorded);
        Assert.IsFalse(recorded.IsValid);
        Assert.AreEqual("The client assertion iat is in the future beyond the skew tolerance.", recorded.FailureReason);
        Assert.IsFalse(isResolverInvoked, "The client-authentication gate refuses before the endpoint's own resolver.");
    }


    /// <summary>
    /// A fetch request POSTed over the wire with a <c>client_assertion</c> whose <c>iat</c> lies exactly 60 seconds
    /// after the clock, the edge of the skew of 60 seconds the deployment's gate applies through
    /// <see cref="FederationClientAuthentication.Validate"/>, is authenticated and served: 200 with the Subordinate
    /// Statement, a compact JWS that verifies under the anchor's federation public key, whose <c>iss</c> is the
    /// anchor, whose <c>sub</c> is the queried subordinate and differs from the <c>iss</c>, and which carries the
    /// subject's <c>jwks</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7523#section-3">RFC 7523 Section 3</see>: "Application of
    /// additional restrictions and policy are at the discretion of the authorization server."
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">RFC 7519 Section 4.1.6</see>: "The "iat"
    /// (issued at) claim identifies the time at which the JWT was issued."
    /// </summary>
    /// <returns>A task that completes when the row has run.</returns>
    [TestMethod]
    public async Task FetchEndpointServesAClientAssertionIssuedAtTheEdgeOfTheSkew()
    {
        (int statusCode, string body, FederationClientAuthenticationResult? recorded, bool isResolverInvoked, bool isBodyVerifiedUnderAnchorKey) =
            await FetchWithClientAssertionAsync(TimeProvider.GetUtcNow().AddSeconds(60)).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode, body);
        Assert.IsNotNull(recorded);
        Assert.IsTrue(recorded.IsValid, recorded.FailureReason);
        Assert.AreEqual(RequesterEntityId, recorded.ClientId);
        Assert.IsTrue(isResolverInvoked, "An authenticated fetch reaches the endpoint's resolver.");

        Dictionary<string, object> payload = DecodeSegment(body, 1);
        Assert.AreEqual(new Uri(AnchorEntityId).ToString(), (string)payload["iss"], "iss must be the issuing anchor.");
        Assert.AreEqual(new Uri(SubordinateEntityId).ToString(), (string)payload["sub"], "sub must be the queried subordinate.");
        Assert.AreNotEqual((string)payload["iss"], (string)payload["sub"], "A Subordinate Statement is never self-issued (iss != sub).");
        Assert.IsTrue(payload.ContainsKey("jwks"), "A Subordinate Statement carries the subject's jwks.");
        Assert.IsTrue(isBodyVerifiedUnderAnchorKey, "The Subordinate Statement must verify under the anchor's federation public key.");
    }


    /// <summary>
    /// Returns a JSON error without invoking resolution when the required subject is missing.
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.1.1">Federation §8.1.1</see>.
    /// </summary>
    [TestMethod]
    public async Task FetchEndpointMissingSubReturnsJsonError()
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        using VerifierKeyMaterial anchor = await RegisterAnchorAsync(app, anchorKeys).ConfigureAwait(false);

        bool delegateInvoked = false;
        await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveSubordinateStatementAsync = (_, _, _, _) =>
            {
                delegateInvoked = true;

                return ValueTask.FromResult<SubordinateStatementContribution?>(null);
            };
        }).ConfigureAwait(false);

        await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string segment = anchor.Registration.TenantId.Value;

        //§8.1.1: sub is REQUIRED. A blank sub is therefore malformed. §8.1.2: an error
        //response MUST be a JSON object with the content type application/json.
        Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_fetch?sub=");
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, (int)response.StatusCode,
            "A fetch request without the REQUIRED sub parameter is malformed (Federation §8.1.1).");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.Content.Headers.ContentType?.MediaType,
            "Federation §8.1.2: a federation endpoint error response must use content type application/json.");

        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Dictionary<string, object> error = JsonSerializer.Deserialize<Dictionary<string, object>>(
            body, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("Error body parsed to null.");
        Assert.IsTrue(error.ContainsKey("error"),
            "Federation §8.1.2: the error response must be a JSON object carrying an error code.");
        Assert.IsFalse(delegateInvoked,
            "A request missing sub must be rejected before consulting the application resolver.");
    }


    /// <summary>The Entity Identifier of the requester that authenticates to the anchor's fetch endpoint with a client assertion.</summary>
    private static string RequesterEntityId => "https://requester.example.com";


    /// <summary>The skew of 60 seconds the deployment's client-authentication gate applies to the client assertion's time claims.</summary>
    private static TimeSpan GateClockSkew { get; } = TimeSpan.FromSeconds(60);


    /// <summary>Serializes a client assertion's protected header to UTF-8 JSON bytes for signing.</summary>
    private static JwtHeaderSerializer ClientAssertionHeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);


    /// <summary>Serializes a client assertion's claims to UTF-8 JSON bytes for signing.</summary>
    private static JwtPayloadSerializer ClientAssertionPayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// Sends one fetch request over the wire to the anchor's fetch endpoint carrying a client assertion signed
    /// by the requester, whose <c>iat</c> is <paramref name="issuedAt"/> and whose <c>exp</c> lies five minutes
    /// after it. The request is a POST whose form body carries <c>sub</c>, <c>client_assertion_type</c> and
    /// <c>client_assertion</c>, and its URI no parameter:
    /// <see href="https://openid.net/specs/openid-federation-1_0.html#section-8.1.1">OpenID Federation 1.0 Section
    /// 8.1.1</see>: "When client authentication is used, the request MUST be an HTTP request using the POST
    /// method, with the parameters passed in the POST body." The deployment's gate, wired as an application
    /// writes it, reads the <c>client_assertion</c> field, verifies its signature under the requester's public
    /// key, and judges its claims with <see cref="FederationClientAuthentication.Validate"/> at the test clock's
    /// current instant under <see cref="GateClockSkew"/>; the anchor vouches for <see cref="SubordinateEntityId"/>.
    /// </summary>
    /// <param name="issuedAt">The instant the client assertion's <c>iat</c> names.</param>
    /// <returns>
    /// The status code and body of the answer, the result the gate decided on (<see langword="null"/> when the
    /// gate recorded none), whether the subordinate-statement resolver was consulted, and whether the body is a
    /// compact JWS that verifies under the anchor's federation public key.
    /// </returns>
    private async Task<(int StatusCode, string Body, FederationClientAuthenticationResult? Recorded, bool IsResolverInvoked, bool IsBodyVerifiedUnderAnchorKey)> FetchWithClientAssertionAsync(
        DateTimeOffset issuedAt)
    {
        await using TestHostShell app = new(TimeProvider);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> requesterKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        try
        {
            using VerifierKeyMaterial anchor = await RegisterAnchorAsync(app, anchorKeys).ConfigureAwait(false);
            EntityIdentifier endpointEntity = new(AnchorEntityId);
            EntityIdentifier requesterEntity = new(RequesterEntityId);

            FederationClientAuthenticationResult? recorded = null;
            bool isResolverInvoked = false;
            await TestHostShell.AlterAsync(app.Server, candidateIntegration =>
            {
                candidateIntegration.ResolveSubordinateStatementAsync = (subject, _, _, _) =>
                {
                    isResolverInvoked = true;

                    return string.Equals(subject.Value, SubordinateEntityId, StringComparison.Ordinal)
                        ? ValueTask.FromResult<SubordinateStatementContribution?>(
                            new SubordinateStatementContribution
                            {
                                Jwks = new Dictionary<string, object>(StringComparer.Ordinal) { ["keys"] = new List<object>() },
                            })
                        : ValueTask.FromResult<SubordinateStatementContribution?>(null);
                };

                candidateIntegration.AuthenticateFederationClientAsync = async (_, fields, _, _, ct) =>
                {
                    if(!fields.TryGetValue(OAuthRequestParameterNames.ClientAssertion, out string? presented))
                    {
                        return FederationClientAuthenticationResult.Rejected("No client assertion was presented.");
                    }

                    bool isSignatureValid = await Jws.VerifyAsync(
                        presented, TestSetup.Base64UrlDecoder, Pool, requesterKeys.PublicKey, ct).ConfigureAwait(false);
                    if(!isSignatureValid)
                    {
                        return FederationClientAuthenticationResult.Rejected("The client assertion signature does not verify.");
                    }

                    string[] segments = presented.Split('.');
                    using IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(segments[1], Pool);
                    JwtPayload payload = JwsAccessTokenTestSupport.Parser.ParseClaims(payloadBytes.Memory);
                    FederationClientAuthenticationResult result = FederationClientAuthentication.Validate(
                        payload, endpointEntity, requesterEntity, TimeProvider.GetUtcNow(), GateClockSkew);
                    recorded = result;

                    return result;
                };
            }).ConfigureAwait(false);

            await app.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
            HostedAuthorizationServer host = app.Host("default");
            string segment = anchor.Registration.TenantId.Value;

            string clientAssertion = await SignClientAssertionAsync(
                requesterKeys.PrivateKey, endpointEntity.Value, issuedAt).ConfigureAwait(false);
            Uri url = new(host.HttpBaseAddress!, $"/connect/{segment}/federation_fetch");
            KeyValuePair<string, string>[] formFields =
            [
                new("sub", SubordinateEntityId),
                new(OAuthRequestParameterNames.ClientAssertionType, WellKnownClientAssertionTypes.JwtBearer),
                new(OAuthRequestParameterNames.ClientAssertion, clientAssertion)
            ];
            using System.Net.Http.HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
                host.SharedHttpClient!, url, formFields, TestContext.CancellationToken).ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
            bool isBodyVerifiedUnderAnchorKey = (int)response.StatusCode == 200
                && await Jws.VerifyAsync(
                    body, TestSetup.Base64UrlDecoder, Pool, anchorKeys.PublicKey, TestContext.CancellationToken).ConfigureAwait(false);

            return ((int)response.StatusCode, body, recorded, isResolverInvoked, isBodyVerifiedUnderAnchorKey);
        }
        finally
        {
            requesterKeys.PublicKey.Dispose();
            requesterKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// Signs a client assertion of the <c>private_key_jwt</c> shape a federation requester presents
    /// (<see href="https://openid.net/specs/openid-federation-1_0.html#section-8.8">OpenID Federation 1.0 Section
    /// 8.8</see>): <c>iss</c> and <c>sub</c> the requester, <c>aud</c> <paramref name="audience"/>, a fresh
    /// <c>jti</c>, the <c>iat</c> <paramref name="issuedAt"/> and an <c>exp</c> five minutes after it.
    /// </summary>
    /// <param name="signingKey">The requester's private signing material.</param>
    /// <param name="audience">The Entity Identifier of the endpoint's entity.</param>
    /// <param name="issuedAt">The instant the <c>iat</c> names.</param>
    /// <returns>The compact JWS.</returns>
    private async Task<string> SignClientAssertionAsync(PrivateKeyMemory signingKey, string audience, DateTimeOffset issuedAt)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeader.ForSigning(algorithm, WellKnownJwkValues.TypeJwt, "requester-signing-1");
        JwtPayload payload = new(capacity: 6)
        {
            [WellKnownJwtClaimNames.Iss] = RequesterEntityId,
            [WellKnownJwtClaimNames.Sub] = RequesterEntityId,
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.Jti] = $"federation-assertion-{Guid.NewGuid():N}",
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = issuedAt.AddMinutes(5).ToUnixTimeSeconds()
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            ClientAssertionHeaderSerializer,
            ClientAssertionPayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    private static async Task<VerifierKeyMaterial> RegisterAnchorAsync(
        TestHostShell app,
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> anchorKeys)
    {
        ImmutableHashSet<CapabilityIdentifier> capabilities = ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownFederationCapabilityIdentifiers.PublishSubordinateStatement);

        return await app.RegisterFederationCapableClientAsync(
            clientId: AnchorEntityId,
            baseUri: new Uri(AnchorEntityId),
            federationEntityId: new Uri(AnchorEntityId),
            federationSigningKeyPair: anchorKeys,
            baseCapabilities: capabilities).ConfigureAwait(false);
    }


    private async ValueTask<string> GetAsync(
        HostedAuthorizationServer host, string absolutePath, int expectedStatus, string expectedContentType)
    {
        Uri url = new(host.HttpBaseAddress!, absolutePath);
        using System.Net.Http.HttpResponseMessage response = await host.SharedHttpClient!
            .GetAsync(url, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(expectedStatus, (int)response.StatusCode,
            $"GET {absolutePath} must return {expectedStatus}. Body: {await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false)}");
        Assert.AreEqual(expectedContentType, response.Content.Headers.ContentType?.MediaType,
            $"GET {absolutePath} must serve {expectedContentType}.");

        return await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);
    }


    private static Dictionary<string, object> DecodeSegment(string compactJws, int index)
    {
        string[] parts = compactJws.Split('.');
        Assert.HasCount(3, parts, "A Subordinate Statement must be a 3-segment compact JWS.");

        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[index], Pool);

        return JsonSerializer.Deserialize<Dictionary<string, object>>(
            bytes.Memory.Span, TestSetup.DefaultSerializationOptions)
            ?? throw new InvalidOperationException("JWS segment parsed to null.");
    }
}
