using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Hand-built real-wire requests to the authorization server's endpoints — PAR, token, authorize
/// and UserInfo — for wire shapes the <see cref="OAuthClient"/> abstraction cannot produce: a
/// non-<c>S256</c> <c>code_challenge_method</c>, an absent <c>redirect_uri</c> or <c>code</c> at
/// the token endpoint, a bare Authorization-header GET to UserInfo, and similar adversarial or
/// off-happy-path fields. Shared across the OAuth test tree so each raw wire request exists once
/// rather than being rebuilt per test class.
/// </summary>
internal static class RawAuthCodeWirePushers
{
    /// <summary>POSTs raw PAR form fields over the real wire, starting the HTTPS listener on first use.</summary>
    public static Task<(int StatusCode, string Body)> PushRawParFieldsAsync(
        TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields,
        CancellationToken cancellationToken) =>
        PushRawParFieldsAsync(host, segment, fields, OutgoingHeaders.Empty, cancellationToken);


    /// <summary>
    /// POSTs raw PAR form fields over the real wire, carrying <paramref name="headers"/> — the
    /// confidential-client entry point for a pushed authorization request: a registration's
    /// declared <c>token_endpoint_auth_method</c> attaches its credentials this way, since the
    /// OAuth client library's PAR leg carries no per-call assertion options.
    /// </summary>
    public static async Task<(int StatusCode, string Body)> PushRawParFieldsAsync(
        TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields,
        OutgoingHeaders headers, CancellationToken cancellationToken)
    {
        await host.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        HttpResponseData response = await PushRawParRequestAsync(
            hosted, segment, fields, headers, cancellationToken).ConfigureAwait(false);

        return (response.StatusCode, response.Body);
    }


    /// <summary>
    /// POSTs raw PAR form fields over the real wire to an already-started
    /// <paramref name="hosted"/> server, carrying <paramref name="headers"/>, and returns the
    /// full <see cref="HttpResponseData"/> — the entry point
    /// <see cref="Verifiable.Tests.TestInfrastructure.AuthCodeFlowDriver"/> uses to authenticate a
    /// confidential registration's pushed request and then parse its <c>request_uri</c> through
    /// the client infrastructure's own parser, since the OAuth client library's PAR leg carries no
    /// per-call assertion options.
    /// </summary>
    public static async Task<HttpResponseData> PushRawParRequestAsync(
        HostedAuthorizationServer hosted, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields,
        OutgoingHeaders headers, CancellationToken cancellationToken)
    {
        Uri endpoint = new(hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));

        return await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, endpoint, fields, headers, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>POSTs raw token-endpoint form fields over the real wire, with no extra headers.</summary>
    public static Task<(int StatusCode, string Body)> PushRawTokenFieldsAsync(
        TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields,
        CancellationToken cancellationToken) =>
        PushRawTokenFieldsAsync(host, segment, fields, OutgoingHeaders.Empty, cancellationToken);


    /// <summary>
    /// POSTs raw token-endpoint form fields over the real wire, carrying <paramref name="headers"/>
    /// — used for adversarial wire shapes an <see cref="OAuthClient"/> would never itself produce,
    /// such as a DPoP proof signed by a key other than the one a request's tokens are bound to.
    /// </summary>
    public static async Task<(int StatusCode, string Body)> PushRawTokenFieldsAsync(
        TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields,
        OutgoingHeaders headers, CancellationToken cancellationToken)
    {
        HostedAuthorizationServer hosted = host.Host("default");
        Uri endpoint = new(hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));

        HttpResponseData response = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, endpoint, fields, headers, cancellationToken).ConfigureAwait(false);

        return (response.StatusCode, response.Body);
    }


    /// <summary>
    /// Resolves the token endpoint's absolute URI for <paramref name="segment"/> — the RFC 9449
    /// §4.2 <c>htu</c> value a hand-built DPoP proof for a raw token-endpoint push must carry.
    /// </summary>
    public static Uri ResolveTokenEndpointUri(TestHostShell host, string segment)
    {
        HostedAuthorizationServer hosted = host.Host("default");

        return new Uri(hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment));
    }


    /// <summary>POSTs raw RFC 7662 introspection-endpoint form fields over the real wire.</summary>
    public static async Task<(int StatusCode, string Body)> PushRawIntrospectionFieldsAsync(
        TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields,
        CancellationToken cancellationToken)
    {
        HostedAuthorizationServer hosted = host.Host("default");
        Uri endpoint = new(hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeIntrospect, segment));

        HttpResponseData response = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, endpoint, fields, OutgoingHeaders.Empty, cancellationToken).ConfigureAwait(false);

        return (response.StatusCode, response.Body);
    }


    /// <summary>POSTs raw RFC 7009 revocation-endpoint form fields over the real wire.</summary>
    public static async Task<(int StatusCode, string Body)> PushRawRevocationFieldsAsync(
        TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields,
        CancellationToken cancellationToken)
    {
        HostedAuthorizationServer hosted = host.Host("default");
        Uri endpoint = new(hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeRevoke, segment));

        HttpResponseData response = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, endpoint, fields, OutgoingHeaders.Empty, cancellationToken).ConfigureAwait(false);

        return (response.StatusCode, response.Body);
    }


    /// <summary>Builds the token-endpoint form fields, omitting <c>code_verifier</c> / <c>code</c> / <c>redirect_uri</c> when their argument is <see langword="null"/>.</summary>
    public static Dictionary<string, string> BuildTokenFields(
        string clientId, string? code, string? codeVerifier, string? redirectUri)
    {
        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.ClientId] = clientId
        };

        if(code is not null)
        {
            fields[OAuthRequestParameterNames.Code] = code;
        }

        if(codeVerifier is not null)
        {
            fields[OAuthRequestParameterNames.CodeVerifier] = codeVerifier;
        }

        if(redirectUri is not null)
        {
            fields[OAuthRequestParameterNames.RedirectUri] = redirectUri;
        }

        return fields;
    }


    /// <summary>
    /// Builds refresh-grant form fields, omitting client_id when credentials in the headers
    /// identify the client or a test intentionally presents no identity.
    /// </summary>
    public static Dictionary<string, string> BuildRefreshTokenFields(string? clientId, string refreshToken)
    {
        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.RefreshToken,
            [OAuthRequestParameterNames.RefreshToken] = refreshToken
        };
        if(clientId is not null)
        {
            fields[OAuthRequestParameterNames.ClientId] = clientId;
        }

        return fields;
    }


    /// <summary>
    /// Computes BASE64URL(SHA256(ASCII(<paramref name="rawCode"/>))) through the configured
    /// crypto path. Used for the persisted authorization-code hash protecting code confidentiality
    /// under <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.5">RFC 6749 §10.5</see>,
    /// and for the S256 code challenge under
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.2">RFC 7636 §4.2</see>:
    /// "code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))".
    /// </summary>
    public static async Task<string> ComputeAuthorizationCodeHashAsync(string rawCode)
    {
        byte[] inputBytes = Encoding.ASCII.GetBytes(rawCode);
        (DigestValue digest, _) = await MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync(
            new ReadOnlySequence<byte>(inputBytes),
            WellKnownHashAlgorithms.Sha256SizeBytes,
            CryptoTags.Sha256Digest,
            BaseMemoryPool.Shared).ConfigureAwait(false);
        using(digest)
        {
            return TestSetup.Base64UrlEncoder(digest.AsReadOnlySpan());
        }
    }


    /// <summary>
    /// Sends a genuine, pinned, auto-redirect-disabled HTTPS GET carrying
    /// <see cref="AuthorizationServerHttpApplication.TestSubjectHeaderName"/> as the
    /// authenticated-session stand-in — the real-wire browser leg for entry points
    /// <see cref="AuthCodeFlowDriver"/> never drives (direct authorize, JAR-by-value, a raw
    /// PAR-completed authorize GET).
    /// </summary>
    public static async Task<HttpResponseMessage> SendPinnedNoRedirectGetAsync(
        TestHostShell host, Uri url, string subjectId, CancellationToken cancellationToken)
    {
        using SocketsHttpHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(host.ServerCertificate);
        noRedirectHandler.AllowAutoRedirect = false;
        using HttpClient browserClient = new(noRedirectHandler);
        using HttpRequestMessage request = new(HttpMethod.Get, url);
        request.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, subjectId);

        return await browserClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives a pushed authorization request followed by its browser authorize GET, both over the
    /// real wire: POSTs <paramref name="parFields"/> to the PAR endpoint exactly as given (so a
    /// caller can repeat a <c>resource</c> occurrence, or carry <c>client_id</c> and a JAR
    /// <c>request</c> instead of the loose fields), and, only when that push answers <c>201</c>,
    /// follows with the pinned no-redirect authorize GET carrying <c>client_id</c> and the returned
    /// <c>request_uri</c> as <paramref name="subjectId"/>. Shared by every real-wire row across the
    /// OAuth test tree that drives PAR followed by authorize, so the pushed-then-authorized shape
    /// exists once. Asserts nothing itself; the caller's own row asserts the returned statuses.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="clientId">The <c>client_id</c> presented at the authorize GET.</param>
    /// <param name="subjectId">The authenticated-session stand-in header value for the authorize GET.</param>
    /// <param name="parFields">The PAR endpoint's form fields, sent exactly as given.</param>
    /// <param name="cancellationToken">Cancellation of both wire exchanges.</param>
    /// <returns>The pushed request's status and body, and, when it was <c>201</c>, the authorize response's status and <c>Location</c>; otherwise a null <c>Location</c> and no authorize GET was sent.</returns>
    public static async Task<(int ParStatusCode, string ParBody, Uri? AuthorizeLocation, int AuthorizeStatusCode)> PushParAndAuthorizeAsync(
        TestHostShell host, string segment, string clientId, string subjectId,
        IReadOnlyCollection<KeyValuePair<string, string>> parFields, CancellationToken cancellationToken)
    {
        (int parStatusCode, string parBody) = await PushRawParFieldsAsync(
            host, segment, parFields, cancellationToken).ConfigureAwait(false);

        if(parStatusCode != 201)
        {
            return (parStatusCode, parBody, null, 0);
        }

        using JsonDocument parDocument = JsonDocument.Parse(parBody);
        string requestUri = parDocument.RootElement.GetProperty("request_uri").GetString()!;

        Uri authorizeUri = ComposeAuthorizeUri(host, segment,
        [
            new(OAuthRequestParameterNames.ClientId, clientId),
            new(OAuthRequestParameterNames.RequestUri, requestUri)
        ]);

        using HttpResponseMessage authorizeResponse = await SendPinnedNoRedirectGetAsync(
            host, authorizeUri, subjectId, cancellationToken).ConfigureAwait(false);

        return (parStatusCode, parBody, authorizeResponse.Headers.Location, (int)authorizeResponse.StatusCode);
    }


    /// <summary>
    /// Composes <paramref name="segment"/>'s absolute authorize-endpoint URI carrying
    /// <paramref name="query"/>, every pair escaped through <see cref="Uri.EscapeDataString(string)"/>:
    /// the direct-authorize and by-value-request-object GETs a caller sends through
    /// <see cref="SendPinnedNoRedirectGetAsync"/>, which need no PAR leg first.
    /// </summary>
    /// <param name="host">The fixture owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="query">The authorize endpoint's query parameters, in the order to compose them.</param>
    /// <returns>The absolute authorize URI.</returns>
    public static Uri ComposeAuthorizeUri(TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> query)
    {
        HostedAuthorizationServer hosted = host.Host("default");
        string path = TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment);
        string escapedQuery = string.Join('&', query.Select(
            pair => $"{Uri.EscapeDataString(pair.Key)}={Uri.EscapeDataString(pair.Value)}"));

        return new Uri(hosted.HttpBaseAddress!, $"{path}?{escapedQuery}");
    }


    /// <summary>Sends a pinned JSON request over the listener without following redirects.</summary>
    /// <param name="host">The listener fixture owning the certificate.</param>
    /// <param name="url">The endpoint URI.</param>
    /// <param name="json">The complete JSON wire body.</param>
    /// <param name="cancellationToken">Cancellation of the wire exchange.</param>
    public static async Task<HttpResponseMessage> SendPinnedJsonPostAsync(
        TestHostShell host, Uri url, string json, CancellationToken cancellationToken)
    {
        using SocketsHttpHandler handler = LoopbackTls.CreatePinnedHandler(host.ServerCertificate);
        handler.AllowAutoRedirect = false;
        using HttpClient client = new(handler);
        using HttpRequestMessage request = new(HttpMethod.Post, url)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };

        return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Sends form fields to an explicit URI through the pinned listener.</summary>
    /// <param name="host">The fixture owning the listener certificate.</param>
    /// <param name="uri">The actual target URI.</param>
    /// <param name="fields">The request form fields.</param>
    /// <param name="cancellationToken">The bounded exchange lifetime.</param>
    public static async Task<HttpResponseMessage> SendPinnedFormPostAsync(TestHostShell host, Uri uri, IReadOnlyDictionary<string, string> fields, CancellationToken cancellationToken)
    {
        using HttpClient client = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        using HttpRequestMessage request = new(HttpMethod.Post, uri) { Content = new FormUrlEncodedContent(fields) };

        return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Sends the named fixture endpoint request over its pinned listener and preserves response bytes.</summary>
    /// <param name="host">The host owning the listener.</param>
    /// <param name="segment">The tenant route segment.</param>
    /// <param name="endpointName">The endpoint whose fixture route is requested.</param>
    /// <param name="method">The HTTP request method.</param>
    /// <param name="fields">The form fields for a POST request.</param>
    /// <param name="context">Fixture input whose region value is carried by an HTTP header.</param>
    /// <param name="cancellationToken">Cancellation of the listener exchange.</param>
    public static async Task<ServerHttpResponse> PushNamedEndpointAsync(
        TestHostShell host, string segment, string endpointName, string method,
        RequestFields fields, ExchangeContext context, CancellationToken cancellationToken)
    {
        await host.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        Uri uri = new(host.Host("default").HttpBaseAddress!, TestHostShell.ComposeEndpointPath(endpointName, segment));
        using HttpClient client = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        using HttpRequestMessage request = new(new HttpMethod(method), uri);
        if(context.TryGetValue("app.region", out object? region) && region is string value)
        {
            request.Headers.Add(AuthorizationServerHttpApplication.TestRegionHeaderName, value);
        }

        if(method == "POST")
        {
            request.Content = new FormUrlEncodedContent(fields.Keys.SelectMany(key => fields.GetValues(key).Select(value => KeyValuePair.Create(key, value))));
        }

        using HttpResponseMessage response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);

        return new ServerHttpResponse
        {
            StatusCode = (int)response.StatusCode,
            Body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false),
            ContentType = response.Content.Headers.ContentType?.ToString() ?? string.Empty,
            Headers = response.Headers.ToImmutableDictionary(pair => pair.Key, pair => string.Join(",", pair.Value), StringComparer.OrdinalIgnoreCase)
        };
    }

    /// <summary>Sends an authenticated registration management operation over the pinned listener.</summary>
    /// <param name="host">The fixture owning the certificate.</param>
    /// <param name="method">The RFC 7592 management verb.</param>
    /// <param name="uri">The registration management URI.</param>
    /// <param name="accessToken">The client-held registration credential.</param>
    /// <param name="json">The complete metadata replacement for PUT, or null.</param>
    /// <param name="cancellationToken">The bounded exchange lifetime.</param>
    public static Task<HttpResponseMessage> SendPinnedRegistrationAsync(
        TestHostShell host, HttpMethod method, Uri uri, string accessToken,
        string? json, CancellationToken cancellationToken) =>
        SendPinnedRegistrationFieldAsync(
            host, method, uri, $"{WellKnownAuthenticationSchemes.Bearer} {accessToken}", json, cancellationToken);


    /// <summary>
    /// Sends a registration management operation over the pinned listener with
    /// <paramref name="authorization"/> as the whole value of its <c>Authorization</c> field, sent as
    /// written, or with no such field when it is <see langword="null"/>.
    /// </summary>
    /// <param name="host">The fixture owning the certificate.</param>
    /// <param name="method">The RFC 7592 management verb.</param>
    /// <param name="uri">The registration management URI.</param>
    /// <param name="authorization">The <c>Authorization</c> field value, or <see langword="null"/> for none.</param>
    /// <param name="json">The complete metadata replacement for PUT, or null.</param>
    /// <param name="cancellationToken">The bounded exchange lifetime.</param>
    public static async Task<HttpResponseMessage> SendPinnedRegistrationFieldAsync(
        TestHostShell host, HttpMethod method, Uri uri, string? authorization,
        string? json, CancellationToken cancellationToken)
    {
        using HttpClient client = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        using HttpRequestMessage request = new(method, uri);
        if(authorization is not null)
        {
            _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, authorization);
        }

        if(json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers a managed client through the host's global registration endpoint over the listener,
    /// asserts the 201 and that no request fault was captured, and reads the client-held credential and
    /// the client configuration URI from the response.
    /// </summary>
    /// <param name="host">The serving fixture; its default host's listener is started.</param>
    /// <param name="cancellationToken">The bounded exchange lifetime.</param>
    /// <returns>The issued client identifier, the registration access token and the client configuration URI.</returns>
    public static async Task<(string ClientId, string AccessToken, Uri ManagementUri)> RegisterManagedClientAsync(
        TestHostShell host, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendPinnedJsonPostAsync(host,
            new Uri(host.Host("default").HttpBaseAddress!, "/connect/register"),
            "{\"client_name\":\"initial-client\",\"client_uri\":\"https://client.example.test/\",\"redirect_uris\":[\"https://client.example.test/callback\"],\"scope\":\"initial-scope\"}", cancellationToken).ConfigureAwait(false);
        Exception[] faults = host.Host("default").ConsumeHttpFaults();
        Assert.AreEqual(201, (int)response.StatusCode, "A committed registration must return HTTP 201.");
        Assert.IsEmpty(faults, "Successful registration must have no unconsumed request faults.");
        using JsonDocument body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false));

        return (body.RootElement.GetProperty("client_id").GetString()!,
            body.RootElement.GetProperty("registration_access_token").GetString()!,
            new Uri(body.RootElement.GetProperty("registration_client_uri").GetString()!, UriKind.Absolute));
    }


    /// <summary>
    /// The issuer the application's issuer resolver names for the client configuration rows of the clients
    /// <see cref="RegisterManagedClientAsync"/> registers: a dynamically registered client carries no issuer of its
    /// own and the request context the listener builds carries none, so the realm of the endpoint's challenges is
    /// the application's configuration, wired through <see cref="TestHostShell.NameIssuerAsync"/>.
    /// </summary>
    public static Uri ManagedClientIssuer { get; } = new("https://registration.issuer.test/");


    /// <summary>Every <c>WWW-Authenticate</c> field value of <paramref name="response"/>, read as sent; empty when it carries none.</summary>
    /// <param name="response">The wire response.</param>
    /// <returns>The field values.</returns>
    public static IReadOnlyList<string> ChallengesOf(HttpResponseMessage response) =>
        response.Headers.NonValidated.TryGetValues(WellKnownHttpHeaderNames.WwwAuthenticate, out System.Net.Http.Headers.HeaderStringValues values)
            ? [.. values]
            : [];


    /// <summary>
    /// The URL of <paramref name="material"/>'s UserInfo endpoint on the host's loopback HTTPS listener,
    /// starting the listener when it is not yet running.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose UserInfo path is addressed.</param>
    /// <param name="cancellationToken">Cancellation of the listener start.</param>
    /// <returns>The absolute UserInfo URL.</returns>
    public static async Task<Uri> ResolveUserInfoUriAsync(
        TestHostShell host, VerifierKeyMaterial material, CancellationToken cancellationToken)
    {
        await host.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);

        return new Uri(host.Host("default").HttpBaseAddress!,
            TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.UserInfo, material.Registration.TenantId.Value));
    }


    /// <summary>
    /// Sends a request to <paramref name="material"/>'s UserInfo endpoint over the host's loopback HTTPS
    /// listener with <paramref name="accessToken"/> in the <c>Authorization</c> header under
    /// <paramref name="scheme"/> and, when given, <paramref name="dpopProof"/> in the <c>DPoP</c> header,
    /// so the request, its headers and the response's headers cross the real transport. Shared by every
    /// test class that presents a token at UserInfo, so the wire request exists once.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose UserInfo path is addressed.</param>
    /// <param name="accessToken">The access token presented.</param>
    /// <param name="scheme">The <c>Authorization</c> scheme the token is presented under.</param>
    /// <param name="dpopProof">The DPoP proof, or <see langword="null"/> to send no <c>DPoP</c> header.</param>
    /// <param name="httpMethod">The request method, or <see langword="null"/> for POST.</param>
    /// <param name="cancellationToken">Cancellation of the wire exchange.</param>
    /// <returns>The wire response; the caller disposes it.</returns>
    public static async Task<HttpResponseMessage> SendUserInfoRequestAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string accessToken,
        string scheme,
        string? dpopProof,
        HttpMethod? httpMethod,
        CancellationToken cancellationToken)
    {
        Uri userInfoUrl = await ResolveUserInfoUriAsync(host, material, cancellationToken).ConfigureAwait(false);
        using HttpRequestMessage request = new(httpMethod ?? HttpMethod.Post, userInfoUrl);
        _ = request.Headers.TryAddWithoutValidation("Authorization", $"{scheme} {accessToken}");
        if(dpopProof is not null)
        {
            _ = request.Headers.TryAddWithoutValidation("DPoP", dpopProof);
        }

        return await host.Host("default").SharedHttpClient!.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }
}
