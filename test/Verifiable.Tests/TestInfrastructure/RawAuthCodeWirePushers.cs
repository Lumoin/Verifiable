using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Hand-built real-wire PAR / token / authorize form pushers for the wire shapes the
/// <see cref="OAuthClient"/> abstraction cannot produce — a non-<c>S256</c>
/// <c>code_challenge_method</c>, an absent <c>redirect_uri</c> or <c>code</c> at the token
/// endpoint, and similar adversarial or off-happy-path fields. Shared by
/// <see cref="Verifiable.Tests.OAuth.RedirectUriMatchingTests"/> and
/// <see cref="Verifiable.Tests.OAuth.AuthCodeParPkceRealWireFlowTests"/> so the wire-plumbing
/// exists once.
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
        using HttpClientHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(host.ServerCertificate);
        noRedirectHandler.AllowAutoRedirect = false;
        using HttpClient browserClient = new(noRedirectHandler);
        using HttpRequestMessage request = new(HttpMethod.Get, url);
        request.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, subjectId);

        return await browserClient.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Sends a pinned JSON request over the listener without following redirects.</summary>
    /// <param name="host">The listener fixture owning the certificate.</param>
    /// <param name="url">The endpoint URI.</param>
    /// <param name="json">The complete JSON wire body.</param>
    /// <param name="cancellationToken">Cancellation of the wire exchange.</param>
    public static async Task<HttpResponseMessage> SendPinnedJsonPostAsync(
        TestHostShell host, Uri url, string json, CancellationToken cancellationToken)
    {
        using HttpClientHandler handler = LoopbackTls.CreatePinnedHandler(host.ServerCertificate);
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
    public static async Task<HttpResponseMessage> SendPinnedRegistrationAsync(
        TestHostShell host, HttpMethod method, Uri uri, string accessToken,
        string? json, CancellationToken cancellationToken)
    {
        using HttpClient client = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        using HttpRequestMessage request = new(method, uri);
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        if(json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

}
