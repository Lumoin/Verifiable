using System.Buffers;
using System.Text;
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
    public static async Task<(int StatusCode, string Body)> PushRawParFieldsAsync(
        TestHostShell host, string segment, IReadOnlyCollection<KeyValuePair<string, string>> fields,
        CancellationToken cancellationToken)
    {
        await host.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer hosted = host.Host("default");
        Uri endpoint = new(hosted.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodePar, segment));

        HttpResponseData response = await HttpClientTransport.SendFormPostAsync(
            hosted.SharedHttpClient!, endpoint, fields, OutgoingHeaders.Empty, cancellationToken).ConfigureAwait(false);

        return (response.StatusCode, response.Body);
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
    /// Computes the SHA-256 base64url digest of <paramref name="rawCode"/> through the project's
    /// own crypto path — the same value <c>ServerCodeIssuedState.CodeHash</c> stores for a code
    /// issued with this raw value (RFC 6749 §10.5: the code at rest is a hash, never the wire
    /// secret). Lets a test predict or reconstruct the persisted hash without a back door into
    /// the host's internal index.
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
}
