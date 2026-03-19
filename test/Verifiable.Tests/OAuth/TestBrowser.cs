using System.Diagnostics;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Simulates the user agent (browser) in OAuth authorization flows.
/// </summary>
/// <remarks>
/// <para>
/// In a real deployment the browser follows the redirect to the authorization
/// endpoint, the user authenticates via the server's login UI, and the server
/// redirects back with an authorization code. In tests, the authentication
/// step is collapsed: the <paramref name="subjectId"/> is placed directly in
/// the request context, exactly as the ASP.NET authentication middleware would
/// do after validating the user's session cookie.
/// </para>
/// <para>
/// This type is a test-only client helper. It does not belong on the server —
/// the server never initiates browser redirects itself.
/// </para>
/// </remarks>
[DebuggerDisplay("TestBrowser")]
internal static class TestBrowser
{
    /// <summary>
    /// Follows the authorize redirect, presenting the authenticated subject
    /// to the server's authorize endpoint, and extracts the authorization code
    /// from the server's redirect response.
    /// </summary>
    /// <param name="server">The authorization server to call.</param>
    /// <param name="registration">The client registration.</param>
    /// <param name="requestUri">
    /// The <c>request_uri</c> from a prior PAR response, or <see langword="null"/>
    /// for direct authorize flows.
    /// </param>
    /// <param name="codeChallenge">
    /// The PKCE code challenge for direct authorize flows.
    /// <see langword="null"/> when using PAR (the challenge was sent in the PAR).
    /// </param>
    /// <param name="subjectId">The authenticated subject identifier.</param>
    /// <param name="issuerUri">The issuer URI for the authorization server.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The authorization code and state extracted from the redirect Location header.
    /// </returns>
    public static async Task<(string Code, string State)> FollowAuthorizeRedirectAsync(
        AuthorizationServer server,
        ClientRegistration registration,
        string? requestUri,
        string? codeChallenge,
        string subjectId,
        Uri issuerUri,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        ArgumentNullException.ThrowIfNull(issuerUri);

        RequestContext context = new();
        context.SetTenantId(registration.TenantId);
        context.SetIssuer(issuerUri);
        context.SetSubjectId(subjectId);

        RequestFields fields = new()
        {
            [OAuthRequestParameters.ClientId] = registration.ClientId
        };

        if(requestUri is not null)
        {
            fields[OAuthRequestParameters.RequestUri] = requestUri;
        }

        if(codeChallenge is not null)
        {
            fields[OAuthRequestParameters.CodeChallenge] = codeChallenge;
            fields[OAuthRequestParameters.CodeChallengeMethod] =
                OAuthRequestParameters.CodeChallengeMethodS256;
            fields[OAuthRequestParameters.Scope] = WellKnownScopes.OpenId;
            fields[OAuthRequestParameters.RedirectUri] = "https://client.example.com/callback";
            fields[WellKnownJwtClaims.Nonce] = $"nonce-{Guid.NewGuid():N}";
        }

        ServerHttpResponse response = await server.DispatchAsync(
            registration,
            ServerCapabilityName.AuthorizationCode,
            "GET",
            fields,
            context,
            cancellationToken).ConfigureAwait(false);

        if(response.StatusCode != 302)
        {
            throw new InvalidOperationException(
                $"Authorize endpoint returned {response.StatusCode}, expected 302. " +
                $"Body: {response.Body}");
        }

        string location = response.Location
            ?? throw new InvalidOperationException("Authorize response missing Location.");

        string code = ExtractQueryParam(location, "code")
            ?? throw new InvalidOperationException("Redirect Location missing code parameter.");

        string? state = ExtractQueryParam(location, "state");

        return (code, state ?? string.Empty);
    }


    /// <summary>
    /// Extracts a single query parameter value from an absolute URI string.
    /// </summary>
    public static string? ExtractQueryParam(string location, string paramName)
    {
        if(!Uri.TryCreate(location, UriKind.Absolute, out Uri? uri))
        {
            return null;
        }

        foreach(string part in uri.Query.TrimStart('?').Split('&'))
        {
            int eq = part.IndexOf('=', StringComparison.Ordinal);
            if(eq < 0)
            {
                continue;
            }

            if(string.Equals(
                Uri.UnescapeDataString(part[..eq]), paramName, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(part[(eq + 1)..]);
            }
        }

        return null;
    }
}
