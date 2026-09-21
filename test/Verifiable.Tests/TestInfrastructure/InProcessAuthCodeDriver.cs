using System.Text.Json;
using Verifiable.Core;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The variation axes a PAR → Authorize → Token in-process drive needs beyond the fixed
/// <c>response_type=code</c>: the requested <c>scope</c>, an optional authentication-request
/// <c>nonce</c>, and the authorize-time context stamps (<c>sid</c>, <c>acr</c>, <c>auth_time</c>) an
/// application's authentication middleware would set — none of which have an HTTP-header carrier in
/// <see cref="AuthorizationServerHttpApplication"/>, so <see cref="InProcessAuthCodeDriver"/> stamps
/// them directly on the authorize leg's <see cref="ExchangeContext"/>.
/// <see cref="UsesRealWireTransport"/> selects whether the PAR and token legs run over the real wire
/// (through <see cref="RawAuthCodeWirePushers"/>) or in-process (through
/// <see cref="TestHostShell.DispatchAtEndpointAsync(string, string, string, RequestFields, ExchangeContext, CancellationToken)"/>)
/// — the authorize leg is always in-process either way.
/// </summary>
internal sealed record InProcessAuthCodeDriveOptions
{
    /// <summary>The space-separated scope list the PAR request declares.</summary>
    public required string Scope { get; init; }

    /// <summary>The authentication-request <c>nonce</c> PAR field, or <see langword="null"/> to omit it.</summary>
    public string? Nonce { get; init; }

    /// <summary>
    /// The authorize-time session identifier (<c>sid</c>) to stamp via <c>SetSessionId</c>, or
    /// <see langword="null"/> to leave it unset.
    /// </summary>
    public string? SessionId { get; init; }

    /// <summary>
    /// The authorize-time Authentication Context Class Reference to stamp via <c>SetAcr</c>, or
    /// <see langword="null"/> to leave it unset.
    /// </summary>
    public string? Acr { get; init; }

    /// <summary>
    /// The authorize-time authentication instant to stamp via <c>SetAuthTime</c>, or
    /// <see langword="null"/> to leave it unset.
    /// </summary>
    public DateTimeOffset? AuthTime { get; init; }

    /// <summary>
    /// When <see langword="true"/>, the PAR and token legs run over the real Kestrel wire through
    /// <see cref="RawAuthCodeWirePushers"/> instead of in-process dispatch. The authorize leg is
    /// unaffected — it is always in-process, since context stamping has no wire carrier.
    /// </summary>
    public bool UsesRealWireTransport { get; init; }
}


/// <summary>
/// The outcome of an <see cref="InProcessAuthCodeDriver.DriveAsync"/> drive: the three legs' raw
/// responses and the authorization code extracted from the authorize redirect — every value the
/// consolidated callers read from a drive today.
/// </summary>
internal sealed record InProcessAuthCodeDriveResult
{
    /// <summary>The PAR endpoint's response.</summary>
    public required ServerHttpResponse ParResponse { get; init; }

    /// <summary>The authorize endpoint's response (a 302 redirect on success).</summary>
    public required ServerHttpResponse AuthorizeResponse { get; init; }

    /// <summary>The token endpoint's response.</summary>
    public required ServerHttpResponse TokenResponse { get; init; }

    /// <summary>The authorization code extracted from <see cref="AuthorizeResponse"/>'s redirect <c>Location</c>.</summary>
    public required string Code { get; init; }
}


/// <summary>
/// The one shared PAR → Authorize → Token drive every in-process OAuth authorization_code test
/// composes: a pushed authorization request, the authorize redirect (with whatever
/// authenticated-session context the scenario needs stamped), and the token exchange. Always sends
/// <c>response_type=code</c> per
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>; every other
/// PAR/token field is fixed PKCE plumbing (<see cref="PkceGeneration"/>, S256) identical across every
/// caller, with <see cref="InProcessAuthCodeDriveOptions"/> carrying the axes that actually vary.
/// </summary>
internal static class InProcessAuthCodeDriver
{
    /// <summary>
    /// Drives PAR → Authorize → Token for <paramref name="material"/>'s registration, stamping
    /// <paramref name="subjectId"/> as the authenticated subject on the authorize leg, and returns
    /// every leg's response plus the extracted authorization code.
    /// </summary>
    /// <param name="host">The test host the drive dispatches against.</param>
    /// <param name="material">The registered client's registration and key material.</param>
    /// <param name="subjectId">The authenticated End-User subject the authorize leg stamps via <c>SetSubjectId</c>.</param>
    /// <param name="redirectUri">The redirect URI the PAR request declares.</param>
    /// <param name="options">The requested scope and the authorize-time context stamps this drive needs.</param>
    /// <param name="cancellationToken">Cancels the drive.</param>
    public static async Task<InProcessAuthCodeDriveResult> DriveAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string subjectId,
        Uri redirectUri,
        InProcessAuthCodeDriveOptions options,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(material);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentNullException.ThrowIfNull(options);

        string segment = material.Registration.TenantId.Value;
        string clientId = material.Registration.ClientId;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, TestHostShell.MemoryPool);

        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = options.Scope
        };
        if(options.Nonce is not null)
        {
            parFields[WellKnownJwtClaimNames.Nonce] = options.Nonce;
        }

        ServerHttpResponse parResponse = options.UsesRealWireTransport
            ? await PushParOverWireAsync(host, segment, parFields, cancellationToken).ConfigureAwait(false)
            : await host.DispatchAtEndpointAsync(
                segment, WellKnownEndpointNames.AuthCodePar, WellKnownHttpMethods.Post,
                new RequestFields(parFields), [], cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        string requestUri = ExtractFromBody(parResponse.Body, "request_uri");

        RequestFields authorizeFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.RequestUri] = requestUri
        };
        ExchangeContext authorizeContext = [];
        authorizeContext.SetSubjectId(subjectId);
        if(options.SessionId is not null)
        {
            authorizeContext.SetSessionId(options.SessionId);
        }

        if(options.Acr is not null)
        {
            authorizeContext.SetAcr(options.Acr);
        }

        if(options.AuthTime is DateTimeOffset authTime)
        {
            authorizeContext.SetAuthTime(authTime);
        }

        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            segment, WellKnownEndpointNames.AuthCodeAuthorize, WellKnownHttpMethods.Get,
            authorizeFields, authorizeContext, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        string code = ExtractCode(authorizeResponse.Location!);

        Dictionary<string, string> tokenFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.AuthorizationCode,
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.OriginalString
        };

        ServerHttpResponse tokenResponse = options.UsesRealWireTransport
            ? await PushTokenOverWireAsync(host, segment, tokenFields, cancellationToken).ConfigureAwait(false)
            : await host.DispatchAtEndpointAsync(
                segment, WellKnownEndpointNames.AuthCodeToken, WellKnownHttpMethods.Post,
                new RequestFields(tokenFields), [], cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        return new InProcessAuthCodeDriveResult
        {
            ParResponse = parResponse,
            AuthorizeResponse = authorizeResponse,
            TokenResponse = tokenResponse,
            Code = code
        };
    }


    /// <summary>Posts the PAR fields over the real wire and wraps the wire result as a <see cref="ServerHttpResponse"/>.</summary>
    private static async Task<ServerHttpResponse> PushParOverWireAsync(
        TestHostShell host, string segment, Dictionary<string, string> fields, CancellationToken cancellationToken)
    {
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawParFieldsAsync(
            host, segment, fields, cancellationToken).ConfigureAwait(false);

        return new ServerHttpResponse { StatusCode = statusCode, Body = body, ContentType = string.Empty };
    }


    /// <summary>Posts the token fields over the real wire and wraps the wire result as a <see cref="ServerHttpResponse"/>.</summary>
    private static async Task<ServerHttpResponse> PushTokenOverWireAsync(
        TestHostShell host, string segment, Dictionary<string, string> fields, CancellationToken cancellationToken)
    {
        (int statusCode, string body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, fields, cancellationToken).ConfigureAwait(false);

        return new ServerHttpResponse { StatusCode = statusCode, Body = body, ContentType = string.Empty };
    }


    /// <summary>Reads a named string property from a JSON response body.</summary>
    private static string ExtractFromBody(string body, string property)
    {
        using JsonDocument doc = JsonDocument.Parse(body);

        return doc.RootElement.GetProperty(property).GetString()
            ?? throw new InvalidOperationException($"Body property '{property}' was null. Body: {body}");
    }


    /// <summary>Extracts the <c>code</c> query parameter from an authorize redirect Location.</summary>
    private static string ExtractCode(string location)
    {
        int q = location.IndexOf('?', StringComparison.Ordinal);
        foreach(string pair in location[(q + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq > 0 && string.Equals(pair[..eq], OAuthRequestParameterNames.Code, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        throw new InvalidOperationException($"Authorize redirect did not carry a code parameter: {location}");
    }
}
