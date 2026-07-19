using System.Net.Http;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Tests.OAuth;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The outcome of a full <see cref="AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync"/>
/// drive: the client-side flow identifier, the raw authorize redirect <c>Location</c> (so callers
/// can assert RFC 9207 <c>iss</c> byte-exactness and other redirect parameters), and the
/// token-endpoint result whose <see cref="AuthCodeFlowEndpointResult.Body"/> carries the issued
/// tokens.
/// </summary>
internal sealed record AuthCodeFlowDriveResult
{
    /// <summary>The client-side flow identifier the drive created.</summary>
    public required string FlowId { get; init; }

    /// <summary>The raw authorize redirect <c>Location</c> header value.</summary>
    public required string AuthorizeLocation { get; init; }

    /// <summary>
    /// The token-endpoint result; <see cref="AuthCodeFlowEndpointResult.Body"/> carries the
    /// issued tokens (access token, and the OIDC <c>id_token</c> when the granted scopes
    /// include <c>openid</c>).
    /// </summary>
    public required AuthCodeFlowEndpointResult TokenResult { get; init; }
}


/// <summary>
/// The one shared real-wire authorization-code drive every suite can compose:
/// PAR → authorize → callback → token against a <see cref="TestHostShell"/>-hosted
/// <see cref="HostedAuthorizationServer"/>. The PAR, callback, and token legs go through the real
/// <see cref="OAuthClient"/> surface (<see cref="AuthCodeClient.StartParAsync(ClientRegistration, Uri, OAuthFormEncodedFields, System.Threading.CancellationToken)"/>,
/// <see cref="AuthCodeClient.HandleCallbackAsync(ClientRegistration, OAuthFormEncodedFields, System.Threading.CancellationToken)"/>,
/// <see cref="AuthCodeClient.ExchangeTokenAsync(ClientRegistration, string, System.Threading.CancellationToken)"/>);
/// the authorize hop is a raw pinned GET carrying
/// <see cref="AuthorizationServerHttpApplication.TestSubjectHeaderName"/> as the
/// authenticated-session stand-in, with the redirect read via
/// <see cref="TestBrowser.ExtractQueryParam"/> rather than followed.
/// </summary>
/// <remarks>
/// The supplied browser <see cref="HttpClient"/> must pin the target host's exact certificate and
/// must have auto-redirect DISABLED (for example
/// <see cref="LoopbackTls.CreateSingleHopPinnedHttpClient"/>, or a handler from
/// <see cref="LoopbackTls.CreatePinnedHandler(IReadOnlyCollection{System.Security.Cryptography.X509Certificates.X509Certificate2})"/>
/// with <see cref="HttpClientHandler.AllowAutoRedirect"/> set to <see langword="false"/>): the
/// driver asserts the authorize 302 itself, so the framework must never silently follow the
/// <c>Location</c> to the client's (non-resolvable) redirect URI. A single multi-pinned client can
/// drive flows against several hosts with distinct TLS identities
/// (<see cref="TestHostShell.AddHost(string, bool)"/>) because the authorize URL is composed
/// absolute from the target host's <see cref="HostedAuthorizationServer.HttpBaseAddress"/>.
/// </remarks>
internal static class AuthCodeFlowDriver
{
    /// <summary>
    /// Drives PAR (a real wire POST through <paramref name="client"/>) and the browser's authorize
    /// GET (a real wire GET on <paramref name="pinnedBrowserClient"/> with the test subject header
    /// standing in for an authenticated session), returning the flow identifier and the raw
    /// redirect <c>Location</c> for the caller to inspect.
    /// </summary>
    /// <param name="host">The target host; its HTTPS listener must already be started.</param>
    /// <param name="client">The OAuth client whose infrastructure posts to the host's real wire.</param>
    /// <param name="registration">The client-side registration the flow runs under.</param>
    /// <param name="clientFlowStore">The client-side flow store the <paramref name="client"/>'s infrastructure saves state into.</param>
    /// <param name="tenantSegment">The server-side tenant segment routing the authorize URL (<see cref="TestHostShell.ComposeEndpointPath"/>).</param>
    /// <param name="redirectUri">The redirect URI the PAR request declares.</param>
    /// <param name="subjectId">The authenticated subject the authorize hop asserts via <see cref="AuthorizationServerHttpApplication.TestSubjectHeaderName"/>.</param>
    /// <param name="pinnedBrowserClient">The pinned, auto-redirect-disabled client the authorize GET rides on.</param>
    /// <param name="scope">The space-separated scope list to request, or <see langword="null"/> to request none.</param>
    /// <param name="additionalParFields">Further PAR form fields (resource indicators, authorization_details, ...).</param>
    /// <param name="cancellationToken">Cancels the drive.</param>
    public static async Task<(string FlowId, string AuthorizeLocation)> DriveParAndAuthorizeAsync(
        HostedAuthorizationServer host,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string tenantSegment,
        Uri redirectUri,
        string subjectId,
        HttpClient pinnedBrowserClient,
        string? scope = null,
        OAuthFormEncodedFields additionalParFields = default,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(host);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(clientFlowStore);
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantSegment);
        ArgumentNullException.ThrowIfNull(redirectUri);
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        ArgumentNullException.ThrowIfNull(pinnedBrowserClient);

        if(host.HttpBaseAddress is null)
        {
            throw new InvalidOperationException(
                $"Host '{host.Name}' has no HTTPS listener. Start it via TestHostShell.StartHttpHostAsync before driving a flow.");
        }

        //Snapshot before PAR so the newly created flow is identified by set difference —
        //this keeps the driver reusable when the same client flow store already carries
        //flows from earlier drives in the same test.
        HashSet<string> preexistingFlowIds = [.. clientFlowStore.Keys];

        OAuthFormEncodedFields parFields = ComposeParFields(scope, additionalParFields);
        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, redirectUri, parFields, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect over the real wire. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single(key => !preexistingFlowIds.Contains(key));
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];

        Uri authorizeUrl = new(
            host.HttpBaseAddress,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, tenantSegment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(registration.ClientId.Value)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(parState.Par.RequestUri.ToString())}");

        using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, subjectId);

        using HttpResponseMessage authorizeResponse = await pinnedBrowserClient
            .SendAsync(authorizeRequest, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect with the authorization code.");

        return (flowId, authorizeResponse.Headers.Location!.ToString());
    }


    /// <summary>
    /// <see cref="DriveParAndAuthorizeAsync"/> plus the client-local callback state transition
    /// (echoing <c>code</c>, <c>state</c>, and — when present — the RFC 9207 <c>iss</c> parameter
    /// back through <see cref="AuthCodeClient.HandleCallbackAsync(ClientRegistration, OAuthFormEncodedFields, System.Threading.CancellationToken)"/>),
    /// returning the flow identifier ready for token exchange together with the raw authorize
    /// redirect <c>Location</c>.
    /// </summary>
    public static async Task<(string FlowId, string AuthorizeLocation)> DriveParAuthorizeAndCallbackAsync(
        HostedAuthorizationServer host,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string tenantSegment,
        Uri redirectUri,
        string subjectId,
        HttpClient pinnedBrowserClient,
        string? scope = null,
        OAuthFormEncodedFields additionalParFields = default,
        CancellationToken cancellationToken = default)
    {
        (string flowId, string authorizeLocation) = await DriveParAndAuthorizeAsync(
            host, client, registration, clientFlowStore, tenantSegment, redirectUri, subjectId,
            pinnedBrowserClient, scope, additionalParFields, cancellationToken).ConfigureAwait(false);

        string code = TestBrowser.ExtractQueryParam(authorizeLocation, OAuthRequestParameterNames.Code)
            ?? throw new InvalidOperationException("Authorize redirect Location missing code.");
        string? issuerParameter = TestBrowser.ExtractQueryParam(authorizeLocation, OAuthRequestParameterNames.Iss);

        Dictionary<string, string> callbackFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.State] = flowId
        };
        if(issuerParameter is not null)
        {
            callbackFields[OAuthRequestParameterNames.Iss] = issuerParameter;
        }

        AuthCodeFlowEndpointResult callbackResult = await client.AuthCode.HandleCallbackAsync(
            registration, new OAuthFormEncodedFields(callbackFields), cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed. ErrorCode={callbackResult.ErrorCode} ErrorDescription={callbackResult.ErrorDescription}");

        return (flowId, authorizeLocation);
    }


    /// <summary>
    /// The complete PAR → authorize → callback → token drive:
    /// <see cref="DriveParAuthorizeAndCallbackAsync"/> followed by the token exchange through
    /// <see cref="AuthCodeClient.ExchangeTokenAsync(ClientRegistration, string, ExchangeContext, ClientAssertionOptions?, System.Threading.CancellationToken)"/>
    /// — the one real-client entry point for every declared
    /// <see cref="ClientRegistration.AuthenticationMethod"/>, since the client itself dispatches on
    /// the method (contract wave-4 D6) — asserting every leg succeeded. The returned
    /// <see cref="AuthCodeFlowDriveResult"/> carries the issued tokens and the raw authorize
    /// redirect for the caller's own assertions.
    /// </summary>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2), required when
    /// <paramref name="registration"/>'s <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>; ignored (<see langword="null"/> is
    /// the default) for every other method, none of which need a signed assertion.
    /// </param>
    public static async Task<AuthCodeFlowDriveResult> DriveParAuthorizeCallbackAndTokenAsync(
        HostedAuthorizationServer host,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string tenantSegment,
        Uri redirectUri,
        string subjectId,
        HttpClient pinnedBrowserClient,
        string? scope = null,
        OAuthFormEncodedFields additionalParFields = default,
        ClientAssertionOptions? clientAssertionOptions = null,
        CancellationToken cancellationToken = default)
    {
        (string flowId, string authorizeLocation) = await DriveParAuthorizeAndCallbackAsync(
            host, client, registration, clientFlowStore, tenantSegment, redirectUri, subjectId,
            pinnedBrowserClient, scope, additionalParFields, cancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, new ExchangeContext(), clientAssertionOptions, cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token exchange must succeed over the real wire. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");

        return new AuthCodeFlowDriveResult
        {
            FlowId = flowId,
            AuthorizeLocation = authorizeLocation,
            TokenResult = tokenResult
        };
    }


    /// <summary>
    /// Refreshes an access token through the real <see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, ExchangeContext, ClientAssertionOptions?, System.Threading.CancellationToken)"/>
    /// entry point — the one real-client path for every declared
    /// <see cref="ClientRegistration.AuthenticationMethod"/>, since the client itself dispatches on the
    /// method the same way the code-exchange leg does (contract wave-4 D6, item 2's refresh mirror) —
    /// asserting the refresh succeeded over the real wire.
    /// </summary>
    /// <param name="client">The OAuth client whose infrastructure posts to the host's real wire.</param>
    /// <param name="registration">The client-side registration the refresh runs under.</param>
    /// <param name="request">The refresh token request.</param>
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2), required when
    /// <paramref name="registration"/>'s <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>; ignored (<see langword="null"/> is the
    /// default) for every other method, none of which need a signed assertion.
    /// </param>
    /// <param name="cancellationToken">Cancels the drive.</param>
    public static async Task<AuthCodeFlowEndpointResult> DriveRefreshAsync(
        OAuthClient client,
        ClientRegistration registration,
        RefreshTokenRequest request,
        ClientAssertionOptions? clientAssertionOptions = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(request);

        AuthCodeFlowEndpointResult refreshResult = await client.AuthCode.RefreshAsync(
            registration, request, new ExchangeContext(), clientAssertionOptions, cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
            $"Refresh must succeed over the real wire. ErrorCode={refreshResult.ErrorCode} ErrorDescription={refreshResult.ErrorDescription}");

        return refreshResult;
    }


    /// <summary>
    /// Composes the effective PAR form fields: <paramref name="additionalParFields"/> with the
    /// <c>scope</c> parameter merged in when <paramref name="scope"/> is non-null. An explicit
    /// <c>scope</c> argument wins over a <c>scope</c> entry in the additional fields.
    /// </summary>
    private static OAuthFormEncodedFields ComposeParFields(string? scope, OAuthFormEncodedFields additionalParFields)
    {
        if(scope is null)
        {
            return additionalParFields;
        }

        Dictionary<string, string> merged = new(additionalParFields.Fields, StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Scope] = scope
        };

        return new OAuthFormEncodedFields(merged);
    }
}
