using System.Collections.Immutable;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
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
/// <see cref="LoopbackTls.CreateSingleHopPinnedHttpClient(System.Security.Cryptography.X509Certificates.X509Certificate2)"/>, or a handler from
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
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2), required when
    /// <paramref name="registration"/>'s <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>; ignored (<see langword="null"/> is
    /// the default) for every other method, none of which need a signed assertion.
    /// </param>
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
        ClientAssertionOptions? clientAssertionOptions = null,
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

        string flowId;
        ParResponse par;

        if(registration.AuthenticationMethod == ClientAuthenticationMethod.None)
        {
            //Snapshot before PAR so the newly created flow is identified by set difference —
            //this keeps the driver reusable when the same client flow store already carries
            //flows from earlier drives in the same test.
            HashSet<string> preexistingFlowIds = [.. clientFlowStore.Keys];

            OAuthFormEncodedFields parFields = ComposeParFields(scope, additionalParFields);
            AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
                registration, redirectUri, parFields, cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
                $"PAR must redirect over the real wire. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

            flowId = clientFlowStore.Keys.Single(key => !preexistingFlowIds.Contains(key));
            par = ((ParCompletedState)clientFlowStore[flowId]).Par;
        }
        else
        {
            //RFC 9126 §2: the pushed request authenticates the client exactly as the token
            //endpoint would. The OAuth client library's StartParAsync carries no per-call
            //assertion options, so a confidential registration's push goes over the raw wire
            //with its declared credentials attached, building the same PAR body and client-side
            //ParCompletedState the library itself would.
            (flowId, par) = await PushConfidentialParAsync(
                host, client, registration, clientFlowStore, tenantSegment, redirectUri,
                scope, additionalParFields, clientAssertionOptions, cancellationToken).ConfigureAwait(false);
        }

        Uri authorizeUrl = new(
            host.HttpBaseAddress,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, tenantSegment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(registration.ClientId.Value)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(par.RequestUri.ToString())}");

        using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, subjectId);

        using HttpResponseMessage authorizeResponse = await pinnedBrowserClient
            .SendAsync(authorizeRequest, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect with the authorization code.");

        return (flowId, authorizeResponse.Headers.Location!.ToString());
    }


    /// <summary>
    /// Pushes a confidential registration's PAR request over the raw wire with its declared
    /// credentials attached (<see cref="AttachConfidentialParCredentialsAsync"/>), then builds
    /// and saves the same client-side <see cref="ParCompletedState"/>
    /// <see cref="AuthCodeClient.StartParAsync(ClientRegistration, Uri, OAuthFormEncodedFields, System.Threading.CancellationToken)"/>
    /// would — the entry point for every <see cref="ClientAuthenticationMethod"/> other than
    /// <see cref="ClientAuthenticationMethod.None"/>, since that client call carries no per-call
    /// assertion options.
    /// </summary>
    private static async Task<(string FlowId, ParResponse Par)> PushConfidentialParAsync(
        HostedAuthorizationServer host,
        OAuthClient client,
        ClientRegistration registration,
        Dictionary<string, FlowState> clientFlowStore,
        string tenantSegment,
        Uri redirectUri,
        string? scope,
        OAuthFormEncodedFields additionalParFields,
        ClientAssertionOptions? clientAssertionOptions,
        CancellationToken cancellationToken)
    {
        (HttpResponseData parHttpResponse, string state, PkceParameters pkce, ImmutableArray<string> scopes, DateTimeOffset now) =
            await PushConfidentialParRequestAsync(
                host, client, registration, tenantSegment, redirectUri, scope, additionalParFields,
                clientAssertionOptions, cancellationToken).ConfigureAwait(false);

        Result<ParResponse, OAuthParseError> parResult = client.Infrastructure.ParseParResponseAsync(parHttpResponse);
        Assert.IsTrue(parResult.IsSuccess,
            $"Confidential PAR must succeed over the real wire. Status={parHttpResponse.StatusCode} Body={parHttpResponse.Body}");

        ParResponse parResponse = parResult.Value;
        ParCompletedState parCompleted = new()
        {
            FlowId = state,
            ExpectedIssuer = registration.AuthorizationServerIssuer.OriginalString,
            EnteredAt = now,
            ExpiresAt = now.AddSeconds(parResponse.ExpiresIn),
            Kind = FlowKind.AuthCodeClient,
            Pkce = pkce,
            RedirectUri = redirectUri,
            Scopes = scopes,
            Par = parResponse
        };

        await client.Infrastructure.SaveStateAsync(parCompleted, [], cancellationToken).ConfigureAwait(false);
        clientFlowStore[state] = parCompleted;

        return (state, parResponse);
    }


    /// <summary>
    /// Builds and pushes a confidential registration's raw PAR request without asserting the
    /// outcome — the entry point a test proving a PAR-level REFUSAL uses directly (a malformed or
    /// mismatched <c>private_key_jwt</c> assertion is now judged at the pushed request per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9126#section-2">RFC 9126 §2</see>, before any
    /// code can ever be issued). <see cref="PushConfidentialParAsync"/> is this method plus the
    /// success assertion and the client-side <see cref="ParCompletedState"/> bookkeeping.
    /// </summary>
    public static async Task<(HttpResponseData Response, string State, PkceParameters Pkce, ImmutableArray<string> Scopes, DateTimeOffset Now)>
        PushConfidentialParRequestAsync(
            HostedAuthorizationServer host,
            OAuthClient client,
            ClientRegistration registration,
            string tenantSegment,
            Uri redirectUri,
            string? scope,
            OAuthFormEncodedFields additionalParFields,
            ClientAssertionOptions? clientAssertionOptions,
            CancellationToken cancellationToken)
    {
        OAuthClientInfrastructure infrastructure = client.Infrastructure;
        DateTimeOffset now = infrastructure.TimeProvider.GetUtcNow();
        string state = Guid.NewGuid().ToString("N");
        PkceParameters pkce = PkceGeneration.Generate(infrastructure.Base64UrlEncoder, infrastructure.MemoryPool);

        //The effective fields are resolved through the same ComposeParFields the public path uses,
        //so the precedence is identical for both: the explicit scope argument, then a scope entry
        //in additionalParFields, then the openid default — never a confidential push silently
        //discarding a caller-supplied scope the public path would have kept.
        OAuthFormEncodedFields effectiveFields = ComposeParFields(scope, additionalParFields);
        string effectiveScope = effectiveFields.Fields.TryGetValue(
            OAuthRequestParameterNames.Scope, out string? scopeField)
            && !string.IsNullOrWhiteSpace(scopeField)
            ? scopeField
            : WellKnownScopes.OpenId;
        ImmutableArray<string> scopes = [.. effectiveScope.Split(' ', StringSplitOptions.RemoveEmptyEntries)];

        Dictionary<string, string> parFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ResponseType] = WellKnownResponseTypes.Code,
            [OAuthRequestParameterNames.ClientId] = registration.ClientId.Value,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = WellKnownCodeChallengeMethods.S256,
            [OAuthRequestParameterNames.RedirectUri] = redirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = string.Join(' ', scopes),
            [OAuthRequestParameterNames.State] = state
        };
        foreach(KeyValuePair<string, string> field in effectiveFields.Fields)
        {
            _ = parFields.TryAdd(field.Key, field.Value);
        }

        OutgoingFormFields form = new(parFields);
        ExchangeContext context = [];
        OutgoingHeaders headers = await AttachConfidentialParCredentialsAsync(
            form, registration, clientAssertionOptions, infrastructure, now, context, cancellationToken)
            .ConfigureAwait(false);

        HttpResponseData parHttpResponse = await RawAuthCodeWirePushers.PushRawParRequestAsync(
            host, tenantSegment, form, headers, cancellationToken).ConfigureAwait(false);

        return (parHttpResponse, state, pkce, scopes, now);
    }


    /// <summary>
    /// Attaches <paramref name="registration"/>'s declared confidential credentials to a raw PAR
    /// push, mirroring what the token endpoint's own client-authentication dispatch attaches for
    /// <see cref="AuthCodeClient.ExchangeTokenAsync(ClientRegistration, string, ExchangeContext, ClientAssertionOptions?, System.Threading.CancellationToken)"/>
    /// / <see cref="AuthCodeClient.RefreshAsync(ClientRegistration, RefreshTokenRequest, ExchangeContext, ClientAssertionOptions?, System.Threading.CancellationToken)"/>,
    /// built entirely from the OAuth client library's public surface
    /// (<see cref="OutgoingFormFieldsClientAuthExtensions.WithClientSecretPost"/>,
    /// <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/>,
    /// <see cref="ClientTokenEndpointAuthentication.AttachClientAssertionAsync"/>) since PAR's own
    /// client call has no such dispatch of its own.
    /// </summary>
    private static async ValueTask<OutgoingHeaders> AttachConfidentialParCredentialsAsync(
        OutgoingFormFields form,
        ClientRegistration registration,
        ClientAssertionOptions? clientAssertionOptions,
        OAuthClientInfrastructure infrastructure,
        DateTimeOffset now,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        if(registration.AuthenticationMethod == ClientAuthenticationMethod.ClientSecretPost)
        {
            PrivateKeyMemory secret = RequireAuthenticationKey(registration);
            _ = form.WithClientSecretPost(registration.ClientId.Value, secret.AsReadOnlySpan());

            return OutgoingHeaders.Empty;
        }

        if(registration.AuthenticationMethod == ClientAuthenticationMethod.ClientSecretBasic)
        {
            PrivateKeyMemory secret = RequireAuthenticationKey(registration);

            return OutgoingHeaders.Empty.WithClientSecretBasic(registration.ClientId.Value, secret.AsReadOnlySpan());
        }

        if(registration.AuthenticationMethod == ClientAuthenticationMethod.PrivateKeyJwt)
        {
            if(clientAssertionOptions is null)
            {
                throw new InvalidOperationException(
                    "ClientAuthenticationMethod.PrivateKeyJwt requires a ClientAssertionOptions instance to sign the PAR client_assertion.");
            }

            PrivateKeyMemory signingKey = RequireAuthenticationKey(registration);
            await ClientTokenEndpointAuthentication.AttachClientAssertionAsync(
                form,
                registration,
                registration.AuthorizationServerIssuer,
                signingKey,
                clientAssertionOptions.SigningKeyId,
                clientAssertionOptions.HeaderSerializer,
                clientAssertionOptions.PayloadSerializer,
                clientAssertionOptions.ClientAssertionLifetime,
                infrastructure,
                now,
                context,
                cancellationToken).ConfigureAwait(false);

            return OutgoingHeaders.Empty;
        }

        throw new NotSupportedException(
            $"Client authentication method '{registration.AuthenticationMethod}' is not supported for a raw confidential PAR push.");
    }


    /// <summary>
    /// Reads the confidential-client secret or signing key from
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/> — the same slot the token
    /// endpoint's own client-authentication dispatch reads.
    /// </summary>
    private static PrivateKeyMemory RequireAuthenticationKey(ClientRegistration registration) =>
        registration.AuthenticationKeyMaterial?.PrivateKey
        ?? throw new InvalidOperationException(
            $"ClientAuthenticationMethod.{registration.AuthenticationMethod} requires "
            + "ClientRegistration.AuthenticationKeyMaterial to carry the client secret or signing key.");


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
        ClientAssertionOptions? clientAssertionOptions = null,
        CancellationToken cancellationToken = default)
    {
        (string flowId, string authorizeLocation) = await DriveParAndAuthorizeAsync(
            host, client, registration, clientFlowStore, tenantSegment, redirectUri, subjectId,
            pinnedBrowserClient, scope, additionalParFields, clientAssertionOptions, cancellationToken).ConfigureAwait(false);

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
    /// the method — asserting every leg succeeded. The returned
    /// <see cref="AuthCodeFlowDriveResult"/> carries the issued tokens and the raw authorize
    /// redirect for the caller's own assertions.
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
    /// <param name="clientAssertionOptions">
    /// The <c>private_key_jwt</c> client-assertion signing inputs (RFC 7523 §2.2), required when
    /// <paramref name="registration"/>'s <see cref="ClientRegistration.AuthenticationMethod"/> is
    /// <see cref="ClientAuthenticationMethod.PrivateKeyJwt"/>; ignored (<see langword="null"/> is
    /// the default) for every other method, none of which need a signed assertion.
    /// </param>
    /// <param name="cancellationToken">Cancels the drive.</param>
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
            pinnedBrowserClient, scope, additionalParFields, clientAssertionOptions, cancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, [], clientAssertionOptions, cancellationToken)
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
    /// method the same way the code-exchange leg does —
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
            registration, request, [], clientAssertionOptions, cancellationToken)
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


    /// <summary>
    /// The test-side reverse of <see cref="OutgoingHeadersClientAuthExtensions.WithClientSecretBasic"/>
    /// (RFC 6749 §2.3.1): base64-decode the <c>Authorization: Basic</c> header, split the pair on the
    /// first <c>:</c> (the join character the encoder never percent-encodes into either half), and
    /// reverse <c>application/x-www-form-urlencoded</c> on each half — a <c>client_id</c> or
    /// <c>client_secret</c> containing <c>:</c>, <c>/</c>, or a space, all of which the encoder
    /// percent-escapes or <c>+</c>-encodes, would otherwise never match a naive raw comparison.
    /// </summary>
    internal static bool DecodeAndMatchBasicHeader(
        IncomingRequest? request, string expectedClientId, string expectedClientSecret)
    {
        if(request is null
            || !request.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authorizationHeader)
            || authorizationHeader is null
            || !authorizationHeader.StartsWith("Basic ", StringComparison.Ordinal))
        {
            return false;
        }

        byte[] decoded = Convert.FromBase64String(authorizationHeader["Basic ".Length..]);
        string pair = Encoding.UTF8.GetString(decoded);
        int separatorIndex = pair.IndexOf(':', StringComparison.Ordinal);
        if(separatorIndex < 0)
        {
            return false;
        }

        string decodedClientId = FormUrlDecode(pair[..separatorIndex]);
        string decodedClientSecret = FormUrlDecode(pair[(separatorIndex + 1)..]);

        return string.Equals(decodedClientId, expectedClientId, StringComparison.Ordinal)
            && string.Equals(decodedClientSecret, expectedClientSecret, StringComparison.Ordinal);
    }


    /// <summary>
    /// Reverses <c>application/x-www-form-urlencoded</c> (RFC 6749 Appendix B) on
    /// <paramref name="value"/>: <c>+</c> becomes space, then
    /// <see cref="Uri.UnescapeDataString(string)"/> resolves the remaining <c>%XX</c> triplets.
    /// </summary>
    private static string FormUrlDecode(string value) => Uri.UnescapeDataString(value.Replace('+', ' '));
}
