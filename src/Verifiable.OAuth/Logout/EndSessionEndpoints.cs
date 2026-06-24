using System.Diagnostics;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Server;

namespace Verifiable.OAuth.Logout;

/// <summary>
/// Endpoint builder for OpenID Connect RP-Initiated Logout 1.0 — the
/// <c>end_session_endpoint</c> (<see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html">OIDC RP-Initiated Logout 1.0</see>).
/// Register at startup via <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
/// </summary>
/// <remarks>
/// <para>
/// The library owns the wire: it verifies the <c>id_token_hint</c> (an ID Token this AS
/// issued) to obtain the <c>sub</c>/<c>sid</c>, validates the <c>post_logout_redirect_uri</c>
/// against the client's registered set, drops out to the application's
/// <see cref="TerminateSessionDelegate"/>, and redirects (302) to the validated URI with
/// <c>state</c> echoed — or answers 200 when no redirect URI was supplied.
/// </para>
/// <para>
/// §3 also defines a sessionless path: a request may instead carry an opaque
/// <c>logout_hint</c> (no <c>id_token_hint</c>). The library does not interpret the hint;
/// it drops out to <see cref="TerminateSessionByHintDelegate"/> so the application resolves
/// it to a session. That branch is available only when the by-hint seam is wired; otherwise
/// an <c>id_token_hint</c> remains required. The <c>post_logout_redirect_uri</c> validation
/// and the 302/200 response are identical on both paths.
/// </para>
/// <para>
/// The <c>id_token_hint</c> is verified for signature and issuer but its <c>exp</c> is
/// deliberately <strong>not</strong> enforced — RP-Initiated Logout §3 expects logout to
/// work for a session whose ID Token has already expired. (Hence this does not reuse
/// <see cref="JwsAccessTokenValidator"/>, which rejects expired tokens.) In this
/// per-tenant model <see cref="ExchangeContext.Registration"/> is the client, so the same
/// record both verifies the hint (its signing key) and supplies the allowed post-logout
/// redirect URIs.
/// </para>
/// </remarks>
[DebuggerDisplay("EndSessionEndpoints")]
public static class EndSessionEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static readonly EndpointBuilderDelegate Builder = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        //Fail-closed: the endpoint must be able to verify the id_token_hint and to
        //terminate the session, so it materializes only when the capability is allowed
        //and both the verification-key resolver and the terminate seam are wired.
        EndpointServer? server = context.Server;
        if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OidcRpInitiatedLogout)
            && server?.OAuth().Cryptography.VerificationKeyResolver is not null
            && server?.OAuth().TerminateSessionAsync is not null)
        {
            candidates.Add(BuildEndSession());
        }

        return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
    };


    /// <summary>
    /// Builds the end-session endpoint candidate. Stateless GET — verify the hint,
    /// terminate, redirect; no flow state and no correlation key.
    /// </summary>
    private static EndpointCandidate BuildEndSession() =>
        new()
        {
            Name = WellKnownEndpointNames.EndSession,
            HttpMethod = WellKnownHttpMethods.Get,
            Capability = WellKnownCapabilityIdentifiers.OidcRpInitiatedLogout,
            StartsNewFlow = true,
            Kind = FlowKind.Stateless,
            DiscoveryMetadataKey = AuthorizationServerMetadataParameterNames.EndSessionEndpoint,

            MatchesRequest = static (fields, context, endpoint, ct) =>
            {
                IncomingRequest? req = context.IncomingRequest;
                if(req is null) { return ValueTask.FromResult<MatchPayload?>(null); }
                if(!WellKnownHttpMethods.IsGet(req.Method))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }
                if(!PathEquals.Equals(req.Path, endpoint.ResolvedUri.AbsolutePath))
                {
                    return ValueTask.FromResult<MatchPayload?>(null);
                }

                return ValueTask.FromResult<MatchPayload?>(MatchPayload.Empty);
            },

            BuildInputAsync = static async (fields, context, currentState, ct) =>
            {
                EndpointServer server = context.Server!;
                var oauth = server.OAuth();

                ClientRecord? registration = context.ClientRegistration;
                if(registration is null)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidClient, "Unknown client."));
                }

                //§2/§3: id_token_hint identifies the session (sub/sid) and is the
                //RECOMMENDED input. logout_hint is the sessionless alternative — an opaque,
                //app-resolved value — usable only when the application wired the by-hint
                //terminate seam. One of the two MUST be present.
                bool hasIdTokenHint = fields.TryGetValue(OAuthRequestParameterNames.IdTokenHint, out string? idTokenHint)
                    && !string.IsNullOrEmpty(idTokenHint);
                bool hasLogoutHint = fields.TryGetValue(OAuthRequestParameterNames.LogoutHint, out string? logoutHint)
                    && !string.IsNullOrEmpty(logoutHint);

                string? subject = null;
                string? sessionId = null;
                bool useLogoutHint = false;
                if(hasIdTokenHint)
                {
                    ServerHttpResponse? hintError;
                    (subject, sessionId, hintError) =
                        await VerifyIdTokenHintAsync(server, registration, idTokenHint!, context, ct)
                            .ConfigureAwait(false);
                    if(hintError is not null)
                    {
                        return (null, hintError);
                    }
                }
                else if(hasLogoutHint && oauth.TerminateSessionByHintAsync is not null)
                {
                    useLogoutHint = true;
                }
                else
                {
                    return (null, ServerHttpResponse.BadRequest(
                        OAuthErrors.InvalidRequest,
                        "id_token_hint is required (or logout_hint when the server supports sessionless logout)."));
                }

                //§2: when present, post_logout_redirect_uri MUST exact-match one the
                //client registered; an unregistered value is rejected with no redirect.
                string? redirectLocation = null;
                if(fields.TryGetValue(OAuthRequestParameterNames.PostLogoutRedirectUri, out string? postLogout)
                    && !string.IsNullOrEmpty(postLogout))
                {
                    if(!Uri.TryCreate(postLogout, UriKind.Absolute, out Uri? postLogoutUri)
                        || !registration.AllowedPostLogoutRedirectUris.Contains(postLogoutUri))
                    {
                        return (null, ServerHttpResponse.BadRequest(
                            OAuthErrors.InvalidRequest,
                            "post_logout_redirect_uri is not registered for this client."));
                    }

                    fields.TryGetValue(OAuthRequestParameterNames.State, out string? state);
                    redirectLocation = AppendState(postLogout, state);
                }

                //Drop out to the application to end the session (and revoke its tokens).
                //§3 sessionless path resolves the opaque logout_hint app-side; otherwise the
                //verified sub/sid path is used.
                if(useLogoutHint)
                {
                    await oauth.TerminateSessionByHintAsync!(
                        logoutHint!, registration, context, ct).ConfigureAwait(false);
                }
                else
                {
                    await oauth.TerminateSessionAsync!(
                        subject!, sessionId, registration, context, ct).ConfigureAwait(false);

                    //OIDC Back-Channel Logout 1.0: once the local session has ended, fan the
                    //logout out to the registered RPs. Gated identically to the discovery
                    //advertisement (capability allowed + deliver seam wired) so the OP behaves
                    //exactly as it advertises. The verified id_token_hint path is the one that
                    //carries the sub/sid the Logout Tokens are built from; the sessionless
                    //logout_hint path leaves any cascade to the app's by-hint terminate.
                    if(((ClientRecord)registration).IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OidcBackChannelLogout)
                        && oauth.DeliverBackChannelLogoutAsync is not null)
                    {
                        await oauth.DeliverBackChannelLogoutAsync(
                            subject!, sessionId, registration, context, ct).ConfigureAwait(false);
                    }
                }

                //§2: redirect to the validated post_logout_redirect_uri (state echoed),
                //else answer 200 — the session is terminated either way.
                return redirectLocation is not null
                    ? ((FlowInput?)null, ServerHttpResponse.Redirect(redirectLocation))
                    : (null, ServerHttpResponse.Ok());
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Verifies the <c>id_token_hint</c> as an ID Token this AS issued — signature (via
    /// the client's verification key) and <c>iss</c> — WITHOUT enforcing <c>exp</c>
    /// (RP-Initiated Logout §3 accepts an expired hint), and extracts <c>sub</c> (required)
    /// and <c>sid</c> (optional). Returns an error response when verification fails.
    /// </summary>
    private static async ValueTask<(string? Subject, string? SessionId, ServerHttpResponse? Error)> VerifyIdTokenHintAsync(
        EndpointServer server,
        ClientRecord registration,
        string idTokenHint,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();
        UnverifiedJwsMessage unverified;
        try
        {
            unverified = JwsParsing.ParseCompact(
                idTokenHint,
                oauth.Codecs.Decoder!,
                bytes => oauth.Codecs.JwtHeaderDeserializer!(bytes),
                BaseMemoryPool.Shared);
        }
        catch(Exception ex) when(ex is FormatException or InvalidOperationException)
        {
            return (null, null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, $"id_token_hint is malformed: {ex.Message}"));
        }

        using(unverified)
        {
            UnverifiedJwtHeader header = unverified.Signatures[0].ProtectedHeader;

            if(!header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algObj)
                || algObj is not string alg
                || string.IsNullOrEmpty(alg)
                || string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "id_token_hint header is missing or carries a forbidden alg."));
            }

            if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj)
                || kidObj is not string kid
                || string.IsNullOrEmpty(kid))
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "id_token_hint header is missing kid."));
            }

            PublicKeyMemory? publicKey = await oauth.Cryptography.VerificationKeyResolver!(
                new KeyId(kid), registration.TenantId, context, cancellationToken).ConfigureAwait(false);
            if(publicKey is null)
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, $"No verification key found for kid '{kid}'."));
            }

            //Verify AND decode in one call: the payload is read from the VERIFIED
            //result, not re-deserialized from the unverified message — the trust state
            //is carried in the type (JwsVerificationResult), not asserted by convention.
            JwsVerificationResult verification;
            try
            {
                verification = await Jws.VerifyAndDecodeAsync(
                    idTokenHint,
                    oauth.Codecs.Decoder!,
                    bytes => oauth.Codecs.JwtPayloadDeserializer!(bytes),
                    BaseMemoryPool.Shared,
                    publicKey,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, $"id_token_hint verification raised: {ex.Message}"));
            }

            if(!verification.IsValid)
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "id_token_hint signature did not verify (not issued by this server)."));
            }

            JwtPayload payload = verification.Payload;

            Uri issuerUri = oauth.ResolveIssuerAsync is not null
                ? (await oauth.ResolveIssuerAsync(registration, context, cancellationToken).ConfigureAwait(false))!
                : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken).ConfigureAwait(false);

            if(!payload.TryGetValue(WellKnownJwtClaimNames.Iss, out object? issObj)
                || issObj is not string iss
                || !string.Equals(iss, issuerUri.OriginalString, StringComparison.Ordinal))
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "id_token_hint iss does not match this Authorization Server."));
            }

            //exp is deliberately NOT checked — logout of an expired session is valid.
            if(!payload.TryGetValue(WellKnownJwtClaimNames.Sub, out object? subObj)
                || subObj is not string subject
                || string.IsNullOrEmpty(subject))
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "id_token_hint is missing the sub claim."));
            }

            string? sessionId = payload.TryGetValue(WellKnownJwtClaimNames.Sid, out object? sidObj)
                && sidObj is string sid && !string.IsNullOrEmpty(sid) ? sid : null;

            return (subject, sessionId, null);
        }
    }


    /// <summary>Appends a <c>state</c> query parameter to the post-logout redirect URI when present.</summary>
    private static string AppendState(string postLogoutRedirectUri, string? state)
    {
        if(string.IsNullOrEmpty(state))
        {
            return postLogoutRedirectUri;
        }

        char separator = postLogoutRedirectUri.Contains('?', StringComparison.Ordinal) ? '&' : '?';

        return $"{postLogoutRedirectUri}{separator}{OAuthRequestParameterNames.State}={Uri.EscapeDataString(state)}";
    }
}
