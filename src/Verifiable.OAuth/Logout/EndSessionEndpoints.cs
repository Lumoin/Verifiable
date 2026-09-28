using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;

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
/// per-tenant model <c>context.ClientRegistration</c> is the client, so the same
/// record both verifies the hint (the keys it lists for ID Token issuance) and supplies the
/// allowed post-logout redirect URIs.
/// </para>
/// </remarks>
public static class EndSessionEndpoints
{
    /// <summary>
    /// The endpoint builder delegate. Pass this to
    /// <see cref="Verifiable.Server.ServerConfiguration.EndpointBuilders"/>.
    /// </summary>
    public static EndpointBuilderDelegate Builder { get; } = static (registration, context, ct) =>
    {
        List<EndpointCandidate> candidates = [];

        //Fail-closed: the endpoint must be able to verify the id_token_hint and to
        //terminate the session, so it materializes only when the capability is allowed
        //and both the verification-key resolver and the terminate seam are wired.
        EndpointServer? server = context.RequestServer;
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
                EndpointServer server = context.RequestServer!;
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

                    _ = fields.TryGetValue(OAuthRequestParameterNames.State, out string? state);
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
                    if(registration.IsCapabilityAllowed(WellKnownCapabilityIdentifiers.OidcBackChannelLogout)
                        && oauth.DeliverBackChannelLogoutAsync is not null)
                    {
                        await oauth.DeliverBackChannelLogoutAsync(
                            subject!, sessionId, registration, context, ct).ConfigureAwait(false);
                    }
                }

                //§2: redirect to the validated post_logout_redirect_uri (state echoed),
                //else answer 200 — the session is terminated either way.
                return redirectLocation is not null
                    ? (null, ServerHttpResponse.Redirect(redirectLocation))
                    : (null, ServerHttpResponse.Ok());
            },

            BuildResponse = static (state, _, _) =>
                ServerHttpResponse.ServerError(OAuthErrors.ServerError, "Not reached.")
        };


    /// <summary>
    /// Verifies the <c>id_token_hint</c> as an ID Token this AS issued — its kind, its signature
    /// under the server's ID Token signing key, and <c>iss</c> — WITHOUT enforcing <c>exp</c>
    /// (RP-Initiated Logout §3 accepts an expired hint), and extracts <c>sub</c> (required)
    /// and <c>sid</c> (optional). Returns an error response when verification fails.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <see href="https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout">RP-Initiated
    /// Logout 1.0 §2</see>: "When an id_token_hint parameter is present, the OP MUST validate that it was
    /// the issuer of the ID Token." The same issuer signs other kinds of JWT (access tokens, logout
    /// tokens, ID-JAGs), and
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see> requires
    /// "the validation rules for those JWTs MUST be written such that they are mutually exclusive,
    /// rejecting JWTs of the wrong kind." Two rules make the hint an ID Token before any key is
    /// resolved. Its <c>typ</c> is absent or <c>JWT</c>, the header the library's own ID Token carries
    /// (<see cref="JwtHeaderExtensions"/>'s <c>ForIdToken</c>), so a hint explicitly typed as another
    /// kind is refused. The <c>typ</c> is compared as the media type
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-4.1.9">RFC 7515 §4.1.9</see> makes it:
    /// "A recipient using the media type value MUST treat it as if "application/" were prepended to any
    /// "typ" value not containing a '/'.", and "Per RFC 2045 [RFC2045], all media type values, subtype
    /// values, and parameter names are case insensitive.", so <c>JWT</c>, <c>jwt</c> and
    /// <c>application/jwt</c> name the same type. Its <c>kid</c> is one the registration lists for
    /// <see cref="KeyUsageContext.IdTokenIssuance"/> (<see cref="IssuedKeyAdmission.IsListedFor"/>), so
    /// a key the resolver holds for another purpose never verifies a hint.
    /// </para>
    /// <para>
    /// The library signs an ID-JAG under the same <see cref="KeyUsageContext.IdTokenIssuance"/> key it
    /// signs ID Tokens with, so the key rule alone admits an ID-JAG's key; the <c>typ</c> rule is what
    /// separates an ID Token from an ID-JAG (typed <c>oauth-id-jag+jwt</c>). Both refusals answer one
    /// fixed description that names neither the <c>typ</c> nor the key.
    /// </para>
    /// <para>
    /// The <see cref="AuthorizationServerCryptography.VerificationKeyResolver"/> is asked for the admitted
    /// key under <see cref="KeyUsageContext.IdTokenIssuance"/>, the usage the key rule names, so a key
    /// store that keeps keys apart per kind answers only a key it holds for ID Tokens; a hint whose key the
    /// resolver does not produce for that usage is refused with a fixed description that names no key. The
    /// key rule stays the library's guarantee: the usage lets the resolver narrow what verifies, never
    /// widen it.
    /// </para>
    /// </remarks>
    private static async ValueTask<(string? Subject, string? SessionId, ServerHttpResponse? Error)> VerifyIdTokenHintAsync(
        EndpointServer server,
        ClientRecord registration,
        string idTokenHint,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        var oauth = server.OAuth();

        //A hint longer than the compact JWS the signature verification accepts
        //(Jws.DefaultMaxJwsLength) is malformed input, refused before it is parsed rather than
        //raised as an exception from that verification.
        if(idTokenHint.Length > Jws.DefaultMaxJwsLength)
        {
            return (null, null, ServerHttpResponse.BadRequest(
                OAuthErrors.InvalidRequest, "id_token_hint exceeds the longest compact JWS this server verifies."));
        }

        UnverifiedJwsMessage unverified;
        try
        {
            unverified = JwsParsing.ParseCompact(
                idTokenHint,
                oauth.Codecs.Decoder!,
                bytes => oauth.Codecs.JwtHeaderDeserializer!(bytes),
                oauth.MemoryPool!);
        }
        catch(Exception ex) when(ex is FormatException or InvalidOperationException or System.Text.Json.JsonException)
        {
            //A protected header that is not a JSON object (for example "[]") fails in the wired
            //header deserializer; the hint is malformed input, refused without ending the session.
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

            //A kid of only whitespace names no key: it is refused here as missing, so it never
            //reaches the KeyId the admission and the resolver are asked with.
            if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj)
                || kidObj is not string kid
                || string.IsNullOrWhiteSpace(kid))
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "id_token_hint header is missing kid."));
            }

            //RP-Initiated Logout 1.0 §2: the OP MUST validate that it was the issuer of the ID Token;
            //RFC 8725 §3.12: the kinds of JWT one issuer signs are told apart. A hint is an ID Token
            //only when its typ is absent or JWT (an access token, a logout token or an ID-JAG types
            //itself otherwise) and its kid is listed for ID Token issuance. The ID-JAG shares the ID
            //Token key, so the typ rule is what turns it away. Both rules run before the resolver,
            //which may answer any key it holds by kid, and share one description naming neither value.
            //The resolver is then asked under the usage the key rule names.
            bool isIdTokenType = !header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typObj)
                || (typObj is string typ && WellKnownJwkValues.IsTypeJwt(typ));
            if(!isIdTokenType
                || !IssuedKeyAdmission.IsListedFor(registration, KeyUsageContext.IdTokenIssuance, new KeyId(kid)))
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "id_token_hint is not an ID Token issued by this server."));
            }

            PublicKeyMemory? publicKey = await oauth.Cryptography.VerificationKeyResolver!(
                new KeyId(kid), KeyUsageContext.IdTokenIssuance, registration.TenantId, context, cancellationToken).ConfigureAwait(false);
            //The description is fixed: a refusal names no key the hint presented.
            if(publicKey is null)
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest, "No verification key is available for the id_token_hint."));
            }

            //RFC 7519 §4: the Claim Names within a JWT Claims Set MUST be unique. Gate the already-
            //decoded payload for well-formedness before it reaches the wired deserializer inside
            //VerifyAndDecodeAsync below, so a duplicate claim name is refused here rather than
            //escaping the deserializer as an unhandled exception.
            if(!JwkJsonReader.IsWellFormedJsonDocument(unverified.Payload.Span))
            {
                return (null, null, ServerHttpResponse.BadRequest(
                    OAuthErrors.InvalidRequest,
                    "id_token_hint payload is not well-formed JSON, or carries a duplicate claim name."));
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
                    oauth.MemoryPool!,
                    publicKey,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException or System.Text.Json.JsonException)
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
