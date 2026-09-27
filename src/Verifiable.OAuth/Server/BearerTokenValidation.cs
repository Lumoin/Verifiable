using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.Server.Pipeline;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Validates a bearer access token presented to a protected endpoint per
/// <see href="https://www.rfc-editor.org/rfc/rfc6750">RFC 6750</see>. The token must be a
/// compact JWS this Authorization Server issued — its <c>iss</c> claim matches the resolved
/// issuer URI and it is unexpired.
/// </summary>
/// <remarks>
/// <para>
/// Both the OIDC Core §5.3 UserInfo endpoint and the OID4VCI 1.0 §8 Credential Endpoint are
/// protected resources that accept an AS-issued access token on the <c>Authorization</c>
/// header; the structural-parse → <c>alg</c>/<c>typ</c>/<c>kid</c> → key-resolve →
/// signature-verify → <c>iss</c> → <c>exp</c> sequence is identical and lives here once so the
/// security-critical validation cannot drift between call sites. Scope and subject-claim
/// requirements are endpoint-specific and stay at the caller (UserInfo enforces <c>openid</c>
/// per §5.3.1).
/// </para>
/// <para>
/// The overload without <c>expectedAudience</c>
/// (<see cref="ValidateAsync(string, EndpointServer, ClientRecord, ExchangeContext, CancellationToken)"/>)
/// does not check the <c>aud</c> claim: a protected resource that accepts any AS-issued access token
/// whose <c>iss</c> matches the resolved issuer calls it directly. A resource server that fronts one
/// identified resource calls the
/// <see cref="ValidateAsync(string, string, EndpointServer, ClientRecord, ExchangeContext, CancellationToken)"/>
/// overload instead, which additionally requires the token's <c>aud</c> claim to contain that
/// resource's identifier per
/// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see>.
/// </para>
/// </remarks>
public static class BearerTokenValidation
{
    /// <summary>
    /// Parses the <c>Authorization</c> header and extracts the bearer token,
    /// rejecting missing / non-Bearer / empty-payload presentations.
    /// </summary>
    /// <param name="context">The per-request context carrying the inbound request.</param>
    /// <param name="bearerToken">The extracted token, or <see langword="null"/> when absent or malformed.</param>
    /// <returns><see langword="true"/> when a well-formed Bearer token was present.</returns>
    public static bool TryExtractBearer(ExchangeContext context, out string? bearerToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        bearerToken = null;
        IncomingRequest? req = context.IncomingRequest;
        string bearerPrefix = WellKnownAuthenticationSchemes.Bearer + " ";

        if(req is null
            || !req.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authHeader)
            || authHeader is null
            || !authHeader.StartsWith(bearerPrefix, StringComparison.Ordinal)
            || authHeader.Length <= bearerPrefix.Length)
        {
            return false;
        }

        bearerToken = authHeader[bearerPrefix.Length..];

        return true;
    }


    /// <summary>
    /// Parses the <c>Authorization</c> header for an access token under EITHER the <c>Bearer</c>
    /// (RFC 6750) or the <c>DPoP</c> (RFC 9449 §7.1) scheme, reporting which scheme carried it.
    /// A sender-constrained token is presented under the <c>DPoP</c> scheme alongside a
    /// <c>DPoP</c> proof header, so a protected resource that honors the binding must accept that
    /// scheme; the <paramref name="isDpopPresentation"/> flag lets the caller reject a
    /// DPoP-bound token presented (downgraded) under <c>Bearer</c>.
    /// </summary>
    /// <param name="context">The per-request context carrying the inbound request.</param>
    /// <param name="accessToken">The extracted token, or <see langword="null"/> when absent or malformed.</param>
    /// <param name="isDpopPresentation"><see langword="true"/> when the token was presented under the <c>DPoP</c> scheme.</param>
    /// <returns><see langword="true"/> when a well-formed token under either scheme was present.</returns>
    public static bool TryExtractAccessToken(
        ExchangeContext context, out string? accessToken, out bool isDpopPresentation)
    {
        ArgumentNullException.ThrowIfNull(context);

        accessToken = null;
        isDpopPresentation = false;

        IncomingRequest? req = context.IncomingRequest;
        if(req is null
            || !req.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authHeader)
            || authHeader is null)
        {
            return false;
        }

        string dpopPrefix = WellKnownAuthenticationSchemes.DPoP + " ";
        if(authHeader.StartsWith(dpopPrefix, StringComparison.Ordinal)
            && authHeader.Length > dpopPrefix.Length)
        {
            accessToken = authHeader[dpopPrefix.Length..];
            isDpopPresentation = true;

            return true;
        }

        string bearerPrefix = WellKnownAuthenticationSchemes.Bearer + " ";
        if(authHeader.StartsWith(bearerPrefix, StringComparison.Ordinal)
            && authHeader.Length > bearerPrefix.Length)
        {
            accessToken = authHeader[bearerPrefix.Length..];

            return true;
        }

        return false;
    }


    /// <summary>
    /// Validates the structure, signature, issuer, and expiry of a bearer access token. Composes
    /// against <see cref="JwsParsing.ParseCompact"/>,
    /// <see cref="Jws.VerifyAsync(string, DecodeDelegate, BaseMemoryPool, PublicKeyMemory, CancellationToken)"/>,
    /// and the AS's wired <see cref="AuthorizationServerCryptography.VerificationKeyResolver"/> /
    /// <see cref="AuthorizationServerCodecs.JwtPayloadDeserializer"/>. Does not check the audience;
    /// see the <see cref="ValidateAsync(string, string, EndpointServer, ClientRecord, ExchangeContext, CancellationToken)"/>
    /// overload for a caller that must bind the token to one resource identifier.
    /// </summary>
    /// <param name="bearerToken">The compact-JWS access token, exactly as presented on the wire.</param>
    /// <param name="server">The authorization server holding codecs, cryptography, and integration delegates.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The validated <see cref="JwtPayload"/> and a <see langword="null"/> failure on success;
    /// a <see langword="null"/> payload and the RFC 6750 error response on failure.
    /// </returns>
    public static ValueTask<(JwtPayload? Payload, ServerHttpResponse? Failure)> ValidateAsync(
        string bearerToken,
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        ValidateCoreAsync(bearerToken, expectedAudience: null, server, registration, context, cancellationToken);


    /// <summary>
    /// Validates a bearer access token exactly as
    /// <see cref="ValidateAsync(string, EndpointServer, ClientRecord, ExchangeContext, CancellationToken)"/>
    /// does, and additionally requires the token's <c>aud</c> claim to contain
    /// <paramref name="expectedAudience"/>, the resource-indicator binding
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 §4</see> requires: "The
    /// resource server MUST validate that the "aud" claim contains a resource indicator value
    /// corresponding to an identifier the resource server expects for itself. The JWT access token
    /// MUST be rejected if "aud" does not contain a resource indicator of the current resource server
    /// as a valid audience." A refusal is reported as the same section requires: "The resource server
    /// MUST handle errors as described in Section 3.1 of [RFC6750]. In particular, in case of any
    /// failure in the validation checks listed above, the authorization server response MUST include
    /// the error code "invalid_token"." A resource server that fronts one identified resource calls
    /// this overload, so a token minted for another resource is refused before the caller judges any
    /// scope.
    /// </summary>
    /// <param name="bearerToken">The compact-JWS access token, exactly as presented on the wire.</param>
    /// <param name="expectedAudience">
    /// The identifier of the resource the caller fronts; the token is admitted only when its
    /// well-formed <c>aud</c> claim, a string or an array of strings, holds an entry equal to it under
    /// ordinal comparison.
    /// </param>
    /// <param name="server">The authorization server holding codecs, cryptography, and integration delegates.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The validated <see cref="JwtPayload"/> and a <see langword="null"/> failure on success;
    /// a <see langword="null"/> payload and the RFC 6750 / RFC 9068 error response on failure.
    /// </returns>
    /// <remarks>
    /// The comparison is exact-string: each <c>aud</c> entry is compared with
    /// <paramref name="expectedAudience"/> ordinally, with no case folding and no URI normalisation, so
    /// an identifier that differs only in the letter case of its host, in a trailing slash or in a
    /// written-out default port is another audience and the token is refused. RFC 9068 §4 asks for
    /// "an identifier the resource server expects for itself"; that identifier is the one string the
    /// resource server is configured with, and the <c>aud</c> entry is the string the client presented
    /// as its resource indicator, so the two are compared as those strings.
    /// </remarks>
    public static ValueTask<(JwtPayload? Payload, ServerHttpResponse? Failure)> ValidateAsync(
        string bearerToken,
        string expectedAudience,
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(expectedAudience);

        return ValidateCoreAsync(bearerToken, expectedAudience, server, registration, context, cancellationToken);
    }


    /// <summary>
    /// The shared validation body both <see cref="ValidateAsync(string, EndpointServer, ClientRecord, ExchangeContext, CancellationToken)"/>
    /// and its audience-checking overload run, so the structural-parse → signature → <c>iss</c> →
    /// (optional) <c>aud</c> → <c>exp</c> sequence cannot drift between the two call shapes.
    /// </summary>
    /// <param name="bearerToken">The compact-JWS access token, exactly as presented on the wire.</param>
    /// <param name="expectedAudience">
    /// The resource identifier the <c>aud</c> claim must contain, or <see langword="null"/> to skip
    /// the audience check (the plain <see cref="ValidateAsync(string, EndpointServer, ClientRecord, ExchangeContext, CancellationToken)"/> shape).
    /// </param>
    /// <param name="server">The authorization server holding codecs, cryptography, and integration delegates.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The validated <see cref="JwtPayload"/> and a <see langword="null"/> failure on success;
    /// a <see langword="null"/> payload and the RFC 6750 / RFC 9068 error response on failure.
    /// </returns>
    private static async ValueTask<(JwtPayload? Payload, ServerHttpResponse? Failure)> ValidateCoreAsync(
        string bearerToken,
        string? expectedAudience,
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrEmpty(bearerToken);
        ArgumentNullException.ThrowIfNull(server);
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        var oauth = server.OAuth();

        if(oauth.Codecs.JwtHeaderDeserializer is null
            || oauth.Codecs.JwtPayloadDeserializer is null
            || oauth.Codecs.Decoder is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "AuthorizationServerCodecs is not fully configured for bearer-token validation."));
        }

        if(oauth.Cryptography.VerificationKeyResolver is null)
        {
            return (null, ServerHttpResponse.ServerError(
                OAuthErrors.ServerError,
                "AuthorizationServerCryptography.VerificationKeyResolver is not configured."));
        }

        //1. Structural parse — three base64url-separated parts, header is
        //   well-formed JSON.
        UnverifiedJwsMessage unverified;
        try
        {
            unverified = JwsParsing.ParseCompact(
                bearerToken,
                oauth.Codecs.Decoder,
                bytes => oauth.Codecs.JwtHeaderDeserializer(bytes),
                oauth.MemoryPool!);
        }
        catch(Exception ex) when(ex is FormatException or InvalidOperationException)
        {
            return (null, ServerHttpResponse.Unauthorized(
                OAuthErrors.InvalidToken,
                $"Access token is malformed: {ex.Message}"));
        }

        using(unverified)
        {
            //2. kid + alg from protected header. alg=none is rejected per
            //   RFC 8725 §3.1.
            UnverifiedJwtHeader header = unverified.Signatures[0].ProtectedHeader;

            if(!header.TryGetValue(WellKnownJwkMemberNames.Alg, out object? algObj)
                || algObj is not string alg
                || string.IsNullOrEmpty(alg)
                || string.Equals(alg, "none", StringComparison.OrdinalIgnoreCase))
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token header is missing or carries a forbidden alg."));
            }

            if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj)
                || kidObj is not string kid
                || string.IsNullOrEmpty(kid))
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token header is missing kid."));
            }

            //RFC 9068 §4 requires the resource server to verify the header's typ is explicitly
            //"at+jwt" or "application/at+jwt" and reject any other value, distinguishing an
            //access token from an ID Token or other JWT profile presented at this endpoint.
            //Comparison is case-insensitive per RFC 7515 §4.1.9 (media type values are case
            //insensitive per RFC 2045), matching the existing WellKnownMediaTypes helpers.
            if(!header.TryGetValue(WellKnownJoseHeaderNames.Typ, out object? typObj)
                || typObj is not string typ
                || string.IsNullOrEmpty(typ)
                || !(WellKnownMediaTypes.Jwt.IsAtJwt(typ) || WellKnownMediaTypes.Application.IsAtJwt(typ)))
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token header typ must be 'at+jwt' or 'application/at+jwt' per RFC 9068 §4."));
            }

            //3. Resolve the verification key.
            PublicKeyMemory? publicKey = await oauth.Cryptography.VerificationKeyResolver(
                new KeyId(kid), registration.TenantId, context, cancellationToken).ConfigureAwait(false);

            if(publicKey is null)
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    $"No verification key found for kid '{kid}'."));
            }

            //4. Verify signature via the algorithm-agnostic Jws.VerifyAsync
            //   overload. The key's tag carries the algorithm; the registry
            //   resolves the verification primitive.
            bool signatureValid;
            try
            {
                signatureValid = await Jws.VerifyAsync(
                    bearerToken,
                    oauth.Codecs.Decoder,
                    oauth.MemoryPool!,
                    publicKey,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    $"Signature verification raised: {ex.Message}"));
            }

            if(!signatureValid)
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token signature verification failed."));
            }

            //5. Parse the payload now that the signature is verified. RFC 7519 §4: the Claim
            //   Names within a JWT Claims Set MUST be unique. Gate the decoded payload for
            //   well-formedness before it reaches the wired deserializer, so a duplicate claim
            //   name is refused here rather than escaping the deserializer as an unhandled
            //   exception.
            if(!JwkJsonReader.IsWellFormedJsonDocument(unverified.Payload.Span))
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token payload is not well-formed JSON, or carries a duplicate claim name."));
            }

            JwtPayload payload;
            try
            {
                payload = new(oauth.Codecs.JwtPayloadDeserializer(unverified.Payload.Span));
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException or System.Text.Json.JsonException)
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    $"Access token payload could not be parsed: {ex.Message}"));
            }

            //6. iss claim must match the resolved issuer for this request.
            Uri issuerUri;
            try
            {
                issuerUri = oauth.ResolveIssuerAsync is not null
                    ? (await oauth.ResolveIssuerAsync(registration, context, cancellationToken)
                        .ConfigureAwait(false))!
                    : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken)
                        .ConfigureAwait(false);
            }
            catch(InvalidOperationException ex)
            {
                return (null, ServerHttpResponse.ServerError(
                    OAuthErrors.ServerError,
                    $"Could not resolve issuer for bearer-token validation: {ex.Message}"));
            }

            if(!payload.TryGetValue(WellKnownJwtClaimNames.Iss, out object? issObj)
                || issObj is not string iss
                || !string.Equals(iss, issuerUri.OriginalString, StringComparison.Ordinal))
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token iss claim does not match this Authorization Server."));
            }

            //6a. aud claim must contain the caller's expected resource identifier, when the caller
            //    asked for that binding. RFC 9068 §4: "The resource server MUST validate that the
            //    "aud" claim contains a resource indicator value corresponding to an identifier the
            //    resource server expects for itself. The JWT access token MUST be rejected if "aud"
            //    does not contain a resource indicator of the current resource server as a valid
            //    audience." and "in case of any failure in the validation checks listed above, the
            //    authorization server response MUST include the error code "invalid_token"." The
            //    claim's shape is read strictly (TryReadWellFormedAudience): an array holding anything
            //    other than non-empty strings is refused outright, never narrowed to its string
            //    entries, so a malformed aud is never admitted on the entries beside the malformed one.
            if(expectedAudience is not null)
            {
                bool isAudienceMatched = TryReadWellFormedAudience(payload, out IReadOnlyList<string> audience)
                    && ContainsOrdinal(audience, expectedAudience);

                if(!isAudienceMatched)
                {
                    return (null, ServerHttpResponse.Unauthorized(
                        OAuthErrors.InvalidToken,
                        "Access token aud claim does not contain the expected resource identifier."));
                }
            }

            //7. exp claim must be in the future. JwtClaimReaders.TryToInt64
            //   handles the broad set of integer types JSON deserializers may
            //   produce for Unix-seconds values (long, int, decimal, ulong, …).
            if(!payload.TryGetValue(WellKnownJwtClaimNames.Exp, out object? expObj)
                || !JwtClaimReaders.TryToInt64(expObj, out long expSeconds))
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token is missing the exp claim."));
            }

            DateTimeOffset now = server.TimeProvider.GetUtcNow();
            if(DateTimeOffset.FromUnixTimeSeconds(expSeconds) < now)
            {
                return (null, ServerHttpResponse.Unauthorized(
                    OAuthErrors.InvalidToken,
                    "Access token has expired."));
            }

            return (payload, null);
        }
    }


    /// <summary>
    /// Whether <paramref name="expected"/> appears in <paramref name="audience"/> under ordinal
    /// equality: the <c>aud</c> comparison is exact-string, with no case folding or URI normalisation,
    /// against an identifier the caller supplies rather than one derived from the inbound request.
    /// </summary>
    /// <param name="audience">The token's <c>aud</c> claim, normalised to a list of strings.</param>
    /// <param name="expected">The resource identifier the caller expects to find.</param>
    /// <returns><see langword="true"/> when <paramref name="expected"/> is one of <paramref name="audience"/>'s entries.</returns>
    private static bool ContainsOrdinal(IReadOnlyList<string> audience, string expected)
    {
        for(int i = 0; i < audience.Count; i++)
        {
            if(string.Equals(audience[i], expected, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Reads the <c>aud</c> claim of <paramref name="payload"/> in the two shapes
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see> defines,
    /// an array of strings or a single string, and refuses every other shape outright: an empty
    /// string, an empty array, an array holding a non-string or empty element, or a value of another
    /// type. A malformed claim is never narrowed to its well-formed part, so a token is never admitted
    /// on the strength of the entries that happened to be strings beside the ones that made the claim
    /// malformed.
    /// </summary>
    /// <param name="payload">The access-token payload whose <c>aud</c> claim is read.</param>
    /// <param name="audience">The audience values when the claim is well formed; otherwise empty.</param>
    /// <returns><see langword="true"/> when the claim is present and well formed.</returns>
    private static bool TryReadWellFormedAudience(JwtPayload payload, out IReadOnlyList<string> audience)
    {
        audience = [];
        if(!payload.TryGetValue(WellKnownJwtClaimNames.Aud, out object? raw))
        {
            return false;
        }

        if(raw is string single)
        {
            if(string.IsNullOrEmpty(single))
            {
                return false;
            }

            audience = [single];

            return true;
        }

        if(raw is not IEnumerable<object> items)
        {
            return false;
        }

        List<string> values = [];
        foreach(object item in items)
        {
            if(item is not string value || string.IsNullOrEmpty(value))
            {
                return false;
            }

            values.Add(value);
        }

        if(values.Count == 0)
        {
            return false;
        }

        audience = values;

        return true;
    }
}
