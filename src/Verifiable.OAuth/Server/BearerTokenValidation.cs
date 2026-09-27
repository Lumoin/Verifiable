using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.ProtectedResource;
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
/// header; the structural-parse → <c>alg</c>/<c>typ</c>/<c>kid</c> → key admission → key-resolve →
/// signature-verify → <c>iss</c> → <c>exp</c> sequence is identical and lives here once so the
/// security-critical validation cannot drift between call sites. Scope and subject-claim
/// requirements are endpoint-specific and stay at the caller (UserInfo enforces <c>openid</c>
/// per §5.3.1).
/// </para>
/// <para>
/// By the library's key-admission policy (<see cref="IssuedKeyAdmission"/>), the token verifies only
/// under a key the registration lists for <see cref="KeyUsageContext.AccessTokenIssuance"/>, the usage
/// the library's access-token producer signs under, in any of that set's rotation slots. The policy is
/// the key-separation strategy
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see> names among
/// several for its rule: "If more than one kind of JWT can be issued by the same issuer, the validation
/// rules for those JWTs MUST be written such that they are mutually exclusive, rejecting JWTs of the
/// wrong kind." Removing a key from the set is what ends its admission.
/// </para>
/// <para>
/// Every refusal of a presented token is a 401 carrying the
/// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see> challenge: "If the
/// protected resource request does not include authentication credentials or does not contain an
/// access token that enables access to the protected resource, the resource server MUST include the
/// HTTP "WWW-Authenticate" response header field". The challenge is
/// <see cref="InvalidTokenChallenge"/>; a host that names a protection space replaces it with its own
/// realm-bearing challenge through <see cref="ServerHttpResponse.WithHeader"/>, which sets a header by
/// name. A 500 server fault carries no challenge: it answers a missing configuration, not a refused
/// token.
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
    /// <remarks>
    /// The header's <c>kid</c> is admitted only when <paramref name="registration"/> lists it for
    /// <see cref="KeyUsageContext.AccessTokenIssuance"/> (<see cref="IssuedKeyAdmission.IsListedFor"/>),
    /// before the <see cref="AuthorizationServerCryptography.VerificationKeyResolver"/> is asked for
    /// the key: <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 §3.12</see>
    /// names "Use different keys for different kinds of JWTs. Then the keys used to validate one kind of
    /// JWT will fail to validate other kinds of JWTs." among the ways to keep the validation rules of the
    /// kinds this issuer produces mutually exclusive. A key the resolver holds but the registration does
    /// not list for access tokens is refused with a fixed description that names no key; a listed key the
    /// resolver cannot produce is refused as unknown.
    /// </remarks>
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
            return (null, RefuseToken(
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
                return (null, RefuseToken(
                    "Access token header is missing or carries a forbidden alg."));
            }

            //A kid of only whitespace names no key: it is refused here as missing, so it never
            //reaches the KeyId the admission and the resolver are asked with.
            if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidObj)
                || kidObj is not string kid
                || string.IsNullOrWhiteSpace(kid))
            {
                return (null, RefuseToken(
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
                return (null, RefuseToken(
                    "Access token header typ must be 'at+jwt' or 'application/at+jwt' per RFC 9068 §4."));
            }

            //RFC 8725 §3.12: an access token verifies as this server's own only under a key the
            //registration lists for access-token issuance, in any rotation slot. The admission runs
            //before the resolver, which answers any key it holds by kid, so a client's assertion key,
            //another registration's key or another token kind's key never verifies an access token
            //here. The description names no key.
            if(!IssuedKeyAdmission.IsListedFor(registration, KeyUsageContext.AccessTokenIssuance, new KeyId(kid)))
            {
                return (null, RefuseToken(
                    "Access token is not signed by a key this server issues access tokens with."));
            }

            //3. Resolve the verification key.
            PublicKeyMemory? publicKey = await oauth.Cryptography.VerificationKeyResolver(
                new KeyId(kid), registration.TenantId, context, cancellationToken).ConfigureAwait(false);

            if(publicKey is null)
            {
                return (null, RefuseToken(
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
                return (null, RefuseToken(
                    $"Signature verification raised: {ex.Message}"));
            }

            if(!signatureValid)
            {
                return (null, RefuseToken(
                    "Access token signature verification failed."));
            }

            //5. Parse the payload now that the signature is verified. RFC 7519 §4: the Claim
            //   Names within a JWT Claims Set MUST be unique. Gate the decoded payload for
            //   well-formedness before it reaches the wired deserializer, so a duplicate claim
            //   name is refused here rather than escaping the deserializer as an unhandled
            //   exception.
            if(!JwkJsonReader.IsWellFormedJsonDocument(unverified.Payload.Span))
            {
                return (null, RefuseToken(
                    "Access token payload is not well-formed JSON, or carries a duplicate claim name."));
            }

            JwtPayload payload;
            try
            {
                payload = new(oauth.Codecs.JwtPayloadDeserializer(unverified.Payload.Span));
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException or System.Text.Json.JsonException)
            {
                return (null, RefuseToken(
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
                return (null, RefuseToken(
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
                    return (null, RefuseToken(
                        "Access token aud claim does not contain the expected resource identifier."));
                }
            }

            //7. exp claim must be in the future. JwtClaimReaders.TryToInt64
            //   handles the broad set of integer types JSON deserializers may
            //   produce for Unix-seconds values (long, int, decimal, ulong, …).
            if(!payload.TryGetValue(WellKnownJwtClaimNames.Exp, out object? expObj)
                || !JwtClaimReaders.TryToInt64(expObj, out long expSeconds))
            {
                return (null, RefuseToken(
                    "Access token is missing the exp claim."));
            }

            DateTimeOffset now = server.TimeProvider.GetUtcNow();
            if(DateTimeOffset.FromUnixTimeSeconds(expSeconds) < now)
            {
                return (null, RefuseToken(
                    "Access token has expired."));
            }

            return (payload, null);
        }
    }


    /// <summary>
    /// The <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3">RFC 6750 §3</see> challenge a
    /// refused token is answered with, <c>Bearer error="invalid_token"</c>: "All challenges defined by
    /// this specification MUST use the auth-scheme value "Bearer". This scheme MUST be followed by one or
    /// more auth-param values", and "If the protected resource request included an access token and
    /// failed authentication, the resource server SHOULD include the "error" attribute". Composed once by
    /// <see cref="BearerTokenChallenge.BuildChallenge"/>. It carries no <c>realm</c>, since the library
    /// does not know the protection space a host names, and no <c>error_description</c>, since a
    /// refusal's description can carry presented text outside the §3 attribute charset; the description
    /// travels in the response body.
    /// </summary>
    private static string InvalidTokenChallenge { get; } =
        BearerTokenChallenge.BuildChallenge(error: OAuthErrors.InvalidToken);


    /// <summary>
    /// Builds the 401 refusal of a presented token: the <c>invalid_token</c> error body per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-3.1">RFC 6750 §3.1</see> ("The access
    /// token provided is expired, revoked, malformed, or invalid for other reasons. The resource SHOULD
    /// respond with the HTTP 401 (Unauthorized) status code.") with
    /// <see cref="InvalidTokenChallenge"/> as its <c>WWW-Authenticate</c> header, so no refusal of this
    /// class leaves without the challenge §3 requires.
    /// </summary>
    /// <param name="description">The <c>error_description</c> the body carries.</param>
    /// <returns>The 401 response.</returns>
    private static ServerHttpResponse RefuseToken(string description) =>
        ServerHttpResponse.Unauthorized(OAuthErrors.InvalidToken, description)
            .WithHeader(WellKnownHttpHeaderNames.WwwAuthenticate, InvalidTokenChallenge);


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
