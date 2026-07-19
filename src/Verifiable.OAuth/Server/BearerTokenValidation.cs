using System.Buffers;
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
/// Audience is deliberately not validated — a protected resource accepts any AS-issued access
/// token whose <c>iss</c> matches the resolved issuer; deployments that need stricter audience
/// binding install a custom <see cref="ResolveAccessTokenAudienceDelegate"/> and add the check
/// at the resource server.
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
    /// <see cref="Jws.VerifyAsync(string, DecodeDelegate, MemoryPool{byte}, PublicKeyMemory, CancellationToken)"/>,
    /// and the AS's wired <see cref="AuthorizationServerCryptography.VerificationKeyResolver"/> /
    /// <see cref="AuthorizationServerCodecs.JwtPayloadDeserializer"/>.
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
    public static async ValueTask<(JwtPayload? Payload, ServerHttpResponse? Failure)> ValidateAsync(
        string bearerToken,
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
                BaseMemoryPool.Shared);
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
                    BaseMemoryPool.Shared,
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

            //5. Parse the payload now that the signature is verified.
            JwtPayload payload;
            try
            {
                payload = new JwtPayload(oauth.Codecs.JwtPayloadDeserializer(unverified.Payload.Span));
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
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
}
