using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth.Jar;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Validation;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Validates a bearer access token presented to a protected endpoint per
/// <see href="https://www.rfc-editor.org/rfc/rfc6750">RFC 6750</see>. The token must be a
/// compact JWS this Authorization Server issued: its <c>iss</c> claim matches the resolved
/// issuer URI, its <c>aud</c> claim contains the identifier of the resource it is presented at,
/// and it is unexpired.
/// </summary>
/// <remarks>
/// <para>
/// The OIDC Core 1.0 Section 5.3 UserInfo endpoint and the OID4VCI 1.0 Credential, Deferred
/// Credential and Notification endpoints are protected resources of this library that accept an
/// AS-issued access token on the <c>Authorization</c> header; the structural parse, the <c>alg</c>,
/// <c>typ</c> and <c>kid</c> checks, key admission, key resolution, signature verification, <c>iss</c>,
/// <c>aud</c> and <c>exp</c> sequence is one body that lives here once, so the security-critical
/// validation cannot drift between call sites. Each step names its own source. The length cap, a token
/// longer than <see cref="Jws.DefaultMaxJwsLength"/> refused before it is parsed, is this library's own
/// bound on the compact JWS it verifies, stated by no specification; the non-blank <c>kid</c> is this
/// library's rule, since the verification key is resolved by it; the key admission is
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.12">RFC 8725 Section 3.12</see> (the next
/// paragraph). The <c>typ</c>, <c>alg</c>, signature, <c>iss</c>, <c>aud</c> and <c>exp</c> checks are the
/// rules of <see href="https://www.rfc-editor.org/rfc/rfc9068#section-4">RFC 9068 Section 4</see>; its audience
/// step is: "The resource server MUST validate that the "aud" claim contains a resource indicator value
/// corresponding to an identifier the resource server expects for itself.  The JWT access token MUST be
/// rejected if "aud" does not contain a resource indicator of the current resource server as a valid
/// audience." The library's own resources are identified by this Authorization Server's issuer, the
/// value the <c>iss</c> claim is compared with; a resource an application serves names its own
/// identifier. Scope and subject-claim requirements are endpoint-specific and stay at the caller
/// (UserInfo enforces <c>openid</c> per OIDC Core 1.0 Section 5.3.1).
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
/// A resource an application serves calls
/// <see cref="ValidateAsync(string, string, EndpointServer, ClientRecord, ExchangeContext, CancellationToken)"/>
/// with its own identifier as the expected audience. The library's own resources run the same body with
/// the issuer as the expected audience, resolved once by the validation itself. A token whose <c>aud</c>
/// does not contain that identifier, a token without <c>aud</c>, and a token at or past the instant of its
/// <c>exp</c> are refused with <c>invalid_token</c>.
/// </para>
/// <para>
/// A fault of the server's own wiring met during the validation, the codecs or the verification-key
/// resolver unwired or an issuer that does not resolve (the default resolver's refusal, or an application
/// resolver that answers nothing), is answered 500 <c>server_error</c> with the fixed description
/// <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/>. No description the validation writes
/// carries an exception's message, a configuration member's name or a value taken from the token.
/// </para>
/// <para>
/// The extractors read the <c>Authorization</c> field through <see cref="AuthorizationFieldReading.Read"/>: the
/// token is the credentials of one well-formed field line of the <c>Bearer</c> or <c>DPoP</c> scheme, the scheme
/// compared case-insensitively, whose credentials are a token68
/// (<see cref="AuthorizationFieldReading.HasToken68Credentials"/>), the form both schemes define:
/// "credentials = "Bearer" 1*SP b64token"
/// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>) and
/// "credentials = "DPoP" 1*SP token68"
/// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>). A field sent on
/// two lines carries no token, and the library's own resources answer it 400 <c>invalid_request</c>: UserInfo and
/// the OID4VCI resources, which accept both schemes, with the <c>Bearer</c> and the <c>DPoP</c> challenge, and the
/// client configuration endpoint with the <c>Bearer</c> challenge. A value of another scheme, outside the grammar,
/// or whose credentials are a list of auth-param, carries no token.
/// </para>
/// </remarks>
public static class BearerTokenValidation
{
    /// <summary>
    /// Reads the request's <c>Authorization</c> field through <see cref="AuthorizationFieldReading.Read"/> and
    /// extracts the bearer token: the credentials of one well-formed field line whose scheme is
    /// <c>Bearer</c>, compared case-insensitively ("It uses a case-insensitive token to identify the
    /// authentication scheme:", <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110
    /// Section 11.1</see>), and whose credentials are a token68, the token's form:
    /// "b64token    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="" and
    /// "credentials = "Bearer" 1*SP b64token"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>). A field that is
    /// absent, repeated, of another scheme, outside the <c>credentials</c> grammar, without credentials or whose
    /// credentials are a list of auth-param carries no token.
    /// </summary>
    /// <param name="context">The per-request context carrying the inbound request.</param>
    /// <param name="bearerToken">The extracted token, or <see langword="null"/> when absent or malformed.</param>
    /// <returns><see langword="true"/> when a well-formed Bearer token was present.</returns>
    public static bool TryExtractBearer(ExchangeContext context, out string? bearerToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        return TryExtractBearer(ReadAuthorizationField(context), out bearerToken);
    }


    /// <summary>
    /// Extracts the bearer token from an <c>Authorization</c> field already read once by the caller, by the
    /// rule of <see cref="TryExtractBearer(ExchangeContext, out string?)"/>.
    /// </summary>
    /// <param name="authorization">The request's <c>Authorization</c> field reading.</param>
    /// <param name="bearerToken">The extracted token, or <see langword="null"/> when absent or malformed.</param>
    /// <returns><see langword="true"/> when a well-formed Bearer token was present.</returns>
    internal static bool TryExtractBearer(AuthorizationFieldReading authorization, out string? bearerToken)
    {
        bearerToken = authorization.HasToken68Credentials
            && authorization.IsScheme(WellKnownAuthenticationSchemes.Bearer)
                ? authorization.Credentials
                : null;

        return bearerToken is not null;
    }


    /// <summary>
    /// Reads the request's <c>Authorization</c> field through <see cref="AuthorizationFieldReading.Read"/>
    /// for an access token under EITHER the <c>Bearer</c> (RFC 6750) or the <c>DPoP</c> (RFC 9449 Section 7.1)
    /// scheme, each compared case-insensitively
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.1">RFC 9110 Section 11.1</see>), reporting
    /// which scheme carried it. A sender-constrained token is presented under the <c>DPoP</c> scheme alongside
    /// a <c>DPoP</c> proof header, so a protected resource that honors the binding must accept that scheme;
    /// the <paramref name="isDpopPresentation"/> flag lets the caller reject a DPoP-bound token presented
    /// (downgraded) under <c>Bearer</c>. The token is the credentials of the one well-formed line when they are a
    /// token68, the form of both schemes: "credentials = "Bearer" 1*SP b64token"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>) and
    /// "credentials = "DPoP" 1*SP token68"
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>). A field that is
    /// absent, repeated, of another scheme, outside the <c>credentials</c> grammar, without credentials or whose
    /// credentials are a list of auth-param carries no token.
    /// </summary>
    /// <param name="context">The per-request context carrying the inbound request.</param>
    /// <param name="accessToken">The extracted token, or <see langword="null"/> when absent or malformed.</param>
    /// <param name="isDpopPresentation"><see langword="true"/> when the token was presented under the <c>DPoP</c> scheme.</param>
    /// <returns><see langword="true"/> when a well-formed token under either scheme was present.</returns>
    public static bool TryExtractAccessToken(
        ExchangeContext context, out string? accessToken, out bool isDpopPresentation)
    {
        ArgumentNullException.ThrowIfNull(context);

        return TryExtractAccessToken(ReadAuthorizationField(context), out accessToken, out isDpopPresentation);
    }


    /// <summary>
    /// Extracts the access token from an <c>Authorization</c> field already read once by the caller, by the
    /// rule of <see cref="TryExtractAccessToken(ExchangeContext, out string?, out bool)"/>.
    /// </summary>
    /// <param name="authorization">The request's <c>Authorization</c> field reading.</param>
    /// <param name="accessToken">The extracted token, or <see langword="null"/> when absent or malformed.</param>
    /// <param name="isDpopPresentation"><see langword="true"/> when the token was presented under the <c>DPoP</c> scheme.</param>
    /// <returns><see langword="true"/> when a well-formed token under either scheme was present.</returns>
    internal static bool TryExtractAccessToken(
        AuthorizationFieldReading authorization, out string? accessToken, out bool isDpopPresentation)
    {
        isDpopPresentation = authorization.IsScheme(WellKnownAuthenticationSchemes.DPoP);
        bool isAccessTokenScheme = isDpopPresentation || authorization.IsScheme(WellKnownAuthenticationSchemes.Bearer);
        accessToken = isAccessTokenScheme && authorization.HasToken68Credentials
            ? authorization.Credentials
            : null;
        isDpopPresentation = isDpopPresentation && accessToken is not null;

        return accessToken is not null;
    }


    /// <summary>
    /// The request's <c>Authorization</c> field, read once through <see cref="AuthorizationFieldReading.Read"/>;
    /// the absent field for a context that carries no request. A protected resource reads the field here,
    /// answers a repeated field (<see cref="AuthorizationFieldReading.IsRepeated"/>) through
    /// <see cref="Oid4Vci.CredentialEndpointDpopValidation.RefuseRepeatedAuthorizationAsync"/>, and extracts the
    /// token from the same reading.
    /// </summary>
    /// <param name="context">The per-request context carrying the inbound request.</param>
    /// <returns>The reading.</returns>
    internal static AuthorizationFieldReading ReadAuthorizationField(ExchangeContext context) =>
        context.IncomingRequest is { } request ? AuthorizationFieldReading.Read(request.Headers) : default;


    /// <summary>
    /// Validates an access token presented at one of this library's own resources, UserInfo and the OID4VCI
    /// Credential, Deferred Credential and Notification endpoints, whose identifier is this Authorization
    /// Server's issuer: the token's <c>aud</c> claim must contain the issuer the validation resolves for the
    /// request, the value its <c>iss</c> claim is compared with, so the issuer is resolved once. The sequence
    /// and the refusals are those of
    /// <see cref="ValidateAsync(string, string, EndpointServer, ClientRecord, ExchangeContext, CancellationToken)"/>.
    /// </summary>
    /// <param name="bearerToken">The compact-JWS access token, exactly as presented on the wire.</param>
    /// <param name="server">The authorization server holding codecs, cryptography, and integration delegates.</param>
    /// <param name="registration">The client (tenant) the request belongs to.</param>
    /// <param name="context">The per-request context bag.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>
    /// The validated <see cref="JwtPayload"/> and a <see langword="null"/> failure on success;
    /// a <see langword="null"/> payload and the RFC 6750 / RFC 9068 error response on failure.
    /// </returns>
    internal static ValueTask<(JwtPayload? Payload, ServerHttpResponse? Failure)> ValidateAtLibraryResourceAsync(
        string bearerToken,
        EndpointServer server,
        ClientRecord registration,
        ExchangeContext context,
        CancellationToken cancellationToken) =>
        ValidateCoreAsync(bearerToken, expectedAudience: null, server, registration, context, cancellationToken);


    /// <summary>
    /// Validates a bearer access token presented at a resource the application serves: its structure,
    /// signature, issuer, audience and expiry, and requires the token's <c>aud</c> claim to contain
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
    /// The one validation body <see cref="ValidateAtLibraryResourceAsync"/> and
    /// <see cref="ValidateAsync(string, string, EndpointServer, ClientRecord, ExchangeContext, CancellationToken)"/>
    /// run, so the structural parse, signature, <c>iss</c>, <c>aud</c> and <c>exp</c> sequence cannot drift
    /// between the library's own resources and an application's. The audience is always checked.
    /// </summary>
    /// <param name="bearerToken">The compact-JWS access token, exactly as presented on the wire.</param>
    /// <param name="expectedAudience">
    /// The resource identifier the <c>aud</c> claim must contain, or <see langword="null"/> for one of the
    /// library's own resources, whose identifier is the issuer this validation resolves for the request:
    /// <see langword="null"/> means that issuer is the expected audience, never that no audience is checked.
    /// Only <see cref="ValidateAtLibraryResourceAsync"/> passes <see langword="null"/>;
    /// <see cref="ValidateAsync(string, string, EndpointServer, ClientRecord, ExchangeContext, CancellationToken)"/>
    /// refuses a <see langword="null"/> or empty audience before this body runs.
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
    /// not list for access tokens is refused with a fixed description that names no key. The resolver is
    /// then asked for the admitted key under the same usage,
    /// <see cref="KeyUsageContext.AccessTokenIssuance"/>, so a key store that keeps keys apart per kind
    /// answers only a key it holds for access tokens; a listed key the resolver does not produce for that
    /// usage is refused with a fixed description that names no key. The admission stays the library's
    /// guarantee: the usage lets the resolver narrow what verifies, never widen it.
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

        //A fault of the server's own wiring is answered with the library's fixed description, which names
        //no configuration member.
        if(oauth.Codecs.JwtHeaderDeserializer is null
            || oauth.Codecs.JwtPayloadDeserializer is null
            || oauth.Codecs.Decoder is null
            || oauth.Cryptography.VerificationKeyResolver is null)
        {
            return (null, ServerNotReady());
        }

        //A token longer than the compact JWS the signature verification accepts
        //(Jws.DefaultMaxJwsLength) is malformed input, refused before it is parsed rather than
        //raised as an exception from that verification.
        if(bearerToken.Length > Jws.DefaultMaxJwsLength)
        {
            return (null, RefuseToken("Access token exceeds the longest compact JWS this server verifies."));
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
                oauth.MemoryPool);
        }
        catch(Exception ex) when(ex is FormatException or InvalidOperationException or System.Text.Json.JsonException)
        {
            //A protected header that is not a JSON object (for example "[]") fails in the wired
            //header deserializer; the token is malformed input, refused with its challenge and a fixed
            //description that carries nothing the parser said about the token.
            return (null, RefuseToken("Access token is malformed."));
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
            //before the resolver, which may answer any key it holds by kid, so a client's assertion
            //key, another registration's key or another token kind's key never verifies an access
            //token here. The description names no key.
            if(!IssuedKeyAdmission.IsListedFor(registration, KeyUsageContext.AccessTokenIssuance, new KeyId(kid)))
            {
                return (null, RefuseToken(
                    "Access token is not signed by a key this server issues access tokens with."));
            }

            //3. Resolve the verification key under the usage the admission names.
            PublicKeyMemory? publicKey = await oauth.Cryptography.VerificationKeyResolver(
                new KeyId(kid), KeyUsageContext.AccessTokenIssuance, registration.TenantId, context, cancellationToken).ConfigureAwait(false);

            //The description is fixed: a refusal names no key the token presented.
            if(publicKey is null)
            {
                return (null, RefuseToken(
                    "No verification key is available for the access token."));
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
                    oauth.MemoryPool,
                    publicKey,
                    cancellationToken).ConfigureAwait(false);
            }
            catch(Exception ex) when(ex is FormatException or InvalidOperationException)
            {
                //The description is fixed: a verification that cannot run is a signature that does not verify.
                return (null, RefuseToken("Access token signature verification failed."));
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
                //The description is fixed: it carries nothing the deserializer said about the payload.
                return (null, RefuseToken("Access token payload could not be parsed."));
            }

            //6. iss claim must match the resolved issuer for this request. An issuer that does not
            //   resolve, by the default resolver's refusal or by an application resolver that answers
            //   nothing, is a fault of the server's own wiring.
            Uri? issuerUri;
            try
            {
                issuerUri = oauth.ResolveIssuerAsync is not null
                    ? await oauth.ResolveIssuerAsync(registration, context, cancellationToken).ConfigureAwait(false)
                    : await DefaultIssuerResolver.ResolveAsync(registration, context, cancellationToken).ConfigureAwait(false);
            }
            catch(InvalidOperationException)
            {
                return (null, ServerNotReady());
            }

            if(issuerUri is null)
            {
                return (null, ServerNotReady());
            }

            string issuer = issuerUri.OriginalString;
            if(!payload.TryGetValue(WellKnownJwtClaimNames.Iss, out object? issObj)
                || issObj is not string iss
                || !string.Equals(iss, issuer, StringComparison.Ordinal))
            {
                return (null, RefuseToken(
                    "Access token iss claim does not match this Authorization Server."));
            }

            //6a. aud claim must contain the resource's identifier: the caller's, or for the library's own
            //    resources the issuer resolved above. RFC 9068 Section 4: "The resource server MUST
            //    validate that the "aud" claim contains a resource indicator value corresponding to an
            //    identifier the resource server expects for itself.  The JWT access token MUST be rejected
            //    if "aud" does not contain a resource indicator of the current resource server as a valid
            //    audience." A token without aud contains no audience and is refused. The claim's shape is
            //    read strictly (TryReadWellFormedAudience): an array holding anything other than non-empty
            //    strings is refused outright, never narrowed to its string entries, so a malformed aud is
            //    never admitted on the entries beside the malformed one.
            bool isAudienceMatched = TryReadWellFormedAudience(payload, out IReadOnlyList<string> audience)
                && ContainsOrdinal(audience, expectedAudience ?? issuer);

            if(!isAudienceMatched)
            {
                return (null, RefuseToken(
                    "Access token aud claim does not contain the expected resource identifier."));
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

            //A NumericDate beyond the instants a DateTimeOffset holds is malformed input: it is
            //refused before the instant is constructed, never raised as a server fault.
            if(!JwtTemporalChecks.IsRepresentableUnixSeconds(expSeconds))
            {
                return (null, RefuseToken(
                    "Access token exp claim is not a representable NumericDate."));
            }

            //RFC 9068 Section 4: "The current time MUST be before the time represented by the "exp"
            //claim." A token at the instant of its exp is expired.
            DateTimeOffset now = server.TimeProvider.GetUtcNow();
            if(DateTimeOffset.FromUnixTimeSeconds(expSeconds) <= now)
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
    internal static string InvalidTokenChallenge { get; } =
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
    /// Builds the 500 answer to a fault of the server's own wiring met while validating a token: the
    /// codecs or the verification-key resolver unwired, or an issuer that does not resolve. The body's
    /// <c>error</c> is <see cref="OAuthErrors.ServerError"/> and its description the library's fixed
    /// <see cref="WellKnownOAuthErrorDescriptions.ServerNotReady"/>, which names no configuration member and
    /// carries no exception text; it carries no challenge, since it answers the server's wiring, not a
    /// refused token.
    /// </summary>
    /// <returns>The 500 response.</returns>
    private static ServerHttpResponse ServerNotReady() =>
        ServerHttpResponse.ServerError(OAuthErrors.ServerError, WellKnownOAuthErrorDescriptions.ServerNotReady);


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
