namespace Verifiable.JCose;

/// <summary>
/// Well-known JWT claim names as registered at the
/// <see href="https://www.iana.org/assignments/jwt/jwt.xhtml#claims">IANA JWT Claims registry</see>.
/// </summary>
/// <remarks>
/// Claim names are case-sensitive per
/// <see href="https://www.rfc-editor.org/rfc/rfc7519">RFC 7519</see>.
/// </remarks>
public static class WellKnownJwtClaims
{
    /// <summary>
    /// The <c>iss</c> (Issuer) claim identifies the principal that issued the JWT.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1">RFC 7519 §4.1.1</see>.
    /// </summary>
    public static readonly string Iss = "iss";

    /// <summary>
    /// The <c>sub</c> (Subject) claim identifies the principal that is the subject of the JWT.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2">RFC 7519 §4.1.2</see>.
    /// </summary>
    public static readonly string Sub = "sub";

    /// <summary>
    /// The <c>aud</c> (Audience) claim identifies the recipients the JWT is intended for.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see>.
    /// </summary>
    public static readonly string Aud = "aud";

    /// <summary>
    /// The <c>exp</c> (Expiration Time) claim identifies the time on or after which the JWT
    /// must not be accepted for processing.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 §4.1.4</see>.
    /// </summary>
    public static readonly string Exp = "exp";

    /// <summary>
    /// The <c>nbf</c> (Not Before) claim identifies the time before which the JWT must not be
    /// accepted for processing.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">RFC 7519 §4.1.5</see>.
    /// </summary>
    public static readonly string Nbf = "nbf";

    /// <summary>
    /// The <c>iat</c> (Issued At) claim identifies the time at which the JWT was issued.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">RFC 7519 §4.1.6</see>.
    /// </summary>
    public static readonly string Iat = "iat";

    /// <summary>
    /// The <c>jti</c> (JWT ID) claim provides a unique identifier for the JWT, used to prevent replay.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 §4.1.7</see>.
    /// </summary>
    public static readonly string Jti = "jti";

    /// <summary>
    /// The <c>scope</c> claim carries the authorized scope values associated with
    /// an access token or an authorization request.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.2">RFC 8693 §4.2</see>.
    /// </summary>
    public static readonly string Scope = "scope";

    /// <summary>
    /// The <c>client_id</c> claim identifies the OAuth client the token was issued to.
    /// Required in OAuth 2.0 JWT access tokens per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 §2.2</see>.
    /// </summary>
    public static readonly string ClientId = "client_id";

    /// <summary>
    /// The <c>nonce</c> claim carries a value used to associate a request with a session
    /// and to mitigate replay attacks.
    /// See <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core §2</see>.
    /// </summary>
    public static readonly string Nonce = "nonce";

    /// <summary>
    /// The <c>auth_time</c> claim carries the time when the End-User authentication occurred.
    /// Its value is a JSON number representing the number of seconds from
    /// 1970-01-01T00:00:00Z UTC until the date/time. Required when a <c>max_age</c> request
    /// was made or when the <c>auth_time</c> claim was requested specifically.
    /// See <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
    /// </summary>
    public static readonly string AuthTime = "auth_time";

    /// <summary>
    /// The <c>name</c> claim carries the end-user's full name in displayable form.
    /// See <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core §5.1</see>.
    /// </summary>
    public static readonly string Name = "name";

    /// <summary>
    /// The <c>vct</c> (Verifiable Credential Type) claim identifies the type of the SD-JWT VC.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9901#section-3.2.2.1.1">RFC 9901 §3.2.2.1.1</see>.
    /// </summary>
    public static readonly string Vct = "vct";

    /// <summary>
    /// The <c>cnf</c> (Confirmation) claim carries the holder's confirmation method,
    /// typically the holder's public key for key binding.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7800#section-3.1">RFC 7800 §3.1</see>.
    /// </summary>
    public static readonly string Cnf = "cnf";

    /// <summary>
    /// The <c>htm</c> (HTTP Method) claim in a DPoP proof JWT carries the HTTP method
    /// of the request to which the proof is attached.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>.
    /// </summary>
    public static readonly string Htm = "htm";

    /// <summary>
    /// The <c>htu</c> (HTTP URI) claim in a DPoP proof JWT carries the HTTP URI of
    /// the request to which the proof is attached, without query and fragment parts.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>.
    /// </summary>
    public static readonly string Htu = "htu";

    /// <summary>
    /// The <c>ath</c> (Access Token Hash) claim in a DPoP proof JWT carries the
    /// base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token.
    /// Required when the DPoP proof is presented alongside an access token.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>.
    /// </summary>
    public static readonly string Ath = "ath";


    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Iss"/>.
    /// </summary>
    public static bool IsIss(string claim) => Equals(claim, Iss);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Sub"/>.
    /// </summary>
    public static bool IsSub(string claim) => Equals(claim, Sub);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Aud"/>.
    /// </summary>
    public static bool IsAud(string claim) => Equals(claim, Aud);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Exp"/>.
    /// </summary>
    public static bool IsExp(string claim) => Equals(claim, Exp);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Nbf"/>.
    /// </summary>
    public static bool IsNbf(string claim) => Equals(claim, Nbf);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Iat"/>.
    /// </summary>
    public static bool IsIat(string claim) => Equals(claim, Iat);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Jti"/>.
    /// </summary>
    public static bool IsJti(string claim) => Equals(claim, Jti);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="ClientId"/>.
    /// </summary>
    public static bool IsClientId(string claim) => Equals(claim, ClientId);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Nonce"/>.
    /// </summary>
    public static bool IsNonce(string claim) => Equals(claim, Nonce);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="AuthTime"/>.
    /// </summary>
    public static bool IsAuthTime(string claim) => Equals(claim, AuthTime);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Name"/>.
    /// </summary>
    public static bool IsName(string claim) => Equals(claim, Name);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Vct"/>.
    /// </summary>
    public static bool IsVct(string claim) => Equals(claim, Vct);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Cnf"/>.
    /// </summary>
    public static bool IsCnf(string claim) => Equals(claim, Cnf);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Htm"/>.
    /// </summary>
    public static bool IsHtm(string claim) => Equals(claim, Htm);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Htu"/>.
    /// </summary>
    public static bool IsHtu(string claim) => Equals(claim, Htu);

    /// <summary>
    /// Whether <paramref name="claim"/> is <see cref="Ath"/>.
    /// </summary>
    public static bool IsAth(string claim) => Equals(claim, Ath);


    /// <summary>
    /// Returns the interned constant for a known claim name, or the original string if
    /// unrecognized. Enables reference-equality fast paths downstream.
    /// </summary>
    /// <param name="claim">The claim name to canonicalize.</param>
    /// <returns>The canonical constant, or <paramref name="claim"/> unchanged.</returns>
    public static string GetCanonicalizedValue(string claim) => claim switch
    {
        _ when IsIss(claim) => Iss,
        _ when IsSub(claim) => Sub,
        _ when IsAud(claim) => Aud,
        _ when IsExp(claim) => Exp,
        _ when IsNbf(claim) => Nbf,
        _ when IsIat(claim) => Iat,
        _ when IsJti(claim) => Jti,
        _ when IsClientId(claim) => ClientId,
        _ when IsNonce(claim) => Nonce,
        _ when IsAuthTime(claim) => AuthTime,
        _ when IsName(claim) => Name,
        _ when IsVct(claim) => Vct,
        _ when IsCnf(claim) => Cnf,
        _ when IsHtm(claim) => Htm,
        _ when IsHtu(claim) => Htu,
        _ when IsAth(claim) => Ath,
        _ => claim
    };


    /// <summary>
    /// Compares two claim names for equality. Comparison is case-sensitive per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519">RFC 7519</see>.
    /// </summary>
    public static bool Equals(string claimA, string claimB) =>
        object.ReferenceEquals(claimA, claimB) || StringComparer.Ordinal.Equals(claimA, claimB);
}
