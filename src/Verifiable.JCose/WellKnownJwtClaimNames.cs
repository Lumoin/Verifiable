using System.Text;
using Verifiable.Cryptography.Text;

namespace Verifiable.JCose;

/// <summary>
/// Well-known JWT claim NAMES — strings that appear as JSON keys in the
/// JWT payload object. Sourced from
/// <see href="https://www.iana.org/assignments/jwt/jwt.xhtml#claims">IANA JSON Web Token Claims registry</see>
/// plus OpenID Connect Core 1.0 §2 and §5.1.
/// </summary>
/// <remarks>
/// <para>
/// These are the NAMES of claims (<c>"sub"</c>, <c>"iss"</c>, <c>"aud"</c>),
/// not their VALUES. Values are application- or context-defined: a subject
/// identifier, an issuer URL, an audience list. Claim values do not live
/// in this class.
/// </para>
/// <para>
/// Claim names are case-sensitive per
/// <see href="https://www.rfc-editor.org/rfc/rfc7519">RFC 7519</see>.
/// </para>
/// </remarks>
public static class WellKnownJwtClaimNames
{
    /// <summary>The UTF-8 source literal of <see cref="Iss"/>.</summary>
    public static ReadOnlySpan<byte> IssUtf8 => "iss"u8;

    /// <summary>
    /// The <c>iss</c> (Issuer) claim identifies the principal that issued the JWT.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1">RFC 7519 §4.1.1</see>.
    /// </summary>
    public static readonly string Iss = Utf8Constants.ToInternedString(IssUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Sub"/>.</summary>
    public static ReadOnlySpan<byte> SubUtf8 => "sub"u8;

    /// <summary>
    /// The <c>sub</c> (Subject) claim identifies the principal that is the subject of the JWT.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2">RFC 7519 §4.1.2</see>.
    /// </summary>
    public static readonly string Sub = Utf8Constants.ToInternedString(SubUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Aud"/>.</summary>
    public static ReadOnlySpan<byte> AudUtf8 => "aud"u8;

    /// <summary>
    /// The <c>aud</c> (Audience) claim identifies the recipients the JWT is intended for.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3">RFC 7519 §4.1.3</see>.
    /// </summary>
    public static readonly string Aud = Utf8Constants.ToInternedString(AudUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Exp"/>.</summary>
    public static ReadOnlySpan<byte> ExpUtf8 => "exp"u8;

    /// <summary>
    /// The <c>exp</c> (Expiration Time) claim identifies the time on or after which the JWT
    /// must not be accepted for processing.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 §4.1.4</see>.
    /// </summary>
    public static readonly string Exp = Utf8Constants.ToInternedString(ExpUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Nbf"/>.</summary>
    public static ReadOnlySpan<byte> NbfUtf8 => "nbf"u8;

    /// <summary>
    /// The <c>nbf</c> (Not Before) claim identifies the time before which the JWT must not be
    /// accepted for processing.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">RFC 7519 §4.1.5</see>.
    /// </summary>
    public static readonly string Nbf = Utf8Constants.ToInternedString(NbfUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Iat"/>.</summary>
    public static ReadOnlySpan<byte> IatUtf8 => "iat"u8;

    /// <summary>
    /// The <c>iat</c> (Issued At) claim identifies the time at which the JWT was issued.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">RFC 7519 §4.1.6</see>.
    /// </summary>
    public static readonly string Iat = Utf8Constants.ToInternedString(IatUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Jti"/>.</summary>
    public static ReadOnlySpan<byte> JtiUtf8 => "jti"u8;

    /// <summary>
    /// The <c>jti</c> (JWT ID) claim provides a unique identifier for the JWT, used to prevent replay.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7">RFC 7519 §4.1.7</see>.
    /// </summary>
    public static readonly string Jti = Utf8Constants.ToInternedString(JtiUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Scope"/>.</summary>
    public static ReadOnlySpan<byte> ScopeUtf8 => "scope"u8;

    /// <summary>
    /// The <c>scope</c> claim carries the authorized scope values associated with
    /// an access token or an authorization request.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc6749#section-3.3">RFC 6749 §3.3</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc8693#section-4.2">RFC 8693 §4.2</see>.
    /// </summary>
    public static readonly string Scope = Utf8Constants.ToInternedString(ScopeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientId"/>.</summary>
    public static ReadOnlySpan<byte> ClientIdUtf8 => "client_id"u8;

    /// <summary>
    /// The <c>client_id</c> claim identifies the OAuth client the token was issued to.
    /// Required in OAuth 2.0 JWT access tokens per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9068#section-2.2">RFC 9068 §2.2</see>.
    /// </summary>
    public static readonly string ClientId = Utf8Constants.ToInternedString(ClientIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Nonce"/>.</summary>
    public static ReadOnlySpan<byte> NonceUtf8 => "nonce"u8;

    /// <summary>
    /// The <c>nonce</c> claim carries a value used to associate a request with a session
    /// and to mitigate replay attacks.
    /// See <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OpenID Connect Core §2</see>.
    /// </summary>
    public static readonly string Nonce = Utf8Constants.ToInternedString(NonceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthTime"/>.</summary>
    public static ReadOnlySpan<byte> AuthTimeUtf8 => "auth_time"u8;

    /// <summary>
    /// The <c>auth_time</c> claim carries the time when the End-User authentication occurred.
    /// Required when a <c>max_age</c> request was made or when the <c>auth_time</c> claim was
    /// requested specifically.
    /// See <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
    /// </summary>
    public static readonly string AuthTime = Utf8Constants.ToInternedString(AuthTimeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Sid"/>.</summary>
    public static ReadOnlySpan<byte> SidUtf8 => "sid"u8;

    /// <summary>
    /// The <c>sid</c> (Session ID) claim — identifies the End-User's authentication
    /// session at the OP. Emitted in the ID Token and referenced by OIDC Back-Channel
    /// and Front-Channel Logout, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html">OIDC Core</see>
    /// and <see href="https://openid.net/specs/openid-connect-backchannel-1_0.html">Back-Channel Logout 1.0</see>.
    /// </summary>
    public static readonly string Sid = Utf8Constants.ToInternedString(SidUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Acr"/>.</summary>
    public static ReadOnlySpan<byte> AcrUtf8 => "acr"u8;

    /// <summary>
    /// The <c>acr</c> (Authentication Context Class Reference) claim per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
    /// Value is an application-defined assurance level (e.g. an eIDAS LoA or NIST 800-63 IAL/AAL).
    /// </summary>
    public static readonly string Acr = Utf8Constants.ToInternedString(AcrUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Amr"/>.</summary>
    public static ReadOnlySpan<byte> AmrUtf8 => "amr"u8;

    /// <summary>
    /// The <c>amr</c> (Authentication Methods References) claim per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>.
    /// Value is an array of method identifiers (e.g. <c>pwd</c>, <c>mfa</c>, <c>hwk</c>).
    /// </summary>
    public static readonly string Amr = Utf8Constants.ToInternedString(AmrUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Azp"/>.</summary>
    public static ReadOnlySpan<byte> AzpUtf8 => "azp"u8;

    /// <summary>
    /// The <c>azp</c> (Authorized Party) claim per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>
    /// — identifies the OAuth client the ID Token was issued to when different from the audience.
    /// </summary>
    public static readonly string Azp = Utf8Constants.ToInternedString(AzpUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Name"/>.</summary>
    public static ReadOnlySpan<byte> NameUtf8 => "name"u8;

    /// <summary>The <c>name</c> claim per OIDC Core §5.1 — full name in displayable form.</summary>
    public static readonly string Name = Utf8Constants.ToInternedString(NameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="GivenName"/>.</summary>
    public static ReadOnlySpan<byte> GivenNameUtf8 => "given_name"u8;

    /// <summary>The <c>given_name</c> claim per OIDC Core §5.1.</summary>
    public static readonly string GivenName = Utf8Constants.ToInternedString(GivenNameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FamilyName"/>.</summary>
    public static ReadOnlySpan<byte> FamilyNameUtf8 => "family_name"u8;

    /// <summary>The <c>family_name</c> claim per OIDC Core §5.1.</summary>
    public static readonly string FamilyName = Utf8Constants.ToInternedString(FamilyNameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="MiddleName"/>.</summary>
    public static ReadOnlySpan<byte> MiddleNameUtf8 => "middle_name"u8;

    /// <summary>The <c>middle_name</c> claim per OIDC Core §5.1.</summary>
    public static readonly string MiddleName = Utf8Constants.ToInternedString(MiddleNameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Nickname"/>.</summary>
    public static ReadOnlySpan<byte> NicknameUtf8 => "nickname"u8;

    /// <summary>The <c>nickname</c> claim per OIDC Core §5.1.</summary>
    public static readonly string Nickname = Utf8Constants.ToInternedString(NicknameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PreferredUsername"/>.</summary>
    public static ReadOnlySpan<byte> PreferredUsernameUtf8 => "preferred_username"u8;

    /// <summary>The <c>preferred_username</c> claim per OIDC Core §5.1.</summary>
    public static readonly string PreferredUsername = Utf8Constants.ToInternedString(PreferredUsernameUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Profile"/>.</summary>
    public static ReadOnlySpan<byte> ProfileUtf8 => "profile"u8;

    /// <summary>The <c>profile</c> claim per OIDC Core §5.1 — URL of the end-user's profile page.</summary>
    public static readonly string Profile = Utf8Constants.ToInternedString(ProfileUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Picture"/>.</summary>
    public static ReadOnlySpan<byte> PictureUtf8 => "picture"u8;

    /// <summary>The <c>picture</c> claim per OIDC Core §5.1 — URL of the end-user's profile picture.</summary>
    public static readonly string Picture = Utf8Constants.ToInternedString(PictureUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Website"/>.</summary>
    public static ReadOnlySpan<byte> WebsiteUtf8 => "website"u8;

    /// <summary>The <c>website</c> claim per OIDC Core §5.1.</summary>
    public static readonly string Website = Utf8Constants.ToInternedString(WebsiteUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Gender"/>.</summary>
    public static ReadOnlySpan<byte> GenderUtf8 => "gender"u8;

    /// <summary>The <c>gender</c> claim per OIDC Core §5.1.</summary>
    public static readonly string Gender = Utf8Constants.ToInternedString(GenderUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Birthdate"/>.</summary>
    public static ReadOnlySpan<byte> BirthdateUtf8 => "birthdate"u8;

    /// <summary>The <c>birthdate</c> claim per OIDC Core §5.1 — <c>YYYY-MM-DD</c> string.</summary>
    public static readonly string Birthdate = Utf8Constants.ToInternedString(BirthdateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Zoneinfo"/>.</summary>
    public static ReadOnlySpan<byte> ZoneinfoUtf8 => "zoneinfo"u8;

    /// <summary>The <c>zoneinfo</c> claim per OIDC Core §5.1 — IANA tz database string.</summary>
    public static readonly string Zoneinfo = Utf8Constants.ToInternedString(ZoneinfoUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Locale"/>.</summary>
    public static ReadOnlySpan<byte> LocaleUtf8 => "locale"u8;

    /// <summary>The <c>locale</c> claim per OIDC Core §5.1 — BCP47 language tag.</summary>
    public static readonly string Locale = Utf8Constants.ToInternedString(LocaleUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UpdatedAt"/>.</summary>
    public static ReadOnlySpan<byte> UpdatedAtUtf8 => "updated_at"u8;

    /// <summary>The <c>updated_at</c> claim per OIDC Core §5.1 — Unix seconds.</summary>
    public static readonly string UpdatedAt = Utf8Constants.ToInternedString(UpdatedAtUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Email"/>.</summary>
    public static ReadOnlySpan<byte> EmailUtf8 => "email"u8;

    /// <summary>The <c>email</c> claim per OIDC Core §5.1.</summary>
    public static readonly string Email = Utf8Constants.ToInternedString(EmailUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EmailVerified"/>.</summary>
    public static ReadOnlySpan<byte> EmailVerifiedUtf8 => "email_verified"u8;

    /// <summary>The <c>email_verified</c> claim per OIDC Core §5.1 — JSON boolean.</summary>
    public static readonly string EmailVerified = Utf8Constants.ToInternedString(EmailVerifiedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PhoneNumber"/>.</summary>
    public static ReadOnlySpan<byte> PhoneNumberUtf8 => "phone_number"u8;

    /// <summary>The <c>phone_number</c> claim per OIDC Core §5.1.</summary>
    public static readonly string PhoneNumber = Utf8Constants.ToInternedString(PhoneNumberUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PhoneNumberVerified"/>.</summary>
    public static ReadOnlySpan<byte> PhoneNumberVerifiedUtf8 => "phone_number_verified"u8;

    /// <summary>The <c>phone_number_verified</c> claim per OIDC Core §5.1.</summary>
    public static readonly string PhoneNumberVerified = Utf8Constants.ToInternedString(PhoneNumberVerifiedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Address"/>.</summary>
    public static ReadOnlySpan<byte> AddressUtf8 => "address"u8;

    /// <summary>The <c>address</c> claim per OIDC Core §5.1.1 — structured JSON object.</summary>
    public static readonly string Address = Utf8Constants.ToInternedString(AddressUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Roles"/>.</summary>
    public static ReadOnlySpan<byte> RolesUtf8 => "roles"u8;

    /// <summary>
    /// The <c>roles</c> claim — commonly used to communicate roles a principal has been granted.
    /// Application-defined value shape (typically a JSON array of role strings).
    /// </summary>
    public static readonly string Roles = Utf8Constants.ToInternedString(RolesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Tenant"/>.</summary>
    public static ReadOnlySpan<byte> TenantUtf8 => "tenant"u8;

    /// <summary>
    /// The <c>tenant</c> claim — commonly used in multitenant applications to specify the
    /// tenant the JWT is scoped to. Application-defined value shape.
    /// </summary>
    public static readonly string Tenant = Utf8Constants.ToInternedString(TenantUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Vct"/>.</summary>
    public static ReadOnlySpan<byte> VctUtf8 => "vct"u8;

    /// <summary>
    /// The <c>vct</c> (Verifiable Credential Type) claim identifies the type of the SD-JWT VC.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9901#section-3.2.2.1.1">RFC 9901 §3.2.2.1.1</see>.
    /// </summary>
    public static readonly string Vct = Utf8Constants.ToInternedString(VctUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Cnf"/>.</summary>
    public static ReadOnlySpan<byte> CnfUtf8 => "cnf"u8;

    /// <summary>
    /// The <c>cnf</c> (Confirmation) claim carries the holder's confirmation method,
    /// typically the holder's public key for key binding.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc7800#section-3.1">RFC 7800 §3.1</see>.
    /// </summary>
    public static readonly string Cnf = Utf8Constants.ToInternedString(CnfUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Htm"/>.</summary>
    public static ReadOnlySpan<byte> HtmUtf8 => "htm"u8;

    /// <summary>
    /// The <c>htm</c> (HTTP Method) claim in a DPoP proof JWT carries the HTTP method
    /// of the request to which the proof is attached.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>.
    /// </summary>
    public static readonly string Htm = Utf8Constants.ToInternedString(HtmUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Htu"/>.</summary>
    public static ReadOnlySpan<byte> HtuUtf8 => "htu"u8;

    /// <summary>
    /// The <c>htu</c> (HTTP URI) claim in a DPoP proof JWT carries the HTTP URI of
    /// the request to which the proof is attached, without query and fragment parts.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>.
    /// </summary>
    public static readonly string Htu = Utf8Constants.ToInternedString(HtuUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Ath"/>.</summary>
    public static ReadOnlySpan<byte> AthUtf8 => "ath"u8;

    /// <summary>
    /// The <c>ath</c> (Access Token Hash) claim in a DPoP proof JWT carries the
    /// base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token.
    /// Required when the DPoP proof is presented alongside an access token.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 §4.2</see>.
    /// </summary>
    public static readonly string Ath = Utf8Constants.ToInternedString(AthUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JwkThumbprint"/>.</summary>
    public static ReadOnlySpan<byte> JwkThumbprintUtf8 => "jkt"u8;

    /// <summary>
    /// The <c>jkt</c> member name inside the <c>cnf</c> (Confirmation)
    /// structured claim per RFC 7800 §3.1. Carries the base64url-encoded
    /// RFC 7638 JWK thumbprint of the proof-of-possession key the token is
    /// sender-constrained to per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">RFC 9449 §6.1</see>.
    /// </summary>
    public static readonly string JwkThumbprint = Utf8Constants.ToInternedString(JwkThumbprintUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SubJwk"/>.</summary>
    public static ReadOnlySpan<byte> SubJwkUtf8 => "sub_jwk"u8;

    /// <summary>
    /// The <c>sub_jwk</c> claim carries the bare public key (JWK format, not an
    /// X.509 certificate value) used to check the signature of a Self-Issued ID
    /// Token when the Subject Syntax Type is JWK Thumbprint. Present if and only
    /// if the <c>sub</c> claim is the RFC 7638 thumbprint of this key. See
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#SelfIssuedResponse">OIDC Core §7.4</see>
    /// and
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11">SIOPv2 §11</see>.
    /// </summary>
    public static readonly string SubJwk = Utf8Constants.ToInternedString(SubJwkUtf8);


    /// <summary>Whether <paramref name="claim"/> is <see cref="Iss"/>.</summary>
    public static bool IsIss(string claim) => Equals(claim, Iss);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Sub"/>.</summary>
    public static bool IsSub(string claim) => Equals(claim, Sub);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Aud"/>.</summary>
    public static bool IsAud(string claim) => Equals(claim, Aud);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Exp"/>.</summary>
    public static bool IsExp(string claim) => Equals(claim, Exp);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Nbf"/>.</summary>
    public static bool IsNbf(string claim) => Equals(claim, Nbf);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Iat"/>.</summary>
    public static bool IsIat(string claim) => Equals(claim, Iat);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Jti"/>.</summary>
    public static bool IsJti(string claim) => Equals(claim, Jti);

    /// <summary>Whether <paramref name="claim"/> is <see cref="ClientId"/>.</summary>
    public static bool IsClientId(string claim) => Equals(claim, ClientId);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Nonce"/>.</summary>
    public static bool IsNonce(string claim) => Equals(claim, Nonce);

    /// <summary>Whether <paramref name="claim"/> is <see cref="AuthTime"/>.</summary>
    public static bool IsAuthTime(string claim) => Equals(claim, AuthTime);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Acr"/>.</summary>
    public static bool IsAcr(string claim) => Equals(claim, Acr);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Amr"/>.</summary>
    public static bool IsAmr(string claim) => Equals(claim, Amr);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Azp"/>.</summary>
    public static bool IsAzp(string claim) => Equals(claim, Azp);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Name"/>.</summary>
    public static bool IsName(string claim) => Equals(claim, Name);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Roles"/>.</summary>
    public static bool IsRoles(string claim) => Equals(claim, Roles);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Tenant"/>.</summary>
    public static bool IsTenant(string claim) => Equals(claim, Tenant);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Vct"/>.</summary>
    public static bool IsVct(string claim) => Equals(claim, Vct);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Cnf"/>.</summary>
    public static bool IsCnf(string claim) => Equals(claim, Cnf);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Htm"/>.</summary>
    public static bool IsHtm(string claim) => Equals(claim, Htm);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Htu"/>.</summary>
    public static bool IsHtu(string claim) => Equals(claim, Htu);

    /// <summary>Whether <paramref name="claim"/> is <see cref="Ath"/>.</summary>
    public static bool IsAth(string claim) => Equals(claim, Ath);

    /// <summary>Whether <paramref name="claim"/> is <see cref="JwkThumbprint"/>.</summary>
    public static bool IsJwkThumbprint(string claim) => Equals(claim, JwkThumbprint);

    /// <summary>Whether <paramref name="claim"/> is <see cref="SubJwk"/>.</summary>
    public static bool IsSubJwk(string claim) => Equals(claim, SubJwk);


    /// <summary>
    /// Returns the interned constant for a known claim name, or the original string if
    /// unrecognized. Enables reference-equality fast paths downstream.
    /// </summary>
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
        _ when IsAcr(claim) => Acr,
        _ when IsAmr(claim) => Amr,
        _ when IsAzp(claim) => Azp,
        _ when IsName(claim) => Name,
        _ when IsRoles(claim) => Roles,
        _ when IsTenant(claim) => Tenant,
        _ when IsVct(claim) => Vct,
        _ when IsCnf(claim) => Cnf,
        _ when IsHtm(claim) => Htm,
        _ when IsHtu(claim) => Htu,
        _ when IsAth(claim) => Ath,
        _ when IsJwkThumbprint(claim) => JwkThumbprint,
        _ when IsSubJwk(claim) => SubJwk,
        _ => claim
    };


    /// <summary>
    /// Compares two claim names for equality. Comparison is case-sensitive per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519">RFC 7519</see>.
    /// </summary>
    public static bool Equals(string claimA, string claimB) =>
        object.ReferenceEquals(claimA, claimB) || StringComparer.Ordinal.Equals(claimA, claimB);
}
