using System.Diagnostics;

namespace Verifiable.OAuth.Introspection;

/// <summary>
/// The application's answer to an OAuth 2.0 Token Introspection request
/// (<see href="https://www.rfc-editor.org/rfc/rfc7662#section-2.2">RFC 7662 §2.2</see>):
/// the token's metadata as the authorization server knows it, projected onto the
/// specification's top-level response members. The application produces this from its
/// own token store; the library owns the wire shape, serialising it to the
/// <c>application/json</c> response body.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="IsActive"/> is the one REQUIRED member. When it is <see langword="false"/>
/// — the token is unknown, expired, revoked, or this caller may not see it — the library
/// emits <c>{"active":false}</c> and nothing else, honouring RFC 7662 §2.2's instruction
/// that the server SHOULD NOT disclose any further information about an inactive token
/// (including why it is inactive). Every other member here is therefore only ever written
/// when <see cref="IsActive"/> is <see langword="true"/>; an application returning an
/// inactive result can use <see cref="Inactive"/> and ignore the rest.
/// </para>
/// <para>
/// The standard members are typed; <see cref="AdditionalClaims"/> carries any
/// service-specific extension members the deployment adds (RFC 7662 §2.2 permits these as
/// top-level members) — for instance the <c>acr</c> and <c>auth_time</c> an RFC 9470
/// step-up deployment records on its access tokens. A proof-of-possession binding is
/// <see cref="Confirmation"/>, written as the top-level <c>cnf</c> member.
/// </para>
/// </remarks>
[DebuggerDisplay("TokenIntrospectionResult IsActive={IsActive} Subject={Subject}")]
public sealed record TokenIntrospectionResult
{
    /// <summary>
    /// RFC 7662 §2.2 <c>active</c> (REQUIRED): whether the presented token is currently
    /// active — generally that the authorization server issued it, the resource owner has
    /// not revoked it, and it is within its validity window.
    /// </summary>
    public required bool IsActive { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>scope</c>: the space-separated scopes associated with the token
    /// (OAuth 2.0 §3.3 format), or <see langword="null"/> when not surfaced.
    /// </summary>
    public string? Scope { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>client_id</c>: the client the token was issued to, or
    /// <see langword="null"/> when not surfaced.
    /// </summary>
    public string? ClientId { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>username</c>: a human-readable identifier for the resource owner
    /// who authorized the token, or <see langword="null"/> when not surfaced.
    /// </summary>
    public string? Username { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>token_type</c>: the token type (OAuth 2.0 §5.1), or
    /// <see langword="null"/> when not surfaced.
    /// </summary>
    public string? TokenType { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>exp</c>: when the token expires. Serialised as a JWT NumericDate
    /// (seconds since the Unix epoch). <see langword="null"/> when not surfaced.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>iat</c>: when the token was issued. Serialised as a JWT NumericDate.
    /// <see langword="null"/> when not surfaced.
    /// </summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>nbf</c>: the earliest time the token may be used. Serialised as a
    /// JWT NumericDate. <see langword="null"/> when not surfaced.
    /// </summary>
    public DateTimeOffset? NotBefore { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>sub</c>: the token's subject, usually a machine-readable identifier
    /// of the resource owner, or <see langword="null"/> when not surfaced.
    /// </summary>
    public string? Subject { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>aud</c>: the token's intended audience(s). A single entry is written
    /// as a JSON string and multiple entries as a JSON array, both valid per RFC 7519.
    /// <see langword="null"/> or empty when not surfaced.
    /// </summary>
    public IReadOnlyList<string>? Audience { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>iss</c>: the issuer of the token (a JWT StringOrURI), or
    /// <see langword="null"/> when not surfaced.
    /// </summary>
    public string? Issuer { get; init; }

    /// <summary>
    /// RFC 7662 §2.2 <c>jti</c>: the token's unique identifier, or <see langword="null"/>
    /// when not surfaced.
    /// </summary>
    public string? JwtId { get; init; }

    /// <summary>
    /// RFC 9396 §9.2 <c>authorization_details</c>: the granted Rich Authorization Requests
    /// details associated with the token, or <see langword="null"/> when the token carries none
    /// (or the deployment does not surface them to this caller). Written as the top-level
    /// <c>authorization_details</c> member of the introspection response. RFC 9396 §9.2: "If the
    /// AS includes authorization detail information for the token in its response, the information
    /// MUST be conveyed with authorization_details as a top-level member of the introspection
    /// response JSON object." The library emits exactly what the application supplies — the
    /// application owns the §9.2 "potentially filtered and extended for the RS making the
    /// introspection request" decision, the same way it narrows <see cref="Scope"/> per calling
    /// resource. Each entry carries the §2 structure (the §2 REQUIRED <c>type</c> and any common
    /// or type-specific members).
    /// </summary>
    public IReadOnlyList<AuthorizationDetail>? AuthorizationDetails { get; init; }

    /// <summary>
    /// The proof-of-possession binding of a sender-constrained token, or <see langword="null"/> for a token bound to no
    /// key. The library writes a confirmation carrying a <see cref="Server.ConfirmationMethod.JwkThumbprint"/> as the
    /// top-level <c>cnf</c> member <c>{"jkt":"&lt;thumbprint&gt;"}</c>, the shape it writes into the tokens it issues
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.2">RFC 9449 Section 6.2</see>: "For a DPoP-bound
    /// access token, the hash of the public key to which the token is bound is conveyed to the protected resource as
    /// metainformation in a token introspection response. The hash is conveyed using the same cnf content with jkt
    /// member structure as the JWK Thumbprint confirmation method, described in Section 6.1, as a top-level member of the
    /// introspection response JSON."), and with it <c>token_type</c> written <c>DPoP</c> where <see cref="TokenType"/>
    /// is <see langword="null"/> or a case variant of it (Section 6.2: "If the token_type member is included in the
    /// introspection response, it MUST contain the value DPoP."). A <see cref="TokenType"/> other than <c>DPoP</c> beside a
    /// confirmation, or <c>DPoP</c> without one, contradicts that section, and so does a
    /// <see cref="Server.ConfirmationMethod.JwkThumbprint"/> that is no JWK SHA-256 Thumbprint spelling, the base64url
    /// encoding of 32 octets, a blank value included
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9449#section-6.1">Section 6.1</see>: "The value of the jkt member MUST
    /// be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint"); each is answered as a fault of
    /// the application's wiring (<see cref="Server.IntrospectTokenDelegate"/>).
    /// </summary>
    public Server.ConfirmationMethod? Confirmation { get; init; }

    /// <summary>
    /// Service-specific extension members written as additional top-level members of the
    /// response object (RFC 7662 §2.2). Each value is serialised by its runtime type
    /// (string, boolean, number, nested object, or array). <see langword="null"/> when the
    /// deployment surfaces no extensions. A key naming a member the library writes from the typed
    /// members above, <c>active</c>, <c>scope</c>, <c>client_id</c>, <c>username</c>,
    /// <c>token_type</c>, <c>exp</c>, <c>iat</c>, <c>nbf</c>, <c>sub</c>, <c>aud</c>, <c>iss</c>,
    /// <c>jti</c>, <c>cnf</c> or <c>authorization_details</c>, would overwrite it after the typed
    /// members were checked, so an active answer carrying one is answered as a fault of the
    /// application's wiring (<see cref="Server.IntrospectTokenDelegate"/>); the binding is
    /// <see cref="Confirmation"/> and the token type <see cref="TokenType"/>.
    /// </summary>
    /// <remarks>
    /// A result <see cref="OAuthResponseParsers.ParseTokenIntrospectionResponse"/> reads carries here every extension
    /// member the authorization server wrote, <c>authorization_details</c> among them since the reader does not type it
    /// (<see cref="AuthorizationDetails"/> stays <see langword="null"/>), each value decoded by its JSON shape: a string as
    /// its text, a boolean as a <see cref="bool"/>, an integer as a <see cref="long"/>, another number as a
    /// <see cref="double"/>, an object or an array as its decoded value; a member whose value is <c>null</c> is omitted. A
    /// parsed result is not thereby valid for the server's own writing: an active result answered back through
    /// <see cref="Server.IntrospectTokenDelegate"/> with <c>authorization_details</c> here is a fault of the application's
    /// wiring by the rule above.
    /// </remarks>
    public IReadOnlyDictionary<string, object>? AdditionalClaims { get; init; }

    /// <summary>
    /// The canonical inactive result — <c>{"active":false}</c> — for a token that is
    /// unknown, expired, revoked, or that the calling resource may not introspect
    /// (RFC 7662 §2.2 / §2.3).
    /// </summary>
    public static TokenIntrospectionResult Inactive { get; } = new() { IsActive = false };
}
