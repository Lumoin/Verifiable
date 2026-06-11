using System;
using System.Collections.Generic;
using System.Diagnostics;

using Verifiable.OAuth;

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
/// step-up deployment records on its access tokens, or a <c>cnf</c> proof-of-possession
/// confirmation.
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
    /// Service-specific extension members written as additional top-level members of the
    /// response object (RFC 7662 §2.2). Each value is serialised by its runtime type
    /// (string, boolean, number, nested object, or array). <see langword="null"/> when the
    /// deployment surfaces no extensions.
    /// </summary>
    public IReadOnlyDictionary<string, object>? AdditionalClaims { get; init; }

    /// <summary>
    /// The canonical inactive result — <c>{"active":false}</c> — for a token that is
    /// unknown, expired, revoked, or that the calling resource may not introspect
    /// (RFC 7662 §2.2 / §2.3).
    /// </summary>
    public static TokenIntrospectionResult Inactive { get; } = new() { IsActive = false };
}
