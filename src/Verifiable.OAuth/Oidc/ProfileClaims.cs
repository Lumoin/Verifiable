using System.Diagnostics;

namespace Verifiable.OAuth.Oidc;

/// <summary>
/// Claims emitted under the OpenID Connect Core 1.0 §5.4 <c>profile</c>
/// scope. All members optional; the producer emits only those populated.
/// </summary>
[DebuggerDisplay("ProfileClaims Name={Name,nq}")]
public sealed record ProfileClaims
{
    /// <summary>
    /// The End-User's full name in displayable form, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>name</c> claim.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// The End-User's surname(s) or last name(s), per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>family_name</c> claim.
    /// </summary>
    public string? FamilyName { get; init; }

    /// <summary>
    /// The End-User's given name(s) or first name(s), per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>given_name</c> claim.
    /// </summary>
    public string? GivenName { get; init; }

    /// <summary>
    /// The End-User's middle name(s), per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>middle_name</c> claim.
    /// </summary>
    public string? MiddleName { get; init; }

    /// <summary>
    /// The End-User's casual name, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>nickname</c> claim.
    /// </summary>
    public string? Nickname { get; init; }

    /// <summary>
    /// The shorthand name by which the End-User wishes to be referred to, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>preferred_username</c> claim.
    /// </summary>
    public string? PreferredUsername { get; init; }

    /// <summary>
    /// The URL of the End-User's profile page, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>profile</c> claim.
    /// </summary>
    public Uri? Profile { get; init; }

    /// <summary>
    /// The URL of the End-User's profile picture, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>picture</c> claim.
    /// </summary>
    public Uri? Picture { get; init; }

    /// <summary>
    /// The URL of the End-User's web page or blog, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>website</c> claim.
    /// </summary>
    public Uri? Website { get; init; }

    /// <summary>
    /// The End-User's gender, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>gender</c> claim.
    /// </summary>
    public string? Gender { get; init; }

    /// <summary>
    /// The End-User's birthday, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>birthdate</c> claim.
    /// </summary>
    public DateOnly? Birthdate { get; init; }

    /// <summary>
    /// The End-User's time zone, e.g. <c>Europe/Paris</c>, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>zoneinfo</c> claim.
    /// </summary>
    public string? Zoneinfo { get; init; }

    /// <summary>
    /// The End-User's locale, e.g. <c>en-US</c>, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>locale</c> claim.
    /// </summary>
    public string? Locale { get; init; }

    /// <summary>
    /// The time the End-User's information was last updated, per
    /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims">OpenID Connect Core 1.0 §5.1</see>'s <c>updated_at</c> claim.
    /// </summary>
    public DateTimeOffset? UpdatedAt { get; init; }
}
