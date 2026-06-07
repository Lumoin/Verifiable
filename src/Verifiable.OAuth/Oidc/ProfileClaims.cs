using System.Diagnostics;

namespace Verifiable.OAuth.Oidc;

/// <summary>
/// Claims emitted under the OpenID Connect Core 1.0 §5.4 <c>profile</c>
/// scope. All members optional; the producer emits only those populated.
/// </summary>
[DebuggerDisplay("ProfileClaims Name={Name,nq}")]
public sealed record ProfileClaims
{
    public string? Name { get; init; }
    public string? FamilyName { get; init; }
    public string? GivenName { get; init; }
    public string? MiddleName { get; init; }
    public string? Nickname { get; init; }
    public string? PreferredUsername { get; init; }
    public Uri? Profile { get; init; }
    public Uri? Picture { get; init; }
    public Uri? Website { get; init; }
    public string? Gender { get; init; }
    public DateOnly? Birthdate { get; init; }
    public string? Zoneinfo { get; init; }
    public string? Locale { get; init; }
    public DateTimeOffset? UpdatedAt { get; init; }
}
