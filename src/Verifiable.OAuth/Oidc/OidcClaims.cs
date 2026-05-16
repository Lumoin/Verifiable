using System.Diagnostics;

namespace Verifiable.OAuth.Oidc;

/// <summary>
/// The OpenID Connect Core 1.0 standard claim set an application supplies
/// for an authenticated user. Composed of typed sub-records, each
/// corresponding to an OIDC scope per §5.4. The application populates only
/// the sub-records relevant to the scopes granted at authorization.
/// </summary>
/// <remarks>
/// <para>
/// The library doesn't generate or persist claims — it carries them from
/// the application's identity source
/// (<see cref="Verifiable.OAuth.Server.ResolveOidcClaimsDelegate"/>) into
/// the ID Token payload and the UserInfo response. The producer and the
/// UserInfo handler both consume the same record.
/// </para>
/// <para>
/// A minimal authenticated session carries only <see cref="Subject"/> (the
/// REQUIRED <c>sub</c> claim per OIDC Core §2). Higher-scope requests
/// populate more sub-records.
/// </para>
/// </remarks>
[DebuggerDisplay("OidcClaims Sub={Subject,nq}")]
public sealed record OidcClaims
{
    /// <summary>
    /// The Subject Identifier (<c>sub</c> claim per OIDC Core §2). REQUIRED.
    /// Stable, opaque identifier for the authenticated user within this
    /// issuer's scope. Application-defined format (UUID, opaque string,
    /// pairwise-pseudonymous identifier).
    /// </summary>
    public required string Subject { get; init; }

    /// <summary>
    /// Profile claims emitted when the <c>profile</c> scope is granted.
    /// </summary>
    public ProfileClaims? Profile { get; init; }

    /// <summary>
    /// Email claims emitted when the <c>email</c> scope is granted.
    /// </summary>
    public EmailClaims? Email { get; init; }

    /// <summary>
    /// Address claims emitted when the <c>address</c> scope is granted.
    /// </summary>
    public AddressClaims? Address { get; init; }

    /// <summary>
    /// Phone claims emitted when the <c>phone</c> scope is granted.
    /// </summary>
    public PhoneClaims? Phone { get; init; }

    /// <summary>
    /// Authentication context (<c>amr</c>, <c>acr</c>, <c>auth_time</c>) per
    /// OIDC Core §2. Emitted on the ID Token when populated.
    /// </summary>
    public AuthenticationContext? AuthContext { get; init; }
}
