using System.Diagnostics;

namespace Verifiable.OAuth.Oidc;

/// <summary>
/// Authentication-context claims for the ID Token: <c>acr</c>, <c>amr</c>,
/// <c>auth_time</c>. Per OpenID Connect Core 1.0 §2.
/// </summary>
[DebuggerDisplay("AuthenticationContext Acr={Acr,nq}")]
public sealed record AuthenticationContext
{
    /// <summary>
    /// Authentication Methods References (<c>amr</c>): identifiers for the
    /// methods used at authentication (e.g. <c>pwd</c>, <c>mfa</c>, <c>hwk</c>).
    /// OIDC Core §2.
    /// </summary>
    public IReadOnlyList<string>? Amr { get; init; }

    /// <summary>
    /// Authentication Context Class Reference (<c>acr</c>): the assurance
    /// level. RFC 6711 IANA registry; application-defined values when not
    /// registered.
    /// </summary>
    public string? Acr { get; init; }

    /// <summary>
    /// Time when the End-User authentication occurred (<c>auth_time</c>).
    /// When populated, overrides <see cref="IssuanceContext.AuthTime"/> for
    /// ID Token emission; otherwise the producer uses the context's value.
    /// </summary>
    public DateTimeOffset? AuthTime { get; init; }
}
