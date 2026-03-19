using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Provides typed accessors for well-known token audits stored in an
/// <see cref="IssuedTokenAuditSet"/>.
/// </summary>
/// <remarks>
/// <para>
/// Mirrors the shape of <see cref="IssuedTokenSetExtensions"/>. Library users
/// add their own typed accessors via additional extension blocks following the
/// same pattern.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class IssuedTokenAuditSetExtensions
{
    extension(IssuedTokenAuditSet set)
    {
        /// <summary>
        /// The audit for the OAuth 2.0 access token, or <see langword="null"/>
        /// when none was issued.
        /// </summary>
        public IssuedTokenAudit? AccessTokenAudit => set.Get(WellKnownTokenTypes.AccessToken);

        /// <summary>
        /// The audit for the OpenID Connect ID Token, or <see langword="null"/>
        /// when none was issued.
        /// </summary>
        public IssuedTokenAudit? IdTokenAudit => set.Get(WellKnownTokenTypes.IdToken);

        /// <summary>
        /// The audit for the OAuth 2.0 refresh token, or <see langword="null"/>
        /// when none was issued.
        /// </summary>
        public IssuedTokenAudit? RefreshTokenAudit => set.Get(WellKnownTokenTypes.RefreshToken);
    }
}
