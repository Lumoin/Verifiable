using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Provides typed accessors for well-known tokens stored in an <see cref="IssuedTokenSet"/>.
/// </summary>
/// <remarks>
/// <para>
/// Accessors are surfaced via C# 14 extension syntax so they appear directly on
/// <see cref="IssuedTokenSet"/> in IntelliSense without modifying the type. Library
/// users can define their own extension class and the methods appear alongside the
/// library-provided ones:
/// </para>
/// <code>
/// public static class MyTokenSetExtensions
/// {
///     extension(IssuedTokenSet set)
///     {
///         public string? MyLogoutToken => set.Get(WellKnownTokenTypes.LogoutToken);
///     }
/// }
/// </code>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class IssuedTokenSetExtensions
{
    extension(IssuedTokenSet set)
    {
        /// <summary>
        /// The OAuth 2.0 access token, or <see langword="null"/> when the response did
        /// not include one.
        /// </summary>
        public string? AccessToken => set.Get(WellKnownTokenTypes.AccessToken);

        /// <summary>
        /// The OpenID Connect ID Token, or <see langword="null"/> when the response did
        /// not include one.
        /// </summary>
        public string? IdToken => set.Get(WellKnownTokenTypes.IdToken);

        /// <summary>
        /// The OAuth 2.0 refresh token, or <see langword="null"/> when the response did
        /// not include one.
        /// </summary>
        public string? RefreshToken => set.Get(WellKnownTokenTypes.RefreshToken);
    }
}
