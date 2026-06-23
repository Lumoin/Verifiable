using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.WellKnown;

/// <summary>
/// The <c>code_challenge_method</c> wire values per
/// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.3">RFC 7636 §4.3</see>. Comparison is ordinal.
/// </summary>
public static class WellKnownCodeChallengeMethods
{
    /// <summary>The UTF-8 source literal of <see cref="S256"/>.</summary>
    public static ReadOnlySpan<byte> S256Utf8 => "S256"u8;

    /// <summary>
    /// The <c>S256</c> PKCE code challenge method (RFC 7636 §4.3) — the only permitted value per HAIP 1.0
    /// and RFC 9700 §2.1.1; the plain method must not be used as it negates PKCE's downgrade protection.
    /// </summary>
    public static readonly string S256 = Utf8Constants.ToInternedString(S256Utf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="S256"/>.</summary>
    public static bool IsS256(string value) => string.Equals(value, S256, StringComparison.Ordinal);
}
