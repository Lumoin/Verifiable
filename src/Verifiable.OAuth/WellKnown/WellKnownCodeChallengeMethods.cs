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
    public static string S256 { get; } = Utf8Constants.ToInternedString(S256Utf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="S256"/>.</summary>
    public static bool IsS256(string value) => string.Equals(value, S256, StringComparison.Ordinal);

    /// <summary>The UTF-8 source literal of <see cref="Plain"/>.</summary>
    public static ReadOnlySpan<byte> PlainUtf8 => "plain"u8;

    /// <summary>
    /// The <c>plain</c> PKCE code challenge method (RFC 7636 §4.3) — where
    /// <c>code_verifier == code_challenge</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7636#section-4.6">RFC 7636 §4.6</see>. Accepted
    /// only under a deployment's
    /// <see cref="Verifiable.OAuth.Server.PkceMethodSet.S256AndPlain"/> policy, for interoperating
    /// with pre-OAuth-2.1 RFC 6749 + RFC 7636 deployments; the OAuth 2.1 profiles
    /// (<see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">draft-16 §7.5.2</see>)
    /// forbid it and RFC 9700 §2.1.1 discourages it because it exposes the verifier on the front
    /// channel, negating PKCE's downgrade protection.
    /// </summary>
    public static string Plain { get; } = Utf8Constants.ToInternedString(PlainUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="Plain"/>.</summary>
    public static bool IsPlain(string value) => string.Equals(value, Plain, StringComparison.Ordinal);
}
