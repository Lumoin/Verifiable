using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.WellKnown;

/// <summary>
/// The <c>prompt</c> wire values per
/// <see href="https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest">OIDC Core §3.1.2.1</see>.
/// Comparison is ordinal. A value outside this set is not an error: "If an OP receives a
/// <c>prompt</c> value outside the set defined above that it does not understand, it MAY
/// return an error or it MAY ignore it" (§3.1.2.1) — this library ignores it.
/// </summary>
public static class WellKnownPromptValues
{
    /// <summary>The UTF-8 source literal of <see cref="None"/>.</summary>
    public static ReadOnlySpan<byte> NoneUtf8 => "none"u8;

    /// <summary>
    /// The <c>none</c> value: the Authorization Server MUST NOT display any authentication or
    /// consent user interface pages, per OIDC Core §3.1.2.1. Combined with any other value in
    /// the same request, the request is an error ("If this parameter contains none with any
    /// other value, an error is returned.").
    /// </summary>
    public static string None { get; } = Utf8Constants.ToInternedString(NoneUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="None"/>.</summary>
    public static bool IsNone(string value) => string.Equals(value, None, StringComparison.Ordinal);

    /// <summary>The UTF-8 source literal of <see cref="Login"/>.</summary>
    public static ReadOnlySpan<byte> LoginUtf8 => "login"u8;

    /// <summary>
    /// The <c>login</c> value: the Authorization Server SHOULD prompt the End-User for
    /// reauthentication; "If it cannot reauthenticate the End-User, it MUST return an error,
    /// typically login_required" (OIDC Core §3.1.2.1).
    /// </summary>
    public static string Login { get; } = Utf8Constants.ToInternedString(LoginUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="Login"/>.</summary>
    public static bool IsLogin(string value) => string.Equals(value, Login, StringComparison.Ordinal);

    /// <summary>The UTF-8 source literal of <see cref="Consent"/>.</summary>
    public static ReadOnlySpan<byte> ConsentUtf8 => "consent"u8;

    /// <summary>
    /// The <c>consent</c> value: the Authorization Server SHOULD prompt the End-User for
    /// consent; "If it cannot obtain consent, it MUST return an error, typically
    /// consent_required" (OIDC Core §3.1.2.1).
    /// </summary>
    public static string Consent { get; } = Utf8Constants.ToInternedString(ConsentUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="Consent"/>.</summary>
    public static bool IsConsent(string value) => string.Equals(value, Consent, StringComparison.Ordinal);

    /// <summary>The UTF-8 source literal of <see cref="SelectAccount"/>.</summary>
    public static ReadOnlySpan<byte> SelectAccountUtf8 => "select_account"u8;

    /// <summary>
    /// The <c>select_account</c> value: the Authorization Server SHOULD prompt the End-User to
    /// select a user account; "If it cannot obtain an account selection choice made by the
    /// End-User, it MUST return an error, typically account_selection_required" (OIDC Core
    /// §3.1.2.1).
    /// </summary>
    public static string SelectAccount { get; } = Utf8Constants.ToInternedString(SelectAccountUtf8);


    /// <summary>Whether <paramref name="value"/> is <see cref="SelectAccount"/>.</summary>
    public static bool IsSelectAccount(string value) => string.Equals(value, SelectAccount, StringComparison.Ordinal);
}
