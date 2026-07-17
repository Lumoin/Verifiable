using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// Wire-string constants for <see cref="PublicKeyCredentialHint"/> plus the enum/string conversions
/// between them.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-hints">W3C Web Authentication Level 3, section
/// 5.8.8: User-agent Hints Enumeration (enum <c>PublicKeyCredentialHint</c>)</see>. A ceremony-options
/// builder carries a sequence of <see cref="PublicKeyCredentialHint"/> values; a
/// <c>PublicKeyCredentialCreationOptions</c>/<c>PublicKeyCredentialRequestOptions</c> JSON writer
/// calls <see cref="ToWireValue"/> to render each <c>hints</c> array element, and a reader calls
/// <see cref="FromWireValue"/> to parse them back.
/// </remarks>
public static class WellKnownPublicKeyCredentialHints
{
    /// <summary>The UTF-8 source literal of <see cref="SecurityKey"/>.</summary>
    public static ReadOnlySpan<byte> SecurityKeyUtf8 => "security-key"u8;

    /// <summary>
    /// The <c>security-key</c> wire value.
    /// </summary>
    public static readonly string SecurityKey = Utf8Constants.ToInternedString(SecurityKeyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientDevice"/>.</summary>
    public static ReadOnlySpan<byte> ClientDeviceUtf8 => "client-device"u8;

    /// <summary>
    /// The <c>client-device</c> wire value.
    /// </summary>
    public static readonly string ClientDevice = Utf8Constants.ToInternedString(ClientDeviceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Hybrid"/>.</summary>
    public static ReadOnlySpan<byte> HybridUtf8 => "hybrid"u8;

    /// <summary>
    /// The <c>hybrid</c> wire value.
    /// </summary>
    public static readonly string Hybrid = Utf8Constants.ToInternedString(HybridUtf8);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="SecurityKey"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="SecurityKey"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsSecurityKey(string value) => Equals(SecurityKey, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="ClientDevice"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="ClientDevice"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsClientDevice(string value) => Equals(ClientDevice, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="Hybrid"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="Hybrid"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsHybrid(string value) => Equals(Hybrid, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is one of the three registered
    /// <c>PublicKeyCredentialHint</c> wire values.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is a registered value; otherwise <see langword="false"/>.</returns>
    public static bool IsRegisteredValue(string value) => IsSecurityKey(value) || IsClientDevice(value) || IsHybrid(value);


    /// <summary>
    /// Maps a <see cref="PublicKeyCredentialHint"/> to its CR-defined wire string.
    /// </summary>
    /// <param name="value">The hint value to convert.</param>
    /// <returns>The wire string for <paramref name="value"/>.</returns>
    public static string ToWireValue(PublicKeyCredentialHint value)
    {
        return value switch
        {
            PublicKeyCredentialHint.SecurityKey => SecurityKey,
            PublicKeyCredentialHint.ClientDevice => ClientDevice,
            PublicKeyCredentialHint.Hybrid => Hybrid,
            _ => throw new System.Diagnostics.UnreachableException($"Unhandled {nameof(PublicKeyCredentialHint)} value '{value}'; the enum admits only SecurityKey, ClientDevice and Hybrid.")
        };
    }


    /// <summary>
    /// Maps a wire string to its <see cref="PublicKeyCredentialHint"/> value.
    /// </summary>
    /// <param name="value">The wire value to convert.</param>
    /// <returns>The <see cref="PublicKeyCredentialHint"/> value corresponding to <paramref name="value"/>.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException">
    /// Thrown when <paramref name="value"/> is not one of <see cref="SecurityKey"/>,
    /// <see cref="ClientDevice"/> or <see cref="Hybrid"/>.
    /// </exception>
    public static PublicKeyCredentialHint FromWireValue(string value)
    {
        return value switch
        {
            _ when IsSecurityKey(value) => PublicKeyCredentialHint.SecurityKey,
            _ when IsClientDevice(value) => PublicKeyCredentialHint.ClientDevice,
            _ when IsHybrid(value) => PublicKeyCredentialHint.Hybrid,
            _ => throw new System.ArgumentOutOfRangeException(nameof(value), value, $"'{value}' is not a registered PublicKeyCredentialHint wire value.")
        };
    }


    /// <summary>
    /// Maps a hint to the <c>authenticatorSelection.authenticatorAttachment</c> value older user
    /// agents expect it to imply, per the compatibility SHOULD documented on each
    /// <see cref="PublicKeyCredentialHint"/> member.
    /// </summary>
    /// <param name="value">The hint to map.</param>
    /// <returns>
    /// <see cref="WellKnownAuthenticatorAttachments.CrossPlatform"/> for
    /// <see cref="PublicKeyCredentialHint.SecurityKey"/> and <see cref="PublicKeyCredentialHint.Hybrid"/>;
    /// <see cref="WellKnownAuthenticatorAttachments.Platform"/> for
    /// <see cref="PublicKeyCredentialHint.ClientDevice"/>.
    /// </returns>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-hints-extension">W3C Web Authentication
    /// Level 3, section 5.8.8</see> — row 4470 of this arc's normative tally. Registration-options
    /// only: request options carry no <c>authenticatorAttachment</c> member for this mapping to set.
    /// </remarks>
    public static string ToCompatibilityAuthenticatorAttachment(PublicKeyCredentialHint value)
    {
        return value switch
        {
            PublicKeyCredentialHint.SecurityKey => WellKnownAuthenticatorAttachments.CrossPlatform,
            PublicKeyCredentialHint.ClientDevice => WellKnownAuthenticatorAttachments.Platform,
            PublicKeyCredentialHint.Hybrid => WellKnownAuthenticatorAttachments.CrossPlatform,
            _ => throw new System.Diagnostics.UnreachableException($"Unhandled {nameof(PublicKeyCredentialHint)} value '{value}'; the enum admits only SecurityKey, ClientDevice and Hybrid.")
        };
    }


    /// <summary>
    /// Returns a value that indicates if the wire values are the same.
    /// </summary>
    /// <param name="valueA">The first wire value to compare.</param>
    /// <param name="valueB">The second wire value to compare.</param>
    /// <returns>
    /// <see langword="true" /> if <paramref name="valueA"/> and <paramref name="valueB"/> are the same; otherwise, <see langword="false" />.
    /// </returns>
    public static bool Equals(string valueA, string valueB)
    {
        return object.ReferenceEquals(valueA, valueB) || StringComparer.Ordinal.Equals(valueA, valueB);
    }
}
