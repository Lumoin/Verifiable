using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// The <c>AuthenticatorAttachment</c> enumeration's wire values.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-attachment">W3C Web Authentication Level 3,
/// section 5.4.5: Authenticator Attachment Enumeration (enum
/// <c>AuthenticatorAttachment</c>)</see>. Used both as an <c>authenticatorSelection.authenticatorAttachment</c>
/// request value (a relying party's authenticator-selection input) and as the client-reported
/// <c>PublicKeyCredential.authenticatorAttachment</c>/<c>RegistrationResponseJSON.authenticatorAttachment</c>/
/// <c>AuthenticationResponseJSON.authenticatorAttachment</c> value a relying party may choose to
/// store on <see cref="Fido2CredentialRecord"/>.
/// </remarks>
public static class WellKnownAuthenticatorAttachments
{
    /// <summary>The UTF-8 source literal of <see cref="Platform"/>.</summary>
    public static ReadOnlySpan<byte> PlatformUtf8 => "platform"u8;

    /// <summary>
    /// The <c>platform</c> value, for an authenticator that is part of the client device.
    /// </summary>
    public static readonly string Platform = Utf8Constants.ToInternedString(PlatformUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CrossPlatform"/>.</summary>
    public static ReadOnlySpan<byte> CrossPlatformUtf8 => "cross-platform"u8;

    /// <summary>
    /// The <c>cross-platform</c> value, for an authenticator that is removable from the client device.
    /// </summary>
    public static readonly string CrossPlatform = Utf8Constants.ToInternedString(CrossPlatformUtf8);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="Platform"/> value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="Platform"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsPlatform(string value) => Equals(Platform, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="CrossPlatform"/> value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="CrossPlatform"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsCrossPlatform(string value) => Equals(CrossPlatform, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is one of the two registered
    /// <c>AuthenticatorAttachment</c> wire values.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is a registered value; otherwise <see langword="false"/>.</returns>
    public static bool IsRegisteredValue(string value) => IsPlatform(value) || IsCrossPlatform(value);


    /// <summary>
    /// Normalizes a caller-supplied <c>authenticatorAttachment</c> value, treating anything that is
    /// not exactly <see cref="Platform"/> or <see cref="CrossPlatform"/> as absent.
    /// </summary>
    /// <param name="value">The raw value reported by the client, or <see langword="null"/> if none was reported.</param>
    /// <returns>
    /// <paramref name="value"/> unchanged when it is a registered value; otherwise
    /// <see langword="null"/>.
    /// </returns>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#iface-pkcredential">W3C Web Authentication
    /// Level 3, section 5.1: PublicKeyCredential Interface</see>: "Relying Parties SHOULD treat
    /// unknown values as if the value were null."
    /// </remarks>
    public static string? NormalizeOrDefault(string? value)
    {
        return value is not null && IsRegisteredValue(value) ? value : null;
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
