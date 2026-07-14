using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// Wire-string constants for <see cref="AttestationConveyancePreference"/> plus the enum/string
/// conversions between them.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-attestation-convey">W3C Web Authentication
/// Level 3, section 5.4.7: Attestation Conveyance Preference Enumeration (enum
/// <c>AttestationConveyancePreference</c>)</see>. A ceremony-options builder carries the
/// <see cref="AttestationConveyancePreference"/> enum; a <c>PublicKeyCredentialCreationOptions</c>
/// JSON writer calls <see cref="ToWireValue"/> to render the <c>attestation</c> member, and a reader
/// calls <see cref="FromWireValue"/> to parse it back.
/// </remarks>
public static class WellKnownAttestationConveyancePreferences
{
    /// <summary>The UTF-8 source literal of <see cref="None"/>.</summary>
    public static ReadOnlySpan<byte> NoneUtf8 => "none"u8;

    /// <summary>
    /// The <c>none</c> wire value.
    /// </summary>
    public static readonly string None = Utf8Constants.ToInternedString(NoneUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Indirect"/>.</summary>
    public static ReadOnlySpan<byte> IndirectUtf8 => "indirect"u8;

    /// <summary>
    /// The <c>indirect</c> wire value.
    /// </summary>
    public static readonly string Indirect = Utf8Constants.ToInternedString(IndirectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Direct"/>.</summary>
    public static ReadOnlySpan<byte> DirectUtf8 => "direct"u8;

    /// <summary>
    /// The <c>direct</c> wire value.
    /// </summary>
    public static readonly string Direct = Utf8Constants.ToInternedString(DirectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Enterprise"/>.</summary>
    public static ReadOnlySpan<byte> EnterpriseUtf8 => "enterprise"u8;

    /// <summary>
    /// The <c>enterprise</c> wire value.
    /// </summary>
    public static readonly string Enterprise = Utf8Constants.ToInternedString(EnterpriseUtf8);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="None"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="None"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsNone(string value) => Equals(None, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="Indirect"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="Indirect"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsIndirect(string value) => Equals(Indirect, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="Direct"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="Direct"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsDirect(string value) => Equals(Direct, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="Enterprise"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="Enterprise"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsEnterprise(string value) => Equals(Enterprise, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is one of the four registered
    /// <c>AttestationConveyancePreference</c> wire values.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is a registered value; otherwise <see langword="false"/>.</returns>
    public static bool IsRegisteredValue(string value) => IsNone(value) || IsIndirect(value) || IsDirect(value) || IsEnterprise(value);


    /// <summary>
    /// Maps an <see cref="AttestationConveyancePreference"/> to its CR-defined wire string.
    /// </summary>
    /// <param name="value">The preference value to convert.</param>
    /// <returns>The wire string for <paramref name="value"/>.</returns>
    public static string ToWireValue(AttestationConveyancePreference value)
    {
        return value switch
        {
            AttestationConveyancePreference.None => None,
            AttestationConveyancePreference.Indirect => Indirect,
            AttestationConveyancePreference.Direct => Direct,
            AttestationConveyancePreference.Enterprise => Enterprise,
            _ => throw new System.Diagnostics.UnreachableException($"Unhandled {nameof(AttestationConveyancePreference)} value '{value}'; the enum admits only None, Indirect, Direct and Enterprise.")
        };
    }


    /// <summary>
    /// Maps a wire string to its <see cref="AttestationConveyancePreference"/> value.
    /// </summary>
    /// <param name="value">The wire value to convert.</param>
    /// <returns>The <see cref="AttestationConveyancePreference"/> value corresponding to <paramref name="value"/>.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException">
    /// Thrown when <paramref name="value"/> is not one of <see cref="None"/>, <see cref="Indirect"/>,
    /// <see cref="Direct"/> or <see cref="Enterprise"/>.
    /// </exception>
    public static AttestationConveyancePreference FromWireValue(string value)
    {
        return value switch
        {
            _ when IsNone(value) => AttestationConveyancePreference.None,
            _ when IsIndirect(value) => AttestationConveyancePreference.Indirect,
            _ when IsDirect(value) => AttestationConveyancePreference.Direct,
            _ when IsEnterprise(value) => AttestationConveyancePreference.Enterprise,
            _ => throw new System.ArgumentOutOfRangeException(nameof(value), value, $"'{value}' is not a registered AttestationConveyancePreference wire value.")
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
