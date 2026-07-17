using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// Wire-string constants for <see cref="ResidentKeyRequirement"/> plus the enum/string conversions
/// between them.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement">W3C Web Authentication
/// Level 3, section 5.4.6: Resident Key Requirement Enumeration (enum
/// <c>ResidentKeyRequirement</c>)</see>. A ceremony-options builder carries the
/// <see cref="ResidentKeyRequirement"/> enum; a <c>PublicKeyCredentialCreationOptions</c> JSON writer
/// calls <see cref="ToWireValue"/> to render the <c>authenticatorSelection.residentKey</c> member,
/// and a reader calls <see cref="FromWireValue"/> to parse it back.
/// </remarks>
public static class WellKnownResidentKeyRequirements
{
    /// <summary>The UTF-8 source literal of <see cref="Discouraged"/>.</summary>
    public static ReadOnlySpan<byte> DiscouragedUtf8 => "discouraged"u8;

    /// <summary>
    /// The <c>discouraged</c> wire value.
    /// </summary>
    public static readonly string Discouraged = Utf8Constants.ToInternedString(DiscouragedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Preferred"/>.</summary>
    public static ReadOnlySpan<byte> PreferredUtf8 => "preferred"u8;

    /// <summary>
    /// The <c>preferred</c> wire value.
    /// </summary>
    public static readonly string Preferred = Utf8Constants.ToInternedString(PreferredUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Required"/>.</summary>
    public static ReadOnlySpan<byte> RequiredUtf8 => "required"u8;

    /// <summary>
    /// The <c>required</c> wire value.
    /// </summary>
    public static readonly string Required = Utf8Constants.ToInternedString(RequiredUtf8);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="Discouraged"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="Discouraged"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsDiscouraged(string value) => Equals(Discouraged, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="Preferred"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="Preferred"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsPreferred(string value) => Equals(Preferred, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="Required"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="Required"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsRequired(string value) => Equals(Required, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is one of the three registered
    /// <c>ResidentKeyRequirement</c> wire values.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is a registered value; otherwise <see langword="false"/>.</returns>
    public static bool IsRegisteredValue(string value) => IsDiscouraged(value) || IsPreferred(value) || IsRequired(value);


    /// <summary>
    /// Maps a <see cref="ResidentKeyRequirement"/> to its CR-defined wire string.
    /// </summary>
    /// <param name="value">The policy value to convert.</param>
    /// <returns>The wire string for <paramref name="value"/>.</returns>
    public static string ToWireValue(ResidentKeyRequirement value)
    {
        return value switch
        {
            ResidentKeyRequirement.Discouraged => Discouraged,
            ResidentKeyRequirement.Preferred => Preferred,
            ResidentKeyRequirement.Required => Required,
            _ => throw new System.Diagnostics.UnreachableException($"Unhandled {nameof(ResidentKeyRequirement)} value '{value}'; the enum admits only Discouraged, Preferred and Required.")
        };
    }


    /// <summary>
    /// Maps a wire string to its <see cref="ResidentKeyRequirement"/> value.
    /// </summary>
    /// <param name="value">The wire value to convert.</param>
    /// <returns>The <see cref="ResidentKeyRequirement"/> value corresponding to <paramref name="value"/>.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException">
    /// Thrown when <paramref name="value"/> is not one of <see cref="Discouraged"/>,
    /// <see cref="Preferred"/> or <see cref="Required"/>.
    /// </exception>
    public static ResidentKeyRequirement FromWireValue(string value)
    {
        return value switch
        {
            _ when IsDiscouraged(value) => ResidentKeyRequirement.Discouraged,
            _ when IsPreferred(value) => ResidentKeyRequirement.Preferred,
            _ when IsRequired(value) => ResidentKeyRequirement.Required,
            _ => throw new System.ArgumentOutOfRangeException(nameof(value), value, $"'{value}' is not a registered ResidentKeyRequirement wire value.")
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
