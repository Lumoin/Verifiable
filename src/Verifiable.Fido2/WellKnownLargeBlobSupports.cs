using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// Wire-string constants for <see cref="LargeBlobSupport"/> plus the enum/string conversions between
/// them.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension">W3C Web Authentication
/// Level 3, section 10.1.5: Large blob storage extension (largeBlob)</see>. A registration-options
/// builder carries the <see cref="LargeBlobSupport"/> enum on
/// <see cref="Fido2LargeBlobRegistrationExtensionInput.Support"/>; a
/// <c>PublicKeyCredentialCreationOptions</c> JSON writer calls <see cref="ToWireValue"/> to render
/// the <c>extensions.largeBlob.support</c> member, and a reader calls <see cref="FromWireValue"/> to
/// parse it back.
/// </remarks>
public static class WellKnownLargeBlobSupports
{
    /// <summary>The UTF-8 source literal of <see cref="Required"/>.</summary>
    public static ReadOnlySpan<byte> RequiredUtf8 => "required"u8;

    /// <summary>
    /// The <c>required</c> wire value.
    /// </summary>
    public static readonly string Required = Utf8Constants.ToInternedString(RequiredUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Preferred"/>.</summary>
    public static ReadOnlySpan<byte> PreferredUtf8 => "preferred"u8;

    /// <summary>
    /// The <c>preferred</c> wire value.
    /// </summary>
    public static readonly string Preferred = Utf8Constants.ToInternedString(PreferredUtf8);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="Required"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="Required"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsRequired(string value) => Equals(Required, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="Preferred"/> wire value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="Preferred"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsPreferred(string value) => Equals(Preferred, value);


    /// <summary>
    /// Determines whether <paramref name="value"/> is one of the two registered
    /// <c>LargeBlobSupport</c> wire values.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is a registered value; otherwise <see langword="false"/>.</returns>
    public static bool IsRegisteredValue(string value) => IsRequired(value) || IsPreferred(value);


    /// <summary>
    /// Maps a <see cref="LargeBlobSupport"/> to its CR-defined wire string.
    /// </summary>
    /// <param name="value">The support value to convert.</param>
    /// <returns>The wire string for <paramref name="value"/>.</returns>
    public static string ToWireValue(LargeBlobSupport value)
    {
        return value switch
        {
            LargeBlobSupport.Required => Required,
            LargeBlobSupport.Preferred => Preferred,
            _ => throw new System.Diagnostics.UnreachableException($"Unhandled {nameof(LargeBlobSupport)} value '{value}'; the enum admits only Required and Preferred.")
        };
    }


    /// <summary>
    /// Maps a wire string to its <see cref="LargeBlobSupport"/> value.
    /// </summary>
    /// <param name="value">The wire value to convert.</param>
    /// <returns>The <see cref="LargeBlobSupport"/> value corresponding to <paramref name="value"/>.</returns>
    /// <exception cref="System.ArgumentOutOfRangeException">
    /// Thrown when <paramref name="value"/> is not one of <see cref="Required"/> or
    /// <see cref="Preferred"/>.
    /// </exception>
    public static LargeBlobSupport FromWireValue(string value)
    {
        return value switch
        {
            _ when IsRequired(value) => LargeBlobSupport.Required,
            _ when IsPreferred(value) => LargeBlobSupport.Preferred,
            _ => throw new System.ArgumentOutOfRangeException(nameof(value), value, $"'{value}' is not a registered LargeBlobSupport wire value.")
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
