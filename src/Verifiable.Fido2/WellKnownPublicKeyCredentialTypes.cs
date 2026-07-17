using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// The <c>PublicKeyCredentialType</c> enumeration values.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-credentialType">W3C Web Authentication Level
/// 3, section 5.8.2: Credential Type Enumeration (enum <c>PublicKeyCredentialType</c>)</see>.
/// </remarks>
public static class WellKnownPublicKeyCredentialTypes
{
    /// <summary>The UTF-8 source literal of <see cref="PublicKey"/>.</summary>
    public static ReadOnlySpan<byte> PublicKeyUtf8 => "public-key"u8;

    /// <summary>
    /// The <c>public-key</c> value — currently the only member of the
    /// <c>PublicKeyCredentialType</c> enumeration.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#enum-credentialType">W3C Web Authentication
    /// Level 3, section 5.8.2: Credential Type Enumeration (enum <c>PublicKeyCredentialType</c>)</see>.
    /// </remarks>
    public static readonly string PublicKey = Utf8Constants.ToInternedString(PublicKeyUtf8);


    /// <summary>
    /// Determines whether <paramref name="type"/> is the <see cref="PublicKey"/> value.
    /// </summary>
    /// <param name="type">The <c>PublicKeyCredentialType</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="type"/> is <see cref="PublicKey"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsPublicKey(string type) => Equals(PublicKey, type);


    /// <summary>
    /// Returns a value that indicates if the credential types are the same.
    /// </summary>
    /// <param name="typeA">The first credential type to compare.</param>
    /// <param name="typeB">The second credential type to compare.</param>
    /// <returns>
    /// <see langword="true" /> if <paramref name="typeA"/> and <paramref name="typeB"/> are the same; otherwise, <see langword="false" />.
    /// </returns>
    public static bool Equals(string typeA, string typeB)
    {
        return object.ReferenceEquals(typeA, typeB) || StringComparer.Ordinal.Equals(typeA, typeB);
    }
}
