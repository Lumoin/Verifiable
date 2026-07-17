using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// The <c>type</c> member values of <c>CollectedClientData</c>, identifying which WebAuthn
/// ceremony produced the client data.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3, section 5.8.1: Client Data Used in WebAuthn Signatures.</see>
/// </remarks>
public static class WellKnownClientDataTypes
{
    /// <summary>The UTF-8 source literal of <see cref="Create"/>.</summary>
    public static ReadOnlySpan<byte> CreateUtf8 => "webauthn.create"u8;

    /// <summary>
    /// The <c>webauthn.create</c> value, present when the client data was produced by a
    /// registration ceremony.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3, section 5.8.1: Client Data Used in WebAuthn Signatures.</see>
    /// </remarks>
    public static readonly string Create = Utf8Constants.ToInternedString(CreateUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Get"/>.</summary>
    public static ReadOnlySpan<byte> GetUtf8 => "webauthn.get"u8;

    /// <summary>
    /// The <c>webauthn.get</c> value, present when the client data was produced by an
    /// authentication ceremony.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">W3C Web Authentication Level 3, section 5.8.1: Client Data Used in WebAuthn Signatures.</see>
    /// </remarks>
    public static readonly string Get = Utf8Constants.ToInternedString(GetUtf8);


    /// <summary>
    /// Determines whether <paramref name="type"/> is the registration-ceremony
    /// <c>type</c> value.
    /// </summary>
    /// <param name="type">The <c>CollectedClientData.type</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="type"/> is <see cref="Create"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsCreate(string type) => Equals(Create, type);

    /// <summary>
    /// Determines whether <paramref name="type"/> is the authentication-ceremony
    /// <c>type</c> value.
    /// </summary>
    /// <param name="type">The <c>CollectedClientData.type</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="type"/> is <see cref="Get"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsGet(string type) => Equals(Get, type);


    /// <summary>
    /// Returns a value that indicates if the client data types are the same.
    /// </summary>
    /// <param name="typeA">The first client data type to compare.</param>
    /// <param name="typeB">The second client data type to compare.</param>
    /// <returns>
    /// <see langword="true" /> if <paramref name="typeA"/> and <paramref name="typeB"/> are the same; otherwise, <see langword="false" />.
    /// </returns>
    public static bool Equals(string typeA, string typeB)
    {
        return object.ReferenceEquals(typeA, typeB) || StringComparer.Ordinal.Equals(typeA, typeB);
    }
}
