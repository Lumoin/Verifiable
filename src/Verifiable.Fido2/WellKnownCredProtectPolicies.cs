using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// Wire-string constants for the <c>credProtect</c> extension's <c>credentialProtectionPolicy</c>
/// client extension input, exactly as spelled by the CTAP 2.3 §12.1 client extension input section.
/// </summary>
/// <remarks>
/// <see href="https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#sctn-credProtect-extension">
/// CTAP 2.3, section 12.1: Credential Protection (credProtect)</see>. Unlike
/// <see cref="WellKnownLargeBlobSupports"/>, <see cref="Fido2CredProtectRegistrationExtensionInput.CredentialProtectionPolicy"/>
/// stays a plain <see cref="string"/> rather than an enum-backed member — these three values exist
/// for wire-value validation and emission, mirroring <see cref="WellKnownPublicKeyCredentialTypes"/>'s
/// value-plus-predicate shape rather than an enum/wire-string conversion pair.
/// </remarks>
public static class WellKnownCredProtectPolicies
{
    /// <summary>The UTF-8 source literal of <see cref="UserVerificationOptional"/>.</summary>
    public static ReadOnlySpan<byte> UserVerificationOptionalUtf8 => "userVerificationOptional"u8;

    /// <summary>
    /// The <c>userVerificationOptional</c> value: credProtect wire value <c>0x01</c>, the default
    /// policy when the extension is not requested at all.
    /// </summary>
    public static readonly string UserVerificationOptional = Utf8Constants.ToInternedString(UserVerificationOptionalUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UserVerificationOptionalWithCredentialIdList"/>.</summary>
    public static ReadOnlySpan<byte> UserVerificationOptionalWithCredentialIdListUtf8 => "userVerificationOptionalWithCredentialIDList"u8;

    /// <summary>
    /// The <c>userVerificationOptionalWithCredentialIDList</c> value: credProtect wire value
    /// <c>0x02</c> — discoverable only via a presented credential ID or user verification.
    /// </summary>
    public static readonly string UserVerificationOptionalWithCredentialIdList = Utf8Constants.ToInternedString(UserVerificationOptionalWithCredentialIdListUtf8);

    /// <summary>The UTF-8 source literal of <see cref="UserVerificationRequired"/>.</summary>
    public static ReadOnlySpan<byte> UserVerificationRequiredUtf8 => "userVerificationRequired"u8;

    /// <summary>
    /// The <c>userVerificationRequired</c> value: credProtect wire value <c>0x03</c> — discovery and
    /// usage MUST be preceded by some form of user verification.
    /// </summary>
    public static readonly string UserVerificationRequired = Utf8Constants.ToInternedString(UserVerificationRequiredUtf8);


    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="UserVerificationOptional"/> value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="UserVerificationOptional"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsUserVerificationOptional(string value) => Equals(UserVerificationOptional, value);

    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="UserVerificationOptionalWithCredentialIdList"/> value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="UserVerificationOptionalWithCredentialIdList"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsUserVerificationOptionalWithCredentialIdList(string value) => Equals(UserVerificationOptionalWithCredentialIdList, value);

    /// <summary>
    /// Determines whether <paramref name="value"/> is the <see cref="UserVerificationRequired"/> value.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is <see cref="UserVerificationRequired"/>; otherwise <see langword="false"/>.</returns>
    public static bool IsUserVerificationRequired(string value) => Equals(UserVerificationRequired, value);

    /// <summary>
    /// Determines whether <paramref name="value"/> is one of the three registered
    /// <c>credentialProtectionPolicy</c> wire values.
    /// </summary>
    /// <param name="value">The wire value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="value"/> is a registered value; otherwise <see langword="false"/>.</returns>
    public static bool IsRegisteredValue(string value) =>
        IsUserVerificationOptional(value) || IsUserVerificationOptionalWithCredentialIdList(value) || IsUserVerificationRequired(value);


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
