using Verifiable.Cryptography.Text;

namespace Verifiable.Fido2;

/// <summary>
/// Attestation statement format identifiers used in a WebAuthn attestation object.
/// </summary>
/// <remarks>
/// <para>
/// The attestation statement format identifier is the value of the <c>fmt</c>
/// member of the attestation object produced during a registration ceremony. It
/// selects the verification procedure a relying party applies to the attestation
/// statement (<c>attStmt</c>).
/// </para>
/// <para>
/// Identifiers are registered strings. Additional formats plug in through the
/// attestation-format registry rather than by extending this list.
/// </para>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-defined-attestation-formats">W3C Web Authentication Level 3, section 8: Defined Attestation Statement Formats.</see>
/// <see href="https://www.iana.org/assignments/webauthn/webauthn.xhtml">IANA WebAuthn Attestation Statement Format Identifiers registry.</see>
/// </remarks>
public static class WellKnownWebAuthnAttestationFormats
{
    /// <summary>The UTF-8 source literal of <see cref="None"/>.</summary>
    public static ReadOnlySpan<byte> NoneUtf8 => "none"u8;

    /// <summary>
    /// The <c>none</c> format, in which no attestation statement is conveyed.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-none-attestation">W3C Web Authentication Level 3, section 8.7: None Attestation Statement Format.</see>
    /// </remarks>
    public static readonly string None = Utf8Constants.ToInternedString(NoneUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Packed"/>.</summary>
    public static ReadOnlySpan<byte> PackedUtf8 => "packed"u8;

    /// <summary>
    /// The <c>packed</c> format, covering self, full-basic, and attestation-CA statements.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation">W3C Web Authentication Level 3, section 8.2: Packed Attestation Statement Format.</see>
    /// </remarks>
    public static readonly string Packed = Utf8Constants.ToInternedString(PackedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Tpm"/>.</summary>
    public static ReadOnlySpan<byte> TpmUtf8 => "tpm"u8;

    /// <summary>
    /// The <c>tpm</c> format, in which attestation is rooted in a Trusted Platform Module.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-tpm-attestation">W3C Web Authentication Level 3, section 8.3: TPM Attestation Statement Format.</see>
    /// </remarks>
    public static readonly string Tpm = Utf8Constants.ToInternedString(TpmUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AndroidKey"/>.</summary>
    public static ReadOnlySpan<byte> AndroidKeyUtf8 => "android-key"u8;

    /// <summary>
    /// The <c>android-key</c> format, backed by an Android hardware keystore attestation.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-key-attestation">W3C Web Authentication Level 3, section 8.4: Android Key Attestation Statement Format.</see>
    /// </remarks>
    public static readonly string AndroidKey = Utf8Constants.ToInternedString(AndroidKeyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AndroidSafetyNet"/>.</summary>
    public static ReadOnlySpan<byte> AndroidSafetyNetUtf8 => "android-safetynet"u8;

    /// <summary>
    /// The <c>android-safetynet</c> format, backed by an Android SafetyNet response.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-android-safetynet-attestation">W3C Web Authentication Level 3, section 8.5: Android SafetyNet Attestation Statement Format.</see>
    /// </remarks>
    public static readonly string AndroidSafetyNet = Utf8Constants.ToInternedString(AndroidSafetyNetUtf8);

    /// <summary>The UTF-8 source literal of <see cref="FidoU2f"/>.</summary>
    public static ReadOnlySpan<byte> FidoU2fUtf8 => "fido-u2f"u8;

    /// <summary>
    /// The <c>fido-u2f</c> format, produced by a U2f-era authenticator.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-fido-u2f-attestation">W3C Web Authentication Level 3, section 8.6: FIDO U2f Attestation Statement Format.</see>
    /// </remarks>
    public static readonly string FidoU2f = Utf8Constants.ToInternedString(FidoU2fUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Apple"/>.</summary>
    public static ReadOnlySpan<byte> AppleUtf8 => "apple"u8;

    /// <summary>
    /// The <c>apple</c> anonymous attestation format.
    /// </summary>
    /// <remarks>
    /// Registered in the IANA WebAuthn Attestation Statement Format Identifiers
    /// registry outside the core specification section list.
    /// </remarks>
    public static readonly string Apple = Utf8Constants.ToInternedString(AppleUtf8);


    /// <summary>Determines whether <paramref name="identifier"/> is <see cref="None"/>.</summary>
    /// <param name="identifier">The <c>fmt</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> is <c>none</c>.</returns>
    public static bool IsNone(string identifier) => Equals(None, identifier);

    /// <summary>Determines whether <paramref name="identifier"/> is <see cref="Packed"/>.</summary>
    /// <param name="identifier">The <c>fmt</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> is <c>packed</c>.</returns>
    public static bool IsPacked(string identifier) => Equals(Packed, identifier);

    /// <summary>Determines whether <paramref name="identifier"/> is <see cref="Tpm"/>.</summary>
    /// <param name="identifier">The <c>fmt</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> is <c>tpm</c>.</returns>
    public static bool IsTpm(string identifier) => Equals(Tpm, identifier);

    /// <summary>Determines whether <paramref name="identifier"/> is <see cref="AndroidKey"/>.</summary>
    /// <param name="identifier">The <c>fmt</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> is <c>android-key</c>.</returns>
    public static bool IsAndroidKey(string identifier) => Equals(AndroidKey, identifier);

    /// <summary>Determines whether <paramref name="identifier"/> is <see cref="AndroidSafetyNet"/>.</summary>
    /// <param name="identifier">The <c>fmt</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> is <c>android-safetynet</c>.</returns>
    public static bool IsAndroidSafetyNet(string identifier) => Equals(AndroidSafetyNet, identifier);

    /// <summary>Determines whether <paramref name="identifier"/> is <see cref="FidoU2f"/>.</summary>
    /// <param name="identifier">The <c>fmt</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> is <c>fido-u2f</c>.</returns>
    public static bool IsFidoU2f(string identifier) => Equals(FidoU2f, identifier);

    /// <summary>Determines whether <paramref name="identifier"/> is <see cref="Apple"/>.</summary>
    /// <param name="identifier">The <c>fmt</c> value to test.</param>
    /// <returns><see langword="true"/> if <paramref name="identifier"/> is <c>apple</c>.</returns>
    public static bool IsApple(string identifier) => Equals(Apple, identifier);


    /// <summary>
    /// Determines whether <paramref name="identifier"/> is an attestation statement
    /// format identifier known to this library.
    /// </summary>
    /// <param name="identifier">The <c>fmt</c> value to test.</param>
    /// <returns>
    /// <see langword="true"/> if the identifier is one of the known registered
    /// formats; otherwise <see langword="false"/>.
    /// </returns>
    public static bool IsRegisteredFormatIdentifier(string identifier)
    {
        return IsNone(identifier)
            || IsPacked(identifier)
            || IsTpm(identifier)
            || IsAndroidKey(identifier)
            || IsAndroidSafetyNet(identifier)
            || IsFidoU2f(identifier)
            || IsApple(identifier);
    }


    /// <summary>
    /// Returns a value that indicates if the attestation format identifiers are the same.
    /// </summary>
    /// <param name="identifierA">The first identifier to compare.</param>
    /// <param name="identifierB">The second identifier to compare.</param>
    /// <returns>
    /// <see langword="true" /> if <paramref name="identifierA"/> and <paramref name="identifierB"/> are the same; otherwise, <see langword="false" />.
    /// </returns>
    public static bool Equals(string identifierA, string identifierB)
    {
        return object.ReferenceEquals(identifierA, identifierB) || StringComparer.Ordinal.Equals(identifierA, identifierB);
    }
}
