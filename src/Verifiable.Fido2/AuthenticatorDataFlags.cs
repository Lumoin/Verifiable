using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// The single-byte flags field of <c>authData</c>.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
/// </remarks>
[DebuggerDisplay("AuthenticatorDataFlags(UP={UserPresent} UV={UserVerified} BE={BackupEligible} BS={BackupState} AT={AttestedCredentialDataIncluded} ED={ExtensionDataIncluded})")]
public readonly struct AuthenticatorDataFlags: IEquatable<AuthenticatorDataFlags>
{
    /// <summary>
    /// The flags byte with no bits set.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public const byte None = 0x00;

    /// <summary>The bit position of the <c>UP</c> (User Present) flag.</summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public const byte UserPresentBit = 0x01;

    /// <summary>The bit position of the <c>UV</c> (User Verified) flag.</summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public const byte UserVerifiedBit = 0x04;

    /// <summary>The bit position of the <c>BE</c> (Backup Eligibility) flag.</summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public const byte BackupEligibleBit = 0x08;

    /// <summary>The bit position of the <c>BS</c> (Backup State) flag.</summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public const byte BackupStateBit = 0x10;

    /// <summary>The bit position of the <c>AT</c> (Attested credential data included) flag.</summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public const byte AttestedCredentialDataIncludedBit = 0x40;

    /// <summary>The bit position of the <c>ED</c> (Extension data included) flag.</summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public const byte ExtensionDataIncludedBit = 0x80;


    /// <summary>
    /// Initializes a new instance of the <see cref="AuthenticatorDataFlags"/> struct from the
    /// raw flags byte.
    /// </summary>
    /// <param name="value">The raw <c>flags</c> byte.</param>
    public AuthenticatorDataFlags(byte value)
    {
        Value = value;
    }


    /// <summary>
    /// The raw flags byte as received on the wire.
    /// </summary>
    public byte Value { get; }

    /// <summary>
    /// The <c>UP</c> flag (bit 0): the user was present during the ceremony.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public bool UserPresent => (Value & UserPresentBit) != 0;

    /// <summary>
    /// The <c>UV</c> flag (bit 2): the user was verified during the ceremony.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public bool UserVerified => (Value & UserVerifiedBit) != 0;

    /// <summary>
    /// The <c>BE</c> flag (bit 3): the credential is backup eligible.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public bool BackupEligible => (Value & BackupEligibleBit) != 0;

    /// <summary>
    /// The <c>BS</c> flag (bit 4): the credential is currently backed up.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public bool BackupState => (Value & BackupStateBit) != 0;

    /// <summary>
    /// The <c>AT</c> flag (bit 6): attested credential data is present.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public bool AttestedCredentialDataIncluded => (Value & AttestedCredentialDataIncludedBit) != 0;

    /// <summary>
    /// The <c>ED</c> flag (bit 7): extension data is present.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data">W3C Web Authentication Level 3, section 6.1: Authenticator Data.</see>
    /// </remarks>
    public bool ExtensionDataIncluded => (Value & ExtensionDataIncludedBit) != 0;

    /// <summary>
    /// Determines whether this instance and <paramref name="other"/> carry the same raw flags byte.
    /// </summary>
    /// <param name="other">The other instance to compare against.</param>
    /// <returns><see langword="true"/> if <see cref="Value"/> is equal on both instances; otherwise <see langword="false"/>.</returns>
    public bool Equals(AuthenticatorDataFlags other)
    {
        return Value == other.Value;
    }


    /// <summary>
    /// Determines whether this instance and <paramref name="obj"/> carry the same raw flags byte.
    /// </summary>
    /// <param name="obj">The object to compare against.</param>
    /// <returns><see langword="true"/> if <paramref name="obj"/> is an <see cref="AuthenticatorDataFlags"/> equal to this instance; otherwise <see langword="false"/>.</returns>
    public override bool Equals(object? obj)
    {
        return obj is AuthenticatorDataFlags other && Equals(other);
    }


    /// <summary>
    /// Returns the hash code for this instance, derived from the raw flags byte.
    /// </summary>
    /// <returns>The hash code for <see cref="Value"/>.</returns>
    public override int GetHashCode()
    {
        return Value.GetHashCode();
    }


    /// <summary>
    /// Determines whether <paramref name="left"/> and <paramref name="right"/> carry the same raw flags byte.
    /// </summary>
    /// <param name="left">The left-hand instance.</param>
    /// <param name="right">The right-hand instance.</param>
    /// <returns><see langword="true"/> if the two instances are equal; otherwise <see langword="false"/>.</returns>
    public static bool operator ==(AuthenticatorDataFlags left, AuthenticatorDataFlags right)
    {
        return left.Equals(right);
    }


    /// <summary>
    /// Determines whether <paramref name="left"/> and <paramref name="right"/> carry different raw flags bytes.
    /// </summary>
    /// <param name="left">The left-hand instance.</param>
    /// <param name="right">The right-hand instance.</param>
    /// <returns><see langword="true"/> if the two instances are not equal; otherwise <see langword="false"/>.</returns>
    public static bool operator !=(AuthenticatorDataFlags left, AuthenticatorDataFlags right)
    {
        return !left.Equals(right);
    }
}
