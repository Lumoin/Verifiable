namespace Verifiable.Fido2;

/// <summary>
/// A relying party's requirement regarding client-side discoverable credentials (formerly "resident
/// keys") for a registration ceremony.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-residentKeyRequirement">W3C Web Authentication
/// Level 3, section 5.4.6: Resident Key Requirement Enumeration (enum
/// <c>ResidentKeyRequirement</c>)</see>. Like <see cref="UserVerificationRequirement"/>, this is an
/// RP-authored ceremony-options input, never parsed off the wire by <c>Verifiable.Fido2</c>, so it
/// is modeled as a plain enum rather than a <c>WellKnown*</c> string class. Wire (de)serialization of
/// the three string values is a JSON-layer concern, via
/// <see cref="WellKnownResidentKeyRequirements"/>.
/// </remarks>
public enum ResidentKeyRequirement
{
    /// <summary>
    /// The relying party prefers creating a server-side credential, but will accept a client-side
    /// discoverable credential.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-discouraged">W3C Web
    /// Authentication Level 3, section 5.4.6</see>: "The Relying Party prefers creating a server-side
    /// credential, but will accept a client-side discoverable credential. The client and
    /// authenticator SHOULD create a server-side credential if possible."
    /// </remarks>
    Discouraged,

    /// <summary>
    /// The relying party strongly prefers creating a client-side discoverable credential, but will
    /// accept a server-side credential.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-preferred">W3C Web
    /// Authentication Level 3, section 5.4.6</see>: "The Relying Party strongly prefers creating a
    /// client-side discoverable credential, but will accept a server-side credential. The client and
    /// authenticator SHOULD create a discoverable credential if possible. ... This takes precedence
    /// over the setting of userVerification."
    /// </remarks>
    Preferred,

    /// <summary>
    /// The relying party requires a client-side discoverable credential.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-residentkeyrequirement-required">W3C Web
    /// Authentication Level 3, section 5.4.6</see>: "The Relying Party requires a client-side
    /// discoverable credential. The client MUST return an error if a client-side discoverable
    /// credential cannot be created."
    /// </remarks>
    Required
}
