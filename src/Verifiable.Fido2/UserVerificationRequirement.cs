namespace Verifiable.Fido2;

/// <summary>
/// A relying party's user-verification policy for a registration or assertion ceremony.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-userVerificationRequirement">W3C Web
/// Authentication Level 3, section 5.8.6: User Verification Requirement Enumeration (enum
/// <c>UserVerificationRequirement</c>)</see>. This is an RP-authored ceremony-input policy value:
/// it is never parsed off the wire by <c>Verifiable.Fido2</c> (only assembled into an options
/// document by a caller), so — unlike wire-parsed values such as the attestation statement
/// <c>fmt</c> or client-data <c>type</c> — it is modeled as a plain enum rather than a
/// <c>WellKnown*</c> string class, mirroring <see cref="Verifiable.OAuth.Pkce.PkceMethod"/>. Wire
/// (de)serialization of the three string values is a JSON-layer concern, via
/// <see cref="WellKnownUserVerificationRequirements"/>.
/// </remarks>
public enum UserVerificationRequirement
{
    /// <summary>
    /// The relying party requires user verification for the operation and will fail the overall
    /// ceremony if the response does not have the <c>UV</c> flag set.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-required">W3C
    /// Web Authentication Level 3, section 5.8.6</see>: "The Relying Party requires user
    /// verification for the operation and will fail the overall ceremony if the response does not
    /// have the UV flag set. The client MUST return an error if user verification cannot be
    /// performed."
    /// </remarks>
    Required,

    /// <summary>
    /// The relying party prefers user verification for the operation if possible, but will not
    /// fail the operation if the response does not have the <c>UV</c> flag set. This is the CR's
    /// own IDL default.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-preferred">W3C
    /// Web Authentication Level 3, section 5.8.6</see>: "The Relying Party prefers user
    /// verification for the operation if possible, but will not fail the operation if the response
    /// does not have the UV flag set."
    /// </remarks>
    Preferred,

    /// <summary>
    /// The relying party does not want user verification employed during the operation, e.g. in
    /// the interest of minimizing disruption to the user interaction flow.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-userverificationrequirement-discouraged">
    /// W3C Web Authentication Level 3, section 5.8.6</see>: "The Relying Party does not want user
    /// verification employed during the operation (e.g., in the interest of minimizing disruption
    /// to the user interaction flow)."
    /// </remarks>
    Discouraged
}
