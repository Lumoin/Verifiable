namespace Verifiable.Fido2;

/// <summary>
/// A hint a relying party gives the user agent about how a registration or assertion request may
/// best be completed.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#enum-hints">W3C Web Authentication Level 3, section
/// 5.8.8: User-agent Hints Enumeration (enum <c>PublicKeyCredentialHint</c>)</see>: "These hints are
/// not requirements, and do not bind the user-agent, but may guide it ... Hints are provided in order
/// of decreasing preference so, if two hints are contradictory, the first one controls." Like
/// <see cref="UserVerificationRequirement"/>, this is an RP-authored ceremony-options input, never
/// parsed off the wire by <c>Verifiable.Fido2</c>, so it is modeled as a plain enum rather than a
/// <c>WellKnown*</c> string class. Wire (de)serialization of the three string values is a JSON-layer
/// concern, via <see cref="WellKnownPublicKeyCredentialHints"/>.
/// </remarks>
public enum PublicKeyCredentialHint
{
    /// <summary>
    /// The relying party believes that users will satisfy this request with a physical security key.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-security-key">W3C Web
    /// Authentication Level 3, section 5.8.8</see>. "For compatibility with older user agents, when
    /// this hint is used in <c>PublicKeyCredentialCreationOptions</c>, the
    /// <c>authenticatorAttachment</c> SHOULD be set to <c>cross-platform</c>", SHOULD.
    /// </remarks>
    SecurityKey,

    /// <summary>
    /// The relying party believes that users will satisfy this request with a platform authenticator
    /// attached to the client device.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-client-device">W3C
    /// Web Authentication Level 3, section 5.8.8</see>. "For compatibility with older user agents,
    /// when this hint is used in <c>PublicKeyCredentialCreationOptions</c>, the
    /// <c>authenticatorAttachment</c> SHOULD be set to <c>platform</c>", SHOULD.
    /// </remarks>
    ClientDevice,

    /// <summary>
    /// The relying party believes that users will satisfy this request with general-purpose
    /// authenticators such as smartphones.
    /// </summary>
    /// <remarks>
    /// <see href="https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialhint-hybrid">W3C Web
    /// Authentication Level 3, section 5.8.8</see>. "For compatibility with older user agents, when
    /// this hint is used in <c>PublicKeyCredentialCreationOptions</c>, the
    /// <c>authenticatorAttachment</c> SHOULD be set to <c>cross-platform</c>", SHOULD.
    /// </remarks>
    Hybrid
}
