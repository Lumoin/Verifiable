using System.Diagnostics;

namespace Verifiable.Fido2;

/// <summary>
/// A relying party's requirements regarding authenticator attributes for a registration ceremony.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://www.w3.org/TR/webauthn-3/#dictionary-authenticatorSelection">W3C Web
/// Authentication Level 3, section 5.4.4: Authenticator Selection Criteria (dictionary
/// <c>AuthenticatorSelectionCriteria</c>)</see>.
/// </para>
/// <para>
/// <strong>residentKey/requireResidentKey consistency.</strong> The CR states the interaction
/// between these two members from the client's reading perspective: "If no value is given then the
/// effective value is <c>required</c> if <c>requireResidentKey</c> is true or <c>discouraged</c> if
/// it is false or absent." Row 3731 states the mirror-image RP-authoring SHOULD: "Relying Parties
/// SHOULD set [<c>requireResidentKey</c>] to true if, and only if, <c>residentKey</c> is set to
/// <c>required</c>." <see cref="Fido2RegistrationOptionsBuilder"/>'s default transformation keeps
/// both members consistent by construction rather than leaving either to drift, satisfying both
/// directions at once.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthenticatorSelectionCriteria(AuthenticatorAttachment={AuthenticatorAttachment}, ResidentKey={ResidentKey}, RequireResidentKey={RequireResidentKey}, UserVerification={UserVerification})")]
public sealed record AuthenticatorSelectionCriteria
{
    /// <summary>
    /// Filters eligible authenticators to a specific attachment modality, or <see langword="null"/>
    /// when any attachment modality is acceptable.
    /// </summary>
    /// <remarks>
    /// Modeled as the raw wire string (via <see cref="WellKnownAuthenticatorAttachments"/>) rather
    /// than a closed enum, mirroring <see cref="Fido2CredentialRecord.Type"/>'s own precedent: unlike
    /// <see cref="ResidentKeyRequirement"/>/<see cref="UserVerificationRequirement"/>, this same
    /// wire-name family is also consumed on the client-reported, wire-decoded side (a stored
    /// <c>Fido2CredentialRecord.AuthenticatorAttachment</c>), so the two directions share one shape
    /// rather than needing a conversion between an enum and a string.
    /// </remarks>
    public string? AuthenticatorAttachment { get; init; }

    /// <summary>
    /// The extent to which the relying party desires a client-side discoverable credential, or
    /// <see langword="null"/> when the effective value should derive from
    /// <see cref="RequireResidentKey"/> alone (see the type-level remarks).
    /// </summary>
    public ResidentKeyRequirement? ResidentKey { get; init; }

    /// <summary>
    /// Retained for WebAuthn Level 1 backwards compatibility. See the type-level remarks on keeping
    /// this consistent with <see cref="ResidentKey"/>.
    /// </summary>
    public bool RequireResidentKey { get; init; }

    /// <summary>
    /// The relying party's requirements regarding user verification for the <c>create()</c>
    /// operation. The CR's own IDL default is <see cref="UserVerificationRequirement.Preferred"/>.
    /// </summary>
    public UserVerificationRequirement UserVerification { get; init; }
}
