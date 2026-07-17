namespace Verifiable.Fido2;

/// <summary>
/// The certified-path axis of a WebAuthn attestation: how an attestation statement's X.509
/// certificate path relates to the authenticator and its vendor.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-attestation-types">W3C Web Authentication Level 3, section 6.5.3: Attestation Types.</see>
/// <para>
/// Covers only the attestation types whose statement conveys an X.509 certificate path — Basic,
/// Attestation CA, and Anonymization CA. That section notes attestation statements conveying
/// Basic, AttCA, or AnonCA attestation share the same data structure, so the three are, in
/// general, distinguishable only with externally supplied knowledge of the attestation
/// certificate's contents; <see cref="Unknown"/> is the result when a verification procedure
/// has no such external knowledge to draw on.
/// </para>
/// <para>
/// Self and None attestation carry no certificate path at all, so they are not members of this
/// enumeration; they are instead their own <see cref="AttestationResult"/> cases —
/// <see cref="SelfAttestationResult"/> and <see cref="NoneAttestationResult"/> respectively.
/// </para>
/// </remarks>
public enum AttestationType
{
    /// <summary>
    /// Basic attestation: the authenticator's attestation key pair is specific to an
    /// authenticator model or batch, so authenticators of the same or similar model often share
    /// it. Also referred to as batch attestation.
    /// </summary>
    Basic,

    /// <summary>
    /// Attestation CA (AttCA) attestation: a Trusted Platform Module-based authenticator holds
    /// an authenticator-specific endorsement key and requests an Attestation CA to issue an
    /// attestation identity key certificate for each generated credential.
    /// </summary>
    AttestationCa,

    /// <summary>
    /// Anonymization CA (AnonCA) attestation: an Anonymization CA dynamically generates
    /// per-credential attestation certificates such that the attestation statements presented to
    /// relying parties carry no uniquely identifying information.
    /// </summary>
    AnonymizationCa,

    /// <summary>
    /// The certified-path attestation type could not be determined by the verification
    /// procedure alone: the attestation statement conveys a valid certificate path, but
    /// distinguishing Basic from Attestation CA (or Anonymization CA) attestation requires
    /// externally supplied authenticator metadata that this layer does not consult.
    /// </summary>
    Unknown
}
