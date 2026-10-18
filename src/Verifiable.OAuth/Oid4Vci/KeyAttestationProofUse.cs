namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The use a key attestation (OID4VCI 1.0 Appendix D.1) is verified for, as the verifier's caller knows it: Appendix D.1 makes
/// <c>exp</c> OPTIONAL in general and REQUIRED "if the attestation is used with the JWT proof type", so whether the attestation
/// is used with a JWT proof decides whether its omitted <c>exp</c> is valid, and a caller that does not know states that it does
/// not, as a value of this type, never as a flag.
/// </summary>
public enum KeyAttestationProofUse
{
    /// <summary>
    /// The caller does not state which proof the attestation is used with: a present <c>exp</c> is enforced and an omitted one is
    /// valid, the general rule of Appendix D.1, since the condition that would require it is not known to hold.
    /// </summary>
    NotStated,

    /// <summary>
    /// The attestation is used with the JWT proof type, carried in a <c>jwt</c> proof's <c>key_attestation</c> header (Appendix
    /// F.1): its <c>exp</c> is REQUIRED, and an attestation omitting it is refused.
    /// </summary>
    JwtProof,

    /// <summary>
    /// The attestation is used as the proof itself, the <c>attestation</c> proof type (Appendix F.3), not with a JWT proof: its
    /// <c>exp</c> is OPTIONAL, enforced where present.
    /// </summary>
    AttestationProof
}
