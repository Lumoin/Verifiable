namespace Verifiable.Apdu.Pace;

/// <summary>
/// The nonce-mapping mechanism a PACE protocol OID selects (ICAO Doc 9303 Part 11 §4.4.3.3): it determines
/// how the decrypted nonce becomes the ephemeral group generator the key agreement runs over.
/// </summary>
/// <remarks>
/// The mechanism is read from the PACE OID's protocol byte (the 9th value octet) by
/// <see cref="PaceObjectIdentifier.GetMappingType"/>; only the elliptic-curve (ECDH) variants this library
/// supports are modelled.
/// </remarks>
public enum PaceMappingType
{
    /// <summary>Generic Mapping (§4.4.3.3.1): <c>Ĝ = s·G + H</c> from an ephemeral Diffie-Hellman exchange. OID protocol byte <c>0x02</c> (id-PACE-ECDH-GM).</summary>
    GenericMapping,

    /// <summary>Integrated Mapping (§4.4.3.3.2): <c>Ĝ = f_G(R_p(s,t))</c> from a direct field-element map of the two nonces. OID protocol byte <c>0x04</c> (id-PACE-ECDH-IM).</summary>
    IntegratedMapping,

    /// <summary>Chip Authentication Mapping (§4.4.3.3.3): the Generic Mapping extended to fold Chip Authentication into PACE. OID protocol byte <c>0x06</c> (id-PACE-ECDH-CAM).</summary>
    ChipAuthenticationMapping
}
