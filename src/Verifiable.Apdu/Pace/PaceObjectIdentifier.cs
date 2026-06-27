using System;

namespace Verifiable.Apdu.Pace;

/// <summary>
/// Reads the parameters a PACE protocol OID encodes (ICAO Doc 9303 Part 11 §9.2.3). A PACE OID's value bytes
/// (the inner DER, without the outer <c>0x06</c> tag) are <c>04 00 7F 00 07 02 02 04 PP CC</c>, where
/// <c>PP</c> is the protocol byte selecting the key-agreement and mapping mechanism and <c>CC</c> is the
/// symmetric-cipher parameter.
/// </summary>
public static class PaceObjectIdentifier
{
    /// <summary>The index of the protocol byte (the 9th value octet) selecting the key agreement and mapping.</summary>
    private const int MappingTypeIndex = 8;

    /// <summary>The protocol byte of id-PACE-ECDH-GM (Generic Mapping over ECDH).</summary>
    private const byte GenericMappingByte = 0x02;

    /// <summary>The protocol byte of id-PACE-ECDH-IM (Integrated Mapping over ECDH).</summary>
    private const byte IntegratedMappingByte = 0x04;

    /// <summary>The protocol byte of id-PACE-ECDH-CAM (Chip Authentication Mapping over ECDH).</summary>
    private const byte ChipAuthenticationMappingByte = 0x06;


    /// <summary>
    /// Reads the nonce-mapping mechanism from a PACE OID's protocol byte.
    /// </summary>
    /// <param name="objectIdentifier">The PACE protocol OID value bytes (without the outer <c>0x06</c> tag).</param>
    /// <returns>The <see cref="PaceMappingType"/> the OID selects.</returns>
    /// <exception cref="ArgumentException">Thrown when the OID is too short to carry a protocol byte, or the protocol byte is not a supported ECDH mechanism.</exception>
    public static PaceMappingType GetMappingType(ReadOnlySpan<byte> objectIdentifier)
    {
        if(objectIdentifier.Length <= MappingTypeIndex)
        {
            throw new ArgumentException(
                $"A PACE OID must be at least {MappingTypeIndex + 1} bytes to carry a protocol byte.", nameof(objectIdentifier));
        }

        byte protocolByte = objectIdentifier[MappingTypeIndex];

        return protocolByte switch
        {
            GenericMappingByte => PaceMappingType.GenericMapping,
            IntegratedMappingByte => PaceMappingType.IntegratedMapping,
            ChipAuthenticationMappingByte => PaceMappingType.ChipAuthenticationMapping,
            _ => throw new ArgumentException(
                $"The PACE OID protocol byte 0x{protocolByte:X2} is not a supported ECDH mapping (expected 0x02, 0x04, or 0x06).", nameof(objectIdentifier))
        };
    }
}
