using System;

namespace Verifiable.Apdu;

/// <summary>
/// Application identifier (AID) constants for common card applications.
/// </summary>
/// <remarks>
/// <para>
/// An AID is a byte sequence that uniquely identifies an application on a
/// multi-application smart card. The card selects the application when it
/// receives a <c>SELECT</c> command with the AID in the data field.
/// </para>
/// <para>
/// AIDs are assigned by ISO (5-byte Registered Application Provider Identifier,
/// or RID) with optional Proprietary Application Identifier Extension (PIX).
/// </para>
/// </remarks>
public static class WellKnownAid
{
    /// <summary>
    /// NIST PIV (A0 00 00 03 08 00 00 10 00).
    /// </summary>
    /// <remarks>
    /// Personal Identity Verification as defined in NIST SP 800-73.
    /// </remarks>
    public static ReadOnlySpan<byte> Piv => [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

    /// <summary>
    /// ICAO MRTD (A0 00 00 02 47 10 01).
    /// </summary>
    /// <remarks>
    /// Machine Readable Travel Documents as defined in ICAO Doc 9303.
    /// </remarks>
    public static ReadOnlySpan<byte> Mrtd => [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

    /// <summary>
    /// GlobalPlatform ISD (A0 00 00 01 51 00 00).
    /// </summary>
    /// <remarks>
    /// Issuer Security Domain for GlobalPlatform card management.
    /// </remarks>
    public static ReadOnlySpan<byte> GlobalPlatformIsd => [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];

    /// <summary>
    /// FIDO/CTAP over NFC (A0 00 00 06 47 2F 00 01).
    /// </summary>
    /// <remarks>
    /// FIDO2 CTAP2 application for WebAuthn over NFC transport.
    /// </remarks>
    public static ReadOnlySpan<byte> Fido => [0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01];

    /// <summary>
    /// OpenPGP (D2 76 00 01 24 01).
    /// </summary>
    public static ReadOnlySpan<byte> OpenPgp => [0xD2, 0x76, 0x00, 0x01, 0x24, 0x01];

    /// <summary>
    /// Checks whether two AIDs match. Supports partial matching where the
    /// candidate is a prefix of the full AID (right-truncated selection).
    /// </summary>
    /// <param name="candidate">The AID to check.</param>
    /// <param name="reference">The reference AID.</param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="candidate"/> is an exact match
    /// or a valid prefix of <paramref name="reference"/>.
    /// </returns>
    public static bool Matches(ReadOnlySpan<byte> candidate, ReadOnlySpan<byte> reference)
    {
        if(candidate.Length > reference.Length)
        {
            return false;
        }

        return reference[..candidate.Length].SequenceEqual(candidate);
    }
}
