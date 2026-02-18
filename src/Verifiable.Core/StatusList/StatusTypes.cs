namespace Verifiable.Core.StatusList;

/// <summary>
/// Defines the standard status type values for Referenced Tokens as specified
/// in Section 7.1 of draft-ietf-oauth-status-list.
/// </summary>
/// <remarks>
/// <para>
/// Processing rules for JWT or CWT take precedence over these status values. For example,
/// if a token is expired through the <c>exp</c> claim but has a status of 0x00 (Valid),
/// the token is considered expired.
/// </para>
/// <para>
/// Values 0x03 and 0x0C through 0x0F are permanently reserved for application-specific use.
/// All other values are reserved for future registration.
/// </para>
/// </remarks>
public static class StatusTypes
{
    /// <summary>
    /// The token status is valid, correct, or legal.
    /// </summary>
    public const byte Valid = 0x00;

    /// <summary>
    /// The token status is revoked, annulled, taken back, recalled, or cancelled.
    /// </summary>
    public const byte Invalid = 0x01;

    /// <summary>
    /// The token status is temporarily invalid, hanging, or debarred from privilege.
    /// </summary>
    public const byte Suspended = 0x02;

    /// <summary>
    /// Application-specific status value (0x03).
    /// </summary>
    public const byte ApplicationSpecific03 = 0x03;

    /// <summary>
    /// Application-specific status value (0x0C).
    /// </summary>
    public const byte ApplicationSpecific0C = 0x0C;

    /// <summary>
    /// Application-specific status value (0x0D).
    /// </summary>
    public const byte ApplicationSpecific0D = 0x0D;

    /// <summary>
    /// Application-specific status value (0x0E).
    /// </summary>
    public const byte ApplicationSpecific0E = 0x0E;

    /// <summary>
    /// Application-specific status value (0x0F).
    /// </summary>
    public const byte ApplicationSpecific0F = 0x0F;

    /// <summary>
    /// Checks whether the given value is a well-known standard status type.
    /// </summary>
    /// <param name="value">The status value to check.</param>
    /// <returns><see langword="true"/> if the value is a standard status type; otherwise, <see langword="false"/>.</returns>
    public static bool IsStandardStatus(byte value)
    {
        return value is Valid or Invalid or Suspended;
    }

    /// <summary>
    /// Checks whether the given value is a reserved application-specific status type.
    /// </summary>
    /// <param name="value">The status value to check.</param>
    /// <returns><see langword="true"/> if the value is a reserved application-specific status; otherwise, <see langword="false"/>.</returns>
    public static bool IsApplicationSpecific(byte value)
    {
        return value is ApplicationSpecific03 or (>= ApplicationSpecific0C and <= ApplicationSpecific0F);
    }
}