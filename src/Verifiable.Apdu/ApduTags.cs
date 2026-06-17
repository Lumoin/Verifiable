namespace Verifiable.Apdu;

/// <summary>
/// Predefined <see cref="Tag"/> instances for APDU-related <see cref="SensitiveMemory"/> subtypes.
/// </summary>
/// <remarks>
/// <para>
/// These tags identify the semantic role of memory in the APDU subsystem, analogous
/// to how <c>TpmTags</c> identifies TPM memory roles. Every <see cref="SensitiveMemory"/>
/// instance in the APDU subsystem carries one of these tags.
/// </para>
/// </remarks>
public static class ApduTags
{
    /// <summary>
    /// Tag for raw APDU response bytes (data + status word).
    /// </summary>
    public static Tag Response { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.Response));

    /// <summary>
    /// Tag for command APDU data field bytes.
    /// </summary>
    public static Tag CommandData { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.CommandData));

    /// <summary>
    /// Tag for secure messaging session key material.
    /// </summary>
    public static Tag SecureMessagingKey { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.SecureMessagingKey));

    /// <summary>
    /// Tag for secure messaging MAC value.
    /// </summary>
    public static Tag SecureMessagingMac { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.SecureMessagingMac));

    /// <summary>
    /// Tag for PIN or password bytes submitted via VERIFY.
    /// </summary>
    public static Tag Pin { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.Pin));
}


/// <summary>
/// Discriminator for APDU-specific memory roles.
/// </summary>
public enum ApduTagKind
{
    /// <summary>
    /// Raw APDU response bytes.
    /// </summary>
    Response,

    /// <summary>
    /// Command APDU data field.
    /// </summary>
    CommandData,

    /// <summary>
    /// Secure messaging session key.
    /// </summary>
    SecureMessagingKey,

    /// <summary>
    /// Secure messaging MAC.
    /// </summary>
    SecureMessagingMac,

    /// <summary>
    /// PIN or password value.
    /// </summary>
    Pin
}
