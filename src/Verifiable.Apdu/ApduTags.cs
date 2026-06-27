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

    /// <summary>
    /// Tag for the assembled content of a transparent elementary file (EF.COM, EF.SOD, a data group).
    /// </summary>
    public static Tag ElementaryFile { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.ElementaryFile));

    /// <summary>
    /// Tag for the encoded wire bytes of a command APDU.
    /// </summary>
    public static Tag CommandApdu { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.CommandApdu));

    /// <summary>
    /// Tag for the encoded wire bytes of a Secure Messaging protected command APDU.
    /// </summary>
    public static Tag ProtectedCommandApdu { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.ProtectedCommandApdu));

    /// <summary>
    /// Tag for the encoded wire bytes of a Secure Messaging protected response APDU (the card side).
    /// </summary>
    public static Tag ProtectedResponseApdu { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.ProtectedResponseApdu));

    /// <summary>
    /// Tag for the value of a GENERAL AUTHENTICATE dynamic authentication data object (DO'7C').
    /// </summary>
    public static Tag DynamicAuthenticationData { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.DynamicAuthenticationData));

    /// <summary>
    /// Tag for an encoded biometric face image extracted from EF.DG2.
    /// </summary>
    public static Tag FaceImage { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.FaceImage));

    /// <summary>
    /// Tag for a CBEFF-wrapped biometric data record extracted from EF.DG3 (finger) or EF.DG4 (iris).
    /// </summary>
    public static Tag BiometricRecord { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.BiometricRecord));

    /// <summary>
    /// Tag for a chip's static Chip Authentication private key (the personalisation secret matching an EF.DG14 public key).
    /// </summary>
    public static Tag ChipAuthenticationPrivateKey { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.ChipAuthenticationPrivateKey));

    /// <summary>
    /// Tag for a chip's Active Authentication private key (the personalisation secret matching the EF.DG15 public key).
    /// </summary>
    public static Tag ActiveAuthenticationPrivateKey { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.ActiveAuthenticationPrivateKey));

    /// <summary>
    /// Tag for a DER-encoded RSA public key (<c>RSAPublicKey</c>: modulus and exponent), as carried in an EF.DG15 RSA Active Authentication key.
    /// </summary>
    public static Tag RsaPublicKey { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.RsaPublicKey));

    /// <summary>
    /// Tag for the encoded wire bytes of a card-verifiable certificate (the outer <c>7F21</c> structure) used by Terminal Authentication.
    /// </summary>
    public static Tag CardVerifiableCertificate { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.CardVerifiableCertificate));

    /// <summary>
    /// Tag for the discretionary-data value (<c>53</c>) of a Certificate Holder Authorization Template — the certificate holder's role and access-rights bitmask.
    /// </summary>
    public static Tag CertificateHolderAuthorization { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.CertificateHolderAuthorization));

    /// <summary>
    /// Tag for the displayed signature or usual mark image extracted from EF.DG7.
    /// </summary>
    public static Tag DisplayedSignature { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.DisplayedSignature));

    /// <summary>
    /// Tag for the free-format optional-details content of EF.DG13.
    /// </summary>
    public static Tag OptionalDetails { get; } = Tag.Create(
        (typeof(ApduTagKind), ApduTagKind.OptionalDetails));
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
    Pin,

    /// <summary>
    /// The assembled content of a transparent elementary file.
    /// </summary>
    ElementaryFile,

    /// <summary>
    /// The encoded wire bytes of a command APDU.
    /// </summary>
    CommandApdu,

    /// <summary>
    /// The encoded wire bytes of a Secure Messaging protected command APDU.
    /// </summary>
    ProtectedCommandApdu,

    /// <summary>
    /// The encoded wire bytes of a Secure Messaging protected response APDU.
    /// </summary>
    ProtectedResponseApdu,

    /// <summary>
    /// The value of a GENERAL AUTHENTICATE dynamic authentication data object.
    /// </summary>
    DynamicAuthenticationData,

    /// <summary>
    /// An encoded biometric face image from EF.DG2.
    /// </summary>
    FaceImage,

    /// <summary>
    /// A CBEFF-wrapped biometric data record from EF.DG3 (finger) or EF.DG4 (iris).
    /// </summary>
    BiometricRecord,

    /// <summary>
    /// A chip's static Chip Authentication private key.
    /// </summary>
    ChipAuthenticationPrivateKey,

    /// <summary>
    /// A chip's Active Authentication private key.
    /// </summary>
    ActiveAuthenticationPrivateKey,

    /// <summary>
    /// A DER-encoded RSA public key (modulus and exponent).
    /// </summary>
    RsaPublicKey,

    /// <summary>
    /// The encoded wire bytes of a card-verifiable certificate.
    /// </summary>
    CardVerifiableCertificate,

    /// <summary>
    /// The discretionary-data value of a Certificate Holder Authorization Template.
    /// </summary>
    CertificateHolderAuthorization,

    /// <summary>
    /// A displayed signature or usual mark image from EF.DG7.
    /// </summary>
    DisplayedSignature,

    /// <summary>
    /// The free-format optional-details content of EF.DG13.
    /// </summary>
    OptionalDetails
}
