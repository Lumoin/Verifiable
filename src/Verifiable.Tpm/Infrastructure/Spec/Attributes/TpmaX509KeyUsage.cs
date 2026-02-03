using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_X509_KEY_USAGE - X.509 KeyUsage bit labels for TPM2_CertifyX509() validation.
/// </summary>
/// <remarks>
/// <para>
/// Deprecated: TPM2_CertifyX509() was deprecated in version 184, but this attribute definition remains for compatibility.
/// </para>
/// <para>
/// These attributes are as specified in RFC 5280 (KeyUsage) and are used by the TPM to validate that the key to be certified meets the
/// requirements of the provided DER-encoded KeyUsage.
/// </para>
/// <para>
/// This structure is input to the TPM as a DER-encoded structure and is not present on the TPM interface in canonical TPM format.
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 8.11 (TPMA_X509_KEY_USAGE).
/// </para>
/// </remarks>
[Flags]
public enum TpmaX509KeyUsage: uint
{
    /// <summary>
    /// DECIPHER_ONLY (bit 23): requires Attributes.DECRYPT set.
    /// </summary>
    DECIPHER_ONLY = 1u << 23,

    /// <summary>
    /// ENCIPHER_ONLY (bit 24): requires Attributes.DECRYPT set.
    /// </summary>
    ENCIPHER_ONLY = 1u << 24,

    /// <summary>
    /// CRL_SIGN (bit 25): requires Attributes.SIGN set.
    /// </summary>
    CRL_SIGN = 1u << 25,

    /// <summary>
    /// KEY_CERT_SIGN (bit 26): requires Attributes.SIGN set.
    /// </summary>
    KEY_CERT_SIGN = 1u << 26,

    /// <summary>
    /// KEY_AGREEMENT (bit 27): requires Attributes.DECRYPT set.
    /// </summary>
    KEY_AGREEMENT = 1u << 27,

    /// <summary>
    /// DATA_ENCIPHERMENT (bit 28): requires Attributes.DECRYPT set.
    /// </summary>
    DATA_ENCIPHERMENT = 1u << 28,

    /// <summary>
    /// KEY_ENCIPHERMENT (bit 29): requires asymmetric key with Attributes.DECRYPT and Attributes.RESTRICTED set (parent-key attributes).
    /// </summary>
    KEY_ENCIPHERMENT = 1u << 29,

    /// <summary>
    /// NON_REPUDIATION_CONTENT_COMMITMENT (bit 30): requires Attributes.FIXED_TPM set in SubjectKey.
    /// </summary>
    NON_REPUDIATION_CONTENT_COMMITMENT = 1u << 30,

    /// <summary>
    /// DIGITAL_SIGNATURE (bit 31): requires Attributes.SIGN set in SubjectKey.
    /// </summary>
    DIGITAL_SIGNATURE = 1u << 31
}
