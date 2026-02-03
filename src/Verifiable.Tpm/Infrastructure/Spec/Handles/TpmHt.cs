namespace Verifiable.Tpm.Infrastructure.Spec.Handles;


/// <summary>
/// TPM 2.0 handle types (TPM_HT) encoded in the most-significant octet of a handle.
/// </summary>
/// <remarks>
/// <para>
/// Purpose: A TPM handle is a 32-bit value. The most-significant octet (MSO) indicates the handle type,
/// and the remaining 24 bits are the handle index within that type.
/// </para>
/// <para>
/// Usage: Handle types are used to interpret and validate handles, and to construct handles when interacting
/// with TPM commands that take handles (e.g., transient object handles, NV indices, PCR handles, sessions).
/// </para>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "Handles" / TPM_HT).
/// </para>
/// </remarks>
public enum TpmHt: byte
{
    /// <summary>
    /// TPM_HT_PCR (0x00): Platform Configuration Registers (PCR).
    /// </summary>
    TPM_HT_PCR = 0x00,

    /// <summary>
    /// TPM_HT_NV_INDEX (0x01): NV Index handles.
    /// </summary>
    TPM_HT_NV_INDEX = 0x01,

    /// <summary>
    /// TPM_HT_HMAC_SESSION (0x02): HMAC session handles.
    /// </summary>
    TPM_HT_HMAC_SESSION = 0x02,

    /// <summary>
    /// TPM_HT_LOADED_SESSION (0x02): Alias for <see cref="TPM_HT_HMAC_SESSION"/>.
    /// </summary>
    TPM_HT_LOADED_SESSION = 0x02,

    /// <summary>
    /// TPM_HT_POLICY_SESSION (0x03): Policy session handles.
    /// </summary>
    TPM_HT_POLICY_SESSION = 0x03,

    /// <summary>
    /// TPM_HT_SAVED_SESSION (0x03): Alias for <see cref="TPM_HT_POLICY_SESSION"/>.
    /// </summary>
    TPM_HT_SAVED_SESSION = 0x03,

    /// <summary>
    /// TPM_HT_PERMANENT (0x40): Permanent handles (TPM_RH_*).
    /// </summary>
    TPM_HT_PERMANENT = 0x40,

    /// <summary>
    /// TPM_HT_TRANSIENT (0x80): Transient object handles.
    /// </summary>
    TPM_HT_TRANSIENT = 0x80,

    /// <summary>
    /// TPM_HT_PERSISTENT (0x81): Persistent object handles.
    /// </summary>
    TPM_HT_PERSISTENT = 0x81,

    /// <summary>
    /// TPM_HT_AC (0x90): Attached Component (AC) handles.
    /// </summary>
    TPM_HT_AC = 0x90,

    /// <summary>
    /// TPM_HT_EXTERNAL_NV (0xA0): External NV Index handles.
    /// </summary>
    TPM_HT_EXTERNAL_NV = 0xA0,

    /// <summary>
    /// TPM_HT_PERMANENT_NV (0xA1): Permanent NV Index handles.
    /// </summary>
    TPM_HT_PERMANENT_NV = 0xA1,
}
