using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_NV - NV Index attributes.
/// </summary>
/// <remarks>
/// <para>
/// Allows the TPM to keep track of the data and permissions to manipulate an NV Index.
/// </para>
/// <para>
/// This attribute is part of NV public area structures and is validated/used by NV commands (DefineSpace, Read/Write, Lock, etc.).
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 13.4 (TPMA_NV).
/// </para>
/// </remarks>
[Flags]
public enum TpmaNv: uint
{
    /// <summary>
    /// TPMA_NV_PPWRITE (bit 0): SET (1) indicates the Index data can be written or write-locked if Platform Authorization is provided.
    /// CLEAR (0) indicates writing or write-locking cannot be authorized with Platform Authorization.
    /// </summary>
    TPMA_NV_PPWRITE = 0x0000_0001,

    /// <summary>
    /// TPMA_NV_OWNERWRITE (bit 1): SET (1) indicates the Index data can be written or write-locked if Owner Authorization is provided.
    /// CLEAR (0) indicates writing or write-locking cannot be authorized with Owner Authorization.
    /// </summary>
    TPMA_NV_OWNERWRITE = 0x0000_0002,

    /// <summary>
    /// TPMA_NV_AUTHWRITE (bit 2): SET (1) indicates the Index data may be written or write-locked if the Index authValue is provided.
    /// CLEAR (0) indicates writing or write-locking cannot be authorized with the Index authValue.
    /// </summary>
    TPMA_NV_AUTHWRITE = 0x0000_0004,

    /// <summary>
    /// TPMA_NV_POLICYWRITE (bit 3): SET (1) indicates USER role authorizations to change contents or write-lock may be provided with a policy session.
    /// CLEAR (0) indicates such authorizations may not be provided with a policy session.
    /// </summary>
    TPMA_NV_POLICYWRITE = 0x0000_0008,

    /// <summary>
    /// TPMA_NV_POLICY_DELETE (bit 10): SET (1) indicates the Index may not be deleted unless authPolicy is satisfied using
    /// TPM2_NV_UndefineSpaceSpecial(); CLEAR (0) indicates it may be deleted with platform/owner authorization using TPM2_NV_UndefineSpace().
    /// </summary>
    TPMA_NV_POLICY_DELETE = 0x0000_0400,

    /// <summary>
    /// TPMA_NV_WRITELOCKED (bit 11): SET (1) indicates the Index cannot be written; CLEAR (0) indicates it can be written.
    /// </summary>
    TPMA_NV_WRITELOCKED = 0x0000_0800,

    /// <summary>
    /// TPMA_NV_WRITEALL (bit 12): SET (1) indicates partial write is not allowed; write size shall match defined space size.
    /// CLEAR (0) indicates partial writes are allowed.
    /// </summary>
    TPMA_NV_WRITEALL = 0x0000_1000,

    /// <summary>
    /// TPMA_NV_WRITEDEFINE (bit 13): SET (1) indicates TPM2_NV_WriteLock() may be used to prevent further writes.
    /// CLEAR (0) indicates TPM2_NV_WriteLock() does not block subsequent writes if TPMA_NV_WRITE_STCLEAR is also CLEAR.
    /// </summary>
    TPMA_NV_WRITEDEFINE = 0x0000_2000,

    /// <summary>
    /// TPMA_NV_WRITE_STCLEAR (bit 14): SET (1) indicates TPM2_NV_WriteLock() may be used to prevent further writes until next TPM Reset or Restart.
    /// CLEAR (0) indicates TPM2_NV_WriteLock() does not block subsequent writes if TPMA_NV_WRITEDEFINE is also CLEAR.
    /// </summary>
    TPMA_NV_WRITE_STCLEAR = 0x0000_4000,

    /// <summary>
    /// TPMA_NV_GLOBALLOCK (bit 15): SET (1) indicates if TPM2_NV_GlobalWriteLock() is successful, TPMA_NV_WRITELOCKED is set.
    /// CLEAR (0) indicates TPM2_NV_GlobalWriteLock() has no effect on writing this Index.
    /// </summary>
    TPMA_NV_GLOBALLOCK = 0x0000_8000,

    /// <summary>
    /// TPMA_NV_PPREAD (bit 16): SET (1) indicates the Index data can be read or read-locked if Platform Authorization is provided.
    /// CLEAR (0) indicates reading or read-locking cannot be authorized with Platform Authorization.
    /// </summary>
    TPMA_NV_PPREAD = 0x0001_0000,

    /// <summary>
    /// TPMA_NV_OWNERREAD (bit 17): SET (1) indicates the Index data can be read or read-locked if Owner Authorization is provided.
    /// CLEAR (0) indicates reading or read-locking cannot be authorized with Owner Authorization.
    /// </summary>
    TPMA_NV_OWNERREAD = 0x0002_0000,

    /// <summary>
    /// TPMA_NV_AUTHREAD (bit 18): SET (1) indicates the Index data may be read or read-locked if the Index authValue is provided.
    /// CLEAR (0) indicates reading or read-locking cannot be authorized with the Index authValue.
    /// </summary>
    TPMA_NV_AUTHREAD = 0x0004_0000,

    /// <summary>
    /// TPMA_NV_POLICYREAD (bit 19): SET (1) indicates the Index data may be read or read-locked if the authPolicy is satisfied.
    /// CLEAR (0) indicates reading or read-locking cannot be authorized with the Index authPolicy.
    /// </summary>
    TPMA_NV_POLICYREAD = 0x0008_0000,

    /// <summary>
    /// TPMA_NV_NO_DA (bit 25): SET (1) indicates authorization failures do not affect DA logic and authorization is not blocked in lockout.
    /// CLEAR (0) indicates failures increment the failure counter and authorizations are not allowed in lockout mode.
    /// </summary>
    TPMA_NV_NO_DA = 0x0200_0000,

    /// <summary>
    /// TPMA_NV_ORDERLY (bit 26): SET (1) indicates Index state is only saved to NV on orderly shutdown; CLEAR (0) indicates updates are persistent after command.
    /// </summary>
    TPMA_NV_ORDERLY = 0x0400_0000,

    /// <summary>
    /// TPMA_NV_CLEAR_STCLEAR (bit 27): SET (1) indicates TPMA_NV_WRITTEN is cleared by TPM Reset or Restart; CLEAR (0) indicates it is not changed by restart.
    /// </summary>
    TPMA_NV_CLEAR_STCLEAR = 0x0800_0000,

    /// <summary>
    /// TPMA_NV_READLOCKED (bit 28): SET (1) indicates reads are blocked until next TPM Reset or Restart; CLEAR (0) indicates reads are allowed with authorization.
    /// </summary>
    TPMA_NV_READLOCKED = 0x1000_0000,

    /// <summary>
    /// TPMA_NV_WRITTEN (bit 29): SET (1) indicates Index has been written; CLEAR (0) indicates it has not been written.
    /// </summary>
    TPMA_NV_WRITTEN = 0x2000_0000,

    /// <summary>
    /// TPMA_NV_PLATFORMCREATE (bit 30): SET (1) indicates the Index may be undefined with Platform Authorization but not Owner Authorization.
    /// CLEAR (0) indicates it may be undefined with Owner Authorization but not Platform Authorization.
    /// </summary>
    TPMA_NV_PLATFORMCREATE = 0x4000_0000,

    /// <summary>
    /// TPMA_NV_READ_STCLEAR (bit 31): SET (1) indicates TPM2_NV_ReadLock() may be used to set TPMA_NV_READLOCKED for this Index.
    /// CLEAR (0) indicates TPM2_NV_ReadLock() has no effect.
    /// </summary>
    TPMA_NV_READ_STCLEAR = 0x8000_0000
}

/// <summary>
/// Helper accessors for packed fields in <see cref="TpmaNv"/>.
/// </summary>
/// <remarks>
/// <para>
/// This type is NOT part of the TPM 2.0 specification.
/// It is provided as a language-binding convenience for the multi-bit field TPM_NT (bits 7:4).
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 13.4 (TPMA_NV).
/// </para>
/// </remarks>
public static class TpmaNvFields
{
    /// <summary>TPM_NT field mask (bits 7:4).</summary>
    public const uint TPM_NT_MASK = 0x0000_00F0u;

    /// <summary>TPM_NT field shift (bits 7:4).</summary>
    public const int TPM_NT_SHIFT = 4;

    /// <summary>Extracts TPM_NT (0..15) from a TPMA_NV value.</summary>
    public static uint GetTpmNtRaw(TpmaNv attributes) => ((uint)attributes & TPM_NT_MASK) >> TPM_NT_SHIFT;

    /// <summary>Extracts TPM_NT as <see cref="TpmNt"/> when the value corresponds to a defined constant.</summary>
    public static TpmNt GetTpmNt(TpmaNv attributes) => (TpmNt)GetTpmNtRaw(attributes);
}
