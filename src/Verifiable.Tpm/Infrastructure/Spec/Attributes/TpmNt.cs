using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPM_NT - the type of an NV Index (the TPM_NT field within TPMA_NV bits 7:4).
/// </summary>
/// <remarks>
/// <para>
/// This field is 4 bits wide. All other values are reserved and TPM2_NV_DefineSpace() returns TPM_RC_ATTRIBUTES.
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 13.2 (TPM_NT).
/// </para>
/// </remarks>
/// 
[SuppressMessage("Design", "CA1027:Mark enums with FlagsAttribute", Justification = "Enum values defined by TPM 2.0 specification.")]
public enum TpmNt: uint
{
    /// <summary>
    /// TPM_NT_ORDINARY (0x0): Ordinary - opaque data; modified using TPM2_NV_Write().
    /// </summary>
    TPM_NT_ORDINARY = 0x0,

    /// <summary>
    /// TPM_NT_COUNTER (0x1): Counter - 8-octet value used as a counter; modified using TPM2_NV_Increment().
    /// </summary>
    TPM_NT_COUNTER = 0x1,

    /// <summary>
    /// TPM_NT_BITS (0x2): BitField - 8-octet value used as a bit field; modified using TPM2_NV_SetBits().
    /// </summary>
    TPM_NT_BITS = 0x2,

    /// <summary>
    /// TPM_NT_EXTEND (0x4): Extend - digest-sized value used like a PCR; modified using TPM2_NV_Extend(); extend uses nameAlg of the Index.
    /// </summary>
    TPM_NT_EXTEND = 0x4,

    /// <summary>
    /// TPM_NT_PIN_FAIL (0x8): PINFail - contains pinCount (increment on PIN authorization failure) and pinLimit.
    /// </summary>
    TPM_NT_PIN_FAIL = 0x8,

    /// <summary>
    /// TPM_NT_PIN_PASS (0x9): PINPass - contains pinCount (increment on PIN authorization success) and pinLimit.
    /// </summary>
    TPM_NT_PIN_PASS = 0x9
}
