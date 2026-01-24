using System;

namespace Verifiable.Tpm.Infrastructure.Spec.Attributes;

/// <summary>
/// TPMA_SESSION - session attribute bits.
/// </summary>
/// <remarks>
/// <para>
/// Identifies session type, relationships to handles in the command, and use in parameter encryption.
/// </para>
/// <para>
/// These bits are present in each authorization session entry for commands and are reflected in responses.
/// </para>
/// <para>
/// Specification: <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>, Part 2: Structures, section 8.4 (TPMA_SESSION).
/// </para>
/// </remarks>
[Flags]
public enum TpmaSession: byte
{
    /// <summary>
    /// CONTINUE_SESSION (bit 0): SET (1) indicates the session remains active after successful completion of the command; in a response,
    /// indicates the session is still active. CLEAR (0) indicates the TPM should close the session on successful completion; in a response,
    /// indicates the session is closed.
    /// </summary>
    CONTINUE_SESSION = 0x01,

    /// <summary>
    /// AUDIT_EXCLUSIVE (bit 1): SET (1) indicates the command should only be executed if the session is exclusive at start; in a response,
    /// indicates the session is exclusive. Only allowed if AUDIT is set (otherwise TPM_RC_ATTRIBUTES).
    /// </summary>
    AUDIT_EXCLUSIVE = 0x02,

    /// <summary>
    /// AUDIT_RESET (bit 2): SET (1) indicates the audit digest should be initialized and the exclusive status set. Only allowed if AUDIT is set
    /// (otherwise TPM_RC_ATTRIBUTES). This bit is always CLEAR in a response.
    /// </summary>
    AUDIT_RESET = 0x04,

    /// <summary>
    /// DECRYPT (bit 5): SET (1) indicates the first parameter in the command is symmetrically encrypted using the parameter encryption scheme
    /// described in Part 1. In a response, this attribute is copied from the request but has no effect on the response.
    /// </summary>
    DECRYPT = 0x20,

    /// <summary>
    /// ENCRYPT (bit 6): SET (1) indicates the TPM should use this session to encrypt the first parameter in the response; in a response,
    /// indicates the attribute was set and the TPM used the session to encrypt the first response parameter.
    /// </summary>
    ENCRYPT = 0x40,

    /// <summary>
    /// AUDIT (bit 7): SET (1) indicates the session is for audit and that AUDIT_EXCLUSIVE and AUDIT_RESET have meaning. If set in the command,
    /// this attribute will be set in the response. CLEAR (0) indicates the session is not used for audit.
    /// </summary>
    AUDIT = 0x80
}
