namespace Verifiable.Tpm.Infrastructure.Spec.Constants;

/// <summary>
/// TPM_ST constants (Table 23).
/// </summary>
/// <remarks>
/// <para>
/// Specification:
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library Specification</see>
/// (Part 2: Structures, section "6 Constants", Table 23).
/// </para>
/// </remarks>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1008:Enums should have zero value", Justification = "Specifica")]
public enum TpmStConstants: ushort
{
    /// <summary>
    /// tag value for a response; used when there is an error in the tag. This is also the value returned from a TPM 1.2 when an error occurs. This value is used in this specification because an error in the command tag may prevent determination of the family. When this tag is used in the response, the response code will be TPM_RC_BAD_TAG (0x001E), which has the same numeric value as the TPM 1.2 response code for TPM_BADTAG. Note: In a previously published version of this specification, TPM_RC_BAD_TAG was incorrectly assigned a value of 0x030 instead of 30 (0x01e). Some implementations my return the old value instead of the new value. .
    /// </summary>
    TPM_ST_RSP_COMMAND = 0x00C4,

    /// <summary>
    /// tag value for a command/response for a command defined in this specification; indicating that the command/response has no attached sessions and no authorizationSize/parameterSize value is present If the responseCode from the TPM is not TPM_RC_SUCCESS, then the response tag shall have this value.
    /// </summary>
    TPM_ST_NO_SESSIONS = 0x8001,

    /// <summary>
    /// tag value for a command/response for a command defined in this specification; indicating that the command/response has one or more attached sessions and the authorizationSize/parameterSize field is present Name Value Comments reserved 0x8003 When used between application software and the TPM resource manager, this tag indicates that the command has no sessions and the handles are using the Name format rather than the 32-bit handle format. Note: The response to application software will have a tag of TPM_ST_NO_SESSIONS. Between the TRM and TPM, this tag would occur in a response from a TPM that overlaps the tag parameter of a request with the tag parameter of a response, when the response has no associated sessions. . Note: This tag is not used by all TPM or TRM implementations. . reserved 0x8004 When used between application software and the TPM resource manager, this tag indicates that the command has sessions and the handles are using the Name format rather than the 32-bit handle format. Note: If the command completes successfully, the response to application software will have a tag of TPM_ST_SESSIONS. Be .tween the TRM and TPM, would occur in a response from a TPM that overlaps the tag parameter of a request with the tag parameter of a response, when the response has authorization sessions. Note: This tag is not used by all TPM or TRM implementations. .
    /// </summary>
    TPM_ST_SESSIONS = 0x8002,

    /// <summary>
    /// tag for an attestation structure
    /// </summary>
    TPM_ST_ATTEST_NV = 0x8014,

    /// <summary>
    /// tag for an attestation structure
    /// </summary>
    TPM_ST_ATTEST_COMMAND_AUDIT = 0x8015,

    /// <summary>
    /// tag for an attestation structure
    /// </summary>
    TPM_ST_ATTEST_SESSION_AUDIT = 0x8016,

    /// <summary>
    /// tag for an attestation structure
    /// </summary>
    TPM_ST_ATTEST_CERTIFY = 0x8017,

    /// <summary>
    /// tag for an attestation structure
    /// </summary>
    TPM_ST_ATTEST_QUOTE = 0x8018,

    /// <summary>
    /// tag for an attestation structure
    /// </summary>
    TPM_ST_ATTEST_TIME = 0x8019,

    /// <summary>
    /// tag for an attestation structure Name Value Comments reserved 0x801B do not use Note: This was previously assigned to
    /// </summary>
    TPM_ST_ATTEST_CREATION = 0x801A,

    /// <summary>
    /// tag for an attestation structure
    /// </summary>
    TPM_ST_ATTEST_NV_DIGEST = 0x801C,

    /// <summary>
    /// tag for a ticket type
    /// </summary>
    TPM_ST_CREATION = 0x8021,

    /// <summary>
    /// tag for a ticket type
    /// </summary>
    TPM_ST_VERIFIED = 0x8022,

    /// <summary>
    /// tag for a ticket type
    /// </summary>
    TPM_ST_AUTH_SECRET = 0x8023,

    /// <summary>
    /// tag for a ticket type
    /// </summary>
    TPM_ST_HASHCHECK = 0x8024,

    /// <summary>
    /// tag for a ticket type
    /// </summary>
    TPM_ST_AUTH_SIGNED = 0x8025,

    /// <summary>
    /// tag for a structure describing a Field Upgrade Policy
    /// </summary>
    TPM_ST_FU_MANIFEST = 0x8029
}