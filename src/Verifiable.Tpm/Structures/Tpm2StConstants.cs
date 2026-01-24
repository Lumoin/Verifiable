namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM 2.0 structure tags (TPM_ST) indicating command/response format.
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 6.3 - TPM_ST.
/// </para>
/// </remarks>
public enum Tpm2StConstants: ushort
{
    /// <summary>
    /// TPM_ST_RSP_COMMAND: Tag for a response where an error occurred and no sessions.
    /// </summary>
    TPM_ST_RSP_COMMAND = 0x00C4,

    /// <summary>
    /// TPM_ST_NULL: Indicates a null tag value in certain structures.
    /// </summary>
    TPM_ST_NULL = 0x8000,

    /// <summary>
    /// TPM_ST_NO_SESSIONS: Command/response structure has no authorization sessions.
    /// </summary>
    TPM_ST_NO_SESSIONS = 0x8001,

    /// <summary>
    /// TPM_ST_SESSIONS: Command/response structure has one or more authorization sessions.
    /// </summary>
    TPM_ST_SESSIONS = 0x8002,

    /// <summary>
    /// TPM_ST_ATTEST_NV: Tag for an attestation structure for TPM2_NV_Certify.
    /// </summary>
    TPM_ST_ATTEST_NV = 0x8014,

    /// <summary>
    /// TPM_ST_ATTEST_COMMAND_AUDIT: Tag for a command audit attestation structure.
    /// </summary>
    TPM_ST_ATTEST_COMMAND_AUDIT = 0x8015,

    /// <summary>
    /// TPM_ST_ATTEST_SESSION_AUDIT: Tag for a session audit attestation structure.
    /// </summary>
    TPM_ST_ATTEST_SESSION_AUDIT = 0x8016,

    /// <summary>
    /// TPM_ST_ATTEST_CERTIFY: Tag for a key certification attestation structure.
    /// </summary>
    TPM_ST_ATTEST_CERTIFY = 0x8017,

    /// <summary>
    /// TPM_ST_ATTEST_QUOTE: Tag for a PCR quote attestation structure.
    /// </summary>
    TPM_ST_ATTEST_QUOTE = 0x8018,

    /// <summary>
    /// TPM_ST_ATTEST_TIME: Tag for a time attestation structure.
    /// </summary>
    TPM_ST_ATTEST_TIME = 0x8019,

    /// <summary>
    /// TPM_ST_ATTEST_CREATION: Tag for an object creation attestation structure.
    /// </summary>
    TPM_ST_ATTEST_CREATION = 0x801A,

    /// <summary>
    /// TPM_ST_CREATION: Tag indicating an object creation data structure.
    /// </summary>
    TPM_ST_CREATION = 0x8021,

    /// <summary>
    /// TPM_ST_VERIFIED: Tag indicating a verified signature structure.
    /// </summary>
    TPM_ST_VERIFIED = 0x8022,

    /// <summary>
    /// TPM_ST_AUTH_SECRET: Tag for a secret authorization structure.
    /// </summary>
    TPM_ST_AUTH_SECRET = 0x8023,

    /// <summary>
    /// TPM_ST_HASHCHECK: Tag for hash check ticket.
    /// </summary>
    TPM_ST_HASHCHECK = 0x8024,

    /// <summary>
    /// TPM_ST_AUTH_SIGNED: Tag for a signed authorization structure.
    /// </summary>
    TPM_ST_AUTH_SIGNED = 0x8025,

    /// <summary>
    /// TPM_ST_FU_MANIFEST: Tag for field upgrade manifest.
    /// </summary>
    TPM_ST_FU_MANIFEST = 0x8029
}