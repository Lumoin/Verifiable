namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM 2.0 command codes (TPM_CC).
/// </summary>
/// <remarks>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see>, Part 2: Structures, Section 6.5.2 - TPM_CC.
/// </para>
/// </remarks>
public enum Tpm2CcConstants: uint
{
    /// <summary>
    /// TPM2_HierarchyControl: Enable or disable a hierarchy.
    /// </summary>
    TPM2_CC_HierarchyControl = 0x00000121,

    /// <summary>
    /// TPM2_NV_UndefineSpace: Remove an NV Index from the TPM.
    /// </summary>
    TPM2_CC_NV_UndefineSpace = 0x00000122,

    /// <summary>
    /// TPM2_Clear: Remove all TPM context associated with a specific owner.
    /// </summary>
    TPM2_CC_Clear = 0x00000126,

    /// <summary>
    /// TPM2_NV_DefineSpace: Define an NV Index with given attributes.
    /// </summary>
    TPM2_CC_NV_DefineSpace = 0x0000012A,

    /// <summary>
    /// TPM2_NV_Write: Write data to an NV Index.
    /// </summary>
    TPM2_CC_NV_Write = 0x00000137,

    /// <summary>
    /// TPM2_NV_WriteLock: Lock an NV Index for writing until the next TPM reset.
    /// </summary>
    TPM2_CC_NV_WriteLock = 0x00000138,

    /// <summary>
    /// TPM2_SequenceComplete: Complete a hash or HMAC sequence and return the result.
    /// </summary>
    TPM2_CC_SequenceComplete = 0x0000013E,

    /// <summary>
    /// TPM2_SelfTest: Cause the TPM to perform a self-test of selected algorithms.
    /// </summary>
    TPM2_CC_SelfTest = 0x00000143,

    /// <summary>
    /// TPM2_Startup: Initialize the TPM after a power-on or reset.
    /// </summary>
    TPM2_CC_Startup = 0x00000144,

    /// <summary>
    /// TPM2_Shutdown: Prepare the TPM for a power cycle or reset.
    /// </summary>
    TPM2_CC_Shutdown = 0x00000145,

    /// <summary>
    /// TPM2_NV_Read: Read data from an NV Index.
    /// </summary>
    TPM2_CC_NV_Read = 0x0000014E,

    /// <summary>
    /// TPM2_NV_ReadLock: Lock an NV Index for reading until the next TPM reset.
    /// </summary>
    TPM2_CC_NV_ReadLock = 0x0000014F,

    /// <summary>
    /// TPM2_SequenceUpdate: Add data to a hash or HMAC sequence.
    /// </summary>
    TPM2_CC_SequenceUpdate = 0x0000015C,

    /// <summary>
    /// TPM2_FlushContext: Remove a loaded object or session from TPM memory.
    /// </summary>
    TPM2_CC_FlushContext = 0x00000165,

    /// <summary>
    /// TPM2_NV_ReadPublic: Read the public area of an NV Index.
    /// </summary>
    TPM2_CC_NV_ReadPublic = 0x00000169,

    /// <summary>
    /// TPM2_GetCapability: Returns various information about the TPM and its state.
    /// </summary>
    TPM2_CC_GetCapability = 0x0000017A,

    /// <summary>
    /// TPM2_GetRandom: Returns random bytes from the TPM's RNG.
    /// </summary>
    TPM2_CC_GetRandom = 0x0000017B,

    /// <summary>
    /// TPM2_Hash: Performs a hash operation on a data buffer and returns the result.
    /// </summary>
    TPM2_CC_Hash = 0x0000017D,

    /// <summary>
    /// TPM2_ReadClock: Returns the current values of time and clock.
    /// </summary>
    TPM2_CC_ReadClock = 0x00000181,

    /// <summary>
    /// TPM2_HashSequenceStart: Start a hash or event sequence.
    /// </summary>
    TPM2_CC_HashSequenceStart = 0x00000186
}