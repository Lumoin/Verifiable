using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_WriteLock - SETs <c>TPMA_NV_WRITELOCKED</c> on an NV Index, inhibiting further writes.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (2 handles):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@authHandle (TPMI_RH_NV_AUTH) - the source of the authorization value; authorized with
///   USER role. "Proper write authorization is required for this command" (TPM 2.0 Library Part 3, clause
///   31.11.1): for Index authorization this is the <c>nvIndex</c> itself (<c>TPMA_NV_AUTHWRITE</c>), the owner
///   hierarchy (<c>TPMA_NV_OWNERWRITE</c>) is the other modelled arm.</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX) - the NV Index of the area to lock; Auth Index
///   None.</description></item>
/// </list>
/// <para>
/// There are no parameters and no response parameters. The Index must carry <c>TPMA_NV_WRITEDEFINE</c> or
/// <c>TPMA_NV_WRITE_STCLEAR</c> (else <c>TPM_RC_ATTRIBUTES</c>); an already-locked Index answers
/// <c>TPM_RC_SUCCESS</c>. The lock is CLEAR by the next <c>TPM2_Startup(TPM_SU_CLEAR)</c> unless
/// <c>TPMA_NV_WRITEDEFINE</c> is SET and the Index has been written, in which case only deleting and redefining the
/// Index clears it. Locking changes the Index's Name (Part 1, clause 13). This command is authorized, so it is sent
/// with <c>TPM_ST_SESSIONS</c>, and the command is <c>{NV}</c>. See
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, Section 31.11 (Table 261/262).
/// </para>
/// </remarks>
/// <param name="AuthHandle">The authorization handle (the Index itself for Index authorization, or the owner hierarchy).</param>
/// <param name="NvIndex">The NV Index to lock for writing.</param>
public readonly record struct NvWriteLockInput(uint AuthHandle, uint NvIndex): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_WriteLock;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint) + sizeof(uint); //authHandle + nvIndex.

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(AuthHandle);
        writer.WriteUInt32(NvIndex);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_NV_WriteLock has no parameters.
    }
}
