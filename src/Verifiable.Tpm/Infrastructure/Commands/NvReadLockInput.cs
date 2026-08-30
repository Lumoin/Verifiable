using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_ReadLock - SETs <c>TPMA_NV_READLOCKED</c> on an NV Index, blocking reads until the next
/// <c>TPM2_Startup(TPM_SU_CLEAR)</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (2 handles):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@authHandle (TPMI_RH_NV_AUTH) - the source of the authorization value; authorized with
///   USER role. "Proper authorizations are required for this command as determined by TPMA_NV_PPREAD,
///   TPMA_NV_OWNERREAD, TPMA_NV_AUTHREAD" (TPM 2.0 Library Part 3, clause 31.14.1) - a READ authorization: for
///   Index authorization this is the <c>nvIndex</c> itself (<c>TPMA_NV_AUTHREAD</c>), the owner hierarchy
///   (<c>TPMA_NV_OWNERREAD</c>) is the other modelled arm.</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX) - the NV Index to be locked; Auth Index None.</description></item>
/// </list>
/// <para>
/// There are no parameters and no response parameters. The Index must carry <c>TPMA_NV_READ_STCLEAR</c> (else
/// <c>TPM_RC_ATTRIBUTES</c>); an already-locked Index answers <c>TPM_RC_SUCCESS</c>; "An Index that had not been
/// written may be locked for reading". Locking changes the Index's Name (Part 1, clause 13). This command is
/// authorized, so it is sent with <c>TPM_ST_SESSIONS</c>, and the command is <c>{NV}</c>. See
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, Section 31.14 (Table 267/268).
/// </para>
/// </remarks>
/// <param name="AuthHandle">The authorization handle (the Index itself for Index authorization, or the owner hierarchy).</param>
/// <param name="NvIndex">The NV Index to lock for reading.</param>
public readonly record struct NvReadLockInput(uint AuthHandle, uint NvIndex): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_ReadLock;

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
        //TPM2_NV_ReadLock has no parameters.
    }
}
