using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_NV_GlobalWriteLock command (TPM 2.0 Library Part 3, clause 31.12). SETs
/// <c>TPMA_NV_WRITELOCKED</c> on every defined NV Index whose <c>TPMA_NV_GLOBALLOCK</c> attribute is SET, rather
/// than the one Index <c>TPM2_NV_WriteLock()</c> names.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> <c>@authHandle</c> (<c>TPMI_RH_PROVISION</c>) - <c>TPM_RH_OWNER</c> or
/// <c>TPM_RH_PLATFORM</c>; authorized with USER role (1 handle). "This command requires either
/// platformAuth/platformPolicy or ownerAuth/ownerPolicy" (clause 31.12.1). The caller supplies the authorizing
/// session separately (via <c>TpmCommandExecutor</c>'s session list); this type carries only the handle.
/// </para>
/// <para>
/// This command has no parameters and no response parameters. The authorizing handle plays no part in which
/// Indexes lock - every Index carrying <c>TPMA_NV_GLOBALLOCK</c> locks "whether the index was defined using
/// Owner Authorization or Platform Authorization" (clause 31.12.1). It is authorized, so it is sent with
/// <c>TPM_ST_SESSIONS</c>, and the command is <c>{NV}</c>. See
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 31.12 (Tables 263/264).
/// </para>
/// </remarks>
/// <param name="AuthHandle">The owner or platform hierarchy authorizing the global write lock.</param>
public readonly record struct NvGlobalWriteLockInput(TpmRh AuthHandle): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_GlobalWriteLock;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint);

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)AuthHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_NV_GlobalWriteLock has no parameters.
    }
}
