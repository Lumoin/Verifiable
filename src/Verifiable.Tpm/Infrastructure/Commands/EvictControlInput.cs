using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_EvictControl - makes a transient object persistent, or evicts a persistent object.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (2 handles):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@auth (TPMI_RH_PROVISION) - <c>TPM_RH_OWNER</c> or <c>TPM_RH_PLATFORM</c>; authorized with USER role.</description></item>
///   <item><description>objectHandle (TPMI_DH_OBJECT) - the object to persist (a transient handle) or to evict (the persistent handle itself).</description></item>
/// </list>
/// <para>
/// <strong>Parameter area:</strong> persistentHandle (TPMI_DH_PERSISTENT) - the persistent handle to assign
/// (when persisting) or the handle being evicted (when <c>objectHandle</c> is already persistent and equals it).
/// </para>
/// <para>
/// Owner-hierarchy persistent handles occupy 0x81000000-0x817FFFFF. This command is authorized, so it is sent
/// with <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library Part 3, Section 28.5 (Table 196). It has no response
/// parameters.
/// </para>
/// </remarks>
/// <param name="Auth">The provisioning hierarchy that authorizes the operation (owner or platform).</param>
/// <param name="ObjectHandle">The transient object to persist, or the persistent handle to evict.</param>
/// <param name="PersistentHandle">The persistent handle to assign or evict.</param>
public readonly record struct EvictControlInput(TpmRh Auth, uint ObjectHandle, uint PersistentHandle): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_EvictControl;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint) + sizeof(uint)     //auth + objectHandle.
        + sizeof(uint);                 //persistentHandle.

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)Auth);
        writer.WriteUInt32(ObjectHandle);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt32(PersistentHandle);
    }
}
