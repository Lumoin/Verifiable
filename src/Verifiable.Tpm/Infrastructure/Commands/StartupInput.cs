using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_Startup command (TPM 2.0 Library Part 1, clause 10.2.3; Part 3, clause 9.3).
/// </summary>
/// <remarks>
/// <para>
/// <strong>Wire format:</strong> a single <c>TPM_SU</c> startupType (UINT16). No handles, no
/// authorization, no response parameters.
/// </para>
/// </remarks>
/// <param name="StartupType">The startup type (<c>TPM_SU_CLEAR</c> or <c>TPM_SU_STATE</c>).</param>
public readonly record struct StartupInput(TpmSuConstants StartupType): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_Startup;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(ushort);

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        //TPM2_Startup has no input handles.
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer) => writer.WriteUInt16((ushort)StartupType);
}
