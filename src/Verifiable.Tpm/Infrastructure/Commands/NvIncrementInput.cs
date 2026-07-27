using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_Increment - increments an NV Counter Index's 8-octet value by one.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (2 handles):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@authHandle (TPMI_RH_NV_AUTH) - the source of the authorization value; authorized with
///   USER role. For Index authorization this is the <c>nvIndex</c> itself; the owner hierarchy is the other
///   modelled arm.</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX) - the NV Index to increment.</description></item>
/// </list>
/// <para>
/// There are no parameters and no response parameters. This command is authorized, so it is sent with
/// <c>TPM_ST_SESSIONS</c>. See
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, Section 31.8 (Table 222/223).
/// </para>
/// </remarks>
/// <param name="AuthHandle">The authorization handle (the Index itself for Index authorization, or the owner hierarchy).</param>
/// <param name="NvIndex">The NV Counter Index to increment.</param>
public readonly record struct NvIncrementInput(uint AuthHandle, uint NvIndex): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_Increment;

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
        //TPM2_NV_Increment has no parameters.
    }
}
