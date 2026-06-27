using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_Read - reads data from an NV Index.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (2 handles):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@authHandle (TPMI_RH_NV_AUTH) - the source of the authorization value;
///   authorized with USER role. For Index authorization this is the <c>nvIndex</c> itself.</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX) - the NV Index to read.</description></item>
/// </list>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>size (UINT16) - number of octets to read.</description></item>
///   <item><description>offset (UINT16) - octet offset into the NV area.</description></item>
/// </list>
/// <para>
/// This command is authorized, so it is sent with <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library Part 3,
/// Section 31.13 (Table 248).
/// </para>
/// </remarks>
public readonly record struct NvReadInput(uint AuthHandle, uint NvIndex, ushort Size, ushort Offset): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_Read;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint) + sizeof(uint)     //authHandle + nvIndex.
        + sizeof(ushort) + sizeof(ushort); //size + offset.

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(AuthHandle);
        writer.WriteUInt32(NvIndex);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt16(Size);
        writer.WriteUInt16(Offset);
    }
}
