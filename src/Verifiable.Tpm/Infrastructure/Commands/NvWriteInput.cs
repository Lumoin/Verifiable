using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_Write - writes data to an NV Index at the given offset.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (2 handles):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@authHandle (TPMI_RH_NV_AUTH) - the source of the authorization value; authorized with
///   USER role. For Index authorization this is the <c>nvIndex</c> itself.</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX) - the NV Index to write.</description></item>
/// </list>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>data (TPM2B_MAX_NV_BUFFER) - the data to write.</description></item>
///   <item><description>offset (UINT16) - octet offset into the NV area.</description></item>
/// </list>
/// <para>
/// A successful write sets the Index's <c>TPMA_NV_WRITTEN</c> attribute, after which the data can be read back
/// with TPM2_NV_Read. This command is authorized, so it is sent with <c>TPM_ST_SESSIONS</c>. See TPM 2.0 Library
/// Part 3, Section 31.7 (Table 232).
/// </para>
/// </remarks>
/// <param name="AuthHandle">The authorization handle (the Index itself for Index authorization).</param>
/// <param name="NvIndex">The NV Index to write.</param>
/// <param name="Data">The data to write (TPM2B_MAX_NV_BUFFER). The caller owns the underlying memory.</param>
/// <param name="Offset">The octet offset into the NV area at which to write.</param>
public readonly record struct NvWriteInput(uint AuthHandle, uint NvIndex, Tpm2bMaxBuffer Data, ushort Offset): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_Write;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint) + sizeof(uint)     //authHandle + nvIndex.
        + Data.SerializedSize           //data (TPM2B_MAX_NV_BUFFER: size prefix + bytes).
        + sizeof(ushort);               //offset.

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(AuthHandle);
        writer.WriteUInt32(NvIndex);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteTpm2b(Data.Buffer.Span);
        writer.WriteUInt16(Offset);
    }
}
