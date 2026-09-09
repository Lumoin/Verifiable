using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_Extend - extends data into an NV Extend Index's digest.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (2 handles):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@authHandle (TPMI_RH_NV_AUTH) - the source of the authorization value; authorized with
///   USER role. For Index authorization this is the <c>nvIndex</c> itself; the owner hierarchy
///   (<c>TPM_RH_OWNER</c>) is the other modelled arm.</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX) - the NV Index to extend; Auth Index None.</description></item>
/// </list>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>data (TPM2B_MAX_NV_BUFFER) - the data to extend into the Index. A successful command
///   replaces the Index's contents with <c>nvIndex→data_new = H_nameAlg(nvIndex→data_old ‖ data.buffer)</c> (TPM
///   2.0 Library Part 1, clause 34.2.6.5, equation 56), where <c>nameAlg</c> is the hash algorithm bound to the
///   Index at definition. <c>data.buffer</c> need not be the size of the Index (clause 31.9.1); an empty buffer
///   is a valid extend.</description></item>
/// </list>
/// <para>
/// A successful extend sets the Index's <c>TPMA_NV_WRITTEN</c> attribute. This command is authorized, so it is
/// sent with <c>TPM_ST_SESSIONS</c>, and the command is <c>{NV}</c>. See
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 31.9 (Table 257/258).
/// </para>
/// <para>
/// <c>data</c> is the first parameter and a sized TPM2B, so TPM 2.0 Library Part 1, clause 18.1 makes it
/// decrypt-eligible in principle. The NV family keeps parameter encryption on <c>data</c> closed on both the
/// host and the simulator, the same posture <see cref="NvWriteInput"/> takes for its own <c>data</c> parameter,
/// so <see cref="FirstCommandParameterIsEncryptable"/> is left at its default <see langword="false"/> and the
/// executor refuses a decrypt session for this command client-side.
/// </para>
/// </remarks>
/// <param name="AuthHandle">The authorization handle (the Index itself for Index authorization, or the owner hierarchy).</param>
/// <param name="NvIndex">The NV Index to extend.</param>
/// <param name="Data">The data to extend into the Index (<c>TPM2B_MAX_NV_BUFFER</c>, TPM 2.0 Library Part 2, clause 10.3.9, Table 97) in a pooled carrier this input BORROWS: the caller owns it and releases it once the command has been framed.</param>
public readonly record struct NvExtendInput(uint AuthHandle, uint NvIndex, Tpm2bMaxNvBuffer Data): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_Extend;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint) + sizeof(uint)     //authHandle + nvIndex.
        + Data.SerializedSize;          //data (TPM2B_MAX_NV_BUFFER: size prefix + bytes).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(AuthHandle);
        writer.WriteUInt32(NvIndex);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteTpm2b(Data.Span);
    }
}
