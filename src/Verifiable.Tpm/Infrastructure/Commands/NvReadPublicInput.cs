using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_ReadPublic - reads the public area and Name of an NV Index.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (1 handle):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>nvIndex (TPMI_RH_NV_INDEX) - the NV Index to read. Auth Index: None - the
///   handle carries no <c>@</c> authorization decoration, so no authorization session and no
///   password is ever attached to this command.</description></item>
/// </list>
/// <para>
/// There is no parameter area beyond the handle. The public area of an NV Index is not
/// privacy-sensitive, so the command is unconditionally world-readable: it needs no session and
/// is never gated on <c>TPMA_NV_READLOCKED</c>/<c>TPMA_NV_WRITELOCKED</c>/<c>TPMA_NV_WRITTEN</c>
/// (those gates apply only to commands that access the Index's data area; this command reads only
/// the public area and computes the Name). See
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0
/// Library Specification</see>, Part 3, Section 31.6 (Table 251).
/// </para>
/// </remarks>
/// <param name="NvIndex">The handle of the NV Index whose public area and Name are read.</param>
public readonly record struct NvReadPublicInput(uint NvIndex): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_ReadPublic;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint); //nvIndex.

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(NvIndex);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        //TPM2_NV_ReadPublic has no parameters beyond the handle.
    }
}
