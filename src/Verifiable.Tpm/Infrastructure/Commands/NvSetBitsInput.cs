using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for TPM2_NV_SetBits - ORs a 64-bit value into an NV Bit Field Index.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area (2 handles):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>@authHandle (TPMI_RH_NV_AUTH) - the source of the authorization value; authorized with
///   USER role. For Index authorization this is the <c>nvIndex</c> itself; the owner hierarchy
///   (<c>TPM_RH_OWNER</c>) is the other modelled arm.</description></item>
///   <item><description>nvIndex (TPMI_RH_NV_INDEX) - the NV Index of the area in which the bits are to be set;
///   Auth Index None.</description></item>
/// </list>
/// <para>
/// <strong>Parameter area:</strong>
/// </para>
/// <list type="bullet">
///   <item><description>bits (UINT64) - the data to OR with the current contents. "Any number of bits from 0 to 64
///   may be SET" and an unwritten Index "is considered to contain all zero bits" (TPM 2.0 Library Part 3, clause
///   31.10.1), so the first successful command stores exactly <c>bits</c>; every later one stores the OR.
///   <c>TPMA_NV_WRITTEN</c> is SET even when no bit is.</description></item>
/// </list>
/// <para>
/// This command is authorized, so it is sent with <c>TPM_ST_SESSIONS</c>, and the command is <c>{NV}</c>. See
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 31.10 (Table 259/260).
/// </para>
/// <para>
/// <c>bits</c> is a plain <c>UINT64</c>, not a sized TPM2B, so TPM 2.0 Library Part 1, clause 18.1 makes it
/// ineligible for parameter encryption: <see cref="FirstCommandParameterIsEncryptable"/> stays at its default
/// <see langword="false"/> by the specification's own rule, and the executor refuses a decrypt session for this
/// command client-side.
/// </para>
/// </remarks>
/// <param name="AuthHandle">The authorization handle (the Index itself for Index authorization, or the owner hierarchy).</param>
/// <param name="NvIndex">The NV Bit Field Index whose bits are SET.</param>
/// <param name="Bits">The 64-bit value ORed into the Index's current contents.</param>
public readonly record struct NvSetBitsInput(uint AuthHandle, uint NvIndex, ulong Bits): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_NV_SetBits;

    /// <inheritdoc/>
    public int GetSerializedSize() =>
        sizeof(uint) + sizeof(uint)     //authHandle + nvIndex.
        + sizeof(ulong);                //bits (UINT64).

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32(AuthHandle);
        writer.WriteUInt32(NvIndex);
    }

    /// <inheritdoc/>
    public void WriteParameters(ref TpmWriter writer)
    {
        writer.WriteUInt64(Bits);
    }
}
