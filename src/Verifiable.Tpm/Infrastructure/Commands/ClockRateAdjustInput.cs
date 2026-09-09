using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Input for the TPM2_ClockRateAdjust command (TPM 2.0 Library Part 3, clause 29.3). Adjusts the rate at
/// which <c>Clock</c> and <c>Time</c> advance, relative to their current rate, authorized by the owner or
/// platform hierarchy.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Handle area:</strong> <c>@auth</c> (<c>TPMI_RH_PROVISION</c>) — <c>TPM_RH_OWNER</c> or
/// <c>TPM_RH_PLATFORM</c>; authorized with USER role (1 handle). The caller supplies the authorizing
/// session separately (via <c>TpmCommandExecutor</c>'s session list); this type carries only the handle
/// and the requested adjustment.
/// </para>
/// <para>
/// <strong>Parameter area:</strong> <c>rateAdjust</c> (<c>TPM_CLOCK_ADJUST</c>, a single signed octet) — the
/// requested step, relative to the current rate rather than the nominal one.
/// </para>
/// <para>
/// This command is authorized, so it is sent with <c>TPM_ST_SESSIONS</c>. See
/// <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">TPM 2.0 Library
/// Specification</see>, Part 3, clause 29.3 (Table 236).
/// </para>
/// </remarks>
/// <param name="AuthHandle">The provisioning hierarchy authorizing the adjustment.</param>
/// <param name="RateAdjust">The requested rate adjustment.</param>
public readonly record struct ClockRateAdjustInput(TpmRh AuthHandle, TpmClockAdjustConstants RateAdjust): ITpmCommandInput
{
    /// <inheritdoc/>
    public TpmCcConstants CommandCode => TpmCcConstants.TPM_CC_ClockRateAdjust;

    /// <inheritdoc/>
    public int GetSerializedSize() => sizeof(uint) + sizeof(sbyte);

    /// <inheritdoc/>
    public void WriteHandles(ref TpmWriter writer)
    {
        writer.WriteUInt32((uint)AuthHandle);
    }

    /// <summary>
    /// Writes the single <c>rateAdjust</c> octet, refusing a value outside Table 19's seven defined
    /// <c>TPM_CLOCK_ADJUST</c> steps before it is ever framed. This is the executor's client-side posture: a
    /// caller mistake is caught here, on the local stack, rather than round-tripped to the TPM only to be
    /// refused by its own Table 19 membership check (TPM 2.0 Library Part 2, clause 6.7).
    /// </summary>
    /// <param name="writer">The writer positioned at the start of the parameter area.</param>
    /// <exception cref="System.ArgumentOutOfRangeException">
    /// <see cref="RateAdjust"/> is not one of Table 19's seven defined members
    /// (<see cref="TpmClockAdjustConstantsExtensions.IsDefined"/>).
    /// </exception>
    public void WriteParameters(ref TpmWriter writer)
    {
        EnsureRateAdjustIsDefined(RateAdjust);

        writer.WriteInt8((sbyte)RateAdjust);
    }

    /// <summary>
    /// Refuses a <paramref name="rateAdjust"/> outside Table 19's seven defined <c>TPM_CLOCK_ADJUST</c> members.
    /// </summary>
    /// <param name="rateAdjust">The requested rate adjustment to validate before it is framed.</param>
    /// <exception cref="System.ArgumentOutOfRangeException"><paramref name="rateAdjust"/> is not one of Table 19's seven defined members.</exception>
    private static void EnsureRateAdjustIsDefined(TpmClockAdjustConstants rateAdjust)
    {
        if(!rateAdjust.IsDefined())
        {
            throw new System.ArgumentOutOfRangeException(nameof(rateAdjust), rateAdjust, "TPM 2.0 Library Part 2, clause 6.7, Table 19 defines seven TPM_CLOCK_ADJUST members; the supplied value is not one of them.");
        }
    }
}
