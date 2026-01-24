using System.Diagnostics;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Reports ACT (Authenticated Countdown Timer) data (TPMS_ACT_DATA).
/// </summary>
/// <remarks>
/// <para>
/// Returned by <c>TPM2_GetCapability(capability == TPM_CAP_ACT)</c> to report
/// the timeout and state of Authenticated Countdown Timers.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_HANDLE handle;     // A permanent handle.
///     UINT32 timeout;        // The current timeout of the ACT.
///     TPMA_ACT attributes;   // The state of the ACT.
/// } TPMS_ACT_DATA;
/// </code>
/// <para>
/// ACTs are countdown timers that can trigger actions when they expire.
/// They are used for time-limited authorizations and other time-sensitive
/// TPM operations.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, section 10.8.5, Table 117.
/// </para>
/// </remarks>
/// <param name="Handle">A permanent handle identifying the ACT.</param>
/// <param name="Timeout">The current timeout value in seconds.</param>
/// <param name="Attributes">The state attributes of the ACT.</param>
/// <seealso cref="TpmsActDataExtensions"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly record struct TpmsActData(uint Handle, uint Timeout, TpmaAct Attributes)
{
    private string DebuggerDisplay
    {
        get
        {
            string handleName = TpmValueConversions.GetHandleDescription(Handle);
            string timeoutStr = Timeout == 0 ? "expired" : $"{Timeout}s remaining";

            var states = new System.Collections.Generic.List<string>();

            if(Attributes.HasFlag(TpmaAct.Signaled))
            {
                states.Add("signaled");
            }

            if(Attributes.HasFlag(TpmaAct.PreserveSignaled))
            {
                states.Add("preserve-signaled");
            }

            string stateStr = states.Count > 0
                ? string.Join(", ", states)
                : "idle";

            return $"{handleName}: {timeoutStr} [{stateStr}]";
        }
    }
}
