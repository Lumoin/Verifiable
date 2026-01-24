using System;
using System.Collections.Generic;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM ACT (Authenticated Countdown Timer) capability data (TPM_CAP_ACT).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format (TPML_ACT_DATA):</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                  // Number of ACT entries.
///     TPMS_ACT_DATA actData[count];  // Array of ACT data.
/// } TPML_ACT_DATA;
/// </code>
/// <para>
/// <b>Content:</b> Lists the authenticated countdown timers supported by the TPM.
/// ACTs are hardware timers that can trigger platform-specific actions when they expire.
/// </para>
/// <para>
/// <b>Note:</b> ACT support was added in TPM 2.0 revision 1.59. Older TPMs may not
/// support this capability.
/// </para>
/// </remarks>
/// <seealso cref="TpmsActData"/>
/// <seealso cref="TpmCapabilityData"/>
public sealed record TpmActData: TpmCapabilityData
{
    /// <inheritdoc/>
    public override TpmCapConstants Capability => TpmCapConstants.TPM_CAP_ACT;

    /// <summary>
    /// Gets the list of ACT data entries.
    /// </summary>
    /// <remarks>
    /// Each entry contains information about an authenticated countdown timer
    /// including its handle, timeout value, and attributes.
    /// </remarks>
    public required IReadOnlyList<TpmsActDataEntry> ActEntries { get; init; }
}