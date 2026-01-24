using System.Collections.Generic;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM handles capability data (TPM_CAP_HANDLES).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format (TPML_HANDLE):</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;              // Number of handles.
///     TPM_HANDLE handle[count];  // Array of handles.
/// } TPML_HANDLE;
/// </code>
/// <para>
/// <b>Handle types:</b> The starting property value determines which handle type is queried:
/// </para>
/// <list type="bullet">
///   <item><description>HT_PCR (0x00): PCR handles.</description></item>
///   <item><description>HT_NV_INDEX (0x01): NV index handles.</description></item>
///   <item><description>HT_LOADED_SESSION (0x02): Loaded HMAC/policy session handles.</description></item>
///   <item><description>HT_SAVED_SESSION (0x03): Saved session handles.</description></item>
///   <item><description>HT_PERMANENT (0x40): Permanent handles.</description></item>
///   <item><description>HT_TRANSIENT (0x80): Transient object handles.</description></item>
///   <item><description>HT_PERSISTENT (0x81): Persistent object handles.</description></item>
/// </list>
/// </remarks>
/// <seealso cref="TpmCapabilityData"/>
public sealed record TpmHandlesData: TpmCapabilityData
{
    /// <inheritdoc/>
    public override TpmCapConstants Capability => TpmCapConstants.TPM_CAP_HANDLES;

    /// <summary>
    /// Gets the list of handles.
    /// </summary>
    /// <remarks>
    /// Handles are 32-bit values where the upper byte indicates the handle type.
    /// </remarks>
    public required IReadOnlyList<uint> Handles { get; init; }
}