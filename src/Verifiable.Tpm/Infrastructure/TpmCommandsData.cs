using System.Collections.Generic;
using Verifiable.Tpm.Infrastructure.Spec.Attributes;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM commands capability data (TPM_CAP_COMMANDS).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format (TPML_CCA):</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                      // Number of command attributes.
///     TPMA_CC commandAttributes[count];  // Array of command attributes.
/// } TPML_CCA;
/// </code>
/// <para>
/// <b>Content:</b> Lists all commands supported by the TPM along with their attributes.
/// Each entry is a TPMA_CC value that encodes the command code and its properties
/// (number of handles, whether it uses authorization, etc.).
/// </para>
/// </remarks>
/// <seealso cref="TpmaCc"/>
/// <seealso cref="TpmCapabilityData"/>
public sealed record TpmCommandsData: TpmCapabilityData
{
    /// <inheritdoc/>
    public override TpmCapConstants Capability => TpmCapConstants.TPM_CAP_COMMANDS;

    /// <summary>
    /// Gets the list of command attributes.
    /// </summary>
    /// <remarks>
    /// Each entry is a TPMA_CC value containing the command code and attribute flags.
    /// Use <see cref="TpmaCc"/> to extract individual fields.
    /// </remarks>
    public required IReadOnlyList<TpmaCc> Commands { get; init; }
}