using System;
using System.Collections.Generic;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM PCR properties capability data (TPM_CAP_PCR_PROPERTIES).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format (TPML_TAGGED_PCR_PROPERTY):</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                              // Number of PCR properties.
///     TPMS_TAGGED_PCR_SELECT pcrProperty[count]; // Array of PCR properties.
/// } TPML_TAGGED_PCR_PROPERTY;
/// </code>
/// <para>
/// <b>Content:</b> Lists PCR properties such as which PCRs can be reset, extended,
/// or have specific locality requirements. Each property is tagged with a property
/// identifier and includes a bitmap of affected PCR indices.
/// </para>
/// </remarks>
/// <seealso cref="TpmsTaggedPcrSelect"/>
/// <seealso cref="TpmCapabilityData"/>
public sealed record TpmPcrPropertiesData: TpmCapabilityData
{
    /// <inheritdoc/>
    public override TpmCapConstants Capability => TpmCapConstants.TPM_CAP_PCR_PROPERTIES;

    /// <summary>
    /// Gets the list of tagged PCR properties.
    /// </summary>
    /// <remarks>
    /// Each entry specifies a PCR property type and a bitmap of PCR indices
    /// that have that property.
    /// </remarks>
    public required IReadOnlyList<TpmsTaggedPcrSelect> PcrProperties { get; init; }
}