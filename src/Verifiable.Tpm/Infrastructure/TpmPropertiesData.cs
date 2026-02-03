using System.Collections.Generic;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// TPM properties capability data (TPM_CAP_TPM_PROPERTIES).
/// </summary>
/// <remarks>
/// <para>
/// <b>Wire format (TPML_TAGGED_TPM_PROPERTY):</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT32 count;                              // Number of properties.
///     TPMS_TAGGED_PROPERTY tpmProperty[count];   // Array of tagged properties.
/// } TPML_TAGGED_TPM_PROPERTY;
/// </code>
/// <para>
/// <b>Property categories:</b>
/// </para>
/// <list type="bullet">
///   <item><description><b>Fixed properties</b> (PT_FIXED, 0x100-0x1FF): Immutable values like
///   manufacturer ID, firmware version, specification level. These never change.</description></item>
///   <item><description><b>Variable properties</b> (PT_VAR, 0x200-0x2FF): Mutable values like
///   startup clear flag, lockout counter, audit counter. These change during operation.</description></item>
/// </list>
/// <para>
/// <b>Semantic interpretation:</b> Use <c>TpmFixedProperties.FromData()</c> or
/// <c>TpmVariableProperties.FromData()</c> to convert wire data into POCOs with
/// named accessors like Manufacturer, FirmwareVersion, IsFipsMode.
/// </para>
/// </remarks>
/// <seealso cref="TpmsTaggedProperty"/>
/// <seealso cref="TpmCapabilityData"/>
public sealed record TpmPropertiesData: TpmCapabilityData
{
    /// <inheritdoc/>
    public override TpmCapConstants Capability => TpmCapConstants.TPM_CAP_TPM_PROPERTIES;

    /// <summary>
    /// Gets the list of tagged properties.
    /// </summary>
    /// <remarks>
    /// Each property is a key-value pair where the key is a <see cref="Tpm2PtConstants"/>
    /// identifier and the value is a 32-bit unsigned integer. The interpretation of the
    /// value depends on the property type.
    /// </remarks>
    public required IReadOnlyList<TpmsTaggedProperty> Properties { get; init; }
}