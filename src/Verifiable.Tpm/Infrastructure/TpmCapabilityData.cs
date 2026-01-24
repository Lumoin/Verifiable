using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm.Structures;

/// <summary>
/// Abstract base for TPM capability data returned by TPM2_GetCapability.
/// </summary>
/// <remarks>
/// <para>
/// <b>Design:</b> This type hierarchy represents the discriminated union returned by
/// TPM2_GetCapability. Rather than using an interface with runtime type checking
/// (as in traditional TPM libraries), we use sealed record types that enable
/// exhaustive pattern matching at compile time.
/// </para>
/// <para>
/// <b>Wire format (TPMS_CAPABILITY_DATA):</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM_CAP capability;      // Selector indicating which union member is present.
///     TPMU_CAPABILITIES data;  // Union of capability-specific data.
/// } TPMS_CAPABILITY_DATA;
/// </code>
/// <para>
/// <b>Union variants (TPMU_CAPABILITIES):</b>
/// </para>
/// <list type="bullet">
///   <item><description><see cref="TpmAlgorithmsData"/> - TPM_CAP_ALGS: Supported algorithms.</description></item>
///   <item><description><see cref="TpmHandlesData"/> - TPM_CAP_HANDLES: Active handles.</description></item>
///   <item><description><see cref="TpmCommandsData"/> - TPM_CAP_COMMANDS: Supported commands.</description></item>
///   <item><description><see cref="TpmCommandCodesData"/> - TPM_CAP_PP_COMMANDS, TPM_CAP_AUDIT_COMMANDS: Command code lists.</description></item>
///   <item><description><see cref="TpmPcrSelectionData"/> - TPM_CAP_PCRS: PCR bank configuration.</description></item>
///   <item><description><see cref="TpmPropertiesData"/> - TPM_CAP_TPM_PROPERTIES: Fixed/variable properties.</description></item>
///   <item><description><see cref="TpmPcrPropertiesData"/> - TPM_CAP_PCR_PROPERTIES: PCR properties.</description></item>
///   <item><description><see cref="TpmEccCurvesData"/> - TPM_CAP_ECC_CURVES: Supported ECC curves.</description></item>
///   <item><description><see cref="TpmAuthPoliciesData"/> - TPM_CAP_AUTH_POLICIES: Permanent handle policies.</description></item>
///   <item><description><see cref="TpmActData"/> - TPM_CAP_ACT: Authenticated countdown timers.</description></item>
/// </list>
/// <para>
/// <b>Usage with pattern matching:</b>
/// </para>
/// <code>
/// TpmCapabilityData data = device.GetCapability(...);
/// 
/// string result = data switch
/// {
///     TpmPropertiesData props => $"Got {props.Properties.Count} properties",
///     TpmAlgorithmsData algs => $"Got {algs.Algorithms.Count} algorithms",
///     _ => "Other capability type"
/// };
/// </code>
/// <para>
/// <b>Two-layer architecture:</b>
/// </para>
/// <list type="number">
///   <item><description><b>Wire types</b> (this hierarchy): Spec-faithful structures for parsing.
///   These mirror the TPM2 specification exactly.</description></item>
///   <item><description><b>Semantic POCOs</b> (separate types): Consumer-friendly types with named
///   accessors like Manufacturer, FirmwareVersion, IsFipsMode. Created by interpreting wire types.</description></item>
/// </list>
/// </remarks>
/// <seealso href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification, Part 2: Structures, Section 10.10 - TPMS_CAPABILITY_DATA.
/// </seealso>
public abstract record TpmCapabilityData
{
    /// <summary>
    /// Gets the capability type selector.
    /// </summary>
    /// <remarks>
    /// This corresponds to the TPM_CAP value that identifies which union member is present.
    /// Each derived type returns its specific capability constant.
    /// </remarks>
    public abstract TpmCapConstants Capability { get; }

    /// <summary>
    /// Gets a value indicating whether more data is available.
    /// </summary>
    /// <remarks>
    /// When <c>true</c>, the TPM has more capability data than could fit in a single response.
    /// Call GetCapability again with an updated starting value to retrieve additional data.
    /// Extension methods like GetFixedProperties handle paging automatically.
    /// </remarks>
    public bool MoreData { get; init; }
}