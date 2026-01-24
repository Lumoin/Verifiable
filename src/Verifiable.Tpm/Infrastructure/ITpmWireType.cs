namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Marker interface for TPM wire types.
/// </summary>
/// <remarks>
/// <para>
/// Wire types are spec-faithful structures that mirror the TPM specification
/// layout exactly. They contain no derived interpretation logic.
/// </para>
/// <para>
/// <b>Requirements for wire types:</b>
/// </para>
/// <list type="bullet">
///   <item><description>Field layout matches TPM specification.</description></item>
///   <item><description>No derived interpretation (e.g., no vendor string concatenation).</description></item>
///   <item><description>Provide <c>static Parse(ref TpmReader)</c> method.</description></item>
///   <item><description>Optionally provide <c>WriteTo(ref TpmWriter)</c> method.</description></item>
///   <item><description>Optionally provide <c>SerializedSize</c> property.</description></item>
/// </list>
/// <para>
/// Semantic convenience wrappers (e.g., <c>TpmDeviceInfo</c>) are built from
/// wire types in the extensions layer, not in the core.
/// </para>
/// </remarks>
public interface ITpmWireType
{
}