using System;
using Verifiable.Tpm.Infrastructure.Spec.Structures;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_GetCapability.
/// </summary>
/// <remarks>
/// <para>
/// This type represents the complete response parameter area for the
/// TPM2_GetCapability command. It bundles the individual response parameters
/// as defined in the specification.
/// </para>
/// <para>
/// <b>Response parameters (Part 3, Section 30.2):</b>
/// </para>
/// <list type="bullet">
///   <item><description>moreData (TPMI_YES_NO) - flag indicating if more data is available.</description></item>
///   <item><description>capabilityData (TPMS_CAPABILITY_DATA) - the capability data.</description></item>
/// </list>
/// <para>
/// <b>Note:</b> This is a library convenience type that bundles the response
/// parameters. The TPM specification defines these as separate parameters in
/// the response, not as a named structure.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class GetCapabilityResponse: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the moreData flag indicating if additional data is available.
    /// </summary>
    /// <remarks>
    /// When true, the caller should issue another TPM2_GetCapability command
    /// with an updated property value to retrieve the remaining data.
    /// </remarks>
    public TpmiYesNo MoreData { get; }

    /// <summary>
    /// Gets the capability data.
    /// </summary>
    public TpmsCapabilityData CapabilityData { get; }

    private GetCapabilityResponse(TpmiYesNo moreData, TpmsCapabilityData capabilityData)
    {
        MoreData = moreData;
        CapabilityData = capabilityData;
    }

    /// <summary>
    /// Parses the response parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for allocations.</param>
    /// <returns>The parsed response.</returns>
    public static GetCapabilityResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        TpmiYesNo moreData = TpmiYesNo.Parse(ref reader);
        TpmsCapabilityData capabilityData = TpmsCapabilityData.Parse(ref reader, pool);

        return new GetCapabilityResponse(moreData, capabilityData);
    }

    /// <summary>
    /// Releases resources owned by this response.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            CapabilityData.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"GetCapabilityResponse(MoreData={MoreData.IsYes}, {CapabilityData.Capability})";
}