using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Handles;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_Load.
/// </summary>
/// <remarks>
/// <para>
/// <b>Response handle (Part 3, Section 12.2):</b>
/// </para>
/// <list type="bullet">
///   <item><description>objectHandle (TPMI_DH_OBJECT) - the transient handle of the loaded object.</description></item>
/// </list>
/// <para>
/// <b>Response parameters:</b>
/// </para>
/// <list type="bullet">
///   <item><description>name (TPM2B_NAME) - the Name of the loaded object.</description></item>
/// </list>
/// <para>
/// The handle is transient: release it with <c>TPM2_FlushContext()</c> when no longer needed (it is also
/// cleared by the next TPM Reset).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class LoadResponse: ITpmWireType, IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the transient handle of the loaded object.
    /// </summary>
    public TpmiDhObject ObjectHandle { get; }

    /// <summary>
    /// Gets the Name of the loaded object.
    /// </summary>
    public Tpm2bName Name { get; }

    private LoadResponse(TpmiDhObject objectHandle, Tpm2bName name)
    {
        ObjectHandle = objectHandle;
        Name = name;
    }

    /// <summary>
    /// Parses the response from handle and parameter data.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="objectHandle">The object handle from the response handle area.</param>
    /// <param name="pool">The memory pool for allocations.</param>
    /// <returns>The parsed response.</returns>
    public static LoadResponse Parse(ref TpmReader reader, TpmiDhObject objectHandle, MemoryPool<byte> pool)
    {
        Tpm2bName name = Tpm2bName.Parse(ref reader, pool);

        return new LoadResponse(objectHandle, name);
    }

    /// <summary>
    /// Releases resources owned by this response.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Name.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"LoadResponse(Handle=0x{ObjectHandle.Value:X8}, Name={Name.Size} bytes)";
}
