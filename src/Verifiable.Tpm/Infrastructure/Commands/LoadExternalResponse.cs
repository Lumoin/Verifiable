using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Handles;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_LoadExternal.
/// </summary>
/// <remarks>
/// <para>
/// <b>Response handle (Part 3, clause 12.3.2, Table 23):</b>
/// </para>
/// <list type="bullet">
///   <item><description>objectHandle (TPM_HANDLE) - the transient handle of the loaded object.</description></item>
/// </list>
/// <para>
/// <b>Response parameters:</b>
/// </para>
/// <list type="bullet">
///   <item><description>name (TPM2B_NAME) - the Name of the loaded object; the Empty Buffer when nameAlg = TPM_ALG_NULL.</description></item>
/// </list>
/// <para>
/// The handle is transient: release it with <c>TPM2_FlushContext()</c> when no longer needed (it is also
/// cleared by the next TPM Reset, or when the object's associated hierarchy is disabled). The shape is
/// identical to <see cref="LoadResponse"/>'s; this type exists separately so each command's response keeps its
/// own name in the codec table.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class LoadExternalResponse: ITpmWireType, IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already released the owned Name carrier.</summary>
    private bool disposed;

    /// <summary>
    /// Gets the transient handle of the loaded object.
    /// </summary>
    public TpmiDhObject ObjectHandle { get; }

    /// <summary>
    /// Gets the Name of the loaded object (the Empty Buffer for a NULL <c>nameAlg</c> load).
    /// </summary>
    public Tpm2bName Name { get; }

    /// <summary>Initializes the response around the parsed handle and the owned Name carrier.</summary>
    /// <param name="objectHandle">The loaded object's transient handle.</param>
    /// <param name="name">The loaded object's Name; ownership transfers to the response.</param>
    private LoadExternalResponse(TpmiDhObject objectHandle, Tpm2bName name)
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
    public static LoadExternalResponse Parse(ref TpmReader reader, TpmiDhObject objectHandle, BaseMemoryPool pool)
    {
        Tpm2bName name = Tpm2bName.Parse(ref reader, pool);

        return new LoadExternalResponse(objectHandle, name);
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

    /// <summary>The debugger text this type's <see cref="DebuggerDisplayAttribute"/> names: the handle and the Name's width.</summary>
    private string DebuggerDisplay => $"LoadExternalResponse(Handle=0x{ObjectHandle.Value:X8}, Name={Name.Size} bytes)";
}
