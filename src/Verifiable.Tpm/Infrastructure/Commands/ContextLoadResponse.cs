using System.Diagnostics;
using Verifiable.Tpm.Spec.Handles;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_ContextLoad.
/// </summary>
/// <remarks>
/// <para>
/// <b>Response handle (Part 3, clause 28.3.2, Table 227):</b>
/// </para>
/// <list type="bullet">
///   <item><description>loadedHandle (TPMI_DH_CONTEXT) - the handle assigned to the resource after it has been successfully loaded.</description></item>
/// </list>
/// <para>
/// TPM2_ContextLoad() carries no response parameters — <see cref="LoadedHandle"/>, riding the response handle
/// area alone, is the whole response. Nothing here is owned or disposed: unlike <see cref="LoadExternalResponse"/>'s
/// owned Name, this response is a bare value type.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ContextLoadResponse: ITpmWireType
{
    /// <summary>
    /// Gets the handle assigned to the reloaded resource — the saved handle itself for a session, or the
    /// freshly drawn transient handle for an object or sequence.
    /// </summary>
    public TpmiDhContext LoadedHandle { get; }

    /// <summary>Initializes the response around the parsed handle.</summary>
    /// <param name="loadedHandle">The handle assigned to the reloaded resource.</param>
    private ContextLoadResponse(TpmiDhContext loadedHandle)
    {
        LoadedHandle = loadedHandle;
    }

    /// <summary>
    /// Builds the response from the response handle area alone — there is no parameter area to read.
    /// </summary>
    /// <param name="handle">The loaded handle from the response handle area.</param>
    /// <returns>The parsed response.</returns>
    public static ContextLoadResponse Parse(uint handle) => new(TpmiDhContext.FromValue(handle));

    /// <summary>The debugger text this type's <see cref="DebuggerDisplayAttribute"/> names: the loaded handle.</summary>
    private string DebuggerDisplay => $"ContextLoadResponse(LoadedHandle=0x{LoadedHandle.Value:X8})";
}
