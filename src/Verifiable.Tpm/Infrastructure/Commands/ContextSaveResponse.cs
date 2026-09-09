using System;
using System.Diagnostics;
using Verifiable.Tpm.Spec;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response for TPM2_ContextSave.
/// </summary>
/// <remarks>
/// <para>
/// <b>Response parameters (Part 3, clause 28.2.2, Table 225):</b>
/// </para>
/// <list type="bullet">
///   <item><description>context (TPMS_CONTEXT) - the saved context: sequence, savedHandle, hierarchy, and the encrypted, integrity-protected context blob.</description></item>
/// </list>
/// <para>
/// TPM2_ContextSave() carries no response handle — the whole parameter area is <see cref="Context"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ContextSaveResponse: ITpmWireType, IDisposable
{
    /// <summary>Whether <see cref="Dispose"/> has already released the owned context.</summary>
    private bool disposed;

    /// <summary>
    /// Gets the saved context.
    /// </summary>
    public TpmsContext Context { get; }

    /// <summary>Initializes the response around the parsed, owned context.</summary>
    /// <param name="context">The parsed context; ownership transfers to the response.</param>
    private ContextSaveResponse(TpmsContext context)
    {
        Context = context;
    }

    /// <summary>
    /// Parses the response from the parameter area.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for allocations.</param>
    /// <returns>The parsed response.</returns>
    public static ContextSaveResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        TpmsContext context = TpmsContext.Parse(ref reader, pool);

        return new ContextSaveResponse(context);
    }

    /// <summary>
    /// Releases resources owned by this response.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            Context.Dispose();
            disposed = true;
        }
    }

    /// <summary>The debugger text this type's <see cref="DebuggerDisplayAttribute"/> names: the context's sequence number.</summary>
    private string DebuggerDisplay => $"ContextSaveResponse(Sequence={Context.Sequence})";
}
