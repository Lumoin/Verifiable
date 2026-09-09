using System;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_Import command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Library Part 3, clause 13.3):
/// </para>
/// <list type="bullet">
///   <item><description>outPrivate (TPM2B_PRIVATE): the imported object's sensitive area re-wrapped under the new parent, ready for <c>TPM2_Load</c>.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ImportResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the imported object's sensitive area re-wrapped under the new parent.
    /// </summary>
    public Tpm2bPrivate OutPrivate { get; }

    private ImportResponse(Tpm2bPrivate outPrivate)
    {
        OutPrivate = outPrivate;
    }

    /// <summary>
    /// Parses a TPM2_Import response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static ImportResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new ImportResponse(Tpm2bPrivate.Parse(ref reader, pool));
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            OutPrivate.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay => $"ImportResponse(OutPrivate={OutPrivate.Length} bytes)";
}
