using System;
using System.Diagnostics;
using Verifiable.Cryptography;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_ObjectChangeAuth command (TPM 2.0 Library Part 3, clause 12.8, Table 33).
/// </summary>
/// <remarks>
/// <para>
/// Response structure:
/// </para>
/// <list type="bullet">
///   <item><description>outPrivate (TPM2B_PRIVATE): the object's sensitive area re-wrapped under its parent with the new authorization value, ready for <c>TPM2_Load</c>.</description></item>
/// </list>
/// <para>
/// <c>outPrivate</c> is the response's first parameter and a sized buffer, so an encrypt session may protect it
/// (Part 1, clause 18.1).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ObjectChangeAuthResponse: IDisposable, ITpmWireType
{
    /// <summary>Whether <see cref="Dispose"/> has already released the owned private area.</summary>
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the object's sensitive area re-wrapped under its parent with the new authorization value.
    /// </summary>
    public Tpm2bPrivate OutPrivate { get; }

    /// <summary>Initializes the response around the parsed private area.</summary>
    /// <param name="outPrivate">The re-wrapped private area; ownership transfers to the response.</param>
    private ObjectChangeAuthResponse(Tpm2bPrivate outPrivate)
    {
        OutPrivate = outPrivate;
    }

    /// <summary>
    /// Parses a TPM2_ObjectChangeAuth response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static ObjectChangeAuthResponse Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return new ObjectChangeAuthResponse(Tpm2bPrivate.Parse(ref reader, pool));
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

    /// <summary>The debugger text this type's <see cref="DebuggerDisplayAttribute"/> names: the private area's width.</summary>
    private string DebuggerDisplay => $"ObjectChangeAuthResponse(OutPrivate={OutPrivate.Length} bytes)";
}
