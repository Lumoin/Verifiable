using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response from the TPM2_ReadPublic command.
/// </summary>
/// <remarks>
/// <para>
/// Response structure (TPM 2.0 Part 3, Section 12.4):
/// </para>
/// <list type="bullet">
///   <item><description>outPublic (TPM2B_PUBLIC): The public area of the object.</description></item>
///   <item><description>name (TPM2B_NAME): The object name (hash of the public area).</description></item>
///   <item><description>qualifiedName (TPM2B_NAME): The qualified name (hash of parent name + name).</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class ReadPublicResponse: IDisposable, ITpmWireType
{
    private bool Disposed { get; set; }

    /// <summary>
    /// Gets the parsed public area of the object.
    /// </summary>
    public Tpm2bPublic PublicArea { get; }

    /// <summary>
    /// Gets the object name.
    /// </summary>
    public Tpm2bName Name { get; }

    /// <summary>
    /// Gets the qualified name.
    /// </summary>
    public Tpm2bName QualifiedName { get; }

    private ReadPublicResponse(Tpm2bPublic publicArea, Tpm2bName name, Tpm2bName qualifiedName)
    {
        PublicArea = publicArea;
        Name = name;
        QualifiedName = qualifiedName;
    }

    /// <summary>
    /// Parses a ReadPublic response from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for buffer allocation.</param>
    /// <returns>The parsed response.</returns>
    public static ReadPublicResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bPublic publicArea = Tpm2bPublic.Parse(ref reader, pool);
        Tpm2bName name = Tpm2bName.Parse(ref reader, pool);
        Tpm2bName qualifiedName = Tpm2bName.Parse(ref reader, pool);
        return new ReadPublicResponse(publicArea, name, qualifiedName);
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            PublicArea.Dispose();
            Name.Dispose();
            QualifiedName.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"ReadPublicResponse(Name={Name.Size} bytes, QualifiedName={QualifiedName.Size} bytes)";
}
