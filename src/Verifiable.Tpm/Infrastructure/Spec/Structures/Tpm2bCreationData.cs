using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Sized buffer containing creation data (TPM2B_CREATION_DATA).
/// </summary>
/// <remarks>
/// <para>
/// This structure wraps <see cref="TpmsCreationData"/> with a size prefix.
/// It is returned by <c>TPM2_Create()</c> and <c>TPM2_CreatePrimary()</c>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     UINT16 size;                             // Size of creationData.
///     TPMS_CREATION_DATA creationData;         // The creation data.
/// } TPM2B_CREATION_DATA;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 15.2, Table 247.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bCreationData: IDisposable, ITpmWireType
{
    private readonly IMemoryOwner<byte> rawStorage;
    private readonly int rawLength;
    private bool disposed;

    /// <summary>
    /// Gets the creation data.
    /// </summary>
    public TpmsCreationData CreationData { get; }

    /// <summary>
    /// Initializes a new creation data buffer.
    /// </summary>
    private Tpm2bCreationData(TpmsCreationData creationData, IMemoryOwner<byte> rawStorage, int rawLength)
    {
        CreationData = creationData;
        this.rawStorage = rawStorage;
        this.rawLength = rawLength;
    }

    /// <summary>
    /// Gets the raw bytes of the creation data (for hashing).
    /// </summary>
    /// <returns>The raw creation data bytes.</returns>
    public ReadOnlySpan<byte> GetRawBytes()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return rawStorage.Memory.Span.Slice(0, rawLength);
    }

    /// <summary>
    /// Parses creation data from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed creation data.</returns>
    public static Tpm2bCreationData Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            throw new InvalidOperationException("TPM2B_CREATION_DATA size cannot be zero.");
        }

        // Read raw bytes for hashing purposes.
        IMemoryOwner<byte> rawStorage = pool.Rent(size);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(rawStorage.Memory.Span.Slice(0, size));

        // Parse the structure from the raw bytes.
        var innerReader = new TpmReader(rawStorage.Memory.Span.Slice(0, size));
        var creationData = TpmsCreationData.Parse(ref innerReader, pool);

        return new Tpm2bCreationData(creationData, rawStorage, size);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            CreationData.Dispose();
            rawStorage.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPM2B_CREATION_DATA({rawLength} bytes)";
}