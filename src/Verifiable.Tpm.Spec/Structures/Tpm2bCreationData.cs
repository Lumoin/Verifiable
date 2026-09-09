using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Spec.Structures;

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
/// Specification reference: TPM 2.0 Library Part 2, clause 15.2, Table 262.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class Tpm2bCreationData: IDisposable, ITpmWireType
{
    private IMemoryOwner<byte> RawStorage { get; }
    private int RawLength { get; }
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
        this.RawStorage = rawStorage;
        this.RawLength = rawLength;
    }

    /// <summary>
    /// Gets the raw bytes of the creation data (for hashing).
    /// </summary>
    /// <returns>The raw creation data bytes.</returns>
    public ReadOnlySpan<byte> GetRawBytes()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return RawStorage.Memory.Span.Slice(0, RawLength);
    }

    /// <summary>
    /// Gets the raw creation data bytes as memory, for asynchronous consumers such as the registered digest
    /// seam. The memory aliases this instance's pooled storage — it is valid until <see cref="Dispose"/> and
    /// must not be copied out into untracked arrays.
    /// </summary>
    /// <returns>The raw creation data bytes.</returns>
    public ReadOnlyMemory<byte> GetRawMemory()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return RawStorage.Memory.Slice(0, RawLength);
    }

    /// <summary>
    /// Gets the serialized size of this structure: the <c>UINT16</c> size field plus the marshaled
    /// <c>TPMS_CREATION_DATA</c> octets.
    /// </summary>
    public int SerializedSize
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return sizeof(ushort) + RawLength;
        }
    }

    /// <summary>
    /// Writes this structure to a TPM writer: the <c>UINT16</c> size field followed by the marshaled
    /// <c>TPMS_CREATION_DATA</c> octets exactly as they were adopted or read.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)RawLength);
        writer.WriteBytes(GetRawBytes());
    }

    /// <summary>
    /// Adopts an already-marshaled <c>TPMS_CREATION_DATA</c> buffer as this structure's storage: ownership of
    /// <paramref name="marshaled"/> transfers to the returned instance with no second rental and no copy — the
    /// production counterpart of <see cref="Parse"/> for the TPM side, which marshals the creation data into a
    /// buffer it rented itself and then frames the whole <c>TPM2B_CREATION_DATA</c> from it.
    /// </summary>
    /// <remarks>
    /// The inner structure is parsed out of the adopted octets, so an adopted instance carries the same
    /// <see cref="CreationData"/> view a wire-parsed one does and its <see cref="Dispose"/> releases both. An
    /// argument that does not describe a valid <c>TPM2B_CREATION_DATA</c> releases <paramref name="marshaled"/>
    /// before the exception leaves, so a rejected adoption never orphans the rental.
    /// </remarks>
    /// <param name="marshaled">The pooled buffer whose leading octets hold the marshaled <c>TPMS_CREATION_DATA</c>; ownership transfers to the returned instance or is released here.</param>
    /// <param name="length">The number of valid octets at the head of <paramref name="marshaled"/>.</param>
    /// <param name="pool">The memory pool the parsed inner structure's own buffers are rented from.</param>
    /// <returns>The adopted creation data.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="marshaled"/> or <paramref name="pool"/> is <see langword="null"/>.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><paramref name="length"/> is not positive, exceeds <paramref name="marshaled"/>'s length, or exceeds the 16-bit width of a <c>TPM2B</c> size field.</exception>
    public static Tpm2bCreationData FromMarshaled(IMemoryOwner<byte> marshaled, int length, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(marshaled);

        try
        {
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, marshaled.Memory.Length);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(length, ushort.MaxValue);

            var innerReader = new TpmReader(marshaled.Memory.Span.Slice(0, length));
            TpmsCreationData creationData = TpmsCreationData.Parse(ref innerReader, pool);

            return new Tpm2bCreationData(creationData, marshaled, length);
        }
        catch
        {
            marshaled.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Parses creation data from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The declared size is checked against <see cref="TpmReader.Remaining"/> before <c>rawStorage</c> is
    /// rented, so a truncated outer buffer throws the same <see cref="ArgumentOutOfRangeException"/>
    /// <see cref="TpmReader.ReadBytes(int)"/> would have thrown without ever renting. Once <c>rawStorage</c> is
    /// rented, a refusing <see cref="TpmsCreationData.Parse"/> — any field of the enclosed structure declaring a
    /// size past its own bound, or truncated before it — is caught and <c>rawStorage</c> is released before the
    /// exception leaves, the same try/catch/dispose/rethrow shape as <see cref="FromMarshaled"/>.
    /// </remarks>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed creation data.</returns>
    /// <exception cref="InvalidOperationException">The declared size is zero, or a field of the enclosed <c>TPMS_CREATION_DATA</c> declares a size past its own structure's bound.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The declared size exceeds the octets remaining in <paramref name="reader"/>, or a field of the enclosed <c>TPMS_CREATION_DATA</c> is truncated before its own declared size.</exception>
    public static Tpm2bCreationData Parse(ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            throw new InvalidOperationException("TPM2B_CREATION_DATA size cannot be zero.");
        }

        if(size > reader.Remaining)
        {
            throw new ArgumentOutOfRangeException(nameof(reader), size, $"TPM2B_CREATION_DATA size {size} exceeds the {reader.Remaining} octets remaining in the reader.");
        }

        IMemoryOwner<byte> rawStorage = pool.Rent(size);
        try
        {
            ReadOnlySpan<byte> source = reader.ReadBytes(size);
            source.CopyTo(rawStorage.Memory.Span.Slice(0, size));

            var innerReader = new TpmReader(rawStorage.Memory.Span.Slice(0, size));
            var creationData = TpmsCreationData.Parse(ref innerReader, pool);

            return new Tpm2bCreationData(creationData, rawStorage, size);
        }
        catch
        {
            rawStorage.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            CreationData.Dispose();
            RawStorage.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPM2B_CREATION_DATA({RawLength} bytes)";
}
