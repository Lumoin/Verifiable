using System;
using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// NV-certify-specific attestation information (TPMS_NV_CERTIFY_INFO), the <c>nv</c> member of TPMU_ATTEST.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <c>TPM2_NV_Certify()</c> when the caller requests actual index contents (a non-zero <c>size</c>
/// or <c>offset</c>): attests that the octets at <see cref="Offset"/> in the NV Index with the given
/// <see cref="IndexName"/> equal <see cref="NvContents"/>. A verifier confirms the binding by recomputing the
/// Index's Name (<c>nameAlg ‖ H(TPMS_NV_PUBLIC)</c>) and comparing it to <see cref="IndexName"/>.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPM2B_NAME            indexName;         // Name of the NV Index.
///     UINT16                offset;            // Offset parameter of TPM2_NV_Certify().
///     TPM2B_MAX_NV_BUFFER   nvContents;        // Contents of the NV Index.
/// } TPMS_NV_CERTIFY_INFO;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 10.12.8, Table 128.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmsNvCertifyInfo: ITpmWireType, IDisposable
{
    private readonly IMemoryOwner<byte>? nvContentsStorage;
    private readonly int nvContentsLength;
    private bool disposed;

    /// <summary>
    /// Gets the Name of the NV Index.
    /// </summary>
    public Tpm2bName IndexName { get; }

    /// <summary>
    /// Gets the octet offset of <see cref="NvContents"/> within the NV Index's data area.
    /// </summary>
    public ushort Offset { get; }

    /// <summary>
    /// Gets the attested NV Index contents at <see cref="Offset"/>.
    /// </summary>
    public ReadOnlySpan<byte> NvContents
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return nvContentsStorage is null ? [] : nvContentsStorage.Memory.Span[..nvContentsLength];
        }
    }

    /// <summary>
    /// Initializes a new NV-certify-info structure.
    /// </summary>
    private TpmsNvCertifyInfo(Tpm2bName indexName, ushort offset, IMemoryOwner<byte>? nvContentsStorage, int nvContentsLength)
    {
        IndexName = indexName;
        Offset = offset;
        this.nvContentsStorage = nvContentsStorage;
        this.nvContentsLength = nvContentsLength;
    }

    /// <summary>
    /// Creates an NV-certify-info structure from an Index Name, offset, and contents (for tests and round-trips).
    /// </summary>
    /// <param name="indexName">The NV Index's Name. Ownership is transferred.</param>
    /// <param name="offset">The octet offset of <paramref name="nvContents"/> within the Index's data area.</param>
    /// <param name="nvContents">The attested NV Index contents.</param>
    /// <param name="pool">The memory pool for the contents buffer.</param>
    /// <returns>The created NV-certify info.</returns>
    public static TpmsNvCertifyInfo Create(Tpm2bName indexName, ushort offset, ReadOnlySpan<byte> nvContents, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(indexName);
        ArgumentNullException.ThrowIfNull(pool);

        if(nvContents.IsEmpty)
        {
            return new TpmsNvCertifyInfo(indexName, offset, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(nvContents.Length);
        nvContents.CopyTo(storage.Memory.Span);

        return new TpmsNvCertifyInfo(indexName, offset, storage, nvContents.Length);
    }

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int SerializedSize
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return IndexName.SerializedSize + sizeof(ushort) + sizeof(ushort) + nvContentsLength;
        }
    }

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        IndexName.WriteTo(ref writer);
        writer.WriteUInt16(Offset);
        writer.WriteTpm2b(NvContents);
    }

    /// <summary>
    /// Parses an NV-certify-info structure from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed NV-certify info.</returns>
    public static TpmsNvCertifyInfo Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        Tpm2bName indexName = Tpm2bName.Parse(ref reader, pool);
        ushort offset = reader.ReadUInt16();
        ushort size = reader.ReadUInt16();

        if(size == 0)
        {
            return new TpmsNvCertifyInfo(indexName, offset, null, 0);
        }

        IMemoryOwner<byte> storage = pool.Rent(size);
        ReadOnlySpan<byte> source = reader.ReadBytes(size);
        source.CopyTo(storage.Memory.Span[..size]);

        return new TpmsNvCertifyInfo(indexName, offset, storage, size);
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            IndexName.Dispose();
            nvContentsStorage?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"TPMS_NV_CERTIFY_INFO(indexName={IndexName.Size} bytes, offset={Offset}, nvContents={nvContentsLength} bytes)";
}
