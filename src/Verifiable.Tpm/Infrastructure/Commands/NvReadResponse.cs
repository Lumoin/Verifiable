using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// Response parameters for TPM2_NV_Read: the data read from the NV Index.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Response parameters (Part 3, Section 31.13):</strong>
/// </para>
/// <list type="bullet">
///   <item><description>data (TPM2B_MAX_NV_BUFFER) - the data read.</description></item>
/// </list>
/// <para>
/// A successful read requires the Index to have been written (<c>TPMA_NV_WRITTEN</c> SET); an
/// unwritten Index answers <c>TPM_RC_NV_UNINITIALIZED</c> and never reaches this response.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class NvReadResponse: ITpmWireType, IDisposable
{
    private readonly IMemoryOwner<byte> data;
    private bool disposed;

    /// <summary>Gets the number of octets read.</summary>
    public int Length { get; }

    private NvReadResponse(IMemoryOwner<byte> data, int length)
    {
        this.data = data;
        Length = length;
    }

    /// <summary>Gets the data read from the NV Index.</summary>
    public ReadOnlySpan<byte> Data => data.Memory.Span[..Length];

    /// <summary>
    /// Parses the response parameters from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader positioned at the response parameters.</param>
    /// <param name="pool">The memory pool for the data buffer.</param>
    /// <returns>The parsed response.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The rented buffer is owned by the returned NvReadResponse and disposed by the caller under test.")]
    public static NvReadResponse Parse(ref TpmReader reader, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        ushort size = reader.ReadUInt16();
        IMemoryOwner<byte> owner = pool.Rent(Math.Max((int)size, 1));
        if(size > 0)
        {
            reader.ReadBytes(size).CopyTo(owner.Memory.Span[..size]);
        }

        return new NvReadResponse(owner, size);
    }

    /// <summary>
    /// Releases the data buffer.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            data.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => $"NvReadResponse({Length} bytes)";
}
