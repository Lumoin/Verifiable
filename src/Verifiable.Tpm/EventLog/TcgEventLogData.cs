using System;
using System.Buffers;

namespace Verifiable.Tpm.Extensions.EventLog;

/// <summary>
/// Wraps raw TCG event log data with its owning memory.
/// </summary>
/// <remarks>
/// <para>
/// This type owns the underlying memory buffer and must be disposed when no longer needed.
/// The <see cref="Span"/> property provides access to the actual log data.
/// </para>
/// </remarks>
public sealed class TcgEventLogData: IDisposable
{
    private readonly IMemoryOwner<byte> memoryOwner;
    private bool disposed;

    /// <summary>
    /// Gets the length of the event log data in bytes.
    /// </summary>
    public int Length { get; }

    /// <summary>
    /// Gets a span over the event log data.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The object has been disposed.</exception>
    public ReadOnlySpan<byte> Span
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return memoryOwner.Memory.Span.Slice(0, Length);
        }
    }

    /// <summary>
    /// Gets a memory region over the event log data.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The object has been disposed.</exception>
    public ReadOnlyMemory<byte> Memory
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);
            return memoryOwner.Memory.Slice(0, Length);
        }
    }

    /// <summary>
    /// Creates a new event log data wrapper.
    /// </summary>
    /// <param name="memoryOwner">The memory owner containing the data.</param>
    /// <param name="length">The actual length of the data.</param>
    public TcgEventLogData(IMemoryOwner<byte> memoryOwner, int length)
    {
        this.memoryOwner = memoryOwner;
        Length = length;
    }

    /// <summary>
    /// Copies the event log data to a new byte array.
    /// </summary>
    /// <exception cref="ObjectDisposedException">The object has been disposed.</exception>
    public byte[] ToArray()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return Span.ToArray();
    }

    /// <summary>
    /// Releases the underlying memory.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            disposed = true;
            memoryOwner.Dispose();
        }
    }
}