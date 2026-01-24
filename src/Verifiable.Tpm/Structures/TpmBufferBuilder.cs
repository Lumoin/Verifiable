using System;
using System.Buffers;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm.Infrastructure;

/// <summary>
/// Builds TPM command and response buffers from typed objects.
/// </summary>
public static class TpmBufferBuilder
{
    /// <summary>
    /// Builds a complete command buffer from typed input.
    /// </summary>
    /// <typeparam name="T">The input type.</typeparam>
    /// <param name="input">The command input.</param>
    /// <param name="pool">The memory pool to use for allocation.</param>
    /// <returns>Memory owner containing the command buffer.</returns>
    public static IMemoryOwner<byte> BuildCommand<T>(T input, MemoryPool<byte> pool)
        where T : ITpmCommandInput<T>
    {
        ArgumentNullException.ThrowIfNull(pool);

        int totalSize = TpmHeader.HeaderSize + input.SerializedSize;
        IMemoryOwner<byte> owner = pool.Rent(totalSize);
        Span<byte> buffer = owner.Memory.Span[..totalSize];

        TpmHeader header = TpmHeader.CreateCommand(T.CommandCode, (uint)totalSize);
        header.WriteTo(buffer);
        input.WriteTo(buffer[TpmHeader.HeaderSize..]);

        return new ExactSizeMemoryOwner(owner, totalSize);
    }

    /// <summary>
    /// Builds a complete response buffer from typed output.
    /// </summary>
    /// <typeparam name="T">The output type.</typeparam>
    /// <param name="output">The command output.</param>
    /// <param name="pool">The memory pool to use for allocation.</param>
    /// <returns>Memory owner containing the response buffer.</returns>
    public static IMemoryOwner<byte> BuildResponse<T>(T output, MemoryPool<byte> pool)
        where T : ITpmCommandOutput<T>
    {
        ArgumentNullException.ThrowIfNull(pool);

        int totalSize = TpmHeader.HeaderSize + output.SerializedSize;
        IMemoryOwner<byte> owner = pool.Rent(totalSize);
        Span<byte> buffer = owner.Memory.Span[..totalSize];

        TpmHeader header = TpmHeader.CreateResponse(TpmRc.Success, (uint)totalSize);
        header.WriteTo(buffer);
        output.WriteTo(buffer[TpmHeader.HeaderSize..]);

        return new ExactSizeMemoryOwner(owner, totalSize);
    }

    /// <summary>
    /// Builds an error response buffer.
    /// </summary>
    /// <param name="responseCode">The error response code.</param>
    /// <param name="pool">The memory pool to use for allocation.</param>
    /// <returns>Memory owner containing the response buffer.</returns>
    public static IMemoryOwner<byte> BuildErrorResponse(TpmRc responseCode, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> owner = pool.Rent(TpmHeader.HeaderSize);
        Span<byte> buffer = owner.Memory.Span[..TpmHeader.HeaderSize];

        TpmHeader header = TpmHeader.CreateResponse(responseCode, TpmHeader.HeaderSize);
        header.WriteTo(buffer);

        return new ExactSizeMemoryOwner(owner, TpmHeader.HeaderSize);
    }

    /// <summary>
    /// Wrapper that exposes only the exact size needed from a rented buffer.
    /// </summary>
    private sealed class ExactSizeMemoryOwner : IMemoryOwner<byte>
    {
        private readonly IMemoryOwner<byte> _inner;
        private readonly int _size;

        public ExactSizeMemoryOwner(IMemoryOwner<byte> inner, int size)
        {
            _inner = inner;
            _size = size;
        }

        public Memory<byte> Memory => _inner.Memory[.._size];

        public void Dispose() => _inner.Dispose();
    }
}
