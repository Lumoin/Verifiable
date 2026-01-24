using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Structures;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm;
/*
/// <summary>
/// A virtual TPM that replays canned responses from recordings or typed command/output pairs.
/// Used for development, testing, and debugging without hardware.
/// </summary>
/// <remarks>
/// <para>
/// <b>Design:</b> VirtualTpm provides deterministic replay of TPM exchanges. It can be
/// loaded from raw recordings captured via <see cref="TpmRecorder"/>, or from typed
/// input/output pairs using <see cref="TpmBufferBuilder"/> for serialization.
/// </para>
/// <para>
/// <b>Loading from recordings:</b>
/// </para>
/// <code>
/// var virtualTpm = new VirtualTpm();
/// virtualTpm.Load(recording);
/// </code>
/// <para>
/// <b>Loading typed responses:</b> Create test fixtures from typed objects:
/// </para>
/// <code>
/// var virtualTpm = new VirtualTpm();
/// virtualTpm.Record(
///     new GetRandomInput(16),
///     new GetRandomOutput(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, ... }));
/// </code>
/// <para>
/// See <see href="https://trustedcomputinggroup.org/resource/tpm-library-specification/">
/// TPM 2.0 Library Specification</see> for protocol details.
/// </para>
/// </remarks>
/// <seealso cref="TpmRecording"/>
/// <seealso cref="TpmRecorder"/>
/// <seealso cref="TpmBufferBuilder"/>
public sealed class VirtualTpm
{
    private readonly Dictionary<int, byte[]> _responses = [];
    private readonly Lock _lock = new();

    /// <summary>
    /// Gets the number of canned responses loaded.
    /// </summary>
    public int ResponseCount
    {
        get
        {
            lock(_lock)
            {
                return _responses.Count;
            }
        }
    }

    /// <summary>
    /// Loads responses from a recording.
    /// </summary>
    /// <param name="recording">The recording to load responses from.</param>
    public void Load(TpmRecording recording)
    {
        ArgumentNullException.ThrowIfNull(recording);

        lock(_lock)
        {
            foreach(TpmExchange exchange in recording.Exchanges)
            {
                int hash = ComputeCommandHash(exchange.Command.Span);
                _responses[hash] = exchange.Response.ToArray();
            }
        }
    }

    /// <summary>
    /// Loads responses from a sequence of exchanges.
    /// </summary>
    /// <param name="exchanges">The exchanges to load.</param>
    public void Load(IEnumerable<TpmExchange> exchanges)
    {
        ArgumentNullException.ThrowIfNull(exchanges);

        lock(_lock)
        {
            foreach(TpmExchange exchange in exchanges)
            {
                int hash = ComputeCommandHash(exchange.Command.Span);
                _responses[hash] = exchange.Response.ToArray();
            }
        }
    }

    /// <summary>
    /// Records a single command/response pair from raw bytes.
    /// </summary>
    /// <param name="command">The command bytes.</param>
    /// <param name="response">The response bytes.</param>
    public void Record(ReadOnlySpan<byte> command, ReadOnlySpan<byte> response)
    {
        int hash = ComputeCommandHash(command);
        lock(_lock)
        {
            _responses[hash] = response.ToArray();
        }
    }

    /// <summary>
    /// Records a typed command/response pair by serializing to bytes.
    /// </summary>
    /// <typeparam name="TInput">The command input type.</typeparam>
    /// <typeparam name="TOutput">The command output type.</typeparam>
    /// <param name="input">The command input.</param>
    /// <param name="output">The expected output.</param>
    /// <param name="pool">Optional memory pool for serialization.</param>
    public void Record<TInput, TOutput>(TInput input, TOutput output, MemoryPool<byte>? pool = null)
        where TInput : ITpmCommandInput<TInput>
        where TOutput : ITpmCommandOutput<TOutput>
    {
        pool ??= MemoryPool<byte>.Shared;

        using IMemoryOwner<byte> commandOwner = TpmBufferBuilder.BuildCommand(input, pool);
        using IMemoryOwner<byte> responseOwner = TpmBufferBuilder.BuildResponse(output, pool);

        int hash = ComputeCommandHash(commandOwner.Memory.Span);
        lock(_lock)
        {
            _responses[hash] = responseOwner.Memory.ToArray();
        }
    }

    /// <summary>
    /// Records a typed command with an error response.
    /// </summary>
    /// <typeparam name="TInput">The command input type.</typeparam>
    /// <param name="input">The command input.</param>
    /// <param name="errorCode">The error code to return.</param>
    /// <param name="pool">Optional memory pool for serialization.</param>
    public void RecordError<TInput>(TInput input, TpmRcConstants errorCode, MemoryPool<byte>? pool = null) where TInput: ITpmCommandInput<TInput>
    {
        pool ??= MemoryPool<byte>.Shared;

        using IMemoryOwner<byte> commandOwner = TpmBufferBuilder.BuildCommand(input, pool);
        using IMemoryOwner<byte> responseOwner = TpmBufferBuilder.BuildErrorResponse(errorCode, pool);

        int hash = ComputeCommandHash(commandOwner.Memory.Span);
        lock(_lock)
        {
            _responses[hash] = responseOwner.Memory.ToArray();
        }
    }

    /// <summary>
    /// Submits a command and returns a canned response if available.
    /// </summary>
    /// <param name="command">The command bytes.</param>
    /// <param name="response">Buffer to receive the response.</param>
    /// <returns>Number of bytes written to response buffer.</returns>
    public int Submit(ReadOnlySpan<byte> command, Span<byte> response)
    {
        int hash = ComputeCommandHash(command);

        lock(_lock)
        {
            if(_responses.TryGetValue(hash, out byte[]? cannedResponse))
            {
                cannedResponse.CopyTo(response);
                return cannedResponse.Length;
            }
        }

        //No canned response available. Return error response.
        return WriteErrorResponse(response, TpmRcConstants.TPM_RC_FAILURE);
    }

    /// <summary>
    /// Checks if a canned response exists for the given command.
    /// </summary>
    /// <param name="command">The command bytes to check.</param>
    /// <returns><c>true</c> if a canned response is available; otherwise, <c>false</c>.</returns>
    public bool HasResponse(ReadOnlySpan<byte> command)
    {
        int hash = ComputeCommandHash(command);
        lock(_lock)
        {
            return _responses.ContainsKey(hash);
        }
    }

    /// <summary>
    /// Checks if a canned response exists for the given typed input.
    /// </summary>
    /// <typeparam name="TInput">The command input type.</typeparam>
    /// <param name="input">The command input to check.</param>
    /// <param name="pool">Optional memory pool for serialization.</param>
    /// <returns><c>true</c> if a canned response is available; otherwise, <c>false</c>.</returns>
    public bool HasResponse<TInput>(TInput input, MemoryPool<byte>? pool = null)
        where TInput : ITpmCommandInput<TInput>
    {
        pool ??= MemoryPool<byte>.Shared;

        using IMemoryOwner<byte> commandOwner = TpmBufferBuilder.BuildCommand(input, pool);
        return HasResponse(commandOwner.Memory.Span);
    }

    /// <summary>
    /// Clears all canned responses.
    /// </summary>
    public void Clear()
    {
        lock(_lock)
        {
            _responses.Clear();
        }
    }

    private static int ComputeCommandHash(ReadOnlySpan<byte> command)
    {
        //Simple hash combining all bytes. Good enough for small TPM commands.
        var hash = new HashCode();
        hash.AddBytes(command);
        return hash.ToHashCode();
    }

    private static int WriteErrorResponse(Span<byte> response, TpmRcConstants errorCode)
    {
        TpmHeader header = TpmHeader.CreateResponse(errorCode, TpmHeader.HeaderSize);
        header.WriteTo(response);
        return TpmHeader.HeaderSize;
    }
}*/
