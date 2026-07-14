using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm.Infrastructure;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Structures.Spec.Constants;

namespace Verifiable.Tpm;

/// <summary>
/// A virtual TPM that replays recorded responses, for development and testing without hardware.
/// </summary>
/// <remarks>
/// <para>
/// The device is loaded with command/response exchanges captured from a real device via
/// <see cref="TpmRecorder"/> (or registered directly), then exposed through
/// <see cref="SubmitAsync"/>, which has the <see cref="TpmSubmitHandler"/> shape so it plugs
/// straight into <see cref="TpmDevice.Create(TpmSubmitHandler, Action?)"/>:
/// </para>
/// <code>
/// var virtualDevice = new TpmVirtualDevice();
/// virtualDevice.Load(recording);
/// using TpmDevice device = TpmDevice.Create(virtualDevice.SubmitAsync);
/// </code>
/// <para>
/// <strong>Replay scope:</strong> a recorded response is keyed on the exact command bytes, so
/// replay is reliable for deterministic commands — in practice the sessionless ones (GetRandom,
/// GetCapability, PcrRead, …), whose request bytes are identical every time. A command carrying a
/// session authorization area embeds per-call nonces and HMACs, so its bytes differ on every
/// invocation and exact-match replay will miss. Reproducing session behaviour requires a
/// behavioural simulator that maintains TPM state and recomputes nonces, which is a separate
/// milestone; the normalized replay key that would strip the authorization area needs a
/// command-to-input-handle-count map that the simulator introduces.
/// </para>
/// <para>
/// When no recorded response matches, <see cref="SubmitAsync"/> returns a
/// <see cref="TpmRcConstants.TPM_RC_FAILURE"/> response so the caller sees the miss through the
/// normal executor error path rather than as a transport failure.
/// </para>
/// </remarks>
/// <seealso cref="TpmRecording"/>
/// <seealso cref="TpmRecorder"/>
public sealed class TpmVirtualDevice
{
    private Dictionary<int, byte[]> Responses { get; } = [];
    private readonly Lock gate = new();

    /// <summary>
    /// Gets the number of recorded responses currently loaded.
    /// </summary>
    public int ResponseCount
    {
        get
        {
            lock(gate)
            {
                return Responses.Count;
            }
        }
    }

    /// <summary>
    /// Loads responses from a recording captured by <see cref="TpmRecorder"/>.
    /// </summary>
    /// <param name="recording">The recording whose exchanges are loaded.</param>
    public void Load(TpmRecording recording)
    {
        ArgumentNullException.ThrowIfNull(recording);

        Load(recording.Exchanges);
    }

    /// <summary>
    /// Loads responses from a sequence of command/response exchanges.
    /// </summary>
    /// <param name="exchanges">The exchanges to load.</param>
    public void Load(IEnumerable<TpmExchange> exchanges)
    {
        ArgumentNullException.ThrowIfNull(exchanges);

        lock(gate)
        {
            foreach(TpmExchange exchange in exchanges)
            {
                Responses[ComputeReplayKey(exchange.Command.Span)] = exchange.Response.ToArray();
            }
        }
    }

    /// <summary>
    /// Registers a single command/response pair from raw bytes.
    /// </summary>
    /// <param name="command">The command bytes to match.</param>
    /// <param name="response">The response bytes to replay for that command.</param>
    public void Record(ReadOnlySpan<byte> command, ReadOnlySpan<byte> response)
    {
        int key = ComputeReplayKey(command);

        lock(gate)
        {
            Responses[key] = response.ToArray();
        }
    }

    /// <summary>
    /// Gets a value indicating whether a recorded response exists for the given command.
    /// </summary>
    /// <param name="command">The command bytes to check.</param>
    /// <returns><see langword="true"/> if a recorded response is available.</returns>
    public bool HasResponse(ReadOnlySpan<byte> command)
    {
        int key = ComputeReplayKey(command);

        lock(gate)
        {
            return Responses.ContainsKey(key);
        }
    }

    /// <summary>
    /// Removes all recorded responses.
    /// </summary>
    public void Clear()
    {
        lock(gate)
        {
            Responses.Clear();
        }
    }

    /// <summary>
    /// Replays the recorded response for a command. Has the <see cref="TpmSubmitHandler"/> shape so
    /// it can be passed to <see cref="TpmDevice.Create(TpmSubmitHandler, Action?)"/>.
    /// </summary>
    /// <param name="command">The command bytes.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>
    /// The recorded response, or a <see cref="TpmRcConstants.TPM_RC_FAILURE"/> response when no
    /// recorded response matches. The caller owns the returned response and must dispose it.
    /// </returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    public ValueTask<TpmResult<TpmResponse>> SubmitAsync(
        ReadOnlyMemory<byte> command,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        byte[]? canned;
        lock(gate)
        {
            _ = Responses.TryGetValue(ComputeReplayKey(command.Span), out canned);
        }

        if(canned is null)
        {
            return ValueTask.FromResult(BuildFailureResponse(pool));
        }

        IMemoryOwner<byte> owner = pool.Rent(canned.Length);
        canned.CopyTo(owner.Memory.Span);

        return ValueTask.FromResult(TpmResult<TpmResponse>.Success(new TpmResponse(owner, canned.Length)));
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of the rented buffer and is owned by the returned TpmResult, which the caller disposes.")]
    private static TpmResult<TpmResponse> BuildFailureResponse(MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(TpmHeader.HeaderSize);
        var header = new TpmHeader(
            (ushort)TpmStConstants.TPM_ST_NO_SESSIONS,
            TpmHeader.HeaderSize,
            (uint)TpmRcConstants.TPM_RC_FAILURE);

        var writer = new TpmWriter(owner.Memory.Span);
        header.WriteTo(ref writer);

        return TpmResult<TpmResponse>.Success(new TpmResponse(owner, TpmHeader.HeaderSize));
    }

    private static int ComputeReplayKey(ReadOnlySpan<byte> command)
    {
        var hash = new HashCode();
        hash.AddBytes(command);

        return hash.ToHashCode();
    }
}
