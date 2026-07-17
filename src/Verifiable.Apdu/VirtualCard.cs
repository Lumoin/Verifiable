using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu;

/// <summary>
/// A virtual card that replays canned responses from recordings or manually registered pairs.
/// Used for development, testing, and debugging without card hardware.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Design:</strong> VirtualCard provides deterministic replay of APDU exchanges.
/// It can be loaded from recordings captured via <see cref="ApduRecorder"/>, or from
/// manually registered command/response pairs.
/// </para>
/// <para>
/// <strong>Loading from recordings:</strong>
/// </para>
/// <code>
/// var virtualCard = new VirtualCard();
/// virtualCard.Load(recording);
/// using var device = ApduDevice.Create(virtualCard.TransceiveAsync);
/// </code>
/// <para>
/// <strong>Manual registration:</strong>
/// </para>
/// <code>
/// var virtualCard = new VirtualCard();
/// virtualCard.Register(
///     new byte[] { 0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08 },
///     new byte[] { 0x61, 0x11, 0x4F, 0x06, ..., 0x90, 0x00 });
/// </code>
/// <para>
/// <strong>Command matching:</strong> Commands are matched by content hash. The entire
/// command APDU (CLA, INS, P1, P2, Lc, data, Le) is hashed for lookup. If no match is
/// found, the virtual card returns <c>6D00</c> (instruction not supported).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class VirtualCard
{
    private Dictionary<int, byte[]> Responses { get; } = [];
    private readonly Lock gate = new();

    /// <summary>
    /// Gets the number of canned responses registered.
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
    /// Loads responses from a recording.
    /// </summary>
    /// <param name="recording">The recording to load responses from.</param>
    public void Load(ApduRecording recording)
    {
        ArgumentNullException.ThrowIfNull(recording);

        lock(gate)
        {
            foreach(ApduExchange exchange in recording.Exchanges)
            {
                if(exchange.Response.Length >= ApduConstants.StatusWordSize)
                {
                    int hash = ComputeCommandHash(exchange.Command.Span);
                    Responses[hash] = exchange.Response.ToArray();
                }
            }
        }
    }

    /// <summary>
    /// Loads responses from a sequence of exchanges.
    /// </summary>
    /// <param name="exchanges">The exchanges to load.</param>
    public void Load(IEnumerable<ApduExchange> exchanges)
    {
        ArgumentNullException.ThrowIfNull(exchanges);

        lock(gate)
        {
            foreach(ApduExchange exchange in exchanges)
            {
                if(exchange.Response.Length >= ApduConstants.StatusWordSize)
                {
                    int hash = ComputeCommandHash(exchange.Command.Span);
                    Responses[hash] = exchange.Response.ToArray();
                }
            }
        }
    }

    /// <summary>
    /// Registers a single command/response pair.
    /// </summary>
    /// <param name="command">The command APDU bytes.</param>
    /// <param name="response">The response APDU bytes (data + SW).</param>
    public void Register(ReadOnlySpan<byte> command, ReadOnlySpan<byte> response)
    {
        int hash = ComputeCommandHash(command);
        lock(gate)
        {
            Responses[hash] = response.ToArray();
        }
    }

    /// <summary>
    /// Checks whether a canned response exists for the given command.
    /// </summary>
    /// <param name="command">The command APDU bytes.</param>
    /// <returns><see langword="true"/> if a response is registered.</returns>
    public bool HasResponse(ReadOnlySpan<byte> command)
    {
        int hash = ComputeCommandHash(command);
        lock(gate)
        {
            return Responses.ContainsKey(hash);
        }
    }

    /// <summary>
    /// Clears all registered responses.
    /// </summary>
    public void Clear()
    {
        lock(gate)
        {
            Responses.Clear();
        }
    }

    /// <summary>
    /// The transceive delegate that can be passed to <see cref="ApduDevice.Create"/>.
    /// </summary>
    /// <param name="commandApdu">The command APDU bytes.</param>
    /// <param name="pool">The memory pool for response allocation.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A result containing the canned response or a default error.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "ApduResponse takes ownership of responseOwner. The caller is responsible for disposing the returned ApduResult.")]
    public ValueTask<ApduResult<ApduResponse>> TransceiveAsync(
        ReadOnlyMemory<byte> commandApdu,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(pool);

        cancellationToken.ThrowIfCancellationRequested();

        int hash = ComputeCommandHash(commandApdu.Span);
        byte[] responseBytes;

        lock(gate)
        {
            if(!Responses.TryGetValue(hash, out byte[]? canned))
            {
                //No canned response available. Return INS not supported.
                canned = [0x6D, 0x00];
            }

            responseBytes = canned;
        }

        IMemoryOwner<byte> responseOwner = pool.Rent(responseBytes.Length);
        responseBytes.CopyTo(responseOwner.Memory.Span);

        var response = new ApduResponse(responseOwner, responseBytes.Length);
        return ValueTask.FromResult(ApduResult<ApduResponse>.Success(response, response.StatusWord));
    }

    private static int ComputeCommandHash(ReadOnlySpan<byte> command)
    {
        var hash = new HashCode();
        hash.AddBytes(command);
        return hash.ToHashCode();
    }

    private string DebuggerDisplay => $"VirtualCard({ResponseCount} responses)";
}
