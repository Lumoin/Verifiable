using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Tpm;
using Verifiable.Tpm.Infrastructure;

namespace Verifiable.Tests.TestInfrastructure.TpmSimulator;

/// <summary>
/// A test-only client for the Microsoft ms-tpm-20-ref software TPM simulator over its TCP protocol, used by the
/// <c>RequiresTpmSimulator</c> acceptance lane to exercise the production executor / session / parameter-encryption
/// code against a genuine TPM implementation (notably AES-CFB, which this development box's hardware TPM may not
/// implement).
/// </summary>
/// <remarks>
/// <para>
/// The simulator exposes two ports: a command port (default 2321) that handles <c>TPM_REMOTE_HANDSHAKE</c> and
/// <c>TPM_SEND_COMMAND</c>, and a platform port (command port + 1) that handles power/NV/reset signals. Every
/// framing integer is a 32-bit network-order value. <c>TPM_SEND_COMMAND</c> sends
/// <c>[uint32 8][uint8 locality][uint32 len][command]</c> and receives <c>[uint32 len][response][uint32 ack]</c>;
/// each platform signal sends <c>[uint32 signal]</c> and receives <c>[uint32 ack]</c>. See the protocol in
/// ms-tpm-20-ref <c>TPMCmd/Simulator/include/TpmTcpProtocol.h</c> and <c>src/TcpServer.c</c>.
/// </para>
/// <para>
/// Raw <see cref="Socket"/> send/receive is used rather than a <see cref="System.IO.Stream"/> wrapper, per the
/// project's no-Stream transport convention. <see cref="SubmitAsync"/> matches the
/// <c>TpmSubmitHandler</c> shape so a <c>TpmDevice</c> can be created over this connection with
/// <c>TpmDevice.Create</c>, reusing the entire production command path.
/// </para>
/// </remarks>
internal sealed class MsTpmSimulatorConnection: IDisposable
{
    private const uint TpmSignalPowerOn = 1;
    private const uint TpmSignalPowerOff = 2;
    private const uint TpmSignalNvOn = 11;
    private const uint TpmSendCommand = 8;
    private const uint TpmRemoteHandshake = 15;
    private const uint ClientVersion = 1;
    private const byte DefaultLocality = 0;

    //TPM2_Startup(CLEAR): tag TPM_ST_NO_SESSIONS, size 12, TPM_CC_Startup, TPM_SU_CLEAR.
    private static byte[] StartupClearCommand { get; } =
        [0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00];

    private readonly Socket commandSocket;
    private readonly Socket platformSocket;
    private readonly SemaphoreSlim sendGate = new(1, 1);
    private bool disposed;

    private MsTpmSimulatorConnection(Socket commandSocket, Socket platformSocket)
    {
        this.commandSocket = commandSocket;
        this.platformSocket = platformSocket;
    }

    /// <summary>
    /// Gets the default command port of the simulator.
    /// </summary>
    public static int DefaultCommandPort => 2321;

    /// <summary>
    /// Probes whether a simulator is accepting connections on the command and platform ports.
    /// </summary>
    /// <param name="host">The simulator host.</param>
    /// <param name="commandPort">The command port; the platform port is <paramref name="commandPort"/> + 1.</param>
    /// <param name="timeout">The connection timeout.</param>
    /// <returns><see langword="true"/> if both ports accept a connection.</returns>
    public static bool IsAvailable(string host, int commandPort, TimeSpan timeout)
    {
        return CanConnect(host, commandPort, timeout) && CanConnect(host, commandPort + 1, timeout);
    }

    /// <summary>
    /// Connects to the simulator and brings the TPM up: handshake, power-on, NV-on, and TPM2_Startup(CLEAR).
    /// </summary>
    /// <param name="host">The simulator host.</param>
    /// <param name="commandPort">The command port; the platform port is <paramref name="commandPort"/> + 1.</param>
    /// <param name="cancellationToken">A token observed across the connection and bring-up exchanges.</param>
    /// <returns>The established connection.</returns>
    public static async Task<MsTpmSimulatorConnection> ConnectAsync(string host, int commandPort, CancellationToken cancellationToken)
    {
        IPAddress address = ResolveLoopbackOrParse(host);

        var commandSocket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        Socket? platformSocket = null;
        try
        {
            await commandSocket.ConnectAsync(new IPEndPoint(address, commandPort), cancellationToken).ConfigureAwait(false);

            platformSocket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            await platformSocket.ConnectAsync(new IPEndPoint(address, commandPort + 1), cancellationToken).ConfigureAwait(false);

            var connection = new MsTpmSimulatorConnection(commandSocket, platformSocket);
            await connection.BringUpAsync(cancellationToken).ConfigureAwait(false);

            return connection;
        }
        catch
        {
            commandSocket.Dispose();
            platformSocket?.Dispose();

            throw;
        }
    }

    /// <summary>
    /// Submits a TPM command and returns the response, matching the <c>TpmSubmitHandler</c> delegate shape so a
    /// <c>TpmDevice</c> can be created over this connection.
    /// </summary>
    /// <param name="command">The fully framed TPM command bytes.</param>
    /// <param name="pool">The memory pool for the response buffer.</param>
    /// <param name="cancellationToken">A token observed across the send and receive.</param>
    /// <returns>The TPM response, or a transport error if the exchange fails.</returns>
    public async ValueTask<TpmResult<TpmResponse>> SubmitAsync(ReadOnlyMemory<byte> command, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ArgumentNullException.ThrowIfNull(pool);

        await sendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return await SendCommandAsync(command, pool, cancellationToken).ConfigureAwait(false);
        }
        catch(SocketException)
        {
            return TpmResult<TpmResponse>.TransportError(0u);
        }
        catch(IOException)
        {
            return TpmResult<TpmResponse>.TransportError(0u);
        }
        catch(ObjectDisposedException)
        {
            //A Dispose() racing an in-flight exchange surfaces as a disposed socket; report it as a transport error.
            return TpmResult<TpmResponse>.TransportError(0u);
        }
        finally
        {
            _ = sendGate.Release();
        }
    }

    private async Task BringUpAsync(CancellationToken cancellationToken)
    {
        //Handshake on the command socket: send [TPM_REMOTE_HANDSHAKE][clientVersion], read [serverVersion][endpointInfo][ack].
        byte[] handshake = new byte[sizeof(uint) * 2];
        BinaryPrimitives.WriteUInt32BigEndian(handshake.AsSpan(0), TpmRemoteHandshake);
        BinaryPrimitives.WriteUInt32BigEndian(handshake.AsSpan(sizeof(uint)), ClientVersion);
        await SendAllAsync(commandSocket, handshake, cancellationToken).ConfigureAwait(false);

        byte[] handshakeReply = new byte[sizeof(uint) * 3];
        await ReceiveExactlyAsync(commandSocket, handshakeReply, cancellationToken).ConfigureAwait(false);

        //Power-cycle the platform, then enable NV, then start the TPM. The POWER_OFF first is essential: the
        //simulator is a long-lived process whose TPM state persists across client connections, and POWER_ON is a
        //no-op on an already-powered TPM, so without the POWER_OFF a second connection would find the TPM already
        //started and TPM2_Startup(CLEAR) would return TPM_RC_INITIALIZE. POWER_OFF resets it to a clean
        //pre-startup state (a power cycle preserves manufactured NV but clears transient objects), making bring-up
        //idempotent regardless of prior state.
        await SendPlatformSignalAsync(TpmSignalPowerOff, cancellationToken).ConfigureAwait(false);
        await SendPlatformSignalAsync(TpmSignalPowerOn, cancellationToken).ConfigureAwait(false);
        await SendPlatformSignalAsync(TpmSignalNvOn, cancellationToken).ConfigureAwait(false);

        (IMemoryOwner<byte> startupOwner, int startupLength) = await RawSendCommandAsync(StartupClearCommand, MemoryPool<byte>.Shared, cancellationToken).ConfigureAwait(false);
        using(startupOwner)
        {
            if(startupLength < 10)
            {
                throw new InvalidOperationException($"TPM2_Startup(CLEAR) returned a truncated {startupLength}-byte response.");
            }

            uint responseCode = BinaryPrimitives.ReadUInt32BigEndian(startupOwner.Memory.Span.Slice(6, sizeof(uint)));
            if(responseCode != 0u)
            {
                throw new InvalidOperationException($"TPM2_Startup(CLEAR) on the simulator failed with response code 0x{responseCode:X8}.");
            }
        }
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "The TpmResponse takes ownership of the pooled buffer and is owned by the returned TpmResult, which the command executor disposes.")]
    private async ValueTask<TpmResult<TpmResponse>> SendCommandAsync(ReadOnlyMemory<byte> command, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        (IMemoryOwner<byte> responseOwner, int responseLength) = await RawSendCommandAsync(command, pool, cancellationToken).ConfigureAwait(false);

        return TpmResult<TpmResponse>.Success(new TpmResponse(responseOwner, responseLength));
    }

    /// <summary>
    /// Performs one TPM_SEND_COMMAND exchange and returns a pooled buffer together with the exact response length
    /// (the pool buffer may be larger than the response).
    /// </summary>
    private async Task<(IMemoryOwner<byte> Owner, int Length)> RawSendCommandAsync(ReadOnlyMemory<byte> command, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        //Frame: [uint32 TPM_SEND_COMMAND][uint8 locality][uint32 commandLength][command].
        int frameLength = sizeof(uint) + sizeof(byte) + sizeof(uint) + command.Length;
        byte[] frame = ArrayPool<byte>.Shared.Rent(frameLength);
        try
        {
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(0), TpmSendCommand);
            frame[sizeof(uint)] = DefaultLocality;
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(sizeof(uint) + sizeof(byte)), (uint)command.Length);
            command.Span.CopyTo(frame.AsSpan(sizeof(uint) + sizeof(byte) + sizeof(uint)));

            await SendAllAsync(commandSocket, frame.AsMemory(0, frameLength), cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(frame);
        }

        //Reply: [uint32 responseLength][response][uint32 ack].
        byte[] lengthBuffer = new byte[sizeof(uint)];
        await ReceiveExactlyAsync(commandSocket, lengthBuffer, cancellationToken).ConfigureAwait(false);
        uint rawResponseLength = BinaryPrimitives.ReadUInt32BigEndian(lengthBuffer);

        //Bound the wire-supplied length before renting (a malformed/oversized value would otherwise throw an
        //unmapped ArgumentOutOfRangeException or attempt a huge allocation). Surface it as a transport error.
        if(rawResponseLength > TpmConstants.MaxResponseSize)
        {
            throw new IOException($"The simulator reported an out-of-range response length ({rawResponseLength}).");
        }

        int responseLength = (int)rawResponseLength;
        IMemoryOwner<byte> responseOwner = pool.Rent(responseLength);
        try
        {
            await ReceiveExactlyAsync(commandSocket, responseOwner.Memory[..responseLength], cancellationToken).ConfigureAwait(false);

            //Consume and discard the trailing acknowledgement uint32.
            await ReceiveExactlyAsync(commandSocket, lengthBuffer, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            responseOwner.Dispose();

            throw;
        }

        return (responseOwner, responseLength);
    }

    private async Task SendPlatformSignalAsync(uint signal, CancellationToken cancellationToken)
    {
        byte[] signalBuffer = new byte[sizeof(uint)];
        BinaryPrimitives.WriteUInt32BigEndian(signalBuffer, signal);
        await SendAllAsync(platformSocket, signalBuffer, cancellationToken).ConfigureAwait(false);

        byte[] ackBuffer = new byte[sizeof(uint)];
        await ReceiveExactlyAsync(platformSocket, ackBuffer, cancellationToken).ConfigureAwait(false);
        uint ack = BinaryPrimitives.ReadUInt32BigEndian(ackBuffer);
        if(ack != 0u)
        {
            throw new InvalidOperationException($"Simulator platform signal {signal} returned a non-zero acknowledgement ({ack}).");
        }
    }

    private static async Task SendAllAsync(Socket socket, ReadOnlyMemory<byte> data, CancellationToken cancellationToken)
    {
        int sent = 0;
        while(sent < data.Length)
        {
            int n = await socket.SendAsync(data[sent..], SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if(n <= 0)
            {
                throw new IOException("The simulator connection was closed while sending.");
            }

            sent += n;
        }
    }

    private static async Task ReceiveExactlyAsync(Socket socket, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int received = 0;
        while(received < buffer.Length)
        {
            int n = await socket.ReceiveAsync(buffer[received..], SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if(n <= 0)
            {
                throw new IOException("The simulator connection was closed while receiving.");
            }

            received += n;
        }
    }

    private static bool CanConnect(string host, int port, TimeSpan timeout)
    {
        try
        {
            IPAddress address = ResolveLoopbackOrParse(host);
            using var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
            IAsyncResult result = socket.BeginConnect(new IPEndPoint(address, port), null, null);
            if(!result.AsyncWaitHandle.WaitOne(timeout))
            {
                return false;
            }

            socket.EndConnect(result);

            return socket.Connected;
        }
        catch(SocketException)
        {
            return false;
        }
    }

    private static IPAddress ResolveLoopbackOrParse(string host)
    {
        if(string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return IPAddress.Loopback;
        }

        return IPAddress.Parse(host);
    }

    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;

        //Closing the sockets signals end-of-session to the simulator, which keeps serving other clients.
        commandSocket.Dispose();
        platformSocket.Dispose();
        sendGate.Dispose();
    }
}
