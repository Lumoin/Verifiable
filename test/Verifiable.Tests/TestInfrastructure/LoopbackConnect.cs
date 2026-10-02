using Microsoft.Extensions.Logging;
using System.Net;
using System.Net.Sockets;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// The one body that opens the TCP connection of a test client dialing a loopback listener
/// (<see cref="ConnectAsync(EndPoint, CancellationToken)"/>); every handler
/// <see cref="LoopbackTls"/> builds connects through it. A listener port and a local port are both
/// reused within the operating system's TIME_WAIT period: a test host listens on a port of the
/// dynamic range and closes, a later host receives the same port, and a client connect can be given a
/// local port from which an earlier connection to that same listener port rests in TIME_WAIT. On
/// Windows, the platform where this behaviour is observed and pinned, a connect from a local port whose
/// four-tuple rests in TIME_WAIT fails with <see cref="SocketError.AddressAlreadyInUse"/>. A connect on
/// a new socket receives another local port, so this body retries on that code only: it disposes the
/// failed socket and tries again at once, up to a fixed count of attempts, and writes one line per
/// retry through <see cref="LoopbackKestrelDiagnostics"/> so a run's output shows how often it happened.
/// Any other failure leaves at the attempt it occurs on.
/// </summary>
internal static class LoopbackConnect
{
    /// <summary>
    /// The number of connect attempts a test client makes when every attempt before the last meets
    /// <see cref="SocketError.AddressAlreadyInUse"/>.
    /// </summary>
    internal static int DefaultMaxAttempts { get; } = 4;

    /// <summary>The logging category of the line <see cref="ConnectAsync(EndPoint, int, Action{Socket, int}?, LoopbackKestrelDiagnostics, CancellationToken)"/> writes per retry.</summary>
    internal static string DiagnosticsCategory { get; } = "Verifiable.Tests.TestInfrastructure.LoopbackConnect";

    /// <summary>
    /// The event id of the line written per retry; its name is the text a run's output is searched
    /// for to count the retries of that run.
    /// </summary>
    internal static EventId RetriedAfterAddressInUseEventId { get; } = new(1, "ConnectRetriedAfterAddressInUse");


    /// <summary>
    /// Opens a TCP connection to <paramref name="destination"/> with up to
    /// <see cref="DefaultMaxAttempts"/> attempts, preparing nothing on an attempt's socket before its
    /// connect and writing the retry lines through <see cref="LoopbackKestrelDiagnostics.Provider"/>.
    /// </summary>
    /// <param name="destination">The listener's endpoint.</param>
    /// <param name="cancellationToken">Cancels the connect.</param>
    /// <returns>The connected socket, owned by the caller.</returns>
    internal static Task<Socket> ConnectAsync(EndPoint destination, CancellationToken cancellationToken) =>
        ConnectAsync(destination, DefaultMaxAttempts, prepareAttempt: null, LoopbackKestrelDiagnostics.Provider, cancellationToken);


    /// <summary>
    /// Opens a TCP connection to <paramref name="destination"/>. Each attempt creates a socket the way
    /// <see cref="SocketsHttpHandler"/> creates one when no connect callback is set (a stream socket
    /// over TCP with <see cref="Socket.NoDelay"/> on), hands it to <paramref name="prepareAttempt"/>,
    /// and connects it. A <see cref="SocketException"/> whose <see cref="SocketException.SocketErrorCode"/>
    /// is <see cref="SocketError.AddressAlreadyInUse"/> on an attempt before the last writes one line
    /// through <paramref name="diagnostics"/> naming the destination and the attempt number, disposes
    /// that socket, and starts the next attempt at once. Any other failure, and the failure of the
    /// last attempt, leaves unchanged.
    /// </summary>
    /// <param name="destination">The listener's endpoint.</param>
    /// <param name="maxAttempts">The number of attempts, at least one.</param>
    /// <param name="prepareAttempt">
    /// Prepares an attempt's socket before its connect, given the socket and the one-based attempt
    /// number; <see langword="null"/> prepares nothing. A row that proves the retry binds an attempt to
    /// a local port whose four-tuple with the listener rests in TIME_WAIT through it.
    /// </param>
    /// <param name="diagnostics">Receives the line written per retry.</param>
    /// <param name="cancellationToken">Cancels the connect.</param>
    /// <returns>The connected socket, owned by the caller.</returns>
    internal static async Task<Socket> ConnectAsync(
        EndPoint destination,
        int maxAttempts,
        Action<Socket, int>? prepareAttempt,
        LoopbackKestrelDiagnostics diagnostics,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentOutOfRangeException.ThrowIfLessThan(maxAttempts, 1);
        ArgumentNullException.ThrowIfNull(diagnostics);

        ILogger logger = diagnostics.CreateLogger(DiagnosticsCategory);
        for(int attempt = 1; ; attempt++)
        {
            Socket? socket = new(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                prepareAttempt?.Invoke(socket, attempt);
                await socket.ConnectAsync(destination, cancellationToken).ConfigureAwait(false);

                Socket connected = socket;
                socket = null;

                return connected;
            }
            catch(SocketException exception) when(exception.SocketErrorCode == SocketError.AddressAlreadyInUse && attempt < maxAttempts)
            {
                int failedAttempt = attempt;
                logger.Log(LogLevel.Warning, RetriedAfterAddressInUseEventId, destination, exception,
                    (state, _) => $"connect to {state} met AddressAlreadyInUse on attempt {failedAttempt} of {maxAttempts}; a fresh socket tries again");
            }
            finally
            {
                socket?.Dispose();
            }
        }
    }
}
