using System;
using System.Buffers;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Apdu;

/// <summary>
/// Cross-platform APDU device access with observable command/response traffic.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Design:</strong> ApduDevice abstracts platform-specific card access (Android NFC,
/// iOS NFC, PC/SC) behind a unified async interface. It implements <see cref="IObservable{T}"/>
/// to enable non-intrusive traffic capture for recording, debugging, and compliance.
/// </para>
/// <para>
/// <strong>Architecture layers:</strong>
/// </para>
/// <list type="number">
///   <item><description><strong>Executor</strong> — <c>ApduExecutor</c> handles protocol mechanics (response chaining, Le correction).</description></item>
///   <item><description><strong>Transport</strong> — this class handles raw command/response byte submission.</description></item>
///   <item><description><strong>Platform</strong> — Android IsoDep, iOS Core NFC, PC/SC SCardTransmit.</description></item>
/// </list>
/// <para>
/// <strong>Basic usage:</strong>
/// </para>
/// <code>
/// using var device = ApduDevice.Create(nfcTransceive);
/// MemoryPool&lt;byte&gt; pool = BaseMemoryPool.Shared;
///
/// ApduResult&lt;ApduResponse&gt; result = await device.TransceiveAsync(commandBytes, pool, ct);
/// </code>
/// <para>
/// <strong>Recording traffic:</strong>
/// </para>
/// <code>
/// using var recorder = new ApduRecorder();
/// using (device.Subscribe(recorder))
/// {
///     await device.TransceiveAsync(commandBytes, pool, ct);
/// }
/// ApduRecording recording = recorder.ToRecording(sessionInfo);
/// </code>
/// <para>
/// <strong>Transport health:</strong> Once a transport error occurs (NFC tag lost, reader
/// disconnected), the device transitions to a permanently failed state. All subsequent
/// <see cref="TransceiveAsync"/> calls return the same transport error. Check
/// <see cref="IsHealthy"/> and inspect <see cref="Failure"/> for diagnostics.
/// </para>
/// </remarks>
public sealed class ApduDevice : IDisposable, IObservable<ApduExchange>
{
    private readonly Lock observerLock = new();
    private TransceiveDelegate Handler { get; }
    private Action? DisposeAction { get; }
    private IObserver<ApduExchange>[] observers = [];
    private bool disposed;
    private ApduTransportFailure? failure;

    /// <summary>
    /// Gets the platform for this device instance.
    /// </summary>
    public ApduPlatform Platform { get; }

    /// <summary>
    /// Gets a value indicating whether the transport is still functional.
    /// </summary>
    /// <remarks>
    /// Once a transport failure occurs, the device is permanently unhealthy.
    /// The caller should dispose this device and create a new one.
    /// </remarks>
    public bool IsHealthy => failure is null;

    /// <summary>
    /// Gets the transport failure that caused this device to become unhealthy,
    /// or <see langword="null"/> if the device is still healthy.
    /// </summary>
    public ApduTransportFailure? Failure => failure;

    private ApduDevice(TransceiveDelegate handler, ApduPlatform platform, Action? disposeAction)
    {
        ArgumentNullException.ThrowIfNull(handler);
        this.Handler = handler;
        Platform = platform;
        this.DisposeAction = disposeAction;
    }

    /// <summary>
    /// Creates a device from a custom transceive delegate.
    /// </summary>
    /// <param name="handler">The transceive delegate.</param>
    /// <param name="platform">The platform identifier. Defaults to <see cref="ApduPlatform.Virtual"/>.</param>
    /// <param name="disposeAction">Optional action to invoke on disposal.</param>
    /// <returns>A new device wrapping the delegate.</returns>
    public static ApduDevice Create(
        TransceiveDelegate handler,
        ApduPlatform platform = ApduPlatform.Virtual,
        Action? disposeAction = null)
    {
        return new ApduDevice(handler, platform, disposeAction);
    }

    /// <summary>
    /// Sends a command APDU and receives a response APDU.
    /// </summary>
    /// <param name="commandApdu">The complete command APDU bytes.</param>
    /// <param name="pool">The memory pool for allocating the response buffer.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>A result containing the response or an error.</returns>
    public async ValueTask<ApduResult<ApduResponse>> TransceiveAsync(
        ReadOnlyMemory<byte> commandApdu,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(failure is not null)
        {
            return ApduResult<ApduResponse>.TransportError(failure.ErrorCode);
        }

        long startTicks = Stopwatch.GetTimestamp();
        ApduResult<ApduResponse> result = await Handler(commandApdu, pool, cancellationToken).ConfigureAwait(false);
        long endTicks = Stopwatch.GetTimestamp();

        if(result.IsTransportError)
        {
            failure = new ApduTransportFailure(result.TransportErrorCode, Platform, "Transport error during transceive.");
            NotifyObservers(startTicks, endTicks, commandApdu.Span, ReadOnlySpan<byte>.Empty);
            return result;
        }

        if(result.IsSuccess)
        {
            NotifyObservers(startTicks, endTicks, commandApdu.Span, result.Value.AsReadOnlySpan());
        }
        else
        {
            NotifyObservers(startTicks, endTicks, commandApdu.Span, ReadOnlySpan<byte>.Empty);
        }

        return result;
    }

    /// <summary>
    /// Subscribes an observer to receive APDU exchange notifications.
    /// </summary>
    /// <param name="observer">The observer to subscribe.</param>
    /// <returns>A disposable that removes the subscription when disposed.</returns>
    public IDisposable Subscribe(IObserver<ApduExchange> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

        lock(observerLock)
        {
            IObserver<ApduExchange>[] current = observers;
            IObserver<ApduExchange>[] updated = new IObserver<ApduExchange>[current.Length + 1];
            current.CopyTo(updated, 0);
            updated[current.Length] = observer;
            observers = updated;
        }

        return new Unsubscriber(this, observer);
    }

    /// <summary>
    /// Releases all resources used by this device.
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;

        IObserver<ApduExchange>[] currentObservers;
        lock(observerLock)
        {
            currentObservers = observers;
            observers = [];
        }

        foreach(IObserver<ApduExchange> observer in currentObservers)
        {
            observer.OnCompleted();
        }

        DisposeAction?.Invoke();
    }

    private void NotifyObservers(long startTicks, long endTicks, ReadOnlySpan<byte> command, ReadOnlySpan<byte> response)
    {
        IObserver<ApduExchange>[] currentObservers;
        lock(observerLock)
        {
            if(observers.Length == 0)
            {
                return;
            }

            currentObservers = observers;
        }

        //Copy bytes only when there are observers.
        var exchange = new ApduExchange(
            startTicks,
            endTicks,
            command.ToArray(),
            response.ToArray());

        foreach(IObserver<ApduExchange> observer in currentObservers)
        {
            observer.OnNext(exchange);
        }
    }

    private void Unsubscribe(IObserver<ApduExchange> observer)
    {
        lock(observerLock)
        {
            int index = Array.IndexOf(observers, observer);
            if(index < 0)
            {
                return;
            }

            var newObservers = new IObserver<ApduExchange>[observers.Length - 1];
            if(index > 0)
            {
                Array.Copy(observers, 0, newObservers, 0, index);
            }

            if(index < newObservers.Length)
            {
                Array.Copy(observers, index + 1, newObservers, index, newObservers.Length - index);
            }

            observers = newObservers;
        }
    }

    private sealed class Unsubscriber(ApduDevice device, IObserver<ApduExchange> observer) : IDisposable
    {
        public void Dispose() => device.Unsubscribe(observer);
    }
}
