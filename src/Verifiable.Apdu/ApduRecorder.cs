using System;
using System.Collections.Generic;
using System.Threading;

namespace Verifiable.Apdu;

/// <summary>
/// Captures APDU command/response exchanges for replay, debugging, or compliance auditing.
/// Implements <see cref="IObserver{T}"/> to attach to an <see cref="ApduDevice"/> subscription.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Design:</strong> ApduRecorder implements the observer pattern to non-intrusively
/// capture all APDU traffic. Exchanges are stored in memory with high-resolution timestamps.
/// The recorder is thread-safe and can be shared across multiple subscriptions.
/// </para>
/// <para>
/// <strong>Basic usage:</strong>
/// </para>
/// <code>
/// using var device = ApduDevice.Create(nfcTransceive);
/// using var recorder = new ApduRecorder();
///
/// using (device.Subscribe(recorder))
/// {
///     await device.TransceiveAsync(selectCommand, pool, ct);
///     await device.TransceiveAsync(getDataCommand, pool, ct);
/// }
///
/// CardSessionInfo info = CardSessionInfo.Create(atr, null, ApduPlatform.PcSc, TimeProvider.System);
/// ApduRecording recording = recorder.ToRecording(info);
/// </code>
/// <para>
/// <strong>Lifecycle:</strong> After <see cref="OnCompleted"/> or <see cref="OnError"/> is called,
/// the recorder stops accepting new exchanges. Call <see cref="Clear"/> to reset and reuse.
/// </para>
/// <para>
/// <strong>Thread safety:</strong> All public methods are synchronized. Multiple threads can
/// safely call <see cref="Count"/>, <see cref="GetExchanges"/>, and <see cref="ToRecording"/>
/// while recording is in progress.
/// </para>
/// </remarks>
public sealed class ApduRecorder : IObserver<ApduExchange>, IDisposable
{
    private List<ApduExchange> Exchanges { get; } = [];
    private readonly Lock gate = new();
    private bool completed;

    /// <summary>
    /// Gets the number of exchanges recorded so far.
    /// </summary>
    public int Count
    {
        get
        {
            lock(gate)
            {
                return Exchanges.Count;
            }
        }
    }

    /// <summary>
    /// Gets a copy of all recorded exchanges.
    /// </summary>
    /// <returns>An array of recorded exchanges.</returns>
    public ApduExchange[] GetExchanges()
    {
        lock(gate)
        {
            return [.. Exchanges];
        }
    }

    /// <summary>
    /// Creates a recording with the provided session information.
    /// </summary>
    /// <param name="info">Information about the card that produced these exchanges.</param>
    /// <returns>A complete recording ready to be saved or replayed.</returns>
    public ApduRecording ToRecording(CardSessionInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);

        lock(gate)
        {
            return new ApduRecording(info, [.. Exchanges]);
        }
    }

    /// <summary>
    /// Receives the next exchange from the device.
    /// </summary>
    /// <param name="value">The exchange to record.</param>
    public void OnNext(ApduExchange value)
    {
        lock(gate)
        {
            if(!completed)
            {
                Exchanges.Add(value);
            }
        }
    }

    /// <summary>
    /// Called when the device encounters an error.
    /// </summary>
    /// <param name="error">The error that occurred.</param>
    public void OnError(Exception error)
    {
        lock(gate)
        {
            completed = true;
        }
    }

    /// <summary>
    /// Called when the device is disposed.
    /// </summary>
    public void OnCompleted()
    {
        lock(gate)
        {
            completed = true;
        }
    }

    /// <summary>
    /// Clears all recorded exchanges and resets the completed state.
    /// </summary>
    public void Clear()
    {
        lock(gate)
        {
            Exchanges.Clear();
            completed = false;
        }
    }

    /// <summary>
    /// Releases resources used by the recorder.
    /// </summary>
    public void Dispose()
    {
        lock(gate)
        {
            completed = true;
            Exchanges.Clear();
        }
    }
}
