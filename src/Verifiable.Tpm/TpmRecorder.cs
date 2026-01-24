using System;
using System.Collections.Generic;
using System.Threading;

namespace Verifiable.Tpm;

/// <summary>
/// Captures TPM command/response exchanges for replay, debugging, or compliance auditing.
/// Implements <see cref="IObserver{T}"/> to attach to a <see cref="TpmDevice"/> subscription.
/// </summary>
/// <remarks>
/// <para>
/// <b>Design:</b> TpmRecorder implements the observer pattern to non-intrusively capture
/// all TPM traffic. Exchanges are stored in memory with microsecond timestamps. The recorder
/// is thread-safe and can be shared across multiple subscriptions, though typically one
/// recorder captures one session.
/// </para>
/// <para>
/// <b>Basic usage:</b> Subscribe to a TpmDevice, perform operations, then extract the recording:
/// </para>
/// <code>
/// using var tpm = TpmDevice.Open();
/// using var recorder = new TpmRecorder();
///
/// // Subscribe returns IDisposable; disposing ends the subscription.
/// using (tpm.Subscribe(recorder))
/// {
///     tpm.GetRandom(16);
///     tpm.Hash(Tpm2AlgId.TPM_ALG_SHA256, data);
/// }
///
/// // Create a recording with TPM metadata for later replay.
/// TpmSessionInfo info = tpm.GetSessionInfo(TimeProvider.System);
/// TpmRecording recording = recorder.ToRecording(info);
/// </code>
/// <para>
/// <b>Lifecycle:</b> After <see cref="OnCompleted"/> or <see cref="OnError"/> is called,
/// the recorder stops accepting new exchanges. Call <see cref="Clear"/> to reset and reuse.
/// </para>
/// <para>
/// <b>Thread safety:</b> All public methods are synchronized. Multiple threads can safely
/// call <see cref="Count"/>, <see cref="GetExchanges"/>, and <see cref="ToRecording"/>
/// while recording is in progress.
/// </para>
/// </remarks>
/// <seealso cref="TpmRecording"/>
/// <seealso cref="VirtualTpm"/>
/// <seealso cref="TpmDevice"/>
public sealed class TpmRecorder: IObserver<TpmExchange>, IDisposable
{
    private readonly List<TpmExchange> _exchanges = [];
    private readonly Lock _lock = new();
    private bool _completed;

    /// <summary>
    /// Gets the number of exchanges recorded so far.
    /// </summary>
    public int Count
    {
        get
        {
            lock(_lock)
            {
                return _exchanges.Count;
            }
        }
    }

    /// <summary>
    /// Gets a copy of all recorded exchanges.
    /// </summary>
    /// <returns>An array of recorded exchanges.</returns>
    public TpmExchange[] GetExchanges()
    {
        lock(_lock)
        {
            return [.. _exchanges];
        }
    }

    /// <summary>
    /// Creates a recording with the provided session information.
    /// </summary>
    /// <param name="info">Information about the TPM that produced these exchanges.</param>
    /// <returns>A complete recording ready to be saved or shared.</returns>
    public TpmRecording ToRecording(TpmSessionInfo info)
    {
        ArgumentNullException.ThrowIfNull(info);

        lock(_lock)
        {
            return new TpmRecording(info, [.. _exchanges]);
        }
    }

    /// <summary>
    /// Receives the next exchange from the TPM device.
    /// </summary>
    /// <param name="value">The exchange to record.</param>
    public void OnNext(TpmExchange value)
    {
        lock(_lock)
        {
            if(!_completed)
            {
                _exchanges.Add(value);
            }
        }
    }

    /// <summary>
    /// Called when the TPM device encounters an error.
    /// </summary>
    /// <param name="error">The error that occurred.</param>
    public void OnError(Exception error)
    {
        //Errors are not recorded. The recording stops.
        lock(_lock)
        {
            _completed = true;
        }
    }

    /// <summary>
    /// Called when the TPM device is disposed.
    /// </summary>
    public void OnCompleted()
    {
        lock(_lock)
        {
            _completed = true;
        }
    }

    /// <summary>
    /// Clears all recorded exchanges.
    /// </summary>
    public void Clear()
    {
        lock(_lock)
        {
            _exchanges.Clear();
            _completed = false;
        }
    }

    /// <summary>
    /// Releases resources used by the recorder.
    /// </summary>
    public void Dispose()
    {
        lock(_lock)
        {
            _completed = true;
            _exchanges.Clear();
        }
    }
}