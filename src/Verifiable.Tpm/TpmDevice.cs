using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using Verifiable.Tpm.Structures;

namespace Verifiable.Tpm;

/// <summary>
/// Cross-platform TPM 2.0 device access with observable command/response traffic.
/// </summary>
/// <remarks>
/// <para>
/// <b>Design:</b> TpmDevice abstracts platform-specific TPM access (Windows TBS API,
/// Linux /dev/tpm0) behind a unified interface. It implements <see cref="IObservable{T}"/>
/// to enable non-intrusive traffic capture for recording, debugging, and compliance.
/// </para>
/// <para>
/// <b>Architecture layers:</b>
/// </para>
/// <list type="number">
///   <item><description><b>Intent API</b> - High-level methods in <see cref="TpmDeviceExtensions"/> (Hash, GetRandom, GetCapability).</description></item>
///   <item><description><b>Transport</b> - This class handles raw command/response byte submission.</description></item>
///   <item><description><b>Platform</b> - Windows TBS or Linux device file I/O.</description></item>
/// </list>
/// <para>
/// <b>Basic usage:</b>
/// </para>
/// <code>
/// using var tpm = TpmDevice.Open();
///
/// // High-level operations via extension methods.
/// byte[] random = tpm.GetRandom(16);
/// byte[] hash = tpm.Hash(Tpm2AlgId.TPM_ALG_SHA256, data);
/// bool isFips = tpm.IsFipsMode();
/// </code>
/// <para>
/// <b>Recording traffic:</b> Attach a <see cref="TpmRecorder"/> to capture exchanges:
/// </para>
/// <code>
/// using var recorder = new TpmRecorder();
/// using (tpm.Subscribe(recorder))
/// {
///     tpm.GetRandom(16);
/// }
/// TpmRecording recording = recorder.ToRecording(tpm.GetSessionInfo(TimeProvider.System));
/// </code>
/// <para>
/// <b>Memory pooling:</b> For high-throughput scenarios, provide a memory pool:
/// </para>
/// <code>
/// using var tpm = TpmDevice.Open(pool: myMemoryPool);
/// </code>
/// <para>
/// <b>Thread safety:</b> A single TpmDevice instance is not thread-safe for concurrent
/// <see cref="Submit"/> calls. Create separate instances or synchronize externally.
/// Observer subscription management is thread-safe.
/// </para>
/// </remarks>
/// <seealso cref="TpmDeviceExtensions"/>
/// <seealso cref="TpmRecorder"/>
/// <seealso cref="VirtualTpm"/>
public sealed partial class TpmDevice: IDisposable, IObservable<TpmExchange>
{
    private readonly MemoryPool<byte>? _pool;
    private readonly Lock _observerLock = new();
    private IObserver<TpmExchange>[] _observers = [];
    private bool _disposed;

    //Platform-specific state.
    private FileStream? _linuxStream;
    private IntPtr _windowsContext;

    /// <summary>
    /// Delegate for platform detection. Replace to override auto-detection.
    /// </summary>
    public static Func<TpmPlatform> DetectPlatform { get; set; } = DefaultDetectPlatform;

    /// <summary>
    /// Gets a value indicating whether a TPM is available on this system.
    /// </summary>
    public static bool IsAvailable
    {
        get
        {
            TpmPlatform platform = DetectPlatform();

            if(platform == TpmPlatform.Windows)
            {
                //Try to open and immediately close a context.
                uint result = Tbsi_Context_Create(ref _defaultContextParams, out IntPtr context);
                if(result == TBS_SUCCESS)
                {
                    Tbsip_Context_Close(context);
                    return true;
                }

                return false;
            }

            if(platform == TpmPlatform.Linux)
            {
                return File.Exists("/dev/tpmrm0");
            }

            return false;
        }
    }

    /// <summary>
    /// The detected or configured platform for this device instance.
    /// </summary>
    public TpmPlatform Platform { get; }

    /// <summary>
    /// The memory pool used for pooled operations, if configured.
    /// </summary>
    public MemoryPool<byte>? Pool => _pool;

    private TpmDevice(TpmPlatform platform, MemoryPool<byte>? pool)
    {
        Platform = platform;
        _pool = pool;
    }

    /// <summary>
    /// Opens a connection to the TPM using auto-detected platform.
    /// </summary>
    /// <param name="pool">Optional memory pool for pooled operations.</param>
    /// <returns>An open TPM device.</returns>
    public static TpmDevice Open(MemoryPool<byte>? pool = null)
    {
        TpmPlatform platform = DetectPlatform();
        var device = new TpmDevice(platform, pool);
        device.OpenCore();
        return device;
    }

    /// <summary>
    /// Opens a connection to the TPM for a specific platform.
    /// </summary>
    /// <param name="platform">The platform to use.</param>
    /// <param name="pool">Optional memory pool for pooled operations.</param>
    /// <returns>An open TPM device.</returns>
    public static TpmDevice Open(TpmPlatform platform, MemoryPool<byte>? pool = null)
    {
        var device = new TpmDevice(platform, pool);
        device.OpenCore();
        return device;
    }

    private void OpenCore()
    {
        if(Platform is TpmPlatform.Windows)
        {
            OpenWindows();
        }
        else if(Platform is TpmPlatform.Linux)
        {
            OpenLinux();
        }
        else
        {
            throw new PlatformNotSupportedException($"TPM not supported on platform: {Platform}");
        }
    }

    private void OpenLinux()
    {
        _linuxStream = new FileStream("/dev/tpmrm0", FileMode.Open, FileAccess.ReadWrite);
    }

    private void OpenWindows()
    {
        uint result = Tbsi_Context_Create(ref _defaultContextParams, out _windowsContext);
        if(result != TBS_SUCCESS)
        {
            TbsResult tbsResult = (TbsResult)result;
            throw new InvalidOperationException($"Failed to open TPM context: '{tbsResult}' - {tbsResult.GetDescription()}");
        }
    }

    /// <summary>
    /// Submits a command to the TPM and receives the response.
    /// </summary>
    /// <param name="command">The command bytes to send.</param>
    /// <param name="response">Buffer to receive the response.</param>
    /// <returns>Number of bytes written to response buffer.</returns>
    public int Submit(ReadOnlySpan<byte> command, Span<byte> response)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        long startTicks = Stopwatch.GetTimestamp();
        int bytesWritten = SubmitCore(command, response);
        long endTicks = Stopwatch.GetTimestamp();

        NotifyObservers(startTicks, endTicks, command, response[..bytesWritten]);

        return bytesWritten;
    }

    private int SubmitCore(ReadOnlySpan<byte> command, Span<byte> response)
    {
        if(Platform is TpmPlatform.Linux)
        {
            return SubmitLinux(command, response);
        }
        else if(Platform is TpmPlatform.Windows)
        {
            return SubmitWindows(command, response);
        }
        else
        {
            throw new PlatformNotSupportedException();
        }
    }

    private int SubmitLinux(ReadOnlySpan<byte> command, Span<byte> response)
    {
        if(_linuxStream is null)
        {
            throw new InvalidOperationException("TPM device not open.");
        }

        _linuxStream.Write(command);
        _linuxStream.Flush();
        return _linuxStream.Read(response);
    }

    private int SubmitWindows(ReadOnlySpan<byte> command, Span<byte> response)
    {
        if(_windowsContext == IntPtr.Zero)
        {
            throw new InvalidOperationException("TPM context not open.");
        }

        uint responseSize = (uint)response.Length;
        uint result = Tbsip_Submit_Command(
            _windowsContext,
            TBS_COMMAND_LOCALITY_ZERO,
            TBS_COMMAND_PRIORITY_NORMAL,
            command,
            (uint)command.Length,
            response,
            ref responseSize);

        if(result != TBS_SUCCESS)
        {
            TbsResult tbsResult = (TbsResult)result;
            throw new InvalidOperationException($"TPM command failed: '{tbsResult}' - {tbsResult.GetDescription()}");
        }

        return (int)responseSize;
    }

    private void NotifyObservers(long startTicks, long endTicks, ReadOnlySpan<byte> command, ReadOnlySpan<byte> response)
    {
        IObserver<TpmExchange>[] observers;
        lock(_observerLock)
        {
            if(_observers.Length == 0)
            {
                return;
            }

            observers = _observers;
        }

        //Copy bytes only when there are observers.
        var exchange = new TpmExchange(
            startTicks,
            endTicks,
            command.ToArray(),
            response.ToArray());

        foreach(IObserver<TpmExchange> observer in observers)
        {
            observer.OnNext(exchange);
        }
    }

    /// <summary>
    /// Subscribes an observer to receive TPM exchange notifications.
    /// </summary>
    /// <param name="observer">The observer to subscribe.</param>
    /// <returns>A disposable that unsubscribes the observer when disposed.</returns>
    public IDisposable Subscribe(IObserver<TpmExchange> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

        lock(_observerLock)
        {
            var newObservers = new IObserver<TpmExchange>[_observers.Length + 1];
            _observers.CopyTo(newObservers, 0);
            newObservers[^1] = observer;
            _observers = newObservers;
        }

        return new Unsubscriber(this, observer);
    }

    private void Unsubscribe(IObserver<TpmExchange> observer)
    {
        lock(_observerLock)
        {
            int index = Array.IndexOf(_observers, observer);
            if(index < 0)
            {
                return;
            }

            var newObservers = new IObserver<TpmExchange>[_observers.Length - 1];
            if(index > 0)
            {
                Array.Copy(_observers, 0, newObservers, 0, index);
            }

            if(index < newObservers.Length)
            {
                Array.Copy(_observers, index + 1, newObservers, index, newObservers.Length - index);
            }

            _observers = newObservers;
        }
    }

    /// <summary>
    /// Releases all resources used by this TPM device.
    /// </summary>
    public void Dispose()
    {
        if(_disposed)
        {
            return;
        }

        _disposed = true;

        //Notify observers of completion.
        IObserver<TpmExchange>[] observers;
        lock(_observerLock)
        {
            observers = _observers;
            _observers = [];
        }

        foreach(IObserver<TpmExchange> observer in observers)
        {
            observer.OnCompleted();
        }

        //Close platform-specific resources.
        _linuxStream?.Dispose();
        _linuxStream = null;

        if(_windowsContext != IntPtr.Zero)
        {
            //We capture the result but can't throw in Dispose. The result is available for debugging.
            uint closeResult = Tbsip_Context_Close(_windowsContext);
            Debug.Assert(closeResult == TBS_SUCCESS, $"Tbsip_Context_Close failed: {(TbsResult)closeResult}");
            _windowsContext = IntPtr.Zero;
        }
    }

    private static TpmPlatform DefaultDetectPlatform()
    {
        if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return TpmPlatform.Windows;
        }

        if(RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return TpmPlatform.Linux;
        }

        return TpmPlatform.Unknown;
    }

    private sealed class Unsubscriber(TpmDevice device, IObserver<TpmExchange> observer): IDisposable
    {
        public void Dispose() => device.Unsubscribe(observer);
    }

    //Windows TBS interop.
    private const uint TBS_SUCCESS = 0;
    private const uint TBS_COMMAND_LOCALITY_ZERO = 0;
    private const uint TBS_COMMAND_PRIORITY_NORMAL = 200;

    [StructLayout(LayoutKind.Sequential)]
    private struct TbsContextParams
    {
        public uint Version;
        public uint Flags;
    }

    private static TbsContextParams _defaultContextParams = new()
    {
        Version = 2,
        Flags = 4 //IncludeTpm20.
    };

    [LibraryImport("tbs", EntryPoint = "Tbsi_Context_Create")]
    private static partial uint Tbsi_Context_Create(ref TbsContextParams contextParams, out IntPtr context);

    [LibraryImport("tbs", EntryPoint = "Tbsip_Context_Close")]
    private static partial uint Tbsip_Context_Close(IntPtr context);

    [LibraryImport("tbs", EntryPoint = "Tbsip_Submit_Command")]
    private static partial uint Tbsip_Submit_Command(
        IntPtr context,
        uint locality,
        uint priority,
        ReadOnlySpan<byte> command,
        uint commandSize,
        Span<byte> response,
        ref uint responseSize);
}