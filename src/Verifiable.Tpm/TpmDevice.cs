using System;
using System.Buffers;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace Verifiable.Tpm;

/// <summary>
/// Delegate for submitting TPM commands.
/// </summary>
/// <param name="command">The command bytes to submit.</param>
/// <param name="pool">The memory pool for allocating the response.</param>
/// <returns>A result containing the TPM response or a transport error.</returns>
public delegate TpmResult<TpmResponse> TpmSubmitHandler(ReadOnlySpan<byte> command, MemoryPool<byte> pool);

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
///   <item><description><b>Executor</b> - <c>TpmCommandExecutor</c> handles protocol framing.</description></item>
///   <item><description><b>Transport</b> - This class handles raw command/response byte submission.</description></item>
///   <item><description><b>Platform</b> - Windows TBS or Linux device file I/O.</description></item>
/// </list>
/// <para>
/// <b>Basic usage:</b>
/// </para>
/// <code>
/// using var tpm = TpmDevice.Open();
/// using var pool = SensitiveMemoryPool&lt;byte&gt;.Shared;
///
/// using TpmResponse response = tpm.Submit(commandBytes, pool);
/// //Parse response...
/// </code>
/// <para>
/// <b>Delegate-based usage:</b> Use custom submit handler for testing or virtual TPM:
/// </para>
/// <code>
/// var virtualTpm = new TpmVirtualDevice();
/// virtualTpm.Record(input, output);
/// using var tpm = TpmDevice.Create(virtualTpm.Submit);
/// </code>
/// <para>
/// <b>Recording traffic:</b> Attach a <see cref="TpmRecorder"/> to capture exchanges:
/// </para>
/// <code>
/// using var recorder = new TpmRecorder();
/// using(tpm.Subscribe(recorder))
/// {
///     using TpmResponse response = tpm.Submit(commandBytes, pool);
/// }
/// TpmRecording recording = recorder.ToRecording(tpm.GetSessionInfo(TimeProvider.System));
/// </code>
/// <para>
/// <b>Thread safety:</b> A single TpmDevice instance is not thread-safe for concurrent
/// <see cref="Submit"/> calls. Create separate instances or synchronize externally.
/// Observer subscription management is thread-safe.
/// </para>
/// </remarks>
/// <seealso cref="TpmRecorder"/>
/// <seealso cref="TpmVirtualDevice"/>
public sealed partial class TpmDevice: IDisposable, IObservable<TpmExchange>
{
    private readonly Lock observerLock = new();
    private readonly TpmSubmitHandler? customHandler;
    private readonly Action? customDispose;
    private IObserver<TpmExchange>[] observers = [];
    private bool disposed;

    //Platform-specific state.
    private FileStream? linuxStream;
    private IntPtr windowsContext;

    /// <summary>
    /// Delegate for platform detection. Replace to override auto-detection.
    /// </summary>
    public static Func<TpmPlatform> DetectPlatform { get; set; } = DefaultDetectPlatform;

    /// <summary>
    /// The detected or configured platform for this device instance.
    /// </summary>
    public TpmPlatform Platform { get; }


    /// <summary>
    /// Releases all resources used by this TPM device.
    /// </summary>
    public void Dispose()
    {
        if(disposed)
        {
            return;
        }

        disposed = true;

        //Notify observers of completion.
        IObserver<TpmExchange>[] currentObservers;
        lock(observerLock)
        {
            currentObservers = observers;
            observers = [];
        }

        foreach(IObserver<TpmExchange> observer in currentObservers)
        {
            observer.OnCompleted();
        }

        //Invoke custom dispose action if provided.
        customDispose?.Invoke();

        //Close platform-specific resources.
        linuxStream?.Dispose();
        linuxStream = null;

        if(windowsContext != IntPtr.Zero)
        {
            //We capture the result but can't throw in Dispose. The result is available for debugging.
            uint closeResult = Tbsip_Context_Close(windowsContext);
            Debug.Assert(closeResult == (uint)TbsResult.TBS_SUCCESS, $"Tbsip_Context_Close failed: {(TbsResult)closeResult}");
            windowsContext = IntPtr.Zero;
        }
    }


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
                uint result = Tbsi_Context_Create(ref defaultContextParams, out IntPtr context);
                if(result == (uint)TbsResult.TBS_SUCCESS)
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
    /// Opens a connection to the TPM using auto-detected platform.
    /// </summary>
    /// <returns>An open TPM device.</returns>
    public static TpmDevice Open()
    {
        TpmPlatform platform = DetectPlatform();
        var device = new TpmDevice(platform);
        device.OpenCore();

        return device;
    }

    
    /// <summary>
    /// Submits a command to the TPM and receives the response.
    /// </summary>
    /// <param name="command">The command bytes to send.</param>
    /// <param name="pool">The memory pool for allocating the response buffer.</param>
    /// <returns>A result containing the TPM response or a transport error.</returns>
    /// <remarks>
    /// <para>
    /// On success, the caller is responsible for disposing the returned <see cref="TpmResponse"/>.
    /// The response buffer is allocated from the provided pool and will be returned
    /// to the pool when disposed.
    /// </para>
    /// <para>
    /// On transport error, the result contains the platform-specific error code
    /// (<see cref="TbsResult"/> on Windows, errno on Linux).
    /// </para>
    /// <para>
    /// For sensitive operations, use <see cref="SensitiveMemoryPool{T}"/> to ensure
    /// the response bytes are securely cleared when disposed.
    /// </para>
    /// </remarks>
    public TpmResult<TpmResponse> Submit(ReadOnlySpan<byte> command, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ObjectDisposedException.ThrowIf(disposed, this);

        long startTicks = Stopwatch.GetTimestamp();
        TpmResult<TpmResponse> result = SubmitCore(command, pool);
        long endTicks = Stopwatch.GetTimestamp();

        if(result.IsSuccess)
        {
            NotifyObservers(startTicks, endTicks, command, result.Value.AsReadOnlySpan());
        }

        return result;
    }


    /// <summary>
    /// Initializes a new TpmDevice with a custom submit handler.
    /// </summary>
    private TpmDevice(TpmSubmitHandler handler, Action? disposeAction)
    {
        Platform = TpmPlatform.Virtual;
        customHandler = handler;
        customDispose = disposeAction;
    }

    
    /// <summary>
    /// Opens a connection to the TPM for a specific platform.
    /// </summary>
    /// <param name="platform">The platform to use.</param>
    /// <returns>An open TPM device.</returns>
    public static TpmDevice Open(TpmPlatform platform)
    {
        var device = new TpmDevice(platform);
        device.OpenCore();

        return device;
    }

    /// <summary>
    /// Creates a TpmDevice backed by a custom submit handler.
    /// </summary>
    /// <param name="handler">The delegate that handles command submission.</param>
    /// <param name="disposeAction">Optional action to invoke when the device is disposed.</param>
    /// <returns>A TpmDevice that delegates to the provided handler.</returns>
    /// <remarks>
    /// <para>
    /// Use this factory to create a TpmDevice backed by a <see cref="TpmVirtualDevice"/>
    /// or any other custom implementation:
    /// </para>
    /// <code>
    /// var virtualTpm = new TpmVirtualDevice();
    /// virtualTpm.Record(input, output);
    /// using var tpm = TpmDevice.Create(virtualTpm.Submit);
    /// </code>
    /// </remarks>
    public static TpmDevice Create(TpmSubmitHandler handler, Action? disposeAction = null)
    {
        ArgumentNullException.ThrowIfNull(handler);

        return new TpmDevice(handler, disposeAction);
    }


    /// <summary>
    /// Subscribes an observer to receive TPM exchange notifications.
    /// </summary>
    /// <param name="observer">The observer to subscribe.</param>
    /// <returns>A disposable that unsubscribes the observer when disposed.</returns>
    public IDisposable Subscribe(IObserver<TpmExchange> observer)
    {
        ArgumentNullException.ThrowIfNull(observer);

        lock(observerLock)
        {
            var newObservers = new IObserver<TpmExchange>[observers.Length + 1];
            observers.CopyTo(newObservers, 0);
            newObservers[^1] = observer;
            observers = newObservers;
        }

        return new Unsubscriber(this, observer);
    }


    /// <summary>
    /// Initializes a new TpmDevice for hardware access.
    /// </summary>
    private TpmDevice(TpmPlatform platform)
    {
        Platform = platform;
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
        linuxStream = new FileStream("/dev/tpmrm0", FileMode.Open, FileAccess.ReadWrite);
    }


    private void OpenWindows()
    {
        uint result = Tbsi_Context_Create(ref defaultContextParams, out windowsContext);
        if(result != (uint)TbsResult.TBS_SUCCESS)
        {
            TbsResult tbsResult = (TbsResult)result;
            throw new InvalidOperationException($"Failed to open TPM context: '{tbsResult}' - {tbsResult.GetDescription()}");
        }
    }

    
    private TpmResult<TpmResponse> SubmitCore(ReadOnlySpan<byte> command, MemoryPool<byte> pool)
    {
        if(customHandler is not null)
        {
            return customHandler(command, pool);
        }

        if(Platform is TpmPlatform.Linux)
        {
            return SubmitLinux(command, pool);
        }

        if(Platform is TpmPlatform.Windows)
        {
            return SubmitWindows(command, pool);
        }

        return TpmResult<TpmResponse>.TransportError(0u);
    }


    private TpmResult<TpmResponse> SubmitLinux(ReadOnlySpan<byte> command, MemoryPool<byte> pool)
    {
        if(linuxStream is null)
        {
            //Device not open - return a generic I/O error.
            return TpmResult<TpmResponse>.TransportError((uint)LinuxErrno.EIO);
        }

        //Allocate response buffer.
        IMemoryOwner<byte> responseOwner = pool.Rent(TpmConstants.MaxResponseSize);
        Span<byte> responseSpan = responseOwner.Memory.Span;

        try
        {
            //Send command.
            linuxStream.Write(command);
            linuxStream.Flush();

            //Read response.
            int bytesRead = linuxStream.Read(responseSpan);

            return TpmResult<TpmResponse>.Success(new TpmResponse(responseOwner, bytesRead));
        }
        catch(IOException)
        {
            responseOwner.Dispose();
            return TpmResult<TpmResponse>.TransportError((uint)LinuxErrno.EIO);
        }
    }


    private TpmResult<TpmResponse> SubmitWindows(ReadOnlySpan<byte> command, MemoryPool<byte> pool)
    {
        if(windowsContext == IntPtr.Zero)
        {
            return TpmResult<TpmResponse>.TransportError((uint)TbsResult.TBS_E_INVALID_CONTEXT);
        }

        //Allocate response buffer.
        IMemoryOwner<byte> responseOwner = pool.Rent(TpmConstants.MaxResponseSize);
        Span<byte> responseSpan = responseOwner.Memory.Span;

        uint responseSize = (uint)responseSpan.Length;
        uint result = Tbsip_Submit_Command(
            windowsContext,
            TbsLocality.Zero,
            TbsPriority.Normal,
            command,
            (uint)command.Length,
            responseSpan,
            ref responseSize);

        if(result != (uint)TbsResult.TBS_SUCCESS)
        {
            responseOwner.Dispose();
            return TpmResult<TpmResponse>.TransportError(result);
        }

        return TpmResult<TpmResponse>.Success(new TpmResponse(responseOwner, (int)responseSize));
    }


    private void NotifyObservers(long startTicks, long endTicks, ReadOnlySpan<byte> command, ReadOnlySpan<byte> response)
    {
        IObserver<TpmExchange>[] currentObservers;
        lock(observerLock)
        {
            if(observers.Length == 0)
            {
                return;
            }

            currentObservers = observers;
        }

        //Copy bytes only when there are observers.
        var exchange = new TpmExchange(
            startTicks,
            endTicks,
            command.ToArray(),
            response.ToArray());

        foreach(IObserver<TpmExchange> observer in currentObservers)
        {
            observer.OnNext(exchange);
        }
    }


    private void Unsubscribe(IObserver<TpmExchange> observer)
    {
        lock(observerLock)
        {
            int index = Array.IndexOf(observers, observer);
            if(index < 0)
            {
                return;
            }

            var newObservers = new IObserver<TpmExchange>[observers.Length - 1];
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
    [StructLayout(LayoutKind.Sequential)]
    private struct TbsContextParams
    {
        public uint Version;
        public uint Flags;
    }


    private static TbsContextParams defaultContextParams = new()
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
        TbsLocality locality,
        TbsPriority priority,
        ReadOnlySpan<byte> command,
        uint commandSize,
        Span<byte> response,
        ref uint responseSize);
}