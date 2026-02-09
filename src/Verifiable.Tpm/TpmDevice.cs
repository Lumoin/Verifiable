using System;
using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
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
/// Linux /dev/tpmrm0) behind a unified interface. It implements <see cref="IObservable{T}"/>
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
/// <b>Linux hardening:</b> The device is opened with <c>O_NOFOLLOW | O_CLOEXEC</c> to prevent
/// symlink-following and file descriptor leakage to child processes. After opening, <c>fstat</c>
/// verifies the descriptor points to a character device (<c>S_IFCHR</c>), closing the TOCTOU gap
/// between path resolution and use. Only <c>/dev/tpmrm0</c> is used; the kernel resource manager
/// prevents session and object handle leaks that direct <c>/dev/tpm0</c> access would expose.
/// </para>
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
/// <para>
/// <b>Transport health:</b> The device tracks transport failures. Once a transport error
/// occurs (I/O failure on Linux, TBS error on Windows), the device transitions to a
/// permanently failed state. All subsequent <see cref="Submit"/> calls return the same
/// transport error immediately. Check <see cref="IsHealthy"/> to detect this, and inspect
/// <see cref="Failure"/> for diagnostic details. The caller should dispose the failed device
/// and create a new one. There is no reconnect — the kernel resource manager flushes all
/// transient objects and sessions when the client connection is lost, so any handles held
/// by the caller are invalid regardless.
/// </para>
/// <code>
/// TpmResult&lt;TpmResponse&gt; result = tpm.Submit(commandBytes, pool);
/// if(result.IsTransportError)
/// {
///     TpmTransportFailure info = tpm.Failure!;
///     logger.LogError("TPM transport failed on {Platform}: {Reason} (0x{Code:X8}).",
///         info.Platform, info.Reason, info.ErrorCode);
///     tpm.Dispose();
///     //Rebuild device, sessions, and handles from scratch.
/// }
/// </code>
/// </remarks>
/// <seealso cref="TpmRecorder"/>
/// <seealso cref="TpmVirtualDevice"/>
public sealed partial class TpmDevice: IDisposable, IObservable<TpmExchange>
{
    /// <summary>
    /// The kernel resource manager device path. Preferred over <c>/dev/tpm0</c> because the
    /// resource manager handles session and object lifetime automatically, preventing handle
    /// exhaustion from application-level leaks. There is no fallback to <c>/dev/tpm0</c>.
    /// </summary>
    private const string LinuxTpmResourceManagerPath = "/dev/tpmrm0";

    //Linux open(2) flags for hardened file descriptor creation.
    //O_NOFOLLOW rejects symlinks at the target; O_CLOEXEC prevents descriptor inheritance across exec.
    private const int O_RDWR = 0x02;
    private const int O_NOFOLLOW = 0x20000;
    private const int O_CLOEXEC = 0x80000;

    //stat(2) file type mask and character device indicator for fstat validation.
    private const uint S_IFMT = 0xF000;
    private const uint S_IFCHR = 0x2000;

    /// <summary>
    /// Size of <c>struct stat</c> on x86_64 Linux. This is architecture-dependent
    /// and would need adjustment for arm64 (where it is also 128 bytes but with different layout).
    /// </summary>
    private const int StatBufSize = 144;

    /// <summary>
    /// Byte offset of <c>st_mode</c> within <c>struct stat</c> on x86_64 Linux.
    /// </summary>
    private const int StModeOffset = 24;

    private readonly Lock observerLock = new();
    private readonly TpmSubmitHandler? customHandler;
    private readonly Action? customDispose;
    private IObserver<TpmExchange>[] observers = [];
    private bool disposed;

    //Platform-specific state.
    private FileStream? linuxStream;
    private IntPtr windowsContext;

    //Health tracking. Once a transport failure occurs, the device is permanently failed.
    private TpmTransportFailure? failure;

    /// <summary>
    /// Delegate for platform detection. Replace to override auto-detection.
    /// </summary>
    public static Func<TpmPlatform> DetectPlatform { get; set; } = DefaultDetectPlatform;

    /// <summary>
    /// The detected or configured platform for this device instance.
    /// </summary>
    public TpmPlatform Platform { get; }

    /// <summary>
    /// The device path or transport endpoint that was opened, for audit and diagnostic purposes.
    /// </summary>
    /// <remarks>
    /// Returns the filesystem path on Linux (e.g. <c>/dev/tpmrm0</c>), <c>"TBS"</c> on Windows,
    /// or <c>"Virtual"</c> for delegate-backed instances. This enables callers to verify and log
    /// which backend was selected without inspecting platform-specific internals.
    /// </remarks>
    public string Endpoint { get; private set; } = "Unknown";

    /// <summary>
    /// Gets a value indicating whether the TPM transport is still functional.
    /// </summary>
    /// <remarks>
    /// Once a transport failure occurs, the device is permanently unhealthy.
    /// All subsequent <see cref="Submit"/> calls will return the same transport error.
    /// The caller should dispose this device and create a new one.
    /// </remarks>
    public bool IsHealthy
    {
        //No failure recorded means the transport is still functional.
        get => failure is null;
    }

    /// <summary>
    /// Gets the transport failure that caused this device to become unhealthy,
    /// or <see langword="null"/> if the device is still healthy.
    /// </summary>
    public TpmTransportFailure? Failure
    {
        //Exposes the diagnostic info so the caller knows why it broke.
        get => failure;
    }


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
                    _ = Tbsip_Context_Close(context);

                    return true;
                }

                return false;
            }

            if(platform == TpmPlatform.Linux)
            {
                //Only check the resource manager path; there is no fallback to /dev/tpm0.
                return File.Exists(LinuxTpmResourceManagerPath);
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
    /// (<see cref="TbsResult"/> on Windows, errno on Linux). A transport error also
    /// transitions the device to a permanently failed state. All subsequent calls will
    /// return the same transport error immediately without attempting I/O. Inspect
    /// <see cref="Failure"/> for diagnostic details.
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

        //Once the transport has failed, all subsequent calls return the same error.
        if(failure is not null)
        {
            return TpmResult<TpmResponse>.TransportError(failure.ErrorCode);
        }

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
        Endpoint = "Virtual";
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


    /// <summary>
    /// Opens the Linux TPM device with hardened file descriptor handling.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Three layers of defense protect against path manipulation and descriptor misuse:
    /// </para>
    /// <list type="number">
    ///   <item><description><c>O_NOFOLLOW</c> rejects symlinks at the path target, preventing an
    ///   adversary from replacing <c>/dev/tpmrm0</c> with a symlink to an arbitrary file.</description></item>
    ///   <item><description><c>O_CLOEXEC</c> prevents the file descriptor from leaking into child
    ///   processes via <c>exec</c>, closing a privilege escalation vector.</description></item>
    ///   <item><description><c>fstat</c> after open verifies the descriptor actually refers to a
    ///   character device (<c>S_IFCHR</c>), closing the TOCTOU gap between path resolution and use.
    ///   This catches scenarios where the path resolves to a regular file, FIFO, or socket.</description></item>
    /// </list>
    /// </remarks>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "SafeFileHandle ownership is transferred to FileStream which is held by the linuxStream field until TpmDevice.Dispose().")]
    private void OpenLinux()
    {
        //O_NOFOLLOW: reject if the target is a symlink (prevents /dev/tpmrm0 -> /dev/sda attacks).
        //O_CLOEXEC: prevent the descriptor from being inherited by child processes after exec.
        int fd = LinuxOpen(LinuxTpmResourceManagerPath, O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0);
        if(fd < 0)
        {
            int errno = Marshal.GetLastPInvokeError();
            throw new IOException($"Failed to open TPM device '{LinuxTpmResourceManagerPath}': errno {errno}.");
        }

        try
        {
            //Validate the opened descriptor refers to a character device. This closes the TOCTOU gap:
            //even though O_NOFOLLOW prevented symlink resolution, a race between unlink and open could
            //yield a descriptor to an unexpected file type. Verifying S_IFCHR on the actual descriptor
            //ensures we are talking to a kernel character device driver, not a regular file or pipe.
            Span<byte> statBuf = stackalloc byte[StatBufSize];
            int statResult;
            unsafe
            {
                fixed(byte* statPtr = statBuf)
                {
                    statResult = LinuxFstat(fd, (IntPtr)statPtr);
                }
            }

            if(statResult != 0)
            {
                int errno = Marshal.GetLastPInvokeError();
                throw new IOException($"fstat failed on TPM device descriptor: errno {errno}.");
            }

            //Extract st_mode and check the file type bits.
            uint stMode = MemoryMarshal.Read<uint>(statBuf.Slice(StModeOffset));
            if((stMode & S_IFMT) != S_IFCHR)
            {
                throw new IOException(
                    $"TPM path '{LinuxTpmResourceManagerPath}' is not a character device (st_mode: 0x{stMode:X}).");
            }

            //Wrap the validated descriptor. SafeFileHandle takes ownership, so if the FileStream
            //constructor succeeds, we must not call LinuxClose manually.
            var safeHandle = new Microsoft.Win32.SafeHandles.SafeFileHandle(fd, ownsHandle: true);
            linuxStream = new FileStream(safeHandle, FileAccess.ReadWrite, bufferSize: 0);
            Endpoint = LinuxTpmResourceManagerPath;
        }
        catch
        {
            //On any failure after open but before SafeFileHandle takes ownership, prevent descriptor leak.
            _ = LinuxClose(fd);
            throw;
        }
    }


    private void OpenWindows()
    {
        uint result = Tbsi_Context_Create(ref defaultContextParams, out windowsContext);
        if(result != (uint)TbsResult.TBS_SUCCESS)
        {
            TbsResult tbsResult = (TbsResult)result;
            throw new InvalidOperationException($"Failed to open TPM context: '{tbsResult}' - {tbsResult.GetDescription()}");
        }

        Endpoint = "TBS";
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


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of responseOwner. The caller is responsible for disposing the returned TpmResult.")]
    private TpmResult<TpmResponse> SubmitLinux(ReadOnlySpan<byte> command, MemoryPool<byte> pool)
    {
        if(linuxStream is null)
        {
            uint errorCode = (uint)LinuxErrno.EIO;
            failure = new TpmTransportFailure(errorCode, TpmPlatform.Linux, "Linux stream is not open.");
            return TpmResult<TpmResponse>.TransportError(errorCode);
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
        catch(IOException ex)
        {
            responseOwner.Dispose();

            int errno = Marshal.GetLastPInvokeError();
            uint errorCode = errno != 0 ? (uint)errno : (uint)LinuxErrno.EIO;
            failure = new TpmTransportFailure(errorCode, TpmPlatform.Linux, ex.Message);

            return TpmResult<TpmResponse>.TransportError(errorCode);
        }
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "TpmResponse takes ownership of responseOwner. The caller is responsible for disposing the returned TpmResult.")]
    private TpmResult<TpmResponse> SubmitWindows(ReadOnlySpan<byte> command, MemoryPool<byte> pool)
    {
        if(windowsContext == IntPtr.Zero)
        {
            uint errorCode = (uint)TbsResult.TBS_E_INVALID_CONTEXT;
            failure = new TpmTransportFailure(errorCode, TpmPlatform.Windows, "TBS context is not open.");
            return TpmResult<TpmResponse>.TransportError(errorCode);
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
            TbsResult tbsResult = (TbsResult)result;
            failure = new TpmTransportFailure(result, TpmPlatform.Windows, tbsResult.GetDescription());
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
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint Tbsi_Context_Create(ref TbsContextParams contextParams, out IntPtr context);


    [LibraryImport("tbs", EntryPoint = "Tbsip_Context_Close")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint Tbsip_Context_Close(IntPtr context);


    [LibraryImport("tbs", EntryPoint = "Tbsip_Submit_Command")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint Tbsip_Submit_Command(
        IntPtr context,
        TbsLocality locality,
        TbsPriority priority,
        ReadOnlySpan<byte> command,
        uint commandSize,
        Span<byte> response,
        ref uint responseSize);


    //Linux POSIX interop for hardened device opening.
    //These are used only by OpenLinux to open with O_NOFOLLOW | O_CLOEXEC and validate via fstat.

    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]

#pragma warning disable CA5392 //Use DefaultDllImportSearchPaths attribute for P/Invokes.

    private static partial int LinuxOpen(string pathname, int flags, int mode);


    [LibraryImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static partial int LinuxFstat(int fd, IntPtr statBuf);

    [LibraryImport("libc", EntryPoint = "close")]
    private static partial int LinuxClose(int fd);

#pragma warning restore CA5392  //Use DefaultDllImportSearchPaths attribute for P/Invokes.
}