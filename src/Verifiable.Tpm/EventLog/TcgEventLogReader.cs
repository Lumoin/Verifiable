using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Verifiable.Tpm.EventLog;

namespace Verifiable.Tpm.Extensions.EventLog;

/// <summary>
/// Reads TCG event logs from the operating system.
/// </summary>
/// <remarks>
/// <para>
/// On Windows, uses the TBS API function <c>Tbsi_Get_TCG_Log</c>:
/// <see href="https://learn.microsoft.com/en-us/windows/win32/api/tbs/nf-tbs-tbsi_get_tcg_log">
/// Microsoft Learn - Tbsi_Get_TCG_Log</see>.
/// </para>
/// <para>
/// On Linux, reads from the securityfs path:
/// <c>/sys/kernel/security/tpm0/binary_bios_measurements</c>.
/// </para>
/// <para>
/// <b>Linux hardening:</b> All Linux file access uses <c>O_NOFOLLOW | O_CLOEXEC</c> and validates
/// the opened descriptor via <c>fstat</c> to confirm it is a regular file (<c>S_IFREG</c>). The
/// public <see cref="ReadEventLogFromFile"/> method restricts paths to a known allowlist to prevent
/// misuse as an arbitrary file reader.
/// </para>
/// </remarks>
public static partial class TcgEventLogReader
{
    /// <summary>
    /// Linux securityfs path for binary BIOS measurements.
    /// </summary>
    private const string LinuxEventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements";

    /// <summary>
    /// Linux securityfs base directory.
    /// </summary>
    private const string LinuxSecurityFsPath = "/sys/kernel/security";

    /// <summary>
    /// Linux TPM device directory in securityfs.
    /// </summary>
    private const string LinuxTpmSecurityPath = "/sys/kernel/security/tpm0";

    /// <summary>
    /// TBS_E_INSUFFICIENT_BUFFER - expected on first call to get required size.
    /// </summary>
    private const uint TbsInsufficientBuffer = 0x80284005;

    /// <summary>
    /// Initial buffer size for chunked reading (64 KB).
    /// </summary>
    private const int InitialBufferSize = 64 * 1024;

    /// <summary>
    /// Maximum event log size (16 MB sanity limit).
    /// </summary>
    private const int MaxEventLogSize = 16 * 1024 * 1024;

    //Linux open(2) flags for hardened file access.
    //O_NOFOLLOW rejects symlinks; O_CLOEXEC prevents descriptor inheritance across exec.
    private const int O_RDONLY = 0x00;
    private const int O_NOFOLLOW = 0x20000;
    private const int O_CLOEXEC = 0x80000;

    //stat(2) file type mask and regular file indicator for fstat validation.
    private const uint S_IFMT = 0xF000;
    private const uint S_IFREG = 0x8000;

    /// <summary>
    /// Size of <c>struct stat</c> on x86_64 Linux.
    /// </summary>
    private const int StatBufSize = 144;

    /// <summary>
    /// Byte offset of <c>st_mode</c> within <c>struct stat</c> on x86_64 Linux.
    /// </summary>
    private const int StModeOffset = 24;

    /// <summary>
    /// Paths allowed for <see cref="ReadEventLogFromFile"/>. This prevents the public method
    /// from being used as a general-purpose file reader. Only known event log locations and
    /// the securityfs binary measurements path are permitted.
    /// </summary>
    private static readonly string[] AllowedEventLogPaths =
    [
        LinuxEventLogPath,
        "/sys/kernel/security/tpm0/binary_bios_measurements",
    ];

    /// <summary>
    /// Reads the TCG event log from the current system using pooled memory.
    /// </summary>
    /// <param name="pool">The memory pool for allocating the buffer.</param>
    /// <returns>The event log data, or an error.</returns>
    /// <remarks>
    /// The caller is responsible for disposing the returned <see cref="IMemoryOwner{T}"/>.
    /// </remarks>
    public static TpmResult<TcgEventLogData> ReadEventLog(MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return ReadWindowsEventLog(pool);
        }

        if(RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return ReadLinuxEventLog(pool);
        }

        return TpmResult<TcgEventLogData>.TransportError((uint)TcgEventLogReaderError.PlatformNotSupported);
    }

    /// <summary>
    /// Reads the TCG event log from a file using pooled memory.
    /// </summary>
    /// <param name="path">Path to the event log file. Must be an allowed event log location.</param>
    /// <param name="pool">The memory pool for allocating the buffer.</param>
    /// <returns>The event log data, or an error.</returns>
    /// <remarks>
    /// <para>
    /// The path is validated against an internal allowlist to prevent this method from being used
    /// to read arbitrary files. Only known TCG event log paths are permitted.
    /// </para>
    /// <para>
    /// On Linux, the file is opened with <c>O_NOFOLLOW | O_CLOEXEC</c> and the descriptor is validated
    /// via <c>fstat</c> to confirm it refers to a regular file, preventing symlink-based redirection.
    /// </para>
    /// </remarks>
    public static TpmResult<TcgEventLogData> ReadEventLogFromFile(string path, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(path);
        ArgumentNullException.ThrowIfNull(pool);

        //Resolve to a canonical form to prevent path traversal (e.g. /sys/kernel/security/tpm0/../../../etc/shadow).
        string resolvedPath = Path.GetFullPath(path);

        //Allowlist check: only permit known event log locations. This prevents the public API
        //from being abused as a general-purpose file reader.
        if(!IsAllowedPath(resolvedPath))
        {
            return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.EACCES);
        }

        if(RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            return ReadLinuxFileHardened(resolvedPath, pool);
        }

        //Non-Linux platforms (Windows, testing) use managed FileStream without hardened POSIX open.
        return ReadFileFallback(resolvedPath, pool);
    }


    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership transferred to TcgEventLogData and then to caller.")]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Any exception is treated the same.")]
    private static TpmResult<TcgEventLogData> ReadWindowsEventLog(MemoryPool<byte> pool)
    {
        IMemoryOwner<byte>? memoryOwner = null;
        try
        {
            //First call with null buffer to get required size.
            uint logSize = 0;
            uint result = Tbsi_Get_TCG_Log(IntPtr.Zero, IntPtr.Zero, ref logSize);

            //TBS_E_INSUFFICIENT_BUFFER is expected on first call.
            if(result != 0 && result != TbsInsufficientBuffer)
            {
                return TpmResult<TcgEventLogData>.TransportError(result);
            }

            if(logSize == 0)
            {
                return TpmResult<TcgEventLogData>.TransportError((uint)TbsResult.TBS_E_NO_EVENT_LOG);
            }

            if(logSize > MaxEventLogSize)
            {
                return TpmResult<TcgEventLogData>.TransportError((uint)TbsResult.TBS_E_BUFFER_TOO_LARGE);
            }

            //Allocate from pool.
            memoryOwner = pool.Rent((int)logSize);
            Span<byte> buffer = memoryOwner.Memory.Span;

            unsafe
            {
                fixed(byte* bufferPtr = buffer)
                {
                    result = Tbsi_Get_TCG_Log(IntPtr.Zero, (IntPtr)bufferPtr, ref logSize);
                }
            }

            if(result != 0)
            {
                memoryOwner.Dispose();
                return TpmResult<TcgEventLogData>.TransportError(result);
            }

            return TpmResult<TcgEventLogData>.Success(new TcgEventLogData(memoryOwner, (int)logSize));
        }
        catch
        {
            memoryOwner?.Dispose();
            return TpmResult<TcgEventLogData>.TransportError((uint)TbsResult.TBS_E_INTERNAL_ERROR);
        }
    }

    /// <summary>
    /// Reads the Linux event log from securityfs.
    /// </summary>
    private static TpmResult<TcgEventLogData> ReadLinuxEventLog(MemoryPool<byte> pool)
    {
        return ReadLinuxFileHardened(LinuxEventLogPath, pool);
    }

    /// <summary>
    /// Opens a Linux file with hardened flags and validates the descriptor before reading.
    /// </summary>
    /// <remarks>
    /// Uses <c>O_NOFOLLOW | O_CLOEXEC</c> to prevent symlink attacks and descriptor leakage,
    /// then validates via <c>fstat</c> that the descriptor refers to a regular file.
    /// The error codes from open(2) are mapped to specific diagnostics: <c>ELOOP</c> indicates
    /// a symlink was encountered (blocked by <c>O_NOFOLLOW</c>), <c>ENOENT</c> means the file
    /// or a path component does not exist, and <c>EACCES</c> indicates a permissions problem.
    /// </remarks>
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Any exception during file operations is treated as I/O error.")]
    private static TpmResult<TcgEventLogData> ReadLinuxFileHardened(string path, MemoryPool<byte> pool)
    {
        //O_NOFOLLOW: reject if the target is a symlink, preventing redirection to an attacker-controlled file.
        //O_CLOEXEC: prevent descriptor from being inherited by child processes.
        int fd = LinuxOpen(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC, 0);
        if(fd < 0)
        {
            int errno = Marshal.GetLastPInvokeError();
            return MapLinuxOpenError(errno, path);
        }

        //Track whether SafeFileHandle has taken ownership.
        bool ownershipTransferred = false;
        try
        {
            //Validate the descriptor points to a regular file. Securityfs entries are pseudo-files
            //presented as S_IFREG by the kernel. If something else appears (device, FIFO, socket),
            //something is wrong and we should not read from it.
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
                return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.EIO);
            }

            uint stMode = MemoryMarshal.Read<uint>(statBuf.Slice(StModeOffset));
            if((stMode & S_IFMT) != S_IFREG)
            {
                //The path resolved to something other than a regular file.
                return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.EACCES);
            }

            //Wrap the validated descriptor in SafeFileHandle. SafeFileHandle is cross-platform
            //in .NET and wraps file descriptors on Unix systems.
            using var safeHandle = new SafeFileHandle((IntPtr)fd, ownsHandle: true);
            ownershipTransferred = true;

            using var stream = new FileStream(safeHandle, FileAccess.Read, bufferSize: 0);
            return ReadFromStream(stream, pool);
        }
        finally
        {
            //Close the raw descriptor only if SafeFileHandle has not taken ownership.
            if(!ownershipTransferred)
            {
                _ = LinuxClose(fd);
            }
        }
    }


    /// <summary>
    /// Maps open(2) errno values to appropriate diagnostic error results.
    /// </summary>
    private static TpmResult<TcgEventLogData> MapLinuxOpenError(int errno, string path)
    {
        //ELOOP (40): O_NOFOLLOW detected a symlink. This is a security-relevant event.
        if(errno == 40)
        {
            return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.EACCES);
        }

        //ENOENT: file or path component does not exist. Provide specific diagnostics.
        if(errno == (int)LinuxErrno.ENOENT)
        {
            if(!Directory.Exists(LinuxSecurityFsPath))
            {
                return TpmResult<TcgEventLogData>.TransportError((uint)TcgEventLogReaderError.SecurityFsNotMounted);
            }

            if(!Directory.Exists(LinuxTpmSecurityPath))
            {
                return TpmResult<TcgEventLogData>.TransportError((uint)TcgEventLogReaderError.TpmNotFound);
            }

            return TpmResult<TcgEventLogData>.TransportError((uint)TcgEventLogReaderError.EventLogNotAvailable);
        }

        //EACCES: permission denied.
        if(errno == (int)LinuxErrno.EACCES)
        {
            return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.EACCES);
        }

        //All other errors map to generic I/O failure.
        return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.EIO);
    }

    /// <summary>
    /// Fallback file reading for non-Linux platforms using managed <see cref="FileStream"/>.
    /// </summary>
    private static TpmResult<TcgEventLogData> ReadFileFallback(string path, MemoryPool<byte> pool)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            return ReadFromStream(stream, pool);
        }
        catch(FileNotFoundException)
        {
            return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.ENOENT);
        }
        catch(DirectoryNotFoundException)
        {
            return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.ENOENT);
        }
        catch(UnauthorizedAccessException)
        {
            return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.EACCES);
        }
        catch(IOException)
        {
            return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.EIO);
        }
    }

    /// <summary>
    /// Checks whether a resolved path is in the event log allowlist.
    /// </summary>
    private static bool IsAllowedPath(string resolvedPath)
    {
        foreach(string allowed in AllowedEventLogPaths)
        {
            if(string.Equals(resolvedPath, allowed, StringComparison.Ordinal))
            {
                return true;
            }
        }

        return false;
    }

    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership transferred to TcgEventLogData and then to caller.")]
    [SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "<Pending>")]
    private static TpmResult<TcgEventLogData> ReadFromStream(Stream stream, MemoryPool<byte> pool)
    {
        //Read in chunks to avoid large single allocation for unknown-size streams.
        IMemoryOwner<byte> memoryOwner = pool.Rent(InitialBufferSize);
        Memory<byte> buffer = memoryOwner.Memory;
        int totalRead = 0;

        try
        {
            while(true)
            {
                //Ensure we have space.
                if(totalRead >= buffer.Length)
                {
                    //Need to grow - rent larger buffer and copy.
                    int newSize = Math.Min(buffer.Length * 2, MaxEventLogSize);
                    if(newSize <= buffer.Length)
                    {
                        //Already at max size.
                        memoryOwner.Dispose();
                        return TpmResult<TcgEventLogData>.TransportError((uint)TbsResult.TBS_E_BUFFER_TOO_LARGE);
                    }

                    IMemoryOwner<byte> newOwner = pool.Rent(newSize);
                    buffer.Slice(0, totalRead).CopyTo(newOwner.Memory);
                    memoryOwner.Dispose();
                    memoryOwner = newOwner;
                    buffer = memoryOwner.Memory;
                }

                int bytesRead = stream.Read(buffer.Span.Slice(totalRead));
                if(bytesRead == 0)
                {
                    break;
                }

                totalRead += bytesRead;
            }

            if(totalRead == 0)
            {
                memoryOwner.Dispose();
                return TpmResult<TcgEventLogData>.TransportError((uint)TcgEventLogReaderError.EventLogNotAvailable);
            }

            return TpmResult<TcgEventLogData>.Success(new TcgEventLogData(memoryOwner, totalRead));
        }
        catch
        {
            memoryOwner.Dispose();
            return TpmResult<TcgEventLogData>.TransportError((uint)LinuxErrno.EIO);
        }
    }

    //Windows TBS interop.
    [LibraryImport("tbs.dll", EntryPoint = "Tbsi_Get_TCG_Log")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial uint Tbsi_Get_TCG_Log(
        IntPtr hContext,
        IntPtr pOutputBuf,
        ref uint pOutputBufLen);

#pragma warning disable CA5392 //Use DefaultDllImportSearchPaths attribute for P/Invokes.

    //Linux POSIX interop for hardened event log file access.
    [LibraryImport("libc", EntryPoint = "open", SetLastError = true, StringMarshalling = StringMarshalling.Utf8)]

    private static partial int LinuxOpen(string pathname, int flags, int mode);

    [LibraryImport("libc", EntryPoint = "fstat", SetLastError = true)]
    private static partial int LinuxFstat(int fd, IntPtr statBuf);

    [LibraryImport("libc", EntryPoint = "close")]
    private static partial int LinuxClose(int fd);

#pragma warning restore CA5392 //Use DefaultDllImportSearchPaths attribute for P/Invokes
}