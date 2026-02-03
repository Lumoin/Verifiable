using System;
using System.Buffers;
using System.IO;
using System.Runtime.InteropServices;

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
/// </remarks>
public static class TcgEventLogReader
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
    /// <param name="path">Path to the event log file.</param>
    /// <param name="pool">The memory pool for allocating the buffer.</param>
    /// <returns>The event log data, or an error.</returns>
    public static TpmResult<TcgEventLogData> ReadEventLogFromFile(string path, MemoryPool<byte> pool)
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

    private static TpmResult<TcgEventLogData> ReadWindowsEventLog(MemoryPool<byte> pool)
    {
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
            IMemoryOwner<byte> memoryOwner = pool.Rent((int)logSize);
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
            return TpmResult<TcgEventLogData>.TransportError((uint)TbsResult.TBS_E_INTERNAL_ERROR);
        }
    }

    private static TpmResult<TcgEventLogData> ReadLinuxEventLog(MemoryPool<byte> pool)
    {
        if(File.Exists(LinuxEventLogPath))
        {
            return ReadEventLogFromFile(LinuxEventLogPath, pool);
        }

        //Provide specific error based on what's missing.
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

    [DllImport("tbs.dll", CallingConvention = CallingConvention.Winapi)]
    private static extern uint Tbsi_Get_TCG_Log(
        IntPtr hContext,
        IntPtr pOutputBuf,
        ref uint pOutputBufLen);
}