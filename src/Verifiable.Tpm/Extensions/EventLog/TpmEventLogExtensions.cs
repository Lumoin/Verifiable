using System.Buffers;
using Verifiable.Tpm.EventLog;

namespace Verifiable.Tpm.Extensions.EventLog;

/// <summary>
/// Extension methods for reading and parsing TPM event logs.
/// </summary>
/// <remarks>
/// <para>
/// Import this namespace to add event log functionality:
/// </para>
/// <code>
/// using Verifiable.Tpm.Extensions.EventLog;
/// 
/// using var pool = MemoryPool&lt;byte&gt;.Shared;
/// var result = TpmEventLogExtensions.ReadAndParseEventLog(pool);
/// if(result.IsSuccess)
/// {
///     var log = result.Value;
///     foreach(var evt in log.Events)
///     {
///         Console.WriteLine($"PCR[{evt.PcrIndex}] {evt.EventTypeName}");
///     }
/// }
/// </code>
/// </remarks>
public static class TpmEventLogExtensions
{
    /// <summary>
    /// Reads and parses the system's TCG event log.
    /// </summary>
    /// <param name="pool">The memory pool for allocating buffers.</param>
    /// <returns>The parsed event log, or an error.</returns>
    public static TpmResult<TcgEventLog> ReadAndParseEventLog(MemoryPool<byte> pool)
    {
        var readResult = TcgEventLogReader.ReadEventLog(pool);

        if(!readResult.IsSuccess)
        {
            return readResult.Match(
                onSuccess: _ => TpmResult<TcgEventLog>.TransportError(0u),
                onTpmError: rc => TpmResult<TcgEventLog>.TpmError(rc),
                onTransportError: tc => TpmResult<TcgEventLog>.TransportError(tc));
        }

        using TcgEventLogData data = readResult.Value!;
        return TcgEventLogParser.Parse(data.Span);
    }

    /// <summary>
    /// Reads and parses a TCG event log from a file.
    /// </summary>
    /// <param name="path">Path to the event log file.</param>
    /// <param name="pool">The memory pool for allocating buffers.</param>
    /// <returns>The parsed event log, or an error.</returns>
    public static TpmResult<TcgEventLog> ReadAndParseEventLogFromFile(string path, MemoryPool<byte> pool)
    {
        var readResult = TcgEventLogReader.ReadEventLogFromFile(path, pool);

        if(!readResult.IsSuccess)
        {
            return readResult.Match(
                onSuccess: _ => TpmResult<TcgEventLog>.TransportError(0u),
                onTpmError: rc => TpmResult<TcgEventLog>.TpmError(rc),
                onTransportError: tc => TpmResult<TcgEventLog>.TransportError(tc));
        }

        using TcgEventLogData data = readResult.Value!;
        return TcgEventLogParser.Parse(data.Span);
    }

    /// <summary>
    /// Reads the raw TCG event log bytes from the system.
    /// </summary>
    /// <param name="pool">The memory pool for allocating buffers.</param>
    /// <returns>The raw event log data, or an error. Caller must dispose the returned data.</returns>
    public static TpmResult<TcgEventLogData> ReadEventLog(MemoryPool<byte> pool)
    {
        return TcgEventLogReader.ReadEventLog(pool);
    }

    /// <summary>
    /// Reads the raw TCG event log bytes from a file.
    /// </summary>
    /// <param name="path">Path to the event log file.</param>
    /// <param name="pool">The memory pool for allocating buffers.</param>
    /// <returns>The raw event log data, or an error. Caller must dispose the returned data.</returns>
    public static TpmResult<TcgEventLogData> ReadEventLogFromFile(string path, MemoryPool<byte> pool)
    {
        return TcgEventLogReader.ReadEventLogFromFile(path, pool);
    }
}