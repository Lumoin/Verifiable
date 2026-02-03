namespace Verifiable.Tpm.EventLog;

/// <summary>
/// Error codes for TCG event log parsing.
/// </summary>
/// <remarks>
/// <para>
/// These error codes are returned as transport errors in <see cref="TpmResult{T}"/>
/// when parsing fails. They use a distinct range (0x80290000) to avoid collision
/// with TBS and TPM error codes.
/// </para>
/// </remarks>
public enum TcgEventLogError: uint
{
    /// <summary>
    /// The log data is too small to contain a valid event.
    /// </summary>
    LogTooSmall = 0x80290001,

    /// <summary>
    /// An exception occurred during parsing.
    /// </summary>
    ParseException = 0x80290002,

    /// <summary>
    /// The first event in the log is invalid or malformed.
    /// </summary>
    InvalidFirstEvent = 0x80290003,

    /// <summary>
    /// Unexpected end of data while parsing an event.
    /// </summary>
    UnexpectedEndOfData = 0x80290004,

    /// <summary>
    /// Event data size exceeds maximum allowed (1 MB).
    /// </summary>
    EventDataTooLarge = 0x80290005,

    /// <summary>
    /// Too many digest algorithms in a single event (max 16).
    /// </summary>
    TooManyDigests = 0x80290006,

    /// <summary>
    /// Unknown hash algorithm with no size information available.
    /// </summary>
    UnknownAlgorithm = 0x80290007,

    /// <summary>
    /// The TCG_EfiSpecIdEvent structure is invalid or too small.
    /// </summary>
    InvalidSpecIdEvent = 0x80290008
}

/// <summary>
/// Extension methods for <see cref="TcgEventLogError"/>.
/// </summary>
public static class TcgEventLogErrorExtensions
{
    /// <summary>
    /// Gets a human-readable description of the error code.
    /// </summary>
    public static string GetDescription(this TcgEventLogError error)
    {
        return error switch
        {
            TcgEventLogError.LogTooSmall => "The log data is too small to contain a valid event.",
            TcgEventLogError.ParseException => "An exception occurred during parsing.",
            TcgEventLogError.InvalidFirstEvent => "The first event in the log is invalid or malformed.",
            TcgEventLogError.UnexpectedEndOfData => "Unexpected end of data while parsing an event.",
            TcgEventLogError.EventDataTooLarge => "Event data size exceeds maximum allowed (1 MB).",
            TcgEventLogError.TooManyDigests => "Too many digest algorithms in a single event (max 16).",
            TcgEventLogError.UnknownAlgorithm => "Unknown hash algorithm with no size information available.",
            TcgEventLogError.InvalidSpecIdEvent => "The TCG_EfiSpecIdEvent structure is invalid or too small.",
            _ => $"Unknown event log error: 0x{(uint)error:X8}"
        };
    }
}