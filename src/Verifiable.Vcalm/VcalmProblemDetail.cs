using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// One RFC 9457 ProblemDetails object as VCALM 1.0 §3.8 shapes it: a <c>type</c> URL (MUST), a
/// <c>title</c> (SHOULD), and a <c>detail</c> (SHOULD). The verifier service gathers these into the
/// §3.3.1 / §3.3.2 <c>problemDetails</c> response array rather than raising errors during
/// verification (§3.8: "It is recommended to avoid raising errors while performing verification,
/// and instead gather ProblemDetails objects to include in the verification results.").
/// </summary>
/// <remarks>
/// <see cref="IsError"/> records the §3.8.1 classification: an ERROR (cryptography, data model,
/// malformed context — unrecoverable) MUST set the overall <c>verified</c> to false; a WARNING
/// (status, validity period) does NOT flip it. The flag is internal to the verifier's result
/// assembly; it is not emitted on the wire (the wire ProblemDetails carries only <c>type</c> /
/// <c>title</c> / <c>detail</c>).
/// </remarks>
[DebuggerDisplay("VcalmProblemDetail Type={Type} IsError={IsError}")]
public sealed record VcalmProblemDetail
{
    /// <summary>The §3.8 <c>type</c> URL identifying the problem (MUST be present and a URL).</summary>
    public required string Type { get; init; }

    /// <summary>The §3.8 <c>title</c> — a short human-readable string (SHOULD).</summary>
    public string? Title { get; init; }

    /// <summary>The §3.8 <c>detail</c> — a longer human-readable string (SHOULD).</summary>
    public string? Detail { get; init; }

    /// <summary>
    /// The §3.8.1 classification: <see langword="true"/> for an unrecoverable ERROR (which MUST
    /// flip the overall <c>verified</c> to false), <see langword="false"/> for a recoverable
    /// WARNING (which does not).
    /// </summary>
    public required bool IsError { get; init; }


    /// <summary>Creates a §3.8.1 ERROR ProblemDetail (flips <c>verified</c> to false).</summary>
    public static VcalmProblemDetail Error(string type, string title, string detail) =>
        new()
        {
            Type = type,
            Title = title,
            Detail = detail,
            IsError = true
        };


    /// <summary>Creates a §3.8.1 WARNING ProblemDetail (does not flip <c>verified</c>).</summary>
    public static VcalmProblemDetail Warning(string type, string title, string detail) =>
        new()
        {
            Type = type,
            Title = title,
            Detail = detail,
            IsError = false
        };
}
