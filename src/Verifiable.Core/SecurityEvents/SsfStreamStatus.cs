namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The status of an Event Stream, per OpenID Shared Signals Framework 1.0 §8.1.2 —
/// the body of a status read/update. Shared by Receiver and Transmitter.
/// </summary>
public sealed record SsfStreamStatus
{
    /// <summary>The <c>stream_id</c> (REQUIRED).</summary>
    public required string StreamId { get; init; }

    /// <summary>
    /// The <c>status</c> (REQUIRED) — one of <see cref="SsfStreamStatusValues.Enabled"/>,
    /// <see cref="SsfStreamStatusValues.Paused"/>, or <see cref="SsfStreamStatusValues.Disabled"/>.
    /// </summary>
    public required string Status { get; init; }

    /// <summary>The OPTIONAL <c>reason</c> expressing why the status holds its current value.</summary>
    public string? Reason { get; init; }
}


/// <summary>
/// The allowable <c>status</c> values for an Event Stream (SSF 1.0 §8.1.2.1).
/// </summary>
public static class SsfStreamStatusValues
{
    /// <summary><c>enabled</c> — the Transmitter MUST transmit events over the stream.</summary>
    public static readonly string Enabled = "enabled";

    /// <summary><c>paused</c> — the Transmitter MUST NOT transmit, SHOULD hold events for resumption.</summary>
    public static readonly string Paused = "paused";

    /// <summary><c>disabled</c> — the Transmitter MUST NOT transmit and holds nothing.</summary>
    public static readonly string Disabled = "disabled";


    /// <summary>Whether <paramref name="status"/> is <see cref="Enabled"/>.</summary>
    public static bool IsEnabled(string status) => Equals(status, Enabled);

    /// <summary>Whether <paramref name="status"/> is <see cref="Paused"/>.</summary>
    public static bool IsPaused(string status) => Equals(status, Paused);

    /// <summary>Whether <paramref name="status"/> is <see cref="Disabled"/>.</summary>
    public static bool IsDisabled(string status) => Equals(status, Disabled);

    /// <summary>Whether <paramref name="status"/> is one of the three allowable status values.</summary>
    public static bool IsAllowed(string status) => IsEnabled(status) || IsPaused(status) || IsDisabled(status);


    /// <summary>Compares two status values for equality (case-sensitive).</summary>
    public static bool Equals(string statusA, string statusB) =>
        object.ReferenceEquals(statusA, statusB) || System.StringComparer.Ordinal.Equals(statusA, statusB);
}


/// <summary>
/// The member NAMES of a Stream Status object (SSF 1.0 §8.1.2).
/// </summary>
public static class SsfStreamStatusParameterNames
{
    /// <summary><c>stream_id</c> — REQUIRED stream identifier.</summary>
    public static readonly string StreamId = "stream_id";

    /// <summary><c>status</c> — REQUIRED status value.</summary>
    public static readonly string Status = "status";

    /// <summary><c>reason</c> — OPTIONAL reason string.</summary>
    public static readonly string Reason = "reason";
}
