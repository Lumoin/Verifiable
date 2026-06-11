using System;
using Verifiable.Cryptography.Text;

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
    /// <summary>The UTF-8 source literal of <see cref="Enabled"/>.</summary>
    public static ReadOnlySpan<byte> EnabledUtf8 => "enabled"u8;

    /// <summary><c>enabled</c> — the Transmitter MUST transmit events over the stream.</summary>
    public static readonly string Enabled = Utf8Constants.ToInternedString(EnabledUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Paused"/>.</summary>
    public static ReadOnlySpan<byte> PausedUtf8 => "paused"u8;

    /// <summary><c>paused</c> — the Transmitter MUST NOT transmit, SHOULD hold events for resumption.</summary>
    public static readonly string Paused = Utf8Constants.ToInternedString(PausedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Disabled"/>.</summary>
    public static ReadOnlySpan<byte> DisabledUtf8 => "disabled"u8;

    /// <summary><c>disabled</c> — the Transmitter MUST NOT transmit and holds nothing.</summary>
    public static readonly string Disabled = Utf8Constants.ToInternedString(DisabledUtf8);


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
    /// <summary>The UTF-8 source literal of <see cref="StreamId"/>.</summary>
    public static ReadOnlySpan<byte> StreamIdUtf8 => "stream_id"u8;

    /// <summary><c>stream_id</c> — REQUIRED stream identifier.</summary>
    public static readonly string StreamId = Utf8Constants.ToInternedString(StreamIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Status"/>.</summary>
    public static ReadOnlySpan<byte> StatusUtf8 => "status"u8;

    /// <summary><c>status</c> — REQUIRED status value.</summary>
    public static readonly string Status = Utf8Constants.ToInternedString(StatusUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Reason"/>.</summary>
    public static ReadOnlySpan<byte> ReasonUtf8 => "reason"u8;

    /// <summary><c>reason</c> — OPTIONAL reason string.</summary>
    public static readonly string Reason = Utf8Constants.ToInternedString(ReasonUtf8);
}
