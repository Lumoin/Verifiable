using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// A single security event carried in a Security Event Token's <c>events</c>
/// claim: an event-type URI mapped to its payload object.
/// </summary>
/// <remarks>
/// <para>
/// This is the format-neutral envelope. The <see cref="EventType"/> selects the
/// profile (CAEP, RISC, or an SSF framework event — see
/// <see cref="CaepEventTypes"/>, <see cref="RiscEventTypes"/>,
/// <see cref="SsfEventTypes"/>); the <see cref="Payload"/> holds the event's
/// fields verbatim as parsed from JSON (strings, numbers, nested objects as
/// <c>Dictionary&lt;string, object&gt;</c>, arrays as <c>List&lt;object&gt;</c>).
/// </para>
/// <para>
/// The subject of the event is the enclosing token's
/// <see cref="SecurityEventToken.SubjectId"/>; individual events do not repeat it.
/// Strongly-typed per-event accessors over <see cref="Payload"/> are layered on
/// top of this envelope as each event profile is filled out.
/// </para>
/// </remarks>
public sealed record SecurityEvent
{
    /// <summary>The event-type URI that keyed this event within the <c>events</c> claim.</summary>
    public required string EventType { get; init; }

    /// <summary>The event payload object — the value mapped to <see cref="EventType"/>.</summary>
    public required IReadOnlyDictionary<string, object> Payload { get; init; }
}
