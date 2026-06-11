using System;
using System.Collections.Generic;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The claim NAMES every CAEP event may carry (CAEP 1.0 §2) — optional unless an
/// event definition says otherwise.
/// </summary>
public static class CaepEventClaimNames
{
    /// <summary>The UTF-8 source literal of <see cref="EventTimestamp"/>.</summary>
    public static ReadOnlySpan<byte> EventTimestampUtf8 => "event_timestamp"u8;

    /// <summary><c>event_timestamp</c> — when the described change occurred, as Unix seconds.</summary>
    public static readonly string EventTimestamp = Utf8Constants.ToInternedString(EventTimestampUtf8);

    /// <summary>The UTF-8 source literal of <see cref="InitiatingEntity"/>.</summary>
    public static ReadOnlySpan<byte> InitiatingEntityUtf8 => "initiating_entity"u8;

    /// <summary><c>initiating_entity</c> — who invoked the event; see <see cref="CaepInitiatingEntityValues"/>.</summary>
    public static readonly string InitiatingEntity = Utf8Constants.ToInternedString(InitiatingEntityUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ReasonAdmin"/>.</summary>
    public static ReadOnlySpan<byte> ReasonAdminUtf8 => "reason_admin"u8;

    /// <summary><c>reason_admin</c> — a BCP47-keyed localizable administrative message object.</summary>
    public static readonly string ReasonAdmin = Utf8Constants.ToInternedString(ReasonAdminUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ReasonUser"/>.</summary>
    public static ReadOnlySpan<byte> ReasonUserUtf8 => "reason_user"u8;

    /// <summary><c>reason_user</c> — a BCP47-keyed localizable end-user message object.</summary>
    public static readonly string ReasonUser = Utf8Constants.ToInternedString(ReasonUserUtf8);
}


/// <summary>
/// The allowed <c>initiating_entity</c> values (CAEP 1.0 §2).
/// </summary>
public static class CaepInitiatingEntityValues
{
    /// <summary>The UTF-8 source literal of <see cref="Admin"/>.</summary>
    public static ReadOnlySpan<byte> AdminUtf8 => "admin"u8;

    /// <summary><c>admin</c> — an administrative action triggered the event.</summary>
    public static readonly string Admin = Utf8Constants.ToInternedString(AdminUtf8);

    /// <summary>The UTF-8 source literal of <see cref="User"/>.</summary>
    public static ReadOnlySpan<byte> UserUtf8 => "user"u8;

    /// <summary><c>user</c> — an end-user action triggered the event.</summary>
    public static readonly string User = Utf8Constants.ToInternedString(UserUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Policy"/>.</summary>
    public static ReadOnlySpan<byte> PolicyUtf8 => "policy"u8;

    /// <summary><c>policy</c> — a policy evaluation triggered the event.</summary>
    public static readonly string Policy = Utf8Constants.ToInternedString(PolicyUtf8);

    /// <summary>The UTF-8 source literal of <see cref="System"/>.</summary>
    public static ReadOnlySpan<byte> SystemUtf8 => "system"u8;

    /// <summary><c>system</c> — a system or platform assertion triggered the event.</summary>
    public static readonly string System = Utf8Constants.ToInternedString(SystemUtf8);


    /// <summary>Whether <paramref name="value"/> is one of the four allowed values.</summary>
    public static bool IsAllowed(string value) =>
        Equals(value, Admin) || Equals(value, User) || Equals(value, Policy) || Equals(value, System);


    /// <summary>Compares two values for equality (case-sensitive).</summary>
    public static bool Equals(string valueA, string valueB) =>
        object.ReferenceEquals(valueA, valueB) || StringComparer.Ordinal.Equals(valueA, valueB);
}


/// <summary>
/// The typed view of the common, optional CAEP event claims (CAEP 1.0 §2),
/// shared by every CAEP event record.
/// </summary>
/// <remarks>
/// Projection is tolerant for these OPTIONAL members: an absent or wrongly-typed
/// member is <see langword="null"/>. The REQUIRED event-specific members are
/// validated strictly by each event record's own projection instead.
/// </remarks>
public sealed record CaepEventClaims
{
    /// <summary>An empty claim set — every member absent.</summary>
    public static CaepEventClaims Empty { get; } = new();

    /// <summary>The <c>event_timestamp</c>; <see langword="null"/> if absent.</summary>
    public DateTimeOffset? EventTimestamp { get; init; }

    /// <summary>The <c>initiating_entity</c>; <see langword="null"/> if absent.</summary>
    public string? InitiatingEntity { get; init; }

    /// <summary>The <c>reason_admin</c> BCP47-keyed messages; <see langword="null"/> if absent.</summary>
    public IReadOnlyDictionary<string, string>? ReasonAdmin { get; init; }

    /// <summary>The <c>reason_user</c> BCP47-keyed messages; <see langword="null"/> if absent.</summary>
    public IReadOnlyDictionary<string, string>? ReasonUser { get; init; }


    /// <summary>
    /// Value equality: the localizable message maps compare by content, not by
    /// reference, so a built claim set equals its wire round-trip.
    /// </summary>
    public bool Equals(CaepEventClaims? other) =>
        other is not null
        && EventTimestamp == other.EventTimestamp
        && string.Equals(InitiatingEntity, other.InitiatingEntity, StringComparison.Ordinal)
        && EventPayloadReading.MapsEqual(ReasonAdmin, other.ReasonAdmin)
        && EventPayloadReading.MapsEqual(ReasonUser, other.ReasonUser);


    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(EventTimestamp, InitiatingEntity, ReasonAdmin?.Count ?? -1, ReasonUser?.Count ?? -1);


    /// <summary>Projects the common claims out of an event payload.</summary>
    public static CaepEventClaims From(IReadOnlyDictionary<string, object> payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        return new CaepEventClaims
        {
            EventTimestamp = EventPayloadReading.ReadUnixSeconds(payload, CaepEventClaimNames.EventTimestamp),
            InitiatingEntity = EventPayloadReading.ReadOptionalString(payload, CaepEventClaimNames.InitiatingEntity),
            ReasonAdmin = EventPayloadReading.ReadLocalizableMap(payload, CaepEventClaimNames.ReasonAdmin),
            ReasonUser = EventPayloadReading.ReadLocalizableMap(payload, CaepEventClaimNames.ReasonUser)
        };
    }


    /// <summary>Writes the present members into <paramref name="payload"/> as wire values.</summary>
    public void WriteTo(IDictionary<string, object> payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        if(EventTimestamp is DateTimeOffset timestamp)
        {
            payload[CaepEventClaimNames.EventTimestamp] = timestamp.ToUnixTimeSeconds();
        }

        if(InitiatingEntity is not null)
        {
            payload[CaepEventClaimNames.InitiatingEntity] = InitiatingEntity;
        }

        if(ReasonAdmin is { Count: > 0 })
        {
            payload[CaepEventClaimNames.ReasonAdmin] = EventPayloadReading.ToWireMap(ReasonAdmin);
        }

        if(ReasonUser is { Count: > 0 })
        {
            payload[CaepEventClaimNames.ReasonUser] = EventPayloadReading.ToWireMap(ReasonUser);
        }
    }
}
