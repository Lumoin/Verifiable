using System;
using System.Collections.Generic;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The claim names of the CAEP <c>device-compliance-change</c> event (CAEP 1.0 §3.5.1).
/// </summary>
public static class CaepDeviceComplianceClaimNames
{
    /// <summary>The UTF-8 source literal of <see cref="PreviousStatus"/>.</summary>
    public static ReadOnlySpan<byte> PreviousStatusUtf8 => "previous_status"u8;

    /// <summary><c>previous_status</c> — REQUIRED; the status prior to the change.</summary>
    public static readonly string PreviousStatus = Utf8Constants.ToInternedString(PreviousStatusUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CurrentStatus"/>.</summary>
    public static ReadOnlySpan<byte> CurrentStatusUtf8 => "current_status"u8;

    /// <summary><c>current_status</c> — REQUIRED; the status that triggered the event.</summary>
    public static readonly string CurrentStatus = Utf8Constants.ToInternedString(CurrentStatusUtf8);
}


/// <summary>
/// The allowed device-compliance status values (CAEP 1.0 §3.5.1) — a closed set.
/// </summary>
public static class CaepComplianceStatusValues
{
    /// <summary>The UTF-8 source literal of <see cref="Compliant"/>.</summary>
    public static ReadOnlySpan<byte> CompliantUtf8 => "compliant"u8;

    /// <summary><c>compliant</c>.</summary>
    public static readonly string Compliant = Utf8Constants.ToInternedString(CompliantUtf8);

    /// <summary>The UTF-8 source literal of <see cref="NotCompliant"/>.</summary>
    public static ReadOnlySpan<byte> NotCompliantUtf8 => "not-compliant"u8;

    /// <summary><c>not-compliant</c>.</summary>
    public static readonly string NotCompliant = Utf8Constants.ToInternedString(NotCompliantUtf8);


    /// <summary>Whether <paramref name="value"/> is one of the two allowed values.</summary>
    public static bool IsAllowed(string value) => Equals(value, Compliant) || Equals(value, NotCompliant);


    /// <summary>Compares two values for equality (case-sensitive).</summary>
    public static bool Equals(string valueA, string valueB) =>
        object.ReferenceEquals(valueA, valueB) || StringComparer.Ordinal.Equals(valueA, valueB);
}


/// <summary>
/// The typed view of a CAEP <c>device-compliance-change</c> event (CAEP 1.0 §3.5):
/// a device's compliance status changed. When the common <c>event_timestamp</c>
/// is present it is the time the status changed.
/// </summary>
public sealed record CaepDeviceComplianceChangeEvent
{
    /// <summary>The REQUIRED <c>previous_status</c> — one of <see cref="CaepComplianceStatusValues"/>.</summary>
    public required string PreviousStatus { get; init; }

    /// <summary>The REQUIRED <c>current_status</c> — one of <see cref="CaepComplianceStatusValues"/>.</summary>
    public required string CurrentStatus { get; init; }

    /// <summary>The common CAEP claims (§2); never <see langword="null"/>.</summary>
    public CaepEventClaims Common { get; init; } = CaepEventClaims.Empty;


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not
    /// <c>device-compliance-change</c> or either REQUIRED status is absent,
    /// not a string, or outside the closed value set.
    /// </summary>
    public static CaepDeviceComplianceChangeEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!CaepEventTypes.IsDeviceComplianceChange(securityEvent.EventType))
        {
            return null;
        }

        IReadOnlyDictionary<string, object> payload = securityEvent.Payload;
        if(!payload.TryGetValue(CaepDeviceComplianceClaimNames.PreviousStatus, out object? previousValue)
            || previousValue is not string previousStatus
            || !CaepComplianceStatusValues.IsAllowed(previousStatus))
        {
            return null;
        }

        if(!payload.TryGetValue(CaepDeviceComplianceClaimNames.CurrentStatus, out object? currentValue)
            || currentValue is not string currentStatus
            || !CaepComplianceStatusValues.IsAllowed(currentStatus))
        {
            return null;
        }

        return new CaepDeviceComplianceChangeEvent
        {
            PreviousStatus = previousStatus,
            CurrentStatus = currentStatus,
            Common = CaepEventClaims.From(payload)
        };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [CaepDeviceComplianceClaimNames.PreviousStatus] = PreviousStatus,
            [CaepDeviceComplianceClaimNames.CurrentStatus] = CurrentStatus
        };

        Common.WriteTo(payload);

        return new SecurityEvent { EventType = CaepEventTypes.DeviceComplianceChange, Payload = payload };
    }
}
