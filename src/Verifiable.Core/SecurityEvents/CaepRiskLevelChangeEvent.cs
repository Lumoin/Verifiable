using System;
using System.Collections.Generic;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The claim names of the CAEP <c>risk-level-change</c> event (CAEP 1.0 §3.8.1).
/// </summary>
public static class CaepRiskLevelChangeClaimNames
{
    /// <summary>The UTF-8 source literal of <see cref="RiskReason"/>.</summary>
    public static ReadOnlySpan<byte> RiskReasonUtf8 => "risk_reason"u8;

    /// <summary><c>risk_reason</c> — RECOMMENDED; the reason that contributed to the change.</summary>
    public static readonly string RiskReason = Utf8Constants.ToInternedString(RiskReasonUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Principal"/>.</summary>
    public static ReadOnlySpan<byte> PrincipalUtf8 => "principal"u8;

    /// <summary><c>principal</c> — REQUIRED; see <see cref="CaepRiskPrincipalValues"/>.</summary>
    public static readonly string Principal = Utf8Constants.ToInternedString(PrincipalUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CurrentLevel"/>.</summary>
    public static ReadOnlySpan<byte> CurrentLevelUtf8 => "current_level"u8;

    /// <summary><c>current_level</c> — REQUIRED; one of <see cref="CaepRiskLevelValues"/>.</summary>
    public static readonly string CurrentLevel = Utf8Constants.ToInternedString(CurrentLevelUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PreviousLevel"/>.</summary>
    public static ReadOnlySpan<byte> PreviousLevelUtf8 => "previous_level"u8;

    /// <summary><c>previous_level</c> — OPTIONAL; omitted means the previous level is unknown to the Transmitter.</summary>
    public static readonly string PreviousLevel = Utf8Constants.ToInternedString(PreviousLevelUtf8);
}


/// <summary>
/// The <c>principal</c> values CAEP 1.0 §3.8.1 enumerates. The set is OPEN —
/// "or any other entity as defined in Section 2 of [SSF]" is also valid — so
/// there is deliberately no IsAllowed gate.
/// </summary>
public static class CaepRiskPrincipalValues
{
    /// <summary>The UTF-8 source literal of <see cref="User"/>.</summary>
    public static ReadOnlySpan<byte> UserUtf8 => "USER"u8;

    /// <summary><c>USER</c>.</summary>
    public static readonly string User = Utf8Constants.ToInternedString(UserUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Device"/>.</summary>
    public static ReadOnlySpan<byte> DeviceUtf8 => "DEVICE"u8;

    /// <summary><c>DEVICE</c>.</summary>
    public static readonly string Device = Utf8Constants.ToInternedString(DeviceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Session"/>.</summary>
    public static ReadOnlySpan<byte> SessionUtf8 => "SESSION"u8;

    /// <summary><c>SESSION</c>.</summary>
    public static readonly string Session = Utf8Constants.ToInternedString(SessionUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Tenant"/>.</summary>
    public static ReadOnlySpan<byte> TenantUtf8 => "TENANT"u8;

    /// <summary><c>TENANT</c>.</summary>
    public static readonly string Tenant = Utf8Constants.ToInternedString(TenantUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OrgUnit"/>.</summary>
    public static ReadOnlySpan<byte> OrgUnitUtf8 => "ORG_UNIT"u8;

    /// <summary><c>ORG_UNIT</c>.</summary>
    public static readonly string OrgUnit = Utf8Constants.ToInternedString(OrgUnitUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Group"/>.</summary>
    public static ReadOnlySpan<byte> GroupUtf8 => "GROUP"u8;

    /// <summary><c>GROUP</c>.</summary>
    public static readonly string Group = Utf8Constants.ToInternedString(GroupUtf8);
}


/// <summary>
/// The allowed risk level values (CAEP 1.0 §3.8.1) — a closed set for both
/// <c>current_level</c> and <c>previous_level</c>.
/// </summary>
public static class CaepRiskLevelValues
{
    /// <summary>The UTF-8 source literal of <see cref="Low"/>.</summary>
    public static ReadOnlySpan<byte> LowUtf8 => "LOW"u8;

    /// <summary><c>LOW</c>.</summary>
    public static readonly string Low = Utf8Constants.ToInternedString(LowUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Medium"/>.</summary>
    public static ReadOnlySpan<byte> MediumUtf8 => "MEDIUM"u8;

    /// <summary><c>MEDIUM</c>.</summary>
    public static readonly string Medium = Utf8Constants.ToInternedString(MediumUtf8);

    /// <summary>The UTF-8 source literal of <see cref="High"/>.</summary>
    public static ReadOnlySpan<byte> HighUtf8 => "HIGH"u8;

    /// <summary><c>HIGH</c>.</summary>
    public static readonly string High = Utf8Constants.ToInternedString(HighUtf8);


    /// <summary>Whether <paramref name="value"/> is one of the three allowed values.</summary>
    public static bool IsAllowed(string value) => Equals(value, Low) || Equals(value, Medium) || Equals(value, High);


    /// <summary>Compares two values for equality (case-sensitive).</summary>
    public static bool Equals(string valueA, string valueB) =>
        object.ReferenceEquals(valueA, valueB) || StringComparer.Ordinal.Equals(valueA, valueB);
}


/// <summary>
/// The typed view of a CAEP <c>risk-level-change</c> event (CAEP 1.0 §3.8):
/// the Transmitter's assessed risk level for the subject changed at the time
/// given by the common <c>event_timestamp</c>.
/// </summary>
public sealed record CaepRiskLevelChangeEvent
{
    /// <summary>The REQUIRED <c>principal</c> — an open set; see <see cref="CaepRiskPrincipalValues"/>.</summary>
    public required string Principal { get; init; }

    /// <summary>The REQUIRED <c>current_level</c> — one of <see cref="CaepRiskLevelValues"/>.</summary>
    public required string CurrentLevel { get; init; }

    /// <summary>
    /// The OPTIONAL <c>previous_level</c>; <see langword="null"/> means the
    /// previous level is unknown to the Transmitter (§3.8.1).
    /// </summary>
    public string? PreviousLevel { get; init; }

    /// <summary>The RECOMMENDED <c>risk_reason</c>.</summary>
    public string? RiskReason { get; init; }

    /// <summary>The common CAEP claims (§2); never <see langword="null"/>.</summary>
    public CaepEventClaims Common { get; init; } = CaepEventClaims.Empty;


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not <c>risk-level-change</c>,
    /// a REQUIRED claim is absent or not a string, or a level value is outside
    /// the closed LOW/MEDIUM/HIGH set.
    /// </summary>
    public static CaepRiskLevelChangeEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!CaepEventTypes.IsRiskLevelChange(securityEvent.EventType))
        {
            return null;
        }

        IReadOnlyDictionary<string, object> payload = securityEvent.Payload;
        if(!payload.TryGetValue(CaepRiskLevelChangeClaimNames.Principal, out object? principalValue)
            || principalValue is not string principal
            || principal.Length == 0)
        {
            return null;
        }

        if(!payload.TryGetValue(CaepRiskLevelChangeClaimNames.CurrentLevel, out object? currentValue)
            || currentValue is not string currentLevel
            || !CaepRiskLevelValues.IsAllowed(currentLevel))
        {
            return null;
        }

        //previous_level is OPTIONAL but closed when present (§3.8.1: "Value
        //MUST be one of LOW, MEDIUM, HIGH").
        string? previousLevel = EventPayloadReading.ReadOptionalString(
            payload, CaepRiskLevelChangeClaimNames.PreviousLevel);
        if(payload.ContainsKey(CaepRiskLevelChangeClaimNames.PreviousLevel)
            && (previousLevel is null || !CaepRiskLevelValues.IsAllowed(previousLevel)))
        {
            return null;
        }

        return new CaepRiskLevelChangeEvent
        {
            Principal = principal,
            CurrentLevel = currentLevel,
            PreviousLevel = previousLevel,
            RiskReason = EventPayloadReading.ReadOptionalString(payload, CaepRiskLevelChangeClaimNames.RiskReason),
            Common = CaepEventClaims.From(payload)
        };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [CaepRiskLevelChangeClaimNames.Principal] = Principal,
            [CaepRiskLevelChangeClaimNames.CurrentLevel] = CurrentLevel
        };

        if(PreviousLevel is not null)
        {
            payload[CaepRiskLevelChangeClaimNames.PreviousLevel] = PreviousLevel;
        }

        if(RiskReason is not null)
        {
            payload[CaepRiskLevelChangeClaimNames.RiskReason] = RiskReason;
        }

        Common.WriteTo(payload);

        return new SecurityEvent { EventType = CaepEventTypes.RiskLevelChange, Payload = payload };
    }
}
