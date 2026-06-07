using System;
using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The claim names of the CAEP <c>risk-level-change</c> event (CAEP 1.0 §3.8.1).
/// </summary>
public static class CaepRiskLevelChangeClaimNames
{
    /// <summary><c>risk_reason</c> — RECOMMENDED; the reason that contributed to the change.</summary>
    public static readonly string RiskReason = "risk_reason";

    /// <summary><c>principal</c> — REQUIRED; see <see cref="CaepRiskPrincipalValues"/>.</summary>
    public static readonly string Principal = "principal";

    /// <summary><c>current_level</c> — REQUIRED; one of <see cref="CaepRiskLevelValues"/>.</summary>
    public static readonly string CurrentLevel = "current_level";

    /// <summary><c>previous_level</c> — OPTIONAL; omitted means the previous level is unknown to the Transmitter.</summary>
    public static readonly string PreviousLevel = "previous_level";
}


/// <summary>
/// The <c>principal</c> values CAEP 1.0 §3.8.1 enumerates. The set is OPEN —
/// "or any other entity as defined in Section 2 of [SSF]" is also valid — so
/// there is deliberately no IsAllowed gate.
/// </summary>
public static class CaepRiskPrincipalValues
{
    /// <summary><c>USER</c>.</summary>
    public static readonly string User = "USER";

    /// <summary><c>DEVICE</c>.</summary>
    public static readonly string Device = "DEVICE";

    /// <summary><c>SESSION</c>.</summary>
    public static readonly string Session = "SESSION";

    /// <summary><c>TENANT</c>.</summary>
    public static readonly string Tenant = "TENANT";

    /// <summary><c>ORG_UNIT</c>.</summary>
    public static readonly string OrgUnit = "ORG_UNIT";

    /// <summary><c>GROUP</c>.</summary>
    public static readonly string Group = "GROUP";
}


/// <summary>
/// The allowed risk level values (CAEP 1.0 §3.8.1) — a closed set for both
/// <c>current_level</c> and <c>previous_level</c>.
/// </summary>
public static class CaepRiskLevelValues
{
    /// <summary><c>LOW</c>.</summary>
    public static readonly string Low = "LOW";

    /// <summary><c>MEDIUM</c>.</summary>
    public static readonly string Medium = "MEDIUM";

    /// <summary><c>HIGH</c>.</summary>
    public static readonly string High = "HIGH";


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
