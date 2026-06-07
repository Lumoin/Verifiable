using System;
using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The claim names of the CAEP <c>assurance-level-change</c> event (CAEP 1.0 §3.4.1).
/// </summary>
public static class CaepAssuranceLevelChangeClaimNames
{
    /// <summary><c>namespace</c> — REQUIRED; see <see cref="CaepAssuranceNamespaceValues"/>.</summary>
    public static readonly string Namespace = "namespace";

    /// <summary><c>current_level</c> — REQUIRED; the current assurance level in the namespace.</summary>
    public static readonly string CurrentLevel = "current_level";

    /// <summary><c>previous_level</c> — OPTIONAL; omitted means the previous level is unknown to the Transmitter.</summary>
    public static readonly string PreviousLevel = "previous_level";

    /// <summary><c>change_direction</c> — OPTIONAL; see <see cref="CaepChangeDirectionValues"/>.</summary>
    public static readonly string ChangeDirection = "change_direction";
}


/// <summary>
/// The <c>namespace</c> values CAEP 1.0 §3.4.1 enumerates. The set is OPEN —
/// "any other value that is an alias for a custom namespace agreed between the
/// Transmitter and the Receiver" is also valid — so there is deliberately no
/// IsAllowed gate.
/// </summary>
public static class CaepAssuranceNamespaceValues
{
    /// <summary><c>RFC8176</c> — Authentication Method Reference values.</summary>
    public static readonly string Rfc8176 = "RFC8176";

    /// <summary><c>RFC6711</c> — IANA Level of Assurance profiles.</summary>
    public static readonly string Rfc6711 = "RFC6711";

    /// <summary><c>ISO-IEC-29115</c> — entity authentication assurance framework.</summary>
    public static readonly string IsoIec29115 = "ISO-IEC-29115";

    /// <summary><c>NIST-IAL</c> — NIST SP 800-63A identity assurance levels.</summary>
    public static readonly string NistIal = "NIST-IAL";

    /// <summary><c>NIST-AAL</c> — NIST SP 800-63B authenticator assurance levels.</summary>
    public static readonly string NistAal = "NIST-AAL";

    /// <summary><c>NIST-FAL</c> — NIST SP 800-63C federation assurance levels.</summary>
    public static readonly string NistFal = "NIST-FAL";
}


/// <summary>
/// The allowed <c>change_direction</c> values (CAEP 1.0 §3.4.1) — a closed set
/// when the claim is present.
/// </summary>
public static class CaepChangeDirectionValues
{
    /// <summary><c>increase</c> — the assurance level increased.</summary>
    public static readonly string Increase = "increase";

    /// <summary><c>decrease</c> — the assurance level decreased.</summary>
    public static readonly string Decrease = "decrease";


    /// <summary>Whether <paramref name="value"/> is one of the two allowed values.</summary>
    public static bool IsAllowed(string value) => Equals(value, Increase) || Equals(value, Decrease);


    /// <summary>Compares two values for equality (case-sensitive).</summary>
    public static bool Equals(string valueA, string valueB) =>
        object.ReferenceEquals(valueA, valueB) || StringComparer.Ordinal.Equals(valueA, valueB);
}


/// <summary>
/// The typed view of a CAEP <c>assurance-level-change</c> event (CAEP 1.0 §3.4):
/// the authentication method changed since the initial login, raising or
/// lowering the assurance level. When the common <c>event_timestamp</c> is
/// present it is the time the level changed.
/// </summary>
public sealed record CaepAssuranceLevelChangeEvent
{
    /// <summary>The REQUIRED <c>namespace</c> — an open set; see <see cref="CaepAssuranceNamespaceValues"/>.</summary>
    public required string Namespace { get; init; }

    /// <summary>The REQUIRED <c>current_level</c>, defined in <see cref="Namespace"/>.</summary>
    public required string CurrentLevel { get; init; }

    /// <summary>
    /// The OPTIONAL <c>previous_level</c>; <see langword="null"/> means the
    /// previous level is unknown to the Transmitter (§3.4.1).
    /// </summary>
    public string? PreviousLevel { get; init; }

    /// <summary>The OPTIONAL <c>change_direction</c> — one of <see cref="CaepChangeDirectionValues"/> when present.</summary>
    public string? ChangeDirection { get; init; }

    /// <summary>The common CAEP claims (§2); never <see langword="null"/>.</summary>
    public CaepEventClaims Common { get; init; } = CaepEventClaims.Empty;


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not
    /// <c>assurance-level-change</c>, a REQUIRED claim is absent or not a
    /// string, or a present <c>change_direction</c> is outside its closed set.
    /// </summary>
    public static CaepAssuranceLevelChangeEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!CaepEventTypes.IsAssuranceLevelChange(securityEvent.EventType))
        {
            return null;
        }

        IReadOnlyDictionary<string, object> payload = securityEvent.Payload;
        if(!payload.TryGetValue(CaepAssuranceLevelChangeClaimNames.Namespace, out object? namespaceValue)
            || namespaceValue is not string levelNamespace
            || levelNamespace.Length == 0)
        {
            return null;
        }

        if(!payload.TryGetValue(CaepAssuranceLevelChangeClaimNames.CurrentLevel, out object? currentValue)
            || currentValue is not string currentLevel
            || currentLevel.Length == 0)
        {
            return null;
        }

        //change_direction is OPTIONAL but closed when present (§3.4.1: "If
        //present, this MUST be one of the following strings").
        string? changeDirection = EventPayloadReading.ReadOptionalString(
            payload, CaepAssuranceLevelChangeClaimNames.ChangeDirection);
        if(payload.ContainsKey(CaepAssuranceLevelChangeClaimNames.ChangeDirection)
            && (changeDirection is null || !CaepChangeDirectionValues.IsAllowed(changeDirection)))
        {
            return null;
        }

        return new CaepAssuranceLevelChangeEvent
        {
            Namespace = levelNamespace,
            CurrentLevel = currentLevel,
            PreviousLevel = EventPayloadReading.ReadOptionalString(payload, CaepAssuranceLevelChangeClaimNames.PreviousLevel),
            ChangeDirection = changeDirection,
            Common = CaepEventClaims.From(payload)
        };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [CaepAssuranceLevelChangeClaimNames.Namespace] = Namespace,
            [CaepAssuranceLevelChangeClaimNames.CurrentLevel] = CurrentLevel
        };

        if(PreviousLevel is not null)
        {
            payload[CaepAssuranceLevelChangeClaimNames.PreviousLevel] = PreviousLevel;
        }

        if(ChangeDirection is not null)
        {
            payload[CaepAssuranceLevelChangeClaimNames.ChangeDirection] = ChangeDirection;
        }

        Common.WriteTo(payload);

        return new SecurityEvent { EventType = CaepEventTypes.AssuranceLevelChange, Payload = payload };
    }
}
