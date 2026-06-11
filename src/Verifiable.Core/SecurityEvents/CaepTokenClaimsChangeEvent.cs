using System;
using System.Collections.Generic;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The claim names of the CAEP <c>token-claims-change</c> event (CAEP 1.0 §3.2.1).
/// </summary>
public static class CaepTokenClaimsChangeClaimNames
{
    /// <summary>The UTF-8 source literal of <see cref="Claims"/>.</summary>
    public static ReadOnlySpan<byte> ClaimsUtf8 => "claims"u8;

    /// <summary><c>claims</c> — REQUIRED; one or more claims with their new value(s).</summary>
    public static readonly string Claims = Utf8Constants.ToInternedString(ClaimsUtf8);
}


/// <summary>
/// The typed view of a CAEP <c>token-claims-change</c> event (CAEP 1.0 §3.2):
/// a claim in a token identified by the subject has changed. When the common
/// <c>event_timestamp</c> is present it is the time the claim value(s) changed.
/// </summary>
public sealed record CaepTokenClaimsChangeEvent
{
    /// <summary>
    /// The REQUIRED <c>claims</c> object — one or more claims with their new
    /// value(s), in the parsed payload shapes.
    /// </summary>
    public required IReadOnlyDictionary<string, object> Claims { get; init; }

    /// <summary>The common CAEP claims (§2); never <see langword="null"/>.</summary>
    public CaepEventClaims Common { get; init; } = CaepEventClaims.Empty;


    /// <summary>
    /// Value equality: the <see cref="Claims"/> map compares by content with
    /// per-entry value equality (sufficient for the string/number leaves;
    /// nested structures compare by reference).
    /// </summary>
    public bool Equals(CaepTokenClaimsChangeEvent? other)
    {
        if(other is null || !Common.Equals(other.Common) || Claims.Count != other.Claims.Count)
        {
            return false;
        }

        foreach(KeyValuePair<string, object> entry in Claims)
        {
            if(!other.Claims.TryGetValue(entry.Key, out object? value) || !Equals(entry.Value, value))
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(Common, Claims.Count);


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not
    /// <c>token-claims-change</c> or the REQUIRED <c>claims</c> member is
    /// absent, not an object, or empty ("one or more claims").
    /// </summary>
    public static CaepTokenClaimsChangeEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!CaepEventTypes.IsTokenClaimsChange(securityEvent.EventType))
        {
            return null;
        }

        if(!securityEvent.Payload.TryGetValue(CaepTokenClaimsChangeClaimNames.Claims, out object? claimsValue)
            || claimsValue is not IReadOnlyDictionary<string, object> claims
            || claims.Count == 0)
        {
            return null;
        }

        return new CaepTokenClaimsChangeEvent
        {
            Claims = claims,
            Common = CaepEventClaims.From(securityEvent.Payload)
        };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var changed = new Dictionary<string, object>(Claims.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> entry in Claims)
        {
            changed[entry.Key] = entry.Value;
        }

        var payload = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [CaepTokenClaimsChangeClaimNames.Claims] = changed
        };

        Common.WriteTo(payload);

        return new SecurityEvent { EventType = CaepEventTypes.TokenClaimsChange, Payload = payload };
    }
}
