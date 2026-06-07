using System;
using System.Collections.Generic;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The typed view of a CAEP <c>session-revoked</c> event (CAEP 1.0 §3.1):
/// the subject's session was revoked. The event carries no event-specific
/// claims (§3.1.1) — only the common set, where <c>event_timestamp</c>, if
/// present, is the time the revocation occurred.
/// </summary>
public sealed record CaepSessionRevokedEvent
{
    /// <summary>The common CAEP claims (§2); never <see langword="null"/>.</summary>
    public CaepEventClaims Common { get; init; } = CaepEventClaims.Empty;


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not <c>session-revoked</c>.
    /// </summary>
    public static CaepSessionRevokedEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!CaepEventTypes.IsSessionRevoked(securityEvent.EventType))
        {
            return null;
        }

        return new CaepSessionRevokedEvent { Common = CaepEventClaims.From(securityEvent.Payload) };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal);
        Common.WriteTo(payload);

        return new SecurityEvent { EventType = CaepEventTypes.SessionRevoked, Payload = payload };
    }
}
