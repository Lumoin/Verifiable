using System;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// Transmitter-side checks for the CAEP Interoperability Profile 1.0: the
/// <c>events</c> claim MUST contain only one event, the event MUST be one of
/// the profile's three use-case types (<c>session-revoked</c>,
/// <c>credential-change</c>, <c>device-compliance-change</c>) with its REQUIRED
/// event-specific claims present and valid, and a Transmitter MUST populate
/// <c>reason_admin</c> with a non-empty object.
/// </summary>
/// <remarks>
/// These are profile checks layered over the base CAEP event definitions —
/// the base spec leaves <c>reason_admin</c> optional and does not bound the
/// event count. Receivers stay tolerant; this gate is for what a conforming
/// Transmitter emits.
/// </remarks>
public static class CaepInteropProfile
{
    /// <summary>
    /// Whether <paramref name="securityEvent"/> is one a conforming Transmitter
    /// may emit: a profile use-case event whose REQUIRED claims project and
    /// whose <c>reason_admin</c> is a non-empty object.
    /// </summary>
    public static bool IsConformantTransmitterEvent(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        CaepEventClaims? common = securityEvent.EventType switch
        {
            _ when CaepEventTypes.IsSessionRevoked(securityEvent.EventType) =>
                CaepSessionRevokedEvent.From(securityEvent)?.Common,
            _ when CaepEventTypes.IsCredentialChange(securityEvent.EventType) =>
                CaepCredentialChangeEvent.From(securityEvent)?.Common,
            _ when CaepEventTypes.IsDeviceComplianceChange(securityEvent.EventType) =>
                CaepDeviceComplianceChangeEvent.From(securityEvent)?.Common,
            _ => null
        };

        return common is { ReasonAdmin.Count: > 0 };
    }


    /// <summary>
    /// Whether <paramref name="token"/> is one a conforming Transmitter may
    /// emit: exactly one event, and that event passes
    /// <see cref="IsConformantTransmitterEvent"/>.
    /// </summary>
    public static bool IsConformantTransmitterToken(SecurityEventToken token)
    {
        ArgumentNullException.ThrowIfNull(token);

        return token.Events.Count == 1 && IsConformantTransmitterEvent(token.Events[0]);
    }
}
