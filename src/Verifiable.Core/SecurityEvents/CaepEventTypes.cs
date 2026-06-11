using System;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The event-type URIs defined by the OpenID Continuous Access Evaluation
/// Profile (CAEP) 1.0 §3. A CAEP event appears as a member of a Security Event
/// Token's <c>events</c> claim, keyed by one of these URIs.
/// </summary>
/// <remarks>
/// These are the URI NAMES that key the <c>events</c> map; the per-event payload
/// fields (and the common optional claims of CAEP §2) are interpreted from the
/// mapped value. CAEP events also reuse the Shared Signals subject model.
/// </remarks>
public static class CaepEventTypes
{
    //The family prefix the StartsWith membership predicate matches on; every member's
    //full URI literal below carries it verbatim (a test pins the coherence).
    private const string Prefix = "https://schemas.openid.net/secevent/caep/event-type/";

    /// <summary>The UTF-8 source literal of <see cref="SessionRevoked"/>.</summary>
    public static ReadOnlySpan<byte> SessionRevokedUtf8 => "https://schemas.openid.net/secevent/caep/event-type/session-revoked"u8;

    /// <summary>Session Revoked (<c>session-revoked</c>) — CAEP §3.1.</summary>
    public static readonly string SessionRevoked = Utf8Constants.ToInternedString(SessionRevokedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TokenClaimsChange"/>.</summary>
    public static ReadOnlySpan<byte> TokenClaimsChangeUtf8 => "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"u8;

    /// <summary>Token Claims Change (<c>token-claims-change</c>) — CAEP §3.2.</summary>
    public static readonly string TokenClaimsChange = Utf8Constants.ToInternedString(TokenClaimsChangeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialChange"/>.</summary>
    public static ReadOnlySpan<byte> CredentialChangeUtf8 => "https://schemas.openid.net/secevent/caep/event-type/credential-change"u8;

    /// <summary>Credential Change (<c>credential-change</c>) — CAEP §3.3.</summary>
    public static readonly string CredentialChange = Utf8Constants.ToInternedString(CredentialChangeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AssuranceLevelChange"/>.</summary>
    public static ReadOnlySpan<byte> AssuranceLevelChangeUtf8 => "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"u8;

    /// <summary>Assurance Level Change (<c>assurance-level-change</c>) — CAEP §3.4.</summary>
    public static readonly string AssuranceLevelChange = Utf8Constants.ToInternedString(AssuranceLevelChangeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DeviceComplianceChange"/>.</summary>
    public static ReadOnlySpan<byte> DeviceComplianceChangeUtf8 => "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"u8;

    /// <summary>Device Compliance Change (<c>device-compliance-change</c>) — CAEP §3.5.</summary>
    public static readonly string DeviceComplianceChange = Utf8Constants.ToInternedString(DeviceComplianceChangeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SessionEstablished"/>.</summary>
    public static ReadOnlySpan<byte> SessionEstablishedUtf8 => "https://schemas.openid.net/secevent/caep/event-type/session-established"u8;

    /// <summary>Session Established (<c>session-established</c>) — CAEP §3.6.</summary>
    public static readonly string SessionEstablished = Utf8Constants.ToInternedString(SessionEstablishedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SessionPresented"/>.</summary>
    public static ReadOnlySpan<byte> SessionPresentedUtf8 => "https://schemas.openid.net/secevent/caep/event-type/session-presented"u8;

    /// <summary>Session Presented (<c>session-presented</c>) — CAEP §3.7.</summary>
    public static readonly string SessionPresented = Utf8Constants.ToInternedString(SessionPresentedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RiskLevelChange"/>.</summary>
    public static ReadOnlySpan<byte> RiskLevelChangeUtf8 => "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"u8;

    /// <summary>Risk Level Change (<c>risk-level-change</c>) — CAEP §3.8.</summary>
    public static readonly string RiskLevelChange = Utf8Constants.ToInternedString(RiskLevelChangeUtf8);


    /// <summary>Whether <paramref name="eventType"/> is <see cref="SessionRevoked"/>.</summary>
    public static bool IsSessionRevoked(string eventType) => Equals(eventType, SessionRevoked);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="TokenClaimsChange"/>.</summary>
    public static bool IsTokenClaimsChange(string eventType) => Equals(eventType, TokenClaimsChange);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="CredentialChange"/>.</summary>
    public static bool IsCredentialChange(string eventType) => Equals(eventType, CredentialChange);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="AssuranceLevelChange"/>.</summary>
    public static bool IsAssuranceLevelChange(string eventType) => Equals(eventType, AssuranceLevelChange);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="DeviceComplianceChange"/>.</summary>
    public static bool IsDeviceComplianceChange(string eventType) => Equals(eventType, DeviceComplianceChange);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="SessionEstablished"/>.</summary>
    public static bool IsSessionEstablished(string eventType) => Equals(eventType, SessionEstablished);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="SessionPresented"/>.</summary>
    public static bool IsSessionPresented(string eventType) => Equals(eventType, SessionPresented);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="RiskLevelChange"/>.</summary>
    public static bool IsRiskLevelChange(string eventType) => Equals(eventType, RiskLevelChange);

    /// <summary>Whether <paramref name="eventType"/> is any CAEP event-type URI.</summary>
    public static bool IsCaepEventType(string eventType) =>
        eventType is not null && eventType.StartsWith(Prefix, System.StringComparison.Ordinal);


    /// <summary>
    /// Returns the interned constant for a known CAEP event-type URI, or the original
    /// string if unrecognized.
    /// </summary>
    public static string GetCanonicalizedValue(string eventType) => eventType switch
    {
        _ when IsSessionRevoked(eventType) => SessionRevoked,
        _ when IsTokenClaimsChange(eventType) => TokenClaimsChange,
        _ when IsCredentialChange(eventType) => CredentialChange,
        _ when IsAssuranceLevelChange(eventType) => AssuranceLevelChange,
        _ when IsDeviceComplianceChange(eventType) => DeviceComplianceChange,
        _ when IsSessionEstablished(eventType) => SessionEstablished,
        _ when IsSessionPresented(eventType) => SessionPresented,
        _ when IsRiskLevelChange(eventType) => RiskLevelChange,
        _ => eventType
    };


    /// <summary>Compares two event-type URIs for equality (case-sensitive).</summary>
    public static bool Equals(string eventTypeA, string eventTypeB) =>
        object.ReferenceEquals(eventTypeA, eventTypeB) || System.StringComparer.Ordinal.Equals(eventTypeA, eventTypeB);
}
