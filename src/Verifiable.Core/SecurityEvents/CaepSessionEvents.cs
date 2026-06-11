using System;
using System.Collections.Generic;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The claim names of the CAEP session property events: <c>session-established</c>
/// (CAEP 1.0 §3.6.1) and <c>session-presented</c> (§3.7.1), which share
/// <c>fp_ua</c> and <c>ext_id</c>.
/// </summary>
public static class CaepSessionClaimNames
{
    /// <summary>The UTF-8 source literal of <see cref="FpUa"/>.</summary>
    public static ReadOnlySpan<byte> FpUaUtf8 => "fp_ua"u8;

    /// <summary><c>fp_ua</c> — OPTIONAL; user-agent fingerprint computed by the Transmitter (qualities, not identity).</summary>
    public static readonly string FpUa = Utf8Constants.ToInternedString(FpUaUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Acr"/>.</summary>
    public static ReadOnlySpan<byte> AcrUtf8 => "acr"u8;

    /// <summary><c>acr</c> — OPTIONAL; authentication context class reference, interpreted as in an OIDC ID Token.</summary>
    public static readonly string Acr = Utf8Constants.ToInternedString(AcrUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Amr"/>.</summary>
    public static ReadOnlySpan<byte> AmrUtf8 => "amr"u8;

    /// <summary><c>amr</c> — OPTIONAL; authentication methods reference array, interpreted as in an OIDC ID Token.</summary>
    public static readonly string Amr = Utf8Constants.ToInternedString(AmrUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ExtId"/>.</summary>
    public static ReadOnlySpan<byte> ExtIdUtf8 => "ext_id"u8;

    /// <summary><c>ext_id</c> — OPTIONAL; external session identifier correlating to a broader session.</summary>
    public static readonly string ExtId = Utf8Constants.ToInternedString(ExtIdUtf8);
}


/// <summary>
/// The typed view of a CAEP <c>session-established</c> event (CAEP 1.0 §3.6):
/// the Transmitter established a new session for the subject. All
/// event-specific claims are OPTIONAL; the common <c>event_timestamp</c> is
/// the time the session was established.
/// </summary>
public sealed record CaepSessionEstablishedEvent
{
    /// <summary>The OPTIONAL <c>fp_ua</c> user-agent fingerprint.</summary>
    public string? FpUa { get; init; }

    /// <summary>The OPTIONAL <c>acr</c> of the session.</summary>
    public string? Acr { get; init; }

    /// <summary>The OPTIONAL <c>amr</c> of the session — an array of strings.</summary>
    public IReadOnlyList<string>? Amr { get; init; }

    /// <summary>The OPTIONAL <c>ext_id</c> external session identifier.</summary>
    public string? ExtId { get; init; }

    /// <summary>The common CAEP claims (§2); never <see langword="null"/>.</summary>
    public CaepEventClaims Common { get; init; } = CaepEventClaims.Empty;


    /// <summary>
    /// Value equality: the <see cref="Amr"/> list compares by content, so a
    /// built event equals its wire round-trip.
    /// </summary>
    public bool Equals(CaepSessionEstablishedEvent? other) =>
        other is not null
        && string.Equals(FpUa, other.FpUa, StringComparison.Ordinal)
        && string.Equals(Acr, other.Acr, StringComparison.Ordinal)
        && EventPayloadReading.ListsEqual(Amr, other.Amr)
        && string.Equals(ExtId, other.ExtId, StringComparison.Ordinal)
        && Common.Equals(other.Common);


    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(FpUa, Acr, Amr?.Count ?? -1, ExtId, Common);


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not <c>session-established</c>.
    /// </summary>
    public static CaepSessionEstablishedEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!CaepEventTypes.IsSessionEstablished(securityEvent.EventType))
        {
            return null;
        }

        IReadOnlyDictionary<string, object> payload = securityEvent.Payload;

        return new CaepSessionEstablishedEvent
        {
            FpUa = EventPayloadReading.ReadOptionalString(payload, CaepSessionClaimNames.FpUa),
            Acr = EventPayloadReading.ReadOptionalString(payload, CaepSessionClaimNames.Acr),
            Amr = EventPayloadReading.ReadStringList(payload, CaepSessionClaimNames.Amr),
            ExtId = EventPayloadReading.ReadOptionalString(payload, CaepSessionClaimNames.ExtId),
            Common = CaepEventClaims.From(payload)
        };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal);
        if(FpUa is not null)
        {
            payload[CaepSessionClaimNames.FpUa] = FpUa;
        }

        if(Acr is not null)
        {
            payload[CaepSessionClaimNames.Acr] = Acr;
        }

        if(Amr is not null)
        {
            payload[CaepSessionClaimNames.Amr] = EventPayloadReading.ToWireList(Amr);
        }

        if(ExtId is not null)
        {
            payload[CaepSessionClaimNames.ExtId] = ExtId;
        }

        Common.WriteTo(payload);

        return new SecurityEvent { EventType = CaepEventTypes.SessionEstablished, Payload = payload };
    }
}


/// <summary>
/// The typed view of a CAEP <c>session-presented</c> event (CAEP 1.0 §3.7):
/// the Transmitter observed the session to be present at the time given by the
/// common <c>event_timestamp</c>. All event-specific claims are OPTIONAL.
/// </summary>
public sealed record CaepSessionPresentedEvent
{
    /// <summary>The OPTIONAL <c>fp_ua</c> user-agent fingerprint.</summary>
    public string? FpUa { get; init; }

    /// <summary>The OPTIONAL <c>ext_id</c> external session identifier.</summary>
    public string? ExtId { get; init; }

    /// <summary>The common CAEP claims (§2); never <see langword="null"/>.</summary>
    public CaepEventClaims Common { get; init; } = CaepEventClaims.Empty;


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not <c>session-presented</c>.
    /// </summary>
    public static CaepSessionPresentedEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!CaepEventTypes.IsSessionPresented(securityEvent.EventType))
        {
            return null;
        }

        IReadOnlyDictionary<string, object> payload = securityEvent.Payload;

        return new CaepSessionPresentedEvent
        {
            FpUa = EventPayloadReading.ReadOptionalString(payload, CaepSessionClaimNames.FpUa),
            ExtId = EventPayloadReading.ReadOptionalString(payload, CaepSessionClaimNames.ExtId),
            Common = CaepEventClaims.From(payload)
        };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal);
        if(FpUa is not null)
        {
            payload[CaepSessionClaimNames.FpUa] = FpUa;
        }

        if(ExtId is not null)
        {
            payload[CaepSessionClaimNames.ExtId] = ExtId;
        }

        Common.WriteTo(payload);

        return new SecurityEvent { EventType = CaepEventTypes.SessionPresented, Payload = payload };
    }
}
