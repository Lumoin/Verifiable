using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The claim names of the RISC <c>account-disabled</c> event (RISC 1.0 §2.3).
/// </summary>
public static class RiscAccountDisabledClaimNames
{
    /// <summary><c>reason</c> — OPTIONAL; why the account was disabled. See <see cref="RiscAccountDisabledReasonValues"/>.</summary>
    public static readonly string Reason = "reason";
}


/// <summary>
/// The <c>reason</c> values RISC 1.0 §2.3 lists for <c>account-disabled</c>.
/// The spec says "possible values" without a MUST, so the set is treated as
/// OPEN — there is deliberately no IsAllowed gate.
/// </summary>
public static class RiscAccountDisabledReasonValues
{
    /// <summary><c>hijacking</c>.</summary>
    public static readonly string Hijacking = "hijacking";

    /// <summary><c>bulk-account</c>.</summary>
    public static readonly string BulkAccount = "bulk-account";
}


/// <summary>
/// The claim names of the RISC <c>identifier-changed</c> event (RISC 1.0 §2.5).
/// </summary>
public static class RiscIdentifierChangedClaimNames
{
    /// <summary><c>new-value</c> (hyphenated on the wire) — OPTIONAL; the new value of the identifier.</summary>
    public static readonly string NewValue = "new-value";
}


/// <summary>
/// The claim names of the RISC <c>credential-compromise</c> event (RISC 1.0 §2.7).
/// </summary>
public static class RiscCredentialCompromiseClaimNames
{
    /// <summary><c>credential_type</c> — REQUIRED; the values of the CAEP credential-change <c>credential_type</c> (<see cref="CaepCredentialTypeValues"/>).</summary>
    public static readonly string CredentialType = "credential_type";

    /// <summary><c>event_timestamp</c> — OPTIONAL; when the Transmitter discovered the compromise, as Unix seconds.</summary>
    public static readonly string EventTimestamp = "event_timestamp";

    /// <summary><c>reason_admin</c> — OPTIONAL; why the event was generated, intended for administrators.</summary>
    public static readonly string ReasonAdmin = "reason_admin";

    /// <summary><c>reason_user</c> — OPTIONAL; why the event was generated, intended for end-users.</summary>
    public static readonly string ReasonUser = "reason_user";
}


/// <summary>
/// The typed view of a RISC <c>credential-compromise</c> event (RISC 1.0 §2.7):
/// the identifier specified in the subject was found to be compromised.
/// </summary>
/// <remarks>
/// RISC 1.0 does not state a JSON type for <c>reason_admin</c>/<c>reason_user</c>;
/// the same-named claims are defined in CAEP 1.0 §2 as BCP47-keyed localizable
/// objects, and this profile is part of the same Shared Signals family, so that
/// shape is used here. The reads stay tolerant — a differently-shaped value
/// projects as <see langword="null"/>.
/// </remarks>
public sealed record RiscCredentialCompromiseEvent
{
    /// <summary>The REQUIRED <c>credential_type</c> — an open set; see <see cref="CaepCredentialTypeValues"/>.</summary>
    public required string CredentialType { get; init; }

    /// <summary>The OPTIONAL <c>event_timestamp</c> — when the compromise was discovered.</summary>
    public DateTimeOffset? EventTimestamp { get; init; }

    /// <summary>The OPTIONAL <c>reason_admin</c> messages.</summary>
    public IReadOnlyDictionary<string, string>? ReasonAdmin { get; init; }

    /// <summary>The OPTIONAL <c>reason_user</c> messages.</summary>
    public IReadOnlyDictionary<string, string>? ReasonUser { get; init; }


    /// <summary>Value equality: the message maps compare by content.</summary>
    public bool Equals(RiscCredentialCompromiseEvent? other) =>
        other is not null
        && string.Equals(CredentialType, other.CredentialType, StringComparison.Ordinal)
        && EventTimestamp == other.EventTimestamp
        && EventPayloadReading.MapsEqual(ReasonAdmin, other.ReasonAdmin)
        && EventPayloadReading.MapsEqual(ReasonUser, other.ReasonUser);


    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(CredentialType, EventTimestamp, ReasonAdmin?.Count ?? -1, ReasonUser?.Count ?? -1);


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not
    /// <c>credential-compromise</c> or the REQUIRED <c>credential_type</c> is
    /// absent or not a non-empty string.
    /// </summary>
    public static RiscCredentialCompromiseEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!RiscEventTypes.IsCredentialCompromise(securityEvent.EventType))
        {
            return null;
        }

        IReadOnlyDictionary<string, object> payload = securityEvent.Payload;
        if(!payload.TryGetValue(RiscCredentialCompromiseClaimNames.CredentialType, out object? credentialValue)
            || credentialValue is not string credentialType
            || credentialType.Length == 0)
        {
            return null;
        }

        return new RiscCredentialCompromiseEvent
        {
            CredentialType = credentialType,
            EventTimestamp = EventPayloadReading.ReadUnixSeconds(payload, RiscCredentialCompromiseClaimNames.EventTimestamp),
            ReasonAdmin = EventPayloadReading.ReadLocalizableMap(payload, RiscCredentialCompromiseClaimNames.ReasonAdmin),
            ReasonUser = EventPayloadReading.ReadLocalizableMap(payload, RiscCredentialCompromiseClaimNames.ReasonUser)
        };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [RiscCredentialCompromiseClaimNames.CredentialType] = CredentialType
        };

        if(EventTimestamp is DateTimeOffset timestamp)
        {
            payload[RiscCredentialCompromiseClaimNames.EventTimestamp] = timestamp.ToUnixTimeSeconds();
        }

        if(ReasonAdmin is { Count: > 0 })
        {
            payload[RiscCredentialCompromiseClaimNames.ReasonAdmin] = EventPayloadReading.ToWireMap(ReasonAdmin);
        }

        if(ReasonUser is { Count: > 0 })
        {
            payload[RiscCredentialCompromiseClaimNames.ReasonUser] = EventPayloadReading.ToWireMap(ReasonUser);
        }

        return new SecurityEvent { EventType = RiscEventTypes.CredentialCompromise, Payload = payload };
    }
}


/// <summary>
/// The typed view of a RISC <c>account-disabled</c> event (RISC 1.0 §2.3):
/// the account identified by the subject has been disabled; it may be enabled
/// again in the future (§2.4).
/// </summary>
public sealed record RiscAccountDisabledEvent
{
    /// <summary>The OPTIONAL <c>reason</c> — an open set; see <see cref="RiscAccountDisabledReasonValues"/>.</summary>
    public string? Reason { get; init; }


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not <c>account-disabled</c>.
    /// </summary>
    public static RiscAccountDisabledEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!RiscEventTypes.IsAccountDisabled(securityEvent.EventType))
        {
            return null;
        }

        return new RiscAccountDisabledEvent
        {
            Reason = EventPayloadReading.ReadOptionalString(securityEvent.Payload, RiscAccountDisabledClaimNames.Reason)
        };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal);
        if(Reason is not null)
        {
            payload[RiscAccountDisabledClaimNames.Reason] = Reason;
        }

        return new SecurityEvent { EventType = RiscEventTypes.AccountDisabled, Payload = payload };
    }
}


/// <summary>
/// The typed view of a RISC <c>identifier-changed</c> event (RISC 1.0 §2.5):
/// the identifier specified in the subject has changed. The enclosing token's
/// subject MUST be <c>email</c> or <c>phone</c> and MUST specify the old
/// value; only the provider authoritative over the identifier SHOULD issue it.
/// </summary>
public sealed record RiscIdentifierChangedEvent
{
    /// <summary>The OPTIONAL <c>new-value</c> of the identifier.</summary>
    public string? NewValue { get; init; }


    /// <summary>
    /// Projects <paramref name="securityEvent"/> into the typed view, or
    /// <see langword="null"/> when its event type is not <c>identifier-changed</c>.
    /// </summary>
    public static RiscIdentifierChangedEvent? From(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        if(!RiscEventTypes.IsIdentifierChanged(securityEvent.EventType))
        {
            return null;
        }

        return new RiscIdentifierChangedEvent
        {
            NewValue = EventPayloadReading.ReadOptionalString(securityEvent.Payload, RiscIdentifierChangedClaimNames.NewValue)
        };
    }


    /// <summary>Builds the wire-shaped event for the <c>events</c> claim.</summary>
    public SecurityEvent ToSecurityEvent()
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal);
        if(NewValue is not null)
        {
            payload[RiscIdentifierChangedClaimNames.NewValue] = NewValue;
        }

        return new SecurityEvent { EventType = RiscEventTypes.IdentifierChanged, Payload = payload };
    }
}


/// <summary>
/// The typed views of the attribute-less RISC events (RISC 1.0 §2): each event
/// carries an empty payload object, so the typed record pins only the event
/// type. Subject constraints stay on the enclosing token (e.g.
/// <c>identifier-recycled</c> requires an <c>email</c> or <c>phone</c> subject).
/// </summary>
public static class RiscPayloadlessEvents
{
    private static readonly ReadOnlyDictionary<string, object> EmptyPayload = ReadOnlyDictionary<string, object>.Empty;


    /// <summary><c>account-credential-change-required</c> (§2.1): the subject was required to change a credential.</summary>
    public static SecurityEvent AccountCredentialChangeRequired() =>
        new() { EventType = RiscEventTypes.AccountCredentialChangeRequired, Payload = EmptyPayload };

    /// <summary><c>account-purged</c> (§2.2): the account has been permanently deleted.</summary>
    public static SecurityEvent AccountPurged() =>
        new() { EventType = RiscEventTypes.AccountPurged, Payload = EmptyPayload };

    /// <summary><c>account-enabled</c> (§2.4): the account has been enabled.</summary>
    public static SecurityEvent AccountEnabled() =>
        new() { EventType = RiscEventTypes.AccountEnabled, Payload = EmptyPayload };

    /// <summary><c>identifier-recycled</c> (§2.6): the subject identifier now belongs to a new user.</summary>
    public static SecurityEvent IdentifierRecycled() =>
        new() { EventType = RiscEventTypes.IdentifierRecycled, Payload = EmptyPayload };

    /// <summary><c>opt-in</c> (§2.8.1): the account opted into RISC event exchanges.</summary>
    public static SecurityEvent OptIn() =>
        new() { EventType = RiscEventTypes.OptIn, Payload = EmptyPayload };

    /// <summary><c>opt-out-initiated</c> (§2.8.2): the account initiated opting out of RISC event exchanges.</summary>
    public static SecurityEvent OptOutInitiated() =>
        new() { EventType = RiscEventTypes.OptOutInitiated, Payload = EmptyPayload };

    /// <summary><c>opt-out-cancelled</c> (§2.8.3): the account cancelled the opt-out.</summary>
    public static SecurityEvent OptOutCancelled() =>
        new() { EventType = RiscEventTypes.OptOutCancelled, Payload = EmptyPayload };

    /// <summary><c>opt-out-effective</c> (§2.8.4): the account was effectively opted out.</summary>
    public static SecurityEvent OptOutEffective() =>
        new() { EventType = RiscEventTypes.OptOutEffective, Payload = EmptyPayload };

    /// <summary><c>recovery-activated</c> (§2.9): the account activated a recovery flow.</summary>
    public static SecurityEvent RecoveryActivated() =>
        new() { EventType = RiscEventTypes.RecoveryActivated, Payload = EmptyPayload };

    /// <summary><c>recovery-information-changed</c> (§2.10): the account changed some of its recovery information.</summary>
    public static SecurityEvent RecoveryInformationChanged() =>
        new() { EventType = RiscEventTypes.RecoveryInformationChanged, Payload = EmptyPayload };

    /// <summary>
    /// <c>sessions-revoked</c> (§2.11): all sessions for the account have been
    /// revoked. DEPRECATED — new implementations MUST use the CAEP
    /// <c>session-revoked</c> event (<see cref="CaepSessionRevokedEvent"/>).
    /// </summary>
    public static SecurityEvent SessionsRevoked() =>
        new() { EventType = RiscEventTypes.SessionsRevoked, Payload = EmptyPayload };
}
