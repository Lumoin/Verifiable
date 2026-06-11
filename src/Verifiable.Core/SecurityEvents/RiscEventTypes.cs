using System;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The event-type URIs defined by the OpenID RISC (Risk Incident Sharing and
/// Coordination) Profile 1.0 §2. A RISC event appears as a member of a Security
/// Event Token's <c>events</c> claim, keyed by one of these URIs.
/// </summary>
/// <remarks>
/// The RISC Profile 1.0 final inlines the full event catalogue, including
/// <see cref="CredentialCompromise"/> which the separate (older) RISC Event Types
/// document omits. These are the URI NAMES that key the <c>events</c> map.
/// </remarks>
public static class RiscEventTypes
{
    //The family prefix the StartsWith membership predicate matches on; every member's
    //full URI literal below carries it verbatim (a test pins the coherence).
    private const string Prefix = "https://schemas.openid.net/secevent/risc/event-type/";

    /// <summary>The UTF-8 source literal of <see cref="AccountCredentialChangeRequired"/>.</summary>
    public static ReadOnlySpan<byte> AccountCredentialChangeRequiredUtf8 => "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"u8;

    /// <summary>Account Credential Change Required (<c>account-credential-change-required</c>) — RISC §2.1.</summary>
    public static readonly string AccountCredentialChangeRequired = Utf8Constants.ToInternedString(AccountCredentialChangeRequiredUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccountPurged"/>.</summary>
    public static ReadOnlySpan<byte> AccountPurgedUtf8 => "https://schemas.openid.net/secevent/risc/event-type/account-purged"u8;

    /// <summary>Account Purged (<c>account-purged</c>) — RISC §2.2.</summary>
    public static readonly string AccountPurged = Utf8Constants.ToInternedString(AccountPurgedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccountDisabled"/>.</summary>
    public static ReadOnlySpan<byte> AccountDisabledUtf8 => "https://schemas.openid.net/secevent/risc/event-type/account-disabled"u8;

    /// <summary>Account Disabled (<c>account-disabled</c>) — RISC §2.3.</summary>
    public static readonly string AccountDisabled = Utf8Constants.ToInternedString(AccountDisabledUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AccountEnabled"/>.</summary>
    public static ReadOnlySpan<byte> AccountEnabledUtf8 => "https://schemas.openid.net/secevent/risc/event-type/account-enabled"u8;

    /// <summary>Account Enabled (<c>account-enabled</c>) — RISC §2.4.</summary>
    public static readonly string AccountEnabled = Utf8Constants.ToInternedString(AccountEnabledUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdentifierChanged"/>.</summary>
    public static ReadOnlySpan<byte> IdentifierChangedUtf8 => "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"u8;

    /// <summary>Identifier Changed (<c>identifier-changed</c>) — RISC §2.5.</summary>
    public static readonly string IdentifierChanged = Utf8Constants.ToInternedString(IdentifierChangedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IdentifierRecycled"/>.</summary>
    public static ReadOnlySpan<byte> IdentifierRecycledUtf8 => "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"u8;

    /// <summary>Identifier Recycled (<c>identifier-recycled</c>) — RISC §2.6.</summary>
    public static readonly string IdentifierRecycled = Utf8Constants.ToInternedString(IdentifierRecycledUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialCompromise"/>.</summary>
    public static ReadOnlySpan<byte> CredentialCompromiseUtf8 => "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"u8;

    /// <summary>Credential Compromise (<c>credential-compromise</c>) — RISC §2.7.</summary>
    public static readonly string CredentialCompromise = Utf8Constants.ToInternedString(CredentialCompromiseUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OptIn"/>.</summary>
    public static ReadOnlySpan<byte> OptInUtf8 => "https://schemas.openid.net/secevent/risc/event-type/opt-in"u8;

    /// <summary>Opt In (<c>opt-in</c>) — RISC §2.8.1.</summary>
    public static readonly string OptIn = Utf8Constants.ToInternedString(OptInUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OptOutInitiated"/>.</summary>
    public static ReadOnlySpan<byte> OptOutInitiatedUtf8 => "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"u8;

    /// <summary>Opt Out Initiated (<c>opt-out-initiated</c>) — RISC §2.8.2.</summary>
    public static readonly string OptOutInitiated = Utf8Constants.ToInternedString(OptOutInitiatedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OptOutCancelled"/>.</summary>
    public static ReadOnlySpan<byte> OptOutCancelledUtf8 => "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"u8;

    /// <summary>Opt Out Cancelled (<c>opt-out-cancelled</c>) — RISC §2.8.3.</summary>
    public static readonly string OptOutCancelled = Utf8Constants.ToInternedString(OptOutCancelledUtf8);

    /// <summary>The UTF-8 source literal of <see cref="OptOutEffective"/>.</summary>
    public static ReadOnlySpan<byte> OptOutEffectiveUtf8 => "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"u8;

    /// <summary>Opt Out Effective (<c>opt-out-effective</c>) — RISC §2.8.4.</summary>
    public static readonly string OptOutEffective = Utf8Constants.ToInternedString(OptOutEffectiveUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RecoveryActivated"/>.</summary>
    public static ReadOnlySpan<byte> RecoveryActivatedUtf8 => "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"u8;

    /// <summary>Recovery Activated (<c>recovery-activated</c>) — RISC §2.9.</summary>
    public static readonly string RecoveryActivated = Utf8Constants.ToInternedString(RecoveryActivatedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RecoveryInformationChanged"/>.</summary>
    public static ReadOnlySpan<byte> RecoveryInformationChangedUtf8 => "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"u8;

    /// <summary>Recovery Information Changed (<c>recovery-information-changed</c>) — RISC §2.10.</summary>
    public static readonly string RecoveryInformationChanged = Utf8Constants.ToInternedString(RecoveryInformationChangedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SessionsRevoked"/>.</summary>
    public static ReadOnlySpan<byte> SessionsRevokedUtf8 => "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"u8;

    /// <summary>Sessions Revoked (<c>sessions-revoked</c>) — RISC §2.11.</summary>
    public static readonly string SessionsRevoked = Utf8Constants.ToInternedString(SessionsRevokedUtf8);


    /// <summary>Whether <paramref name="eventType"/> is <see cref="AccountCredentialChangeRequired"/>.</summary>
    public static bool IsAccountCredentialChangeRequired(string eventType) => Equals(eventType, AccountCredentialChangeRequired);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="AccountPurged"/>.</summary>
    public static bool IsAccountPurged(string eventType) => Equals(eventType, AccountPurged);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="AccountDisabled"/>.</summary>
    public static bool IsAccountDisabled(string eventType) => Equals(eventType, AccountDisabled);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="AccountEnabled"/>.</summary>
    public static bool IsAccountEnabled(string eventType) => Equals(eventType, AccountEnabled);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="IdentifierChanged"/>.</summary>
    public static bool IsIdentifierChanged(string eventType) => Equals(eventType, IdentifierChanged);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="IdentifierRecycled"/>.</summary>
    public static bool IsIdentifierRecycled(string eventType) => Equals(eventType, IdentifierRecycled);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="CredentialCompromise"/>.</summary>
    public static bool IsCredentialCompromise(string eventType) => Equals(eventType, CredentialCompromise);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="OptIn"/>.</summary>
    public static bool IsOptIn(string eventType) => Equals(eventType, OptIn);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="OptOutInitiated"/>.</summary>
    public static bool IsOptOutInitiated(string eventType) => Equals(eventType, OptOutInitiated);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="OptOutCancelled"/>.</summary>
    public static bool IsOptOutCancelled(string eventType) => Equals(eventType, OptOutCancelled);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="OptOutEffective"/>.</summary>
    public static bool IsOptOutEffective(string eventType) => Equals(eventType, OptOutEffective);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="RecoveryActivated"/>.</summary>
    public static bool IsRecoveryActivated(string eventType) => Equals(eventType, RecoveryActivated);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="RecoveryInformationChanged"/>.</summary>
    public static bool IsRecoveryInformationChanged(string eventType) => Equals(eventType, RecoveryInformationChanged);

    /// <summary>Whether <paramref name="eventType"/> is <see cref="SessionsRevoked"/>.</summary>
    public static bool IsSessionsRevoked(string eventType) => Equals(eventType, SessionsRevoked);

    /// <summary>Whether <paramref name="eventType"/> is any RISC event-type URI.</summary>
    public static bool IsRiscEventType(string eventType) =>
        eventType is not null && eventType.StartsWith(Prefix, System.StringComparison.Ordinal);


    /// <summary>
    /// Returns the interned constant for a known RISC event-type URI, or the original
    /// string if unrecognized.
    /// </summary>
    public static string GetCanonicalizedValue(string eventType) => eventType switch
    {
        _ when IsAccountCredentialChangeRequired(eventType) => AccountCredentialChangeRequired,
        _ when IsAccountPurged(eventType) => AccountPurged,
        _ when IsAccountDisabled(eventType) => AccountDisabled,
        _ when IsAccountEnabled(eventType) => AccountEnabled,
        _ when IsIdentifierChanged(eventType) => IdentifierChanged,
        _ when IsIdentifierRecycled(eventType) => IdentifierRecycled,
        _ when IsCredentialCompromise(eventType) => CredentialCompromise,
        _ when IsOptIn(eventType) => OptIn,
        _ when IsOptOutInitiated(eventType) => OptOutInitiated,
        _ when IsOptOutCancelled(eventType) => OptOutCancelled,
        _ when IsOptOutEffective(eventType) => OptOutEffective,
        _ when IsRecoveryActivated(eventType) => RecoveryActivated,
        _ when IsRecoveryInformationChanged(eventType) => RecoveryInformationChanged,
        _ when IsSessionsRevoked(eventType) => SessionsRevoked,
        _ => eventType
    };


    /// <summary>Compares two event-type URIs for equality (case-sensitive).</summary>
    public static bool Equals(string eventTypeA, string eventTypeB) =>
        object.ReferenceEquals(eventTypeA, eventTypeB) || System.StringComparer.Ordinal.Equals(eventTypeA, eventTypeB);
}
