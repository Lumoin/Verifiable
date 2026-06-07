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
    private const string Prefix = "https://schemas.openid.net/secevent/risc/event-type/";

    /// <summary>Account Credential Change Required (<c>account-credential-change-required</c>) — RISC §2.1.</summary>
    public static readonly string AccountCredentialChangeRequired = Prefix + "account-credential-change-required";

    /// <summary>Account Purged (<c>account-purged</c>) — RISC §2.2.</summary>
    public static readonly string AccountPurged = Prefix + "account-purged";

    /// <summary>Account Disabled (<c>account-disabled</c>) — RISC §2.3.</summary>
    public static readonly string AccountDisabled = Prefix + "account-disabled";

    /// <summary>Account Enabled (<c>account-enabled</c>) — RISC §2.4.</summary>
    public static readonly string AccountEnabled = Prefix + "account-enabled";

    /// <summary>Identifier Changed (<c>identifier-changed</c>) — RISC §2.5.</summary>
    public static readonly string IdentifierChanged = Prefix + "identifier-changed";

    /// <summary>Identifier Recycled (<c>identifier-recycled</c>) — RISC §2.6.</summary>
    public static readonly string IdentifierRecycled = Prefix + "identifier-recycled";

    /// <summary>Credential Compromise (<c>credential-compromise</c>) — RISC §2.7.</summary>
    public static readonly string CredentialCompromise = Prefix + "credential-compromise";

    /// <summary>Opt In (<c>opt-in</c>) — RISC §2.8.1.</summary>
    public static readonly string OptIn = Prefix + "opt-in";

    /// <summary>Opt Out Initiated (<c>opt-out-initiated</c>) — RISC §2.8.2.</summary>
    public static readonly string OptOutInitiated = Prefix + "opt-out-initiated";

    /// <summary>Opt Out Cancelled (<c>opt-out-cancelled</c>) — RISC §2.8.3.</summary>
    public static readonly string OptOutCancelled = Prefix + "opt-out-cancelled";

    /// <summary>Opt Out Effective (<c>opt-out-effective</c>) — RISC §2.8.4.</summary>
    public static readonly string OptOutEffective = Prefix + "opt-out-effective";

    /// <summary>Recovery Activated (<c>recovery-activated</c>) — RISC §2.9.</summary>
    public static readonly string RecoveryActivated = Prefix + "recovery-activated";

    /// <summary>Recovery Information Changed (<c>recovery-information-changed</c>) — RISC §2.10.</summary>
    public static readonly string RecoveryInformationChanged = Prefix + "recovery-information-changed";

    /// <summary>Sessions Revoked (<c>sessions-revoked</c>) — RISC §2.11.</summary>
    public static readonly string SessionsRevoked = Prefix + "sessions-revoked";


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
