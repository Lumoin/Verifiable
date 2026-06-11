using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The <c>event</c> values of an OID4VCI 1.0 §11.1 Notification Request — the Wallet's
/// case-sensitive report on what became of the issued Credentials.
/// </summary>
[DebuggerDisplay("Oid4VciNotificationEvents")]
public static class Oid4VciNotificationEvents
{
    /// <summary>The UTF-8 source literal of <see cref="CredentialAccepted"/>.</summary>
    public static ReadOnlySpan<byte> CredentialAcceptedUtf8 => "credential_accepted"u8;

    /// <summary>
    /// The <c>credential_accepted</c> event — the Credentials were successfully stored in the
    /// Wallet, with or without user action.
    /// </summary>
    public static readonly string CredentialAccepted = Utf8Constants.ToInternedString(CredentialAcceptedUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialFailure"/>.</summary>
    public static ReadOnlySpan<byte> CredentialFailureUtf8 => "credential_failure"u8;

    /// <summary>
    /// The <c>credential_failure</c> event — the issuance flow failed for any reason other
    /// than a user action; §11.1 directs partial batch failures to report as this overall
    /// failure too.
    /// </summary>
    public static readonly string CredentialFailure = Utf8Constants.ToInternedString(CredentialFailureUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialDeleted"/>.</summary>
    public static ReadOnlySpan<byte> CredentialDeletedUtf8 => "credential_deleted"u8;

    /// <summary>
    /// The <c>credential_deleted</c> event — the unsuccessful issuance was caused by a user
    /// action.
    /// </summary>
    public static readonly string CredentialDeleted = Utf8Constants.ToInternedString(CredentialDeletedUtf8);


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="value"/> is one of the three §11.1
    /// event values. Comparison is case-sensitive per §11.1.
    /// </summary>
    public static bool IsKnownEvent(string value) =>
        string.Equals(value, CredentialAccepted, StringComparison.Ordinal)
        || string.Equals(value, CredentialFailure, StringComparison.Ordinal)
        || string.Equals(value, CredentialDeleted, StringComparison.Ordinal);
}


/// <summary>
/// A parsed OID4VCI 1.0 §11.1 Notification Request — the Wallet's report on an issuance flow
/// identified by the <c>notification_id</c> a Credential Response (or Deferred Credential
/// Response) carried. Handed to the application's
/// <see cref="Server.ProcessCredentialNotificationDelegate"/> seam.
/// </summary>
[DebuggerDisplay("CredentialNotification NotificationId={NotificationId} Event={Event}")]
public sealed record CredentialNotification
{
    /// <summary>
    /// §11.1 <c>notification_id</c> (REQUIRED): the identifier received in the Credential
    /// Response or Deferred Credential Response.
    /// </summary>
    public required string NotificationId { get; init; }

    /// <summary>
    /// §11.1 <c>event</c> (REQUIRED): one of the <see cref="Oid4VciNotificationEvents"/>
    /// values, validated by the endpoint before the seam is invoked.
    /// </summary>
    public required string Event { get; init; }

    /// <summary>
    /// §11.1 <c>event_description</c> (OPTIONAL): human-readable ASCII text assisting the
    /// Credential Issuer developer, or <see langword="null"/>.
    /// </summary>
    public string? EventDescription { get; init; }
}


/// <summary>
/// An application's verdict on an OID4VCI 1.0 §11.1 Notification Request, returned from the
/// <see cref="Server.ProcessCredentialNotificationDelegate"/> seam. §11 makes the notification
/// idempotent — repeated identical calls for the same <c>notification_id</c> return success.
/// </summary>
/// <remarks>
/// The library owns the wire — bearer-token validation, the §11.1 request shape including the
/// event-value check, the §11.2 success status, and the §11.3 error mapping. The application
/// owns the <c>notification_id</c> store: only it can tell an identifier it never returned from
/// one identifying a real issuance flow.
/// </remarks>
[DebuggerDisplay("CredentialNotificationDecision IsAccepted={IsAccepted}")]
public sealed record CredentialNotificationDecision
{
    /// <summary>
    /// Whether the notification was accepted. <see langword="true"/> answers the §11.2
    /// HTTP 204 No Content; <see langword="false"/> answers the §11.3
    /// <c>invalid_notification_id</c> error.
    /// </summary>
    public required bool IsAccepted { get; init; }

    /// <summary>
    /// An optional human-readable description carried into the error response's
    /// <c>error_description</c>. Ignored on an acceptance.
    /// </summary>
    public string? ErrorDescription { get; init; }


    /// <summary>An acceptance verdict — answers §11.2 success.</summary>
    public static CredentialNotificationDecision Accept { get; } = new() { IsAccepted = true };


    /// <summary>
    /// A rejection verdict: the <c>notification_id</c> was not issued by this Credential
    /// Issuer. Answers the §11.3 <c>invalid_notification_id</c> error.
    /// </summary>
    /// <param name="description">An optional human-readable description.</param>
    /// <returns>A rejected <see cref="CredentialNotificationDecision"/>.</returns>
    public static CredentialNotificationDecision RejectUnknownId(string? description = null) =>
        new() { IsAccepted = false, ErrorDescription = description };
}
