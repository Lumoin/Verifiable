namespace Verifiable.Core.StatusList;

/// <summary>
/// String constants defined by the W3C Bitstring Status List specification: type names,
/// status purposes, property names, and the processing-error type-URL prefix.
/// </summary>
/// <remarks>
/// See <see href="https://www.w3.org/TR/vc-bitstring-status-list/">W3C Bitstring Status List</see>.
/// </remarks>
public static class BitstringStatusListConstants
{
    /// <summary>
    /// The <c>type</c> value of a status entry on a credential being checked (§2.1).
    /// </summary>
    public const string EntryType = "BitstringStatusListEntry";

    /// <summary>
    /// The <c>type</c> value of the verifiable credential that carries the status list (§2.2).
    /// </summary>
    public const string CredentialType = "BitstringStatusListCredential";

    /// <summary>
    /// The <c>credentialSubject.type</c> value of the status list (§2.2).
    /// </summary>
    public const string SubjectType = "BitstringStatusList";

    /// <summary>
    /// Status purpose: an updated credential is available via the refresh service; does not
    /// invalidate the credential and is not reversible (§2.1).
    /// </summary>
    public const string RefreshPurpose = "refresh";

    /// <summary>
    /// Status purpose: the credential's validity is cancelled; not reversible (§2.1).
    /// </summary>
    public const string RevocationPurpose = "revocation";

    /// <summary>
    /// Status purpose: the credential is temporarily prevented from being accepted; reversible (§2.1).
    /// </summary>
    public const string SuspensionPurpose = "suspension";

    /// <summary>
    /// Status purpose: an arbitrary message about the credential status, resolved through the
    /// entry's <c>statusMessage</c> array (§2.1).
    /// </summary>
    public const string MessagePurpose = "message";

    /// <summary>The <c>statusPurpose</c> property name.</summary>
    public const string StatusPurposeProperty = "statusPurpose";

    /// <summary>The <c>statusListIndex</c> property name.</summary>
    public const string StatusListIndexProperty = "statusListIndex";

    /// <summary>The <c>statusListCredential</c> property name.</summary>
    public const string StatusListCredentialProperty = "statusListCredential";

    /// <summary>The <c>statusSize</c> property name.</summary>
    public const string StatusSizeProperty = "statusSize";

    /// <summary>The <c>statusMessage</c> property name (on the entry).</summary>
    public const string StatusMessageProperty = "statusMessage";

    /// <summary>The <c>statusReference</c> property name.</summary>
    public const string StatusReferenceProperty = "statusReference";

    /// <summary>The <c>encodedList</c> property name (on the status list credential subject).</summary>
    public const string EncodedListProperty = "encodedList";

    /// <summary>The <c>ttl</c> property name (on the status list credential subject).</summary>
    public const string TimeToLiveProperty = "ttl";

    /// <summary>
    /// The prefix shared by all processing-error type URLs (§3.5). The specific error code is
    /// appended to form the full <c>type</c> value of an RFC 9457 problem detail.
    /// </summary>
    public const string ErrorTypeUrlPrefix = "https://www.w3.org/ns/credentials/status-list#";
}
