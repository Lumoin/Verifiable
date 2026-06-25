using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci.Wallet;

/// <summary>
/// The Wallet-side outcome of an OID4VCI 1.0 §8.3 Credential Response (or a §9.2 Deferred Credential
/// Response): either the issued Credentials with an optional §11 <c>notification_id</c>, or a §9
/// deferral carrying the <c>transaction_id</c> the Wallet polls with. The richer return that
/// <see cref="Oid4VciWalletClient.IssuePreAuthorizedDetailedAsync(PreAuthorizedCodeOfferGrant, System.Uri, string, Verifiable.Cryptography.PrivateKeyMemory, Verifiable.Cryptography.PublicKeyMemory, Oid4VciIssuanceEndpoints, string?, CredentialResponseEncryption?, System.Threading.CancellationToken)"/>
/// surfaces in place of the single first-Credential string.
/// </summary>
/// <remarks>
/// <para>
/// A batch §8.2 request yields more than one Credential in <see cref="Credentials"/>; a deferred
/// issuance yields an empty <see cref="Credentials"/> with <see cref="IsDeferred"/> set.
/// </para>
/// <para>
/// <see cref="AccessToken"/> / <see cref="TokenType"/> carry the issuance access token so the Wallet
/// can drive the follow-up §9 deferred poll and the §11 notification for this same issuance — both are
/// authorized with the very token the Credential Request used, which the single-use Pre-Authorized Code
/// can no longer re-mint.
/// </para>
/// </remarks>
[DebuggerDisplay("CredentialIssuanceResult Deferred={IsDeferred} Count={Credentials.Count} NotificationId={NotificationId}")]
public sealed record CredentialIssuanceResult
{
    /// <summary>
    /// The §8.3 issued Credentials in response order — one entry for a single issuance, several for a
    /// §8.2 batch. Empty when the issuance was deferred (<see cref="IsDeferred"/>).
    /// </summary>
    public IReadOnlyList<string> Credentials { get; init; } = [];

    /// <summary>
    /// The §8.3 <c>notification_id</c> identifying this issuance for a later §11 Notification Request,
    /// or <see langword="null"/> when the Issuer sent none.
    /// </summary>
    public string? NotificationId { get; init; }

    /// <summary>
    /// The §9.1 <c>transaction_id</c> identifying a deferred issuance to poll at the Deferred Credential
    /// Endpoint, or <see langword="null"/> when the Credentials were issued directly.
    /// </summary>
    public string? TransactionId { get; init; }

    /// <summary>
    /// The §8.3 / §9.2 <c>interval</c> — the minimum seconds to wait before polling the Deferred
    /// Credential Endpoint again — present alongside <see cref="TransactionId"/>, otherwise <see langword="null"/>.
    /// </summary>
    public int? DeferredIntervalSeconds { get; init; }

    /// <summary>The access token authorizing the follow-up §9 deferred poll and §11 notification for this issuance.</summary>
    public required string AccessToken { get; init; }

    /// <summary>The access token's type (<c>Bearer</c> or <c>DPoP</c>) for the follow-up requests' authorization.</summary>
    public required string TokenType { get; init; }

    /// <summary>Whether the issuance was deferred — the Wallet must poll the Deferred Credential Endpoint with <see cref="TransactionId"/>.</summary>
    public bool IsDeferred => TransactionId is not null;

    /// <summary>Whether the response carried at least one issued Credential.</summary>
    public bool IsIssued => Credentials.Count > 0;
}
