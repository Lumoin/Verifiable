using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The reason an application refused a Credential Request at the
/// <see cref="Server.IssueCredentialDelegate"/> seam. The library maps each reason to the
/// OID4VCI 1.0 §8.3.1.2 Credential Error Response code, since only the application — which
/// verifies the holder proofs against its <c>c_nonce</c> store and knows which Credential
/// Configurations it supports — can distinguish these cases.
/// </summary>
public enum CredentialRequestError
{
    /// <summary>
    /// The request is malformed, repeats a parameter, or includes an unsupported parameter or
    /// value. Mapped to <see cref="Oid4VciCredentialErrors.InvalidCredentialRequest"/>.
    /// </summary>
    InvalidCredentialRequest,

    /// <summary>
    /// The requested Credential Configuration is unknown. Mapped to
    /// <see cref="Oid4VciCredentialErrors.UnknownCredentialConfiguration"/>.
    /// </summary>
    UnknownCredentialConfiguration,

    /// <summary>
    /// The requested Credential identifier is unknown. Mapped to
    /// <see cref="Oid4VciCredentialErrors.UnknownCredentialIdentifier"/>.
    /// </summary>
    UnknownCredentialIdentifier,

    /// <summary>
    /// A key proof is missing, invalid, or carries no <c>c_nonce</c>. Mapped to
    /// <see cref="Oid4VciCredentialErrors.InvalidProof"/>.
    /// </summary>
    InvalidProof,

    /// <summary>
    /// A key proof carries an invalid <c>c_nonce</c>. Mapped to
    /// <see cref="Oid4VciCredentialErrors.InvalidNonce"/>.
    /// </summary>
    InvalidNonce,

    /// <summary>
    /// The encryption parameters are invalid or missing when an encrypted response is required.
    /// Mapped to <see cref="Oid4VciCredentialErrors.InvalidEncryptionParameters"/>.
    /// </summary>
    InvalidEncryptionParameters,

    /// <summary>
    /// The Credential Request was not accepted by the Issuer. Mapped to
    /// <see cref="Oid4VciCredentialErrors.CredentialRequestDenied"/>.
    /// </summary>
    CredentialRequestDenied
}


/// <summary>
/// An application's verdict on an OID4VCI 1.0 §8 Credential Request, returned from the
/// <see cref="Server.IssueCredentialDelegate"/> seam. An issuance carries the one-or-more
/// issued <see cref="Credentials"/> (each bound to a holder key from the request's proofs) and
/// an optional <see cref="NotificationId"/>; a refusal carries the
/// <see cref="ErrorReason"/> the library maps to a §8.3.1.2 Credential Error Response code.
/// </summary>
/// <remarks>
/// The library owns only the wire shape — bearer-token validation (§8.3.1.1), the §8.2 request
/// shape, and the §8.3 / §8.3.1.2 response mapping. The application owns proof verification,
/// the <c>c_nonce</c> store, the set of supported Credential Configurations, and the signing
/// key, so it is the only party that can mint a Credential and tell the §8.3.1.2 error cases
/// apart. Mirrors <see cref="PreAuthorizedCodeDecision"/>.
/// </remarks>
[DebuggerDisplay("CredentialIssuanceDecision IsIssued={IsIssued} Credentials={Credentials.Count} ErrorReason={ErrorReason}")]
public sealed record CredentialIssuanceDecision
{
    /// <summary>
    /// Whether the request was accepted and Credentials were issued. <see langword="false"/>
    /// fails the request with the error mapped from <see cref="ErrorReason"/>.
    /// </summary>
    public required bool IsIssued { get; init; }

    /// <summary>
    /// The issued Credentials, each emitted as a §8.3 <c>credential</c> string. One per holder
    /// key the Wallet supplied, unless the Issuer chose to issue fewer. Empty on a refusal.
    /// </summary>
    public IReadOnlyList<string> Credentials { get; init; } = [];

    /// <summary>
    /// The optional §8.3 <c>notification_id</c> identifying the issued Credentials in a later
    /// §11.1 Notification Request. Ignored on a refusal.
    /// </summary>
    public string? NotificationId { get; init; }

    /// <summary>
    /// Whether issuance is deferred (§8.3: e.g. a manual review process, or the dataset is not
    /// ready). The response is HTTP 202 carrying <see cref="TransactionId"/> and
    /// <see cref="IntervalSeconds"/>; the Wallet later polls the §9 Deferred Credential
    /// Endpoint.
    /// </summary>
    public bool IsDeferred { get; init; }

    /// <summary>
    /// The §8.3 <c>transaction_id</c> identifying the Deferred Issuance transaction the
    /// application opened in its store. Only meaningful when <see cref="IsDeferred"/>.
    /// </summary>
    public string? TransactionId { get; init; }

    /// <summary>
    /// The §8.3 <c>interval</c> — the minimum seconds the Wallet SHOULD wait before polling
    /// the Deferred Credential Endpoint. Only meaningful when <see cref="IsDeferred"/>.
    /// </summary>
    public int IntervalSeconds { get; init; }

    /// <summary>
    /// The reason a refused request was not accepted. Ignored when <see cref="IsIssued"/> is
    /// <see langword="true"/>; a refusal with no reason set is treated as
    /// <see cref="CredentialRequestError.InvalidCredentialRequest"/>.
    /// </summary>
    public CredentialRequestError? ErrorReason { get; init; }

    /// <summary>
    /// An optional human-readable description carried into the error response's
    /// <c>error_description</c>. <see langword="null"/> falls back to a reason-specific default.
    /// </summary>
    public string? ErrorDescription { get; init; }


    /// <summary>
    /// An issuance verdict carrying the given <paramref name="credentials"/> and an optional
    /// <paramref name="notificationId"/>.
    /// </summary>
    /// <param name="credentials">The issued Credential strings, one per bound holder key.</param>
    /// <param name="notificationId">The optional <c>notification_id</c>, or <see langword="null"/>.</param>
    /// <returns>An issued <see cref="CredentialIssuanceDecision"/>.</returns>
    public static CredentialIssuanceDecision Issue(
        IReadOnlyList<string> credentials, string? notificationId = null)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        return new CredentialIssuanceDecision
        {
            IsIssued = true,
            Credentials = credentials,
            NotificationId = notificationId
        };
    }


    /// <summary>
    /// A refusal verdict with the given <paramref name="reason"/> and optional
    /// <paramref name="description"/>.
    /// </summary>
    /// <param name="reason">The §8.3.1.2 reason the request was refused.</param>
    /// <param name="description">An optional human-readable description.</param>
    /// <returns>A refused <see cref="CredentialIssuanceDecision"/>.</returns>
    public static CredentialIssuanceDecision Deny(
        CredentialRequestError reason, string? description = null)
    {
        return new CredentialIssuanceDecision
        {
            IsIssued = false,
            ErrorReason = reason,
            ErrorDescription = description
        };
    }


    /// <summary>
    /// A deferral verdict (§8.3): the Issuer cannot issue immediately; the application opened
    /// a Deferred Issuance transaction under <paramref name="transactionId"/> in its store and
    /// the Wallet SHOULD wait <paramref name="intervalSeconds"/> before polling the §9
    /// Deferred Credential Endpoint.
    /// </summary>
    /// <param name="transactionId">The §8.3 <c>transaction_id</c> the application minted.</param>
    /// <param name="intervalSeconds">The §8.3 <c>interval</c>, a positive number of seconds.</param>
    /// <returns>A deferred <see cref="CredentialIssuanceDecision"/>.</returns>
    public static CredentialIssuanceDecision Defer(string transactionId, int intervalSeconds)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(transactionId);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(intervalSeconds);

        return new CredentialIssuanceDecision
        {
            IsIssued = false,
            IsDeferred = true,
            TransactionId = transactionId,
            IntervalSeconds = intervalSeconds
        };
    }
}
