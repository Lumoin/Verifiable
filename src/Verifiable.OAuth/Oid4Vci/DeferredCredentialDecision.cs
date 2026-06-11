using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// The reason an application refused a Deferred Credential Request at the
/// <see cref="Server.ResolveDeferredCredentialDelegate"/> seam. The library maps each reason to
/// its OID4VCI 1.0 §9.3 Deferred Credential Error Response code.
/// </summary>
public enum DeferredCredentialError
{
    /// <summary>
    /// The <c>transaction_id</c> was not issued by this Credential Issuer or was already used
    /// to obtain a Credential. Mapped to
    /// <see cref="Oid4VciCredentialErrors.InvalidTransactionId"/>.
    /// </summary>
    InvalidTransactionId,

    /// <summary>
    /// The Credential Issuer can no longer issue the credential(s) — §9.3 directs the Wallet to
    /// stop polling for this <c>transaction_id</c>. Mapped to
    /// <see cref="Oid4VciCredentialErrors.CredentialRequestDenied"/>.
    /// </summary>
    CredentialRequestDenied
}


/// <summary>
/// An application's verdict on an OID4VCI 1.0 §9 Deferred Credential Request, returned from the
/// <see cref="Server.ResolveDeferredCredentialDelegate"/> seam: the Credentials are ready
/// (<see cref="Issue"/>), more time is needed (<see cref="Defer"/>), or the request is refused
/// (<see cref="Refuse"/>).
/// </summary>
/// <remarks>
/// The library owns the wire — bearer-token validation, the §9.1 request shape, the §9.2
/// 200-with-<c>credentials</c> / 202-with-<c>interval</c> split, and the §9.3 error mapping.
/// The application owns the deferred-transaction store: only it can tell an unknown or consumed
/// <c>transaction_id</c> from one whose issuance is still in flight, and §9.1 makes invalidating
/// the <c>transaction_id</c> after delivery its responsibility. Mirrors
/// <see cref="CredentialIssuanceDecision"/>.
/// </remarks>
[DebuggerDisplay("DeferredCredentialDecision IsIssued={IsIssued} IsPending={IsPending} ErrorReason={ErrorReason}")]
public sealed record DeferredCredentialDecision
{
    /// <summary>
    /// Whether the previously deferred Credentials are now issued. The response is the §9.2
    /// HTTP 200 carrying the <c>credentials</c> array.
    /// </summary>
    public required bool IsIssued { get; init; }

    /// <summary>
    /// Whether the Credential Issuer still requires more time. The response is the §9.2
    /// HTTP 202 echoing the <c>transaction_id</c> with the <c>interval</c> to wait.
    /// </summary>
    public bool IsPending { get; init; }

    /// <summary>
    /// The issued Credentials, each emitted as a §8.3 <c>credential</c> string. Empty unless
    /// <see cref="IsIssued"/>.
    /// </summary>
    public IReadOnlyList<string> Credentials { get; init; } = [];

    /// <summary>
    /// The optional §8.3 <c>notification_id</c> identifying the issued Credentials in a later
    /// §11.1 Notification Request. Only meaningful when <see cref="IsIssued"/>.
    /// </summary>
    public string? NotificationId { get; init; }

    /// <summary>
    /// The §8.3 <c>interval</c> — the minimum seconds the Wallet SHOULD wait before polling
    /// again. Only meaningful when <see cref="IsPending"/>.
    /// </summary>
    public int IntervalSeconds { get; init; }

    /// <summary>
    /// The reason a refused request was not accepted. Ignored on an issuance or a deferral; a
    /// refusal with no reason set is treated as
    /// <see cref="DeferredCredentialError.InvalidTransactionId"/>.
    /// </summary>
    public DeferredCredentialError? ErrorReason { get; init; }

    /// <summary>
    /// An optional human-readable description carried into the error response's
    /// <c>error_description</c>. <see langword="null"/> falls back to a reason-specific default.
    /// </summary>
    public string? ErrorDescription { get; init; }


    /// <summary>
    /// An issuance verdict: the deferred Credentials are ready and the <c>transaction_id</c> is
    /// to be invalidated by the application per §9.1.
    /// </summary>
    /// <param name="credentials">The issued Credential strings.</param>
    /// <param name="notificationId">The optional <c>notification_id</c>, or <see langword="null"/>.</param>
    /// <returns>An issued <see cref="DeferredCredentialDecision"/>.</returns>
    public static DeferredCredentialDecision Issue(
        IReadOnlyList<string> credentials, string? notificationId = null)
    {
        ArgumentNullException.ThrowIfNull(credentials);

        return new DeferredCredentialDecision
        {
            IsIssued = true,
            Credentials = credentials,
            NotificationId = notificationId
        };
    }


    /// <summary>
    /// A deferral verdict: issuance is still in flight; the Wallet SHOULD wait
    /// <paramref name="intervalSeconds"/> before polling again.
    /// </summary>
    /// <param name="intervalSeconds">The §8.3 <c>interval</c>, a positive number of seconds.</param>
    /// <returns>A pending <see cref="DeferredCredentialDecision"/>.</returns>
    public static DeferredCredentialDecision Defer(int intervalSeconds)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(intervalSeconds);

        return new DeferredCredentialDecision
        {
            IsIssued = false,
            IsPending = true,
            IntervalSeconds = intervalSeconds
        };
    }


    /// <summary>
    /// A refusal verdict with the given <paramref name="reason"/> and optional
    /// <paramref name="description"/>.
    /// </summary>
    /// <param name="reason">The §9.3 reason the request was refused.</param>
    /// <param name="description">An optional human-readable description.</param>
    /// <returns>A refused <see cref="DeferredCredentialDecision"/>.</returns>
    public static DeferredCredentialDecision Refuse(
        DeferredCredentialError reason, string? description = null)
    {
        return new DeferredCredentialDecision
        {
            IsIssued = false,
            ErrorReason = reason,
            ErrorDescription = description
        };
    }
}
