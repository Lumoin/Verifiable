namespace Verifiable.OAuth.Logout;

/// <summary>
/// The outcome of verifying an OIDC Back-Channel Logout Token: the extracted
/// <c>sub</c>/<c>sid</c> on success, or a typed failure reason. Mirrors the
/// success/failure shape of the SET verifier
/// (<see cref="Verifiable.Core.SecurityEvents.SecurityEventTokenVerificationResult"/>)
/// — verification reports a cause a Receiver dispatches on rather than throwing.
/// </summary>
/// <remarks>
/// On failure both <see cref="Subject"/> and <see cref="SessionId"/> are
/// <see langword="null"/> and <see cref="Error"/> carries the cause — a firewalled
/// Receiver must not drop a session on claims whose signature or §2.6 validity did not
/// hold. On success at least one of <see cref="Subject"/> / <see cref="SessionId"/> is set.
/// </remarks>
public sealed record BackChannelLogoutVerificationResult
{
    /// <summary>The verified <c>sub</c> claim, when present; otherwise <see langword="null"/>.</summary>
    public string? Subject { get; init; }

    /// <summary>The verified <c>sid</c> claim, when present; otherwise <see langword="null"/>.</summary>
    public string? SessionId { get; init; }

    /// <summary>The failure reason when verification failed; otherwise <see langword="null"/>.</summary>
    public BackChannelLogoutValidationError? Error { get; init; }

    /// <summary><see langword="true"/> when verification and all §2.6 checks succeeded.</summary>
    public bool IsValid => Error is null;


    /// <summary>Builds a success result carrying the verified <paramref name="subject"/> and <paramref name="sessionId"/>.</summary>
    public static BackChannelLogoutVerificationResult Success(string? subject, string? sessionId) =>
        new() { Subject = subject, SessionId = sessionId };


    /// <summary>Builds a failure result carrying <paramref name="error"/>.</summary>
    public static BackChannelLogoutVerificationResult Failed(BackChannelLogoutValidationError error) =>
        new() { Error = error };
}
