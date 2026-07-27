using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.StatusList;

/// <summary>
/// Resolves the Status List Token a credential's <see cref="StatusListReference"/> points at,
/// already cryptographically verified and parsed. The caller — an RP server, a peer wallet, or an
/// agent — owns the fetch, the signature/trust verification of the status list issuer, and any
/// caching (in an Orleans-style deployment this is naturally a status-list grain that fetches once
/// and fans the verified token out to many verifiers). The library does no transport here.
/// </summary>
/// <param name="uri">The <c>uri</c> of the Status List Token (the credential's <c>status_list.uri</c>).</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The verified Status List Token.</returns>
public delegate ValueTask<StatusListToken> ResolveVerifiedStatusListTokenDelegate(
    string uri,
    CancellationToken cancellationToken = default);


/// <summary>
/// The outcome of checking a credential's status against its referenced status list.
/// </summary>
public sealed record CredentialStatusOutcome
{
    /// <summary>The raw status value read from the list at the credential's index.</summary>
    public required byte Status { get; init; }

    /// <summary>
    /// Whether the credential is valid, i.e. <see cref="Status"/> is <see cref="StatusTypes.Valid"/>
    /// (<c>0x00</c>). Any other value — revoked (<c>0x01</c>), suspended (<c>0x02</c>), or
    /// application-specific — is not valid. Inspect <see cref="Status"/> to distinguish them.
    /// </summary>
    public required bool IsValid { get; init; }

    /// <summary>
    /// Whether the resolved Status List Token's <c>ttl</c> claim (Section 5.1 / 8.3, step 4.2.4 of the
    /// Token Status List specification) indicates a fresh copy SHOULD be retrieved. <c>ttl</c> is a
    /// caching hint, not a validity requirement — unlike <see cref="IsValid"/>, this being
    /// <see langword="true"/> does not mean the status is wrong or undeterminable, only that the
    /// resolved token is old enough that the caller's own refresh policy should consider re-fetching
    /// it. Computed via
    /// <see cref="StatusListValidation.ShouldRefresh(StatusListToken, DateTimeOffset, DateTimeOffset)"/>
    /// against the <c>resolvedAt</c> supplied to <see cref="CredentialStatusGate.CheckAsync"/> (or the
    /// check's own <c>currentTime</c> when the caller performs no caching of its own, in which case
    /// this is always <see langword="false"/> — a token resolved this instant is never stale).
    /// </summary>
    public required bool ShouldRefresh { get; init; }
}


/// <summary>
/// The verifier-agnostic revocation gate for the IETF Token Status List: given a credential's
/// status reference, resolve its (already verified) Status List Token and read the status bit.
/// </summary>
/// <remarks>
/// <para>
/// A valid issuer signature only proves a credential was genuinely issued; it does not prove the
/// credential is still valid <em>now</em>. This gate is the "is it still valid?" step, run after
/// signature and holder-binding verification. It is a pure, static, allocation-light function — it
/// holds no state and does no I/O — so it runs identically wherever the verifier role lives: an RP
/// server, a peer wallet in a P2P/proximity exchange, or an agent (or wallet) hosted as an actor in
/// a cluster. Coupling it to any one server pipeline would lock those other verifiers out; keeping
/// it here, taking a resolver the caller supplies, keeps it universal.
/// </para>
/// <para>
/// Resolution, signature verification of the status list, trust, and caching are the caller's
/// concern, expressed through <see cref="ResolveVerifiedStatusListTokenDelegate"/>. The gate only
/// reads the bit via <see cref="StatusListValidation.GetStatus(StatusListToken, StatusListReference, DateTimeOffset)"/>,
/// which also enforces the token's subject match, expiry, and index bounds — so a token whose
/// subject does not match the reference URI, an expired list, or an out-of-range index surfaces as
/// a <see cref="StatusListValidationException"/> (fail-closed: an undeterminable status is not a
/// pass).
/// </para>
/// <para>
/// The token's <c>ttl</c> claim is a different kind of fact: it is a caching hint (Section 8.3, step
/// 4.2.4), not a validity requirement — unlike <c>exp</c>, its breach does not invalidate the status.
/// The gate therefore never rejects on <c>ttl</c>. Instead it evaluates
/// <see cref="StatusListValidation.ShouldRefresh(StatusListToken, DateTimeOffset, DateTimeOffset)"/>
/// and surfaces the verdict on <see cref="CredentialStatusOutcome.ShouldRefresh"/>, so a caller that
/// caches Status List Tokens can apply its own refresh policy to a status it already knows is valid.
/// </para>
/// </remarks>
public static class CredentialStatusGate
{
    /// <summary>
    /// Resolves the credential's verified Status List Token and reads its status.
    /// </summary>
    /// <param name="reference">The credential's status reference (<c>status_list</c> <c>idx</c>/<c>uri</c>).</param>
    /// <param name="resolveVerifiedStatusListToken">The caller-supplied resolver yielding the verified token.</param>
    /// <param name="currentTime">The current time for the token's expiry check.</param>
    /// <param name="resolvedAt">
    /// The time the returned Status List Token was originally resolved (fetched into whatever cache
    /// <paramref name="resolveVerifiedStatusListToken"/> is backed by), used to compute
    /// <see cref="CredentialStatusOutcome.ShouldRefresh"/> from the token's <c>ttl</c> claim. Pass the
    /// caller's own cache timestamp when the resolver may return a cached token; omit it (or pass
    /// <see langword="null"/>) when the resolver always fetches fresh, which makes
    /// <see cref="CredentialStatusOutcome.ShouldRefresh"/> always <see langword="false"/> — there is
    /// nothing to consider stale.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The status value, whether the credential is valid, and whether the caller's cache should refresh.</returns>
    /// <exception cref="ArgumentNullException">Thrown when <paramref name="resolveVerifiedStatusListToken"/> resolves a <see langword="null"/> token, or the delegate is <see langword="null"/>.</exception>
    /// <exception cref="StatusListValidationException">Thrown when the token's subject mismatches, the list has expired, or the index is out of bounds.</exception>
    public static async ValueTask<CredentialStatusOutcome> CheckAsync(
        StatusListReference reference,
        ResolveVerifiedStatusListTokenDelegate resolveVerifiedStatusListToken,
        DateTimeOffset currentTime,
        DateTimeOffset? resolvedAt = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(resolveVerifiedStatusListToken);

        StatusListToken token = await resolveVerifiedStatusListToken(reference.Uri, cancellationToken).ConfigureAwait(false);
        ArgumentNullException.ThrowIfNull(token);

        byte status = StatusListValidation.GetStatus(token, reference, currentTime);
        bool shouldRefresh = StatusListValidation.ShouldRefresh(token, resolvedAt ?? currentTime, currentTime);

        return new CredentialStatusOutcome
        {
            Status = status,
            IsValid = status == StatusTypes.Valid,
            ShouldRefresh = shouldRefresh
        };
    }
}
