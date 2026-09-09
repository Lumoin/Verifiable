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
/// <param name="context">
/// The reference to resolve together with the Referenced Token's verified issuer facts — see
/// <see cref="StatusListResolutionContext"/>, whose <see cref="StatusListResolutionContext.Reference"/>
/// carries the untrusted <c>uri</c> an implementation MUST run through an SSRF policy before
/// dereferencing, and whose issuer members carry what
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Section
/// 11.3</see>'s same-key recommendation is evaluated against.
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The verified Status List Token together with the instant this resolution reports it as valid from
/// (<see cref="ResolvedStatusListToken.ResolvedAt"/> — a fresh fetch reports its fetch instant, a cache
/// reports the cached instant), or <see langword="null"/> when no Status List Token could be obtained.
/// </returns>
public delegate ValueTask<ResolvedStatusListToken?> ResolveVerifiedStatusListTokenDelegate(
    StatusListResolutionContext context,
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
    /// Whether the resolved Status List Token's <c>ttl</c> claim (Section 5.1 / 8.3 step 4.d of the
    /// Token Status List specification) indicates a fresh copy SHOULD be retrieved. <c>ttl</c> is a
    /// caching hint, not a validity requirement — unlike <see cref="IsValid"/>, this being
    /// <see langword="true"/> does not mean the status is wrong or undeterminable, only that the
    /// resolved token is old enough that the caller's own refresh policy should consider re-fetching
    /// it. Computed via
    /// <see cref="StatusListValidation.ShouldRefresh(StatusListToken, DateTimeOffset, DateTimeOffset, StatusListCachingBounds?)"/>
    /// against the <see cref="ResolvedStatusListToken.ResolvedAt"/> the resolver reported (a resolution
    /// reporting the check's own <c>currentTime</c> — a resolver that always fetches fresh — makes this
    /// always <see langword="false"/>, since a token resolved this instant is never stale).
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
/// reads the bit via <see cref="StatusListValidation.GetStatus(StatusListToken, StatusListReference, DateTimeOffset, StatusListFreshnessPolicy?)"/>,
/// which also enforces the token's subject match, freshness, expiry, and index bounds — so a token
/// whose subject does not match the reference URI, is too old for the caller's freshness policy, has
/// expired, or carries an out-of-range index surfaces as a <see cref="StatusListValidationException"/>
/// (fail-closed: an undeterminable status is not a pass).
/// </para>
/// <para>
/// The token's <c>ttl</c> claim is a different kind of fact: it is a caching hint (Section 8.3 step
/// 4.d), not a validity requirement — unlike <c>exp</c>, its breach does not invalidate the status.
/// The gate therefore never rejects on <c>ttl</c>. Instead it evaluates
/// <see cref="StatusListValidation.ShouldRefresh(StatusListToken, DateTimeOffset, DateTimeOffset, StatusListCachingBounds?)"/>
/// and surfaces the verdict on <see cref="CredentialStatusOutcome.ShouldRefresh"/>, so a caller that
/// caches Status List Tokens can apply its own refresh policy to a status it already knows is valid.
/// </para>
/// </remarks>
public static class CredentialStatusGate
{
    /// <summary>
    /// Resolves the credential's verified Status List Token and reads its status.
    /// </summary>
    /// <param name="context">
    /// The credential's status reference (<c>status_list</c> <c>idx</c>/<c>uri</c>) together with the
    /// Referenced Token's verified issuer facts, handed to
    /// <paramref name="resolveVerifiedStatusListToken"/> unchanged.
    /// </param>
    /// <param name="resolveVerifiedStatusListToken">The caller-supplied resolver yielding the verified token and its resolution instant.</param>
    /// <param name="currentTime">The current time for the token's expiry and freshness checks.</param>
    /// <param name="freshnessPolicy">
    /// The caller's step 4.b freshness policy for the token's <c>iat</c>, or <see langword="null"/> to
    /// skip the check (today's behavior). Threaded to
    /// <see cref="StatusListValidation.GetStatus(StatusListToken, StatusListReference, DateTimeOffset, StatusListFreshnessPolicy?)"/>.
    /// </param>
    /// <param name="cachingBounds">
    /// The caller's Section 11.5 refresh-interval floor and ceiling, or <see langword="null"/> to use
    /// the token's <c>ttl</c> unclamped (today's behavior). Threaded to
    /// <see cref="StatusListValidation.ShouldRefresh(StatusListToken, DateTimeOffset, DateTimeOffset, StatusListCachingBounds?)"/>
    /// against the resolution's <see cref="ResolvedStatusListToken.ResolvedAt"/>.
    /// </param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The status value, whether the credential is valid, and whether the caller's cache should refresh.</returns>
    /// <exception cref="ArgumentNullException">
    /// Thrown when <paramref name="context"/> or <paramref name="resolveVerifiedStatusListToken"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="StatusListValidationException">
    /// Thrown when the token's subject mismatches, it is older than <paramref name="freshnessPolicy"/>
    /// allows, it has expired, or the index is out of bounds.
    /// Thrown as its <see cref="StatusListResolutionException"/> subtype when
    /// <paramref name="resolveVerifiedStatusListToken"/> resolves a <see langword="null"/> resolution —
    /// the resolver found nothing to obtain a status from, the same "no statement about the status can
    /// be made" outcome as every other check this gate runs. A resolver that throws its own exception
    /// for a fetch or trust failure is not wrapped here; it propagates as whatever the resolver raised.
    /// </exception>
    public static async ValueTask<CredentialStatusOutcome> CheckAsync(
        StatusListResolutionContext context,
        ResolveVerifiedStatusListTokenDelegate resolveVerifiedStatusListToken,
        DateTimeOffset currentTime,
        StatusListFreshnessPolicy? freshnessPolicy = null,
        StatusListCachingBounds? cachingBounds = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(resolveVerifiedStatusListToken);

        StatusListReference reference = context.Reference;

        ResolvedStatusListToken? resolution = await resolveVerifiedStatusListToken(context, cancellationToken).ConfigureAwait(false);
        if(resolution is null)
        {
            throw new StatusListResolutionException(
                reference.Uri, $"The resolver returned no Status List Token for '{reference.Uri}'.");
        }

        //An owned resolution's pooled Status List is released here, whether GetStatus/ShouldRefresh
        //succeed or one of them throws — CredentialStatusOutcome never carries the token itself, only
        //the bytes and booleans read from it, so nothing above this method needs the carrier alive
        //past this call. A not-owned resolution's Dispose is a no-op; its cache keeps working off the
        //same live carrier.
        using(resolution)
        {
            byte status = StatusListValidation.GetStatus(resolution.Token, reference, currentTime, freshnessPolicy);
            bool shouldRefresh = StatusListValidation.ShouldRefresh(resolution.Token, resolution.ResolvedAt, currentTime, cachingBounds);

            return new CredentialStatusOutcome
            {
                Status = status,
                IsValid = status == StatusTypes.Valid,
                ShouldRefresh = shouldRefresh
            };
        }
    }
}
