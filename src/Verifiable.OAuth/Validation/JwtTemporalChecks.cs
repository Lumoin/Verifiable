using Verifiable.JCose;

namespace Verifiable.OAuth.Validation;

/// <summary>
/// Pure boundary predicates for the JWT temporal claims (<c>iat</c>, <c>nbf</c>, <c>exp</c>)
/// evaluated against a reference instant and a tolerance. These are the shared arithmetic
/// atoms the library's signed-artifact validators compose; the policy over WHICH claims are
/// required and WHICH atoms apply stays at each call site, because the contracts genuinely
/// differ:
/// <list type="bullet">
///   <item><description>
///     RFC 9101 / FAPI 2.0 Authorization Requests (<c>JarVerification</c>) require all of
///     <c>iat</c>/<c>nbf</c>/<c>exp</c> and enforce both not-in-future and lifetime ceilings.
///   </description></item>
///   <item><description>
///     SIOPv2 §11.1 Self-Issued ID Tokens (<c>SelfIssuedIdTokenValidation</c>) check only
///     <c>exp</c>.
///   </description></item>
///   <item><description>
///     RFC 9449 DPoP proofs (<c>DpopProofValidator</c>) check only an <c>iat</c> freshness
///     window — no <c>exp</c>, no <c>nbf</c>.
///   </description></item>
/// </list>
/// Centralizing only the boundary arithmetic (where the tolerance lands, strict vs.
/// non-strict comparisons) keeps the skew semantics identical across all three without
/// collapsing their distinct policies into one validator.
/// <para>
/// Every received date is the <see cref="NumericDate"/> as written, and each atom judges it
/// against its own bound exactly: no part of a tick is moved onto a bound, whichever side of
/// the bound the atom keeps, and no tolerance added to the present or a span added to a date
/// overflows the comparison at the clock's extremes.
/// </para>
/// </summary>
public static class JwtTemporalChecks
{
    /// <summary>
    /// Whether <paramref name="date"/> is no later than <paramref name="now"/> extended by
    /// <paramref name="skew"/> — i.e. not in the future beyond the tolerance. Defends against a
    /// clock-skewed or hostile signer stamping <c>iat</c>/<c>nbf</c> ahead of real time.
    /// </summary>
    /// <param name="date">The received date.</param>
    /// <param name="now">The present.</param>
    /// <param name="skew">The tolerance the present is extended by.</param>
    /// <returns><see langword="true"/> when the date lies at or before the extended present.</returns>
    public static bool IsNotInFuture(NumericDate date, DateTimeOffset now, TimeSpan skew)
    {
        ArgumentNullException.ThrowIfNull(date);

        return date.CompareToLaterBy(now, skew) <= 0;
    }

    /// <summary>
    /// Whether <paramref name="date"/> is no earlier than <paramref name="now"/> reduced by
    /// <paramref name="tolerance"/> — i.e. not stale beyond the tolerance. The lower bound of a
    /// freshness window and the <c>nbf</c>-age ceiling are both this predicate.
    /// </summary>
    /// <param name="date">The received date.</param>
    /// <param name="now">The present.</param>
    /// <param name="tolerance">The tolerance the present is reduced by.</param>
    /// <returns><see langword="true"/> when the date lies at or after the reduced present.</returns>
    public static bool IsNotStale(NumericDate date, DateTimeOffset now, TimeSpan tolerance)
    {
        ArgumentNullException.ThrowIfNull(date);

        return date.CompareToEarlierBy(now, tolerance) >= 0;
    }

    /// <summary>
    /// Whether <paramref name="now"/> is before <paramref name="expiry"/> extended by
    /// <paramref name="leeway"/> — i.e. the artifact has not expired. The comparison is strict so
    /// the instant equal to the (leeway-extended) expiry is treated as expired (RFC 7519 Section
    /// 4.1.4: the present must be before the expiration time).
    /// </summary>
    /// <param name="now">The present.</param>
    /// <param name="expiry">The received expiry.</param>
    /// <param name="leeway">The tolerance the expiry is extended by.</param>
    /// <returns><see langword="true"/> when the present lies before the extended expiry.</returns>
    public static bool IsBeforeExpiry(DateTimeOffset now, NumericDate expiry, TimeSpan leeway)
    {
        ArgumentNullException.ThrowIfNull(expiry);

        return expiry.CompareToEarlierBy(now, leeway) > 0;
    }

    /// <summary>
    /// Whether the interval from <paramref name="start"/> to <paramref name="end"/> is strictly
    /// positive. <c>exp</c> at or before <c>iat</c> (or <c>nbf</c>) is a window that never opens
    /// — structurally invalid independent of the clock.
    /// </summary>
    /// <param name="start">The received date the interval starts at.</param>
    /// <param name="end">The received date it ends at.</param>
    /// <returns><see langword="true"/> when the end lies after the start.</returns>
    public static bool IsPositiveInterval(NumericDate start, NumericDate end)
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(end);

        return end.CompareTo(start) > 0;
    }

    /// <summary>
    /// Whether the interval from <paramref name="start"/> to <paramref name="end"/> does not
    /// exceed <paramref name="ceiling"/> — the declared-lifetime ceiling that stops a long-lived
    /// signed artifact from lingering. A lifetime longer than the ceiling by any part of a tick
    /// exceeds it.
    /// </summary>
    /// <param name="start">The received date the interval starts at.</param>
    /// <param name="end">The received date it ends at.</param>
    /// <param name="ceiling">The longest lifetime admitted.</param>
    /// <returns><see langword="true"/> when the interval is at most the ceiling.</returns>
    public static bool IsWithinLifetimeCeiling(NumericDate start, NumericDate end, TimeSpan ceiling)
    {
        ArgumentNullException.ThrowIfNull(start);
        ArgumentNullException.ThrowIfNull(end);

        return !end.IsMoreThanAfter(start, ceiling);
    }


    /// <summary>
    /// The earliest Unix-seconds value a <see cref="DateTimeOffset"/> represents, 0001-01-01T00:00:00Z.
    /// </summary>
    internal static long MinimumRepresentableUnixSeconds { get; } = DateTimeOffset.MinValue.ToUnixTimeSeconds();


    /// <summary>
    /// The latest Unix-seconds value a <see cref="DateTimeOffset"/> represents, 9999-12-31T23:59:59Z.
    /// </summary>
    internal static long MaximumRepresentableUnixSeconds { get; } = DateTimeOffset.MaxValue.ToUnixTimeSeconds();


    /// <summary>
    /// Whether <paramref name="unixSeconds"/>, a NumericDate read off presented wire input, names an
    /// instant a <see cref="DateTimeOffset"/> can hold. A value outside that range cannot be compared as
    /// an instant, and <see cref="DateTimeOffset.FromUnixTimeSeconds"/> throws on it, so a validator
    /// answers it as malformed input before constructing the instant.
    /// </summary>
    /// <param name="unixSeconds">The seconds since the Unix epoch.</param>
    /// <returns><see langword="true"/> when the value is within the representable range.</returns>
    internal static bool IsRepresentableUnixSeconds(long unixSeconds) =>
        unixSeconds >= MinimumRepresentableUnixSeconds && unixSeconds <= MaximumRepresentableUnixSeconds;
}
