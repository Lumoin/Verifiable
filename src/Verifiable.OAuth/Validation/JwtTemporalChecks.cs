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
/// </summary>
public static class JwtTemporalChecks
{
    /// <summary>
    /// Whether <paramref name="instant"/> is no later than <paramref name="now"/> extended by
    /// <paramref name="skew"/> — i.e. not in the future beyond the tolerance. Defends against a
    /// clock-skewed or hostile signer stamping <c>iat</c>/<c>nbf</c> ahead of real time.
    /// </summary>
    public static bool IsNotInFuture(DateTimeOffset instant, DateTimeOffset now, TimeSpan skew) =>
        instant <= now + skew;

    /// <summary>
    /// Whether <paramref name="instant"/> is no earlier than <paramref name="now"/> reduced by
    /// <paramref name="tolerance"/> — i.e. not stale beyond the tolerance. The lower bound of a
    /// freshness window and the <c>nbf</c>-age ceiling are both this predicate.
    /// </summary>
    public static bool IsNotStale(DateTimeOffset instant, DateTimeOffset now, TimeSpan tolerance) =>
        instant >= now - tolerance;

    /// <summary>
    /// Whether <paramref name="now"/> is before <paramref name="expiry"/> extended by
    /// <paramref name="leeway"/> — i.e. the artifact has not expired. The comparison is strict so
    /// the instant equal to the (leeway-extended) expiry is treated as expired.
    /// </summary>
    public static bool IsBeforeExpiry(DateTimeOffset now, DateTimeOffset expiry, TimeSpan leeway) =>
        now < expiry + leeway;

    /// <summary>
    /// Whether the interval from <paramref name="start"/> to <paramref name="end"/> is strictly
    /// positive. <c>exp</c> at or before <c>iat</c> (or <c>nbf</c>) is a window that never opens
    /// — structurally invalid independent of the clock.
    /// </summary>
    public static bool IsPositiveInterval(DateTimeOffset start, DateTimeOffset end) =>
        end > start;

    /// <summary>
    /// Whether the interval from <paramref name="start"/> to <paramref name="end"/> does not
    /// exceed <paramref name="ceiling"/> — the declared-lifetime ceiling that stops a long-lived
    /// signed artifact from lingering.
    /// </summary>
    public static bool IsWithinLifetimeCeiling(DateTimeOffset start, DateTimeOffset end, TimeSpan ceiling) =>
        end - start <= ceiling;


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


    /// <summary>
    /// Reads a NumericDate that may carry a fraction of a second as the instant it names.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-2">RFC 7519 §2</see> defines a NumericDate
    /// as "A JSON numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC until the
    /// specified UTC date/time, ignoring leap seconds. This is equivalent to the IEEE Std 1003.1, 2013
    /// Edition [POSIX.1] definition "Seconds Since the Epoch", in which each day is accounted for by exactly
    /// 86400 seconds, other than that non-integer values can be represented." The whole seconds are the
    /// floor of the value, so a negative fraction names an instant before the whole second it follows, and
    /// the fraction is kept to the 100-nanosecond tick a <see cref="DateTimeOffset"/> holds. Every instant
    /// from 0001-01-01T00:00:00Z up to the end of 9999-12-31T23:59:59Z is representable, the final
    /// second's fractions included; a value outside that range, or one that is not finite, is not, and the
    /// method answers <see langword="false"/> rather than throwing.
    /// </summary>
    /// <param name="unixSeconds">The seconds since the Unix epoch.</param>
    /// <param name="instant">The instant named, when representable.</param>
    /// <returns><see langword="true"/> when the value names a representable instant.</returns>
    internal static bool TryFromUnixSeconds(double unixSeconds, out DateTimeOffset instant)
    {
        instant = default;
        if(!double.IsFinite(unixSeconds)
            || unixSeconds < MinimumRepresentableUnixSeconds
            || unixSeconds >= MaximumRepresentableUnixSeconds + 1.0)
        {
            return false;
        }

        double wholeSeconds = Math.Floor(unixSeconds);

        //The fraction lies in [0, 1); its product with the ticks of a second can reach a whole second
        //in binary floating point, so it is held below one.
        long fractionTicks = Math.Min(
            (long)((unixSeconds - wholeSeconds) * TimeSpan.TicksPerSecond), TimeSpan.TicksPerSecond - 1);
        instant = DateTimeOffset.FromUnixTimeSeconds((long)wholeSeconds).AddTicks(fractionTicks);

        return true;
    }


    /// <summary>
    /// Reads a decimal NumericDate that may carry a fraction of a second as the instant it names, with the
    /// same range and flooring as <see cref="TryFromUnixSeconds(double, out DateTimeOffset)"/>.
    /// </summary>
    /// <param name="unixSeconds">The seconds since the Unix epoch.</param>
    /// <param name="instant">The instant named, when representable.</param>
    /// <returns><see langword="true"/> when the value names a representable instant.</returns>
    internal static bool TryFromUnixSeconds(decimal unixSeconds, out DateTimeOffset instant)
    {
        instant = default;
        if(unixSeconds < MinimumRepresentableUnixSeconds || unixSeconds >= MaximumRepresentableUnixSeconds + 1m)
        {
            return false;
        }

        decimal wholeSeconds = decimal.Floor(unixSeconds);
        long fractionTicks = (long)decimal.Truncate((unixSeconds - wholeSeconds) * TimeSpan.TicksPerSecond);
        instant = DateTimeOffset.FromUnixTimeSeconds((long)wholeSeconds).AddTicks(fractionTicks);

        return true;
    }
}
