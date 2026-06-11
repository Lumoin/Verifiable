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
}
