using Verifiable.OAuth.Validation;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The shared JWT temporal boundary predicates (<see cref="JwtTemporalChecks"/>) the JAR,
/// Self-Issued ID Token, and DPoP validators each compose. These tests pin the boundary
/// semantics — which comparisons are strict and where the tolerance lands — because the
/// callers depend on the exact edge behaviour (a one-tick drift would change a reject into
/// an accept).
/// </summary>
[TestClass]
internal sealed class JwtTemporalChecksTests
{
    private static readonly DateTimeOffset Now = new(2026, 6, 11, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Skew = TimeSpan.FromSeconds(30);


    [TestMethod]
    public void IsNotInFutureIsInclusiveAtTheSkewBoundary()
    {
        //instant exactly at now+skew is still acceptable; one tick beyond is in the future.
        Assert.IsTrue(JwtTemporalChecks.IsNotInFuture(Now + Skew, Now, Skew));
        Assert.IsTrue(JwtTemporalChecks.IsNotInFuture(Now, Now, Skew));
        Assert.IsFalse(JwtTemporalChecks.IsNotInFuture(Now + Skew + TimeSpan.FromTicks(1), Now, Skew));
    }


    [TestMethod]
    public void IsNotStaleIsInclusiveAtTheToleranceBoundary()
    {
        //instant exactly at now-tolerance is still fresh; one tick earlier is stale.
        Assert.IsTrue(JwtTemporalChecks.IsNotStale(Now - Skew, Now, Skew));
        Assert.IsTrue(JwtTemporalChecks.IsNotStale(Now, Now, Skew));
        Assert.IsFalse(JwtTemporalChecks.IsNotStale(Now - Skew - TimeSpan.FromTicks(1), Now, Skew));
    }


    [TestMethod]
    public void IsBeforeExpiryIsStrictAtTheLeewayBoundary()
    {
        //now strictly before exp+leeway is unexpired; equal to it is expired.
        DateTimeOffset exp = Now;
        TimeSpan leeway = TimeSpan.FromSeconds(10);

        Assert.IsTrue(JwtTemporalChecks.IsBeforeExpiry(exp + leeway - TimeSpan.FromTicks(1), exp, leeway));
        Assert.IsFalse(JwtTemporalChecks.IsBeforeExpiry(exp + leeway, exp, leeway));
        Assert.IsFalse(JwtTemporalChecks.IsBeforeExpiry(exp + leeway + TimeSpan.FromTicks(1), exp, leeway));
    }


    [TestMethod]
    public void IsPositiveIntervalRequiresEndStrictlyAfterStart()
    {
        Assert.IsTrue(JwtTemporalChecks.IsPositiveInterval(Now, Now + TimeSpan.FromTicks(1)));
        Assert.IsFalse(JwtTemporalChecks.IsPositiveInterval(Now, Now));
        Assert.IsFalse(JwtTemporalChecks.IsPositiveInterval(Now, Now - TimeSpan.FromTicks(1)));
    }


    [TestMethod]
    public void IsWithinLifetimeCeilingIsInclusiveAtTheCeiling()
    {
        TimeSpan ceiling = TimeSpan.FromMinutes(5);

        Assert.IsTrue(JwtTemporalChecks.IsWithinLifetimeCeiling(Now, Now + ceiling, ceiling));
        Assert.IsTrue(JwtTemporalChecks.IsWithinLifetimeCeiling(Now, Now + ceiling - TimeSpan.FromTicks(1), ceiling));
        Assert.IsFalse(JwtTemporalChecks.IsWithinLifetimeCeiling(Now, Now + ceiling + TimeSpan.FromTicks(1), ceiling));
    }
}
