using Microsoft.Extensions.Time.Testing;
using System.Text.Json;
using Verifiable.JCose;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests the time-bound checks of a claims set (<see cref="JwtChecks"/>) and the shared temporal atoms
/// (<see cref="JwtTemporalChecks"/>) at their exact bounds: each date is judged against the bound it keeps as written, the expiry
/// instant itself has expired (RFC 7519 Section 4.1.4: the present must be before exp), and no tolerance added to a date the clock
/// represents overflows a comparison.
/// </summary>
[TestClass]
internal sealed class JwtTimeBoundCheckBoundaryTests
{
    /// <summary>The test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock every judgement is made by, at a whole second so each date below is written exactly.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000));

    /// <summary>The clock-skew tolerance the checks are judged under.</summary>
    private static TimeSpan Skew { get; } = TimeSpan.FromSeconds(60);

    /// <summary>The JSON options the library's claims dictionary is parsed with.</summary>
    private static JsonSerializerOptions JsonOptions => TestSetup.DefaultSerializationOptions;


    /// <summary>
    /// A window whose nbf lies ten nanoseconds into its second and whose exp lies twenty nanoseconds into its, sixty seconds on,
    /// is 60.00000001 s long and exceeds a 60 s maximum, where taking its start up to the next tick and its end down to its tick
    /// read it as within; one exactly 60 s long does not exceed it.
    /// </summary>
    [TestMethod]
    public void ALifetimeIsJudgedExactlyAgainstItsMaximum()
    {
        var second = TimeProvider.GetUtcNow().ToUnixTimeSeconds();

        var aPartTooLong = new JwtPayload
        {
            [WellKnownJwtClaimNames.Nbf] = second + 0.00000001m,
            [WellKnownJwtClaimNames.Exp] = second + 60.00000002m
        };
        var exactlyTheMaximum = new JwtPayload
        {
            [WellKnownJwtClaimNames.Nbf] = second + 0.00000001m,
            [WellKnownJwtClaimNames.Exp] = second + 60.00000001m
        };

        Assert.IsTrue(aPartTooLong.LifetimeExceeds(Skew), "A window of 60.00000001 s exceeds a 60 s maximum.");
        Assert.IsFalse(exactlyTheMaximum.LifetimeExceeds(Skew), "A window of exactly 60 s does not.");
    }


    /// <summary>
    /// The expiry instant itself has expired: an exp at the present less the tolerance is expired, the tick after it live and the
    /// tick before it expired.
    /// </summary>
    [TestMethod]
    public void TheExpiryInstantItselfHasExpired()
    {
        var now = TimeProvider.GetUtcNow();
        var bound = now.ToUnixTimeSeconds() - (long)Skew.TotalSeconds;
        const decimal OneTick = 0.0000001m;

        Assert.IsTrue(new JwtPayload { [WellKnownJwtClaimNames.Exp] = (decimal)bound }.IsExpired(now, Skew), "exp at the present less the tolerance has expired.");
        Assert.IsFalse(new JwtPayload { [WellKnownJwtClaimNames.Exp] = bound + OneTick }.IsExpired(now, Skew), "The tick after it is live.");
        Assert.IsTrue(new JwtPayload { [WellKnownJwtClaimNames.Exp] = bound - OneTick }.IsExpired(now, Skew), "The tick before it has expired.");
    }


    /// <summary>
    /// An exp at the clock's last tick is judged under an ordinary tolerance without the tolerance carrying the instant past the
    /// clock, by the time-bound check of a claims set and by the shared expiry atom alike.
    /// </summary>
    [TestMethod]
    public void AnExpiryAtTheClocksLastTickOverflowsNoComparison()
    {
        var now = TimeProvider.GetUtcNow();
        var atTheClocksEnd = new JwtPayload { [WellKnownJwtClaimNames.Exp] = 253_402_300_799.9999999m };

        Assert.IsFalse(atTheClocksEnd.IsExpired(now, Skew), "An exp at the clock's last tick has not expired.");
        Assert.IsTrue(JwtTemporalChecks.IsBeforeExpiry(now, DateTimeOffset.MaxValue, Skew), "The present lies before the clock's last tick extended by the tolerance.");
    }


    /// <summary>
    /// No digit is lost before a bound is judged: an iat whose count carries a remainder past the digits a decimal keeps lies past
    /// the present plus the tolerance by that remainder, read through the claims dictionary the library's JSON layer parses, where
    /// rounding it to a decimal's digits put it onto the bound.
    /// </summary>
    [TestMethod]
    public void AnIatPastTheToleranceByLessThanADecimalKeepsIsIssuedInTheFuture()
    {
        var now = TimeProvider.GetUtcNow();
        var bound = now.ToUnixTimeSeconds() + (long)Skew.TotalSeconds;
        var claims = JsonSerializer.Deserialize<Dictionary<string, object>>($"{{\"iat\":{bound}.00000000000000000001}}", JsonOptions)!;
        var atTheBound = JsonSerializer.Deserialize<Dictionary<string, object>>($"{{\"iat\":{bound}}}", JsonOptions)!;

        Assert.IsTrue(PayloadOf(claims).IsIssuedInFuture(now, Skew), "An iat past the tolerance by 1e-20 s is issued in the future.");
        Assert.IsFalse(PayloadOf(atTheBound).IsIssuedInFuture(now, Skew), "An iat at the tolerance is not.");
    }


    /// <summary>A claims set holding every member of the parsed claims given, each as the JSON layer boxed it.</summary>
    /// <param name="claims">The parsed claims.</param>
    /// <returns>The claims set.</returns>
    private static JwtPayload PayloadOf(Dictionary<string, object> claims)
    {
        var payload = new JwtPayload();

        foreach(var claim in claims)
        {
            payload[claim.Key] = claim.Value;
        }

        return payload;
    }
}
