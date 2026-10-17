using Microsoft.Extensions.Time.Testing;
using System.Globalization;
using System.Text;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests the library's one reading of a JWT NumericDate (<see cref="JwtNumericDates.InstantOf"/>) against RFC 7519 Section 2 as
/// its text reads - "A JSON numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC", in which
/// "non-integer values can be represented" - and the readers that judge a window by it: the span reader of a claims set
/// (<see cref="JwkJsonReader.TryExtractNumericDate"/>) and the time-bound checks of a claims set (<see cref="JwtChecks"/>), each
/// judging the instant written to the tick, never one moved to a whole second.
/// </summary>
[TestClass]
internal sealed class JwtNumericDatesTests
{
    /// <summary>The test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock every judgement is made by.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The clock-skew tolerance the time-bound checks are judged under.</summary>
    private static TimeSpan Skew { get; } = TimeSpan.FromSeconds(60);


    /// <summary>
    /// Whole numbers of every width read as their instant; a fraction names its own instant to the tick, and only a remainder
    /// finer than a tick is taken - down for exp, up for iat and nbf - so the window never widens; a string of digits, a count no
    /// instant represents, and a value of any other kind read as none.
    /// </summary>
    [TestMethod]
    public void ANumericDateIsAJsonNumberReadToTheTick()
    {
        var now = TimeProvider.GetUtcNow();
        var second = now.ToUnixTimeSeconds();

        Assert.AreEqual(now, JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, second));
        Assert.AreEqual(now, JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, (int)second));
        Assert.AreEqual(now, JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, (ulong)second));
        Assert.AreEqual(now, JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, (uint)second));
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddSeconds(7), JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, (sbyte)7));
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddSeconds(7), JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, (ushort)7));
        Assert.AreEqual(now.AddMilliseconds(750), JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, second + 0.75m), "A fraction names its own instant.");
        Assert.AreEqual(now.AddMilliseconds(750), JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Iat, second + 0.75d), "A floating fraction names its own instant.");
        Assert.AreEqual(now.AddMilliseconds(250), JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Nbf, second + 0.25m));
        Assert.AreEqual(now, JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Nbf, second + 0m));
        Assert.AreEqual(now, JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, second + 0.00000001m), "A remainder finer than a tick is taken down for exp.");
        Assert.AreEqual(now, JwtNumericDates.InstantOf(WellKnownJwtClaimNames.AuthTime, second + 0.00000001m), "A remainder finer than a tick is taken down for every claim but iat and nbf.");
        Assert.AreEqual(now.AddTicks(1), JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Iat, second + 0.00000001m), "A remainder finer than a tick is taken up for iat.");
        Assert.AreEqual(now.AddTicks(1), JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Nbf, second + 0.00000001m), "A remainder finer than a tick is taken up for nbf.");
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddMilliseconds(-1500), JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, -1.5m), "A count before the epoch names its instant.");
        Assert.IsNull(JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, second.ToString(CultureInfo.InvariantCulture)), "A string of digits is no NumericDate.");
        Assert.IsNull(JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, long.MaxValue));
        Assert.IsNull(JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, double.NaN));
        Assert.IsNull(JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, decimal.MaxValue));
        Assert.IsNull(JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, true));
        Assert.IsNull(JwtNumericDates.InstantOf(WellKnownJwtClaimNames.Exp, null));
    }


    /// <summary>
    /// The span reader of a claims set reads a NumericDate written as one JSON number token - whole, with a fraction, or with an
    /// exponent - to the tick, where the whole-second reader it replaces found no value in a fraction; a string of digits, a
    /// number run into other bytes, a malformed fraction or exponent and an absent claim read as none.
    /// </summary>
    [TestMethod]
    public void TheSpanReaderReadsANumericDateToTheTick()
    {
        var now = TimeProvider.GetUtcNow();
        var second = now.ToUnixTimeSeconds();

        Assert.AreEqual(now, ReadExp($"{{\"exp\":{second}}}"));
        Assert.AreEqual(now.AddMilliseconds(750), ReadExp($"{{\"exp\": {second}.75 ,\"iat\":1}}"), "A fraction names its own instant.");
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddSeconds(1_700_000_000), ReadExp("{\"exp\":1.7e9}"), "An exponent names its count.");
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddMilliseconds(-1500), ReadExp("{\"exp\":-1.5}"));
        Assert.IsNull(ReadExp($"{{\"exp\":\"{second}\"}}"), "A string of digits is no NumericDate.");
        Assert.IsNull(ReadExp($"{{\"exp\":{second}abc}}"), "A number run into other bytes is none.");
        Assert.IsNull(ReadExp($"{{\"exp\":{second}.}}"), "A fraction without digits is none.");
        Assert.IsNull(ReadExp($"{{\"exp\":{second}e}}"), "An exponent without digits is none.");
        Assert.IsNull(ReadExp("{\"exp\":1e400}"), "A count past what a clock represents is none.");
        Assert.IsNull(ReadExp($"{{\"iat\":{second}}}"), "An absent claim is none.");

        var issuedAt = JwkJsonReader.TryExtractNumericDate(
            Encoding.UTF8.GetBytes($"{{\"iat\":{second}.00000001}}"), WellKnownJwtClaimNames.IatUtf8, WellKnownJwtClaimNames.Iat, out var issued);

        Assert.IsTrue(issuedAt);
        Assert.AreEqual(now.AddTicks(1), issued, "A remainder finer than a tick is taken up for iat.");
    }


    /// <summary>
    /// The time-bound checks of a claims set judge a NumericDate written with a fraction to the tick: an iat three quarters of a
    /// second past the present plus the tolerance is issued in the future, an exp three quarters of a second before the present
    /// less the tolerance has expired and an nbf three quarters of a second past the present plus the tolerance is not yet
    /// valid, where a fraction once read as no claim at all passed each check; and a claim present as no NumericDate is a bound
    /// that cannot be kept, so each check it bounds fails, where a string once read as the count it spells.
    /// </summary>
    [TestMethod]
    public void TheTimeBoundChecksJudgeAFractionalDateToTheTick()
    {
        var now = TimeProvider.GetUtcNow();
        var second = now.ToUnixTimeSeconds();
        var toleranceSeconds = (long)Skew.TotalSeconds;

        var futureIssued = new JwtPayload { [WellKnownJwtClaimNames.Iat] = second + toleranceSeconds + 0.75m };
        var issuedInside = new JwtPayload { [WellKnownJwtClaimNames.Iat] = second + toleranceSeconds - 0.25m };
        var expired = new JwtPayload { [WellKnownJwtClaimNames.Exp] = second - toleranceSeconds - 0.75m };
        var notYetValid = new JwtPayload { [WellKnownJwtClaimNames.Nbf] = second + toleranceSeconds + 0.75m };
        var unreadable = new JwtPayload
        {
            [WellKnownJwtClaimNames.Iat] = "soon",
            [WellKnownJwtClaimNames.Exp] = "later",
            [WellKnownJwtClaimNames.Nbf] = "now"
        };

        Assert.IsTrue(futureIssued.IsIssuedInFuture(now, Skew), "An iat a fraction past the tolerance is issued in the future.");
        Assert.IsFalse(issuedInside.IsIssuedInFuture(now, Skew), "An iat a fraction inside the tolerance is not.");
        Assert.IsTrue(expired.IsExpired(now, Skew), "An exp a fraction before the tolerance has expired.");
        Assert.IsTrue(notYetValid.IsNotYetValid(now, Skew), "An nbf a fraction past the tolerance is not yet valid.");
        Assert.IsTrue(unreadable.IsIssuedInFuture(now, Skew), "An unreadable iat keeps no bound.");
        Assert.IsTrue(unreadable.IsExpired(now, Skew), "An unreadable exp keeps no bound.");
        Assert.IsTrue(unreadable.IsNotYetValid(now, Skew), "An unreadable nbf keeps no bound.");
        Assert.IsTrue(unreadable.LifetimeExceeds(Skew), "An unreadable window keeps no lifetime bound.");
        Assert.IsTrue(unreadable.IsExpBeforeNbf(), "An unreadable window never opens.");
    }


    /// <summary>Reads a claims set's <c>exp</c> by the span reader.</summary>
    /// <param name="json">The claims set's JSON text.</param>
    /// <returns>The instant, or <see langword="null"/> when the reader finds none.</returns>
    private static DateTimeOffset? ReadExp(string json) =>
        JwkJsonReader.TryExtractNumericDate(Encoding.UTF8.GetBytes(json), WellKnownJwtClaimNames.ExpUtf8, WellKnownJwtClaimNames.Exp, out var instant)
            ? instant
            : null;
}
