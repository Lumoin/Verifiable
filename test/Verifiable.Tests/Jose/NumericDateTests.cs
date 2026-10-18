using Microsoft.Extensions.Time.Testing;
using System.Globalization;
using System.Numerics;
using System.Text;
using System.Text.Json;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Jose;

/// <summary>
/// Tests the library's one reading of a JWT NumericDate (<see cref="NumericDate"/>) against RFC 7519 Section 2 as its text reads -
/// "A JSON numeric value representing the number of seconds from 1970-01-01T00:00:00Z UTC", in which "non-integer values can be
/// represented" - and the readers that judge a window by it: the span reader of a claims set
/// (<see cref="JwkJsonReader.ExtractNumericDate"/>), the claims dictionary the library's JSON layer parses, and the time-bound
/// checks of a claims set (<see cref="JwtChecks"/>). Every digit written is kept, and each comparison judges the date against the
/// bound it keeps exactly, whichever side of the bound that is.
/// </summary>
[TestClass]
internal sealed class NumericDateTests
{
    /// <summary>The test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock every judgement is made by.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The clock-skew tolerance the time-bound checks are judged under.</summary>
    private static TimeSpan Skew { get; } = TimeSpan.FromSeconds(60);

    /// <summary>The JSON options the library's claims dictionary is parsed with.</summary>
    private static JsonSerializerOptions JsonOptions => TestSetup.DefaultSerializationOptions;


    /// <summary>
    /// Whole numbers of every width read as their date; a fraction names its own date exactly, a part of a tick included, so the
    /// tick at or before it and the tick at or after it differ; a string of digits, a count no clock represents, and a value of
    /// any other kind read as none.
    /// </summary>
    [TestMethod]
    public void ANumericDateIsAJsonNumberReadExactly()
    {
        var now = TimeProvider.GetUtcNow();
        var second = now.ToUnixTimeSeconds();

        Assert.AreEqual(now, NumericDate.Of(second)!.AtOrBefore);
        Assert.AreEqual(now, NumericDate.Of((int)second)!.AtOrBefore);
        Assert.AreEqual(now, NumericDate.Of((ulong)second)!.AtOrBefore);
        Assert.AreEqual(now, NumericDate.Of((uint)second)!.AtOrBefore);
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddSeconds(7), NumericDate.Of((sbyte)7)!.AtOrBefore);
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddSeconds(7), NumericDate.Of((ushort)7)!.AtOrBefore);
        Assert.AreEqual(now.AddMilliseconds(750), NumericDate.Of(second + 0.75m)!.AtOrBefore, "A fraction names its own date.");
        Assert.AreEqual(now.AddMilliseconds(750), NumericDate.Of(second + 0.75d)!.AtOrBefore, "A floating fraction names its own date.");
        Assert.IsTrue(NumericDate.Of(second + 0.75m)!.FallsOnTick, "A fraction of whole ticks falls on a tick.");
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddMilliseconds(-1500), NumericDate.Of(-1.5m)!.AtOrBefore, "A count before the epoch names its date.");

        var finerThanATick = NumericDate.Of(second + 0.00000001m)!;

        Assert.IsFalse(finerThanATick.FallsOnTick, "A part of a tick is kept, not taken onto either side.");
        Assert.AreEqual(now, finerThanATick.AtOrBefore);
        Assert.AreEqual(now.AddTicks(1), finerThanATick.AtOrAfter);
        Assert.AreEqual(string.Create(CultureInfo.InvariantCulture, $"{second}.00000001"), finerThanATick.ToString(), "The date writes back every digit written.");

        Assert.IsNull(NumericDate.Of(second.ToString(CultureInfo.InvariantCulture)), "A string of digits is no NumericDate.");
        Assert.IsNull(NumericDate.Of(long.MaxValue));
        Assert.IsNull(NumericDate.Of(double.NaN));
        Assert.IsNull(NumericDate.Of(decimal.MaxValue));
        Assert.IsNull(NumericDate.Of(true));
        Assert.IsNull(NumericDate.Of(null));
        Assert.IsNull(NumericDate.FromJsonNumber("253402300800"u8), "The second after the clock's last is no date.");
        Assert.IsNull(NumericDate.FromJsonNumber("253402300799.99999995"u8), "A date between the clock's last tick and the next lies past the clock.");
        Assert.IsNull(NumericDate.FromJsonNumber("-62135596800.00000001"u8), "A date before the clock's first instant is no date.");
        Assert.AreEqual(DateTimeOffset.MaxValue, NumericDate.FromJsonNumber("253402300799.9999999"u8)!.AtOrBefore, "The clock's last tick is a date.");
        Assert.AreEqual(DateTimeOffset.MinValue, NumericDate.FromJsonNumber("-62135596800"u8)!.AtOrBefore, "The clock's first instant is a date.");
    }


    /// <summary>
    /// A JSON number token is read by its grammar (RFC 8259 Section 6) and nothing else: a leading zero before another digit, a
    /// leading plus, a bare point, a missing exponent digit and white space around the token are none; an exponent of any size
    /// is read without forming the number it names, so a count far below a tick or far past the clock is judged, never expanded.
    /// </summary>
    [TestMethod]
    public void AJsonNumberIsReadByItsGrammarAndNoExponentIsExpanded()
    {
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddSeconds(1_700_000_000), NumericDate.FromJsonNumber("1.7e9"u8)!.AtOrBefore);
        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddSeconds(1_700_000_000), NumericDate.FromJsonNumber("17E+8"u8)!.AtOrBefore);
        Assert.AreEqual(DateTimeOffset.UnixEpoch, NumericDate.FromJsonNumber("-0"u8)!.AtOrBefore, "Minus zero is zero.");
        Assert.IsNull(NumericDate.FromJsonNumber("01"u8), "A leading zero before another digit is no JSON number.");
        Assert.IsNull(NumericDate.FromJsonNumber("+1"u8), "A leading plus is no JSON number.");
        Assert.IsNull(NumericDate.FromJsonNumber("1."u8), "A point without digits is no JSON number.");
        Assert.IsNull(NumericDate.FromJsonNumber(".5"u8), "A point without an integer part is no JSON number.");
        Assert.IsNull(NumericDate.FromJsonNumber("1e"u8), "An exponent without digits is no JSON number.");
        Assert.IsNull(NumericDate.FromJsonNumber(" 1"u8), "White space is no part of the token.");
        Assert.IsNull(NumericDate.FromJsonNumber("1e400"u8), "A count past the clock is no date.");
        Assert.IsNull(NumericDate.FromJsonNumber("1e999999999999999999999"u8), "An exponent past any integer type is read, not formed.");

        var farBelowATick = NumericDate.FromJsonNumber("1e-999999999999999999999"u8)!;

        Assert.AreEqual(DateTimeOffset.UnixEpoch, farBelowATick.AtOrBefore, "A count far below a tick lies just past the epoch.");
        Assert.IsFalse(farBelowATick.FallsOnTick);

        var justBeforeTheEpoch = NumericDate.FromJsonNumber("-1e-999999999999999999999"u8)!;

        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddTicks(-1), justBeforeTheEpoch.AtOrBefore, "A count far below a tick before the epoch lies in the tick before it.");
        Assert.IsLessThan(0, justBeforeTheEpoch.CompareTo(farBelowATick));
        Assert.IsLessThan(0, justBeforeTheEpoch.CompareTo(DateTimeOffset.UnixEpoch));
    }


    /// <summary>
    /// No digit is lost before the tick is judged: a count with more digits than a decimal keeps, read through the span reader and
    /// through the claims dictionary the library's JSON layer parses, lies a part of a tick past its whole second, so the tick at
    /// or after it is the next; and the smallest double below zero lies in the tick before the epoch, where subtracting its whole
    /// second first took it to the epoch itself.
    /// </summary>
    [TestMethod]
    public void NoDigitIsLostBeforeTheTick()
    {
        var epochSecond = DateTimeOffset.UnixEpoch.AddSeconds(1_700_000_060);
        const string PastADecimal = "1700000060.00000000000000000001";

        var fromToken = NumericDate.FromJsonNumber(Encoding.UTF8.GetBytes(PastADecimal))!;
        var fromSpan = JwkJsonReader.ExtractNumericDate(Encoding.UTF8.GetBytes($"{{\"iat\":{PastADecimal}}}"), WellKnownJwtClaimNames.IatUtf8)!;
        var claims = JsonSerializer.Deserialize<Dictionary<string, object>>($"{{\"iat\":{PastADecimal}}}", JsonOptions)!;
        var fromDictionary = NumericDate.Of(claims[WellKnownJwtClaimNames.Iat])!;

        foreach(var date in new[] { fromToken, fromSpan, fromDictionary })
        {
            Assert.AreEqual(epochSecond, date.AtOrBefore);
            Assert.IsFalse(date.FallsOnTick, "The remainder past the decimal's digits is kept.");
            Assert.AreEqual(epochSecond.AddTicks(1), date.AtOrAfter);
            Assert.AreEqual(PastADecimal, date.ToString());
        }

        var smallestBelowZero = NumericDate.Of(-double.Epsilon)!;

        Assert.AreEqual(DateTimeOffset.UnixEpoch.AddTicks(-1), smallestBelowZero.AtOrBefore, "The smallest double below zero lies in the tick before the epoch.");
        Assert.AreEqual(DateTimeOffset.UnixEpoch, smallestBelowZero.AtOrAfter);
        Assert.IsLessThan(0, smallestBelowZero.CompareTo(DateTimeOffset.UnixEpoch));
    }


    /// <summary>
    /// The claims dictionary the library's JSON layer parses boxes a number exactly: a long for a whole number a long holds, a
    /// decimal where a decimal holds the number exactly, and the exact number otherwise, which writes back every digit.
    /// </summary>
    [TestMethod]
    public void TheClaimsDictionaryBoxesEveryNumberExactly()
    {
        var claims = JsonSerializer.Deserialize<Dictionary<string, object>>(
            "{\"whole\":1700000060,\"fraction\":1700000060.5,\"exact\":1700000060.00000000000000000001,\"vast\":1e400}", JsonOptions)!;

        Assert.AreEqual(1_700_000_060L, claims["whole"]);
        Assert.AreEqual(1_700_000_060.5m, claims["fraction"]);
        _ = Assert.IsInstanceOfType<DecimalNumber>(claims["exact"]);
        _ = Assert.IsInstanceOfType<DecimalNumber>(claims["vast"], "A number past a decimal's range is boxed as written, never refused.");

        var written = JsonSerializer.Serialize(claims, JsonOptions);

        Assert.Contains("1700000060.00000000000000000001", written, "The exact number writes back every digit.");
    }


    /// <summary>
    /// Each comparison keeps the bound it enforces exactly: a date ten nanoseconds before the present less the tolerance is stale
    /// and one at it is not; a date a part of a tick past the present plus the tolerance lies in the future and one at it does
    /// not; a lifetime a part of a tick longer than the ceiling exceeds it and one exactly at it does not, its start and its end
    /// both carrying parts of a tick.
    /// </summary>
    [TestMethod]
    public void EachComparisonKeepsItsOwnBound()
    {
        var now = TimeProvider.GetUtcNow();
        var second = now.ToUnixTimeSeconds();
        var toleranceSeconds = (long)Skew.TotalSeconds;

        var tenNanosecondsStale = NumericDate.Of(second - toleranceSeconds - 0.00000001m)!;
        var atTheStaleBound = NumericDate.Of(second - toleranceSeconds)!;
        var aPartPastTheFuture = NumericDate.Of(second + toleranceSeconds + 0.00000001m)!;
        var atTheFutureBound = NumericDate.Of(second + toleranceSeconds)!;

        Assert.IsLessThan(0, tenNanosecondsStale.CompareToEarlierBy(now, Skew), "Ten nanoseconds before the freshness lower bound is before it.");
        Assert.AreEqual(0, atTheStaleBound.CompareToEarlierBy(now, Skew));
        Assert.IsGreaterThan(0, aPartPastTheFuture.CompareToLaterBy(now, Skew), "A part of a tick past the future bound is past it.");
        Assert.AreEqual(0, atTheFutureBound.CompareToLaterBy(now, Skew));

        var start = NumericDate.Of(second + 0.00000001m)!;
        var aPartTooLong = NumericDate.Of(second + 300.00000002m)!;
        var exactlyTheCeiling = NumericDate.Of(second + 300.00000001m)!;
        var ceiling = TimeSpan.FromSeconds(300);

        Assert.IsTrue(aPartTooLong.IsMoreThanAfter(start, ceiling), "A lifetime of 300.00000001 s exceeds a ceiling of 300 s.");
        Assert.IsFalse(exactlyTheCeiling.IsMoreThanAfter(start, ceiling), "A lifetime of exactly 300 s is within it.");

        var startBeforeTheEpoch = NumericDate.Of(-0.00000001m)!;
        var endAfterTheEpoch = NumericDate.Of(299.99999999m)!;
        var endJustPast = NumericDate.Of(300.00000000000000000001m)!;

        Assert.IsFalse(endAfterTheEpoch.IsMoreThanAfter(startBeforeTheEpoch, ceiling), "A window spanning the epoch of exactly 300 s is within it.");
        Assert.IsTrue(endJustPast.IsMoreThanAfter(startBeforeTheEpoch, ceiling), "One a part of a tick longer exceeds it.");
    }


    /// <summary>
    /// Expiry is exclusive (RFC 7519 Section 4.1.4: the present must be before exp): the time-bound check of a claims set has an
    /// exp at the present less the tolerance expired, the tick after it live and the tick before it expired.
    /// </summary>
    [TestMethod]
    public void TheExpiryInstantItselfHasExpired()
    {
        var now = TimeProvider.GetUtcNow();
        var atTheBound = now - Skew;

        Assert.IsTrue(PayloadExpiringAt(atTheBound).IsExpired(now, Skew), "exp at the present less the tolerance has expired.");
        Assert.IsFalse(PayloadExpiringAt(atTheBound.AddTicks(1)).IsExpired(now, Skew), "The tick after it is live.");
        Assert.IsTrue(PayloadExpiringAt(atTheBound.AddTicks(-1)).IsExpired(now, Skew), "The tick before it has expired.");
    }


    /// <summary>
    /// No tolerance overflows a comparison at the clock's extremes: an exp at the clock's last tick extended by the tolerance is
    /// judged without forming an instant past the clock, as is a not-before at its first instant reduced by it; an instant formed
    /// for a record's window takes the clock's own last or first instant where the window reaches past it.
    /// </summary>
    [TestMethod]
    public void NoToleranceOverflowsAComparisonAtTheClocksExtremes()
    {
        var now = TimeProvider.GetUtcNow();
        var latest = NumericDate.FromJsonNumber("253402300799.9999999"u8)!;
        var earliest = NumericDate.FromJsonNumber("-62135596800"u8)!;
        var atTheEnd = new JwtPayload { [WellKnownJwtClaimNames.Exp] = latest.ToClaimValue() };
        var atTheStart = new JwtPayload { [WellKnownJwtClaimNames.Nbf] = earliest.ToClaimValue(), [WellKnownJwtClaimNames.Iat] = earliest.ToClaimValue() };

        Assert.IsFalse(atTheEnd.IsExpired(now, Skew), "An exp at the clock's last tick is live, the tolerance added to it overflowing nothing.");
        Assert.IsFalse(atTheEnd.IsExpired(DateTimeOffset.MaxValue.AddTicks(-1), TimeSpan.MaxValue));
        Assert.IsFalse(atTheStart.IsNotYetValid(now, Skew));
        Assert.IsFalse(atTheStart.IsIssuedInFuture(DateTimeOffset.MinValue, TimeSpan.MaxValue));
        Assert.IsGreaterThan(0, latest.CompareToLaterBy(DateTimeOffset.MinValue, TimeSpan.MinValue));
        Assert.IsLessThan(0, earliest.CompareToEarlierBy(DateTimeOffset.MaxValue, TimeSpan.MinValue));
        Assert.AreEqual(DateTimeOffset.MaxValue, latest.AtOrAfterLaterBy(Skew), "A window reaching past the clock ends at its last instant.");
        Assert.AreEqual(DateTimeOffset.MinValue, earliest.AtOrAfterLaterBy(-Skew), "A window reaching before the clock starts at its first instant.");
        Assert.IsFalse(atTheEnd.LifetimeExceeds(Skew), "A window without a start sets no lifetime.");
    }


    /// <summary>
    /// The exact number keeps the comparisons a reader needs whatever form it was written in: the same number written with
    /// different trailing zeros, exponents or leading zeros of its fraction is the same number, and order follows value.
    /// </summary>
    [TestMethod]
    public void TheExactNumberIsCanonicalAndOrderedByValue()
    {
        Assert.AreEqual(DecimalNumber.FromJsonNumber("1.50"u8), DecimalNumber.FromJsonNumber("15e-1"u8));
        Assert.AreEqual(DecimalNumber.FromJsonNumber("0"u8), DecimalNumber.FromJsonNumber("-0.000"u8));
        Assert.AreEqual(DecimalNumber.FromDecimal(1.5m), DecimalNumber.FromJsonNumber("1.5"u8));
        Assert.AreEqual(DecimalNumber.FromDouble(0.5), DecimalNumber.FromJsonNumber("0.5"u8));
        Assert.AreEqual(DecimalNumber.FromInteger(new BigInteger(-12)), DecimalNumber.FromJsonNumber("-1.2e1"u8));
        Assert.IsLessThan(0, DecimalNumber.FromJsonNumber("0.0999"u8)!.CompareTo(DecimalNumber.FromJsonNumber("0.1"u8)!));
        Assert.IsLessThan(0, DecimalNumber.FromJsonNumber("-2"u8)!.CompareTo(DecimalNumber.FromJsonNumber("-1.99999999999999999999999999999"u8)!));
        Assert.IsGreaterThan(0, DecimalNumber.FromJsonNumber("1e-30"u8)!.CompareTo(DecimalNumber.Zero));
        Assert.AreEqual("1e-30", DecimalNumber.FromJsonNumber("0.000000000000000000000000000001"u8)!.ToString());
        Assert.AreEqual(1_700_000_060L, DecimalNumber.FromJsonNumber("1.70000006e9"u8)!.ToClaimValue());
        Assert.AreEqual(10.5m, DecimalNumber.FromJsonNumber("10.5"u8)!.ToClaimValue());
    }


    /// <summary>A claims set whose <c>exp</c> is the instant given, to its tick.</summary>
    /// <param name="expiry">The instant.</param>
    /// <returns>The claims set.</returns>
    private static JwtPayload PayloadExpiringAt(DateTimeOffset expiry) =>
        new() { [WellKnownJwtClaimNames.Exp] = NumericDate.FromInstant(expiry).ToClaimValue() };
}
