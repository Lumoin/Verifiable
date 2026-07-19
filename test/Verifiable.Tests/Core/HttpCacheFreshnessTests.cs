using System;
using System.Collections.Generic;
using System.Globalization;
using Verifiable.Core.OutboundFetch;

namespace Verifiable.Tests.Core;

/// <summary>
/// Known-answer tests for <see cref="HttpCacheFreshness.Compute(OutboundResponse)"/> against
/// the RFC 9111 subset it implements: <c>Cache-Control</c> <c>no-store</c>/<c>no-cache</c>/
/// <c>max-age</c>/<c>s-maxage</c>, the <c>Age</c> header, and the <c>Expires</c>/<c>Date</c>
/// fallback. Every case is header-only input to a pure function — no clock, no network.
/// </summary>
[TestClass]
internal sealed class HttpCacheFreshnessTests
{
    [TestMethod]
    public void NoStoreIsNotStorable()
    {
        OutboundResponse response = Response(("Cache-Control", "no-store"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsFalse(result.IsStorable);
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime);
    }


    [TestMethod]
    public void NoStoreWinsOverMaxAge()
    {
        OutboundResponse response = Response(("Cache-Control", "max-age=300, no-store"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsFalse(result.IsStorable, "no-store is the most restrictive directive present.");
    }


    [TestMethod]
    public void NoCacheIsStorableWithZeroFreshnessAndMustRevalidate()
    {
        OutboundResponse response = Response(("Cache-Control", "no-cache"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable, "no-cache still allows the entry to be kept as a validation target.");
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime);
        Assert.IsTrue(result.MustRevalidate, "no-cache requires revalidation before every reuse (RFC 9111 §5.2.2.4).");
    }


    [TestMethod]
    public void MustRevalidateIsFalseWithoutNoCache()
    {
        OutboundResponse response = Response(("Cache-Control", "max-age=300"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsFalse(result.MustRevalidate, "A positive header lifetime is not a must-revalidate response.");
    }


    [TestMethod]
    public void MustRevalidateIsFalseWhenNoExpirationSignalIsPresent()
    {
        OutboundResponse response = Response(("Content-Type", "application/json"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsFalse(result.MustRevalidate,
            "An absent expiration signal is heuristic-eligible, distinct from an explicit no-cache.");
    }


    [TestMethod]
    public void NoCacheWinsOverMaxAge()
    {
        OutboundResponse response = Response(("Cache-Control", "max-age=300, no-cache"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime, "no-cache is the most restrictive directive present.");
    }


    [TestMethod]
    public void MaxAgeAloneYieldsFreshnessLifetime()
    {
        OutboundResponse response = Response(("Cache-Control", "max-age=300"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.FromSeconds(300), result.FreshnessLifetime);
    }


    [TestMethod]
    public void MaxAgeWithAgeHeaderSubtractsElapsedTime()
    {
        OutboundResponse response = Response(
            ("Cache-Control", "max-age=300"),
            ("Age", "100"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.AreEqual(TimeSpan.FromSeconds(200), result.FreshnessLifetime);
    }


    [TestMethod]
    public void AgeGreaterThanMaxAgeClampsToZeroRatherThanNegative()
    {
        OutboundResponse response = Response(
            ("Cache-Control", "max-age=60"),
            ("Age", "9000"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime);
    }


    [TestMethod]
    public void SharedMaxAgeOverridesMaxAge()
    {
        OutboundResponse response = Response(("Cache-Control", "max-age=300, s-maxage=60"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.AreEqual(TimeSpan.FromSeconds(60), result.FreshnessLifetime,
            "s-maxage overrides max-age for a shared-cache consumer (RFC 9111 §5.2.2.10).");
    }


    [TestMethod]
    public void SharedMaxAgeAppliesWhenMaxAgeAbsent()
    {
        OutboundResponse response = Response(("Cache-Control", "s-maxage=120"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.AreEqual(TimeSpan.FromSeconds(120), result.FreshnessLifetime);
    }


    [TestMethod]
    public void ExpiresMinusDateFallbackAppliesWhenNoCacheControl()
    {
        DateTimeOffset date = new(2024, 1, 15, 10, 0, 0, TimeSpan.Zero);
        DateTimeOffset expires = date.AddSeconds(300);
        OutboundResponse response = Response(
            ("Date", date.ToString("r", CultureInfo.InvariantCulture)),
            ("Expires", expires.ToString("r", CultureInfo.InvariantCulture)));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.FromSeconds(300), result.FreshnessLifetime);
    }


    [TestMethod]
    public void ExpiresBeforeDateYieldsZeroFreshness()
    {
        DateTimeOffset date = new(2024, 1, 15, 10, 0, 0, TimeSpan.Zero);
        DateTimeOffset expires = date.AddSeconds(-300);
        OutboundResponse response = Response(
            ("Date", date.ToString("r", CultureInfo.InvariantCulture)),
            ("Expires", expires.ToString("r", CultureInfo.InvariantCulture)));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime);
    }


    [TestMethod]
    public void MaxAgeIsIgnoredWhenComputingFallbackAndTakesPrecedenceOverExpires()
    {
        DateTimeOffset date = new(2024, 1, 15, 10, 0, 0, TimeSpan.Zero);
        DateTimeOffset expires = date.AddSeconds(9000);
        OutboundResponse response = Response(
            ("Cache-Control", "max-age=30"),
            ("Date", date.ToString("r", CultureInfo.InvariantCulture)),
            ("Expires", expires.ToString("r", CultureInfo.InvariantCulture)));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.AreEqual(TimeSpan.FromSeconds(30), result.FreshnessLifetime,
            "RFC 9111 §4.2.1 evaluates max-age before falling back to Expires/Date.");
    }


    [TestMethod]
    public void ExpiresWithoutDateYieldsZeroFreshness()
    {
        DateTimeOffset expires = new(2024, 1, 15, 10, 5, 0, TimeSpan.Zero);
        OutboundResponse response = Response(("Expires", expires.ToString("r", CultureInfo.InvariantCulture)));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime, "No Date reference instant is available to measure Expires against.");
    }


    [TestMethod]
    public void DateWithoutExpiresYieldsZeroFreshness()
    {
        DateTimeOffset date = new(2024, 1, 15, 10, 0, 0, TimeSpan.Zero);
        OutboundResponse response = Response(("Date", date.ToString("r", CultureInfo.InvariantCulture)));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime);
    }


    [TestMethod]
    public void MalformedExpiresIsTreatedAsAlreadyExpired()
    {
        DateTimeOffset date = new(2024, 1, 15, 10, 0, 0, TimeSpan.Zero);
        OutboundResponse response = Response(
            ("Date", date.ToString("r", CultureInfo.InvariantCulture)),
            ("Expires", "not-a-date"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime);
    }


    [TestMethod]
    public void MalformedMaxAgeIsTreatedAsStaleRatherThanFallingBackToExpires()
    {
        DateTimeOffset date = new(2024, 1, 15, 10, 0, 0, TimeSpan.Zero);
        DateTimeOffset expires = date.AddSeconds(9000);
        OutboundResponse response = Response(
            ("Cache-Control", "max-age=not-a-number"),
            ("Date", date.ToString("r", CultureInfo.InvariantCulture)),
            ("Expires", expires.ToString("r", CultureInfo.InvariantCulture)));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime);
    }


    [TestMethod]
    public void MalformedAgeHeaderIsIgnored()
    {
        OutboundResponse response = Response(
            ("Cache-Control", "max-age=300"),
            ("Age", "not-a-number"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.AreEqual(TimeSpan.FromSeconds(300), result.FreshnessLifetime,
            "An invalid Age value is ignored (RFC 9111 §5.1): it contributes no elapsed time, so the full max-age lifetime remains.");
    }


    [TestMethod]
    public void MalformedEverythingIsZeroFreshnessAndStorable()
    {
        OutboundResponse response = Response(
            ("Cache-Control", "max-age=garbage, ,==,"),
            ("Date", "definitely not a date"),
            ("Expires", "also not a date"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable, "No no-store directive was present.");
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime);
    }


    [TestMethod]
    public void MissingHeadersAreZeroFreshnessAndStorable()
    {
        OutboundResponse response = Response();

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.Zero, result.FreshnessLifetime);
    }


    [TestMethod]
    public void QuotedWhitespaceAndMixedCaseDirectivesAreParsed()
    {
        OutboundResponse response = Response(("Cache-Control", "  Max-Age = \"300\" ,  S-MaxAge=\"60\"  "));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsTrue(result.IsStorable);
        Assert.AreEqual(TimeSpan.FromSeconds(60), result.FreshnessLifetime,
            "Directive names compare case-insensitively and both token and quoted-string argument forms are accepted (RFC 9111 §5.2).");
    }


    [TestMethod]
    public void MixedCaseNoStoreDirectiveIsRecognized()
    {
        OutboundResponse response = Response(("Cache-Control", "NO-STORE"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.IsFalse(result.IsStorable);
    }


    [TestMethod]
    public void DeltaSecondsOverflowClampsRatherThanRejects()
    {
        OutboundResponse response = Response(("Cache-Control", "max-age=99999999999999999999999999999999"));

        HttpCacheFreshness result = HttpCacheFreshness.Compute(response);

        Assert.AreEqual(TimeSpan.FromSeconds(2_147_483_648L), result.FreshnessLifetime,
            "RFC 9111 §1.2.2: an unrepresentable delta-seconds value is clamped to 2^31, not treated as invalid.");
    }


    private static OutboundResponse Response(params (string Name, string Value)[] headers)
    {
        Dictionary<string, string> headerMap = new(StringComparer.OrdinalIgnoreCase);
        foreach((string name, string value) in headers)
        {
            headerMap[name] = value;
        }

        return new OutboundResponse
        {
            StatusCode = 200,
            Headers = headerMap,
        };
    }
}
