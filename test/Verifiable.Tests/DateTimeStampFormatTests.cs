using Verifiable.Core.Model.Common;

namespace Verifiable.Tests;

[TestClass]
internal sealed class DateTimeStampFormatTests
{
    private static readonly DateTimeOffset SampleUtc = new(2024, 1, 15, 10, 30, 45, 123, TimeSpan.Zero);
    private static readonly DateTimeOffset SampleWithOffset = new(2024, 1, 15, 10, 30, 45, 123, TimeSpan.FromHours(2));

    [TestMethod]
    public void FormatUtcProducesExpectedOutput()
    {
        var result = DateTimeStampFormat.Format(SampleUtc, DateTimeStampFormat.Utc);

        Assert.AreEqual("2024-01-15T10:30:45Z", result);
    }


    [TestMethod]
    public void FormatUtcMillisecondsProducesExpectedOutput()
    {
        var result = DateTimeStampFormat.Format(SampleUtc, DateTimeStampFormat.UtcMilliseconds);

        Assert.AreEqual("2024-01-15T10:30:45.123Z", result);
    }


    [TestMethod]
    public void FormatUtcMicrosecondsProducesExpectedOutput()
    {
        var sample = new DateTimeOffset(2024, 1, 15, 10, 30, 45, TimeSpan.Zero).AddTicks(1234560);
        var result = DateTimeStampFormat.Format(sample, DateTimeStampFormat.UtcMicroseconds);

        Assert.AreEqual("2024-01-15T10:30:45.123456Z", result);
    }


    [TestMethod]
    public void FormatWithOffsetPreservesOffset()
    {
        var result = DateTimeStampFormat.Format(SampleWithOffset, DateTimeStampFormat.WithOffset);

        Assert.AreEqual("2024-01-15T10:30:45+02:00", result);
    }


    [TestMethod]
    public void FormatWithOffsetMillisecondsPreservesOffset()
    {
        var result = DateTimeStampFormat.Format(SampleWithOffset, DateTimeStampFormat.WithOffsetMilliseconds);

        Assert.AreEqual("2024-01-15T10:30:45.123+02:00", result);
    }


    [TestMethod]
    public void FormatUtcConvertsOffsetToUtc()
    {
        //10:30 at +02:00 is 08:30 UTC.
        var result = DateTimeStampFormat.Format(SampleWithOffset, DateTimeStampFormat.Utc);

        Assert.AreEqual("2024-01-15T08:30:45Z", result);
    }


    [TestMethod]
    public void FormatDateTimeAssumedUtcWhenUnspecified()
    {
        var dateTime = new DateTime(2024, 1, 15, 10, 30, 45, DateTimeKind.Unspecified);
        var result = DateTimeStampFormat.Format(dateTime);

        Assert.AreEqual("2024-01-15T10:30:45Z", result);
    }


    [TestMethod]
    public void FormatDateTimeConvertsLocalToUtc()
    {
        var localTime = new DateTime(2024, 1, 15, 10, 30, 45, DateTimeKind.Local);
        var result = DateTimeStampFormat.Format(localTime);

        //Result should be UTC version of local time.
        Assert.EndsWith("Z", result);
    }


    [TestMethod]
    [DataRow("2024-01-15T10:30:45Z")]
    [DataRow("2024-01-15T10:30:45.1Z")]
    [DataRow("2024-01-15T10:30:45.12Z")]
    [DataRow("2024-01-15T10:30:45.123Z")]
    [DataRow("2024-01-15T10:30:45.1234567Z")]
    [DataRow("2024-01-15T10:30:45+00:00")]
    [DataRow("2024-01-15T10:30:45+01:00")]
    [DataRow("2024-01-15T10:30:45-05:00")]
    [DataRow("2024-01-15T10:30:45.123+02:00")]
    [DataRow("2024-01-15T10:30:45.123456-08:00")]
    public void TryParseAcceptsValidFormats(string value)
    {
        var success = DateTimeStampFormat.TryParse(value, out var result);

        Assert.IsTrue(success, $"Expected '{value}' to be valid.");
        Assert.AreNotEqual(default, result);
    }


    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("2024-01-15T10:30:45")]
    [DataRow("2024-01-15")]
    [DataRow("10:30:45Z")]
    [DataRow("not-a-date")]
    [DataRow("2024-01-15T10:30:45.12345678Z")]
    public void TryParseRejectsInvalidFormats(string? value)
    {
        var success = DateTimeStampFormat.TryParse(value, out _);

        Assert.IsFalse(success, $"Expected '{value}' to be invalid.");
    }


    [TestMethod]
    public void ParseReturnsCorrectValue()
    {
        var result = DateTimeStampFormat.Parse("2024-01-15T10:30:45.123Z");

        Assert.AreEqual(2024, result.Year);
        Assert.AreEqual(1, result.Month);
        Assert.AreEqual(15, result.Day);
        Assert.AreEqual(10, result.Hour);
        Assert.AreEqual(30, result.Minute);
        Assert.AreEqual(45, result.Second);
        Assert.AreEqual(123, result.Millisecond);
        Assert.AreEqual(TimeSpan.Zero, result.Offset);
    }


    [TestMethod]
    public void ParsePreservesOffset()
    {
        var result = DateTimeStampFormat.Parse("2024-01-15T10:30:45+02:00");

        Assert.AreEqual(TimeSpan.FromHours(2), result.Offset);
    }


    [TestMethod]
    public void ParseThrowsForNullValue()
    {
        Assert.Throws<ArgumentNullException>(() => DateTimeStampFormat.Parse(null!));
    }


    [TestMethod]
    public void ParseThrowsForInvalidFormat()
    {
        var exception = Assert.Throws<FormatException>(() => DateTimeStampFormat.Parse("2024-01-15T10:30:45"));

        Assert.IsTrue(exception.Message.Contains("timezone", StringComparison.OrdinalIgnoreCase));
    }


    [TestMethod]
    [DataRow("2024-01-15T10:30:45Z", true)]
    [DataRow("2024-01-15T10:30:45+01:00", true)]
    [DataRow("2024-01-15T10:30:45", false)]
    [DataRow("", false)]
    [DataRow(null, false)]
    public void IsValidReturnsExpectedResult(string? value, bool expected)
    {
        var result = DateTimeStampFormat.IsValid(value);

        Assert.AreEqual(expected, result);
    }


    [TestMethod]
    public void RoundTripPreservesValue()
    {
        var original = new DateTimeOffset(2024, 6, 15, 14, 30, 45, 123, TimeSpan.Zero);
        var formatted = DateTimeStampFormat.Format(original, DateTimeStampFormat.UtcMilliseconds);
        var parsed = DateTimeStampFormat.Parse(formatted);

        Assert.AreEqual(original.Year, parsed.Year);
        Assert.AreEqual(original.Month, parsed.Month);
        Assert.AreEqual(original.Day, parsed.Day);
        Assert.AreEqual(original.Hour, parsed.Hour);
        Assert.AreEqual(original.Minute, parsed.Minute);
        Assert.AreEqual(original.Second, parsed.Second);
        Assert.AreEqual(original.Millisecond, parsed.Millisecond);
        Assert.AreEqual(original.Offset, parsed.Offset);
    }
}