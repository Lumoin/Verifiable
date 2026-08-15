using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESDateTime.TryParse"/> against
/// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime">XML Schema Part 2: Datatypes</see>
/// section 3.2.7's <c>xsd:dateTime</c> lexical grammar — the type <c>SigningTime</c> (clause 5.2.1 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>) carries. Every case here operates on the raw lexical span directly, the
/// same "test the primitive against spec text" idiom <c>XmlBase64ContentTests</c> uses for the base64 decoder
/// — <see cref="XAdESSigningTimeTests"/> separately proves the full element-reading wiring.
/// </summary>
[TestClass]
internal sealed class XAdESDateTimeTests
{
    /// <summary>
    /// Proves the minimal valid shape — a UTC-timezoned <c>xsd:dateTime</c> with the literal <c>Z</c> — parses
    /// per <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation">XML
    /// Schema Part 2: Datatypes</see> section 3.2.7.1's grammar, with every decomposed field retained exactly —
    /// the shape <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> requires.
    /// </summary>
    [TestMethod]
    public void MinimalUtcDateTimeParses()
    {
        bool isParsed = XAdESDateTime.TryParse("2024-01-01T00:00:00Z"u8, out XAdESDateTime value);
        Assert.IsTrue(isParsed, "A minimal, well-formed UTC dateTime must parse.");
        Assert.IsFalse(value.IsNegativeYear);
        Assert.AreEqual(2024L, value.Year);
        Assert.AreEqual(1, value.Month);
        Assert.AreEqual(1, value.Day);
        Assert.AreEqual(0, value.Hour);
        Assert.AreEqual(0, value.Minute);
        Assert.AreEqual(0, value.Second);
        Assert.IsFalse(value.HasFractionalSecond);
        Assert.IsTrue(value.HasTimezone);
        Assert.IsTrue(value.IsUtcTimezone);
    }


    /// <summary>
    /// Proves a value with no timezone component at all — <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation">
    /// XML Schema Part 2: Datatypes</see> section 3.2.7.1's <c>(zzzzzz)?</c> is optional — parses with
    /// <see cref="XAdESDateTime.HasTimezone"/> <see langword="false"/> ("local" or untimezoned time, per the
    /// clause's own introductory paragraph) — the same <c>xsd:dateTime</c> type
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> carries.
    /// </summary>
    [TestMethod]
    public void ValueWithNoTimezoneParses()
    {
        bool isParsed = XAdESDateTime.TryParse("2024-06-15T12:30:45"u8, out XAdESDateTime value);
        Assert.IsTrue(isParsed, "A dateTime without a timezone component must parse.");
        Assert.IsFalse(value.HasTimezone);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation">XML
    /// Schema Part 2: Datatypes</see> section 3.2.7.1's fractional-second grammar (<c>'.' s+</c>) parses,
    /// retaining the exact digit run via
    /// <see cref="XAdESDateTime.FractionalSecondNumerator"/>/<see cref="XAdESDateTime.FractionalSecondDigitCount"/>
    /// rather than converting to a floating value — "the parse retains the lexical value and components; no
    /// clock reads, no conversion" is the design brief this proves, over the <c>xsd:dateTime</c> type
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void FractionalSecondsAreRetainedExactly()
    {
        bool isParsed = XAdESDateTime.TryParse("2024-06-15T12:30:45.500Z"u8, out XAdESDateTime value);
        Assert.IsTrue(isParsed, "A dateTime with fractional seconds must parse.");
        Assert.IsTrue(value.HasFractionalSecond);
        Assert.AreEqual(500L, value.FractionalSecondNumerator);
        Assert.AreEqual(3, value.FractionalSecondDigitCount);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation">XML
    /// Schema Part 2: Datatypes</see> section 3.2.7.1's leap-day boundary: 29 February parses in a leap year
    /// (2024, divisible by 4, not a century year) and is refused in a non-leap year (2023) — "the day value ...
    /// cannot even be 29 for month 02 and year 2002" is the clause's own worked (non-leap) example; this proves
    /// both directions, over the <c>xsd:dateTime</c> type
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void LeapDayBoundaryIsEnforced()
    {
        Assert.IsTrue(XAdESDateTime.TryParse("2024-02-29T00:00:00Z"u8, out _), "29 February 2024 (a leap year) must parse.");
        Assert.IsFalse(XAdESDateTime.TryParse("2023-02-29T00:00:00Z"u8, out _), "29 February 2023 (not a leap year) must be refused.");
    }


    /// <summary>
    /// Proves the century-year refinement of the Gregorian leap-year rule
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime">XML Schema Part 2:
    /// Datatypes</see> section 3.2.7 implies via its Gregorian reference but does not spell out digit-by-digit:
    /// 1900 (divisible by 100, not by 400) is not a leap year, while 2000 (divisible by 400) is — both
    /// boundary cases are proven explicitly, over the <c>xsd:dateTime</c> type
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void CenturyYearLeapRuleIsEnforced()
    {
        Assert.IsFalse(XAdESDateTime.TryParse("1900-02-29T00:00:00Z"u8, out _), "1900 is divisible by 100 but not 400, so it is not a leap year.");
        Assert.IsTrue(XAdESDateTime.TryParse("2000-02-29T00:00:00Z"u8, out _), "2000 is divisible by 400, so it is a leap year.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation">XML
    /// Schema Part 2: Datatypes</see> section 3.2.7.1's <c>hh</c> boundary: <c>'24'</c> is permitted only when
    /// the minutes and seconds represented are zero, denoting "the first instant of the following day" — both
    /// the accepted boundary shape and the refused non-zero-minute/-second variants are proven, over the
    /// <c>xsd:dateTime</c> type <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void Hour24IsPermittedOnlyAtExactMidnightBoundary()
    {
        Assert.IsTrue(XAdESDateTime.TryParse("2024-01-01T24:00:00Z"u8, out XAdESDateTime value), "24:00:00 must parse.");
        Assert.AreEqual(24, value.Hour);
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T24:00:01Z"u8, out _), "24:00:01 (non-zero second) must be refused.");
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T24:01:00Z"u8, out _), "24:01:00 (non-zero minute) must be refused.");
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T25:00:00Z"u8, out _), "25 is never a valid hour value.");
    }


    /// <summary>
    /// Proves a fractional-second component combined with hour <c>24</c> is refused: <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation"> XML
    /// Schema Part 2: Datatypes</see> section 3.2.7.1 never contemplates the combination, and it would name an instant past the very day boundary the <c>24</c> form exists to denote —
    /// ratifies this refusal for the <c>xsd:dateTime</c> type <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319
    /// 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void Hour24WithFractionalSecondIsRefused()
    {
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T24:00:00.5Z"u8, out _), "24:00:00.5 must be refused.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-timezones">XML Schema
    /// Part 2: Datatypes</see> section 3.2.7.3's timezone-magnitude edge: <c>+14:00</c> and <c>-14:00</c> are
    /// the maximum permitted magnitude ("the hour magnitude limited to at most 14") and parse; <c>+14:30</c>
    /// (a non-zero minute at the 14-hour boundary, forbidden by the same clause's parenthetical) and
    /// <c>+15:00</c> (beyond the magnitude bound) are both refused — over the <c>xsd:dateTime</c> type
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void FourteenHourTimezoneEdgeIsEnforced()
    {
        Assert.IsTrue(XAdESDateTime.TryParse("2024-01-01T00:00:00+14:00"u8, out XAdESDateTime positive), "+14:00 must parse.");
        Assert.AreEqual(14, positive.TimezoneHours);
        Assert.AreEqual(0, positive.TimezoneMinutes);
        Assert.IsFalse(positive.IsTimezoneNegative);

        Assert.IsTrue(XAdESDateTime.TryParse("2024-01-01T00:00:00-14:00"u8, out XAdESDateTime negative), "-14:00 must parse.");
        Assert.IsTrue(negative.IsTimezoneNegative);

        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:00:00+14:30"u8, out _), "+14:30 (non-zero minute at the 14-hour boundary) must be refused.");
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:00:00+15:00"u8, out _), "+15:00 (beyond the 14-hour magnitude bound) must be refused.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-timezones">XML Schema
    /// Part 2: Datatypes</see> section 3.2.7.3's note that <c>+00:00</c>, <c>-00:00</c> and <c>Z</c> all
    /// denote the same zero-length-duration timezone but only <c>Z</c> is canonical: this parser keeps the
    /// written forms lexically distinct (<see cref="XAdESDateTime.IsUtcTimezone"/> is <see langword="true"/>
    /// only for the literal <c>Z</c>) rather than collapsing them, per the "retains the lexical value ... no
    /// conversion" design brief, over the <c>xsd:dateTime</c> type
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void ExplicitZeroOffsetStaysDistinctFromLiteralZ()
    {
        Assert.IsTrue(XAdESDateTime.TryParse("2024-01-01T00:00:00+00:00"u8, out XAdESDateTime explicitPositive));
        Assert.IsTrue(explicitPositive.HasTimezone);
        Assert.IsFalse(explicitPositive.IsUtcTimezone, "+00:00 must not be collapsed into the literal Z form.");

        Assert.IsTrue(XAdESDateTime.TryParse("2024-01-01T00:00:00Z"u8, out XAdESDateTime literalZ));
        Assert.IsTrue(literalZ.IsUtcTimezone);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime">XML Schema Part 2:
    /// Datatypes</see> section 3.2.7's own note: <c>'-0001'</c> is the lexical representation of the year 1
    /// Before Common Era, and this version of the datatype has no year zero — the <c>xsd:dateTime</c> type
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void NegativeYearParsesAsBeforeCommonEra()
    {
        bool isParsed = XAdESDateTime.TryParse("-0001-01-01T00:00:00Z"u8, out XAdESDateTime value);
        Assert.IsTrue(isParsed, "-0001-01-01T00:00:00Z (1 BCE) must parse.");
        Assert.IsTrue(value.IsNegativeYear);
        Assert.AreEqual(1L, value.Year);
    }


    /// <summary>
    /// Proves, per <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime">XML Schema Part 2:
    /// Datatypes</see> section 3.2.7's no-year-zero note, 1 BCE (lexical <c>-0001</c>) is astronomical year 0,
    /// a leap year: <c>-0001-02-29</c> must parse — the <c>xsd:dateTime</c> type
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void OneBceIsALeapYear()
    {
        Assert.IsTrue(XAdESDateTime.TryParse("-0001-02-29T00:00:00Z"u8, out _), "-0001 (1 BCE, astronomical year 0) must be a leap year.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime">XML Schema Part 2:
    /// Datatypes</see> section 3.2.7's note above 3.2.7.1: "'0000' is prohibited" — refused regardless of a
    /// leading <c>'-'</c>, since the magnitude itself is disallowed, not merely the unsigned literal — over the
    /// <c>xsd:dateTime</c> type <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void YearZeroIsRefused()
    {
        Assert.IsFalse(XAdESDateTime.TryParse("0000-01-01T00:00:00Z"u8, out _), "0000-01-01T00:00:00Z must be refused.");
        Assert.IsFalse(XAdESDateTime.TryParse("-0000-01-01T00:00:00Z"u8, out _), "-0000-01-01T00:00:00Z must be refused.");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation">XML
    /// Schema Part 2: Datatypes</see> section 3.2.7.1's leading-zero rule for extended years: "if more than
    /// four digits, leading zeros are prohibited" — a 5-digit year starting with <c>0</c> is refused, while
    /// the same digit count without a leading zero parses — over the <c>xsd:dateTime</c> type
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void ExtendedYearLeadingZeroRuleIsEnforced()
    {
        Assert.IsFalse(XAdESDateTime.TryParse("01234-01-01T00:00:00Z"u8, out _), "A 5-digit year with a leading zero must be refused.");
        Assert.IsTrue(XAdESDateTime.TryParse("12345-01-01T00:00:00Z"u8, out XAdESDateTime value), "A 5-digit year without a leading zero must parse.");
        Assert.AreEqual(12345L, value.Year);
    }


    /// <summary>
    /// Proves the whole-seconds field is never optional: a value omitting it (<c>hh:mm</c> with no
    /// <c>:ss</c>) is refused rather than defaulted — <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation">
    /// XML Schema Part 2: Datatypes</see> section 3.2.7.1's grammar fixes <c>':' ss</c> as a mandatory part of
    /// the production — the <c>xsd:dateTime</c> type
    /// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void MissingSecondsIsRefused()
    {
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:00Z"u8, out _), "A dateTime with no seconds field must be refused.");
    }


    /// <summary>
    /// Proves no whitespace is tolerated anywhere in the lexical value — neither a leading/trailing space nor one embedded mid-value — since <see
    /// href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation"> XML Schema Part 2: Datatypes</see> section 3.2.7.1 defines one fixed-shape production with no whitespace-tolerant
    /// variant, matching the "no whitespace tolerance" requirement — over the <c>xsd:dateTime</c> type <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI
    /// EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void EmbeddedOrSurroundingWhitespaceIsRefused()
    {
        Assert.IsFalse(XAdESDateTime.TryParse(" 2024-01-01T00:00:00Z"u8, out _), "Leading whitespace must be refused.");
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:00:00Z "u8, out _), "Trailing whitespace must be refused.");
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:00:00 Z"u8, out _), "Whitespace between the seconds field and the timezone must be refused.");
    }


    /// <summary>
    /// Proves a timezone offset missing its minute digits (<c>+05:</c>, with nothing after the colon) is
    /// refused rather than defaulted to zero, per <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-timezones">
    /// XML Schema Part 2: Datatypes</see> section 3.2.7.3's fixed <c>hh ':' mm</c> shape — the
    /// <c>xsd:dateTime</c> type <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void EmptyTimezoneMinutesIsRefused()
    {
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:00:00+05:"u8, out _), "A timezone with no minute digits must be refused.");
    }


    /// <summary>
    /// Proves each numeric field's range, per <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime">
    /// XML Schema Part 2: Datatypes</see> section 3.2.7's "the value of each numeric-valued property ... is
    /// limited to the maximum value within the interval determined by the next-higher property," is enforced:
    /// month 13, a day beyond the 30 days April (a 30-day month) has, minute 60, and second 60 are all refused —
    /// over the <c>xsd:dateTime</c> type <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void OutOfRangeFieldsAreRefused()
    {
        Assert.IsFalse(XAdESDateTime.TryParse("2024-13-01T00:00:00Z"u8, out _), "Month 13 must be refused.");
        Assert.IsFalse(XAdESDateTime.TryParse("2024-00-01T00:00:00Z"u8, out _), "Month 00 must be refused.");
        Assert.IsFalse(XAdESDateTime.TryParse("2024-04-31T00:00:00Z"u8, out _), "31 April must be refused — April has 30 days.");
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-00T00:00:00Z"u8, out _), "Day 00 must be refused.");
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:60:00Z"u8, out _), "Minute 60 must be refused.");
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:00:60Z"u8, out _), "Second 60 must be refused.");
    }


    /// <summary>
    /// Proves a fractional-second marker with no following digit is refused rather than treated as an absent
    /// fraction — <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation">
    /// XML Schema Part 2: Datatypes</see> section 3.2.7.1's <c>'.' s+</c> requires at least one digit — the
    /// <c>xsd:dateTime</c> type <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void FractionMarkerWithNoDigitsIsRefused()
    {
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:00:00.Z"u8, out _), "A bare '.' with no following digit must be refused.");
    }


    /// <summary>
    /// Proves empty content is refused — the empty span matches no production of
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation">XML
    /// Schema Part 2: Datatypes</see> section 3.2.7.1's grammar, including empty content for the
    /// <c>xsd:dateTime</c> type <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void EmptyContentIsRefused()
    {
        Assert.IsFalse(XAdESDateTime.TryParse(ReadOnlySpan<byte>.Empty, out _), "Empty content must be refused.");
    }


    /// <summary>
    /// Proves trailing content after a complete, valid value is refused — the whole span must be consumed, not
    /// merely a prefix of it, per <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation">
    /// XML Schema Part 2: Datatypes</see> section 3.2.7.1's fixed-length production — the <c>xsd:dateTime</c>
    /// type <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void TrailingContentAfterTimezoneIsRefused()
    {
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:00:00Zx"u8, out _), "Trailing content after a complete value must be refused.");
    }


    /// <summary>
    /// Proves a lower-case <c>'z'</c> is not accepted for the UTC timezone marker:
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-timezones">XML Schema Part 2:
    /// Datatypes</see> section 3.2.7.3's grammar names the literal <c>'Z'</c> exact-character, upper-case only —
    /// the <c>xsd:dateTime</c> type <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void LowercaseTimezoneMarkerIsRefused()
    {
        Assert.IsFalse(XAdESDateTime.TryParse("2024-01-01T00:00:00z"u8, out _), "A lower-case 'z' timezone marker must be refused.");
    }


    /// <summary>
    /// Hardening bound (over the <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation"> XML Schema Part 2: Datatypes</see> section 3.2.7.1
    /// fractional-second production): a pathologically long fractional-second digit run — beyond what any legitimate signing-time value would ever carry — is refused rather than accepted
    /// and silently truncated or overflowed, over the <c>xsd:dateTime</c> type <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void ExcessivelyLongFractionalSecondRunIsRefused()
    {
        string longFraction = new('9', 40);
        Assert.IsFalse(XAdESDateTime.TryParse(System.Text.Encoding.ASCII.GetBytes($"2024-01-01T00:00:00.{longFraction}Z"), out _), "A pathologically long fractional-second run must be refused.");
    }


    /// <summary>
    /// Hardening bound (over the <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#dateTime-lexical-representation"> XML Schema Part 2: Datatypes</see> section 3.2.7.1 year production): a
    /// pathologically long year digit run is refused rather than accepted and risking numeric overflow during parsing, over the <c>xsd:dateTime</c> type <see
    /// href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.2.1's <c>SigningTime</c> mints.
    /// </summary>
    [TestMethod]
    public void ExcessivelyLongYearRunIsRefused()
    {
        string longYear = new('1', 40);
        Assert.IsFalse(XAdESDateTime.TryParse(System.Text.Encoding.ASCII.GetBytes($"{longYear}-01-01T00:00:00Z"), out _), "A pathologically long year digit run must be refused.");
    }
}
