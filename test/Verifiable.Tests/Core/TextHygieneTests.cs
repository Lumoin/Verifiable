using System.Buffers;
using System.Text;
using Verifiable.Core.Text;

namespace Verifiable.Tests.Core;

/// <summary>
/// Tests the local policy of <see cref="TextHygiene"/>. Cf is "a format control character" in
/// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
/// Unicode data is the running runtime's; Unassigned and PrivateUse answers can differ between runtimes.
/// </summary>
[TestClass]
internal sealed class TextHygieneTests
{
    /// <summary>
    /// <see cref="TextHygieneRule.Default"/> reports the selected category at its input offset.
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>
    /// defines Cc as "a C0 or C1 control code", Cf as "a format control character", Zl as
    /// "U+2028 LINE SEPARATOR only", Zp as "U+2029 PARAGRAPH SEPARATOR only", and Cs as
    /// "a surrogate code point". <see href="https://www.unicode.org/Public/UCD/latest/ucd/Blocks.txt">Blocks.txt</see>
    /// states "E0000..E007F; Tags"; the whole block receives the Tag classification.
    /// Categories use the running runtime's Unicode data.
    /// </summary>
    /// <param name="codePoint">The scalar or lone surrogate code unit.</param>
    /// <param name="expectedClass">Its independently specified classification.</param>
    [TestMethod]
    [DataRow(0x202E, TextHygieneClass.Format)]
    [DataRow(0x2066, TextHygieneClass.Format)]
    [DataRow(0x200B, TextHygieneClass.Format)]
    [DataRow(0x2028, TextHygieneClass.LineSeparator)]
    [DataRow(0x2029, TextHygieneClass.ParagraphSeparator)]
    [DataRow(0x0007, TextHygieneClass.Control)]
    [DataRow(0xE0041, TextHygieneClass.Tag)]
    [DataRow(0xE0000, TextHygieneClass.Tag)]
    [DataRow(0xD800, TextHygieneClass.UnpairedSurrogate)]
    public void DefaultRuleFindsEachActingCodePoint(int codePoint, TextHygieneClass expectedClass)
    {
        string selectedText = codePoint <= char.MaxValue ? ((char)codePoint).ToString() : char.ConvertFromUtf32(codePoint);
        string text = "a" + selectedText + "b";
        TextHygieneFinding expected = new(1, codePoint, expectedClass);

        var inspection = TextHygiene.Inspect(text.AsSpan(), TextHygieneRule.Default);
        Assert.IsFalse(inspection.IsSuccess, "The default rule must report the selected code point.");
        Assert.AreEqual(expected, inspection.Error, "The UTF-16 offset and code point must be retained.");

        List<TextHygieneFinding> findings = [];
        TextHygiene.CollectFindings(text.AsSpan(), TextHygieneRule.Default, findings);
        Assert.HasCount(1, findings);
        Assert.AreEqual(expected, findings[0]);

        if(expectedClass != TextHygieneClass.UnpairedSurrogate)
        {
            byte[] utf8 = Encoding.UTF8.GetBytes(text);
            var utf8Inspection = TextHygiene.Inspect(utf8.AsSpan(), TextHygieneRule.Default);
            Assert.IsFalse(utf8Inspection.IsSuccess, "UTF-8 must classify the same scalar.");
            Assert.AreEqual(expected, utf8Inspection.Error, "The ASCII prefix occupies one byte.");

            List<TextHygieneFinding> utf8Findings = [];
            TextHygiene.CollectFindings(utf8.AsSpan(), TextHygieneRule.Default, utf8Findings);
            Assert.HasCount(1, utf8Findings);
            Assert.AreEqual(expected, utf8Findings[0]);
        }

    }

    /// <summary>
    /// <see cref="TextHygieneRule.Default"/> leaves readable categories alone.
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>
    /// describes Lu as "an uppercase letter", Ll as "a lowercase letter", Nd as "a decimal digit",
    /// So as "a symbol of other type", and Zs as "a space character (of various non-zero widths)".
    /// Categories use the running runtime's Unicode data.
    /// </summary>
    /// <param name="text">Text in categories outside the default rule.</param>
    [TestMethod]
    [DataRow("Aa1 ")]
    [DataRow("\u00E9")]
    [DataRow("\U0001F600")]
    [DataRow("\u00A0")]
    public void DefaultRuleLeavesReadableTextAlone(string text)
    {
        var inspection = TextHygiene.Inspect(text.AsSpan(), TextHygieneRule.Default);
        Assert.IsTrue(inspection.IsSuccess, "The default rule must accept readable text.");

        List<TextHygieneFinding> findings = [];
        TextHygiene.CollectFindings(text.AsSpan(), TextHygieneRule.Default, findings);
        Assert.IsEmpty(findings);

        byte[] utf8 = Encoding.UTF8.GetBytes(text);
        var utf8Inspection = TextHygiene.Inspect(utf8.AsSpan(), TextHygieneRule.Default);
        Assert.IsTrue(utf8Inspection.IsSuccess, "UTF-8 must accept the same readable text.");

        List<TextHygieneFinding> utf8Findings = [];
        TextHygiene.CollectFindings(utf8.AsSpan(), TextHygieneRule.Default, utf8Findings);
        Assert.IsEmpty(utf8Findings);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.DisplayText"/> allows three layout controls that Default reports.
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>
    /// defines Cc as "a C0 or C1 control code". Categories use the running runtime's Unicode data.
    /// </summary>
    /// <param name="codePoint">One explicitly allowed layout control.</param>
    [TestMethod]
    [DataRow(0x0009)]
    [DataRow(0x000A)]
    [DataRow(0x000D)]
    public void DisplayTextAllowsTabAndLineBreaks(int codePoint)
    {
        string text = ((char)codePoint).ToString();

        var displayInspection = TextHygiene.Inspect(text.AsSpan(), TextHygieneRule.DisplayText);
        Assert.IsTrue(displayInspection.IsSuccess, "The display rule must allow this code point.");

        var defaultInspection = TextHygiene.Inspect(text.AsSpan(), TextHygieneRule.Default);
        Assert.IsFalse(defaultInspection.IsSuccess, "The default rule must report the control.");
        Assert.AreEqual(new TextHygieneFinding(0, codePoint, TextHygieneClass.Control), defaultInspection.Error);
    }

    /// <summary>
    /// <see cref="TextHygiene.EscapeVisibly"/> writes visible UTF-16 escapes and retains readable text.
    /// <see href="https://www.unicode.org/reports/tr9/#Explicit_Directional_Overrides">UAX #9, Section 2.2</see>
    /// describes RLO as "Force following characters to be treated as strong right-to-left characters."
    /// <see href="https://www.unicode.org/Public/UCD/latest/ucd/Blocks.txt">Blocks.txt</see> states
    /// "E0000..E007F; Tags". <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44,
    /// Table 12</see> defines Cs as "a surrogate code point". Categories use the running runtime's Unicode data.
    /// </summary>
    /// <param name="codePoint">The scalar or lone surrogate to write.</param>
    /// <param name="prefix">The readable prefix.</param>
    /// <param name="suffix">The readable suffix.</param>
    /// <param name="expectedText">The independently specified output.</param>
    [TestMethod]
    [DataRow(0x202E, "a", "b", "a\\u202Eb")]
    [DataRow(0xE0041, "", "", "\\uDB40\\uDC41")]
    [DataRow(0xD800, "", "", "\\uD800")]
    [DataRow(0x00E9, "", "", "\u00E9")]
    public void EscapeVisiblyWritesTheEscapeOfEachFlaggedScalar(int codePoint, string prefix, string suffix, string expectedText)
    {
        string selectedText = codePoint <= char.MaxValue ? ((char)codePoint).ToString() : char.ConvertFromUtf32(codePoint);
        string text = prefix + selectedText + suffix;
        ArrayBufferWriter<char> writer = new();

        TextHygiene.EscapeVisibly(text.AsSpan(), TextHygieneRule.Default, writer);

        Assert.AreEqual(expectedText, new string(writer.WrittenSpan), "The writer must receive the exact visible text.");
    }

    /// <summary>
    /// <see cref="TextHygiene"/> collectors preserve order and the input's offset unit.
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>
    /// defines Cf as "a format control character" and Zl as "U+2028 LINE SEPARATOR only".
    /// Categories use the running runtime's Unicode data.
    /// </summary>
    [TestMethod]
    public void CollectFindingsReportsEveryFindingInOrder()
    {
        string text = "\u202Ex\u2028y";
        List<TextHygieneFinding> findings = [];

        TextHygiene.CollectFindings(text.AsSpan(), TextHygieneRule.Default, findings);

        Assert.HasCount(2, findings);
        Assert.AreEqual(new TextHygieneFinding(0, 0x202E, TextHygieneClass.Format), findings[0]);
        Assert.AreEqual(new TextHygieneFinding(2, 0x2028, TextHygieneClass.LineSeparator), findings[1]);

        byte[] utf8 = Encoding.UTF8.GetBytes(text);
        List<TextHygieneFinding> utf8Findings = [];

        TextHygiene.CollectFindings(utf8.AsSpan(), TextHygieneRule.Default, utf8Findings);

        Assert.HasCount(2, utf8Findings);
        Assert.AreEqual(new TextHygieneFinding(0, 0x202E, TextHygieneClass.Format), utf8Findings[0]);
        Assert.AreEqual(new TextHygieneFinding(4, 0x2028, TextHygieneClass.LineSeparator), utf8Findings[1]);
    }

    /// <summary>
    /// The local decoding policy reports malformed UTF-8 separately at its byte offset.
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>
    /// defines Cf as "a format control character"; malformed bytes receive
    /// <see cref="TextHygieneClass.IllFormedEncoding"/> instead of a category assignment.
    /// Valid categories use the running runtime's Unicode data.
    /// </summary>
    [TestMethod]
    public void Utf8InspectionReportsAnIllFormedSequence()
    {
        byte[] utf8 = [0xC3, 0x28];
        TextHygieneFinding expected = new(0, -1, TextHygieneClass.IllFormedEncoding);

        var inspection = TextHygiene.Inspect(utf8.AsSpan(), TextHygieneRule.Default);
        Assert.IsFalse(inspection.IsSuccess, "An invalid UTF-8 sequence must produce a finding.");
        Assert.AreEqual(expected, inspection.Error, "The finding must identify byte offset zero.");

        List<TextHygieneFinding> findings = [];
        TextHygiene.CollectFindings(utf8.AsSpan(), TextHygieneRule.Default, findings);

        Assert.HasCount(1, findings, "The following ASCII parenthesis is valid text.");
        Assert.AreEqual(expected, findings[0]);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Strict"/> reports private-use and unassigned code points.
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>
    /// defines Co as "a private-use character" and Cn as "a reserved unassigned code point or a noncharacter".
    /// Unicode data is the running runtime's, so PrivateUse and Unassigned answers can differ between runtimes.
    /// </summary>
    /// <param name="codePoint">The private-use or unassigned code point.</param>
    /// <param name="expectedClass">Its independently specified classification.</param>
    [TestMethod]
    [DataRow(0xE000, TextHygieneClass.PrivateUse)]
    [DataRow(0x0378, TextHygieneClass.Unassigned)]
    public void StrictRuleFindsPrivateUseAndUnassigned(int codePoint, TextHygieneClass expectedClass)
    {
        string text = ((char)codePoint).ToString();

        var inspection = TextHygiene.Inspect(text.AsSpan(), TextHygieneRule.Strict);

        Assert.IsFalse(inspection.IsSuccess, "The strict rule must report the selected category.");
        Assert.AreEqual(new TextHygieneFinding(0, codePoint, expectedClass), inspection.Error);
    }

}
