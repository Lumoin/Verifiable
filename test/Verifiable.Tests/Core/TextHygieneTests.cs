using System.Buffers;
using System.Text;
using Verifiable.Core.Text;

namespace Verifiable.Tests.Core;

/// <summary>
/// Tests how <see cref="TextHygiene"/> classifies, reports and escapes the code points of partner-supplied text
/// that act rather than read when shown, in UTF-16 and UTF-8 input. Every input is built from code point values
/// or ASCII escapes.
/// </summary>
[TestClass]
internal sealed class TextHygieneTests
{
    /// <summary>
    /// <see cref="TextHygieneRule.Default"/> reports every code point of the general categories it selects, at the
    /// start, the middle and the end of the text.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see> defines Cc as
    /// "a C0 or C1 control code", Cf as "a format control character", Zl as "U+2028 LINE SEPARATOR only" and Zp as
    /// "U+2029 PARAGRAPH SEPARATOR only". <see href="https://www.unicode.org/Public/UCD/latest/ucd/Blocks.txt">Blocks.txt</see>
    /// states "E0000..E007F; Tags", both ends of which receive the Tag classification.
    /// <see href="https://www.unicode.org/reports/tr9/#Explicit_Directional_Overrides">UAX #9, Section 2.2</see> describes
    /// RLO as "Force following characters to be treated as strong right-to-left characters." and
    /// <see href="https://www.unicode.org/reports/tr9/#Explicit_Directional_Isolates">Section 2.4</see> describes LRI as
    /// "Treat the following text as isolated and left-to-right." Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G25660">D91</see> states
    /// "isolated UTF-16 code units" in the surrogate range "are ill-formed", so a lone high or low surrogate is reported.
    /// </summary>
    /// <param name="codePoint">The scalar or lone surrogate code unit.</param>
    /// <param name="expectedClass">Its independently specified classification.</param>
    [TestMethod]
    [DataRow(0x202A, TextHygieneClass.Format)]
    [DataRow(0x202E, TextHygieneClass.Format)]
    [DataRow(0x2066, TextHygieneClass.Format)]
    [DataRow(0x2069, TextHygieneClass.Format)]
    [DataRow(0x200B, TextHygieneClass.Format)]
    [DataRow(0x200C, TextHygieneClass.Format)]
    [DataRow(0x200D, TextHygieneClass.Format)]
    [DataRow(0x200E, TextHygieneClass.Format)]
    [DataRow(0x200F, TextHygieneClass.Format)]
    [DataRow(0x00AD, TextHygieneClass.Format)]
    [DataRow(0x061C, TextHygieneClass.Format)]
    [DataRow(0x180E, TextHygieneClass.Format)]
    [DataRow(0xFEFF, TextHygieneClass.Format)]
    [DataRow(0x2060, TextHygieneClass.Format)]
    [DataRow(0x2064, TextHygieneClass.Format)]
    [DataRow(0xFFF9, TextHygieneClass.Format)]
    [DataRow(0xFFFB, TextHygieneClass.Format)]
    [DataRow(0x2028, TextHygieneClass.LineSeparator)]
    [DataRow(0x2029, TextHygieneClass.ParagraphSeparator)]
    [DataRow(0x0007, TextHygieneClass.Control)]
    [DataRow(0x0080, TextHygieneClass.Control)]
    [DataRow(0x009F, TextHygieneClass.Control)]
    [DataRow(0xE0041, TextHygieneClass.Tag)]
    [DataRow(0xE0000, TextHygieneClass.Tag)]
    [DataRow(0xE007F, TextHygieneClass.Tag)]
    [DataRow(0xD800, TextHygieneClass.UnpairedSurrogate)]
    [DataRow(0xDC00, TextHygieneClass.UnpairedSurrogate)]
    public void DefaultRuleFindsEachActingCodePoint(int codePoint, TextHygieneClass expectedClass)
    {
        AssertSelectedInEveryPlacement(codePoint, expectedClass, TextHygieneRule.Default);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Default"/> leaves readable categories alone, emoji presentation and a reserved code
    /// point included.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>
    /// describes Lu as "an uppercase letter", Ll as "a lowercase letter", Nd as "a decimal digit",
    /// So as "a symbol of other type", Zs as "a space character (of various non-zero widths)", and Cn as
    /// "a reserved unassigned code point or a noncharacter", which the default rule does not select.
    /// </summary>
    /// <param name="text">Text in classes outside the default rule.</param>
    [TestMethod]
    [DataRow("Aa1 ")]
    [DataRow("\u00E9")]
    [DataRow("\U0001F600")]
    [DataRow("\u00A0")]
    [DataRow("\u2764\uFE0F")]
    [DataRow("\U000DFFFF")]
    public void DefaultRuleLeavesReadableTextAlone(string text)
    {
        AssertClean(text, TextHygieneRule.Default);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.DisplayText"/> allows tab, line feed and a CRLF line break that
    /// <see cref="TextHygieneRule.Default"/> reports as controls.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>
    /// defines Cc as "a C0 or C1 control code".
    /// </summary>
    /// <param name="text">Text whose layout control starts at index 1.</param>
    [TestMethod]
    [DataRow("a\tb")]
    [DataRow("a\nb")]
    [DataRow("a\r\nb")]
    public void DisplayTextAllowsTabAndLineBreaks(string text)
    {
        AssertClean(text, TextHygieneRule.DisplayText);

        TextHygieneFinding? utf16Inspection = TextHygiene.Inspect(text.AsSpan(), TextHygieneRule.Default);
        Assert.IsTrue(utf16Inspection.HasValue, "The default rule must report the control.");
        AssertFinding(utf16Inspection.Value, 1, 1, text[1], TextHygieneClass.Control);

        TextHygieneFinding? utf8Inspection = TextHygiene.Inspect(Encoding.UTF8.GetBytes(text).AsSpan(), TextHygieneRule.Default);
        Assert.IsTrue(utf8Inspection.HasValue, "The default rule must report the control in UTF-8.");
        AssertFinding(utf8Inspection.Value, 1, 1, text[1], TextHygieneClass.Control);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.DisplayText"/> reports a carriage return that is not the first half of a CRLF line
    /// break: shown alone it returns to the start of the line, and the text after it overwrites what the reader saw.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>
    /// defines Cc as "a C0 or C1 control code".
    /// </summary>
    /// <param name="text">ASCII text holding exactly one lone carriage return.</param>
    /// <param name="offset">The index of the lone carriage return, the same in UTF-16 and UTF-8.</param>
    [TestMethod]
    [DataRow("a\rb", 1)]
    [DataRow("a\r", 1)]
    [DataRow("\r\r\nb", 0)]
    [DataRow("a\n\rb", 2)]
    public void DisplayTextReportsALoneCarriageReturn(string text, int offset)
    {
        List<TextHygieneFinding> utf16Findings = [];
        TextHygiene.CollectFindings(text.AsSpan(), TextHygieneRule.DisplayText, utf16Findings);
        Assert.HasCount(1, utf16Findings, "Only the lone carriage return is a finding.");
        Assert.AreEqual(offset, utf16Findings[0].Offset, "The finding must sit at the lone carriage return.");
        Assert.AreEqual(0x000D, utf16Findings[0].CodePoint, "The finding must hold the carriage return.");
        Assert.AreEqual(TextHygieneClass.Control, utf16Findings[0].Class, "A carriage return is a control.");

        List<TextHygieneFinding> utf8Findings = [];
        TextHygiene.CollectFindings(Encoding.UTF8.GetBytes(text).AsSpan(), TextHygieneRule.DisplayText, utf8Findings);
        Assert.HasCount(1, utf8Findings, "Only the lone carriage return is a finding in UTF-8.");
        Assert.AreEqual(offset, utf8Findings[0].Offset, "The finding must sit at the lone carriage return in UTF-8.");
        Assert.AreEqual(0x000D, utf8Findings[0].CodePoint, "The finding must hold the carriage return in UTF-8.");
        Assert.AreEqual(TextHygieneClass.Control, utf8Findings[0].Class, "A carriage return is a control in UTF-8.");
    }

    /// <summary>
    /// <see cref="TextHygiene.EscapeVisibly"/> writes each flagged UTF-16 code unit as its visible escape and leaves
    /// readable text unchanged, adjacent flagged scalars and lone low surrogates included.
    /// <see href="https://www.unicode.org/reports/tr9/#Explicit_Directional_Overrides">UAX #9, Section 2.2</see>
    /// says of the overrides: "They are to be avoided wherever possible, because of security concerns."
    /// Unicode core <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G25660">D91</see>
    /// assigns "each Unicode scalar value in the range U+10000..U+10FFFF to a surrogate pair", so a supplementary
    /// scalar is written as the escapes of its two code units.
    /// </summary>
    /// <param name="codePoint">The scalar or lone surrogate to write.</param>
    /// <param name="prefix">The text before it.</param>
    /// <param name="suffix">The text after it.</param>
    /// <param name="expectedText">The independently specified output.</param>
    [TestMethod]
    [DataRow(0x202E, "a", "b", "a\\u202Eb")]
    [DataRow(0x202E, "\u202E", "", "\\u202E\\u202E")]
    [DataRow(0xE0041, "", "", "\\uDB40\\uDC41")]
    [DataRow(0xE007F, "x", "", "x\\uDB40\\uDC7F")]
    [DataRow(0xD800, "", "", "\\uD800")]
    [DataRow(0xDC00, "a", "", "a\\uDC00")]
    [DataRow(0x00E9, "", "", "\u00E9")]
    public void EscapeVisiblyWritesTheEscapeOfEachFlaggedScalar(int codePoint, string prefix, string suffix, string expectedText)
    {
        string text = prefix + TextOf(codePoint) + suffix;

        Assert.AreEqual(expectedText, Escape(text), "The writer must receive the exact visible text.");
    }

    /// <summary>
    /// <see cref="TextHygiene.EscapeVisibly"/> writes every reverse solidus of the input as its own escape, so the
    /// six typed characters of an escape in the input never come out as the escape of a code point.
    /// <see href="https://www.unicode.org/reports/tr9/#Explicit_Directional_Overrides">UAX #9, Section 2.2</see>
    /// says of the overrides: "They are to be avoided wherever possible, because of security concerns."
    /// </summary>
    /// <param name="text">ASCII text holding a reverse solidus.</param>
    /// <param name="expectedText">The independently specified output.</param>
    [TestMethod]
    [DataRow("\\", "\\u005C")]
    [DataRow("a\\u202Eb", "a\\u005Cu202Eb")]
    [DataRow("C:\\x", "C:\\u005Cx")]
    public void EscapeVisiblyWritesAReverseSolidusAsItsEscape(string text, string expectedText)
    {
        Assert.AreEqual(expectedText, Escape(text), "The writer must receive the exact visible text.");
    }

    /// <summary>
    /// <see cref="TextHygiene.EscapeVisibly"/> keeps a real override and the typed text of its escape apart, so the
    /// reader of the output can tell which one the partner sent.
    /// <see href="https://www.unicode.org/reports/tr9/#Explicit_Directional_Overrides">UAX #9, Section 2.2</see>
    /// says of the overrides: "They are to be avoided wherever possible, because of security concerns."
    /// </summary>
    [TestMethod]
    public void EscapeVisiblyTellsATypedEscapeFromAnEscapedOverride()
    {
        string escapedOverride = Escape("a" + TextOf(0x202E) + "b");
        string escapedTypedText = Escape("a\\u202Eb");

        Assert.AreNotEqual(escapedOverride, escapedTypedText, "A typed escape must not read as the escape of a real override.");
    }

    /// <summary>
    /// <see cref="TextHygiene"/> collectors report every occurrence in input order, at offsets and lengths in the
    /// input's unit.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>
    /// defines Cf as "a format control character" and Zl as "U+2028 LINE SEPARATOR only".
    /// </summary>
    [TestMethod]
    public void CollectFindingsReportsEveryFindingInOrder()
    {
        string text = TextOf(0x202E) + "x" + TextOf(0x2028) + "y";
        List<TextHygieneFinding> findings = [];

        TextHygiene.CollectFindings(text.AsSpan(), TextHygieneRule.Default, findings);

        Assert.HasCount(2, findings);
        AssertFinding(findings[0], 0, 1, 0x202E, TextHygieneClass.Format);
        AssertFinding(findings[1], 2, 1, 0x2028, TextHygieneClass.LineSeparator);

        List<TextHygieneFinding> utf8Findings = [];

        TextHygiene.CollectFindings(Encoding.UTF8.GetBytes(text).AsSpan(), TextHygieneRule.Default, utf8Findings);

        Assert.HasCount(2, utf8Findings);
        AssertFinding(utf8Findings[0], 0, 3, 0x202E, TextHygieneClass.Format);
        AssertFinding(utf8Findings[1], 4, 3, 0x2028, TextHygieneClass.LineSeparator);
    }

    /// <summary>
    /// UTF-8 inspection reports each maximal subpart of an ill-formed sequence as one occurrence without a code point,
    /// and never swallows the well-formed U+202E that follows.
    /// <see href="https://www.rfc-editor.org/rfc/rfc3629#section-3">RFC 3629, Section 3</see> states:
    /// "Implementations of the decoding algorithm above MUST protect against decoding invalid sequences."
    /// Unicode core <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G48534">Section 3.9.5</see>
    /// states that a converter "must not consume the successor bytes as part of the ill-formed subsequence whenever those
    /// successor bytes themselves constitute part of a well-formed UTF-8 code unit subsequence", and
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G66453">Section 3.9.6</see>
    /// (Tables 3-8 to 3-11) replaces "every byte of a sequence that would correspond to a surrogate code point" and
    /// "every byte of a sequence that would correspond to a code point beyond U+10FFFF" one at a time, while a truncated
    /// sequence "which is otherwise well-formed to that point" is one maximal subpart.
    /// </summary>
    /// <param name="illFormed">The ill-formed bytes placed before the UTF-8 encoding of U+202E.</param>
    /// <param name="offsets">The byte offset of each maximal subpart.</param>
    /// <param name="lengths">The byte length of each maximal subpart.</param>
    [TestMethod]
    [DataRow(new byte[] { 0xC3 }, new[] { 0 }, new[] { 1 })]
    [DataRow(new byte[] { 0x80 }, new[] { 0 }, new[] { 1 })]
    [DataRow(new byte[] { 0xC0, 0x80 }, new[] { 0, 1 }, new[] { 1, 1 })]
    [DataRow(new byte[] { 0xE0, 0x80, 0x80 }, new[] { 0, 1, 2 }, new[] { 1, 1, 1 })]
    [DataRow(new byte[] { 0xED, 0xA0, 0x80 }, new[] { 0, 1, 2 }, new[] { 1, 1, 1 })]
    [DataRow(new byte[] { 0xF4, 0x90, 0x80, 0x80 }, new[] { 0, 1, 2, 3 }, new[] { 1, 1, 1, 1 })]
    [DataRow(new byte[] { 0xFF }, new[] { 0 }, new[] { 1 })]
    [DataRow(new byte[] { 0xE2, 0x80 }, new[] { 0 }, new[] { 2 })]
    [DataRow(new byte[] { 0xF0, 0x90, 0x80 }, new[] { 0 }, new[] { 3 })]
    public void Utf8InspectionReportsAnIllFormedSequence(byte[] illFormed, int[] offsets, int[] lengths)
    {
        byte[] input = [.. illFormed, .. Encoding.UTF8.GetBytes(TextOf(0x202E))];
        List<TextHygieneFinding> findings = [];

        TextHygiene.CollectFindings(input.AsSpan(), TextHygieneRule.Default, findings);

        Assert.HasCount(offsets.Length + 1, findings, "Each maximal subpart and the following override are occurrences.");
        for(int index = 0; index < offsets.Length; index++)
        {
            AssertFinding(findings[index], offsets[index], lengths[index], null, TextHygieneClass.IllFormedEncoding);
        }

        AssertFinding(findings[^1], illFormed.Length, 3, 0x202E, TextHygieneClass.Format);

        TextHygieneFinding? inspection = TextHygiene.Inspect(input.AsSpan(), TextHygieneRule.Default);
        Assert.IsTrue(inspection.HasValue, "An ill-formed sequence must produce a finding.");
        AssertFinding(inspection.Value, 0, lengths[0], null, TextHygieneClass.IllFormedEncoding);
    }

    /// <summary>
    /// An ill-formed UTF-8 sequence holds no code point, so its occurrence states the absence by name while the
    /// well-formed U+202E after it keeps its own.
    /// Unicode core <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G55471">D93b</see>
    /// defines the maximal subpart as "The longest code unit subsequence starting at an unconvertible offset that is
    /// either: a. the initial subsequence of a well-formed code unit sequence, or b. a subsequence of length one."
    /// </summary>
    [TestMethod]
    public void Utf8IllFormedSequenceHoldsNoCodePoint()
    {
        byte[] input = [0xC3, 0xE2, 0x80, 0xAE];
        List<TextHygieneFinding> findings = [];

        TextHygiene.CollectFindings(input.AsSpan(), TextHygieneRule.Default, findings);

        Assert.HasCount(2, findings, "The lone lead byte and the following override are occurrences.");
        Assert.AreEqual(0, findings[0].Offset, "The ill-formed subpart starts the input.");
        Assert.AreEqual(TextHygieneClass.IllFormedEncoding, findings[0].Class, "The lone lead byte is ill-formed.");
        Assert.IsNull(findings[0].CodePoint, "An ill-formed sequence holds no code point.");
        Assert.AreEqual(1, findings[1].Offset, "The override follows the one-byte subpart.");
        Assert.AreEqual(0x202E, findings[1].CodePoint, "The override keeps its code point.");
        Assert.AreEqual(TextHygieneClass.Format, findings[1].Class, "The override is a format character.");
    }

    /// <summary>
    /// UTF-8 inspection reports a sequence truncated by the end of the input as one maximal subpart.
    /// Unicode core <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G66453">Section 3.9.6</see>
    /// states: "Only when a sequence of two or three bytes is a truncated version of a sequence which is otherwise
    /// well-formed to that point, is more than one byte replaced with a single U+FFFD".
    /// </summary>
    /// <param name="input">An ASCII byte followed by a truncated sequence.</param>
    /// <param name="length">The byte length of the truncated sequence.</param>
    [TestMethod]
    [DataRow(new byte[] { 0x61, 0xC3 }, 1)]
    [DataRow(new byte[] { 0x61, 0xE2, 0x80 }, 2)]
    [DataRow(new byte[] { 0x61, 0xF0, 0x90, 0x80 }, 3)]
    public void Utf8InspectionReportsATruncatedFinalSequence(byte[] input, int length)
    {
        List<TextHygieneFinding> findings = [];

        TextHygiene.CollectFindings(input.AsSpan(), TextHygieneRule.Default, findings);

        Assert.HasCount(1, findings, "The truncated sequence is one maximal subpart.");
        AssertFinding(findings[0], 1, length, null, TextHygieneClass.IllFormedEncoding);
    }

    /// <summary>
    /// UTF-16 inspection reports each lone surrogate, whether low first, high twice or high before a pair, and never
    /// swallows the well-formed pair or the U+202E that follows.
    /// Unicode core <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G25660">D91</see>
    /// states "Because surrogate code points are not Unicode scalar values, isolated UTF-16 code units in the range"
    /// of surrogates "are ill-formed."
    /// </summary>
    /// <param name="units">The UTF-16 code units placed before U+202E.</param>
    /// <param name="offsets">The index of each lone surrogate.</param>
    [TestMethod]
    [DataRow(new[] { 0xDC00 }, new[] { 0 })]
    [DataRow(new[] { 0xD800, 0xD800 }, new[] { 0, 1 })]
    [DataRow(new[] { 0xDC00, 0xD800 }, new[] { 0, 1 })]
    [DataRow(new[] { 0xD800, 0xD800, 0xDC00 }, new[] { 0 })]
    public void Utf16InspectionReportsEachLoneSurrogate(int[] units, int[] offsets)
    {
        StringBuilder builder = new();
        foreach(int unit in units)
        {
            _ = builder.Append((char)unit);
        }

        _ = builder.Append(TextOf(0x202E));
        string text = builder.ToString();
        List<TextHygieneFinding> findings = [];

        TextHygiene.CollectFindings(text.AsSpan(), TextHygieneRule.Default, findings);

        Assert.HasCount(offsets.Length + 1, findings, "Each lone surrogate and the following override are occurrences.");
        for(int index = 0; index < offsets.Length; index++)
        {
            AssertFinding(findings[index], offsets[index], 1, units[offsets[index]], TextHygieneClass.UnpairedSurrogate);
        }

        AssertFinding(findings[^1], units.Length, 1, 0x202E, TextHygieneClass.Format);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Strict"/> reports private-use code points, noncharacters and reserved code points,
    /// the reserved default-ignorable ones included, in both encodings.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>
    /// defines Co as "a private-use character" and Cn as "a reserved unassigned code point or a noncharacter".
    /// The reserved rows depend on the running runtime's Unicode data; the noncharacters are Cn in every version.
    /// </summary>
    /// <param name="codePoint">The private-use, noncharacter or reserved code point.</param>
    /// <param name="expectedClass">Its independently specified classification.</param>
    [TestMethod]
    [DataRow(0xE000, TextHygieneClass.PrivateUse)]
    [DataRow(0xF0000, TextHygieneClass.PrivateUse)]
    [DataRow(0x10FFFD, TextHygieneClass.PrivateUse)]
    [DataRow(0x0378, TextHygieneClass.Unassigned)]
    [DataRow(0xFDD0, TextHygieneClass.Unassigned)]
    [DataRow(0xFFFE, TextHygieneClass.Unassigned)]
    [DataRow(0xFFFF, TextHygieneClass.Unassigned)]
    [DataRow(0xDFFFF, TextHygieneClass.Unassigned)]
    [DataRow(0x10FFFF, TextHygieneClass.Unassigned)]
    [DataRow(0x2065, TextHygieneClass.Unassigned)]
    [DataRow(0xE0080, TextHygieneClass.Unassigned)]
    public void StrictRuleFindsPrivateUseAndUnassigned(int codePoint, TextHygieneClass expectedClass)
    {
        AssertSelectedInEveryPlacement(codePoint, expectedClass, TextHygieneRule.Strict);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Strict"/> passes the code points that act when shown but that no class covers: the
    /// variation selectors, the assigned default-ignorable code points outside Cf, stacked combining marks, look-alike
    /// spaces and U+2800. This pins the boundary the rule documents; it is not a claim that such text is safe to show.
    /// <see href="https://www.unicode.org/reports/tr44/#Default_Ignorable_Code_Point">UAX #44</see> describes
    /// Default_Ignorable_Code_Point as "characters that should be ignored in rendering (unless explicitly supported)",
    /// generated from "Other_Default_Ignorable_Code_Point + Cf (Format characters) + Variation_Selector", and
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">Table 12</see> defines Mn as "a nonspacing
    /// combining mark (zero advance width)" and Zs as "a space character (of various non-zero widths)".
    /// </summary>
    /// <param name="text">Text whose acting code points no class covers.</param>
    [TestMethod]
    [DataRow("a\uFE0Fb")]
    [DataRow("a\u180Bb")]
    [DataRow("a\U000E0100b")]
    [DataRow("a\U000E01EFb")]
    [DataRow("a\u034Fb")]
    [DataRow("\u115F\u1160")]
    [DataRow("a\u17B4b")]
    [DataRow("\u3164")]
    [DataRow("\uFFA0")]
    [DataRow("e\u0301\u0301\u0301")]
    [DataRow("\u2000")]
    [DataRow("\u200A")]
    [DataRow("\u3000")]
    [DataRow("\u2800")]
    public void StrictRuleLeavesTheUncoveredCodePointsAlone(string text)
    {
        AssertClean(text, TextHygieneRule.Strict);
    }

    /// <summary>
    /// A rule that selects only <see cref="TextHygieneClass.Tag"/> reports exactly the Tags block, both ends included and
    /// the neighbours outside it left alone.
    /// <see href="https://www.unicode.org/Public/UCD/latest/ucd/Blocks.txt">Blocks.txt</see> states "E0000..E007F; Tags".
    /// </summary>
    /// <param name="codePoint">A code point at or next to a Tags block boundary.</param>
    /// <param name="isInTagsBlock">Whether the code point lies in the block.</param>
    [TestMethod]
    [DataRow(0xE0000, true)]
    [DataRow(0xE007F, true)]
    [DataRow(0xE0080, false)]
    [DataRow(0xDFFFF, false)]
    public void TagOnlyRuleSelectsExactlyTheTagsBlock(int codePoint, bool isInTagsBlock)
    {
        TextHygieneRule rule = CreateRule([TextHygieneClass.Tag], []);
        if(isInTagsBlock)
        {
            AssertSelectedInEveryPlacement(codePoint, TextHygieneClass.Tag, rule);
        }
        else
        {
            AssertClean(TextOf(codePoint), rule);
        }
    }

    /// <summary>
    /// A rule's exception overrides every class it selects, format characters, tags, lone surrogates and a whole
    /// single-code-point class included, while the classes stay selected for every other code point.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>
    /// defines Cf as "a format control character", Cc as "a C0 or C1 control code" and Zl as
    /// "U+2028 LINE SEPARATOR only"; <see href="https://www.unicode.org/Public/UCD/latest/ucd/Blocks.txt">Blocks.txt</see>
    /// states "E0000..E007F; Tags".
    /// </summary>
    /// <param name="codePoint">The exempt code point, placed before a U+202E the rule still reports.</param>
    [TestMethod]
    [DataRow(0x200B)]
    [DataRow(0xE0041)]
    [DataRow(0xD800)]
    [DataRow(0x000D)]
    [DataRow(0x2028)]
    public void RuleExceptionOverridesEverySelectedClass(int codePoint)
    {
        TextHygieneRule rule = CreateRule(
            [TextHygieneClass.Control, TextHygieneClass.Format, TextHygieneClass.LineSeparator, TextHygieneClass.Tag, TextHygieneClass.UnpairedSurrogate],
            [0x200B, 0xE0041, 0xD800, 0x000D, 0x2028]);
        string exempt = TextOf(codePoint);
        string text = exempt + TextOf(0x202E);
        List<TextHygieneFinding> findings = [];

        TextHygiene.CollectFindings(text.AsSpan(), rule, findings);

        Assert.HasCount(1, findings, "Only the override that is not exempt is an occurrence.");
        AssertFinding(findings[0], exempt.Length, 1, 0x202E, TextHygieneClass.Format);
        if(Rune.IsValid(codePoint))
        {
            List<TextHygieneFinding> utf8Findings = [];
            TextHygiene.CollectFindings(Encoding.UTF8.GetBytes(text).AsSpan(), rule, utf8Findings);
            Assert.HasCount(1, utf8Findings, "Only the override that is not exempt is an occurrence in UTF-8.");
            AssertFinding(utf8Findings[0], Encoding.UTF8.GetByteCount(exempt), 3, 0x202E, TextHygieneClass.Format);
        }
    }

    /// <summary>
    /// No exception reaches an ill-formed UTF-8 sequence, not even the value of its byte or of U+FFFD, because the
    /// sequence has no code point.
    /// <see href="https://www.rfc-editor.org/rfc/rfc3629#section-3">RFC 3629, Section 3</see> states:
    /// "Implementations of the decoding algorithm above MUST protect against decoding invalid sequences."
    /// </summary>
    [TestMethod]
    public void RuleExceptionNeverExemptsAnIllFormedSequence()
    {
        TextHygieneRule rule = CreateRule([TextHygieneClass.IllFormedEncoding], [0x00C3, 0xFFFD]);
        byte[] input = [0xC3];

        TextHygieneFinding? inspection = TextHygiene.Inspect(input.AsSpan(), rule);

        Assert.IsTrue(inspection.HasValue, "An ill-formed sequence must produce a finding whatever the exceptions.");
        AssertFinding(inspection.Value, 0, 1, null, TextHygieneClass.IllFormedEncoding);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Create"/> refuses a rule without classes, which could select nothing.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see> lists the categories a
    /// rule selects from; a rule that names none of them passes every input.
    /// </summary>
    [TestMethod]
    public void RuleCreationRefusesAnEmptyClassSet()
    {
        var creation = TextHygieneRule.Create([], [0x0009]);

        Assert.IsFalse(creation.IsSuccess, "A rule without classes must be refused.");
        Assert.AreEqual(TextHygieneRuleRefusalReason.EmptyClassSet, creation.Error.Reason);
        Assert.IsNull(creation.Error.Value, "An empty class set has no single offending value.");
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Create"/> refuses a class value that is not a defined <see cref="TextHygieneClass"/>,
    /// naming it, because no occurrence can carry it.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see> lists the categories a
    /// rule selects from.
    /// </summary>
    /// <param name="undefinedClass">A numeric value outside the enumeration.</param>
    [TestMethod]
    [DataRow(-1)]
    [DataRow(999)]
    public void RuleCreationRefusesAnUndefinedClass(int undefinedClass)
    {
        var creation = TextHygieneRule.Create([TextHygieneClass.Format, (TextHygieneClass)undefinedClass], []);

        Assert.IsFalse(creation.IsSuccess, "An undefined class must be refused.");
        Assert.AreEqual(TextHygieneRuleRefusalReason.UndefinedClass, creation.Error.Reason);
        Assert.AreEqual(undefinedClass, creation.Error.Value);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Create"/> refuses an exception outside the Unicode codespace, naming it, because no
    /// input can hold it. Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G22696">D9</see> defines the
    /// Unicode codespace as "A range of integers from 0 to" 10FFFF (hexadecimal).
    /// </summary>
    /// <param name="codePoint">A value outside the codespace.</param>
    [TestMethod]
    [DataRow(-1)]
    [DataRow(0x110000)]
    public void RuleCreationRefusesAnExceptionOutsideTheCodespace(int codePoint)
    {
        var creation = TextHygieneRule.Create([TextHygieneClass.Format], [0x0009, codePoint]);

        Assert.IsFalse(creation.IsSuccess, "An exception outside the codespace must be refused.");
        Assert.AreEqual(TextHygieneRuleRefusalReason.CodePointOutsideCodespace, creation.Error.Reason);
        Assert.AreEqual(codePoint, creation.Error.Value);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Create"/> accepts an exception anywhere in the Unicode codespace, surrogate code
    /// points included, which exempt a lone UTF-16 code unit. Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G22696">D9</see> defines the
    /// Unicode codespace as "A range of integers from 0 to" 10FFFF (hexadecimal).
    /// </summary>
    /// <param name="codePoint">A value at an edge of the codespace or of the surrogate range.</param>
    [TestMethod]
    [DataRow(0x0000)]
    [DataRow(0xD800)]
    [DataRow(0x10FFFF)]
    public void RuleCreationAcceptsEveryCodespaceValue(int codePoint)
    {
        var creation = TextHygieneRule.Create([TextHygieneClass.Format], [codePoint]);

        Assert.IsTrue(creation.IsSuccess, "An exception in the codespace must be accepted.");
        Assert.Contains(codePoint, creation.Value.AllowedCodePoints, "The rule must keep the exception.");
    }

    /// <summary>
    /// Asserts that the rule reports the code point with its class and length at the start, the middle and the end of
    /// a text, through inspection and collection, in UTF-16 and, for a scalar, in UTF-8.
    /// </summary>
    /// <param name="codePoint">The scalar or lone surrogate code unit.</param>
    /// <param name="expectedClass">Its independently specified classification.</param>
    /// <param name="rule">The rule under test.</param>
    private static void AssertSelectedInEveryPlacement(int codePoint, TextHygieneClass expectedClass, TextHygieneRule rule)
    {
        string selected = TextOf(codePoint);
        bool isScalar = Rune.IsValid(codePoint);
        foreach((string prefix, string suffix) in new[] { ("", "b"), ("a", "b"), ("a", "") })
        {
            string text = prefix + selected + suffix;

            TextHygieneFinding? inspection = TextHygiene.Inspect(text.AsSpan(), rule);
            Assert.IsTrue(inspection.HasValue, "The rule must report the selected code point.");
            AssertFinding(inspection.Value, prefix.Length, selected.Length, codePoint, expectedClass);

            List<TextHygieneFinding> findings = [];
            TextHygiene.CollectFindings(text.AsSpan(), rule, findings);
            Assert.HasCount(1, findings, "Only the selected code point is an occurrence.");
            AssertFinding(findings[0], prefix.Length, selected.Length, codePoint, expectedClass);

            if(isScalar)
            {
                byte[] utf8 = Encoding.UTF8.GetBytes(text);
                int utf8Length = Encoding.UTF8.GetByteCount(selected);

                TextHygieneFinding? utf8Inspection = TextHygiene.Inspect(utf8.AsSpan(), rule);
                Assert.IsTrue(utf8Inspection.HasValue, "UTF-8 must report the same scalar.");
                AssertFinding(utf8Inspection.Value, prefix.Length, utf8Length, codePoint, expectedClass);

                List<TextHygieneFinding> utf8Findings = [];
                TextHygiene.CollectFindings(utf8.AsSpan(), rule, utf8Findings);
                Assert.HasCount(1, utf8Findings, "Only the selected scalar is an occurrence in UTF-8.");
                AssertFinding(utf8Findings[0], prefix.Length, utf8Length, codePoint, expectedClass);
            }
        }
    }

    /// <summary>
    /// Asserts that the rule reports nothing in the text, through inspection and collection, in UTF-16 and UTF-8.
    /// </summary>
    /// <param name="text">Well-formed text.</param>
    /// <param name="rule">The rule under test.</param>
    private static void AssertClean(string text, TextHygieneRule rule)
    {
        Assert.IsFalse(TextHygiene.Inspect(text.AsSpan(), rule).HasValue, "The rule must accept this text.");

        List<TextHygieneFinding> findings = [];
        TextHygiene.CollectFindings(text.AsSpan(), rule, findings);
        Assert.IsEmpty(findings);

        byte[] utf8 = Encoding.UTF8.GetBytes(text);
        Assert.IsFalse(TextHygiene.Inspect(utf8.AsSpan(), rule).HasValue, "The rule must accept this text in UTF-8.");

        List<TextHygieneFinding> utf8Findings = [];
        TextHygiene.CollectFindings(utf8.AsSpan(), rule, utf8Findings);
        Assert.IsEmpty(utf8Findings);
    }

    /// <summary>
    /// Asserts every member of one occurrence by name, the scalar included, which exists only for a scalar value.
    /// </summary>
    /// <param name="finding">The occurrence reported.</param>
    /// <param name="offset">The expected offset in the input's unit.</param>
    /// <param name="length">The expected length in the input's unit.</param>
    /// <param name="codePoint">The expected code point, or null for an ill-formed sequence.</param>
    /// <param name="expectedClass">The expected class.</param>
    private static void AssertFinding(TextHygieneFinding finding, int offset, int length, int? codePoint, TextHygieneClass expectedClass)
    {
        Assert.AreEqual(offset, finding.Offset, "The offset must follow the input's unit.");
        Assert.AreEqual(length, finding.Length, "The length must span the occurrence's input units.");
        Assert.AreEqual(codePoint, finding.CodePoint, "The code point must be the occurrence's own, or absent.");
        Assert.AreEqual(expectedClass, finding.Class, "The class must be the independently specified one.");
        Rune? expectedScalar = codePoint is { } value && Rune.IsValid(value) ? new Rune(value) : null;
        Assert.AreEqual(expectedScalar, finding.Scalar, "The scalar exists only for a Unicode scalar value.");
    }

    /// <summary>
    /// Builds the UTF-16 text of one code point: a scalar's encoding, or the lone surrogate code unit itself.
    /// </summary>
    /// <param name="codePoint">The scalar or surrogate code point.</param>
    /// <returns>The one or two UTF-16 code units.</returns>
    private static string TextOf(int codePoint)
    {
        return codePoint <= char.MaxValue ? ((char)codePoint).ToString() : char.ConvertFromUtf32(codePoint);
    }

    /// <summary>
    /// Runs <see cref="TextHygiene.EscapeVisibly"/> under <see cref="TextHygieneRule.Default"/> into a caller-owned writer.
    /// </summary>
    /// <param name="text">The input.</param>
    /// <returns>The written text.</returns>
    private static string Escape(string text)
    {
        ArrayBufferWriter<char> writer = new();
        TextHygiene.EscapeVisibly(text.AsSpan(), TextHygieneRule.Default, writer);

        return new string(writer.WrittenSpan);
    }

    /// <summary>
    /// Creates a rule the test knows to be valid, failing the test if it is refused.
    /// </summary>
    /// <param name="classes">The classes to select.</param>
    /// <param name="allowedCodePoints">The exempt code points.</param>
    /// <returns>The rule.</returns>
    private static TextHygieneRule CreateRule(TextHygieneClass[] classes, int[] allowedCodePoints)
    {
        var creation = TextHygieneRule.Create(classes, allowedCodePoints);
        Assert.IsTrue(creation.IsSuccess, "The test's rule must be valid.");

        return creation.Value;
    }
}
