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
    /// "Treat the following text as isolated and left-to-right." The other explicit formatting characters have rows
    /// too: <see href="https://www.unicode.org/reports/tr9/#Explicit_Directional_Embeddings">Section 2.1</see>
    /// describes RLE as "Treat the following text as embedded right-to-left.", Section 2.2 describes LRO as
    /// "Force following characters to be treated as strong left-to-right characters.",
    /// <see href="https://www.unicode.org/reports/tr9/#Terminating_Explicit_Directional_Embeddings_and_Overrides">Section 2.3</see>
    /// describes PDF, the terminator of the embeddings and overrides, as "End the scope of the last LRE, RLE, RLO, or
    /// LRO.", and Section 2.4 describes RLI as "Treat the following text as isolated and right-to-left." and FSI as
    /// "Treat the following text as isolated and in the direction of its first strong directional character that is
    /// not inside a nested isolate." Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G25660">D91</see> states
    /// "isolated UTF-16 code units" in the surrogate range "are ill-formed", so a lone high or low surrogate is reported.
    /// The format characters that
    /// <see href="https://www.unicode.org/reports/tr44/#Default_Ignorable_Code_Point">UAX #44</see> subtracts from
    /// Default_Ignorable_Code_Point, "FFF9..FFFB (Interlinear annotation format characters)" and "13430..1343F
    /// (Egyptian hieroglyph format characters)", are in category Cf all the same, so their rows are reported as
    /// <see cref="TextHygieneClass.Format"/>; U+13430 is the first of the Egyptian hieroglyph format controls.
    /// </summary>
    /// <param name="codePoint">The scalar or lone surrogate code unit.</param>
    /// <param name="expectedClass">Its independently specified classification.</param>
    [TestMethod]
    [DataRow(0x202A, TextHygieneClass.Format)]
    [DataRow(0x202E, TextHygieneClass.Format)]
    [DataRow(0x2066, TextHygieneClass.Format)]
    [DataRow(0x2069, TextHygieneClass.Format)]
    [DataRow(0x202B, TextHygieneClass.Format)]
    [DataRow(0x202C, TextHygieneClass.Format)]
    [DataRow(0x202D, TextHygieneClass.Format)]
    [DataRow(0x2067, TextHygieneClass.Format)]
    [DataRow(0x2068, TextHygieneClass.Format)]
    [DataRow(0x200B, TextHygieneClass.Format)]
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
    [DataRow(0x13430, TextHygieneClass.Format)]
    [DataRow(0x2028, TextHygieneClass.LineSeparator)]
    [DataRow(0x2029, TextHygieneClass.ParagraphSeparator)]
    [DataRow(0x0007, TextHygieneClass.Control)]
    [DataRow(0x0080, TextHygieneClass.Control)]
    [DataRow(0x009F, TextHygieneClass.Control)]
    [DataRow(0xE0041, TextHygieneClass.Tag)]
    [DataRow(0xE0000, TextHygieneClass.Tag)]
    [DataRow(0xE0002, TextHygieneClass.Tag)]
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
    [DataRow("\u2065")]
    [DataRow("\U000E0080")]
    public void DefaultRuleLeavesReadableTextAlone(string text)
    {
        AssertClean(text, TextHygieneRule.Default);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Default"/> passes a private-use code point, which
    /// <see cref="TextHygieneRule.Strict"/> reports as <see cref="TextHygieneClass.PrivateUse"/>.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>
    /// defines Co as "a private-use character", a class the default rule does not select.
    /// </summary>
    [TestMethod]
    public void DefaultRulePassesAPrivateUseCodePointThatStrictReports()
    {
        AssertClean(TextOf(0xE000), TextHygieneRule.Default);
        AssertSelectedInEveryPlacement(0xE000, TextHygieneClass.PrivateUse, TextHygieneRule.Strict);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Default"/> reports the Join_Control characters, the zero width non-joiner and the
    /// zero width joiner, as <see cref="TextHygieneClass.Format"/>.
    /// <see href="https://www.unicode.org/reports/tr44/#Join_Control">UAX #44</see> describes Join_Control as
    /// "Format control characters which have specific functions for control of cursive joining and ligation." The
    /// membership, U+200C and U+200D, is that of
    /// <see href="https://www.unicode.org/Public/UCD/latest/ucd/PropList.txt">PropList.txt</see>.
    /// </summary>
    /// <param name="codePoint">A Join_Control character.</param>
    [TestMethod]
    [DataRow(0x200C)]
    [DataRow(0x200D)]
    public void DefaultRuleReportsTheJoinControlCharacters(int codePoint)
    {
        AssertSelectedInEveryPlacement(codePoint, TextHygieneClass.Format, TextHygieneRule.Default);
    }

    /// <summary>
    /// <see cref="TextHygieneRule.Default"/> reports a Prepended_Concatenation_Mark character as
    /// <see cref="TextHygieneClass.Format"/>, though the property marks it visible.
    /// <see href="https://www.unicode.org/reports/tr44/#Prepended_Concatenation_Mark">UAX #44</see> describes
    /// Prepended_Concatenation_Mark as "A small class of visible format controls, which precede and then span a
    /// sequence of other characters, usually digits." The membership, of which the rows here sample U+0600,
    /// U+06DD and U+110BD, is that of
    /// <see href="https://www.unicode.org/Public/UCD/latest/ucd/PropList.txt">PropList.txt</see>.
    /// </summary>
    /// <param name="codePoint">A Prepended_Concatenation_Mark character in general category Cf.</param>
    [TestMethod]
    [DataRow(0x0600)]
    [DataRow(0x06DD)]
    [DataRow(0x110BD)]
    public void DefaultRuleReportsAPrependedConcatenationMark(int codePoint)
    {
        AssertSelectedInEveryPlacement(codePoint, TextHygieneClass.Format, TextHygieneRule.Default);
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
    /// <see cref="TextHygiene.EscapeVisibly"/> reserves and advances the caller's writer once for a whole run of
    /// several clean scalars, not once per scalar, so a partner's large adversarial input is written without one
    /// allocation request per code unit. This pins the documented contract of
    /// <see cref="TextHygiene.EscapeVisibly"/>: "Everything else is written unchanged, one run at a time."
    /// </summary>
    [TestMethod]
    public void EscapeVisiblyReservesOnceForARunOfCleanScalars()
    {
        CountingBufferWriter writer = new();

        TextHygiene.EscapeVisibly("abc".AsSpan(), TextHygieneRule.Default, writer);

        Assert.AreEqual(1, writer.ReservationCount, "A clean run must ask the writer for storage once.");
        Assert.AreEqual(1, writer.AdvanceCount, "A clean run must advance the writer once.");
        Assert.AreEqual("abc", new string(writer.WrittenSpan), "The run must be written unchanged.");
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
        int? codePoint = findings[0].CodePoint;
        Assert.IsNull(codePoint, "An ill-formed sequence holds no code point.");
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
    /// UTF-16 inspection reports each lone surrogate, whether low first or high twice, and never swallows the U+202E
    /// that follows.
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
    /// UTF-16 inspection reports a lone surrogate and resumes decoding at the next code unit, so a well-formed pair
    /// immediately following it is inspected on its own and never swallowed together with the lone code unit.
    /// Unicode core <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G25660">D91</see>
    /// states "Because surrogate code points are not Unicode scalar values, isolated UTF-16 code units in the range"
    /// of surrogates "are ill-formed", so only the isolated code unit is an occurrence; the pair that follows decodes
    /// to its own scalar and is reported under whatever class that scalar has.
    /// </summary>
    [TestMethod]
    public void Utf16InspectionRecoversAfterALoneSurrogate()
    {
        string text = TextOf(0xD800) + TextOf(0xE0041) + TextOf(0x202E);
        List<TextHygieneFinding> findings = [];

        TextHygiene.CollectFindings(text.AsSpan(), TextHygieneRule.Default, findings);

        Assert.HasCount(3, findings, "The lone surrogate, the following pair and the override are each occurrences.");
        AssertFinding(findings[0], 0, 1, 0xD800, TextHygieneClass.UnpairedSurrogate);
        AssertFinding(findings[1], 1, 2, 0xE0041, TextHygieneClass.Tag);
        AssertFinding(findings[2], 3, 1, 0x202E, TextHygieneClass.Format);
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
    /// <see href="https://www.unicode.org/reports/tr44/#Default_Ignorable_Code_Point">UAX #44</see> generates
    /// Default_Ignorable_Code_Point from "Other_Default_Ignorable_Code_Point + Cf (Format characters) +
    /// Variation_Selector - White_Space - FFF9..FFFB (Interlinear annotation format characters) - 13430..1343F
    /// (Egyptian hieroglyph format characters) - Prepended_Concatenation_Mark (Exceptional format characters that
    /// should be visible)" and says of the property that "New characters that should be ignored in rendering (unless
    /// explicitly supported) will be assigned in these ranges", so the rendering phrase describes characters yet to be
    /// assigned in the property's ranges, not the property's current members; and
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
    /// A rule built with U+2029 as an exception passes a paragraph separator that
    /// <see cref="TextHygieneRule.Default"/> reports, so the exception exempts the whole single-code-point class.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see>
    /// defines Zp as "U+2029 PARAGRAPH SEPARATOR only".
    /// </summary>
    [TestMethod]
    public void RuleExceptionForAParagraphSeparatorPassesWhatDefaultReports()
    {
        TextHygieneRule rule = CreateRule([TextHygieneClass.ParagraphSeparator], [0x2029]);

        AssertClean(TextOf(0x2029), rule);
        AssertSelectedInEveryPlacement(0x2029, TextHygieneClass.ParagraphSeparator, TextHygieneRule.Default);
    }

    /// <summary>
    /// A rule that exempts U+202E but not U+202C reports the terminator and passes the override, so the override's
    /// directional scope open to the end of the paragraph, which includes any text the application renders after
    /// the output in it; the visible escape rewrites the terminator and leaves the override unchanged.
    /// <see href="https://www.unicode.org/reports/tr9/#Terminating_Explicit_Directional_Embeddings_and_Overrides">UAX #9, Section 2.3</see>
    /// states "The following character terminates the scope of the last LRE, RLE, LRO, or RLO whose scope has not
    /// yet been terminated." and <see href="https://www.unicode.org/reports/tr9/#X8">rule X8</see> states "All explicit
    /// directional embeddings, overrides and isolates are completely terminated at the end of each paragraph."
    /// </summary>
    [TestMethod]
    public void RuleThatExemptsAnOverrideButNotItsTerminatorLeavesTheScopeOpen()
    {
        TextHygieneRule rule = CreateRule([TextHygieneClass.Format], [0x202E]);
        string text = "a" + TextOf(0x202E) + "b" + TextOf(0x202C) + "c";
        List<TextHygieneFinding> findings = [];
        TextHygiene.CollectFindings(text.AsSpan(), rule, findings);
        List<TextHygieneFinding> utf8Findings = [];
        TextHygiene.CollectFindings(Encoding.UTF8.GetBytes(text).AsSpan(), rule, utf8Findings);
        ArrayBufferWriter<char> writer = new();
        TextHygiene.EscapeVisibly(text.AsSpan(), rule, writer);

        Assert.HasCount(1, findings, "Only the terminator is an occurrence; the exempt override is not.");
        AssertFinding(findings[0], 3, 1, 0x202C, TextHygieneClass.Format);
        Assert.HasCount(1, utf8Findings, "Only the terminator is an occurrence in UTF-8.");
        AssertFinding(utf8Findings[0], 5, 3, 0x202C, TextHygieneClass.Format);
        Assert.AreEqual("a" + TextOf(0x202E) + "b" + "\\" + "u202Cc", new string(writer.WrittenSpan), "The override stays and the terminator is written as its escape.");
    }

    /// <summary>
    /// A rule that exempts U+2067 (RLI) but not U+2069 (PDI) reports the terminator and passes the isolate initiator,
    /// so the isolate's scope stays open to the end of the paragraph; inspection returns that same terminator finding
    /// first, and the visible escape rewrites the terminator and leaves the initiator unchanged.
    /// <see href="https://www.unicode.org/reports/tr9/#Terminating_Explicit_Directional_Isolates">UAX #9, Section 2.5</see>
    /// states "The following character terminates the scope of the last LRI, RLI, or FSI whose scope has not yet been
    /// terminated," and <see href="https://www.unicode.org/reports/tr9/#X8">rule X8</see> states "All explicit
    /// directional embeddings, overrides and isolates are completely terminated at the end of each paragraph."
    /// </summary>
    [TestMethod]
    public void RuleThatExemptsAnIsolateInitiatorButNotItsTerminatorLeavesTheScopeOpen()
    {
        TextHygieneRule rule = CreateRule([TextHygieneClass.Format], [0x2067]);
        string text = "a" + TextOf(0x2067) + "b" + TextOf(0x2069) + "c";
        List<TextHygieneFinding> findings = [];
        TextHygiene.CollectFindings(text.AsSpan(), rule, findings);
        TextHygieneFinding? inspection = TextHygiene.Inspect(text.AsSpan(), rule);
        List<TextHygieneFinding> utf8Findings = [];
        TextHygiene.CollectFindings(Encoding.UTF8.GetBytes(text).AsSpan(), rule, utf8Findings);
        ArrayBufferWriter<char> writer = new();
        TextHygiene.EscapeVisibly(text.AsSpan(), rule, writer);

        Assert.HasCount(1, findings, "Only the terminator is an occurrence; the exempt initiator is not.");
        AssertFinding(findings[0], 3, 1, 0x2069, TextHygieneClass.Format);
        Assert.IsTrue(inspection.HasValue, "Inspection must report the terminator.");
        Assert.AreEqual(findings[0], inspection.Value, "Inspection must return the same terminator finding first.");
        Assert.HasCount(1, utf8Findings, "Only the terminator is an occurrence in UTF-8.");
        AssertFinding(utf8Findings[0], 5, 3, 0x2069, TextHygieneClass.Format);
        Assert.AreEqual("a" + TextOf(0x2067) + "b" + "\\" + "u2069c", new string(writer.WrittenSpan), "The initiator stays and the terminator is written as its escape.");
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
    /// The <see cref="TextHygieneRule(IEnumerable{TextHygieneClass}, IEnumerable{int})"/> constructor throws for a
    /// rule without classes, which could select nothing.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see> lists the categories a
    /// rule selects from; a rule that names none of them passes every input.
    /// </summary>
    [TestMethod]
    public void RuleCreationRefusesAnEmptyClassSet()
    {
        ArgumentException thrown = Assert.ThrowsExactly<ArgumentException>(() => new TextHygieneRule([], [0x0009]));

        Assert.AreEqual("classes", thrown.ParamName, "The refusal must name the empty class set.");
    }

    /// <summary>
    /// The <see cref="TextHygieneRule(IEnumerable{TextHygieneClass}, IEnumerable{int})"/> constructor throws for a
    /// class value that is not a defined <see cref="TextHygieneClass"/>, naming it, because no occurrence can carry it.
    /// <see href="https://www.unicode.org/reports/tr44/#GC_Values_Table">UAX #44, Table 12</see> lists the categories a
    /// rule selects from.
    /// </summary>
    /// <param name="undefinedClass">A numeric value outside the enumeration.</param>
    [TestMethod]
    [DataRow(-1)]
    [DataRow(999)]
    public void RuleCreationRefusesAnUndefinedClass(int undefinedClass)
    {
        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new TextHygieneRule([TextHygieneClass.Format, (TextHygieneClass)undefinedClass], []));

        Assert.AreEqual("classes", thrown.ParamName, "The refusal must name the class collection.");
        Assert.AreEqual(undefinedClass, thrown.ActualValue);
    }

    /// <summary>
    /// The <see cref="TextHygieneRule(IEnumerable{TextHygieneClass}, IEnumerable{int})"/> constructor throws for an
    /// exception outside the Unicode codespace, naming it, because no input can hold it. Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G22696">D9</see> defines the
    /// Unicode codespace as "A range of integers from 0 to" 10FFFF (hexadecimal).
    /// </summary>
    /// <param name="codePoint">A value outside the codespace.</param>
    [TestMethod]
    [DataRow(-1)]
    [DataRow(0x110000)]
    public void RuleCreationRefusesAnExceptionOutsideTheCodespace(int codePoint)
    {
        ArgumentOutOfRangeException thrown = Assert.ThrowsExactly<ArgumentOutOfRangeException>(
            () => new TextHygieneRule([TextHygieneClass.Format], [0x0009, codePoint]));

        Assert.AreEqual("allowedCodePoints", thrown.ParamName, "The refusal must name the exempt code point collection.");
        Assert.AreEqual(codePoint, thrown.ActualValue);
    }

    /// <summary>
    /// The <see cref="TextHygieneRule(IEnumerable{TextHygieneClass}, IEnumerable{int})"/> constructor accepts an
    /// exception anywhere in the Unicode codespace, surrogate code points included, which exempt a lone UTF-16 code
    /// unit. Unicode core
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
        TextHygieneRule rule = new([TextHygieneClass.Format], [codePoint]);

        Assert.Contains(codePoint, rule.AllowedCodePoints, "The rule must keep the exception.");
    }

    /// <summary>
    /// <see cref="TextHygieneFinding"/>'s default value, which no inspection produces, pins the type's documented
    /// default: a zero-length occurrence at offset zero whose class is <see cref="TextHygieneClass.Control"/>, the
    /// enumeration's first and so default, member. Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G25539">D76</see> defines a
    /// Unicode scalar value as "Any Unicode code point except high-surrogate and low-surrogate code points", so
    /// U+0000, the default's <see cref="TextHygieneFinding.Scalar"/>, is one.
    /// </summary>
    [TestMethod]
    public void DefaultValueIsAZeroLengthControlAtOffsetZero()
    {
        TextHygieneFinding finding = default;

        Assert.AreEqual(0, finding.Offset, "The default value's offset is zero.");
        Assert.AreEqual(0, finding.Length, "The default value's length is zero.");
        Assert.AreEqual(0, finding.CodePoint, "The default value's stored code point is zero.");
        Assert.AreEqual(TextHygieneClass.Control, finding.Class, "The default value's class is the enumeration's first member.");
        Assert.AreEqual(new Rune(0), finding.Scalar, "U+0000 is a valid scalar value.");
    }

    /// <summary>
    /// Every occurrence <see cref="TextHygiene"/> reports over mixed input has a length of at least one input unit,
    /// whatever its class, so <see cref="TextHygieneFinding"/>'s unproduced zero-length default is never mistaken
    /// for a real occurrence. Unicode core
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G25660">D91</see> states
    /// "Because surrogate code points are not Unicode scalar values, isolated UTF-16 code units in the range"
    /// of surrogates "are ill-formed", and
    /// <see href="https://www.unicode.org/versions/Unicode18.0.0/core-spec/chapter-3/#G55471">D93b</see> defines the
    /// maximal subpart of an ill-formed UTF-8 sequence as never shorter than "a subsequence of length one", so the
    /// two classes the decoding itself produces are as bounded as the classes a general category selects.
    /// </summary>
    [TestMethod]
    public void EveryProducedFindingHasAPositiveLength()
    {
        string text = TextOf(0x202E) + "a" + TextOf(0xD800) + "b" + TextOf(0xE0041);
        List<TextHygieneFinding> findings = [];

        TextHygiene.CollectFindings(text.AsSpan(), TextHygieneRule.Strict, findings);

        Assert.IsNotEmpty(findings, "The mixed input must produce findings.");
        foreach(TextHygieneFinding finding in findings)
        {
            Assert.IsGreaterThanOrEqualTo(1, finding.Length, "A produced occurrence never has a zero length.");
        }

        byte[] utf8 = [.. Encoding.UTF8.GetBytes(TextOf(0x202E)), (byte)'a', 0xC3, (byte)'b', .. Encoding.UTF8.GetBytes(TextOf(0xE0041))];
        List<TextHygieneFinding> utf8Findings = [];

        TextHygiene.CollectFindings(utf8.AsSpan(), TextHygieneRule.Strict, utf8Findings);

        Assert.IsNotEmpty(utf8Findings, "The mixed UTF-8 input must produce findings.");
        bool hasIllFormedEncodingFinding = false;
        foreach(TextHygieneFinding finding in utf8Findings)
        {
            Assert.IsGreaterThanOrEqualTo(1, finding.Length, "A produced occurrence never has a zero length in UTF-8.");
            hasIllFormedEncodingFinding = hasIllFormedEncodingFinding || finding.Class == TextHygieneClass.IllFormedEncoding;
        }

        Assert.IsTrue(hasIllFormedEncodingFinding, "The lone lead byte must be reported as an ill-formed occurrence.");
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
    /// Creates a rule the test knows to be valid.
    /// </summary>
    /// <param name="classes">The classes to select.</param>
    /// <param name="allowedCodePoints">The exempt code points.</param>
    /// <returns>The rule.</returns>
    private static TextHygieneRule CreateRule(TextHygieneClass[] classes, int[] allowedCodePoints)
    {
        return new TextHygieneRule(classes, allowedCodePoints);
    }

    /// <summary>
    /// A caller-owned <see cref="IBufferWriter{T}"/> that counts its own reservation and advance calls, so a test
    /// can tell one reservation over a run of scalars from one reservation per scalar. It delegates every write to
    /// an inner <see cref="ArrayBufferWriter{T}"/> and adds no behavior beyond the count.
    /// </summary>
    private sealed class CountingBufferWriter : IBufferWriter<char>
    {
        /// <summary>
        /// Gets the storage this counting writer hands out.
        /// </summary>
        private ArrayBufferWriter<char> Inner { get; } = new();

        /// <summary>
        /// Gets how many times <see cref="GetSpan"/> or <see cref="GetMemory"/> reserved storage.
        /// </summary>
        public int ReservationCount { get; private set; }

        /// <summary>
        /// Gets how many times <see cref="Advance"/> committed written storage.
        /// </summary>
        public int AdvanceCount { get; private set; }

        /// <summary>
        /// Gets the characters committed so far, in the order they were written.
        /// </summary>
        public ReadOnlySpan<char> WrittenSpan => Inner.WrittenSpan;

        /// <summary>
        /// Commits <paramref name="count"/> characters of the last reservation, counting the call.
        /// </summary>
        /// <param name="count">The characters the caller wrote into the reserved storage.</param>
        public void Advance(int count)
        {
            AdvanceCount++;
            Inner.Advance(count);
        }

        /// <summary>
        /// Reserves at least <paramref name="sizeHint"/> characters as writable memory, counting the call.
        /// </summary>
        /// <param name="sizeHint">The minimum characters the caller needs.</param>
        /// <returns>The reserved storage.</returns>
        public Memory<char> GetMemory(int sizeHint = 0)
        {
            ReservationCount++;

            return Inner.GetMemory(sizeHint);
        }

        /// <summary>
        /// Reserves at least <paramref name="sizeHint"/> characters as a writable span, counting the call.
        /// </summary>
        /// <param name="sizeHint">The minimum characters the caller needs.</param>
        /// <returns>The reserved storage.</returns>
        public Span<char> GetSpan(int sizeHint = 0)
        {
            ReservationCount++;

            return Inner.GetSpan(sizeHint);
        }
    }
}
