using System.Buffers;
using System.Globalization;
using System.Text;

namespace Verifiable.Core.Text;

/// <summary>
/// Inspects or visibly escapes code points selected by a <see cref="TextHygieneRule"/>.
/// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>
/// defines Cf as "a format control character". Unicode data is the running runtime's, so
/// Unassigned and PrivateUse answers can differ between runtimes. Input errors are data;
/// only null arguments are rejected by this primitive. Caller collectors and writers can throw.
/// </summary>
public static class TextHygiene
{
    /// <summary>
    /// The six characters in a visible UTF-16 escape: a reverse solidus, u, and four hexadecimal digits.
    /// Used by <see cref="WriteEscape"/> to obtain only caller-owned storage, including for Cs,
    /// "a surrogate code point", in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    private static int EscapeLength { get; } = 6;

    /// <summary>
    /// Inspects UTF-16 for the first category selected by <see cref="TextHygieneRule"/>.
    /// Cs is "a surrogate code point" in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>;
    /// a lone code unit is reported without throwing.
    /// </summary>
    /// <param name="text">The complete UTF-16 input.</param>
    /// <param name="rule">The categories to select and code points to allow.</param>
    /// <returns>Success with true for clean input, or the first finding at a UTF-16 code-unit offset.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="rule"/> is null.</exception>
    public static Result<bool, TextHygieneFinding> Inspect(ReadOnlySpan<char> text, TextHygieneRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        int offset = 0;
        while(offset < text.Length)
        {
            TextHygieneFinding? finding = ReadNext(text, offset, rule, out int consumed);
            if(finding is { } value)
            {
                return Result<bool, TextHygieneFinding>.Failure(value);
            }

            offset += consumed;
        }

        return Result<bool, TextHygieneFinding>.Success(true);
    }

    /// <summary>
    /// Appends every selected UTF-16 occurrence to the caller's <see cref="ICollection{T}"/> in input order.
    /// Cf is "a format control character" in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    /// <param name="text">The complete UTF-16 input.</param>
    /// <param name="rule">The categories to select and code points to allow.</param>
    /// <param name="collector">The destination, which is neither cleared nor replaced.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rule"/> or <paramref name="collector"/> is null.</exception>
    public static void CollectFindings(ReadOnlySpan<char> text, TextHygieneRule rule, ICollection<TextHygieneFinding> collector)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(collector);
        int offset = 0;
        while(offset < text.Length)
        {
            TextHygieneFinding? finding = ReadNext(text, offset, rule, out int consumed);
            if(finding is { } value)
            {
                collector.Add(value);
            }

            offset += consumed;
        }

    }

    /// <summary>
    /// Inspects UTF-8 for the first selected occurrence using <see cref="Rune.DecodeFromUtf8"/>.
    /// Unlike Cf, "a format control character" in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>,
    /// an ill-formed sequence has no scalar and is classified as <see cref="TextHygieneClass.IllFormedEncoding"/>.
    /// </summary>
    /// <param name="text">The complete UTF-8 input; a truncated final sequence is ill-formed.</param>
    /// <param name="rule">The categories to select and code points to allow.</param>
    /// <returns>Success with true for clean input, or the first finding at a byte offset.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="rule"/> is null.</exception>
    public static Result<bool, TextHygieneFinding> Inspect(ReadOnlySpan<byte> text, TextHygieneRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        int offset = 0;
        while(offset < text.Length)
        {
            TextHygieneFinding? finding = ReadNext(text, offset, rule, out int consumed);
            if(finding is { } value)
            {
                return Result<bool, TextHygieneFinding>.Failure(value);
            }

            offset += consumed;
        }

        return Result<bool, TextHygieneFinding>.Success(true);
    }

    /// <summary>
    /// Appends every selected UTF-8 occurrence at its byte offset to the caller's <see cref="ICollection{T}"/>.
    /// <see cref="Rune.DecodeFromUtf8"/> determines how many bytes each scalar or malformed subpart consumes;
    /// categories follow <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44,
    /// Table 12</see>, including Cf, "a format control character".
    /// No replacement scalar is classified for malformed bytes.
    /// </summary>
    /// <param name="text">The complete UTF-8 input; a truncated final sequence is ill-formed.</param>
    /// <param name="rule">The categories to select and code points to allow.</param>
    /// <param name="collector">The destination, which is neither cleared nor replaced.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rule"/> or <paramref name="collector"/> is null.</exception>
    public static void CollectFindings(ReadOnlySpan<byte> text, TextHygieneRule rule, ICollection<TextHygieneFinding> collector)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(collector);
        int offset = 0;
        while(offset < text.Length)
        {
            TextHygieneFinding? finding = ReadNext(text, offset, rule, out int consumed);
            if(finding is { } value)
            {
                collector.Add(value);
            }

            offset += consumed;
        }

    }

    /// <summary>
    /// Writes flagged scalars as visible uppercase UTF-16 escapes and other text unchanged into the
    /// caller's <see cref="IBufferWriter{T}"/>, allocating no buffer. A supplementary scalar becomes two escapes;
    /// a lone surrogate becomes one. <see href="https://www.unicode.org/reports/tr9/#Explicit_Directional_Overrides">UAX #9,
    /// Section 2.2</see> says overrides "are to be avoided wherever possible, because of security concerns."
    /// This is display escaping, not a serialization format or confusable analysis.
    /// </summary>
    /// <param name="text">The complete UTF-16 input.</param>
    /// <param name="rule">The categories to escape and code points to leave unchanged.</param>
    /// <param name="writer">The destination owning all output storage.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rule"/> or <paramref name="writer"/> is null.</exception>
    public static void EscapeVisibly(ReadOnlySpan<char> text, TextHygieneRule rule, IBufferWriter<char> writer)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(writer);
        int offset = 0;
        while(offset < text.Length)
        {
            TextHygieneFinding? finding = ReadNext(text, offset, rule, out int consumed);
            ReadOnlySpan<char> units = text.Slice(offset, consumed);
            if(finding.HasValue)
            {
                foreach(char unit in units)
                {
                    WriteEscape(unit, writer);
                }

            }
            else
            {
                writer.Write(units);
            }

            offset += consumed;
        }

    }

    /// <summary>
    /// Reads one scalar or lone UTF-16 code unit for <see cref="Inspect(ReadOnlySpan{char}, TextHygieneRule)"/>.
    /// Cs means "a surrogate code point" in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    /// <param name="text">The complete input with a nonempty suffix at the offset.</param>
    /// <param name="offset">The current UTF-16 code-unit index.</param>
    /// <param name="rule">The category and exception selection.</param>
    /// <param name="consumed">One lone code unit or the decoded scalar's UTF-16 length.</param>
    /// <returns>The selected occurrence, or null when this input unit is allowed.</returns>
    private static TextHygieneFinding? ReadNext(ReadOnlySpan<char> text, int offset, TextHygieneRule rule, out int consumed)
    {
        OperationStatus status = Rune.DecodeFromUtf16(text[offset..], out Rune rune, out consumed);
        bool isDecoded = status == OperationStatus.Done;
        if(!isDecoded)
        {
            consumed = 1;
        }

        int codePoint = isDecoded ? rune.Value : text[offset];
        TextHygieneClass? category = isDecoded ? Classify(rune) : TextHygieneClass.UnpairedSurrogate;

        return SelectFinding(offset, codePoint, category, rule);
    }

    /// <summary>
    /// Reads one scalar or malformed subpart for <see cref="Inspect(ReadOnlySpan{byte}, TextHygieneRule)"/>.
    /// <see cref="Rune.DecodeFromUtf8"/> supplies consumption, including a truncated final subpart;
    /// encoding failures stay distinct from the scalar categories of
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>,
    /// which calls Cf "a format control character".
    /// </summary>
    /// <param name="text">The complete input with a nonempty suffix at the offset.</param>
    /// <param name="offset">The current byte offset.</param>
    /// <param name="rule">The category and exception selection.</param>
    /// <param name="consumed">The decoder's consumed bytes, with at least one byte of progress.</param>
    /// <returns>The selected occurrence; -1 denotes the absence of a code point for malformed bytes.</returns>
    private static TextHygieneFinding? ReadNext(ReadOnlySpan<byte> text, int offset, TextHygieneRule rule, out int consumed)
    {
        OperationStatus status = Rune.DecodeFromUtf8(text[offset..], out Rune rune, out consumed);
        if(status != OperationStatus.Done)
        {
            consumed = Math.Max(consumed, 1);

            return rule.Classes.Contains(TextHygieneClass.IllFormedEncoding)
                ? new TextHygieneFinding(offset, -1, TextHygieneClass.IllFormedEncoding)
                : null;
        }

        return SelectFinding(offset, rune.Value, Classify(rune), rule);
    }

    /// <summary>
    /// Applies <see cref="TextHygieneRule"/> exceptions before category selection so allowed code points pass.
    /// For example, Cc is "a C0 or C1 control code" in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>,
    /// but <see cref="TextHygieneRule.DisplayText"/> allows three layout controls.
    /// </summary>
    private static TextHygieneFinding? SelectFinding(int offset, int codePoint, TextHygieneClass? category, TextHygieneRule rule)
    {
        return category is { } value && rule.Classes.Contains(value) && !rule.AllowedCodePoints.Contains(codePoint)
            ? new TextHygieneFinding(offset, codePoint, value)
            : null;
    }

    /// <summary>
    /// Maps <see cref="Rune.GetUnicodeCategory"/> using the running runtime's Unicode data.
    /// <see href="https://www.unicode.org/Public/UCD/latest/ucd/Blocks.txt">Blocks.txt</see> lists
    /// "E0000..E007F; Tags"; that whole block takes precedence over
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see> categories.
    /// </summary>
    private static TextHygieneClass? Classify(Rune rune)
    {
        return rune.Value is >= 0xE0000 and <= 0xE007F
            ? TextHygieneClass.Tag
            : Rune.GetUnicodeCategory(rune) switch
            {
                UnicodeCategory.Control => TextHygieneClass.Control,
                UnicodeCategory.Format => TextHygieneClass.Format,
                UnicodeCategory.LineSeparator => TextHygieneClass.LineSeparator,
                UnicodeCategory.ParagraphSeparator => TextHygieneClass.ParagraphSeparator,
                UnicodeCategory.PrivateUse => TextHygieneClass.PrivateUse,
                UnicodeCategory.OtherNotAssigned => TextHygieneClass.Unassigned,
                _ => null
            };
    }

    /// <summary>
    /// Writes one six-character escape directly to <see cref="IBufferWriter{T}"/> storage.
    /// Four uppercase hexadecimal digits expose the UTF-16 unit, including Cs,
    /// "a surrogate code point", in
    /// <see href="https://www.unicode.org/reports/tr44/#General_Category_Values">UAX #44, Table 12</see>.
    /// </summary>
    private static void WriteEscape(char unit, IBufferWriter<char> writer)
    {
        Span<char> destination = writer.GetSpan(EscapeLength);
        destination[0] = '\\';
        destination[1] = 'u';
        _ = ((int)unit).TryFormat(destination[2..EscapeLength], out _, "X4", CultureInfo.InvariantCulture);
        writer.Advance(EscapeLength);
    }

}
