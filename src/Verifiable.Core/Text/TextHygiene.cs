using System.Buffers;
using System.Globalization;
using System.Text;

namespace Verifiable.Core.Text;

/// <summary>
/// Finds, in text a partner supplied, the code points that act rather than read when shown (the classes a
/// <see cref="TextHygieneRule"/> selects), and reports them as data or writes them as visible escapes. Of a decoded
/// scalar's class, only <see cref="TextHygieneClass.Tag"/> is a fixed range; every other class comes from the running
/// runtime's Unicode category data, so a code point assigned in a later Unicode version reads as Cn on an older
/// runtime and passes <see cref="TextHygieneRule.Default"/>. <see cref="TextHygieneClass.UnpairedSurrogate"/> and
/// <see cref="TextHygieneClass.IllFormedEncoding"/> come from the decoding itself, an isolated surrogate code unit or
/// an ill-formed maximal subpart, and carry no runtime category. The remarks of <see cref="TextHygieneClass"/> name
/// the code points that act when shown and that no class covers, which pass every rule. Input errors are data: only
/// null arguments are rejected, and the caller's collector or writer may throw. Time is linear in the input and the
/// primitive allocates nothing: <c>CollectFindings</c> adds at most one finding per input unit, and
/// <see cref="EscapeVisibly"/> writes at most six characters per input unit, so a caller holding hostile input caps
/// the input or passes a bounded collector or writer.
/// </summary>
public static class TextHygiene
{
    /// <summary>
    /// The number of characters in one visible escape: a reverse solidus, the letter u and four hexadecimal digits.
    /// <see cref="WriteEscape"/> asks the caller's writer for exactly this much storage.
    /// </summary>
    private static int EscapeLength { get; } = 6;

    /// <summary>
    /// U+005C REVERSE SOLIDUS, the first character of every escape. <see cref="EscapeVisibly"/> escapes it wherever
    /// it occurs in the input, so every reverse solidus in the output begins an escape the primitive wrote.
    /// </summary>
    private static char ReverseSolidus { get; } = '\\';

    /// <summary>
    /// U+000D CARRIAGE RETURN, which shares the exception of a line feed that directly follows it (a CRLF line break).
    /// </summary>
    private static int CarriageReturn { get; } = 0x000D;

    /// <summary>
    /// U+000A LINE FEED, whose exception a directly preceding carriage return shares.
    /// </summary>
    private static int LineFeed { get; } = 0x000A;

    /// <summary>
    /// Inspects UTF-16 text for the first occurrence of a class the rule selects. The occurrence is the inspection's
    /// answer, not an error of it, so clean text answers null. A lone surrogate code unit is an occurrence of
    /// <see cref="TextHygieneClass.UnpairedSurrogate"/> and is never thrown.
    /// </summary>
    /// <param name="text">The complete UTF-16 input.</param>
    /// <param name="rule">The classes to select and the code points to allow.</param>
    /// <returns>The first occurrence, its <see cref="TextHygieneFinding.Offset"/> a UTF-16 code-unit index; null when the text is clean.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="rule"/> is null.</exception>
    public static TextHygieneFinding? Inspect(ReadOnlySpan<char> text, TextHygieneRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        int offset = 0;
        while(offset < text.Length)
        {
            TextHygieneFinding? finding = ReadNext(text, offset, rule, out int consumed);
            if(finding.HasValue)
            {
                return finding;
            }

            offset += consumed;
        }

        return null;
    }

    /// <summary>
    /// Appends every occurrence the rule selects in UTF-16 text to the caller's <see cref="ICollection{T}"/>, in input
    /// order, so the caller can reveal each one; at most one occurrence per input code unit.
    /// </summary>
    /// <param name="text">The complete UTF-16 input.</param>
    /// <param name="rule">The classes to select and the code points to allow.</param>
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
    /// Inspects UTF-8 bytes for the first occurrence of a class the rule selects. Each ill-formed maximal subpart,
    /// a truncated final sequence included, is one <see cref="TextHygieneClass.IllFormedEncoding"/> occurrence, and
    /// decoding resumes at the next byte after it, so a well-formed sequence that follows is never swallowed.
    /// </summary>
    /// <param name="text">The complete UTF-8 input.</param>
    /// <param name="rule">The classes to select and the code points to allow.</param>
    /// <returns>The first occurrence, its <see cref="TextHygieneFinding.Offset"/> a byte offset; null when the bytes are clean.</returns>
    /// <exception cref="ArgumentNullException"><paramref name="rule"/> is null.</exception>
    public static TextHygieneFinding? Inspect(ReadOnlySpan<byte> text, TextHygieneRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        int offset = 0;
        while(offset < text.Length)
        {
            TextHygieneFinding? finding = ReadNext(text, offset, rule, out int consumed);
            if(finding.HasValue)
            {
                return finding;
            }

            offset += consumed;
        }

        return null;
    }

    /// <summary>
    /// Appends every occurrence the rule selects in UTF-8 bytes to the caller's <see cref="ICollection{T}"/>, in input
    /// order and at byte offsets; each ill-formed maximal subpart is one occurrence. At most one occurrence per byte.
    /// </summary>
    /// <param name="text">The complete UTF-8 input.</param>
    /// <param name="rule">The classes to select and the code points to allow.</param>
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
    /// Writes UTF-16 text into the caller's <see cref="IBufferWriter{T}"/> with every occurrence the rule selects
    /// replaced by the visible text of its escape: a reverse solidus, u and four uppercase hexadecimal digits per UTF-16
    /// code unit, so a supplementary scalar becomes two escapes and a lone surrogate one. Every reverse solidus in the
    /// input is written as its escape too, whatever the rule, so the output is injective: every reverse solidus in it
    /// begins an escape this method wrote, and the six input characters of a typed escape never read as an escaped
    /// code point. Everything else is written unchanged, one run at a time. The output is for a reader, not a
    /// serialization format, and it is not confusable analysis.
    /// </summary>
    /// <param name="text">The complete UTF-16 input.</param>
    /// <param name="rule">The classes to escape and the code points to leave unchanged.</param>
    /// <param name="writer">The destination owning all output storage.</param>
    /// <exception cref="ArgumentNullException"><paramref name="rule"/> or <paramref name="writer"/> is null.</exception>
    public static void EscapeVisibly(ReadOnlySpan<char> text, TextHygieneRule rule, IBufferWriter<char> writer)
    {
        ArgumentNullException.ThrowIfNull(rule);
        ArgumentNullException.ThrowIfNull(writer);
        int runStart = 0;
        int offset = 0;
        while(offset < text.Length)
        {
            TextHygieneFinding? finding = ReadNext(text, offset, rule, out int consumed);
            bool isEscaped = finding.HasValue || text[offset] == ReverseSolidus;
            if(isEscaped)
            {
                WriteRun(text[runStart..offset], writer);
                foreach(char unit in text.Slice(offset, consumed))
                {
                    WriteEscape(unit, writer);
                }

                runStart = offset + consumed;
            }

            offset += consumed;
        }

        WriteRun(text[runStart..], writer);
    }

    /// <summary>
    /// Reads one scalar, or one lone surrogate code unit, of UTF-16 input and selects it under the rule.
    /// </summary>
    /// <param name="text">The complete input with a nonempty suffix at the offset.</param>
    /// <param name="offset">The current UTF-16 code-unit index.</param>
    /// <param name="rule">The class and exception selection.</param>
    /// <param name="consumed">One for a lone code unit, otherwise the decoded scalar's UTF-16 length.</param>
    /// <returns>The selected occurrence, or null when the input unit is not selected.</returns>
    private static TextHygieneFinding? ReadNext(ReadOnlySpan<char> text, int offset, TextHygieneRule rule, out int consumed)
    {
        OperationStatus status = Rune.DecodeFromUtf16(text[offset..], out Rune rune, out consumed);
        if(status != OperationStatus.Done)
        {
            consumed = 1;

            return SelectFinding(offset, consumed, text[offset], TextHygieneClass.UnpairedSurrogate, isBeforeLineFeed: false, rule);
        }

        int next = offset + consumed;
        bool isBeforeLineFeed = next < text.Length && text[next] == LineFeed;

        return SelectFinding(offset, consumed, rune.Value, Classify(rune), isBeforeLineFeed, rule);
    }

    /// <summary>
    /// Reads one scalar, or one ill-formed maximal subpart, of UTF-8 input and selects it under the rule.
    /// <see cref="Rune.DecodeFromUtf8"/> reports the length of the maximal subpart it could not decode; at least one
    /// byte is consumed, so every call makes progress.
    /// </summary>
    /// <param name="text">The complete input with a nonempty suffix at the offset.</param>
    /// <param name="offset">The current byte offset.</param>
    /// <param name="rule">The class and exception selection.</param>
    /// <param name="consumed">The bytes of the scalar or of the maximal subpart.</param>
    /// <returns>The selected occurrence, or null when the input unit is not selected.</returns>
    private static TextHygieneFinding? ReadNext(ReadOnlySpan<byte> text, int offset, TextHygieneRule rule, out int consumed)
    {
        OperationStatus status = Rune.DecodeFromUtf8(text[offset..], out Rune rune, out consumed);
        if(status != OperationStatus.Done)
        {
            consumed = Math.Max(consumed, 1);

            return rule.Classes.Contains(TextHygieneClass.IllFormedEncoding)
                ? TextHygieneFinding.ForIllFormedEncoding(offset, consumed)
                : null;
        }

        int next = offset + consumed;
        bool isBeforeLineFeed = next < text.Length && text[next] == LineFeed;

        return SelectFinding(offset, consumed, rune.Value, Classify(rune), isBeforeLineFeed, rule);
    }

    /// <summary>
    /// Selects an occurrence when the rule names its class and no exception covers its code point. A carriage return
    /// directly followed by a line feed is exempt whenever the line feed is, because the pair is one line break.
    /// </summary>
    /// <param name="offset">The index of the first input unit.</param>
    /// <param name="length">The input units the code point spans.</param>
    /// <param name="codePoint">The scalar value or lone code unit.</param>
    /// <param name="category">The class, or null when no class covers the code point.</param>
    /// <param name="isBeforeLineFeed">Whether the next input unit is a line feed.</param>
    /// <param name="rule">The class and exception selection.</param>
    /// <returns>The occurrence, or null when it is not selected.</returns>
    private static TextHygieneFinding? SelectFinding(int offset, int length, int codePoint, TextHygieneClass? category, bool isBeforeLineFeed, TextHygieneRule rule)
    {
        bool isAllowed = rule.AllowedCodePoints.Contains(codePoint)
            || (codePoint == CarriageReturn && isBeforeLineFeed && rule.AllowedCodePoints.Contains(LineFeed));

        return category is { } value && rule.Classes.Contains(value) && !isAllowed
            ? TextHygieneFinding.ForCodePoint(offset, length, codePoint, value)
            : null;
    }

    /// <summary>
    /// Classifies a scalar: first by the fixed range of the Tags block, which does not depend on the runtime; then by
    /// <see cref="Rune.GetUnicodeCategory"/>, the running runtime's general category.
    /// </summary>
    /// <param name="rune">The decoded scalar.</param>
    /// <returns>The class, or null when no class covers the scalar.</returns>
    private static TextHygieneClass? Classify(Rune rune)
    {
        return rune.Value switch
        {
            >= 0xE0000 and <= 0xE007F => TextHygieneClass.Tag,
            _ => Rune.GetUnicodeCategory(rune) switch
            {
                UnicodeCategory.Control => TextHygieneClass.Control,
                UnicodeCategory.Format => TextHygieneClass.Format,
                UnicodeCategory.LineSeparator => TextHygieneClass.LineSeparator,
                UnicodeCategory.ParagraphSeparator => TextHygieneClass.ParagraphSeparator,
                UnicodeCategory.PrivateUse => TextHygieneClass.PrivateUse,
                UnicodeCategory.OtherNotAssigned => TextHygieneClass.Unassigned,
                _ => null
            }
        };
    }

    /// <summary>
    /// Writes a run of unescaped input into the caller's writer, asking it for no storage when the run is empty.
    /// </summary>
    /// <param name="run">The characters to copy unchanged.</param>
    /// <param name="writer">The destination owning the storage.</param>
    private static void WriteRun(ReadOnlySpan<char> run, IBufferWriter<char> writer)
    {
        if(!run.IsEmpty)
        {
            writer.Write(run);
        }
    }

    /// <summary>
    /// Writes the visible escape of one UTF-16 code unit, a reverse solidus, u and four uppercase hexadecimal digits,
    /// straight into storage the caller's writer provides.
    /// </summary>
    /// <param name="unit">The code unit to escape.</param>
    /// <param name="writer">The destination owning the storage.</param>
    private static void WriteEscape(char unit, IBufferWriter<char> writer)
    {
        Span<char> destination = writer.GetSpan(EscapeLength);
        destination[0] = ReverseSolidus;
        destination[1] = 'u';
        _ = ((int)unit).TryFormat(destination[2..EscapeLength], out _, "X4", CultureInfo.InvariantCulture);
        writer.Advance(EscapeLength);
    }
}
