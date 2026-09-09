using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// What syntactic kind of PDF object (ISO 32000-1 clause 7.3) a <see cref="PdfValue"/> holds.
/// </summary>
/// <remarks>Closed: ISO 32000-1 clause 7.3 enumerates exactly these object kinds (booleans, numbers, strings, names, arrays, dictionaries, streams, the null object, and indirect references), and clause 7.5.1 adds the keyword form this parser also returns for a bareword it does not otherwise recognise (never itself a valid top-level PDF object, but a shape the tokenizer must still be able to name rather than fail on).</remarks>
internal enum PdfValueKind
{
    /// <summary>An integer object.</summary>
    Integer,

    /// <summary>A real-number object.</summary>
    Real,

    /// <summary>A boolean object (<c>true</c> or <c>false</c>).</summary>
    Boolean,

    /// <summary>The <c>null</c> object.</summary>
    Null,

    /// <summary>A name object, decoded (<c>#XX</c> escapes resolved).</summary>
    Name,

    /// <summary>A literal string object (<c>(...)</c>), decoded (escapes resolved).</summary>
    LiteralString,

    /// <summary>A hexadecimal string object (<c>&lt;...&gt;</c>), decoded.</summary>
    HexString,

    /// <summary>An array object.</summary>
    Array,

    /// <summary>A dictionary object.</summary>
    Dictionary,

    /// <summary>A stream object — a dictionary immediately followed by <c>stream</c>/<c>endstream</c>-delimited data this parser does not decode.</summary>
    Stream,

    /// <summary>An indirect reference (<c>N G R</c>).</summary>
    Reference,

    /// <summary>An unrecognised bareword keyword.</summary>
    Keyword
}


/// <summary>
/// One parsed PDF object, in the minimal shape the byte-surface reader needs to locate signature dictionaries
/// and walk cross-reference structures — not a general PDF object model (RP-1): no type here interprets what an
/// object means, only what syntactic shape it has and, for strings, where its content bytes sit in the source.
/// </summary>
/// <remarks>
/// Internal to this assembly's PDF-locating machinery; never a public return type. <see cref="HexContentStart"/>/
/// <see cref="HexContentEnd"/> carry the source-byte span of a hexadecimal string's digit content (the bytes
/// between, not including, its <c>&lt;</c>/<c>&gt;</c> delimiters) — the span
/// <see cref="PdfByteSurfaceReader"/> checks a signature dictionary's own <c>ByteRange</c> gap against.
/// </remarks>
internal readonly struct PdfValue
{
    /// <summary>The syntactic kind this value holds.</summary>
    public required PdfValueKind Kind { get; init; }

    /// <summary>The numeric value for <see cref="PdfValueKind.Integer"/> or the object number for <see cref="PdfValueKind.Reference"/>; the value for <see cref="PdfValueKind.Boolean"/> as 0/1.</summary>
    public long Number { get; init; }

    /// <summary>The real-number value for <see cref="PdfValueKind.Real"/>.</summary>
    public double RealNumber { get; init; }

    /// <summary>The generation number for <see cref="PdfValueKind.Reference"/>.</summary>
    public long Generation { get; init; }

    /// <summary>The decoded name (without the leading <c>/</c>) for <see cref="PdfValueKind.Name"/>, or the raw text for <see cref="PdfValueKind.Keyword"/>.</summary>
    public string? Text { get; init; }

    /// <summary>The decoded content bytes for <see cref="PdfValueKind.LiteralString"/> or <see cref="PdfValueKind.HexString"/>.</summary>
    public byte[]? StringBytes { get; init; }

    /// <summary>For <see cref="PdfValueKind.HexString"/>, the source-byte offset of the first digit character (after the opening <c>&lt;</c>).</summary>
    public int HexContentStart { get; init; }

    /// <summary>For <see cref="PdfValueKind.HexString"/>, the source-byte offset just past the last digit character (before the closing <c>&gt;</c>).</summary>
    public int HexContentEnd { get; init; }

    /// <summary>The elements for <see cref="PdfValueKind.Array"/>.</summary>
    public IReadOnlyList<PdfValue>? Items { get; init; }

    /// <summary>The entries for <see cref="PdfValueKind.Dictionary"/> or <see cref="PdfValueKind.Stream"/>.</summary>
    public IReadOnlyDictionary<string, PdfValue>? Entries { get; init; }

    /// <summary>For <see cref="PdfValueKind.Dictionary"/> or <see cref="PdfValueKind.Stream"/>, the source-byte offset of the first byte after the opening <c>&lt;&lt;</c>.</summary>
    public int DictionaryContentStart { get; init; }

    /// <summary>For <see cref="PdfValueKind.Dictionary"/> or <see cref="PdfValueKind.Stream"/>, the source-byte offset of the closing <c>&gt;&gt;</c>'s first byte — the raw entries text this dictionary parsed from sits in <c>[DictionaryContentStart, DictionaryContentEnd)</c>, whitespace included, exactly as written.</summary>
    public int DictionaryContentEnd { get; init; }

    /// <summary>For <see cref="PdfValueKind.Stream"/>, the source-byte offset of the stream's own data, right after the <c>stream</c> keyword's end-of-line marker.</summary>
    public int StreamDataStart { get; init; }

    /// <summary>For <see cref="PdfValueKind.Stream"/>, the length in bytes of the stream's own data.</summary>
    public int StreamDataLength { get; init; }
}


/// <summary>
/// A minimal recursive-descent parser for PDF objects (ISO 32000-1 clause 7.3) over a byte span, sized to what
/// locating signature dictionaries and walking cross-reference structures needs (RP-1/RP-2): no content-stream
/// interpretation, no font/image/colour-space semantics, no general object graph — every value this parser
/// returns is read once, inspected for the handful of keys <see cref="PdfByteSurfaceReader"/> asks about, and
/// discarded.
/// </summary>
/// <remarks>
/// <strong>Attacker-reachable input.</strong> A PDF byte stream is exactly as hostile as any other wire format
/// this library parses: every loop is bounded (<see cref="MaxNestingDepth"/>, <see cref="MaxArrayElements"/>,
/// <see cref="MaxDictionaryEntries"/>), every read is span-bounds-checked, and a value this parser cannot make
/// sense of is reported through a <see langword="bool"/> return and an <c>error</c> message — never an
/// exception — mirroring the discipline <see cref="ManagedCertificate"/> applies to DER.
/// </remarks>
internal static class PdfValueParser
{
    /// <summary>The deepest array/dictionary nesting this parser descends into before failing closed.</summary>
    private const int MaxNestingDepth = 64;

    /// <summary>The most elements one array may declare before this parser fails closed.</summary>
    private const int MaxArrayElements = 4096;

    /// <summary>The most entries one dictionary may declare before this parser fails closed.</summary>
    private const int MaxDictionaryEntries = 1024;


    /// <summary>Reports whether a byte is PDF whitespace (ISO 32000-1 clause 7.2.2, table 1).</summary>
    public static bool IsWhitespace(byte b) => b is 0x00 or 0x09 or 0x0A or 0x0C or 0x0D or 0x20;


    /// <summary>Reports whether a byte is a PDF delimiter (ISO 32000-1 clause 7.2.2, table 2).</summary>
    public static bool IsDelimiter(byte b) =>
        b is (byte)'(' or (byte)')' or (byte)'<' or (byte)'>' or (byte)'[' or (byte)']' or (byte)'{' or (byte)'}' or (byte)'/' or (byte)'%';


    private static bool IsDigit(byte b) => b is >= (byte)'0' and <= (byte)'9';


    private static bool IsHexDigit(byte b) => IsDigit(b) || (b is >= (byte)'a' and <= (byte)'f') || (b is >= (byte)'A' and <= (byte)'F');


    private static int HexValue(byte b) => b switch
    {
        >= (byte)'0' and <= (byte)'9' => b - (byte)'0',
        >= (byte)'a' and <= (byte)'f' => b - (byte)'a' + 10,
        >= (byte)'A' and <= (byte)'F' => b - (byte)'A' + 10,
        _ => 0
    };


    /// <summary>Advances past whitespace and <c>%</c>-comments (ISO 32000-1 clause 7.2.3).</summary>
    public static void SkipWhitespaceAndComments(ReadOnlySpan<byte> s, ref int pos)
    {
        while(pos < s.Length)
        {
            if(IsWhitespace(s[pos]))
            {
                pos++;

                continue;
            }

            if(s[pos] == (byte)'%')
            {
                while(pos < s.Length && s[pos] != (byte)'\n' && s[pos] != (byte)'\r')
                {
                    pos++;
                }

                continue;
            }

            break;
        }
    }


    /// <summary>Reads consecutive non-whitespace, non-delimiter bytes as a bareword token.</summary>
    private static ReadOnlySpan<byte> ReadBareword(ReadOnlySpan<byte> s, ref int pos)
    {
        int start = pos;
        while(pos < s.Length && !IsWhitespace(s[pos]) && !IsDelimiter(s[pos]))
        {
            pos++;
        }

        return s[start..pos];
    }


    /// <summary>Reads a run of ASCII digits as an unsigned integer.</summary>
    public static bool TryReadUnsignedInteger(ReadOnlySpan<byte> s, ref int pos, out long value)
    {
        int start = pos;
        while(pos < s.Length && IsDigit(s[pos]))
        {
            pos++;
        }

        if(pos == start)
        {
            value = 0;

            return false;
        }

        return Utf8Parser.TryParse(s[start..pos], out value, out int consumed) && consumed == pos - start;
    }


    /// <summary>Skips whitespace/comments, then reads a run of ASCII digits as an unsigned integer.</summary>
    public static bool SkipWhitespaceThenReadUnsignedInteger(ReadOnlySpan<byte> s, ref int pos, out long value)
    {
        SkipWhitespaceAndComments(s, ref pos);

        return TryReadUnsignedInteger(s, ref pos, out value);
    }


    /// <summary>
    /// Parses the <c>N G obj</c> header of an indirect object at the current position.
    /// </summary>
    public static bool TryParseIndirectObjectHeader(ReadOnlySpan<byte> s, ref int pos, out long objectNumber, out long generation)
    {
        int start = pos;
        objectNumber = 0;
        generation = 0;
        SkipWhitespaceAndComments(s, ref pos);
        if(!TryReadUnsignedInteger(s, ref pos, out objectNumber) || !SkipWhitespaceThenReadUnsignedInteger(s, ref pos, out generation))
        {
            pos = start;

            return false;
        }

        SkipWhitespaceAndComments(s, ref pos);
        if(pos + 3 > s.Length || !s.Slice(pos, 3).SequenceEqual("obj"u8))
        {
            pos = start;

            return false;
        }

        pos += 3;

        return true;
    }


    /// <summary>
    /// Parses one PDF object at the current position, descending into arrays, dictionaries, and streams as
    /// needed.
    /// </summary>
    /// <param name="s">The whole document's bytes.</param>
    /// <param name="pos">The position to parse from; advanced past the parsed value.</param>
    /// <param name="depth">The current nesting depth, for the bound in <see cref="MaxNestingDepth"/>.</param>
    /// <param name="value">The parsed value, when this method returns <see langword="true"/>.</param>
    /// <param name="error">The reason parsing failed, when this method returns <see langword="false"/>.</param>
    public static bool TryParseValue(ReadOnlySpan<byte> s, ref int pos, int depth, out PdfValue value, out string? error)
    {
        value = default;
        error = null;
        SkipWhitespaceAndComments(s, ref pos);
        if(pos >= s.Length)
        {
            error = "Unexpected end of data while reading a PDF object.";

            return false;
        }

        if(depth > MaxNestingDepth)
        {
            error = "A PDF object's array/dictionary nesting exceeds the supported depth.";

            return false;
        }

        byte c = s[pos];
        if(c == (byte)'/')
        {
            return TryParseName(s, ref pos, out value, out error);
        }

        if(c == (byte)'(')
        {
            return TryParseLiteralString(s, ref pos, out value, out error);
        }

        if(c == (byte)'<')
        {
            return pos + 1 < s.Length && s[pos + 1] == (byte)'<'
                ? TryParseDictionaryOrStream(s, ref pos, depth, out value, out error)
                : TryParseHexString(s, ref pos, out value, out error);
        }

        if(c == (byte)'[')
        {
            return TryParseArray(s, ref pos, depth, out value, out error);
        }

        if(c is (byte)'+' or (byte)'-' or (byte)'.' || IsDigit(c))
        {
            return TryParseNumberOrReference(s, ref pos, out value, out error);
        }

        ReadOnlySpan<byte> word = ReadBareword(s, ref pos);
        if(word.IsEmpty)
        {
            error = $"An unrecognised delimiter 0x{c:X2} at offset {pos}.";

            return false;
        }

        if(word.SequenceEqual("true"u8))
        {
            value = new PdfValue { Kind = PdfValueKind.Boolean, Number = 1 };

            return true;
        }

        if(word.SequenceEqual("false"u8))
        {
            value = new PdfValue { Kind = PdfValueKind.Boolean, Number = 0 };

            return true;
        }

        if(word.SequenceEqual("null"u8))
        {
            value = new PdfValue { Kind = PdfValueKind.Null };

            return true;
        }

        value = new PdfValue { Kind = PdfValueKind.Keyword, Text = Encoding.Latin1.GetString(word) };

        return true;
    }


    private static bool TryParseName(ReadOnlySpan<byte> s, ref int pos, out PdfValue value, out string? error)
    {
        value = default;
        error = null;
        pos++; //Consumes the leading '/'.

        var decoded = new StringBuilder();
        while(pos < s.Length && !IsWhitespace(s[pos]) && !IsDelimiter(s[pos]))
        {
            byte b = s[pos];
            if(b == (byte)'#' && pos + 2 < s.Length && IsHexDigit(s[pos + 1]) && IsHexDigit(s[pos + 2]))
            {
                decoded.Append((char)((HexValue(s[pos + 1]) << 4) | HexValue(s[pos + 2])));
                pos += 3;
            }
            else
            {
                decoded.Append((char)b);
                pos++;
            }
        }

        value = new PdfValue { Kind = PdfValueKind.Name, Text = decoded.ToString() };

        return true;
    }


    private static bool TryParseLiteralString(ReadOnlySpan<byte> s, ref int pos, out PdfValue value, out string? error)
    {
        value = default;
        error = null;
        pos++; //Consumes the opening '('.

        var bytes = new List<byte>();
        int nesting = 1;
        while(pos < s.Length)
        {
            byte b = s[pos];
            if(b == (byte)'\\')
            {
                pos++;
                if(pos >= s.Length)
                {
                    error = "A literal string ends with a trailing, unresolved escape.";

                    return false;
                }

                byte e = s[pos];
                switch(e)
                {
                    case (byte)'n':
                        bytes.Add((byte)'\n');
                        pos++;
                        break;
                    case (byte)'r':
                        bytes.Add((byte)'\r');
                        pos++;
                        break;
                    case (byte)'t':
                        bytes.Add((byte)'\t');
                        pos++;
                        break;
                    case (byte)'b':
                        bytes.Add(0x08);
                        pos++;
                        break;
                    case (byte)'f':
                        bytes.Add(0x0C);
                        pos++;
                        break;
                    case (byte)'(':
                        bytes.Add((byte)'(');
                        pos++;
                        break;
                    case (byte)')':
                        bytes.Add((byte)')');
                        pos++;
                        break;
                    case (byte)'\\':
                        bytes.Add((byte)'\\');
                        pos++;
                        break;
                    case (byte)'\r':
                        pos++;
                        if(pos < s.Length && s[pos] == (byte)'\n')
                        {
                            pos++;
                        }

                        break;
                    case (byte)'\n':
                        pos++;
                        break;
                    case >= (byte)'0' and <= (byte)'7':
                        {
                            int octal = 0;
                            int digits = 0;
                            while(digits < 3 && pos < s.Length && s[pos] is >= (byte)'0' and <= (byte)'7')
                            {
                                octal = (octal << 3) | (s[pos] - (byte)'0');
                                pos++;
                                digits++;
                            }

                            bytes.Add((byte)(octal & 0xFF));
                        }

                        break;
                    default:
                        bytes.Add(e);
                        pos++;
                        break;
                }

                continue;
            }

            if(b == (byte)'(')
            {
                nesting++;
                bytes.Add(b);
                pos++;
                continue;
            }

            if(b == (byte)')')
            {
                nesting--;
                pos++;
                if(nesting == 0)
                {
                    break;
                }

                bytes.Add(b);
                continue;
            }

            bytes.Add(b);
            pos++;
        }

        if(nesting != 0)
        {
            error = "A literal string's parentheses are not balanced.";

            return false;
        }

        value = new PdfValue { Kind = PdfValueKind.LiteralString, StringBytes = [.. bytes] };

        return true;
    }


    private static bool TryParseHexString(ReadOnlySpan<byte> s, ref int pos, out PdfValue value, out string? error)
    {
        value = default;
        error = null;
        pos++; //Consumes the opening '<'.
        int contentStart = pos;
        while(pos < s.Length && s[pos] != (byte)'>')
        {
            byte b = s[pos];
            if(!IsWhitespace(b) && !IsHexDigit(b))
            {
                error = $"A hexadecimal string contains a non-hexadecimal, non-whitespace byte 0x{b:X2} at offset {pos}.";

                return false;
            }

            pos++;
        }

        if(pos >= s.Length)
        {
            error = "A hexadecimal string is not terminated by '>'.";

            return false;
        }

        int contentEnd = pos;
        pos++; //Consumes the closing '>'.

        var bytes = new List<byte>((contentEnd - contentStart + 1) / 2);
        int highNibble = -1;
        for(int i = contentStart; i < contentEnd; i++)
        {
            byte b = s[i];
            if(IsWhitespace(b))
            {
                continue;
            }

            int nibble = HexValue(b);
            if(highNibble < 0)
            {
                highNibble = nibble;
            }
            else
            {
                bytes.Add((byte)((highNibble << 4) | nibble));
                highNibble = -1;
            }
        }

        if(highNibble >= 0)
        {
            bytes.Add((byte)(highNibble << 4));
        }

        value = new PdfValue
        {
            Kind = PdfValueKind.HexString,
            StringBytes = [.. bytes],
            HexContentStart = contentStart,
            HexContentEnd = contentEnd
        };

        return true;
    }


    private static bool TryParseArray(ReadOnlySpan<byte> s, ref int pos, int depth, out PdfValue value, out string? error)
    {
        value = default;
        error = null;
        pos++; //Consumes the opening '['.

        var items = new List<PdfValue>();
        while(true)
        {
            SkipWhitespaceAndComments(s, ref pos);
            if(pos >= s.Length)
            {
                error = "An array is not terminated by ']'.";

                return false;
            }

            if(s[pos] == (byte)']')
            {
                pos++;
                break;
            }

            if(items.Count >= MaxArrayElements)
            {
                error = "An array declares more elements than this reader supports.";

                return false;
            }

            if(!TryParseValue(s, ref pos, depth + 1, out PdfValue item, out error))
            {
                return false;
            }

            items.Add(item);
        }

        value = new PdfValue { Kind = PdfValueKind.Array, Items = items };

        return true;
    }


    private static bool TryParseNumberOrReference(ReadOnlySpan<byte> s, ref int pos, out PdfValue value, out string? error)
    {
        value = default;
        error = null;

        ReadOnlySpan<byte> firstToken = ReadBareword(s, ref pos);
        if(!TryParseNumberToken(firstToken, out double firstReal, out bool firstIsInteger, out long firstInteger))
        {
            error = "A malformed numeric token.";

            return false;
        }

        if(firstIsInteger && firstInteger >= 0)
        {
            int beforeLookahead = pos;
            SkipWhitespaceAndComments(s, ref pos);
            if(pos < s.Length && IsDigit(s[pos]))
            {
                ReadOnlySpan<byte> secondToken = ReadBareword(s, ref pos);
                if(TryParseNumberToken(secondToken, out _, out bool secondIsInteger, out long secondInteger) && secondIsInteger && secondInteger >= 0)
                {
                    int beforeR = pos;
                    SkipWhitespaceAndComments(s, ref pos);
                    if(pos < s.Length && s[pos] == (byte)'R' && (pos + 1 >= s.Length || IsWhitespace(s[pos + 1]) || IsDelimiter(s[pos + 1])))
                    {
                        pos++; //Consumes the 'R'.
                        value = new PdfValue { Kind = PdfValueKind.Reference, Number = firstInteger, Generation = secondInteger };

                        return true;
                    }

                    pos = beforeR;
                }
            }

            pos = beforeLookahead;
        }

        value = firstIsInteger
            ? new PdfValue { Kind = PdfValueKind.Integer, Number = firstInteger }
            : new PdfValue { Kind = PdfValueKind.Real, RealNumber = firstReal };

        return true;
    }


    private static bool TryParseNumberToken(ReadOnlySpan<byte> token, out double real, out bool isInteger, out long integer)
    {
        real = 0;
        integer = 0;
        isInteger = false;
        if(token.IsEmpty)
        {
            return false;
        }

        if(Utf8Parser.TryParse(token, out long parsedInteger, out int integerConsumed) && integerConsumed == token.Length)
        {
            integer = parsedInteger;
            real = parsedInteger;
            isInteger = true;

            return true;
        }

        if(Utf8Parser.TryParse(token, out double parsedReal, out int realConsumed) && realConsumed == token.Length)
        {
            real = parsedReal;

            return true;
        }

        return false;
    }


    private static bool TryParseDictionaryOrStream(ReadOnlySpan<byte> s, ref int pos, int depth, out PdfValue value, out string? error)
    {
        value = default;
        error = null;
        pos += 2; //Consumes the opening '<<'.
        int dictionaryContentStart = pos;

        var entries = new Dictionary<string, PdfValue>(StringComparer.Ordinal);
        int dictionaryContentEnd;
        while(true)
        {
            SkipWhitespaceAndComments(s, ref pos);
            if(pos + 1 < s.Length && s[pos] == (byte)'>' && s[pos + 1] == (byte)'>')
            {
                dictionaryContentEnd = pos;
                pos += 2;
                break;
            }

            if(pos >= s.Length)
            {
                error = "A dictionary is not terminated by '>>'.";

                return false;
            }

            if(s[pos] != (byte)'/')
            {
                error = $"A dictionary key must be a Name; found a different token at offset {pos}.";

                return false;
            }

            if(entries.Count >= MaxDictionaryEntries)
            {
                error = "A dictionary declares more entries than this reader supports.";

                return false;
            }

            if(!TryParseName(s, ref pos, out PdfValue key, out error) || !TryParseValue(s, ref pos, depth + 1, out PdfValue entryValue, out error))
            {
                return false;
            }

            entries[key.Text!] = entryValue;
        }

        int beforeStreamKeyword = pos;
        SkipWhitespaceAndComments(s, ref pos);
        if(pos + 6 > s.Length || !s.Slice(pos, 6).SequenceEqual("stream"u8))
        {
            pos = beforeStreamKeyword;
            value = new PdfValue
            {
                Kind = PdfValueKind.Dictionary,
                Entries = entries,
                DictionaryContentStart = dictionaryContentStart,
                DictionaryContentEnd = dictionaryContentEnd
            };

            return true;
        }

        pos += 6;

        //ISO 32000-1 clause 7.3.8.1: the 'stream' keyword is followed by CRLF or a bare LF, never a bare CR.
        if(pos < s.Length && s[pos] == (byte)'\r')
        {
            pos++;
        }

        if(pos < s.Length && s[pos] == (byte)'\n')
        {
            pos++;
        }

        int streamStart = pos;
        int streamLength = -1;
        if(entries.TryGetValue("Length", out PdfValue lengthValue) && lengthValue.Kind == PdfValueKind.Integer && lengthValue.Number >= 0)
        {
            streamLength = (int)lengthValue.Number;
        }

        int streamEnd;
        if(streamLength >= 0 && streamStart + streamLength <= s.Length && MatchesEndstreamAfter(s, streamStart + streamLength))
        {
            streamEnd = streamStart + streamLength;
        }
        else
        {
            //An indirect (unresolved) or missing /Length falls back to scanning for the literal 'endstream'
            //keyword — safe for locating purposes, since this parser never needs the stream's own decoded bytes.
            int found = IndexOf(s, "endstream"u8, streamStart);
            if(found < 0)
            {
                error = "A stream object has no matching 'endstream' keyword.";

                return false;
            }

            streamEnd = found;
        }

        pos = streamEnd;
        SkipWhitespaceAndComments(s, ref pos);
        if(pos + 9 > s.Length || !s.Slice(pos, 9).SequenceEqual("endstream"u8))
        {
            error = "A stream's declared length does not reach its 'endstream' keyword.";

            return false;
        }

        pos += 9;
        value = new PdfValue
        {
            Kind = PdfValueKind.Stream,
            Entries = entries,
            DictionaryContentStart = dictionaryContentStart,
            DictionaryContentEnd = dictionaryContentEnd,
            StreamDataStart = streamStart,
            StreamDataLength = streamEnd - streamStart
        };

        return true;
    }


    private static bool MatchesEndstreamAfter(ReadOnlySpan<byte> s, int pos)
    {
        SkipWhitespaceAndComments(s, ref pos);

        return pos + 9 <= s.Length && s.Slice(pos, 9).SequenceEqual("endstream"u8);
    }


    private static int IndexOf(ReadOnlySpan<byte> s, ReadOnlySpan<byte> needle, int from)
    {
        int index = s[from..].IndexOf(needle);

        return index < 0 ? -1 : from + index;
    }


    /// <summary>Finds the last occurrence of a byte sequence in a span, or -1 when absent.</summary>
    public static int LastIndexOf(ReadOnlySpan<byte> s, ReadOnlySpan<byte> needle)
    {
        for(int i = s.Length - needle.Length; i >= 0; i--)
        {
            if(s.Slice(i, needle.Length).SequenceEqual(needle))
            {
                return i;
            }
        }

        return -1;
    }
}
