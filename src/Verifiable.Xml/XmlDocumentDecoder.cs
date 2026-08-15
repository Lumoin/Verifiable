using System.Buffers;
using System.Text;

namespace Verifiable.Xml;

/// <summary>
/// The document encoding detected from the leading octets of an XML document.
/// </summary>
internal enum DetectedXmlEncoding
{
    /// <summary>UTF-8, with or without a byte order mark.</summary>
    Utf8,

    /// <summary>UTF-16 big-endian, discriminated by byte order mark or the 16-bit <c>&lt;?xml</c> pattern.</summary>
    Utf16BigEndian,

    /// <summary>UTF-16 little-endian, discriminated by byte order mark or the 16-bit <c>&lt;?xml</c> pattern.</summary>
    Utf16LittleEndian
}


/// <summary>
/// The encoding front end of <see cref="XmlNodeTable.TryParse"/>: detects UTF-8 and UTF-16 per
/// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 4.3.3
/// and Appendix F, refuses every other encoding, transcodes UTF-16 once into pooled UTF-8, and validates
/// that the octets are well-formed with every character matching production <c>Char</c> of section 2.2.
/// Ill-formed sequences are refused, never substituted with replacement characters, per the fatal-error
/// rule of section 4.3.3. Because no non-UCS encoding is ever transcoded, the Unicode Normalization Form C
/// requirement of <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see>
/// section 2.1 for non-UCS source encodings is vacuously met.
/// </summary>
internal static class XmlDocumentDecoder
{
    /// <summary>
    /// Detects the document encoding from its leading octets. UTF-8 and UTF-16 byte order marks are
    /// honored; a document without one is UTF-16 only when it begins with the unambiguous 16-bit
    /// <c>&lt;?xml</c> pattern of <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth
    /// Edition)</see> Appendix F, and otherwise presumed UTF-8. UCS-4 byte order marks and the EBCDIC
    /// <c>&lt;?xm</c> signature are refused as <see cref="XmlReadFailure.InvalidEncoding"/>.
    /// </summary>
    /// <param name="octets">The document octets.</param>
    /// <param name="detected">The detected encoding.</param>
    /// <param name="bomLength">The length of the byte order mark to skip, zero when there is none.</param>
    /// <param name="error">The refusal when detection fails.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    public static bool TryDetectEncoding(ReadOnlySpan<byte> octets, out DetectedXmlEncoding detected, out int bomLength, out XmlReadError error)
    {
        detected = DetectedXmlEncoding.Utf8;
        bomLength = 0;
        error = default;
        if(octets.Length >= 4)
        {
            ReadOnlySpan<byte> ucs4BigEndian = [0x00, 0x00, 0xFE, 0xFF];
            ReadOnlySpan<byte> ucs4LittleEndian = [0xFF, 0xFE, 0x00, 0x00];
            ReadOnlySpan<byte> ucs4UnusualA = [0x00, 0x00, 0xFF, 0xFE];
            ReadOnlySpan<byte> ucs4UnusualB = [0xFE, 0xFF, 0x00, 0x00];
            ReadOnlySpan<byte> ebcdicSignature = [0x4C, 0x6F, 0xA7, 0x94];
            bool isRefusedSignature = octets[..4].SequenceEqual(ucs4BigEndian)
                || octets[..4].SequenceEqual(ucs4LittleEndian)
                || octets[..4].SequenceEqual(ucs4UnusualA)
                || octets[..4].SequenceEqual(ucs4UnusualB)
                || octets[..4].SequenceEqual(ebcdicSignature);
            if(isRefusedSignature)
            {
                error = new XmlReadError(XmlReadFailure.InvalidEncoding, 0);

                return false;
            }
        }

        if(octets.Length >= 3 && octets[0] == 0xEF && octets[1] == 0xBB && octets[2] == 0xBF)
        {
            detected = DetectedXmlEncoding.Utf8;
            bomLength = 3;

            return true;
        }

        if(octets.Length >= 2 && octets[0] == 0xFE && octets[1] == 0xFF)
        {
            detected = DetectedXmlEncoding.Utf16BigEndian;
            bomLength = 2;

            return true;
        }

        if(octets.Length >= 2 && octets[0] == 0xFF && octets[1] == 0xFE)
        {
            detected = DetectedXmlEncoding.Utf16LittleEndian;
            bomLength = 2;

            return true;
        }

        if(octets.Length >= 10)
        {
            ReadOnlySpan<byte> littleEndianPattern = [0x3C, 0x00, 0x3F, 0x00, 0x78, 0x00, 0x6D, 0x00, 0x6C, 0x00];
            if(octets[..10].SequenceEqual(littleEndianPattern))
            {
                detected = DetectedXmlEncoding.Utf16LittleEndian;

                return true;
            }

            ReadOnlySpan<byte> bigEndianPattern = [0x00, 0x3C, 0x00, 0x3F, 0x00, 0x78, 0x00, 0x6D, 0x00, 0x6C];
            if(octets[..10].SequenceEqual(bigEndianPattern))
            {
                detected = DetectedXmlEncoding.Utf16BigEndian;

                return true;
            }
        }

        detected = DetectedXmlEncoding.Utf8;

        return true;
    }


    /// <summary>
    /// Validates that the octets are well-formed UTF-8 and that every decoded character matches production
    /// <c>Char</c> of <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth
    /// Edition)</see> section 2.2.
    /// </summary>
    /// <param name="utf8Octets">The UTF-8 octets after any byte order mark.</param>
    /// <param name="baseOffset">The offset added to refusal positions so they land in original document coordinates.</param>
    /// <param name="error">The refusal when validation fails.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    public static bool TryValidateUtf8(ReadOnlySpan<byte> utf8Octets, long baseOffset, out XmlReadError error)
    {
        error = default;
        int index = 0;
        while(index < utf8Octets.Length)
        {
            OperationStatus status = Rune.DecodeFromUtf8(utf8Octets[index..], out Rune rune, out int consumed);
            if(status != OperationStatus.Done)
            {
                error = new XmlReadError(XmlReadFailure.IllFormedUtf8, baseOffset + index);

                return false;
            }

            if(!XmlCharacters.IsChar(rune.Value))
            {
                error = new XmlReadError(XmlReadFailure.InvalidCharacter, baseOffset + index);

                return false;
            }

            index += consumed;
        }

        return true;
    }


    /// <summary>
    /// Transcodes UTF-16 document octets once into pooled UTF-8, validating code unit pairing and that
    /// every character matches production <c>Char</c> of
    /// <see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.2.
    /// The leading byte order mark is treated as an artifact of encoding and skipped; interior U+FEFF
    /// characters are content and kept, per
    /// <see href="https://www.w3.org/TR/2001/REC-xml-c14n-20010315">Canonical XML 1.0</see> section 2.1.
    /// </summary>
    /// <param name="octets">The original document octets.</param>
    /// <param name="bomLength">The length of the byte order mark to skip.</param>
    /// <param name="isBigEndian">Whether the code units are big-endian.</param>
    /// <param name="destination">The pooled buffer the UTF-8 form is appended to.</param>
    /// <param name="error">The refusal when transcoding fails; its offset is in original document coordinates.</param>
    /// <returns><see langword="false"/> on refusal.</returns>
    public static bool TryTranscodeUtf16(ReadOnlySpan<byte> octets, int bomLength, bool isBigEndian, PooledStructList<byte> destination, out XmlReadError error)
    {
        error = default;
        Span<byte> scratch = stackalloc byte[4];
        int index = bomLength;
        while(index < octets.Length)
        {
            if(index + 1 >= octets.Length)
            {
                error = new XmlReadError(XmlReadFailure.IllFormedUtf16, index);

                return false;
            }

            int unit = isBigEndian
                ? (octets[index] << 8) | octets[index + 1]
                : (octets[index + 1] << 8) | octets[index];
            int codePoint;
            int unitStart = index;
            if(unit >= 0xD800 && unit <= 0xDBFF)
            {
                if(index + 3 >= octets.Length)
                {
                    error = new XmlReadError(XmlReadFailure.IllFormedUtf16, unitStart);

                    return false;
                }

                int lowUnit = isBigEndian
                    ? (octets[index + 2] << 8) | octets[index + 3]
                    : (octets[index + 3] << 8) | octets[index + 2];
                if(lowUnit < 0xDC00 || lowUnit > 0xDFFF)
                {
                    error = new XmlReadError(XmlReadFailure.IllFormedUtf16, unitStart);

                    return false;
                }

                codePoint = 0x10000 + ((unit - 0xD800) << 10) + (lowUnit - 0xDC00);
                index += 4;
            }
            else if(unit >= 0xDC00 && unit <= 0xDFFF)
            {
                error = new XmlReadError(XmlReadFailure.IllFormedUtf16, unitStart);

                return false;
            }
            else
            {
                codePoint = unit;
                index += 2;
            }

            if(!XmlCharacters.IsChar(codePoint))
            {
                error = new XmlReadError(XmlReadFailure.InvalidCharacter, unitStart);

                return false;
            }

            var rune = new Rune(codePoint);
            int written = rune.EncodeToUtf8(scratch);
            destination.AddRange(scratch[..written]);
        }

        return true;
    }
}
