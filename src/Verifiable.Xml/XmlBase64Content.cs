using System.Diagnostics.CodeAnalysis;
using Lumoin.Base;
using Verifiable.Foundation;

namespace Verifiable.Xml;

/// <summary>
/// Decodes XML element content typed <c>base64Binary</c> — <c>ds:DigestValue</c>, <c>ds:SignatureValue</c>,
/// <c>ds:X509Certificate</c>, <c>ds:SPKISexp</c> and every <c>ds:CryptoBinary</c> key-material field share
/// this one lexical rule, since section 4.0.1 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> defines <c>ds:CryptoBinary</c> as a <c>restriction</c> of <c>base64Binary</c>,
/// the same lexical base — into the octets they encode.
/// </summary>
/// <remarks>
/// <para>
/// The lexical space is
/// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary">XML Schema Part 2:
/// Datatypes</see> section 3.2.16's <c>Base64Binary</c> production: the 64-character base64 alphabet of
/// <see href="https://www.rfc-editor.org/rfc/rfc2045">IETF RFC 2045</see> (<c>A-Za-z0-9+/</c>) together
/// with the XML white space the fixed <c>collapse</c> <c>whiteSpace</c> facet strips; the count of
/// non-white-space characters is a multiple of four; padding (<c>=</c>) appears only as the last one or two
/// characters of the final four-character quantum; and the character immediately preceding a single
/// trailing <c>=</c> or the character immediately preceding a double trailing <c>==</c> carries,
/// respectively, its low 2 or low 4 bits zero — the production's restricted <c>B16</c>/<c>B04</c>
/// alphabets for the "wasted" bits of a padded quantum. <c>ds:CryptoBinary</c>'s own minimal-length/
/// no-leading-zero-octet rule (section 4.0.1) is a generation-side encoding constraint; this decoder
/// exposes the decoded octets as-is, leading zero octets included.
/// </para>
/// <para>
/// RECORDED DEVIATION: section 6.6.2 of
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> names <see href="https://www.rfc-editor.org/rfc/rfc2045">[MIME]</see>, not
/// <c>base64Binary</c>, as "the normative specification for base64 decoding" of its own transform — under
/// RFC 2045 §6.8 a decoder MAY silently discard any character outside the alphabet rather than refuse the
/// input. This decoder applies the stricter <c>base64Binary</c> lexical space (this type's own summary)
/// uniformly to BOTH the model-read base64 content (<c>DigestValue</c>, <c>SignatureValue</c>,
/// <c>CryptoBinary</c>) and the section 6.6.2 transform's own decoding, never the more lenient MIME reading.
/// Grounds: a lenient decoder that silently drops "junk" characters is an evasion channel — the same bytes
/// can decode differently depending on which characters a validator's decoder happens to tolerate, exactly
/// the malleability XSD's stricter, single-valued lexical mapping closes.
/// </para>
/// </remarks>
internal static class XmlBase64Content
{
    /// <summary>
    /// Decodes <c>base64Binary</c> element content into the octets it encodes.
    /// </summary>
    /// <param name="content">The element content octets, already resolved and coalesced by
    /// <see cref="XmlNodeTable.ValueOf"/>; XML white space anywhere in the content is stripped here, not by
    /// the caller.</param>
    /// <param name="pool">The pool the decoded octets and every scratch buffer are rented from.</param>
    /// <param name="decoded">The decoded octets on success, tagged
    /// <see cref="BufferTags.XmlDecodedContent"/>; the caller owns and must dispose them.</param>
    /// <param name="error">The refusal on failure, always carrying
    /// <see cref="XmlSignatureReadFailure.InvalidBase64Content"/>, with the offset into
    /// <paramref name="content"/> of the offending character, or zero when the violation is a property of
    /// the whole content rather than one position.</param>
    /// <returns><see langword="true"/> when the content was accepted.</returns>
    public static bool TryDecode(ReadOnlySpan<byte> content, BaseMemoryPool pool, [NotNullWhen(true)] out PooledMemory? decoded, out XmlSignatureReadError error)
    {
        ArgumentNullException.ThrowIfNull(pool);
        decoded = null;
        error = default;

        using var significant = new PooledStructList<byte>(pool, Math.Max(content.Length, 1));
        for(int i = 0; i < content.Length; ++i)
        {
            byte octet = content[i];
            if(XmlCharacters.IsWhitespace(octet))
            {
                continue;
            }

            if(!TryBase64Value(octet, out _) && octet != (byte)'=')
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.InvalidBase64Content, i);

                return false;
            }

            significant.Add(octet);
        }

        int significantCount = significant.Count;
        if(significantCount == 0)
        {
            decoded = PooledMemory.FromBytes(ReadOnlySpan<byte>.Empty, pool, BufferTags.XmlDecodedContent);

            return true;
        }

        if(significantCount % 4 != 0)
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.InvalidBase64Content, 0);

            return false;
        }

        ReadOnlySpan<byte> significantSpan = significant.AsSpan();
        for(int i = 0; i < significantCount - 4; ++i)
        {
            if(significantSpan[i] == (byte)'=')
            {
                error = new XmlSignatureReadError(XmlSignatureReadFailure.InvalidBase64Content, 0);

                return false;
            }
        }

        ReadOnlySpan<byte> lastQuantum = significantSpan[(significantCount - 4)..];
        int padCount = CountTrailingPadding(lastQuantum);
        if(padCount < 0 || !HasZeroWastedBits(lastQuantum, padCount))
        {
            error = new XmlSignatureReadError(XmlSignatureReadFailure.InvalidBase64Content, 0);

            return false;
        }

        int outputLength = (significantCount / 4 * 3) - padCount;
        using var output = new PooledStructList<byte>(pool, Math.Max(outputLength, 1));
        for(int quantumStart = 0; quantumStart < significantCount; quantumStart += 4)
        {
            int quantumPadCount = quantumStart == significantCount - 4 ? padCount : 0;
            DecodeQuantum(significantSpan.Slice(quantumStart, 4), quantumPadCount, output);
        }

        decoded = PooledMemory.FromBytes(output.AsSpan(), pool, BufferTags.XmlDecodedContent);

        return true;
    }


    /// <summary>
    /// Counts the trailing <c>=</c> padding characters of a four-character quantum per the
    /// <c>Base64Binary</c> production: none, or one at the last position, or two at the last two
    /// positions. A <c>=</c> anywhere else in the quantum is not a legal quantum.
    /// </summary>
    /// <param name="quantum">The final four significant characters.</param>
    /// <returns>0, 1 or 2 padding characters, or -1 when the quantum's padding placement is illegal.</returns>
    private static int CountTrailingPadding(ReadOnlySpan<byte> quantum)
    {
        if(quantum[0] == (byte)'=' || quantum[1] == (byte)'=')
        {
            return -1;
        }

        bool isThirdPadded = quantum[2] == (byte)'=';
        bool isFourthPadded = quantum[3] == (byte)'=';

        return (isThirdPadded, isFourthPadded) switch
        {
            (false, false) => 0,
            (false, true) => 1,
            (true, true) => 2,
            (true, false) => -1
        };
    }


    /// <summary>
    /// Tells whether the significant character immediately preceding the padding of a padded quantum
    /// carries its "wasted" low bits zero, per the <c>Base64Binary</c> production's restricted
    /// <c>B16</c>/<c>B04</c> alphabets: 2 wasted bits for one <c>=</c>, 4 for two.
    /// </summary>
    /// <param name="quantum">The final four significant characters.</param>
    /// <param name="padCount">The trailing padding count <see cref="CountTrailingPadding"/> found.</param>
    /// <returns><see langword="true"/> when the quantum carries no set wasted bits, always true when unpadded.</returns>
    private static bool HasZeroWastedBits(ReadOnlySpan<byte> quantum, int padCount)
    {
        if(padCount == 0)
        {
            return true;
        }

        int significantIndex = padCount == 1 ? 2 : 1;
        int wastedBitCount = padCount == 1 ? 2 : 4;
        _ = TryBase64Value(quantum[significantIndex], out byte value);

        return (value & ((1 << wastedBitCount) - 1)) == 0;
    }


    /// <summary>
    /// Decodes one four-character quantum into its one, two or three significant output octets, appending
    /// them to the output list.
    /// </summary>
    /// <param name="quantum">The four significant characters of the quantum.</param>
    /// <param name="padCount">The trailing padding count: 0 for three output octets, 1 for two, 2 for one.</param>
    /// <param name="output">The list decoded octets are appended to.</param>
    private static void DecodeQuantum(ReadOnlySpan<byte> quantum, int padCount, PooledStructList<byte> output)
    {
        _ = TryBase64Value(quantum[0], out byte first);
        _ = TryBase64Value(quantum[1], out byte second);
        byte third = 0;
        byte fourth = 0;
        if(padCount < 2)
        {
            _ = TryBase64Value(quantum[2], out third);
        }

        if(padCount < 1)
        {
            _ = TryBase64Value(quantum[3], out fourth);
        }

        output.Add((byte)((first << 2) | (second >> 4)));
        if(padCount < 2)
        {
            output.Add((byte)((second << 4) | (third >> 2)));
        }

        if(padCount < 1)
        {
            output.Add((byte)((third << 6) | fourth));
        }
    }


    /// <summary>
    /// Maps one octet of the 64-character base64 alphabet of
    /// <see href="https://www.rfc-editor.org/rfc/rfc2045">IETF RFC 2045</see> to its 6-bit value.
    /// </summary>
    /// <param name="octet">The octet to classify.</param>
    /// <param name="value">The 6-bit value on success.</param>
    /// <returns><see langword="true"/> when the octet is one of the 64 alphabet characters.</returns>
    private static bool TryBase64Value(byte octet, out byte value)
    {
        (bool isAlphabetCharacter, byte decoded) = octet switch
        {
            >= (byte)'A' and <= (byte)'Z' => (true, (byte)(octet - (byte)'A')),
            >= (byte)'a' and <= (byte)'z' => (true, (byte)(octet - (byte)'a' + 26)),
            >= (byte)'0' and <= (byte)'9' => (true, (byte)(octet - (byte)'0' + 52)),
            (byte)'+' => (true, (byte)62),
            (byte)'/' => (true, (byte)63),
            _ => (false, (byte)0)
        };
        value = decoded;

        return isAlphabetCharacter;
    }
}
