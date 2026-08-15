using System.Text;
using Verifiable.Tests.TestInfrastructure;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XmlBase64Content.TryDecode"/> against the <c>base64Binary</c> lexical space of
/// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary">XML Schema Part 2:
/// Datatypes</see> section 3.2.16, which
/// <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
/// (Second Edition)</see> section 4.0.1/4.2/4.3.3.6 relies on without restating for <c>DigestValue</c>,
/// <c>SignatureValue</c> and <c>ds:CryptoBinary</c> content.
/// </summary>
[TestClass]
internal sealed class XmlBase64ContentTests
{
    private static byte[] Base64Of(byte[] plaintext)
    {
        return Encoding.ASCII.GetBytes(Convert.ToBase64String(plaintext));
    }


    /// <summary>
    /// Proves the decode is the inverse of base64 encoding across every padding remainder — zero, one and
    /// two bytes of trailing input — per the <c>Base64Binary</c> production of
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary">XML Schema Part 2:
    /// Datatypes</see> section 3.2.16, whose length calculation states "length := floor(length(lex3) * 3 / 4)":
    /// a well-formed encoding of any byte count decodes back to exactly those bytes.
    /// </summary>
    [TestMethod]
    public void DecodeInvertsEncodingAcrossEveryPaddingRemainder()
    {
        byte[][] fixtures =
        [
            [],
            [0x00],
            [0xFF],
            [0xDE, 0xAD],
            [0x01, 0x02, 0x03],
            [0xDE, 0xAD, 0xBE, 0xEF],
            [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A]
        ];

        foreach(byte[] plaintext in fixtures)
        {
            bool isDecoded = XmlBase64Content.TryDecode(Base64Of(plaintext), BaseMemoryPool.Shared, out PooledMemory? decoded, out XmlSignatureReadError error);
            Assert.IsTrue(isDecoded, $"A {plaintext.Length}-byte value's base64 encoding must decode but was refused with {error.Failure}.");
            using(decoded)
            {
                Assert.AreSequenceEqual(plaintext, decoded!.AsReadOnlySpan().ToArray(), $"A {plaintext.Length}-byte value must round-trip through encode/decode unchanged.");
            }
        }
    }


    /// <summary>
    /// Proves the four XML white space characters
    /// (<see href="https://www.w3.org/TR/2008/REC-xml-20081126/">XML 1.0 (Fifth Edition)</see> section 2.3
    /// production <c>S</c>: <c>#x20 | #x9 | #xD | #xA</c>) are stripped from anywhere in the content —
    /// leading, trailing and interior to the significant characters — consistent with the fixed
    /// <c>collapse</c> <c>whiteSpace</c> facet <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary">
    /// XML Schema Part 2: Datatypes</see> section 3.2.16 documents for <c>base64Binary</c>.
    /// </summary>
    [TestMethod]
    public void XmlWhitespaceIsStrippedFromAnyPosition()
    {
        byte[] plaintext = [0xDE, 0xAD, 0xBE, 0xEF, 0x01];
        string compact = Convert.ToBase64String(plaintext);
        string interspersed = " \t" + string.Join("\r\n", compact.ToCharArray()) + " ";

        bool isDecoded = XmlBase64Content.TryDecode(Encoding.ASCII.GetBytes(interspersed), BaseMemoryPool.Shared, out PooledMemory? decoded, out XmlSignatureReadError error);

        Assert.IsTrue(isDecoded, $"Whitespace-interspersed content must decode but was refused with {error.Failure}.");
        using(decoded)
        {
            Assert.AreSequenceEqual(plaintext, decoded!.AsReadOnlySpan().ToArray());
        }
    }


    /// <summary>
    /// Proves a character outside XML white space and the 64-character base64 alphabet refuses as <see
    /// cref="XmlSignatureReadFailure.InvalidBase64Content"/> at its own offset in the content. Carries the
    /// RECORDED DEVIATION disposition: section 6.6.2 of <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> names [MIME] (RFC 2045) as the base64 transform's own normative reference,
    /// under which a decoder MAY silently discard a character like this comma rather than refuse it — this
    /// decoder applies the stricter <c>base64Binary</c> lexical space uniformly instead, since a lenient
    /// decoder that drops "junk" bytes is an evasion channel.
    /// </summary>
    [TestMethod]
    public void NonAlphabetCharacterRefusesAtItsOffset()
    {
        bool isDecoded = XmlBase64Content.TryDecode("AB,C"u8, BaseMemoryPool.Shared, out PooledMemory? decoded, out XmlSignatureReadError error);
        using(decoded)
        {
            Assert.IsFalse(isDecoded);
            Assert.IsNull(decoded);
            Assert.AreEqual(XmlSignatureReadFailure.InvalidBase64Content, error.Failure);
            Assert.AreEqual(2L, error.ByteOffset, "The offset must name the comma's own position in the content.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary">XML Schema Part
    /// 2: Datatypes</see> section 3.2.16's quantum rule: a significant-character count that is not a
    /// multiple of four refuses, per the <c>Base64Binary</c> production's note that "the number of
    /// non-whitespace characters in the lexical form" must be "a multiple of four".
    /// </summary>
    [TestMethod]
    public void NonMultipleOfFourSignificantCountRefuses()
    {
        bool isDecoded = XmlBase64Content.TryDecode("QQ"u8, BaseMemoryPool.Shared, out PooledMemory? decoded, out XmlSignatureReadError error);
        using(decoded)
        {
            Assert.IsFalse(isDecoded);
            Assert.IsNull(decoded);
            Assert.AreEqual(XmlSignatureReadFailure.InvalidBase64Content, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary">XML Schema Part
    /// 2: Datatypes</see> section 3.2.16's trailing-quantum grammar: padding (<c>=</c>) outside the final
    /// quantum refuses, since the <c>Base64Binary</c> production admits <c>=</c> only as the last one or two
    /// characters of the trailing <c>(B64S B64S B16S '=')</c>/<c>(B64S B04S '=' #x20? '=')</c> alternatives,
    /// never earlier.
    /// </summary>
    [TestMethod]
    public void PaddingOutsideTheFinalQuantumRefuses()
    {
        bool isDecoded = XmlBase64Content.TryDecode("AA=AAAAA"u8, BaseMemoryPool.Shared, out PooledMemory? decoded, out XmlSignatureReadError error);
        using(decoded)
        {
            Assert.IsFalse(isDecoded, "A '=' inside a non-final quantum must refuse.");
            Assert.IsNull(decoded);
            Assert.AreEqual(XmlSignatureReadFailure.InvalidBase64Content, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary">XML Schema Part
    /// 2: Datatypes</see> section 3.2.16's wasted-bits rule: a single trailing <c>=</c> whose preceding
    /// character carries a nonzero low 2 bits refuses, since the <c>Base64Binary</c> production restricts
    /// that character to the 16-member <c>B16</c> alphabet (<c>[AEIMQUYcgkosw048]</c>), the characters whose
    /// value is a multiple of four. <c>'C'</c> (value 2) is not one of them.
    /// </summary>
    [TestMethod]
    public void SinglePaddedQuantumWithNonzeroWastedBitsRefuses()
    {
        bool isDecoded = XmlBase64Content.TryDecode("ABC="u8, BaseMemoryPool.Shared, out PooledMemory? decoded, out XmlSignatureReadError error);
        using(decoded)
        {
            Assert.IsFalse(isDecoded, "'ABC=' carries nonzero wasted bits in 'C' and must refuse despite matching the coarse quantum shape.");
            Assert.IsNull(decoded);
            Assert.AreEqual(XmlSignatureReadFailure.InvalidBase64Content, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary">XML Schema Part
    /// 2: Datatypes</see> section 3.2.16's wasted-bits rule for the double-padded quantum: a double trailing
    /// <c>==</c> whose preceding character carries a nonzero low 4 bits refuses, since the
    /// <c>Base64Binary</c> production restricts that character to the 4-member <c>B04</c> alphabet
    /// (<c>[AQgw]</c>), the characters whose value is a multiple of sixteen. <c>'B'</c> (value 1) is not
    /// one of them.
    /// </summary>
    [TestMethod]
    public void DoublePaddedQuantumWithNonzeroWastedBitsRefuses()
    {
        bool isDecoded = XmlBase64Content.TryDecode("AB=="u8, BaseMemoryPool.Shared, out PooledMemory? decoded, out XmlSignatureReadError error);
        using(decoded)
        {
            Assert.IsFalse(isDecoded, "'AB==' carries nonzero wasted bits in 'B' and must refuse despite matching the coarse quantum shape.");
            Assert.IsNull(decoded);
            Assert.AreEqual(XmlSignatureReadFailure.InvalidBase64Content, error.Failure);
        }
    }


    /// <summary>
    /// Proves the tag assignment — already anchored via <c>href</c> on this class's own type doc comment to
    /// <see href="https://www.w3.org/TR/2004/REC-xmlschema-2-20041028/#base64Binary">XML Schema Part 2:
    /// Datatypes</see> section 3.2.16 and <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.6, which defines the decoded octets this test proves carry <see
    /// cref="BufferTags.XmlDecodedContent"/>, the tag this reader adds beside <see
    /// cref="BufferTags.XmlCanonical"/> ("the digest is always encoded using base64 [MIME]").
    /// </summary>
    [TestMethod]
    public void DecodedOctetsCarryTheXmlDecodedContentTag()
    {
        bool isDecoded = XmlBase64Content.TryDecode(Base64Of([1, 2, 3]), BaseMemoryPool.Shared, out PooledMemory? decoded, out XmlSignatureReadError error);

        Assert.IsTrue(isDecoded, $"Decoding must succeed but was refused with {error.Failure}.");
        using(decoded)
        {
            Assert.AreEqual(BufferTags.XmlDecodedContent, decoded!.Tag);
        }
    }


    /// <summary>
    /// Proves the "MeteredHousePool custody proven on every refusal path", grounded in <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 8.3's "even there perverse parameters might cause unacceptable
    /// processing or memory demand": every pooled buffer the decoder rents is returned, both when the
    /// content is accepted and when it is refused, observed through <see cref="MeteredHousePool"/>
    /// accounting — the same custody discipline the reading surface proves on every refusal path.
    /// </summary>
    [TestMethod]
    public void PoolCustodyIsBalancedOnAcceptanceAndRefusal()
    {
        using var metered = new MeteredHousePool();

        bool isDecoded = XmlBase64Content.TryDecode(Base64Of([1, 2, 3, 4, 5]), metered.Pool, out PooledMemory? decoded, out XmlSignatureReadError successError);
        Assert.IsTrue(isDecoded, $"Decoding must succeed but was refused with {successError.Failure}.");
        decoded!.Dispose();

        bool isRefused = XmlBase64Content.TryDecode("ABC="u8, metered.Pool, out PooledMemory? refusedDecoded, out XmlSignatureReadError refusalError);
        using(refusedDecoded)
        {
            Assert.IsFalse(isRefused);
            Assert.IsNull(refusedDecoded);
        }

        Assert.AreEqual(0L, metered.OutstandingCount, "Every pooled buffer must be returned, whether decoding succeeded or was refused.");
    }
}
