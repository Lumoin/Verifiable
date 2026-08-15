using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Adversarial proofs of <c>HMACOutputLength</c> shapes per section 6.3.1 of <see
/// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing (Second
/// Edition)</see>: "The HMAC algorithm (<see href="https://www.rfc-editor.org/rfc/rfc2104">RFC 2104</see>)
/// takes the truncation length in bits as a parameter; if the parameter is not specified then all the bits
/// of the hash are output." <see cref="XmlSignatureMethodInfo.HmacOutputLengthValue"/> is parsed
/// structurally only and never acted on — MAC verification is out's scope — so an attacker who does not hold
/// the key and alters this value inside an otherwise-unauthenticated <c>SignedInfo</c> gains nothing from
/// this leaf alone: RFC 2104's own truncation weakening only bites an application that reads this value back
/// out and applies it during MAC verification without separately authenticating it: these
/// <c>HMACOutputLength</c> adversarial shapes are parsed, never honored.
/// </summary>
[TestClass]
internal sealed class XmlHmacOutputLengthAdversarialTests
{
    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static string BuildDocument(string hmacOutputLengthContent)
    {
        return $$"""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
                  <HMACOutputLength>{{hmacOutputLengthContent}}</HMACOutputLength>
                </SignatureMethod>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
    }


    private static long ReadHmacOutputLength(string hmacOutputLengthContent)
    {
        using XmlNodeTable table = Parse(BuildDocument(hmacOutputLengthContent));

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(signature)
        {
            XmlSignatureMethodInfo method = signature!.SignedInfo.SignatureMethod;
            Assert.IsTrue(method.HasHmacOutputLength);

            return method.HmacOutputLengthValue;
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.3.1's <c>HMACOutputLengthType</c> parses without an
    /// enforcing verifier: a truncation length of zero — the most severe possible weakening under RFC 2104,
    /// a MAC truncated to nothing — parses structurally: the value is exposed on
    /// <see cref="XmlSignatureMethodInfo.HmacOutputLengthValue"/> exactly as written, never rejected or
    /// clamped, because this leaf performs no MAC verification to weaken.
    /// </summary>
    [TestMethod]
    public void ZeroTruncationLengthParsesStructurally()
    {
        Assert.AreEqual(0L, ReadHmacOutputLength("0"));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.3.1's own truncation rule, "if the parameter is not
    /// specified then all the bits of the hash are output," applied to a specified but adversarial value: a
    /// truncation length of one bit — a MAC an attacker could forge with roughly even odds if an application
    /// both honored this attacker-adjustable field AND verified against it without independent
    /// authentication — parses structurally, exposed unhonored.
    /// </summary>
    [TestMethod]
    public void OneBitTruncationLengthParsesStructurally()
    {
        Assert.AreEqual(1L, ReadHmacOutputLength("1"));
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.3.1's <c>HMACOutputLengthType</c>, an unbounded
    /// <c>integer</c> restriction: an absurdly large truncation length that still fits the parser's 64-bit
    /// accumulator parses structurally to its exact value — no silent clamp to the digest's own bit length,
    /// since this leaf does not know or care what any digest algorithm's bit length is; interpreting the
    /// value against an actual MAC computation is entirely an application's later concern.
    /// </summary>
    [TestMethod]
    public void AbsurdlyLargeButRepresentableTruncationLengthParsesStructurally()
    {
        Assert.AreEqual(999_999_999_999_999_999L, ReadHmacOutputLength("999999999999999999"));
    }


    /// <summary>
    /// Proves this leaf's hardening of <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML
    /// Signature Syntax and Processing (Second Edition)</see> section 6.3.1's unbounded
    /// <c>HMACOutputLengthType</c> against a digit string wider than a 64-bit accumulator: it refuses as
    /// <see cref="XmlSignatureReadFailure.InvalidHmacOutputLength"/> rather than silently wrapping around to
    /// a small or negative value — an overflow-wraparound would itself be a distinct attacker-exploitable
    /// misreading of an adversarial value, which the checked accumulation of
    /// <see cref="XmlSignatureMethodInfo"/>'s own integer parse closes off structurally.
    /// </summary>
    [TestMethod]
    public void TruncationLengthOverflowingInt64RefusesRatherThanWrappingAround()
    {
        using XmlNodeTable table = Parse(BuildDocument("99999999999999999999999999999999"));

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        using(signature)
        {
            Assert.IsFalse(isRead, "An overflowing HMACOutputLength must refuse rather than wrap around.");
            Assert.IsNull(signature);
            Assert.AreEqual(XmlSignatureReadFailure.InvalidHmacOutputLength, error.Failure);
        }
    }
}
