using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// One minimal refusing document per <see cref="XmlSignatureReadFailure"/> member, proving <see
/// cref="XmlSignature.TryRead"/> reads fail-closed, one refusal per
/// <c>XmlSignatureReadFailure</c> member.
/// </summary>
[TestClass]
internal sealed class XmlSignatureRefusalTests
{
    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    private static void AssertRefusal(string document, XmlSignatureReadFailure expected)
    {
        using XmlNodeTable table = Parse(document);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        using(signature)
        {
            Assert.IsFalse(isRead, "The document must be refused.");
            Assert.IsNull(signature);
            Assert.AreEqual(expected, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.1's schema, whose <c>Signature</c> content model is the
    /// ordered sequence <c>SignedInfo, SignatureValue, KeyInfo?, Object*</c>: <see
    /// cref="XmlSignatureReadFailure.MissingSignedInfo"/> for a <c>Signature</c> whose first child is not
    /// <c>SignedInfo</c>.
    /// </summary>
    [TestMethod]
    public void FirstChildNotSignedInfoRefusesAsMissingSignedInfo()
    {
        AssertRefusal(
            """<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"><SignatureValue>AQ==</SignatureValue></Signature>""",
            XmlSignatureReadFailure.MissingSignedInfo);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.1's <c>Signature</c> content model, under which
    /// <c>SignedInfo</c> occurs exactly once: <see cref="XmlSignatureReadFailure.DuplicateCoreChild"/> for a
    /// second <c>SignedInfo</c> where <c>SignatureValue</c> is expected.
    /// </summary>
    [TestMethod]
    public void SecondSignedInfoRefusesAsDuplicateCoreChild()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
            </Signature>
            """,
            XmlSignatureReadFailure.DuplicateCoreChild);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.1's fixed order <c>SignedInfo, SignatureValue, KeyInfo?,
    /// Object*</c>: <see cref="XmlSignatureReadFailure.InvalidChildOrder"/> for a <c>KeyInfo</c> appearing
    /// after an <c>Object</c> — <c>KeyInfo</c>'s single slot is only legal directly after
    /// <c>SignatureValue</c>.
    /// </summary>
    [TestMethod]
    public void KeyInfoAfterObjectRefusesAsInvalidChildOrder()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <Object/>
              <KeyInfo><KeyName>late</KeyName></KeyInfo>
            </Signature>
            """,
            XmlSignatureReadFailure.InvalidChildOrder);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.1's fail-closed core-grammar posture: <see
    /// cref="XmlSignatureReadFailure.UnknownCoreElement"/> for a <c>ds</c>-namespace element name the section
    /// 4.1 schema never declares, in the <c>Object*</c> position.
    /// </summary>
    [TestMethod]
    public void UnrecognizedDsElementRefusesAsUnknownCoreElement()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
              <Bogus/>
            </Signature>
            """,
            XmlSignatureReadFailure.UnknownCoreElement);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.1, whose <c>Signature</c> schema declares only the
    /// attribute <c>Id</c>: <see cref="XmlSignatureReadFailure.UnknownCoreAttribute"/> for an un-prefixed
    /// attribute on <c>Signature</c> beyond it.
    /// </summary>
    [TestMethod]
    public void UnrecognizedUnprefixedAttributeRefusesAsUnknownCoreAttribute()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#" Bogus="x">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.UnknownCoreAttribute);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.1, whose <c>CanonicalizationMethodType</c> declares
    /// <c>Algorithm</c> alone and carries no <c>anyAttribute</c>: <see
    /// cref="XmlSignatureReadFailure.UnknownCoreAttribute"/> for <c>CanonicalizationMethod</c>, the same
    /// shape <c>DigestMethod</c> already refuses an undeclared attribute under.
    /// </summary>
    [TestMethod]
    public void CanonicalizationMethodWithUndeclaredAttributeRefusesAsUnknownCoreAttribute()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11" Evil="x"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.UnknownCoreAttribute);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.2, whose <c>SignatureMethodType</c> declares
    /// <c>Algorithm</c> alone and carries no <c>anyAttribute</c>: <see
    /// cref="XmlSignatureReadFailure.UnknownCoreAttribute"/> for <c>SignatureMethod</c>, the same shape
    /// <c>DigestMethod</c> already refuses an undeclared attribute under.
    /// </summary>
    [TestMethod]
    public void SignatureMethodWithUndeclaredAttributeRefusesAsUnknownCoreAttribute()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1" Evil="x"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.UnknownCoreAttribute);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3's content model, which permits <c>Transforms?</c> at
    /// most once: <see cref="XmlSignatureReadFailure.DuplicateCoreChild"/> for a second <c>Transforms</c>
    /// child under one <c>Reference</c> — a repeat is a duplicate, not the unrelated <see
    /// cref="XmlSignatureReadFailure.UnknownCoreElement"/> the reader fell into before this fix.
    /// </summary>
    [TestMethod]
    public void DuplicateTransformsUnderOneReferenceRefusesAsDuplicateCoreChild()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms>
                  <Transforms><Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/></Transforms>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.DuplicateCoreChild);
    }


    /// <summary>
    /// Proves, a RECORDED DEVIATION from <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.6's <c>DigestValue</c> (a <c>base64Binary</c> simple-content
    /// restriction): a comment SPLITTING a simple-content element's text into more than one node refuses as
    /// <see cref="XmlSignatureReadFailure.UnexpectedElementContent"/>, even though XSD's Element Locally
    /// Valid (Type) rule permits comment/PI information items among a simple-typed element's children without
    /// them affecting its value (this document would be schema-valid with <c>DigestValue</c> = <c>QQ==</c>) —
    /// this reader refuses the whole class rather than distinguish which split shapes are "safe," since a
    /// comment splitting base64 content is exactly the shape comment-smuggling attacks use.
    /// </summary>
    [TestMethod]
    public void CommentSplittingDigestValueTextRefusesAsUnexpectedElementContent()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>QQ<!--x-->==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.UnexpectedElementContent);
    }


    /// <summary>
    /// Proves the XSD <c>base64Binary</c> lexical-space decode rule, applied to <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.6's <c>DigestValue</c>: <see
    /// cref="XmlSignatureReadFailure.InvalidBase64Content"/> propagates from <see
    /// cref="XmlBase64Content.TryDecode"/> through the model reader for content not in the
    /// <c>base64Binary</c> lexical space.
    /// </summary>
    [TestMethod]
    public void NonBase64DigestValueRefusesAsInvalidBase64Content()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>!!!!</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.InvalidBase64Content);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.3.1's <c>HMACOutputLengthType</c>, a <c>simpleType</c>
    /// restriction of <c>integer</c>: <see cref="XmlSignatureReadFailure.InvalidHmacOutputLength"/> for an
    /// <c>HMACOutputLength</c> content that is not a non-negative integer.
    /// </summary>
    [TestMethod]
    public void NonIntegerHmacOutputLengthRefuses()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
                  <HMACOutputLength>-5</HMACOutputLength>
                </SignatureMethod>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.InvalidHmacOutputLength);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3's <c>Reference+</c> cardinality on <c>SignedInfo</c>:
    /// <see cref="XmlSignatureReadFailure.MissingRequiredChild"/> for a <c>SignedInfo</c> with no
    /// <c>Reference</c> at all.
    /// </summary>
    [TestMethod]
    public void SignedInfoWithNoReferenceRefusesAsMissingRequiredChild()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.MissingRequiredChild);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.1's schema, which declares <c>Algorithm</c> required on
    /// <c>CanonicalizationMethod</c>: <see cref="XmlSignatureReadFailure.MissingRequiredAttribute"/> for a
    /// <c>CanonicalizationMethod</c> with no <c>Algorithm</c> attribute.
    /// </summary>
    [TestMethod]
    public void CanonicalizationMethodWithNoAlgorithmRefusesAsMissingRequiredAttribute()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.MissingRequiredAttribute);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.6's <c>DigestValue</c> <c>base64Binary</c>
    /// simple-content restriction, the simple-content direction: <see
    /// cref="XmlSignatureReadFailure.UnexpectedElementContent"/> for a <c>DigestValue</c> containing an
    /// element child rather than the text its content model declares.
    /// </summary>
    [TestMethod]
    public void ElementChildInsideDigestValueRefusesAsUnexpectedElementContent()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue><stray/></DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.UnexpectedElementContent);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3's element-only <c>SignedInfo</c> content model, the
    /// element-only direction: <see cref="XmlSignatureReadFailure.UnexpectedElementContent"/> for
    /// non-whitespace character data between <c>SignedInfo</c>'s element children, which the content model
    /// does not permit (only insignificant whitespace does, per <see cref="XmlSignatureModelGrammar"/>).
    /// </summary>
    [TestMethod]
    public void NonWhitespaceTextBetweenSignedInfoChildrenRefusesAsUnexpectedElementContent()
    {
        AssertRefusal(
            """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                stray text
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """,
            XmlSignatureReadFailure.UnexpectedElementContent);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.1, under which <c>Signature</c> is the root element type
    /// of an XML Signature: an unrecognized top-level element refuses as
    /// <see cref="XmlSignatureReadFailure.UnknownCoreElement"/> when handed directly to
    /// <see cref="XmlSignature.TryRead"/> rather than a <c>ds:Signature</c>.
    /// </summary>
    [TestMethod]
    public void NonSignatureElementRefusesAsUnknownCoreElement()
    {
        AssertRefusal("""<NotASignature xmlns="http://www.w3.org/2000/09/xmldsig#"/>""", XmlSignatureReadFailure.UnknownCoreElement);
    }
}
