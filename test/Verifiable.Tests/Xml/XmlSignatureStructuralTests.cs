using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Structural acceptance proofs of <see cref="XmlSignature.TryRead"/> and <see cref="XmlSignatureLocator"/>
/// over the section 2.1–2.3 example signatures of <see
/// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing (Second
/// Edition)</see>, including locator ordering.
/// </summary>
/// <remarks>
/// The section 2.1–2.3 excerpts are illustrative fragments, not complete parseable documents: they use
/// line-number-prefixed pseudo-markup, elide content with "<c>...</c>", and one line even carries a
/// transcription typo (<c>&lt;/DigestValue&gt;</c> missing its opening angle bracket). Every fixture here
/// keeps the exact element names, attribute names and values, and nesting order the example shows, and
/// fills each elided "<c>...</c>" with the same concrete base64 the example's own <c>DigestValue</c>/
/// <c>SignatureValue</c> placeholder already uses where shown (<c>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</c>,
/// which decodes to the literal text "this is not a signature\n" — the specification authors' own joke
/// placeholder) or a minimal one-octet value for fields the example elides entirely (<c>P</c>/<c>Q</c>/
/// <c>G</c>/<c>Y</c>). This is the same "delta stated in the doc comment" transcription discipline <see
/// href="XmlCanonicalizationFixtureInputs"/> established.
/// </remarks>
[TestClass]
internal sealed class XmlSignatureStructuralTests
{
    private const string ThisIsNotASignatureBase64 = "dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK";

    /// <summary>
    /// Section 2.1's simple detached signature: <c>SignedInfo</c> with one <c>Reference</c> carrying a
    /// <c>Transforms</c> chain, and a <c>KeyInfo</c> containing a <c>KeyValue</c>/<c>DSAKeyValue</c>.
    /// </summary>
    private const string Section21Document = """
        <Signature Id="MyFirstSignature" xmlns="http://www.w3.org/2000/09/xmldsig#">
          <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
            <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
            <Reference URI="http://www.w3.org/TR/2000/REC-xhtml1-20000126/">
              <Transforms>
                <Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
              </Transforms>
              <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
              <DigestValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</DigestValue>
            </Reference>
          </SignedInfo>
          <SignatureValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</SignatureValue>
          <KeyInfo>
            <KeyValue>
              <DSAKeyValue>
                <P>cA==</P><Q>cQ==</Q><G>Zw==</G><Y>eQ==</Y>
              </DSAKeyValue>
            </KeyValue>
          </KeyInfo>
        </Signature>
        """;

    /// <summary>
    /// Section 2.2's extended example: a second <c>Reference</c> of <c>Type</c>
    /// <c>.../SignatureProperties</c>, and an <c>Object</c> holding a <c>SignatureProperties</c>/
    /// <c>SignatureProperty</c> whose foreign-namespace content is a <c>timestamp</c> element the model does
    /// not interpret.
    /// </summary>
    private const string Section22Document = """
        <Signature Id="MySecondSignature" xmlns="http://www.w3.org/2000/09/xmldsig#">
          <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
            <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
            <Reference URI="http://www.w3.org/TR/xml-stylesheet/">
              <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
              <DigestValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</DigestValue>
            </Reference>
            <Reference URI="#AMadeUpTimeStamp" Type="http://www.w3.org/2000/09/xmldsig#SignatureProperties">
              <Transforms>
                <Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
              </Transforms>
              <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
              <DigestValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</DigestValue>
            </Reference>
          </SignedInfo>
          <SignatureValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</SignatureValue>
          <Object>
            <SignatureProperties>
              <SignatureProperty Id="AMadeUpTimeStamp" Target="#MySecondSignature">
                <timestamp xmlns="http://www.ietf.org/rfcXXXX.txt">
                  <date>19990914</date>
                  <time>14:34:34:34</time>
                </timestamp>
              </SignatureProperty>
            </SignatureProperties>
          </Object>
        </Signature>
        """;

    /// <summary>
    /// Section 2.3's extended example: a <c>Reference</c> of <c>Type</c> <c>.../Manifest</c> pointing at a
    /// <c>Manifest</c> nested inside an <c>Object</c>, with two inner <c>Reference</c>s of its own.
    /// </summary>
    private const string Section23Document = """
        <Signature Id="MyThirdSignature" xmlns="http://www.w3.org/2000/09/xmldsig#">
          <SignedInfo>
            <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
            <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
            <Reference URI="#MyFirstManifest" Type="http://www.w3.org/2000/09/xmldsig#Manifest">
              <Transforms>
                <Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
              </Transforms>
              <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
              <DigestValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</DigestValue>
            </Reference>
          </SignedInfo>
          <SignatureValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</SignatureValue>
          <Object>
            <Manifest Id="MyFirstManifest">
              <Reference>
                <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <DigestValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</DigestValue>
              </Reference>
              <Reference>
                <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                <DigestValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</DigestValue>
              </Reference>
            </Manifest>
          </Object>
        </Signature>
        """;


    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 2.1's example reads structurally: the fixed <c>Signature</c> child order, the
    /// <c>SignedInfo</c>'s <c>CanonicalizationMethod</c>/<c>SignatureMethod</c> algorithms, the single
    /// <c>Reference</c>'s <c>URI</c>/<c>Transforms</c>/<c>DigestMethod</c>/decoded <c>DigestValue</c>, the
    /// decoded <c>SignatureValue</c>, and the <c>KeyInfo</c>/<c>KeyValue</c>/<c>DSAKeyValue</c> chain with
    /// its four elided fields decoded.
    /// </summary>
    [TestMethod]
    public void Section21SimpleExampleReadsStructurally()
    {
        using XmlNodeTable table = Parse(Section21Document);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Section 2.1's example must read but was refused with {error.Failure}.");
        using(signature)
        {
            Assert.AreSequenceEqual("MyFirstSignature"u8.ToArray(), signature!.Id.ToArray());
            Assert.AreSequenceEqual("http://www.w3.org/2006/12/xml-c14n11"u8.ToArray(), signature.SignedInfo.CanonicalizationMethod.Algorithm.ToArray());
            Assert.AreSequenceEqual("http://www.w3.org/2000/09/xmldsig#dsa-sha1"u8.ToArray(), signature.SignedInfo.SignatureMethod.Algorithm.ToArray());
            Assert.HasCount(1, signature.SignedInfo.References);

            XmlReference reference = signature.SignedInfo.References[0];
            Assert.AreSequenceEqual("http://www.w3.org/TR/2000/REC-xhtml1-20000126/"u8.ToArray(), reference.Uri.ToArray());
            Assert.HasCount(1, reference.Transforms);
            Assert.AreSequenceEqual("http://www.w3.org/2006/12/xml-c14n11"u8.ToArray(), reference.Transforms[0].Algorithm.ToArray());
            Assert.AreSequenceEqual("http://www.w3.org/2000/09/xmldsig#sha1"u8.ToArray(), reference.DigestMethodAlgorithm.ToArray());
            Assert.AreEqual("this is not a signature\n", Encoding.UTF8.GetString(reference.DigestValueOctets.AsReadOnlySpan()));
            Assert.AreEqual("this is not a signature\n", Encoding.UTF8.GetString(signature.SignatureValueOctets.AsReadOnlySpan()));

            Assert.IsTrue(signature.KeyInfo.HasValue);
            Assert.HasCount(1, signature.KeyInfo!.Value.Children);
            XmlKeyInfoChild keyInfoChild = signature.KeyInfo.Value.Children[0];
            Assert.AreEqual(XmlKeyInfoChildKind.KeyValue, keyInfoChild.Kind);
            Assert.AreEqual(XmlKeyValueKind.Dsa, keyInfoChild.KeyValue!.Value.Kind);
            XmlDsaKeyValue dsa = keyInfoChild.KeyValue.Value.Dsa!.Value;
            Assert.AreEqual((byte)0x70, dsa.P!.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)0x71, dsa.Q!.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)0x67, dsa.G!.AsReadOnlySpan()[0]);
            Assert.AreEqual((byte)0x79, dsa.Y.AsReadOnlySpan()[0]);
            Assert.IsNull(dsa.J);
            Assert.IsNull(dsa.Seed);
            Assert.IsNull(dsa.PgenCounter);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 2.2's example reads structurally: the second <c>Reference</c>'s advisory <c>Type</c>
    /// attribute, and the <c>Object</c>/<c>SignatureProperties</c>/<c>SignatureProperty</c> chain with its
    /// <c>Target</c> referencing the enclosing <c>Signature</c>'s own <c>Id</c> and its foreign
    /// <c>timestamp</c> content left as an opaque node index.
    /// </summary>
    [TestMethod]
    public void Section22ExtendedExampleReadsStructurally()
    {
        using XmlNodeTable table = Parse(Section22Document);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Section 2.2's example must read but was refused with {error.Failure}.");
        using(signature)
        {
            Assert.HasCount(2, signature!.SignedInfo.References);
            XmlReference propertyReference = signature.SignedInfo.References[1];
            Assert.AreSequenceEqual("#AMadeUpTimeStamp"u8.ToArray(), propertyReference.Uri.ToArray());
            Assert.AreSequenceEqual("http://www.w3.org/2000/09/xmldsig#SignatureProperties"u8.ToArray(), propertyReference.Type.ToArray());

            Assert.HasCount(1, signature.Objects);
            XmlSignatureObject signatureObject = signature.Objects[0];
            int signaturePropertiesIndex = FindOnlyElementAmong(table, signatureObject.ContentNodeIndices);

            bool isPropertiesRead = XmlSignatureProperties.TryRead(table, signaturePropertiesIndex, out XmlSignatureProperties? properties, out XmlSignatureReadError propertiesError);
            Assert.IsTrue(isPropertiesRead, $"The nested SignatureProperties must read but was refused with {propertiesError.Failure}.");
            Assert.HasCount(1, properties!.Value.Properties);
            XmlSignatureProperty property = properties.Value.Properties[0];
            Assert.AreSequenceEqual("AMadeUpTimeStamp"u8.ToArray(), property.Id.ToArray());
            Assert.AreSequenceEqual("#MySecondSignature"u8.ToArray(), property.Target.ToArray());
            Assert.AreSequenceEqual(signature.Id.ToArray(), "MySecondSignature"u8.ToArray());
            int timestampIndex = FindOnlyElementAmong(table, property.ContentNodeIndices);
            Assert.AreEqual(XmlNodeKind.Element, table.KindOf(timestampIndex));
            Assert.AreSequenceEqual("timestamp"u8.ToArray(), table.LocalNameOf(timestampIndex).ToArray());
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 2.3's example reads structurally: the <c>Reference</c> of <c>Type</c>
    /// <c>.../Manifest</c>, and the nested <c>Manifest</c> — found via the enclosing <c>Object</c>'s content
    /// indices and read standalone through <see cref="XmlManifest.TryRead"/> — carrying its own two
    /// <c>Reference</c> children with decoded digests.
    /// </summary>
    [TestMethod]
    public void Section23ExtendedExampleReadsStructurally()
    {
        using XmlNodeTable table = Parse(Section23Document);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Section 2.3's example must read but was refused with {error.Failure}.");
        using(signature)
        {
            XmlReference manifestReference = signature!.SignedInfo.References[0];
            Assert.AreSequenceEqual("http://www.w3.org/2000/09/xmldsig#Manifest"u8.ToArray(), manifestReference.Type.ToArray());
            Assert.AreSequenceEqual("#MyFirstManifest"u8.ToArray(), manifestReference.Uri.ToArray());

            Assert.HasCount(1, signature.Objects);
            int manifestElementIndex = FindOnlyElementAmong(table, signature.Objects[0].ContentNodeIndices);

            bool isManifestRead = XmlManifest.TryRead(table, manifestElementIndex, BaseMemoryPool.Shared, out XmlManifest? manifest, out XmlSignatureReadError manifestError);
            Assert.IsTrue(isManifestRead, $"The nested Manifest must read but was refused with {manifestError.Failure}.");
            using(manifest)
            {
                Assert.AreSequenceEqual("MyFirstManifest"u8.ToArray(), manifest!.Id.ToArray());
                Assert.HasCount(2, manifest.References);
                foreach(XmlReference nestedReference in manifest.References)
                {
                    Assert.AreEqual("this is not a signature\n", Encoding.UTF8.GetString(nestedReference.DigestValueOctets.AsReadOnlySpan()));
                }
            }
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 6.3.1: <see cref="XmlSignatureMethodInfo.HmacOutputLengthValue"/>
    /// is parsed structurally but never enforced — the truncation length is exposed for a caller to apply,
    /// not honored here, which is exactly the posture that makes the "not specified then all bits"
    /// truncation attack of section 6.3 a caller obligation rather than something this leaf could silently
    /// get wrong.
    /// </summary>
    [TestMethod]
    public void HmacOutputLengthParsesStructurallyWithoutBeingEnforced()
    {
        using XmlNodeTable table = Parse("""
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1">
                  <HMACOutputLength>80</HMACOutputLength>
                </SignatureMethod>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>dGhpcyBpcyBub3QgYSBzaWduYXR1cmUK</SignatureValue>
            </Signature>
            """);

        bool isRead = XmlSignature.TryRead(table, table.DocumentElementIndex, BaseMemoryPool.Shared, out XmlSignature? signature, out XmlSignatureReadError error);
        Assert.IsTrue(isRead, $"Must read but was refused with {error.Failure}.");
        using(signature)
        {
            Assert.IsTrue(signature!.SignedInfo.SignatureMethod.HasHmacOutputLength);
            Assert.AreEqual(80L, signature.SignedInfo.SignatureMethod.HmacOutputLengthValue);
        }
    }


    /// <summary>
    /// Proves the "an enumerator over the table returning every <c>ds:Signature</c> element index in
    /// document order (nested ones included)": <see cref="XmlSignatureLocator.FindSignatures"/> finds an
    /// outer enveloping <c>Signature</c> and a whole nested <c>Signature</c> inside its own <c>Object</c>,
    /// in document order — the shape <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML
    /// Signature Syntax and Processing (Second Edition)</see> section 9's "Recorded misc. facts" names
    /// ("<c>Object</c> may nest whole signatures") and the mechanism the section 6.6.4 worked example of two
    /// sibling enveloped signatures depends on.
    /// </summary>
    [TestMethod]
    public void LocatorFindsOuterThenNestedSignatureInDocumentOrder()
    {
        string document = $"""
            <Signature Id="Outer" xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#dsa-sha1"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                  <DigestValue>{ThisIsNotASignatureBase64}</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>{ThisIsNotASignatureBase64}</SignatureValue>
              <Object>
                {Section21Document.Replace("MyFirstSignature", "Inner", StringComparison.Ordinal)}
              </Object>
            </Signature>
            """;
        using XmlNodeTable table = Parse(document);

        int[] found = XmlSignatureLocator.FindSignatures(table);

        Assert.HasCount(2, found);
        Assert.AreSequenceEqual("Outer"u8.ToArray(), table.AttributeValueOf(found[0], FindAttributeOrdinal(table, found[0], "Id")).ToArray());
        Assert.AreSequenceEqual("Inner"u8.ToArray(), table.AttributeValueOf(found[1], FindAttributeOrdinal(table, found[1], "Id")).ToArray());
        Assert.IsLessThan(found[1], found[0], "The outer Signature's node index must precede the nested one's, per document order.");
    }


    /// <summary>
    /// Proves the locator over a document with no <c>ds:Signature</c> element at all — a shape <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing (Second
    /// Edition)</see> places no lower bound on, since <c>Signature</c> is the root of a signature but nothing
    /// requires a well-formed XML document to contain one: <see cref="XmlSignatureLocator.FindSignatures"/> returns
    /// an empty result rather than refusing.
    /// </summary>
    [TestMethod]
    public void LocatorReturnsEmptyOverDocumentWithNoSignature()
    {
        using XmlNodeTable table = Parse("<root><child/></root>");

        int[] found = XmlSignatureLocator.FindSignatures(table);

        Assert.IsEmpty(found);
    }


    /// <summary>
    /// Finds the single element node among a mixed-content node index list — <c>Object</c>'s and
    /// <c>SignatureProperty</c>'s content indices include the insignificant whitespace text nodes a
    /// pretty-printed fixture carries between its one significant child and the surrounding markup.
    /// </summary>
    private static int FindOnlyElementAmong(XmlNodeTable table, IReadOnlyList<int> nodeIndices)
    {
        int found = -1;
        foreach(int nodeIndex in nodeIndices)
        {
            if(table.KindOf(nodeIndex) != XmlNodeKind.Element)
            {
                continue;
            }

            Assert.AreEqual(-1, found, "Exactly one element child was expected among the content indices.");
            found = nodeIndex;
        }

        Assert.AreNotEqual(-1, found, "No element child was found among the content indices.");

        return found;
    }


    private static int FindAttributeOrdinal(XmlNodeTable table, int elementIndex, string localName)
    {
        int count = table.AttributeCountOf(elementIndex);
        for(int i = 0; i < count; ++i)
        {
            if(Encoding.UTF8.GetString(table.AttributeLocalNameOf(elementIndex, i)) == localName)
            {
                return i;
            }
        }

        Assert.Fail($"Attribute '{localName}' not found.");

        return -1;
    }
}
