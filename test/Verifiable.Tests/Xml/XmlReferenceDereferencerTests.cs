using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XmlReferenceDereferencer.TryDereference(XmlNodeTable, XmlReference, XmlReferenceResolver?, BaseMemoryPool, out XmlDereferenceResult, out XmlSignatureProcessingError)"/>
/// against the four-form same-document table, the external-resolver seam and the Id ruling. Every same-document case dereferences a real <c>ds:Reference</c> read out of
/// a full <c>ds:Signature</c> structural model, not a hand-built <see cref="XmlNodeSet"/>, so the proof exercises the seam <see cref="XmlSignature.TryRead"/>'s reader and the
/// reference-processing engine actually share.
/// </summary>
[TestClass]
internal sealed class XmlReferenceDereferencerTests
{
    /// <summary>
    /// A document carrying one comment before its root element, one comment inside the same-document
    /// dereference target's own subtree, and one comment after the root element — the same three-position
    /// comment layout its <see cref="XmlNodeSetWithoutCommentsTests"/> fixture uses, wrapped around a full
    /// <c>ds:Signature</c> whose sole <c>Reference</c> carries the URI form under test.
    /// </summary>
    private static string BuildDocument(string referenceUri)
    {
        return $$"""
            <!--doc-comment-before--><Document>
              <Target Id="target"><!--target-comment-->content<Child/></Target>
              <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                  <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  <Reference URI="{{referenceUri}}">
                    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document><!--doc-comment-after-->
            """;
    }


    private static (XmlNodeTable Table, XmlSignature Signature) ReadFirstSignature(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        int[] signatureIndices = XmlSignatureLocator.FindSignatures(table!);
        Assert.HasCount(1, signatureIndices, "The fixture document must carry exactly one Signature element.");

        bool isRead = XmlSignature.TryRead(table!, signatureIndices[0], pool, out XmlSignature? signature, out XmlSignatureReadError readSignatureError);
        Assert.IsTrue(isRead, $"The fixture Signature must read but was refused with {readSignatureError.Failure}.");

        return (table!, signature!);
    }


    private static string Canonicalize(XmlNodeTable table, XmlNodeSet nodeSet, XmlCanonicalizationAlgorithm algorithm)
    {
        bool isCanonicalized = XmlCanonicalization.TryCanonicalize(table, nodeSet, algorithm, BaseMemoryPool.Shared, out PooledMemory? canonicalOctets, out XmlCanonicalizationError error);
        Assert.IsTrue(isCanonicalized, $"Canonicalization must succeed but was refused with {error.Failure}.");
        using(canonicalOctets)
        {
            return Encoding.UTF8.GetString(canonicalOctets!.AsReadOnlySpan());
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.3's chapeau MUST — "dereferencing a null URI
    /// (<c>URI=""</c>) MUST result in an XPath node-set that includes every non-comment node of the XML
    /// document" — via the null-URI form of the table: <c>URI=""</c> dereferences to the whole document with
    /// comments stripped. Rendered under the with-comments algorithm the result carries zero comment octets,
    /// byte-identical to the same dereference rendered under the comment-omitting algorithm.
    /// </summary>
    [TestMethod]
    public void NullUriDereferencesToWholeDocumentWithCommentsStripped()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildDocument(string.Empty), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            XmlReference reference = signature.SignedInfo.References[0];
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, reference, resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsTrue(isDereferenced, $"Must dereference but was refused with {error.Failure}.");
            Assert.IsTrue(result.IsNodeSet);

            string withComments = Canonicalize(table, result.NodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments);
            string omitComments = Canonicalize(table, result.NodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);

            Assert.DoesNotContain("<!--", withComments, "URI=\"\" must strip every comment even under a with-comments algorithm.");
            Assert.AreEqual(omitComments, withComments, "URI=\"\" must render byte-identically under both algorithm variants.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.3 step 4's shortname branch, read together with
    /// section 4.3.3.2's example — "XML Signature (and its applications) modify this node-set to include the
    /// element plus all descendants ... but not comments" — for the bare-name (shortname) XPointer form:
    /// <c>URI="#target"</c> dereferences to the identified element's subtree with comments stripped. The
    /// subtree's own descendant comment is stripped even though it lies inside the identified subtree, and
    /// the document-level comments outside the subtree are absent regardless, since they were never part of
    /// the element-subtree node-set at all.
    /// </summary>
    [TestMethod]
    public void BareNameUriDereferencesToElementSubtreeWithCommentsStripped()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildDocument("#target"), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            XmlReference reference = signature.SignedInfo.References[0];
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, reference, resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsTrue(isDereferenced, $"Must dereference but was refused with {error.Failure}.");
            Assert.IsTrue(result.IsNodeSet);

            string withComments = Canonicalize(table, result.NodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments);

            Assert.DoesNotContain("<!--", withComments, "URI=\"#target\" must strip the subtree's own comment.");
            Assert.Contains("content", withComments, "The identified element's own text content must render.");
            Assert.DoesNotContain("<Signature", withComments, "The subtree must not include content outside the identified element.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.3 step 4 — "if the URI has no fragment identifier or
    /// the fragment identifier is a shortname XPointer, then delete all comment nodes" does not fire for a
    /// scheme-based XPointer — for the <c>#xpointer(/)</c> scheme-based form: comments are RETAINED. Every
    /// comment in the document, both outside and inside the identified (whole-document) node-set, survives
    /// under a with-comments algorithm and is absent under the comment-omitting algorithm — the algorithm
    /// variant alone now governs, since the node-set itself carries no exclusion mark.
    /// </summary>
    [TestMethod]
    public void XPointerRootDereferencesToWholeDocumentWithCommentsRetained()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildDocument("#xpointer(/)"), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            XmlReference reference = signature.SignedInfo.References[0];
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, reference, resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsTrue(isDereferenced, $"Must dereference but was refused with {error.Failure}.");
            Assert.IsTrue(result.IsNodeSet);

            string withComments = Canonicalize(table, result.NodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments);
            string omitComments = Canonicalize(table, result.NodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);

            Assert.Contains("<!--doc-comment-before-->", withComments);
            Assert.Contains("<!--target-comment-->", withComments);
            Assert.Contains("<!--doc-comment-after-->", withComments);
            Assert.DoesNotContain("<!--", omitComments, "The comment-omitting algorithm must still omit comments from an unmarked whole-document set.");
            Assert.AreNotEqual(withComments, omitComments);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.3 step 4 for the <c>#xpointer(id('ID'))</c>
    /// scheme-based form: comments are RETAINED (step 4 does not fire for a scheme-based XPointer). Also
    /// proves "the argument accepts both quote kinds per the XPointer syntax" — the single- and
    /// double-quoted forms of the same identifier dereference to byte-identical results.
    /// </summary>
    [TestMethod]
    public void XPointerByIdDereferencesToElementSubtreeWithCommentsRetainedBothQuoteKinds()
    {
        (XmlNodeTable singleQuoteTable, XmlSignature singleQuoteSignature) = ReadFirstSignature(BuildDocument("#xpointer(id('target'))"), BaseMemoryPool.Shared);
        (XmlNodeTable doubleQuoteTable, XmlSignature doubleQuoteSignature) = ReadFirstSignature(BuildDocument("#xpointer(id(&quot;target&quot;))"), BaseMemoryPool.Shared);
        using(singleQuoteTable)
        using(singleQuoteSignature)
        using(doubleQuoteTable)
        using(doubleQuoteSignature)
        {
            bool isSingleQuoteDereferenced = XmlReferenceDereferencer.TryDereference(
                singleQuoteTable, singleQuoteSignature.SignedInfo.References[0], resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult singleQuoteResult, out XmlSignatureProcessingError singleQuoteError);
            bool isDoubleQuoteDereferenced = XmlReferenceDereferencer.TryDereference(
                doubleQuoteTable, doubleQuoteSignature.SignedInfo.References[0], resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult doubleQuoteResult, out XmlSignatureProcessingError doubleQuoteError);

            Assert.IsTrue(isSingleQuoteDereferenced, $"Must dereference but was refused with {singleQuoteError.Failure}.");
            Assert.IsTrue(isDoubleQuoteDereferenced, $"Must dereference but was refused with {doubleQuoteError.Failure}.");

            string singleQuoteWithComments = Canonicalize(singleQuoteTable, singleQuoteResult.NodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments);
            string doubleQuoteWithComments = Canonicalize(doubleQuoteTable, doubleQuoteResult.NodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10WithComments);
            string singleQuoteOmitComments = Canonicalize(singleQuoteTable, singleQuoteResult.NodeSet, XmlCanonicalizationAlgorithm.CanonicalXml10);

            Assert.Contains("<!--target-comment-->", singleQuoteWithComments);
            Assert.DoesNotContain("<!--doc-comment-before-->", singleQuoteWithComments, "The by-id subtree must not carry document-level comments outside it.");
            Assert.DoesNotContain("<!--", singleQuoteOmitComments);
            Assert.AreEqual(singleQuoteWithComments, doubleQuoteWithComments, "Both XPointer quote kinds must dereference to the same element.");
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's <c>'#xpointer(id('ID'))'</c> MUST-interpretation
    /// together with the <c>#xpointer(id('...'))</c> literal itself validates as <c>NCName</c>, the same
    /// production the bare-name path enforces — an EMPTY literal (<c>#xpointer(id(''))</c>) refuses <see
    /// cref="XmlSignatureProcessingFailure.UnsupportedXPointer"/> rather than reaching <see
    /// cref="XmlNodeTable.TryFindElementById"/> with an empty identifier no legitimate
    /// <c>Id</c>/<c>xml:id</c> attribute can ever carry (an empty value would otherwise happily match any
    /// element carrying <c>Id=""</c>).
    /// </summary>
    [TestMethod]
    public void XPointerByIdWithEmptyLiteralRefusesAsUnsupportedXPointer()
    {
        AssertUnsupportedXPointer("#xpointer(id(''))");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's <c>'#xpointer(id('ID'))'</c> MUST-interpretation
    /// together with for a NON-EMPTY but non-<c>NCName</c> literal (a leading digit, which production
    /// <c>NCName</c> forbids as a start character): the same refusal as the empty case, so the two by-id
    /// dereferencing paths (bare-name and scheme-based) accept exactly the same identifier language rather
    /// than the scheme-based one being more permissive.
    /// </summary>
    [TestMethod]
    public void XPointerByIdWithNonNcNameLiteralRefusesAsUnsupportedXPointer()
    {
        AssertUnsupportedXPointer("#xpointer(id('1bad'))");
    }


    /// <summary>
    /// Pins the RECORDED DEVIATION of a percent-encoded bare-name fragment (<c>#%C3%A4</c>) is matched
    /// LITERALLY against <c>Id</c> values, never percent-decoded, even though section 4.3.3.1 of <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> requires the attribute-to-URI mapping to follow section 3.2.17 of [XMLSCHEMA
    /// Datatypes] — under that mapping this fragment would name the element whose <c>Id</c> is <c>ä</c>.
    /// This leaf's exact-character discipline refuses it instead (<c>%</c> is not an <c>NCName</c>
    /// character), never silently decoding attacker-controlled bytes a second time.
    /// </summary>
    [TestMethod]
    public void PercentEncodedBareNameFragmentDoesNotDecodeAndRefusesAsUnsupportedXPointer()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildDocument("#%C3%A4"), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, signature.SignedInfo.References[0], resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsFalse(isDereferenced, "A percent-encoded fragment must not be decoded and matched against an 'ä' Id value.");
            Assert.IsFalse(result.IsNodeSet);
            Assert.AreEqual(XmlSignatureProcessingFailure.UnsupportedXPointer, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.1's "If the <c>URI</c> attribute is omitted
    /// altogether, the receiving application is expected to know the identity of the object" clause, refused
    /// per the "a <c>Reference</c> with no <c>URI</c> attribute is <c>UriOmitted</c>": a <c>Reference</c>
    /// with no <c>URI</c> attribute at all refuses rather than dereferencing, as <see
    /// cref="XmlSignatureProcessingFailure.UriOmitted"/>.
    /// </summary>
    [TestMethod]
    public void MissingUriAttributeRefusesAsUriOmitted()
    {
        string document = """
            <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
              <SignedInfo>
                <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                <Reference>
                  <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                  <DigestValue>AQ==</DigestValue>
                </Reference>
              </SignedInfo>
              <SignatureValue>AQ==</SignatureValue>
            </Signature>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            XmlReference reference = signature.SignedInfo.References[0];
            Assert.IsFalse(reference.HasUri);

            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, reference, resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsFalse(isDereferenced);
            Assert.IsFalse(result.IsNodeSet);
            Assert.AreEqual(XmlSignatureProcessingFailure.UriOmitted, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's shortname-XPointer support MUST, and the Id
    /// lookup-miss disposition, end to end through a real <c>ds:Reference</c>: a bare-name reference to a
    /// value no recognized <c>Id</c>-typed attribute carries propagates <see
    /// cref="XmlNodeTable.TryFindElementById"/>'s <see cref="XmlSignatureProcessingFailure.IdNotFound"/>
    /// through the dereferencing layer unchanged.
    /// </summary>
    [TestMethod]
    public void BareNameUriToMissingTargetRefusesAsIdNotFound()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildDocument("#missing"), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, signature.SignedInfo.References[0], resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsFalse(isDereferenced);
            Assert.IsFalse(result.IsNodeSet);
            Assert.AreEqual(XmlSignatureProcessingFailure.IdNotFound, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's shortname-XPointer support MUST, and the
    /// ambiguous-target posture ("Duplicate recognized-Id values anywhere in the document →
    /// <c>DuplicateId</c> refusal at lookup time"): a bare-name reference to a document-wide duplicate value
    /// fails closed as <see cref="XmlSignatureProcessingFailure.DuplicateId"/> rather than resolving to the
    /// first match, exercised end to end through a real <c>ds:Reference</c> rather than <see
    /// cref="XmlNodeTable.TryFindElementById"/> called directly.
    /// </summary>
    [TestMethod]
    public void BareNameUriToDuplicateTargetRefusesAsDuplicateId()
    {
        string document = """
            <Document>
              <Target Id="dup"/>
              <Target Id="dup"/>
              <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                  <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  <Reference URI="#dup">
                    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, signature.SignedInfo.References[0], resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsFalse(isDereferenced, "A document-wide duplicate value must refuse rather than resolve to the first match.");
            Assert.IsFalse(result.IsNodeSet);
            Assert.AreEqual(XmlSignatureProcessingFailure.DuplicateId, error.Failure);
        }
    }


    /// <summary>
    /// Pins, against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax
    /// and Processing (Second Edition)</see> section 4.3.3.2's shortname-XPointer support MUST, the
    /// deliberate divergence from the platform: .NET's <c>System.Security.Cryptography.Xml.SignedXml</c>
    /// matches an un-prefixed <c>Id</c>-shaped attribute case-insensitively (it recognizes
    /// <c>ID</c>/<c>id</c> as well as <c>Id</c>), a known signature-wrapping surface. This library adjudicates
    /// exact-character recognition instead: a target element carrying <c>ID="target"</c> (uppercase) rather
    /// than the recognized <c>Id="target"</c> is invisible to this leaf's dereferencing, which refuses as
    /// <see cref="XmlSignatureProcessingFailure.IdNotFound"/> rather than silently matching it the way the
    /// platform would.
    /// </summary>
    [TestMethod]
    public void BareNameUriToUppercaseIdCaseVariantRefusesAsIdNotFoundUnlikePlatform()
    {
        string document = """
            <Document>
              <Target ID="target"/>
              <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
                <SignedInfo>
                  <CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11"/>
                  <SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
                  <Reference URI="#target">
                    <DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                    <DigestValue>AQ==</DigestValue>
                  </Reference>
                </SignedInfo>
                <SignatureValue>AQ==</SignatureValue>
              </Signature>
            </Document>
            """;
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(document, BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, signature.SignedInfo.References[0], resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsFalse(isDereferenced, "The uppercase 'ID' case variant must not be recognized, unlike the platform.");
            Assert.IsFalse(result.IsNodeSet);
            Assert.AreEqual(XmlSignatureProcessingFailure.IdNotFound, error.Failure);
        }
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's recognized-fragment set (the null URI, shortname
    /// XPointer, and the two <c>xpointer</c> scheme-based forms) as narrowed by ("any other fragment is a
    /// refusal <c>UnsupportedXPointer</c>"): a fragment shaped like a namespace-prefixed name
    /// (<c>#foo:bar</c>) is not a valid bare-name XPointer, since <c>NCName</c> forbids the colon, and not
    /// one of the two recognized scheme-based forms either, so it refuses as <see
    /// cref="XmlSignatureProcessingFailure.UnsupportedXPointer"/>.
    /// </summary>
    [TestMethod]
    public void NamespacePrefixedFragmentRefusesAsUnsupportedXPointer()
    {
        AssertUnsupportedXPointer("#foo:bar");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2, which names only the null URI, shortname XPointer,
    /// and the two <c>xpointer</c> scheme-based forms as recognized, for the <c>element</c> scheme
    /// (<c>#element(chapter1)</c>): every other XPointer scheme, including <c>element</c>, is outside the
    /// recognized set fixes, so it refuses as <see
    /// cref="XmlSignatureProcessingFailure.UnsupportedXPointer"/>.
    /// </summary>
    [TestMethod]
    public void ElementSchemeFragmentRefusesAsUnsupportedXPointer()
    {
        AssertUnsupportedXPointer("#element(chapter1)");
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's recognized-fragment set (the null URI, shortname
    /// XPointer, and the two <c>xpointer</c> scheme-based forms), and the "whitespace variance beyond the
    /// spec's own grammar is a refusal, not a tolerance" applies equally to trailing pointer parts, for an
    /// XPointer with multiple pointer parts (<c>#xpointer(id('target'))xpointer(id('other'))</c>): the
    /// fragment does not match either recognized scheme-based form exactly, since trailing content follows the
    /// first part's closing parentheses, so it refuses as <see
    /// cref="XmlSignatureProcessingFailure.UnsupportedXPointer"/>.
    /// </summary>
    [TestMethod]
    public void MultiplePointerPartsFragmentRefusesAsUnsupportedXPointer()
    {
        AssertUnsupportedXPointer("#xpointer(id('target'))xpointer(id('other'))");
    }


    private static void AssertUnsupportedXPointer(string referenceUri)
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildDocument(referenceUri), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, signature.SignedInfo.References[0], resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsFalse(isDereferenced, $"'{referenceUri}' must refuse as UnsupportedXPointer.");
            Assert.IsFalse(result.IsNodeSet);
            Assert.AreEqual(XmlSignatureProcessingFailure.UnsupportedXPointer, error.Failure);
        }
    }


    /// <summary>
    /// Proves the resolver seam happy path, satisfying <see
    /// href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and Processing
    /// (Second Edition)</see> section 4.3.3.2's line-753 MUST ("the result of dereferencing the URI-Reference
    /// MUST be an octet stream") for a non-same-document <c>URI</c>: it dereferences through the
    /// caller-supplied <see cref="XmlReferenceResolver"/>, and the resolver's octets flow through unchanged
    /// as <see cref="XmlDereferenceResult.ExternalOctets"/>.
    /// </summary>
    [TestMethod]
    public void ExternalUriWithRespondingResolverDereferencesToItsOctets()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildDocument("http://example.com/bar.xml"), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, signature.SignedInfo.References[0], ResolveToFixedOctets, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsTrue(isDereferenced, $"Must dereference but was refused with {error.Failure}.");
            Assert.IsFalse(result.IsNodeSet);
            using(result.ExternalOctets)
            {
                Assert.AreSequenceEqual("resolved-octets"u8.ToArray(), result.ExternalOctets!.AsReadOnlySpan().ToArray());
            }
        }
    }


    /// <summary>
    /// Proves, against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax
    /// and Processing (Second Edition)</see> section 4.3.3.2's "the result of dereferencing the URI-Reference
    /// MUST be an octet stream" for a non-same-document reference, the "absent resolver ... →
    /// <c>ExternalReferenceUnresolved</c>": an external reference with no resolver supplied at all refuses as
    /// <see cref="XmlSignatureProcessingFailure.ExternalReferenceUnresolved"/>.
    /// </summary>
    [TestMethod]
    public void ExternalUriWithNoResolverRefusesAsExternalReferenceUnresolved()
    {
        AssertExternalReferenceUnresolved("http://example.com/bar.xml", resolver: null);
    }


    /// <summary>
    /// Proves, against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax
    /// and Processing (Second Edition)</see> section 4.3.3.2's octet-stream MUST for a non-same-document
    /// reference, the "or resolver failure on an external reference → <c>ExternalReferenceUnresolved</c>": an
    /// external reference whose resolver reports failure refuses identically to a missing resolver; the leaf
    /// never inspects or forwards the resolver's own reason for refusing.
    /// </summary>
    [TestMethod]
    public void ExternalUriWithFailingResolverRefusesAsExternalReferenceUnresolved()
    {
        AssertExternalReferenceUnresolved("http://example.com/bar.xml", FailingResolver);
    }


    /// <summary>
    /// Proves, against <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax
    /// and Processing (Second Edition)</see> section 4.3.3.2's octet-stream MUST for a non-same-document
    /// reference, the Result-shaped resolver seam holds even against a misbehaving delegate: the defensive
    /// guard against a resolver that returns <see langword="true"/> while leaving its octets <see
    /// langword="null"/> — a contract-violating implementation is still treated as unresolved rather than
    /// allowed to propagate a null result onward.
    /// </summary>
    [TestMethod]
    public void ExternalUriWithMisbehavingResolverRefusesAsExternalReferenceUnresolved()
    {
        AssertExternalReferenceUnresolved("http://example.com/bar.xml", MisbehavingResolver);
    }


    /// <summary>
    /// Proves <see href="https://www.w3.org/TR/2008/REC-xmldsig-core-20080610/">XML Signature Syntax and
    /// Processing (Second Edition)</see> section 4.3.3.2's same-document definition ("a hash sign followed by
    /// a fragment OR alternatively an empty URI"): a fragment PRECEDED by URI content
    /// (<c>somefile.xml#chapter1</c>) is NOT a same-document reference — the hash sign here does not begin
    /// the value, so the whole value dereferences externally through the resolver rather than through this
    /// leaf's same-document handling, matching section 4.3.3.1's own example of this exact shape.
    /// </summary>
    [TestMethod]
    public void FragmentPrecededByUriDereferencesExternallyNotAsSameDocument()
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildDocument("somefile.xml#chapter1"), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, signature.SignedInfo.References[0], ResolveToFixedOctets, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsTrue(isDereferenced, $"Must dereference externally but was refused with {error.Failure}.");
            Assert.IsFalse(result.IsNodeSet, "A fragment preceded by URI content must not resolve as a same-document node-set.");
            result.ExternalOctets!.Dispose();
        }
    }


    private static void AssertExternalReferenceUnresolved(string referenceUri, XmlReferenceResolver? resolver)
    {
        (XmlNodeTable table, XmlSignature signature) = ReadFirstSignature(BuildDocument(referenceUri), BaseMemoryPool.Shared);
        using(table)
        using(signature)
        {
            bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, signature.SignedInfo.References[0], resolver, BaseMemoryPool.Shared, out XmlDereferenceResult result, out XmlSignatureProcessingError error);

            Assert.IsFalse(isDereferenced);
            Assert.IsFalse(result.IsNodeSet);
            Assert.IsNull(result.ExternalOctets);
            Assert.AreEqual(XmlSignatureProcessingFailure.ExternalReferenceUnresolved, error.Failure);
        }
    }


    private static bool ResolveToFixedOctets(ReadOnlySpan<byte> uri, BaseMemoryPool pool, out PooledMemory? octets)
    {
        octets = PooledMemory.FromBytes("resolved-octets"u8, pool, BufferTags.XmlDigestInput);

        return true;
    }


    private static bool FailingResolver(ReadOnlySpan<byte> uri, BaseMemoryPool pool, out PooledMemory? octets)
    {
        octets = null;

        return false;
    }


    private static bool MisbehavingResolver(ReadOnlySpan<byte> uri, BaseMemoryPool pool, out PooledMemory? octets)
    {
        octets = null;

        return true;
    }
}
