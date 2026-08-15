using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESIncludeUriProcessing.TryRetrieve"/> against the processing model of clause
/// 5.1.4.4.2.2 of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: same-document bare-name XPointer dereference only. Per, this is EXACTLY
/// the shipped <see cref="XmlReferenceDereferencer"/> bare-name machinery — no XPath evaluator runs anywhere
/// in this leaf, and the deferral stands untouched.
/// </summary>
[TestClass]
internal sealed class XAdESIncludeUriProcessingTests
{
    private static XmlNodeTable Parse(string document, BaseMemoryPool pool)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), pool, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves equivalence with the <see cref="XmlReferenceDereferencer"/>'s own bare-name node-set: for the identical fragment over the identical table, <see cref="XAdESIncludeUriProcessing.TryRetrieve"/> produces the same
    /// <see cref="XmlNodeSet"/> value the shipped XMLDSIG same-document dereference already produces for a <c>ds:Reference URI="#id"</c> — proving this new XAdES-level helper is not a second, independently-drifting
    /// implementation of "E plus descendants plus namespace/attribute nodes, comments deleted" (<see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1
    /// V1.3.1</see> clause 5.1.4.4.2.2's XA-5.1.4.4.2.2-2).
    /// </summary>
    [TestMethod]
    public void RetrievalEqualsTheStageTwoDereferencerForTheSameFragment()
    {
        string document = $"""
            <root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
              <Data Id="target"><!--a comment--><child>text</child></Data>
            </root>
            """;

        using XmlNodeTable table = Parse(document, BaseMemoryPool.Shared);
        bool isRetrieved = XAdESIncludeUriProcessing.TryRetrieve(table, "#target"u8, out int targetElementIndex, out XmlNodeSet retrievedNodeSet, out XAdESProcessingError retrieveError);
        Assert.IsTrue(isRetrieved, $"Must retrieve but was refused with {retrieveError.Failure}.");

        bool isDereferenced = XmlReferenceDereferencer.TryDereference(table, hasUri: true, "#target"u8, resolver: null, BaseMemoryPool.Shared, out XmlDereferenceResult dereferenced, out XmlSignatureProcessingError dereferenceError);
        Assert.IsTrue(isDereferenced, $"The dereferencer must dereference but was refused with {dereferenceError.Failure}.");
        Assert.IsTrue(dereferenced.IsNodeSet, "A bare-name fragment must dereference to a node-set.");

        Assert.AreEqual(dereferenced.NodeSet, retrievedNodeSet, "The XAdES Include URI-processing model must produce the identical node-set the shipped dereferencer produces for the same fragment.");
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1's XA-5.1.4.4.2.1-4: a non-empty non-fragment part identifies a non-same-document target, out of
    /// this leaf's retrieval scope (no network or filesystem access occurs in this library).
    /// </summary>
    [TestMethod]
    public void NonSameDocumentUriIsRefused()
    {
        using XmlNodeTable table = Parse("""<root/>""", BaseMemoryPool.Shared);
        bool isRetrieved = XAdESIncludeUriProcessing.TryRetrieve(table, "other-document.xml#target"u8, out _, out _, out XAdESProcessingError error);
        Assert.IsFalse(isRetrieved, "A non-same-document URI must be refused.");
        Assert.AreEqual(XAdESProcessingFailure.NonSameDocumentIncludeUnresolved, error.Failure);
    }


    /// <summary>
    /// Proves an empty <c>URI</c> is refused — <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1's XA-5.1.4.4.2.1-4 always requires a bare-name fragment for the
    /// same-document case, unlike XMLDSIG's own general "empty URI selects the whole document" convention.
    /// </summary>
    [TestMethod]
    public void EmptyUriIsRefused()
    {
        using XmlNodeTable table = Parse("""<root/>""", BaseMemoryPool.Shared);
        bool isRetrieved = XAdESIncludeUriProcessing.TryRetrieve(table, ""u8, out _, out _, out XAdESProcessingError error);
        Assert.IsFalse(isRetrieved, "An empty URI must be refused.");
        Assert.AreEqual(XAdESProcessingFailure.UnsupportedIncludeUriForm, error.Failure);
    }


    /// <summary>
    /// Proves a scheme-based <c>#xpointer(/)</c> fragment is refused — <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.1's XA-5.1.4.4.2.1-4 permits ONLY the
    /// bare-name form for <c>Include</c>, unlike XMLDSIG's general same-document reference, which recognizes
    /// this form too.
    /// </summary>
    [TestMethod]
    public void SchemeBasedXPointerFragmentIsRefused()
    {
        using XmlNodeTable table = Parse("""<root/>""", BaseMemoryPool.Shared);
        bool isRetrieved = XAdESIncludeUriProcessing.TryRetrieve(table, "#xpointer(/)"u8, out _, out _, out XAdESProcessingError error);
        Assert.IsFalse(isRetrieved, "A scheme-based XPointer fragment must be refused for Include.");
        Assert.AreEqual(XAdESProcessingFailure.UnsupportedIncludeUriForm, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.2, a fragment starting with a digit — not a well-formed <c>NCName</c> — is refused.
    /// </summary>
    [TestMethod]
    public void NonNcNameFragmentIsRefused()
    {
        using XmlNodeTable table = Parse("""<root/>""", BaseMemoryPool.Shared);
        bool isRetrieved = XAdESIncludeUriProcessing.TryRetrieve(table, "#1abc"u8, out _, out _, out XAdESProcessingError error);
        Assert.IsFalse(isRetrieved, "A non-NCName fragment must be refused.");
        Assert.AreEqual(XAdESProcessingFailure.UnsupportedIncludeUriForm, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.2, a bare-name fragment naming no recognized <c>Id</c>-typed attribute value is refused, bridged
    /// from <see cref="XmlSignatureProcessingFailure.IdNotFound"/>.
    /// </summary>
    [TestMethod]
    public void MissingTargetIdIsRefused()
    {
        using XmlNodeTable table = Parse("""<root><Data Id="present"/></root>""", BaseMemoryPool.Shared);
        bool isRetrieved = XAdESIncludeUriProcessing.TryRetrieve(table, "#absent"u8, out _, out _, out XAdESProcessingError error);
        Assert.IsFalse(isRetrieved, "A fragment naming no Id must be refused.");
        Assert.AreEqual(XAdESProcessingFailure.IncludeTargetIdNotFound, error.Failure);
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.4.4.2.2, a bare-name fragment naming more than one <c>Id</c>-typed attribute value is refused, bridged
    /// from <see cref="XmlSignatureProcessingFailure.DuplicateId"/> — ambiguous targets are how
    /// signature-wrapping attacks work.
    /// </summary>
    [TestMethod]
    public void DuplicateTargetIdIsRefused()
    {
        using XmlNodeTable table = Parse("""<root><Data Id="dup"/><Other Id="dup"/></root>""", BaseMemoryPool.Shared);
        bool isRetrieved = XAdESIncludeUriProcessing.TryRetrieve(table, "#dup"u8, out _, out _, out XAdESProcessingError error);
        Assert.IsFalse(isRetrieved, "A duplicate Id target must be refused.");
        Assert.AreEqual(XAdESProcessingFailure.DuplicateIncludeTargetId, error.Failure);
    }
}
