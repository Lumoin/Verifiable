using System.Text;
using Verifiable.Xml;

namespace Verifiable.Tests.Xml;

/// <summary>
/// Proofs of <see cref="XAdESUnmodeledContent.Read"/> against clause 5.1.1's <c>AnyType</c> data type of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">
/// ETSI EN 319 132-1 V1.3.1</see>: a content model allowing an unrestricted-length sequence of arbitrary
/// elements mixed with text (XA-5.1.1-1), text content only (XA-5.1.1-2), and an unrestricted number of
/// arbitrary attributes (XA-5.1.1-3) — proven here through the <c>Any</c> element clause 5.1.1 itself
/// declares.
/// </summary>
[TestClass]
internal sealed class XAdESUnmodeledContentTests
{
    private static XmlNodeTable Parse(string document)
    {
        bool isParsed = XmlNodeTable.TryParse(Encoding.UTF8.GetBytes(document), BaseMemoryPool.Shared, out XmlNodeTable? table, out XmlReadError readError);
        Assert.IsTrue(isParsed, $"The fixture document must parse but was refused with {readError.Failure} at offset {readError.ByteOffset}.");

        return table!;
    }


    /// <summary>
    /// Proves XA-5.1.1-1 (a sequence of arbitrary elements mixed with text of unrestricted length) and the <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1
    /// V1.3.1</see> clause's own NOTE that comments and processing instructions are never refused or dropped: every immediate child — text, an element, a comment, a processing instruction, another element, more text — is carried in <see
    /// cref="XAdESUnmodeledContent.ContentNodeIndices"/> in document order, unfiltered. This contrasts directly with <see cref="XmlSignatureModelGrammar.TryGetSimpleContentTextNodeIndex"/>'s comment-smuggling refusal: that refusal is
    /// specific to simple-content elements, never to <c>AnyType</c>, whose content model is <c>mixed="true"</c> by design.
    /// </summary>
    [TestMethod]
    public void MixedContentOfEveryNodeKindIsCarriedUnfilteredInDocumentOrder()
    {
        using XmlNodeTable table = Parse(
            """<Any xmlns="http://uri.etsi.org/01903/v1.3.2#" a="1" b="2">text-before<Child1/><!--a comment--><?pi some-data?><Child2>inner</Child2>text-after</Any>""");

        XAdESUnmodeledContent content = XAdESUnmodeledContent.Read(table, table.DocumentElementIndex);

        Assert.HasCount(6, content.ContentNodeIndices);
        Assert.AreEqual(XmlNodeKind.Text, table.KindOf(content.ContentNodeIndices[0]));
        Assert.AreEqual("text-before", Encoding.UTF8.GetString(table.ValueOf(content.ContentNodeIndices[0])));
        Assert.AreEqual(XmlNodeKind.Element, table.KindOf(content.ContentNodeIndices[1]));
        Assert.AreEqual("Child1", Encoding.UTF8.GetString(table.LocalNameOf(content.ContentNodeIndices[1])));
        Assert.AreEqual(XmlNodeKind.Comment, table.KindOf(content.ContentNodeIndices[2]));
        Assert.AreEqual("a comment", Encoding.UTF8.GetString(table.ValueOf(content.ContentNodeIndices[2])));
        Assert.AreEqual(XmlNodeKind.ProcessingInstruction, table.KindOf(content.ContentNodeIndices[3]));
        Assert.AreEqual(XmlNodeKind.Element, table.KindOf(content.ContentNodeIndices[4]));
        Assert.AreEqual("Child2", Encoding.UTF8.GetString(table.LocalNameOf(content.ContentNodeIndices[4])));
        Assert.AreEqual(XmlNodeKind.Text, table.KindOf(content.ContentNodeIndices[5]));
        Assert.AreEqual("text-after", Encoding.UTF8.GetString(table.ValueOf(content.ContentNodeIndices[5])));

        //XA-5.1.1-3: an unrestricted number of arbitrary attributes — Read performs no attribute-count
        //validation at all (contrast XmlSignatureModelGrammar.TryValidateAttributeCount, which every ds:
        //element reader calls), so the two attributes here are simply present, uncounted against any cap.
        Assert.AreEqual(2, table.AttributeCountOf(table.DocumentElementIndex));
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.1's XA-5.1.1-2: a content model allowing text content only.
    /// </summary>
    [TestMethod]
    public void TextOnlyContentReads()
    {
        using XmlNodeTable table = Parse("""<Any xmlns="http://uri.etsi.org/01903/v1.3.2#">just text, nothing else</Any>""");
        XAdESUnmodeledContent content = XAdESUnmodeledContent.Read(table, table.DocumentElementIndex);

        Assert.HasCount(1, content.ContentNodeIndices);
        Assert.AreEqual(XmlNodeKind.Text, table.KindOf(content.ContentNodeIndices[0]));
        Assert.AreEqual("just text, nothing else", Encoding.UTF8.GetString(table.ValueOf(content.ContentNodeIndices[0])));
    }


    /// <summary>
    /// Proves <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.1's XA-5.1.1-1's element-sequence arm without any interspersed text: a pure sequence of arbitrary
    /// elements reads, each one carried, none refused for being "unspecified."
    /// </summary>
    [TestMethod]
    public void ElementOnlySequenceReads()
    {
        using XmlNodeTable table = Parse("""<Any xmlns="http://uri.etsi.org/01903/v1.3.2#"><One/><Two/><Three/></Any>""");
        XAdESUnmodeledContent content = XAdESUnmodeledContent.Read(table, table.DocumentElementIndex);

        Assert.HasCount(3, content.ContentNodeIndices);
        Assert.IsTrue(content.ContentNodeIndices.All(index => table.KindOf(index) == XmlNodeKind.Element));
    }


    /// <summary>
    /// Proves, per <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.03.01_60/en_31913201v010301p.pdf">ETSI EN 319 132-1 V1.3.1</see> clause 5.1.1, an entirely empty <c>AnyType</c>-typed element reads with zero content — the content model
    /// permits zero occurrences (<c>minOccurs="0"</c> on the inner sequence) just as readily as many.
    /// </summary>
    [TestMethod]
    public void EmptyContentReads()
    {
        using XmlNodeTable table = Parse("""<Any xmlns="http://uri.etsi.org/01903/v1.3.2#"/>""");
        XAdESUnmodeledContent content = XAdESUnmodeledContent.Read(table, table.DocumentElementIndex);

        Assert.IsEmpty(content.ContentNodeIndices);
    }
}
