using System;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Globalization;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Linq;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// One <c>Sequence</c> of a hash tree as this oracle reads it.
/// </summary>
/// <param name="Order">The <c>Order</c> attribute.</param>
/// <param name="DigestValues">The decoded hash values, in document order.</param>
internal sealed record OracleXmlSequence(int Order, List<byte[]> DigestValues);


/// <summary>
/// One <c>ArchiveTimeStamp</c> as this oracle reads it.
/// </summary>
/// <param name="Order">The <c>Order</c> attribute.</param>
/// <param name="HashTree">The <c>Sequence</c> elements in ascending <c>Order</c>; empty when the element carries no hash tree.</param>
/// <param name="TimeStampToken">The DER time-stamp token the <c>TimeStampToken</c> element's base64 decodes to.</param>
/// <param name="MessageImprintAlgorithmOid">The <c>messageImprint.hashAlgorithm</c> object identifier of that token.</param>
/// <param name="MessageImprint">The <c>messageImprint.hashedMessage</c> of that token — the time-stamped value.</param>
internal sealed record OracleXmlArchiveTimeStamp(
    int Order,
    List<OracleXmlSequence> HashTree,
    byte[] TimeStampToken,
    string MessageImprintAlgorithmOid,
    byte[] MessageImprint);


/// <summary>
/// One <c>ArchiveTimeStampChain</c> as this oracle reads it.
/// </summary>
/// <param name="Order">The <c>Order</c> attribute.</param>
/// <param name="DigestMethodUri">The <c>DigestMethod</c> element's <c>Algorithm</c> attribute.</param>
/// <param name="CanonicalizationMethodUri">The <c>CanonicalizationMethod</c> element's <c>Algorithm</c> attribute.</param>
/// <param name="ArchiveTimeStamps">The <c>ArchiveTimeStamp</c> elements in ascending <c>Order</c>.</param>
internal sealed record OracleXmlChain(
    int Order,
    string DigestMethodUri,
    string CanonicalizationMethodUri,
    List<OracleXmlArchiveTimeStamp> ArchiveTimeStamps);


/// <summary>
/// One <c>EvidenceRecord</c> document as this oracle reads it.
/// </summary>
/// <param name="Version">The <c>Version</c> attribute.</param>
/// <param name="Chains">The <c>ArchiveTimeStampChain</c> elements in ascending <c>Order</c>.</param>
internal sealed record OracleXmlEvidenceRecord(string Version, List<OracleXmlChain> Chains);


/// <summary>
/// An independent reader of, and recomputation over, Evidence Records in the XML syntax of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>, written for these tests from the
/// specification text alone.
/// </summary>
/// <remarks>
/// <para>
/// Nothing here calls the surface it checks: the document is walked by this file's own element enumeration
/// rather than through <c>XmlEvidenceRecordXmlBinding</c>, the root rule is written out here rather than taken
/// from <c>XmlEvidenceRecordHashTrees</c>, the time-stamped value is decoded by an <see cref="AsnReader"/> in
/// this file, and every hash value goes through the independent digest implementation
/// <see cref="EvidenceRecordOracle.Hash"/> uses. The ordering primitive
/// <see cref="EvidenceRecordOracle.Compare"/> is shared with the ASN.1 oracle deliberately: "binary ascending
/// order" is the one rule the two specifications state identically, and two copies of an ordering rule are two
/// rules that can disagree.
/// </para>
/// <para>
/// The clause text this reimplements, so a reader can check it against the specification rather than against the
/// production code. Clause 3.1.1: "the content of each <c>DigestValue</c> element within the first
/// <c>Sequence</c> element is base64 decoded to obtain a binary value ... All collected hash values from the
/// sequence are ordered in binary ascending order, concatenated and a new hash value is generated from that
/// string. With one exception to this rule: when the first <c>Sequence</c> element has only one
/// <c>DigestValue</c> element, then its binary value is added to the next list obtained from the next
/// <c>Sequence</c> element"; "The newly calculated hash value is added to the next list of hashes obtained from
/// the next <c>Sequence</c> element and the previous step is repeated until there is only one hash value left
/// ... The last calculated hash value is the root hash value." Clause 4.1.2: the binary representation "is
/// determined by UTF-8 encoding and canonicalization of the XML element", where the element "includes the entire
/// text of the start and end tags as well as all descendant markup and character data".
/// </para>
/// </remarks>
internal static class XmlEvidenceRecordOracle
{
    /// <summary>The namespace clause 8's schema declares as its target.</summary>
    internal static XNamespace Namespace { get; } = "urn:ietf:params:xml:ns:ers";

    /// <summary>The <c>xmlns</c> namespace a namespace declaration attribute itself lives in.</summary>
    private static string XmlnsNamespace { get; } = "http://www.w3.org/2000/xmlns/";

    /// <summary>The <c>xml</c> namespace the <c>xml:lang</c>, <c>xml:space</c> and <c>xml:base</c> attributes live in.</summary>
    private static string XmlAttributeNamespace { get; } = "http://www.w3.org/XML/1998/namespace";


    /// <summary>
    /// Reads an Evidence Record document with this file's own walk.
    /// </summary>
    /// <param name="document">The document's octets.</param>
    /// <returns>What the document states.</returns>
    internal static OracleXmlEvidenceRecord Parse(byte[] document)
    {
        ArgumentNullException.ThrowIfNull(document);

        XDocument xml = Load(document);
        XElement root = xml.Root!;
        var chains = new List<OracleXmlChain>();
        foreach(XElement chainElement in root.Element(Namespace + "ArchiveTimeStampSequence")!.Elements(Namespace + "ArchiveTimeStampChain"))
        {
            var archiveTimeStamps = new List<OracleXmlArchiveTimeStamp>();
            foreach(XElement archiveTimeStamp in chainElement.Elements(Namespace + "ArchiveTimeStamp"))
            {
                var sequences = new List<OracleXmlSequence>();
                XElement? hashTree = archiveTimeStamp.Element(Namespace + "HashTree");
                if(hashTree is not null)
                {
                    foreach(XElement sequence in hashTree.Elements(Namespace + "Sequence"))
                    {
                        var values = new List<byte[]>();
                        foreach(XElement digestValue in sequence.Elements(Namespace + "DigestValue"))
                        {
                            values.Add(Convert.FromBase64String(digestValue.Value.Trim()));
                        }

                        sequences.Add(new OracleXmlSequence(ReadOrder(sequence), values));
                    }

                    sequences.Sort(static (left, right) => left.Order.CompareTo(right.Order));
                }

                XElement timeStampToken = archiveTimeStamp.Element(Namespace + "TimeStamp")!.Element(Namespace + "TimeStampToken")!;
                byte[] token = Convert.FromBase64String(timeStampToken.Value.Trim());
                (string imprintAlgorithmOid, byte[] imprint) = ReadMessageImprint(token);
                archiveTimeStamps.Add(new OracleXmlArchiveTimeStamp(ReadOrder(archiveTimeStamp), sequences, token, imprintAlgorithmOid, imprint));
            }

            archiveTimeStamps.Sort(static (left, right) => left.Order.CompareTo(right.Order));
            chains.Add(new OracleXmlChain(
                ReadOrder(chainElement),
                chainElement.Element(Namespace + "DigestMethod")!.Attribute("Algorithm")!.Value,
                chainElement.Element(Namespace + "CanonicalizationMethod")!.Attribute("Algorithm")!.Value,
                archiveTimeStamps));
        }

        chains.Sort(static (left, right) => left.Order.CompareTo(right.Order));

        return new OracleXmlEvidenceRecord(root.Attribute("Version")!.Value, chains);
    }


    /// <summary>
    /// Recomputes the root hash value of a hash tree, per clause 3.1.1, including its first-<c>Sequence</c>-only
    /// exception.
    /// </summary>
    /// <param name="hashTree">The sequences in ascending <c>Order</c>.</param>
    /// <param name="algorithm">The algorithm the chain names.</param>
    /// <returns>The root hash value.</returns>
    internal static byte[] RootOf(IReadOnlyList<OracleXmlSequence> hashTree, PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(hashTree);

        byte[]? carried = null;
        for(int i = 0; i < hashTree.Count; ++i)
        {
            var level = new List<byte[]>(hashTree[i].DigestValues);
            if(carried is not null)
            {
                level.Add(carried);
            }

            //Clause 3.1.1's one exception, at the first list and nowhere else.
            carried = i == 0 && level.Count == 1 ? level[0] : Combine(level, algorithm);
        }

        return carried!;
    }


    /// <summary>
    /// Applies the level rule of clause 3.1.1: binary sort ascending, concatenate, hash.
    /// </summary>
    /// <param name="hashValues">The hash values of one level.</param>
    /// <param name="algorithm">The algorithm the chain names.</param>
    /// <returns>The level's hash value.</returns>
    internal static byte[] Combine(IReadOnlyList<byte[]> hashValues, PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(hashValues);

        var sorted = new List<byte[]>(hashValues);
        sorted.Sort(EvidenceRecordOracle.Compare);

        var concatenated = new List<byte>();
        for(int i = 0; i < sorted.Count; ++i)
        {
            concatenated.AddRange(sorted[i]);
        }

        return EvidenceRecordOracle.Hash(concatenated.ToArray(), algorithm);
    }


    /// <summary>
    /// Produces the canonical binary representation of the <c>TimeStamp</c> element of one Archive Time-Stamp.
    /// </summary>
    /// <param name="document">The Evidence Record document's octets.</param>
    /// <param name="chainOrder">The chain's <c>Order</c>.</param>
    /// <param name="archiveTimeStampOrder">The Archive Time-Stamp's <c>Order</c>.</param>
    /// <param name="canonicalizationUri">The algorithm identifier the chain names.</param>
    /// <returns>The canonical octets.</returns>
    internal static byte[] CanonicalizeTimeStamp(byte[] document, int chainOrder, int archiveTimeStampOrder, string canonicalizationUri)
    {
        ArgumentNullException.ThrowIfNull(document);

        XmlDocument mutable = LoadMutable(document);
        XmlElement element = SelectTimeStamp(mutable, chainOrder, archiveTimeStampOrder);

        return Canonicalize(element, canonicalizationUri);
    }


    /// <summary>
    /// Produces the canonical binary representation of the <c>ArchiveTimeStampSequence</c> element holding the
    /// first <paramref name="chainCount"/> chains and no others.
    /// </summary>
    /// <param name="document">The Evidence Record document's octets.</param>
    /// <param name="chainCount">How many chains, counted from the lowest <c>Order</c>, the prefix holds.</param>
    /// <param name="canonicalizationUri">The algorithm identifier the SUCCEEDING chain names, per clause 4.1.2.</param>
    /// <returns>The canonical octets.</returns>
    internal static byte[] CanonicalizeSequencePrefix(byte[] document, int chainCount, string canonicalizationUri)
    {
        ArgumentNullException.ThrowIfNull(document);

        XmlDocument mutable = LoadMutable(document);
        XmlElement sequence = (XmlElement)mutable.DocumentElement!
            .GetElementsByTagName("ArchiveTimeStampSequence", Namespace.NamespaceName)[0]!;
        var chains = new List<XmlElement>();
        for(XmlNode? node = sequence.FirstChild; node is not null; node = node.NextSibling)
        {
            if(node is XmlElement element
                && string.Equals(element.LocalName, "ArchiveTimeStampChain", StringComparison.Ordinal)
                && string.Equals(element.NamespaceURI, Namespace.NamespaceName, StringComparison.Ordinal))
            {
                chains.Add(element);
            }
        }

        chains.Sort(static (left, right) => ReadOrder(left).CompareTo(ReadOrder(right)));
        for(int i = chainCount; i < chains.Count; ++i)
        {
            _ = sequence.RemoveChild(chains[i]);
        }

        return Canonicalize(sequence, canonicalizationUri);
    }


    /// <summary>
    /// Produces the canonical binary representation of a standalone XML document — clause 4.1.2's
    /// "canonicalization MUST be applied over XML structured archive data".
    /// </summary>
    /// <param name="archiveData">The XML archive data's octets.</param>
    /// <param name="canonicalizationUri">The algorithm identifier the chain names.</param>
    /// <returns>The canonical octets.</returns>
    internal static byte[] CanonicalizeArchiveData(byte[] archiveData, string canonicalizationUri)
    {
        ArgumentNullException.ThrowIfNull(archiveData);

        XmlDocument mutable = LoadMutable(archiveData);

        return Canonicalize(mutable.DocumentElement!, canonicalizationUri);
    }


    /// <summary>
    /// Canonicalizes one element by lifting it into a document of its own with every in-scope ancestor namespace
    /// declaration and <c>xml:*</c> attribute copied down, nearer declarations winning.
    /// </summary>
    /// <param name="element">The element.</param>
    /// <param name="canonicalizationUri">The algorithm identifier.</param>
    /// <returns>The canonical octets.</returns>
    private static byte[] Canonicalize(XmlElement element, string canonicalizationUri)
    {
        var lifted = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        lifted.LoadXml(element.OuterXml);
        XmlElement liftedRoot = lifted.DocumentElement!;
        XmlNode? ancestor = element.ParentNode;
        while(ancestor is XmlElement ancestorElement)
        {
            foreach(XmlAttribute attribute in ancestorElement.Attributes)
            {
                bool copyable = string.Equals(attribute.NamespaceURI, XmlnsNamespace, StringComparison.Ordinal)
                    || string.Equals(attribute.NamespaceURI, XmlAttributeNamespace, StringComparison.Ordinal);
                if(copyable && !liftedRoot.HasAttribute(attribute.LocalName, attribute.NamespaceURI))
                {
                    liftedRoot.SetAttribute(attribute.LocalName, attribute.NamespaceURI, attribute.Value);
                }
            }

            ancestor = ancestor.ParentNode;
        }

        bool withComments = canonicalizationUri.EndsWith("#WithComments", StringComparison.Ordinal);
        Transform transform = canonicalizationUri.StartsWith("http://www.w3.org/2001/10/xml-exc-c14n#", StringComparison.Ordinal)
            ? new XmlDsigExcC14NTransform(withComments)
            : new XmlDsigC14NTransform(withComments);
        transform.LoadInput(lifted);
        using var output = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        output.CopyTo(buffer);

        return buffer.ToArray();
    }


    /// <summary>
    /// Locates the <c>TimeStamp</c> element named by two <c>Order</c> attributes.
    /// </summary>
    /// <param name="document">The loaded document.</param>
    /// <param name="chainOrder">The chain's <c>Order</c>.</param>
    /// <param name="archiveTimeStampOrder">The Archive Time-Stamp's <c>Order</c>.</param>
    /// <returns>The element.</returns>
    private static XmlElement SelectTimeStamp(XmlDocument document, int chainOrder, int archiveTimeStampOrder)
    {
        XmlNodeList archiveTimeStamps = document.GetElementsByTagName("ArchiveTimeStamp", Namespace.NamespaceName);
        for(int i = 0; i < archiveTimeStamps.Count; ++i)
        {
            var candidate = (XmlElement)archiveTimeStamps[i]!;
            if(ReadOrder(candidate) != archiveTimeStampOrder || ReadOrder((XmlElement)candidate.ParentNode!) != chainOrder)
            {
                continue;
            }

            for(XmlNode? node = candidate.FirstChild; node is not null; node = node.NextSibling)
            {
                if(node is XmlElement child
                    && string.Equals(child.LocalName, "TimeStamp", StringComparison.Ordinal)
                    && string.Equals(child.NamespaceURI, Namespace.NamespaceName, StringComparison.Ordinal))
                {
                    return child;
                }
            }
        }

        throw new InvalidOperationException($"The document carries no TimeStamp element for chain {chainOrder}, archive time-stamp {archiveTimeStampOrder}.");
    }


    /// <summary>
    /// Reads the <c>messageImprint</c> of the <c>TSTInfo</c> a time-stamp token encapsulates, by position.
    /// </summary>
    /// <param name="token">The DER-encoded token.</param>
    /// <returns>The imprint's algorithm identifier and its hashed message.</returns>
    private static (string AlgorithmOid, byte[] Imprint) ReadMessageImprint(byte[] token)
    {
        var reader = new AsnReader(token, AsnEncodingRules.BER);
        AsnReader contentInfo = reader.ReadSequence();
        _ = contentInfo.ReadObjectIdentifier();
        AsnReader content = contentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        AsnReader signedData = content.ReadSequence();

        _ = signedData.ReadInteger();                           //version.
        _ = signedData.ReadSetOf(skipSortOrderValidation: true);//digestAlgorithms.
        AsnReader encapContentInfo = signedData.ReadSequence();
        _ = encapContentInfo.ReadObjectIdentifier();            //eContentType.
        AsnReader eContent = encapContentInfo.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
        byte[] tstInfoOctets = eContent.ReadOctetString();

        var tstInfoReader = new AsnReader(tstInfoOctets, AsnEncodingRules.BER);
        AsnReader tstInfo = tstInfoReader.ReadSequence();
        _ = tstInfo.ReadInteger();                              //version.
        _ = tstInfo.ReadObjectIdentifier();                     //policy.
        AsnReader messageImprint = tstInfo.ReadSequence();
        AsnReader hashAlgorithm = messageImprint.ReadSequence();
        string algorithmOid = hashAlgorithm.ReadObjectIdentifier();
        byte[] imprint = messageImprint.ReadOctetString();

        return (algorithmOid, imprint);
    }


    /// <summary>
    /// Loads octets as an <see cref="XDocument"/> that resolves nothing.
    /// </summary>
    /// <param name="octets">The document's octets.</param>
    /// <returns>The loaded document.</returns>
    private static XDocument Load(byte[] octets)
    {
        using var stream = new MemoryStream(octets, writable: false);
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, CloseInput = false };
        using XmlReader reader = XmlReader.Create(stream, settings);

        return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
    }


    /// <summary>
    /// Loads octets as an <see cref="XmlDocument"/> that resolves nothing.
    /// </summary>
    /// <param name="octets">The document's octets.</param>
    /// <returns>The loaded document.</returns>
    private static XmlDocument LoadMutable(byte[] octets)
    {
        using var stream = new MemoryStream(octets, writable: false);
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, CloseInput = false };
        using XmlReader reader = XmlReader.Create(stream, settings);
        var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        document.Load(reader);

        return document;
    }


    /// <summary>Reads an element's <c>Order</c> attribute in the tree model.</summary>
    /// <param name="element">The element.</param>
    /// <returns>The value, or zero when absent.</returns>
    private static int ReadOrder(XElement element) =>
        int.TryParse(element.Attribute("Order")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int order) ? order : 0;


    /// <summary>Reads an element's <c>Order</c> attribute in the mutable model.</summary>
    /// <param name="element">The element.</param>
    /// <returns>The value, or zero when absent.</returns>
    private static int ReadOrder(XmlElement element) =>
        int.TryParse(element.GetAttribute("Order"), NumberStyles.Integer, CultureInfo.InvariantCulture, out int order) ? order : 0;
}
