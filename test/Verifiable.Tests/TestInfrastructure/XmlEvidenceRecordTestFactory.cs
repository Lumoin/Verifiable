using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Xml.Linq;
using Verifiable.Cryptography.Pki;
using Verifiable.Tests.X509;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Mints Evidence Record documents in the XML syntax of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283">IETF RFC 6283</see>, which this library validates but does
/// not create.
/// </summary>
/// <remarks>
/// <para>
/// Every hash value this factory writes is computed by <see cref="XmlEvidenceRecordOracle"/> and every
/// time-stamp token by the independent minting authority of <see cref="X509ChainTestRingTimestamping"/>, so a
/// document it produces was built without the surface under test taking part in any step. A verification that
/// succeeds against one of these documents is therefore a statement about the specification's algorithm rather
/// than a round trip through one implementation of it.
/// </para>
/// <para>
/// The factory writes the hash tree it is given rather than deriving one, which is what makes the edge cases
/// reachable: a first <c>Sequence</c> holding exactly one value and a later one holding exactly one value are
/// different structures that a naive reading of clause 3.1.1 treats alike, and only a factory that writes what
/// it is told can produce both.
/// </para>
/// </remarks>
internal static class XmlEvidenceRecordTestFactory
{
    /// <summary>The namespace clause 8's schema declares as its target.</summary>
    internal static XNamespace Namespace { get; } = "urn:ietf:params:xml:ns:ers";

    /// <summary>The namespace prefix the factory declares unless a caller states another one.</summary>
    internal static string DefaultPrefix { get; } = "ers";


    /// <summary>
    /// Mints a document carrying one chain with one Archive Time-Stamp.
    /// </summary>
    /// <param name="hashTree">The <c>Sequence</c> elements to write, leaf list first; empty writes no <c>HashTree</c> element at all.</param>
    /// <param name="algorithm">The algorithm the chain's <c>DigestMethod</c> names.</param>
    /// <param name="canonicalizationUri">The identifier the chain's <c>CanonicalizationMethod</c> names.</param>
    /// <param name="authority">The Time-Stamping Authority node.</param>
    /// <param name="embeddedCertificates">The certificates the token carries.</param>
    /// <param name="generationTime">The <c>genTime</c> the authority states.</param>
    /// <param name="timestampedValueWhenNoHashTree">The value the token binds when <paramref name="hashTree"/> is empty.</param>
    /// <param name="prefix">The namespace prefix to declare.</param>
    /// <param name="comment">A comment to write inside the first <c>Sequence</c>, for the comment-preserving canonicalization cases; none when <see langword="null"/>.</param>
    /// <param name="tokenImprintAlgorithm">The algorithm the token's message imprint is stated under, when it is deliberately NOT the chain's — clause 4.1.1 forbids that, and a verifier has to say so.</param>
    /// <returns>The document's octets.</returns>
    internal static byte[] MintInitial(
        IReadOnlyList<IReadOnlyList<byte[]>> hashTree,
        PkiDigestAlgorithm algorithm,
        string canonicalizationUri,
        X509ChainTestRingNode authority,
        IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
        DateTimeOffset generationTime,
        byte[]? timestampedValueWhenNoHashTree = null,
        string? prefix = null,
        string? comment = null,
        PkiDigestAlgorithm? tokenImprintAlgorithm = null)
    {
        ArgumentNullException.ThrowIfNull(hashTree);
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(embeddedCertificates);

        byte[] timestampedValue = hashTree.Count == 0
            ? timestampedValueWhenNoHashTree ?? throw new ArgumentException("A document with no hash tree needs the value its token binds.", nameof(timestampedValueWhenNoHashTree))
            : RootOf(hashTree, algorithm);

        PkiDigestAlgorithm imprintAlgorithm = tokenImprintAlgorithm ?? algorithm;
        if(imprintAlgorithm != algorithm)
        {
            timestampedValue = EvidenceRecordOracle.Hash(timestampedValue, imprintAlgorithm);
        }

        XElement archiveTimeStamp = BuildArchiveTimeStamp(1, hashTree, timestampedValue, imprintAlgorithm, authority, embeddedCertificates, generationTime, comment);
        XElement chain = BuildChain(1, algorithm, canonicalizationUri, [archiveTimeStamp]);
        var root = new XElement(
            Namespace + "EvidenceRecord",
            new XAttribute(XNamespace.Xmlns + (prefix ?? DefaultPrefix), Namespace.NamespaceName),
            new XAttribute("Version", "1.0"),
            new XElement(Namespace + "ArchiveTimeStampSequence", chain));

        return Serialize(new XDocument(root));
    }


    /// <summary>
    /// Appends a Time-Stamp Renewal (clause 4.2.1) to the last chain of a document: a new Archive Time-Stamp
    /// whose first <c>Sequence</c> holds the digest of the previous <c>TimeStamp</c> element's canonical binary
    /// representation.
    /// </summary>
    /// <param name="document">The document to renew.</param>
    /// <param name="authority">The Time-Stamping Authority node.</param>
    /// <param name="embeddedCertificates">The certificates the token carries.</param>
    /// <param name="generationTime">The <c>genTime</c> the authority states.</param>
    /// <param name="siblingLevels">Further <c>Sequence</c> elements beyond the first, for a renewal batched with other records; none when <see langword="null"/>.</param>
    /// <param name="includeHashTree">Whether to write a <c>HashTree</c> element at all, which clause 4.2.1 states the renewal MAY omit.</param>
    /// <returns>The renewed document's octets.</returns>
    internal static byte[] AppendTimestampRenewal(
        byte[] document,
        X509ChainTestRingNode authority,
        IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
        DateTimeOffset generationTime,
        IReadOnlyList<IReadOnlyList<byte[]>>? siblingLevels = null,
        bool includeHashTree = true)
    {
        ArgumentNullException.ThrowIfNull(document);

        OracleXmlEvidenceRecord parsed = XmlEvidenceRecordOracle.Parse(document);
        OracleXmlChain lastChain = parsed.Chains[^1];
        OracleXmlArchiveTimeStamp lastMember = lastChain.ArchiveTimeStamps[^1];
        PkiDigestAlgorithm algorithm = AlgorithmOf(lastChain.DigestMethodUri);
        byte[] canonical = XmlEvidenceRecordOracle.CanonicalizeTimeStamp(
            document, lastChain.Order, lastMember.Order, lastChain.CanonicalizationMethodUri);
        byte[] previousDigest = EvidenceRecordOracle.Hash(canonical, algorithm);

        var hashTree = new List<IReadOnlyList<byte[]>>();
        if(includeHashTree)
        {
            hashTree.Add([previousDigest]);
            if(siblingLevels is not null)
            {
                hashTree.AddRange(siblingLevels);
            }
        }

        byte[] timestampedValue = includeHashTree ? RootOf(hashTree, algorithm) : previousDigest;
        XDocument xml = Load(document);
        XElement chainElement = ChainElements(xml)[^1];
        chainElement.Add(BuildArchiveTimeStamp(
            lastChain.ArchiveTimeStamps.Count + 1, hashTree, timestampedValue, algorithm, authority, embeddedCertificates, generationTime, comment: null));

        return Serialize(xml);
    }


    /// <summary>
    /// Appends a Hash-Tree Renewal (clause 4.2.2) to a document: a new chain under a new algorithm whose first
    /// <c>Sequence</c> holds the data-object digests together with the digest of the canonical
    /// <c>ArchiveTimeStampSequence</c> of every preceding chain.
    /// </summary>
    /// <param name="document">The document to renew.</param>
    /// <param name="dataObjectDigests">The data objects' digests under <paramref name="algorithm"/>.</param>
    /// <param name="algorithm">The new algorithm.</param>
    /// <param name="canonicalizationUri">The identifier the new chain's <c>CanonicalizationMethod</c> names.</param>
    /// <param name="authority">The Time-Stamping Authority node.</param>
    /// <param name="embeddedCertificates">The certificates the token carries.</param>
    /// <param name="generationTime">The <c>genTime</c> the authority states.</param>
    /// <param name="siblingLevels">Further <c>Sequence</c> elements beyond the first; none when <see langword="null"/>.</param>
    /// <returns>The renewed document's octets.</returns>
    internal static byte[] AppendHashTreeRenewal(
        byte[] document,
        IReadOnlyList<byte[]> dataObjectDigests,
        PkiDigestAlgorithm algorithm,
        string canonicalizationUri,
        X509ChainTestRingNode authority,
        IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
        DateTimeOffset generationTime,
        IReadOnlyList<IReadOnlyList<byte[]>>? siblingLevels = null)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(dataObjectDigests);

        OracleXmlEvidenceRecord parsed = XmlEvidenceRecordOracle.Parse(document);
        byte[] sequenceCanonical = XmlEvidenceRecordOracle.CanonicalizeSequencePrefix(document, parsed.Chains.Count, canonicalizationUri);
        byte[] sequenceDigest = EvidenceRecordOracle.Hash(sequenceCanonical, algorithm);

        var firstSequence = new List<byte[]>(dataObjectDigests) { sequenceDigest };
        var hashTree = new List<IReadOnlyList<byte[]>> { firstSequence };
        if(siblingLevels is not null)
        {
            hashTree.AddRange(siblingLevels);
        }

        byte[] timestampedValue = RootOf(hashTree, algorithm);
        XElement archiveTimeStamp = BuildArchiveTimeStamp(
            1, hashTree, timestampedValue, algorithm, authority, embeddedCertificates, generationTime, comment: null);
        XDocument xml = Load(document);
        xml.Root!.Element(Namespace + "ArchiveTimeStampSequence")!
            .Add(BuildChain(parsed.Chains.Count + 1, algorithm, canonicalizationUri, [archiveTimeStamp]));

        return Serialize(xml);
    }


    /// <summary>
    /// Replaces one <c>DigestValue</c> element's text, so that a document differing from a valid one in exactly
    /// one hash value can be produced.
    /// </summary>
    /// <param name="document">The document.</param>
    /// <param name="original">The base64 text to replace.</param>
    /// <param name="replacement">The base64 text to write in its place.</param>
    /// <returns>The changed document's octets.</returns>
    internal static byte[] ReplaceDigestValue(byte[] document, string original, string replacement)
    {
        ArgumentNullException.ThrowIfNull(document);

        XDocument xml = Load(document);
        foreach(XElement digestValue in xml.Descendants(Namespace + "DigestValue"))
        {
            if(string.Equals(digestValue.Value.Trim(), original, StringComparison.Ordinal))
            {
                digestValue.Value = replacement;
            }
        }

        return Serialize(xml);
    }


    /// <summary>
    /// Adds one further <c>DigestValue</c> element to the first <c>Sequence</c> of the first Archive Time-Stamp,
    /// which is what an Archive Time-Stamp that also covers something the verifier was never shown looks like.
    /// </summary>
    /// <param name="document">The document.</param>
    /// <param name="extraValue">The hash value to add.</param>
    /// <returns>The changed document's octets, whose token no longer binds the root and whose first sequence holds an extraneous value.</returns>
    internal static byte[] AddValueToFirstSequence(byte[] document, byte[] extraValue)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(extraValue);

        XDocument xml = Load(document);
        XElement firstSequence = xml.Descendants(Namespace + "Sequence").First(static sequence => ReadOrder(sequence) == 1);
        firstSequence.Add(new XElement(Namespace + "DigestValue", Convert.ToBase64String(extraValue)));

        return Serialize(xml);
    }


    /// <summary>
    /// Re-serialises a document with indentation, producing a different octet sequence for the same information
    /// set — the input to the canonicalization-insensitivity case.
    /// </summary>
    /// <param name="document">The document.</param>
    /// <returns>The re-serialised octets.</returns>
    internal static byte[] Reserialize(byte[] document)
    {
        ArgumentNullException.ThrowIfNull(document);

        XDocument xml = Load(document);

        return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
            .GetBytes(xml.ToString(SaveOptions.None));
    }


    /// <summary>
    /// Recomputes the root of a hash tree through the independent oracle.
    /// </summary>
    /// <param name="hashTree">The sequences, leaf list first.</param>
    /// <param name="algorithm">The algorithm the chain names.</param>
    /// <returns>The root hash value.</returns>
    internal static byte[] RootOf(IReadOnlyList<IReadOnlyList<byte[]>> hashTree, PkiDigestAlgorithm algorithm)
    {
        ArgumentNullException.ThrowIfNull(hashTree);

        var sequences = new List<OracleXmlSequence>(hashTree.Count);
        for(int i = 0; i < hashTree.Count; ++i)
        {
            sequences.Add(new OracleXmlSequence(i + 1, [.. hashTree[i]]));
        }

        return XmlEvidenceRecordOracle.RootOf(sequences, algorithm);
    }


    /// <summary>
    /// Builds one <c>ArchiveTimeStamp</c> element with its hash tree and a freshly minted token.
    /// </summary>
    /// <param name="order">The element's <c>Order</c>.</param>
    /// <param name="hashTree">The sequences to write; empty writes no <c>HashTree</c> element.</param>
    /// <param name="timestampedValue">The value the token's message imprint states.</param>
    /// <param name="algorithm">The algorithm the chain names.</param>
    /// <param name="authority">The Time-Stamping Authority node.</param>
    /// <param name="embeddedCertificates">The certificates the token carries.</param>
    /// <param name="generationTime">The <c>genTime</c> the authority states.</param>
    /// <param name="comment">A comment to write inside the first <c>Sequence</c>, or <see langword="null"/>.</param>
    /// <returns>The element.</returns>
    private static XElement BuildArchiveTimeStamp(
        int order,
        IReadOnlyList<IReadOnlyList<byte[]>> hashTree,
        byte[] timestampedValue,
        PkiDigestAlgorithm algorithm,
        X509ChainTestRingNode authority,
        IReadOnlyList<X509ChainTestRingNode> embeddedCertificates,
        DateTimeOffset generationTime,
        string? comment)
    {
        using PkiCertificateMemory token = X509ChainTestRingTimestamping.MintTimestampTokenOverImprint(
            authority, embeddedCertificates, timestampedValue, generationTime, messageImprintAlgorithm: algorithm);

        var element = new XElement(Namespace + "ArchiveTimeStamp", new XAttribute("Order", order.ToString(CultureInfo.InvariantCulture)));
        if(hashTree.Count > 0)
        {
            var hashTreeElement = new XElement(Namespace + "HashTree");
            for(int i = 0; i < hashTree.Count; ++i)
            {
                var sequence = new XElement(Namespace + "Sequence", new XAttribute("Order", (i + 1).ToString(CultureInfo.InvariantCulture)));
                if(i == 0 && comment is not null)
                {
                    sequence.Add(new XComment(comment));
                }

                for(int valueIndex = 0; valueIndex < hashTree[i].Count; ++valueIndex)
                {
                    sequence.Add(new XElement(Namespace + "DigestValue", Convert.ToBase64String(hashTree[i][valueIndex])));
                }

                hashTreeElement.Add(sequence);
            }

            element.Add(hashTreeElement);
        }

        element.Add(new XElement(
            Namespace + "TimeStamp",
            new XElement(
                Namespace + "TimeStampToken",
                new XAttribute("Type", "RFC3161"),
                Convert.ToBase64String(token.AsReadOnlySpan()))));

        return element;
    }


    /// <summary>
    /// Builds one <c>ArchiveTimeStampChain</c> element.
    /// </summary>
    /// <param name="order">The chain's <c>Order</c>.</param>
    /// <param name="algorithm">The algorithm its <c>DigestMethod</c> names.</param>
    /// <param name="canonicalizationUri">The identifier its <c>CanonicalizationMethod</c> names.</param>
    /// <param name="archiveTimeStamps">The members to write.</param>
    /// <returns>The element.</returns>
    private static XElement BuildChain(
        int order,
        PkiDigestAlgorithm algorithm,
        string canonicalizationUri,
        IReadOnlyList<XElement> archiveTimeStamps)
    {
        var chain = new XElement(
            Namespace + "ArchiveTimeStampChain",
            new XAttribute("Order", order.ToString(CultureInfo.InvariantCulture)),
            new XElement(Namespace + "DigestMethod", new XAttribute("Algorithm", XmlSignatureWellKnown.DigestUriFromAlgorithm(algorithm)!)),
            new XElement(Namespace + "CanonicalizationMethod", new XAttribute("Algorithm", canonicalizationUri)));
        for(int i = 0; i < archiveTimeStamps.Count; ++i)
        {
            chain.Add(archiveTimeStamps[i]);
        }

        return chain;
    }


    /// <summary>Resolves the algorithm a <c>DigestMethod</c> identifier names.</summary>
    /// <param name="digestMethodUri">The identifier.</param>
    /// <returns>The algorithm.</returns>
    private static PkiDigestAlgorithm AlgorithmOf(string digestMethodUri) =>
        XmlSignatureWellKnown.DigestAlgorithmFromUri(digestMethodUri)
        ?? throw new InvalidOperationException($"'{digestMethodUri}' names no algorithm this factory mints under.");


    /// <summary>Enumerates the chain elements of a document in document order.</summary>
    /// <param name="document">The document.</param>
    /// <returns>The chain elements.</returns>
    private static List<XElement> ChainElements(XDocument document) =>
        [.. document.Root!.Element(Namespace + "ArchiveTimeStampSequence")!.Elements(Namespace + "ArchiveTimeStampChain")];


    /// <summary>Reads an element's <c>Order</c> attribute.</summary>
    /// <param name="element">The element.</param>
    /// <returns>The value, or zero when absent.</returns>
    private static int ReadOrder(XElement element) =>
        int.TryParse(element.Attribute("Order")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int order) ? order : 0;


    /// <summary>Loads a document with whitespace preserved.</summary>
    /// <param name="octets">The document's octets.</param>
    /// <returns>The loaded document.</returns>
    private static XDocument Load(byte[] octets) =>
        XDocument.Parse(
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(octets),
            LoadOptions.PreserveWhitespace);


    /// <summary>Serialises a document with no added formatting.</summary>
    /// <param name="document">The document.</param>
    /// <returns>The octets.</returns>
    private static byte[] Serialize(XDocument document) =>
        new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true)
            .GetBytes(document.ToString(SaveOptions.DisableFormatting));
}
