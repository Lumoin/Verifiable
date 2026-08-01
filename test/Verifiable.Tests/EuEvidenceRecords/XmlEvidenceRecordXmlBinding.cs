using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cryptography.Pki.Xml;

/// <summary>
/// A worked <see cref="ParseEvidenceRecordXmlDelegate"/> and
/// <see cref="CanonicalizeXmlEvidenceRecordDelegate"/> pair for the <c>EvidenceRecord</c> element of
/// <see href="https://www.rfc-editor.org/rfc/rfc6283#section-8">IETF RFC 6283 clause 8</see>, using
/// <see cref="System.Xml.Linq"/> to move between the document and the serialisation-agnostic
/// <see cref="XmlEvidenceRecord"/> model and <see cref="System.Security.Cryptography.Xml"/>'s canonicalizers to
/// produce the binary representations clause 4.1.2 requires.
/// </summary>
/// <remarks>
/// <para>
/// This is a staged, promotable worked example, not a shipped library type: it lives beside
/// <c>TestInfrastructure</c>, never inside it, carries no test-framework type, and depends on nothing but the
/// base class library and <c>Verifiable.Cryptography.Pki</c> itself. Its namespace already names where a future
/// package would place it. The same shape carries <c>AsicManifestXmlBinding</c> for the container manifest and
/// <c>TrustedListXmlParser</c> for the Trusted List profile.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> An Evidence Record arrives from whoever archived the data and is
/// not authenticated by anything until its own time-stamps have been verified, which cannot happen until it has
/// been parsed. Document type definitions are prohibited outright (blocking entity expansion and external entity
/// fetch), no external resource is ever resolved, every count is bounded by
/// <see cref="XmlEvidenceRecordParseLimits"/>, and the depth is bounded by an explicit
/// <see cref="Stack{T}"/> walk rather than by a recursive method call.
/// </para>
/// <para>
/// <strong>Canonicalizing a sub-tree is not the same as serialising it.</strong> An element's canonical form
/// under an inclusive algorithm carries every namespace declaration and <c>xml:*</c> attribute its ancestors put
/// in scope, whether or not the sub-tree uses them; under an exclusive algorithm it carries only the ones it
/// visibly utilises. <see cref="CanonicalizeAsync"/> therefore lifts the wanted element into a document of its
/// own with every in-scope ancestor declaration copied down — nearer declarations winning — and canonicalizes
/// that, so the inclusive algorithms see what they are supposed to see and the exclusive ones discard what they
/// are supposed to discard.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code (layering-split-ledger.md): public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
public static class XmlEvidenceRecordXmlBinding
{
    /// <summary>The namespace clause 8's schema declares as its target.</summary>
    public static XNamespace EvidenceRecordNamespace { get; } = XmlEvidenceRecordWellKnown.EvidenceRecordNamespace;

    /// <summary>The <c>xmlns</c> namespace a namespace declaration attribute itself lives in.</summary>
    private static string XmlnsNamespace { get; } = "http://www.w3.org/2000/xmlns/";

    /// <summary>The <c>xml</c> namespace the <c>xml:lang</c>, <c>xml:space</c> and <c>xml:base</c> attributes live in.</summary>
    private static string XmlNamespace { get; } = "http://www.w3.org/XML/1998/namespace";


    /// <summary>
    /// Parses an <c>EvidenceRecord</c> document into the <see cref="XmlEvidenceRecord"/> model. Has the
    /// <see cref="ParseEvidenceRecordXmlDelegate"/> shape.
    /// </summary>
    /// <param name="context">The document and the bounds to parse it under.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The parse result.</returns>
    public static ValueTask<XmlEvidenceRecordParseResult> ParseAsync(
        XmlEvidenceRecordParseContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        XmlEvidenceRecordParseLimits limits = context.Limits;
        ReadOnlySpan<byte> octets = context.Document.Span;
        if(octets.Length > limits.MaximumDocumentByteLength)
        {
            return ValueTask.FromResult(XmlEvidenceRecordParseResult.Failed(
                XmlEvidenceRecordParseStatus.LimitExceeded,
                $"The document is {octets.Length} octets, over the {limits.MaximumDocumentByteLength} the limits admit."));
        }

        XDocument xml;
        try
        {
            xml = LoadDocument(context.Document);
        }
        catch(Exception ex) when(ex is XmlException or InvalidOperationException or DecoderFallbackException)
        {
            return ValueTask.FromResult(XmlEvidenceRecordParseResult.Failed(
                XmlEvidenceRecordParseStatus.Malformed,
                $"The document is not well-formed XML: {ex.Message}"));
        }

        XElement? root = xml.Root;
        if(root is null || root.Name != EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.EvidenceRecordElementName)
        {
            return ValueTask.FromResult(XmlEvidenceRecordParseResult.Failed(
                XmlEvidenceRecordParseStatus.Malformed,
                $"Unexpected root element '{root?.Name.ToString() ?? "(none)"}'."));
        }

        if(!IsWithinDepthBound(root, limits.MaximumElementDepth))
        {
            return ValueTask.FromResult(XmlEvidenceRecordParseResult.Failed(
                XmlEvidenceRecordParseStatus.LimitExceeded,
                $"The document nests deeper than the {limits.MaximumElementDepth} elements the limits admit."));
        }

        return ValueTask.FromResult(ReadEvidenceRecord(root, limits, pool));
    }


    /// <summary>
    /// Produces the canonical binary representation of the element the context names. Has the
    /// <see cref="CanonicalizeXmlEvidenceRecordDelegate"/> shape.
    /// </summary>
    /// <param name="context">The document, the algorithm and which sub-tree is wanted.</param>
    /// <param name="pool">The memory pool the produced octets' carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The canonicalization result.</returns>
    public static ValueTask<XmlEvidenceRecordCanonicalizationResult> CanonicalizeAsync(
        XmlEvidenceRecordCanonicalizationContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        if(!XmlSignatureWellKnown.IsRecognizedCanonicalizationUri(context.AlgorithmUri))
        {
            return ValueTask.FromResult(XmlEvidenceRecordCanonicalizationResult.Failed(
                XmlEvidenceRecordCanonicalizationStatus.UnsupportedAlgorithm,
                $"'{context.AlgorithmUri}' is not a canonicalization algorithm of the space IETF RFC 3275 and IETF RFC 4051 define."));
        }

        XmlDocument document;
        try
        {
            document = LoadMutableDocument(
                context.Target == XmlEvidenceRecordCanonicalizationTarget.ArchiveDataObject ? context.ArchiveData : context.Document);
        }
        catch(Exception ex) when(ex is XmlException or InvalidOperationException or DecoderFallbackException)
        {
            return ValueTask.FromResult(XmlEvidenceRecordCanonicalizationResult.Failed(
                XmlEvidenceRecordCanonicalizationStatus.Malformed,
                $"The octets to canonicalize are not well-formed XML: {ex.Message}"));
        }

        XmlElement? wanted = context.Target switch
        {
            XmlEvidenceRecordCanonicalizationTarget.ArchiveDataObject => document.DocumentElement,
            XmlEvidenceRecordCanonicalizationTarget.TimeStampElement => FindTimeStampElement(document, context.ChainOrder, context.ArchiveTimeStampOrder),
            XmlEvidenceRecordCanonicalizationTarget.ArchiveTimeStampSequencePrefix => BuildSequencePrefix(document, context.ChainCount),
            _ => null
        };
        if(wanted is null)
        {
            return ValueTask.FromResult(XmlEvidenceRecordCanonicalizationResult.Failed(
                XmlEvidenceRecordCanonicalizationStatus.TargetNotFound,
                $"The document carries no {context.Target} for chain {context.ChainOrder}, archive time-stamp {context.ArchiveTimeStampOrder}, chain count {context.ChainCount}."));
        }

        byte[] canonical = Canonicalize(wanted, context.AlgorithmUri);

        return ValueTask.FromResult(XmlEvidenceRecordCanonicalizationResult.Canonicalized(
            PooledMemory.FromBytes(canonical, pool, XmlEvidenceRecordTags.CanonicalizedElement)));
    }


    /// <summary>
    /// Loads octets as an <see cref="XDocument"/> under settings that resolve nothing and admit no document type
    /// definition.
    /// </summary>
    /// <param name="octets">The document's octets.</param>
    /// <returns>The loaded document, with whitespace preserved.</returns>
    private static XDocument LoadDocument(ReadOnlyMemory<byte> octets)
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(octets.Length, 1));
        try
        {
            octets.Span.CopyTo(rented);
            using var stream = new MemoryStream(rented, 0, octets.Length, writable: false);
            var readerSettings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                CloseInput = false
            };

            using XmlReader reader = XmlReader.Create(stream, readerSettings);

            return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }


    /// <summary>
    /// Loads octets as an <see cref="XmlDocument"/>, which is the shape the canonicalizers of
    /// <see cref="System.Security.Cryptography.Xml"/> take, under the same resolve-nothing settings.
    /// </summary>
    /// <param name="octets">The document's octets.</param>
    /// <returns>The loaded document, with whitespace preserved.</returns>
    private static XmlDocument LoadMutableDocument(ReadOnlyMemory<byte> octets)
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(octets.Length, 1));
        try
        {
            octets.Span.CopyTo(rented);
            using var stream = new MemoryStream(rented, 0, octets.Length, writable: false);
            var readerSettings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                CloseInput = false
            };

            using XmlReader reader = XmlReader.Create(stream, readerSettings);
            var document = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
            document.Load(reader);

            return document;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }


    /// <summary>
    /// Locates the <c>TimeStamp</c> element of one Archive Time-Stamp by the two <c>Order</c> attributes that
    /// name it.
    /// </summary>
    /// <param name="document">The Evidence Record document.</param>
    /// <param name="chainOrder">The chain's <c>Order</c>.</param>
    /// <param name="archiveTimeStampOrder">The Archive Time-Stamp's <c>Order</c>.</param>
    /// <returns>The element, or <see langword="null"/> when the document carries no such element.</returns>
    private static XmlElement? FindTimeStampElement(XmlDocument document, int chainOrder, int archiveTimeStampOrder)
    {
        XmlElement? sequence = FindChild(document.DocumentElement, XmlEvidenceRecordWellKnown.ArchiveTimeStampSequenceElementName);
        if(sequence is null)
        {
            return null;
        }

        foreach(XmlElement chain in ChildElements(sequence, XmlEvidenceRecordWellKnown.ArchiveTimeStampChainElementName))
        {
            if(ReadOrder(chain) != chainOrder)
            {
                continue;
            }

            foreach(XmlElement archiveTimeStamp in ChildElements(chain, XmlEvidenceRecordWellKnown.ArchiveTimeStampElementName))
            {
                if(ReadOrder(archiveTimeStamp) == archiveTimeStampOrder)
                {
                    return FindChild(archiveTimeStamp, XmlEvidenceRecordWellKnown.TimeStampElementName);
                }
            }
        }

        return null;
    }


    /// <summary>
    /// Builds the <c>ArchiveTimeStampSequence</c> element holding the first <paramref name="chainCount"/> chains
    /// and no others — Appendix A step 4.a.ii's "ordered ATSSeq without this and successive chains".
    /// </summary>
    /// <param name="document">The Evidence Record document, which is mutated in place; the caller loaded it for this purpose alone.</param>
    /// <param name="chainCount">How many chains, counted from the lowest <c>Order</c>, the prefix holds.</param>
    /// <returns>The element, or <see langword="null"/> when the document carries fewer chains than that.</returns>
    /// <remarks>
    /// The chains beyond the prefix are removed and nothing else is touched, so every octet of what remains —
    /// comments, attribute order, prefixes — is what the producer canonicalized when it built the renewal. A
    /// producer that wrote inter-element whitespace between chains would leave that whitespace behind here; the
    /// records this example is exercised against write none, and the general fix belongs to whoever needs it.
    /// </remarks>
    private static XmlElement? BuildSequencePrefix(XmlDocument document, int chainCount)
    {
        XmlElement? sequence = FindChild(document.DocumentElement, XmlEvidenceRecordWellKnown.ArchiveTimeStampSequenceElementName);
        if(sequence is null || chainCount <= 0)
        {
            return null;
        }

        var chains = new List<XmlElement>();
        foreach(XmlElement chain in ChildElements(sequence, XmlEvidenceRecordWellKnown.ArchiveTimeStampChainElementName))
        {
            chains.Add(chain);
        }

        if(chains.Count < chainCount)
        {
            return null;
        }

        chains.Sort(static (left, right) => ReadOrder(left).CompareTo(ReadOrder(right)));
        for(int i = chainCount; i < chains.Count; ++i)
        {
            _ = sequence.RemoveChild(chains[i]);
        }

        return sequence;
    }


    /// <summary>
    /// Produces the canonical form of one element under a recognised canonicalization algorithm.
    /// </summary>
    /// <param name="element">The element whose canonical form is wanted.</param>
    /// <param name="algorithmUri">The algorithm identifier the chain names.</param>
    /// <returns>The canonical octets.</returns>
    /// <remarks>
    /// The element is lifted into a document of its own with every in-scope ancestor namespace declaration and
    /// <c>xml:*</c> attribute copied down, nearer declarations winning, which is what an inclusive algorithm's
    /// node-set view of the sub-tree carries. An exclusive algorithm then drops the ones the sub-tree does not
    /// visibly utilise, exactly as it would have on the original document.
    /// </remarks>
    private static byte[] Canonicalize(XmlElement element, string algorithmUri)
    {
        var lifted = new XmlDocument { PreserveWhitespace = true, XmlResolver = null };
        lifted.LoadXml(element.OuterXml);
        XmlElement liftedRoot = lifted.DocumentElement!;
        for(XmlNode? ancestor = element.ParentNode; ancestor is XmlElement ancestorElement; ancestor = ancestor.ParentNode)
        {
            foreach(XmlAttribute attribute in ancestorElement.Attributes)
            {
                bool isNamespaceDeclaration = string.Equals(attribute.NamespaceURI, XmlnsNamespace, StringComparison.Ordinal);
                bool isXmlAttribute = string.Equals(attribute.NamespaceURI, XmlNamespace, StringComparison.Ordinal);
                if((!isNamespaceDeclaration && !isXmlAttribute) || liftedRoot.HasAttribute(attribute.LocalName, attribute.NamespaceURI))
                {
                    continue;
                }

                liftedRoot.SetAttribute(attribute.LocalName, attribute.NamespaceURI, attribute.Value);
            }
        }

        bool withComments = XmlSignatureWellKnown.IsCanonicalizationWithComments(algorithmUri);
        Transform transform = XmlSignatureWellKnown.IsExclusiveCanonicalXml10Uri(algorithmUri)
            ? new XmlDsigExcC14NTransform(withComments)
            : new XmlDsigC14NTransform(withComments);
        transform.LoadInput(lifted);
        using var output = (Stream)transform.GetOutput(typeof(Stream));
        using var buffer = new MemoryStream();
        output.CopyTo(buffer);

        return buffer.ToArray();
    }


    /// <summary>
    /// Reads the whole model out of the root element.
    /// </summary>
    /// <param name="root">The <c>EvidenceRecord</c> element.</param>
    /// <param name="limits">The bounds to read under.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The parse result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the record, and of every chain and supporting information element it holds, transfers to the returned result on success; the finally releases all of them on every other path. The rule's data flow does not follow ownership through the transfer flag.")]
    private static XmlEvidenceRecordParseResult ReadEvidenceRecord(XElement root, XmlEvidenceRecordParseLimits limits, BaseMemoryPool pool)
    {
        string? version = root.Attribute(XmlEvidenceRecordWellKnown.VersionAttributeName)?.Value;
        if(version is null)
        {
            return XmlEvidenceRecordParseResult.Failed(
                XmlEvidenceRecordParseStatus.MissingRequiredElement,
                "Clause 2.1 requires the Version attribute on the EvidenceRecord element.");
        }

        XElement? sequence = root.Element(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.ArchiveTimeStampSequenceElementName);
        if(sequence is null)
        {
            return XmlEvidenceRecordParseResult.Failed(
                XmlEvidenceRecordParseStatus.MissingRequiredElement,
                "Clause 2.1 requires the ArchiveTimeStampSequence element.");
        }

        var supporting = new List<XmlEvidenceRecordInformation>();
        var chains = new List<XmlEvidenceRecordArchiveTimeStampChain>();
        bool transferred = false;
        try
        {
            XElement? supportingList = root.Element(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.SupportingInformationListElementName);
            if(supportingList is not null)
            {
                foreach(XElement information in supportingList.Elements(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.SupportingInformationElementName))
                {
                    if(supporting.Count >= limits.MaximumSupportingInformation)
                    {
                        return XmlEvidenceRecordParseResult.Failed(
                            XmlEvidenceRecordParseStatus.LimitExceeded,
                            $"The record states more than the {limits.MaximumSupportingInformation} SupportingInformation elements the limits admit.");
                    }

                    supporting.Add(new XmlEvidenceRecordInformation
                    {
                        InformationType = information.Attribute(XmlEvidenceRecordWellKnown.TypeAttributeName)?.Value,
                        Content = SerializeElement(information, pool)
                    });
                }
            }

            var chainElements = new List<XElement>(sequence.Elements(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.ArchiveTimeStampChainElementName));
            if(chainElements.Count == 0)
            {
                return XmlEvidenceRecordParseResult.Failed(
                    XmlEvidenceRecordParseStatus.MissingRequiredElement,
                    "Clause 4.1 requires at least one ArchiveTimeStampChain element.");
            }

            if(chainElements.Count > limits.MaximumChains)
            {
                return XmlEvidenceRecordParseResult.Failed(
                    XmlEvidenceRecordParseStatus.LimitExceeded,
                    $"The record states more than the {limits.MaximumChains} chains the limits admit.");
            }

            if(!TryOrder(chainElements, out List<XElement>? orderedChains))
            {
                return XmlEvidenceRecordParseResult.Failed(
                    XmlEvidenceRecordParseStatus.OrderMalformed,
                    "Clause 2.1 makes the Order attributes of the ArchiveTimeStampChain elements the run 1..n, and these are not.");
            }

            for(int i = 0; i < orderedChains.Count; ++i)
            {
                (XmlEvidenceRecordParseStatus status, XmlEvidenceRecordArchiveTimeStampChain? chain, string? reason) =
                    ReadChain(orderedChains[i], i + 1, limits, pool);
                if(chain is null)
                {
                    return XmlEvidenceRecordParseResult.Failed(status, reason!);
                }

                chains.Add(chain);
            }

            var record = new XmlEvidenceRecord
            {
                Version = version,
                HasEncryptionInformation = root.Element(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.EncryptionInformationElementName) is not null,
                SupportingInformation = supporting,
                Chains = chains
            };
            transferred = true;

            return XmlEvidenceRecordParseResult.Valid(record);
        }
        finally
        {
            if(!transferred)
            {
                for(int i = 0; i < supporting.Count; ++i)
                {
                    supporting[i].Dispose();
                }

                for(int i = 0; i < chains.Count; ++i)
                {
                    chains[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Reads one <c>ArchiveTimeStampChain</c> element.
    /// </summary>
    /// <param name="element">The chain element.</param>
    /// <param name="order">The chain's <c>Order</c>, already validated to be the run position.</param>
    /// <param name="limits">The bounds to read under.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The status, the chain when it was read, and the reason when it was not.</returns>
    private static (XmlEvidenceRecordParseStatus Status, XmlEvidenceRecordArchiveTimeStampChain? Chain, string? Reason) ReadChain(
        XElement element,
        int order,
        XmlEvidenceRecordParseLimits limits,
        BaseMemoryPool pool)
    {
        string? digestMethodUri = element
            .Element(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.DigestMethodElementName)
            ?.Attribute(XmlEvidenceRecordWellKnown.AlgorithmAttributeName)?.Value;
        if(digestMethodUri is null)
        {
            return (XmlEvidenceRecordParseStatus.MissingRequiredElement, null, "Clause 4.1.1 requires a DigestMethod element with an Algorithm attribute in every chain.");
        }

        if(XmlSignatureWellKnown.DigestAlgorithmFromUri(digestMethodUri) is not PkiDigestAlgorithm digestAlgorithm)
        {
            return (XmlEvidenceRecordParseStatus.UnsupportedDigestAlgorithm, null, $"'{digestMethodUri}' names a digest algorithm this library will not compute.");
        }

        string? canonicalizationUri = element
            .Element(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.CanonicalizationMethodElementName)
            ?.Attribute(XmlEvidenceRecordWellKnown.AlgorithmAttributeName)?.Value;
        if(canonicalizationUri is null)
        {
            return (XmlEvidenceRecordParseStatus.MissingRequiredElement, null, "Clause 4.1.2 requires a CanonicalizationMethod element with an Algorithm attribute in every chain.");
        }

        if(!XmlSignatureWellKnown.IsRecognizedCanonicalizationUri(canonicalizationUri))
        {
            return (XmlEvidenceRecordParseStatus.UnsupportedCanonicalizationAlgorithm, null, $"'{canonicalizationUri}' is not a canonicalization algorithm of the space clause 4.1.2 binds the identifier to.");
        }

        var memberElements = new List<XElement>(element.Elements(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.ArchiveTimeStampElementName));
        if(memberElements.Count == 0)
        {
            return (XmlEvidenceRecordParseStatus.MissingRequiredElement, null, "Clause 4.1 requires at least one ArchiveTimeStamp element in every chain.");
        }

        if(memberElements.Count > limits.MaximumArchiveTimeStampsPerChain)
        {
            return (XmlEvidenceRecordParseStatus.LimitExceeded, null, $"A chain states more than the {limits.MaximumArchiveTimeStampsPerChain} Archive Time-Stamps the limits admit.");
        }

        if(!TryOrder(memberElements, out List<XElement>? orderedMembers))
        {
            return (XmlEvidenceRecordParseStatus.OrderMalformed, null, "Clause 2.1 makes the Order attributes of the ArchiveTimeStamp elements of a chain the run 1..n, and these are not.");
        }

        var members = new List<XmlEvidenceRecordArchiveTimeStamp>(orderedMembers.Count);
        bool transferred = false;
        try
        {
            for(int i = 0; i < orderedMembers.Count; ++i)
            {
                (XmlEvidenceRecordParseStatus status, XmlEvidenceRecordArchiveTimeStamp? member, string? reason) =
                    ReadArchiveTimeStamp(orderedMembers[i], i + 1, digestAlgorithm, limits, pool);
                if(member is null)
                {
                    return (status, null, reason);
                }

                members.Add(member);
            }

            var chain = new XmlEvidenceRecordArchiveTimeStampChain
            {
                Order = order,
                DigestMethodUri = digestMethodUri,
                DigestAlgorithm = digestAlgorithm,
                CanonicalizationMethodUri = canonicalizationUri,
                ArchiveTimeStamps = members
            };
            transferred = true;

            return (XmlEvidenceRecordParseStatus.Valid, chain, null);
        }
        finally
        {
            if(!transferred)
            {
                for(int i = 0; i < members.Count; ++i)
                {
                    members[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Reads one <c>ArchiveTimeStamp</c> element.
    /// </summary>
    /// <param name="element">The Archive Time-Stamp element.</param>
    /// <param name="order">The element's <c>Order</c>, already validated to be the run position.</param>
    /// <param name="digestAlgorithm">The algorithm the chain names, which every hash value is checked against.</param>
    /// <param name="limits">The bounds to read under.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The status, the element when it was read, and the reason when it was not.</returns>
    private static (XmlEvidenceRecordParseStatus Status, XmlEvidenceRecordArchiveTimeStamp? ArchiveTimeStamp, string? Reason) ReadArchiveTimeStamp(
        XElement element,
        int order,
        PkiDigestAlgorithm digestAlgorithm,
        XmlEvidenceRecordParseLimits limits,
        BaseMemoryPool pool)
    {
        XElement? timeStampElement = element.Element(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.TimeStampElementName);
        if(timeStampElement is null)
        {
            return (XmlEvidenceRecordParseStatus.MissingRequiredElement, null, "Clause 2.1 requires a TimeStamp element in every ArchiveTimeStamp.");
        }

        XmlEvidenceRecordHashTree? hashTree = null;
        XmlEvidenceRecordTimeStamp? timeStamp = null;
        var attributes = new List<XmlEvidenceRecordInformation>();
        bool transferred = false;
        try
        {
            XElement? hashTreeElement = element.Element(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.HashTreeElementName);
            if(hashTreeElement is not null)
            {
                (XmlEvidenceRecordParseStatus status, XmlEvidenceRecordHashTree? tree, string? reason) =
                    ReadHashTree(hashTreeElement, digestAlgorithm, limits, pool);
                if(tree is null)
                {
                    return (status, null, reason);
                }

                hashTree = tree;
            }

            (XmlEvidenceRecordParseStatus timeStampStatus, XmlEvidenceRecordTimeStamp? readTimeStamp, string? timeStampReason) =
                ReadTimeStamp(timeStampElement, limits, pool);
            if(readTimeStamp is null)
            {
                return (timeStampStatus, null, timeStampReason);
            }

            timeStamp = readTimeStamp;

            XElement? attributesElement = element.Element(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.AttributesElementName);
            if(attributesElement is not null)
            {
                foreach(XElement attribute in attributesElement.Elements(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.AttributeElementName))
                {
                    if(attributes.Count >= limits.MaximumAttributesPerArchiveTimeStamp)
                    {
                        return (XmlEvidenceRecordParseStatus.LimitExceeded, null, $"An ArchiveTimeStamp states more than the {limits.MaximumAttributesPerArchiveTimeStamp} Attribute elements the limits admit.");
                    }

                    attributes.Add(new XmlEvidenceRecordInformation
                    {
                        Order = TryReadOrder(attribute),
                        InformationType = attribute.Attribute(XmlEvidenceRecordWellKnown.TypeAttributeName)?.Value,
                        Content = SerializeElement(attribute, pool)
                    });
                }
            }

            var archiveTimeStamp = new XmlEvidenceRecordArchiveTimeStamp
            {
                Order = order,
                HashTree = hashTree,
                TimeStamp = timeStamp,
                Attributes = attributes
            };
            transferred = true;

            return (XmlEvidenceRecordParseStatus.Valid, archiveTimeStamp, null);
        }
        finally
        {
            if(!transferred)
            {
                hashTree?.Dispose();
                timeStamp?.Dispose();
                for(int i = 0; i < attributes.Count; ++i)
                {
                    attributes[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Reads one <c>HashTree</c> element, decoding every <c>DigestValue</c> and checking its length against the
    /// algorithm the chain names.
    /// </summary>
    /// <param name="element">The hash tree element.</param>
    /// <param name="digestAlgorithm">The algorithm the chain names.</param>
    /// <param name="limits">The bounds to read under.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The status, the hash tree when it was read, and the reason when it was not.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each decoded hash value transfers to the sequence holding it and of each sequence to the returned hash tree; both finally blocks release what has not been transferred. The rule's data flow does not follow ownership through the transfer flags.")]
    private static (XmlEvidenceRecordParseStatus Status, XmlEvidenceRecordHashTree? HashTree, string? Reason) ReadHashTree(
        XElement element,
        PkiDigestAlgorithm digestAlgorithm,
        XmlEvidenceRecordParseLimits limits,
        BaseMemoryPool pool)
    {
        var sequenceElements = new List<XElement>(element.Elements(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.SequenceElementName));
        if(sequenceElements.Count == 0)
        {
            return (XmlEvidenceRecordParseStatus.MissingRequiredElement, null, "Clause 3.1.1 requires at least one Sequence element in a HashTree.");
        }

        if(sequenceElements.Count > limits.MaximumSequencesPerHashTree)
        {
            return (XmlEvidenceRecordParseStatus.LimitExceeded, null, $"A hash tree states more than the {limits.MaximumSequencesPerHashTree} Sequence elements the limits admit.");
        }

        if(!TryOrder(sequenceElements, out List<XElement>? orderedSequences))
        {
            return (XmlEvidenceRecordParseStatus.OrderMalformed, null, "Clause 2.1 makes the Order attributes of the Sequence elements of a hash tree the run 1..n, and these are not.");
        }

        var sequences = new List<XmlEvidenceRecordSequence>(orderedSequences.Count);
        bool transferred = false;
        try
        {
            for(int i = 0; i < orderedSequences.Count; ++i)
            {
                var values = new List<DigestValue>();
                bool valuesTransferred = false;
                try
                {
                    foreach(XElement digestValue in orderedSequences[i].Elements(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.DigestValueElementName))
                    {
                        if(values.Count >= limits.MaximumDigestValuesPerSequence)
                        {
                            return (XmlEvidenceRecordParseStatus.LimitExceeded, null, $"A Sequence states more than the {limits.MaximumDigestValuesPerSequence} DigestValue elements the limits admit.");
                        }

                        DigestValue? decoded = ReadDigestValue(digestValue.Value, digestAlgorithm, pool);
                        if(decoded is null)
                        {
                            return (XmlEvidenceRecordParseStatus.DigestValueMalformed, null, $"A DigestValue is not {digestAlgorithm.OutputByteLength} octets of base64 under the algorithm the chain names.");
                        }

                        values.Add(decoded);
                    }

                    if(values.Count == 0)
                    {
                        return (XmlEvidenceRecordParseStatus.MissingRequiredElement, null, "Clause 3.1.1 requires at least one DigestValue element in a Sequence.");
                    }

                    sequences.Add(new XmlEvidenceRecordSequence { Order = i + 1, DigestValues = values });
                    valuesTransferred = true;
                }
                finally
                {
                    if(!valuesTransferred)
                    {
                        for(int valueIndex = 0; valueIndex < values.Count; ++valueIndex)
                        {
                            values[valueIndex].Dispose();
                        }
                    }
                }
            }

            var hashTree = new XmlEvidenceRecordHashTree { Sequences = sequences };
            transferred = true;

            return (XmlEvidenceRecordParseStatus.Valid, hashTree, null);
        }
        finally
        {
            if(!transferred)
            {
                for(int i = 0; i < sequences.Count; ++i)
                {
                    sequences[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Reads one <c>TimeStamp</c> element: the token and whatever cryptographic information sits beside it.
    /// </summary>
    /// <param name="element">The time-stamp element.</param>
    /// <param name="limits">The bounds to read under.</param>
    /// <param name="pool">The memory pool every carrier is rented from.</param>
    /// <returns>The status, the time-stamp when it was read, and the reason when it was not.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the decoded token and of every cryptographic information element transfers to the returned time-stamp; the finally releases them on every other path. The rule's data flow does not follow ownership through the transfer flag.")]
    private static (XmlEvidenceRecordParseStatus Status, XmlEvidenceRecordTimeStamp? TimeStamp, string? Reason) ReadTimeStamp(
        XElement element,
        XmlEvidenceRecordParseLimits limits,
        BaseMemoryPool pool)
    {
        XElement? tokenElement = element.Element(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.TimeStampTokenElementName);
        if(tokenElement is null)
        {
            return (XmlEvidenceRecordParseStatus.MissingRequiredElement, null, "Clause 3.1.2 requires a TimeStampToken element in every TimeStamp.");
        }

        string? tokenType = tokenElement.Attribute(XmlEvidenceRecordWellKnown.TypeAttributeName)?.Value;
        if(tokenType is null || !XmlEvidenceRecordWellKnown.IsRegisteredTimeStampTokenType(tokenType))
        {
            return (XmlEvidenceRecordParseStatus.TimeStampTokenMalformed, null, $"Clause 3.1.2 registers two TimeStampToken types and '{tokenType ?? "(none)"}' is neither.");
        }

        PkiCertificateMemory? token = null;
        var information = new List<XmlEvidenceRecordCryptographicInformation>();
        bool transferred = false;
        try
        {
            if(XmlEvidenceRecordWellKnown.IsRfc3161TimeStampTokenType(tokenType))
            {
                byte[] decoded;
                try
                {
                    decoded = Convert.FromBase64String(tokenElement.Value);
                }
                catch(FormatException)
                {
                    return (XmlEvidenceRecordParseStatus.TimeStampTokenMalformed, null, "Clause 3.1.2 requires the content of an RFC3161 TimeStampToken to be the base64 encoding of a DER TimeStampToken.");
                }

                IMemoryOwner<byte> owner = pool.Rent(Math.Max(decoded.Length, 1));
                decoded.AsSpan().CopyTo(owner.Memory.Span);
                token = new PkiCertificateMemory(owner, PkiCertificateTags.TimestampToken);
            }

            XElement? informationList = element.Element(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.CryptographicInformationListElementName);
            if(informationList is not null)
            {
                foreach(XElement entry in informationList.Elements(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.CryptographicInformationElementName))
                {
                    if(information.Count >= limits.MaximumCryptographicInformationPerTimeStamp)
                    {
                        return (XmlEvidenceRecordParseStatus.LimitExceeded, null, $"A TimeStamp states more than the {limits.MaximumCryptographicInformationPerTimeStamp} CryptographicInformation elements the limits admit.");
                    }

                    string? informationType = entry.Attribute(XmlEvidenceRecordWellKnown.TypeAttributeName)?.Value;
                    if(informationType is null || TryReadOrder(entry) is not int entryOrder)
                    {
                        return (XmlEvidenceRecordParseStatus.MissingRequiredElement, null, "Clause 3.1.3 makes both the Order and the Type attributes required on a CryptographicInformation element.");
                    }

                    byte[] content;
                    try
                    {
                        content = Convert.FromBase64String(entry.Value);
                    }
                    catch(FormatException)
                    {
                        return (XmlEvidenceRecordParseStatus.Malformed, null, $"The content of a CryptographicInformation element of type '{informationType}' is not base64.");
                    }

                    information.Add(new XmlEvidenceRecordCryptographicInformation
                    {
                        Order = entryOrder,
                        InformationType = informationType,
                        Content = PooledMemory.FromBytes(content, pool, XmlEvidenceRecordTags.CryptographicInformation)
                    });
                }
            }

            var timeStamp = new XmlEvidenceRecordTimeStamp
            {
                TokenType = tokenType,
                Rfc3161Token = token,
                CryptographicInformation = information
            };
            transferred = true;

            return (XmlEvidenceRecordParseStatus.Valid, timeStamp, null);
        }
        finally
        {
            if(!transferred)
            {
                token?.Dispose();
                for(int i = 0; i < information.Count; ++i)
                {
                    information[i].Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Decodes a <c>DigestValue</c> element's base64 content into a digest carrier.
    /// </summary>
    /// <param name="value">The element's text content.</param>
    /// <param name="algorithm">The algorithm the chain names.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The carrier, or <see langword="null"/> when the content is not exactly one digest of base64.</returns>
    /// <remarks>
    /// The length is checked against the algorithm rather than accepted as whatever decodes: clause 4.1.1 makes
    /// one algorithm govern every hash value of a chain, so a value of another length can never take part in the
    /// comparison the walk is going to make.
    /// </remarks>
    private static DigestValue? ReadDigestValue(string value, PkiDigestAlgorithm algorithm, BaseMemoryPool pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(algorithm.OutputByteLength);
        try
        {
            if(!Convert.TryFromBase64String(value.Trim(), owner.Memory.Span, out int written) || written != algorithm.OutputByteLength)
            {
                owner.Dispose();

                return null;
            }

            return new DigestValue(owner, algorithm.DigestTag);
        }
        catch
        {
            owner.Dispose();

            throw;
        }
    }


    /// <summary>
    /// Serialises one element verbatim into a pooled carrier, for the lax-processed content clause 8's schema
    /// places no constraint on.
    /// </summary>
    /// <param name="element">The element to serialise.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The carrier.</returns>
    private static PooledMemory SerializeElement(XElement element, BaseMemoryPool pool) =>
        PooledMemory.FromBytes(
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetBytes(element.ToString(SaveOptions.DisableFormatting)),
            pool,
            XmlEvidenceRecordTags.OpaqueInformation);


    /// <summary>
    /// Sorts a set of same-named siblings by their <c>Order</c> attributes and checks that those attributes are
    /// the run 1..n clause 2.1 and clause 8's <c>OrderType</c> together require.
    /// </summary>
    /// <param name="elements">The siblings in document order.</param>
    /// <param name="ordered">The siblings in ascending <c>Order</c>, when the run is well formed.</param>
    /// <returns><see langword="true"/> when every element carries an <c>Order</c> and the set of them is 1..n.</returns>
    private static bool TryOrder(List<XElement> elements, [NotNullWhen(true)] out List<XElement>? ordered)
    {
        ordered = null;
        var orders = new List<int>(elements.Count);
        for(int i = 0; i < elements.Count; ++i)
        {
            if(TryReadOrder(elements[i]) is not int order || order < 1 || order > elements.Count || orders.Contains(order))
            {
                return false;
            }

            orders.Add(order);
        }

        var sorted = new List<XElement>(elements);
        sorted.Sort(static (left, right) => TryReadOrder(left)!.Value.CompareTo(TryReadOrder(right)!.Value));
        ordered = sorted;

        return true;
    }


    /// <summary>
    /// Reads an element's <c>Order</c> attribute.
    /// </summary>
    /// <param name="element">The element.</param>
    /// <returns>The value, or <see langword="null"/> when the attribute is absent or is not an integer.</returns>
    private static int? TryReadOrder(XElement element) =>
        int.TryParse(element.Attribute(XmlEvidenceRecordWellKnown.OrderAttributeName)?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int order)
            ? order
            : null;


    /// <summary>
    /// Reads an element's <c>Order</c> attribute in the mutable document model.
    /// </summary>
    /// <param name="element">The element.</param>
    /// <returns>The value, or zero when the attribute is absent or is not an integer.</returns>
    private static int ReadOrder(XmlElement element) =>
        int.TryParse(element.GetAttribute(XmlEvidenceRecordWellKnown.OrderAttributeName), NumberStyles.Integer, CultureInfo.InvariantCulture, out int order)
            ? order
            : 0;


    /// <summary>
    /// Finds one child element of the Evidence Record namespace by local name, in the mutable document model.
    /// </summary>
    /// <param name="parent">The parent element, or <see langword="null"/>.</param>
    /// <param name="localName">The child's local name.</param>
    /// <returns>The first such child, or <see langword="null"/>.</returns>
    private static XmlElement? FindChild(XmlElement? parent, string localName)
    {
        foreach(XmlElement child in ChildElements(parent, localName))
        {
            return child;
        }

        return null;
    }


    /// <summary>
    /// Enumerates the child elements of the Evidence Record namespace with a given local name, in the mutable
    /// document model.
    /// </summary>
    /// <param name="parent">The parent element, or <see langword="null"/>.</param>
    /// <param name="localName">The children's local name.</param>
    /// <returns>The matching children, in document order.</returns>
    private static IEnumerable<XmlElement> ChildElements(XmlElement? parent, string localName)
    {
        if(parent is null)
        {
            yield break;
        }

        for(XmlNode? node = parent.FirstChild; node is not null; node = node.NextSibling)
        {
            if(node is XmlElement child
                && string.Equals(child.LocalName, localName, StringComparison.Ordinal)
                && string.Equals(child.NamespaceURI, XmlEvidenceRecordWellKnown.EvidenceRecordNamespace, StringComparison.Ordinal))
            {
                yield return child;
            }
        }
    }


    /// <summary>
    /// Determines whether an element tree stays within a depth bound, walking it with an explicit stack rather
    /// than recursively.
    /// </summary>
    /// <param name="root">The tree's root.</param>
    /// <param name="maximumDepth">The deepest nesting admitted, counting the root as depth 1.</param>
    /// <returns><see langword="true"/> when no element sits deeper than the bound.</returns>
    private static bool IsWithinDepthBound(XElement root, int maximumDepth)
    {
        var pending = new Stack<(XElement Element, int Depth)>();
        pending.Push((root, 1));
        while(pending.Count > 0)
        {
            (XElement element, int depth) = pending.Pop();
            if(depth > maximumDepth)
            {
                return false;
            }

            foreach(XElement child in element.Elements())
            {
                pending.Push((child, depth + 1));
            }
        }

        return true;
    }


    /// <summary>
    /// Serialises an <see cref="XmlEvidenceRecord"/> model into an <c>EvidenceRecord</c> document conformant to
    /// clause 8's schema. Has the <see cref="WriteEvidenceRecordXmlDelegate"/> shape.
    /// </summary>
    /// <param name="context">The assembled record to serialise.</param>
    /// <param name="pool">The memory pool the produced octets' carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The write result.</returns>
    /// <remarks>
    /// <para>
    /// The document is written without inter-element whitespace, exactly as the records this binding's own
    /// canonicalization side is exercised against are written — <see cref="BuildSequencePrefix"/>'s remark
    /// records that a producer writing whitespace between chains would leave it behind in a renewal prefix, so
    /// this producer writes none.
    /// </para>
    /// <para>
    /// The <c>DigestValue</c> elements of every <c>Sequence</c> are emitted in binary ascending order of their
    /// decoded octets — clause 3.2.2's generation rule, ordered by the one primitive both syntaxes state
    /// identically (<see cref="EvidenceRecordHashTree.HashValueComparer"/>). What this example cannot write
    /// faithfully it refuses as <see cref="XmlEvidenceRecordWriteStatus.Unwritable"/> rather than approximates:
    /// a record stating <c>EncryptionInformation</c>, supporting information, per-member attributes,
    /// cryptographic information, or a time-stamp of any format but RFC 3161.
    /// </para>
    /// </remarks>
    public static ValueTask<XmlEvidenceRecordWriteResult> WriteAsync(
        XmlEvidenceRecordWriteContext context,
        BaseMemoryPool pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        XmlEvidenceRecord record = context.EvidenceRecord;
        if(record.HasEncryptionInformation || record.SupportingInformation.Count > 0)
        {
            return ValueTask.FromResult(XmlEvidenceRecordWriteResult.Failed(
                XmlEvidenceRecordWriteStatus.Unwritable,
                "This worked example writes neither EncryptionInformation (clause 5) nor SupportingInformation; a record stating them needs a fuller writer."));
        }

        var sequenceElement = new XElement(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.ArchiveTimeStampSequenceElementName);
        foreach(XmlEvidenceRecordArchiveTimeStampChain chain in record.Chains)
        {
            var chainElement = new XElement(
                EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.ArchiveTimeStampChainElementName,
                new XAttribute(XmlEvidenceRecordWellKnown.OrderAttributeName, chain.Order),
                new XElement(
                    EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.DigestMethodElementName,
                    new XAttribute(XmlEvidenceRecordWellKnown.AlgorithmAttributeName, chain.DigestMethodUri)),
                new XElement(
                    EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.CanonicalizationMethodElementName,
                    new XAttribute(XmlEvidenceRecordWellKnown.AlgorithmAttributeName, chain.CanonicalizationMethodUri)));

            foreach(XmlEvidenceRecordArchiveTimeStamp member in chain.ArchiveTimeStamps)
            {
                if(member.Attributes.Count > 0
                    || member.TimeStamp.CryptographicInformation.Count > 0
                    || !string.Equals(member.TimeStamp.TokenType, XmlEvidenceRecordWellKnown.Rfc3161TimeStampTokenType, StringComparison.Ordinal)
                    || member.TimeStamp.Rfc3161Token is null)
                {
                    return ValueTask.FromResult(XmlEvidenceRecordWriteResult.Failed(
                        XmlEvidenceRecordWriteStatus.Unwritable,
                        "This worked example writes RFC 3161 time-stamps without attributes or cryptographic information; a record stating more needs a fuller writer."));
                }

                var memberElement = new XElement(
                    EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.ArchiveTimeStampElementName,
                    new XAttribute(XmlEvidenceRecordWellKnown.OrderAttributeName, member.Order));
                if(member.HashTree is XmlEvidenceRecordHashTree hashTree)
                {
                    memberElement.Add(BuildHashTreeElement(hashTree));
                }

                memberElement.Add(new XElement(
                    EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.TimeStampElementName,
                    new XElement(
                        EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.TimeStampTokenElementName,
                        new XAttribute(XmlEvidenceRecordWellKnown.TypeAttributeName, member.TimeStamp.TokenType),
                        Convert.ToBase64String(member.TimeStamp.Rfc3161Token.AsReadOnlySpan()))));
                chainElement.Add(memberElement);
            }

            sequenceElement.Add(chainElement);
        }

        var document = new XDocument(new XElement(
            EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.EvidenceRecordElementName,
            new XAttribute(XmlEvidenceRecordWellKnown.VersionAttributeName, record.Version),
            sequenceElement));

        using var buffer = new MemoryStream();
        using(XmlWriter writer = XmlWriter.Create(buffer, new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
            OmitXmlDeclaration = false,
            Indent = false
        }))
        {
            document.Save(writer);
        }

        return ValueTask.FromResult(XmlEvidenceRecordWriteResult.Written(
            PooledMemory.FromBytes(buffer.GetBuffer().AsSpan(0, (int)buffer.Length), pool, XmlEvidenceRecordTags.EvidenceRecord)));


        //Builds one HashTree element: every Sequence in ascending Order, its DigestValue elements emitted in
        //binary ascending order of the decoded octets (clause 3.2.2's generation rule).
        static XElement BuildHashTreeElement(XmlEvidenceRecordHashTree hashTree)
        {
            var hashTreeElement = new XElement(EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.HashTreeElementName);
            foreach(XmlEvidenceRecordSequence sequence in hashTree.Sequences)
            {
                var values = new List<ReadOnlyMemory<byte>>(sequence.DigestValues.Count);
                foreach(DigestValue value in sequence.DigestValues)
                {
                    values.Add(value.AsReadOnlyMemory());
                }

                values.Sort(EvidenceRecordHashTree.HashValueComparer);

                var sequenceElement = new XElement(
                    EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.SequenceElementName,
                    new XAttribute(XmlEvidenceRecordWellKnown.OrderAttributeName, sequence.Order));
                foreach(ReadOnlyMemory<byte> value in values)
                {
                    sequenceElement.Add(new XElement(
                        EvidenceRecordNamespace + XmlEvidenceRecordWellKnown.DigestValueElementName,
                        Convert.ToBase64String(value.Span)));
                }

                hashTreeElement.Add(sequenceElement);
            }

            return hashTreeElement;
        }
    }
}
