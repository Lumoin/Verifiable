using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cryptography.Pki.Xml;

/// <summary>
/// A worked <see cref="ParseAsicManifestDelegate"/> and <see cref="EncodeAsicManifestDelegate"/> pair for the
/// <c>ASiCManifest</c> element, using <see cref="System.Xml.Linq"/> (BCL, no package) to move between the
/// serialisation-agnostic <see cref="AsicManifest"/> model and the schema
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2 states.
/// </summary>
/// <remarks>
/// <para>
/// This is a staged, promotable worked example, not a shipped library type: it lives beside
/// <c>TestInfrastructure</c>, never inside it, carries no test-framework type, and depends on nothing but the
/// BCL and <c>Verifiable.Cryptography.Pki</c> itself. Its namespace already names where a future package
/// would place it. The same shape carries <c>TrustedListXmlParser</c> for the Trusted List profile.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> A manifest arrives inside a container this library did not
/// produce and is not authenticated until the CAdES object or the time-stamp token naming it has been
/// verified, so the octets are treated as hostile: document type definitions are prohibited outright
/// (blocking entity expansion and external entity fetch), no external resource is ever resolved, and the one
/// particle of the schema whose depth a producer controls — an <c>Extension</c>'s <c>AnyType</c> content —
/// is walked with an explicit <see cref="Stack{T}"/> under
/// <see cref="AsicManifestParseLimits.MaximumElementDepth"/> rather than by a recursive method call.
/// </para>
/// <para>
/// <strong>The octets a manifest is stored as are the signed object.</strong> Annex A.4.1 makes a CAdES
/// object or time-stamp token named by <c>SigReference</c> apply "to the file containing the
/// <c>ASiCManifest</c> element", so <see cref="EncodeAsync"/> writes without indentation and a caller stores
/// what it returns verbatim. Re-encoding a manifest that has already been committed to produces a different
/// signed object even when the model is unchanged.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code (layering-split-ledger.md): public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
public static class AsicManifestXmlBinding
{
    /// <summary>
    /// The namespace Annex A.3's schema declares as its target, <c>http://uri.etsi.org/02918/v1.2.1#</c>. Its
    /// <c>elementFormDefault="qualified"</c> puts every element of a manifest in it.
    /// </summary>
    public static XNamespace AsicNamespace { get; } = "http://uri.etsi.org/02918/v1.2.1#";

    /// <summary>The XML Signature core namespace, which the ASiC schema imports to reach <c>ds:DigestMethod</c> and <c>ds:DigestValue</c>.</summary>
    private static XNamespace DigitalSignatureNamespace { get; } = XmlSignatureWellKnown.XmlSignatureNamespace;

    /// <summary>The root element's name, <c>ASiCManifest</c> (Annex A.4.2).</summary>
    private static XName ManifestElementName { get; } = AsicNamespace + "ASiCManifest";

    /// <summary>The <c>SigReference</c> element's name (Annex A.4.2).</summary>
    private static XName SignatureReferenceElementName { get; } = AsicNamespace + "SigReference";

    /// <summary>The <c>DataObjectReference</c> element's name (Annex A.4.2).</summary>
    private static XName DataObjectReferenceElementName { get; } = AsicNamespace + "DataObjectReference";

    /// <summary>The <c>ASiCManifestExtensions</c> element's name (Annex A.4.2).</summary>
    private static XName ManifestExtensionsElementName { get; } = AsicNamespace + "ASiCManifestExtensions";

    /// <summary>The <c>DataObjectReferenceExtensions</c> element's name (Annex A.4.2).</summary>
    private static XName DataObjectReferenceExtensionsElementName { get; } = AsicNamespace + "DataObjectReferenceExtensions";

    /// <summary>The <c>Extension</c> element's name (Annex A.4.2).</summary>
    private static XName ExtensionElementName { get; } = AsicNamespace + "Extension";

    /// <summary>The <c>ds:DigestMethod</c> element's name.</summary>
    private static XName DigestMethodElementName { get; } = DigitalSignatureNamespace + XmlSignatureWellKnown.DigestMethodElementName;

    /// <summary>The <c>ds:DigestValue</c> element's name.</summary>
    private static XName DigestValueElementName { get; } = DigitalSignatureNamespace + XmlSignatureWellKnown.DigestValueElementName;

    /// <summary>The <c>URI</c> attribute's name, unqualified per the schema's <c>attributeFormDefault</c>.</summary>
    private static XName UriAttributeName { get; } = "URI";

    /// <summary>The <c>MimeType</c> attribute's name.</summary>
    private static XName MimeTypeAttributeName { get; } = "MimeType";

    /// <summary>The <c>Rootfile</c> attribute's name.</summary>
    private static XName RootfileAttributeName { get; } = "Rootfile";

    /// <summary>The <c>Critical</c> attribute's name.</summary>
    private static XName CriticalAttributeName { get; } = "Critical";

    /// <summary>The <c>Algorithm</c> attribute's name, carried by <c>ds:DigestMethod</c>.</summary>
    private static XName AlgorithmAttributeName { get; } = XmlSignatureWellKnown.AlgorithmAttributeName;

    /// <summary>The encoding a manifest is written in: UTF-8 with no byte order mark, per clause 4.2 item 2 b.</summary>
    private static UTF8Encoding ManifestEncoding { get; } = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);


    /// <summary>
    /// Parses a manifest document into the <see cref="AsicManifest"/> model. Has the
    /// <see cref="ParseAsicManifestDelegate"/> shape.
    /// </summary>
    /// <param name="context">The document and the bounds to parse it under.</param>
    /// <param name="pool">The memory pool digest and extension carriers are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The parse result.</returns>
    public static ValueTask<AsicManifestParseResult> ParseAsync(AsicManifestParseContext context, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        AsicManifestParseLimits limits = context.Limits;
        ReadOnlySpan<byte> octets = context.Document.AsReadOnlySpan();
        if(octets.Length > limits.MaximumDocumentByteLength)
        {
            return ValueTask.FromResult(AsicManifestParseResult.Failed(
                AsicManifestParseStatus.LimitExceeded,
                $"The document is {octets.Length} octets, over the {limits.MaximumDocumentByteLength} the limits admit."));
        }

        XDocument xml;
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(octets.Length, 1));
        try
        {
            octets.CopyTo(rented);
            using var stream = new MemoryStream(rented, 0, octets.Length, writable: false);

            //Document type definitions are prohibited outright: the document is attacker-reachable and a
            //manifest has no legitimate use for an internal or external subset.
            var readerSettings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                CloseInput = false
            };

            using XmlReader reader = XmlReader.Create(stream, readerSettings);
            xml = XDocument.Load(reader, LoadOptions.None);
        }
        catch(Exception ex) when(ex is XmlException or InvalidOperationException or DecoderFallbackException)
        {
            return ValueTask.FromResult(AsicManifestParseResult.Failed(
                AsicManifestParseStatus.Malformed,
                $"The document is not well-formed XML: {ex.Message}"));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }

        XElement? root = xml.Root;
        if(root is null || root.Name != ManifestElementName)
        {
            return ValueTask.FromResult(AsicManifestParseResult.Failed(
                AsicManifestParseStatus.Malformed,
                $"Unexpected root element '{root?.Name.ToString() ?? "(none)"}'."));
        }

        if(!IsWithinDepthBound(root, limits.MaximumElementDepth))
        {
            return ValueTask.FromResult(AsicManifestParseResult.Failed(
                AsicManifestParseStatus.LimitExceeded,
                $"The document nests deeper than the {limits.MaximumElementDepth} elements the limits admit."));
        }

        return ValueTask.FromResult(ReadManifest(root, limits, pool));
    }


    /// <summary>
    /// Writes an <see cref="AsicManifest"/> as a manifest document. Has the
    /// <see cref="EncodeAsicManifestDelegate"/> shape.
    /// </summary>
    /// <param name="context">The manifest to write.</param>
    /// <param name="pool">The memory pool the produced document's carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encoding result.</returns>
    public static ValueTask<AsicManifestEncodeResult> EncodeAsync(AsicManifestEncodeContext context, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        AsicManifest manifest = context.Manifest;
        if(manifest.DataObjectReferences.Count == 0)
        {
            return ValueTask.FromResult(AsicManifestEncodeResult.Failed(
                AsicManifestEncodeStatus.NoDataObjectReferences,
                "Annex A.4.1 item 2 requires a manifest to reference one or more data files."));
        }

        if(!AsicContainerUri.Resolve(manifest.SignatureReference.Uri).IsResolved)
        {
            return ValueTask.FromResult(AsicManifestEncodeResult.Failed(
                AsicManifestEncodeStatus.InvalidUriReference,
                $"The signature reference '{manifest.SignatureReference.Uri}' does not name a container entry."));
        }

        //The XML Signature prefix is declared on the root so that ds:DigestMethod and ds:DigestValue serialise
        //under it rather than each carrying its own default-namespace declaration. Both forms are the same
        //information set; this one is what a reader of the octets sees in every manifest the specification
        //prints, and it is shorter, which matters because these octets are what a signature commits to.
        var root = new XElement(
            ManifestElementName,
            new XAttribute(XNamespace.Xmlns + "ds", DigitalSignatureNamespace.NamespaceName),
            new XElement(
                SignatureReferenceElementName,
                new XAttribute(UriAttributeName, manifest.SignatureReference.Uri),
                manifest.SignatureReference.MimeType is null ? null : new XAttribute(MimeTypeAttributeName, manifest.SignatureReference.MimeType)));

        foreach(AsicDataObjectReference reference in manifest.DataObjectReferences)
        {
            (AsicManifestEncodeStatus status, XElement? element) = WriteDataObjectReference(reference);
            if(element is null)
            {
                return ValueTask.FromResult(AsicManifestEncodeResult.Failed(status, $"The data object reference '{reference.Uri}' could not be written: {status}."));
            }

            root.Add(element);
        }

        if(manifest.Extensions.Count > 0)
        {
            (AsicManifestEncodeStatus status, XElement? extensions) = WriteExtensions(ManifestExtensionsElementName, manifest.Extensions);
            if(extensions is null)
            {
                return ValueTask.FromResult(AsicManifestEncodeResult.Failed(status, $"The manifest extensions could not be written: {status}."));
            }

            root.Add(extensions);
        }

        return ValueTask.FromResult(AsicManifestEncodeResult.Encoded(Serialize(root, pool)));
    }


    /// <summary>
    /// Reads the manifest under a validated root element.
    /// </summary>
    /// <param name="root">The <c>ASiCManifest</c> element.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <param name="pool">The memory pool carriers are rented from.</param>
    /// <returns>The parse result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every carrier built here transfers to the successful AsicManifestParseResult, which the caller disposes; the finally block disposes them on every path that does not transfer.")]
    private static AsicManifestParseResult ReadManifest(XElement root, AsicManifestParseLimits limits, BaseMemoryPool pool)
    {
        List<AsicDataObjectReference> references = [];
        List<AsicManifestExtension> manifestExtensions = [];
        bool owned = true;
        try
        {
            XElement? signatureReferenceElement = root.Element(SignatureReferenceElementName);
            if(signatureReferenceElement is null)
            {
                return AsicManifestParseResult.Failed(AsicManifestParseStatus.MissingRequiredElement, "The manifest carries no SigReference element.");
            }

            string? signatureReferenceUri = (string?)signatureReferenceElement.Attribute(UriAttributeName);
            if(signatureReferenceUri is null)
            {
                return AsicManifestParseResult.Failed(AsicManifestParseStatus.MissingRequiredElement, "The SigReference element carries no URI attribute.");
            }

            AsicContainerUriResolution signatureReferenceResolution = AsicContainerUri.Resolve(signatureReferenceUri, limits.MaximumUriLength);
            if(!signatureReferenceResolution.IsResolved)
            {
                return AsicManifestParseResult.Failed(
                    AsicManifestParseStatus.InvalidUriReference,
                    $"The SigReference URI '{signatureReferenceUri}' does not name a container entry: {signatureReferenceResolution.Status}.");
            }

            var signatureReference = new AsicSignatureReference
            {
                Uri = signatureReferenceUri,
                MimeType = (string?)signatureReferenceElement.Attribute(MimeTypeAttributeName)
            };

            foreach(XElement referenceElement in root.Elements(DataObjectReferenceElementName))
            {
                if(references.Count == limits.MaximumDataObjectReferences)
                {
                    return AsicManifestParseResult.Failed(
                        AsicManifestParseStatus.LimitExceeded,
                        $"The manifest carries more than the {limits.MaximumDataObjectReferences} data object references the limits admit.");
                }

                (AsicManifestParseStatus status, AsicDataObjectReference? reference, string reason) = ReadDataObjectReference(referenceElement, limits, pool);
                if(reference is null)
                {
                    return AsicManifestParseResult.Failed(status, reason);
                }

                references.Add(reference);
            }

            if(references.Count == 0)
            {
                return AsicManifestParseResult.Failed(
                    AsicManifestParseStatus.MissingRequiredElement,
                    "The manifest carries no DataObjectReference element; Annex A.4.1 item 2 requires one or more.");
            }

            (AsicManifestParseStatus extensionsStatus, string extensionsReason) = ReadExtensions(
                root.Element(ManifestExtensionsElementName), limits, pool, manifestExtensions);
            if(extensionsStatus != AsicManifestParseStatus.Valid)
            {
                return AsicManifestParseResult.Failed(extensionsStatus, extensionsReason);
            }

            var manifest = new AsicManifest
            {
                SignatureReference = signatureReference,
                DataObjectReferences = references,
                Extensions = manifestExtensions
            };

            owned = false;

            return AsicManifestParseResult.Valid(manifest);
        }
        finally
        {
            if(owned)
            {
                foreach(AsicDataObjectReference reference in references)
                {
                    reference.Dispose();
                }

                foreach(AsicManifestExtension extension in manifestExtensions)
                {
                    extension.Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Reads one <c>DataObjectReference</c> element.
    /// </summary>
    /// <param name="referenceElement">The element to read.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <param name="pool">The memory pool carriers are rented from.</param>
    /// <returns>The status, the reference when it was read, and the reason when it was not.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the digest and of every extension transfers to the returned AsicDataObjectReference, or is released on the failure paths before returning.")]
    private static (AsicManifestParseStatus Status, AsicDataObjectReference? Reference, string Reason) ReadDataObjectReference(
        XElement referenceElement,
        AsicManifestParseLimits limits,
        BaseMemoryPool pool)
    {
        string? uri = (string?)referenceElement.Attribute(UriAttributeName);
        if(uri is null)
        {
            return (AsicManifestParseStatus.MissingRequiredElement, null, "A DataObjectReference element carries no URI attribute.");
        }

        AsicContainerUriResolution resolution = AsicContainerUri.Resolve(uri, limits.MaximumUriLength);
        if(!resolution.IsResolved)
        {
            return (AsicManifestParseStatus.InvalidUriReference, null, $"The DataObjectReference URI '{uri}' does not name a container entry: {resolution.Status}.");
        }

        XElement? digestMethodElement = referenceElement.Element(DigestMethodElementName);
        if(digestMethodElement is null)
        {
            return (AsicManifestParseStatus.MissingRequiredElement, null, $"The DataObjectReference for '{uri}' carries no ds:DigestMethod element.");
        }

        string? algorithmUri = (string?)digestMethodElement.Attribute(AlgorithmAttributeName);
        if(algorithmUri is null)
        {
            return (AsicManifestParseStatus.MissingRequiredElement, null, $"The ds:DigestMethod for '{uri}' carries no Algorithm attribute.");
        }

        PkiDigestAlgorithm? algorithm = XmlSignatureWellKnown.DigestAlgorithmFromUri(algorithmUri);
        if(algorithm is null)
        {
            return (AsicManifestParseStatus.UnsupportedDigestAlgorithm, null, $"The ds:DigestMethod for '{uri}' names '{algorithmUri}', which this library does not compute.");
        }

        XElement? digestValueElement = referenceElement.Element(DigestValueElementName);
        if(digestValueElement is null)
        {
            return (AsicManifestParseStatus.MissingRequiredElement, null, $"The DataObjectReference for '{uri}' carries no ds:DigestValue element.");
        }

        bool? isRootFile = null;
        XAttribute? rootfileAttribute = referenceElement.Attribute(RootfileAttributeName);
        if(rootfileAttribute is not null)
        {
            try
            {
                isRootFile = XmlConvert.ToBoolean(rootfileAttribute.Value.Trim());
            }
            catch(FormatException)
            {
                return (AsicManifestParseStatus.Malformed, null, $"The Rootfile attribute of '{uri}' is not an xsd:boolean.");
            }
        }

        DigestValue? digest = ReadDigestValue(digestValueElement.Value, algorithm.Value, pool);
        if(digest is null)
        {
            return (AsicManifestParseStatus.DigestValueMalformed, null, $"The ds:DigestValue for '{uri}' is not {algorithm.Value.OutputByteLength} octets of base64.");
        }

        List<AsicManifestExtension> extensions = [];
        (AsicManifestParseStatus extensionsStatus, string extensionsReason) = ReadExtensions(
            referenceElement.Element(DataObjectReferenceExtensionsElementName), limits, pool, extensions);
        if(extensionsStatus != AsicManifestParseStatus.Valid)
        {
            digest.Dispose();
            foreach(AsicManifestExtension extension in extensions)
            {
                extension.Dispose();
            }

            return (extensionsStatus, null, extensionsReason);
        }

        var reference = new AsicDataObjectReference
        {
            Uri = uri,
            DigestAlgorithm = algorithm.Value,
            Digest = digest,
            MimeType = (string?)referenceElement.Attribute(MimeTypeAttributeName),
            IsRootFile = isRootFile,
            Extensions = extensions
        };

        return (AsicManifestParseStatus.Valid, reference, string.Empty);
    }


    /// <summary>
    /// Reads the <c>Extension</c> children of an extensions list element into <paramref name="into"/>.
    /// </summary>
    /// <param name="listElement">The extensions list element, or <see langword="null"/> when the document carried none.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <param name="pool">The memory pool extension carriers are rented from.</param>
    /// <param name="into">The list the extensions are added to; the caller owns what it receives.</param>
    /// <returns>The status and, when it is not <see cref="AsicManifestParseStatus.Valid"/>, the reason.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of each extension transfers to the caller-supplied list, which the caller disposes on both the success and the failure path.")]
    private static (AsicManifestParseStatus Status, string Reason) ReadExtensions(
        XElement? listElement,
        AsicManifestParseLimits limits,
        BaseMemoryPool pool,
        List<AsicManifestExtension> into)
    {
        if(listElement is null)
        {
            return (AsicManifestParseStatus.Valid, string.Empty);
        }

        foreach(XElement extensionElement in listElement.Elements(ExtensionElementName))
        {
            if(into.Count == limits.MaximumExtensions)
            {
                return (AsicManifestParseStatus.LimitExceeded, $"An extensions list carries more than the {limits.MaximumExtensions} extensions the limits admit.");
            }

            XAttribute? criticalAttribute = extensionElement.Attribute(CriticalAttributeName);
            if(criticalAttribute is null)
            {
                return (AsicManifestParseStatus.MissingRequiredElement, "An Extension element carries no Critical attribute, which Annex A.4.2 declares required.");
            }

            bool critical;
            try
            {
                critical = XmlConvert.ToBoolean(criticalAttribute.Value.Trim());
            }
            catch(FormatException)
            {
                return (AsicManifestParseStatus.Malformed, "An Extension element's Critical attribute is not an xsd:boolean.");
            }

            string serialized = extensionElement.ToString(SaveOptions.DisableFormatting);
            int octetCount = ManifestEncoding.GetByteCount(serialized);
            if(octetCount > limits.MaximumExtensionByteLength)
            {
                return (AsicManifestParseStatus.LimitExceeded, $"An Extension element is {octetCount} octets, over the {limits.MaximumExtensionByteLength} the limits admit.");
            }

            XElement? content = FirstChildElement(extensionElement);
            byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(octetCount, 1));
            try
            {
                int written = ManifestEncoding.GetBytes(serialized, rented);
                into.Add(new AsicManifestExtension
                {
                    Critical = critical,
                    ElementNamespace = content?.Name.NamespaceName,
                    ElementName = content?.Name.LocalName,
                    Content = PooledMemory.FromBytes(rented.AsSpan(0, written), pool, AsicTags.ManifestExtension)
                });
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
            }
        }

        return (AsicManifestParseStatus.Valid, string.Empty);
    }


    /// <summary>
    /// Decodes a <c>ds:DigestValue</c> element's base64 content into a digest carrier.
    /// </summary>
    /// <param name="value">The element's text content.</param>
    /// <param name="algorithm">The algorithm the value is stated under.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The carrier, or <see langword="null"/> when the content is not exactly one digest of base64.</returns>
    /// <remarks>
    /// The length is checked against the algorithm rather than accepted as whatever decodes, because a digest
    /// of the wrong length can never equal a recomputation and the clause 4.4.4.2 item d comparison is
    /// unconditional — a producer that stated one has stated something no verifier can act on.
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
    /// Writes one <c>DataObjectReference</c> element in the order Annex A.4.2's sequence states.
    /// </summary>
    /// <param name="reference">The reference to write.</param>
    /// <returns>The status and, when it is <see cref="AsicManifestEncodeStatus.Encoded"/>, the element.</returns>
    private static (AsicManifestEncodeStatus Status, XElement? Element) WriteDataObjectReference(AsicDataObjectReference reference)
    {
        if(!AsicContainerUri.Resolve(reference.Uri).IsResolved)
        {
            return (AsicManifestEncodeStatus.InvalidUriReference, null);
        }

        string? algorithmUri = XmlSignatureWellKnown.DigestUriFromAlgorithm(reference.DigestAlgorithm);
        if(algorithmUri is null)
        {
            return (AsicManifestEncodeStatus.UnsupportedDigestAlgorithm, null);
        }

        if(reference.Digest.Length != reference.DigestAlgorithm.OutputByteLength)
        {
            return (AsicManifestEncodeStatus.DigestValueMalformed, null);
        }

        var element = new XElement(
            DataObjectReferenceElementName,
            new XAttribute(UriAttributeName, reference.Uri),
            reference.MimeType is null ? null : new XAttribute(MimeTypeAttributeName, reference.MimeType),
            reference.IsRootFile is null ? null : new XAttribute(RootfileAttributeName, XmlConvert.ToString(reference.IsRootFile.Value)),
            new XElement(DigestMethodElementName, new XAttribute(AlgorithmAttributeName, algorithmUri)),
            new XElement(DigestValueElementName, Convert.ToBase64String(reference.Digest.AsReadOnlySpan())));

        if(reference.Extensions.Count > 0)
        {
            (AsicManifestEncodeStatus status, XElement? extensions) = WriteExtensions(DataObjectReferenceExtensionsElementName, reference.Extensions);
            if(extensions is null)
            {
                return (status, null);
            }

            element.Add(extensions);
        }

        return (AsicManifestEncodeStatus.Encoded, element);
    }


    /// <summary>
    /// Writes an extensions list element from the carried octets of each extension.
    /// </summary>
    /// <param name="listElementName">Which of the two extensions list elements to write.</param>
    /// <param name="extensions">The extensions to write.</param>
    /// <returns>The status and, when it is <see cref="AsicManifestEncodeStatus.Encoded"/>, the element.</returns>
    private static (AsicManifestEncodeStatus Status, XElement? Element) WriteExtensions(XName listElementName, IReadOnlyList<AsicManifestExtension> extensions)
    {
        var listElement = new XElement(listElementName);
        foreach(AsicManifestExtension extension in extensions)
        {
            XElement? extensionElement = ReadExtensionElement(extension);
            if(extensionElement is null || extensionElement.Name != ExtensionElementName)
            {
                return (AsicManifestEncodeStatus.ExtensionMalformed, null);
            }

            listElement.Add(extensionElement);
        }

        return (AsicManifestEncodeStatus.Encoded, listElement);
    }


    /// <summary>
    /// Reads an extension's carried octets back into an element.
    /// </summary>
    /// <param name="extension">The extension whose content is to be read.</param>
    /// <returns>The element, or <see langword="null"/> when the octets are not one well-formed element.</returns>
    private static XElement? ReadExtensionElement(AsicManifestExtension extension)
    {
        try
        {
            string text = ManifestEncoding.GetString(extension.Content.AsReadOnlySpan());
            var readerSettings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                CloseInput = false
            };

            using var textReader = new StringReader(text);
            using XmlReader reader = XmlReader.Create(textReader, readerSettings);

            return XElement.Load(reader, LoadOptions.None);
        }
        catch(Exception ex) when(ex is XmlException or InvalidOperationException or DecoderFallbackException)
        {
            return null;
        }
    }


    /// <summary>
    /// Serialises a manifest's root element into a pooled carrier.
    /// </summary>
    /// <param name="root">The <c>ASiCManifest</c> element to write.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The produced octets. The caller owns and disposes them.</returns>
    private static PooledMemory Serialize(XElement root, BaseMemoryPool pool)
    {
        var writerSettings = new XmlWriterSettings
        {
            Encoding = ManifestEncoding,
            Indent = false,
            OmitXmlDeclaration = false,
            NewLineHandling = NewLineHandling.None,
            CloseOutput = false
        };

        using var stream = new MemoryStream();
        using(XmlWriter writer = XmlWriter.Create(stream, writerSettings))
        {
            root.WriteTo(writer);
        }

        return stream.TryGetBuffer(out ArraySegment<byte> buffer)
            ? PooledMemory.FromBytes(buffer.AsSpan(), pool, AsicTags.Manifest)
            : PooledMemory.FromBytes(stream.ToArray(), pool, AsicTags.Manifest);
    }


    /// <summary>
    /// Determines whether an element tree stays within a nesting bound, walking it with an explicit
    /// <see cref="Stack{T}"/> rather than recursively.
    /// </summary>
    /// <param name="root">The element to walk.</param>
    /// <param name="maximumDepth">The deepest nesting admitted, counting <paramref name="root"/> as depth one.</param>
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
    /// Returns an element's first child element, or <see langword="null"/> when it has none.
    /// </summary>
    /// <param name="element">The element to look under.</param>
    /// <returns>The first child element, or <see langword="null"/>.</returns>
    private static XElement? FirstChildElement(XElement element)
    {
        foreach(XElement child in element.Elements())
        {
            return child;
        }

        return null;
    }
}
