using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cryptography.Pki.Xml;

/// <summary>
/// A worked implementation of <see cref="EncodePreservationAsicExtensionDelegate"/> and
/// <see cref="ParsePreservationAsicExtensionDelegate"/> — the seven container-extension payloads of clause 5.5 of
/// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119512/01.02.01_60/ts_119512v010201p.pdf">
/// ETSI TS 119 512 V1.2.1</see>, written into and read out of an <c>Extension</c> element of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see> Annex A.4.2.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Why this lives test-side.</strong> An <c>Extension</c>'s content is markup and
/// <c>Verifiable.Cryptography</c> references no XML package, so the seam is declared there and implemented here,
/// exactly as <see cref="AsicManifestXmlBinding"/> and the message binding beside it already are. Its namespace
/// already names where a future XML-binding package would live.
/// </para>
/// <para>
/// <strong>The element names are the library's, never spelled here.</strong> Every name comes from
/// <see cref="PreservationAsicExtensionWellKnown"/> and every preservation-object member name from
/// <see cref="PreservationObjectParameterNames"/>, so a name this binding writes is a name the specification's
/// own table states.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> An extension arrives inside a container a peer produced: document
/// type definitions are prohibited, no resolver is supplied, the octet bound is applied before anything is
/// parsed, and the depth bound is checked by walking with an explicit <see cref="Stack{T}"/>.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code: public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
[SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
    Justification = "Ownership of an extension this binding writes transfers to the returned encode result, and ownership of a payload it reads transfers to the returned parse result; the caller disposes the result, which disposes what it owns.")]
public static class PreservationAsicExtensionXmlBinding
{
    /// <summary>The namespace Annex A.3 of the container specification declares as its target — the one an <c>Extension</c> element itself sits in.</summary>
    public static XNamespace AsicNamespace { get; } = "http://uri.etsi.org/02918/v1.2.1#";

    /// <summary>The preservation protocol's own namespace, which the six extensions this document declares sit in.</summary>
    public static XNamespace PreservationNamespace { get; } = PreservationWellKnown.PreservationNamespace;

    /// <summary>The <c>Extension</c> element name.</summary>
    public static XName ExtensionElementName { get; } = AsicNamespace + "Extension";

    /// <summary>The <c>Critical</c> attribute name, which Annex A.4.2 makes required on every extension.</summary>
    public static XName CriticalAttributeName { get; } = "Critical";

    /// <summary>The encoding an extension is written in.</summary>
    private static Encoding ExtensionEncoding { get; } = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);


    /// <summary>
    /// Writes one payload as an <c>Extension</c> element. Has the
    /// <see cref="EncodePreservationAsicExtensionDelegate"/> shape.
    /// </summary>
    /// <param name="context">The payload to write and how to write it.</param>
    /// <param name="pool">The memory pool the extension's carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encoding result.</returns>
    public static ValueTask<PreservationAsicExtensionEncodeResult> EncodeAsync(
        PreservationAsicExtensionEncodeContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        PreservationAsicExtensionPayload payload = context.Payload;
        if(payload.Kind == PreservationAsicExtensionKind.CanonicalizationMethod && context.CanonicalizationMethodNamespace is null)
        {
            return ValueTask.FromResult(PreservationAsicExtensionEncodeResult.Failed(
                PreservationAsicExtensionEncodeStatus.CanonicalizationMethodNamespaceNotStated,
                "Clause 5.5.2.5.2 defines the CanonicalizationMethod element in an external schema; state the namespace it is written under."));
        }

        (PreservationAsicExtensionEncodeStatus status, XElement? content) = WriteContent(payload, context);
        if(content is null)
        {
            return ValueTask.FromResult(PreservationAsicExtensionEncodeResult.Failed(
                status,
                $"The payload '{payload.Kind}' could not be written: {status}."));
        }

        bool critical = context.Critical ?? PreservationAsicExtensionWellKnown.IsCriticalRecommended(payload.Kind);
        var element = new XElement(
            ExtensionElementName,
            new XAttribute(CriticalAttributeName, critical ? "true" : "false"),
            content);

        byte[] octets = Serialize(element);
        if(octets.Length > context.Limits.MaximumExtensionByteLength)
        {
            return ValueTask.FromResult(PreservationAsicExtensionEncodeResult.Failed(
                PreservationAsicExtensionEncodeStatus.LimitExceeded,
                $"The extension is {octets.Length} octets, over the {context.Limits.MaximumExtensionByteLength} the limits admit."));
        }

        var extension = new AsicManifestExtension
        {
            Critical = critical,
            ElementNamespace = content.Name.NamespaceName,
            ElementName = content.Name.LocalName,
            Content = PooledMemory.FromBytes(octets, pool, PreservationTags.AsicExtension)
        };

        return ValueTask.FromResult(PreservationAsicExtensionEncodeResult.Encoded(extension));
    }


    /// <summary>
    /// Reads one payload out of an <c>Extension</c> element. Has the
    /// <see cref="ParsePreservationAsicExtensionDelegate"/> shape.
    /// </summary>
    /// <param name="context">The extension to read and the bounds to read it under.</param>
    /// <param name="pool">The memory pool a payload's carriers are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The parse result.</returns>
    public static ValueTask<PreservationAsicExtensionParseResult> ParseAsync(
        PreservationAsicExtensionParseContext context,
        MemoryPool<byte> pool,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        PreservationAsicExtensionLimits limits = context.Limits;
        ReadOnlySpan<byte> octets = context.Extension.Content.AsReadOnlySpan();
        if(octets.Length > limits.MaximumExtensionByteLength)
        {
            return ValueTask.FromResult(PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.LimitExceeded,
                $"The extension is {octets.Length} octets, over the {limits.MaximumExtensionByteLength} the limits admit."));
        }

        XElement root;
        try
        {
            root = ReadElement(octets);
        }
        catch(Exception ex) when(ex is XmlException or InvalidOperationException or DecoderFallbackException)
        {
            return ValueTask.FromResult(PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.Malformed,
                $"The extension is not well-formed XML: {ex.Message}"));
        }

        if(root.Name != ExtensionElementName)
        {
            return ValueTask.FromResult(PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.Malformed,
                $"Unexpected root element '{root.Name}'."));
        }

        if(!IsWithinDepthBound(root, limits.MaximumDepth))
        {
            return ValueTask.FromResult(PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.LimitExceeded,
                $"The extension nests deeper than the {limits.MaximumDepth} elements the limits admit."));
        }

        XElement? content = null;
        foreach(XElement child in root.Elements())
        {
            content = child;

            break;
        }

        if(content is null)
        {
            return ValueTask.FromResult(PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.PayloadNotRecognized,
                "The extension carries no content element."));
        }

        var name = new AsicManifestExtensionName(content.Name.NamespaceName, content.Name.LocalName);
        PreservationAsicExtensionKind kind = context.CanonicalizationMethodNamespace is string canonicalizationNamespace
            ? PreservationAsicExtensionWellKnown.KindOf(name, canonicalizationNamespace)
            : PreservationAsicExtensionWellKnown.KindOf(name);

        if(kind == PreservationAsicExtensionKind.None)
        {
            return ValueTask.FromResult(PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.PayloadNotRecognized,
                $"'{content.Name}' is not a payload clause 5.5 states."));
        }

        return ValueTask.FromResult(ReadPayload(kind, content, root, limits, pool));
    }


    /// <summary>
    /// Writes the content element of one payload.
    /// </summary>
    /// <param name="payload">The payload to write.</param>
    /// <param name="context">The encoding context, which states the canonicalization method's namespace.</param>
    /// <returns>The status and the element, of which the element is <see langword="null"/> on a refusal.</returns>
    private static (PreservationAsicExtensionEncodeStatus Status, XElement? Content) WriteContent(
        PreservationAsicExtensionPayload payload,
        PreservationAsicExtensionEncodeContext context) => payload switch
        {
            PreservationContainerIdExtension containerId => WriteContainerId(containerId),
            PreservationPeriodExtension period => (
                PreservationAsicExtensionEncodeStatus.Encoded,
                new XElement(
                    PreservationNamespace + PreservationAsicExtensionWellKnown.PreservationPeriodElementName,
                    period.Period.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture))),
            PreservationSubmitterExtension submitter => (
                PreservationAsicExtensionEncodeStatus.Encoded,
                new XElement(
                    PreservationNamespace + PreservationAsicExtensionWellKnown.PreservationSubmitterElementName,
                    submitter.Submitter)),
            PreservationIsUpdatedVersionOfExtension updated => (
                PreservationAsicExtensionEncodeStatus.Encoded,
                new XElement(
                    PreservationNamespace + PreservationAsicExtensionWellKnown.IsUpdatedVersionOfElementName,
                    updated.Reference)),
            PreservationCanonicalizationMethodExtension canonicalization => (
                PreservationAsicExtensionEncodeStatus.Encoded,
                new XElement(
                    XNamespace.Get(context.CanonicalizationMethodNamespace!) + PreservationAsicExtensionWellKnown.CanonicalizationMethodElementName,
                    new XAttribute("Algorithm", canonicalization.Algorithm))),
            PreservationValidationReportExtension report => WriteValidationReport(report),
            PreservationIsMetaDataOfExtension metadata => (
                PreservationAsicExtensionEncodeStatus.Encoded,
                new XElement(
                    PreservationNamespace + PreservationAsicExtensionWellKnown.IsMetaDataOfElementName,
                    metadata.Reference)),
            _ => (PreservationAsicExtensionEncodeStatus.PayloadNotSupported, null)
        };


    /// <summary>
    /// Writes the <c>ContainerID</c> element, whose <c>POID</c> child clause 5.5.2.1.1 makes mandatory.
    /// </summary>
    /// <param name="containerId">The payload.</param>
    /// <returns>The status and the element.</returns>
    private static (PreservationAsicExtensionEncodeStatus Status, XElement? Content) WriteContainerId(PreservationContainerIdExtension containerId)
    {
        if(containerId.PreservationObjectId.Length == 0)
        {
            return (PreservationAsicExtensionEncodeStatus.MissingRequiredElement, null);
        }

        var element = new XElement(
            PreservationNamespace + PreservationAsicExtensionWellKnown.ContainerIdElementName,
            new XElement(PreservationNamespace + PreservationAsicExtensionWellKnown.PreservationObjectIdElementName, containerId.PreservationObjectId));

        if(containerId.VersionId is string versionId)
        {
            element.Add(new XElement(PreservationNamespace + PreservationAsicExtensionWellKnown.VersionIdElementName, versionId));
        }

        return (PreservationAsicExtensionEncodeStatus.Encoded, element);
    }


    /// <summary>
    /// Writes the <c>ValidationReport</c> element, which clause 5.5.2.6.2 requires to satisfy clause 5.4.5 — the
    /// preservation object component, whose member names are the library's own registry's.
    /// </summary>
    /// <param name="report">The payload.</param>
    /// <returns>The status and the element.</returns>
    private static (PreservationAsicExtensionEncodeStatus Status, XElement? Content) WriteValidationReport(PreservationValidationReportExtension report)
    {
        PreservationObject preservationObject = report.Report;
        if(preservationObject.FormatId is null && preservationObject.MimeType is null)
        {
            //Clause 5.4.5.1 makes the media type mandatory whenever the format identifier is omitted, so an
            //object stating neither is one no conformant document can carry.
            return (PreservationAsicExtensionEncodeStatus.MissingRequiredElement, null);
        }

        var element = new XElement(PreservationNamespace + PreservationAsicExtensionWellKnown.ValidationReportElementName);
        if(preservationObject.FormatId is string formatId)
        {
            element.Add(new XAttribute(PreservationObjectParameterNames.FormatId.XmlElementName, formatId));
        }

        if(preservationObject.MimeType is string mimeType)
        {
            element.Add(new XAttribute(PreservationObjectParameterNames.MimeType.XmlElementName, mimeType));
        }

        element.Add(new XElement(
            PreservationNamespace + PreservationObjectParameterNames.BinaryData.XmlElementName,
            Convert.ToBase64String(preservationObject.Content.AsReadOnlySpan())));

        return (PreservationAsicExtensionEncodeStatus.Encoded, element);
    }


    /// <summary>
    /// Reads the payload one recognised content element carries.
    /// </summary>
    /// <param name="kind">Which payload the element's name classified it as.</param>
    /// <param name="content">The content element.</param>
    /// <param name="extension">The <c>Extension</c> element, which carries the criticality.</param>
    /// <param name="limits">The bounds values are read under.</param>
    /// <param name="pool">The memory pool a payload's carriers are rented from.</param>
    /// <returns>The parse result.</returns>
    private static PreservationAsicExtensionParseResult ReadPayload(
        PreservationAsicExtensionKind kind,
        XElement content,
        XElement extension,
        PreservationAsicExtensionLimits limits,
        MemoryPool<byte> pool)
    {
        bool critical = string.Equals(extension.Attribute(CriticalAttributeName)?.Value, "true", StringComparison.Ordinal);
        PreservationAsicExtensionCriticality criticality = PreservationAsicExtensionWellKnown.StateCriticality(kind, critical);

        return kind switch
        {
            PreservationAsicExtensionKind.ContainerId => ReadContainerId(content, criticality, limits),
            PreservationAsicExtensionKind.PreservationPeriod => ReadPeriod(content, criticality, limits),
            PreservationAsicExtensionKind.PreservationSubmitter => ReadValue(
                content, limits, static value => new PreservationSubmitterExtension { Submitter = value }, criticality),
            PreservationAsicExtensionKind.IsUpdatedVersionOf => ReadValue(
                content, limits, static value => new PreservationIsUpdatedVersionOfExtension { Reference = value }, criticality),
            PreservationAsicExtensionKind.CanonicalizationMethod => ReadCanonicalizationMethod(content, criticality, limits),
            PreservationAsicExtensionKind.ValidationReport => ReadValidationReport(content, criticality, limits, pool),
            PreservationAsicExtensionKind.IsMetaDataOf => ReadValue(
                content, limits, static value => new PreservationIsMetaDataOfExtension { Reference = value }, criticality),
            _ => PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.PayloadNotRecognized,
                $"'{kind}' is not a payload clause 5.5 states.")
        };
    }


    /// <summary>
    /// Reads a payload whose whole content is one text value.
    /// </summary>
    /// <param name="content">The content element.</param>
    /// <param name="limits">The bounds the value is read under.</param>
    /// <param name="build">Builds the payload from the value read.</param>
    /// <param name="criticality">What the extension stated about its criticality.</param>
    /// <returns>The parse result.</returns>
    private static PreservationAsicExtensionParseResult ReadValue(
        XElement content,
        PreservationAsicExtensionLimits limits,
        Func<string, PreservationAsicExtensionPayload> build,
        PreservationAsicExtensionCriticality criticality)
    {
        string value = content.Value;

        return value.Length switch
        {
            0 => PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.MissingRequiredElement,
                $"'{content.Name.LocalName}' carries no value."),
            var length when length > limits.MaximumValueLength => PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.LimitExceeded,
                $"'{content.Name.LocalName}' carries {length} characters, over the {limits.MaximumValueLength} the limits admit."),
            _ => PreservationAsicExtensionParseResult.Valid(build(value), criticality)
        };
    }


    /// <summary>
    /// Reads the <c>ContainerID</c> payload.
    /// </summary>
    /// <param name="content">The content element.</param>
    /// <param name="criticality">What the extension stated about its criticality.</param>
    /// <param name="limits">The bounds values are read under.</param>
    /// <returns>The parse result.</returns>
    private static PreservationAsicExtensionParseResult ReadContainerId(
        XElement content,
        PreservationAsicExtensionCriticality criticality,
        PreservationAsicExtensionLimits limits)
    {
        string? preservationObjectId = content
            .Element(PreservationNamespace + PreservationAsicExtensionWellKnown.PreservationObjectIdElementName)?.Value;

        if(string.IsNullOrEmpty(preservationObjectId))
        {
            return PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.MissingRequiredElement,
                "Clause 5.5.2.1.1 makes the POID element mandatory within the ContainerID component.");
        }

        string? versionId = content
            .Element(PreservationNamespace + PreservationAsicExtensionWellKnown.VersionIdElementName)?.Value;

        if(preservationObjectId.Length > limits.MaximumValueLength || versionId?.Length > limits.MaximumValueLength)
        {
            return PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.LimitExceeded,
                $"A ContainerID value is over the {limits.MaximumValueLength} characters the limits admit.");
        }

        return PreservationAsicExtensionParseResult.Valid(
            new PreservationContainerIdExtension
            {
                PreservationObjectId = preservationObjectId,
                VersionId = string.IsNullOrEmpty(versionId) ? null : versionId
            },
            criticality);
    }


    /// <summary>
    /// Reads the <c>PreservationPeriod</c> payload, whose schema type is a calendar date.
    /// </summary>
    /// <param name="content">The content element.</param>
    /// <param name="criticality">What the extension stated about its criticality.</param>
    /// <param name="limits">The bounds the value is read under.</param>
    /// <returns>The parse result.</returns>
    private static PreservationAsicExtensionParseResult ReadPeriod(
        XElement content,
        PreservationAsicExtensionCriticality criticality,
        PreservationAsicExtensionLimits limits)
    {
        string value = content.Value;
        if(value.Length == 0 || value.Length > limits.MaximumValueLength)
        {
            return PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.MissingRequiredElement,
                "Clause 5.5.2.2.1 makes the PreservationPeriod element carry the preservation period.");
        }

        return DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out DateOnly period)
            ? PreservationAsicExtensionParseResult.Valid(new PreservationPeriodExtension { Period = period }, criticality)
            : PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.MalformedValue,
                $"'{value}' is not a date, which is the schema type clause 5.5.2.2.2 gives the element.");
    }


    /// <summary>
    /// Reads the <c>CanonicalizationMethod</c> payload, whose algorithm rides in an attribute.
    /// </summary>
    /// <param name="content">The content element.</param>
    /// <param name="criticality">What the extension stated about its criticality.</param>
    /// <param name="limits">The bounds the value is read under.</param>
    /// <returns>The parse result.</returns>
    private static PreservationAsicExtensionParseResult ReadCanonicalizationMethod(
        XElement content,
        PreservationAsicExtensionCriticality criticality,
        PreservationAsicExtensionLimits limits)
    {
        string? algorithm = content.Attribute("Algorithm")?.Value;
        if(string.IsNullOrEmpty(algorithm))
        {
            return PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.MissingRequiredElement,
                "The canonicalization method names no algorithm.");
        }

        return algorithm.Length > limits.MaximumValueLength
            ? PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.LimitExceeded,
                $"The algorithm is {algorithm.Length} characters, over the {limits.MaximumValueLength} the limits admit.")
            : PreservationAsicExtensionParseResult.Valid(
                new PreservationCanonicalizationMethodExtension { Algorithm = algorithm }, criticality);
    }


    /// <summary>
    /// Reads the <c>ValidationReport</c> payload, which is the preservation object component of clause 5.4.5.
    /// </summary>
    /// <param name="content">The content element.</param>
    /// <param name="criticality">What the extension stated about its criticality.</param>
    /// <param name="limits">The bounds values are read under.</param>
    /// <param name="pool">The memory pool the report's carrier is rented from.</param>
    /// <returns>The parse result.</returns>
    private static PreservationAsicExtensionParseResult ReadValidationReport(
        XElement content,
        PreservationAsicExtensionCriticality criticality,
        PreservationAsicExtensionLimits limits,
        MemoryPool<byte> pool)
    {
        XElement? binaryData = content.Element(PreservationNamespace + PreservationObjectParameterNames.BinaryData.XmlElementName);
        if(binaryData is null)
        {
            return PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.MissingRequiredElement,
                "Clause 5.4.5.1 requires one instance of the value choice, of which this binding writes and reads the binary alternative.");
        }

        string? formatId = content.Attribute(PreservationObjectParameterNames.FormatId.XmlElementName)?.Value;
        string? mimeType = content.Attribute(PreservationObjectParameterNames.MimeType.XmlElementName)?.Value;
        if(formatId is null && mimeType is null)
        {
            return PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.MissingRequiredElement,
                "Clause 5.4.5.1 makes the MimeType element mandatory whenever the FormatId element is omitted.");
        }

        byte[] octets;
        try
        {
            octets = Convert.FromBase64String(binaryData.Value);
        }
        catch(FormatException)
        {
            return PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.MalformedValue,
                "The report's value is not base-64 encoded binary data.");
        }

        if(octets.Length > limits.MaximumExtensionByteLength)
        {
            return PreservationAsicExtensionParseResult.Failed(
                PreservationAsicExtensionParseStatus.LimitExceeded,
                $"The report is {octets.Length} octets, over the {limits.MaximumExtensionByteLength} the limits admit.");
        }

        var report = new PreservationObject
        {
            Content = PooledMemory.FromBytes(octets, pool, PreservationTags.PreservationObject),
            ContentForm = PreservationContentForm.BinaryData,
            FormatId = formatId,
            MimeType = mimeType
        };

        return PreservationAsicExtensionParseResult.Valid(
            new PreservationValidationReportExtension { Report = report }, criticality);
    }


    /// <summary>
    /// Reads an element out of octets, with document type definitions prohibited and no resolver supplied.
    /// </summary>
    /// <param name="octets">The extension's octets.</param>
    /// <returns>The parsed element.</returns>
    private static XElement ReadElement(ReadOnlySpan<byte> octets)
    {
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(octets.Length, 1));
        try
        {
            octets.CopyTo(rented);
            using var stream = new MemoryStream(rented, 0, octets.Length, writable: false);
            var readerSettings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                CloseInput = false
            };

            using XmlReader reader = XmlReader.Create(stream, readerSettings);

            return XElement.Load(reader, LoadOptions.None);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }


    /// <summary>
    /// Writes one element as octets.
    /// </summary>
    /// <param name="element">The element to write.</param>
    /// <returns>The octets.</returns>
    private static byte[] Serialize(XElement element)
    {
        var writerSettings = new XmlWriterSettings
        {
            Encoding = ExtensionEncoding,
            Indent = false,
            OmitXmlDeclaration = true,
            NewLineHandling = NewLineHandling.None,
            CloseOutput = false
        };

        using var stream = new MemoryStream();
        using(XmlWriter writer = XmlWriter.Create(stream, writerSettings))
        {
            element.WriteTo(writer);
        }

        return stream.ToArray();
    }


    /// <summary>
    /// Determines whether an element tree stays within a nesting bound, walking it with an explicit
    /// <see cref="Stack{T}"/> rather than recursively.
    /// </summary>
    /// <param name="root">The element to walk.</param>
    /// <param name="maximumDepth">The deepest nesting admitted.</param>
    /// <returns><see langword="true"/> when nothing nests deeper.</returns>
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
}
