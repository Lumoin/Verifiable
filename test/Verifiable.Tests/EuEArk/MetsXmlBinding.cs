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
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cryptography.Pki.Xml;

/// <summary>
/// A worked <see cref="ParseMetsDelegate"/> and <see cref="EncodeMetsDelegate"/> pair for a package manifest,
/// using <see cref="System.Xml.Linq"/> (BCL, no package) to move between the serialisation-agnostic
/// <see cref="MetsDocument"/> model and the METS profile of
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is a staged, promotable worked example, not a shipped library type: it lives beside
/// <c>TestInfrastructure</c>, never inside it, carries no test-framework type, and depends on nothing but the BCL
/// and <c>Verifiable.Cryptography.Pki</c> itself. Its namespace already names where a future package would place
/// it. The same shape carries <see cref="AsicManifestXmlBinding"/> for the container manifest and
/// <see cref="PremisXmlBinding"/> for preservation metadata.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> A manifest arrives from wherever the package came from and nothing
/// about the package has been verified when it is read, so the octets are treated as hostile: document type
/// definitions are prohibited outright (blocking entity expansion and external entity fetch), no external
/// resource is ever resolved — the <c>xsi:schemaLocation</c> a conformant manifest carries is read past, never
/// fetched — and the one particle whose depth a producer controls, the <c>div</c> tree, is walked with an
/// explicit <see cref="Stack{T}"/> under <see cref="MetsParseLimits.MaximumElementDepth"/> rather than by a
/// recursive method call.
/// </para>
/// <para>
/// <strong>Instants are read deterministically.</strong> An <c>xsd:dateTime</c> may legally omit its zone, and
/// several of the reference packages' manifests do. Reading such a value as local time would make the parse depend
/// on the machine it runs on, so a value with no zone is read as if it stated <c>Z</c> — stated once here, and the
/// reason the model can carry instants at all.
/// </para>
/// <para>
/// <strong>What this writer does not write.</strong> The profile's prose asks a root element to declare "all of
/// the relevant namespaces and locations for XML schema used in the package". The namespaces are declared here;
/// the locations are not, because a schema location names where a copy of a schema sits inside the package, which
/// is the package layer's knowledge and not this document writer's. A caller assembling a package adds it to the
/// octets it stores.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code: public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
public static class MetsXmlBinding
{
    /// <summary>The METS namespace, whose <c>elementFormDefault="qualified"</c> puts every element of a manifest in it.</summary>
    public static XNamespace MetsNamespace { get; } = MetsWellKnown.MetsNamespace;

    /// <summary>The extension namespace the profile's own schema declares for its four attributes.</summary>
    public static XNamespace CsipNamespace { get; } = MetsWellKnown.CsipExtensionNamespace;

    /// <summary>The XLink namespace the base schema imports for <c>xlink:type</c>, <c>xlink:href</c> and <c>xlink:title</c>.</summary>
    public static XNamespace XLinkNamespace { get; } = MetsWellKnown.XLinkNamespace;

    /// <summary>The encoding a manifest is written in: UTF-8 with no byte order mark.</summary>
    private static UTF8Encoding DocumentEncoding { get; } = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);


    /// <summary>
    /// Parses a manifest document into the <see cref="MetsDocument"/> model. Has the
    /// <see cref="ParseMetsDelegate"/> shape.
    /// </summary>
    /// <param name="context">The document and the bounds to parse it under.</param>
    /// <param name="pool">The memory pool fixity carriers are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The parse result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every fixity carrier built here transfers to the successful MetsParseResult, which the caller disposes; the failure paths dispose everything the reader has built so far.")]
    public static ValueTask<MetsParseResult> ParseAsync(MetsParseContext context, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        MetsParseLimits limits = context.Limits;
        ReadOnlySpan<byte> octets = context.Document.AsReadOnlySpan();
        if(octets.Length > limits.MaximumDocumentByteLength)
        {
            return ValueTask.FromResult(MetsParseResult.Failed(
                MetsParseStatus.LimitExceeded,
                $"The document is {octets.Length} octets, over the {limits.MaximumDocumentByteLength} the limits admit."));
        }

        XDocument xml;
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(octets.Length, 1));
        try
        {
            octets.CopyTo(rented);
            using var stream = new MemoryStream(rented, 0, octets.Length, writable: false);
            using XmlReader reader = XmlReader.Create(stream, HostileInputSettings());
            xml = XDocument.Load(reader, LoadOptions.None);
        }
        catch(Exception ex) when(ex is XmlException or InvalidOperationException or DecoderFallbackException)
        {
            return ValueTask.FromResult(MetsParseResult.Failed(MetsParseStatus.Malformed, $"The document is not well-formed XML: {ex.Message}"));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }

        XElement? root = xml.Root;
        if(root is null || root.Name != MetsNamespace + "mets")
        {
            return ValueTask.FromResult(MetsParseResult.Failed(MetsParseStatus.Malformed, $"Unexpected root element '{root?.Name.ToString() ?? "(none)"}'."));
        }

        if(!IsWithinDepthBound(root, limits.MaximumElementDepth))
        {
            return ValueTask.FromResult(MetsParseResult.Failed(
                MetsParseStatus.LimitExceeded,
                $"The document nests deeper than the {limits.MaximumElementDepth} elements the limits admit."));
        }

        List<EArkFixity> fixities = [];
        bool owned = true;
        try
        {
            MetsParseResult result = ReadDocument(root, limits, pool, fixities);
            owned = !result.IsValid;

            return ValueTask.FromResult(result);
        }
        finally
        {
            if(owned)
            {
                foreach(EArkFixity fixity in fixities)
                {
                    fixity.Dispose();
                }
            }
        }
    }


    /// <summary>
    /// Writes a <see cref="MetsDocument"/> as a manifest document. Has the <see cref="EncodeMetsDelegate"/> shape.
    /// </summary>
    /// <param name="context">The document to write and the fixity policy to write it under.</param>
    /// <param name="pool">The memory pool the produced document's carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encoding result.</returns>
    public static ValueTask<MetsEncodeResult> EncodeAsync(MetsEncodeContext context, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        MetsDocument document = context.Document;
        if(document.StructuralMaps.Count == 0)
        {
            return ValueTask.FromResult(MetsEncodeResult.Failed(
                MetsEncodeStatus.NoStructuralMap,
                "Requirement CSIP80 requires one or more structMap elements."));
        }

        var root = new XElement(
            MetsNamespace + "mets",
            new XAttribute(XNamespace.Xmlns + "csip", CsipNamespace.NamespaceName),
            new XAttribute(XNamespace.Xmlns + "xlink", XLinkNamespace.NamespaceName),
            new XAttribute("OBJID", document.ObjectIdentifier),
            new XAttribute("TYPE", document.ContentCategory),
            new XAttribute("PROFILE", document.Profile),
            Optional(CsipNamespace + "OTHERTYPE", document.OtherContentCategory),
            Optional(CsipNamespace + "CONTENTINFORMATIONTYPE", document.ContentInformationType),
            Optional(CsipNamespace + "OTHERCONTENTINFORMATIONTYPE", document.OtherContentInformationType),
            WriteHeader(document.Header));

        foreach(MetsDescriptiveMetadataSection section in document.DescriptiveMetadataSections)
        {
            if(!MetsWellKnown.IsNCName(section.Id))
            {
                return ValueTask.FromResult(InvalidIdentifier(section.Id));
            }

            (MetsEncodeStatus status, XElement? reference) = WriteMetadataReference(section.Reference, context.AllowUnrecomputableFixity);
            if(status != MetsEncodeStatus.Encoded)
            {
                return ValueTask.FromResult(UnrecomputableFixity());
            }

            root.Add(new XElement(
                MetsNamespace + "dmdSec",
                new XAttribute("ID", section.Id),
                new XAttribute("CREATED", XmlConvert.ToString(section.Created)),
                Optional("STATUS", section.Status),
                reference));
        }

        if(document.AdministrativeMetadata is MetsAdministrativeMetadata administrative)
        {
            var element = new XElement(MetsNamespace + "amdSec");

            //The base schema sequences the sub-sections techMD, rightsMD, sourceMD, digiprovMD — so rights
            //sections are written before provenance sections even though the requirement catalogue numbers them
            //the other way round.
            foreach((string elementName, IReadOnlyList<MetsAdministrativeMetadataSection> sections) in
                new[] { ("rightsMD", administrative.RightsSections), ("digiprovMD", administrative.DigitalProvenanceSections) })
            {
                foreach(MetsAdministrativeMetadataSection section in sections)
                {
                    if(!MetsWellKnown.IsNCName(section.Id))
                    {
                        return ValueTask.FromResult(InvalidIdentifier(section.Id));
                    }

                    (MetsEncodeStatus status, XElement? reference) = WriteMetadataReference(section.Reference, context.AllowUnrecomputableFixity);
                    if(status != MetsEncodeStatus.Encoded)
                    {
                        return ValueTask.FromResult(UnrecomputableFixity());
                    }

                    element.Add(new XElement(
                        MetsNamespace + elementName,
                        new XAttribute("ID", section.Id),
                        Optional("STATUS", section.Status),
                        reference));
                }
            }

            root.Add(element);
        }

        if(document.FileSection is MetsFileSection fileSection)
        {
            if(!MetsWellKnown.IsNCName(fileSection.Id))
            {
                return ValueTask.FromResult(InvalidIdentifier(fileSection.Id));
            }

            var element = new XElement(MetsNamespace + "fileSec", new XAttribute("ID", fileSection.Id));
            foreach(MetsFileGroup group in fileSection.FileGroups)
            {
                if(!MetsWellKnown.IsNCName(group.Id))
                {
                    return ValueTask.FromResult(InvalidIdentifier(group.Id));
                }

                var groupElement = new XElement(
                    MetsNamespace + "fileGrp",
                    new XAttribute("ID", group.Id),
                    new XAttribute("USE", group.Use),
                    OptionalIdentifierList("ADMID", group.AdministrativeMetadataIds),
                    Optional(CsipNamespace + "CONTENTINFORMATIONTYPE", group.ContentInformationType),
                    Optional(CsipNamespace + "OTHERCONTENTINFORMATIONTYPE", group.OtherContentInformationType));

                foreach(MetsFile file in group.Files)
                {
                    if(!MetsWellKnown.IsNCName(file.Id))
                    {
                        return ValueTask.FromResult(InvalidIdentifier(file.Id));
                    }

                    if(!TryWriteFixity(file.Fixity, context.AllowUnrecomputableFixity, out XAttribute? checksum, out XAttribute? checksumType))
                    {
                        return ValueTask.FromResult(UnrecomputableFixity());
                    }

                    groupElement.Add(new XElement(
                        MetsNamespace + "file",
                        new XAttribute("ID", file.Id),
                        new XAttribute("MIMETYPE", file.MediaType),
                        new XAttribute("SIZE", XmlConvert.ToString(file.Size)),
                        new XAttribute("CREATED", XmlConvert.ToString(file.Created)),
                        checksum,
                        checksumType,
                        Optional("OWNERID", file.OwnerId),
                        OptionalIdentifierList("ADMID", file.AdministrativeMetadataIds),
                        OptionalIdentifierList("DMDID", file.DescriptiveMetadataIds),
                        new XElement(
                            MetsNamespace + "FLocat",
                            new XAttribute("LOCTYPE", file.Locator.LocatorType),
                            new XAttribute(XLinkNamespace + "type", file.Locator.LinkType),
                            new XAttribute(XLinkNamespace + "href", file.Locator.Href))));
                }

                element.Add(groupElement);
            }

            root.Add(element);
        }

        foreach(MetsStructuralMap map in document.StructuralMaps)
        {
            if(!MetsWellKnown.IsNCName(map.Id))
            {
                return ValueTask.FromResult(InvalidIdentifier(map.Id));
            }

            (MetsEncodeStatus status, XElement? division) = WriteDivision(map.RootDivision);
            if(division is null)
            {
                return ValueTask.FromResult(MetsEncodeResult.Failed(status, "A structural division carries an identifier that is not an XML NCName."));
            }

            root.Add(new XElement(
                MetsNamespace + "structMap",
                new XAttribute("ID", map.Id),
                new XAttribute("TYPE", map.Type),
                new XAttribute("LABEL", map.Label),
                division));
        }

        return ValueTask.FromResult(MetsEncodeResult.Encoded(Serialize(root, pool)));

        //A failed result naming the identifier that cannot be written.
        static MetsEncodeResult InvalidIdentifier(string id) => MetsEncodeResult.Failed(
            MetsEncodeStatus.InvalidIdentifier,
            $"The identifier '{id}' is not an XML NCName, which clause 5.1 requires of every identifier.");

        //A failed result for a fixity the context did not admit.
        static MetsEncodeResult UnrecomputableFixity() => MetsEncodeResult.Failed(
            MetsEncodeStatus.UnrecomputableFixity,
            "The document carries a fixity this library cannot recompute; state AllowUnrecomputableFixity to write it through.");
    }


    /// <summary>
    /// Reads the whole document under a validated root element.
    /// </summary>
    /// <param name="root">The <c>mets</c> element.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <param name="pool">The memory pool fixity carriers are rented from.</param>
    /// <param name="fixities">Every fixity built so far, so a failure path can dispose them all.</param>
    /// <returns>The parse result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the administrative-metadata element and of the document built around it transfers to the returned MetsParseResult, which the caller disposes; every failure path returns before either is built and the fixities the caller collected are disposed by ParseAsync.")]
    private static MetsParseResult ReadDocument(XElement root, MetsParseLimits limits, MemoryPool<byte> pool, List<EArkFixity> fixities)
    {
        string? objectIdentifier = (string?)root.Attribute("OBJID");
        string? contentCategory = (string?)root.Attribute("TYPE");
        string? profile = (string?)root.Attribute("PROFILE");
        if(objectIdentifier is null || contentCategory is null || profile is null)
        {
            return MetsParseResult.Failed(
                MetsParseStatus.MissingRequiredElement,
                "Requirements CSIP1, CSIP2 and CSIP6 make mets/@OBJID, mets/@TYPE and mets/@PROFILE mandatory.");
        }

        XElement? headerElement = root.Element(MetsNamespace + "metsHdr");
        if(headerElement is null)
        {
            return MetsParseResult.Failed(MetsParseStatus.MissingRequiredElement, "Requirement CSIP117 makes mets/metsHdr mandatory.");
        }

        (MetsParseStatus headerStatus, MetsHeader? header, string headerReason) = ReadHeader(headerElement, limits);
        if(header is null)
        {
            return MetsParseResult.Failed(headerStatus, headerReason);
        }

        List<MetsDescriptiveMetadataSection> descriptiveSections = [];
        foreach(XElement element in root.Elements(MetsNamespace + "dmdSec"))
        {
            if(descriptiveSections.Count == limits.MaximumMetadataSections)
            {
                return MetsParseResult.Failed(MetsParseStatus.LimitExceeded, $"The document carries more than the {limits.MaximumMetadataSections} dmdSec elements the limits admit.");
            }

            string? id = ReadIdentifier(element, out MetsParseStatus idStatus);
            if(id is null)
            {
                return MetsParseResult.Failed(idStatus, "A dmdSec element carries no @ID, or one that is not an XML NCName (CSIP18).");
            }

            if(!TryReadInstant(element, "CREATED", out DateTimeOffset created, out bool createdPresent))
            {
                return MetsParseResult.Failed(
                    createdPresent ? MetsParseStatus.MalformedValue : MetsParseStatus.MissingRequiredElement,
                    "A dmdSec element carries no @CREATED, or one that is not an xsd:dateTime (CSIP19).");
            }

            (MetsParseStatus referenceStatus, MetsMetadataReference? reference, string referenceReason) =
                ReadMetadataReference(element, limits, pool, fixities);
            if(referenceStatus != MetsParseStatus.Valid)
            {
                return MetsParseResult.Failed(referenceStatus, referenceReason);
            }

            descriptiveSections.Add(new MetsDescriptiveMetadataSection
            {
                Id = id,
                Created = created,
                Status = (string?)element.Attribute("STATUS"),
                Reference = reference
            });
        }

        MetsAdministrativeMetadata? administrative = null;
        XElement? administrativeElement = root.Element(MetsNamespace + "amdSec");
        if(administrativeElement is not null)
        {
            List<MetsAdministrativeMetadataSection> provenance = [];
            List<MetsAdministrativeMetadataSection> rights = [];
            foreach((string elementName, List<MetsAdministrativeMetadataSection> into) in
                new[] { ("digiprovMD", provenance), ("rightsMD", rights) })
            {
                foreach(XElement element in administrativeElement.Elements(MetsNamespace + elementName))
                {
                    if(into.Count == limits.MaximumMetadataSections)
                    {
                        return MetsParseResult.Failed(MetsParseStatus.LimitExceeded, $"The document carries more than the {limits.MaximumMetadataSections} {elementName} elements the limits admit.");
                    }

                    string? id = ReadIdentifier(element, out MetsParseStatus idStatus);
                    if(id is null)
                    {
                        return MetsParseResult.Failed(idStatus, $"A {elementName} element carries no @ID, or one that is not an XML NCName (CSIP33, CSIP46).");
                    }

                    (MetsParseStatus referenceStatus, MetsMetadataReference? reference, string referenceReason) =
                        ReadMetadataReference(element, limits, pool, fixities);
                    if(referenceStatus != MetsParseStatus.Valid)
                    {
                        return MetsParseResult.Failed(referenceStatus, referenceReason);
                    }

                    into.Add(new MetsAdministrativeMetadataSection
                    {
                        Id = id,
                        Status = (string?)element.Attribute("STATUS"),
                        Reference = reference
                    });
                }
            }

            administrative = new MetsAdministrativeMetadata { DigitalProvenanceSections = provenance, RightsSections = rights };
        }

        MetsFileSection? fileSection = null;
        XElement? fileSectionElement = root.Element(MetsNamespace + "fileSec");
        if(fileSectionElement is not null)
        {
            (MetsParseStatus status, MetsFileSection? section, string reason) = ReadFileSection(fileSectionElement, limits, pool, fixities);
            if(section is null)
            {
                return MetsParseResult.Failed(status, reason);
            }

            fileSection = section;
        }

        List<MetsStructuralMap> maps = [];
        int divisionBudget = limits.MaximumDivisions;
        foreach(XElement element in root.Elements(MetsNamespace + "structMap"))
        {
            if(maps.Count == limits.MaximumStructuralMaps)
            {
                return MetsParseResult.Failed(MetsParseStatus.LimitExceeded, $"The document carries more than the {limits.MaximumStructuralMaps} structMap elements the limits admit.");
            }

            (MetsParseStatus status, MetsStructuralMap? map, string reason) = ReadStructuralMap(element, limits, ref divisionBudget);
            if(map is null)
            {
                return MetsParseResult.Failed(status, reason);
            }

            maps.Add(map);
        }

        if(maps.Count == 0)
        {
            return MetsParseResult.Failed(MetsParseStatus.MissingRequiredElement, "Requirement CSIP80 makes mets/structMap mandatory.");
        }

        return MetsParseResult.Valid(new MetsDocument
        {
            ObjectIdentifier = objectIdentifier,
            ContentCategory = contentCategory,
            Profile = profile,
            OtherContentCategory = (string?)root.Attribute(CsipNamespace + "OTHERTYPE"),
            ContentInformationType = (string?)root.Attribute(CsipNamespace + "CONTENTINFORMATIONTYPE"),
            OtherContentInformationType = (string?)root.Attribute(CsipNamespace + "OTHERCONTENTINFORMATIONTYPE"),
            Header = header,
            DescriptiveMetadataSections = descriptiveSections,
            AdministrativeMetadata = administrative,
            FileSection = fileSection,
            StructuralMaps = maps
        });
    }


    /// <summary>
    /// Reads the <c>metsHdr</c> element.
    /// </summary>
    /// <param name="element">The element to read.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <returns>The status, the header when it was read, and the reason when it was not.</returns>
    private static (MetsParseStatus Status, MetsHeader? Header, string Reason) ReadHeader(XElement element, MetsParseLimits limits)
    {
        if(!TryReadInstant(element, "CREATEDATE", out DateTimeOffset created, out bool createdPresent))
        {
            return (createdPresent ? MetsParseStatus.MalformedValue : MetsParseStatus.MissingRequiredElement,
                null, "The metsHdr element carries no @CREATEDATE, or one that is not an xsd:dateTime (CSIP7).");
        }

        DateTimeOffset? lastModified = null;
        if(element.Attribute("LASTMODDATE") is not null)
        {
            if(!TryReadInstant(element, "LASTMODDATE", out DateTimeOffset value, out _))
            {
                return (MetsParseStatus.MalformedValue, null, "The metsHdr element's @LASTMODDATE is not an xsd:dateTime (CSIP8).");
            }

            lastModified = value;
        }

        string? packageType = (string?)element.Attribute(CsipNamespace + "OAISPACKAGETYPE");
        if(packageType is null)
        {
            return (MetsParseStatus.MissingRequiredElement, null, "The metsHdr element carries no @csip:OAISPACKAGETYPE (CSIP9).");
        }

        List<MetsAgent> agents = [];
        foreach(XElement agentElement in element.Elements(MetsNamespace + "agent"))
        {
            if(agents.Count == limits.MaximumAgents)
            {
                return (MetsParseStatus.LimitExceeded, null, $"The header carries more than the {limits.MaximumAgents} agent elements the limits admit.");
            }

            string? role = (string?)agentElement.Attribute("ROLE");
            string? type = (string?)agentElement.Attribute("TYPE");
            if(role is null || type is null)
            {
                return (MetsParseStatus.MissingRequiredElement, null, "An agent element carries no @ROLE or no @TYPE (CSIP11, CSIP12).");
            }

            List<MetsAgentNote> notes = [];
            foreach(XElement noteElement in agentElement.Elements(MetsNamespace + "note"))
            {
                if(noteElement.Value.Length > limits.MaximumTextLength)
                {
                    return (MetsParseStatus.LimitExceeded, null, $"An agent note is longer than the {limits.MaximumTextLength} characters the limits admit.");
                }

                notes.Add(new MetsAgentNote((string?)noteElement.Attribute(CsipNamespace + "NOTETYPE"), noteElement.Value));
            }

            agents.Add(new MetsAgent
            {
                Role = role,
                Type = type,
                OtherType = (string?)agentElement.Attribute("OTHERTYPE"),
                Name = agentElement.Element(MetsNamespace + "name")?.Value,
                Notes = notes
            });
        }

        return (MetsParseStatus.Valid, new MetsHeader
        {
            CreateDate = created,
            LastModificationDate = lastModified,
            OaisPackageType = packageType,
            Agents = agents
        }, string.Empty);
    }


    /// <summary>
    /// Reads the <c>mdRef</c> child of a metadata section, when it has one.
    /// </summary>
    /// <param name="sectionElement">The <c>dmdSec</c>, <c>digiprovMD</c> or <c>rightsMD</c> element.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <param name="pool">The memory pool the fixity carrier is rented from.</param>
    /// <param name="fixities">Every fixity built so far, so a failure path can dispose them all.</param>
    /// <returns>The status, the reference when the section had one, and the reason when it could not be read.</returns>
    private static (MetsParseStatus Status, MetsMetadataReference? Reference, string Reason) ReadMetadataReference(
        XElement sectionElement,
        MetsParseLimits limits,
        MemoryPool<byte> pool,
        List<EArkFixity> fixities)
    {
        XElement? element = sectionElement.Element(MetsNamespace + "mdRef");
        if(element is null)
        {
            return (MetsParseStatus.Valid, null, string.Empty);
        }

        string? locatorType = (string?)element.Attribute("LOCTYPE");
        string? linkType = (string?)element.Attribute(XLinkNamespace + "type");
        string? href = (string?)element.Attribute(XLinkNamespace + "href");
        string? metadataType = (string?)element.Attribute("MDTYPE");
        string? mediaType = (string?)element.Attribute("MIMETYPE");
        if(locatorType is null || linkType is null || href is null || metadataType is null || mediaType is null)
        {
            return (MetsParseStatus.MissingRequiredElement, null, "An mdRef element carries none of @LOCTYPE, @xlink:type, @xlink:href, @MDTYPE and @MIMETYPE it is required to.");
        }

        if(href.Length > limits.MaximumTextLength)
        {
            return (MetsParseStatus.LimitExceeded, null, $"An mdRef location is longer than the {limits.MaximumTextLength} characters the limits admit.");
        }

        if(!TryReadSize(element, out long size, out bool sizePresent))
        {
            return (sizePresent ? MetsParseStatus.MalformedValue : MetsParseStatus.MissingRequiredElement, null, "An mdRef element carries no @SIZE, or one that is not an xsd:long.");
        }

        if(!TryReadInstant(element, "CREATED", out DateTimeOffset created, out bool createdPresent))
        {
            return (createdPresent ? MetsParseStatus.MalformedValue : MetsParseStatus.MissingRequiredElement, null, "An mdRef element carries no @CREATED, or one that is not an xsd:dateTime.");
        }

        EArkFixity fixity = EArkFixity.Read((string?)element.Attribute("CHECKSUMTYPE"), (string?)element.Attribute("CHECKSUM"), pool);
        fixities.Add(fixity);

        return (MetsParseStatus.Valid, new MetsMetadataReference
        {
            LocatorType = locatorType,
            LinkType = linkType,
            Href = href,
            MetadataType = metadataType,
            OtherMetadataType = (string?)element.Attribute("OTHERMDTYPE"),
            MetadataTypeVersion = (string?)element.Attribute("MDTYPEVERSION"),
            MediaType = mediaType,
            Size = size,
            Created = created,
            Fixity = fixity
        }, string.Empty);
    }


    /// <summary>
    /// Reads the <c>fileSec</c> element.
    /// </summary>
    /// <param name="element">The element to read.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <param name="pool">The memory pool fixity carriers are rented from.</param>
    /// <param name="fixities">Every fixity built so far, so a failure path can dispose them all.</param>
    /// <returns>The status, the section when it was read, and the reason when it was not.</returns>
    private static (MetsParseStatus Status, MetsFileSection? Section, string Reason) ReadFileSection(
        XElement element,
        MetsParseLimits limits,
        MemoryPool<byte> pool,
        List<EArkFixity> fixities)
    {
        string? id = ReadIdentifier(element, out MetsParseStatus idStatus);
        if(id is null)
        {
            return (idStatus, null, "The fileSec element carries no @ID, or one that is not an XML NCName (CSIP59).");
        }

        List<MetsFileGroup> groups = [];
        int fileBudget = limits.MaximumFiles;
        foreach(XElement groupElement in element.Elements(MetsNamespace + "fileGrp"))
        {
            if(groups.Count == limits.MaximumFileGroups)
            {
                return (MetsParseStatus.LimitExceeded, null, $"The file section carries more than the {limits.MaximumFileGroups} fileGrp elements the limits admit.");
            }

            string? groupId = ReadIdentifier(groupElement, out MetsParseStatus groupIdStatus);
            string? use = (string?)groupElement.Attribute("USE");
            if(groupId is null)
            {
                return (groupIdStatus, null, "A fileGrp element carries no @ID, or one that is not an XML NCName (CSIP65).");
            }

            if(use is null)
            {
                return (MetsParseStatus.MissingRequiredElement, null, "A fileGrp element carries no @USE (CSIP64).");
            }

            List<MetsFile> files = [];
            foreach(XElement fileElement in groupElement.Elements(MetsNamespace + "file"))
            {
                if(fileBudget == 0)
                {
                    return (MetsParseStatus.LimitExceeded, null, $"The document carries more than the {limits.MaximumFiles} file elements the limits admit.");
                }

                --fileBudget;

                (MetsParseStatus status, MetsFile? file, string reason) = ReadFile(fileElement, limits, pool, fixities);
                if(file is null)
                {
                    return (status, null, reason);
                }

                files.Add(file);
            }

            groups.Add(new MetsFileGroup
            {
                Id = groupId,
                Use = use,
                AdministrativeMetadataIds = ReadIdentifierList(groupElement, "ADMID"),
                ContentInformationType = (string?)groupElement.Attribute(CsipNamespace + "CONTENTINFORMATIONTYPE"),
                OtherContentInformationType = (string?)groupElement.Attribute(CsipNamespace + "OTHERCONTENTINFORMATIONTYPE"),
                Files = files
            });
        }

        return (MetsParseStatus.Valid, new MetsFileSection { Id = id, FileGroups = groups }, string.Empty);
    }


    /// <summary>
    /// Reads one <c>file</c> element.
    /// </summary>
    /// <param name="element">The element to read.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <param name="pool">The memory pool the fixity carrier is rented from.</param>
    /// <param name="fixities">Every fixity built so far, so a failure path can dispose them all.</param>
    /// <returns>The status, the file when it was read, and the reason when it was not.</returns>
    private static (MetsParseStatus Status, MetsFile? File, string Reason) ReadFile(
        XElement element,
        MetsParseLimits limits,
        MemoryPool<byte> pool,
        List<EArkFixity> fixities)
    {
        string? id = ReadIdentifier(element, out MetsParseStatus idStatus);
        if(id is null)
        {
            return (idStatus, null, "A file element carries no @ID, or one that is not an XML NCName (CSIP67).");
        }

        string? mediaType = (string?)element.Attribute("MIMETYPE");
        if(mediaType is null)
        {
            return (MetsParseStatus.MissingRequiredElement, null, $"The file element '{id}' carries no @MIMETYPE (CSIP68).");
        }

        if(!TryReadSize(element, out long size, out bool sizePresent))
        {
            return (sizePresent ? MetsParseStatus.MalformedValue : MetsParseStatus.MissingRequiredElement, null, $"The file element '{id}' carries no @SIZE, or one that is not an xsd:long (CSIP69).");
        }

        if(!TryReadInstant(element, "CREATED", out DateTimeOffset created, out bool createdPresent))
        {
            return (createdPresent ? MetsParseStatus.MalformedValue : MetsParseStatus.MissingRequiredElement, null, $"The file element '{id}' carries no @CREATED, or one that is not an xsd:dateTime (CSIP70).");
        }

        XElement? locatorElement = element.Element(MetsNamespace + "FLocat");
        string? locatorType = (string?)locatorElement?.Attribute("LOCTYPE");
        string? linkType = (string?)locatorElement?.Attribute(XLinkNamespace + "type");
        string? href = (string?)locatorElement?.Attribute(XLinkNamespace + "href");
        if(locatorType is null || linkType is null || href is null)
        {
            return (MetsParseStatus.MissingRequiredElement, null, $"The file element '{id}' carries no conformant FLocat element (CSIP76 to CSIP79).");
        }

        if(href.Length > limits.MaximumTextLength)
        {
            return (MetsParseStatus.LimitExceeded, null, $"A file location is longer than the {limits.MaximumTextLength} characters the limits admit.");
        }

        EArkFixity fixity = EArkFixity.Read((string?)element.Attribute("CHECKSUMTYPE"), (string?)element.Attribute("CHECKSUM"), pool);
        fixities.Add(fixity);

        return (MetsParseStatus.Valid, new MetsFile
        {
            Id = id,
            MediaType = mediaType,
            Size = size,
            Created = created,
            Fixity = fixity,
            Locator = new MetsFileLocator(locatorType, linkType, href),
            OwnerId = (string?)element.Attribute("OWNERID"),
            AdministrativeMetadataIds = ReadIdentifierList(element, "ADMID"),
            DescriptiveMetadataIds = ReadIdentifierList(element, "DMDID")
        }, string.Empty);
    }


    /// <summary>
    /// Reads one <c>structMap</c> element and the division tree under it.
    /// </summary>
    /// <param name="element">The element to read.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <param name="divisionBudget">How many more <c>div</c> elements the document may carry across every map.</param>
    /// <returns>The status, the map when it was read, and the reason when it was not.</returns>
    private static (MetsParseStatus Status, MetsStructuralMap? Map, string Reason) ReadStructuralMap(
        XElement element,
        MetsParseLimits limits,
        ref int divisionBudget)
    {
        string? id = ReadIdentifier(element, out MetsParseStatus idStatus);
        if(id is null)
        {
            return (idStatus, null, "A structMap element carries no @ID, or one that is not an XML NCName (CSIP83).");
        }

        string? type = (string?)element.Attribute("TYPE");
        string? label = (string?)element.Attribute("LABEL");
        if(type is null || label is null)
        {
            return (MetsParseStatus.MissingRequiredElement, null, "A structMap element carries no @TYPE or no @LABEL (CSIP81, CSIP82).");
        }

        XElement? rootDivisionElement = element.Element(MetsNamespace + "div");
        if(rootDivisionElement is null)
        {
            return (MetsParseStatus.MissingRequiredElement, null, "A structMap element carries no root div element (CSIP84).");
        }

        (MetsParseStatus divisionStatus, MetsDivision? rootDivision, string divisionReason) =
            ReadDivisionTree(rootDivisionElement, limits, ref divisionBudget);
        if(rootDivision is null)
        {
            return (divisionStatus, null, divisionReason);
        }

        return (MetsParseStatus.Valid, new MetsStructuralMap
        {
            Id = id,
            Type = type,
            Label = label,
            RootDivision = rootDivision
        }, string.Empty);
    }


    /// <summary>
    /// Reads a division tree, walking it with an explicit stack rather than recursively.
    /// </summary>
    /// <param name="rootElement">The root <c>div</c> element.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <param name="divisionBudget">How many more <c>div</c> elements the document may carry across every map.</param>
    /// <returns>The status, the root division when the tree was read, and the reason when it was not.</returns>
    /// <remarks>
    /// The tree is the one particle of this vocabulary whose depth a producer controls, so it is the one the
    /// house rule against recursion exists for: a document nesting ten thousand divisions would exhaust a
    /// recursive reader's stack before any limit could refuse it.
    /// </remarks>
    private static (MetsParseStatus Status, MetsDivision? Division, string Reason) ReadDivisionTree(
        XElement rootElement,
        MetsParseLimits limits,
        ref int divisionBudget)
    {
        var pending = new Stack<DivisionFrame>();
        pending.Push(new DivisionFrame(rootElement, 1));
        MetsDivision? result = null;
        while(pending.Count > 0)
        {
            DivisionFrame frame = pending.Peek();
            if(frame.NextChild < frame.ChildElements.Count)
            {
                XElement child = frame.ChildElements[frame.NextChild];
                ++frame.NextChild;
                if(frame.Depth == limits.MaximumElementDepth)
                {
                    return (MetsParseStatus.LimitExceeded, null, $"The division tree nests deeper than the {limits.MaximumElementDepth} elements the limits admit.");
                }

                if(divisionBudget == 0)
                {
                    return (MetsParseStatus.LimitExceeded, null, $"The document carries more than the {limits.MaximumDivisions} div elements the limits admit.");
                }

                --divisionBudget;
                pending.Push(new DivisionFrame(child, frame.Depth + 1));

                continue;
            }

            _ = pending.Pop();

            XElement element = frame.Element;
            string? id = ReadIdentifier(element, out MetsParseStatus idStatus);
            if(id is null)
            {
                return (idStatus, null, "A div element carries no @ID, or one that is not an XML NCName (CSIP85 and its siblings).");
            }

            List<MetsFilePointer> filePointers = [];
            foreach(XElement pointerElement in element.Elements(MetsNamespace + "fptr"))
            {
                string? fileId = (string?)pointerElement.Attribute("FILEID");
                if(fileId is null)
                {
                    return (MetsParseStatus.MissingRequiredElement, null, "An fptr element carries no @FILEID (CSIP116, CSIP118, CSIP119).");
                }

                filePointers.Add(new MetsFilePointer(fileId));
            }

            List<MetsPointer> metsPointers = [];
            foreach(XElement pointerElement in element.Elements(MetsNamespace + "mptr"))
            {
                string? href = (string?)pointerElement.Attribute(XLinkNamespace + "href");
                string? locatorType = (string?)pointerElement.Attribute("LOCTYPE");
                string? linkType = (string?)pointerElement.Attribute(XLinkNamespace + "type");
                if(href is null || locatorType is null || linkType is null)
                {
                    return (MetsParseStatus.MissingRequiredElement, null, "An mptr element carries none of @xlink:href, @LOCTYPE and @xlink:type it is required to (CSIP110 to CSIP112).");
                }

                if(href.Length > limits.MaximumTextLength)
                {
                    return (MetsParseStatus.LimitExceeded, null, $"An mptr location is longer than the {limits.MaximumTextLength} characters the limits admit.");
                }

                metsPointers.Add(new MetsPointer(href, locatorType, linkType, (string?)pointerElement.Attribute(XLinkNamespace + "title")));
            }

            var division = new MetsDivision
            {
                Id = id,
                Label = (string?)element.Attribute("LABEL"),
                AdministrativeMetadataIds = ReadIdentifierList(element, "ADMID"),
                DescriptiveMetadataIds = ReadIdentifierList(element, "DMDID"),
                FilePointers = filePointers,
                MetsPointers = metsPointers,
                Divisions = frame.BuiltChildren
            };

            if(pending.Count > 0)
            {
                pending.Peek().BuiltChildren.Add(division);
            }
            else
            {
                result = division;
            }
        }

        return result is null
            ? (MetsParseStatus.MissingRequiredElement, null, "The structural map carries no root division.")
            : (MetsParseStatus.Valid, result, string.Empty);
    }


    /// <summary>
    /// Writes one <c>mdRef</c> element, when the section has a reference.
    /// </summary>
    /// <param name="reference">The reference to write, or <see langword="null"/>.</param>
    /// <param name="allowUnrecomputableFixity">Whether a fixity this library cannot recompute may be written through.</param>
    /// <returns>The status and, when the section had a reference that could be written, the element.</returns>
    private static (MetsEncodeStatus Status, XElement? Element) WriteMetadataReference(MetsMetadataReference? reference, bool allowUnrecomputableFixity)
    {
        if(reference is null)
        {
            return (MetsEncodeStatus.Encoded, null);
        }

        if(!TryWriteFixity(reference.Fixity, allowUnrecomputableFixity, out XAttribute? checksum, out XAttribute? checksumType))
        {
            return (MetsEncodeStatus.UnrecomputableFixity, null);
        }

        return (MetsEncodeStatus.Encoded, new XElement(
            MetsNamespace + "mdRef",
            new XAttribute("LOCTYPE", reference.LocatorType),
            new XAttribute(XLinkNamespace + "type", reference.LinkType),
            new XAttribute(XLinkNamespace + "href", reference.Href),
            new XAttribute("MDTYPE", reference.MetadataType),
            Optional("OTHERMDTYPE", reference.OtherMetadataType),
            Optional("MDTYPEVERSION", reference.MetadataTypeVersion),
            new XAttribute("MIMETYPE", reference.MediaType),
            new XAttribute("SIZE", XmlConvert.ToString(reference.Size)),
            new XAttribute("CREATED", XmlConvert.ToString(reference.Created)),
            checksum,
            checksumType));
    }


    /// <summary>
    /// Writes a division tree, walking it with an explicit stack rather than recursively.
    /// </summary>
    /// <param name="rootDivision">The root division to write.</param>
    /// <returns>The status and, when every identifier could be written, the element.</returns>
    private static (MetsEncodeStatus Status, XElement? Element) WriteDivision(MetsDivision rootDivision)
    {
        var pending = new Stack<(MetsDivision Division, XElement Element)>();
        var rootElement = new XElement(MetsNamespace + "div");
        pending.Push((rootDivision, rootElement));
        while(pending.Count > 0)
        {
            (MetsDivision division, XElement element) = pending.Pop();
            if(!MetsWellKnown.IsNCName(division.Id))
            {
                return (MetsEncodeStatus.InvalidIdentifier, null);
            }

            element.Add(new XAttribute("ID", division.Id));
            element.Add(Optional("LABEL", division.Label));
            element.Add(OptionalIdentifierList("DMDID", division.DescriptiveMetadataIds));
            element.Add(OptionalIdentifierList("ADMID", division.AdministrativeMetadataIds));

            //The base schema sequences a division's children mptr, fptr, div — in that order.
            foreach(MetsPointer pointer in division.MetsPointers)
            {
                element.Add(new XElement(
                    MetsNamespace + "mptr",
                    new XAttribute("LOCTYPE", pointer.LocatorType),
                    new XAttribute(XLinkNamespace + "type", pointer.LinkType),
                    new XAttribute(XLinkNamespace + "href", pointer.Href),
                    Optional(XLinkNamespace + "title", pointer.Title)));
            }

            foreach(MetsFilePointer pointer in division.FilePointers)
            {
                element.Add(new XElement(MetsNamespace + "fptr", new XAttribute("FILEID", pointer.FileId)));
            }

            //Each child's element is created and appended in the model's own order, which is the package's folder
            //order and the only source a reader has for it. The order the frames are then popped in does not
            //matter: every child element already sits where it belongs and only its content is still to come.
            foreach(MetsDivision child in division.Divisions)
            {
                var childElement = new XElement(MetsNamespace + "div");
                element.Add(childElement);
                pending.Push((child, childElement));
            }
        }

        return (MetsEncodeStatus.Encoded, rootElement);
    }


    /// <summary>
    /// Writes the <c>metsHdr</c> element.
    /// </summary>
    /// <param name="header">The header to write.</param>
    /// <returns>The element.</returns>
    private static XElement WriteHeader(MetsHeader header)
    {
        var element = new XElement(
            MetsNamespace + "metsHdr",
            new XAttribute("CREATEDATE", XmlConvert.ToString(header.CreateDate)),
            header.LastModificationDate is null ? null : new XAttribute("LASTMODDATE", XmlConvert.ToString(header.LastModificationDate.Value)),
            new XAttribute(CsipNamespace + "OAISPACKAGETYPE", header.OaisPackageType));

        foreach(MetsAgent agent in header.Agents)
        {
            var agentElement = new XElement(
                MetsNamespace + "agent",
                new XAttribute("ROLE", agent.Role),
                new XAttribute("TYPE", agent.Type),
                Optional("OTHERTYPE", agent.OtherType),
                agent.Name is null ? null : new XElement(MetsNamespace + "name", agent.Name));

            foreach(MetsAgentNote note in agent.Notes)
            {
                agentElement.Add(new XElement(
                    MetsNamespace + "note",
                    note.NoteType is null ? null : new XAttribute(CsipNamespace + "NOTETYPE", note.NoteType),
                    note.Text));
            }

            element.Add(agentElement);
        }

        return element;
    }


    /// <summary>
    /// Writes the <c>@CHECKSUM</c>/<c>@CHECKSUMTYPE</c> attribute pair for a fixity.
    /// </summary>
    /// <param name="fixity">The fixity to write.</param>
    /// <param name="allowUnrecomputable">Whether a fixity this library cannot recompute may be written through.</param>
    /// <param name="checksum">The <c>@CHECKSUM</c> attribute, when one could be written.</param>
    /// <param name="checksumType">The <c>@CHECKSUMTYPE</c> attribute, when one could be written.</param>
    /// <returns><see langword="true"/> when the pair could be written.</returns>
    private static bool TryWriteFixity(EArkFixity fixity, bool allowUnrecomputable, out XAttribute? checksum, out XAttribute? checksumType)
    {
        switch(fixity)
        {
            case EArkRecomputableFixity recomputable:
                checksum = new XAttribute("CHECKSUM", Convert.ToHexStringLower(recomputable.Digest.AsReadOnlySpan()));
                checksumType = new XAttribute("CHECKSUMTYPE", recomputable.ChecksumType);

                return true;

            case EArkStatedFixity stated when allowUnrecomputable:
                checksum = new XAttribute("CHECKSUM", stated.Checksum);
                checksumType = new XAttribute("CHECKSUMTYPE", stated.ChecksumType);

                return true;

            default:
                checksum = null;
                checksumType = null;

                return false;
        }
    }


    /// <summary>
    /// Serialises a manifest's root element into a pooled carrier.
    /// </summary>
    /// <param name="root">The <c>mets</c> element to write.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The produced octets. The caller owns and disposes them.</returns>
    private static PooledMemory Serialize(XElement root, MemoryPool<byte> pool)
    {
        var writerSettings = new XmlWriterSettings
        {
            Encoding = DocumentEncoding,
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
            ? PooledMemory.FromBytes(buffer.AsSpan(), pool, EArkTags.MetsDocument)
            : PooledMemory.FromBytes(stream.ToArray(), pool, EArkTags.MetsDocument);
    }


    /// <summary>
    /// Reads an element's <c>@ID</c> attribute, refusing one that is not an XML <c>NCName</c>.
    /// </summary>
    /// <param name="element">The element to read.</param>
    /// <param name="status">Why the identifier could not be read, when it could not.</param>
    /// <returns>The identifier, or <see langword="null"/>.</returns>
    private static string? ReadIdentifier(XElement element, out MetsParseStatus status)
    {
        string? id = (string?)element.Attribute("ID");
        if(id is null)
        {
            status = MetsParseStatus.MissingRequiredElement;

            return null;
        }

        if(!MetsWellKnown.IsNCName(id))
        {
            status = MetsParseStatus.MalformedValue;

            return null;
        }

        status = MetsParseStatus.Valid;

        return id;
    }


    /// <summary>
    /// Reads a whitespace-separated identifier reference list.
    /// </summary>
    /// <param name="element">The element to read.</param>
    /// <param name="attributeName">The attribute's name, <c>ADMID</c> or <c>DMDID</c>.</param>
    /// <returns>The identifiers, empty when the attribute is absent.</returns>
    private static string[] ReadIdentifierList(XElement element, string attributeName)
    {
        string? value = (string?)element.Attribute(attributeName);

        return value is null ? [] : value.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }


    /// <summary>
    /// Reads an <c>xsd:dateTime</c> attribute.
    /// </summary>
    /// <param name="element">The element to read.</param>
    /// <param name="attributeName">The attribute's name.</param>
    /// <param name="value">The instant, when one was read.</param>
    /// <param name="present">Whether the attribute was present at all, which is what separates a missing value from a malformed one.</param>
    /// <returns><see langword="true"/> when the attribute was present and parsed.</returns>
    /// <remarks>
    /// A lexical value that states no zone is read as though it stated <c>Z</c>. The alternative — the local zone
    /// of whichever machine reads the package — would make the same octets parse to different instants in
    /// different places, which is not something a preservation format can afford.
    /// </remarks>
    private static bool TryReadInstant(XElement element, string attributeName, out DateTimeOffset value, out bool present)
    {
        string? text = (string?)element.Attribute(attributeName);
        present = text is not null;
        value = default;
        if(text is null)
        {
            return false;
        }

        string trimmed = text.Trim();
        try
        {
            value = XmlConvert.ToDateTimeOffset(HasZone(trimmed) ? trimmed : trimmed + "Z");

            return true;
        }
        catch(Exception ex) when(ex is FormatException or ArgumentOutOfRangeException)
        {
            return false;
        }

        //An xsd:dateTime states its zone as a trailing "Z" or as a sign and an offset after the time part, which
        //begins at the "T". Anything else states none.
        static bool HasZone(string lexical)
        {
            int time = lexical.IndexOf('T', StringComparison.Ordinal);

            return time >= 0
                && (lexical.EndsWith('Z')
                    || lexical.IndexOf('+', time) >= 0
                    || lexical.IndexOf('-', time) >= 0);
        }
    }


    /// <summary>
    /// Reads an <c>xsd:long</c> <c>@SIZE</c> attribute.
    /// </summary>
    /// <param name="element">The element to read.</param>
    /// <param name="value">The size, when one was read.</param>
    /// <param name="present">Whether the attribute was present at all.</param>
    /// <returns><see langword="true"/> when the attribute was present and parsed.</returns>
    private static bool TryReadSize(XElement element, out long value, out bool present)
    {
        string? text = (string?)element.Attribute("SIZE");
        present = text is not null;
        value = default;

        return text is not null
            && long.TryParse(text.Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out value);
    }


    /// <summary>
    /// Builds an attribute when a value is present.
    /// </summary>
    /// <param name="name">The attribute's name.</param>
    /// <param name="value">The value, or <see langword="null"/>.</param>
    /// <returns>The attribute, or <see langword="null"/>.</returns>
    private static XAttribute? Optional(XName name, string? value) => value is null ? null : new XAttribute(name, value);


    /// <summary>
    /// Builds a whitespace-separated identifier reference list attribute when the list is not empty.
    /// </summary>
    /// <param name="name">The attribute's name.</param>
    /// <param name="values">The identifiers.</param>
    /// <returns>The attribute, or <see langword="null"/>.</returns>
    private static XAttribute? OptionalIdentifierList(XName name, IReadOnlyList<string> values) =>
        values.Count == 0 ? null : new XAttribute(name, string.Join(' ', values));


    /// <summary>
    /// The reader settings every parse here uses: no document type definitions and no external resolution.
    /// </summary>
    /// <returns>The settings.</returns>
    private static XmlReaderSettings HostileInputSettings() => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        CloseInput = false
    };


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
    /// One division of the tree being read, and how far its children have been walked.
    /// </summary>
    private sealed class DivisionFrame
    {
        /// <summary>
        /// Initialises a frame over one <c>div</c> element.
        /// </summary>
        /// <param name="element">The element.</param>
        /// <param name="depth">How deep the element sits, counting the root division as depth one.</param>
        internal DivisionFrame(XElement element, int depth)
        {
            Element = element;
            Depth = depth;
            ChildElements = [.. element.Elements(MetsNamespace + "div")];
        }


        /// <summary>The element this frame is over.</summary>
        internal XElement Element { get; }

        /// <summary>How deep the element sits.</summary>
        internal int Depth { get; }

        /// <summary>The child <c>div</c> elements, in document order.</summary>
        internal List<XElement> ChildElements { get; }

        /// <summary>The divisions already built from <see cref="ChildElements"/>, in document order.</summary>
        internal List<MetsDivision> BuiltChildren { get; } = [];

        /// <summary>Which of <see cref="ChildElements"/> is walked next.</summary>
        internal int NextChild { get; set; }
    }
}
