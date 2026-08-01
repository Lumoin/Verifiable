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
/// A worked <see cref="ParsePremisDelegate"/> and <see cref="EncodePremisDelegate"/> pair for a
/// preservation-metadata document, using <see cref="System.Xml.Linq"/> (BCL, no package) to move between the
/// serialisation-agnostic <see cref="PremisDocument"/> model and the vocabulary
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> constrains.
/// </summary>
/// <remarks>
/// <para>
/// This is a staged, promotable worked example, not a shipped library type, on exactly the terms
/// <see cref="MetsXmlBinding"/> states.
/// </para>
/// <para>
/// <strong>A documented interpretation of a transcription discrepancy.</strong> Requirement <c>PM64</c> names the
/// type element of a <c>relatedEventIdentifier</c> as <c>relatedObjectIdentifierType</c>, while its own sibling
/// <c>PM65</c> names the value element <c>relatedEventIdentifierValue</c> — the two cannot both be right, and
/// every other identifier container in the catalogue spells its two children with one prefix. This binding writes
/// and reads <c>relatedEventIdentifierType</c> beside <c>relatedEventIdentifierValue</c>, the reading the rest of
/// the vocabulary supports.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> The document arrives inside a package this library did not build:
/// document type definitions are prohibited outright, no external resource is ever resolved, and the element tree
/// is walked with an explicit <see cref="Stack{T}"/> under
/// <see cref="PremisParseLimits.MaximumElementDepth"/> rather than by a recursive method call.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code: public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
public static class PremisXmlBinding
{
    /// <summary>The preservation-metadata namespace, whose <c>elementFormDefault="qualified"</c> puts every element of a document in it.</summary>
    public static XNamespace PremisNamespace { get; } = PremisWellKnown.PremisNamespace;

    /// <summary>The XML Schema instance namespace, which carries the <c>xsi:type</c> attribute an object states its category in.</summary>
    public static XNamespace XmlSchemaInstanceNamespace { get; } = PremisWellKnown.XmlSchemaInstanceNamespace;

    /// <summary>The encoding a document is written in: UTF-8 with no byte order mark.</summary>
    private static UTF8Encoding DocumentEncoding { get; } = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);


    /// <summary>
    /// Parses a preservation-metadata document into the <see cref="PremisDocument"/> model. Has the
    /// <see cref="ParsePremisDelegate"/> shape.
    /// </summary>
    /// <param name="context">The document and the bounds to parse it under.</param>
    /// <param name="pool">The memory pool fixity carriers are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The parse result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every fixity carrier built here transfers to the successful PremisParseResult, which the caller disposes; the failure paths dispose everything the reader has built so far.")]
    public static ValueTask<PremisParseResult> ParseAsync(PremisParseContext context, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        PremisParseLimits limits = context.Limits;
        ReadOnlySpan<byte> octets = context.Document.AsReadOnlySpan();
        if(octets.Length > limits.MaximumDocumentByteLength)
        {
            return ValueTask.FromResult(PremisParseResult.Failed(
                PremisParseStatus.LimitExceeded,
                $"The document is {octets.Length} octets, over the {limits.MaximumDocumentByteLength} the limits admit."));
        }

        XDocument xml;
        byte[] rented = ArrayPool<byte>.Shared.Rent(Math.Max(octets.Length, 1));
        try
        {
            octets.CopyTo(rented);
            using var stream = new MemoryStream(rented, 0, octets.Length, writable: false);
            using XmlReader reader = XmlReader.Create(stream, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                CloseInput = false
            });

            xml = XDocument.Load(reader, LoadOptions.None);
        }
        catch(Exception ex) when(ex is XmlException or InvalidOperationException or DecoderFallbackException)
        {
            return ValueTask.FromResult(PremisParseResult.Failed(PremisParseStatus.Malformed, $"The document is not well-formed XML: {ex.Message}"));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }

        XElement? root = xml.Root;
        if(root is null || root.Name != PremisNamespace + "premis")
        {
            return ValueTask.FromResult(PremisParseResult.Failed(PremisParseStatus.Malformed, $"Unexpected root element '{root?.Name.ToString() ?? "(none)"}'."));
        }

        if(!IsWithinDepthBound(root, limits.MaximumElementDepth))
        {
            return ValueTask.FromResult(PremisParseResult.Failed(
                PremisParseStatus.LimitExceeded,
                $"The document nests deeper than the {limits.MaximumElementDepth} elements the limits admit."));
        }

        List<EArkFixity> fixities = [];
        bool owned = true;
        try
        {
            PremisParseResult result = ReadDocument(root, limits, pool, fixities);
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
    /// Writes a <see cref="PremisDocument"/> as a preservation-metadata document. Has the
    /// <see cref="EncodePremisDelegate"/> shape.
    /// </summary>
    /// <param name="context">The document to write and the fixity policy to write it under.</param>
    /// <param name="pool">The memory pool the produced document's carrier is rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The encoding result.</returns>
    public static ValueTask<PremisEncodeResult> EncodeAsync(PremisEncodeContext context, BaseMemoryPool pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(pool);
        cancellationToken.ThrowIfCancellationRequested();

        PremisDocument document = context.Document;
        var root = new XElement(
            PremisNamespace + "premis",
            new XAttribute(XNamespace.Xmlns + "xsi", XmlSchemaInstanceNamespace.NamespaceName),
            new XAttribute("version", document.Version));

        foreach(PremisObject premisObject in document.Objects)
        {
            if(premisObject.Identifiers.Count == 0)
            {
                return ValueTask.FromResult(MissingIdentifier("object"));
            }

            var element = new XElement(
                PremisNamespace + "object",
                new XAttribute(XmlSchemaInstanceNamespace + "type", premisObject.Category));

            WriteIdentifiers(element, "objectIdentifier", premisObject.Identifiers);
            foreach(PremisSignificantProperty property in premisObject.SignificantProperties)
            {
                element.Add(new XElement(
                    PremisNamespace + "significantProperties",
                    new XElement(PremisNamespace + "significantPropertiesType", property.Type),
                    new XElement(PremisNamespace + "significantPropertiesValue", property.Value)));
            }

            foreach(PremisObjectCharacteristics characteristics in premisObject.Characteristics)
            {
                var characteristicsElement = new XElement(PremisNamespace + "objectCharacteristics");
                foreach(EArkFixity fixity in characteristics.Fixities)
                {
                    if(!TryWriteFixity(fixity, context.AllowUnrecomputableFixity, out XElement? fixityElement))
                    {
                        return ValueTask.FromResult(PremisEncodeResult.Failed(
                            PremisEncodeStatus.UnrecomputableFixity,
                            "The document carries a fixity this library cannot recompute; state AllowUnrecomputableFixity to write it through."));
                    }

                    characteristicsElement.Add(fixityElement);
                }

                if(characteristics.Format is PremisFormat format)
                {
                    var formatElement = new XElement(PremisNamespace + "format");
                    if(format.Designation is PremisFormatDesignation designation)
                    {
                        formatElement.Add(new XElement(
                            PremisNamespace + "formatDesignation",
                            new XElement(PremisNamespace + "formatName", designation.Name),
                            OptionalElement("formatVersion", designation.Version)));
                    }

                    if(format.Registry is PremisFormatRegistry registry)
                    {
                        formatElement.Add(new XElement(
                            PremisNamespace + "formatRegistry",
                            new XElement(PremisNamespace + "formatRegistryName", registry.Name),
                            new XElement(PremisNamespace + "formatRegistryKey", registry.Key),
                            OptionalElement("formatRegistryRole", registry.Role)));
                    }

                    characteristicsElement.Add(formatElement);
                }

                foreach(PremisCreatingApplication application in characteristics.CreatingApplications)
                {
                    characteristicsElement.Add(new XElement(
                        PremisNamespace + "creatingApplication",
                        new XElement(PremisNamespace + "creatingApplicationName", application.Name),
                        OptionalElement("creatingApplicationVersion", application.Version),
                        OptionalElement("dateCreatedByApplication", application.DateCreatedByApplication)));
                }

                element.Add(characteristicsElement);
            }

            element.Add(OptionalElement("originalName", premisObject.OriginalName));
            foreach(PremisStorage storage in premisObject.Storage)
            {
                var storageElement = new XElement(PremisNamespace + "storage");
                if(storage.ContentLocation is PremisContentLocation location)
                {
                    storageElement.Add(new XElement(
                        PremisNamespace + "contentLocation",
                        new XElement(PremisNamespace + "contentLocationType", location.Type),
                        new XElement(PremisNamespace + "contentLocationValue", location.Value)));
                }

                storageElement.Add(OptionalElement("storageMedium", storage.Medium));
                element.Add(storageElement);
            }

            foreach(PremisEnvironmentFunction function in premisObject.EnvironmentFunctions)
            {
                element.Add(new XElement(
                    PremisNamespace + "environmentFunction",
                    new XElement(PremisNamespace + "environmentFunctionType", function.Type),
                    new XElement(PremisNamespace + "environmentFunctionLevel", function.Level)));
            }

            if(premisObject.EnvironmentDesignation is PremisEnvironmentDesignation environment)
            {
                element.Add(new XElement(
                    PremisNamespace + "environmentDesignation",
                    new XElement(PremisNamespace + "environmentName", environment.Name),
                    OptionalElement("environmentVersion", environment.Version),
                    OptionalElement("environmentOrigin", environment.Origin),
                    OptionalElement("environmentDesignationNote", environment.Note)));
            }

            foreach(PremisRelationship relationship in premisObject.Relationships)
            {
                var relationshipElement = new XElement(
                    PremisNamespace + "relationship",
                    new XElement(PremisNamespace + "relationshipType", relationship.Type),
                    new XElement(PremisNamespace + "relationshipSubType", relationship.SubType));

                WriteIdentifiers(relationshipElement, "relatedObjectIdentifier", relationship.RelatedObjectIdentifiers);
                WriteIdentifiers(relationshipElement, "relatedEventIdentifier", relationship.RelatedEventIdentifiers);
                relationshipElement.Add(OptionalElement("relatedEnvironmentPurpose", relationship.RelatedEnvironmentPurpose));
                element.Add(relationshipElement);
            }

            WriteIdentifiers(element, "linkingRightsStatementIdentifier", premisObject.RightsStatementIdentifiers);
            root.Add(element);
        }

        foreach(PremisEvent premisEvent in document.Events)
        {
            if(premisEvent.Identifiers.Count == 0)
            {
                return ValueTask.FromResult(MissingIdentifier("event"));
            }

            var element = new XElement(PremisNamespace + "event");
            WriteIdentifiers(element, "eventIdentifier", premisEvent.Identifiers);
            element.Add(new XElement(PremisNamespace + "eventType", premisEvent.Type));
            element.Add(new XElement(PremisNamespace + "eventDateTime", premisEvent.EventDateTime));
            if(premisEvent.Outcome is not null)
            {
                element.Add(new XElement(
                    PremisNamespace + "eventOutcomeInformation",
                    new XElement(PremisNamespace + "eventOutcome", premisEvent.Outcome)));
            }

            WriteIdentifiers(element, "linkingAgentIdentifier", premisEvent.LinkingAgentIdentifiers);
            WriteIdentifiers(element, "linkingObjectIdentifier", premisEvent.LinkingObjectIdentifiers);
            root.Add(element);
        }

        foreach(PremisAgent agent in document.Agents)
        {
            if(agent.Identifiers.Count == 0)
            {
                return ValueTask.FromResult(MissingIdentifier("agent"));
            }

            var element = new XElement(PremisNamespace + "agent");
            WriteIdentifiers(element, "agentIdentifier", agent.Identifiers);
            element.Add(new XElement(PremisNamespace + "agentName", agent.Name));
            element.Add(new XElement(PremisNamespace + "agentType", agent.Type));
            element.Add(OptionalElement("agentVersion", agent.Version));
            element.Add(OptionalElement("agentNote", agent.Note));
            WriteIdentifiers(element, "linkingRightsStatementIdentifier", agent.RightsStatementIdentifiers);
            root.Add(element);
        }

        if(document.RightsStatements.Count > 0)
        {
            var rightsElement = new XElement(PremisNamespace + "rights");
            foreach(PremisRightsStatement statement in document.RightsStatements)
            {
                if(statement.Identifiers.Count == 0)
                {
                    return ValueTask.FromResult(MissingIdentifier("rightsStatement"));
                }

                var element = new XElement(PremisNamespace + "rightsStatement");
                WriteIdentifiers(element, "rightsStatementIdentifier", statement.Identifiers);
                element.Add(new XElement(PremisNamespace + "rightsBasis", statement.Basis));
                if(statement.CopyrightInformation is PremisCopyrightInformation copyright)
                {
                    var copyrightElement = new XElement(
                        PremisNamespace + "copyrightInformation",
                        new XElement(PremisNamespace + "copyrightStatus", copyright.Status),
                        new XElement(PremisNamespace + "copyrightJurisdiction", copyright.Jurisdiction));

                    WriteIdentifiers(copyrightElement, "copyrightDocumentationIdentifier", copyright.DocumentationIdentifiers);
                    element.Add(copyrightElement);
                }

                if(statement.LicenseInformation is PremisLicenseInformation license)
                {
                    var licenseElement = new XElement(PremisNamespace + "licenseInformation");
                    WriteIdentifiers(licenseElement, "licenseDocumentationIdentifier", license.DocumentationIdentifiers);
                    element.Add(licenseElement);
                }

                if(statement.StatuteInformation is PremisStatuteInformation statute)
                {
                    var statuteElement = new XElement(
                        PremisNamespace + "statuteInformation",
                        new XElement(PremisNamespace + "statuteJurisdiction", statute.Jurisdiction),
                        new XElement(PremisNamespace + "statuteCitation", statute.Citation));

                    WriteIdentifiers(statuteElement, "statuteDocumentationIdentifier", statute.DocumentationIdentifiers);
                    element.Add(statuteElement);
                }

                if(statement.OtherRightsInformation is PremisOtherRightsInformation other)
                {
                    var otherElement = new XElement(PremisNamespace + "otherRightsInformation");
                    WriteIdentifiers(otherElement, "otherRightsDocumentationIdentifier", other.DocumentationIdentifiers);
                    otherElement.Add(new XElement(PremisNamespace + "otherRightsBasis", other.Basis));
                    element.Add(otherElement);
                }

                if(statement.RightsGranted is PremisRightsGranted granted)
                {
                    var grantedElement = new XElement(PremisNamespace + "rightsGranted");
                    foreach(string act in granted.Acts)
                    {
                        grantedElement.Add(new XElement(PremisNamespace + "act", act));
                    }

                    if(granted.TermOfGrant is PremisTermOfGrant term)
                    {
                        grantedElement.Add(new XElement(
                            PremisNamespace + "termOfGrant",
                            new XElement(PremisNamespace + "startDate", term.StartDate),
                            OptionalElement("endDate", term.EndDate)));
                    }

                    grantedElement.Add(OptionalElement("rightsGrantedNote", granted.Note));
                    element.Add(grantedElement);
                }

                rightsElement.Add(element);
            }

            root.Add(rightsElement);
        }

        return ValueTask.FromResult(PremisEncodeResult.Encoded(Serialize(root, pool)));

        //A failed result naming the entity that states no identifier.
        static PremisEncodeResult MissingIdentifier(string entity) => PremisEncodeResult.Failed(
            PremisEncodeStatus.MissingIdentifier,
            $"A {entity} element states no identifier, which the catalogue makes mandatory for every entity.");
    }


    /// <summary>
    /// Reads the whole document under a validated root element.
    /// </summary>
    /// <param name="root">The <c>premis</c> element.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <param name="pool">The memory pool fixity carriers are rented from.</param>
    /// <param name="fixities">Every fixity built so far, so a failure path can dispose them all.</param>
    /// <returns>The parse result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every object built here, and of the document built around them, transfers to the returned PremisParseResult, which the caller disposes; every failure path returns before the document is built and the fixities the caller collected are disposed by ParseAsync.")]
    private static PremisParseResult ReadDocument(XElement root, PremisParseLimits limits, BaseMemoryPool pool, List<EArkFixity> fixities)
    {
        string? version = (string?)root.Attribute("version");
        if(version is null)
        {
            return PremisParseResult.Failed(PremisParseStatus.MissingRequiredElement, "Requirement PM1 makes premis/@version mandatory.");
        }

        List<PremisObject> objects = [];
        foreach(XElement element in root.Elements(PremisNamespace + "object"))
        {
            if(objects.Count == limits.MaximumObjects)
            {
                return PremisParseResult.Failed(PremisParseStatus.LimitExceeded, $"The document carries more than the {limits.MaximumObjects} object elements the limits admit.");
            }

            string? category = (string?)element.Attribute(XmlSchemaInstanceNamespace + "type");
            if(category is null)
            {
                return PremisParseResult.Failed(PremisParseStatus.MissingRequiredElement, "An object element states no @xsi:type category (PM2, PM14, PM28).");
            }

            //The attribute's value is a qualified name, so "premis:file" and a prefix-free "file" under a default
            //declaration of this vocabulary's namespace name the same category. The prefix is resolved against
            //the element that carries it rather than stripped, because a prefix bound to some other namespace
            //names some other type and must not be read as this vocabulary's.
            category = ResolveCategory(element, category);

            (PremisParseStatus identifierStatus, IReadOnlyList<PremisIdentifier>? identifiers, string identifierReason) =
                ReadIdentifiers(element, "objectIdentifier", limits);
            if(identifiers is null)
            {
                return PremisParseResult.Failed(identifierStatus, identifierReason);
            }

            List<PremisSignificantProperty> properties = [];
            foreach(XElement propertyElement in element.Elements(PremisNamespace + "significantProperties"))
            {
                string? type = ChildValue(propertyElement, "significantPropertiesType");
                string? value = ChildValue(propertyElement, "significantPropertiesValue");
                if(type is null || value is null)
                {
                    return PremisParseResult.Failed(PremisParseStatus.MissingRequiredElement, "A significantProperties element states no type or no value (PM19, PM20).");
                }

                properties.Add(new PremisSignificantProperty(type, value));
            }

            List<PremisObjectCharacteristics> characteristics = [];
            foreach(XElement characteristicsElement in element.Elements(PremisNamespace + "objectCharacteristics"))
            {
                List<EArkFixity> characteristicsFixities = [];
                foreach(XElement fixityElement in characteristicsElement.Elements(PremisNamespace + "fixity"))
                {
                    if(characteristicsFixities.Count == limits.MaximumChildElements)
                    {
                        return PremisParseResult.Failed(PremisParseStatus.LimitExceeded, $"An objectCharacteristics element carries more than the {limits.MaximumChildElements} fixity elements the limits admit.");
                    }

                    EArkFixity fixity = EArkFixity.Read(
                        ChildValue(fixityElement, "messageDigestAlgorithm"),
                        ChildValue(fixityElement, "messageDigest"),
                        pool);

                    fixities.Add(fixity);
                    characteristicsFixities.Add(fixity);
                }

                characteristics.Add(new PremisObjectCharacteristics
                {
                    Fixities = characteristicsFixities,
                    Format = ReadFormat(characteristicsElement),
                    CreatingApplications = ReadCreatingApplications(characteristicsElement)
                });
            }

            List<PremisStorage> storage = [];
            foreach(XElement storageElement in element.Elements(PremisNamespace + "storage"))
            {
                PremisContentLocation? location = null;
                XElement? locationElement = storageElement.Element(PremisNamespace + "contentLocation");
                if(locationElement is not null)
                {
                    string? type = ChildValue(locationElement, "contentLocationType");
                    string? value = ChildValue(locationElement, "contentLocationValue");
                    if(type is null || value is null)
                    {
                        return PremisParseResult.Failed(PremisParseStatus.MissingRequiredElement, "A contentLocation element states no type or no value (PM54, PM55).");
                    }

                    location = new PremisContentLocation(type, value);
                }

                storage.Add(new PremisStorage(location, ChildValue(storageElement, "storageMedium")));
            }

            List<PremisEnvironmentFunction> functions = [];
            foreach(XElement functionElement in element.Elements(PremisNamespace + "environmentFunction"))
            {
                string? type = ChildValue(functionElement, "environmentFunctionType");
                string? level = ChildValue(functionElement, "environmentFunctionLevel");
                if(type is null || level is null)
                {
                    return PremisParseResult.Failed(PremisParseStatus.MissingRequiredElement, "An environmentFunction element states no type or no level (PM7, PM8).");
                }

                functions.Add(new PremisEnvironmentFunction(type, level));
            }

            PremisEnvironmentDesignation? designation = null;
            XElement? designationElement = element.Element(PremisNamespace + "environmentDesignation");
            if(designationElement is not null)
            {
                string? name = ChildValue(designationElement, "environmentName");
                if(name is null)
                {
                    return PremisParseResult.Failed(PremisParseStatus.MissingRequiredElement, "An environmentDesignation element states no name (PM10).");
                }

                designation = new PremisEnvironmentDesignation(
                    name,
                    ChildValue(designationElement, "environmentVersion"),
                    ChildValue(designationElement, "environmentOrigin"),
                    ChildValue(designationElement, "environmentDesignationNote"));
            }

            List<PremisRelationship> relationships = [];
            foreach(XElement relationshipElement in element.Elements(PremisNamespace + "relationship"))
            {
                string? type = ChildValue(relationshipElement, "relationshipType");
                string? subType = ChildValue(relationshipElement, "relationshipSubType");
                if(type is null || subType is null)
                {
                    return PremisParseResult.Failed(PremisParseStatus.MissingRequiredElement, "A relationship element states no type or no subtype (PM22, PM23, PM58, PM59).");
                }

                (PremisParseStatus relatedObjectStatus, IReadOnlyList<PremisIdentifier>? relatedObjects, string relatedObjectReason) =
                    ReadIdentifiers(relationshipElement, "relatedObjectIdentifier", limits);
                if(relatedObjects is null)
                {
                    return PremisParseResult.Failed(relatedObjectStatus, relatedObjectReason);
                }

                (PremisParseStatus relatedEventStatus, IReadOnlyList<PremisIdentifier>? relatedEvents, string relatedEventReason) =
                    ReadIdentifiers(relationshipElement, "relatedEventIdentifier", limits);
                if(relatedEvents is null)
                {
                    return PremisParseResult.Failed(relatedEventStatus, relatedEventReason);
                }

                relationships.Add(new PremisRelationship
                {
                    Type = type,
                    SubType = subType,
                    RelatedObjectIdentifiers = relatedObjects,
                    RelatedEventIdentifiers = relatedEvents,
                    RelatedEnvironmentPurpose = ChildValue(relationshipElement, "relatedEnvironmentPurpose")
                });
            }

            (PremisParseStatus rightsLinkStatus, IReadOnlyList<PremisIdentifier>? rightsLinks, string rightsLinkReason) =
                ReadIdentifiers(element, "linkingRightsStatementIdentifier", limits);
            if(rightsLinks is null)
            {
                return PremisParseResult.Failed(rightsLinkStatus, rightsLinkReason);
            }

            objects.Add(new PremisObject
            {
                Category = category,
                Identifiers = identifiers,
                SignificantProperties = properties,
                Characteristics = characteristics,
                OriginalName = ChildValue(element, "originalName"),
                Storage = storage,
                Relationships = relationships,
                RightsStatementIdentifiers = rightsLinks,
                EnvironmentFunctions = functions,
                EnvironmentDesignation = designation
            });
        }

        List<PremisEvent> events = [];
        foreach(XElement element in root.Elements(PremisNamespace + "event"))
        {
            if(events.Count == limits.MaximumEvents)
            {
                return PremisParseResult.Failed(PremisParseStatus.LimitExceeded, $"The document carries more than the {limits.MaximumEvents} event elements the limits admit.");
            }

            (PremisParseStatus identifierStatus, IReadOnlyList<PremisIdentifier>? identifiers, string identifierReason) =
                ReadIdentifiers(element, "eventIdentifier", limits);
            if(identifiers is null)
            {
                return PremisParseResult.Failed(identifierStatus, identifierReason);
            }

            string? type = ChildValue(element, "eventType");
            string? instant = ChildValue(element, "eventDateTime");
            if(type is null || instant is null)
            {
                return PremisParseResult.Failed(PremisParseStatus.MissingRequiredElement, "An event element states no type or no instant (PM84, PM85).");
            }

            (PremisParseStatus agentStatus, IReadOnlyList<PremisIdentifier>? agentLinks, string agentReason) =
                ReadIdentifiers(element, "linkingAgentIdentifier", limits);
            if(agentLinks is null)
            {
                return PremisParseResult.Failed(agentStatus, agentReason);
            }

            (PremisParseStatus objectStatus, IReadOnlyList<PremisIdentifier>? objectLinks, string objectReason) =
                ReadIdentifiers(element, "linkingObjectIdentifier", limits);
            if(objectLinks is null)
            {
                return PremisParseResult.Failed(objectStatus, objectReason);
            }

            events.Add(new PremisEvent
            {
                Identifiers = identifiers,
                Type = type,
                EventDateTime = instant,
                Outcome = ChildValue(element.Element(PremisNamespace + "eventOutcomeInformation"), "eventOutcome"),
                LinkingAgentIdentifiers = agentLinks,
                LinkingObjectIdentifiers = objectLinks
            });
        }

        List<PremisAgent> agents = [];
        foreach(XElement element in root.Elements(PremisNamespace + "agent"))
        {
            if(agents.Count == limits.MaximumAgents)
            {
                return PremisParseResult.Failed(PremisParseStatus.LimitExceeded, $"The document carries more than the {limits.MaximumAgents} agent elements the limits admit.");
            }

            (PremisParseStatus identifierStatus, IReadOnlyList<PremisIdentifier>? identifiers, string identifierReason) =
                ReadIdentifiers(element, "agentIdentifier", limits);
            if(identifiers is null)
            {
                return PremisParseResult.Failed(identifierStatus, identifierReason);
            }

            string? name = ChildValue(element, "agentName");
            string? type = ChildValue(element, "agentType");
            if(name is null || type is null)
            {
                return PremisParseResult.Failed(PremisParseStatus.MissingRequiredElement, "An agent element states no name or no type (PM73, PM74).");
            }

            (PremisParseStatus rightsStatus, IReadOnlyList<PremisIdentifier>? rightsLinks, string rightsReason) =
                ReadIdentifiers(element, "linkingRightsStatementIdentifier", limits);
            if(rightsLinks is null)
            {
                return PremisParseResult.Failed(rightsStatus, rightsReason);
            }

            agents.Add(new PremisAgent
            {
                Identifiers = identifiers,
                Name = name,
                Type = type,
                Version = ChildValue(element, "agentVersion"),
                Note = ChildValue(element, "agentNote"),
                RightsStatementIdentifiers = rightsLinks
            });
        }

        List<PremisRightsStatement> rightsStatements = [];
        foreach(XElement rightsElement in root.Elements(PremisNamespace + "rights"))
        {
            foreach(XElement element in rightsElement.Elements(PremisNamespace + "rightsStatement"))
            {
                if(rightsStatements.Count == limits.MaximumRightsStatements)
                {
                    return PremisParseResult.Failed(PremisParseStatus.LimitExceeded, $"The document carries more than the {limits.MaximumRightsStatements} rightsStatement elements the limits admit.");
                }

                (PremisParseStatus status, PremisRightsStatement? statement, string reason) = ReadRightsStatement(element, limits);
                if(statement is null)
                {
                    return PremisParseResult.Failed(status, reason);
                }

                rightsStatements.Add(statement);
            }
        }

        return PremisParseResult.Valid(new PremisDocument
        {
            Version = version,
            Objects = objects,
            Events = events,
            Agents = agents,
            RightsStatements = rightsStatements
        });
    }


    /// <summary>
    /// Reads one <c>rightsStatement</c> element.
    /// </summary>
    /// <param name="element">The element to read.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <returns>The status, the statement when it was read, and the reason when it was not.</returns>
    private static (PremisParseStatus Status, PremisRightsStatement? Statement, string Reason) ReadRightsStatement(XElement element, PremisParseLimits limits)
    {
        (PremisParseStatus identifierStatus, IReadOnlyList<PremisIdentifier>? identifiers, string identifierReason) =
            ReadIdentifiers(element, "rightsStatementIdentifier", limits);
        if(identifiers is null)
        {
            return (identifierStatus, null, identifierReason);
        }

        string? basis = ChildValue(element, "rightsBasis");
        if(basis is null)
        {
            return (PremisParseStatus.MissingRequiredElement, null, "A rightsStatement element states no basis (PM98).");
        }

        PremisCopyrightInformation? copyright = null;
        XElement? copyrightElement = element.Element(PremisNamespace + "copyrightInformation");
        if(copyrightElement is not null)
        {
            string? status = ChildValue(copyrightElement, "copyrightStatus");
            string? jurisdiction = ChildValue(copyrightElement, "copyrightJurisdiction");
            if(status is null || jurisdiction is null)
            {
                return (PremisParseStatus.MissingRequiredElement, null, "A copyrightInformation element states no status or no jurisdiction (PM100, PM101).");
            }

            (_, IReadOnlyList<PremisIdentifier>? documentation, string reason) = ReadIdentifiers(copyrightElement, "copyrightDocumentationIdentifier", limits);
            if(documentation is null)
            {
                return (PremisParseStatus.MissingRequiredElement, null, reason);
            }

            copyright = new PremisCopyrightInformation { Status = status, Jurisdiction = jurisdiction, DocumentationIdentifiers = documentation };
        }

        PremisLicenseInformation? license = null;
        XElement? licenseElement = element.Element(PremisNamespace + "licenseInformation");
        if(licenseElement is not null)
        {
            (_, IReadOnlyList<PremisIdentifier>? documentation, string reason) = ReadIdentifiers(licenseElement, "licenseDocumentationIdentifier", limits);
            if(documentation is null)
            {
                return (PremisParseStatus.MissingRequiredElement, null, reason);
            }

            license = new PremisLicenseInformation { DocumentationIdentifiers = documentation };
        }

        PremisStatuteInformation? statute = null;
        XElement? statuteElement = element.Element(PremisNamespace + "statuteInformation");
        if(statuteElement is not null)
        {
            string? jurisdiction = ChildValue(statuteElement, "statuteJurisdiction");
            string? citation = ChildValue(statuteElement, "statuteCitation");
            if(jurisdiction is null || citation is null)
            {
                return (PremisParseStatus.MissingRequiredElement, null, "A statuteInformation element states no jurisdiction or no citation (PM110, PM111).");
            }

            (_, IReadOnlyList<PremisIdentifier>? documentation, string reason) = ReadIdentifiers(statuteElement, "statuteDocumentationIdentifier", limits);
            if(documentation is null)
            {
                return (PremisParseStatus.MissingRequiredElement, null, reason);
            }

            statute = new PremisStatuteInformation { Jurisdiction = jurisdiction, Citation = citation, DocumentationIdentifiers = documentation };
        }

        PremisOtherRightsInformation? other = null;
        XElement? otherElement = element.Element(PremisNamespace + "otherRightsInformation");
        if(otherElement is not null)
        {
            string? otherBasis = ChildValue(otherElement, "otherRightsBasis");
            if(otherBasis is null)
            {
                return (PremisParseStatus.MissingRequiredElement, null, "An otherRightsInformation element states no basis (PM119).");
            }

            (_, IReadOnlyList<PremisIdentifier>? documentation, string reason) = ReadIdentifiers(otherElement, "otherRightsDocumentationIdentifier", limits);
            if(documentation is null)
            {
                return (PremisParseStatus.MissingRequiredElement, null, reason);
            }

            other = new PremisOtherRightsInformation { Basis = otherBasis, DocumentationIdentifiers = documentation };
        }

        PremisRightsGranted? granted = null;
        XElement? grantedElement = element.Element(PremisNamespace + "rightsGranted");
        if(grantedElement is not null)
        {
            List<string> acts = [];
            foreach(XElement actElement in grantedElement.Elements(PremisNamespace + "act"))
            {
                acts.Add(actElement.Value);
            }

            PremisTermOfGrant? term = null;
            XElement? termElement = grantedElement.Element(PremisNamespace + "termOfGrant");
            if(termElement is not null)
            {
                string? startDate = ChildValue(termElement, "startDate");
                if(startDate is null)
                {
                    return (PremisParseStatus.MissingRequiredElement, null, "A termOfGrant element states no start date (PM123).");
                }

                term = new PremisTermOfGrant(startDate, ChildValue(termElement, "endDate"));
            }

            granted = new PremisRightsGranted { Acts = acts, TermOfGrant = term, Note = ChildValue(grantedElement, "rightsGrantedNote") };
        }

        return (PremisParseStatus.Valid, new PremisRightsStatement
        {
            Identifiers = identifiers,
            Basis = basis,
            CopyrightInformation = copyright,
            LicenseInformation = license,
            StatuteInformation = statute,
            OtherRightsInformation = other,
            RightsGranted = granted
        }, string.Empty);
    }


    /// <summary>
    /// Reads every identifier container of one name under an element.
    /// </summary>
    /// <param name="element">The element to read under.</param>
    /// <param name="containerName">The container element's name, whose two children are that name plus <c>Type</c> and <c>Value</c>.</param>
    /// <param name="limits">The bounds the parse applies.</param>
    /// <returns>The status, the identifiers when they were read, and the reason when they were not.</returns>
    private static (PremisParseStatus Status, IReadOnlyList<PremisIdentifier>? Identifiers, string Reason) ReadIdentifiers(
        XElement element,
        string containerName,
        PremisParseLimits limits)
    {
        List<PremisIdentifier> identifiers = [];
        foreach(XElement container in element.Elements(PremisNamespace + containerName))
        {
            if(identifiers.Count == limits.MaximumChildElements)
            {
                return (PremisParseStatus.LimitExceeded, null, $"An element carries more than the {limits.MaximumChildElements} {containerName} elements the limits admit.");
            }

            string? type = ChildValue(container, containerName + "Type");
            string? value = ChildValue(container, containerName + "Value");
            if(type is null || value is null)
            {
                return (PremisParseStatus.MissingRequiredElement, null, $"A {containerName} element states no type or no value.");
            }

            if(type.Length > limits.MaximumTextLength || value.Length > limits.MaximumTextLength)
            {
                return (PremisParseStatus.LimitExceeded, null, $"A {containerName} value is longer than the {limits.MaximumTextLength} characters the limits admit.");
            }

            identifiers.Add(new PremisIdentifier(type, value));
        }

        return (PremisParseStatus.Valid, identifiers, string.Empty);
    }


    /// <summary>
    /// Reads the <c>format</c> element of an object's characteristics.
    /// </summary>
    /// <param name="element">The <c>objectCharacteristics</c> element.</param>
    /// <returns>The format, or <see langword="null"/> when the element states none.</returns>
    private static PremisFormat? ReadFormat(XElement element)
    {
        XElement? formatElement = element.Element(PremisNamespace + "format");
        if(formatElement is null)
        {
            return null;
        }

        PremisFormatDesignation? designation = null;
        XElement? designationElement = formatElement.Element(PremisNamespace + "formatDesignation");
        if(ChildValue(designationElement, "formatName") is string formatName)
        {
            designation = new PremisFormatDesignation(formatName, ChildValue(designationElement, "formatVersion"));
        }

        PremisFormatRegistry? registry = null;
        XElement? registryElement = formatElement.Element(PremisNamespace + "formatRegistry");
        if(ChildValue(registryElement, "formatRegistryName") is string registryName
            && ChildValue(registryElement, "formatRegistryKey") is string registryKey)
        {
            registry = new PremisFormatRegistry(registryName, registryKey, ChildValue(registryElement, "formatRegistryRole"));
        }

        return new PremisFormat(designation, registry);
    }


    /// <summary>
    /// Reads the <c>creatingApplication</c> elements of an object's characteristics.
    /// </summary>
    /// <param name="element">The <c>objectCharacteristics</c> element.</param>
    /// <returns>The applications, empty when the element states none.</returns>
    private static List<PremisCreatingApplication> ReadCreatingApplications(XElement element)
    {
        List<PremisCreatingApplication> applications = [];
        foreach(XElement applicationElement in element.Elements(PremisNamespace + "creatingApplication"))
        {
            if(ChildValue(applicationElement, "creatingApplicationName") is string name)
            {
                applications.Add(new PremisCreatingApplication(
                    name,
                    ChildValue(applicationElement, "creatingApplicationVersion"),
                    ChildValue(applicationElement, "dateCreatedByApplication")));
            }
        }

        return applications;
    }


    /// <summary>
    /// Writes every identifier of one container name under an element.
    /// </summary>
    /// <param name="element">The element to write under.</param>
    /// <param name="containerName">The container element's name.</param>
    /// <param name="identifiers">The identifiers to write.</param>
    private static void WriteIdentifiers(XElement element, string containerName, IReadOnlyList<PremisIdentifier> identifiers)
    {
        foreach(PremisIdentifier identifier in identifiers)
        {
            element.Add(new XElement(
                PremisNamespace + containerName,
                new XElement(PremisNamespace + containerName + "Type", identifier.Type),
                new XElement(PremisNamespace + containerName + "Value", identifier.Value)));
        }
    }


    /// <summary>
    /// Writes one <c>fixity</c> element.
    /// </summary>
    /// <param name="fixity">The fixity to write.</param>
    /// <param name="allowUnrecomputable">Whether a fixity this library cannot recompute may be written through.</param>
    /// <param name="element">The element, when one could be written.</param>
    /// <returns><see langword="true"/> when the element could be written.</returns>
    private static bool TryWriteFixity(EArkFixity fixity, bool allowUnrecomputable, out XElement? element)
    {
        switch(fixity)
        {
            case EArkRecomputableFixity recomputable:
                element = new XElement(
                    PremisNamespace + "fixity",
                    new XElement(PremisNamespace + "messageDigestAlgorithm", recomputable.ChecksumType),
                    new XElement(PremisNamespace + "messageDigest", Convert.ToHexStringLower(recomputable.Digest.AsReadOnlySpan())));

                return true;

            case EArkStatedFixity stated when allowUnrecomputable:
                element = new XElement(
                    PremisNamespace + "fixity",
                    new XElement(PremisNamespace + "messageDigestAlgorithm", stated.ChecksumType),
                    new XElement(PremisNamespace + "messageDigest", stated.Checksum));

                return true;

            default:
                element = null;

                return false;
        }
    }


    /// <summary>
    /// Resolves the qualified name an object states its category by.
    /// </summary>
    /// <param name="element">The <c>object</c> element carrying the attribute.</param>
    /// <param name="value">The attribute's value.</param>
    /// <returns>
    /// The local name when the qualified name resolves into this vocabulary's namespace, and the value exactly as
    /// stated when it does not — which is then a category no recognition helper will accept, as it should be.
    /// </returns>
    private static string ResolveCategory(XElement element, string value)
    {
        int colon = value.IndexOf(':', StringComparison.Ordinal);
        XNamespace? resolved = colon >= 0
            ? element.GetNamespaceOfPrefix(value[..colon])
            : element.GetDefaultNamespace();

        return resolved == PremisNamespace ? value[(colon + 1)..] : value;
    }


    /// <summary>
    /// Reads a child element's text value.
    /// </summary>
    /// <param name="element">The element to read under, or <see langword="null"/>.</param>
    /// <param name="childName">The child element's name.</param>
    /// <returns>The value, or <see langword="null"/> when the child is absent.</returns>
    private static string? ChildValue(XElement? element, string childName) =>
        element?.Element(PremisNamespace + childName)?.Value;


    /// <summary>
    /// Builds an element when a value is present.
    /// </summary>
    /// <param name="name">The element's local name.</param>
    /// <param name="value">The value, or <see langword="null"/>.</param>
    /// <returns>The element, or <see langword="null"/>.</returns>
    private static XElement? OptionalElement(string name, string? value) =>
        value is null ? null : new XElement(PremisNamespace + name, value);


    /// <summary>
    /// Serialises a document's root element into a pooled carrier.
    /// </summary>
    /// <param name="root">The <c>premis</c> element to write.</param>
    /// <param name="pool">The memory pool the carrier is rented from.</param>
    /// <returns>The produced octets. The caller owns and disposes them.</returns>
    private static PooledMemory Serialize(XElement root, BaseMemoryPool pool)
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
            ? PooledMemory.FromBytes(buffer.AsSpan(), pool, EArkTags.PremisDocument)
            : PooledMemory.FromBytes(stream.ToArray(), pool, EArkTags.PremisDocument);
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
}
