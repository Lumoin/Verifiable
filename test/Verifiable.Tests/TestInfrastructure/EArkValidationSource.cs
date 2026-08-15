using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Hand-built manifests, preservation-metadata documents and validation contexts for the E-ARK validation rule
/// tests: one conformant instance of each, and the mutations a rule is meant to catch expressed as changes to it.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Everything here is built from the shipped model rather than from XML.</strong> A rule reads the
/// serialisation-agnostic model and nothing else, so a rule test that went through a binding would be testing
/// the binding too and would fail for two different reasons. The binding has its own tests; these have theirs.
/// </para>
/// <para>
/// <strong>The conformant instances are conformant on purpose.</strong> Each satisfies every MUST and every
/// SHOULD of the catalogue its rules judge, so that a test asserting a failure can state exactly one departure
/// from it and know that nothing else contributed. The instances are built fresh on each call because the models
/// own pooled carriers and every caller disposes what it was handed.
/// </para>
/// </remarks>
internal static class EArkValidationSource
{
    /// <summary>The instant every hand-built document is stamped with, stated rather than read from a clock.</summary>
    internal static DateTimeOffset Instant { get; } = new(2026, 7, 31, 12, 0, 0, TimeSpan.Zero);

    /// <summary>A well-formed placeholder digest: 64 hexadecimal digits, which is what a SHA-256 checksum is.</summary>
    internal static string PlaceholderChecksum { get; } =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// <summary>The name of the software the conformant manifest names as its creator.</summary>
    internal static string CreatingAgentName { get; } = "the package writer under test";

    /// <summary>
    /// The package identifier the conformant manifest carries by default, a uniform resource name — the form
    /// the reference material's own worked packages use.
    /// </summary>
    internal static string UrnPackageIdentifier { get; } = "urn:uuid:2e1f6a52-9f0b-4a34-9d5e-0e2b8f0f1c77";

    /// <summary>
    /// A package identifier a root folder can actually be named with, which the one above cannot be: the
    /// colon a uniform resource name carries is a volume qualifier on some file systems and every entry-name
    /// rule in this repository refuses it, so a package whose identifier is a URN cannot follow the
    /// naming recommendation inside an archive at all.
    /// </summary>
    internal static string PortablePackageIdentifier { get; } = "uuid-2e1f6a52-9f0b-4a34-9d5e-0e2b8f0f1c77";


    /// <summary>Builds a fixity stating a checksum under an algorithm this library recomputes.</summary>
    /// <param name="checksum">The checksum value, as hexadecimal.</param>
    /// <returns>The fixity. The caller owns and disposes it, usually by disposing the document holding it.</returns>
    internal static EArkFixity Fixity(string? checksum = null) =>
        EArkFixity.Read(MetsWellKnown.Sha256ChecksumType, checksum ?? PlaceholderChecksum, BaseMemoryPool.Shared);


    /// <summary>Builds a fixity stating a checksum under an algorithm this library will not treat as evidence.</summary>
    /// <param name="checksumType">The algorithm name, one of the enumeration's weak or non-cryptographic members.</param>
    /// <returns>The fixity. The caller owns and disposes it.</returns>
    internal static EArkFixity WeakFixity(string checksumType) =>
        EArkFixity.Read(checksumType, "0123456789abcdef0123456789abcdef", BaseMemoryPool.Shared);


    /// <summary>Builds a metadata reference satisfying every row the catalogue states over one.</summary>
    /// <param name="href">The resource location the reference names.</param>
    /// <param name="metadataType">The metadata type the referenced document is written in.</param>
    /// <param name="metadataTypeVersion">The version of that type, or <see langword="null"/>.</param>
    /// <param name="checksum">The checksum value, or <see langword="null"/> for the placeholder.</param>
    /// <returns>The reference. The caller owns and disposes it.</returns>
    internal static MetsMetadataReference Reference(
        string href,
        string? metadataType = null,
        string? metadataTypeVersion = null,
        string? checksum = null) =>
        new()
        {
            LocatorType = MetsWellKnown.UrlLocatorType,
            LinkType = MetsWellKnown.SimpleLinkType,
            Href = href,
            MetadataType = metadataType ?? MetsWellKnown.OtherMetadataType,
            MetadataTypeVersion = metadataTypeVersion,
            MediaType = "text/xml",
            Size = 128,
            Created = Instant,
            Fixity = Fixity(checksum),
        };


    /// <summary>Builds a file entry satisfying every row the catalogue states over one.</summary>
    /// <param name="id">The file's identifier.</param>
    /// <param name="href">The resource location the file's locator names.</param>
    /// <param name="checksum">The checksum value, or <see langword="null"/> for the placeholder.</param>
    /// <param name="fixity">A fixity of the caller's own, which overrides <paramref name="checksum"/>.</param>
    /// <returns>The file. The caller owns and disposes it.</returns>
    internal static MetsFile File(string id, string href, string? checksum = null, EArkFixity? fixity = null) =>
        new()
        {
            Id = id,
            MediaType = "application/octet-stream",
            Size = 16,
            Created = Instant,
            Fixity = fixity ?? Fixity(checksum),
            Locator = new MetsFileLocator(MetsWellKnown.UrlLocatorType, MetsWellKnown.SimpleLinkType, href),
        };


    /// <summary>
    /// Builds a manifest satisfying every MUST and every SHOULD of the METS profile catalogue: the root
    /// attributes, the header with its closed-form creator stamp, a descriptive section, an administrative
    /// section with both a provenance and a rights sub-section, the three mandatory file groups, and the
    /// structural map with its four named divisions and one representation division.
    /// </summary>
    /// <param name="files">Files of the caller's own to place in the representation group, or <see langword="null"/> for the default one.</param>
    /// <param name="provenanceReference">A provenance reference of the caller's own, or <see langword="null"/> for the default one.</param>
    /// <param name="objectIdentifier">The package identifier, or <see langword="null"/> for the default one.</param>
    /// <param name="additionalFileGroups">
    /// Further file groups the caller places beside the three the profile's own catalogue asks for — a
    /// <c>Metadata</c> group naming an evidential artifact, for instance. Ownership of everything in them
    /// transfers to the returned manifest.
    /// </param>
    /// <returns>The manifest. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every section, file entry and fixity carrier built here transfers to the returned MetsDocument, whose own Dispose releases them and which the caller disposes.")]
    internal static MetsDocument ConformantManifest(
        IReadOnlyList<MetsFile>? files = null,
        MetsMetadataReference? provenanceReference = null,
        string? objectIdentifier = null,
        IReadOnlyList<MetsFileGroup>? additionalFileGroups = null) =>
        new()
        {
            ObjectIdentifier = objectIdentifier ?? UrnPackageIdentifier,
            ContentCategory = "OTHER",
            OtherContentCategory = "records",
            ContentInformationType = "MIXED",
            Profile = MetsWellKnown.CsipProfileUri,
            Header = new MetsHeader
            {
                CreateDate = Instant,
                LastModificationDate = Instant,
                OaisPackageType = MetsWellKnown.ArchivalPackageType,
                Agents =
                [
                    new MetsAgent
                    {
                        Role = MetsWellKnown.CreatorAgentRole,
                        Type = MetsWellKnown.OtherAgentType,
                        OtherType = MetsWellKnown.SoftwareAgentOtherType,
                        Name = CreatingAgentName,
                        Notes = [new MetsAgentNote(MetsWellKnown.SoftwareVersionNoteType, "1.0.0")],
                    }
                ],
            },
            DescriptiveMetadataSections =
            [
                new MetsDescriptiveMetadataSection
                {
                    Id = "dmd-1",
                    Created = Instant,
                    Status = MetsWellKnown.CurrentStatus,
                    Reference = Reference("metadata/descriptive/EAD.xml"),
                }
            ],
            AdministrativeMetadata = new MetsAdministrativeMetadata
            {
                DigitalProvenanceSections =
                [
                    new MetsAdministrativeMetadataSection
                    {
                        Id = "digiprov-1",
                        Status = MetsWellKnown.CurrentStatus,
                        Reference = provenanceReference ?? Reference(
                            "metadata/preservation/PREMIS.xml",
                            MetsWellKnown.PremisMetadataType,
                            PremisWellKnown.PremisVersion),
                    }
                ],
                RightsSections =
                [
                    new MetsAdministrativeMetadataSection
                    {
                        Id = "rights-1",
                        Status = MetsWellKnown.CurrentStatus,
                        Reference = Reference("metadata/other/rights.xml"),
                    }
                ],
            },
            FileSection = new MetsFileSection
            {
                Id = "file-section-1",
                FileGroups =
                [
                    new MetsFileGroup
                    {
                        Id = "group-documentation",
                        Use = MetsWellKnown.DocumentationLabel,
                        Files = [File("file-documentation-1", "documentation/manual.txt")],
                    },
                    new MetsFileGroup
                    {
                        Id = "group-schemas",
                        Use = MetsWellKnown.SchemasLabel,
                        Files = [File("file-schema-1", "schemas/mets.xsd")],
                    },
                    new MetsFileGroup
                    {
                        Id = "group-representations-rep1",
                        Use = MetsWellKnown.RepresentationsPrefix + "rep1",
                        ContentInformationType = "records",
                        Files = files ?? [File("file-data-1", "representations/rep1/data/record.bin")],
                    },
                    .. additionalFileGroups ?? []
                ],
            },
            StructuralMaps =
            [
                new MetsStructuralMap
                {
                    Id = "struct-map-1",
                    Type = MetsWellKnown.PhysicalStructuralMapType,
                    Label = MetsWellKnown.CsipStructuralMapLabel,
                    RootDivision = new MetsDivision
                    {
                        Id = "div-root",
                        Label = "the package",
                        Divisions =
                        [
                            new MetsDivision
                            {
                                Id = "div-metadata",
                                Label = MetsWellKnown.MetadataLabel,
                                AdministrativeMetadataIds = ["digiprov-1"],
                                DescriptiveMetadataIds = ["dmd-1"],
                            },
                            new MetsDivision
                            {
                                Id = "div-documentation",
                                Label = MetsWellKnown.DocumentationLabel,
                                FilePointers = [new MetsFilePointer("file-documentation-1")],
                            },
                            new MetsDivision
                            {
                                Id = "div-schemas",
                                Label = MetsWellKnown.SchemasLabel,
                                FilePointers = [new MetsFilePointer("file-schema-1")],
                            },
                            new MetsDivision
                            {
                                Id = "div-representations",
                                Label = MetsWellKnown.RepresentationsLabel,
                                FilePointers = [new MetsFilePointer("file-data-1")],
                            },
                            new MetsDivision
                            {
                                Id = "div-rep1",
                                Label = MetsWellKnown.RepresentationsPrefix + "rep1",
                                MetsPointers =
                                [
                                    new MetsPointer(
                                        "representations/rep1/METS.xml",
                                        MetsWellKnown.UrlLocatorType,
                                        MetsWellKnown.SimpleLinkType,
                                        "rep1")
                                ],
                            }
                        ],
                    },
                }
            ],
        };


    /// <summary>
    /// Builds a preservation-metadata document satisfying every MUST and every SHOULD of the preservation
    /// metadata catalogue that a document can satisfy at once: an intellectual entity describing an
    /// environment, a representation related to it, a file with its characteristics and fixity, an agent, an
    /// event naming that agent, and a rights statement resting on a copyright basis.
    /// </summary>
    /// <param name="additionalObjects">
    /// Further objects the caller places beside the three the catalogue's own rows are stated over — the object
    /// identifying an evidential artifact, for instance. Ownership transfers to the returned document.
    /// </param>
    /// <param name="additionalEvents">Further events the caller places beside the ingestion event.</param>
    /// <returns>The document. The caller owns and disposes it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of every object, characteristics block and fixity carrier built here transfers to the returned PremisDocument, whose own Dispose releases them and which the caller disposes.")]
    internal static PremisDocument ConformantPreservationMetadata(
        IReadOnlyList<PremisObject>? additionalObjects = null,
        IReadOnlyList<PremisEvent>? additionalEvents = null) =>
        new()
        {
            Version = PremisWellKnown.PremisVersion,
            Objects =
            [
                new PremisObject
                {
                    Category = PremisWellKnown.IntellectualEntityObjectCategory,
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "entity-1")],
                    EnvironmentFunctions = [new PremisEnvironmentFunction("software", "1")],
                    EnvironmentDesignation = new PremisEnvironmentDesignation("a rendering environment", "3.1", "an origin", "a note"),
                },
                new PremisObject
                {
                    Category = PremisWellKnown.RepresentationObjectCategory,
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "representation-1")],
                    SignificantProperties = [new PremisSignificantProperty("appearance", "page order preserved")],
                    Relationships =
                    [
                        new PremisRelationship
                        {
                            Type = "dependency",
                            SubType = "requires",
                            RelatedObjectIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "entity-1")],
                            RelatedEnvironmentPurpose = "render",
                        }
                    ],
                },
                new PremisObject
                {
                    Category = PremisWellKnown.FileObjectCategory,
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "file-1")],
                    OriginalName = "record.bin",
                    Characteristics =
                    [
                        new PremisObjectCharacteristics
                        {
                            Fixities = [Fixity()],
                            Format = new PremisFormat(
                                new PremisFormatDesignation("Octet Stream", "1.0"),
                                new PremisFormatRegistry("a format registry", "fmt/000", "specification")),
                            CreatingApplications = [new PremisCreatingApplication("the package writer under test", "1.0.0", "2026-07-31T12:00:00Z")],
                        }
                    ],
                    Storage = [new PremisStorage(new PremisContentLocation("URI", "representations/rep1/data/record.bin"), "disk")],
                    Relationships =
                    [
                        new PremisRelationship
                        {
                            Type = "structural",
                            SubType = "is part of",
                            RelatedObjectIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "representation-1")],
                            RelatedEventIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "event-ingest-1")],
                        }
                    ],
                    RightsStatementIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "rights-1")],
                },
                .. additionalObjects ?? []
            ],
            Events =
            [
                new PremisEvent
                {
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "event-ingest-1")],
                    Type = "ingestion",
                    EventDateTime = "2026-07-31T12:00:00Z",
                    Outcome = "success",
                    LinkingAgentIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "agent-1")],
                    LinkingObjectIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "file-1")],
                },
                .. additionalEvents ?? []
            ],
            Agents =
            [
                new PremisAgent
                {
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "agent-1")],
                    Name = CreatingAgentName,
                    Type = "software",
                    Version = "1.0.0",
                    Note = "the agent that performed the ingestion",
                    RightsStatementIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "rights-1")],
                }
            ],
            RightsStatements =
            [
                new PremisRightsStatement
                {
                    Identifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "rights-1")],
                    Basis = PremisWellKnown.CopyrightRightsBasis,
                    CopyrightInformation = new PremisCopyrightInformation
                    {
                        Status = "copyrighted",
                        Jurisdiction = "fi",
                        DocumentationIdentifiers = [new PremisIdentifier(PremisWellKnown.LocalIdentifierType, "copyright-doc-1")],
                    },
                    RightsGranted = new PremisRightsGranted
                    {
                        Acts = ["disseminate"],
                        TermOfGrant = new PremisTermOfGrant("2026-01-01", "2036-01-01"),
                        Note = "granted for the duration stated",
                    },
                }
            ],
        };


    /// <summary>The entries of a package satisfying every folder requirement of the structure catalogue.</summary>
    /// <returns>The entries, which the snapshot reader copies.</returns>
    internal static IReadOnlyList<EArkPackageEntrySource> ConformantPackageEntries() =>
    [
        EArkPackageSource.TextFile("METS.xml", "<mets/>"),
        EArkPackageSource.TextFile("metadata/preservation/PREMIS.xml", "<premis/>"),
        EArkPackageSource.TextFile("metadata/descriptive/EAD.xml", "<ead/>"),
        EArkPackageSource.TextFile("metadata/other/rights.xml", "<rights/>"),
        EArkPackageSource.TextFile("schemas/mets.xsd", "<xs:schema/>"),
        EArkPackageSource.TextFile("documentation/manual.txt", "how this package was made"),
        EArkPackageSource.TextFile("representations/rep1/METS.xml", "<mets/>"),
        EArkPackageSource.TextFile("representations/rep1/metadata/summary.txt", "about this representation"),
        EArkPackageSource.TextFile("representations/rep1/data/record.bin", "the bits themselves"),
    ];
}
