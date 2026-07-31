using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using System.Xml.Schema;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Validates what the staged bindings write against grammars stated independently of them: the authentic METS
/// schemas the <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> clone ships,
/// and — for preservation metadata, whose schema the clone does not ship — a subset schema written here from the
/// requirement tables of <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see>.
/// </summary>
/// <remarks>
/// <para>
/// The schemas are optional local reference material under <c>tempdocs/</c>, which is not a repository asset, so
/// <see cref="TryBuildMetsSchemas"/> answers <see langword="null"/> when they are absent and the tests that use it
/// report inconclusive rather than failing for a reason that has nothing to do with what they check — the shape
/// <see cref="AsicManifestSchemaOracle"/> established.
/// </para>
/// <para>
/// <strong>Three legs, of two different strengths, and the weaker one is named as such.</strong> The METS leg and
/// the authentic preservation-metadata leg both validate against the specifications' own schema files, which
/// nothing in this repository wrote: the METS schemas sit in the package-specification clone's <c>schema</c>
/// folder, and the preservation-metadata schema ships inside the reference corpus' own packages, where the
/// folder-structure requirements ask a package to carry a copy of every schema its metadata is stated under. The
/// third leg is <see cref="PremisSubsetSchema"/>, written out here from the requirement tables — element names,
/// containment and cardinality read off <c>PM1</c>–<c>PM125</c>. It is an independent statement of the same
/// requirements, written from the tables rather than from the binding, but it is not the vocabulary's own schema
/// and does not claim to be; it exists so that the catalogue's own reading is checked even where the vocabulary's
/// schema is looser, and so that a document can be validated at all when the optional reference material is
/// absent.
/// </para>
/// </remarks>
internal static class EArkSchemaOracle
{
    /// <summary>What a test reports when the optional local reference material is absent.</summary>
    internal static string MissingSchemaMessage { get; } =
        "The METS schemas were not found under tempdocs/earchiving-reference; they are optional local reference material, not a repository asset.";

    /// <summary>What a test reports when the authentic preservation-metadata schema is absent.</summary>
    internal static string MissingPremisSchemaMessage { get; } =
        "The authentic preservation-metadata schema was not found under tempdocs/earchiving-reference; it is optional local reference material, not a repository asset.";

    /// <summary>The file name of the base METS schema, as the specification clone ships it.</summary>
    private static string MetsSchemaFileName { get; } = "mets.xsd";

    /// <summary>The file name of the extension schema that declares the profile's own attributes.</summary>
    private static string ExtensionSchemaFileName { get; } = "DILCISExtensionMETS.xsd";

    /// <summary>The file name of the XLink schema the base METS schema imports.</summary>
    private static string XLinkSchemaFileName { get; } = "xlink.xsd";

    /// <summary>
    /// The absolute location the base METS schema states in its one <c>xsd:import</c>, which
    /// <see cref="OfflineSchemaResolver"/> answers from disk and which nothing here ever fetches.
    /// </summary>
    private static string XLinkSchemaLocation { get; } = "http://www.loc.gov/standards/xlink/xlink.xsd";

    /// <summary>
    /// The declaration that tells the XLink schema the base METS schema imports apart from the other schema of the
    /// same namespace and the same file name.
    /// </summary>
    /// <remarks>
    /// <strong>Two different schemas for one namespace ship in the reference corpus, and picking the wrong one
    /// silently ruins the validation.</strong> The corpus' packages carry two documents named <c>xlink.xsd</c>,
    /// both declaring the XLink namespace: the one the base METS schema names in its import, which defines the
    /// attribute groups <c>simpleLink</c>, <c>extendedLink</c>, <c>locatorLink</c> and <c>arcLink</c> that METS
    /// references by name; and the link-language's own later schema, which defines a different set under different
    /// names and imports a further namespace. Taking whichever the file system enumerates first leaves every one
    /// of those references undeclared, which is how this was found. The marker below selects by what the schema
    /// declares rather than by where it sits.
    /// </remarks>
    private static string XLinkAttributeGroupMarker { get; } = "attributeGroup name=\"simpleLink\"";

    /// <summary>
    /// The file name the reference corpus' packages carry the authentic preservation-metadata schema under.
    /// </summary>
    /// <remarks>
    /// The name is the corpus', not the vocabulary's: the schema the packages ship is the version 3.0 document the
    /// vocabulary publishes, stored under a name that states its version so that a package may carry a copy of an
    /// earlier one beside it — which several corpus packages do, under <c>premis-v2-1.xsd</c>, for their
    /// representation-level metadata.
    /// </remarks>
    private static string PremisSchemaFileName { get; } = "premis-v3-0.xsd";

    /// <summary>The identifier containers the catalogue states, each with its own two child element names.</summary>
    private static IReadOnlyList<string> IdentifierContainers { get; } =
    [
        "objectIdentifier",
        "relatedObjectIdentifier",
        "relatedEventIdentifier",
        "linkingRightsStatementIdentifier",
        "eventIdentifier",
        "linkingAgentIdentifier",
        "linkingObjectIdentifier",
        "agentIdentifier",
        "rightsStatementIdentifier",
        "copyrightDocumentationIdentifier",
        "licenseDocumentationIdentifier",
        "statuteDocumentationIdentifier",
        "otherRightsDocumentationIdentifier"
    ];


    /// <summary>
    /// Builds the METS schema set from the specification clone's own schema files.
    /// </summary>
    /// <returns>The compiled schema set, or <see langword="null"/> when the reference material is absent.</returns>
    /// <remarks>
    /// The base schema imports the XLink namespace by an absolute location, and a schema processor satisfies such
    /// an import by fetching that location rather than by looking for the namespace among the schemas it already
    /// holds. The set is therefore given <see cref="OfflineSchemaResolver"/>, which answers exactly the one
    /// location the schemas name — from the copy the reference corpus ships inside every package's own
    /// <c>schemas</c> folder, as the folder-structure requirements ask a package to — and refuses every other,
    /// so a test never reaches a network and a schema quietly fetched from one can never take part in a
    /// validation.
    /// </remarks>
    internal static XmlSchemaSet? TryBuildMetsSchemas()
    {
        string? referenceMaterial = TryFindReferenceMaterial();
        if(referenceMaterial is null)
        {
            return null;
        }

        string? metsSchema = TryFindFile(referenceMaterial, MetsSchemaFileName);
        string? extensionSchema = TryFindFile(referenceMaterial, ExtensionSchemaFileName);
        string? xlinkSchema = TryFindFile(referenceMaterial, XLinkSchemaFileName, XLinkAttributeGroupMarker);
        if(metsSchema is null || extensionSchema is null || xlinkSchema is null)
        {
            return null;
        }

        var readerSettings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        var schemas = new XmlSchemaSet
        {
            XmlResolver = new OfflineSchemaResolver(new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [XLinkSchemaLocation] = xlinkSchema
            })
        };

        using(var xmlNamespace = new StringReader(XmlNamespaceSchema()))
        using(XmlReader reader = XmlReader.Create(xmlNamespace, readerSettings))
        {
            _ = schemas.Add(null, reader);
        }

        //The XLink schema is not added here: the base METS schema imports it, and the resolver above answers that
        //import from the same file. Adding it beside the import would declare its global attributes twice.
        foreach(string schemaPath in new[] { extensionSchema, metsSchema })
        {
            using XmlReader reader = XmlReader.Create(schemaPath, readerSettings);
            _ = schemas.Add(null, reader);
        }

        schemas.Compile();

        return schemas;
    }


    /// <summary>
    /// Writes the schema for the namespace reserved by
    /// <see href="https://www.w3.org/TR/xml-names/#xmlReserved">Namespaces in XML 1.0 clause 3</see>, declaring
    /// the four attributes that namespace holds.
    /// </summary>
    /// <returns>The schema document.</returns>
    /// <remarks>
    /// <para>
    /// It is needed because the base METS schema annotates almost every declaration it makes with
    /// <c>xsd:documentation xml:lang="en"</c> while importing only the XLink namespace — so the namespace those
    /// annotations are written in is never declared to a processor that resolves nothing over a network. Supplying
    /// the declarations from the namespace's own specification is the only way to compile the schema set offline
    /// without either fetching a document or silencing the compiler's diagnostics, and silencing them would make
    /// every validation this oracle performs worth nothing.
    /// </para>
    /// <para>
    /// The four attributes are the ones the clause reserves, with the types
    /// <see href="https://www.w3.org/TR/xmlschema11-2/">XML Schema Definition Language Part 2</see> gives them.
    /// Nothing here is this repository's invention and nothing here is METS-specific.
    /// </para>
    /// </remarks>
    private static string XmlNamespaceSchema() =>
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xml="http://www.w3.org/XML/1998/namespace"
          targetNamespace="http://www.w3.org/XML/1998/namespace">
          <xs:attribute name="lang" type="xs:language"/>
          <xs:attribute name="space">
            <xs:simpleType>
              <xs:restriction base="xs:NCName">
                <xs:enumeration value="default"/>
                <xs:enumeration value="preserve"/>
              </xs:restriction>
            </xs:simpleType>
          </xs:attribute>
          <xs:attribute name="base" type="xs:anyURI"/>
          <xs:attribute name="id" type="xs:ID"/>
        </xs:schema>
        """;


    /// <summary>
    /// Builds the preservation-metadata schema set from the authentic schema the reference corpus' packages ship.
    /// </summary>
    /// <returns>The compiled schema set, or <see langword="null"/> when the reference material is absent.</returns>
    /// <remarks>
    /// The schema imports nothing, so the set compiles from one file with the resolver disabled and a test never
    /// depends on a network. This is the strongest of the three legs: what the binding writes is checked against
    /// the vocabulary's own grammar rather than against this repository's reading of the requirement tables.
    /// </remarks>
    internal static XmlSchemaSet? TryBuildAuthenticPremisSchemas()
    {
        string? referenceMaterial = TryFindReferenceMaterial();
        if(referenceMaterial is null)
        {
            return null;
        }

        string? premisSchema = TryFindFile(referenceMaterial, PremisSchemaFileName);
        if(premisSchema is null)
        {
            return null;
        }

        var readerSettings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        var schemas = new XmlSchemaSet { XmlResolver = null };
        using(XmlReader reader = XmlReader.Create(premisSchema, readerSettings))
        {
            _ = schemas.Add(null, reader);
        }

        schemas.Compile();

        return schemas;
    }


    /// <summary>
    /// Builds the preservation-metadata subset schema.
    /// </summary>
    /// <returns>The compiled schema set, which needs no reference material because the schema is written here.</returns>
    internal static XmlSchemaSet BuildPremisSchemas()
    {
        var readerSettings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        var schemas = new XmlSchemaSet { XmlResolver = null };
        using(var text = new StringReader(PremisSubsetSchema()))
        using(XmlReader reader = XmlReader.Create(text, readerSettings))
        {
            _ = schemas.Add(null, reader);
        }

        schemas.Compile();

        return schemas;
    }


    /// <summary>
    /// Validates a document against a compiled schema set.
    /// </summary>
    /// <param name="document">The document's octets.</param>
    /// <param name="schemas">The schema set to validate against.</param>
    /// <returns>Every problem the validation reported; empty when the document is schema-valid.</returns>
    internal static List<string> Validate(ReadOnlySpan<byte> document, XmlSchemaSet schemas)
    {
        List<string> problems = [];
        XDocument parsed = XDocument.Parse(Encoding.UTF8.GetString(document));
        parsed.Validate(schemas, (_, arguments) => problems.Add(arguments.Message));

        return problems;
    }


    /// <summary>
    /// Walks up from the test assembly's location to the repository root and names the reference-material folder.
    /// </summary>
    /// <returns>The folder's path, or <see langword="null"/> when it is absent.</returns>
    private static string? TryFindReferenceMaterial()
    {
        DirectoryInfo? current = new(AppContext.BaseDirectory);
        while(current is not null && !File.Exists(Path.Combine(current.FullName, "Verifiable.slnx")))
        {
            current = current.Parent;
        }

        if(current is null)
        {
            return null;
        }

        string referenceMaterial = Path.Combine(current.FullName, "tempdocs", "earchiving-reference");

        return Directory.Exists(referenceMaterial) ? referenceMaterial : null;
    }


    /// <summary>
    /// Finds the first file of a given name anywhere under the reference material, optionally requiring it to
    /// declare something in particular.
    /// </summary>
    /// <param name="referenceMaterial">The reference-material folder.</param>
    /// <param name="fileName">The file's name.</param>
    /// <param name="requiredContent">
    /// Text the file has to carry, or <see langword="null"/> when the name settles it. It exists because the
    /// reference material carries more than one document under one name — see
    /// <see cref="XLinkAttributeGroupMarker"/> — and a schema chosen by name alone would be the wrong schema
    /// without anything saying so.
    /// </param>
    /// <returns>The file's path, or <see langword="null"/> when no matching file is present.</returns>
    private static string? TryFindFile(string referenceMaterial, string fileName, string? requiredContent = null)
    {
        foreach(string candidate in Directory.EnumerateFiles(referenceMaterial, fileName, SearchOption.AllDirectories))
        {
            if(requiredContent is null || File.ReadAllText(candidate).Contains(requiredContent, StringComparison.Ordinal))
            {
                return candidate;
            }
        }

        return null;
    }


    /// <summary>
    /// Answers exactly the schema locations a known schema names, from disk, and refuses every other.
    /// </summary>
    /// <remarks>
    /// A schema that imports another by an absolute location gives a processor two ways to satisfy the import and
    /// only one of them is acceptable here: fetching the location is a network dependency and a silent
    /// substitution of whatever is served today for what a validation was meant to be against. Refusing outright
    /// is the alternative, and it makes an unknown location a loud failure rather than a schema that quietly
    /// validates less than it should.
    /// </remarks>
    private sealed class OfflineSchemaResolver: XmlResolver
    {
        /// <summary>
        /// Initialises a resolver over the locations it will answer.
        /// </summary>
        /// <param name="knownLocations">Each absolute location the schemas name, mapped to the file that holds it.</param>
        internal OfflineSchemaResolver(IReadOnlyDictionary<string, string> knownLocations)
        {
            KnownLocations = knownLocations;
        }


        /// <summary>Each absolute location the schemas name, mapped to the file that holds it.</summary>
        private IReadOnlyDictionary<string, string> KnownLocations { get; }


        /// <summary>
        /// Opens the file a known location stands for.
        /// </summary>
        /// <param name="absoluteUri">The location being resolved.</param>
        /// <param name="role">The resolution's role, which nothing here varies on.</param>
        /// <param name="ofObjectToReturn">The type asked for, which is a stream or unspecified.</param>
        /// <returns>A stream over the file.</returns>
        /// <exception cref="XmlException">When the location is not one of the known ones.</exception>
        public override object GetEntity(Uri absoluteUri, string? role, Type? ofObjectToReturn)
        {
            ArgumentNullException.ThrowIfNull(absoluteUri);

            if(KnownLocations.TryGetValue(absoluteUri.OriginalString, out string? path))
            {
                return File.OpenRead(path);
            }

            throw new XmlException($"The schema location '{absoluteUri.OriginalString}' is not one this oracle holds a copy of, and nothing here fetches one.");
        }
    }


    /// <summary>
    /// Writes the preservation-metadata subset schema from the catalogue's tables.
    /// </summary>
    /// <returns>The schema document.</returns>
    /// <remarks>
    /// <para>
    /// Every particle below is read off a requirement rather than off the binding: the version attribute from
    /// <c>PM1</c>; the four object categories from <c>PM2</c>, <c>PM14</c> and <c>PM28</c>, modelled as the
    /// derivations of an abstract base so that an object stating no category cannot validate at all; the object's
    /// members from <c>PM3</c>–<c>PM68</c>; the agent's from <c>PM69</c>–<c>PM79</c>; the event's from
    /// <c>PM80</c>–<c>PM92</c>; and the rights statement's from <c>PM93</c>–<c>PM125</c>. Cardinalities are the
    /// tables' own.
    /// </para>
    /// <para>
    /// The type element of a <c>relatedEventIdentifier</c> is spelled <c>relatedEventIdentifierType</c> here. The
    /// catalogue spells it <c>relatedObjectIdentifierType</c> at <c>PM64</c> while spelling its sibling value
    /// element <c>relatedEventIdentifierValue</c> at <c>PM65</c>; the two cannot both be right, and every other
    /// container in the catalogue spells its children with one prefix.
    /// </para>
    /// </remarks>
    private static string PremisSubsetSchema()
    {
        var schema = new StringBuilder();
        _ = schema.Append(
            """
            <?xml version="1.0" encoding="UTF-8"?>
            <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns="http://www.loc.gov/premis/v3"
              targetNamespace="http://www.loc.gov/premis/v3" elementFormDefault="qualified">

            """);

        foreach(string container in IdentifierContainers)
        {
            _ = schema.Append(
                CultureInfo.InvariantCulture,
                $"""
                  <xs:element name="{container}">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="{container}Type" type="xs:string"/>
                        <xs:element name="{container}Value" type="xs:string"/>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>

                """);
        }

        _ = schema.Append(
            """
              <xs:complexType name="objectComplexType" abstract="true">
                <xs:sequence>
                  <xs:element ref="objectIdentifier" maxOccurs="unbounded"/>
                  <xs:element name="significantProperties" minOccurs="0" maxOccurs="unbounded">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="significantPropertiesType" type="xs:string"/>
                        <xs:element name="significantPropertiesValue" type="xs:string"/>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element name="objectCharacteristics" minOccurs="0" maxOccurs="unbounded">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="fixity" minOccurs="0" maxOccurs="unbounded">
                          <xs:complexType>
                            <xs:sequence>
                              <xs:element name="messageDigestAlgorithm" type="xs:string"/>
                              <xs:element name="messageDigest" type="xs:string"/>
                              <xs:element name="messageDigestOriginator" type="xs:string" minOccurs="0"/>
                            </xs:sequence>
                          </xs:complexType>
                        </xs:element>
                        <xs:element name="format" minOccurs="0">
                          <xs:complexType>
                            <xs:sequence>
                              <xs:element name="formatDesignation" minOccurs="0">
                                <xs:complexType>
                                  <xs:sequence>
                                    <xs:element name="formatName" type="xs:string"/>
                                    <xs:element name="formatVersion" type="xs:string" minOccurs="0"/>
                                  </xs:sequence>
                                </xs:complexType>
                              </xs:element>
                              <xs:element name="formatRegistry" minOccurs="0">
                                <xs:complexType>
                                  <xs:sequence>
                                    <xs:element name="formatRegistryName" type="xs:string"/>
                                    <xs:element name="formatRegistryKey" type="xs:string"/>
                                    <xs:element name="formatRegistryRole" type="xs:string" minOccurs="0"/>
                                  </xs:sequence>
                                </xs:complexType>
                              </xs:element>
                            </xs:sequence>
                          </xs:complexType>
                        </xs:element>
                        <xs:element name="creatingApplication" minOccurs="0" maxOccurs="unbounded">
                          <xs:complexType>
                            <xs:sequence>
                              <xs:element name="creatingApplicationName" type="xs:string"/>
                              <xs:element name="creatingApplicationVersion" type="xs:string" minOccurs="0"/>
                              <xs:element name="dateCreatedByApplication" type="xs:string" minOccurs="0"/>
                            </xs:sequence>
                          </xs:complexType>
                        </xs:element>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element name="originalName" type="xs:string" minOccurs="0"/>
                  <xs:element name="storage" minOccurs="0" maxOccurs="unbounded">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="contentLocation" minOccurs="0">
                          <xs:complexType>
                            <xs:sequence>
                              <xs:element name="contentLocationType" type="xs:string"/>
                              <xs:element name="contentLocationValue" type="xs:string"/>
                            </xs:sequence>
                          </xs:complexType>
                        </xs:element>
                        <xs:element name="storageMedium" type="xs:string" minOccurs="0"/>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element name="environmentFunction" minOccurs="0" maxOccurs="unbounded">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="environmentFunctionType" type="xs:string"/>
                        <xs:element name="environmentFunctionLevel" type="xs:string"/>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element name="environmentDesignation" minOccurs="0">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="environmentName" type="xs:string"/>
                        <xs:element name="environmentVersion" type="xs:string" minOccurs="0"/>
                        <xs:element name="environmentOrigin" type="xs:string" minOccurs="0"/>
                        <xs:element name="environmentDesignationNote" type="xs:string" minOccurs="0"/>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element name="relationship" minOccurs="0" maxOccurs="unbounded">
                    <xs:complexType>
                      <xs:sequence>
                        <xs:element name="relationshipType" type="xs:string"/>
                        <xs:element name="relationshipSubType" type="xs:string"/>
                        <xs:element ref="relatedObjectIdentifier" minOccurs="0" maxOccurs="unbounded"/>
                        <xs:element ref="relatedEventIdentifier" minOccurs="0" maxOccurs="unbounded"/>
                        <xs:element name="relatedEnvironmentPurpose" type="xs:string" minOccurs="0"/>
                      </xs:sequence>
                    </xs:complexType>
                  </xs:element>
                  <xs:element ref="linkingRightsStatementIdentifier" minOccurs="0" maxOccurs="unbounded"/>
                </xs:sequence>
              </xs:complexType>

              <xs:complexType name="intellectualEntity">
                <xs:complexContent><xs:extension base="objectComplexType"/></xs:complexContent>
              </xs:complexType>
              <xs:complexType name="representation">
                <xs:complexContent><xs:extension base="objectComplexType"/></xs:complexContent>
              </xs:complexType>
              <xs:complexType name="file">
                <xs:complexContent><xs:extension base="objectComplexType"/></xs:complexContent>
              </xs:complexType>
              <xs:complexType name="bitstream">
                <xs:complexContent><xs:extension base="objectComplexType"/></xs:complexContent>
              </xs:complexType>

              <xs:element name="object" type="objectComplexType"/>

              <xs:element name="event">
                <xs:complexType>
                  <xs:sequence>
                    <xs:element ref="eventIdentifier" maxOccurs="unbounded"/>
                    <xs:element name="eventType" type="xs:string"/>
                    <xs:element name="eventDateTime" type="xs:string"/>
                    <xs:element name="eventOutcomeInformation" minOccurs="0">
                      <xs:complexType>
                        <xs:sequence>
                          <xs:element name="eventOutcome" type="xs:string"/>
                        </xs:sequence>
                      </xs:complexType>
                    </xs:element>
                    <xs:element ref="linkingAgentIdentifier" minOccurs="0" maxOccurs="unbounded"/>
                    <xs:element ref="linkingObjectIdentifier" minOccurs="0" maxOccurs="unbounded"/>
                  </xs:sequence>
                </xs:complexType>
              </xs:element>

              <xs:element name="agent">
                <xs:complexType>
                  <xs:sequence>
                    <xs:element ref="agentIdentifier" maxOccurs="unbounded"/>
                    <xs:element name="agentName" type="xs:string"/>
                    <xs:element name="agentType" type="xs:string"/>
                    <xs:element name="agentVersion" type="xs:string" minOccurs="0"/>
                    <xs:element name="agentNote" type="xs:string" minOccurs="0"/>
                    <xs:element ref="linkingRightsStatementIdentifier" minOccurs="0" maxOccurs="unbounded"/>
                  </xs:sequence>
                </xs:complexType>
              </xs:element>

              <xs:element name="rights">
                <xs:complexType>
                  <xs:sequence>
                    <xs:element name="rightsStatement" maxOccurs="unbounded">
                      <xs:complexType>
                        <xs:sequence>
                          <xs:element ref="rightsStatementIdentifier" maxOccurs="unbounded"/>
                          <xs:element name="rightsBasis" type="xs:string"/>
                          <xs:element name="copyrightInformation" minOccurs="0">
                            <xs:complexType>
                              <xs:sequence>
                                <xs:element name="copyrightStatus" type="xs:string"/>
                                <xs:element name="copyrightJurisdiction" type="xs:string"/>
                                <xs:element ref="copyrightDocumentationIdentifier" minOccurs="0" maxOccurs="unbounded"/>
                              </xs:sequence>
                            </xs:complexType>
                          </xs:element>
                          <xs:element name="licenseInformation" minOccurs="0">
                            <xs:complexType>
                              <xs:sequence>
                                <xs:element ref="licenseDocumentationIdentifier" minOccurs="0" maxOccurs="unbounded"/>
                              </xs:sequence>
                            </xs:complexType>
                          </xs:element>
                          <xs:element name="statuteInformation" minOccurs="0">
                            <xs:complexType>
                              <xs:sequence>
                                <xs:element name="statuteJurisdiction" type="xs:string"/>
                                <xs:element name="statuteCitation" type="xs:string"/>
                                <xs:element ref="statuteDocumentationIdentifier" minOccurs="0" maxOccurs="unbounded"/>
                              </xs:sequence>
                            </xs:complexType>
                          </xs:element>
                          <xs:element name="otherRightsInformation" minOccurs="0">
                            <xs:complexType>
                              <xs:sequence>
                                <xs:element ref="otherRightsDocumentationIdentifier" minOccurs="0" maxOccurs="unbounded"/>
                                <xs:element name="otherRightsBasis" type="xs:string"/>
                              </xs:sequence>
                            </xs:complexType>
                          </xs:element>
                          <xs:element name="rightsGranted" minOccurs="0">
                            <xs:complexType>
                              <xs:sequence>
                                <xs:element name="act" type="xs:string" minOccurs="0" maxOccurs="unbounded"/>
                                <xs:element name="termOfGrant" minOccurs="0">
                                  <xs:complexType>
                                    <xs:sequence>
                                      <xs:element name="startDate" type="xs:string"/>
                                      <xs:element name="endDate" type="xs:string" minOccurs="0"/>
                                    </xs:sequence>
                                  </xs:complexType>
                                </xs:element>
                                <xs:element name="rightsGrantedNote" type="xs:string" minOccurs="0"/>
                              </xs:sequence>
                            </xs:complexType>
                          </xs:element>
                        </xs:sequence>
                      </xs:complexType>
                    </xs:element>
                  </xs:sequence>
                </xs:complexType>
              </xs:element>

              <xs:element name="premis">
                <xs:complexType>
                  <xs:sequence>
                    <xs:element ref="object" minOccurs="0" maxOccurs="unbounded"/>
                    <xs:element ref="event" minOccurs="0" maxOccurs="unbounded"/>
                    <xs:element ref="agent" minOccurs="0" maxOccurs="unbounded"/>
                    <xs:element ref="rights" minOccurs="0" maxOccurs="unbounded"/>
                  </xs:sequence>
                  <xs:attribute name="version" type="xs:string" use="required"/>
                </xs:complexType>
              </xs:element>
            </xs:schema>
            """);

        return schema.ToString();
    }
}
