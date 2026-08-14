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
/// Builds the preservation-metadata catalogue-subset schema and validates documents against a compiled schema
/// set — an independent statement of <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata
/// v1.0.1</see>'s requirement tables, written from the tables themselves rather than from any binding this
/// repository ships.
/// </summary>
/// <remarks>
/// Element names, containment and cardinality are read off <c>PM1</c>–<c>PM125</c> directly, so a document that
/// satisfies this schema satisfies the catalogue's own reading of the vocabulary. The schema is written here and
/// needs no external reference material, so a validation against it runs on a clean clone.
/// </remarks>
internal static class EArkSchemaOracle
{
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
