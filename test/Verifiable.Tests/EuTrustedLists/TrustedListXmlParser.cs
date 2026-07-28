using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Linq;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Cryptography.Pki.Xml;

/// <summary>
/// A worked <see cref="ParseTrustedListDelegate"/> implementation for the TLv6 XML profile, using
/// <see cref="System.Xml.Linq"/> (BCL, no package) to read a Trusted List or List Of the Trusted Lists
/// document into the pure <see cref="TrustedList"/> model per
/// <see href="https://www.etsi.org/deliver/etsi_ts/119600_119699/119612/02.04.01_60/ts_119612v020401p.pdf">
/// ETSI TS 119 612 V2.4.1 clause 5</see>.
/// </summary>
/// <remarks>
/// <para>
/// This is a staged, promotable worked example (contract R-4), not a shipped library type: it lives beside
/// <c>TestInfrastructure</c>, never inside it, carries no test-framework type, and depends on nothing from
/// <c>TestInfrastructure</c> — every dependency is either the BCL or <c>Verifiable.Cryptography.Pki</c>
/// itself. Its namespace (<c>Verifiable.Cryptography.Pki.Xml</c>) already names where a future package would
/// place it.
/// </para>
/// <para>
/// <strong>Attacker-reachable input.</strong> A Trusted List is fetched from a network location and is not
/// itself authenticated until <see cref="TrustedListXmlSignatureVerifier"/> runs, so this parser treats the
/// bytes as hostile: DTD processing is prohibited (blocking XML entity expansion / XXE) and the
/// criteria-list qualifier tree — the one part of the schema that nests to unbounded depth — is built
/// iteratively with an explicit <see cref="Stack{T}"/> under <see cref="MaxCriteriaListDepth"/>, never by a
/// recursive method call.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1515:Consider making public types internal", Justification = "Staged composition-edge code (layering-split-ledger.md): public by design so the boundary is already the future package's API boundary, per the promotability rules.")]
public static class TrustedListXmlParser
{
    /// <summary>The maximum nesting depth this parser accepts for a <c>CriteriaList</c> qualifier-condition tree, bounding an attacker-supplied document's depth.</summary>
    public const int MaxCriteriaListDepth = 64;

    /// <summary>The TS 119 612 core schema namespace (root document, scheme/TSP/service structure, digital identities).</summary>
    private static readonly XNamespace Tsl = "http://uri.etsi.org/02231/v2#";

    /// <summary>The XAdES 1.3.2 namespace (<c>ObjectIdentifierType</c>'s <c>Identifier</c>, and the signature's own <c>QualifyingProperties</c> read by the signature verifier, not this parser).</summary>
    private static readonly XNamespace Xades132 = "http://uri.etsi.org/01903/v1.3.2#";

    /// <summary>The Service Information Extensions namespace (<c>Qualifications</c>/<c>QualificationElement</c>/<c>CriteriaList</c>/<c>Qualifier</c>/<c>KeyUsage</c>/<c>PolicySet</c>).</summary>
    private static readonly XNamespace Sie = "http://uri.etsi.org/TrstSvc/SvcInfoExt/eSigDir-1999-93-EC-TrustedList/#";

    /// <summary>The TS 119 612 additional-types namespace (<c>ExtendedKeyUsage</c>, <c>CertSubjectDNAttribute</c> — the <c>otherCriteriaList</c> leaves this parser recognises).</summary>
    private static readonly XNamespace Tslx = "http://uri.etsi.org/02231/v2/additionaltypes#";

    /// <summary>The built-in XML namespace carrying the <c>xml:lang</c> attribute every multilingual field uses.</summary>
    private static readonly XNamespace XmlLang = XNamespace.Xml;


    /// <summary>
    /// Parses <paramref name="document"/> into a <see cref="TrustedList"/>. Has the
    /// <see cref="ParseTrustedListDelegate"/> shape.
    /// </summary>
    /// <param name="document">The raw, not-yet-verified document bytes. The caller retains ownership.</param>
    /// <param name="pool">The memory pool certificate byte carriers are rented from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The parse result.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the assembled TrustedList (and every certificate its tree carries) transfers to the successful TrustedListParseResult, which the caller disposes.")]
    public static ValueTask<TrustedListParseResult> ParseAsync(PooledMemory document, MemoryPool<byte> pool, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        ArgumentNullException.ThrowIfNull(pool);

        XDocument xml;
        try
        {
            using var stream = new MemoryStream(document.AsReadOnlySpan().ToArray(), writable: false);

            //DTD processing is prohibited outright: the document is attacker-reachable and this parser has no
            //legitimate use for an internal/external DTD subset (entity expansion, external entity fetch).
            var readerSettings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            };

            using XmlReader reader = XmlReader.Create(stream, readerSettings);
            xml = XDocument.Load(reader, LoadOptions.None);
        }
        catch(Exception ex) when(ex is XmlException or InvalidOperationException)
        {
            return ValueTask.FromResult(TrustedListParseResult.Failed(TrustedListParseStatus.Malformed, $"The document is not well-formed XML: {ex.Message}"));
        }

        try
        {
            XElement root = xml.Root ?? throw new TrustedListXmlParseException("The document has no root element.");
            if(root.Name != Tsl + "TrustServiceStatusList")
            {
                return ValueTask.FromResult(TrustedListParseResult.Failed(TrustedListParseStatus.Malformed, $"Unexpected root element '{root.Name}'."));
            }

            XElement schemeInformationElement = RequireElement(root, Tsl + "SchemeInformation");
            TrustedListSchemeInformation schemeInformation = ReadSchemeInformation(schemeInformationElement, pool);

            List<TrustServiceProvider> providers = [];
            XElement? providerListElement = root.Element(Tsl + "TrustServiceProviderList");
            if(providerListElement is not null)
            {
                foreach(XElement providerElement in providerListElement.Elements(Tsl + "TrustServiceProvider"))
                {
                    providers.Add(ReadTrustServiceProvider(providerElement, pool));
                }
            }

            TrustedList trustedList = new()
            {
                SchemeInformation = schemeInformation,
                TrustServiceProviders = providers
            };

            return ValueTask.FromResult(TrustedListParseResult.Valid(trustedList));
        }
        catch(TrustedListXmlParseException ex)
        {
            return ValueTask.FromResult(TrustedListParseResult.Failed(ex.Status, ex.Message));
        }
    }


    /// <summary>Reads the <c>SchemeInformation</c> block (clause 5.3).</summary>
    private static TrustedListSchemeInformation ReadSchemeInformation(XElement schemeInformationElement, MemoryPool<byte> pool)
    {
        //Carries whatever value the document declares — see TrustedListKind's own remarks for why this is a
        //wire-value wrapper rather than a gate that rejects an unrecognized TSLType outright: real documents
        //carry a pre-2016 legacy URI shape or a third-country MRA value neither of the two current EU-
        //registered values matches, and are otherwise perfectly parseable. Trimmed per XSD anyURI's
        //whiteSpace=collapse facet (XML Schema Part 2 §3.2.17), so incidental pretty-printing whitespace in
        //the element's text node is not mistaken for a different value.
        var tslType = new TrustedListKind(RequireElement(schemeInformationElement, Tsl + "TSLType").Value.Trim());

        XElement? operatorAddressElement = schemeInformationElement.Element(Tsl + "SchemeOperatorAddress");
        XElement? pointersElement = schemeInformationElement.Element(Tsl + "PointersToOtherTSL");
        XElement? nextUpdateElement = schemeInformationElement.Element(Tsl + "NextUpdate")?.Element(Tsl + "dateTime");

        return new TrustedListSchemeInformation
        {
            TslVersionIdentifier = int.Parse(RequireElement(schemeInformationElement, Tsl + "TSLVersionIdentifier").Value, CultureInfo.InvariantCulture),
            TslSequenceNumber = int.Parse(RequireElement(schemeInformationElement, Tsl + "TSLSequenceNumber").Value, CultureInfo.InvariantCulture),
            TslType = tslType,
            SchemeOperatorNames = ReadLocalizedTexts(schemeInformationElement.Element(Tsl + "SchemeOperatorName"), Tsl + "Name"),
            SchemeOperatorPostalAddresses = ReadPostalAddresses(operatorAddressElement),
            SchemeOperatorElectronicAddresses = ReadLocalizedTexts(operatorAddressElement?.Element(Tsl + "ElectronicAddress"), Tsl + "URI"),
            SchemeNames = ReadLocalizedTexts(schemeInformationElement.Element(Tsl + "SchemeName"), Tsl + "Name"),
            SchemeInformationUris = ReadLocalizedTexts(schemeInformationElement.Element(Tsl + "SchemeInformationURI"), Tsl + "URI"),
            StatusDeterminationApproach = RequireElement(schemeInformationElement, Tsl + "StatusDeterminationApproach").Value.Trim(),
            SchemeTypeCommunityRules = ReadLocalizedTexts(schemeInformationElement.Element(Tsl + "SchemeTypeCommunityRules"), Tsl + "URI"),
            SchemeTerritory = schemeInformationElement.Element(Tsl + "SchemeTerritory")?.Value,
            PolicyOrLegalNotices = ReadLocalizedTexts(schemeInformationElement.Element(Tsl + "PolicyOrLegalNotice"), Tsl + "TSLLegalNotice"),
            HistoricalInformationPeriodYears = int.Parse(RequireElement(schemeInformationElement, Tsl + "HistoricalInformationPeriod").Value, CultureInfo.InvariantCulture),
            PointersToOtherTrustedLists = pointersElement is null
                ? []
                : [.. pointersElement.Elements(Tsl + "OtherTSLPointer").Select(pointer => ReadOtherTslPointer(pointer, pool))],
            ListIssueDateTime = ReadDateTimeOffset(RequireElement(schemeInformationElement, Tsl + "ListIssueDateTime").Value),
            NextUpdate = nextUpdateElement is null ? null : ReadDateTimeOffset(nextUpdateElement.Value),
            DistributionPoints = schemeInformationElement.Element(Tsl + "DistributionPoints")?.Elements(Tsl + "URI").Select(e => e.Value).ToList() ?? []
        };
    }


    /// <summary>Reads one <c>OtherTSLPointer</c> (clause 5.3.13).</summary>
    private static OtherTrustedListPointer ReadOtherTslPointer(XElement pointerElement, MemoryPool<byte> pool)
    {
        ServiceDigitalIdentity identities = ReadServiceDigitalIdentitiesList(pointerElement.Element(Tsl + "ServiceDigitalIdentities"), pool);
        XElement? additionalInformationElement = pointerElement.Element(Tsl + "AdditionalInformation");

        return new OtherTrustedListPointer
        {
            //RelativeOrAbsolute rather than requiring Absolute: a conformant published list always uses an
            //absolute URL, but this parser does not reject a document merely for using a relative one (a
            //handful of the DSS pivot-mechanism test fixtures use a bare relative file name here).
            TslLocation = new Uri(RequireElement(pointerElement, Tsl + "TSLLocation").Value, UriKind.RelativeOrAbsolute),
            ServiceDigitalIdentities = identities,
            AdditionalInformation = ReadPointerAdditionalInformation(additionalInformationElement)
        };
    }


    /// <summary>
    /// Reads an <c>OtherTSLPointer</c>'s <c>AdditionalInformation</c> — a mixed choice of
    /// <c>TextualInformation</c> and <c>OtherInformation</c> (an extension point most commonly carrying
    /// <c>sie:SchemeTerritory</c>, <c>sie:MimeType</c>, <c>sie:SchemeOperatorName</c>, and
    /// <c>sie:SchemeTypeCommunityRules</c> in real-world lists).
    /// </summary>
    private static OtherTrustedListPointerAdditionalInformation ReadPointerAdditionalInformation(XElement? additionalInformationElement)
    {
        if(additionalInformationElement is null)
        {
            return new OtherTrustedListPointerAdditionalInformation();
        }

        List<LocalizedText> textualInformation = [.. additionalInformationElement.Elements(Tsl + "TextualInformation")
            .Select(e => new LocalizedText(ReadLanguage(e), e.Value))];

        string? schemeTerritory = null;
        string? mimeType = null;
        List<LocalizedText> operatorNames = [];
        List<string> communityRules = [];

        foreach(XElement otherInformationElement in additionalInformationElement.Elements(Tsl + "OtherInformation"))
        {
            foreach(XElement candidate in otherInformationElement.Elements())
            {
                if(candidate.Name == Sie + "SchemeTerritory")
                {
                    schemeTerritory = candidate.Value;
                }
                else if(candidate.Name == Sie + "MimeType")
                {
                    mimeType = candidate.Value;
                }
                else if(candidate.Name == Sie + "SchemeOperatorName")
                {
                    operatorNames.AddRange(ReadLocalizedTexts(candidate, Tsl + "Name"));
                }
                else if(candidate.Name == Sie + "SchemeTypeCommunityRules")
                {
                    communityRules.AddRange(candidate.Elements(Tsl + "URI").Select(e => e.Value));
                }
            }
        }

        return new OtherTrustedListPointerAdditionalInformation
        {
            SchemeTerritory = schemeTerritory,
            MimeType = mimeType,
            SchemeOperatorNames = operatorNames,
            SchemeTypeCommunityRules = communityRules,
            TextualInformation = textualInformation
        };
    }


    /// <summary>Reads a <c>TrustServiceProvider</c> (clause 5.4).</summary>
    private static TrustServiceProvider ReadTrustServiceProvider(XElement providerElement, MemoryPool<byte> pool)
    {
        XElement informationElement = RequireElement(providerElement, Tsl + "TSPInformation");
        XElement? addressElement = informationElement.Element(Tsl + "TSPAddress");
        XElement servicesElement = RequireElement(providerElement, Tsl + "TSPServices");

        return new TrustServiceProvider
        {
            Names = ReadLocalizedTexts(RequireElement(informationElement, Tsl + "TSPName"), Tsl + "Name"),
            TradeNames = ReadLocalizedTexts(informationElement.Element(Tsl + "TSPTradeName"), Tsl + "Name"),
            PostalAddresses = ReadPostalAddresses(addressElement),
            ElectronicAddresses = ReadLocalizedTexts(addressElement?.Element(Tsl + "ElectronicAddress"), Tsl + "URI"),
            InformationUris = ReadLocalizedTexts(RequireElement(informationElement, Tsl + "TSPInformationURI"), Tsl + "URI"),
            Services = [.. servicesElement.Elements(Tsl + "TSPService").Select(service => ReadTrustService(service, pool))]
        };
    }


    /// <summary>Reads a <c>TSPService</c>'s current <c>ServiceInformation</c> and its <c>ServiceHistory</c> (clause 5.5).</summary>
    private static TrustService ReadTrustService(XElement serviceElement, MemoryPool<byte> pool)
    {
        XElement informationElement = RequireElement(serviceElement, Tsl + "ServiceInformation");
        (List<TrustServiceAdditionalInformationType> additionalInformation, List<QualificationElement> qualifications) =
            ReadServiceInformationExtensions(informationElement.Element(Tsl + "ServiceInformationExtensions"));

        List<TrustServiceHistoryEntry> history = [];
        XElement? historyElement = serviceElement.Element(Tsl + "ServiceHistory");
        if(historyElement is not null)
        {
            foreach(XElement historyInstanceElement in historyElement.Elements(Tsl + "ServiceHistoryInstance"))
            {
                history.Add(ReadServiceHistoryEntry(historyInstanceElement, pool));
            }
        }

        return new TrustService
        {
            ServiceTypeIdentifier = new TrustServiceTypeIdentifier(RequireElement(informationElement, Tsl + "ServiceTypeIdentifier").Value.Trim()),
            ServiceNames = ReadLocalizedTexts(RequireElement(informationElement, Tsl + "ServiceName"), Tsl + "Name"),
            DigitalIdentity = ReadServiceDigitalIdentitiesList(informationElement.Element(Tsl + "ServiceDigitalIdentity"), pool),
            Status = new TrustServiceStatus(RequireElement(informationElement, Tsl + "ServiceStatus").Value.Trim()),
            StatusStartingTime = ReadDateTimeOffset(RequireElement(informationElement, Tsl + "StatusStartingTime").Value),
            AdditionalServiceInformation = additionalInformation,
            Qualifications = qualifications,
            History = history
        };
    }


    /// <summary>Reads one <c>ServiceHistoryInstance</c> (clause 5.6).</summary>
    private static TrustServiceHistoryEntry ReadServiceHistoryEntry(XElement historyInstanceElement, MemoryPool<byte> pool)
    {
        (List<TrustServiceAdditionalInformationType> additionalInformation, List<QualificationElement> qualifications) =
            ReadServiceInformationExtensions(historyInstanceElement.Element(Tsl + "ServiceInformationExtensions"));

        return new TrustServiceHistoryEntry
        {
            ServiceTypeIdentifier = new TrustServiceTypeIdentifier(RequireElement(historyInstanceElement, Tsl + "ServiceTypeIdentifier").Value.Trim()),
            ServiceNames = ReadLocalizedTexts(RequireElement(historyInstanceElement, Tsl + "ServiceName"), Tsl + "Name"),
            DigitalIdentity = ReadServiceDigitalIdentitiesList(historyInstanceElement.Element(Tsl + "ServiceDigitalIdentity"), pool),
            PreviousStatus = new TrustServiceStatus(RequireElement(historyInstanceElement, Tsl + "ServiceStatus").Value.Trim()),
            StatusStartingTime = ReadDateTimeOffset(RequireElement(historyInstanceElement, Tsl + "StatusStartingTime").Value),
            AdditionalServiceInformation = additionalInformation,
            Qualifications = qualifications
        };
    }


    /// <summary>
    /// Reads a <c>ServiceInformationExtensions</c> block's two extensions this model surfaces:
    /// <c>AdditionalServiceInformation</c> (clause 5.5.9.1) and <c>Qualifications</c> (clause 5.5.9.2). Any
    /// other extension (for example <c>TakenOverBy</c> or <c>expiredCertsRevocationInfo</c>) is out of this
    /// wave's scope and is skipped rather than failing the parse.
    /// </summary>
    private static (List<TrustServiceAdditionalInformationType> AdditionalInformation, List<QualificationElement> Qualifications) ReadServiceInformationExtensions(XElement? extensionsElement)
    {
        List<TrustServiceAdditionalInformationType> additionalInformation = [];
        List<QualificationElement> qualifications = [];

        if(extensionsElement is null)
        {
            return (additionalInformation, qualifications);
        }

        foreach(XElement extensionElement in extensionsElement.Elements(Tsl + "Extension"))
        {
            foreach(XElement content in extensionElement.Elements())
            {
                if(content.Name == Tsl + "AdditionalServiceInformation")
                {
                    XElement? uriElement = content.Element(Tsl + "URI");
                    if(uriElement is not null)
                    {
                        additionalInformation.Add(new TrustServiceAdditionalInformationType(uriElement.Value.Trim()));
                    }
                }
                else if(content.Name == Sie + "Qualifications")
                {
                    //The extension's Critical attribute (schema ExtensionType, clause 5.5.9) travels onto
                    //each carried element: TS 119 615 PRO-4.5.4-04 (b) branches the QSCD determination on it.
                    bool isCritical = string.Equals(((string?)extensionElement.Attribute("Critical"))?.Trim(), "true", StringComparison.OrdinalIgnoreCase);
                    qualifications.AddRange(content.Elements(Sie + "QualificationElement").Select(element => ReadQualificationElement(element, isCritical)));
                }
            }
        }

        return (additionalInformation, qualifications);
    }


    /// <summary>Reads one <c>QualificationElement</c> (clause 5.5.9.2.1).</summary>
    /// <param name="qualificationElement">The element to read.</param>
    /// <param name="isCritical">The <c>Critical</c> attribute of the containing <c>Qualifications</c> extension.</param>
    private static QualificationElement ReadQualificationElement(XElement qualificationElement, bool isCritical)
    {
        XElement? qualifiersElement = qualificationElement.Element(Sie + "Qualifiers");
        List<ServiceQualifier> qualifiers = qualifiersElement is null
            ? []
            : [.. qualifiersElement.Elements(Sie + "Qualifier").Select(q => new ServiceQualifier(((string?)q.Attribute("uri"))?.Trim() ?? string.Empty))];

        XElement criteriaListElement = RequireElement(qualificationElement, Sie + "CriteriaList");

        return new QualificationElement
        {
            Qualifiers = qualifiers,
            Condition = BuildCriteriaTree(criteriaListElement),
            IsCritical = isCritical
        };
    }


    /// <summary>
    /// One frame of the iterative <c>CriteriaList</c> tree build: an element awaiting either its nested
    /// <c>CriteriaList</c> children to be queued (<see cref="ChildrenQueued"/> <see langword="false"/>), or
    /// its own <see cref="CriteriaListCondition"/> to be assembled from those already-built children
    /// (<see langword="true"/>).
    /// </summary>
    private readonly record struct CriteriaWorkItem(XElement Element, XElement? Parent, int Depth, bool ChildrenQueued);


    /// <summary>
    /// Builds a <see cref="CriteriaListCondition"/> tree from a <c>CriteriaList</c> element WITHOUT
    /// recursion: an explicit <see cref="Stack{T}"/> of <see cref="CriteriaWorkItem"/> frames drives an
    /// iterative post-order build, bounded by <see cref="MaxCriteriaListDepth"/> — the one part of the TLv6
    /// schema that nests to unbounded depth, and so the one place this parser must defend against a
    /// maliciously deep attacker-supplied document.
    /// </summary>
    /// <param name="rootElement">The outermost <c>CriteriaList</c> element.</param>
    /// <returns>The built condition tree.</returns>
    /// <exception cref="TrustedListXmlParseException">The tree nests deeper than <see cref="MaxCriteriaListDepth"/>.</exception>
    private static CriteriaListCondition BuildCriteriaTree(XElement rootElement)
    {
        Stack<CriteriaWorkItem> work = new();
        Dictionary<XElement, List<QualifierCondition>> nestedChildren = [];
        work.Push(new CriteriaWorkItem(rootElement, null, 0, false));

        CriteriaListCondition? result = null;

        while(work.Count > 0)
        {
            CriteriaWorkItem item = work.Pop();

            if(!item.ChildrenQueued)
            {
                if(item.Depth > MaxCriteriaListDepth)
                {
                    throw new TrustedListXmlParseException($"A CriteriaList nests deeper than the maximum supported depth of {MaxCriteriaListDepth}.", TrustedListParseStatus.ExcessiveNesting);
                }

                nestedChildren[item.Element] = [];
                work.Push(item with { ChildrenQueued = true });

                foreach(XElement nested in item.Element.Elements(Sie + "CriteriaList"))
                {
                    work.Push(new CriteriaWorkItem(nested, item.Element, item.Depth + 1, false));
                }
            }
            else
            {
                List<QualifierCondition> children = [.. ReadLeafConditions(item.Element), .. nestedChildren[item.Element]];
                nestedChildren.Remove(item.Element);

                QualifierAssertion assertion = QualifierAssertionMapping.FromWireValue((string?)item.Element.Attribute("assert") ?? "all") ?? QualifierAssertion.All;
                string? description = item.Element.Element(Sie + "Description")?.Value;
                CriteriaListCondition built = new(assertion, description, children);

                if(item.Parent is null)
                {
                    result = built;
                }
                else
                {
                    nestedChildren[item.Parent].Add(built);
                }
            }
        }

        return result ?? throw new TrustedListXmlParseException("Failed to build the criteria list tree.");
    }


    /// <summary>
    /// Reads a single <c>CriteriaList</c> element's own leaf conditions — its direct <c>KeyUsage</c> and
    /// <c>PolicySet</c> children, plus its single <c>otherCriteriaList</c> extension, EXCLUDING nested
    /// <c>CriteriaList</c> children (those are handled separately by <see cref="BuildCriteriaTree"/>'s
    /// iterative walk).
    /// </summary>
    private static List<QualifierCondition> ReadLeafConditions(XElement criteriaListElement)
    {
        List<QualifierCondition> leaves = [];

        foreach(XElement keyUsageElement in criteriaListElement.Elements(Sie + "KeyUsage"))
        {
            List<KeyUsageBitAssertion> bits = [.. keyUsageElement.Elements(Sie + "KeyUsageBit").Select(ReadKeyUsageBit).OfType<KeyUsageBitAssertion>()];
            leaves.Add(new KeyUsageCondition(bits));
        }

        foreach(XElement policySetElement in criteriaListElement.Elements(Sie + "PolicySet"))
        {
            List<string> policyOids = [.. policySetElement.Elements(Sie + "PolicyIdentifier").Select(ReadObjectIdentifier)];
            leaves.Add(new PolicySetCondition(policyOids));
        }

        XElement? otherCriteriaListElement = criteriaListElement.Element(Sie + "otherCriteriaList");
        if(otherCriteriaListElement is not null)
        {
            leaves.Add(ReadOtherCriteriaListLeaf(otherCriteriaListElement));
        }

        return leaves;
    }


    /// <summary>Reads one <c>KeyUsageBit</c> element into a <see cref="KeyUsageBitAssertion"/>, or <see langword="null"/> when its <c>name</c> attribute is not one of the nine registered bits.</summary>
    private static KeyUsageBitAssertion? ReadKeyUsageBit(XElement keyUsageBitElement)
    {
        string? name = (string?)keyUsageBitElement.Attribute("name");
        KeyUsageBitName? bit = name switch
        {
            "digitalSignature" => KeyUsageBitName.DigitalSignature,
            "nonRepudiation" => KeyUsageBitName.NonRepudiation,
            "keyEncipherment" => KeyUsageBitName.KeyEncipherment,
            "dataEncipherment" => KeyUsageBitName.DataEncipherment,
            "keyAgreement" => KeyUsageBitName.KeyAgreement,
            "keyCertSign" => KeyUsageBitName.KeyCertSign,
            "crlSign" => KeyUsageBitName.CrlSign,
            "encipherOnly" => KeyUsageBitName.EncipherOnly,
            "decipherOnly" => KeyUsageBitName.DecipherOnly,
            _ => null
        };

        return bit is null ? null : new KeyUsageBitAssertion(bit.Value, XmlConvert.ToBoolean(keyUsageBitElement.Value.Trim()));
    }


    /// <summary>
    /// Reads the <c>otherCriteriaList</c> extension point's single child into the recognised
    /// <see cref="ExtendedKeyUsageCondition"/> / <see cref="CertSubjectDistinguishedNameAttributeCondition"/>
    /// leaves, or an <see cref="OtherQualifierCondition"/> naming what was found when it is neither.
    /// </summary>
    private static QualifierCondition ReadOtherCriteriaListLeaf(XElement otherCriteriaListElement)
    {
        XElement? content = otherCriteriaListElement.Elements().FirstOrDefault();
        if(content is null)
        {
            return new OtherQualifierCondition("otherCriteriaList");
        }

        if(content.Name == Tslx + "ExtendedKeyUsage")
        {
            List<string> keyPurposeOids = [.. content.Elements(Tslx + "KeyPurposeId").Select(ReadObjectIdentifier)];
            return new ExtendedKeyUsageCondition(keyPurposeOids);
        }

        if(content.Name == Tslx + "CertSubjectDNAttribute")
        {
            List<string> attributeOids = [.. content.Elements(Tslx + "AttributeOID").Select(ReadObjectIdentifier)];
            return new CertSubjectDistinguishedNameAttributeCondition(attributeOids);
        }

        return new OtherQualifierCondition(content.Name.LocalName);
    }


    /// <summary>Reads an <c>xades:ObjectIdentifierType</c> container's <c>Identifier</c> text, stripping a leading <c>urn:oid:</c> prefix when present.</summary>
    private static string ReadObjectIdentifier(XElement container)
    {
        string identifier = container.Element(Xades132 + "Identifier")?.Value.Trim() ?? string.Empty;
        const string urnOidPrefix = "urn:oid:";

        return identifier.StartsWith(urnOidPrefix, StringComparison.OrdinalIgnoreCase)
            ? identifier[urnOidPrefix.Length..]
            : identifier;
    }


    /// <summary>Reads a <c>ServiceDigitalIdentity</c>/<c>ServiceDigitalIdentities</c> container's <c>DigitalId</c> entries (clause 5.5.3).</summary>
    private static ServiceDigitalIdentity ReadServiceDigitalIdentitiesList(XElement? container, MemoryPool<byte> pool)
    {
        if(container is null)
        {
            return ServiceDigitalIdentity.Empty;
        }

        List<ServiceDigitalIdentityEntry> entries = [];
        foreach(XElement digitalIdElement in container.Elements(Tsl + "DigitalId"))
        {
            entries.Add(ReadDigitalIdentityEntry(digitalIdElement, pool));
        }

        return new ServiceDigitalIdentity { Entries = entries };
    }


    /// <summary>Reads one <c>DigitalId</c> choice element into a <see cref="ServiceDigitalIdentityEntry"/>.</summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the rented certificate bytes transfers to the returned X509CertificateIdentity, which the caller (through the owning TrustedList) disposes.")]
    private static ServiceDigitalIdentityEntry ReadDigitalIdentityEntry(XElement digitalIdElement, MemoryPool<byte> pool)
    {
        XElement? certificateElement = digitalIdElement.Element(Tsl + "X509Certificate");
        if(certificateElement is not null)
        {
            byte[] derBytes = Convert.FromBase64String(certificateElement.Value.Trim());
            IMemoryOwner<byte> owner = pool.Rent(derBytes.Length);
            derBytes.CopyTo(owner.Memory.Span);

            return new X509CertificateIdentity(new PkiCertificateMemory(owner, PkiCertificateTags.X509Certificate));
        }

        XElement? skiElement = digitalIdElement.Element(Tsl + "X509SKI");
        if(skiElement is not null)
        {
            return new X509SubjectKeyIdentifierIdentity(skiElement.Value.Trim());
        }

        XElement? subjectNameElement = digitalIdElement.Element(Tsl + "X509SubjectName");
        if(subjectNameElement is not null)
        {
            return new X509SubjectNameIdentity(subjectNameElement.Value.Trim());
        }

        XElement? otherElement = digitalIdElement.Element(Tsl + "Other");
        string localName = otherElement?.Elements().FirstOrDefault()?.Name.LocalName ?? "Other";

        return new OtherDigitalIdentity(localName);
    }


    /// <summary>Reads a <c>PostalAddresses</c> container's language-tagged <c>PostalAddress</c> entries.</summary>
    private static List<TrustedListPostalAddress> ReadPostalAddresses(XElement? addressContainerElement)
    {
        XElement? postalAddressesElement = addressContainerElement?.Element(Tsl + "PostalAddresses");
        if(postalAddressesElement is null)
        {
            return [];
        }

        List<TrustedListPostalAddress> addresses = [];
        foreach(XElement postalAddressElement in postalAddressesElement.Elements(Tsl + "PostalAddress"))
        {
            addresses.Add(new TrustedListPostalAddress
            {
                Language = ReadLanguage(postalAddressElement),
                StreetAddress = RequireElement(postalAddressElement, Tsl + "StreetAddress").Value,
                Locality = RequireElement(postalAddressElement, Tsl + "Locality").Value,
                StateOrProvince = postalAddressElement.Element(Tsl + "StateOrProvince")?.Value,
                PostalCode = postalAddressElement.Element(Tsl + "PostalCode")?.Value,
                CountryName = RequireElement(postalAddressElement, Tsl + "CountryName").Value
            });
        }

        return addresses;
    }


    /// <summary>Reads a container's language-tagged leaf elements (the recurring <c>InternationalNamesType</c>/<c>MultiLangURIListType</c>/<c>MultiLangStringType</c> shape) into <see cref="LocalizedText"/> entries.</summary>
    private static List<LocalizedText> ReadLocalizedTexts(XElement? containerElement, XName leafName)
    {
        if(containerElement is null)
        {
            return [];
        }

        return [.. containerElement.Elements(leafName).Select(e => new LocalizedText(ReadLanguage(e), e.Value))];
    }


    /// <summary>Reads an element's <c>xml:lang</c> attribute, or the empty string when absent.</summary>
    private static string ReadLanguage(XElement element) => (string?)element.Attribute(XmlLang + "lang") ?? string.Empty;


    /// <summary>Reads an ISO 8601 <c>xsd:dateTime</c> value as a <see cref="DateTimeOffset"/>.</summary>
    private static DateTimeOffset ReadDateTimeOffset(string value) =>
        DateTimeOffset.Parse(value.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);


    /// <summary>Returns <paramref name="parent"/>'s required child <paramref name="name"/>, or throws when absent.</summary>
    /// <exception cref="TrustedListXmlParseException">The required element is absent.</exception>
    private static XElement RequireElement(XElement parent, XName name) =>
        parent.Element(name) ?? throw new TrustedListXmlParseException($"Required element '{name}' is missing under '{parent.Name}'.");
}
