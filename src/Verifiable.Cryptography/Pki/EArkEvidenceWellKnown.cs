using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// Which kind of evidential artifact an Information Package carries as an opaque payload file.
/// </summary>
/// <remarks>
/// <para>
/// The three cases are the three this library can create, augment, renew and verify: a Signed Data Object of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf">
/// ETSI EN 319 122-1 V1.3.1</see>, an Associated Signature Container of
/// <see href="https://www.etsi.org/deliver/etsi_en/319100_319199/31916201/01.01.01_60/en_31916201v010101p.pdf">
/// ETSI EN 319 162-1 V1.1.1</see>, and an Evidence Record of
/// <see href="https://www.rfc-editor.org/rfc/rfc4998">IETF RFC 4998</see>.
/// </para>
/// <para>
/// <see cref="NotEvaluated"/> occupies zero so a default-initialised kind never reads as an artifact this
/// library knows how to verify.
/// </para>
/// </remarks>
public enum EArkEvidenceKind
{
    /// <summary>No kind stated. The value of an unset field, by design.</summary>
    NotEvaluated = 0,

    /// <summary>
    /// A CAdES Signed Data Object — one CMS <c>SignedData</c> whose signature, and whatever augmentation level
    /// it has reached, attests the data it covers.
    /// </summary>
    SignedDataObject = 1,

    /// <summary>
    /// An Associated Signature Container — one archive carrying signed or time-asserted data objects together
    /// with the signatures, time assertions or Evidence Records over them.
    /// </summary>
    Container = 2,

    /// <summary>
    /// An Evidence Record — the long-term non-repudiable proof of existence for one archived data object or
    /// data object group, renewable by both procedures of RFC 4998 clause 5.2.
    /// </summary>
    EvidenceRecord = 3
}


/// <summary>
/// The vocabulary this library states for how an evidential artifact sits inside an E-ARK Information Package:
/// where the artifact's file goes, how the package manifest names it, how the preservation-metadata document
/// records what it attests, and how the artifact describes the preservation service, policy and profile it was
/// produced under.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Every value here is this library's convention, and it has to be.</strong> A systematic search of
/// <see href="https://earkcsip.dilcis.eu/">E-ARK CSIP v2.2.0</see> and
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> for signatures, time-stamps,
/// evidence records and non-repudiation returns nothing at all: neither specification has a semantic unit
/// meaning "this file attests that one". The only native extension points are the preservation-metadata
/// <c>event</c> and <c>relationship</c> elements, whose type vocabularies are externally hosted and open, and
/// the package's own admission that "the IP MAY be extended" (<c>CSIPSTR14</c>). What is stated below is
/// therefore a convention over those extension points, documented as one, and anchored to the semantic unit
/// each value fills rather than to a requirement that does not exist.
/// </para>
/// <para>
/// <strong>The consumer alignment, recorded per element.</strong> A consuming system assembles a provenance
/// graph in the W3C Provenance Ontology from what a package states, so this convention deliberately prefers the
/// preservation-metadata semantic units that have direct counterparts in the preservation vocabulary's own OWL
/// alignment: an <c>object</c> is a <c>prov:Entity</c>, an <c>event</c> is a <c>prov:Activity</c>, an
/// <c>agent</c> is a <c>prov:Agent</c>, an event's <c>linkingAgentIdentifier</c> is
/// <c>prov:wasAssociatedWith</c>, its <c>linkingObjectIdentifier</c> is <c>prov:used</c> for what the activity
/// consumed and <c>prov:generated</c> for what it produced, an object's <c>relationship</c> to another object
/// is <c>prov:wasDerivedFrom</c>, and a <c>relatedEventIdentifier</c> chaining one event to the event that
/// created its source is <c>prov:wasInformedBy</c>. Each member below states which counterpart it fills.
/// </para>
/// <para>
/// <strong>What this convention deliberately does not use.</strong> The preservation vocabulary's own schema
/// declares a <c>signatureInformation</c> element on a file object, which reads at first like the natural home
/// for a signature. It is refused here for two reasons: the requirement catalogue this library implements
/// (<c>PM1</c>–<c>PM125</c>) constrains no row over it, so a package stating it says nothing a validation can
/// judge; and it has no counterpart in the OWL alignment above, so a consumer graphing the package would lose
/// exactly the statement the convention exists to make. The <c>event</c> and <c>relationship</c> route says the
/// same thing in units that survive the mapping.
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive</strong>, as everywhere else in this wave: an identifier
/// that differs only in case names a different thing, and a reader that folded case would recognise a
/// convention a producer did not follow.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The convention identifier is compared and written as an exact character sequence — as an XML namespace name it must be, since two namespace names that differ by escaping or case are two namespaces. System.Uri normalises both, which would make them compare equal.")]
public static class EArkEvidenceWellKnown
{
    /// <summary>
    /// The universally unique identifier this convention is identified by,
    /// <c>4b7a3c2e-5d18-4f6a-9c03-8e1f2a7b6d54</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <strong>Why a generated identifier rather than a registered one.</strong> No source specification defines
    /// an identifier for evidence self-description — that absence is precisely what
    /// <see href="https://www.etsi.org/deliver/etsi_ts/119500_119599/119511/01.02.01_60/ts_119511v010201p.pdf">
    /// ETSI TS 119 511 V1.2.1 clause 6.5</see> requirement <c>OVR-6.5-09</c> and clause 9.2 requirement
    /// <c>OVR-9.2-04</c> ask an evidence policy to fill — and this library holds no registered object-identifier
    /// arc and no namespace host of its own. Minting a value under an arc or a host belonging to someone else
    /// would be a collision waiting to happen.
    /// <see href="https://www.itu.int/rec/T-REC-X.667">ITU-T Recommendation X.667</see> exists for exactly this
    /// case: a universally unique identifier may be generated by anyone, without a registration authority, and
    /// mapped into the object-identifier tree under the arc <c>2.25</c>. The same value serves as a uniform
    /// resource name under <see href="https://www.rfc-editor.org/rfc/rfc4122#section-3">IETF RFC 4122 clause
    /// 3</see>, which is what makes one identity spellable in both the places this convention needs it.
    /// </para>
    /// <para>
    /// <strong>This value is stable.</strong> It is the key a consuming system's provenance graph and every
    /// package this library writes agree on; changing it would orphan both.
    /// </para>
    /// </remarks>
    public static string ConventionUuid { get; } = "4b7a3c2e-5d18-4f6a-9c03-8e1f2a7b6d54";

    /// <summary>
    /// The convention's identity as a uniform resource name, <c>urn:uuid:4b7a3c2e-5d18-4f6a-9c03-8e1f2a7b6d54</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc4122#section-3">IETF RFC 4122 clause 3</see>) — the form
    /// used wherever a uniform resource identifier is wanted, which is the XML namespace of the container
    /// extension below.
    /// </summary>
    public static string ConventionIdentifier { get; } = "urn:uuid:" + ConventionUuid;

    /// <summary>
    /// The convention's identity as an object identifier,
    /// <c>2.25.100326780518493129361456062577426263380</c> — the same universally unique identifier read as a
    /// single integer under the arc <see href="https://www.itu.int/rec/T-REC-X.667">ITU-T Recommendation
    /// X.667</see> reserves for them. This is the <c>attrType</c> of the CMS attribute both attribute-shaped
    /// carriers of this convention use.
    /// </summary>
    public static string SelfDescriptionAttributeType { get; } = "2.25.100326780518493129361456062577426263380";

    /// <summary>
    /// The XML namespace of the container-extension carrier, which is
    /// <see cref="ConventionIdentifier"/> — one identity, spelled as a uniform resource name because an XML
    /// namespace name is a uniform resource identifier reference.
    /// </summary>
    public static string SelfDescriptionElementNamespace { get; } = ConventionIdentifier;

    /// <summary>
    /// The local name of the container-extension carrier's element,
    /// <c>PreservationEvidenceSelfDescription</c>. Its text content is the canonical encoding of
    /// <see cref="EArkEvidenceSelfDescription"/> in base 64 — the same octets the attribute-shaped carriers hold
    /// verbatim, so the three carriers state one value rather than three shapes of it.
    /// </summary>
    public static string SelfDescriptionElementName { get; } = "PreservationEvidenceSelfDescription";

    /// <summary>
    /// The qualified name a container manifest's <c>Extension</c> carries when it holds this convention's
    /// self-description — the value a caller states in
    /// <see cref="AsicManifestExtensionPolicy.RecognizedExtensions"/> to say that it understands it.
    /// </summary>
    public static AsicManifestExtensionName SelfDescriptionExtensionName { get; } =
        new(SelfDescriptionElementNamespace, SelfDescriptionElementName);

    /// <summary>
    /// Whether this convention writes its container extension with the <c>Critical</c> attribute set,
    /// <see langword="false"/>.
    /// </summary>
    /// <remarks>
    /// Annex A.4.2 of EN 319 162-1 declares the attribute required and states no validator semantics for it;
    /// this library's answer is that an unrecognised critical extension fails closed. A self-description says
    /// which service, policy and profile produced the evidence — it changes nothing about how the evidence is
    /// verified — so marking it critical would make every consumer that has not heard of this convention refuse
    /// a container it can otherwise validate completely. Writing it non-critical is the choice that keeps a
    /// package readable by consumers this library will never meet, and it costs nothing: a consumer that does
    /// know the convention reads it either way.
    /// </remarks>
    public static bool SelfDescriptionExtensionIsCritical => false;


    /// <summary>
    /// The media type a Signed Data Object's file entry is named with,
    /// <c>application/pkcs7-signature</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc5751#section-3.2">IETF RFC 5751 clause 3.2</see>).
    /// </summary>
    public static string SignedDataObjectMediaType { get; } = "application/pkcs7-signature";

    /// <summary>
    /// The media type an Associated Signature Container's file entry is named with, which is
    /// <see cref="AsicWellKnown.AsicExtendedMediaType"/> — the extended container form, since a package holding
    /// several data objects is what an Information Package is.
    /// </summary>
    public static string ContainerMediaType { get; } = AsicWellKnown.AsicExtendedMediaType;

    /// <summary>
    /// The media type an Evidence Record's file entry is named with, <c>application/octet-stream</c>.
    /// </summary>
    /// <remarks>
    /// <strong>No media type is registered for the Evidence Record Syntax.</strong> RFC 4998 registers none, and
    /// this library does not invent one under a registry it does not own. The generic type is therefore what a
    /// package states, and it is honest: it tells an ordinary reader exactly what it can do with the octets,
    /// which is nothing. What the file <em>is</em> is said by the preservation event and the relationship this
    /// convention writes beside it — which is where the package specification's own extension points are, and
    /// where a consumer's provenance graph reads it from.
    /// </remarks>
    public static string EvidenceRecordMediaType { get; } = "application/octet-stream";

    /// <summary>
    /// The <c>eventType</c> of the event recording that evidence was produced over a package's objects,
    /// <c>preservation-evidence/creation</c>.
    /// </summary>
    /// <remarks>
    /// The event-type vocabulary requirement <c>PM84</c> names is externally hosted and open, so a value of this
    /// meaning is a convention rather than a defined term; the prefix keeps this library's terms apart from
    /// whatever that vocabulary states. In the ontology alignment the event is a <c>prov:Activity</c>, the
    /// artifact it produced is the <c>prov:Entity</c> its <c>linkingObjectIdentifier</c> names, and the service
    /// that produced it is the <c>prov:Agent</c> its <c>linkingAgentIdentifier</c> names.
    /// </remarks>
    public static string CreationEventType { get; } = "preservation-evidence/creation";

    /// <summary>
    /// The <c>eventType</c> of the event recording that evidence was renewed — either renewal procedure of
    /// <see href="https://www.rfc-editor.org/rfc/rfc4998#section-5.2">RFC 4998 clause 5.2</see>, or an archive
    /// time-stamp added to a signature's chain — <c>preservation-evidence/renewal</c>.
    /// </summary>
    /// <remarks>
    /// A renewal event carries a <c>relatedEventIdentifier</c> naming the event that produced the evidence it
    /// renewed, which is the archival specification's own way of chaining preservation history
    /// (<c>AIP17</c>) and is <c>prov:wasInformedBy</c> in the ontology alignment. Unlike that plain-text chain,
    /// the renewed evidence itself binds the earlier evidence cryptographically.
    /// </remarks>
    public static string RenewalEventType { get; } = "preservation-evidence/renewal";

    /// <summary>
    /// The <c>eventType</c> of the event recording that evidence was verified against the objects it covers,
    /// <c>preservation-evidence/validation</c>.
    /// </summary>
    /// <remarks>
    /// The event is a <c>prov:Activity</c> that <c>prov:used</c> both the evidence and the objects it covers,
    /// and whose <c>eventOutcome</c> is what the verification concluded.
    /// </remarks>
    public static string ValidationEventType { get; } = "preservation-evidence/validation";

    /// <summary>
    /// The <c>relationshipType</c> this convention states between an archived object and the evidence over it,
    /// <c>preservation-evidence</c>.
    /// </summary>
    /// <remarks>
    /// The relationship-type vocabulary requirements <c>PM22</c> and <c>PM58</c> name is externally hosted and
    /// open. In the ontology alignment an object relationship is <c>prov:wasDerivedFrom</c>, which is the
    /// correct reading in this direction too: an Evidence Record is computed from the data objects it covers,
    /// so the evidence is derived from them.
    /// </remarks>
    public static string EvidenceRelationshipType { get; } = "preservation-evidence";

    /// <summary>
    /// The <c>relationshipSubType</c> an archived object states towards the evidence over it,
    /// <c>is attested by</c>.
    /// </summary>
    public static string AttestedBySubType { get; } = "is attested by";

    /// <summary>
    /// The <c>relationshipSubType</c> an evidential artifact states towards an object it covers,
    /// <c>attests</c> — the inverse of <see cref="AttestedBySubType"/>.
    /// </summary>
    public static string AttestsSubType { get; } = "attests";

    /// <summary>
    /// The prefix every object identifier this convention mints for an evidential artifact carries,
    /// <c>evidence-</c>.
    /// </summary>
    /// <remarks>
    /// Clause 5.1 of E-ARK CSIP binds every identifier a package carries to the <c>NCName</c> production, whose
    /// first character must be a letter or an underscore; a prefix guarantees it whatever the file name the
    /// identifier is derived from starts with.
    /// </remarks>
    public static string EvidenceIdentifierPrefix { get; } = "evidence-";

    /// <summary>
    /// The prefix every event identifier this convention mints carries, <c>evidence-event-</c>.
    /// </summary>
    public static string EvidenceEventIdentifierPrefix { get; } = "evidence-event-";

    /// <summary>
    /// The folder a package-level evidential artifact sits in, which is
    /// <see cref="EArkWellKnown.OtherMetadataFolderName"/>.
    /// </summary>
    /// <remarks>
    /// <strong>Not the preservation-metadata folder, on purpose.</strong> Clause 5.2 of CS Preservation Metadata
    /// puts "all the documents giving the preservation metadata" in <c>metadata/preservation</c>, and a reader of
    /// that folder expects documents of that vocabulary; a DER Evidence Record or a container archive placed
    /// there would be handed to a parser that cannot read it. <c>CSIPSTR8</c>'s <c>metadata/other</c> — "metadata
    /// of any other kind" — is the position the specification actually has for it.
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0
    /// CSIPSTR8</see>.
    /// </remarks>
    public static string PackageEvidenceFolderName { get; } = EArkWellKnown.OtherMetadataFolderName;


    /// <summary>
    /// The entry-name separator as text, so that a name is composed without formatting a character into a
    /// string at every call site.
    /// </summary>
    private static string PathSeparatorText { get; } = EArkWellKnown.PathSeparator.ToString();

    /// <summary>A character the <c>NameStartChar</c> production admits, used to probe whether another character is a <c>NameChar</c>.</summary>
    private static string NameStartCharacter { get; } = "a";

    /// <summary>The character every rune an identifier may not carry is folded to, <c>-</c>.</summary>
    private static char FoldedCharacter { get; } = '-';


    /// <summary>
    /// States the media type an evidential artifact's file entry is named with.
    /// </summary>
    /// <param name="kind">The kind of artifact.</param>
    /// <returns>The media type, or <see langword="null"/> when no kind is stated.</returns>
    public static string? MediaTypeOf(EArkEvidenceKind kind) => kind switch
    {
        EArkEvidenceKind.SignedDataObject => SignedDataObjectMediaType,
        EArkEvidenceKind.Container => ContainerMediaType,
        EArkEvidenceKind.EvidenceRecord => EvidenceRecordMediaType,
        _ => null
    };


    /// <summary>
    /// Determines whether an event type is one this convention states.
    /// </summary>
    /// <param name="eventType">The <c>eventType</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one of the three event types above.</returns>
    public static bool IsEvidenceEventType(string? eventType) =>
        string.Equals(eventType, CreationEventType, StringComparison.Ordinal)
        || string.Equals(eventType, RenewalEventType, StringComparison.Ordinal)
        || string.Equals(eventType, ValidationEventType, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a relationship states this convention's meaning — the type is
    /// <see cref="EvidenceRelationshipType"/> and the subtype is one of the two directions.
    /// </summary>
    /// <param name="relationshipType">The <c>relationshipType</c> value, or <see langword="null"/>.</param>
    /// <param name="relationshipSubType">The <c>relationshipSubType</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the pair is one this convention writes.</returns>
    public static bool IsEvidenceRelationship(string? relationshipType, string? relationshipSubType) =>
        string.Equals(relationshipType, EvidenceRelationshipType, StringComparison.Ordinal)
        && (string.Equals(relationshipSubType, AttestedBySubType, StringComparison.Ordinal)
            || string.Equals(relationshipSubType, AttestsSubType, StringComparison.Ordinal));


    /// <summary>
    /// States the entry name a package-level evidential artifact sits under.
    /// </summary>
    /// <param name="fileName">The artifact's file name, which the caller chooses.</param>
    /// <returns>The entry name, root-relative and <c>/</c>-separated.</returns>
    /// <exception cref="ArgumentException">When <paramref name="fileName"/> is <see langword="null"/> or empty.</exception>
    public static string PackageEvidenceEntryName(string fileName)
    {
        ArgumentException.ThrowIfNullOrEmpty(fileName);

        return PackageEvidenceFolderName + PathSeparatorText + fileName;
    }


    /// <summary>
    /// States the entry name an evidential artifact over one representation's data sits under
    /// (<c>CSIPSTR11</c>).
    /// </summary>
    /// <param name="representationLabel">The representation's folder name under <c>representations</c> (<c>CSIPSTR10</c>).</param>
    /// <param name="fileName">The artifact's file name, which the caller chooses.</param>
    /// <returns>The entry name, root-relative and <c>/</c>-separated.</returns>
    /// <exception cref="ArgumentException">When either argument is <see langword="null"/> or empty.</exception>
    public static string RepresentationEvidenceEntryName(string representationLabel, string fileName)
    {
        ArgumentException.ThrowIfNullOrEmpty(representationLabel);
        ArgumentException.ThrowIfNullOrEmpty(fileName);

        return string.Concat(
            EArkWellKnown.RepresentationsFolderName + PathSeparatorText,
            representationLabel + PathSeparatorText,
            EArkWellKnown.RepresentationDataFolderName + PathSeparatorText,
            fileName);
    }


    /// <summary>
    /// Determines whether a position the package layout gives an entry is one this convention puts an evidential
    /// artifact at.
    /// </summary>
    /// <param name="placement">The position the tree classifier stated.</param>
    /// <returns><see langword="true"/> when the position is <c>metadata/other</c> or a representation's <c>data</c> folder.</returns>
    /// <remarks>
    /// The two positions are the two the convention states: package-level evidence in <c>metadata/other</c>
    /// (<c>CSIPSTR8</c>), and evidence over a representation's data beside that data (<c>CSIPSTR11</c>).
    /// Everything else is an extension position the package specification admits and this convention does not
    /// claim.
    /// </remarks>
    public static bool IsEvidencePlacement(EArkPackageEntryPlacement placement) =>
        placement is EArkPackageEntryPlacement.OtherMetadata or EArkPackageEntryPlacement.Data;


    /// <summary>
    /// States the <c>fileGrp/@USE</c> value an evidential artifact's file entry belongs under.
    /// </summary>
    /// <param name="representationLabel">The representation the artifact covers, or <see langword="null"/> for a package-level artifact.</param>
    /// <returns>The file-group use value.</returns>
    /// <remarks>
    /// No new value is minted: a package-level artifact sits in the <c>Metadata</c> group of <c>CSIP90</c>
    /// because it sits under <c>metadata</c>, and a representation's artifact sits in that representation's own
    /// group of <c>CSIP114</c> because it sits under that representation.
    /// </remarks>
    public static string EvidenceFileGroupUse(string? representationLabel) =>
        representationLabel is null
            ? MetsWellKnown.MetadataLabel
            : MetsWellKnown.RepresentationsPrefix + representationLabel;


    /// <summary>
    /// States the preservation-metadata identifier of an evidential artifact — the <c>prov:Entity</c> a
    /// consumer's provenance graph names the artifact by.
    /// </summary>
    /// <param name="entryName">The entry name the artifact sits under.</param>
    /// <returns>A locally minted identifier (clause 2.2.5) whose value is a legal <c>NCName</c>.</returns>
    /// <exception cref="ArgumentException">When <paramref name="entryName"/> is <see langword="null"/> or empty.</exception>
    public static PremisIdentifier EvidenceObjectIdentifier(string entryName)
    {
        ArgumentException.ThrowIfNullOrEmpty(entryName);

        return new PremisIdentifier(PremisWellKnown.LocalIdentifierType, EvidenceIdentifierPrefix + ToIdentifierToken(entryName));
    }


    /// <summary>
    /// States the preservation-metadata identifier of one event this convention records about an artifact — the
    /// <c>prov:Activity</c> a consumer's provenance graph names the event by.
    /// </summary>
    /// <param name="entryName">The entry name the artifact sits under.</param>
    /// <param name="eventType">The event type, one of the three this class states.</param>
    /// <returns>A locally minted identifier whose value is a legal <c>NCName</c>.</returns>
    /// <exception cref="ArgumentException">
    /// When <paramref name="entryName"/> is <see langword="null"/> or empty, or <paramref name="eventType"/> is
    /// not one this convention states.
    /// </exception>
    public static PremisIdentifier EvidenceEventIdentifier(string entryName, string eventType)
    {
        ArgumentException.ThrowIfNullOrEmpty(entryName);
        if(!IsEvidenceEventType(eventType))
        {
            throw new ArgumentException(
                $"'{eventType}' is not one of the event types this convention states.", nameof(eventType));
        }

        return new PremisIdentifier(
            PremisWellKnown.LocalIdentifierType,
            string.Concat(EvidenceEventIdentifierPrefix, ToIdentifierToken(eventType), "-", ToIdentifierToken(entryName)));
    }


    /// <summary>
    /// Turns arbitrary text — an entry name, an event type — into a token that may stand inside an identifier
    /// bound to the <c>NCName</c> production.
    /// </summary>
    /// <param name="value">The text to fold.</param>
    /// <returns>The folded token, which carries only characters an <c>NCName</c> admits after its first.</returns>
    /// <exception cref="ArgumentException">When <paramref name="value"/> is <see langword="null"/> or empty.</exception>
    /// <remarks>
    /// <para>
    /// Every character the production does not admit becomes a hyphen, which it does. The result is not itself an
    /// <c>NCName</c> — it may start with a digit — which is why every identifier this class mints puts a prefix
    /// in front of it, and why <see cref="MetsWellKnown.IsNCName"/> is what a rule asks rather than this.
    /// <see href="https://www.w3.org/TR/xml-names/#NT-NCName">Namespaces in XML 1.0 clause 4</see>.
    /// </para>
    /// <para>
    /// The fold is not injective — two entry names differing only in a character the production refuses fold to
    /// one token — so a package carrying two such artifacts states two identifiers that collide. That is a
    /// property of the fold, not a hidden failure: identifier uniqueness is what <c>PREMIS-ID-LOCAL</c> asks of
    /// the producer, and a producer meeting it names its files so.
    /// </para>
    /// </remarks>
    public static string ToIdentifierToken(string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(value);

        var builder = new StringBuilder(value.Length);
        foreach(Rune rune in value.EnumerateRunes())
        {
            //A rune is admitted when a two-character name starting with a letter and continuing with it is an
            //NCName: that asks exactly the NameChar question, without restating the production here.
            if(MetsWellKnown.IsNCName(NameStartCharacter + rune.ToString()))
            {
                _ = builder.Append(rune);
            }
            else
            {
                _ = builder.Append(FoldedCharacter);
            }
        }

        return builder.ToString();
    }
}
