using System;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The wire names an E-ARK Common Specification for Information Packages METS document fixes — the namespaces, the
/// profile identifiers, the nine controlled vocabularies the profile gates its attributes with, and the checksum
/// algorithm names the base METS schema admits — together with the recognition helpers a dispatch site uses
/// instead of comparing string literals at the call site.
/// </summary>
/// <remarks>
/// <para>
/// The values come from three artefacts rather than from prose: the METS profile document of
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> (its
/// <c>controlled_vocabularies</c> block and its <c>CSIP1</c>–<c>CSIP119</c> requirement catalogue), the
/// <c>DILCISExtensionMETS.xsd</c> schema that declares the four <c>csip:</c> attributes, and the base METS schema
/// the profile narrows, which is where the <c>CHECKSUMTYPE</c> enumeration lives. The folder names the same
/// vocabulary doubles as are stated by <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">
/// E-ARK CSIP v2.2.0 clause 4.1</see> requirements <c>CSIPSTR5</c>–<c>CSIPSTR16</c>.
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive</strong>, unlike the media types of
/// <see cref="AsicWellKnown"/>. Every value here is either a fixed token the profile prints literally
/// (<c>CREATOR</c>, <c>PHYSICAL</c>, <c>CSIP</c>, <c>SOFTWARE VERSION</c>) or an XML enumeration facet, and an XML
/// enumeration facet matches by exact character sequence — a document stating <c>sha-256</c> is not schema-valid
/// and must not be read as though it were.
/// </para>
/// <para>
/// <strong>Document values only.</strong> What a package's folders and files are NAMED is a different vocabulary
/// living a layer up, beside the package-tree classifier and the validation profiles, and it is not repeated here
/// — the same value stated in two places is two vocabularies. This class holds what a METS document's attributes
/// and their controlled vocabularies say; the labels below that happen to read like folder names are attribute
/// values (<c>fileGrp/@USE</c>, <c>div/@LABEL</c>) whose capitalisation is the profile's, not the folder layout's.
/// </para>
/// <para>
/// <strong>What is deliberately not enumerated here.</strong> <c>mets/@TYPE</c>'s content-category vocabulary is
/// 33 free-text descriptive terms with no implementation consequence, <c>@MIMETYPE</c> is the IANA media-type
/// registry, and <c>metsHdr/altRecordID/@TYPE</c> is an externally hosted identifier-type vocabulary. Those three
/// are carried as text by the model rather than closed here.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1054:URI-like parameters should not be strings",
    Justification = "A profile identifier is compared as written: CSIP6 and AIPM2 fix an exact attribute value, and System.Uri normalises case, escaping and default ports, which would make two values that name different profiles compare equal.")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "These are namespace and profile identifiers compared as strings, never dereferenced; nothing here fetches a URI.")]
public static class MetsWellKnown
{
    /// <summary>
    /// The METS namespace, <c>http://www.loc.gov/METS/</c>, which the base METS schema declares as its target and
    /// whose <c>elementFormDefault="qualified"</c> puts every element of a METS document in it.
    /// </summary>
    public static string MetsNamespace { get; } = "http://www.loc.gov/METS/";

    /// <summary>
    /// The CSIP extension namespace, <c>https://DILCIS.eu/XML/METS/CSIPExtensionMETS</c>, declared by
    /// <c>DILCISExtensionMETS.xsd</c> as the target of the four attributes <c>CSIP3</c>–<c>CSIP5</c>,
    /// <c>CSIP9</c>, <c>CSIP16</c> and <c>CSIP62</c>–<c>CSIP63</c> name.
    /// </summary>
    public static string CsipExtensionNamespace { get; } = "https://DILCIS.eu/XML/METS/CSIPExtensionMETS";

    /// <summary>
    /// The XLink namespace, <c>http://www.w3.org/1999/xlink</c>, which the base METS schema imports to reach the
    /// <c>xlink:type</c> and <c>xlink:href</c> attributes <c>CSIP23</c>/<c>CSIP24</c>, <c>CSIP78</c>/<c>CSIP79</c>
    /// and <c>CSIP110</c>/<c>CSIP111</c> require.
    /// </summary>
    public static string XLinkNamespace { get; } = "http://www.w3.org/1999/xlink";

    /// <summary>
    /// The profile identifier a CSIP-conformant METS document states in <c>mets/@PROFILE</c>,
    /// <c>https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml</c> (<c>CSIP6</c>).
    /// </summary>
    public static string CsipProfileUri { get; } = "https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml";

    /// <summary>
    /// The profile identifier an AIP-conformant METS document states in <c>mets/@PROFILE</c>,
    /// <c>https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml</c>
    /// (<see href="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml">E-ARK AIP v2.2.0</see>
    /// requirement <c>AIPM2</c>).
    /// </summary>
    /// <remarks>
    /// <strong>A documented interpretation of a spec-body inconsistency.</strong> The AIP profile document states
    /// this value twice under different hosts: its own machine-checkable conformance test
    /// <c>TEST-AIPM2-1</c> requires <c>/mets[@PROFILE="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml"]</c>
    /// while a worked example inside the same document writes the <c>earkcsip</c> host instead. The value here is
    /// the one the conformance test states, because that test is what an <c>AIPM2</c> claim is decided by; a
    /// reader meeting the other host meets a document that fails the profile's own test.
    /// </remarks>
    public static string AipProfileUri { get; } = "https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml";

    /// <summary>The <c>SIP</c> value of the OAIS package-type vocabulary (<c>CSIP9</c>).</summary>
    public static string SubmissionPackageType { get; } = "SIP";

    /// <summary>The <c>AIP</c> value of the OAIS package-type vocabulary (<c>CSIP9</c>, and the value <c>AIPM3</c> fixes).</summary>
    public static string ArchivalPackageType { get; } = "AIP";

    /// <summary>The <c>DIP</c> value of the OAIS package-type vocabulary (<c>CSIP9</c>).</summary>
    public static string DisseminationPackageType { get; } = "DIP";

    /// <summary>The <c>AIU</c> value of the OAIS package-type vocabulary (<c>CSIP9</c>): an Archival Information Unit.</summary>
    public static string ArchivalUnitPackageType { get; } = "AIU";

    /// <summary>The <c>AIC</c> value of the OAIS package-type vocabulary (<c>CSIP9</c>): an Archival Information Collection.</summary>
    public static string ArchivalCollectionPackageType { get; } = "AIC";

    /// <summary>The <c>CURRENT</c> value of the metadata-status vocabulary (<c>CSIP20</c>, <c>CSIP34</c>, <c>CSIP47</c>; the value <c>AIPM4</c> asks one <c>dmdSec</c> to carry).</summary>
    public static string CurrentStatus { get; } = "CURRENT";

    /// <summary>The <c>SUPERSEDED</c> value of the metadata-status vocabulary (<c>CSIP20</c>, <c>CSIP34</c>, <c>CSIP47</c>).</summary>
    public static string SupersededStatus { get; } = "SUPERSEDED";

    /// <summary>The fixed <c>agent/@ROLE</c> value <c>CREATOR</c> (<c>CSIP11</c>).</summary>
    public static string CreatorAgentRole { get; } = "CREATOR";

    /// <summary>The fixed <c>agent/@TYPE</c> value <c>OTHER</c> (<c>CSIP12</c>).</summary>
    public static string OtherAgentType { get; } = "OTHER";

    /// <summary>The fixed <c>agent/@OTHERTYPE</c> value <c>SOFTWARE</c> (<c>CSIP13</c>), the sole member of its vocabulary.</summary>
    public static string SoftwareAgentOtherType { get; } = "SOFTWARE";

    /// <summary>The <c>SOFTWARE VERSION</c> value of the agent-note vocabulary (<c>CSIP16</c>).</summary>
    public static string SoftwareVersionNoteType { get; } = "SOFTWARE VERSION";

    /// <summary>The <c>IDENTIFICATIONCODE</c> value of the agent-note vocabulary, the vocabulary's other member.</summary>
    public static string IdentificationCodeNoteType { get; } = "IDENTIFICATIONCODE";

    /// <summary>The fixed <c>structMap/@TYPE</c> value <c>PHYSICAL</c> (<c>CSIP81</c>), the sole member of its vocabulary.</summary>
    public static string PhysicalStructuralMapType { get; } = "PHYSICAL";

    /// <summary>
    /// The fixed <c>structMap/@LABEL</c> value <c>CSIP</c> (<c>CSIP82</c>), which the specification's own note
    /// says "should be treated as a unique id" so that a package may carry further structural maps of its own
    /// without colliding with the one the profile mandates.
    /// </summary>
    public static string CsipStructuralMapLabel { get; } = "CSIP";

    /// <summary>The <c>Metadata</c> value of the file-group-use and division-label vocabulary (<c>CSIP90</c>) and the folder name <c>CSIPSTR5</c> states.</summary>
    public static string MetadataLabel { get; } = "Metadata";

    /// <summary>The <c>Documentation</c> value of the file-group-use and division-label vocabulary (<c>CSIP60</c>, <c>CSIP95</c>) and the folder name <c>CSIPSTR16</c> states.</summary>
    public static string DocumentationLabel { get; } = "Documentation";

    /// <summary>The <c>Schemas</c> value of the file-group-use and division-label vocabulary (<c>CSIP113</c>, <c>CSIP99</c>) and the folder name <c>CSIPSTR15</c> states.</summary>
    public static string SchemasLabel { get; } = "Schemas";

    /// <summary>The <c>Representations</c> value of the file-group-use and division-label vocabulary (<c>CSIP103</c>) and the folder name <c>CSIPSTR9</c> states.</summary>
    public static string RepresentationsLabel { get; } = "Representations";

    /// <summary>
    /// The <c>Representations/</c> prefix a per-representation <c>fileGrp/@USE</c> and the matching representation
    /// division's <c>@LABEL</c> carry (<c>CSIP114</c>, <c>CSIP107</c>), followed by the representation's folder
    /// name.
    /// </summary>
    public static string RepresentationsPrefix { get; } = "Representations/";

    /// <summary>The fixed <c>@LOCTYPE</c> value <c>URL</c> that <c>CSIP22</c>, <c>CSIP36</c>, <c>CSIP49</c>, <c>CSIP77</c> and <c>CSIP112</c> require.</summary>
    public static string UrlLocatorType { get; } = "URL";

    /// <summary>The fixed <c>xlink:type</c> value <c>simple</c> that <c>CSIP23</c>, <c>CSIP37</c>, <c>CSIP50</c>, <c>CSIP78</c> and <c>CSIP111</c> require.</summary>
    public static string SimpleLinkType { get; } = "simple";

    /// <summary>
    /// The <c>@MDTYPE</c> value <c>PREMIS</c> that the clause 5.1.1 table of
    /// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> fixes for a
    /// <c>digiprovMD/mdRef</c> pointing at a preservation-metadata document, and that <c>AIPM6</c> asks an AIP to
    /// carry at least once.
    /// </summary>
    public static string PremisMetadataType { get; } = "PREMIS";

    /// <summary>The <c>@MDTYPE</c> value <c>OTHER</c>, which is what makes <c>@OTHERMDTYPE</c> meaningful.</summary>
    public static string OtherMetadataType { get; } = "OTHER";

    /// <summary>The <c>mets/@TYPE</c> value stating that the content category is one the vocabulary does not name, <c>OTHER</c>, which <c>CSIP3</c> then requires be spelled out (<c>CSIP2</c>, <c>CSIP3</c>).</summary>
    public static string OtherContentCategory { get; } = "OTHER";

    /// <summary>The <c>MIXED</c> value of the content-information-type vocabulary (<c>CSIP4</c>, <c>CSIP62</c>): the package mixes several specifications.</summary>
    public static string MixedContentInformationType { get; } = "MIXED";

    /// <summary>The <c>OTHER</c> value of the content-information-type vocabulary (<c>CSIP4</c>), which is what makes <c>csip:OTHERCONTENTINFORMATIONTYPE</c> meaningful (<c>CSIP5</c>).</summary>
    public static string OtherContentInformationType { get; } = "OTHER";

    /// <summary>The <c>Adler-32</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    public static string Adler32ChecksumType { get; } = "Adler-32";

    /// <summary>The <c>CRC32</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    public static string Crc32ChecksumType { get; } = "CRC32";

    /// <summary>The <c>HAVAL</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    public static string HavalChecksumType { get; } = "HAVAL";

    /// <summary>The <c>MD5</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    public static string Md5ChecksumType { get; } = "MD5";

    /// <summary>The <c>MNP</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    public static string MnpChecksumType { get; } = "MNP";

    /// <summary>The <c>SHA-1</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    public static string Sha1ChecksumType { get; } = "SHA-1";

    /// <summary>The <c>SHA-256</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration, and the algorithm the preservation-metadata specification recommends outright.</summary>
    public static string Sha256ChecksumType { get; } = "SHA-256";

    /// <summary>The <c>SHA-384</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    public static string Sha384ChecksumType { get; } = "SHA-384";

    /// <summary>The <c>SHA-512</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    public static string Sha512ChecksumType { get; } = "SHA-512";

    /// <summary>The <c>TIGER</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    public static string TigerChecksumType { get; } = "TIGER";

    /// <summary>The <c>WHIRLPOOL</c> value of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    public static string WhirlpoolChecksumType { get; } = "WHIRLPOOL";


    /// <summary>Determines whether a value is one of the five members of the OAIS package-type vocabulary.</summary>
    /// <param name="packageType">The <c>metsHdr/@csip:OAISPACKAGETYPE</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one the vocabulary states.</returns>
    public static bool IsOaisPackageType(string? packageType) =>
        string.Equals(packageType, SubmissionPackageType, StringComparison.Ordinal)
        || string.Equals(packageType, ArchivalPackageType, StringComparison.Ordinal)
        || string.Equals(packageType, DisseminationPackageType, StringComparison.Ordinal)
        || string.Equals(packageType, ArchivalUnitPackageType, StringComparison.Ordinal)
        || string.Equals(packageType, ArchivalCollectionPackageType, StringComparison.Ordinal);


    /// <summary>Determines whether a value is one of the two members of the metadata-status vocabulary.</summary>
    /// <param name="status">The <c>@STATUS</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one the vocabulary states.</returns>
    public static bool IsMetadataStatus(string? status) =>
        string.Equals(status, CurrentStatus, StringComparison.Ordinal)
        || string.Equals(status, SupersededStatus, StringComparison.Ordinal);


    /// <summary>Determines whether a value is one of the two members of the agent-note vocabulary.</summary>
    /// <param name="noteType">The <c>agent/note/@csip:NOTETYPE</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one the vocabulary states.</returns>
    public static bool IsAgentNoteType(string? noteType) =>
        string.Equals(noteType, SoftwareVersionNoteType, StringComparison.Ordinal)
        || string.Equals(noteType, IdentificationCodeNoteType, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a value is one of the four members of the file-group-use and division-label vocabulary,
    /// counting a per-representation value as a member of it.
    /// </summary>
    /// <param name="label">The <c>fileGrp/@USE</c> or <c>div/@LABEL</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one the vocabulary states.</returns>
    /// <remarks>
    /// A per-representation value is <c>Representations/</c> followed by the representation's folder name
    /// (<c>CSIP114</c>, <c>CSIP107</c>), which the profile writes with a <c>starts-with</c> predicate rather than
    /// as an enumeration facet — see <see cref="IsRepresentationLabel"/>.
    /// </remarks>
    public static bool IsFileGroupUse(string? label) =>
        string.Equals(label, MetadataLabel, StringComparison.Ordinal)
        || string.Equals(label, DocumentationLabel, StringComparison.Ordinal)
        || string.Equals(label, SchemasLabel, StringComparison.Ordinal)
        || string.Equals(label, RepresentationsLabel, StringComparison.Ordinal)
        || IsRepresentationLabel(label);


    /// <summary>
    /// Determines whether a value names one representation — <c>Representations/</c> followed by a non-empty
    /// folder name (<c>CSIP114</c>, <c>CSIP107</c>).
    /// </summary>
    /// <param name="label">The <c>fileGrp/@USE</c> or <c>div/@LABEL</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value names one representation.</returns>
    /// <remarks>
    /// The profile writes this rule as <c>fileGrp[@USE=[starts-with('Representations')]]</c>, which is its own
    /// shorthand rather than executable XPath. The reading here is the stricter of the two the shorthand admits:
    /// the prefix ends at a solidus and something follows it, so the bare value <c>Representations</c> — which is
    /// the division label of <c>CSIP103</c> and not a representation — is not mistaken for a representation of
    /// that name.
    /// </remarks>
    public static bool IsRepresentationLabel(string? label) =>
        label is not null
        && label.StartsWith(RepresentationsPrefix, StringComparison.Ordinal)
        && label.Length > RepresentationsPrefix.Length;


    /// <summary>
    /// States the representation folder name a per-representation label names.
    /// </summary>
    /// <param name="label">The <c>fileGrp/@USE</c> or <c>div/@LABEL</c> value, or <see langword="null"/>.</param>
    /// <returns>The folder name, or <see langword="null"/> when the value does not name a representation.</returns>
    public static string? RepresentationFolderFromLabel(string? label) =>
        IsRepresentationLabel(label) ? label![RepresentationsPrefix.Length..] : null;


    /// <summary>Determines whether a value is one of the eleven members of the base METS <c>CHECKSUMTYPE</c> enumeration.</summary>
    /// <param name="checksumType">The <c>@CHECKSUMTYPE</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one the enumeration states.</returns>
    /// <remarks>
    /// Membership says only that a document is schema-valid. Whether this library will recompute the value is a
    /// different question, and <see cref="EArkFixity"/> is where it is answered — the enumeration admits MD5,
    /// CRC32 and Adler-32 as first-class values and imposes no minimum strength of its own.
    /// </remarks>
    public static bool IsChecksumType(string? checksumType) =>
        string.Equals(checksumType, Adler32ChecksumType, StringComparison.Ordinal)
        || string.Equals(checksumType, Crc32ChecksumType, StringComparison.Ordinal)
        || string.Equals(checksumType, HavalChecksumType, StringComparison.Ordinal)
        || string.Equals(checksumType, Md5ChecksumType, StringComparison.Ordinal)
        || string.Equals(checksumType, MnpChecksumType, StringComparison.Ordinal)
        || string.Equals(checksumType, Sha1ChecksumType, StringComparison.Ordinal)
        || string.Equals(checksumType, Sha256ChecksumType, StringComparison.Ordinal)
        || string.Equals(checksumType, Sha384ChecksumType, StringComparison.Ordinal)
        || string.Equals(checksumType, Sha512ChecksumType, StringComparison.Ordinal)
        || string.Equals(checksumType, TigerChecksumType, StringComparison.Ordinal)
        || string.Equals(checksumType, WhirlpoolChecksumType, StringComparison.Ordinal);


    /// <summary>
    /// Resolves the digest algorithm a <c>@CHECKSUMTYPE</c> value names onto the registry the digest seam
    /// dispatches on.
    /// </summary>
    /// <param name="checksumType">The <c>@CHECKSUMTYPE</c> value, or <see langword="null"/>.</param>
    /// <returns>The resolved algorithm, or <see langword="null"/> when this library will not compute it.</returns>
    /// <remarks>
    /// Exactly the three algorithms <see cref="PkiDigestAlgorithm.FromOid"/> resolves from an object identifier
    /// and <see cref="XmlSignatureWellKnown.DigestAlgorithmFromUri"/> resolves from a URI resolve here, so a
    /// caller cannot reach a stronger or a weaker set by stating an algorithm as a METS checksum type rather than
    /// in one of the other two forms.
    /// </remarks>
    public static PkiDigestAlgorithm? DigestAlgorithmFromChecksumType(string? checksumType) => checksumType switch
    {
        null => null,
        _ when string.Equals(checksumType, Sha256ChecksumType, StringComparison.Ordinal) => PkiDigestAlgorithm.Sha256,
        _ when string.Equals(checksumType, Sha384ChecksumType, StringComparison.Ordinal) => PkiDigestAlgorithm.Sha384,
        _ when string.Equals(checksumType, Sha512ChecksumType, StringComparison.Ordinal) => PkiDigestAlgorithm.Sha512,
        _ => null
    };


    /// <summary>
    /// States the <c>@CHECKSUMTYPE</c> value for a digest algorithm — the inverse of
    /// <see cref="DigestAlgorithmFromChecksumType"/>, used when a document is written rather than read.
    /// </summary>
    /// <param name="algorithm">The algorithm to name.</param>
    /// <returns>The value, or <see langword="null"/> when the algorithm has no registered checksum-type name here.</returns>
    /// <remarks>
    /// This is where the creation-side floor lives: the three names this returns are the only <c>@CHECKSUMTYPE</c>
    /// values anything in this library writes, even though the enumeration would admit eight more. The
    /// specification imposes no minimum strength and the reference material's own worked examples use MD5, so the
    /// floor is this library's deliberate choice rather than an inherited one.
    /// </remarks>
    public static string? ChecksumTypeFromDigestAlgorithm(PkiDigestAlgorithm algorithm) => algorithm.Identifier.Oid switch
    {
        WellKnownOids.Sha256 => Sha256ChecksumType,
        WellKnownOids.Sha384 => Sha384ChecksumType,
        WellKnownOids.Sha512 => Sha512ChecksumType,
        _ => null
    };


    /// <summary>
    /// Determines whether a value is a legal XML <c>NCName</c>, which every identifier a METS or a
    /// preservation-metadata document carries has to be.
    /// </summary>
    /// <param name="value">The identifier value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is an <c>NCName</c>.</returns>
    /// <remarks>
    /// <para>
    /// Clause 5.1 of <see href="https://earkcsip.dilcis.eu/specification/implementation/metadata/general-requirements/">
    /// E-ARK CSIP v2.2.0</see> states the obligation without giving it a requirement identifier of its own:
    /// "Valid XML IDs must also conform to the NCName restrictions ... must begin a letter or an underscore
    /// character ('_'), and contain no characters other than letters, digits, hyphens, underscores, full stops,
    /// plus some extension and combination characters." It binds every <c>@ID</c> row of the catalogue and every
    /// identifier container of the preservation-metadata vocabulary, which is why the recognition sits in one
    /// place rather than at each of them.
    /// </para>
    /// <para>
    /// The character classes are the <c>NameStartChar</c> and <c>NameChar</c> productions of
    /// <see href="https://www.w3.org/TR/xml/#NT-Name">Extensible Markup Language (XML) 1.0 clause 2.3</see>,
    /// minus the colon, which is what makes a <c>Name</c> an <c>NCName</c>
    /// (<see href="https://www.w3.org/TR/xml-names/#NT-NCName">Namespaces in XML 1.0 clause 4</see>). They are
    /// enumerated here as code-point ranges rather than reached through an XML library, because this project
    /// references none.
    /// </para>
    /// <para>
    /// The practical consequence the specification itself calls out: a bare UUID is not an <c>NCName</c>, because
    /// it may start with a digit — an identifier built from one needs a letter or underscore prefix.
    /// </para>
    /// </remarks>
    public static bool IsNCName(string? value)
    {
        if(string.IsNullOrEmpty(value))
        {
            return false;
        }

        bool first = true;
        foreach(Rune rune in value.EnumerateRunes())
        {
            if(first)
            {
                if(!IsNameStartCharacter(rune.Value))
                {
                    return false;
                }

                first = false;
            }
            else if(!IsNameCharacter(rune.Value))
            {
                return false;
            }
        }

        return true;

        //The NameStartChar production of XML 1.0 clause 2.3 with the colon removed. Written as an explicit range
        //test rather than as a Unicode-category test because the production enumerates code points, and the two
        //do not agree: it admits U+00B7 nowhere and U+2070 everywhere a category test would not.
        static bool IsNameStartCharacter(int codePoint) =>
            codePoint is '_'
            or (>= 'A' and <= 'Z')
            or (>= 'a' and <= 'z')
            or (>= 0x00C0 and <= 0x00D6)
            or (>= 0x00D8 and <= 0x00F6)
            or (>= 0x00F8 and <= 0x02FF)
            or (>= 0x0370 and <= 0x037D)
            or (>= 0x037F and <= 0x1FFF)
            or (>= 0x200C and <= 0x200D)
            or (>= 0x2070 and <= 0x218F)
            or (>= 0x2C00 and <= 0x2FEF)
            or (>= 0x3001 and <= 0xD7FF)
            or (>= 0xF900 and <= 0xFDCF)
            or (>= 0xFDF0 and <= 0xFFFD)
            or (>= 0x10000 and <= 0xEFFFF);

        //The NameChar production of XML 1.0 clause 2.3 with the colon removed: a NameStartChar plus the four
        //additional classes.
        static bool IsNameCharacter(int codePoint) =>
            IsNameStartCharacter(codePoint)
            || codePoint is '-'
            or '.'
            or (>= '0' and <= '9')
            or 0x00B7
            or (>= 0x0300 and <= 0x036F)
            or (>= 0x203F and <= 0x2040);
    }
}
