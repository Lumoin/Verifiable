using System;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// The wire names a preservation-metadata document fixes — its namespace, the version the specification pins, the
/// object categories, the rights bases and the identifier type its own examples use throughout — together with the
/// recognition helpers a dispatch site uses instead of comparing string literals at the call site.
/// </summary>
/// <remarks>
/// <para>
/// Every value here is stated by <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see>:
/// the version by requirement <c>PM1</c>, the object categories by <c>PM2</c>, <c>PM14</c> and <c>PM28</c>, the
/// rights bases by <c>PM98</c>, the identifier convention by clause 2.2.5, and the document-naming recommendation
/// by clause 2.2.3.
/// </para>
/// <para>
/// <strong>Most of this vocabulary's value sets are deliberately not closed here.</strong> Clause 2.2.4 defines no
/// vocabulary of its own and points at an externally hosted family of them for event types, event outcomes,
/// relationship types and subtypes, agent types, format-registry roles, storage media and content-location types.
/// Those reach the model as text: closing them here would either hard-code a registry this library does not own or
/// refuse a document that used a term added to it after this file was written.
/// </para>
/// <para>
/// <strong>Comparison is ordinal and case-sensitive.</strong> Every value here is either an XML enumeration facet
/// or a fixed attribute value, and both match by exact character sequence.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The namespace is compared as written and never dereferenced; System.Uri normalises case and escaping, which would make two namespaces that are not the same namespace compare equal.")]
public static class PremisWellKnown
{
    /// <summary>
    /// The preservation-metadata namespace, <c>http://www.loc.gov/premis/v3</c>, which the vocabulary's own schema
    /// declares as its target and whose <c>elementFormDefault="qualified"</c> puts every element of a document in
    /// it.
    /// </summary>
    public static string PremisNamespace { get; } = "http://www.loc.gov/premis/v3";

    /// <summary>
    /// The XML Schema instance namespace, <c>http://www.w3.org/2001/XMLSchema-instance</c>, which carries the
    /// <c>xsi:type</c> attribute an object states its category in (<c>PM2</c>, <c>PM14</c>, <c>PM28</c>).
    /// </summary>
    public static string XmlSchemaInstanceNamespace { get; } = "http://www.w3.org/2001/XMLSchema-instance";

    /// <summary>The value requirement <c>PM1</c> fixes for <c>premis/@version</c>, <c>3.0</c>.</summary>
    public static string PremisVersion { get; } = "3.0";

    /// <summary>
    /// The document name clause 2.2.3 recommends, <c>PREMIS.xml</c> — "to follow the CSIP". The clause states no
    /// requirement, so this is a recommendation a caller may follow and a reader must not depend on.
    /// </summary>
    public static string PremisFileName { get; } = "PREMIS.xml";

    /// <summary>
    /// The identifier type clause 2.2.5 uses throughout for a value the repository minted itself, <c>local</c>.
    /// Every <c>[entity]IdentifierType</c> row of the catalogue names it as what to state "if locally created".
    /// </summary>
    public static string LocalIdentifierType { get; } = "local";

    /// <summary>The <c>intellectualEntity</c> object category (<c>PM2</c>).</summary>
    public static string IntellectualEntityObjectCategory { get; } = "intellectualEntity";

    /// <summary>The <c>representation</c> object category (<c>PM14</c>).</summary>
    public static string RepresentationObjectCategory { get; } = "representation";

    /// <summary>The <c>file</c> object category (<c>PM28</c>) — the one that carries fixity, format and storage.</summary>
    public static string FileObjectCategory { get; } = "file";

    /// <summary>
    /// The <c>bitstream</c> object category. The vocabulary's own schema declares it; this specification
    /// constrains no requirement over it, so it is recognised on read and never written by anything here.
    /// </summary>
    public static string BitstreamObjectCategory { get; } = "bitstream";

    /// <summary>The <c>copyright</c> rights basis (<c>PM98</c>), which makes <c>copyrightInformation</c> meaningful (<c>PM99</c>).</summary>
    public static string CopyrightRightsBasis { get; } = "copyright";

    /// <summary>The <c>license</c> rights basis (<c>PM98</c>), which makes <c>licenseInformation</c> meaningful (<c>PM105</c>).</summary>
    public static string LicenseRightsBasis { get; } = "license";

    /// <summary>The <c>statute</c> rights basis (<c>PM98</c>), which makes <c>statuteInformation</c> meaningful (<c>PM109</c>).</summary>
    public static string StatuteRightsBasis { get; } = "statute";

    /// <summary>The <c>other</c> rights basis (<c>PM98</c>), which makes <c>otherRightsInformation</c> meaningful (<c>PM115</c>) and its own locally maintained basis mandatory (<c>PM119</c>).</summary>
    public static string OtherRightsBasis { get; } = "other";


    /// <summary>Determines whether a value is the version requirement <c>PM1</c> fixes.</summary>
    /// <param name="version">The <c>premis/@version</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="PremisVersion"/>.</returns>
    public static bool IsPremisVersion(string? version) =>
        string.Equals(version, PremisVersion, StringComparison.Ordinal);


    /// <summary>Determines whether a value is one of the four object categories the vocabulary declares.</summary>
    /// <param name="category">The <c>object/@xsi:type</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one the vocabulary states.</returns>
    public static bool IsObjectCategory(string? category) =>
        string.Equals(category, IntellectualEntityObjectCategory, StringComparison.Ordinal)
        || string.Equals(category, RepresentationObjectCategory, StringComparison.Ordinal)
        || string.Equals(category, FileObjectCategory, StringComparison.Ordinal)
        || string.Equals(category, BitstreamObjectCategory, StringComparison.Ordinal);


    /// <summary>Determines whether a value is one of the four rights bases requirement <c>PM98</c> states.</summary>
    /// <param name="basis">The <c>rightsStatement/rightsBasis</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is one the vocabulary states.</returns>
    public static bool IsRightsBasis(string? basis) =>
        string.Equals(basis, CopyrightRightsBasis, StringComparison.Ordinal)
        || string.Equals(basis, LicenseRightsBasis, StringComparison.Ordinal)
        || string.Equals(basis, StatuteRightsBasis, StringComparison.Ordinal)
        || string.Equals(basis, OtherRightsBasis, StringComparison.Ordinal);


    /// <summary>Determines whether an identifier type is the locally minted one clause 2.2.5 names.</summary>
    /// <param name="identifierType">The <c>[entity]IdentifierType</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value is <see cref="LocalIdentifierType"/>.</returns>
    public static bool IsLocalIdentifierType(string? identifierType) =>
        string.Equals(identifierType, LocalIdentifierType, StringComparison.Ordinal);


    /// <summary>
    /// Determines whether a metadata-type version names the major version this vocabulary requires.
    /// </summary>
    /// <param name="metadataTypeVersion">The <c>mdRef/@MDTYPEVERSION</c> value, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the value begins with <c>3</c>.</returns>
    /// <remarks>
    /// Requirement <c>AIPM7</c> of <see href="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml">E-ARK AIP
    /// v2.2.0</see> states the rule as a prefix rather than as an exact value, so that a document stating
    /// <c>3.0</c> and one stating a later revision of the same major version both satisfy it.
    /// </remarks>
    public static bool IsPremisMajorVersion(string? metadataTypeVersion) =>
        metadataTypeVersion is not null && metadataTypeVersion.StartsWith('3');
}
