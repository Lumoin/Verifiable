using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One identifier container — the <c>[entity]IdentifierType</c>/<c>[entity]IdentifierValue</c> pair every entity
/// of the preservation-metadata vocabulary is identified by, per clause 2.2.5 of
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see>.
/// </summary>
/// <remarks>
/// One type serves all of them because the vocabulary states one shape and repeats it: for objects
/// (<c>PM4</c>/<c>PM5</c>, <c>PM16</c>/<c>PM17</c>, <c>PM30</c>/<c>PM31</c>), for events
/// (<c>PM82</c>/<c>PM83</c>), for agents (<c>PM71</c>/<c>PM72</c>), for rights statements
/// (<c>PM96</c>/<c>PM97</c>), for every <c>related*</c> and <c>linking*</c> reference between them, and for the
/// documentation identifiers of every rights basis. What differs between the occurrences is the element name the
/// serialisation seam writes, not the shape.
/// </remarks>
/// <param name="Type">The identifier's type, which clause 2.2.5 states as <see cref="PremisWellKnown.LocalIdentifierType"/> for a value the repository minted itself.</param>
/// <param name="Value">The identifier's value, unique within the document and — for a local one, per requirement <c>PREMIS-ID-LOCAL</c> — within the repository.</param>
[DebuggerDisplay("PremisIdentifier: {Type,nq}:{Value,nq}")]
public readonly record struct PremisIdentifier(string Type, string Value);


/// <summary>
/// One <c>significantProperties</c> element of a representation object, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM18</c>–<c>PM20</c>.
/// </summary>
/// <param name="Type">The <c>significantPropertiesType</c> element (<c>PM19</c>): what kind of property it is — content, structure, behaviour, page count.</param>
/// <param name="Value">The <c>significantPropertiesValue</c> element (<c>PM20</c>).</param>
[DebuggerDisplay("PremisSignificantProperty: {Type,nq}={Value,nq}")]
public readonly record struct PremisSignificantProperty(string Type, string Value);


/// <summary>
/// One <c>environmentFunction</c> element of an environment object, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM6</c>–<c>PM8</c>.
/// </summary>
/// <param name="Type">The <c>environmentFunctionType</c> element (<c>PM7</c>), from the externally hosted environment-function vocabulary.</param>
/// <param name="Level">The <c>environmentFunctionLevel</c> element (<c>PM8</c>): the sequence number that orders the environment for rendering.</param>
[DebuggerDisplay("PremisEnvironmentFunction: {Type,nq} level {Level,nq}")]
public readonly record struct PremisEnvironmentFunction(string Type, string Level);


/// <summary>
/// The <c>environmentDesignation</c> element of an environment object, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM9</c>–<c>PM13</c>.
/// </summary>
/// <param name="Name">The <c>environmentName</c> element (<c>PM10</c>): the described software's name.</param>
/// <param name="Version">The <c>environmentVersion</c> element (<c>PM11</c>), or <see langword="null"/>.</param>
/// <param name="Origin">The <c>environmentOrigin</c> element (<c>PM12</c>), or <see langword="null"/>.</param>
/// <param name="Note">The <c>environmentDesignationNote</c> element (<c>PM13</c>), or <see langword="null"/>.</param>
[DebuggerDisplay("PremisEnvironmentDesignation: {Name,nq} {Version,nq}")]
public readonly record struct PremisEnvironmentDesignation(string Name, string? Version, string? Origin, string? Note);


/// <summary>
/// The <c>formatDesignation</c> element of a file object's format, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM38</c>–<c>PM40</c>.
/// </summary>
/// <param name="Name">The <c>formatName</c> element (<c>PM39</c>).</param>
/// <param name="Version">The <c>formatVersion</c> element (<c>PM40</c>), or <see langword="null"/>.</param>
[DebuggerDisplay("PremisFormatDesignation: {Name,nq} {Version,nq}")]
public readonly record struct PremisFormatDesignation(string Name, string? Version);


/// <summary>
/// The <c>formatRegistry</c> element of a file object's format, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM41</c>–<c>PM44</c>.
/// </summary>
/// <remarks>
/// Requirement <c>PREMIS-FILE-FORMAT-PUID</c> recommends a persistent format identifier from a format registry as
/// the key. The registry itself is external to this library: nothing here resolves a key, and no registry is
/// shipped or required.
/// </remarks>
/// <param name="Name">The <c>formatRegistryName</c> element (<c>PM42</c>).</param>
/// <param name="Key">The <c>formatRegistryKey</c> element (<c>PM43</c>): the registry's identifier for the format.</param>
/// <param name="Role">The <c>formatRegistryRole</c> element (<c>PM44</c>), or <see langword="null"/>.</param>
[DebuggerDisplay("PremisFormatRegistry: {Name,nq}:{Key,nq}")]
public readonly record struct PremisFormatRegistry(string Name, string Key, string? Role);


/// <summary>
/// The <c>format</c> element of a file object's characteristics, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirement <c>PM37</c>.
/// </summary>
/// <remarks>
/// Requirement <c>PREMIS-FILE-FORMAT</c> admits either sub-element or both, which is why neither is required
/// here — a format stated only by name and one stated only by registry key are both conformant.
/// </remarks>
/// <param name="Designation">The <c>formatDesignation</c> element (<c>PM38</c>), or <see langword="null"/>.</param>
/// <param name="Registry">The <c>formatRegistry</c> element (<c>PM41</c>), or <see langword="null"/>.</param>
[DebuggerDisplay("PremisFormat: {Designation.Name,nq}")]
public readonly record struct PremisFormat(PremisFormatDesignation? Designation, PremisFormatRegistry? Registry);


/// <summary>
/// One <c>creatingApplication</c> element of a file object's characteristics, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM45</c>–<c>PM48</c>.
/// </summary>
/// <param name="Name">The <c>creatingApplicationName</c> element (<c>PM46</c>).</param>
/// <param name="Version">The <c>creatingApplicationVersion</c> element (<c>PM47</c>), or <see langword="null"/>.</param>
/// <param name="DateCreatedByApplication">The <c>dateCreatedByApplication</c> element (<c>PM48</c>), or <see langword="null"/>.</param>
[DebuggerDisplay("PremisCreatingApplication: {Name,nq} {Version,nq}")]
public readonly record struct PremisCreatingApplication(string Name, string? Version, string? DateCreatedByApplication);


/// <summary>
/// The <c>contentLocation</c> element of a file object's storage, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM53</c>–<c>PM55</c>.
/// </summary>
/// <remarks>
/// <strong>A documented interpretation.</strong> Requirement <c>PM53</c>'s keyword in the source tables is the
/// word <c>COULD</c>, which is not one of the terms the requirement-level vocabulary defines and which appears
/// nowhere else in the catalogue except at <c>PM66</c>. Read against its own <c>0..1</c> cardinality, it is
/// permissive, so this model treats it as optional — the same reading either of the defined permissive keywords
/// would produce.
/// </remarks>
/// <param name="Type">The <c>contentLocationType</c> element (<c>PM54</c>), from the externally hosted content-location-type vocabulary.</param>
/// <param name="Value">The <c>contentLocationValue</c> element (<c>PM55</c>): where the content sits.</param>
[DebuggerDisplay("PremisContentLocation: {Type,nq}:{Value,nq}")]
public readonly record struct PremisContentLocation(string Type, string Value);


/// <summary>
/// One <c>storage</c> element of a file object, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM52</c> and <c>PM56</c>.
/// </summary>
/// <remarks>
/// What an operator records here — a resolvable location, an access-control hint, the coordinates of a segment of
/// a divided package — is a repository's business and not this library's: the element is carried, never acted on.
/// </remarks>
/// <param name="ContentLocation">The <c>contentLocation</c> element (<c>PM53</c>), or <see langword="null"/>.</param>
/// <param name="Medium">The <c>storageMedium</c> element (<c>PM56</c>), or <see langword="null"/>.</param>
[DebuggerDisplay("PremisStorage: {Medium,nq}")]
public readonly record struct PremisStorage(PremisContentLocation? ContentLocation, string? Medium);


/// <summary>
/// One <c>objectCharacteristics</c> element of a file object — its fixity, its format and what created it, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM32</c>–<c>PM50</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is the second of a package's fixity layers.</strong> A file may carry a fixity here and another
/// one on its METS file entry, computed independently and never cross-checked by either specification; a file that
/// is itself a signed object carries a third inside its own structure. Requirement <c>PREMIS-CHECKSUMS</c>
/// recommends a specific algorithm for this one — "in the form of the recommended SHA-256 hashsum, a fixed size
/// 256-bit value" — which is the only place in either specification of this family that names a preferred
/// algorithm outright.
/// </para>
/// <para>
/// The <c>objectCharacteristicsExtension</c> element (<c>PM50</c>) and the <c>creatingApplicationExtension</c>
/// element (<c>PM49</c>) are not modelled: both are arbitrary foreign XML whose content the specification neither
/// constrains nor interprets, and a model of them would describe nothing.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every fixity it carries; disposing the object that carries it
/// disposes them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisObjectCharacteristics: IDisposable
{
    /// <summary>The <c>fixity</c> elements (<c>PM33</c>–<c>PM36</c>). The instance owns them.</summary>
    public IReadOnlyList<EArkFixity> Fixities { get; init; } = [];

    /// <summary>The <c>format</c> element (<c>PM37</c>), or <see langword="null"/>.</summary>
    public PremisFormat? Format { get; init; }

    /// <summary>The <c>creatingApplication</c> elements (<c>PM45</c>).</summary>
    public IReadOnlyList<PremisCreatingApplication> CreatingApplications { get; init; } = [];


    /// <summary>Disposes every fixity this element owns.</summary>
    public void Dispose()
    {
        foreach(EArkFixity fixity in Fixities)
        {
            fixity.Dispose();
        }
    }


    /// <summary>A short debugger string showing how the object is characterised.</summary>
    private string DebuggerDisplay => $"PremisObjectCharacteristics({Fixities.Count} fixities, {Format?.Designation?.Name ?? "no format"})";
}


/// <summary>
/// One <c>relationship</c> element of an object, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements
/// <c>PM21</c>–<c>PM27</c> (a representation's relationship to its rendering software) and <c>PM57</c>–<c>PM65</c>
/// (a file's relationships to other objects and to events).
/// </summary>
/// <remarks>
/// <para>
/// <strong>This element is the vocabulary's only extension point for saying what one object is to another.</strong>
/// Neither this specification nor the package specification it extends defines any term meaning "is signed by" or
/// "is attested by" — a systematic search of both finds no mention of signatures, time-stamps or evidence records
/// anywhere. The type and subtype vocabularies are externally hosted and open, so a relationship of that meaning
/// is a convention rather than a defined mechanism, and both values are carried as text here for exactly that
/// reason.
/// </para>
/// <para>
/// Requirement <c>PREMIS-IP-INCLUDED</c> uses this element for the one relationship the specification does fix:
/// when a package is part of another package, <c>relationshipSubType</c> references the superordinate one — which
/// is also requirement <c>AIP13</c> of
/// <see href="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml">E-ARK AIP v2.2.0</see>, the object-level
/// half of an archival package's parent-child chain.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisRelationship
{
    /// <summary>The <c>relationshipType</c> element (<c>PM22</c>/<c>PM58</c>), from the externally hosted relationship-type vocabulary.</summary>
    public required string Type { get; init; }

    /// <summary>The <c>relationshipSubType</c> element (<c>PM23</c>/<c>PM59</c>), from the externally hosted relationship-subtype vocabulary.</summary>
    public required string SubType { get; init; }

    /// <summary>The <c>relatedObjectIdentifier</c> elements (<c>PM24</c>–<c>PM26</c>, <c>PM60</c>–<c>PM62</c>).</summary>
    public IReadOnlyList<PremisIdentifier> RelatedObjectIdentifiers { get; init; } = [];

    /// <summary>
    /// The <c>relatedEventIdentifier</c> elements (<c>PM63</c>–<c>PM65</c>), which requirement <c>AIP17</c> of the
    /// archival profile uses to chain an object back to the event that created its source — the closest thing
    /// either specification has to a migration history, and one nothing binds cryptographically.
    /// </summary>
    public IReadOnlyList<PremisIdentifier> RelatedEventIdentifiers { get; init; } = [];

    /// <summary>The <c>relatedEnvironmentPurpose</c> element (<c>PM27</c>), or <see langword="null"/>.</summary>
    public string? RelatedEnvironmentPurpose { get; init; }


    /// <summary>A short debugger string showing what the relationship says.</summary>
    private string DebuggerDisplay => $"PremisRelationship({Type}/{SubType}, {RelatedObjectIdentifiers.Count} objects, {RelatedEventIdentifiers.Count} events)";
}


/// <summary>
/// One <c>object</c> element, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM2</c>–<c>PM68</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>One type for every category, because the vocabulary states one element.</strong> The category is an
/// <c>xsi:type</c> attribute (<c>PM2</c>, <c>PM14</c>, <c>PM28</c>) and it decides which of the members below the
/// specification gives requirements for: an intellectual-entity or environment object carries the environment
/// members, a representation object carries significant properties and a relationship to its rendering software,
/// and a file object carries the characteristics, the original name, the storage and the relationships. Nothing
/// here enforces that split — it is a set of requirements, and requirements are the validation profiles' business.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every characteristics element it carries — and through them every
/// fixity carrier; disposing the document that carries it disposes them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisObject: IDisposable
{
    /// <summary>
    /// The <c>@xsi:type</c> attribute (<c>PM2</c>, <c>PM14</c>, <c>PM28</c>): which category of object this is.
    /// Carried as text so a document stating a value outside the vocabulary can be read and reported on;
    /// <see cref="PremisWellKnown.IsObjectCategory"/> is the recognition.
    /// </summary>
    public required string Category { get; init; }

    /// <summary>The <c>objectIdentifier</c> elements (<c>PM3</c>, <c>PM15</c>, <c>PM29</c>).</summary>
    public IReadOnlyList<PremisIdentifier> Identifiers { get; init; } = [];

    /// <summary>The <c>significantProperties</c> elements (<c>PM18</c>).</summary>
    public IReadOnlyList<PremisSignificantProperty> SignificantProperties { get; init; } = [];

    /// <summary>The <c>objectCharacteristics</c> elements (<c>PM32</c>). The instance owns them.</summary>
    public IReadOnlyList<PremisObjectCharacteristics> Characteristics { get; init; } = [];

    /// <summary>The <c>originalName</c> element (<c>PM51</c>), stated when the name changed during preservation, or <see langword="null"/>.</summary>
    public string? OriginalName { get; init; }

    /// <summary>The <c>storage</c> elements (<c>PM52</c>).</summary>
    public IReadOnlyList<PremisStorage> Storage { get; init; } = [];

    /// <summary>The <c>relationship</c> elements (<c>PM21</c>, <c>PM57</c>).</summary>
    public IReadOnlyList<PremisRelationship> Relationships { get; init; } = [];

    /// <summary>The <c>linkingRightsStatementIdentifier</c> elements (<c>PM66</c>–<c>PM68</c>), naming rights statements attached to the object.</summary>
    public IReadOnlyList<PremisIdentifier> RightsStatementIdentifiers { get; init; } = [];

    /// <summary>The <c>environmentFunction</c> elements (<c>PM6</c>), stated by an environment object.</summary>
    public IReadOnlyList<PremisEnvironmentFunction> EnvironmentFunctions { get; init; } = [];

    /// <summary>The <c>environmentDesignation</c> element (<c>PM9</c>), stated by an environment object, or <see langword="null"/>.</summary>
    public PremisEnvironmentDesignation? EnvironmentDesignation { get; init; }


    /// <summary>Disposes every characteristics element this object owns.</summary>
    public void Dispose()
    {
        foreach(PremisObjectCharacteristics characteristics in Characteristics)
        {
            characteristics.Dispose();
        }
    }


    /// <summary>A short debugger string showing the object's category and identifier.</summary>
    private string DebuggerDisplay => $"PremisObject({Category}, {(Identifiers.Count > 0 ? Identifiers[0].Value : "unidentified")})";
}


/// <summary>
/// One <c>event</c> element — one preservation action recorded against the objects it affected, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM80</c>–<c>PM92</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is where an archival package's provenance chain lives, and it is plain text.</strong>
/// Requirements <c>AIP15</c>–<c>AIP17</c> of
/// <see href="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml">E-ARK AIP v2.2.0</see> build a migration
/// history out of these elements: an event of a migration type, the agent that performed it (<c>AIP16</c>,
/// mandatory), the object it produced, and a reference back to the event that created its source. Nothing in that
/// chain is cryptographically bound — a reference can name any event, and no specification of this family says
/// otherwise. Binding it is exactly what an evidence record or an archive time-stamp over the document that
/// carries these events does, and that binding is this library's convention rather than the vocabulary's.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisEvent
{
    /// <summary>The <c>eventIdentifier</c> elements (<c>PM81</c>–<c>PM83</c>).</summary>
    public IReadOnlyList<PremisIdentifier> Identifiers { get; init; } = [];

    /// <summary>The <c>eventType</c> element (<c>PM84</c>), from the externally hosted event-type vocabulary.</summary>
    public required string Type { get; init; }

    /// <summary>
    /// The <c>eventDateTime</c> element (<c>PM85</c>): when the event occurred. Carried as text because the
    /// vocabulary types it as an extended date/time value, which admits partial dates and intervals that no single
    /// instant can hold.
    /// </summary>
    public required string EventDateTime { get; init; }

    /// <summary>The <c>eventOutcomeInformation/eventOutcome</c> element (<c>PM86</c>), from the externally hosted event-outcome vocabulary, or <see langword="null"/>.</summary>
    public string? Outcome { get; init; }

    /// <summary>The <c>linkingAgentIdentifier</c> elements (<c>PM87</c>–<c>PM89</c>): the agents that carried the event out.</summary>
    public IReadOnlyList<PremisIdentifier> LinkingAgentIdentifiers { get; init; } = [];

    /// <summary>The <c>linkingObjectIdentifier</c> elements (<c>PM90</c>–<c>PM92</c>): the objects the event affected.</summary>
    public IReadOnlyList<PremisIdentifier> LinkingObjectIdentifiers { get; init; } = [];


    /// <summary>A short debugger string showing what happened and when.</summary>
    private string DebuggerDisplay => $"PremisEvent({Type}, {EventDateTime}, {LinkingObjectIdentifiers.Count} objects)";
}


/// <summary>
/// One <c>agent</c> element — someone or something that took part in an event, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM69</c>–<c>PM79</c>.
/// </summary>
/// <remarks>
/// Clause 2.2 draws a line the package vocabulary does not: information about the actors of preservation actions
/// belongs here and not in the package header's own agent element, which covers package-level events such as
/// creation and submission. Requirement <c>PREMIS-AGENT</c> makes it an obligation — an agent an event references
/// must be described by one of these.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisAgent
{
    /// <summary>The <c>agentIdentifier</c> elements (<c>PM70</c>–<c>PM72</c>).</summary>
    public IReadOnlyList<PremisIdentifier> Identifiers { get; init; } = [];

    /// <summary>The <c>agentName</c> element (<c>PM73</c>): a name a human can understand.</summary>
    public required string Name { get; init; }

    /// <summary>The <c>agentType</c> element (<c>PM74</c>), from the externally hosted agent-type vocabulary.</summary>
    public required string Type { get; init; }

    /// <summary>The <c>agentVersion</c> element (<c>PM75</c>), stated when the agent is software, or <see langword="null"/>.</summary>
    public string? Version { get; init; }

    /// <summary>The <c>agentNote</c> element (<c>PM76</c>), or <see langword="null"/>.</summary>
    public string? Note { get; init; }

    /// <summary>The <c>linkingRightsStatementIdentifier</c> elements (<c>PM77</c>–<c>PM79</c>): the rights the agent was granted.</summary>
    public IReadOnlyList<PremisIdentifier> RightsStatementIdentifiers { get; init; } = [];


    /// <summary>A short debugger string showing who the agent is.</summary>
    private string DebuggerDisplay => $"PremisAgent({Name}, {Type})";
}


/// <summary>
/// The <c>termOfGrant</c> element of a rights grant, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM122</c>–<c>PM124</c>.
/// </summary>
/// <param name="StartDate">The <c>startDate</c> element (<c>PM123</c>): when the granted act becomes allowed.</param>
/// <param name="EndDate">The <c>endDate</c> element (<c>PM124</c>), or <see langword="null"/> when the grant does not end.</param>
[DebuggerDisplay("PremisTermOfGrant: {StartDate,nq}..{EndDate,nq}")]
public readonly record struct PremisTermOfGrant(string StartDate, string? EndDate);


/// <summary>
/// The <c>rightsGranted</c> element of a rights statement, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM120</c>–<c>PM125</c>.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisRightsGranted
{
    /// <summary>The <c>act</c> elements (<c>PM121</c>): which acts the statement allows.</summary>
    public IReadOnlyList<string> Acts { get; init; } = [];

    /// <summary>The <c>termOfGrant</c> element (<c>PM122</c>), or <see langword="null"/>.</summary>
    public PremisTermOfGrant? TermOfGrant { get; init; }

    /// <summary>The <c>rightsGrantedNote</c> element (<c>PM125</c>), which is where a risk assessment is recorded, or <see langword="null"/>.</summary>
    public string? Note { get; init; }


    /// <summary>A short debugger string showing what is granted.</summary>
    private string DebuggerDisplay => $"PremisRightsGranted({Acts.Count} acts)";
}


/// <summary>
/// The <c>copyrightInformation</c> element of a rights statement, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM99</c>–<c>PM104</c>.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisCopyrightInformation
{
    /// <summary>The <c>copyrightStatus</c> element (<c>PM100</c>), from the externally hosted copyright-status vocabulary.</summary>
    public required string Status { get; init; }

    /// <summary>The <c>copyrightJurisdiction</c> element (<c>PM101</c>): the country whose copyright law applies, as its two-letter code.</summary>
    public required string Jurisdiction { get; init; }

    /// <summary>The <c>copyrightDocumentationIdentifier</c> elements (<c>PM102</c>–<c>PM104</c>).</summary>
    public IReadOnlyList<PremisIdentifier> DocumentationIdentifiers { get; init; } = [];


    /// <summary>A short debugger string showing the copyright status and where it applies.</summary>
    private string DebuggerDisplay => $"PremisCopyrightInformation({Status}, {Jurisdiction})";
}


/// <summary>
/// The <c>licenseInformation</c> element of a rights statement, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM105</c>–<c>PM108</c>.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisLicenseInformation
{
    /// <summary>The <c>licenseDocumentationIdentifier</c> elements (<c>PM106</c>–<c>PM108</c>).</summary>
    public IReadOnlyList<PremisIdentifier> DocumentationIdentifiers { get; init; } = [];


    /// <summary>A short debugger string showing how much documentation the licence has.</summary>
    private string DebuggerDisplay => $"PremisLicenseInformation({DocumentationIdentifiers.Count} documentation identifiers)";
}


/// <summary>
/// The <c>statuteInformation</c> element of a rights statement, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM109</c>–<c>PM114</c>.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisStatuteInformation
{
    /// <summary>The <c>statuteJurisdiction</c> element (<c>PM110</c>): the country whose statute applies, as its two-letter code.</summary>
    public required string Jurisdiction { get; init; }

    /// <summary>The <c>statuteCitation</c> element (<c>PM111</c>): the statute's identifying designation.</summary>
    public required string Citation { get; init; }

    /// <summary>The <c>statuteDocumentationIdentifier</c> elements (<c>PM112</c>–<c>PM114</c>).</summary>
    public IReadOnlyList<PremisIdentifier> DocumentationIdentifiers { get; init; } = [];


    /// <summary>A short debugger string showing which statute applies.</summary>
    private string DebuggerDisplay => $"PremisStatuteInformation({Jurisdiction}, {Citation})";
}


/// <summary>
/// The <c>otherRightsInformation</c> element of a rights statement, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM115</c>–<c>PM119</c>.
/// </summary>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisOtherRightsInformation
{
    /// <summary>The <c>otherRightsBasis</c> element (<c>PM119</c>), from a vocabulary the repository maintains itself.</summary>
    public required string Basis { get; init; }

    /// <summary>The <c>otherRightsDocumentationIdentifier</c> elements (<c>PM116</c>–<c>PM118</c>).</summary>
    public IReadOnlyList<PremisIdentifier> DocumentationIdentifiers { get; init; } = [];


    /// <summary>A short debugger string showing the locally defined basis.</summary>
    private string DebuggerDisplay => $"PremisOtherRightsInformation({Basis})";
}


/// <summary>
/// One <c>rightsStatement</c> element, per
/// <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> requirements <c>PM94</c>–<c>PM125</c>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="Basis"/> is what makes exactly one of the four information members meaningful (<c>PM98</c>), and the
/// four are modelled separately rather than as one bag because each states a different mandatory content:
/// a copyright basis needs a status and a jurisdiction, a statute basis needs a jurisdiction and a citation, an
/// other basis needs a locally defined basis of its own, and a licence basis needs none of them.
/// </para>
/// <para>
/// <strong>This has nothing to do with cryptographic attestation.</strong> A rights statement is about permission
/// to use content; the identifiers that link objects and agents to one carry no evidential meaning, and reading
/// them as a signature relation would be a category error.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisRightsStatement
{
    /// <summary>The <c>rightsStatementIdentifier</c> elements (<c>PM95</c>–<c>PM97</c>): what an object's or an agent's rights link names.</summary>
    public IReadOnlyList<PremisIdentifier> Identifiers { get; init; } = [];

    /// <summary>
    /// The <c>rightsBasis</c> element (<c>PM98</c>). Carried as text so a document stating a value outside the
    /// vocabulary can be read and reported on; <see cref="PremisWellKnown.IsRightsBasis"/> is the recognition.
    /// </summary>
    public required string Basis { get; init; }

    /// <summary>The <c>copyrightInformation</c> element (<c>PM99</c>), meaningful when <see cref="Basis"/> is <see cref="PremisWellKnown.CopyrightRightsBasis"/>, or <see langword="null"/>.</summary>
    public PremisCopyrightInformation? CopyrightInformation { get; init; }

    /// <summary>The <c>licenseInformation</c> element (<c>PM105</c>), meaningful when <see cref="Basis"/> is <see cref="PremisWellKnown.LicenseRightsBasis"/>, or <see langword="null"/>.</summary>
    public PremisLicenseInformation? LicenseInformation { get; init; }

    /// <summary>The <c>statuteInformation</c> element (<c>PM109</c>), meaningful when <see cref="Basis"/> is <see cref="PremisWellKnown.StatuteRightsBasis"/>, or <see langword="null"/>.</summary>
    public PremisStatuteInformation? StatuteInformation { get; init; }

    /// <summary>The <c>otherRightsInformation</c> element (<c>PM115</c>), meaningful when <see cref="Basis"/> is <see cref="PremisWellKnown.OtherRightsBasis"/>, or <see langword="null"/>.</summary>
    public PremisOtherRightsInformation? OtherRightsInformation { get; init; }

    /// <summary>The <c>rightsGranted</c> element (<c>PM120</c>), or <see langword="null"/>.</summary>
    public PremisRightsGranted? RightsGranted { get; init; }


    /// <summary>A short debugger string showing what the statement is based on.</summary>
    private string DebuggerDisplay => $"PremisRightsStatement({Basis}, {Identifiers.Count} identifiers)";
}


/// <summary>
/// One preservation-metadata document — the <c>premis</c> element instance a package's digital-provenance section
/// references, as <see href="https://citspremis.dilcis.eu/">CS Preservation Metadata v1.0.1</see> constrains it.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The specification's subset, not all of the vocabulary.</strong> The underlying data dictionary is far
/// larger than what this specification asks a conformant package to state; its clause 2.2.2 declares a mapping of
/// the object, event and agent entities, and its own catalogue — requirements <c>PM1</c>–<c>PM125</c> across eight
/// tables, plus the fourteen named requirements its narrative carries — is what this model covers. A document
/// carrying more than that reads into this model without the surplus.
/// </para>
/// <para>
/// <strong>Leaves are text, on purpose.</strong> Apart from fixity — an algorithm plus octets, which is why
/// <see cref="EArkFixity"/> exists — this vocabulary types nearly every leaf as free text or as an open union: an
/// event's instant is an extended date/time value that admits partial dates and intervals, and every controlled
/// vocabulary it names is externally hosted and open. Parsing such values into stronger types would refuse
/// conformant documents, so the model carries what the document said and
/// <see cref="PremisWellKnown"/> supplies the recognition a caller wants.
/// </para>
/// <para>
/// <strong>Where a document sits.</strong> Clause 5.2 places the document in the package's metadata folder and
/// clause 5.1.1 binds it into the package manifest as one <c>digiprovMD</c> per document, whose <c>mdRef</c>
/// states <see cref="MetsWellKnown.PremisMetadataType"/> — never embedded in the manifest itself. Clause 2.2.3
/// adds the completeness rule: every such document present in the package is listed in the manifest at its own
/// level, package documents from the package manifest and representation documents from the representation's.
/// </para>
/// <para>
/// <strong>Serialisation-agnostic.</strong> This is a plain model: it names no XML type and this project
/// references no XML package. Reading and writing reach the library as <see cref="ParsePremisDelegate"/> and
/// <see cref="EncodePremisDelegate"/>.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every object it carries — and through them every fixity carrier;
/// the caller disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record PremisDocument: IDisposable
{
    /// <summary>
    /// The <c>@version</c> attribute (<c>PM1</c>), which the specification fixes to
    /// <see cref="PremisWellKnown.PremisVersion"/>. Carried as text so a document stating another version can be
    /// read and reported on.
    /// </summary>
    public required string Version { get; init; }

    /// <summary>The <c>object</c> elements. The instance owns them.</summary>
    public IReadOnlyList<PremisObject> Objects { get; init; } = [];

    /// <summary>The <c>event</c> elements (<c>PM80</c>).</summary>
    public IReadOnlyList<PremisEvent> Events { get; init; } = [];

    /// <summary>The <c>agent</c> elements (<c>PM69</c>).</summary>
    public IReadOnlyList<PremisAgent> Agents { get; init; } = [];

    /// <summary>The <c>rights/rightsStatement</c> elements (<c>PM93</c>, <c>PM94</c>).</summary>
    public IReadOnlyList<PremisRightsStatement> RightsStatements { get; init; } = [];


    /// <summary>Disposes every object this document owns.</summary>
    public void Dispose()
    {
        foreach(PremisObject premisObject in Objects)
        {
            premisObject.Dispose();
        }
    }


    /// <summary>A short debugger string showing how much the document states.</summary>
    private string DebuggerDisplay => $"PremisDocument({Version}, {Objects.Count} objects, {Events.Count} events, {Agents.Count} agents)";
}
