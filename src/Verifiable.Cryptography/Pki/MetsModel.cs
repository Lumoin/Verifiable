using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography.Pki;

/// <summary>
/// One <c>agent/note</c> element of a package header — free text plus the classification
/// <c>@csip:NOTETYPE</c> gives it, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP15</c> and <c>CSIP16</c>.
/// </summary>
/// <param name="NoteType">
/// The <c>@csip:NOTETYPE</c> value, or <see langword="null"/> when the document stated none. <c>CSIP16</c>
/// requires <see cref="MetsWellKnown.SoftwareVersionNoteType"/> on the note of the mandatory creator agent.
/// </param>
/// <param name="Text">The note's text, which for the mandatory creator agent is the creating tool's version.</param>
[DebuggerDisplay("MetsAgentNote: {NoteType,nq} {Text,nq}")]
public readonly record struct MetsAgentNote(string? NoteType, string Text);


/// <summary>
/// One <c>metsHdr/agent</c> element, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP10</c>–<c>CSIP16</c>.
/// </summary>
/// <remarks>
/// <para>
/// The profile fixes one agent completely: <c>CSIP11</c>–<c>CSIP13</c> require an agent whose <c>@ROLE</c> is
/// <c>CREATOR</c>, <c>@TYPE</c> is <c>OTHER</c> and <c>@OTHERTYPE</c> is <c>SOFTWARE</c>, carrying the creating
/// tool's name (<c>CSIP14</c>) and its version as a note (<c>CSIP15</c>, <c>CSIP16</c>). Further agents are
/// admitted by <c>CSIP10</c>'s <c>1..n</c> cardinality and constrained by nothing, so the three attributes are
/// carried as text rather than as closed vocabularies.
/// </para>
/// <para>
/// The preservation-metadata specification draws a line worth remembering here: agents that took part in
/// preservation actions belong in the preservation metadata, not in this element, which covers only package-level
/// events such as creation and submission.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record MetsAgent
{
    /// <summary>The <c>@ROLE</c> attribute (<c>CSIP11</c> fixes <see cref="MetsWellKnown.CreatorAgentRole"/> for the mandatory agent).</summary>
    public required string Role { get; init; }

    /// <summary>The <c>@TYPE</c> attribute (<c>CSIP12</c> fixes <see cref="MetsWellKnown.OtherAgentType"/> for the mandatory agent).</summary>
    public required string Type { get; init; }

    /// <summary>The <c>@OTHERTYPE</c> attribute (<c>CSIP13</c> fixes <see cref="MetsWellKnown.SoftwareAgentOtherType"/> for the mandatory agent), or <see langword="null"/> when the document stated none.</summary>
    public string? OtherType { get; init; }

    /// <summary>The <c>name</c> element (<c>CSIP14</c>), or <see langword="null"/> when the document stated none.</summary>
    public string? Name { get; init; }

    /// <summary>The <c>note</c> elements (<c>CSIP15</c>).</summary>
    public IReadOnlyList<MetsAgentNote> Notes { get; init; } = [];


    /// <summary>A short debugger string showing the agent's role and name.</summary>
    private string DebuggerDisplay => $"MetsAgent({Role}/{Type}/{OtherType ?? "unstated"}, {Name ?? "unnamed"})";
}


/// <summary>
/// The <c>metsHdr</c> element — the package header, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP117</c> and <c>CSIP7</c>–<c>CSIP16</c>.
/// </summary>
/// <remarks>
/// <c>CSIP7</c>'s <c>@CREATEDATE</c> and <c>CSIP8</c>'s <c>@LASTMODDATE</c> are <c>xsd:dateTime</c>, and clause
/// 5.1's general requirements say so outright — "are in fact XML Schema <c>datetime</c> and must include a time as
/// well as a date" — which is why they are instants here rather than dates.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record MetsHeader
{
    /// <summary>The <c>@CREATEDATE</c> attribute (<c>CSIP7</c>): when the package was created.</summary>
    public required DateTimeOffset CreateDate { get; init; }

    /// <summary>The <c>@LASTMODDATE</c> attribute (<c>CSIP8</c>): when the package was last modified, or <see langword="null"/> when the document stated none.</summary>
    public DateTimeOffset? LastModificationDate { get; init; }

    /// <summary>
    /// The <c>@csip:OAISPACKAGETYPE</c> attribute (<c>CSIP9</c>), which is also what an AIP states as
    /// <see cref="MetsWellKnown.ArchivalPackageType"/> per requirement <c>AIPM3</c> of
    /// <see href="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml">E-ARK AIP v2.2.0</see>. Carried as text
    /// so a document stating a value outside the vocabulary can be read and reported on;
    /// <see cref="MetsWellKnown.IsOaisPackageType"/> is the recognition.
    /// </summary>
    public required string OaisPackageType { get; init; }

    /// <summary>The <c>agent</c> elements (<c>CSIP10</c>, <c>1..n</c>).</summary>
    public IReadOnlyList<MetsAgent> Agents { get; init; } = [];


    /// <summary>A short debugger string showing the package type and when it was created.</summary>
    private string DebuggerDisplay => $"MetsHeader({OaisPackageType}, {CreateDate:O}, {Agents.Count} agents)";
}


/// <summary>
/// One <c>mdRef</c> element — the reference from a metadata section to the document that carries its content, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP22</c>–<c>CSIP30</c> (descriptive), <c>CSIP36</c>–<c>CSIP44</c> (digital provenance) and
/// <c>CSIP49</c>–<c>CSIP57</c> (rights) — which state one identical shape three times.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Referenced, never embedded.</strong> The specification's own guidance is that metadata "should not be
/// embedded directly in the METS file", and that every referenced document sits inside the package's
/// <c>metadata</c> folder. The reference itself is a URI conformant to
/// <see href="https://www.rfc-editor.org/rfc/rfc3986">IETF RFC 3986</see> or a path relative to the package root;
/// it is carried verbatim rather than resolved, because resolution is the package layer's business and the value
/// is part of what a fixity value over this document commits to.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns <see cref="Fixity"/>; disposing the section that carries it
/// disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "Clause 5.1 admits either an RFC 3986 URI or a path relative to the package root, and System.Uri cannot hold a relative reference without a base. The value is carried exactly as written — it is part of the octets a fixity value over the document commits to — and resolved by the package layer.")]
public sealed record MetsMetadataReference: IDisposable
{
    /// <summary>The <c>@LOCTYPE</c> attribute, which <c>CSIP22</c>/<c>CSIP36</c>/<c>CSIP49</c> fix to <see cref="MetsWellKnown.UrlLocatorType"/>.</summary>
    public required string LocatorType { get; init; }

    /// <summary>The <c>xlink:type</c> attribute, which <c>CSIP23</c>/<c>CSIP37</c>/<c>CSIP50</c> fix to <see cref="MetsWellKnown.SimpleLinkType"/>.</summary>
    public required string LinkType { get; init; }

    /// <summary>The <c>xlink:href</c> attribute (<c>CSIP24</c>/<c>CSIP38</c>/<c>CSIP51</c>): where the referenced document sits.</summary>
    public required string Href { get; init; }

    /// <summary>
    /// The <c>@MDTYPE</c> attribute (<c>CSIP25</c>/<c>CSIP39</c>/<c>CSIP52</c>): which metadata vocabulary the
    /// referenced document speaks. A digital-provenance reference to a preservation-metadata document states
    /// <see cref="MetsWellKnown.PremisMetadataType"/>.
    /// </summary>
    public required string MetadataType { get; init; }

    /// <summary>The <c>@OTHERMDTYPE</c> attribute, meaningful when <see cref="MetadataType"/> is <see cref="MetsWellKnown.OtherMetadataType"/>, or <see langword="null"/>.</summary>
    public string? OtherMetadataType { get; init; }

    /// <summary>
    /// The <c>@MDTYPEVERSION</c> attribute, or <see langword="null"/> when the document stated none. Requirement
    /// <c>AIPM7</c> of <see href="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml">E-ARK AIP v2.2.0</see>
    /// asks a preservation-metadata reference to state a version beginning with <c>3</c>.
    /// </summary>
    public string? MetadataTypeVersion { get; init; }

    /// <summary>The <c>@MIMETYPE</c> attribute (<c>CSIP26</c>/<c>CSIP40</c>/<c>CSIP53</c>): the referenced document's media type.</summary>
    public required string MediaType { get; init; }

    /// <summary>The <c>@SIZE</c> attribute (<c>CSIP27</c>/<c>CSIP41</c>/<c>CSIP54</c>): the referenced document's size in octets.</summary>
    public required long Size { get; init; }

    /// <summary>The <c>@CREATED</c> attribute (<c>CSIP28</c>/<c>CSIP42</c>/<c>CSIP55</c>): when the referenced document was created.</summary>
    public required DateTimeOffset Created { get; init; }

    /// <summary>
    /// The <c>@CHECKSUM</c>/<c>@CHECKSUMTYPE</c> pair (<c>CSIP29</c>/<c>CSIP30</c>, <c>CSIP43</c>/<c>CSIP44</c>,
    /// <c>CSIP56</c>/<c>CSIP57</c>). The instance owns it.
    /// </summary>
    public required EArkFixity Fixity { get; init; }


    /// <summary>Disposes <see cref="Fixity"/>.</summary>
    public void Dispose() => Fixity.Dispose();


    /// <summary>A short debugger string showing what is referenced and under which vocabulary.</summary>
    private string DebuggerDisplay => $"MetsMetadataReference({Href}, {MetadataType}, {Size} octets)";
}


/// <summary>
/// One <c>dmdSec</c> element — a descriptive-metadata section, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP17</c>–<c>CSIP21</c>.
/// </summary>
/// <remarks>
/// <para>
/// The referenced document's own vocabulary is deliberately unconstrained — the specification says implementers
/// "are free to use descriptive metadata standards of their choosing" — so this type models the wrapper and
/// nothing about what it points at.
/// </para>
/// <para>
/// Requirement <c>AIPM4</c> of <see href="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml">E-ARK AIP
/// v2.2.0</see> adds one rule over <see cref="Status"/> that no single section can satisfy alone: among an AIP's
/// sections, one should be <see cref="MetsWellKnown.CurrentStatus"/>.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns <see cref="Reference"/>; disposing the document that carries it
/// disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record MetsDescriptiveMetadataSection: IDisposable
{
    /// <summary>The <c>@ID</c> attribute (<c>CSIP18</c>), which clause 5.1 requires to be an XML <c>NCName</c>.</summary>
    public required string Id { get; init; }

    /// <summary>The <c>@CREATED</c> attribute (<c>CSIP19</c>): when the section was created.</summary>
    public required DateTimeOffset Created { get; init; }

    /// <summary>The <c>@STATUS</c> attribute (<c>CSIP20</c>), or <see langword="null"/> when the document stated none.</summary>
    public string? Status { get; init; }

    /// <summary>The <c>mdRef</c> element (<c>CSIP21</c>), or <see langword="null"/> when the document stated none. The instance owns it.</summary>
    public MetsMetadataReference? Reference { get; init; }


    /// <summary>Disposes <see cref="Reference"/>, when present.</summary>
    public void Dispose() => Reference?.Dispose();


    /// <summary>A short debugger string showing the section's identifier and what it points at.</summary>
    private string DebuggerDisplay => $"MetsDescriptiveMetadataSection({Id}, {Reference?.Href ?? "no reference"})";
}


/// <summary>
/// One <c>digiprovMD</c> or <c>rightsMD</c> element — the two administrative-metadata sections the profile
/// constrains, per <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>
/// requirements <c>CSIP32</c>–<c>CSIP35</c> and <c>CSIP45</c>–<c>CSIP48</c>.
/// </summary>
/// <remarks>
/// <para>
/// One type serves both because the profile states one shape twice, differing only in which requirement numbers
/// name it. Which of the two a section is, is the list it sits in on <see cref="MetsAdministrativeMetadata"/> —
/// the same discipline that keeps a manifest's role out of the manifest.
/// </para>
/// <para>
/// <strong>This is where evidence is anchored.</strong> <c>CSIP32</c> is the mooring point the preservation
/// metadata attaches to, and requirement <c>AIPM5</c> of
/// <see href="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml">E-ARK AIP v2.2.0</see> makes a reference of
/// this shape the only way an AIP may state digital provenance at all. Neither specification says anything about
/// signatures, time-stamps or evidence records — that convention is this library's, and it is expressed through
/// what these sections reference rather than through anything new in the vocabulary.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns <see cref="Reference"/>; disposing the section list that carries
/// it disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record MetsAdministrativeMetadataSection: IDisposable
{
    /// <summary>The <c>@ID</c> attribute (<c>CSIP33</c>/<c>CSIP46</c>), which clause 5.1 requires to be an XML <c>NCName</c>.</summary>
    public required string Id { get; init; }

    /// <summary>The <c>@STATUS</c> attribute (<c>CSIP34</c>/<c>CSIP47</c>), or <see langword="null"/> when the document stated none.</summary>
    public string? Status { get; init; }

    /// <summary>The <c>mdRef</c> element (<c>CSIP35</c>/<c>CSIP48</c>), or <see langword="null"/> when the document stated none. The instance owns it.</summary>
    public MetsMetadataReference? Reference { get; init; }


    /// <summary>Disposes <see cref="Reference"/>, when present.</summary>
    public void Dispose() => Reference?.Dispose();


    /// <summary>A short debugger string showing the section's identifier and what it points at.</summary>
    private string DebuggerDisplay => $"MetsAdministrativeMetadataSection({Id}, {Reference?.Href ?? "no reference"})";
}


/// <summary>
/// The <c>amdSec</c> element, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirement
/// <c>CSIP31</c>.
/// </summary>
/// <remarks>
/// <para>
/// The base vocabulary also admits <c>techMD</c> and <c>sourceMD</c> sub-sections, and the specification declines
/// to constrain either — "population of the other metadata sections are left to local policy" — so neither is
/// modelled: this type covers exactly the two the profile gives requirement numbers to.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every section it carries; disposing the document that carries it
/// disposes them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record MetsAdministrativeMetadata: IDisposable
{
    /// <summary>The <c>digiprovMD</c> elements (<c>CSIP32</c>, <c>0..n</c>).</summary>
    public IReadOnlyList<MetsAdministrativeMetadataSection> DigitalProvenanceSections { get; init; } = [];

    /// <summary>The <c>rightsMD</c> elements (<c>CSIP45</c>, <c>0..n</c>).</summary>
    public IReadOnlyList<MetsAdministrativeMetadataSection> RightsSections { get; init; } = [];


    /// <summary>Disposes every section this element owns.</summary>
    public void Dispose()
    {
        foreach(MetsAdministrativeMetadataSection section in DigitalProvenanceSections)
        {
            section.Dispose();
        }

        foreach(MetsAdministrativeMetadataSection section in RightsSections)
        {
            section.Dispose();
        }
    }


    /// <summary>A short debugger string showing how many sections of each kind the element carries.</summary>
    private string DebuggerDisplay => $"MetsAdministrativeMetadata({DigitalProvenanceSections.Count} provenance, {RightsSections.Count} rights)";
}


/// <summary>
/// One <c>FLocat</c> element — where a file entry's content sits, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP76</c>–<c>CSIP79</c>.
/// </summary>
/// <param name="LocatorType">The <c>@LOCTYPE</c> attribute, which <c>CSIP77</c> fixes to <see cref="MetsWellKnown.UrlLocatorType"/>.</param>
/// <param name="LinkType">The <c>xlink:type</c> attribute, which <c>CSIP78</c> fixes to <see cref="MetsWellKnown.SimpleLinkType"/>.</param>
/// <param name="Href">The <c>xlink:href</c> attribute (<c>CSIP79</c>): the file's location, carried exactly as written.</param>
[DebuggerDisplay("MetsFileLocator: {Href,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "Clause 5.1 admits either an RFC 3986 URI or a path relative to the package root, and System.Uri cannot hold a relative reference without a base. The value is carried exactly as written and resolved by the package layer.")]
public readonly record struct MetsFileLocator(string LocatorType, string LinkType, string Href);


/// <summary>
/// One <c>file</c> element — one content file of the package, its fixity and its locator, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP66</c>–<c>CSIP79</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>This is the package's fixity manifest.</strong> The per-element narrative states it without a
/// requirement number of its own — "Location and checksum values must be provided for all file entries" — and the
/// catalogue makes every one of <c>@ID</c>, <c>@MIMETYPE</c>, <c>@SIZE</c>, <c>@CREATED</c>, <c>@CHECKSUM</c>,
/// <c>@CHECKSUMTYPE</c> and one <c>FLocat</c> mandatory once a file entry exists at all.
/// </para>
/// <para>
/// A file entry is also where a signature, a time-stamp token or an evidence record sits when a package carries
/// one: to this vocabulary such a file is an opaque content file like any other, distinguished only by its media
/// type, and what it attests is said elsewhere.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns <see cref="Fixity"/>; disposing the group that carries it disposes
/// it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record MetsFile: IDisposable
{
    /// <summary>The <c>@ID</c> attribute (<c>CSIP67</c>), which clause 5.1 requires to be an XML <c>NCName</c> and which a <c>fptr/@FILEID</c> points at.</summary>
    public required string Id { get; init; }

    /// <summary>The <c>@MIMETYPE</c> attribute (<c>CSIP68</c>): the file's media type, from the IANA registry.</summary>
    public required string MediaType { get; init; }

    /// <summary>The <c>@SIZE</c> attribute (<c>CSIP69</c>): the file's size in octets.</summary>
    public required long Size { get; init; }

    /// <summary>The <c>@CREATED</c> attribute (<c>CSIP70</c>): when the file was created.</summary>
    public required DateTimeOffset Created { get; init; }

    /// <summary>The <c>@CHECKSUM</c>/<c>@CHECKSUMTYPE</c> pair (<c>CSIP71</c>, <c>CSIP72</c>). The instance owns it.</summary>
    public required EArkFixity Fixity { get; init; }

    /// <summary>The <c>FLocat</c> element (<c>CSIP76</c>): where the file's content sits.</summary>
    public required MetsFileLocator Locator { get; init; }

    /// <summary>The <c>@OWNERID</c> attribute (<c>CSIP73</c>): the file's identification before it entered the package, or <see langword="null"/>.</summary>
    public string? OwnerId { get; init; }

    /// <summary>The identifiers the <c>@ADMID</c> attribute (<c>CSIP74</c>) lists, naming administrative-metadata sections that describe this file.</summary>
    public IReadOnlyList<string> AdministrativeMetadataIds { get; init; } = [];

    /// <summary>The identifiers the <c>@DMDID</c> attribute (<c>CSIP75</c>) lists, naming descriptive-metadata sections that describe this file.</summary>
    public IReadOnlyList<string> DescriptiveMetadataIds { get; init; } = [];


    /// <summary>Disposes <see cref="Fixity"/>.</summary>
    public void Dispose() => Fixity.Dispose();


    /// <summary>A short debugger string showing the file's identifier and where it sits.</summary>
    private string DebuggerDisplay => $"MetsFile({Id}, {Locator.Href}, {Size} octets)";
}


/// <summary>
/// One <c>fileGrp</c> element — one category of the package's files, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP60</c>–<c>CSIP65</c>, <c>CSIP113</c> and <c>CSIP114</c>.
/// </summary>
/// <remarks>
/// <para>
/// The profile mandates three categories and admits more: a <c>Documentation</c> group (<c>CSIP60</c>), a
/// <c>Schemas</c> group (<c>CSIP113</c>) and one group per representation whose <c>@USE</c> begins
/// <c>Representations/</c> (<c>CSIP114</c>). The per-element narrative adds a rule with no requirement number of
/// its own: groups shall not be nested inside one another, so the structure is flat and this type carries files
/// rather than child groups.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every file it carries; disposing the section that carries it
/// disposes them.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record MetsFileGroup: IDisposable
{
    /// <summary>The <c>@ID</c> attribute (<c>CSIP65</c>), which clause 5.1 requires to be an XML <c>NCName</c> and which a <c>fptr/@FILEID</c> may point at.</summary>
    public required string Id { get; init; }

    /// <summary>
    /// The <c>@USE</c> attribute (<c>CSIP64</c>): which category the group is. <see cref="MetsWellKnown.IsFileGroupUse"/>
    /// recognises the ones the vocabulary states, including the per-representation form.
    /// </summary>
    public required string Use { get; init; }

    /// <summary>The identifiers the <c>@ADMID</c> attribute (<c>CSIP61</c>) lists, naming administrative-metadata sections that describe the group.</summary>
    public IReadOnlyList<string> AdministrativeMetadataIds { get; init; } = [];

    /// <summary>
    /// The <c>@csip:CONTENTINFORMATIONTYPE</c> attribute (<c>CSIP62</c>), or <see langword="null"/> when the
    /// document stated none. The profile makes it mandatory on a representation group.
    /// </summary>
    public string? ContentInformationType { get; init; }

    /// <summary>The <c>@csip:OTHERCONTENTINFORMATIONTYPE</c> attribute (<c>CSIP63</c>), meaningful when <see cref="ContentInformationType"/> is <see cref="MetsWellKnown.OtherContentInformationType"/>, or <see langword="null"/>.</summary>
    public string? OtherContentInformationType { get; init; }

    /// <summary>The <c>file</c> elements (<c>CSIP66</c>, <c>1..n</c>).</summary>
    public IReadOnlyList<MetsFile> Files { get; init; } = [];


    /// <summary>Disposes every file this group owns.</summary>
    public void Dispose()
    {
        foreach(MetsFile file in Files)
        {
            file.Dispose();
        }
    }


    /// <summary>A short debugger string showing the group's category and how many files it carries.</summary>
    private string DebuggerDisplay => $"MetsFileGroup({Use}, {Files.Count} files)";
}


/// <summary>
/// The <c>fileSec</c> element, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP58</c> and <c>CSIP59</c>.
/// </summary>
/// <remarks>
/// <strong>Ownership.</strong> An instance owns every group it carries; disposing the document that carries it
/// disposes them.
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record MetsFileSection: IDisposable
{
    /// <summary>The <c>@ID</c> attribute (<c>CSIP59</c>), which clause 5.1 requires to be an XML <c>NCName</c>.</summary>
    public required string Id { get; init; }

    /// <summary>The <c>fileGrp</c> elements.</summary>
    public IReadOnlyList<MetsFileGroup> FileGroups { get; init; } = [];


    /// <summary>Disposes every group this section owns.</summary>
    public void Dispose()
    {
        foreach(MetsFileGroup group in FileGroups)
        {
            group.Dispose();
        }
    }


    /// <summary>A short debugger string showing how many groups the section carries.</summary>
    private string DebuggerDisplay => $"MetsFileSection({Id}, {FileGroups.Count} file groups)";
}


/// <summary>
/// One <c>fptr</c> element — a structural division's pointer at a file or a file group, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP96</c>/<c>CSIP116</c>, <c>CSIP100</c>/<c>CSIP118</c> and <c>CSIP104</c>/<c>CSIP119</c>.
/// </summary>
/// <param name="FileId">
/// The <c>@FILEID</c> attribute: the <c>@ID</c> of the file or file group the division points at. The three
/// requirement pairs above make the attribute mandatory wherever the element appears.
/// </param>
[DebuggerDisplay("MetsFilePointer: {FileId,nq}")]
public readonly record struct MetsFilePointer(string FileId);


/// <summary>
/// One <c>mptr</c> element — a structural division's pointer at another METS document, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP108</c>–<c>CSIP112</c>.
/// </summary>
/// <remarks>
/// <para>
/// This is the package-to-representation traversal: a package-level document points at each representation's own
/// <c>METS.xml</c> rather than inlining it, and <c>CSIP108</c> makes <c>xlink:title</c> mandatory beside the
/// location.
/// </para>
/// <para>
/// <strong>It is also how packages point at each other.</strong> Clause 5.1 states, in prose and without a
/// requirement number, that "all references to other packages MUST USE the <c>mets/@OBJID</c> value of the target
/// package" — so in a parent-child chain the value here is the other package's identifier rather than a location.
/// That is what makes such a chain independent of where the packages are stored, and it is why the value is
/// carried exactly as written instead of being resolved.
/// </para>
/// </remarks>
/// <param name="Href">The <c>xlink:href</c> attribute (<c>CSIP110</c>): a location, or another package's identifier.</param>
/// <param name="LocatorType">The <c>@LOCTYPE</c> attribute, which <c>CSIP112</c> fixes to <see cref="MetsWellKnown.UrlLocatorType"/>.</param>
/// <param name="LinkType">The <c>xlink:type</c> attribute, which <c>CSIP111</c> fixes to <see cref="MetsWellKnown.SimpleLinkType"/>.</param>
/// <param name="Title">The <c>xlink:title</c> attribute (<c>CSIP108</c>), or <see langword="null"/> when the document stated none.</param>
[DebuggerDisplay("MetsPointer: {Href,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "The attribute carries either a relative location or another package's OBJID, which is not a URI at all; System.Uri can hold neither faithfully, and the value is part of what a fixity value over the document commits to.")]
public readonly record struct MetsPointer(string Href, string LocatorType, string LinkType, string? Title);


/// <summary>
/// One <c>div</c> element of a structural map, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP84</c>–<c>CSIP107</c>.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The divisions mirror the folders.</strong> Under the single root division (<c>CSIP84</c>) the profile
/// names four by label — <c>Metadata</c> (<c>CSIP88</c>–<c>CSIP92</c>), <c>Documentation</c>
/// (<c>CSIP93</c>–<c>CSIP96</c>, <c>CSIP116</c>), <c>Schemas</c> (<c>CSIP97</c>–<c>CSIP100</c>, <c>CSIP118</c>)
/// and <c>Representations</c> (<c>CSIP101</c>–<c>CSIP104</c>, <c>CSIP119</c>) — and one per representation
/// (<c>CSIP105</c>–<c>CSIP112</c>), whose label is <c>Representations/</c> followed by the representation's folder
/// name. The per-element narrative generalises it without a requirement number: a division's <c>@LABEL</c> is the
/// folder's name.
/// </para>
/// <para>
/// One type covers all of them, because the profile states one element with one attribute set and varies only
/// which label is expected where. Which division a given instance is, is its <see cref="Label"/>.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record MetsDivision
{
    /// <summary>The <c>@ID</c> attribute (<c>CSIP85</c>, <c>CSIP89</c>, <c>CSIP94</c>, <c>CSIP98</c>, <c>CSIP102</c>, <c>CSIP106</c>), which clause 5.1 requires to be an XML <c>NCName</c>.</summary>
    public required string Id { get; init; }

    /// <summary>
    /// The <c>@LABEL</c> attribute (<c>CSIP90</c>, <c>CSIP95</c>, <c>CSIP99</c>, <c>CSIP103</c>, <c>CSIP107</c>),
    /// or <see langword="null"/> when the document stated none — which the root division may legitimately do,
    /// since the requirement that once bound its label to the package identifier is retired.
    /// </summary>
    public string? Label { get; init; }

    /// <summary>The identifiers the <c>@ADMID</c> attribute (<c>CSIP91</c>) lists, naming administrative-metadata sections the division points at.</summary>
    public IReadOnlyList<string> AdministrativeMetadataIds { get; init; } = [];

    /// <summary>The identifiers the <c>@DMDID</c> attribute (<c>CSIP92</c>) lists, naming descriptive-metadata sections the division points at.</summary>
    public IReadOnlyList<string> DescriptiveMetadataIds { get; init; } = [];

    /// <summary>The <c>fptr</c> elements the division carries.</summary>
    public IReadOnlyList<MetsFilePointer> FilePointers { get; init; } = [];

    /// <summary>The <c>mptr</c> elements the division carries (<c>CSIP109</c>).</summary>
    public IReadOnlyList<MetsPointer> MetsPointers { get; init; } = [];

    /// <summary>The child <c>div</c> elements.</summary>
    public IReadOnlyList<MetsDivision> Divisions { get; init; } = [];


    /// <summary>A short debugger string showing the division's label and what it carries.</summary>
    private string DebuggerDisplay => $"MetsDivision({Label ?? "unlabelled"}, {Divisions.Count} divisions, {FilePointers.Count} file pointers, {MetsPointers.Count} package pointers)";
}


/// <summary>
/// One <c>structMap</c> element, per
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see> requirements
/// <c>CSIP80</c>–<c>CSIP85</c>.
/// </summary>
/// <remarks>
/// <para>
/// A document carries one or more structural maps and exactly one of them is the profile's: the one whose
/// <c>@LABEL</c> is <see cref="MetsWellKnown.CsipStructuralMapLabel"/> (<c>CSIP82</c>), which the specification's
/// own note says "should be treated as a unique id" precisely so that an implementer may add further maps for
/// internal purposes without colliding with it.
/// </para>
/// <para>
/// <strong>This is where an archival package's parent-child chain is expressed.</strong> Requirement
/// <c>AIP13</c> of <see href="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml">E-ARK AIP v2.2.0</see>
/// binds a child to its superordinate package through the preservation metadata, and the same specification adds,
/// in prose and without a requirement number, that "the parent AIP which is referenced by child AIPs must have a
/// structural map listing all child AIPs" — a list of <see cref="MetsPointer"/> values, each carrying a child's
/// <c>mets/@OBJID</c>. The chain grows by appending: existing children are untouched when a new parent version is
/// written, so only the newest parent lists them all. Nothing in it is cryptographically bound — a chain that
/// needs to be is one whose documents an evidence record or an archive time-stamp covers.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed record MetsStructuralMap
{
    /// <summary>The <c>@ID</c> attribute (<c>CSIP83</c>), which clause 5.1 requires to be an XML <c>NCName</c>.</summary>
    public required string Id { get; init; }

    /// <summary>The <c>@TYPE</c> attribute, which <c>CSIP81</c> fixes to <see cref="MetsWellKnown.PhysicalStructuralMapType"/>.</summary>
    public required string Type { get; init; }

    /// <summary>The <c>@LABEL</c> attribute, which <c>CSIP82</c> fixes to <see cref="MetsWellKnown.CsipStructuralMapLabel"/> for the map the profile mandates.</summary>
    public required string Label { get; init; }

    /// <summary>The single root <c>div</c> element (<c>CSIP84</c>).</summary>
    public required MetsDivision RootDivision { get; init; }


    /// <summary>A short debugger string showing which map this is.</summary>
    private string DebuggerDisplay => $"MetsStructuralMap({Label}, {Type}, root {RootDivision.Id})";
}


/// <summary>
/// One METS document — the package-level or representation-level <c>METS.xml</c> of an Information Package, as the
/// METS profile of <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>
/// constrains it, narrowed further by
/// <see href="https://earkdip.dilcis.eu/profile/E-ARK-AIP-v2-2-0.xml">E-ARK AIP v2.2.0</see> when the package is
/// an archival one.
/// </summary>
/// <remarks>
/// <para>
/// <strong>The profile's subset, not all of METS.</strong> The base vocabulary is far larger than what a
/// conformant Information Package uses, and the profile itself declines to constrain several of its sections —
/// <c>structLink</c> and <c>behaviorSec</c> are marked "not defined or used", <c>techMD</c> and <c>sourceMD</c>
/// are left to local policy, and the content of every referenced metadata document is deliberately unconstrained.
/// This model covers what the profile's <c>CSIP1</c>–<c>CSIP119</c> catalogue and the archival profile's
/// <c>AIPM1</c>–<c>AIPM7</c> catalogue name, and nothing else. A document carrying more than that reads into this
/// model without the surplus; a caller needing the surplus needs the octets.
/// </para>
/// <para>
/// <strong>One model, two levels.</strong> The package-level and the representation-level document use the same
/// profile — the same catalogue applies to both — and differ only in what populates them: a package-level
/// <c>structMap</c> points at each representation through <see cref="MetsPointer"/>, and a representation-level
/// one does not. The level travels beside an instance rather than inside it, the same discipline that keeps a
/// manifest's role out of the manifest.
/// </para>
/// <para>
/// <strong>Serialisation-agnostic.</strong> This is a plain model: it names no XML type and this project
/// references no XML package. Reading and writing reach the library as <see cref="ParseMetsDelegate"/> and
/// <see cref="EncodeMetsDelegate"/>, the same pattern <see cref="ParseAsicManifestDelegate"/> established.
/// </para>
/// <para>
/// <strong>Ownership.</strong> An instance owns every section it carries — and through them every fixity carrier;
/// the caller disposes it.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
    Justification = "CSIP6 and AIPM2 fix an exact attribute value that a conformance test compares character by character; System.Uri normalises case, escaping and default ports, which would make a document that fails the test compare equal to one that passes.")]
public sealed record MetsDocument: IDisposable
{
    /// <summary>
    /// The <c>@OBJID</c> attribute (<c>CSIP1</c>): the package's identifier, which is also the name its root
    /// folder should carry and the value every reference from another package uses. Requirement <c>AIPM1</c> of
    /// the archival profile adds that it must not change over the package's life-cycle — an obligation across
    /// versions that no single document can evidence.
    /// </summary>
    public required string ObjectIdentifier { get; init; }

    /// <summary>The <c>@TYPE</c> attribute (<c>CSIP2</c>): the content category, from a 33-term descriptive vocabulary this library does not close.</summary>
    public required string ContentCategory { get; init; }

    /// <summary>The <c>@PROFILE</c> attribute (<c>CSIP6</c>, and <c>AIPM2</c> for an archival package): the profile the document claims conformance to.</summary>
    public required string Profile { get; init; }

    /// <summary>The <c>metsHdr</c> element (<c>CSIP117</c>).</summary>
    public required MetsHeader Header { get; init; }

    /// <summary>The <c>@csip:OTHERTYPE</c> attribute (<c>CSIP3</c>), meaningful when <see cref="ContentCategory"/> is <c>OTHER</c>, or <see langword="null"/>.</summary>
    public string? OtherContentCategory { get; init; }

    /// <summary>
    /// The <c>@csip:CONTENTINFORMATIONTYPE</c> attribute (<c>CSIP4</c>), or <see langword="null"/> when the
    /// document stated none. The profile's cardinality is <c>0..1</c>, but its prose makes the attribute
    /// mandatory on a representation-level document — a context-dependent obligation the flat catalogue does not
    /// show.
    /// </summary>
    public string? ContentInformationType { get; init; }

    /// <summary>The <c>@csip:OTHERCONTENTINFORMATIONTYPE</c> attribute (<c>CSIP5</c>), meaningful when <see cref="ContentInformationType"/> is <see cref="MetsWellKnown.OtherContentInformationType"/>, or <see langword="null"/>.</summary>
    public string? OtherContentInformationType { get; init; }

    /// <summary>The <c>dmdSec</c> elements (<c>CSIP17</c>, <c>0..n</c>).</summary>
    public IReadOnlyList<MetsDescriptiveMetadataSection> DescriptiveMetadataSections { get; init; } = [];

    /// <summary>The <c>amdSec</c> element (<c>CSIP31</c>), or <see langword="null"/> when the document stated none.</summary>
    public MetsAdministrativeMetadata? AdministrativeMetadata { get; init; }

    /// <summary>The <c>fileSec</c> element (<c>CSIP58</c>), or <see langword="null"/> when the document stated none.</summary>
    public MetsFileSection? FileSection { get; init; }

    /// <summary>The <c>structMap</c> elements (<c>CSIP80</c>, <c>1..n</c>).</summary>
    public IReadOnlyList<MetsStructuralMap> StructuralMaps { get; init; } = [];


    /// <summary>Disposes every section this document owns.</summary>
    public void Dispose()
    {
        foreach(MetsDescriptiveMetadataSection section in DescriptiveMetadataSections)
        {
            section.Dispose();
        }

        AdministrativeMetadata?.Dispose();
        FileSection?.Dispose();
    }


    /// <summary>A short debugger string showing which package the document describes.</summary>
    private string DebuggerDisplay => $"MetsDocument({ObjectIdentifier}, {Header.OaisPackageType}, {StructuralMaps.Count} structural maps)";
}
