using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using System.Xml.Linq;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Reads the published METS profile catalogues of the Common Specification for Information Packages out of the
/// optional local reference material, so that a delta between two editions is read off the editions themselves
/// rather than off anybody's prose.
/// </summary>
/// <remarks>
/// <para>
/// The catalogue is the machine-readable half of
/// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP</see>: one
/// <c>requirement</c> element per requirement identifier, carrying the requirement level, the heading, the
/// element location and the cardinality. Every published edition ships as its own document, which is what makes
/// an edition-to-edition comparison possible without a single transcription step.
/// </para>
/// <para>
/// <strong>Discovery is by content.</strong> A document is a catalogue of this family when its root is a METS
/// profile and its requirement identifiers include the Common Specification's own numbering and none of the
/// sibling specifications' — the submission, archival and dissemination profiles state their own prefixes and
/// are told apart by that alone. Nothing here names a directory, a file or a clone.
/// </para>
/// <para>
/// The material lives under <c>tempdocs/</c>, which is not a repository asset, so discovery answers an empty
/// result when it is absent and the tests that use it report inconclusive.
/// </para>
/// </remarks>
internal static class EArkProfileCatalogueSource
{
    /// <summary>What a test reports when the optional local catalogues are absent.</summary>
    internal static string MissingCataloguesMessage { get; } =
        "No published METS profile catalogue of the Common Specification was found under tempdocs/earchiving-reference; the catalogues are optional local reference material, not a repository asset.";

    /// <summary>The namespace a METS profile document declares.</summary>
    private static XNamespace ProfileNamespace { get; } = "http://www.loc.gov/METS_Profile/v2";

    /// <summary>The namespace the profile's prose particles are written in.</summary>
    private static XNamespace ProseNamespace { get; } = "http://www.w3.org/1999/xhtml";


    /// <summary>
    /// Finds every published catalogue of the Common Specification family the reference material carries.
    /// </summary>
    /// <returns>
    /// The catalogues keyed by the version each document states of itself, ordered ordinally by that version.
    /// Empty when the reference material is absent.
    /// </returns>
    internal static IReadOnlyList<EArkProfileCatalogue> FindCatalogues()
    {
        string? referenceMaterial = TryFindReferenceMaterial();
        if(referenceMaterial is null)
        {
            return [];
        }

        var catalogues = new List<EArkProfileCatalogue>();
        foreach(string candidate in Directory.EnumerateFiles(referenceMaterial, "*.xml", SearchOption.AllDirectories))
        {
            EArkProfileCatalogue? read = TryReadCatalogue(candidate);
            if(read is not null)
            {
                catalogues.Add(read);
            }
        }

        catalogues.Sort(static (left, right) => string.CompareOrdinal(left.Version, right.Version));

        return catalogues;
    }


    /// <summary>
    /// Finds the one published catalogue that states the given version of itself.
    /// </summary>
    /// <param name="version">The version, as the document spells it without its leading letter.</param>
    /// <returns>The catalogue, or <see langword="null"/> when the material carries no such edition.</returns>
    internal static EArkProfileCatalogue? FindCatalogue(string version)
    {
        IReadOnlyList<EArkProfileCatalogue> catalogues = FindCatalogues();
        for(int i = 0; i < catalogues.Count; ++i)
        {
            if(string.Equals(catalogues[i].Version, version, StringComparison.Ordinal))
            {
                return catalogues[i];
            }
        }

        return null;
    }


    /// <summary>
    /// Reads one document as a catalogue of this family, answering nothing when it is not one.
    /// </summary>
    /// <param name="path">The document's path.</param>
    /// <returns>The catalogue, or <see langword="null"/>.</returns>
    /// <remarks>
    /// A document that is not well-formed XML at all is simply not a catalogue: the reference material holds
    /// deliberately broken documents for other purposes, and a discovery that threw on one of them would make
    /// the whole leg depend on what else somebody stored nearby.
    /// </remarks>
    private static EArkProfileCatalogue? TryReadCatalogue(string path)
    {
        XDocument document;
        try
        {
            using var reader = XmlReader.Create(path, HostileInputSettings());
            document = XDocument.Load(reader);
        }
        catch(XmlException)
        {
            return null;
        }

        XElement? root = document.Root;
        if(root is null || root.Name != ProfileNamespace + "METS_Profile")
        {
            return null;
        }

        var rows = new List<EArkProfileRequirementRow>();
        bool namesThisFamily = false;
        foreach(XElement requirement in root.Descendants(ProfileNamespace + "requirement"))
        {
            string? id = (string?)requirement.Attribute("ID");
            if(string.IsNullOrEmpty(id))
            {
                continue;
            }

            if(NamesAnotherFamily(id))
            {
                return null;
            }

            if(IsCommonSpecificationRow(id))
            {
                namesThisFamily = true;
            }

            rows.Add(ReadRow(requirement, id));
        }

        if(!namesThisFamily)
        {
            return null;
        }

        string version = ((string?)root.Attribute("ID") ?? string.Empty).TrimStart('V', 'v');

        return new EArkProfileCatalogue { Version = version, Path = path, Rows = rows };
    }


    /// <summary>Reads one requirement row out of a catalogue.</summary>
    /// <param name="requirement">The requirement element.</param>
    /// <param name="id">The identifier the element states.</param>
    /// <returns>The row.</returns>
    private static EArkProfileRequirementRow ReadRow(XElement requirement, string id)
    {
        string head = string.Empty;
        XElement? heading = FirstOrNull(requirement.Descendants(ProfileNamespace + "head"));
        if(heading is not null)
        {
            head = heading.Value.Trim();
        }

        string location = string.Empty;
        string cardinality = string.Empty;
        foreach(XElement term in requirement.Descendants(ProseNamespace + "dt"))
        {
            if(term.NextNode is not XElement definition)
            {
                continue;
            }

            string label = term.Value.Trim();
            string value = definition.Value.Trim();
            if(label.EndsWith("XPath", StringComparison.Ordinal))
            {
                location = value;
            }
            else if(label.StartsWith("Cardinality", StringComparison.Ordinal))
            {
                cardinality = value;
            }
        }

        return new EArkProfileRequirementRow
        {
            RequirementId = id,
            Level = (string?)requirement.Attribute("REQLEVEL") ?? string.Empty,
            Head = head,
            Location = location,
            Cardinality = cardinality
        };

        //Written out rather than taken from a query library so that this source depends on nothing but the base
        //class library, which is what lets it move beside the corpus reader if a later wave promotes either.
        static XElement? FirstOrNull(IEnumerable<XElement> elements)
        {
            foreach(XElement element in elements)
            {
                return element;
            }

            return null;
        }
    }


    /// <summary>States whether an identifier is a Common Specification requirement number.</summary>
    /// <param name="id">The identifier.</param>
    /// <returns><see langword="true"/> when it is.</returns>
    private static bool IsCommonSpecificationRow(string id) =>
        id.StartsWith("CSIP", StringComparison.Ordinal) && HasTrailingNumber(id, "CSIP".Length);


    /// <summary>States whether an identifier belongs to one of the sibling package specifications.</summary>
    /// <param name="id">The identifier.</param>
    /// <returns><see langword="true"/> when it does.</returns>
    private static bool NamesAnotherFamily(string id) =>
        (id.StartsWith("SIP", StringComparison.Ordinal) && HasTrailingNumber(id, "SIP".Length))
        || (id.StartsWith("DIP", StringComparison.Ordinal) && HasTrailingNumber(id, "DIP".Length))
        || (id.StartsWith("AIPM", StringComparison.Ordinal) && HasTrailingNumber(id, "AIPM".Length))
        || (id.StartsWith("AIP", StringComparison.Ordinal) && HasTrailingNumber(id, "AIP".Length));


    /// <summary>States whether an identifier ends in a number after a prefix.</summary>
    /// <param name="id">The identifier.</param>
    /// <param name="prefixLength">How many characters the prefix takes.</param>
    /// <returns><see langword="true"/> when the rest is one or more digits.</returns>
    private static bool HasTrailingNumber(string id, int prefixLength)
    {
        if(id.Length <= prefixLength)
        {
            return false;
        }

        for(int i = prefixLength; i < id.Length; ++i)
        {
            if(!char.IsAsciiDigit(id[i]))
            {
                return false;
            }
        }

        return true;
    }


    /// <summary>
    /// The reader settings every catalogue is read under: no document type definition, no external resource.
    /// </summary>
    /// <returns>The settings.</returns>
    private static XmlReaderSettings HostileInputSettings() => new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        CloseInput = true
    };


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
}


/// <summary>
/// One published edition of the Common Specification's METS profile catalogue.
/// </summary>
internal sealed record EArkProfileCatalogue
{
    /// <summary>Gets the version the document states of itself, without its leading letter.</summary>
    public required string Version { get; init; }

    /// <summary>Gets the document's path, for a failure message that names where a reading came from.</summary>
    public required string Path { get; init; }

    /// <summary>Gets the requirement rows the catalogue states, in the order it states them.</summary>
    public required IReadOnlyList<EArkProfileRequirementRow> Rows { get; init; }


    /// <summary>
    /// Finds one requirement row by its identifier.
    /// </summary>
    /// <param name="requirementId">The identifier to look for.</param>
    /// <returns>The row, or <see langword="null"/> when this edition does not state it.</returns>
    public EArkProfileRequirementRow? Find(string requirementId)
    {
        for(int i = 0; i < Rows.Count; ++i)
        {
            if(string.Equals(Rows[i].RequirementId, requirementId, StringComparison.Ordinal))
            {
                return Rows[i];
            }
        }

        return null;
    }
}


/// <summary>
/// One requirement row of a published catalogue: what it is called, how hard it binds, and where it lives.
/// </summary>
internal sealed record EArkProfileRequirementRow
{
    /// <summary>Gets the requirement identifier, verbatim.</summary>
    public required string RequirementId { get; init; }

    /// <summary>Gets the requirement level the catalogue states — <c>MUST</c>, <c>SHOULD</c> or <c>MAY</c>.</summary>
    public required string Level { get; init; }

    /// <summary>Gets the requirement's heading, verbatim.</summary>
    public required string Head { get; init; }

    /// <summary>Gets the element location the catalogue states, or the empty string when it states none.</summary>
    public required string Location { get; init; }

    /// <summary>Gets the cardinality the catalogue states, or the empty string when it states none.</summary>
    public required string Cardinality { get; init; }
}
