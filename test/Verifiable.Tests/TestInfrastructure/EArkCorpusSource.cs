using System;
using System.Collections.Generic;
using System.IO;
using System.Xml;
using System.Xml.Linq;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Reads the optional local Information Package reference corpus — the requirement-keyed test cases, their rules,
/// and the packages each rule names — into values the sweep drives through the shipped validation profiles.
/// </summary>
/// <remarks>
/// <para>
/// <strong>Discovery is by layout and by content, never by a folder name somebody cloned.</strong> A requirement
/// directory is any folder that directly holds a <c>testCase.xml</c> document; which specification family a case
/// belongs to is read out of the requirement identifier the document itself states, not out of the folder above
/// it. Nothing here knows what the corpus is called or how deep it sits.
/// </para>
/// <para>
/// <strong>The documents are attacker-shaped input like any other.</strong> They come from outside this
/// repository, so the reader prohibits document type definitions outright and resolves no external resource —
/// the same posture the worked manifest bindings take, for the same reason.
/// </para>
/// <para>
/// The corpus lives under <c>tempdocs/</c>, which is not a repository asset, so every discovery method answers
/// an empty result when it is absent and the tests that use it report inconclusive — the shape
/// <see cref="EArkSchemaOracle"/> established and <see cref="EArkPackageSource"/> repeats.
/// </para>
/// <para>
/// Case metadata is documented at
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0</see> only
/// indirectly: the corpus is the specification family's own conformance material, and each case carries the
/// requirement identifier, the requirement's own text, the rules derived from it, the severity a violation is
/// reported at, and the packages that exercise it.
/// </para>
/// </remarks>
internal static class EArkCorpusSource
{
    /// <summary>What a test reports when the optional local reference corpus is absent.</summary>
    internal static string MissingCorpusMessage { get; } =
        "No requirement-keyed test case was found under tempdocs/earchiving-reference; the reference corpus is optional local reference material, not a repository asset.";

    /// <summary>The file name a requirement directory states its case in.</summary>
    private static string CaseFileName { get; } = "testCase.xml";

    /// <summary>The separator a stated package path uses, whichever file system the corpus was cloned onto.</summary>
    private static char PathSeparator { get; } = '/';


    /// <summary>
    /// Finds every requirement-keyed test case the local reference material carries.
    /// </summary>
    /// <returns>
    /// The cases, ordered ordinally by their requirement directory so that a run reads them in the same order
    /// every time. Empty when the reference material is absent.
    /// </returns>
    internal static IReadOnlyList<EArkCorpusTestCase> FindTestCases()
    {
        string? referenceMaterial = TryFindReferenceMaterial();
        if(referenceMaterial is null)
        {
            return [];
        }

        var caseFiles = new List<string>();
        foreach(string caseFile in Directory.EnumerateFiles(referenceMaterial, CaseFileName, SearchOption.AllDirectories))
        {
            if(string.Equals(Path.GetFileName(caseFile), CaseFileName, StringComparison.Ordinal))
            {
                caseFiles.Add(caseFile);
            }
        }

        caseFiles.Sort(static (left, right) => string.CompareOrdinal(left, right));

        var cases = new List<EArkCorpusTestCase>(caseFiles.Count);
        for(int i = 0; i < caseFiles.Count; ++i)
        {
            EArkCorpusTestCase? read = ReadTestCase(caseFiles[i]);
            if(read is not null)
            {
                cases.Add(read);
            }
        }

        return cases;
    }


    /// <summary>
    /// Reads one requirement directory's test case.
    /// </summary>
    /// <param name="caseFile">The case document's path.</param>
    /// <returns>The case, or <see langword="null"/> when the document states no requirement identifier.</returns>
    private static EArkCorpusTestCase? ReadTestCase(string caseFile)
    {
        string directory = Path.GetDirectoryName(caseFile) ?? throw new InvalidOperationException("A case document always sits in a directory.");

        XDocument document;
        using(var reader = XmlReader.Create(caseFile, HostileInputSettings()))
        {
            document = XDocument.Load(reader);
        }

        XElement? root = document.Root;
        XElement? identity = root?.Element("id");
        string? requirementId = (string?)identity?.Attribute("requirementId");
        if(root is null || identity is null || string.IsNullOrEmpty(requirementId))
        {
            return null;
        }

        XElement? requirementText = root.Element("requirementText");

        var rules = new List<EArkCorpusRule>();
        XElement? ruleContainer = root.Element("rules");
        if(ruleContainer is not null)
        {
            foreach(XElement rule in ruleContainer.Elements("rule"))
            {
                rules.Add(ReadRule(rule, directory));
            }
        }

        return new EArkCorpusTestCase
        {
            RequirementId = requirementId,
            Family = FamilyOf(requirementId),
            StatedSpecification = (string?)identity.Attribute("specification") ?? string.Empty,
            StatedVersion = (string?)identity.Attribute("version") ?? string.Empty,
            IsTestable = string.Equals((string?)root.Attribute("testable"), "TRUE", StringComparison.Ordinal),
            StatedLevel = TextOf(requirementText?.Element("level")),
            StatedLocation = TextOf(requirementText?.Element("location")),
            StatedCardinality = TextOf(requirementText?.Element("cardinality")),
            StatedName = TextOf(requirementText?.Element("name")),
            Directory = directory,
            Rules = rules
        };
    }


    /// <summary>
    /// Reads one rule of a test case, with the packages it names.
    /// </summary>
    /// <param name="rule">The rule element.</param>
    /// <param name="directory">The requirement directory every stated package path is relative to.</param>
    /// <returns>The rule.</returns>
    private static EArkCorpusRule ReadRule(XElement rule, string directory)
    {
        XElement? error = rule.Element("error");
        var packages = new List<EArkCorpusPackageReference>();
        XElement? packageContainer = rule.Element("corpusPackages");
        if(packageContainer is not null)
        {
            foreach(XElement package in packageContainer.Elements("package"))
            {
                packages.Add(ReadPackage(package, directory));
            }
        }

        return new EArkCorpusRule
        {
            RuleId = (string?)rule.Attribute("id") ?? string.Empty,
            ErrorLevel = (string?)error?.Attribute("level") ?? string.Empty,
            Description = TextOf(rule.Element("description")),
            Packages = packages
        };
    }


    /// <summary>
    /// Reads one package reference of a rule.
    /// </summary>
    /// <param name="package">The package element.</param>
    /// <param name="directory">The requirement directory the stated path is relative to.</param>
    /// <returns>The reference, carrying the resolved root when the package really is on disk.</returns>
    private static EArkCorpusPackageReference ReadPackage(XElement package, string directory)
    {
        string statedPath = TextOf(package.Element("path"));
        string? root = null;
        if(statedPath.Length > 0)
        {
            string candidate = Path.Combine(directory, statedPath.Replace(PathSeparator, Path.DirectorySeparatorChar));
            if(Directory.Exists(candidate))
            {
                root = candidate;
            }
        }

        return new EArkCorpusPackageReference
        {
            Name = (string?)package.Attribute("name") ?? string.Empty,
            IsValid = string.Equals((string?)package.Attribute("isValid"), "TRUE", StringComparison.Ordinal),
            IsImplemented = string.Equals((string?)package.Attribute("isImplemented"), "TRUE", StringComparison.Ordinal),
            StatedPath = statedPath,
            PackageRoot = root
        };
    }


    /// <summary>
    /// Names the specification family a requirement identifier belongs to, read from the identifier itself.
    /// </summary>
    /// <param name="requirementId">The requirement identifier the case states.</param>
    /// <returns>The family.</returns>
    /// <remarks>
    /// The corpus spells the specification attribute inconsistently — the same family appears as <c>CSIP</c> and
    /// as <c>E-ARK CSIP</c> — so the identifier's own prefix decides, which is the one spelling every case agrees
    /// on. The structural rows of the Common Specification carry their own prefix and are told apart here so a
    /// caller never has to parse the identifier a second time.
    /// </remarks>
    private static EArkCorpusFamily FamilyOf(string requirementId) => requirementId switch
    {
        _ when requirementId.StartsWith("CSIPSTR", StringComparison.Ordinal) => EArkCorpusFamily.CommonSpecificationStructure,
        _ when requirementId.StartsWith("CSIP", StringComparison.Ordinal) => EArkCorpusFamily.CommonSpecification,
        _ when requirementId.StartsWith("SIP", StringComparison.Ordinal) => EArkCorpusFamily.SubmissionPackage,
        _ when requirementId.StartsWith("DIP", StringComparison.Ordinal) => EArkCorpusFamily.DisseminationPackage,
        _ => EArkCorpusFamily.Unrecognised
    };


    /// <summary>Reads an element's text, trimmed, answering the empty string when the element is absent.</summary>
    /// <param name="element">The element to read.</param>
    /// <returns>The text.</returns>
    private static string TextOf(XElement? element) =>
        element is null ? string.Empty : element.Value.Trim();


    /// <summary>
    /// The reader settings every case document is read under: no document type definition, no external resource.
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
/// The specification family a corpus requirement identifier belongs to.
/// </summary>
/// <remarks>
/// <see cref="Unrecognised"/> occupies zero so a default-initialised family never reads as a family the sweep
/// knows how to drive.
/// </remarks>
internal enum EArkCorpusFamily
{
    /// <summary>No family recognised from the identifier. The value of an unset field, by design.</summary>
    Unrecognised = 0,

    /// <summary>
    /// The METS profile catalogue of
    /// <see href="https://earkcsip.dilcis.eu/profile/E-ARK-CSIP.xml">E-ARK CSIP v2.2.0</see>, <c>CSIPn</c>.
    /// </summary>
    CommonSpecification = 1,

    /// <summary>
    /// The folder-structure catalogue of
    /// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0
    /// clause 4</see>, <c>CSIPSTRn</c>.
    /// </summary>
    CommonSpecificationStructure = 2,

    /// <summary>
    /// The submission-package deltas of <see href="https://earksip.dilcis.eu/">E-ARK SIP v2.2.0</see>,
    /// <c>SIPn</c>.
    /// </summary>
    SubmissionPackage = 3,

    /// <summary>
    /// The dissemination-package deltas of <see href="https://earkdip.dilcis.eu/">E-ARK DIP v2.2.0</see>,
    /// <c>DIPn</c>.
    /// </summary>
    DisseminationPackage = 4
}


/// <summary>
/// One requirement-keyed case of the reference corpus: the requirement it is about, the text the corpus states
/// for it, and the rules derived from it.
/// </summary>
internal sealed record EArkCorpusTestCase
{
    /// <summary>Gets the requirement identifier the case is keyed by, verbatim.</summary>
    public required string RequirementId { get; init; }

    /// <summary>Gets the specification family the identifier names.</summary>
    public required EArkCorpusFamily Family { get; init; }

    /// <summary>Gets the specification name the case states, verbatim and inconsistently spelled.</summary>
    public required string StatedSpecification { get; init; }

    /// <summary>Gets the specification version the case states, verbatim.</summary>
    public required string StatedVersion { get; init; }

    /// <summary>Gets whether the case declares itself testable at all.</summary>
    public required bool IsTestable { get; init; }

    /// <summary>Gets the requirement level the case states, or the empty string when its text is unstructured.</summary>
    public required string StatedLevel { get; init; }

    /// <summary>Gets the element location the case states, or the empty string when its text is unstructured.</summary>
    public required string StatedLocation { get; init; }

    /// <summary>Gets the cardinality the case states, or the empty string when its text is unstructured.</summary>
    public required string StatedCardinality { get; init; }

    /// <summary>Gets the requirement name the case states, or the empty string when its text is unstructured.</summary>
    public required string StatedName { get; init; }

    /// <summary>Gets the requirement directory the case was read from.</summary>
    public required string Directory { get; init; }

    /// <summary>Gets the rules the case derives from its requirement, in the order it states them.</summary>
    public required IReadOnlyList<EArkCorpusRule> Rules { get; init; }
}


/// <summary>
/// One rule a corpus case derives from its requirement, with the severity a violation is reported at and the
/// packages that exercise it.
/// </summary>
internal sealed record EArkCorpusRule
{
    /// <summary>Gets the rule's own identifier within its case.</summary>
    public required string RuleId { get; init; }

    /// <summary>
    /// Gets the severity a violation of this rule is reported at — <c>ERROR</c>, <c>WARNING</c> or <c>INFO</c>.
    /// </summary>
    public required string ErrorLevel { get; init; }

    /// <summary>Gets the rule's own description, verbatim.</summary>
    public required string Description { get; init; }

    /// <summary>Gets the packages the rule names, in the order it states them.</summary>
    public required IReadOnlyList<EArkCorpusPackageReference> Packages { get; init; }
}


/// <summary>
/// One package a corpus rule names, and where it is on disk when it was really built.
/// </summary>
internal sealed record EArkCorpusPackageReference
{
    /// <summary>Gets the package's own name in the corpus.</summary>
    public required string Name { get; init; }

    /// <summary>Gets whether the corpus declares the package conformant to the rule that names it.</summary>
    public required bool IsValid { get; init; }

    /// <summary>Gets whether the corpus declares the package actually built rather than merely planned.</summary>
    public required bool IsImplemented { get; init; }

    /// <summary>Gets the path the rule states for the package, relative to the requirement directory.</summary>
    public required string StatedPath { get; init; }

    /// <summary>Gets the package's root folder when it is really on disk, and <see langword="null"/> otherwise.</summary>
    public string? PackageRoot { get; init; }
}
