using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Tests.Foundation;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for the eArchiving <see cref="ClaimId"/> allocation: <see cref="EArkClaimIds"/>,
/// <see cref="PremisClaimIds"/> and <see cref="PreservationClaimIds"/>. The properties tested here are the ones
/// a consuming system relies on when it keys a requirements-to-code graph on the integer code — the codes are
/// unique, each sits in the band its source specification reserves, each describes itself with that
/// specification's own identifier, and a numbered requirement's code is its band start plus its own number.
/// </summary>
[TestClass]
internal sealed class EArkClaimIdAllocationTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }


    /// <summary>
    /// Every identifier the E-ARK CSIP catalogues state is allocated: 116 METS profile rows — the numbers 1 to
    /// 119 less the three the specification retired or never allocated — 16 folder-structure rows, and the
    /// house conventions this library adds beside them.
    /// </summary>
    [TestMethod]
    public void TheEArkAllocationHoldsEveryIdentifierTheCatalogueStates()
    {
        var allocations = AllocationsOf(EArkClaimIdsPath);

        Assert.HasCount(140, allocations);
        Assert.HasCount(116, allocations.Where(allocation => allocation.Code >= EArkClaimIds.MetsProfileRangeStart && allocation.Code <= EArkClaimIds.MetsProfileRangeEnd).ToList());
        Assert.HasCount(16, allocations.Where(allocation => allocation.Code >= EArkClaimIds.FolderStructureRangeStart && allocation.Code <= EArkClaimIds.FolderStructureRangeEnd).ToList());
        Assert.HasCount(8, allocations.Where(allocation => allocation.Code >= EArkClaimIds.HouseConventionRangeStart && allocation.Code <= EArkClaimIds.HouseConventionRangeEnd).ToList());
    }


    /// <summary>
    /// Every identifier the E-ARK AIP specification states is allocated: the 17 numbers its prose catalogue
    /// really assigns out of the 28 it counts to, the 7 rows of its METS profile, and the 4 obligations its
    /// prose states with no identifier of its own.
    /// </summary>
    [TestMethod]
    public void TheArchivalPackageAllocationHoldsEveryIdentifierTheSpecificationStates()
    {
        var allocations = AllocationsOf(AipClaimIdsPath);

        Assert.HasCount(28, allocations);
        Assert.HasCount(17, allocations.Where(allocation => allocation.Code >= AipClaimIds.ProseRangeStart && allocation.Code <= AipClaimIds.ProseRangeEnd).ToList());
        Assert.HasCount(7, allocations.Where(allocation => allocation.Code >= AipClaimIds.MetsProfileRangeStart && allocation.Code <= AipClaimIds.MetsProfileRangeEnd).ToList());
        Assert.HasCount(4, allocations.Where(allocation => allocation.Code >= AipClaimIds.NarrativeRangeStart && allocation.Code <= AipClaimIds.NarrativeRangeEnd).ToList());
    }


    /// <summary>
    /// The eleven numbers the archival specification's prose counts to but never assigns stay allocated to
    /// nothing, so every requirement that does exist keeps a code matching its own number. The gap is a defect
    /// of the source document rather than of this transcription, which is why it is asserted rather than
    /// quietly closed up.
    /// </summary>
    [TestMethod]
    public void TheElevenUnassignedArchivalProseNumbersStayUnallocated()
    {
        var codes = EveryEArchivingAllocation().Select(allocation => allocation.Code).ToHashSet();

        foreach(int unassigned in new int[] { 4, 5, 6, 9, 10, 14, 19, 23, 24, 25, 26 })
        {
            Assert.DoesNotContain(AipClaimIds.ProseRangeStart + unassigned, codes, $"AIP{unassigned} is allocated, and the specification never assigns it.");
        }

        Assert.Contains(AipClaimIds.ProseRangeStart + 3, codes);
        Assert.Contains(AipClaimIds.ProseRangeStart + 7, codes);
        Assert.Contains(AipClaimIds.ProseRangeStart + 13, codes);
        Assert.Contains(AipClaimIds.ProseRangeStart + 15, codes);
        Assert.Contains(AipClaimIds.ProseRangeStart + 27, codes);
    }


    /// <summary>
    /// Every identifier the preservation-metadata specification states is allocated: 125 tabulated rows and the
    /// 14 named mnemonics its narrative states beside them.
    /// </summary>
    [TestMethod]
    public void ThePreservationMetadataAllocationHoldsEveryIdentifierTheSpecificationStates()
    {
        var allocations = AllocationsOf(PremisClaimIdsPath);

        Assert.HasCount(139, allocations);
        Assert.HasCount(125, allocations.Where(allocation => allocation.Code >= PremisClaimIds.TableRequirementRangeStart && allocation.Code <= PremisClaimIds.TableRequirementRangeEnd).ToList());
        Assert.HasCount(14, allocations.Where(allocation => allocation.Code >= PremisClaimIds.NarrativeRequirementRangeStart && allocation.Code <= PremisClaimIds.NarrativeRequirementRangeEnd).ToList());
    }


    /// <summary>
    /// Every identifier the two preservation-service specifications state is allocated: 107 <c>OVR-</c> rows,
    /// 15 <c>PRP-</c> rows, the eight protocol operations and the 17 result codes.
    /// </summary>
    [TestMethod]
    public void ThePreservationServiceAllocationHoldsEveryIdentifierBothSpecificationsState()
    {
        var allocations = AllocationsOf(PreservationClaimIdsPath);

        Assert.HasCount(147, allocations);
        Assert.HasCount(107, allocations.Where(allocation => allocation.Code >= PreservationClaimIds.OverallRequirementRangeStart && allocation.Code <= PreservationClaimIds.OverallRequirementRangeEnd).ToList());
        Assert.HasCount(15, allocations.Where(allocation => allocation.Code >= PreservationClaimIds.ProtocolRequirementRangeStart && allocation.Code <= PreservationClaimIds.ProtocolRequirementRangeEnd).ToList());
        Assert.HasCount(8, allocations.Where(allocation => allocation.Code >= PreservationClaimIds.ProtocolOperationRangeStart && allocation.Code <= PreservationClaimIds.ProtocolOperationRangeEnd).ToList());
        Assert.HasCount(17, allocations.Where(allocation => allocation.Code >= PreservationClaimIds.ProtocolResultRangeStart && allocation.Code <= PreservationClaimIds.ProtocolResultRangeEnd).ToList());
    }


    /// <summary>
    /// No code is allocated twice across the four eArchiving classes, and no description is either: a claim
    /// read back out of a result names exactly one requirement.
    /// </summary>
    [TestMethod]
    public void NoCodeAndNoDescriptionIsAllocatedTwice()
    {
        var allocations = EveryEArchivingAllocation();

        Assert.HasCount(454, allocations);
        Assert.HasCount(454, allocations.Select(allocation => allocation.Code).Distinct().ToList());
        Assert.HasCount(454, allocations.Select(allocation => allocation.Description).Distinct(StringComparer.Ordinal).ToList());
    }


    /// <summary>
    /// Every allocation describes itself with its source specification's own identifier text, verbatim — the
    /// property name is this library's, the description is the specification's.
    /// </summary>
    [TestMethod]
    public void EveryAllocationDescribesItselfWithItsSpecificationsOwnIdentifier()
    {
        Assert.AreEqual("CSIP1", EArkClaimIds.Csip1.ToString());
        Assert.AreEqual("CSIP119", EArkClaimIds.Csip119.ToString());
        Assert.AreEqual("CSIPSTR16", EArkClaimIds.CsipStr16.ToString());
        Assert.AreEqual("PM125", PremisClaimIds.Pm125.ToString());
        Assert.AreEqual("PREMIS-ID-LOCAL", PremisClaimIds.PremisIdLocal.ToString());
        Assert.AreEqual("OVR-6.4-04", PreservationClaimIds.Ovr64Item04.ToString());
        Assert.AreEqual("OVR-A-02A", PreservationClaimIds.OvrAnnexAItem02A.ToString());
        Assert.AreEqual("PRP-8.1-01", PreservationClaimIds.Prp81Item01.ToString());
        Assert.AreEqual("RetrieveInfo", PreservationClaimIds.OperationRetrieveInfo.ToString());
        Assert.AreEqual(
            "http://uri.etsi.org/19512/error/noPermission",
            PreservationClaimIds.ResultNoPermission.ToString());

        //Nothing carries an empty description, which is what a ClaimId read out of a result would otherwise
        //print instead of naming its requirement.
        foreach(var allocation in EveryEArchivingAllocation())
        {
            Assert.IsFalse(
                string.IsNullOrWhiteSpace(allocation.Description),
                $"{allocation.PropertyName} carries no description.");
        }
    }


    /// <summary>
    /// A numbered requirement's code is its band start plus its own number, and a clause-and-sequence
    /// requirement's code is its band start plus its clause and sequence — recomputed here from the
    /// description text alone, so the arithmetic the allocation sites document is checked rather than restated.
    /// </summary>
    [TestMethod]
    public void ANumberedRequirementsCodeIsItsBandStartPlusItsOwnNumber()
    {
        int recomputed = 0;
        foreach(var allocation in EveryEArchivingAllocation())
        {
            int expectedCode = ExpectedCodeOf(allocation.Description);
            if(expectedCode >= 0)
            {
                Assert.AreEqual(
                    expectedCode,
                    allocation.Code,
                    $"{allocation.PropertyName} ({allocation.Description}) is not at the code its band arithmetic states.");
                ++recomputed;
            }
        }

        //The identifiers with no numeric grammar of their own — the 14 preservation-metadata mnemonics, the
        //five annex requirements, the eight operations, the 17 result codes, the four archival obligations
        //stated without an identifier and this library's eight house conventions — are the only ones the
        //arithmetic does not reach.
        Assert.AreEqual(454 - 14 - 5 - 8 - 17 - 4 - 8, recomputed);
    }


    /// <summary>
    /// The three METS profile numbers the specification retired or never allocated — <c>CSIP86</c>,
    /// <c>CSIP87</c> and <c>CSIP115</c> — are allocated to nothing, so every other requirement's code keeps
    /// matching its own number.
    /// </summary>
    [TestMethod]
    public void TheThreeRetiredMetsProfileNumbersStayUnallocated()
    {
        var codes = EveryEArchivingAllocation().Select(allocation => allocation.Code).ToHashSet();

        Assert.DoesNotContain(EArkClaimIds.MetsProfileRangeStart + 86, codes);
        Assert.DoesNotContain(EArkClaimIds.MetsProfileRangeStart + 87, codes);
        Assert.DoesNotContain(EArkClaimIds.MetsProfileRangeStart + 115, codes);
        Assert.Contains(EArkClaimIds.MetsProfileRangeStart + 85, codes);
        Assert.Contains(EArkClaimIds.MetsProfileRangeStart + 88, codes);
        Assert.Contains(EArkClaimIds.MetsProfileRangeStart + 114, codes);
        Assert.Contains(EArkClaimIds.MetsProfileRangeStart + 116, codes);
    }


    /// <summary>
    /// Each band helper recognises its own band and nothing else: a requirement of another source
    /// specification, an identifier from another track of this library, and a default-initialized
    /// <see cref="ClaimId"/> are all refused.
    /// </summary>
    [TestMethod]
    public void EachBandHelperRecognisesItsOwnBandAndNothingElse()
    {
        Assert.IsTrue(EArkClaimIds.IsEArkRequirement(EArkClaimIds.Csip1));
        Assert.IsTrue(EArkClaimIds.IsEArkRequirement(EArkClaimIds.CsipStr4));
        Assert.IsFalse(EArkClaimIds.IsEArkRequirement(EArkClaimIds.PackageWithinStatedLimits));
        Assert.IsFalse(EArkClaimIds.IsEArkRequirement(PremisClaimIds.Pm1));
        Assert.IsFalse(EArkClaimIds.IsMetsProfileRequirement(EArkClaimIds.CsipStr4));
        Assert.IsFalse(EArkClaimIds.IsFolderStructureRequirement(EArkClaimIds.Csip1));

        Assert.IsTrue(PremisClaimIds.IsPreservationMetadataRequirement(PremisClaimIds.Pm33));
        Assert.IsTrue(PremisClaimIds.IsPreservationMetadataRequirement(PremisClaimIds.PremisChecksums));
        Assert.IsFalse(PremisClaimIds.IsPreservationMetadataRequirement(EArkClaimIds.Csip32));
        Assert.IsFalse(PremisClaimIds.IsTableRequirement(PremisClaimIds.PremisChecksums));

        Assert.IsTrue(PreservationClaimIds.IsPreservationServiceRequirement(PreservationClaimIds.Ovr715Item03));
        Assert.IsTrue(PreservationClaimIds.IsPreservationServiceRequirement(PreservationClaimIds.Prp81Item05));
        Assert.IsTrue(PreservationClaimIds.IsPreservationProtocolIdentifier(PreservationClaimIds.OperationPreservePo));
        Assert.IsTrue(PreservationClaimIds.IsPreservationProtocolIdentifier(PreservationClaimIds.ResultLowSpace));
        Assert.IsFalse(PreservationClaimIds.IsPreservationServiceRequirement(PreservationClaimIds.OperationPreservePo));
        Assert.IsFalse(PreservationClaimIds.IsProtocolOperation(PreservationClaimIds.ResultLowSpace));

        Assert.IsTrue(AipClaimIds.IsProseRequirement(AipClaimIds.Aip13));
        Assert.IsTrue(AipClaimIds.IsMetsProfileRequirement(AipClaimIds.Aipm5));
        Assert.IsTrue(AipClaimIds.IsNarrativeObligation(AipClaimIds.ArchivalPackageParentChainListed));
        Assert.IsFalse(AipClaimIds.IsProseRequirement(AipClaimIds.Aipm5));
        Assert.IsFalse(AipClaimIds.IsMetsProfileRequirement(AipClaimIds.Aip13));
        Assert.IsFalse(AipClaimIds.IsProseRequirement(EArkClaimIds.Csip1));

        //A claim identifier of another track of this library, and one that was never created at all.
        int otherTrackCode = ClaimId.AlgIsValid.Code;
        int neverCreatedCode = default(ClaimId).Code;
        foreach((int start, int end) in BandHelpers())
        {
            Assert.IsFalse(otherTrackCode >= start && otherTrackCode <= end, "A claim identifier of another track was recognised.");
            Assert.IsFalse(neverCreatedCode >= start && neverCreatedCode <= end, "A default-initialized claim identifier was recognised.");
        }
    }


    /// <summary>
    /// The bands do not overlap, and each one starts where its own documented boundary states.
    /// </summary>
    [TestMethod]
    public void TheBandsAreDisjointAndStartWhereTheyAreDocumentedToStart()
    {
        Assert.AreEqual(2_000_000, EArkClaimIds.MetsProfileRangeStart);
        Assert.AreEqual(2_100_000, EArkClaimIds.FolderStructureRangeStart);
        Assert.AreEqual(2_200_000, PremisClaimIds.TableRequirementRangeStart);
        Assert.AreEqual(2_300_000, PremisClaimIds.NarrativeRequirementRangeStart);
        Assert.AreEqual(2_400_000, PreservationClaimIds.OverallRequirementRangeStart);
        Assert.AreEqual(2_499_000, PreservationClaimIds.OverallAnnexRangeStart);
        Assert.AreEqual(2_500_000, PreservationClaimIds.ProtocolRequirementRangeStart);
        Assert.AreEqual(2_600_000, PreservationClaimIds.ProtocolOperationRangeStart);
        Assert.AreEqual(2_700_000, PreservationClaimIds.ProtocolResultRangeStart);
        Assert.AreEqual(2_800_000, AipClaimIds.ProseRangeStart);
        Assert.AreEqual(2_850_000, AipClaimIds.MetsProfileRangeStart);
        Assert.AreEqual(2_860_000, AipClaimIds.NarrativeRangeStart);
        Assert.AreEqual(2_900_000, EArkClaimIds.HouseConventionRangeStart);

        foreach(var allocation in EveryEArchivingAllocation())
        {
            int matchingBands = BandHelpers().Count(band => allocation.Code >= band.Start && allocation.Code <= band.End);
            Assert.AreEqual(
                1,
                matchingBands,
                $"{allocation.PropertyName} ({allocation.Description}) is recognised by {matchingBands} bands.");
        }
    }


    /// <summary>
    /// The narrowest band boundary of each source specification, one per band, so a code can be tested for
    /// falling inside exactly one of them — read by direct, non-reflective access to each class's own
    /// <c>RangeStart</c>/<c>RangeEnd</c> properties, the same numbers every <c>Is*</c> predicate in these
    /// classes compares a code against.
    /// </summary>
    /// <returns>One (start, end) boundary pair per allocated band.</returns>
    private static IReadOnlyList<(int Start, int End)> BandHelpers() =>
    [
        (EArkClaimIds.MetsProfileRangeStart, EArkClaimIds.MetsProfileRangeEnd),
        (EArkClaimIds.FolderStructureRangeStart, EArkClaimIds.FolderStructureRangeEnd),
        (EArkClaimIds.HouseConventionRangeStart, EArkClaimIds.HouseConventionRangeEnd),
        (PremisClaimIds.TableRequirementRangeStart, PremisClaimIds.TableRequirementRangeEnd),
        (PremisClaimIds.NarrativeRequirementRangeStart, PremisClaimIds.NarrativeRequirementRangeEnd),
        (PreservationClaimIds.OverallRequirementRangeStart, PreservationClaimIds.OverallRequirementRangeEnd),
        (PreservationClaimIds.ProtocolRequirementRangeStart, PreservationClaimIds.ProtocolRequirementRangeEnd),
        (PreservationClaimIds.ProtocolOperationRangeStart, PreservationClaimIds.ProtocolOperationRangeEnd),
        (PreservationClaimIds.ProtocolResultRangeStart, PreservationClaimIds.ProtocolResultRangeEnd),
        (AipClaimIds.ProseRangeStart, AipClaimIds.ProseRangeEnd),
        (AipClaimIds.MetsProfileRangeStart, AipClaimIds.MetsProfileRangeEnd),
        (AipClaimIds.NarrativeRangeStart, AipClaimIds.NarrativeRangeEnd),
    ];


    /// <summary>The repository-relative path declaring <see cref="EArkClaimIds"/>.</summary>
    private const string EArkClaimIdsPath = "src/Verifiable.Core/Assessment/EArchiving/EArkClaimIds.cs";

    /// <summary>The repository-relative path declaring <see cref="PremisClaimIds"/>.</summary>
    private const string PremisClaimIdsPath = "src/Verifiable.Core/Assessment/EArchiving/PremisClaimIds.cs";

    /// <summary>The repository-relative path declaring <see cref="PreservationClaimIds"/>.</summary>
    private const string PreservationClaimIdsPath = "src/Verifiable.Core/Assessment/EArchiving/PreservationClaimIds.cs";

    /// <summary>The repository-relative path declaring <see cref="AipClaimIds"/>.</summary>
    private const string AipClaimIdsPath = "src/Verifiable.Core/Assessment/EArchiving/AipClaimIds.cs";

    /// <summary>Matches a declared <c>public static int X { get; } = LITERAL;</c> range-boundary constant.</summary>
    private static Regex RangeConstantPattern { get; } = new(
        @"public\s+static\s+int\s+(\w+)\s*\{\s*get;\s*\}\s*=\s*(-?[\d_]+)\s*;",
        RegexOptions.Compiled);

    /// <summary>
    /// Matches a declared <c>public static ClaimId X { get; } = ClaimId.Create(code, "description");</c>
    /// allocation, whose code is either a bare integer literal or a range constant plus a literal offset.
    /// </summary>
    private static Regex ClaimIdCreatePattern { get; } = new(
        @"public\s+static\s+ClaimId\s+(\w+)\s*\{\s*get;\s*\}\s*=\s*ClaimId\.Create\(\s*(?:(\w+)\s*\+\s*)?(-?[\d_]+)\s*,\s*""((?:[^""\\]|\\.)*)""\s*\)\s*;",
        RegexOptions.Compiled);


    /// <summary>Every allocation of the four eArchiving classes, in one list.</summary>
    /// <returns>The property name, code and description of every allocation.</returns>
    private static IReadOnlyList<(string PropertyName, int Code, string Description)> EveryEArchivingAllocation() =>
    [
        .. AllocationsOf(EArkClaimIdsPath),
        .. AllocationsOf(PremisClaimIdsPath),
        .. AllocationsOf(PreservationClaimIdsPath),
        .. AllocationsOf(AipClaimIdsPath),
    ];


    /// <summary>
    /// Reads every <see cref="ClaimId"/> a well-known class allocates, by a source scan of its own declaring
    /// file — resolving a <c>RangeStart + offset</c> code expression against that same file's own range
    /// constant — rather than by reflection over the loaded type, so a property added without a test row
    /// still shows up in the counts.
    /// </summary>
    /// <param name="relativePath">The declaring file's repository-relative path.</param>
    /// <returns>The property name, code and description of every allocation.</returns>
    private static List<(string PropertyName, int Code, string Description)> AllocationsOf(string relativePath)
    {
        string text = File.ReadAllText(Path.Combine(SourceHygieneScanner.FindRepositoryRoot(), relativePath));

        Dictionary<string, int> rangeConstants = [];
        foreach(Match rangeMatch in RangeConstantPattern.Matches(text))
        {
            rangeConstants[rangeMatch.Groups[1].Value] = int.Parse(rangeMatch.Groups[2].Value.Replace("_", string.Empty, StringComparison.Ordinal), CultureInfo.InvariantCulture);
        }

        List<(string PropertyName, int Code, string Description)> allocations = [];
        foreach(Match match in ClaimIdCreatePattern.Matches(text))
        {
            int offset = int.Parse(match.Groups[3].Value.Replace("_", string.Empty, StringComparison.Ordinal), CultureInfo.InvariantCulture);
            int code = match.Groups[2].Success ? rangeConstants[match.Groups[2].Value] + offset : offset;
            allocations.Add((match.Groups[1].Value, code, match.Groups[4].Value));
        }

        return allocations;
    }


    /// <summary>
    /// Recomputes the code a requirement identifier must carry from the identifier text alone, independently of
    /// the allocation sites: a <c>CSIPn</c>, <c>CSIPSTRn</c> or <c>PMn</c> row is its band start plus
    /// <em>n</em>, and an <c>OVR-</c> or <c>PRP-</c> row is its band start plus its clause and sequence.
    /// </summary>
    /// <param name="description">The identifier text as the specification states it.</param>
    /// <returns>The code the identifier must carry, or <c>-1</c> when the identifier has no numeric grammar.</returns>
    private static int ExpectedCodeOf(string description)
    {
        if(description.StartsWith("AIPM", StringComparison.Ordinal))
        {
            return 2_850_000 + int.Parse(description["AIPM".Length..], CultureInfo.InvariantCulture);
        }

        if(description.StartsWith("AIP", StringComparison.Ordinal) && char.IsAsciiDigit(description["AIP".Length]))
        {
            return 2_800_000 + int.Parse(description["AIP".Length..], CultureInfo.InvariantCulture);
        }

        if(description.StartsWith("CSIPSTR", StringComparison.Ordinal))
        {
            return 2_100_000 + int.Parse(description["CSIPSTR".Length..], CultureInfo.InvariantCulture);
        }

        if(description.StartsWith("CSIP", StringComparison.Ordinal))
        {
            return 2_000_000 + int.Parse(description["CSIP".Length..], CultureInfo.InvariantCulture);
        }

        if(description.StartsWith("PM", StringComparison.Ordinal))
        {
            return 2_200_000 + int.Parse(description["PM".Length..], CultureInfo.InvariantCulture);
        }

        bool isOverall = description.StartsWith("OVR-", StringComparison.Ordinal);
        if(isOverall || description.StartsWith("PRP-", StringComparison.Ordinal))
        {
            string[] parts = description.Split('-');
            if(parts[1].StartsWith('A'))
            {
                return -1;
            }

            string[] clause = parts[1].Split('.');
            int major = int.Parse(clause[0], CultureInfo.InvariantCulture);
            int minor = clause.Length > 1 ? int.Parse(clause[1], CultureInfo.InvariantCulture) : 0;
            int sequence = int.Parse(parts[2], CultureInfo.InvariantCulture);

            return (isOverall ? 2_400_000 : 2_500_000) + (major * 10_000) + (minor * 100) + sequence;
        }

        return -1;
    }
}
