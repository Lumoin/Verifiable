using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.Assessment;
using Verifiable.Core.Assessment.EArchiving;
using Verifiable.Cryptography.Pki;

namespace Verifiable.Tests.EuEArk;

/// <summary>
/// Conformance tests for <see cref="EArkValidationProfiles"/> and <see cref="EArkValidationChecks"/>: the rule
/// lists compose, a caller can extend one with a rule of its own, and each of the three keywords the E-ARK CSIP
/// folder-structure catalogue is stated in — MUST, SHOULD and MAY — reaches the outcome
/// <see href="https://earkcsip.dilcis.eu/specification/implementation/structure/">E-ARK CSIP v2.2.0 clause 4.1</see>
/// gives it.
/// </summary>
[TestClass]
internal sealed class EArkValidationProfileTests
{
    /// <summary>The MSTest context, carrying the cancellation token every asynchronous call observes.</summary>
    public required TestContext TestContext { get; set; }

    /// <summary>The identifier the test issuer states as its own.</summary>
    private const string IssuerId = "eark-package-validator";

    /// <summary>The correlation identifier the test issuer carries through a run.</summary>
    private const string CorrelationId = "eark-package-validation";

    /// <summary>
    /// The claim identifier a caller's own rule issues. Its code sits outside every band the eArchiving
    /// allocation reserves, which is what a consumer adding a rule of its own does.
    /// </summary>
    private static ClaimId CallerOwnRule { get; } = ClaimId.Create(3_000_001, "CallerOwnEArkRule");

    /// <summary>The instant every validation in this class runs at, stated rather than read from a clock.</summary>
    private static DateTimeOffset ValidationInstant { get; } = new(2026, 7, 31, 12, 0, 0, TimeSpan.Zero);

    /// <summary>The time provider the issuer stamps its results with.</summary>
    private static FakeTimeProvider IssuerTime { get; } = new(ValidationInstant);


    /// <summary>
    /// The structural profile composes the integrity profile rather than restating it, and states the
    /// requirement identifiers its rules issue.
    /// </summary>
    [TestMethod]
    public void TheStructuralProfileComposesTheIntegrityProfile()
    {
        var integrityRules = EArkValidationProfiles.PackageIntegrityRules();
        var structuralRules = EArkValidationProfiles.CsipStructuralRules();

        Assert.HasCount(1, integrityRules);
        Assert.HasCount(17, structuralRules);

        var expectedClaimIds = structuralRules.SelectMany(rule => rule.ExpectedClaimIds).Select(claimId => claimId.Code).ToList();
        Assert.Contains(EArkClaimIds.PackageWithinStatedLimits.Code, expectedClaimIds);
        Assert.Contains(EArkClaimIds.CsipStr4.Code, expectedClaimIds);
        Assert.Contains(EArkClaimIds.CsipStr5.Code, expectedClaimIds);
        Assert.Contains(EArkClaimIds.CsipStr8.Code, expectedClaimIds);

        //The public summary of CsipStructuralRules() names the surface it issues, so the surface is pinned
        //here row by row rather than by a count alone: the whole folder catalogue in the catalogue's own order.
        int[] catalogue =
        [
            EArkClaimIds.PackageWithinStatedLimits.Code,
            EArkClaimIds.CsipStr1.Code, EArkClaimIds.CsipStr2.Code, EArkClaimIds.CsipStr3.Code, EArkClaimIds.CsipStr4.Code,
            EArkClaimIds.CsipStr5.Code, EArkClaimIds.CsipStr6.Code, EArkClaimIds.CsipStr7.Code, EArkClaimIds.CsipStr8.Code,
            EArkClaimIds.CsipStr9.Code, EArkClaimIds.CsipStr10.Code, EArkClaimIds.CsipStr11.Code, EArkClaimIds.CsipStr12.Code,
            EArkClaimIds.CsipStr13.Code, EArkClaimIds.CsipStr14.Code, EArkClaimIds.CsipStr15.Code, EArkClaimIds.CsipStr16.Code
        ];
        Assert.AreSequenceEqual(catalogue, expectedClaimIds);
    }


    /// <summary>
    /// Every profile returns a list a caller can extend, and the appended rule runs beside the library's own
    /// through one issuer — the composition the whole pipeline convention rests on.
    /// </summary>
    [TestMethod]
    public async Task ACallerCanAppendARuleOfItsOwnToAProfile()
    {
        var rules = EArkValidationProfiles.CsipStructuralRules();
        rules.Add(new ClaimDelegate<EArkValidationContext>(CheckCallerOwnRule, [CallerOwnRule]));

        var issuer = new ClaimIssuer<EArkValidationContext>(IssuerId, rules, IssuerTime);
        var result = await issuer.GenerateClaimsAsync(
            ConformantPackage(),
            CorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsComplete);
        Assert.AreEqual(18, result.TotalRules);
        Assert.HasCount(18, result.Claims);
        Assert.AreEqual(ClaimOutcome.Success, OutcomeOf(result, CallerOwnRule));
    }


    /// <summary>
    /// A package holding the root manifest, a metadata folder, a further metadata sub-folder and a
    /// representation satisfies every structural rule the profile issues today.
    /// </summary>
    [TestMethod]
    public async Task AConformantPackageSatisfiesEveryStructuralRule()
    {
        var result = await RunStructuralRulesAsync(ConformantPackage()).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Success, OutcomeOf(result, EArkClaimIds.PackageWithinStatedLimits));
        Assert.AreEqual(ClaimOutcome.Success, OutcomeOf(result, EArkClaimIds.CsipStr4));
        Assert.AreEqual(ClaimOutcome.Success, OutcomeOf(result, EArkClaimIds.CsipStr5));
        Assert.AreEqual(ClaimOutcome.Success, OutcomeOf(result, EArkClaimIds.CsipStr8));
    }


    /// <summary>
    /// A package missing all three subjects reaches the three outcomes the three keywords give: the MUST of
    /// <c>CSIPSTR4</c> fails, the SHOULD of <c>CSIPSTR5</c> is inconclusive, and the MAY of <c>CSIPSTR8</c> is
    /// not applicable. Nothing defaults to success.
    /// </summary>
    [TestMethod]
    public async Task EachKeywordReachesTheOutcomeTheSpecificationGivesIt()
    {
        var package = new EArkValidationContext
        {
            EntryNames = ["representations/rep1/data/content.bin"],
            CurrentTime = ValidationInstant,
        };

        var result = await RunStructuralRulesAsync(package).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Failure, OutcomeOf(result, EArkClaimIds.CsipStr4));
        Assert.AreEqual(ClaimOutcome.Inconclusive, OutcomeOf(result, EArkClaimIds.CsipStr5));
        Assert.AreEqual(ClaimOutcome.NotApplicable, OutcomeOf(result, EArkClaimIds.CsipStr8));
    }


    /// <summary>
    /// The manifest name is matched exactly as the specification states it: a differently cased name is not the
    /// root manifest, because a conforming reader on a case-sensitive file system would not find it either.
    /// </summary>
    [TestMethod]
    public async Task AManifestNameDifferingInCaseIsNotTheRootManifest()
    {
        var package = new EArkValidationContext
        {
            EntryNames = ["mets.xml", "representations/rep1/METS.xml"],
            CurrentTime = ValidationInstant,
        };

        var result = await RunStructuralRulesAsync(package).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Failure, OutcomeOf(result, EArkClaimIds.CsipStr4));
    }


    /// <summary>
    /// A package beyond any one of the bounds the caller stated fails the integrity rule, whichever bound it
    /// exceeded — the entry count, the entry name length or the depth.
    /// </summary>
    /// <param name="entryName">The entry name the package holds beside its root manifest.</param>
    /// <param name="maximumEntryCount">The entry-count bound the caller states.</param>
    /// <param name="maximumEntryNameByteLength">The name-length bound the caller states.</param>
    /// <param name="maximumFolderDepth">The depth bound the caller states.</param>
    /// <returns>A task that completes when the package has been validated.</returns>
    [TestMethod]
    [DataRow("metadata/descriptive/record.xml", 1, 512, 32, DisplayName = "Beyond the entry count")]
    [DataRow("metadata/descriptive/record.xml", 64, 8, 32, DisplayName = "Beyond the name length")]
    [DataRow("metadata/descriptive/record.xml", 64, 512, 1, DisplayName = "Beyond the depth")]
    public async Task APackageBeyondAStatedBoundFailsTheIntegrityRule(
        string entryName,
        int maximumEntryCount,
        int maximumEntryNameByteLength,
        int maximumFolderDepth)
    {
        var package = new EArkValidationContext
        {
            EntryNames = [EArkWellKnown.PackageManifestFileName, entryName],
            CurrentTime = ValidationInstant,
            Limits = new EArkPackageLimits
            {
                MaximumEntryCount = maximumEntryCount,
                MaximumEntryNameByteLength = maximumEntryNameByteLength,
                MaximumFolderDepth = maximumFolderDepth,
            },
        };

        var result = await RunStructuralRulesAsync(package).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Failure, OutcomeOf(result, EArkClaimIds.PackageWithinStatedLimits));
    }


    /// <summary>
    /// A package inside every bound the caller stated passes the integrity rule, so the failures above are the
    /// bounds speaking rather than the rule refusing everything.
    /// </summary>
    [TestMethod]
    public async Task APackageInsideEveryStatedBoundPassesTheIntegrityRule()
    {
        var package = new EArkValidationContext
        {
            EntryNames = [EArkWellKnown.PackageManifestFileName, "metadata/descriptive/record.xml"],
            CurrentTime = ValidationInstant,
            Limits = new EArkPackageLimits
            {
                MaximumEntryCount = 2,
                MaximumEntryNameByteLength = 64,
                MaximumFolderDepth = 2,
            },
        };

        var result = await RunStructuralRulesAsync(package).ConfigureAwait(false);

        Assert.AreEqual(ClaimOutcome.Success, OutcomeOf(result, EArkClaimIds.PackageWithinStatedLimits));
    }


    /// <summary>
    /// No rule of any profile answers with nothing: a rule that could not conclude says so with a claim, and an
    /// empty package therefore still produces one claim per rule.
    /// </summary>
    [TestMethod]
    public async Task NoRuleOfAnyProfileAnswersWithAnEmptyClaimList()
    {
        var package = new EArkValidationContext
        {
            EntryNames = [],
            CurrentTime = ValidationInstant,
        };

        foreach(var rule in EArkValidationProfiles.CsipStructuralRules())
        {
            var claims = await rule.Delegate(package, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.HasCount(1, claims);
            Assert.AreEqual(rule.ExpectedClaimIds[0].Code, claims[0].Id.Code);
        }
    }


    /// <summary>Runs the structural profile over one package.</summary>
    /// <param name="package">The package to validate.</param>
    /// <returns>What the issuer concluded.</returns>
    private async Task<ClaimIssueResult> RunStructuralRulesAsync(EArkValidationContext package)
    {
        var issuer = new ClaimIssuer<EArkValidationContext>(
            IssuerId,
            EArkValidationProfiles.CsipStructuralRules(),
            IssuerTime);

        return await issuer.GenerateClaimsAsync(
            package,
            CorrelationId,
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>A package holding a root manifest, package metadata, further metadata and one representation.</summary>
    /// <returns>The package snapshot the conformant cases run over.</returns>
    private static EArkValidationContext ConformantPackage() => new()
    {
        EntryNames =
        [
            EArkWellKnown.PackageManifestFileName,
            "metadata/",
            "metadata/preservation/premis.xml",
            "metadata/other/notes.txt",
            "representations/rep1/METS.xml",
            "representations/rep1/data/content.bin",
            "schemas/mets.xsd",
            "documentation/readme.txt",
        ],
        CurrentTime = ValidationInstant,
    };


    /// <summary>Reads the outcome one requirement's claim carries out of a result.</summary>
    /// <param name="result">What the issuer concluded.</param>
    /// <param name="claimId">The requirement whose claim is read.</param>
    /// <returns>The outcome the claim carries.</returns>
    private static ClaimOutcome OutcomeOf(ClaimIssueResult result, ClaimId claimId)
    {
        foreach(var claim in result.Claims)
        {
            if(claim.Id.Code == claimId.Code)
            {
                return claim.Outcome;
            }
        }

        Assert.Fail($"The result carries no claim for {claimId}.");
        return ClaimOutcome.Failure;
    }


    /// <summary>
    /// A rule of a caller's own, matching <see cref="ClaimDelegateAsync{TInput}"/> exactly, which is what an
    /// application adds to a profile before handing it to an issuer.
    /// </summary>
    /// <param name="context">The package validation is given.</param>
    /// <param name="cancellationToken">Token to observe for cancellation requests.</param>
    /// <returns>One claim, the caller's own.</returns>
    private static ValueTask<List<Claim>> CheckCallerOwnRule(
        EArkValidationContext context,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ClaimOutcome outcome = context.EntryNames.Count > 0 ? ClaimOutcome.Success : ClaimOutcome.Failure;

        return ValueTask.FromResult<List<Claim>>([new Claim(CallerOwnRule, outcome)]);
    }
}
