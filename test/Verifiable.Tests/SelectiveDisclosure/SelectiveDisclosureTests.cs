using Verifiable.Core.Model.SelectiveDisclosure;

using SelectiveDisclosureCore = Verifiable.Core.Model.SelectiveDisclosure.SelectiveDisclosure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for <see cref="SelectiveDisclosure"/>.
/// </summary>
[TestClass]
internal sealed class SelectiveDisclosureTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void ComputeMinimumDisclosureIncludesMandatoryAndRequested()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 3, 4 };

        var (disclosures, unavailable) = SelectiveDisclosureCore.ComputeMinimumDisclosure(lattice, requested);

        Assert.IsTrue(disclosures.SetEquals(new HashSet<int> { 1, 2, 3, 4 }), "Minimum must include mandatory and requested.");
        Assert.IsEmpty(unavailable, "No unavailable claims expected.");
    }


    [TestMethod]
    public void ComputeMinimumDisclosureIncludesRegulatoryMandated()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var regulatory = new HashSet<int> { 3 };

        var (disclosures, unavailable) = SelectiveDisclosureCore.ComputeMinimumDisclosure(
            lattice,
            verifierRequested: null,
            regulatoryMandated: regulatory);

        Assert.IsTrue(disclosures.SetEquals(new HashSet<int> { 1, 2, 3 }), "Minimum must include mandatory and regulatory-mandated claims.");
        Assert.IsEmpty(unavailable, "No unavailable claims expected.");
    }


    [TestMethod]
    public void ComputeMinimumDisclosureIncludesStructurallyRequired()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var structural = new HashSet<int> { 4 };

        var (disclosures, unavailable) = SelectiveDisclosureCore.ComputeMinimumDisclosure(
            lattice,
            verifierRequested: null,
            regulatoryMandated: null,
            structurallyRequired: structural);

        Assert.IsTrue(disclosures.SetEquals(new HashSet<int> { 1, 2, 4 }), "Minimum must include mandatory and structurally-required claims.");
        Assert.IsEmpty(unavailable, "No unavailable claims expected.");
    }


    [TestMethod]
    public void ComputeMinimumDisclosureUnionsAllThreeSources()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        var (disclosures, unavailable) = SelectiveDisclosureCore.ComputeMinimumDisclosure(
            lattice,
            verifierRequested: new HashSet<int> { 3 },
            regulatoryMandated: new HashSet<int> { 4 },
            structurallyRequired: new HashSet<int> { 5 });

        Assert.IsTrue(disclosures.SetEquals(new HashSet<int> { 1, 2, 3, 4, 5 }), "Minimum must union mandatory, verifier, regulatory and structural claims.");
        Assert.IsEmpty(unavailable, "No unavailable claims expected.");
    }


    [TestMethod]
    public void ComputeMinimumDisclosureReportsUnavailableFromEverySource()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        var (disclosures, unavailable) = SelectiveDisclosureCore.ComputeMinimumDisclosure(
            lattice,
            verifierRequested: new HashSet<int> { 6 },
            regulatoryMandated: new HashSet<int> { 7 },
            structurallyRequired: new HashSet<int> { 8 });

        Assert.IsTrue(disclosures.SetEquals(new HashSet<int> { 1, 2 }), "Only mandatory claims remain when every requested claim is unavailable.");
        Assert.IsTrue(unavailable.SetEquals(new HashSet<int> { 6, 7, 8 }), "Unavailable claims from all three sources must be reported.");
    }


    [TestMethod]
    public void ComputeMinimumDisclosureReportsUnavailableClaims()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 3, 6, 7 };

        var (disclosures, unavailable) = SelectiveDisclosureCore.ComputeMinimumDisclosure(lattice, requested);

        Assert.IsTrue(disclosures.SetEquals(new HashSet<int> { 1, 2, 3 }), "Minimum must include only available claims.");
        Assert.IsTrue(unavailable.SetEquals(new HashSet<int> { 6, 7 }), "Unavailable claims must be reported.");
    }


    [TestMethod]
    public void ComputeMinimumDisclosureHandlesMandatoryInRequest()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 1, 3 };

        var (disclosures, unavailable) = SelectiveDisclosureCore.ComputeMinimumDisclosure(lattice, requested);

        Assert.IsTrue(disclosures.SetEquals(new HashSet<int> { 1, 2, 3 }), "Requesting mandatory claim must not cause issues.");
        Assert.IsEmpty(unavailable, "No unavailable claims when requesting existing claims.");
    }


    [TestMethod]
    public void ComputeMaximumDisclosureReturnsAllMinusExclusions()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var exclusions = new HashSet<int> { 4, 5 };

        var result = SelectiveDisclosureCore.ComputeMaximumDisclosure(lattice, exclusions);

        Assert.IsTrue(result.SetEquals(new HashSet<int> { 1, 2, 3 }), "Maximum must exclude user exclusions.");
    }


    [TestMethod]
    public void ComputeMaximumDisclosureIgnoresMandatoryExclusions()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var exclusions = new HashSet<int> { 1, 4 };

        var result = SelectiveDisclosureCore.ComputeMaximumDisclosure(lattice, exclusions);

        Assert.Contains(1, result, "User cannot exclude mandatory claim 1.");
        Assert.DoesNotContain(4, result, "User can exclude selectable claim 4.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureSatisfiesWhenNoConflict()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 3 };
        var exclusions = new HashSet<int> { 5 };

        var result = SelectiveDisclosureCore.ComputeOptimalDisclosure(lattice, requested, exclusions);

        Assert.IsTrue(result.SatisfiesRequirements, "Requirements must be satisfied when no conflict.");
        Assert.IsTrue(result.SelectedClaims.SetEquals(new HashSet<int> { 1, 2, 3 }), "Selected must include mandatory and requested.");
        Assert.IsNull(result.ConflictingClaims, "No conflicts expected.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureDetectsConflict()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 3, 4 };
        var exclusions = new HashSet<int> { 4 };

        var result = SelectiveDisclosureCore.ComputeOptimalDisclosure(lattice, requested, exclusions);

        Assert.IsFalse(result.SatisfiesRequirements, "Requirements must not be satisfied when conflict exists.");
        Assert.IsNotNull(result.ConflictingClaims, "Conflicting claims must be reported.");
        Assert.Contains(4, result.ConflictingClaims, "Claim 4 must be in conflicts.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureReturnsUnavailableClaims()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 3, 6 };

        var result = SelectiveDisclosureCore.ComputeOptimalDisclosure(lattice, requested);

        Assert.IsFalse(result.SatisfiesRequirements, "Requirements not fully satisfied when claims unavailable.");
        Assert.IsNotNull(result.UnavailableClaims, "Unavailable claims must be reported.");
        Assert.Contains(6, result.UnavailableClaims, "Claim 6 must be unavailable.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureHandlesMandatoryInRequest()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 1, 2, 3 };

        var result = SelectiveDisclosureCore.ComputeOptimalDisclosure(lattice, requested);

        Assert.IsTrue(result.SatisfiesRequirements, "Requesting mandatory claims must succeed.");
        Assert.IsTrue(result.SelectedClaims.SetEquals(new HashSet<int> { 1, 2, 3 }), "Selected must include all requested.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureWithNullInputsReturnsOnlyMandatory()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        var result = SelectiveDisclosureCore.ComputeOptimalDisclosure(lattice);

        Assert.IsTrue(result.SatisfiesRequirements, "No requirements means satisfied.");
        Assert.IsTrue(result.SelectedClaims.SetEquals(new HashSet<int> { 1, 2 }), "Only mandatory claims when no request.");
    }


    [TestMethod]
    public void ValidateDisclosureReturnsTrueForValidSet()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var disclosures = new HashSet<int> { 1, 2, 3 };
        var requirements = new HashSet<int> { 3 };

        var result = SelectiveDisclosureCore.ValidateDisclosure(lattice, disclosures, requirements);

        Assert.IsTrue(result, "Valid disclosure satisfying requirements must validate.");
    }


    [TestMethod]
    public void ValidateDisclosureReturnsFalseWhenMissingRequired()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var disclosures = new HashSet<int> { 1, 2, 3 };
        var requirements = new HashSet<int> { 3, 4 };

        var result = SelectiveDisclosureCore.ValidateDisclosure(lattice, disclosures, requirements);

        Assert.IsFalse(result, "Disclosure missing required claim must fail validation.");
    }


    [TestMethod]
    public void ValidateDisclosureReturnsFalseWhenMissingMandatory()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var disclosures = new HashSet<int> { 1, 3 };
        var requirements = new HashSet<int> { 3 };

        var result = SelectiveDisclosureCore.ValidateDisclosure(lattice, disclosures, requirements);

        Assert.IsFalse(result, "Disclosure missing mandatory claim must fail validation.");
    }


    [TestMethod]
    public void SelectCredentialsFindsBestCombination()
    {
        var lattice1 = new SetDisclosureLattice<string>(["name", "email"], ["name"]);
        var lattice2 = new SetDisclosureLattice<string>(["phone", "address"], []);

        var credentials = new List<(string Credential, SetDisclosureLattice<string> Lattice)>
        {
            ("cred1", lattice1),
            ("cred2", lattice2)
        };

        var requirements = new HashSet<string> { "email", "phone" };

        var result = SelectiveDisclosureCore.SelectCredentials(credentials, requirements);

        Assert.IsTrue(result.SatisfiesAllRequirements, "Both requirements must be satisfied.");
        Assert.HasCount(2, result.Selections, "Two credentials must be selected.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureIncludesRegulatoryAndStructural()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        var result = SelectiveDisclosureCore.ComputeOptimalDisclosure(
            lattice,
            verifierRequested: new HashSet<int> { 3 },
            userExclusions: new HashSet<int> { 5 },
            regulatoryMandated: new HashSet<int> { 4 });

        Assert.IsTrue(result.SatisfiesRequirements, "No conflict: regulatory claim 4 is not excluded.");
        Assert.IsTrue(result.SelectedClaims.SetEquals(new HashSet<int> { 1, 2, 3, 4 }), "Selected must include mandatory, verifier and regulatory claims.");
        Assert.IsNull(result.ConflictingClaims, "No conflicts expected.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureConflictReturnsIntersectionPlusMandatory()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 3, 4 };
        var exclusions = new HashSet<int> { 4 };

        var result = SelectiveDisclosureCore.ComputeOptimalDisclosure(lattice, requested, exclusions);

        Assert.IsFalse(result.SatisfiesRequirements, "Excluding a requested claim is a conflict.");
        Assert.IsTrue(result.SelectedClaims.SetEquals(new HashSet<int> { 1, 2, 3 }), "Best effort must be (minimum ∩ maximum) ∪ mandatory.");
        Assert.IsNotNull(result.ConflictingClaims, "Conflicts must be reported.");
        Assert.IsTrue(result.ConflictingClaims!.SetEquals(new HashSet<int> { 4 }), "Only the excluded-yet-required claim conflicts.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureRegulatoryClaimCannotBeExcludedByUser()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        var result = SelectiveDisclosureCore.ComputeOptimalDisclosure(
            lattice,
            verifierRequested: null,
            userExclusions: new HashSet<int> { 4 },
            regulatoryMandated: new HashSet<int> { 4 });

        Assert.IsFalse(result.SatisfiesRequirements, "A user exclusion cannot override a regulatory mandate.");
        Assert.IsNotNull(result.ConflictingClaims, "The regulated-yet-excluded claim must surface as a conflict.");
        Assert.Contains(4, result.ConflictingClaims!, "Claim 4 is regulatory-mandated but user-excluded.");
        Assert.IsTrue(result.SelectedClaims.SetEquals(new HashSet<int> { 1, 2 }), "Best effort drops the conflicting claim, keeping only mandatory.");
    }


    [TestMethod]
    public void SelectCredentialsPrefersFewerCredentialsByGreedyCoverage()
    {
        //cred1 can satisfy both requirements, cred2 only one — greedy must pick cred1 alone.
        var lattice1 = new SetDisclosureLattice<string>(["email", "phone"], []);
        var lattice2 = new SetDisclosureLattice<string>(["phone"], []);

        var credentials = new List<(string Credential, SetDisclosureLattice<string> Lattice)>
        {
            ("cred2", lattice2),
            ("cred1", lattice1)
        };

        var requirements = new HashSet<string> { "email", "phone" };

        var result = SelectiveDisclosureCore.SelectCredentials(credentials, requirements);

        Assert.IsTrue(result.SatisfiesAllRequirements, "Both requirements must be satisfied.");
        Assert.HasCount(1, result.Selections, "Greedy must satisfy everything from the single highest-coverage credential.");
        Assert.AreEqual("cred1", result.Selections[0].Credential, "The credential covering both requirements must be chosen.");
    }


    [TestMethod]
    public void SelectCredentialsRespectsUserExclusions()
    {
        var lattice1 = new SetDisclosureLattice<string>(["name", "email"], ["name"]);

        var credentials = new List<(string Credential, SetDisclosureLattice<string> Lattice)>
        {
            ("cred1", lattice1)
        };

        var requirements = new HashSet<string> { "email" };
        var exclusions = new Dictionary<string, IReadOnlySet<string>>
        {
            ["cred1"] = new HashSet<string> { "email" }
        };

        var result = SelectiveDisclosureCore.SelectCredentials(credentials, requirements, exclusions);

        Assert.IsFalse(result.SatisfiesAllRequirements, "An excluded claim cannot satisfy the requirement.");
        Assert.IsNotNull(result.UnsatisfiedRequirements, "The blocked requirement must be reported.");
        Assert.Contains("email", result.UnsatisfiedRequirements!, "Email stays unsatisfied because the user excluded it.");
    }


    [TestMethod]
    public void SelectCredentialsWithEmptyRequirementsSelectsNothing()
    {
        var lattice1 = new SetDisclosureLattice<string>(["name", "email"], ["name"]);

        var credentials = new List<(string Credential, SetDisclosureLattice<string> Lattice)>
        {
            ("cred1", lattice1)
        };

        var result = SelectiveDisclosureCore.SelectCredentials(credentials, new HashSet<string>());

        Assert.IsTrue(result.SatisfiesAllRequirements, "No requirements are trivially satisfied.");
        Assert.IsEmpty(result.Selections, "Nothing should be selected when nothing is required.");
        Assert.IsNull(result.UnsatisfiedRequirements, "No unsatisfied requirements when none were asked for.");
    }


    [TestMethod]
    public void SelectCredentialsWithNoCredentialsReportsAllUnsatisfied()
    {
        var credentials = new List<(string Credential, SetDisclosureLattice<string> Lattice)>();
        var requirements = new HashSet<string> { "email" };

        var result = SelectiveDisclosureCore.SelectCredentials(credentials, requirements);

        Assert.IsFalse(result.SatisfiesAllRequirements, "Nothing can be satisfied without credentials.");
        Assert.IsNotNull(result.UnsatisfiedRequirements, "All requirements must be reported unsatisfied.");
        Assert.Contains("email", result.UnsatisfiedRequirements!, "Email cannot be satisfied.");
    }


    [TestMethod]
    public void SelectCredentialsReportsUnsatisfiedRequirements()
    {
        var lattice1 = new SetDisclosureLattice<string>(["name", "email"], ["name"]);

        var credentials = new List<(string Credential, SetDisclosureLattice<string> Lattice)>
    {
        ("cred1", lattice1)
    };

        var requirements = new HashSet<string> { "email", "phone" };

        var result = SelectiveDisclosureCore.SelectCredentials(credentials, requirements);

        Assert.IsFalse(result.SatisfiesAllRequirements, "Phone requirement cannot be satisfied.");
        Assert.IsNotNull(result.UnsatisfiedRequirements, "Unsatisfied requirements must be reported.");
        Assert.Contains("phone", result.UnsatisfiedRequirements, "Phone must be unsatisfied.");
    }
}
