using Verifiable.Core.SelectiveDisclosure;

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

        var (disclosures, unavailable) = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeMinimumDisclosure(lattice, requested);

        Assert.IsTrue(disclosures.SetEquals(new HashSet<int> { 1, 2, 3, 4 }), "Minimum must include mandatory and requested.");
        Assert.IsEmpty(unavailable, "No unavailable claims expected.");
    }


    [TestMethod]
    public void ComputeMinimumDisclosureReportsUnavailableClaims()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 3, 6, 7 };

        var (disclosures, unavailable) = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeMinimumDisclosure(lattice, requested);

        Assert.IsTrue(disclosures.SetEquals(new HashSet<int> { 1, 2, 3 }), "Minimum must include only available claims.");
        Assert.IsTrue(unavailable.SetEquals(new HashSet<int> { 6, 7 }), "Unavailable claims must be reported.");
    }


    [TestMethod]
    public void ComputeMinimumDisclosureHandlesMandatoryInRequest()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 1, 3 };

        var (disclosures, unavailable) = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeMinimumDisclosure(lattice, requested);

        Assert.IsTrue(disclosures.SetEquals(new HashSet<int> { 1, 2, 3 }), "Requesting mandatory claim must not cause issues.");
        Assert.IsEmpty(unavailable, "No unavailable claims when requesting existing claims.");
    }


    [TestMethod]
    public void ComputeMaximumDisclosureReturnsAllMinusExclusions()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var exclusions = new HashSet<int> { 4, 5 };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeMaximumDisclosure(lattice, exclusions);

        Assert.IsTrue(result.SetEquals(new HashSet<int> { 1, 2, 3 }), "Maximum must exclude user exclusions.");
    }


    [TestMethod]
    public void ComputeMaximumDisclosureIgnoresMandatoryExclusions()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var exclusions = new HashSet<int> { 1, 4 };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeMaximumDisclosure(lattice, exclusions);

        Assert.Contains(1, result, "User cannot exclude mandatory claim 1.");
        Assert.DoesNotContain(4, result, "User can exclude selectable claim 4.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureSatisfiesWhenNoConflict()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 3 };
        var exclusions = new HashSet<int> { 5 };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeOptimalDisclosure(lattice, requested, exclusions);

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

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeOptimalDisclosure(lattice, requested, exclusions);

        Assert.IsFalse(result.SatisfiesRequirements, "Requirements must not be satisfied when conflict exists.");
        Assert.IsNotNull(result.ConflictingClaims, "Conflicting claims must be reported.");
        Assert.Contains(4, result.ConflictingClaims, "Claim 4 must be in conflicts.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureReturnsUnavailableClaims()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 3, 6 };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeOptimalDisclosure(lattice, requested);

        Assert.IsFalse(result.SatisfiesRequirements, "Requirements not fully satisfied when claims unavailable.");
        Assert.IsNotNull(result.UnavailableClaims, "Unavailable claims must be reported.");
        Assert.Contains(6, result.UnavailableClaims, "Claim 6 must be unavailable.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureHandlesMandatoryInRequest()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 1, 2, 3 };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeOptimalDisclosure(lattice, requested);

        Assert.IsTrue(result.SatisfiesRequirements, "Requesting mandatory claims must succeed.");
        Assert.IsTrue(result.SelectedClaims.SetEquals(new HashSet<int> { 1, 2, 3 }), "Selected must include all requested.");
    }


    [TestMethod]
    public void ComputeOptimalDisclosureWithNullInputsReturnsOnlyMandatory()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ComputeOptimalDisclosure(lattice);

        Assert.IsTrue(result.SatisfiesRequirements, "No requirements means satisfied.");
        Assert.IsTrue(result.SelectedClaims.SetEquals(new HashSet<int> { 1, 2 }), "Only mandatory claims when no request.");
    }


    [TestMethod]
    public void ValidateDisclosureReturnsTrueForValidSet()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var disclosures = new HashSet<int> { 1, 2, 3 };
        var requirements = new HashSet<int> { 3 };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ValidateDisclosure(lattice, disclosures, requirements);

        Assert.IsTrue(result, "Valid disclosure satisfying requirements must validate.");
    }


    [TestMethod]
    public void ValidateDisclosureReturnsFalseWhenMissingRequired()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var disclosures = new HashSet<int> { 1, 2, 3 };
        var requirements = new HashSet<int> { 3, 4 };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ValidateDisclosure(lattice, disclosures, requirements);

        Assert.IsFalse(result, "Disclosure missing required claim must fail validation.");
    }


    [TestMethod]
    public void ValidateDisclosureReturnsFalseWhenMissingMandatory()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var disclosures = new HashSet<int> { 1, 3 };
        var requirements = new HashSet<int> { 3 };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.ValidateDisclosure(lattice, disclosures, requirements);

        Assert.IsFalse(result, "Disclosure missing mandatory claim must fail validation.");
    }


    [TestMethod]
    public void SelectCredentialsFindsBestCombination()
    {
        var lattice1 = new SetDisclosureLattice<string>(["name", "email"], ["name"]);
        var lattice2 = new SetDisclosureLattice<string>(["phone", "address"], []);

        var credentials = new List<(string Credential, IBoundedDisclosureLattice<string> Lattice)>
    {
        ("cred1", lattice1),
        ("cred2", lattice2)
    };

        var requirements = new HashSet<string> { "email", "phone" };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.SelectCredentials(credentials, requirements);

        Assert.IsTrue(result.SatisfiesAllRequirements, "Both requirements must be satisfied.");
        Assert.HasCount(2, result.Selections, "Two credentials must be selected.");
    }


    [TestMethod]
    public void SelectCredentialsReportsUnsatisfiedRequirements()
    {
        var lattice1 = new SetDisclosureLattice<string>(["name", "email"], ["name"]);

        var credentials = new List<(string Credential, IBoundedDisclosureLattice<string> Lattice)>
    {
        ("cred1", lattice1)
    };

        var requirements = new HashSet<string> { "email", "phone" };

        var result = Core.SelectiveDisclosure.SelectiveDisclosure.SelectCredentials(credentials, requirements);

        Assert.IsFalse(result.SatisfiesAllRequirements, "Phone requirement cannot be satisfied.");
        Assert.IsNotNull(result.UnsatisfiedRequirements, "Unsatisfied requirements must be reported.");
        Assert.Contains("phone", result.UnsatisfiedRequirements, "Phone must be unsatisfied.");
    }
}
