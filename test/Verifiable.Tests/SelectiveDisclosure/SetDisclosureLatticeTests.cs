using Verifiable.Core.SelectiveDisclosure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for <see cref="SetDisclosureLattice{TClaim}"/>.
/// </summary>
[TestClass]
public sealed class SetDisclosureLatticeTests
{
    public TestContext TestContext { get; set; } = null!;


    [TestMethod]
    public void ConstructorSetsTopBottomAndSelectable()
    {
        var allClaims = new HashSet<int> { 1, 2, 3, 4, 5 };
        var mandatoryClaims = new HashSet<int> { 1, 2 };

        var lattice = new SetDisclosureLattice<int>(allClaims, mandatoryClaims);

        Assert.HasCount(5, lattice.Top, "Top must contain all claims.");
        Assert.HasCount(2, lattice.Bottom, "Bottom must contain mandatory claims.");
        Assert.HasCount(3, lattice.Selectable, "Selectable must be Top minus Bottom.");
        Assert.IsTrue(lattice.Selectable.SetEquals(new HashSet<int> { 3, 4, 5 }), "Selectable must contain non-mandatory claims.");
    }


    [TestMethod]
    public void ConstructorThrowsWhenMandatoryNotSubsetOfAll()
    {
        var allClaims = new HashSet<int> { 1, 2, 3 };
        var mandatoryClaims = new HashSet<int> { 1, 4 };

        Assert.Throws<ArgumentException>(() => new SetDisclosureLattice<int>(allClaims, mandatoryClaims));
    }


    [TestMethod]
    public void ConstructorAllowsEmptyMandatory()
    {
        var allClaims = new HashSet<int> { 1, 2, 3 };
        var mandatoryClaims = new HashSet<int>();

        var lattice = new SetDisclosureLattice<int>(allClaims, mandatoryClaims);

        Assert.IsEmpty(lattice.Bottom, "Bottom must be empty when no mandatory claims.");
        Assert.HasCount(3, lattice.Selectable, "All claims must be selectable when no mandatory.");
    }


    [TestMethod]
    public void JoinReturnsUnion()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], []);
        var a = new HashSet<int> { 1, 2 };
        var b = new HashSet<int> { 2, 3 };

        var result = lattice.Join(a, b);

        Assert.IsTrue(result.SetEquals(new HashSet<int> { 1, 2, 3 }), "Join must be union of sets.");
    }


    [TestMethod]
    public void MeetReturnsIntersection()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], []);
        var a = new HashSet<int> { 1, 2, 3 };
        var b = new HashSet<int> { 2, 3, 4 };

        var result = lattice.Meet(a, b);

        Assert.IsTrue(result.SetEquals(new HashSet<int> { 2, 3 }), "Meet must be intersection of sets.");
    }


    [TestMethod]
    public void LessOrEqualReturnsTrueForSubset()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], []);
        var a = new HashSet<int> { 1, 2 };
        var b = new HashSet<int> { 1, 2, 3 };

        Assert.IsTrue(lattice.LessOrEqual(a, b), "Subset must be less or equal.");
        Assert.IsFalse(lattice.LessOrEqual(b, a), "Superset must not be less or equal.");
    }


    [TestMethod]
    public void IsValidReturnsTrueWhenWithinBounds()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        Assert.IsTrue(lattice.IsValid(new HashSet<int> { 1, 2 }), "Bottom must be valid.");
        Assert.IsTrue(lattice.IsValid(new HashSet<int> { 1, 2, 3, 4, 5 }), "Top must be valid.");
        Assert.IsTrue(lattice.IsValid(new HashSet<int> { 1, 2, 3 }), "Set between Bottom and Top must be valid.");
    }


    [TestMethod]
    public void IsValidReturnsFalseWhenMissingMandatory()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        Assert.IsFalse(lattice.IsValid(new HashSet<int> { 1, 3 }), "Missing mandatory claim 2 must be invalid.");
        Assert.IsFalse(lattice.IsValid(new HashSet<int> { 3, 4, 5 }), "Missing all mandatory claims must be invalid.");
    }


    [TestMethod]
    public void IsValidReturnsFalseWhenExceedsTop()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        Assert.IsFalse(lattice.IsValid(new HashSet<int> { 1, 2, 6 }), "Claim outside Top must be invalid.");
    }


    [TestMethod]
    public void NormalizeRequestCategorizesClaimsCorrectly()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 1, 3, 6 };

        var result = lattice.NormalizeRequest(requested);

        Assert.IsTrue(result.MandatoryClaims.SetEquals(new HashSet<int> { 1 }), "Claim 1 is mandatory.");
        Assert.IsTrue(result.SelectableClaims.SetEquals(new HashSet<int> { 3 }), "Claim 3 is selectable.");
        Assert.IsTrue(result.UnavailableClaims.SetEquals(new HashSet<int> { 6 }), "Claim 6 is unavailable.");
    }


    [TestMethod]
    public void NormalizeRequestReturnsEmptySetsForNullRequest()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        var result = lattice.NormalizeRequest(null);

        Assert.IsEmpty(result.SelectableClaims, "Selectable must be empty for null request.");
        Assert.IsEmpty(result.MandatoryClaims, "Mandatory must be empty for null request.");
        Assert.IsEmpty(result.UnavailableClaims, "Unavailable must be empty for null request.");
    }


    [TestMethod]
    public void NormalizeRequestCanSatisfyIsTrueWhenNoUnavailable()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);

        var satisfiable = lattice.NormalizeRequest(new HashSet<int> { 1, 3, 4 });
        var unsatisfiable = lattice.NormalizeRequest(new HashSet<int> { 1, 3, 6 });

        Assert.IsTrue(satisfiable.CanSatisfy, "Request with only available claims can be satisfied.");
        Assert.IsFalse(unsatisfiable.CanSatisfy, "Request with unavailable claims cannot be fully satisfied.");
    }


    [TestMethod]
    public void NormalizeRequestEffectiveClaimsReturnsUnion()
    {
        var lattice = new SetDisclosureLattice<int>([1, 2, 3, 4, 5], [1, 2]);
        var requested = new HashSet<int> { 1, 3, 6 };

        var result = lattice.NormalizeRequest(requested);

        Assert.IsTrue(result.EffectiveClaims.SetEquals(new HashSet<int> { 1, 3 }), "Effective claims must be mandatory plus selectable.");
    }


    [TestMethod]
    public void LatticeWorksWithStringClaims()
    {
        var allClaims = new HashSet<string> { "name", "email", "phone", "address" };
        var mandatoryClaims = new HashSet<string> { "name" };

        var lattice = new SetDisclosureLattice<string>(allClaims, mandatoryClaims);

        Assert.HasCount(4, lattice.Top, "Top must contain all string claims.");
        Assert.HasCount(1, lattice.Bottom, "Bottom must contain mandatory string claims.");
        Assert.HasCount(3, lattice.Selectable, "Selectable must contain non-mandatory string claims.");

        var normalized = lattice.NormalizeRequest(new HashSet<string> { "name", "email", "unknown" });

        Assert.Contains("name", normalized.MandatoryClaims, "Name must be mandatory.");
        Assert.Contains("email", normalized.SelectableClaims, "Email must be selectable.");
        Assert.Contains("unknown", normalized.UnavailableClaims, "Unknown must be unavailable.");
    }


    [TestMethod]
    public void LatticeUsesCustomComparer()
    {
        var allClaims = new HashSet<string> { "Name", "Email" };
        var mandatoryClaims = new HashSet<string> { "name" };

        var lattice = new SetDisclosureLattice<string>(
            allClaims,
            mandatoryClaims,
            StringComparer.OrdinalIgnoreCase);

        Assert.HasCount(1, lattice.Bottom, "Case-insensitive comparer must match 'name' with 'Name'.");
        Assert.Contains("Name", lattice.Bottom, "Bottom must contain 'Name' via case-insensitive match.");
    }
}