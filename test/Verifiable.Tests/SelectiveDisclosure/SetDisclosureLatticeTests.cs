using CsCheck;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Tests for <see cref="SetDisclosureLattice{TClaim}"/>.
/// </summary>
[TestClass]
internal sealed class SetDisclosureLatticeTests
{
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A lattice over the universe {0..9}. The <see cref="SetDisclosureLattice{TClaim}.Join"/>,
    /// <see cref="SetDisclosureLattice{TClaim}.Meet"/> and
    /// <see cref="SetDisclosureLattice{TClaim}.LessOrEqual"/> operations are pure set
    /// operations independent of Top/Bottom, so a fixed universe suffices for the
    /// algebraic laws below.
    /// </summary>
    private static SetDisclosureLattice<int> Universe { get; } =
        new([0, 1, 2, 3, 4, 5, 6, 7, 8, 9], []);


    /// <summary>Generates arbitrary subsets of the {0..9} universe.</summary>
    private static Gen<IReadOnlySet<int>> SubsetGen { get; } =
        Gen.Int[0, 9].Array[0, 10].Select(xs => (IReadOnlySet<int>)new HashSet<int>(xs));


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
    public void JoinAndMeetAreIdempotent()
    {
        SubsetGen.Sample(a =>
        {
            Assert.IsTrue(Universe.Join(a, a).SetEquals(a), "Join must be idempotent: a ∨ a = a.");
            Assert.IsTrue(Universe.Meet(a, a).SetEquals(a), "Meet must be idempotent: a ∧ a = a.");
        });
    }


    [TestMethod]
    public void JoinAndMeetAreCommutative()
    {
        Gen.Select(SubsetGen, SubsetGen, (a, b) => (a, b)).Sample(pair =>
        {
            var (a, b) = pair;

            Assert.IsTrue(Universe.Join(a, b).SetEquals(Universe.Join(b, a)), "Join must be commutative: a ∨ b = b ∨ a.");
            Assert.IsTrue(Universe.Meet(a, b).SetEquals(Universe.Meet(b, a)), "Meet must be commutative: a ∧ b = b ∧ a.");
        });
    }


    [TestMethod]
    public void JoinAndMeetAreAssociative()
    {
        Gen.Select(SubsetGen, SubsetGen, SubsetGen, (a, b, c) => (a, b, c)).Sample(triple =>
        {
            var (a, b, c) = triple;

            var joinLeft = Universe.Join(Universe.Join(a, b), c);
            var joinRight = Universe.Join(a, Universe.Join(b, c));
            Assert.IsTrue(joinLeft.SetEquals(joinRight), "Join must be associative: (a ∨ b) ∨ c = a ∨ (b ∨ c).");

            var meetLeft = Universe.Meet(Universe.Meet(a, b), c);
            var meetRight = Universe.Meet(a, Universe.Meet(b, c));
            Assert.IsTrue(meetLeft.SetEquals(meetRight), "Meet must be associative: (a ∧ b) ∧ c = a ∧ (b ∧ c).");
        });
    }


    [TestMethod]
    public void JoinAndMeetSatisfyAbsorption()
    {
        Gen.Select(SubsetGen, SubsetGen, (a, b) => (a, b)).Sample(pair =>
        {
            var (a, b) = pair;

            Assert.IsTrue(Universe.Join(a, Universe.Meet(a, b)).SetEquals(a), "Absorption: a ∨ (a ∧ b) = a.");
            Assert.IsTrue(Universe.Meet(a, Universe.Join(a, b)).SetEquals(a), "Absorption: a ∧ (a ∨ b) = a.");
        });
    }


    [TestMethod]
    public void LessOrEqualIsConsistentWithJoinAndMeet()
    {
        Gen.Select(SubsetGen, SubsetGen, (a, b) => (a, b)).Sample(pair =>
        {
            var (a, b) = pair;
            bool aLeB = Universe.LessOrEqual(a, b);

            //In any lattice: a ≤ b ⟺ a ∧ b = a ⟺ a ∨ b = b.
            Assert.AreEqual(aLeB, Universe.Meet(a, b).SetEquals(a), "a ≤ b must coincide with a ∧ b = a.");
            Assert.AreEqual(aLeB, Universe.Join(a, b).SetEquals(b), "a ≤ b must coincide with a ∨ b = b.");
        });
    }


    [TestMethod]
    public void JoinWithEmptyAndMeetWithUniverseAreIdentities()
    {
        var empty = (IReadOnlySet<int>)new HashSet<int>();

        SubsetGen.Sample(a =>
        {
            Assert.IsTrue(Universe.Join(a, empty).SetEquals(a), "Empty set is the identity for Join: a ∨ ∅ = a.");
            Assert.IsTrue(Universe.Meet(a, Universe.Top).SetEquals(a), "The universe is the identity for Meet over its subsets: a ∧ ⊤ = a.");
        });
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
