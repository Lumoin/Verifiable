using CsCheck;
using Verifiable.Core.Model.SelectiveDisclosure;

namespace Verifiable.Tests.SelectiveDisclosure;

/// <summary>
/// Property-based tests (CsCheck) for <see cref="SetDisclosureLattice{TClaim}"/>: the algebraic lattice
/// laws (idempotence, commutativity, associativity, absorption, the order-join-meet correspondence and the
/// empty-set/universe identities) that must hold for every subset of the universe, not just the hand-picked
/// sets in <see cref="SetDisclosureLatticeTests"/>.
/// </summary>
[TestClass]
internal sealed class SetDisclosureLatticePropertyTests
{
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
}
