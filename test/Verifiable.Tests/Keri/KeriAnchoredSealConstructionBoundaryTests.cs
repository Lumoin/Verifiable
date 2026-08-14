using System.Linq;
using System.Reflection;
using Verifiable.Keri;

namespace Verifiable.Tests.Keri;

/// <summary>
/// The construction-boundary proof for <see cref="KeriAnchoredSeal"/>: the
/// (Aid, Seal) pairing an ACDC-to-KERI issuer binding mints from MUST be producible only by an actual KEL replay
/// (<see cref="KeriIssuerAnchors.ReplayAsync"/>), never hand-built by a caller — the exact shape an earlier
/// attempt left open (a public <c>issuerAnchors</c> parameter a caller fed with a hand-built anchor,
/// forging a <c>Bound</c> naming a victim AID with no KEL and no key). Checked via reflection, since a
/// negative-compilation claim ("<c>new KeriAnchoredSeal(...)</c> does not compile") has no direct expression
/// inside an MSTest method body — mirroring <c>JAdESPromotionDisciplineTests</c>' own template for the same class
/// of claim.
/// </summary>
[TestClass]
internal sealed class KeriAnchoredSealConstructionBoundaryTests
{
    /// <summary>
    /// <see cref="KeriAnchoredSeal"/> has no public constructor: an external assembly cannot wrap an AID and a
    /// seal into one — however innocuous the AID looks — without first running an actual KEL replay.
    /// </summary>
    [TestMethod]
    public void KeriAnchoredSealHasNoPublicConstructor()
    {
        ConstructorInfo[] constructors = typeof(KeriAnchoredSeal).GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);

        Assert.IsGreaterThan(0, constructors.Length);
        Assert.IsTrue(constructors.All(static c => !c.IsPublic),
            "KeriAnchoredSeal's constructor must stay non-public -- a public constructor would let any caller assert an AID for a seal it never replayed.");
    }


    /// <summary>
    /// <see cref="KeriAnchoredSeal"/>'s sole minting factory, <c>Create</c>, is <see langword="internal"/> — not
    /// public — and it is called only from within <c>Verifiable.Keri</c> itself
    /// (<see cref="KeriIssuerAnchors.ReplayAsync"/>). <c>Verifiable.Keri</c> grants no <c>InternalsVisibleTo</c>
    /// to <c>Verifiable.Acdc</c>, so the ACDC layer — and every downstream consumer — can obtain a
    /// <see cref="KeriAnchoredSeal"/> only by calling <see cref="KeriIssuerAnchors.ReplayAsync"/> and letting a
    /// real KEL verify, never by constructing or minting one directly.
    /// </summary>
    [TestMethod]
    public void KeriAnchoredSealFactoryIsNotPublic()
    {
        MethodInfo? factory = typeof(KeriAnchoredSeal).GetMethod("Create", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);

        Assert.IsNotNull(factory, "KeriAnchoredSeal must expose exactly the Create factory KeriIssuerAnchors.ReplayAsync mints through.");
        Assert.IsFalse(factory!.IsPublic, "Create must stay non-public -- minting an anchored seal is KeriIssuerAnchors.ReplayAsync's exclusive responsibility.");
    }
}
