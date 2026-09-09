using System;
using System.IO;
using System.Text.RegularExpressions;
using Verifiable.Keri;
using Verifiable.Tests.Foundation;

namespace Verifiable.Tests.Keri;

/// <summary>
/// The construction-boundary proof for <see cref="KeriAnchoredSeal"/>: the
/// (Aid, Seal) pairing an ACDC-to-KERI issuer binding mints from MUST be producible only by an actual KEL replay
/// (<see cref="KeriIssuerAnchors.ReplayAsync"/>), never hand-built by a caller — the exact shape an earlier
/// attempt left open (a public <c>issuerAnchors</c> parameter a caller fed with a hand-built anchor,
/// forging a <c>Bound</c> naming a victim AID with no KEL and no key). Checked as a source scan of the
/// declaring file's own constructor and factory declaration lines, since a negative-compilation claim
/// ("<c>new KeriAnchoredSeal(...)</c> does not compile") has no direct expression inside an MSTest method body
/// — mirroring <c>JAdESPromotionDisciplineTests</c>' own template for the same class of claim.
/// </summary>
[TestClass]
internal sealed class KeriAnchoredSealConstructionBoundaryTests
{
    /// <summary>The repository-relative path declaring <see cref="KeriAnchoredSeal"/>.</summary>
    private const string KeriAnchoredSealPath = "src/Verifiable.Keri/KeriAnchoredSeal.cs";


    /// <summary>
    /// <see cref="KeriAnchoredSeal"/> has no public constructor: an external assembly cannot wrap an AID and a
    /// seal into one — however innocuous the AID looks — without first running an actual KEL replay.
    /// </summary>
    [TestMethod]
    public void KeriAnchoredSealHasNoPublicConstructor()
    {
        string text = File.ReadAllText(Path.Combine(SourceHygieneScanner.FindRepositoryRoot(), KeriAnchoredSealPath));

        Assert.IsFalse(
            Regex.IsMatch(text, @"(?m)^\s*public\s+KeriAnchoredSeal\s*\("),
            "KeriAnchoredSeal must declare no public constructor -- a public one would let any caller assert an AID for a seal it never replayed.");
        Assert.IsTrue(
            Regex.IsMatch(text, @"(?m)^\s*private\s+KeriAnchoredSeal\s*\("),
            "KeriAnchoredSeal must declare a private constructor.");
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
        string text = File.ReadAllText(Path.Combine(SourceHygieneScanner.FindRepositoryRoot(), KeriAnchoredSealPath));

        Assert.IsFalse(
            Regex.IsMatch(text, @"(?m)^\s*public\s+static\s+\S.*\bCreate\s*\("),
            "Create must stay non-public -- minting an anchored seal is KeriIssuerAnchors.ReplayAsync's exclusive responsibility.");
        Assert.IsTrue(
            Regex.IsMatch(text, @"(?m)^\s*internal\s+static\s+\S.*\bCreate\s*\("),
            "KeriAnchoredSeal must expose exactly the internal Create factory KeriIssuerAnchors.ReplayAsync mints through.");
    }

}
