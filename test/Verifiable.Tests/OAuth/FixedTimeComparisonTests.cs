using Verifiable.OAuth;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Pins the equality semantics of <see cref="FixedTimeComparison"/> — the fixed-time
/// property is not observable in a unit test, but the comparison must agree with
/// ordinal equality on every input class so swapping it in changes timing only.
/// </summary>
[TestClass]
internal sealed class FixedTimeComparisonTests
{
    [TestMethod]
    public void AgreesWithOrdinalEqualityOnEveryInputClass()
    {
        Assert.IsTrue(FixedTimeComparison.AreEqual(null, null),
            "Two nulls compare equal.");
        Assert.IsFalse(FixedTimeComparison.AreEqual(null, "a"),
            "Null and non-null compare unequal.");
        Assert.IsFalse(FixedTimeComparison.AreEqual("a", null),
            "Non-null and null compare unequal.");
        Assert.IsTrue(FixedTimeComparison.AreEqual(string.Empty, string.Empty),
            "Two empty strings compare equal.");
        Assert.IsTrue(FixedTimeComparison.AreEqual("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
            "Identical values compare equal.");
        Assert.IsFalse(FixedTimeComparison.AreEqual("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cN"),
            "A single differing character compares unequal.");
        Assert.IsFalse(FixedTimeComparison.AreEqual("short", "short-but-longer"),
            "Different lengths compare unequal.");
        Assert.IsFalse(FixedTimeComparison.AreEqual("a", "A"),
            "The comparison is case-sensitive, matching ordinal semantics.");
    }
}
