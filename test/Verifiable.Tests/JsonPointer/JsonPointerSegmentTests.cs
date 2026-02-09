using Verifiable.JsonPointer;
using Seg = Verifiable.JsonPointer.JsonPointerSegment;

namespace Verifiable.Tests.JsonPointer;

[TestClass]
internal sealed class JsonPointerSegmentTests
{
    [TestMethod]
    public void CreateStoresToken()
    {
        var segment = Seg.Create("name");

        Assert.AreEqual("name", segment.Value);
    }

    [TestMethod]
    public void CreateAcceptsEmptyString()
    {
        var segment = Seg.Create("");

        Assert.AreEqual("", segment.Value);
    }

    [TestMethod]
    public void CreateThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => Seg.Create(null!));
    }

    [TestMethod]
    public void FromIndexStoresTokenAsDecimalString()
    {
        var segment = Seg.FromIndex(42);

        Assert.AreEqual("42", segment.Value);
    }

    [TestMethod]
    public void FromIndexAcceptsZero()
    {
        var segment = Seg.FromIndex(0);

        Assert.AreEqual("0", segment.Value);
    }

    [TestMethod]
    public void FromIndexThrowsOnNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Seg.FromIndex(-1));
    }

    [TestMethod]
    public void AppendMarkerValueIsDash()
    {
        Assert.AreEqual("-", Seg.AppendMarker.Value);
        Assert.IsTrue(Seg.AppendMarker.IsAppendMarker);
    }

    [TestMethod]
    public void IsAppendMarkerTrueOnlyForDash()
    {
        Assert.IsTrue(Seg.Create("-").IsAppendMarker);
        Assert.IsFalse(Seg.Create("name").IsAppendMarker);
        Assert.IsFalse(Seg.Create("0").IsAppendMarker);
        Assert.IsFalse(Seg.Create("").IsAppendMarker);
    }

    [TestMethod]
    public void TryGetArrayIndexSucceedsForValidIndexes()
    {
        Assert.IsTrue(Seg.Create("0").TryGetArrayIndex(out int zero));
        Assert.AreEqual(0, zero);

        Assert.IsTrue(Seg.Create("5").TryGetArrayIndex(out int five));
        Assert.AreEqual(5, five);

        Assert.IsTrue(Seg.Create("123").TryGetArrayIndex(out int onetwothree));
        Assert.AreEqual(123, onetwothree);
    }

    [TestMethod]
    public void TryGetArrayIndexFailsForNonNumericTokens()
    {
        Assert.IsFalse(Seg.Create("name").TryGetArrayIndex(out _));
        Assert.IsFalse(Seg.Create("").TryGetArrayIndex(out _));
        Assert.IsFalse(Seg.Create("-").TryGetArrayIndex(out _));
        Assert.IsFalse(Seg.Create("abc123").TryGetArrayIndex(out _));
    }

    [TestMethod]
    public void TryGetArrayIndexRejectsLeadingZeros()
    {
        Assert.IsFalse(Seg.Create("01").TryGetArrayIndex(out _));
        Assert.IsFalse(Seg.Create("007").TryGetArrayIndex(out _));
    }

    [TestMethod]
    public void CanBeArrayIndexMatchesTryGetArrayIndex()
    {
        Assert.IsTrue(Seg.Create("0").CanBeArrayIndex);
        Assert.IsTrue(Seg.Create("42").CanBeArrayIndex);
        Assert.IsFalse(Seg.Create("name").CanBeArrayIndex);
        Assert.IsFalse(Seg.Create("01").CanBeArrayIndex);
        Assert.IsFalse(Seg.Create("-").CanBeArrayIndex);
    }

    [TestMethod]
    public void ToEscapedStringEscapesTildeAndSlash()
    {
        var segment = Seg.Create("a/b~c");

        Assert.Contains("~1", segment.ToEscapedString());
        Assert.Contains("~0", segment.ToEscapedString());
    }

    [TestMethod]
    public void ToEscapedStringReturnsTokenUnchangedWhenNoSpecialChars()
    {
        var segment = Seg.Create("simple");

        Assert.AreEqual("simple", segment.ToEscapedString());
    }

    [TestMethod]
    public void ToStringReturnsRawToken()
    {
        Assert.AreEqual("name", Seg.Create("name").ToString());
        Assert.AreEqual("42", Seg.FromIndex(42).ToString());
        Assert.AreEqual("-", Seg.AppendMarker.ToString());
        Assert.AreEqual("a/b", Seg.Create("a/b").ToString());
    }

    [TestMethod]
    public void EqualSegmentsAreEqual()
    {
        var a = Seg.Create("name");
        var b = Seg.Create("name");

        Assert.IsTrue(a.Equals(b));
        Assert.IsTrue(a == b);
        Assert.IsFalse(a != b);
        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
    }

    [TestMethod]
    public void DifferentSegmentsAreNotEqual()
    {
        var a = Seg.Create("name");
        var b = Seg.Create("other");

        Assert.IsFalse(a.Equals(b));
        Assert.IsTrue(a != b);
    }

    [TestMethod]
    public void NumericTokenEqualsByStringValue()
    {
        //Both "0" whether created via Create or FromIndex.
        var fromString = Seg.Create("0");
        var fromIndex = Seg.FromIndex(0);

        Assert.AreEqual(fromString, fromIndex);
        Assert.AreEqual(fromString.GetHashCode(), fromIndex.GetHashCode());
    }

    [TestMethod]
    public void EqualsObjectOverload()
    {
        var a = Seg.Create("name");
        object b = Seg.Create("name");
        object c = "not a segment";

        Assert.IsTrue(a.Equals(b));
        Assert.IsFalse(a.Equals(c));
        Assert.IsFalse(a.Equals((object?)null));
    }

    [TestMethod]
    public void CompareToUsesOrdinalStringComparison()
    {
        var apple = Seg.Create("apple");
        var banana = Seg.Create("banana");

        Assert.IsLessThan(0, apple.CompareTo(banana));
        Assert.IsGreaterThan(0, banana.CompareTo(apple));
        Assert.AreEqual(0, apple.CompareTo(Seg.Create("apple")));
    }

    [TestMethod]
    public void ComparisonOperatorsWork()
    {
        var a = Seg.Create("a");
        var b = Seg.Create("b");

        Assert.IsTrue(a < b);
        Assert.IsTrue(a <= b);
        Assert.IsTrue(b > a);
        Assert.IsTrue(b >= a);
        Assert.IsTrue(a <= Seg.Create("a"));
        Assert.IsTrue(a >= Seg.Create("a"));
    }

    [TestMethod]
    public void ImplicitConversionFromStringCreatesSegment()
    {
        Seg segment = "name";

        Assert.AreEqual("name", segment.Value);
    }

    [TestMethod]
    public void ImplicitConversionFromIntCreatesSegment()
    {
        Seg segment = 3;

        Assert.AreEqual("3", segment.Value);
    }
}