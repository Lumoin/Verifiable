using Verifiable.JsonPointer;
using Ptr = Verifiable.JsonPointer.JsonPointer;
using Seg = Verifiable.JsonPointer.JsonPointerSegment;

namespace Verifiable.Tests.JsonPointer;

[TestClass]
internal sealed class JsonPointerTests
{
    [TestMethod]
    public void ParseEmptyStringReturnsRoot()
    {
        var pointer = Ptr.Parse("");

        Assert.IsTrue(pointer.IsRoot);
        Assert.AreEqual(0, pointer.Depth);
        Assert.AreEqual("", pointer.ToString());
    }

    [TestMethod]
    public void ParseSingleSlashReturnsEmptyTokenSegment()
    {
        var pointer = Ptr.Parse("/");

        Assert.AreEqual(1, pointer.Depth);
        Assert.AreEqual("", pointer.Segments[0].Value);
    }

    [TestMethod]
    public void ParsePropertyPath()
    {
        var pointer = Ptr.Parse("/foo/bar");

        Assert.AreEqual(2, pointer.Depth);
        Assert.AreEqual("foo", pointer.Segments[0].Value);
        Assert.AreEqual("bar", pointer.Segments[1].Value);
    }

    [TestMethod]
    public void ParseNumericTokensAsTokens()
    {
        var pointer = Ptr.Parse("/items/0/name");

        Assert.AreEqual(3, pointer.Depth);
        Assert.AreEqual("items", pointer.Segments[0].Value);
        Assert.AreEqual("0", pointer.Segments[1].Value);
        Assert.IsTrue(pointer.Segments[1].CanBeArrayIndex);
        Assert.AreEqual("name", pointer.Segments[2].Value);
    }

    [TestMethod]
    public void ParseAppendMarker()
    {
        var pointer = Ptr.Parse("/items/-");

        Assert.AreEqual(2, pointer.Depth);
        Assert.IsTrue(pointer.Segments[1].IsAppendMarker);
    }

    [TestMethod]
    public void ParseUnescapesTildeSequences()
    {
        var pointer = Ptr.Parse("/a~1b/c~0d");

        Assert.AreEqual("a/b", pointer.Segments[0].Value);
        Assert.AreEqual("c~d", pointer.Segments[1].Value);
    }

    [TestMethod]
    public void ParseThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => Ptr.Parse(null!));
    }

    [TestMethod]
    public void ParseThrowsOnMissingLeadingSlash()
    {
        Assert.Throws<FormatException>(() => Ptr.Parse("foo"));
    }

    [TestMethod]
    public void ParseLeadingZeroAsToken()
    {
        var pointer = Ptr.Parse("/01");

        //Stored as raw token; TryGetArrayIndex rejects leading zeros.
        Assert.AreEqual("01", pointer.Segments[0].Value);
        Assert.IsFalse(pointer.Segments[0].CanBeArrayIndex);
    }

    [TestMethod]
    public void ParseInvalidEscapeThrows()
    {
        Assert.Throws<FormatException>(() => Ptr.Parse("/a~2b"));
    }

    [TestMethod]
    public void ParseTrailingTildeThrows()
    {
        Assert.Throws<FormatException>(() => Ptr.Parse("/a~"));
    }

    [TestMethod]
    public void TryParseReturnsTrueForValidPointer()
    {
        bool success = Ptr.TryParse("/foo/0", out var result);

        Assert.IsTrue(success);
        Assert.AreEqual(2, result.Depth);
    }

    [TestMethod]
    public void TryParseReturnsTrueForEmptyString()
    {
        bool success = Ptr.TryParse("", out var result);

        Assert.IsTrue(success);
        Assert.IsTrue(result.IsRoot);
    }

    [TestMethod]
    public void TryParseReturnsFalseForNull()
    {
        Assert.IsFalse(Ptr.TryParse(null, out _));
    }

    [TestMethod]
    public void TryParseReturnsFalseForMissingSlash()
    {
        Assert.IsFalse(Ptr.TryParse("noslash", out _));
    }

    [TestMethod]
    public void TryParseReturnsFalseForInvalidEscape()
    {
        Assert.IsFalse(Ptr.TryParse("/a~2b", out _));
    }

    [TestMethod]
    public void ToStringPreservesEscaping()
    {
        var pointer = Ptr.Parse("/a~1b/0/c~0d");

        Assert.AreEqual("/a~1b/0/c~0d", pointer.ToString());
    }

    [TestMethod]
    public void ToStringRootReturnsEmptyString()
    {
        Assert.AreEqual("", Ptr.Root.ToString());
    }

    [TestMethod]
    public void FromSegmentsEmptyReturnsRoot()
    {
        Assert.IsTrue(Ptr.FromSegments([]).IsRoot);
    }

    [TestMethod]
    public void FromSegmentsCreatesPointerWithCorrectDepth()
    {
        Seg[] segments = [Seg.Create("a"), Seg.FromIndex(1)];
        var pointer = Ptr.FromSegments(segments);

        Assert.AreEqual(2, pointer.Depth);
        Assert.AreEqual("a", pointer.Segments[0].Value);
        Assert.AreEqual("1", pointer.Segments[1].Value);
    }

    [TestMethod]
    public void FromPropertyCreatesSingleSegmentPointer()
    {
        var pointer = Ptr.FromProperty("name");

        Assert.AreEqual(1, pointer.Depth);
        Assert.AreEqual("name", pointer.Segments[0].Value);
    }

    [TestMethod]
    public void FromPropertyThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => Ptr.FromProperty(null!));
    }

    [TestMethod]
    public void FromIndexCreatesSingleSegmentPointer()
    {
        var pointer = Ptr.FromIndex(5);

        Assert.AreEqual(1, pointer.Depth);
        Assert.AreEqual("5", pointer.Segments[0].Value);
        Assert.IsTrue(pointer.Segments[0].CanBeArrayIndex);
    }

    [TestMethod]
    public void FromIndexThrowsOnNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Ptr.FromIndex(-1));
    }

    [TestMethod]
    public void ParentReturnsNullForRoot()
    {
        Assert.IsNull(Ptr.Root.Parent);
    }

    [TestMethod]
    public void ParentReturnsRootForDepthOne()
    {
        var pointer = Ptr.Parse("/foo");

        Assert.AreEqual(Ptr.Root, pointer.Parent);
    }

    [TestMethod]
    public void ParentRemovesLastSegment()
    {
        var pointer = Ptr.Parse("/foo/bar/baz");

        var parent = pointer.Parent!.Value;
        Assert.AreEqual(2, parent.Depth);
        Assert.AreEqual("/foo/bar", parent.ToString());
    }

    [TestMethod]
    public void LastSegmentReturnsNullForRoot()
    {
        Assert.IsNull(Ptr.Root.LastSegment);
    }

    [TestMethod]
    public void LastSegmentReturnsFinalSegment()
    {
        var pointer = Ptr.Parse("/foo/42");

        Assert.AreEqual("42", pointer.LastSegment!.Value.Value);
    }

    [TestMethod]
    public void AncestorsOfRootIsEmpty()
    {
        Assert.HasCount(0, Ptr.Root.Ancestors().ToList());
    }

    [TestMethod]
    public void AncestorsEnumeratesFromRootToParent()
    {
        var pointer = Ptr.Parse("/a/b/c");
        var ancestors = pointer.Ancestors().ToList();

        Assert.HasCount(3, ancestors);
        Assert.IsTrue(ancestors[0].IsRoot);
        Assert.AreEqual("/a", ancestors[1].ToString());
        Assert.AreEqual("/a/b", ancestors[2].ToString());
    }

    [TestMethod]
    public void SelfAndAncestorsIncludesSelf()
    {
        var pointer = Ptr.Parse("/a/b");
        var all = pointer.SelfAndAncestors().ToList();

        Assert.HasCount(3, all);
        Assert.IsTrue(all[0].IsRoot);
        Assert.AreEqual("/a", all[1].ToString());
        Assert.AreEqual("/a/b", all[2].ToString());
    }

    [TestMethod]
    public void AppendPropertyAddsSegment()
    {
        var pointer = Ptr.Parse("/foo");
        var result = pointer.Append("bar");

        Assert.AreEqual(2, result.Depth);
        Assert.AreEqual("/foo/bar", result.ToString());
    }

    [TestMethod]
    public void AppendIndexAddsSegment()
    {
        var pointer = Ptr.Parse("/items");
        var result = pointer.Append(3);

        Assert.AreEqual(2, result.Depth);
        Assert.AreEqual("3", result.Segments[1].Value);
    }

    [TestMethod]
    public void AppendIndexThrowsOnNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Ptr.Root.Append(-1));
    }

    [TestMethod]
    public void AppendSegmentAddsSegment()
    {
        var pointer = Ptr.Root;
        var result = pointer.Append(Seg.AppendMarker);

        Assert.AreEqual(1, result.Depth);
        Assert.IsTrue(result.Segments[0].IsAppendMarker);
    }

    [TestMethod]
    public void AppendPointerConcatenates()
    {
        var a = Ptr.Parse("/foo");
        var b = Ptr.Parse("/bar/baz");
        var result = a.Append(b);

        Assert.AreEqual(3, result.Depth);
        Assert.AreEqual("/foo/bar/baz", result.ToString());
    }

    [TestMethod]
    public void AppendRootPointerReturnsSelf()
    {
        var pointer = Ptr.Parse("/foo");
        var result = pointer.Append(Ptr.Root);

        Assert.AreEqual(pointer, result);
    }

    [TestMethod]
    public void AppendToRootReturnsOther()
    {
        var other = Ptr.Parse("/foo/bar");
        var result = Ptr.Root.Append(other);

        Assert.AreEqual(other, result);
    }

    [TestMethod]
    public void IsAncestorOfReturnsTrueForPrefix()
    {
        var ancestor = Ptr.Parse("/foo");
        var descendant = Ptr.Parse("/foo/bar/baz");

        Assert.IsTrue(ancestor.IsAncestorOf(descendant));
    }

    [TestMethod]
    public void IsAncestorOfReturnsFalseForSelf()
    {
        var pointer = Ptr.Parse("/foo");

        Assert.IsFalse(pointer.IsAncestorOf(pointer));
    }

    [TestMethod]
    public void IsAncestorOfReturnsFalseForDivergent()
    {
        var a = Ptr.Parse("/foo/bar");
        var b = Ptr.Parse("/foo/baz");

        Assert.IsFalse(a.IsAncestorOf(b));
    }

    [TestMethod]
    public void RootIsAncestorOfEverything()
    {
        Assert.IsTrue(Ptr.Root.IsAncestorOf(Ptr.Parse("/anything")));
    }

    [TestMethod]
    public void IsDescendantOfIsSymmetric()
    {
        var ancestor = Ptr.Parse("/foo");
        var descendant = Ptr.Parse("/foo/bar");

        Assert.IsTrue(descendant.IsDescendantOf(ancestor));
        Assert.IsFalse(ancestor.IsDescendantOf(descendant));
    }

    [TestMethod]
    public void IsAncestorOfOrEqualToIncludesSelf()
    {
        var pointer = Ptr.Parse("/foo");

        Assert.IsTrue(pointer.IsAncestorOfOrEqualTo(pointer));
        Assert.IsTrue(pointer.IsAncestorOfOrEqualTo(Ptr.Parse("/foo/bar")));
    }

    [TestMethod]
    public void IsDescendantOfOrEqualToIncludesSelf()
    {
        var pointer = Ptr.Parse("/foo");

        Assert.IsTrue(pointer.IsDescendantOfOrEqualTo(pointer));
        Assert.IsTrue(pointer.IsDescendantOfOrEqualTo(Ptr.Root));
    }

    [TestMethod]
    public void RelativeToReturnsRemainingSegments()
    {
        var ancestor = Ptr.Parse("/foo");
        var descendant = Ptr.Parse("/foo/bar/baz");

        var relative = descendant.RelativeTo(ancestor);

        Assert.AreEqual(2, relative.Depth);
        Assert.AreEqual("/bar/baz", relative.ToString());
    }

    [TestMethod]
    public void RelativeToSelfReturnsRoot()
    {
        var pointer = Ptr.Parse("/foo/bar");

        Assert.IsTrue(pointer.RelativeTo(pointer).IsRoot);
    }

    [TestMethod]
    public void RelativeToThrowsForNonAncestor()
    {
        var a = Ptr.Parse("/foo");
        var b = Ptr.Parse("/bar");

        Assert.Throws<ArgumentException>(() => a.RelativeTo(b));
    }

    [TestMethod]
    public void ToUriFragmentProducesHashPrefix()
    {
        var pointer = Ptr.Parse("/foo/0");

        Assert.AreEqual("#/foo/0", pointer.ToUriFragment());
    }

    [TestMethod]
    public void ToUriFragmentRootIsHash()
    {
        Assert.AreEqual("#", Ptr.Root.ToUriFragment());
    }

    [TestMethod]
    public void ToUriFragmentPercentEncodesSpecialCharacters()
    {
        var pointer = Ptr.Parse("/a b");

        Assert.Contains("%20", pointer.ToUriFragment());
    }

    [TestMethod]
    public void ParseUriFragmentRoundtrips()
    {
        var pointer = Ptr.Parse("/foo/0/bar");
        string fragment = pointer.ToUriFragment();
        var parsed = Ptr.ParseUriFragment(fragment);

        Assert.AreEqual(pointer, parsed);
    }

    [TestMethod]
    public void ParseUriFragmentThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => Ptr.ParseUriFragment(null!));
    }

    [TestMethod]
    public void ParseUriFragmentThrowsWithoutHash()
    {
        Assert.Throws<FormatException>(() => Ptr.ParseUriFragment("/foo"));
    }

    [TestMethod]
    public void TryParseUriFragmentReturnsFalseForNull()
    {
        Assert.IsFalse(Ptr.TryParseUriFragment(null, out _));
    }

    [TestMethod]
    public void TryParseUriFragmentReturnsFalseWithoutHash()
    {
        Assert.IsFalse(Ptr.TryParseUriFragment("/foo", out _));
    }

    [TestMethod]
    public void TryParseUriFragmentReturnsTrueForValid()
    {
        bool success = Ptr.TryParseUriFragment("#/foo/0", out var result);

        Assert.IsTrue(success);
        Assert.AreEqual(2, result.Depth);
    }

    [TestMethod]
    public void EscapeEncodesSpecialCharacters()
    {
        Assert.AreEqual("a~0b", Ptr.Escape("a~b"));
        Assert.AreEqual("a~1b", Ptr.Escape("a/b"));
        Assert.AreEqual("a~0~1b", Ptr.Escape("a~/b"));
    }

    [TestMethod]
    public void EscapeReturnsInputUnchangedWhenNoSpecialChars()
    {
        string input = "simple";
        Assert.AreSame(input, Ptr.Escape(input));
    }

    [TestMethod]
    public void EscapeThrowsOnNull()
    {
        Assert.Throws<ArgumentNullException>(() => Ptr.Escape(null!));
    }

    [TestMethod]
    public void EqualPointersAreEqual()
    {
        var a = Ptr.Parse("/foo/0");
        var b = Ptr.Parse("/foo/0");

        Assert.AreEqual(a, b);
        Assert.IsTrue(a == b);
        Assert.IsFalse(a != b);
        Assert.AreEqual(a.GetHashCode(), b.GetHashCode());
    }

    [TestMethod]
    public void DifferentPointersAreNotEqual()
    {
        var a = Ptr.Parse("/foo");
        var b = Ptr.Parse("/bar");

        Assert.AreNotEqual(a, b);
        Assert.IsTrue(a != b);
    }

    [TestMethod]
    public void DifferentDepthPointersAreNotEqual()
    {
        var a = Ptr.Parse("/foo");
        var b = Ptr.Parse("/foo/bar");

        Assert.AreNotEqual(a, b);
    }

    [TestMethod]
    public void EqualsObjectOverload()
    {
        var a = Ptr.Parse("/foo");
        object b = Ptr.Parse("/foo");
        object c = "not a pointer";

        Assert.IsTrue(a.Equals(b));
        Assert.IsFalse(a.Equals(c));
        Assert.IsFalse(a.Equals((object?)null));
    }

    [TestMethod]
    public void CompareToSortsLexicographically()
    {
        var a = Ptr.Parse("/a");
        var b = Ptr.Parse("/b");

        Assert.IsLessThan(0, a.CompareTo(b));
        Assert.IsGreaterThan(0, b.CompareTo(a));
    }

    [TestMethod]
    public void CompareToShorterPointerSortsFirst()
    {
        var shorter = Ptr.Parse("/a");
        var longer = Ptr.Parse("/a/b");

        Assert.IsLessThan(0, shorter.CompareTo(longer));
    }

    [TestMethod]
    public void ComparisonOperatorsWork()
    {
        var a = Ptr.Parse("/a");
        var b = Ptr.Parse("/b");

        Assert.IsTrue(a < b);
        Assert.IsTrue(a <= b);
        Assert.IsTrue(b > a);
        Assert.IsTrue(b >= a);
        Assert.IsTrue(a <= Ptr.Parse("/a"));
        Assert.IsTrue(a >= Ptr.Parse("/a"));
    }

    [TestMethod]
    public void ImplicitConversionFromStringParses()
    {
        Ptr pointer = "/foo/bar";

        Assert.AreEqual(2, pointer.Depth);
    }

    [TestMethod]
    public void ExplicitConversionToStringCallsToString()
    {
        var pointer = Ptr.Parse("/foo/bar");

        Assert.AreEqual("/foo/bar", (string)pointer);
    }

    [TestMethod]
    public void NumericTokenRoundtripsCorrectly()
    {
        //This is the key test: "0" as a token survives parse roundtrip
        //without being transformed into an "index" type.
        var pointer = Ptr.Parse("/0");
        var reparsed = Ptr.Parse(pointer.ToString());

        Assert.AreEqual(pointer, reparsed);
        Assert.AreEqual("0", reparsed.Segments[0].Value);
    }

    [TestMethod]
    public void NumericPropertyKeyRoundtrips()
    {
        //JSON-LD and JSON Schema use objects with numeric keys.
        var pointer = Ptr.FromProperty("42");
        var reparsed = Ptr.Parse(pointer.ToString());

        Assert.AreEqual(pointer, reparsed);
    }
}