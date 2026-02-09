using CsCheck;
using Verifiable.JsonPointer;
using Ptr = Verifiable.JsonPointer.JsonPointer;
using Seg = Verifiable.JsonPointer.JsonPointerSegment;

namespace Verifiable.Tests.JsonPointer;

[TestClass]
internal sealed class JsonPointerPropertyTests
{
    private static readonly Gen<string> GenToken =
        Gen.String[Gen.Char.AlphaNumeric, 0, 10];

    private static readonly Gen<Seg> GenSegment =
        GenToken.Select(Seg.Create);

    private static readonly Gen<Ptr> GenPointer =
        Gen.Int[0, 5].SelectMany(depth =>
            GenSegment.Array[depth, depth]
               .Select(segs => Ptr.FromSegments(segs)));

    //Generates tokens that include characters requiring escaping.
    private static readonly Gen<string> GenTokenWithSpecialChars =
        Gen.OneOf(
            Gen.Const("a/b"),
            Gen.Const("c~d"),
            Gen.Const("~/"),
            Gen.Const("a~0b"),
            GenToken);


    [TestMethod]
    public void ParseToStringRoundtrip()
    {
        GenPointer.Sample(pointer =>
        {
            string str = pointer.ToString();
            var parsed = Ptr.Parse(str);

            Assert.AreEqual(pointer, parsed, $"Roundtrip failed for '{str}'.");
        });
    }

    [TestMethod]
    public void TryParseAgreesWithParse()
    {
        GenPointer.Sample(pointer =>
        {
            string str = pointer.ToString();
            bool success = Ptr.TryParse(str, out var result);

            Assert.IsTrue(success);
            Assert.AreEqual(pointer, result);
        });
    }

    [TestMethod]
    public void UriFragmentRoundtrip()
    {
        GenPointer.Sample(pointer =>
        {
            string fragment = pointer.ToUriFragment();
            var parsed = Ptr.ParseUriFragment(fragment);

            Assert.AreEqual(pointer, parsed, $"URI fragment roundtrip failed for '{pointer}'.");
        });
    }

    [TestMethod]
    public void EscapeUnescapeRoundtrip()
    {
        GenTokenWithSpecialChars.Sample(token =>
        {
            string escaped = Ptr.Escape(token);
            var pointer = Ptr.Parse("/" + escaped);

            Assert.AreEqual(token, pointer.Segments[0].Value,
                $"Escape roundtrip failed for '{token}' (escaped: '{escaped}').");
        });
    }

    [TestMethod]
    public void AppendPropertyThenParentReturnsOriginal()
    {
        GenPointer.SelectMany(pointer =>
            GenToken.Where(t => t.Length > 0).Select(token => (pointer, token)))
        .Sample(t =>
        {
            var appended = t.pointer.Append(t.token);
            var parent = appended.Parent!.Value;

            Assert.AreEqual(t.pointer, parent,
                $"Append('{t.token}').Parent should equal original for '{t.pointer}'.");
        });
    }

    [TestMethod]
    public void AppendIndexThenParentReturnsOriginal()
    {
        GenPointer.SelectMany(pointer =>
            Gen.Int[0, 999].Select(idx => (pointer, idx)))
        .Sample(t =>
        {
            var appended = t.pointer.Append(t.idx);
            var parent = appended.Parent!.Value;

            Assert.AreEqual(t.pointer, parent,
                $"Append({t.idx}).Parent should equal original for '{t.pointer}'.");
        });
    }

    [TestMethod]
    public void AppendIncreasesDepthByOne()
    {
        GenPointer.SelectMany(pointer =>
            GenSegment.Select(seg => (pointer, seg)))
        .Sample(t =>
        {
            var appended = t.pointer.Append(t.seg);

            Assert.AreEqual(t.pointer.Depth + 1, appended.Depth);
        });
    }

    [TestMethod]
    public void AppendPointerDepthIsSum()
    {
        GenPointer.SelectMany(a =>
            GenPointer.Select(b => (a, b)))
        .Sample(t =>
        {
            var combined = t.a.Append(t.b);

            Assert.AreEqual(t.a.Depth + t.b.Depth, combined.Depth);
        });
    }

    [TestMethod]
    public void IsAncestorOfIsAntisymmetric()
    {
        GenPointer.SelectMany(ancestor =>
            GenSegment.Select(seg => (ancestor, descendant: ancestor.Append(seg))))
        .Sample(t =>
        {
            Assert.IsTrue(t.ancestor.IsAncestorOf(t.descendant),
                $"'{t.ancestor}' should be ancestor of '{t.descendant}'.");
            Assert.IsFalse(t.descendant.IsAncestorOf(t.ancestor),
                $"'{t.descendant}' should not be ancestor of '{t.ancestor}'.");
        });
    }

    [TestMethod]
    public void IsDescendantOfIsSymmetricWithIsAncestorOf()
    {
        GenPointer.SelectMany(ancestor =>
            GenSegment.Select(seg => (ancestor, descendant: ancestor.Append(seg))))
        .Sample(t =>
        {
            Assert.AreEqual(
                t.ancestor.IsAncestorOf(t.descendant),
                t.descendant.IsDescendantOf(t.ancestor));
        });
    }

    [TestMethod]
    public void RootIsAncestorOfAllNonRootPointers()
    {
        GenPointer.Where(p => !p.IsRoot)
        .Sample(pointer =>
        {
            Assert.IsTrue(Ptr.Root.IsAncestorOf(pointer));
        });
    }

    [TestMethod]
    public void NothingIsAncestorOfRoot()
    {
        GenPointer.Sample(pointer =>
        {
            Assert.IsFalse(pointer.IsAncestorOf(Ptr.Root));
        });
    }

    [TestMethod]
    public void IsAncestorOfOrEqualToIsReflexive()
    {
        GenPointer.Sample(pointer =>
        {
            Assert.IsTrue(pointer.IsAncestorOfOrEqualTo(pointer));
        });
    }

    [TestMethod]
    public void RelativeToUndoesAppend()
    {
        GenPointer.SelectMany(ancestor =>
            GenPointer.Where(p => !p.IsRoot).Select(suffix => (ancestor, suffix)))
        .Sample(t =>
        {
            var combined = t.ancestor.Append(t.suffix);
            var relative = combined.RelativeTo(t.ancestor);

            Assert.AreEqual(t.suffix.Depth, relative.Depth,
                $"RelativeTo should undo append for '{t.ancestor}' + '{t.suffix}'.");
        });
    }

    [TestMethod]
    public void SelfAndAncestorsCountEqualsDepthPlusOne()
    {
        GenPointer.Sample(pointer =>
        {
            int count = pointer.SelfAndAncestors().Count();

            Assert.AreEqual(pointer.Depth + 1, count);
        });
    }

    [TestMethod]
    public void AncestorsCountEqualsDepth()
    {
        GenPointer.Sample(pointer =>
        {
            int count = pointer.Ancestors().Count();

            Assert.AreEqual(pointer.Depth, count);
        });
    }

    [TestMethod]
    public void EqualityIsReflexive()
    {
        GenPointer.Sample(pointer =>
        {
            Assert.AreEqual(pointer, pointer);
            Assert.AreEqual(pointer.GetHashCode(), pointer.GetHashCode());
        });
    }

    [TestMethod]
    public void CompareToIsReflexive()
    {
        GenPointer.Sample(pointer =>
        {
            Assert.AreEqual(0, pointer.CompareTo(pointer));
        });
    }

    [TestMethod]
    public void CompareToIsAntisymmetric()
    {
        GenPointer.SelectMany(a =>
            GenPointer.Select(b => (a, b)))
        .Sample(t =>
        {
            int ab = t.a.CompareTo(t.b);
            int ba = t.b.CompareTo(t.a);

            if(ab > 0)
            {
                Assert.IsLessThan(0, ba);
            }
            else if(ab < 0)
            {
                Assert.IsGreaterThan(0, ba);
            }
            else
            {
                Assert.AreEqual(0, ba);
            }
        });
    }

    [TestMethod]
    public void CompareToIsConsistentWithOperators()
    {
        GenPointer.SelectMany(a =>
            GenPointer.Select(b => (a, b)))
        .Sample(t =>
        {
            int cmp = t.a.CompareTo(t.b);

            Assert.AreEqual(cmp < 0, t.a < t.b);
            Assert.AreEqual(cmp <= 0, t.a <= t.b);
            Assert.AreEqual(cmp > 0, t.a > t.b);
            Assert.AreEqual(cmp >= 0, t.a >= t.b);
        });
    }

    [TestMethod]
    public void LastSegmentMatchesSegmentsArrayEnd()
    {
        GenPointer.Where(p => !p.IsRoot)
        .Sample(pointer =>
        {
            var last = pointer.LastSegment!.Value;
            var fromArray = pointer.Segments[pointer.Depth - 1];

            Assert.AreEqual(fromArray, last);
        });
    }
}