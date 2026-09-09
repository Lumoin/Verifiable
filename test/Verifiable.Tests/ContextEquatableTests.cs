using System;
using System.Collections.Generic;
using Verifiable.Core.Model.Common;

namespace Verifiable.Tests;

/// <summary>
/// Tests for <see cref="ContextEntry"/> and <see cref="Context"/> value equality.
/// </summary>
[TestClass]
internal sealed class ContextEquatableTests
{
    /// <summary>
    /// Two IRI entries carrying the same string are equal, ordinally, per
    /// <see cref="ContextEntry.Equals(ContextEntry)"/>'s own contract.
    /// </summary>
    [TestMethod]
    public void IriEntriesWithSameValueAreEqual()
    {
        ContextEntry first = ContextEntry.FromIri("https://example.com/v1");
        ContextEntry second = ContextEntry.FromIri("https://example.com/v1");

        Assert.IsTrue(first.Equals(second));
        Assert.IsTrue(first == second);
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode());
    }


    /// <summary>
    /// Two IRI entries with different strings are unequal, per
    /// <see cref="ContextEntry.Equals(ContextEntry)"/>'s own contract.
    /// </summary>
    [TestMethod]
    public void IriEntriesWithDifferentValuesAreNotEqual()
    {
        ContextEntry first = ContextEntry.FromIri("https://example.com/v1");
        ContextEntry second = ContextEntry.FromIri("https://example.com/v2");

        Assert.IsFalse(first.Equals(second));
        Assert.IsTrue(first != second);
    }


    /// <summary>
    /// An IRI entry and a definition entry are never equal, whatever their content, per
    /// <see cref="ContextEntry.Equals(ContextEntry)"/>'s own contract: "An IRI entry is never equal
    /// to a definition entry."
    /// </summary>
    [TestMethod]
    public void IriEntryAndDefinitionEntryAreNotEqual()
    {
        ContextEntry iri = ContextEntry.FromIri("https://example.com/v1");
        ContextEntry definition = ContextEntry.FromDefinition(new Dictionary<string, object> { ["name"] = "http://schema.org/name" });

        Assert.IsFalse(iri.Equals(definition));
        Assert.IsFalse(definition.Equals(iri));
    }


    /// <summary>
    /// Two definition entries with the same properties in a different order compare equal via
    /// <see cref="Verifiable.Foundation.StructuralEquality.JsonEqual"/> (key-set equality, order
    /// irrelevant), and hash identically because <see cref="ContextEntry.GetHashCode"/> delegates
    /// to <see cref="Verifiable.Foundation.StructuralEquality.JsonHashCode"/>, which combines the
    /// property names order-independently.
    /// </summary>
    [TestMethod]
    public void DefinitionEntriesWithReorderedPropertiesAreEqual()
    {
        var firstOrder = new Dictionary<string, object> { ["name"] = "http://schema.org/name", ["image"] = "http://schema.org/image" };
        var secondOrder = new Dictionary<string, object> { ["image"] = "http://schema.org/image", ["name"] = "http://schema.org/name" };

        ContextEntry first = ContextEntry.FromDefinition(firstOrder);
        ContextEntry second = ContextEntry.FromDefinition(secondOrder);

        Assert.IsTrue(first.Equals(second));
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode());
    }


    /// <summary>
    /// Two definition entries with different content are unequal, per
    /// <see cref="Verifiable.Foundation.StructuralEquality.JsonEqual"/>, which
    /// <see cref="ContextEntry.Equals(ContextEntry)"/> delegates a definition comparison to.
    /// </summary>
    [TestMethod]
    public void DefinitionEntriesWithDifferentContentAreNotEqual()
    {
        var first = new Dictionary<string, object> { ["name"] = "http://schema.org/name" };
        var second = new Dictionary<string, object> { ["name"] = "http://schema.org/other" };

        Assert.IsFalse(ContextEntry.FromDefinition(first).Equals(ContextEntry.FromDefinition(second)));
    }


    /// <summary>
    /// A definition entry deep-copies its source: mutating the dictionary passed to
    /// <see cref="ContextEntry.FromDefinition"/> after construction does not change the entry, since
    /// the entry's own <see cref="ContextEntry.Definition"/> is a separate copy.
    /// </summary>
    [TestMethod]
    public void FromDefinitionDeepCopiesSoLaterMutationOfTheSourceDoesNotReachTheEntry()
    {
        var source = new Dictionary<string, object> { ["name"] = "http://schema.org/name" };
        ContextEntry entry = ContextEntry.FromDefinition(source);

        source["name"] = "http://schema.org/mutated";

        Assert.AreEqual("http://schema.org/name", entry.Definition!["name"]);
    }


    /// <summary>
    /// <see cref="ContextEntry"/>'s parameterless constructor refuses to build a bare entry — an
    /// entry carries an IRI or a definition, supplied only through <see cref="ContextEntry.FromIri"/>
    /// or <see cref="ContextEntry.FromDefinition"/>.
    /// </summary>
    [TestMethod]
    public void ParameterlessConstructorThrows()
    {
        Assert.ThrowsExactly<InvalidOperationException>(() => new ContextEntry());
    }


    /// <summary>
    /// The struct's zero value (reachable only through <see langword="default"/>, never through the
    /// throwing parameterless constructor) is equal to another zero value — required for
    /// reflexivity, which <see cref="HashSet{T}"/> and LINQ's <c>Distinct</c>/<c>Contains</c> both
    /// depend on.
    /// </summary>
    [TestMethod]
    public void DefaultValueIsReflexive()
    {
        ContextEntry firstDefault = default;
        ContextEntry secondDefault = default;

        Assert.IsTrue(firstDefault.Equals(secondDefault));
        Assert.AreEqual(firstDefault.GetHashCode(), secondDefault.GetHashCode());
    }


    /// <summary>
    /// The struct's zero value is unequal to a properly constructed IRI entry, per
    /// <see cref="ContextEntry.Equals(ContextEntry)"/>'s own contract: the degenerate value is
    /// "unequal to every properly constructed entry."
    /// </summary>
    [TestMethod]
    public void DefaultValueIsNotEqualToAProperEntry()
    {
        ContextEntry defaultEntry = default;
        ContextEntry iri = ContextEntry.FromIri("https://example.com/v1");

        Assert.IsFalse(defaultEntry.Equals(iri));
        Assert.IsFalse(iri.Equals(defaultEntry));
    }


    /// <summary>
    /// Two contexts built from the same IRIs in the same order are equal, per
    /// <see cref="Context.Equals(Context?)"/>'s own contract.
    /// </summary>
    [TestMethod]
    public void ContextsWithSameEntriesInSameOrderAreEqual()
    {
        Context first = Context.FromIris(Context.Credentials20, Context.DataIntegrity20);
        Context second = Context.FromIris(Context.Credentials20, Context.DataIntegrity20);

        Assert.IsTrue(first.Equals(second));
        Assert.IsTrue(first == second);
        Assert.AreEqual(first.GetHashCode(), second.GetHashCode());
    }


    /// <summary>
    /// Order is significant: the same two IRIs in a different order are unequal contexts, per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>, whose <c>@context</c> value is an
    /// <see href="https://infra.spec.whatwg.org/#ordered-set">ordered set</see> — an ordered list,
    /// not a bag.
    /// </summary>
    [TestMethod]
    public void ContextsWithSameEntriesInDifferentOrderAreNotEqual()
    {
        Context first = Context.FromIris(Context.Credentials20, Context.DataIntegrity20);
        Context second = Context.FromIris(Context.DataIntegrity20, Context.Credentials20);

        Assert.IsFalse(first.Equals(second));
        Assert.IsTrue(first != second);
    }


    /// <summary>
    /// <see cref="Context.Form"/> is excluded from equality: a context holding one entry in
    /// <see cref="ContextForm.Scalar"/> form equals a context holding that same single entry in
    /// <see cref="ContextForm.Array"/> form, per
    /// <see href="https://www.w3.org/TR/json-ld11/#dfn-embedded-context">JSON-LD 1.1 §1.4
    /// Terminology, "embedded context"</see>: "Its value may be a map for a context definition, as
    /// an IRI, or as an array combining either of the above" — JSON-LD treats the two shapes as the
    /// same context.
    /// </summary>
    [TestMethod]
    public void FormIsExcludedFromEquality()
    {
        var scalarForm = new Context([ContextEntry.FromIri(Context.Credentials20)], ContextForm.Scalar);
        var arrayForm = new Context([ContextEntry.FromIri(Context.Credentials20)], ContextForm.Array);

        Assert.AreNotEqual(scalarForm.Form, arrayForm.Form);
        Assert.IsTrue(scalarForm.Equals(arrayForm));
        Assert.AreEqual(scalarForm.GetHashCode(), arrayForm.GetHashCode());
    }


    /// <summary>
    /// A context with a different number of entries is unequal regardless of a shared prefix, per
    /// <see cref="Context.Equals(Context?)"/>'s own contract, which compares
    /// <see cref="Context.Entries"/> by count before comparing element-wise.
    /// </summary>
    [TestMethod]
    public void ContextsWithDifferentEntryCountsAreNotEqual()
    {
        Context shorter = Context.FromIris(Context.Credentials20);
        Context longer = Context.FromIris(Context.Credentials20, Context.DataIntegrity20);

        Assert.IsFalse(shorter.Equals(longer));
    }


    /// <summary>
    /// <see cref="Context"/> is unequal to <see langword="null"/> and vice versa through the
    /// <c>==</c> operator, per <see cref="Context.Equals(Context?)"/>'s own null handling, which
    /// the <c>==</c> operator delegates to.
    /// </summary>
    [TestMethod]
    public void ContextIsNotEqualToNull()
    {
        Context context = Context.FromIris(Context.Credentials20);

        Assert.IsFalse(context.Equals(null));
        Assert.IsFalse(context == null);
        Assert.IsTrue(context != null);
    }


    /// <summary>
    /// <see cref="Context.FromIris"/> always produces <see cref="ContextForm.Array"/>, per
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
    /// Contexts</see>: "The value of the <c>@context</c> property MUST be an ordered set" — a JSON
    /// array — even for a single entry.
    /// </summary>
    [TestMethod]
    public void FromIrisWithASingleIriProducesArrayForm()
    {
        Context context = Context.FromIris(Context.Credentials20);

        Assert.AreEqual(ContextForm.Array, context.Form);
    }


    /// <summary>
    /// The <see cref="Context(IReadOnlyList{ContextEntry}, ContextForm)"/> constructor refuses
    /// <see cref="ContextForm.Scalar"/> with zero entries: a scalar wire value is a single string or
    /// object, per <see href="https://www.w3.org/TR/json-ld11/#dfn-embedded-context">JSON-LD 1.1
    /// §1.4 Terminology, "embedded context"</see> ("as an IRI, or as an array combining either of the
    /// above"), so an empty entry list has no scalar wire form to round-trip as.
    /// </summary>
    [TestMethod]
    public void ScalarFormConstructorThrowsWithZeroEntries()
    {
        Assert.ThrowsExactly<ArgumentException>(() => new Context([], ContextForm.Scalar));
    }


    /// <summary>
    /// The <see cref="Context(IReadOnlyList{ContextEntry}, ContextForm)"/> constructor refuses
    /// <see cref="ContextForm.Scalar"/> with more than one entry: a scalar wire value is a single
    /// string or object, per <see href="https://www.w3.org/TR/json-ld11/#dfn-embedded-context">
    /// JSON-LD 1.1 §1.4 Terminology, "embedded context"</see>, so multiple entries have no scalar
    /// wire form to round-trip as and would otherwise silently fall back to being written as an
    /// array.
    /// </summary>
    [TestMethod]
    public void ScalarFormConstructorThrowsWithMultipleEntries()
    {
        var entries = new[]
        {
            ContextEntry.FromIri(Context.Credentials20),
            ContextEntry.FromIri(Context.DataIntegrity20)
        };

        Assert.ThrowsExactly<ArgumentException>(() => new Context(entries, ContextForm.Scalar));
    }


    /// <summary>
    /// The <see cref="Context(IReadOnlyList{ContextEntry}, ContextForm)"/> constructor accepts
    /// <see cref="ContextForm.Scalar"/> with exactly one entry: a scalar wire value is a single
    /// string or object, per <see href="https://www.w3.org/TR/json-ld11/#dfn-embedded-context">
    /// JSON-LD 1.1 §1.4 Terminology, "embedded context"</see>, the only entry count that shape can
    /// represent.
    /// </summary>
    [TestMethod]
    public void ScalarFormConstructorAcceptsExactlyOneEntry()
    {
        Context context = new([ContextEntry.FromIri(Context.Credentials20)], ContextForm.Scalar);

        Assert.HasCount(1, context.Entries);
        Assert.AreEqual(ContextForm.Scalar, context.Form);
    }


    /// <summary>
    /// The <see cref="Context(IReadOnlyList{ContextEntry}, ContextForm)"/> constructor copies the
    /// caller's entry list: mutating the array passed in after construction does not reach
    /// <see cref="Context.Entries"/>, since <see cref="Context"/> is otherwise immutable end to end.
    /// </summary>
    [TestMethod]
    public void ContextConstructorCopiesTheEntryList()
    {
        ContextEntry[] source = [ContextEntry.FromIri(Context.Credentials20)];
        Context context = new(source, ContextForm.Array);

        source[0] = ContextEntry.FromIri(Context.DataIntegrity20);

        Assert.AreEqual(Context.Credentials20, context.Entries[0].Iri);
    }
}
