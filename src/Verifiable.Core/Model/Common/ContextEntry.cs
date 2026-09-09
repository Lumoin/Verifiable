using System;
using System.Collections.Generic;
using Verifiable.Foundation;

namespace Verifiable.Core.Model.Common;

/// <summary>
/// A single element of a JSON-LD <c>@context</c> value: either an IRI reference to an external
/// context document, or an inline context definition.
/// </summary>
/// <remarks>
/// <para>
/// Per <see href="https://www.w3.org/TR/vc-data-model-2.0/#contexts">VC Data Model 2.0 §4.3
/// Contexts</see>, subsequent <c>@context</c> items "MUST be composed of any combination of
/// URLs and objects, where each is processable as a
/// <see href="https://www.w3.org/TR/json-ld11/#the-context">JSON-LD Context</see>". This type
/// models that union: <see cref="IsIri"/> entries carry the URL as a plain string (no URI
/// parsing — a context IRI is not necessarily dereferenceable or RFC 3986-normalizable, and the
/// library does not run JSON-LD processing over it); <see cref="IsDefinition"/> entries carry the
/// inline object as the materialized-JSON object model
/// (<see cref="IReadOnlyDictionary{TKey, TValue}"/> of <see cref="string"/> to <see cref="object"/>)
/// that the <c>Verifiable.Json</c> leaf's manual readers produce — <see cref="Verifiable.Core"/>
/// itself never references a JSON serialization library (<c>System.Text.Json</c> is a banned
/// symbol in this project), so a definition cannot be carried as a <c>JsonElement</c>.
/// </para>
/// <para>
/// Construction is only through <see cref="FromIri"/> and <see cref="FromDefinition"/>, both of
/// which the parameterless constructor refuses to substitute for — see its own remarks. The
/// struct's zero value (from <see langword="default"/>, an array allocation, or an uninitialized
/// field — none of which run a constructor) is a degenerate entry that is neither an IRI nor a
/// definition; <see cref="Equals(ContextEntry)"/> treats two such degenerate values as equal to
/// each other (reflexivity, required by <see cref="System.Collections.Generic.HashSet{T}"/> and
/// LINQ's <c>Distinct</c>/<c>Contains</c>) but unequal to every properly constructed entry, and
/// <c>JsonLdContextConverter</c> (Verifiable.Json) refuses to write one.
/// </para>
/// </remarks>
public readonly record struct ContextEntry
{
    /// <summary>
    /// The IRI, when this entry is <see cref="IsIri"/>; otherwise <see langword="null"/>.
    /// </summary>
    public string? Iri { get; }

    /// <summary>
    /// The inline context definition, when this entry is <see cref="IsDefinition"/>; otherwise
    /// <see langword="null"/>. A defensive deep copy the caller's own graph cannot mutate after
    /// construction — see <see cref="FromDefinition"/>.
    /// </summary>
    public IReadOnlyDictionary<string, object>? Definition { get; }


    /// <summary>
    /// Constructs an entry from exactly one of <paramref name="iri"/> or <paramref name="definition"/>.
    /// Private: <see cref="FromIri"/> and <see cref="FromDefinition"/> are the only construction paths,
    /// so a caller can never build an entry that is both or neither by accident.
    /// </summary>
    /// <param name="iri">The IRI, or <see langword="null"/> for a definition entry.</param>
    /// <param name="definition">The inline definition, or <see langword="null"/> for an IRI entry.</param>
    private ContextEntry(string? iri, IReadOnlyDictionary<string, object>? definition)
    {
        Iri = iri;
        Definition = definition;
    }


    /// <summary>
    /// Refuses to construct a bare entry: an entry carries an IRI or a definition, and the only
    /// paths that supply one are <see cref="FromIri"/> and <see cref="FromDefinition"/>. Modeled on
    /// <see cref="Assessment.ClaimId"/>'s own parameterless constructor.
    /// </summary>
    /// <exception cref="InvalidOperationException">Always thrown.</exception>
    /// <remarks>
    /// This constructor cannot prevent the struct's zero value: <see langword="default"/>, an array
    /// element, and an uninitialized field all bypass every constructor, by the language's own rules
    /// for struct types. Guarding against IT is <see cref="Equals(ContextEntry)"/>'s and
    /// <c>JsonLdContextConverter</c>'s job, not this constructor's.
    /// </remarks>
    public ContextEntry()
    {
        throw new InvalidOperationException($"Use {nameof(FromIri)} or {nameof(FromDefinition)}.");
    }


    /// <summary>
    /// Creates an entry carrying an IRI reference to an external context document.
    /// </summary>
    /// <param name="iri">The context IRI, exactly as it will be written to the wire.</param>
    /// <returns>The IRI entry.</returns>
    public static ContextEntry FromIri(string iri)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(iri);

        return new ContextEntry(iri, null);
    }


    /// <summary>
    /// Creates an entry carrying an inline context definition, deep-copied into plain
    /// <see cref="Dictionary{TKey, TValue}"/>/<see cref="List{T}"/> nodes (the same materialized
    /// shape the source is assumed to already be in) so the entry does not alias — and is not later
    /// mutated through — the caller's own graph.
    /// </summary>
    /// <param name="definition">The parsed inline context object.</param>
    /// <returns>The definition entry.</returns>
    public static ContextEntry FromDefinition(IReadOnlyDictionary<string, object> definition)
    {
        ArgumentNullException.ThrowIfNull(definition);

        return new ContextEntry(null, DeepCopyMap(definition));
    }


    /// <summary>
    /// <see langword="true"/> when this entry carries an IRI (<see cref="Iri"/> is non-null).
    /// </summary>
    public bool IsIri => Iri is not null;


    /// <summary>
    /// <see langword="true"/> when this entry carries an inline definition
    /// (<see cref="Definition"/> is non-null).
    /// </summary>
    public bool IsDefinition => Definition is not null;


    /// <summary>
    /// Compares two entries by value: IRIs ordinally, definitions structurally via
    /// <see cref="StructuralEquality.JsonEqual"/> so that property order in an inline definition
    /// does not affect equality. An IRI entry is never equal to a definition entry. Two degenerate
    /// (neither-IRI-nor-definition) entries — reachable only through the struct's zero value, never
    /// through <see cref="FromIri"/>/<see cref="FromDefinition"/> — are equal to each other, so this
    /// relation stays reflexive over every value the type can actually hold, including the zero one.
    /// </summary>
    /// <param name="other">The entry to compare against.</param>
    /// <returns><see langword="true"/> if the entries carry the same value.</returns>
    public bool Equals(ContextEntry other)
    {
        return (IsIri, other.IsIri, IsDefinition, other.IsDefinition) switch
        {
            (true, true, _, _) => string.Equals(Iri, other.Iri, StringComparison.Ordinal),
            (_, _, true, true) => StructuralEquality.JsonEqual(Definition, other.Definition),
            (false, false, false, false) => true,
            _ => false
        };
    }


    /// <summary>
    /// A hash consistent with <see cref="Equals(ContextEntry)"/>: an IRI hashes ordinally on its
    /// string value; a definition hashes via <see cref="StructuralEquality.JsonHashCode"/>, which
    /// combines the entry count with an order-independent combination of the top-level property
    /// names, so re-ordering an inline definition's properties (which <see cref="Equals(ContextEntry)"/>
    /// treats as equal) does not change the hash; the degenerate zero value hashes to a fixed constant
    /// distinct from either, consistent with it comparing equal only to itself.
    /// </summary>
    /// <returns>The hash code.</returns>
    public override int GetHashCode()
    {
        return (IsIri, IsDefinition) switch
        {
            (true, _) => HashCode.Combine(true, StringComparer.Ordinal.GetHashCode(Iri!)),
            (_, true) => HashCode.Combine(false, StructuralEquality.JsonHashCode(Definition)),
            _ => -1
        };
    }


    /// <summary>
    /// Renders the entry for test output and debugging: the IRI itself, the definition's
    /// top-level property names, or a marker for the degenerate zero value.
    /// </summary>
    /// <returns>The string representation.</returns>
    public override string ToString()
    {
        return (IsIri, IsDefinition) switch
        {
            (true, _) => Iri!,
            (_, true) => $"{{{string.Join(", ", Definition!.Keys)}}}",
            _ => "<default ContextEntry>"
        };
    }


    /// <summary>
    /// Deep-copies a materialized-JSON object (<see cref="Dictionary{TKey, TValue}"/>/<see cref="List{T}"/>/scalars/
    /// <see langword="null"/>, the shape <c>ManualJsonReader</c> produces in <c>Verifiable.Json</c>) so the copy
    /// shares no mutable node with its source.
    /// </summary>
    /// <param name="source">The map to copy.</param>
    /// <returns>A new map holding deep copies of every value in <paramref name="source"/>.</returns>
    /// <remarks>
    /// Plain recursion: a JSON-LD context definition is shallow, and <see cref="Verifiable.Core"/> takes no JSON
    /// library dependency that would offer an iterative walker for this exact shape.
    /// </remarks>
    private static Dictionary<string, object> DeepCopyMap(IReadOnlyDictionary<string, object> source)
    {
        var copy = new Dictionary<string, object>(source.Count, StringComparer.Ordinal);
        foreach(KeyValuePair<string, object> entry in source)
        {
            copy[entry.Key] = DeepCopyValue(entry.Value)!;
        }

        return copy;
    }


    /// <summary>
    /// Deep-copies one materialized-JSON value: a nested object or array is copied recursively; a scalar
    /// (<see cref="string"/>/<see cref="bool"/>/<see cref="int"/>/<see cref="long"/>/<see cref="decimal"/>) or
    /// <see langword="null"/> is immutable already and returned as-is.
    /// </summary>
    /// <param name="value">The value to copy.</param>
    /// <returns>A deep copy of <paramref name="value"/>, or the value itself when it is already immutable.</returns>
    private static object? DeepCopyValue(object? value)
    {
        return value switch
        {
            null => null,
            IReadOnlyDictionary<string, object> map => DeepCopyMap(map),
            IReadOnlyList<object> list => DeepCopyList(list),
            _ => value
        };
    }


    /// <summary>
    /// Deep-copies a materialized-JSON array into a new <see cref="List{T}"/> holding a deep copy of every
    /// element, so the copy shares no mutable node with <paramref name="source"/>.
    /// </summary>
    /// <param name="source">The list to copy.</param>
    /// <returns>A new list holding deep copies of every element in <paramref name="source"/>.</returns>
    private static List<object> DeepCopyList(IReadOnlyList<object> source)
    {
        var copy = new List<object>(source.Count);
        foreach(object item in source)
        {
            copy.Add(DeepCopyValue(item)!);
        }

        return copy;
    }
}
