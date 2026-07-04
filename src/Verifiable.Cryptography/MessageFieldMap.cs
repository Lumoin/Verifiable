using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// A decoded message field map: the serialization-neutral, order-preserving hand-off between a serializer that
/// decodes a message body's fields (a JSON, CBOR, MGPK, or CESR-native decode arm) and a protocol reader that
/// folds those fields into a typed message. It gives that hand-off a named type rather than a raw dictionary, the
/// same way the JOSE field-map types (<c>JwtHeader</c>, <c>JwtPayload</c>, <c>JsonWebKey</c>) name the JWT
/// hand-off, so a method signature states it takes a decoded message field map and not any string-keyed map.
/// </summary>
/// <remarks>
/// <para>
/// It derives from <see cref="OrderedDictionary{TKey, TValue}"/> rather than <see cref="Dictionary{TKey, TValue}"/>
/// because a message's fields have a fixed serialization order that the SAID computed over the serialization
/// depends on; the ordered base makes "the fields enumerate in serialization order" a property of the type rather
/// than a documented convention a caller must uphold. The value of a field follows the neutral-map conventions a
/// decode arm normalizes to — a scalar is a <see cref="string"/> and a homogeneous list is an
/// <see cref="IReadOnlyList{T}"/> of <see cref="string"/>, with any other value (a nested data-plane map or list)
/// left general — which <see cref="TryGetString(string, out string)"/> and
/// <see cref="TryGetStringList(string, out IReadOnlyList{string})"/> read without the caller reaching for the raw
/// <see cref="object"/> value.
/// </para>
/// <para>
/// This type lives in <c>Verifiable.Cryptography</c> because it is the shared vocabulary a serializer leaf and a
/// protocol reader meet on: the leaf produces it and the reader consumes it, while neither references the other.
/// </para>
/// </remarks>
public sealed class MessageFieldMap: OrderedDictionary<string, object?>
{
    /// <summary>
    /// Creates an empty message field map.
    /// </summary>
    public MessageFieldMap()
    {
    }


    /// <summary>
    /// Creates an empty message field map that compares field labels with the given comparer.
    /// </summary>
    /// <param name="comparer">The comparer for field labels, or <see langword="null"/> for the default.</param>
    public MessageFieldMap(IEqualityComparer<string>? comparer): base(comparer)
    {
    }


    /// <summary>
    /// Creates an empty message field map with the given initial capacity that compares field labels with the
    /// given comparer.
    /// </summary>
    /// <param name="capacity">The initial number of fields the map can hold.</param>
    /// <param name="comparer">The comparer for field labels, or <see langword="null"/> for the default.</param>
    public MessageFieldMap(int capacity, IEqualityComparer<string>? comparer): base(capacity, comparer)
    {
    }


    /// <summary>
    /// Tries to read a field as a scalar string, the neutral-map convention for a scalar field.
    /// </summary>
    /// <param name="label">The field label.</param>
    /// <param name="value">The field's string value, when present and a string.</param>
    /// <returns><see langword="true"/> when the field is present and a string; otherwise <see langword="false"/>.</returns>
    public bool TryGetString(string label, [NotNullWhen(true)] out string? value)
    {
        if(TryGetValue(label, out object? raw) && raw is string text)
        {
            value = text;

            return true;
        }

        value = null;

        return false;
    }


    /// <summary>
    /// Tries to read a field as a list of strings, the neutral-map convention for a key-state list field.
    /// </summary>
    /// <param name="label">The field label.</param>
    /// <param name="value">The field's string-list value, when present and a string list.</param>
    /// <returns><see langword="true"/> when the field is present and a string list; otherwise <see langword="false"/>.</returns>
    public bool TryGetStringList(string label, [NotNullWhen(true)] out IReadOnlyList<string>? value)
    {
        if(TryGetValue(label, out object? raw) && raw is IReadOnlyList<string> list)
        {
            value = list;

            return true;
        }

        value = null;

        return false;
    }
}
