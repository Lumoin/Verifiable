using System.Collections.Frozen;
using System.ComponentModel;
using System.Diagnostics;

namespace Verifiable.Cryptography;

/// <summary>
/// A general-purpose type-keyed metadata container for tagging data with out-of-band information.
/// </summary>
/// <param name="Data">The metadata associated with the tag.</param>
/// <remarks>
/// <para>
/// <strong>Purpose</strong>
/// </para>
/// <para>
/// The Tag provides metadata to assist in managing otherwise opaque data blocks.
/// It is not tightly bound to the data itself, but rather describes characteristics
/// such as identifiers, storage locations, data formats, or content types.
/// Despite the provided metadata, all inputs should be validated.
/// </para>
/// <para>
/// <strong>Type-Keyed Design</strong>
/// </para>
/// <para>
/// Unlike string-keyed dictionaries, this uses <see cref="Type"/> as the key,
/// providing compile-time safety and avoiding magic strings. Values are retrieved
/// using <see cref="Get{T}"/> which infers the key from the generic type parameter.
/// </para>
/// <para>
/// <strong>Immutability</strong>
/// </para>
/// <para>
/// Tags are immutable once created. Use <see cref="Create"/> to construct new tags
/// with <see cref="FrozenDictionary{TKey, TValue}"/> for optimal read performance.
/// </para>
/// <para>
/// <strong>Usage Examples</strong>
/// </para>
/// <code>
/// //Create a tag with multiple metadata items.
/// var tag = Tag.Create(
///     (typeof(BufferKind), BufferKind.JwtPayload),
///     (typeof(EncodingFormat), EncodingFormat.Json));
///
/// //Retrieve a value.
/// var kind = tag.Get&lt;BufferKind&gt;();
/// </code>
/// </remarks>
/// <seealso cref="CryptoTags"/>
[DebuggerDisplay("{DebuggerView,nq}")]
public record Tag(IReadOnlyDictionary<Type, object> Data)
{
    /// <summary>
    /// An empty tag with no metadata.
    /// </summary>
    public static Tag Empty { get; } = new(FrozenDictionary<Type, object>.Empty);


    /// <summary>
    /// Creates a new tag from the specified key-value pairs.
    /// </summary>
    /// <param name="items">The metadata items as type-value tuples.</param>
    /// <returns>A new tag containing the specified metadata.</returns>
    /// <remarks>
    /// <para>
    /// This factory method creates an immutable <see cref="FrozenDictionary{TKey, TValue}"/>
    /// internally, optimized for read-heavy access patterns typical of tag lookups.
    /// </para>
    /// </remarks>
    /// <example>
    /// <code>
    /// var tag = Tag.Create(
    ///     (typeof(CryptoAlgorithm), CryptoAlgorithm.P256),
    ///     (typeof(Purpose), Purpose.Verification));
    /// </code>
    /// </example>
    public static Tag Create(params ReadOnlySpan<(Type Key, object Value)> items)
    {
        if(items.IsEmpty)
        {
            return Empty;
        }

        var dict = new Dictionary<Type, object>(items.Length);
        foreach((Type key, object value) in items)
        {
            dict[key] = value;
        }

        return new Tag(dict.ToFrozenDictionary());
    }


    /// <summary>
    /// Retrieves a value from the tag, inferring the key from the generic type.
    /// </summary>
    /// <typeparam name="T">The type of the value to retrieve, also used as the key.</typeparam>
    /// <returns>The value associated with the type key, cast to the specified type.</returns>
    /// <exception cref="KeyNotFoundException">Thrown if the key is not found in the tag.</exception>
    /// <exception cref="InvalidCastException">Thrown if the value cannot be cast to the specified type.</exception>
    public T Get<T>()
    {
        Type key = typeof(T);
        if(!Data.TryGetValue(key, out object? value))
        {
            throw new KeyNotFoundException($"Key '{key}' was not found in the tag's data.");
        }

        if(value is not T typedValue)
        {
            throw new InvalidCastException($"Value for key '{key}' is not of type '{typeof(T)}'.");
        }

        return typedValue;
    }


    /// <summary>
    /// Attempts to retrieve a value from the tag.
    /// </summary>
    /// <typeparam name="T">The type of the value to retrieve, also used as the key.</typeparam>
    /// <param name="value">When successful, contains the retrieved value.</param>
    /// <returns><see langword="true"/> if the value was found and cast successfully; otherwise <see langword="false"/>.</returns>
    public bool TryGet<T>([System.Diagnostics.CodeAnalysis.MaybeNullWhen(false)] out T value)
    {
        Type key = typeof(T);
        if(Data.TryGetValue(key, out object? obj) && obj is T typedValue)
        {
            value = typedValue;
            return true;
        }

        value = default;
        return false;
    }


    /// <summary>
    /// Gets the value associated with the specified key in the Tag data.
    /// </summary>
    /// <param name="key">The key of the value to get.</param>
    /// <returns>The value associated with the specified key.</returns>
    /// <exception cref="KeyNotFoundException">Thrown if the key is not found.</exception>
    public object this[Type key] => Data[key];


    /// <inheritdoc />
    public override string ToString() => TagString;


    /// <summary>
    /// Debugging view of the Tag.
    /// </summary>
    private string DebuggerView
    {
        get
        {
            try
            {
                return TagString;
            }
            catch
            {
                return "Tag: (error)";
            }
        }
    }


    private string TagString => Data.Count == 0
        ? "Tag: (empty)"
        : $"Tag: [{string.Join(", ", Data.Select(kvp => $"{kvp.Key.Name}={kvp.Value}"))}]";
}