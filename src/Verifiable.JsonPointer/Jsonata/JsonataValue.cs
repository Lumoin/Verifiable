using System.Collections.Generic;
using System.Diagnostics;

namespace Verifiable.JsonPointer.Jsonata;

/// <summary>
/// The kind of a <see cref="JsonataValue"/>: the JSON value shapes the minimal in-repo JSONata
/// evaluator reads from its input and constructs as its output.
/// </summary>
public enum JsonataValueKind
{
    /// <summary>The JSON <c>null</c> literal, and the value of a missing path navigation.</summary>
    Null = 0,

    /// <summary>A JSON object: an ordered string-keyed map of values.</summary>
    Object,

    /// <summary>A JSON array: an ordered list of values.</summary>
    Array,

    /// <summary>A JSON string.</summary>
    String,

    /// <summary>A JSON number carried as an integral <see cref="long"/>.</summary>
    Integer,

    /// <summary>A JSON number carried as a fractional <see cref="double"/>.</summary>
    Number,

    /// <summary>A JSON boolean.</summary>
    Boolean
}


/// <summary>
/// A self-contained JSON value the minimal in-repo JSONata evaluator reads as input and constructs
/// as output. It mirrors the CLR-JSON object graph shape <c>Verifiable.OAuth</c>'s
/// <c>JsonScalarText.DecodeValue</c> produces (object = ordered string→value map, array = list,
/// string, integral <see cref="long"/> / fractional <see cref="double"/> number, boolean, null) but
/// as a clean local model in this leaf, so <c>Verifiable.JsonPointer</c> stays free of
/// <c>System.Text.Json</c> and model-agnostic.
/// </summary>
/// <remarks>
/// <para>
/// The application — or the full JSONata engine in <c>Lumoin.Veritas</c> that supersedes this
/// minimal evaluator in production — adapts its own JSON representation to this model at the seam.
/// The factory methods are the only way to build a value, keeping the discriminated kind and the
/// payload in lockstep.
/// </para>
/// <para>
/// <strong>Object ordering:</strong> objects preserve insertion order so a constructed credential
/// body renders its members in template order. Keys are compared ordinally.
/// </para>
/// </remarks>
[DebuggerDisplay("{Kind}")]
public readonly struct JsonataValue: IEquatable<JsonataValue>
{
    private readonly object? _payload;

    /// <summary>
    /// The discriminated kind of this value.
    /// </summary>
    public JsonataValueKind Kind { get; }


    private JsonataValue(JsonataValueKind kind, object? payload)
    {
        Kind = kind;
        _payload = payload;
    }


    /// <summary>
    /// The JSON <c>null</c> value, also the result of navigating into a member or element that does
    /// not exist (JSONata navigation yields "nothing", modelled here as <see cref="Null"/>).
    /// </summary>
    public static JsonataValue Null { get; } = new(JsonataValueKind.Null, null);

    /// <summary>The JSON boolean <c>true</c>.</summary>
    public static JsonataValue True { get; } = new(JsonataValueKind.Boolean, true);

    /// <summary>The JSON boolean <c>false</c>.</summary>
    public static JsonataValue False { get; } = new(JsonataValueKind.Boolean, false);


    /// <summary>
    /// Creates a JSON string value.
    /// </summary>
    /// <param name="value">The string contents.</param>
    /// <returns>A <see cref="JsonataValueKind.String"/> value.</returns>
    public static JsonataValue FromString(string value)
    {
        ArgumentNullException.ThrowIfNull(value);

        return new JsonataValue(JsonataValueKind.String, value);
    }


    /// <summary>
    /// Creates a JSON number value carried as an integral <see cref="long"/>.
    /// </summary>
    /// <param name="value">The integral value.</param>
    /// <returns>An <see cref="JsonataValueKind.Integer"/> value.</returns>
    public static JsonataValue FromInteger(long value)
    {
        return new JsonataValue(JsonataValueKind.Integer, value);
    }


    /// <summary>
    /// Creates a JSON number value carried as a fractional <see cref="double"/>.
    /// </summary>
    /// <param name="value">The fractional value.</param>
    /// <returns>A <see cref="JsonataValueKind.Number"/> value.</returns>
    public static JsonataValue FromNumber(double value)
    {
        return new JsonataValue(JsonataValueKind.Number, value);
    }


    /// <summary>
    /// Returns the JSON boolean value for <paramref name="value"/>.
    /// </summary>
    /// <param name="value">The boolean value.</param>
    /// <returns>A <see cref="JsonataValueKind.Boolean"/> value.</returns>
    public static JsonataValue FromBoolean(bool value)
    {
        return value ? True : False;
    }


    /// <summary>
    /// Creates a JSON object value from an ordered string→value map. The supplied dictionary is
    /// taken as-is (the caller transfers ownership); use an order-preserving dictionary to keep
    /// member order stable.
    /// </summary>
    /// <param name="members">The object members, in order.</param>
    /// <returns>An <see cref="JsonataValueKind.Object"/> value.</returns>
    public static JsonataValue FromObject(Dictionary<string, JsonataValue> members)
    {
        ArgumentNullException.ThrowIfNull(members);

        return new JsonataValue(JsonataValueKind.Object, members);
    }


    /// <summary>
    /// Creates a JSON array value from an ordered list of elements. The supplied list is taken
    /// as-is (the caller transfers ownership).
    /// </summary>
    /// <param name="elements">The array elements, in order.</param>
    /// <returns>An <see cref="JsonataValueKind.Array"/> value.</returns>
    public static JsonataValue FromArray(List<JsonataValue> elements)
    {
        ArgumentNullException.ThrowIfNull(elements);

        return new JsonataValue(JsonataValueKind.Array, elements);
    }


    /// <summary>Whether this value is the JSON <c>null</c> (or an absent navigation result).</summary>
    public bool IsNull => Kind == JsonataValueKind.Null;


    /// <summary>
    /// The string contents when <see cref="Kind"/> is <see cref="JsonataValueKind.String"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">When this value is not a string.</exception>
    public string AsString()
    {
        return Kind == JsonataValueKind.String
            ? (string)_payload!
            : throw new InvalidOperationException($"Value is {Kind}, not a string.");
    }


    /// <summary>
    /// The integral contents when <see cref="Kind"/> is <see cref="JsonataValueKind.Integer"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">When this value is not an integer.</exception>
    public long AsInteger()
    {
        return Kind == JsonataValueKind.Integer
            ? (long)_payload!
            : throw new InvalidOperationException($"Value is {Kind}, not an integer.");
    }


    /// <summary>
    /// The fractional contents when <see cref="Kind"/> is <see cref="JsonataValueKind.Number"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">When this value is not a fractional number.</exception>
    public double AsNumber()
    {
        return Kind == JsonataValueKind.Number
            ? (double)_payload!
            : throw new InvalidOperationException($"Value is {Kind}, not a number.");
    }


    /// <summary>
    /// The boolean contents when <see cref="Kind"/> is <see cref="JsonataValueKind.Boolean"/>.
    /// </summary>
    /// <exception cref="InvalidOperationException">When this value is not a boolean.</exception>
    public bool AsBoolean()
    {
        return Kind == JsonataValueKind.Boolean
            ? (bool)_payload!
            : throw new InvalidOperationException($"Value is {Kind}, not a boolean.");
    }


    /// <summary>
    /// The object members when <see cref="Kind"/> is <see cref="JsonataValueKind.Object"/>, in
    /// insertion order. The returned dictionary is the live backing store.
    /// </summary>
    /// <exception cref="InvalidOperationException">When this value is not an object.</exception>
    public IReadOnlyDictionary<string, JsonataValue> AsObject()
    {
        return Kind == JsonataValueKind.Object
            ? (Dictionary<string, JsonataValue>)_payload!
            : throw new InvalidOperationException($"Value is {Kind}, not an object.");
    }


    /// <summary>
    /// The array elements when <see cref="Kind"/> is <see cref="JsonataValueKind.Array"/>, in
    /// order. The returned list is the live backing store.
    /// </summary>
    /// <exception cref="InvalidOperationException">When this value is not an array.</exception>
    public IReadOnlyList<JsonataValue> AsArray()
    {
        return Kind == JsonataValueKind.Array
            ? (List<JsonataValue>)_payload!
            : throw new InvalidOperationException($"Value is {Kind}, not an array.");
    }


    /// <summary>
    /// Looks up a member by name when this value is an object, returning the member value or
    /// <see cref="Null"/> when this value is not an object or the member is absent. This is the
    /// navigation step the evaluator uses for a field reference into the input.
    /// </summary>
    /// <param name="name">The member name to look up.</param>
    /// <returns>The member value, or <see cref="Null"/> when absent or this value is not an object.</returns>
    public JsonataValue GetMemberOrNull(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        if(Kind != JsonataValueKind.Object)
        {
            return Null;
        }

        var members = (Dictionary<string, JsonataValue>)_payload!;

        return members.TryGetValue(name, out JsonataValue member) ? member : Null;
    }


    /// <inheritdoc/>
    public bool Equals(JsonataValue other)
    {
        if(Kind != other.Kind)
        {
            return false;
        }

        return Kind switch
        {
            JsonataValueKind.Null => true,
            JsonataValueKind.Boolean => (bool)_payload! == (bool)other._payload!,
            JsonataValueKind.Integer => (long)_payload! == (long)other._payload!,
            JsonataValueKind.Number => ((double)_payload!).Equals((double)other._payload!),
            JsonataValueKind.String => string.Equals((string)_payload!, (string)other._payload!, StringComparison.Ordinal),
            _ => ReferenceEquals(_payload, other._payload)
        };
    }


    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is JsonataValue other && Equals(other);


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return Kind switch
        {
            JsonataValueKind.Null => 0,
            JsonataValueKind.Boolean => HashCode.Combine(Kind, (bool)_payload!),
            JsonataValueKind.Integer => HashCode.Combine(Kind, (long)_payload!),
            JsonataValueKind.Number => HashCode.Combine(Kind, (double)_payload!),
            JsonataValueKind.String => HashCode.Combine(Kind, string.GetHashCode((string)_payload!, StringComparison.Ordinal)),
            _ => HashCode.Combine(Kind, _payload)
        };
    }


    /// <inheritdoc/>
    public static bool operator ==(JsonataValue left, JsonataValue right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(JsonataValue left, JsonataValue right) => !left.Equals(right);
}
