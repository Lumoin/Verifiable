using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JsonPointer;

/// <summary>
/// Represents a node during document traversal with its path and value.
/// </summary>
/// <typeparam name="TValue">The type of the node value.</typeparam>
/// <remarks>
/// <para>
/// This struct captures the context at each point during depth-first traversal,
/// enabling filtering, transformation, and collection of nodes.
/// </para>
/// </remarks>
public readonly struct TraversalNode<TValue>: IEquatable<TraversalNode<TValue>>
{
    /// <summary>
    /// The JSON Pointer path to this node from the document root.
    /// </summary>
    public JsonPointer Path { get; }

    /// <summary>
    /// The value at this node.
    /// </summary>
    public TValue Value { get; }

    /// <summary>
    /// The depth of this node (0 = root).
    /// </summary>
    public int Depth => Path.Depth;

    /// <summary>
    /// Whether this node is the root of the document.
    /// </summary>
    public bool IsRoot => Path.IsRoot;


    /// <summary>
    /// Creates a new traversal node.
    /// </summary>
    /// <param name="path">The path to this node.</param>
    /// <param name="value">The value at this node.</param>
    public TraversalNode(JsonPointer path, TValue value)
    {
        Path = path;
        Value = value;
    }


    /// <summary>
    /// Deconstructs this node into its path and value.
    /// </summary>
    public void Deconstruct(out JsonPointer path, out TValue value)
    {
        path = Path;
        value = Value;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(TraversalNode<TValue> other)
    {
        return Path.Equals(other.Path) &&
               EqualityComparer<TValue>.Default.Equals(Value, other.Value);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is TraversalNode<TValue> other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() => HashCode.Combine(Path, Value);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(TraversalNode<TValue> left, TraversalNode<TValue> right) =>
        left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(TraversalNode<TValue> left, TraversalNode<TValue> right) =>
        !left.Equals(right);
}