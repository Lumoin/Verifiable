using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Assessment;

[DebuggerDisplay("Node = {Node}, Depth = {Depth}")]
internal readonly struct TreeTraversalNode<TNodeType>(TNodeType node, int depth)
    : IEquatable<TreeTraversalNode<TNodeType>>
{
    public TNodeType Node { get; } = node;

    public int Depth { get; } = depth;


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(TreeTraversalNode<TNodeType> other)
    {
        return EqualityComparer<TNodeType>.Default.Equals(Node, other.Node) && Depth == other.Depth;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj)
    {
        return obj is TreeTraversalNode<TNodeType> other && Equals(other);
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        return HashCode.Combine(Node, Depth);
    }


    /// <summary>
    /// Determines whether two nodes are equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(TreeTraversalNode<TNodeType> left, TreeTraversalNode<TNodeType> right) => left.Equals(right);

    /// <summary>
    /// Determines whether two nodes are not equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(TreeTraversalNode<TNodeType> left, TreeTraversalNode<TNodeType> right) => !left.Equals(right);
}