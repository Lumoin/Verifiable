using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Asssesment
{
    [DebuggerDisplay("Node = {Node}, Depth = {Depth}")]
    public readonly struct TreeTraversalNode<TNodeType>
    {
        public TNodeType Node { get; }
        public int Depth { get; }

        public TreeTraversalNode(TNodeType node, int depth)
        {
            Node = node;
            Depth = depth;
        }

        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public bool Equals(TreeTraversalNode<TNodeType> other)
        {
            return EqualityComparer<TNodeType>.Default.Equals(Node, other.Node) && Depth == other.Depth;
        }


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override bool Equals([NotNullWhen(true)] object? o) => o is TreeTraversalNode<TNodeType> cryptoAlgorithm && Equals(cryptoAlgorithm);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in TreeTraversalNode<TNodeType> treeNode1, in TreeTraversalNode<TNodeType> treeNode2) => Equals(treeNode1, treeNode2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in TreeTraversalNode<TNodeType> treeNode1, in TreeTraversalNode<TNodeType> treeNode2) => !Equals(treeNode1, treeNode2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in object treeNode1, in TreeTraversalNode<TNodeType> treeNode2) => Equals(treeNode1, treeNode2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator ==(in TreeTraversalNode<TNodeType> treeNode1, in object treeNode2) => Equals(treeNode1, treeNode2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in object treeNode1, in TreeTraversalNode<TNodeType> treeNode2) => !Equals(treeNode1, treeNode2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public static bool operator !=(in TreeTraversalNode<TNodeType> treeNode1, in object treeNode2) => !Equals(treeNode1, treeNode2);


        /// <inheritdoc />
        [EditorBrowsable(EditorBrowsableState.Never)]
        public override int GetHashCode()
        {
            return HashCode.Combine(Node, Depth);
        }
    }
}
