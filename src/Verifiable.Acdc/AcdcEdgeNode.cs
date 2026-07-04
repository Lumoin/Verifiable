using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// A node in an ACDC edge section's sub-graph, which is one of a closed set of three forms:
/// <see cref="AcdcEdgeGroup"/> — an intermediate node that aggregates nested edges or edge-groups under an
/// operator — or <see cref="AcdcEdge"/> — a directed edge that points, via its node <c>n</c> field, to a far ACDC —
/// or <see cref="AcdcCompactEdgeNode"/> — a nested node disclosed in compact string form (a compact edge's block
/// SAID, or a simple-compact edge's far-node SAID).
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#block-types-2">
/// edge section block types</see>: the values nested within an edge section are Edges or Edge-groups, and an edge is
/// distinguished from an edge-group by the required presence of a node, <c>n</c>, field — an edge MUST have one and
/// an edge-group MUST NOT. The edge section as a whole is the top-level edge-group, so reading an edge section
/// produces an <see cref="AcdcEdgeGroup"/> whose members are these nodes. A set of ACDCs linked by edges forms a
/// distributed property graph; each edge's node points to a far ACDC by its SAID, and the edge and edge-group
/// operators express the validity logic over that sub-graph.
/// </para>
/// <para>
/// This is modeled as a closed discriminated-union hierarchy: the base constructor is <see langword="private protected"/>
/// so the only cases are the three declared here, and a consumer is expected to match them exhaustively with a
/// switch expression. This follows the codebase's existing closed-sum shape (a sealed abstract base with sibling
/// record cases, as <see cref="AcdcRuleNode"/> and <see cref="AcdcSection"/> do) and is a candidate to become a
/// language discriminated union once one is available.
/// </para>
/// <para>
/// This models the edge section's structure and its SAID tree. Evaluating an edge sub-graph's validity — resolving
/// the effective operator list (the <c>I2I</c>/<c>NI2I</c> defaults that depend on whether the far node is
/// targeted), aggregating member validity under the m-ary operators, and checking the far node against the edge's
/// schema <c>s</c> — requires resolving the far ACDCs and the issuer key state, so it is a separate capability built
/// on this one.
/// </para>
/// </remarks>
public abstract record AcdcEdgeNode
{
    /// <summary>
    /// Restricts the cases to those declared in this assembly, making this a closed hierarchy: no external type can
    /// derive from it.
    /// </summary>
    private protected AcdcEdgeNode()
    {
    }
}


/// <summary>
/// An edge-group: an intermediate node in an edge section that aggregates one or more labeled edges or edge-groups
/// under an m-ary operator, and MAY carry a SAID, a UUID, the operator, and a weight, but never a node <c>n</c>
/// field. The edge section as a whole is the top-level edge-group.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#edge-group">
/// edge-group</see>: the reserved fields are <c>[d, u, o, w]</c> in that order (all optional, and the UUID only with
/// a SAID), followed by the nested labeled members. The operator <c>o</c> is an m-ary operator over the members
/// (<c>AND</c>, <c>OR</c>, <c>NAND</c>, <c>NOR</c>, <c>AVG</c>, or <c>WAVG</c>), defaulting to <c>AND</c> when
/// absent. The top-level edge-group MUST NOT have a weight, <c>w</c>, because it is not a member of another
/// edge-group.
/// </remarks>
/// <param name="Said">The edge-group's SAID <c>d</c>, or <see langword="null"/> when absent.</param>
/// <param name="Uuid">The edge-group's UUID <c>u</c> (a high-entropy salty nonce), or <see langword="null"/> when absent; present only when <paramref name="Said"/> is present.</param>
/// <param name="Operator">The m-ary operator <c>o</c> over the members, or <see langword="null"/> when absent (the default <c>AND</c> applies).</param>
/// <param name="Weight">The edge-group's weight <c>w</c>, or <see langword="null"/> when absent; always absent for the top-level edge-group.</param>
/// <param name="Members">The nested labeled edges and edge-groups, in their order of appearance; empty when the edge-group has no nested members.</param>
public sealed record AcdcEdgeGroup(string? Said, string? Uuid, string? Operator, string? Weight, IReadOnlyList<AcdcEdgeMember> Members): AcdcEdgeNode;


/// <summary>
/// An edge: a directed edge from the near node (the enclosing ACDC) to a far node ACDC, identified by the required
/// node <c>n</c> field. It MAY carry a SAID, a UUID, a far-node schema constraint <c>s</c>, one or more unary
/// operators, a weight, and additional labeled property fields.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#edge">
/// edge</see>: the reserved fields are <c>[d, u, n, s, o, w]</c> in that order, the node <c>n</c> is required (its
/// presence is what distinguishes an edge from an edge-group), the UUID <c>u</c> appears only with a SAID <c>d</c>,
/// and the schema <c>s</c>, when present, constrains the far node ACDC. The operator <c>o</c> is one unary operator
/// or a list of them (<c>I2I</c>, <c>NI2I</c>, <c>DI2I</c>, or <c>NOT</c>); their effective evaluation, including the
/// targeted-node defaults, is part of edge evaluation rather than this structural model. Any non-reserved labeled
/// fields are the edge's property fields, which MUST appear after the reserved fields.
/// </remarks>
/// <param name="Said">The edge's SAID <c>d</c>, or <see langword="null"/> when absent.</param>
/// <param name="Uuid">The edge's UUID <c>u</c> (a high-entropy salty nonce), or <see langword="null"/> when absent; present only when <paramref name="Said"/> is present.</param>
/// <param name="Node">The node <c>n</c>: the SAID of the far ACDC this edge points to; required.</param>
/// <param name="Schema">The far-node schema constraint <c>s</c> (a schema SAID), or <see langword="null"/> when absent.</param>
/// <param name="Operators">The unary operators <c>o</c> in order, or <see langword="null"/> when absent; a single operator is carried as a one-element list.</param>
/// <param name="Weight">The edge's weight <c>w</c>, or <see langword="null"/> when absent.</param>
/// <param name="Properties">The edge's non-reserved labeled property fields, in order, or <see langword="null"/> when the edge has none.</param>
public sealed record AcdcEdge(string? Said, string? Uuid, string Node, string? Schema, IReadOnlyList<string>? Operators, string? Weight, MessageFieldMap? Properties): AcdcEdgeNode;


/// <summary>
/// A nested edge node disclosed in compact string form. The same string spans two of the specification's compact
/// variants that are not distinguishable without the schema: a compact edge (the value is the hidden edge block's
/// SAID) and a simple-compact edge (the value is the far node's SAID directly). Classifying which variant a given
/// value is requires the section's schema, so this node carries the raw string and leaves the classification to a
/// schema-aware step.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#compact-edge">
/// compact edge</see> and <see href="https://trustoverip.github.io/kswg-acdc-specification/#simple-compact-edge">
/// simple-compact edge</see>: the schema for a nested label MUST indicate via a <c>oneOf</c> composition whether a
/// string value at that label is the edge block's SAID or, for a simple-compact edge, the far node's SAID. Because
/// that determination is "type-is-schema" and the repository's schema validation is deferred with the schema
/// section, this models the value without asserting which variant it is.
/// </remarks>
/// <param name="Value">The compact string value: either an edge block's SAID or a simple-compact edge's far-node SAID, as the section's schema determines.</param>
public sealed record AcdcCompactEdgeNode(string Value): AcdcEdgeNode;


/// <summary>
/// A labeled member of an edge-group: the locally unique non-reserved field label that identifies a nested edge or
/// edge-group, paired with that node.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#labeled-nested-edge-and-edge-group-fields">
/// labeled nested edge and edge-group fields</see>: each nested block is a field whose label is locally unique and
/// is not one of the reserved edge labels <c>[d, u, n, s, o, w]</c>, and the label's matching subschema (not a type
/// field) indicates the nested block's type.
/// </remarks>
/// <param name="Label">The member's local, non-reserved field label.</param>
/// <param name="Node">The nested edge or edge-group, or its compact string form.</param>
public sealed record AcdcEdgeMember(string Label, AcdcEdgeNode Node);
