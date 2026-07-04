using System;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// Reads a decoded ACDC edge section field map into a typed <see cref="AcdcEdgeGroup"/> tree. This is the
/// serialization-agnostic parse of an edge section's expanded block (the <c>e</c> field's detail): the
/// bytes-to-field-map decode is a separate per-serialization seam, and this folds the neutral field map into the
/// typed property-graph sub-graph, validating the structural rules the specification fixes for edges and
/// edge-groups.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#edge-section">
/// edge section</see> and its <see href="https://trustoverip.github.io/kswg-acdc-specification/#block-types-2">
/// block types</see>: the edge section is the top-level edge-group, so reading it produces an
/// <see cref="AcdcEdgeGroup"/>. A block is an edge when it has a node, <c>n</c>, field and an edge-group when it does
/// not — an edge MUST have a node and an edge-group MUST NOT. A rule-group's reserved fields are <c>[d, u, o, w]</c>
/// and an edge's are <c>[d, u, n, s, o, w]</c>, each in that order (all optional except an edge's node), with the
/// UUID only following a SAID; the nested members of an edge-group, and the property fields of an edge, appear after
/// the reserved fields. The top-level edge-group MUST NOT carry a weight. A nested value that is a string is a
/// compact form — a compact edge's block SAID or a simple-compact edge's far-node SAID, distinguished by the
/// section's schema — so this carries the string as an <see cref="AcdcCompactEdgeNode"/> without classifying it.
/// </para>
/// <para>
/// The tree is materialized iteratively with an explicit work stack rather than by recursion, so the parse uses
/// bounded call-stack space however deeply the edge-groups nest; the nesting depth is itself bounded by the decode
/// arm that produced the field map. Edges are leaves of the edge sub-graph (their node points to a far ACDC by
/// SAID, not to a nested block), so an edge is built in place; only edge-groups are descended into. Evaluating the
/// sub-graph's validity — the operator defaults, the member aggregation, and the far-node schema checks — is a
/// separate capability that needs the far ACDCs resolved.
/// </para>
/// </remarks>
public static class AcdcEdgeReader
{
    /// <summary>
    /// Reads an edge section's expanded block into its typed edge-group tree.
    /// </summary>
    /// <param name="edgeSection">The edge section's expanded detail block (the <c>e</c> field's detail), an order-preserving field map as every decode arm produces.</param>
    /// <returns>The top-level edge-group (the edge section) with its nested edges and edge-groups in order.</returns>
    /// <exception cref="AcdcException">The top-level block is an edge rather than an edge-group; a reserved field is out of the order <c>[d, u, n, s, o, w]</c>, appears after a member, or is a reserved label not allowed in an edge block; a UUID appears without a SAID; an edge-group carries a node or a schema field; the top-level edge-group carries a weight; an operator or weight has an unsupported shape; or a member value is neither a block nor a string.</exception>
    public static AcdcEdgeGroup Read(MessageFieldMap edgeSection)
    {
        ArgumentNullException.ThrowIfNull(edgeSection);

        EdgeShell rootShell = ReadReservedFields(edgeSection);
        if(rootShell.Node is not null)
        {
            throw new AcdcException("The top-level edge section MUST be an edge-group, not an edge; it MUST NOT have a node 'n' field.");
        }

        RequireEdgeGroup(rootShell, isRoot: true);

        var stack = new Stack<Frame>();
        stack.Push(new Frame(label: null, indexInParent: -1, rootShell));
        AcdcEdgeGroup? result = null;

        while(stack.Count > 0)
        {
            Frame frame = stack.Peek();
            if(frame.Cursor < frame.Members.Count)
            {
                KeyValuePair<string, object?> member = frame.Members[frame.Cursor];
                int slot = frame.Cursor;
                frame.Cursor++;

                //A member is either a compact string (built inline), an edge block (a leaf, built inline), or a
                //nested edge-group block (a child frame to descend into, filled when it pops). The arm yields the
                //frame to push or null when the member was built without descending.
                Frame? child = member.Value switch
                {
                    string compact => Inline(frame, slot, member.Key, new AcdcCompactEdgeNode(compact)),
                    MessageFieldMap block => Descend(frame, slot, member.Key, block),
                    _ => throw new AcdcException($"ACDC edge member '{member.Key}' is neither an edge or edge-group block nor a compact string.")
                };

                if(child is not null)
                {
                    stack.Push(child);
                }

                continue;
            }

            //The frame's members are all built; close it into an edge-group and attach it to its parent's member
            //slot, or return it as the root when there is no parent.
            stack.Pop();
            var group = new AcdcEdgeGroup(frame.Said, frame.Uuid, ParseMaryOperator(frame.OperatorRaw), frame.Weight, Materialize(frame.Built));
            if(stack.Count == 0)
            {
                result = group;
            }
            else
            {
                stack.Peek().Built[frame.IndexInParent] = new AcdcEdgeMember(frame.Label!, group);
            }
        }

        return result!;

        static Frame? Inline(Frame frame, int slot, string label, AcdcEdgeNode node)
        {
            frame.Built[slot] = new AcdcEdgeMember(label, node);

            return null;
        }

        static Frame? Descend(Frame frame, int slot, string label, MessageFieldMap block)
        {
            EdgeShell shell = ReadReservedFields(block);
            if(shell.Node is not null)
            {
                frame.Built[slot] = new AcdcEdgeMember(label, BuildEdge(shell));

                return null;
            }

            RequireEdgeGroup(shell, isRoot: false);

            return new Frame(label, slot, shell);
        }

        static AcdcEdge BuildEdge(EdgeShell shell)
        {
            MessageFieldMap? properties = null;
            if(shell.Members.Count > 0)
            {
                properties = new MessageFieldMap(StringComparer.Ordinal);
                foreach(KeyValuePair<string, object?> property in shell.Members)
                {
                    properties[property.Key] = property.Value;
                }
            }

            return new AcdcEdge(shell.Said, shell.Uuid, shell.Node!, shell.Schema, ParseUnaryOperators(shell.OperatorRaw), shell.Weight, properties);
        }

        static void RequireEdgeGroup(EdgeShell shell, bool isRoot)
        {
            if(shell.Schema is not null)
            {
                throw new AcdcException("ACDC edge-group carries a schema 's' field, which is an edge-only reserved field; an edge-group's reserved fields are '[d, u, o, w]'.");
            }

            if(isRoot && shell.Weight is not null)
            {
                throw new AcdcException("The top-level edge-group (the edge section) MUST NOT have a weight 'w' field; it is not a member of another edge-group.");
            }
        }

        static IReadOnlyList<string>? ParseUnaryOperators(object? raw)
        {
            return raw switch
            {
                null => null,
                string single => [single],
                List<object?> list => ToOperatorList(list),
                _ => throw new AcdcException("An ACDC edge operator 'o' MUST be a single unary operator string or a list of unary operator strings.")
            };

            static IReadOnlyList<string> ToOperatorList(List<object?> list)
            {
                var operators = new List<string>(list.Count);
                foreach(object? entry in list)
                {
                    operators.Add(entry is string text
                        ? text
                        : throw new AcdcException("An ACDC edge operator list 'o' MUST contain only unary operator strings."));
                }

                return operators;
            }
        }

        static string? ParseMaryOperator(object? raw)
        {
            return raw switch
            {
                null => null,
                string single => single,
                _ => throw new AcdcException("An ACDC edge-group operator 'o' MUST be a single m-ary operator string.")
            };
        }

        static EdgeShell ReadReservedFields(MessageFieldMap block)
        {
            string? said = null;
            string? uuid = null;
            string? node = null;
            string? schema = null;
            object? operatorRaw = null;
            string? weight = null;
            var members = new List<KeyValuePair<string, object?>>();
            int lastReservedRank = -1;
            bool membersStarted = false;

            foreach(KeyValuePair<string, object?> field in block)
            {
                int rank = ReservedRank(field.Key);
                if(rank < 0)
                {
                    if(AcdcMessageFields.IsReserved(field.Key))
                    {
                        throw new AcdcException($"ACDC edge block carries the reserved field '{field.Key}', which is not allowed in an edge or edge-group; only '[d, u, n, s, o, w]' are reserved there.");
                    }

                    membersStarted = true;
                    members.Add(field);

                    continue;
                }

                if(membersStarted)
                {
                    throw new AcdcException($"ACDC edge block carries the reserved field '{field.Key}' after a nested member; the reserved fields MUST appear before any nested edge, edge-group, or property.");
                }

                if(rank <= lastReservedRank)
                {
                    throw new AcdcException($"ACDC edge block field '{field.Key}' is out of order; the reserved fields MUST appear in the order '[d, u, n, s, o, w]'.");
                }

                lastReservedRank = rank;
                object? value = field.Value;
                _ = rank switch
                {
                    0 => said = RequireString(field.Key, value),
                    1 => uuid = RequireString(field.Key, value),
                    2 => node = RequireString(field.Key, value),
                    3 => schema = RequireString(field.Key, value),
                    4 => operatorRaw = value,
                    5 => weight = ReadWeight(field.Key, value),
                    _ => throw new AcdcException($"ACDC edge block field '{field.Key}' has an unexpected reserved rank.")
                };
            }

            if(uuid is not null && said is null)
            {
                throw new AcdcException("ACDC edge block carries a UUID 'u' without a SAID 'd'; the UUID appears only as the second field following the SAID.");
            }

            return new EdgeShell(said, uuid, node, schema, operatorRaw, weight, members);
        }

        static int ReservedRank(string label) => label switch
        {
            _ when label == AcdcMessageFields.Said => 0,
            _ when label == AcdcMessageFields.Uuid => 1,
            _ when label == AcdcMessageFields.Node => 2,
            _ when label == AcdcMessageFields.Schema => 3,
            _ when label == AcdcMessageFields.Operator => 4,
            _ when label == AcdcMessageFields.Weight => 5,
            _ => -1
        };

        static string RequireString(string label, object? value)
        {
            return value is string text
                ? text
                : throw new AcdcException($"ACDC edge block field '{label}' MUST be a string.");
        }

        static string ReadWeight(string label, object? value)
        {
            return value is string text
                ? text
                : throw new AcdcException($"ACDC edge block field '{label}' is a non-string weight; numeric or structured edge weights are not modeled yet, only string weights.");
        }

        static IReadOnlyList<AcdcEdgeMember> Materialize(AcdcEdgeMember?[] built)
        {
            var members = new List<AcdcEdgeMember>(built.Length);
            foreach(AcdcEdgeMember? member in built)
            {
                members.Add(member ?? throw new AcdcException("An ACDC edge-group member was left unresolved while reading; this indicates a reader defect."));
            }

            return members;
        }
    }


    /// <summary>
    /// A mutable work item for the edge-tree walk: an edge-group being built — its reserved fields, the source
    /// members still to process, and the resolved members by slot. Held as a class so the cursor and the resolved
    /// slots mutate in place across <see cref="Stack{T}.Peek"/> calls; a struct frame would be copied and lose that
    /// progress.
    /// </summary>
    private sealed class Frame
    {
        /// <summary>
        /// Creates a frame for an edge-group at the given position in its parent.
        /// </summary>
        /// <param name="label">The non-reserved label this edge-group attaches under in its parent, or <see langword="null"/> for the root (the edge section).</param>
        /// <param name="indexInParent">The slot in the parent's resolved members this edge-group fills, or <c>-1</c> for the root.</param>
        /// <param name="shell">The edge-group's reserved fields and its source members.</param>
        public Frame(string? label, int indexInParent, EdgeShell shell)
        {
            Label = label;
            IndexInParent = indexInParent;
            Said = shell.Said;
            Uuid = shell.Uuid;
            OperatorRaw = shell.OperatorRaw;
            Weight = shell.Weight;
            Members = shell.Members;
            Built = new AcdcEdgeMember?[shell.Members.Count];
        }

        /// <summary>The non-reserved label this edge-group attaches under in its parent, or <see langword="null"/> for the root.</summary>
        public string? Label { get; }

        /// <summary>The slot in the parent's resolved members this edge-group fills, or <c>-1</c> for the root.</summary>
        public int IndexInParent { get; }

        /// <summary>The edge-group's SAID <c>d</c>, or <see langword="null"/> when absent.</summary>
        public string? Said { get; }

        /// <summary>The edge-group's UUID <c>u</c>, or <see langword="null"/> when absent.</summary>
        public string? Uuid { get; }

        /// <summary>The edge-group's raw operator <c>o</c> value, parsed to a single m-ary operator when the group is closed.</summary>
        public object? OperatorRaw { get; }

        /// <summary>The edge-group's weight <c>w</c>, or <see langword="null"/> when absent.</summary>
        public string? Weight { get; }

        /// <summary>The edge-group's nested members in source order, still to be resolved.</summary>
        public IReadOnlyList<KeyValuePair<string, object?>> Members { get; }

        /// <summary>The resolved members by slot, filled inline for edges and on pop for nested edge-groups.</summary>
        public AcdcEdgeMember?[] Built { get; }

        /// <summary>The index of the next source member to process.</summary>
        public int Cursor { get; set; }
    }


    /// <summary>
    /// The reserved fields read from an edge or edge-group block plus its nested members or properties, the
    /// intermediate the reader produces before classifying the block as an edge (when it has a node) or an
    /// edge-group (when it does not).
    /// </summary>
    /// <param name="Said">The block's SAID <c>d</c>, or <see langword="null"/> when absent.</param>
    /// <param name="Uuid">The block's UUID <c>u</c>, or <see langword="null"/> when absent.</param>
    /// <param name="Node">The block's node <c>n</c>, or <see langword="null"/> when absent (an edge-group); its presence marks the block an edge.</param>
    /// <param name="Schema">The block's far-node schema <c>s</c>, or <see langword="null"/> when absent.</param>
    /// <param name="OperatorRaw">The block's raw operator <c>o</c> value (a string or a list), or <see langword="null"/> when absent.</param>
    /// <param name="Weight">The block's weight <c>w</c>, or <see langword="null"/> when absent.</param>
    /// <param name="Members">The block's non-reserved labeled fields in source order: nested members for an edge-group, property fields for an edge.</param>
    private readonly record struct EdgeShell(string? Said, string? Uuid, string? Node, string? Schema, object? OperatorRaw, string? Weight, IReadOnlyList<KeyValuePair<string, object?>> Members);
}
