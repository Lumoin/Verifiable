using System;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// Reads a decoded ACDC rule section field map into a typed <see cref="AcdcRuleGroup"/> tree. This is the
/// serialization-agnostic parse of a rule section's expanded block (the <c>r</c> field's detail), the second
/// half of ACDC rule parsing: the bytes-to-field-map decode is a separate per-serialization seam, and this folds
/// the neutral field map into the typed Ricardian-contract tree, validating the structural rules the specification
/// fixes for rules and rule-groups.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#rule-section">
/// rule section</see> and its <see href="https://trustoverip.github.io/kswg-acdc-specification/#block-types">
/// block types</see>: the rule section is the top-level rule-group (the Rules Section), so reading it produces an
/// <see cref="AcdcRuleGroup"/>. A rule-group's reserved fields are <c>[d, u, l]</c> in that order — all optional,
/// and the UUID only following a SAID — after which its nested members appear, each labeled with a locally unique
/// non-reserved label. A nested block with one or more non-reserved labeled fields is itself a rule-group; a nested
/// block whose fields are only the reserved <c>[d, u, l]</c> is a rule, which MUST carry legal language <c>l</c>
/// and MUST NOT carry any other field. A nested value that is a string is a compact form — either the hidden
/// block's SAID (a compact rule or rule-group) or a simple-compact rule's legal language; those two are
/// distinguished by the section's schema, so this carries the string as an <see cref="AcdcCompactRuleNode"/>
/// without classifying it.
/// </para>
/// <para>
/// The tree is materialized iteratively with an explicit work stack rather than by recursion, so the parse uses
/// bounded call-stack space regardless of how deeply the rule-groups nest; the nesting depth is itself bounded by
/// the decode arm that produced the field map, which limits parse depth as a defense against adversarial input.
/// </para>
/// </remarks>
public static class AcdcRuleReader
{
    /// <summary>
    /// Reads a rule section's expanded block into its typed rule-group tree.
    /// </summary>
    /// <param name="ruleSection">The rule section's expanded detail block (the <c>r</c> field's detail), an order-preserving field map as every decode arm produces.</param>
    /// <returns>The top-level rule-group (the Rules Section) with its nested rules and rule-groups in order.</returns>
    /// <exception cref="AcdcException">A reserved field is out of the order <c>[d, u, l]</c>, appears after a nested member, is a reserved label other than <c>[d, u, l]</c>, or is not a string; a UUID appears without a SAID; a rule has no legal language; or a member value is neither a block nor a string.</exception>
    public static AcdcRuleGroup Read(MessageFieldMap ruleSection)
    {
        ArgumentNullException.ThrowIfNull(ruleSection);

        var stack = new Stack<Frame>();
        stack.Push(new Frame(label: null, indexInParent: -1, ReadReservedFields(ruleSection)));
        AcdcRuleGroup? result = null;

        while(stack.Count > 0)
        {
            Frame frame = stack.Peek();
            if(frame.Cursor < frame.Members.Count)
            {
                KeyValuePair<string, object?> member = frame.Members[frame.Cursor];
                int slot = frame.Cursor;
                frame.Cursor++;

                //A member is either a compact string (built inline), a leaf rule block (built inline), or a nested
                //rule-group (a child frame to descend into, filled when it pops). The arm yields the frame to push
                //or null when the member was built without descending.
                Frame? child = member.Value switch
                {
                    string compact => Inline(frame, slot, member.Key, new AcdcCompactRuleNode(compact)),
                    MessageFieldMap block => Descend(frame, slot, member.Key, block),
                    _ => throw new AcdcException($"ACDC rule member '{member.Key}' is neither a rule or rule-group block nor a compact string.")
                };

                if(child is not null)
                {
                    stack.Push(child);
                }

                continue;
            }

            //The frame's members are all built; close it into a rule-group and attach it to its parent's reserved
            //slot, or return it as the root when there is no parent.
            stack.Pop();
            var group = new AcdcRuleGroup(frame.Said, frame.Uuid, frame.Legal, Materialize(frame.Built));
            if(stack.Count == 0)
            {
                result = group;
            }
            else
            {
                stack.Peek().Built[frame.IndexInParent] = new AcdcRuleMember(frame.Label!, group);
            }
        }

        return result!;

        static Frame? Inline(Frame frame, int slot, string label, AcdcRuleNode node)
        {
            frame.Built[slot] = new AcdcRuleMember(label, node);

            return null;
        }

        static Frame? Descend(Frame frame, int slot, string label, MessageFieldMap block)
        {
            RuleShell shell = ReadReservedFields(block);
            if(shell.Members.Count > 0)
            {
                return new Frame(label, slot, shell);
            }

            frame.Built[slot] = new AcdcRuleMember(label, BuildRule(label, shell));

            return null;
        }

        static AcdcRule BuildRule(string label, RuleShell shell)
        {
            if(shell.Legal is null)
            {
                throw new AcdcException($"ACDC rule '{label}' is missing the required legal language 'l' field; a rule MUST have legal language.");
            }

            return new AcdcRule(shell.Said, shell.Uuid, shell.Legal);
        }

        static RuleShell ReadReservedFields(MessageFieldMap block)
        {
            string? said = null;
            string? uuid = null;
            string? legal = null;
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
                        throw new AcdcException($"ACDC rule block carries the reserved field '{field.Key}', which is not allowed in a rule or rule-group; only '[d, u, l]' are reserved there.");
                    }

                    membersStarted = true;
                    members.Add(field);

                    continue;
                }

                if(membersStarted)
                {
                    throw new AcdcException($"ACDC rule block carries the reserved field '{field.Key}' after a nested member; the reserved fields MUST appear before any nested rule or rule-group.");
                }

                if(rank <= lastReservedRank)
                {
                    throw new AcdcException($"ACDC rule block field '{field.Key}' is out of order; the reserved fields MUST appear in the order '[d, u, l]'.");
                }

                lastReservedRank = rank;
                string text = RequireString(field.Key, field.Value);
                _ = rank switch
                {
                    0 => said = text,
                    1 => uuid = text,
                    2 => legal = text,
                    _ => throw new AcdcException($"ACDC rule block field '{field.Key}' has an unexpected reserved rank.")
                };
            }

            if(uuid is not null && said is null)
            {
                throw new AcdcException("ACDC rule block carries a UUID 'u' without a SAID 'd'; the UUID appears only as the second field following the SAID.");
            }

            return new RuleShell(said, uuid, legal, members);
        }

        static int ReservedRank(string label) => label switch
        {
            _ when label == AcdcMessageFields.Said => 0,
            _ when label == AcdcMessageFields.Uuid => 1,
            _ when label == AcdcMessageFields.LegalLanguage => 2,
            _ => -1
        };

        static string RequireString(string label, object? value)
        {
            return value is string text
                ? text
                : throw new AcdcException($"ACDC rule block field '{label}' MUST be a string.");
        }

        static IReadOnlyList<AcdcRuleMember> Materialize(AcdcRuleMember?[] built)
        {
            var members = new List<AcdcRuleMember>(built.Length);
            foreach(AcdcRuleMember? member in built)
            {
                members.Add(member ?? throw new AcdcException("An ACDC rule-group member was left unresolved while reading; this indicates a reader defect."));
            }

            return members;
        }
    }


    /// <summary>
    /// A mutable work item for the rule-tree walk: a rule-group being built — its reserved fields, the source
    /// members still to process, and the resolved members by slot. Held as a class so the cursor and the resolved
    /// slots mutate in place across <see cref="Stack{T}.Peek"/> calls; a struct frame would be copied and lose that
    /// progress.
    /// </summary>
    private sealed class Frame
    {
        /// <summary>
        /// Creates a frame for a rule-group at the given position in its parent.
        /// </summary>
        /// <param name="label">The non-reserved label this rule-group attaches under in its parent, or <see langword="null"/> for the root (the rule section).</param>
        /// <param name="indexInParent">The slot in the parent's resolved members this rule-group fills, or <c>-1</c> for the root.</param>
        /// <param name="shell">The rule-group's reserved fields and its source members.</param>
        public Frame(string? label, int indexInParent, RuleShell shell)
        {
            Label = label;
            IndexInParent = indexInParent;
            Said = shell.Said;
            Uuid = shell.Uuid;
            Legal = shell.Legal;
            Members = shell.Members;
            Built = new AcdcRuleMember?[shell.Members.Count];
        }

        /// <summary>The non-reserved label this rule-group attaches under in its parent, or <see langword="null"/> for the root.</summary>
        public string? Label { get; }

        /// <summary>The slot in the parent's resolved members this rule-group fills, or <c>-1</c> for the root.</summary>
        public int IndexInParent { get; }

        /// <summary>The rule-group's SAID <c>d</c>, or <see langword="null"/> when absent.</summary>
        public string? Said { get; }

        /// <summary>The rule-group's UUID <c>u</c>, or <see langword="null"/> when absent.</summary>
        public string? Uuid { get; }

        /// <summary>The rule-group's legal language <c>l</c>, or <see langword="null"/> when absent.</summary>
        public string? Legal { get; }

        /// <summary>The rule-group's nested members in source order, still to be resolved.</summary>
        public IReadOnlyList<KeyValuePair<string, object?>> Members { get; }

        /// <summary>The resolved members by slot, filled inline for leaves and on pop for nested rule-groups.</summary>
        public AcdcRuleMember?[] Built { get; }

        /// <summary>The index of the next source member to process.</summary>
        public int Cursor { get; set; }
    }


    /// <summary>
    /// The reserved fields read from a rule or rule-group block plus its nested members, the intermediate the reader
    /// produces before classifying the block as a rule or a rule-group.
    /// </summary>
    /// <param name="Said">The block's SAID <c>d</c>, or <see langword="null"/> when absent.</param>
    /// <param name="Uuid">The block's UUID <c>u</c>, or <see langword="null"/> when absent.</param>
    /// <param name="Legal">The block's legal language <c>l</c>, or <see langword="null"/> when absent.</param>
    /// <param name="Members">The block's nested non-reserved labeled members in source order.</param>
    private readonly record struct RuleShell(string? Said, string? Uuid, string? Legal, IReadOnlyList<KeyValuePair<string, object?>> Members);
}
