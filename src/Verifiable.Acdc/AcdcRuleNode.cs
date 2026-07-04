using System.Collections.Generic;

namespace Verifiable.Acdc;

/// <summary>
/// A node in an ACDC rule section's sub-graph of Ricardian-contract clauses, which is one of a closed set of three
/// forms: <see cref="AcdcRuleGroup"/> — an intermediate node that nests further rules or rule-groups — or
/// <see cref="AcdcRule"/> — a terminal clause that carries legal language — or <see cref="AcdcCompactRuleNode"/> —
/// a nested node disclosed in compact string form (either a compact SAID standing in for a hidden block, or a
/// simple-compact rule whose value is the legal language itself).
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#block-types">
/// rule section block types</see>: the values nested within a rule section are Rules or Rule-groups, and each MAY be
/// disclosed either as its block or, in compact form, as a string. The rule section as a whole is the top-level
/// Rule-group (the Rules Section), so reading a rule section produces an <see cref="AcdcRuleGroup"/> whose members
/// are these nodes.
/// </para>
/// <para>
/// This is modeled as a closed discriminated-union hierarchy: the base constructor is <see langword="private protected"/>
/// so the only cases are the three declared here (no type outside this assembly can add a case), and a consumer is
/// expected to match them exhaustively with a switch expression. This follows the codebase's existing closed-sum
/// shape (a sealed abstract base with sibling record cases, as <see cref="AcdcSection"/> does) and is a candidate to
/// become a language discriminated union once one is available, at which point the declaration migrates while the
/// pattern-matching call sites stay as they are.
/// </para>
/// </remarks>
public abstract record AcdcRuleNode
{
    /// <summary>
    /// Restricts the cases to those declared in this assembly, making this a closed hierarchy: no external type can
    /// derive from it.
    /// </summary>
    private protected AcdcRuleNode()
    {
    }
}


/// <summary>
/// A rule-group: an intermediate node in a rule section that nests one or more labeled rules or rule-groups, and MAY
/// itself carry a SAID, a UUID, and legal language. The rule section as a whole is the top-level rule-group.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#rule-group">
/// rule-group</see>: the reserved fields are <c>[d, u, l]</c> in that order (all optional, and the UUID only with a
/// SAID), followed by the nested labeled members. The top-level rule-group's SAID is the same value used as the
/// compacted rule section, <c>r</c>; a nested rule-group's SAID and UUID, when both present, make it a private
/// rule-group that can be hidden behind its SAID until disclosed.
/// </remarks>
/// <param name="Said">The rule-group's SAID <c>d</c>, or <see langword="null"/> when absent.</param>
/// <param name="Uuid">The rule-group's UUID <c>u</c> (a high-entropy salty nonce), or <see langword="null"/> when absent; present only when <paramref name="Said"/> is present.</param>
/// <param name="Legal">The rule-group's legal language <c>l</c>, or <see langword="null"/> when absent.</param>
/// <param name="Members">The nested labeled rules and rule-groups, in their order of appearance; empty when the rule-group has no nested members.</param>
public sealed record AcdcRuleGroup(string? Said, string? Uuid, string? Legal, IReadOnlyList<AcdcRuleMember> Members): AcdcRuleNode;


/// <summary>
/// A rule: a terminal clause that carries legal language and MAY carry a SAID and a UUID, but no other fields.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#rule">
/// rule</see>: the reserved fields are <c>[d, u, l]</c> in that order, the legal language <c>l</c> is required, the
/// UUID <c>u</c> appears only with a SAID <c>d</c>, and a rule MUST NOT have any other fields. A rule with both a
/// SAID and a UUID is a private rule that can be hidden behind its SAID until disclosed.
/// </remarks>
/// <param name="Said">The rule's SAID <c>d</c>, or <see langword="null"/> when absent.</param>
/// <param name="Uuid">The rule's UUID <c>u</c> (a high-entropy salty nonce), or <see langword="null"/> when absent; present only when <paramref name="Said"/> is present.</param>
/// <param name="Legal">The rule's legal language <c>l</c>; required.</param>
public sealed record AcdcRule(string? Said, string? Uuid, string Legal): AcdcRuleNode;


/// <summary>
/// A nested rule node disclosed in compact string form. The same string spans two of the specification's compact
/// variants that are not distinguishable without the schema: a compact rule or rule-group (the value is the hidden
/// block's SAID) and a simple-compact rule (the value is the legal language itself). Classifying which variant a
/// given value is requires the section's schema, so this node carries the raw string and leaves the classification
/// to a schema-aware step.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#compact-rule">
/// compact rule</see> and <see href="https://trustoverip.github.io/kswg-acdc-specification/#simple-compact-rule">
/// simple-compact rule</see>: the schema for a nested label MUST indicate via a <c>oneOf</c> composition whether a
/// string value at that label is the block's SAID or, for a simple-compact rule, the legal language. Because that
/// determination is "type-is-schema" and the repository's schema validation is deferred with the schema section,
/// this models the value without asserting which variant it is.
/// </remarks>
/// <param name="Value">The compact string value: either a block's SAID or a simple-compact rule's legal language, as the section's schema determines.</param>
public sealed record AcdcCompactRuleNode(string Value): AcdcRuleNode;


/// <summary>
/// A labeled member of a rule-group: the locally unique non-reserved field label that identifies a nested rule or
/// rule-group, paired with that node.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#rule-group">
/// labeled nested rule and rule-group fields</see>: each nested block is a field whose label is locally unique and
/// is not one of the reserved rule labels <c>[d, u, l]</c>, and the label's matching subschema (not a type field)
/// indicates the nested block's type.
/// </remarks>
/// <param name="Label">The member's local, non-reserved field label.</param>
/// <param name="Node">The nested rule or rule-group, or its compact string form.</param>
public sealed record AcdcRuleMember(string Label, AcdcRuleNode Node);
