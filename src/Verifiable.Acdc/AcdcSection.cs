using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// A top-level ACDC section value (schema, attribute, edge, or rule), which is one of a closed set of two forms:
/// <see cref="CompactAcdcSection"/> — the section's SAID standing in for the whole section — or
/// <see cref="ExpandedAcdcSection"/> — the section's expanded detail block. A composable ACDC schema admits both via
/// a <c>oneOf</c> of the section's SAID or its block, so a received ACDC carries each section in whichever form was
/// disclosed.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#composable-json-schema">
/// composable JSON Schema</see>: the section field value is either the section's SAID (compact) or the section's
/// field map (expanded), and the same SAID identifies the section in either form.
/// </para>
/// <para>
/// This is modeled as a closed discriminated-union hierarchy: the base constructor is <see langword="private protected"/>
/// so the only cases are the two declared here (no type outside this assembly can add a case), and a consumer is
/// expected to match them exhaustively with a switch expression. This follows the codebase's existing closed-sum
/// shape (a sealed abstract base with sibling record cases, as the KERI key event types do) and is a candidate to
/// become a language discriminated union once one is available, at which point the declaration migrates while the
/// pattern-matching call sites stay as they are.
/// </para>
/// </remarks>
public abstract record AcdcSection
{
    /// <summary>
    /// Restricts the cases to those declared in this assembly, making this a closed hierarchy: no external type can
    /// derive from it.
    /// </summary>
    private protected AcdcSection()
    {
    }
}


/// <summary>
/// The compact form of an ACDC section: the section is represented by its SAID, the digest of the section's expanded
/// block.
/// </summary>
/// <param name="Said">The section's SAID.</param>
public sealed record CompactAcdcSection(string Said): AcdcSection;


/// <summary>
/// The expanded form of an ACDC section: the section's detail field map.
/// </summary>
/// <param name="Detail">The section's expanded detail block, an order-preserving field map.</param>
public sealed record ExpandedAcdcSection(MessageFieldMap Detail): AcdcSection;
