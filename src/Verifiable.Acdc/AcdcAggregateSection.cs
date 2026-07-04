using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// A typed ACDC selectively disclosable aggregate section (the top-level <c>A</c> field): the aggregate identifier
/// (AGID) that commits to an ordered set of blinded attribute blocks, together with those blocks in whichever form
/// each was disclosed. Unlike the partially disclosable attribute section <c>a</c>, whose compact form is a SAID,
/// the aggregate section's compact form is the AGID — an aggregate of the blocks' cryptographic commitments — which
/// enables selective disclosure: any one block can be revealed and proven a member of the set without revealing the
/// others.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#aggregate-section">
/// aggregate section</see> and <see href="https://trustoverip.github.io/kswg-acdc-specification/#blinded-attribute-array">
/// blinded attribute array</see>: the uncompacted aggregate section is a list whose zeroth element is the AGID and
/// whose remaining elements are the blinded attribute blocks. Each block carries its own SAID, <c>d</c>, and a
/// high-entropy UUID, <c>u</c>, so the block's SAID blinds its attribute values; the AGID is the digest of the
/// ordered list of the blocks' SAIDs (with the AGID's own slot dummied), as computed in
/// <see href="https://trustoverip.github.io/kswg-acdc-specification/#computation-of-the-agid-aggregate-id">
/// computation of the AGID</see>.
/// </para>
/// <para>
/// In a disclosure, each block is present either as its SAID (a <see cref="CompactAggregateBlock"/>, blinded) or as
/// its detail block (an <see cref="ExpandedAggregateBlock"/>, revealed); the AGID is the same in either case, so a
/// verifier reconstructs the list of block SAIDs — recomputing the SAID of each revealed block — and confirms the
/// recomputed AGID matches.
/// </para>
/// </remarks>
/// <param name="Agid">The aggregate identifier <c>a₀</c>: the digest committing to the ordered set of block SAIDs.</param>
/// <param name="Blocks">The blinded attribute blocks <c>a₁ … a_N</c> in order, each a SAID (blinded) or a detail block (revealed).</param>
public sealed record AcdcAggregateSection(string Agid, IReadOnlyList<AcdcAggregateBlock> Blocks);


/// <summary>
/// A blinded attribute block in an ACDC aggregate section, which is one of a closed set of two forms:
/// <see cref="CompactAggregateBlock"/> — the block's SAID standing in for the blinded block — or
/// <see cref="ExpandedAggregateBlock"/> — the block's revealed detail. A selectively disclosed aggregate section
/// carries each block in whichever form the discloser chose to reveal.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#composed-schema-for-selectively-disclosable-aggregate-section">
/// composed schema for the aggregate section</see>: each array item is a <c>oneOf</c> of the block's SAID or its
/// detail, so a block is disclosed either by its SAID (revealing nothing) or by its full detail.
/// </para>
/// <para>
/// This is modeled as a closed discriminated-union hierarchy: the base constructor is <see langword="private protected"/>
/// so the only cases are the two declared here, and a consumer is expected to match them exhaustively with a switch
/// expression, following the codebase's existing closed-sum shape (as <see cref="AcdcSection"/> does).
/// </para>
/// </remarks>
public abstract record AcdcAggregateBlock
{
    /// <summary>
    /// Restricts the cases to those declared in this assembly, making this a closed hierarchy: no external type can
    /// derive from it.
    /// </summary>
    private protected AcdcAggregateBlock()
    {
    }
}


/// <summary>
/// The blinded (undisclosed) form of an aggregate block: the block is represented by its SAID, the digest of the
/// block's detail, revealing nothing about the block's attribute values.
/// </summary>
/// <param name="Said">The block's SAID.</param>
public sealed record CompactAggregateBlock(string Said): AcdcAggregateBlock;


/// <summary>
/// The revealed form of an aggregate block: the block's detail field map (<c>d</c>, <c>u</c>, and its attribute
/// fields), from which the block's SAID is recomputed to prove the block a member of the aggregate.
/// </summary>
/// <param name="Detail">The block's revealed detail block, an order-preserving field map.</param>
public sealed record ExpandedAggregateBlock(MessageFieldMap Detail): AcdcAggregateBlock;
