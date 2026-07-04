using System;
using System.Collections.Generic;
using Verifiable.Cryptography;

namespace Verifiable.Acdc;

/// <summary>
/// Reads a decoded ACDC aggregate section value (the top-level <c>A</c> field) into a typed
/// <see cref="AcdcAggregateSection"/>. This is the serialization-agnostic parse of the aggregate section: the
/// bytes-to-value decode is a separate per-serialization seam, and this folds the neutral value — a compact AGID
/// string or a blinded attribute list — into the typed section the <see cref="AcdcAggregate"/> verifier checks.
/// </summary>
/// <remarks>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#aggregate-section">
/// aggregate section</see>: the <c>A</c> field is either the AGID (compact form, a string) or a list whose zeroth
/// element is the AGID and whose remaining elements are the blinded attribute blocks, each a SAID (blinded) or a
/// detail block (revealed). The list is flat — the blocks carry no nested SAIDed subblocks — so the parse is a
/// single pass rather than a tree walk.
/// </remarks>
public static class AcdcAggregateReader
{
    /// <summary>
    /// Reads a decoded aggregate section value into its typed section.
    /// </summary>
    /// <param name="aggregate">The decoded <c>A</c> field value: a string (the compact AGID) or a list whose zeroth element is the AGID and whose remaining elements are the blocks (a SAID string or a detail field map).</param>
    /// <returns>The typed aggregate section: the AGID and its blocks in order (empty when the section is the compact AGID alone).</returns>
    /// <exception cref="AcdcException">The value is neither a string nor a list, the list is empty, the AGID is not a string, or a block is neither a SAID nor a detail block.</exception>
    public static AcdcAggregateSection Read(object? aggregate)
    {
        return aggregate switch
        {
            string agid => new AcdcAggregateSection(agid, []),
            List<object?> list => ReadList(list),
            _ => throw new AcdcException("An ACDC aggregate section 'A' is neither a compact AGID string nor a blinded attribute list.")
        };

        static AcdcAggregateSection ReadList(List<object?> list)
        {
            if(list.Count == 0)
            {
                throw new AcdcException("An ACDC aggregate section list is empty; its zeroth element MUST be the AGID.");
            }

            if(list[0] is not string agid)
            {
                throw new AcdcException("An ACDC aggregate section list's zeroth element MUST be the AGID string.");
            }

            var blocks = new List<AcdcAggregateBlock>(list.Count - 1);
            for(int index = 1; index < list.Count; index++)
            {
                blocks.Add(list[index] switch
                {
                    string said => new CompactAggregateBlock(said),
                    MessageFieldMap detail => new ExpandedAggregateBlock(detail),
                    _ => throw new AcdcException($"An ACDC aggregate block at index {index} is neither a blinded SAID string nor a revealed detail block.")
                });
            }

            return new AcdcAggregateSection(agid, blocks);
        }
    }
}
