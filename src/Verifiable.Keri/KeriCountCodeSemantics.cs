using Verifiable.Cesr;

namespace Verifiable.Keri;

/// <summary>
/// The genus-specific meaning of the KERI / ACDC count and group codes: given a count code, says what its group
/// body frames (<see cref="KeriGroupContent"/>) so a consumer can choose how to walk the body the CESR codec
/// handed back. This is the bridge from the genus-neutral codec to the protocol layer — the codec frames a
/// group; this table, keyed by the genus the stream declared, gives that group its meaning.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the CESR specification's <see href="https://trustoverip.github.io/kswg-cesr-specification/#master-code-table-for-genusversion--_aaacaa-keriacdc-protocol-stack-version-200">
/// Master code table for genus/version -_AAACAA</see> (KERI/ACDC protocol stack version 2.00). The
/// classification is by the code's type character, which is the same for the small (<c>-X##</c>) and large
/// (<c>--X#####</c>) forms of a code. The opaque genus/version code (<c>-_…</c>) frames no group body and is
/// rejected.
/// </para>
/// </remarks>
public static class KeriCountCodeSemantics
{
    /// <summary>
    /// Classifies what the group body framed by a KERI / ACDC count code contains.
    /// </summary>
    /// <param name="code">The stable (hard) count code, for example <c>-K</c>, <c>--K</c>, or <c>-Q</c>.</param>
    /// <returns>What the framed body contains, and so which walk to run over it.</returns>
    /// <exception cref="CesrFormatException">The code is not a KERI / ACDC count code, or is a genus/version code that frames no body.</exception>
    public static KeriGroupContent Classify(string code)
    {
        ArgumentNullException.ThrowIfNull(code);

        if(code.Length < 2 || code[0] != '-')
        {
            throw new CesrFormatException($"'{code}' is not a CESR count code.");
        }

        if(code[1] == '_')
        {
            throw new CesrFormatException($"Genus/version code '{code}' frames no group body.");
        }

        char type = TypeCharacterOf(code);

        return type switch
        {
            //Genus-specific indexed signature groups (spec rows -K controller, -L witness). These are the one
            //place the two signature-group type characters are defined; consumers read the meaning off
            //KeriGroupContent rather than re-testing the character.
            'K' => KeriGroupContent.ControllerSignatures,
            'L' => KeriGroupContent.WitnessSignatures,

            //Flat primitive tuples: receipts and first-seen replay (-M, -N, -O), seals (-Q..-W), and blinded
            //state (-a, -b, -c). Their bodies are sequences of primitives grouped by the code's arity.
            'M' or 'N' or 'O' or 'Q' or 'R' or 'S' or 'T' or 'U' or 'V' or 'W' or 'a' or 'b' or 'c' => KeriGroupContent.Primitives,

            //Containers, messages, and mixed/composite groups whose bodies hold nested count groups or a
            //structured message: the universal pipeline/message/attachment/datagram/ESSR/native-message/field-map
            //and list codes (-A..-J) plus the pathed (-P), transferable indexed-signature (-X, -Y), and ESSR
            //payload (-Z) groups.
            'A' or 'B' or 'C' or 'D' or 'E' or 'F' or 'G' or 'H' or 'I' or 'J' or 'P' or 'X' or 'Y' or 'Z' => KeriGroupContent.NestedGroups,

            _ => throw new CesrFormatException($"Unsupported KERI/ACDC count code type '{type}' in code '{code}'.")
        };
    }


    /// <summary>
    /// Whether a count code frames a group of indexed signatures (so a consumer walks it as indexed signatures),
    /// whether controller (<c>-K</c>) or witness (<c>-L</c>).
    /// </summary>
    /// <param name="code">The stable (hard) count code.</param>
    /// <returns><see langword="true"/> when the code is an indexed controller or witness signature group.</returns>
    public static bool IsIndexedSignatureGroup(string code) => Classify(code) is KeriGroupContent.ControllerSignatures or KeriGroupContent.WitnessSignatures;


    /// <summary>
    /// Whether a count code frames a flat sequence of primitives (so a consumer walks it as primitives).
    /// </summary>
    /// <param name="code">The stable (hard) count code.</param>
    /// <returns><see langword="true"/> when the code is a seal, receipt, replay, or blinded-state group.</returns>
    public static bool IsPrimitiveGroup(string code) => Classify(code) == KeriGroupContent.Primitives;


    /// <summary>
    /// Reads the type character of a count code: the character after the single selector of a small code
    /// (<c>-X##</c>) or after the double selector of a large code (<c>--X#####</c>).
    /// </summary>
    private static char TypeCharacterOf(string code)
    {
        if(code[1] != '-')
        {
            return code[1];
        }

        if(code.Length < 3)
        {
            throw new CesrFormatException($"Truncated large CESR count code '{code}'.");
        }

        return code[2];
    }
}
