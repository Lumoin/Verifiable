using System.Collections.Generic;

namespace Verifiable.Keri;

/// <summary>
/// The field labels of KERI seals (the field maps in an event's anchor list, field <c>a</c>). A seal makes a
/// verifiable, nonrepudiable commitment to external data via a digest without disclosing the data; its type is
/// determined by which of these labels it carries. This centralizes the labels so a reader, a builder, and the
/// tests agree on the wire names, kept separate from <see cref="KeriMessageFields"/> because a seal label such as
/// <c>t</c> (seal type) has a different meaning from the same string at the top level (message type).
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the KERI specification's <see href="https://trustoverip.github.io/kswg-keri-specification/#seals">
/// seals</see>. The label combinations identify the seal type: a digest seal carries only <c>d</c>; a Merkle tree
/// root seal only <c>rd</c>; a source event seal <c>[s, d]</c>; a key event seal <c>[i, s, d]</c>; a latest
/// establishment event seal only <c>i</c>; a registrar backer seal <c>[bi, d]</c>; and a typed seal <c>[t, d]</c>.
/// Each seal type fixes the order of its fields on the wire (which bears on a SAID computed over the
/// serialization); reading from an unordered decoded map verifies the field set rather than the order.
/// </para>
/// </remarks>
public static class KeriSealFields
{
    /// <summary>The digest label <c>d</c>: a cryptographic digest of external data, usually its SAID.</summary>
    public static string Digest { get; } = "d";

    /// <summary>The Merkle tree root digest label <c>rd</c>: the root digest of a Merkle tree of external data digests.</summary>
    public static string MerkleRootDigest { get; } = "rd";

    /// <summary>The sequence number label <c>s</c>: the hexadecimal sequence number of the sealed source event.</summary>
    public static string SequenceNumber { get; } = "s";

    /// <summary>The identifier prefix label <c>i</c>: the AID of the external event log a seal references.</summary>
    public static string Prefix { get; } = "i";

    /// <summary>The backer identifier label <c>bi</c>: the non-transferable AID of a registrar backer.</summary>
    public static string BackerIdentifier { get; } = "bi";

    /// <summary>The seal type label <c>t</c>: the versioned type of a typed seal (a qb64 text primitive).</summary>
    public static string SealType { get; } = "t";


    /// <summary>
    /// The set of KERI seal field labels.
    /// </summary>
    private static HashSet<string> Labels { get; } = new(System.StringComparer.Ordinal)
    {
        Digest, MerkleRootDigest, SequenceNumber, Prefix, BackerIdentifier, SealType
    };


    /// <summary>
    /// Whether a label is one of the KERI seal field labels.
    /// </summary>
    /// <param name="label">The field label to test.</param>
    /// <returns><see langword="true"/> when the label is a seal field label.</returns>
    public static bool IsSealField(string label)
    {
        ArgumentNullException.ThrowIfNull(label);

        return Labels.Contains(label);
    }
}
