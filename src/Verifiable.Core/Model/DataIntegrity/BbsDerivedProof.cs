using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Represents the parsed components of a bbs-2023 derived proof value.
/// </summary>
/// <remarks>
/// <para>
/// The derived proof is created by the holder from a base proof and sent to the verifier.
/// It contains only the information needed to verify the selectively disclosed statements.
/// </para>
/// <list type="bullet">
///   <item><description>BBS proof over the disclosed messages.</description></item>
///   <item><description>Label map from canonical to HMAC-based blank node identifiers.</description></item>
///   <item><description>Mandatory indexes indicating which statements in the reveal document are mandatory.</description></item>
///   <item><description>Selective indexes indicating which non-mandatory statements were disclosed.</description></item>
///   <item><description>Presentation header binding the proof to a presentation context.</description></item>
/// </list>
/// <para>
/// <strong>Comparison with Other Selective Disclosure Mechanisms:</strong>
/// </para>
/// <para>
/// This structure is analogous to:
/// </para>
/// <list type="bullet">
///   <item>
///     <term>SD-JWT Presentation</term>
///     <description>
///       In SD-JWT, the holder selects which disclosures to include. The presentation is
///       <c>&lt;JWT&gt;~&lt;Disclosure1&gt;~&lt;Disclosure2&gt;~</c>. Unlike BBS-2023,
///       SD-JWT reveals claim structure through <c>_sd</c> arrays even for undisclosed claims.
///       See <see cref="Verifiable.JCose.Sd.SdJwtToken"/>.
///     </description>
///   </item>
///   <item>
///     <term>SD-CWT Presentation</term>
///     <description>
///       SD-CWT (draft-ietf-spice-sd-cwt) uses CBOR encoding with disclosures in the
///       <c>sd_claims</c> unprotected header parameter. Same disclosure model as SD-JWT
///       but in COSE format.
///     </description>
///   </item>
/// </list>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#parsederivedproofvalue">
/// W3C VC DI BBS parseDerivedProofValue</see>.
/// </para>
/// </remarks>
/// <seealso cref="BbsBaseProof"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class BbsDerivedProof: IEquatable<BbsDerivedProof>
{
    /// <summary>
    /// Gets the BBS proof over the disclosed messages.
    /// </summary>
    /// <remarks>
    /// This proof is verified against the issuer's public key, the BBS header,
    /// the presentation header, and the disclosed messages.
    /// </remarks>
    public required byte[] BbsProof { get; init; }

    /// <summary>
    /// Gets the label map from canonical blank node identifiers to HMAC-based identifiers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Keys are canonical identifiers (e.g., <c>"c14n0"</c>, <c>"c14n1"</c>) that the verifier
    /// will produce when canonicalizing the reveal document. Values are HMAC-based identifiers
    /// (e.g., <c>"b2"</c>) that correspond to the blank node labels in the originally signed
    /// statements.
    /// </para>
    /// <para>
    /// Both keys and values use bare identifiers without the <c>"_:"</c> prefix. The codec
    /// compresses and decompresses both sides as integers.
    /// </para>
    /// </remarks>
    public required IReadOnlyDictionary<string, string> LabelMap { get; init; }

    /// <summary>
    /// Gets the indexes of mandatory statements in the reveal document.
    /// </summary>
    /// <remarks>
    /// These are relative indexes into the canonicalized reveal document,
    /// indicating which N-Quads are mandatory (always disclosed) statements.
    /// </remarks>
    public required IReadOnlyList<int> MandatoryIndexes { get; init; }

    /// <summary>
    /// Gets the indexes of selectively disclosed non-mandatory statements.
    /// </summary>
    /// <remarks>
    /// These indicate which of the non-mandatory statements the holder chose to disclose.
    /// </remarks>
    public required IReadOnlyList<int> SelectiveIndexes { get; init; }

    /// <summary>
    /// Gets the presentation header bound into the BBS proof.
    /// </summary>
    /// <remarks>
    /// This binds the derived proof to a presentation context and is supplied
    /// to the BBS proof verification routine.
    /// </remarks>
    public required byte[] PresentationHeader { get; init; }


    private string DebuggerDisplay =>
        $"BbsDerivedProof: {MandatoryIndexes.Count} mandatory, {SelectiveIndexes.Count} selective";


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(BbsDerivedProof? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(!BbsProof.AsSpan().SequenceEqual(other.BbsProof))
        {
            return false;
        }

        if(LabelMap.Count != other.LabelMap.Count)
        {
            return false;
        }

        foreach(KeyValuePair<string, string> entry in LabelMap)
        {
            if(!other.LabelMap.TryGetValue(entry.Key, out string? otherValue) ||
               !string.Equals(entry.Value, otherValue, StringComparison.Ordinal))
            {
                return false;
            }
        }

        if(MandatoryIndexes.Count != other.MandatoryIndexes.Count)
        {
            return false;
        }

        for(int i = 0; i < MandatoryIndexes.Count; i++)
        {
            if(MandatoryIndexes[i] != other.MandatoryIndexes[i])
            {
                return false;
            }
        }

        if(SelectiveIndexes.Count != other.SelectiveIndexes.Count)
        {
            return false;
        }

        for(int i = 0; i < SelectiveIndexes.Count; i++)
        {
            if(SelectiveIndexes[i] != other.SelectiveIndexes[i])
            {
                return false;
            }
        }

        if(!PresentationHeader.AsSpan().SequenceEqual(other.PresentationHeader))
        {
            return false;
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => obj is BbsDerivedProof other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach(byte b in BbsProof)
        {
            hash.Add(b);
        }

        hash.Add(LabelMap.Count);
        hash.Add(MandatoryIndexes.Count);
        hash.Add(SelectiveIndexes.Count);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Determines whether two <see cref="BbsDerivedProof"/> instances are equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(BbsDerivedProof? left, BbsDerivedProof? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="BbsDerivedProof"/> instances are not equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(BbsDerivedProof? left, BbsDerivedProof? right) =>
        !(left == right);
}
