using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Represents the parsed components of an ecdsa-sd-2023 derived proof value.
/// </summary>
/// <remarks>
/// <para>
/// The derived proof is created by the holder from a base proof and sent to the verifier.
/// It contains only the information needed to verify the selectively disclosed statements.
/// </para>
/// <list type="bullet">
///   <item><description>Base signature from the issuer.</description></item>
///   <item><description>Proof-scoped public key for verifying statement signatures.</description></item>
///   <item><description>Filtered signatures for the disclosed non-mandatory statements only.</description></item>
///   <item><description>Label map from canonical to HMAC-based blank node identifiers.</description></item>
///   <item><description>Mandatory indexes indicating which statements in the reveal document are mandatory.</description></item>
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
///       <c>&lt;JWT&gt;~&lt;Disclosure1&gt;~&lt;Disclosure2&gt;~</c>. Unlike ECDSA-SD-2023,
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
/// See <see href="https://w3c.github.io/vc-di-ecdsa/#parsederivedproofvalue">
/// W3C VC DI ECDSA §3.3.19 parseDerivedProofValue</see>.
/// </para>
/// </remarks>
/// <seealso cref="EcdsaSdBaseProof"/>
/// <seealso cref="EcdsaSd2023CryptosuiteInfo"/>
/// <seealso cref="EcdsaSd2023ProofSerializer"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class EcdsaSdDerivedProof: IEquatable<EcdsaSdDerivedProof>
{
    /// <summary>
    /// Gets the base signature from the issuer.
    /// </summary>
    /// <remarks>
    /// This is the same base signature from the base proof, used to verify
    /// the binding between the proof hash, public key, and mandatory hash.
    /// </remarks>
    public required byte[] BaseSignature { get; init; }

    /// <summary>
    /// Gets the proof-scoped multikey-encoded public key.
    /// </summary>
    /// <remarks>
    /// This is the same ephemeral public key from the base proof, used to verify
    /// the individual statement signatures.
    /// </remarks>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// Gets the filtered signatures for disclosed non-mandatory statements.
    /// </summary>
    /// <remarks>
    /// This is a subset of the signatures from the base proof, containing only
    /// signatures for the non-mandatory statements that the holder chose to disclose.
    /// </remarks>
    public required IReadOnlyList<byte[]> Signatures { get; init; }

    /// <summary>
    /// Gets the label map from canonical blank node identifiers to HMAC-based identifiers.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Keys are canonical identifiers (e.g., "c14n0", "c14n1") that the verifier
    /// will produce when canonicalizing the reveal document.
    /// </para>
    /// <para>
    /// Values are HMAC-based identifiers (e.g., "u..." base64url strings) that
    /// correspond to the blank node labels in the originally signed statements.
    /// </para>
    /// </remarks>
    public required IReadOnlyDictionary<string, string> LabelMap { get; init; }

    /// <summary>
    /// Gets the indexes of mandatory statements in the reveal document.
    /// </summary>
    /// <remarks>
    /// These are relative indexes into the canonicalized reveal document,
    /// indicating which N-Quads are mandatory (always disclosed) statements.
    /// The verifier uses these to separate mandatory from non-mandatory statements
    /// and to compute the mandatory hash for verification.
    /// </remarks>
    public required IReadOnlyList<int> MandatoryIndexes { get; init; }


    private string DebuggerDisplay =>
        $"EcdsaSdDerivedProof: {Signatures.Count} signatures, {MandatoryIndexes.Count} mandatory indexes";


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(EcdsaSdDerivedProof? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(!BaseSignature.AsSpan().SequenceEqual(other.BaseSignature))
        {
            return false;
        }

        if(!PublicKey.AsSpan().SequenceEqual(other.PublicKey))
        {
            return false;
        }

        if(Signatures.Count != other.Signatures.Count)
        {
            return false;
        }

        for(int i = 0; i < Signatures.Count; i++)
        {
            if(!Signatures[i].AsSpan().SequenceEqual(other.Signatures[i]))
            {
                return false;
            }
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

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => obj is EcdsaSdDerivedProof other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach(byte b in BaseSignature)
        {
            hash.Add(b);
        }

        hash.Add(Signatures.Count);
        hash.Add(LabelMap.Count);
        hash.Add(MandatoryIndexes.Count);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Determines whether two <see cref="EcdsaSdDerivedProof"/> instances are equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(EcdsaSdDerivedProof? left, EcdsaSdDerivedProof? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="EcdsaSdDerivedProof"/> instances are not equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(EcdsaSdDerivedProof? left, EcdsaSdDerivedProof? right) =>
        !(left == right);
}