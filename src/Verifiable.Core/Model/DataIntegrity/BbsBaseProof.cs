using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Represents the parsed components of a bbs-2023 base proof value.
/// </summary>
/// <remarks>
/// <para>
/// The base proof is created by the issuer and given to the holder. It contains:
/// </para>
/// <list type="bullet">
///   <item><description>BBS signature over the BBS header and messages.</description></item>
///   <item><description>BBS header formed as proof hash concatenated with mandatory hash.</description></item>
///   <item><description>Issuer BLS12-381 G2 public key bytes.</description></item>
///   <item><description>HMAC key for blank node label randomization.</description></item>
///   <item><description>Array of mandatory JSON pointers specifying always-disclosed claims.</description></item>
/// </list>
/// <para>
/// The holder uses this to create a <see cref="BbsDerivedProof"/> that selectively discloses statements.
/// </para>
/// <para>
/// <strong>Comparison with Other Selective Disclosure Mechanisms:</strong>
/// </para>
/// <para>
/// This structure is analogous to:
/// </para>
/// <list type="bullet">
///   <item>
///     <term>SD-JWT Issuance</term>
///     <description>
///       In SD-JWT, the issuer creates a JWT with <c>_sd</c> arrays containing digests of
///       disclosures, plus the disclosures themselves. The holder receives both the JWT and
///       all disclosures. Unlike BBS-2023, SD-JWT uses hash-based redaction rather than a
///       single multi-message signature with proof derivation.
///       See <see cref="Verifiable.JCose.Sd.SdJwtToken"/>.
///     </description>
///   </item>
///   <item>
///     <term>SD-CWT Issuance</term>
///     <description>
///       SD-CWT (draft-ietf-spice-sd-cwt) places salted claims in the <c>sd_claims</c>
///       unprotected header. Uses CBOR encoding with similar disclosure model to SD-JWT.
///     </description>
///   </item>
/// </list>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-di-bbs/#parsebaseproofvalue">
/// W3C VC DI BBS parseBaseProofValue</see>.
/// </para>
/// </remarks>
/// <seealso cref="BbsDerivedProof"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class BbsBaseProof: IEquatable<BbsBaseProof>
{
    /// <summary>
    /// Gets the BBS signature created by the issuer's verification method private key.
    /// </summary>
    /// <remarks>
    /// This signature is over the BBS header and the BBS messages. It is 80 bytes.
    /// </remarks>
    public required byte[] BbsSignature { get; init; }

    /// <summary>
    /// Gets the BBS header bound into the signature.
    /// </summary>
    /// <remarks>
    /// This is 64 bytes formed as <c>proofHash || mandatoryHash</c>.
    /// </remarks>
    public required byte[] BbsHeader { get; init; }

    /// <summary>
    /// Gets the issuer's BLS12-381 G2 public key bytes.
    /// </summary>
    /// <remarks>
    /// These are the raw 96-byte G2 public key bytes after the multicodec header
    /// has been stripped during parsing.
    /// </remarks>
    public required byte[] PublicKey { get; init; }

    /// <summary>
    /// Gets the HMAC key used for blank node label randomization.
    /// </summary>
    /// <remarks>
    /// This key is used to generate pseudorandom blank node identifiers to prevent
    /// information leakage from blank node ordering. Length is 32 bytes for SHA-256.
    /// </remarks>
    public required byte[] HmacKey { get; init; }

    /// <summary>
    /// Gets the array of mandatory JSON pointers.
    /// </summary>
    /// <remarks>
    /// These JSON pointers identify claims that must always be disclosed.
    /// They are used to separate mandatory from non-mandatory statements during verification.
    /// </remarks>
    public required IReadOnlyList<string> MandatoryPointers { get; init; }


    private string DebuggerDisplay =>
        $"BbsBaseProof: {MandatoryPointers.Count} mandatory pointers";


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(BbsBaseProof? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(!BbsSignature.AsSpan().SequenceEqual(other.BbsSignature))
        {
            return false;
        }

        if(!BbsHeader.AsSpan().SequenceEqual(other.BbsHeader))
        {
            return false;
        }

        if(!PublicKey.AsSpan().SequenceEqual(other.PublicKey))
        {
            return false;
        }

        if(!HmacKey.AsSpan().SequenceEqual(other.HmacKey))
        {
            return false;
        }

        if(MandatoryPointers.Count != other.MandatoryPointers.Count)
        {
            return false;
        }

        for(int i = 0; i < MandatoryPointers.Count; i++)
        {
            if(!string.Equals(MandatoryPointers[i], other.MandatoryPointers[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals(object? obj) => obj is BbsBaseProof other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();

        foreach(byte b in BbsSignature)
        {
            hash.Add(b);
        }

        hash.Add(MandatoryPointers.Count);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Determines whether two <see cref="BbsBaseProof"/> instances are equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(BbsBaseProof? left, BbsBaseProof? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="BbsBaseProof"/> instances are not equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(BbsBaseProof? left, BbsBaseProof? right) =>
        !(left == right);
}
