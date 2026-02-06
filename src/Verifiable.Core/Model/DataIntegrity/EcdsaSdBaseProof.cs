using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Represents the parsed components of an ecdsa-sd-2023 base proof value.
/// </summary>
/// <remarks>
/// <para>
/// The base proof is created by the issuer and given to the holder. It contains:
/// </para>
/// <list type="bullet">
///   <item><description>Base signature over proof hash, public key, and mandatory hash.</description></item>
///   <item><description>Proof-scoped ephemeral public key for verifying individual statement signatures.</description></item>
///   <item><description>HMAC key for blank node label randomization.</description></item>
///   <item><description>Array of signatures, one for each non-mandatory statement.</description></item>
///   <item><description>Array of mandatory JSON pointers specifying always-disclosed claims.</description></item>
/// </list>
/// <para>
/// The holder uses this to create a <see cref="EcdsaSdDerivedProof"/> that selectively discloses statements.
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
///       all disclosures. Unlike ECDSA-SD-2023, SD-JWT uses hash-based redaction rather than
///       individual signatures. See <see cref="Verifiable.JCose.Sd.SdJwtToken"/>.
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
/// See <see href="https://w3c.github.io/vc-di-ecdsa/#parsebaseproofvalue">
/// W3C VC DI ECDSA §3.3.14 parseBaseProofValue</see>.
/// </para>
/// </remarks>
/// <seealso cref="EcdsaSdDerivedProof"/>
/// <seealso cref="EcdsaSd2023CryptosuiteInfo"/>
/// <seealso cref="EcdsaSd2023ProofSerializer"/>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
[SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "Wire-format POCO representing parsed proof components.")]
public sealed class EcdsaSdBaseProof: IEquatable<EcdsaSdBaseProof>
{
    /// <summary>
    /// Gets the base signature created by the issuer's verification method private key.
    /// </summary>
    /// <remarks>
    /// This signature is over the concatenation of proof hash, public key, and mandatory hash.
    /// For P-256, this is 64 bytes in IEEE P1363 format.
    /// </remarks>
    public required byte[] BaseSignature { get; init; }

    /// <summary>
    /// Gets the proof-scoped multikey-encoded public key.
    /// </summary>
    /// <remarks>
    /// This is an ephemeral public key used to verify the individual statement signatures.
    /// Format: 2-byte multikey header (0x80, 0x24) + 33-byte compressed P-256 public key.
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
    /// Gets the array of signatures for non-mandatory statements.
    /// </summary>
    /// <remarks>
    /// Each signature is over the UTF-8 representation of a single N-Quad string
    /// from the non-mandatory statement group, signed with the ephemeral private key.
    /// </remarks>
    public required IReadOnlyList<byte[]> Signatures { get; init; }

    /// <summary>
    /// Gets the array of mandatory JSON pointers.
    /// </summary>
    /// <remarks>
    /// These JSON pointers identify claims that must always be disclosed.
    /// They are used to separate mandatory from non-mandatory statements during verification.
    /// </remarks>
    public required IReadOnlyList<string> MandatoryPointers { get; init; }


    private string DebuggerDisplay =>
        $"EcdsaSdBaseProof: {Signatures.Count} signatures, {MandatoryPointers.Count} mandatory pointers";


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(EcdsaSdBaseProof? other)
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

        if(!HmacKey.AsSpan().SequenceEqual(other.HmacKey))
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
    public override bool Equals(object? obj) => obj is EcdsaSdBaseProof other && Equals(other);


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
        hash.Add(MandatoryPointers.Count);

        return hash.ToHashCode();
    }


    /// <summary>
    /// Determines whether two <see cref="EcdsaSdBaseProof"/> instances are equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(EcdsaSdBaseProof? left, EcdsaSdBaseProof? right) =>
        left is null ? right is null : left.Equals(right);


    /// <summary>
    /// Determines whether two <see cref="EcdsaSdBaseProof"/> instances are not equal.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(EcdsaSdBaseProof? left, EcdsaSdBaseProof? right) =>
        !(left == right);
}