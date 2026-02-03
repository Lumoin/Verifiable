using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Pre-Hash ML-DSA signature structure (TPMS_SIGNATURE_HASH_MLDSA).
/// </summary>
/// <remarks>
/// <para>
/// Contains a Pre-Hash ML-DSA signature with the hash algorithm used for pre-hashing.
/// </para>
/// <para>
/// <b>Wire format:</b>
/// </para>
/// <code>
/// typedef struct {
///     TPMI_ALG_HASH          hashAlg;   // The hash algorithm used for pre-hashing.
///     TPM2B_SIGNATURE_MLDSA  sig;       // The ML-DSA signature.
/// } TPMS_SIGNATURE_HASH_MLDSA;
/// </code>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.3.4, Table 218 (v1.85).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public readonly struct TpmsSignatureHashMlDsa: IDisposable, IEquatable<TpmsSignatureHashMlDsa>
{
    /// <summary>
    /// Gets the hash algorithm used for pre-hashing.
    /// </summary>
    public TpmAlgIdConstants HashAlg { get; init; }

    /// <summary>
    /// Gets the ML-DSA signature.
    /// </summary>
    public Tpm2bSignatureMlDsa Signature { get; init; }

    /// <summary>
    /// Creates a new Pre-Hash ML-DSA signature structure.
    /// </summary>
    /// <param name="hashAlg">The hash algorithm used for pre-hashing.</param>
    /// <param name="signature">The ML-DSA signature.</param>
    /// <returns>The Pre-Hash ML-DSA signature.</returns>
    public static TpmsSignatureHashMlDsa Create(TpmAlgIdConstants hashAlg, Tpm2bSignatureMlDsa signature) => new()
    {
        HashAlg = hashAlg,
        Signature = signature
    };

    /// <summary>
    /// Gets the serialized size of this structure.
    /// </summary>
    public int GetSerializedSize() => sizeof(ushort) + Signature.GetSerializedSize();

    /// <summary>
    /// Writes this structure to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        writer.WriteUInt16((ushort)HashAlg);
        Signature.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a Pre-Hash ML-DSA signature from a TPM reader.
    /// </summary>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool to allocate from.</param>
    /// <returns>The parsed Pre-Hash ML-DSA signature.</returns>
    public static TpmsSignatureHashMlDsa Parse(ref TpmReader reader, MemoryPool<byte>? pool = null)
    {
        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();
        var signature = Tpm2bSignatureMlDsa.Parse(ref reader, pool);

        return new TpmsSignatureHashMlDsa
        {
            HashAlg = hashAlg,
            Signature = signature
        };
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        Signature.Dispose();
    }

    /// <inheritdoc/>
    public bool Equals(TpmsSignatureHashMlDsa other) =>
        HashAlg == other.HashAlg && Signature.Equals(other.Signature);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is TpmsSignatureHashMlDsa other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() => HashCode.Combine(HashAlg, Signature.GetHashCode());

    /// <summary>
    /// Equality operator.
    /// </summary>
    public static bool operator ==(TpmsSignatureHashMlDsa left, TpmsSignatureHashMlDsa right) => left.Equals(right);

    /// <summary>
    /// Inequality operator.
    /// </summary>
    public static bool operator !=(TpmsSignatureHashMlDsa left, TpmsSignatureHashMlDsa right) => !left.Equals(right);

    private string DebuggerDisplay => $"TPMS_SIGNATURE_HASH_MLDSA({HashAlg}, {Signature.Size} bytes)";
}