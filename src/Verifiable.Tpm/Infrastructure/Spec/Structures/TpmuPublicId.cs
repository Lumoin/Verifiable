using System;
using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Infrastructure.Spec.Constants;

namespace Verifiable.Tpm.Infrastructure.Spec.Structures;

/// <summary>
/// Union of public key unique identifiers (TPMU_PUBLIC_ID).
/// </summary>
/// <remarks>
/// <para>
/// This union contains the unique identifier for a public key. For asymmetric keys,
/// this is the public key material. For creation templates, this can be empty.
/// </para>
/// <para>
/// <b>Union members:</b>
/// </para>
/// <list type="bullet">
///   <item><description>TPM_ALG_KEYEDHASH: TPM2B_DIGEST</description></item>
///   <item><description>TPM_ALG_SYMCIPHER: TPM2B_DIGEST</description></item>
///   <item><description>TPM_ALG_RSA: TPM2B_PUBLIC_KEY_RSA (public modulus)</description></item>
///   <item><description>TPM_ALG_ECC: TPMS_ECC_POINT (X, Y coordinates)</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 12.2.3.2, Table 212.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmuPublicId: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the algorithm type that determines union interpretation.
    /// </summary>
    public TpmAlgIdConstants Type { get; }

    /// <summary>
    /// Gets the ECC point (when Type is TPM_ALG_ECC).
    /// </summary>
    public TpmsEccPoint? Ecc { get; }

    /// <summary>
    /// Gets the RSA modulus storage (when Type is TPM_ALG_RSA).
    /// </summary>
    private IMemoryOwner<byte>? RsaStorage { get; }

    /// <summary>
    /// Gets the RSA modulus length.
    /// </summary>
    private int RsaLength { get; }

    /// <summary>
    /// Initializes a new public ID for RSA.
    /// </summary>
    private TpmuPublicId(TpmAlgIdConstants type, IMemoryOwner<byte>? rsaStorage, int rsaLength)
    {
        Type = type;
        RsaStorage = rsaStorage;
        RsaLength = rsaLength;
        Ecc = null;
    }

    /// <summary>
    /// Initializes a new public ID for ECC.
    /// </summary>
    private TpmuPublicId(TpmAlgIdConstants type, TpmsEccPoint ecc)
    {
        Type = type;
        Ecc = ecc;
        RsaStorage = null;
        RsaLength = 0;
    }

    /// <summary>
    /// Gets whether this unique identifier is empty (for templates).
    /// </summary>
    public bool IsEmpty => Type switch
    {
        TpmAlgIdConstants.TPM_ALG_RSA => RsaLength == 0,
        TpmAlgIdConstants.TPM_ALG_ECC => Ecc?.IsEmpty ?? true,
        _ => true
    };

    /// <summary>
    /// Gets the RSA public modulus as a read-only span.
    /// </summary>
    /// <returns>The modulus bytes, or empty if not RSA or empty.</returns>
    public ReadOnlySpan<byte> GetRsaModulus()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(Type != TpmAlgIdConstants.TPM_ALG_RSA || RsaStorage is null)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        return RsaStorage.Memory.Span.Slice(0, RsaLength);
    }

    /// <summary>
    /// Creates an empty RSA public ID (for templates).
    /// </summary>
    /// <returns>An empty RSA unique.</returns>
    public static TpmuPublicId EmptyRsa() => new(TpmAlgIdConstants.TPM_ALG_RSA, null, 0);

    /// <summary>
    /// Creates an empty ECC public ID (for templates).
    /// </summary>
    /// <returns>An empty ECC unique.</returns>
    public static TpmuPublicId EmptyEcc() => new(TpmAlgIdConstants.TPM_ALG_ECC, TpmsEccPoint.Empty);

    /// <summary>
    /// Gets the serialized size of this union.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return Type switch
        {
            TpmAlgIdConstants.TPM_ALG_RSA => sizeof(ushort) + RsaLength,
            TpmAlgIdConstants.TPM_ALG_ECC => Ecc!.GetSerializedSize(),
            _ => throw new NotSupportedException($"Algorithm type '{Type}' is not supported for serialization.")
        };
    }

    /// <summary>
    /// Writes this union to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <remarks>
    /// The type selector is not written; it must be written separately as part of TPMT_PUBLIC.
    /// </remarks>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        switch(Type)
        {
            case TpmAlgIdConstants.TPM_ALG_RSA:
                writer.WriteUInt16((ushort)RsaLength);
                if(RsaLength > 0)
                {
                    writer.WriteBytes(GetRsaModulus());
                }
                break;
            case TpmAlgIdConstants.TPM_ALG_ECC:
                Ecc!.WriteTo(ref writer);
                break;
            default:
                throw new NotSupportedException($"Algorithm type '{Type}' is not supported for serialization.");
        }
    }

    /// <summary>
    /// Parses a public ID from a TPM reader.
    /// </summary>
    /// <param name="type">The algorithm type (selector).</param>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed public ID.</returns>
    public static TpmuPublicId Parse(TpmAlgIdConstants type, ref TpmReader reader, MemoryPool<byte> pool)
    {
        switch(type)
        {
            case TpmAlgIdConstants.TPM_ALG_RSA:
                ushort rsaSize = reader.ReadUInt16();
                if(rsaSize == 0)
                {
                    return EmptyRsa();
                }

                IMemoryOwner<byte> rsaStorage = pool.Rent(rsaSize);
                ReadOnlySpan<byte> rsaSource = reader.ReadBytes(rsaSize);
                rsaSource.CopyTo(rsaStorage.Memory.Span.Slice(0, rsaSize));
                return new TpmuPublicId(type, rsaStorage, rsaSize);

            case TpmAlgIdConstants.TPM_ALG_ECC:
                TpmsEccPoint ecc = TpmsEccPoint.Parse(ref reader, pool);
                return new TpmuPublicId(type, ecc);

            default:
                throw new NotSupportedException($"Algorithm type '{type}' is not supported for parsing.");
        }
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            RsaStorage?.Dispose();
            Ecc?.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay
    {
        get
        {
            if(IsEmpty)
            {
                return $"TPMU_PUBLIC_ID({Type}, empty)";
            }

            return Type switch
            {
                TpmAlgIdConstants.TPM_ALG_RSA => $"TPMU_PUBLIC_ID(RSA, {RsaLength} bytes)",
                TpmAlgIdConstants.TPM_ALG_ECC => $"TPMU_PUBLIC_ID(ECC)",
                _ => $"TPMU_PUBLIC_ID({Type})"
            };
        }
    }
}