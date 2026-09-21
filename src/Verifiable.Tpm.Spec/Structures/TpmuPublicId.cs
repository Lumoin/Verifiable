using System.Buffers;
using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

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
///   <item><description>TPM_ALG_KEYEDHASH: TPM2B_DIGEST (unique value of a sealed data object or HMAC key)</description></item>
///   <item><description>TPM_ALG_SYMCIPHER: TPM2B_DIGEST</description></item>
///   <item><description>TPM_ALG_RSA: TPM2B_PUBLIC_KEY_RSA (public modulus)</description></item>
///   <item><description>TPM_ALG_ECC: TPMS_ECC_POINT (X, Y coordinates)</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 12.2.3.2, Table 226.
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
    /// Gets the keyed-hash unique-value storage (when Type is TPM_ALG_KEYEDHASH).
    /// </summary>
    private IMemoryOwner<byte>? KeyedHashStorage { get; }

    /// <summary>
    /// Gets the keyed-hash unique-value length.
    /// </summary>
    private int KeyedHashLength { get; }

    /// <summary>
    /// Initializes a new public ID for RSA.
    /// </summary>
    private TpmuPublicId(TpmAlgIdConstants type, IMemoryOwner<byte>? rsaStorage, int rsaLength)
    {
        Type = type;
        RsaStorage = rsaStorage;
        RsaLength = rsaLength;
        Ecc = null;
        KeyedHashStorage = null;
        KeyedHashLength = 0;
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
        KeyedHashStorage = null;
        KeyedHashLength = 0;
    }

    /// <summary>
    /// Initializes a new public ID for a keyed-hash object (the distinct parameter shape avoids colliding with
    /// the RSA constructor).
    /// </summary>
    private TpmuPublicId(IMemoryOwner<byte>? keyedHashStorage, int keyedHashLength)
    {
        Type = TpmAlgIdConstants.TPM_ALG_KEYEDHASH;
        KeyedHashStorage = keyedHashStorage;
        KeyedHashLength = keyedHashLength;
        Ecc = null;
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
        TpmAlgIdConstants.TPM_ALG_KEYEDHASH => KeyedHashLength == 0,
        TpmAlgIdConstants.TPM_ALG_ERROR or
        TpmAlgIdConstants.TPM_ALG_TDES or
        TpmAlgIdConstants.TPM_ALG_SHA or
        TpmAlgIdConstants.TPM_ALG_HMAC or
        TpmAlgIdConstants.TPM_ALG_AES or
        TpmAlgIdConstants.TPM_ALG_MGF1 or
        TpmAlgIdConstants.TPM_ALG_XOR or
        TpmAlgIdConstants.TPM_ALG_SHA256 or
        TpmAlgIdConstants.TPM_ALG_SHA384 or
        TpmAlgIdConstants.TPM_ALG_SHA512 or
        TpmAlgIdConstants.TPM_ALG_SHA256_192 or
        TpmAlgIdConstants.TPM_ALG_NULL or
        TpmAlgIdConstants.TPM_ALG_SM3_256 or
        TpmAlgIdConstants.TPM_ALG_SM4 or
        TpmAlgIdConstants.TPM_ALG_RSASSA or
        TpmAlgIdConstants.TPM_ALG_RSAES or
        TpmAlgIdConstants.TPM_ALG_RSAPSS or
        TpmAlgIdConstants.TPM_ALG_OAEP or
        TpmAlgIdConstants.TPM_ALG_ECDSA or
        TpmAlgIdConstants.TPM_ALG_ECDH or
        TpmAlgIdConstants.TPM_ALG_ECDAA or
        TpmAlgIdConstants.TPM_ALG_SM2 or
        TpmAlgIdConstants.TPM_ALG_ECSCHNORR or
        TpmAlgIdConstants.TPM_ALG_ECMQV or
        TpmAlgIdConstants.TPM_ALG_HKDF or
        TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A or
        TpmAlgIdConstants.TPM_ALG_KDF2 or
        TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 or
        TpmAlgIdConstants.TPM_ALG_SYMCIPHER or
        TpmAlgIdConstants.TPM_ALG_CAMELLIA or
        TpmAlgIdConstants.TPM_ALG_SHA3_256 or
        TpmAlgIdConstants.TPM_ALG_SHA3_384 or
        TpmAlgIdConstants.TPM_ALG_SHA3_512 or
        TpmAlgIdConstants.TPM_ALG_SHAKE128 or
        TpmAlgIdConstants.TPM_ALG_SHAKE256 or
        TpmAlgIdConstants.TPM_ALG_SHAKE256_192 or
        TpmAlgIdConstants.TPM_ALG_SHAKE256_256 or
        TpmAlgIdConstants.TPM_ALG_SHAKE256_512 or
        TpmAlgIdConstants.TPM_ALG_CMAC or
        TpmAlgIdConstants.TPM_ALG_CTR or
        TpmAlgIdConstants.TPM_ALG_OFB or
        TpmAlgIdConstants.TPM_ALG_CBC or
        TpmAlgIdConstants.TPM_ALG_CFB or
        TpmAlgIdConstants.TPM_ALG_ECB or
        TpmAlgIdConstants.TPM_ALG_CCM or
        TpmAlgIdConstants.TPM_ALG_GCM or
        TpmAlgIdConstants.TPM_ALG_KW or
        TpmAlgIdConstants.TPM_ALG_KWP or
        TpmAlgIdConstants.TPM_ALG_EAX or
        TpmAlgIdConstants.TPM_ALG_EDDSA or
        TpmAlgIdConstants.TPM_ALG_EDDSA_PH or
        TpmAlgIdConstants.TPM_ALG_LMS or
        TpmAlgIdConstants.TPM_ALG_XMSS or
        TpmAlgIdConstants.TPM_ALG_KEYEDXOF or
        TpmAlgIdConstants.TPM_ALG_KMACXOF128 or
        TpmAlgIdConstants.TPM_ALG_KMACXOF256 or
        TpmAlgIdConstants.TPM_ALG_KMAC128 or
        TpmAlgIdConstants.TPM_ALG_KMAC256 or
        TpmAlgIdConstants.TPM_ALG_MLKEM or
        TpmAlgIdConstants.TPM_ALG_MLDSA or
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => true,
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

        return RsaStorage.Memory.Span[..RsaLength];
    }

    /// <summary>
    /// Gets the RSA public modulus as read-only memory — the same octets <see cref="GetRsaModulus"/> exposes
    /// as a span, in the memory-typed form a carrier stored on a durable record (for example a verify action)
    /// can hold, since a <see cref="ReadOnlySpan{T}"/> cannot be a field.
    /// </summary>
    /// <returns>The modulus bytes, or empty if not RSA or empty.</returns>
    public ReadOnlyMemory<byte> GetRsaModulusMemory()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(Type != TpmAlgIdConstants.TPM_ALG_RSA || RsaStorage is null)
        {
            return ReadOnlyMemory<byte>.Empty;
        }

        return RsaStorage.Memory[..RsaLength];
    }

    /// <summary>
    /// Creates an empty RSA public ID (for templates).
    /// </summary>
    /// <returns>An empty RSA unique.</returns>
    public static TpmuPublicId EmptyRsa() => new(TpmAlgIdConstants.TPM_ALG_RSA, null, 0);

    /// <summary>
    /// Creates an RSA public ID carrying a concrete public modulus — the unique area of a generated RSA key, as
    /// distinct from <see cref="EmptyRsa"/>, which leaves it empty for an input template.
    /// </summary>
    /// <param name="modulus">The RSA public modulus (big-endian); copied into pooled storage the returned union owns.</param>
    /// <param name="pool">The memory pool for the modulus storage.</param>
    /// <returns>An RSA unique carrying <paramref name="modulus"/>.</returns>
    public static TpmuPublicId FromRsaModulus(ReadOnlySpan<byte> modulus, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(modulus.IsEmpty)
        {
            return EmptyRsa();
        }

        IMemoryOwner<byte> storage = pool.Rent(modulus.Length);
        modulus.CopyTo(storage.Memory.Span);

        return new TpmuPublicId(TpmAlgIdConstants.TPM_ALG_RSA, storage, modulus.Length);
    }

    /// <summary>
    /// Gets the keyed-hash <c>unique</c> value as a read-only span — <c>H_nameAlg(seedValue ‖ sensitive)</c>
    /// per TPM 2.0 Library Part 2, clause 12.2.3.1, equation (8); Part 1, clause 24.5.3.2, equation (48), or empty for a creation template.
    /// </summary>
    /// <returns>The unique octets, or empty when the union is not KEYEDHASH or carries the template form.</returns>
    public ReadOnlySpan<byte> GetKeyedHashUnique()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        if(Type != TpmAlgIdConstants.TPM_ALG_KEYEDHASH || KeyedHashStorage is null)
        {
            return ReadOnlySpan<byte>.Empty;
        }

        return KeyedHashStorage.Memory.Span[..KeyedHashLength];
    }

    /// <summary>
    /// Creates a KEYEDHASH public ID carrying a concrete <c>unique</c> value —
    /// <c>H_nameAlg(seedValue ‖ sensitive)</c> per TPM 2.0 Library Part 2, clause 12.2.3.1, equation (8); Part 1, clause 24.5.3.2, equation (48) —
    /// the form a created object's public area carries, as opposed to <see cref="EmptyKeyedHash"/>'s template form.
    /// </summary>
    /// <param name="unique">The unique octets; copied into pooled storage the returned union owns.</param>
    /// <param name="pool">The memory pool.</param>
    /// <returns>The public ID.</returns>
    public static TpmuPublicId FromKeyedHashUnique(ReadOnlySpan<byte> unique, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(unique.IsEmpty)
        {
            return EmptyKeyedHash();
        }

        IMemoryOwner<byte> storage = pool.Rent(unique.Length);
        unique.CopyTo(storage.Memory.Span);

        return new TpmuPublicId(storage, unique.Length);
    }

    /// <summary>
    /// Creates an empty ECC public ID (for templates).
    /// </summary>
    /// <returns>An empty ECC unique.</returns>
    public static TpmuPublicId EmptyEcc() => new(TpmAlgIdConstants.TPM_ALG_ECC, TpmsEccPoint.Empty);

    /// <summary>
    /// Creates an ECC public ID carrying a concrete public point — the unique area of a generated key, as
    /// distinct from <see cref="EmptyEcc"/>, which leaves it empty for an input template.
    /// </summary>
    /// <param name="point">The public point (X, Y); ownership transfers to the returned union.</param>
    /// <returns>An ECC unique carrying <paramref name="point"/>.</returns>
    public static TpmuPublicId FromEccPoint(TpmsEccPoint point)
    {
        ArgumentNullException.ThrowIfNull(point);

        return new TpmuPublicId(TpmAlgIdConstants.TPM_ALG_ECC, point);
    }

    /// <summary>
    /// Creates an empty keyed-hash public ID (for sealed-data templates; the TPM fills in the unique value).
    /// </summary>
    /// <returns>An empty keyed-hash unique.</returns>
    public static TpmuPublicId EmptyKeyedHash() => new(null, 0);

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
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH => sizeof(ushort) + KeyedHashLength,
            TpmAlgIdConstants.TPM_ALG_ERROR or
            TpmAlgIdConstants.TPM_ALG_TDES or
            TpmAlgIdConstants.TPM_ALG_SHA or
            TpmAlgIdConstants.TPM_ALG_HMAC or
            TpmAlgIdConstants.TPM_ALG_AES or
            TpmAlgIdConstants.TPM_ALG_MGF1 or
            TpmAlgIdConstants.TPM_ALG_XOR or
            TpmAlgIdConstants.TPM_ALG_SHA256 or
            TpmAlgIdConstants.TPM_ALG_SHA384 or
            TpmAlgIdConstants.TPM_ALG_SHA512 or
            TpmAlgIdConstants.TPM_ALG_SHA256_192 or
            TpmAlgIdConstants.TPM_ALG_NULL or
            TpmAlgIdConstants.TPM_ALG_SM3_256 or
            TpmAlgIdConstants.TPM_ALG_SM4 or
            TpmAlgIdConstants.TPM_ALG_RSASSA or
            TpmAlgIdConstants.TPM_ALG_RSAES or
            TpmAlgIdConstants.TPM_ALG_RSAPSS or
            TpmAlgIdConstants.TPM_ALG_OAEP or
            TpmAlgIdConstants.TPM_ALG_ECDSA or
            TpmAlgIdConstants.TPM_ALG_ECDH or
            TpmAlgIdConstants.TPM_ALG_ECDAA or
            TpmAlgIdConstants.TPM_ALG_SM2 or
            TpmAlgIdConstants.TPM_ALG_ECSCHNORR or
            TpmAlgIdConstants.TPM_ALG_ECMQV or
            TpmAlgIdConstants.TPM_ALG_HKDF or
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A or
            TpmAlgIdConstants.TPM_ALG_KDF2 or
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 or
            TpmAlgIdConstants.TPM_ALG_SYMCIPHER or
            TpmAlgIdConstants.TPM_ALG_CAMELLIA or
            TpmAlgIdConstants.TPM_ALG_SHA3_256 or
            TpmAlgIdConstants.TPM_ALG_SHA3_384 or
            TpmAlgIdConstants.TPM_ALG_SHA3_512 or
            TpmAlgIdConstants.TPM_ALG_SHAKE128 or
            TpmAlgIdConstants.TPM_ALG_SHAKE256 or
            TpmAlgIdConstants.TPM_ALG_SHAKE256_192 or
            TpmAlgIdConstants.TPM_ALG_SHAKE256_256 or
            TpmAlgIdConstants.TPM_ALG_SHAKE256_512 or
            TpmAlgIdConstants.TPM_ALG_CMAC or
            TpmAlgIdConstants.TPM_ALG_CTR or
            TpmAlgIdConstants.TPM_ALG_OFB or
            TpmAlgIdConstants.TPM_ALG_CBC or
            TpmAlgIdConstants.TPM_ALG_CFB or
            TpmAlgIdConstants.TPM_ALG_ECB or
            TpmAlgIdConstants.TPM_ALG_CCM or
            TpmAlgIdConstants.TPM_ALG_GCM or
            TpmAlgIdConstants.TPM_ALG_KW or
            TpmAlgIdConstants.TPM_ALG_KWP or
            TpmAlgIdConstants.TPM_ALG_EAX or
            TpmAlgIdConstants.TPM_ALG_EDDSA or
            TpmAlgIdConstants.TPM_ALG_EDDSA_PH or
            TpmAlgIdConstants.TPM_ALG_LMS or
            TpmAlgIdConstants.TPM_ALG_XMSS or
            TpmAlgIdConstants.TPM_ALG_KEYEDXOF or
            TpmAlgIdConstants.TPM_ALG_KMACXOF128 or
            TpmAlgIdConstants.TPM_ALG_KMACXOF256 or
            TpmAlgIdConstants.TPM_ALG_KMAC128 or
            TpmAlgIdConstants.TPM_ALG_KMAC256 or
            TpmAlgIdConstants.TPM_ALG_MLKEM or
            TpmAlgIdConstants.TPM_ALG_MLDSA or
            TpmAlgIdConstants.TPM_ALG_HASH_MLDSA =>
                throw new NotSupportedException($"Algorithm type '{Type}' is not supported for serialization."),
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
            {
                writer.WriteUInt16((ushort)RsaLength);
                if(RsaLength > 0)
                {
                    writer.WriteBytes(GetRsaModulus());
                }

                break;
            }
            case TpmAlgIdConstants.TPM_ALG_ECC:
            {
                Ecc!.WriteTo(ref writer);
                break;
            }
            case TpmAlgIdConstants.TPM_ALG_KEYEDHASH:
            {
                writer.WriteUInt16((ushort)KeyedHashLength);
                if(KeyedHashLength > 0)
                {
                    writer.WriteBytes(KeyedHashStorage!.Memory.Span[..KeyedHashLength]);
                }

                break;
            }
            case TpmAlgIdConstants.TPM_ALG_ERROR:
            case TpmAlgIdConstants.TPM_ALG_TDES:
            case TpmAlgIdConstants.TPM_ALG_SHA:
            case TpmAlgIdConstants.TPM_ALG_HMAC:
            case TpmAlgIdConstants.TPM_ALG_AES:
            case TpmAlgIdConstants.TPM_ALG_MGF1:
            case TpmAlgIdConstants.TPM_ALG_XOR:
            case TpmAlgIdConstants.TPM_ALG_SHA256:
            case TpmAlgIdConstants.TPM_ALG_SHA384:
            case TpmAlgIdConstants.TPM_ALG_SHA512:
            case TpmAlgIdConstants.TPM_ALG_SHA256_192:
            case TpmAlgIdConstants.TPM_ALG_NULL:
            case TpmAlgIdConstants.TPM_ALG_SM3_256:
            case TpmAlgIdConstants.TPM_ALG_SM4:
            case TpmAlgIdConstants.TPM_ALG_RSASSA:
            case TpmAlgIdConstants.TPM_ALG_RSAES:
            case TpmAlgIdConstants.TPM_ALG_RSAPSS:
            case TpmAlgIdConstants.TPM_ALG_OAEP:
            case TpmAlgIdConstants.TPM_ALG_ECDSA:
            case TpmAlgIdConstants.TPM_ALG_ECDH:
            case TpmAlgIdConstants.TPM_ALG_ECDAA:
            case TpmAlgIdConstants.TPM_ALG_SM2:
            case TpmAlgIdConstants.TPM_ALG_ECSCHNORR:
            case TpmAlgIdConstants.TPM_ALG_ECMQV:
            case TpmAlgIdConstants.TPM_ALG_HKDF:
            case TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A:
            case TpmAlgIdConstants.TPM_ALG_KDF2:
            case TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108:
            case TpmAlgIdConstants.TPM_ALG_SYMCIPHER:
            case TpmAlgIdConstants.TPM_ALG_CAMELLIA:
            case TpmAlgIdConstants.TPM_ALG_SHA3_256:
            case TpmAlgIdConstants.TPM_ALG_SHA3_384:
            case TpmAlgIdConstants.TPM_ALG_SHA3_512:
            case TpmAlgIdConstants.TPM_ALG_SHAKE128:
            case TpmAlgIdConstants.TPM_ALG_SHAKE256:
            case TpmAlgIdConstants.TPM_ALG_SHAKE256_192:
            case TpmAlgIdConstants.TPM_ALG_SHAKE256_256:
            case TpmAlgIdConstants.TPM_ALG_SHAKE256_512:
            case TpmAlgIdConstants.TPM_ALG_CMAC:
            case TpmAlgIdConstants.TPM_ALG_CTR:
            case TpmAlgIdConstants.TPM_ALG_OFB:
            case TpmAlgIdConstants.TPM_ALG_CBC:
            case TpmAlgIdConstants.TPM_ALG_CFB:
            case TpmAlgIdConstants.TPM_ALG_ECB:
            case TpmAlgIdConstants.TPM_ALG_CCM:
            case TpmAlgIdConstants.TPM_ALG_GCM:
            case TpmAlgIdConstants.TPM_ALG_KW:
            case TpmAlgIdConstants.TPM_ALG_KWP:
            case TpmAlgIdConstants.TPM_ALG_EAX:
            case TpmAlgIdConstants.TPM_ALG_EDDSA:
            case TpmAlgIdConstants.TPM_ALG_EDDSA_PH:
            case TpmAlgIdConstants.TPM_ALG_LMS:
            case TpmAlgIdConstants.TPM_ALG_XMSS:
            case TpmAlgIdConstants.TPM_ALG_KEYEDXOF:
            case TpmAlgIdConstants.TPM_ALG_KMACXOF128:
            case TpmAlgIdConstants.TPM_ALG_KMACXOF256:
            case TpmAlgIdConstants.TPM_ALG_KMAC128:
            case TpmAlgIdConstants.TPM_ALG_KMAC256:
            case TpmAlgIdConstants.TPM_ALG_MLKEM:
            case TpmAlgIdConstants.TPM_ALG_MLDSA:
            case TpmAlgIdConstants.TPM_ALG_HASH_MLDSA:
            default:
            {
                throw new NotSupportedException($"Algorithm type '{Type}' is not supported for serialization.");
            }
        }
    }

    /// <summary>
    /// Parses a public ID from a TPM reader.
    /// </summary>
    /// <param name="type">The algorithm type (selector).</param>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed public ID.</returns>
    public static TpmuPublicId Parse(TpmAlgIdConstants type, ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return type switch
        {
            TpmAlgIdConstants.TPM_ALG_RSA => ParseRsa(ref reader, pool),
            TpmAlgIdConstants.TPM_ALG_ECC => new TpmuPublicId(type, TpmsEccPoint.Parse(ref reader, pool)),
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH => ParseKeyedHash(ref reader, pool),
            TpmAlgIdConstants.TPM_ALG_ERROR or
            TpmAlgIdConstants.TPM_ALG_TDES or
            TpmAlgIdConstants.TPM_ALG_SHA or
            TpmAlgIdConstants.TPM_ALG_HMAC or
            TpmAlgIdConstants.TPM_ALG_AES or
            TpmAlgIdConstants.TPM_ALG_MGF1 or
            TpmAlgIdConstants.TPM_ALG_XOR or
            TpmAlgIdConstants.TPM_ALG_SHA256 or
            TpmAlgIdConstants.TPM_ALG_SHA384 or
            TpmAlgIdConstants.TPM_ALG_SHA512 or
            TpmAlgIdConstants.TPM_ALG_SHA256_192 or
            TpmAlgIdConstants.TPM_ALG_NULL or
            TpmAlgIdConstants.TPM_ALG_SM3_256 or
            TpmAlgIdConstants.TPM_ALG_SM4 or
            TpmAlgIdConstants.TPM_ALG_RSASSA or
            TpmAlgIdConstants.TPM_ALG_RSAES or
            TpmAlgIdConstants.TPM_ALG_RSAPSS or
            TpmAlgIdConstants.TPM_ALG_OAEP or
            TpmAlgIdConstants.TPM_ALG_ECDSA or
            TpmAlgIdConstants.TPM_ALG_ECDH or
            TpmAlgIdConstants.TPM_ALG_ECDAA or
            TpmAlgIdConstants.TPM_ALG_SM2 or
            TpmAlgIdConstants.TPM_ALG_ECSCHNORR or
            TpmAlgIdConstants.TPM_ALG_ECMQV or
            TpmAlgIdConstants.TPM_ALG_HKDF or
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A or
            TpmAlgIdConstants.TPM_ALG_KDF2 or
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 or
            TpmAlgIdConstants.TPM_ALG_SYMCIPHER or
            TpmAlgIdConstants.TPM_ALG_CAMELLIA or
            TpmAlgIdConstants.TPM_ALG_SHA3_256 or
            TpmAlgIdConstants.TPM_ALG_SHA3_384 or
            TpmAlgIdConstants.TPM_ALG_SHA3_512 or
            TpmAlgIdConstants.TPM_ALG_SHAKE128 or
            TpmAlgIdConstants.TPM_ALG_SHAKE256 or
            TpmAlgIdConstants.TPM_ALG_SHAKE256_192 or
            TpmAlgIdConstants.TPM_ALG_SHAKE256_256 or
            TpmAlgIdConstants.TPM_ALG_SHAKE256_512 or
            TpmAlgIdConstants.TPM_ALG_CMAC or
            TpmAlgIdConstants.TPM_ALG_CTR or
            TpmAlgIdConstants.TPM_ALG_OFB or
            TpmAlgIdConstants.TPM_ALG_CBC or
            TpmAlgIdConstants.TPM_ALG_CFB or
            TpmAlgIdConstants.TPM_ALG_ECB or
            TpmAlgIdConstants.TPM_ALG_CCM or
            TpmAlgIdConstants.TPM_ALG_GCM or
            TpmAlgIdConstants.TPM_ALG_KW or
            TpmAlgIdConstants.TPM_ALG_KWP or
            TpmAlgIdConstants.TPM_ALG_EAX or
            TpmAlgIdConstants.TPM_ALG_EDDSA or
            TpmAlgIdConstants.TPM_ALG_EDDSA_PH or
            TpmAlgIdConstants.TPM_ALG_LMS or
            TpmAlgIdConstants.TPM_ALG_XMSS or
            TpmAlgIdConstants.TPM_ALG_KEYEDXOF or
            TpmAlgIdConstants.TPM_ALG_KMACXOF128 or
            TpmAlgIdConstants.TPM_ALG_KMACXOF256 or
            TpmAlgIdConstants.TPM_ALG_KMAC128 or
            TpmAlgIdConstants.TPM_ALG_KMAC256 or
            TpmAlgIdConstants.TPM_ALG_MLKEM or
            TpmAlgIdConstants.TPM_ALG_MLDSA or
            TpmAlgIdConstants.TPM_ALG_HASH_MLDSA =>
                throw new NotSupportedException($"Algorithm type '{type}' is not supported for parsing."),
            _ => throw new NotSupportedException($"Algorithm type '{type}' is not supported for parsing.")
        };

        static TpmuPublicId ParseRsa(ref TpmReader reader, BaseMemoryPool pool)
        {
            ushort size = reader.ReadUInt16();
            if(size == 0)
            {
                return EmptyRsa();
            }

            IMemoryOwner<byte> storage = pool.Rent(size);
            reader.ReadBytes(size).CopyTo(storage.Memory.Span[..size]);

            return new TpmuPublicId(TpmAlgIdConstants.TPM_ALG_RSA, storage, size);
        }

        static TpmuPublicId ParseKeyedHash(ref TpmReader reader, BaseMemoryPool pool)
        {
            ushort size = reader.ReadUInt16();
            if(size == 0)
            {
                return EmptyKeyedHash();
            }

            IMemoryOwner<byte> storage = pool.Rent(size);
            reader.ReadBytes(size).CopyTo(storage.Memory.Span[..size]);

            return new TpmuPublicId(storage, size);
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
            KeyedHashStorage?.Dispose();
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
                TpmAlgIdConstants.TPM_ALG_KEYEDHASH => $"TPMU_PUBLIC_ID(KEYEDHASH, {KeyedHashLength} bytes)",
                TpmAlgIdConstants.TPM_ALG_ERROR or
                TpmAlgIdConstants.TPM_ALG_TDES or
                TpmAlgIdConstants.TPM_ALG_SHA or
                TpmAlgIdConstants.TPM_ALG_HMAC or
                TpmAlgIdConstants.TPM_ALG_AES or
                TpmAlgIdConstants.TPM_ALG_MGF1 or
                TpmAlgIdConstants.TPM_ALG_XOR or
                TpmAlgIdConstants.TPM_ALG_SHA256 or
                TpmAlgIdConstants.TPM_ALG_SHA384 or
                TpmAlgIdConstants.TPM_ALG_SHA512 or
                TpmAlgIdConstants.TPM_ALG_SHA256_192 or
                TpmAlgIdConstants.TPM_ALG_NULL or
                TpmAlgIdConstants.TPM_ALG_SM3_256 or
                TpmAlgIdConstants.TPM_ALG_SM4 or
                TpmAlgIdConstants.TPM_ALG_RSASSA or
                TpmAlgIdConstants.TPM_ALG_RSAES or
                TpmAlgIdConstants.TPM_ALG_RSAPSS or
                TpmAlgIdConstants.TPM_ALG_OAEP or
                TpmAlgIdConstants.TPM_ALG_ECDSA or
                TpmAlgIdConstants.TPM_ALG_ECDH or
                TpmAlgIdConstants.TPM_ALG_ECDAA or
                TpmAlgIdConstants.TPM_ALG_SM2 or
                TpmAlgIdConstants.TPM_ALG_ECSCHNORR or
                TpmAlgIdConstants.TPM_ALG_ECMQV or
                TpmAlgIdConstants.TPM_ALG_HKDF or
                TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A or
                TpmAlgIdConstants.TPM_ALG_KDF2 or
                TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 or
                TpmAlgIdConstants.TPM_ALG_SYMCIPHER or
                TpmAlgIdConstants.TPM_ALG_CAMELLIA or
                TpmAlgIdConstants.TPM_ALG_SHA3_256 or
                TpmAlgIdConstants.TPM_ALG_SHA3_384 or
                TpmAlgIdConstants.TPM_ALG_SHA3_512 or
                TpmAlgIdConstants.TPM_ALG_SHAKE128 or
                TpmAlgIdConstants.TPM_ALG_SHAKE256 or
                TpmAlgIdConstants.TPM_ALG_SHAKE256_192 or
                TpmAlgIdConstants.TPM_ALG_SHAKE256_256 or
                TpmAlgIdConstants.TPM_ALG_SHAKE256_512 or
                TpmAlgIdConstants.TPM_ALG_CMAC or
                TpmAlgIdConstants.TPM_ALG_CTR or
                TpmAlgIdConstants.TPM_ALG_OFB or
                TpmAlgIdConstants.TPM_ALG_CBC or
                TpmAlgIdConstants.TPM_ALG_CFB or
                TpmAlgIdConstants.TPM_ALG_ECB or
                TpmAlgIdConstants.TPM_ALG_CCM or
                TpmAlgIdConstants.TPM_ALG_GCM or
                TpmAlgIdConstants.TPM_ALG_KW or
                TpmAlgIdConstants.TPM_ALG_KWP or
                TpmAlgIdConstants.TPM_ALG_EAX or
                TpmAlgIdConstants.TPM_ALG_EDDSA or
                TpmAlgIdConstants.TPM_ALG_EDDSA_PH or
                TpmAlgIdConstants.TPM_ALG_LMS or
                TpmAlgIdConstants.TPM_ALG_XMSS or
                TpmAlgIdConstants.TPM_ALG_KEYEDXOF or
                TpmAlgIdConstants.TPM_ALG_KMACXOF128 or
                TpmAlgIdConstants.TPM_ALG_KMACXOF256 or
                TpmAlgIdConstants.TPM_ALG_KMAC128 or
                TpmAlgIdConstants.TPM_ALG_KMAC256 or
                TpmAlgIdConstants.TPM_ALG_MLKEM or
                TpmAlgIdConstants.TPM_ALG_MLDSA or
                TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => $"TPMU_PUBLIC_ID({Type})",
                _ => $"TPMU_PUBLIC_ID({Type})"
            };
        }
    }
}
