using System.Diagnostics;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Union of an object's type-specific private data (TPMU_SENSITIVE_COMPOSITE).
/// </summary>
/// <remarks>
/// <para>
/// This union carries the <c>[sensitiveType]sensitive</c> member of <c>TPMT_SENSITIVE</c>: TPM 2.0 Library
/// Part 2, clause 12.3.2.3, Table 239 defines <c>rsa TPM2B_PRIVATE_KEY_RSA</c> (<c>TPM_ALG_RSA</c>) as "a prime
/// factor of the public key", <c>ecc TPM2B_ECC_PARAMETER</c> (<c>TPM_ALG_ECC</c>) as "the integer private key",
/// and <c>bits TPM2B_SENSITIVE_DATA</c> (<c>TPM_ALG_KEYEDHASH</c>) as "the private data"; the table's remaining
/// members — <c>sym</c> (<c>TPM_ALG_SYMCIPHER</c>), <c>mldsa</c>, <c>mlkem</c> and <c>any</c> — are not
/// modeled and refuse to parse.
/// </para>
/// <para>
/// Each carrier's arm is a pooled or pinned rental this union adopts through <see cref="FromRsa"/>,
/// <see cref="FromEcc"/> and <see cref="FromBits"/>; <see cref="Dispose"/> releases whichever arm the selector
/// names.
/// </para>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 12.3.2.3, Table 239.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmuSensitiveComposite: IDisposable, IEquatable<TpmuSensitiveComposite>
{
    /// <summary>Whether <see cref="Dispose"/> has already released the populated arm.</summary>
    private bool disposed;

    /// <summary>
    /// Gets the algorithm type that determines union interpretation — the enclosing <c>TPMT_SENSITIVE</c>'s
    /// <c>sensitiveType</c>.
    /// </summary>
    public TpmAlgIdConstants Type { get; }

    /// <summary>
    /// Gets the RSA arm's storage (when <see cref="Type"/> is <see cref="TpmAlgIdConstants.TPM_ALG_RSA"/>), or
    /// <see langword="null"/> otherwise.
    /// </summary>
    private Tpm2bPrivateKeyRsa? RsaValue { get; }

    /// <summary>
    /// Gets the ECC arm's storage (when <see cref="Type"/> is <see cref="TpmAlgIdConstants.TPM_ALG_ECC"/>), or
    /// <see langword="null"/> otherwise.
    /// </summary>
    private Tpm2bEccParameter? EccValue { get; }

    /// <summary>
    /// Gets the KEYEDHASH arm's storage (when <see cref="Type"/> is <see cref="TpmAlgIdConstants.TPM_ALG_KEYEDHASH"/>), or
    /// <see langword="null"/> otherwise.
    /// </summary>
    private Tpm2bSensitiveData? BitsValue { get; }

    /// <summary>
    /// Initializes a new composite over the RSA arm; ownership of <paramref name="rsa"/> transfers here.
    /// </summary>
    /// <param name="rsa">The RSA prime factor.</param>
    private TpmuSensitiveComposite(Tpm2bPrivateKeyRsa rsa)
    {
        Type = TpmAlgIdConstants.TPM_ALG_RSA;
        RsaValue = rsa;
    }

    /// <summary>
    /// Initializes a new composite over the ECC arm; ownership of <paramref name="ecc"/> transfers here.
    /// </summary>
    /// <param name="ecc">The ECC private scalar.</param>
    private TpmuSensitiveComposite(Tpm2bEccParameter ecc)
    {
        Type = TpmAlgIdConstants.TPM_ALG_ECC;
        EccValue = ecc;
    }

    /// <summary>
    /// Initializes a new composite over the KEYEDHASH arm; ownership of <paramref name="bits"/> transfers here.
    /// </summary>
    /// <param name="bits">The private data.</param>
    private TpmuSensitiveComposite(Tpm2bSensitiveData bits)
    {
        Type = TpmAlgIdConstants.TPM_ALG_KEYEDHASH;
        BitsValue = bits;
    }

    /// <summary>
    /// Creates a composite carrying an RSA prime factor; ownership of <paramref name="prime"/> transfers to the
    /// returned union.
    /// </summary>
    /// <param name="prime">The RSA prime factor.</param>
    /// <returns>The RSA-selected composite.</returns>
    public static TpmuSensitiveComposite FromRsa(Tpm2bPrivateKeyRsa prime)
    {
        ArgumentNullException.ThrowIfNull(prime);

        return new TpmuSensitiveComposite(prime);
    }

    /// <summary>
    /// Creates a composite carrying an ECC private scalar; ownership of <paramref name="scalar"/> transfers to
    /// the returned union.
    /// </summary>
    /// <param name="scalar">The ECC private scalar, a pinned <see cref="Tpm2bEccParameter"/> rental.</param>
    /// <returns>The ECC-selected composite.</returns>
    public static TpmuSensitiveComposite FromEcc(Tpm2bEccParameter scalar)
    {
        ArgumentNullException.ThrowIfNull(scalar);

        return new TpmuSensitiveComposite(scalar);
    }

    /// <summary>
    /// Creates a composite carrying KEYEDHASH private data; ownership of <paramref name="bits"/> transfers to
    /// the returned union.
    /// </summary>
    /// <param name="bits">The private data.</param>
    /// <returns>The KEYEDHASH-selected composite.</returns>
    public static TpmuSensitiveComposite FromBits(Tpm2bSensitiveData bits)
    {
        ArgumentNullException.ThrowIfNull(bits);

        return new TpmuSensitiveComposite(bits);
    }

    /// <summary>
    /// Gets the RSA prime factor.
    /// </summary>
    /// <exception cref="InvalidOperationException"><see cref="Type"/> is not <see cref="TpmAlgIdConstants.TPM_ALG_RSA"/>.</exception>
    public Tpm2bPrivateKeyRsa Rsa
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return RsaValue ?? throw new InvalidOperationException($"The composite carries '{Type}', not TPM_ALG_RSA.");
        }
    }

    /// <summary>
    /// Gets the ECC private scalar.
    /// </summary>
    /// <exception cref="InvalidOperationException"><see cref="Type"/> is not <see cref="TpmAlgIdConstants.TPM_ALG_ECC"/>.</exception>
    public Tpm2bEccParameter Ecc
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return EccValue ?? throw new InvalidOperationException($"The composite carries '{Type}', not TPM_ALG_ECC.");
        }
    }

    /// <summary>
    /// Gets the KEYEDHASH private data.
    /// </summary>
    /// <exception cref="InvalidOperationException"><see cref="Type"/> is not <see cref="TpmAlgIdConstants.TPM_ALG_KEYEDHASH"/>.</exception>
    public Tpm2bSensitiveData Bits
    {
        get
        {
            ObjectDisposedException.ThrowIf(disposed, this);

            return BitsValue ?? throw new InvalidOperationException($"The composite carries '{Type}', not TPM_ALG_KEYEDHASH.");
        }
    }

    /// <summary>
    /// Gets the serialized size of the selected arm — the selector itself is written by the enclosing
    /// <c>TPMT_SENSITIVE</c>, not by this union.
    /// </summary>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return Type switch
        {
            TpmAlgIdConstants.TPM_ALG_RSA => Rsa.SerializedSize,
            TpmAlgIdConstants.TPM_ALG_ECC => Ecc.SerializedSize,
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH => Bits.SerializedSize,
            TpmAlgIdConstants.TPM_ALG_ERROR or
            TpmAlgIdConstants.TPM_ALG_TDES or
            TpmAlgIdConstants.TPM_ALG_SHA1 or
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
                throw new NotSupportedException($"Sensitive-composite type '{Type}' is not supported for serialization."),
            _ => throw new NotSupportedException($"Sensitive-composite type '{Type}' is not supported for serialization.")
        };
    }

    /// <summary>
    /// Writes the selected arm to a TPM writer.
    /// </summary>
    /// <param name="writer">The writer.</param>
    /// <remarks>
    /// The type selector is not written; it is written separately as part of <c>TPMT_SENSITIVE</c>.
    /// </remarks>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        switch(Type)
        {
            case TpmAlgIdConstants.TPM_ALG_RSA:
            {
                Rsa.WriteTo(ref writer);
                break;
            }
            case TpmAlgIdConstants.TPM_ALG_ECC:
            {
                Ecc.WriteTo(ref writer);
                break;
            }
            case TpmAlgIdConstants.TPM_ALG_KEYEDHASH:
            {
                Bits.WriteTo(ref writer);
                break;
            }
            case TpmAlgIdConstants.TPM_ALG_ERROR:
            case TpmAlgIdConstants.TPM_ALG_TDES:
            case TpmAlgIdConstants.TPM_ALG_SHA1:
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
                throw new NotSupportedException($"Sensitive-composite type '{Type}' is not supported for serialization.");
            }
        }
    }

    /// <summary>
    /// Parses the type-selected composite from a TPM reader.
    /// </summary>
    /// <remarks>
    /// The ECC arm rents <see cref="AllocationKind.Pinned"/> storage through
    /// <see cref="Tpm2bEccParameter.Parse(ref TpmReader, BaseMemoryPool, AllocationKind)"/>, since it carries the
    /// private scalar rather than a public coordinate.
    /// </remarks>
    /// <param name="selector">The <c>sensitiveType</c> selector already read from the enclosing <c>TPMT_SENSITIVE</c>.</param>
    /// <param name="reader">The reader.</param>
    /// <param name="pool">The memory pool for allocating storage.</param>
    /// <returns>The parsed composite; ownership transfers to the caller.</returns>
    /// <exception cref="NotSupportedException"><paramref name="selector"/> names an arm this union does not model.</exception>
    public static TpmuSensitiveComposite Parse(TpmAlgIdConstants selector, ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return selector switch
        {
            TpmAlgIdConstants.TPM_ALG_RSA => FromRsa(Tpm2bPrivateKeyRsa.Parse(ref reader, pool)),
            TpmAlgIdConstants.TPM_ALG_ECC => FromEcc(Tpm2bEccParameter.Parse(ref reader, pool, AllocationKind.Pinned)),
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH => FromBits(Tpm2bSensitiveData.Parse(ref reader, pool)),
            TpmAlgIdConstants.TPM_ALG_ERROR or
            TpmAlgIdConstants.TPM_ALG_TDES or
            TpmAlgIdConstants.TPM_ALG_SHA1 or
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
                throw new NotSupportedException($"Sensitive-composite type '0x{(ushort)selector:X4}' is not modeled; only TPM_ALG_RSA, TPM_ALG_ECC and TPM_ALG_KEYEDHASH are."),
            _ => throw new NotSupportedException($"Sensitive-composite type '0x{(ushort)selector:X4}' is not modeled; only TPM_ALG_RSA, TPM_ALG_ECC and TPM_ALG_KEYEDHASH are.")
        };
    }

    /// <summary>
    /// Releases the memory owned by the populated arm.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            RsaValue?.Dispose();
            EccValue?.Dispose();
            BitsValue?.Dispose();
            disposed = true;
        }
    }

    /// <summary>
    /// Determines whether this composite and <paramref name="other"/> carry the same selector and identical
    /// octets in the selected arm.
    /// </summary>
    /// <param name="other">The composite to compare against.</param>
    /// <returns><see langword="true"/> when the selector and the selected arm's content match.</returns>
    public bool Equals(TpmuSensitiveComposite? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(Type != other.Type)
        {
            return false;
        }

        return Type switch
        {
            TpmAlgIdConstants.TPM_ALG_RSA => Rsa.AsReadOnlySpan().SequenceEqual(other.Rsa.AsReadOnlySpan()),
            TpmAlgIdConstants.TPM_ALG_ECC => Ecc.AsReadOnlySpan().SequenceEqual(other.Ecc.AsReadOnlySpan()),
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH => Bits.AsReadOnlySpan().SequenceEqual(other.Bits.AsReadOnlySpan()),
            TpmAlgIdConstants.TPM_ALG_ERROR or
            TpmAlgIdConstants.TPM_ALG_TDES or
            TpmAlgIdConstants.TPM_ALG_SHA1 or
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
            TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => false,
            _ => false
        };
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) => Equals(obj as TpmuSensitiveComposite);

    /// <inheritdoc/>
    public override int GetHashCode()
    {
        return Type switch
        {
            TpmAlgIdConstants.TPM_ALG_RSA => HashCode.Combine(Type, Rsa.Length),
            TpmAlgIdConstants.TPM_ALG_ECC => HashCode.Combine(Type, Ecc.Length),
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH => HashCode.Combine(Type, Bits.Length),
            TpmAlgIdConstants.TPM_ALG_ERROR or
            TpmAlgIdConstants.TPM_ALG_TDES or
            TpmAlgIdConstants.TPM_ALG_SHA1 or
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
            TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => HashCode.Combine(Type),
            _ => HashCode.Combine(Type)
        };
    }

    /// <summary>
    /// Determines whether two composites are equal.
    /// </summary>
    /// <param name="left">The first composite.</param>
    /// <param name="right">The second composite.</param>
    public static bool operator ==(TpmuSensitiveComposite? left, TpmuSensitiveComposite? right)
    {
        if(left is null)
        {
            return right is null;
        }

        return left.Equals(right);
    }

    /// <summary>
    /// Determines whether two composites are not equal.
    /// </summary>
    /// <param name="left">The first composite.</param>
    /// <param name="right">The second composite.</param>
    public static bool operator !=(TpmuSensitiveComposite? left, TpmuSensitiveComposite? right) => !(left == right);

    /// <summary>The debugger text this type's <see cref="DebuggerDisplayAttribute"/> names: the union, its selected arm and that arm's width.</summary>
    private string DebuggerDisplay => Type switch
    {
        TpmAlgIdConstants.TPM_ALG_RSA => $"TPMU_SENSITIVE_COMPOSITE(RSA, {RsaValue!.Length} bytes)",
        TpmAlgIdConstants.TPM_ALG_ECC => $"TPMU_SENSITIVE_COMPOSITE(ECC, {EccValue!.Length} bytes)",
        TpmAlgIdConstants.TPM_ALG_KEYEDHASH => $"TPMU_SENSITIVE_COMPOSITE(KEYEDHASH, {BitsValue!.Length} bytes)",
        TpmAlgIdConstants.TPM_ALG_ERROR or
        TpmAlgIdConstants.TPM_ALG_TDES or
        TpmAlgIdConstants.TPM_ALG_SHA1 or
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
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => $"TPMU_SENSITIVE_COMPOSITE({Type})",
        _ => $"TPMU_SENSITIVE_COMPOSITE({Type})"
    };
}
