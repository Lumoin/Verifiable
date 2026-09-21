using System.Diagnostics;
using Verifiable.Tpm.Spec.Algorithms;
using Verifiable.Tpm.Spec.Constants;

namespace Verifiable.Tpm.Spec.Structures;

/// <summary>
/// Union of signature values (TPMU_SIGNATURE), selected by the signing algorithm.
/// </summary>
/// <remarks>
/// <para>
/// The active member is chosen by the <c>sigAlg</c> selector of the enclosing TPMT_SIGNATURE. Each
/// member carries the hash algorithm used followed by the scheme-specific signature value.
/// </para>
/// <para>
/// <b>Union members:</b>
/// </para>
/// <list type="bullet">
///   <item><description>TPM_ALG_ECDSA: TPMS_SIGNATURE_ECC (hash + signatureR + signatureS), Part 2, clause 11.3.2, Table 214.</description></item>
///   <item><description>TPM_ALG_RSASSA / TPM_ALG_RSAPSS: TPMS_SIGNATURE_RSA (hash + sig), Part 2, clause 11.3.1, Table 212.</description></item>
///   <item><description>TPM_ALG_HMAC: TPMT_HA (hashAlg + digest, unsized), Part 2, clause 10.2.2, Table 89.</description></item>
///   <item><description>TPM_ALG_NULL: no member (see <see cref="Null"/>) — the NULL Signature.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, clause 11.3.5, Table 218 (TPMU_SIGNATURE).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmuSignature: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the signing algorithm selector (for example TPM_ALG_ECDSA, TPM_ALG_RSASSA, TPM_ALG_RSAPSS, or TPM_ALG_HMAC).
    /// </summary>
    public TpmAlgIdConstants Type { get; }

    /// <summary>
    /// Gets the hash algorithm reported inside the signature member.
    /// </summary>
    public TpmAlgIdConstants HashAlgorithm { get; }

    /// <summary>
    /// Gets the r component of an ECDSA signature, when <see cref="Type"/> is TPM_ALG_ECDSA; otherwise <see langword="null"/>.
    /// </summary>
    public Tpm2bEccParameter? SignatureR { get; }

    /// <summary>
    /// Gets the s component of an ECDSA signature, when <see cref="Type"/> is TPM_ALG_ECDSA; otherwise <see langword="null"/>.
    /// </summary>
    public Tpm2bEccParameter? SignatureS { get; }

    /// <summary>
    /// Gets the RSA signature buffer, when <see cref="Type"/> is TPM_ALG_RSASSA or TPM_ALG_RSAPSS; otherwise <see cref="Tpm2bPublicKeyRsa.Empty"/>.
    /// </summary>
    public Tpm2bPublicKeyRsa RsaSignature { get; }

    /// <summary>
    /// Gets the HMAC signature value (TPMT_HA), when <see cref="Type"/> is TPM_ALG_HMAC; otherwise <see langword="null"/>.
    /// </summary>
    public TpmtHa? HmacSignature { get; }

    /// <summary>
    /// Gets the shared NULL signature member (<c>sigAlg</c> TPM_ALG_NULL, no member) — a signature made by the
    /// NULL Signature (TPM 2.0 Library Part 3, clause 18.1: "the attestation block is 'signed' with the NULL
    /// Signature"). Immune to disposal: <see cref="Dispose"/> is a no-op for this instance, since it owns no
    /// buffer, so the shared instance stays usable for every holder.
    /// </summary>
    public static TpmuSignature Null { get; } = new(TpmAlgIdConstants.TPM_ALG_NULL);

    /// <summary>
    /// Gets whether this is the NULL signature member (<see cref="Type"/> is TPM_ALG_NULL).
    /// </summary>
    public bool IsNull => Type == TpmAlgIdConstants.TPM_ALG_NULL;

    /// <summary>
    /// Initializes an ECDSA signature member.
    /// </summary>
    private TpmuSignature(TpmAlgIdConstants type, TpmAlgIdConstants hashAlgorithm, Tpm2bEccParameter signatureR, Tpm2bEccParameter signatureS)
    {
        Type = type;
        HashAlgorithm = hashAlgorithm;
        SignatureR = signatureR;
        SignatureS = signatureS;
        RsaSignature = Tpm2bPublicKeyRsa.Empty;
        HmacSignature = null;
    }

    /// <summary>
    /// Initializes an RSA signature member.
    /// </summary>
    private TpmuSignature(TpmAlgIdConstants type, TpmAlgIdConstants hashAlgorithm, Tpm2bPublicKeyRsa rsaSignature)
    {
        Type = type;
        HashAlgorithm = hashAlgorithm;
        RsaSignature = rsaSignature;
        SignatureR = null;
        SignatureS = null;
        HmacSignature = null;
    }

    /// <summary>
    /// Initializes an HMAC signature member.
    /// </summary>
    private TpmuSignature(TpmAlgIdConstants type, TpmtHa hmacSignature)
    {
        Type = type;
        HashAlgorithm = hmacSignature.HashAlg.Value;
        RsaSignature = Tpm2bPublicKeyRsa.Empty;
        SignatureR = null;
        SignatureS = null;
        HmacSignature = hmacSignature;
    }

    /// <summary>
    /// Initializes the shared NULL signature member: no hash field, no signature bytes.
    /// </summary>
    private TpmuSignature(TpmAlgIdConstants type)
    {
        Type = type;
        HashAlgorithm = TpmAlgIdConstants.TPM_ALG_NULL;
        RsaSignature = Tpm2bPublicKeyRsa.Empty;
        SignatureR = null;
        SignatureS = null;
        HmacSignature = null;
    }

    /// <summary>
    /// Creates a signature union from a raw signature value under the supplied algorithm selector.
    /// </summary>
    /// <param name="sigAlg">The signing-algorithm selector of the enclosing TPMT_SIGNATURE.</param>
    /// <param name="hashAlg">The hash algorithm the signature was made with, carried in the member's <c>hash</c> field.</param>
    /// <param name="signature">
    /// The raw signature value: for <c>TPM_ALG_ECDSA</c> the IEEE P1363 <c>r ‖ s</c> concatenation, whose two
    /// equal-width halves become <c>signatureR</c> and <c>signatureS</c>; for an RSA scheme the signature octets,
    /// which become <c>sig</c> whole. Ignored when <paramref name="sigAlg"/> is <c>TPM_ALG_NULL</c>, which carries
    /// no member at all — the shared <see cref="Null"/> instance is returned regardless.
    /// </param>
    /// <param name="pool">The memory pool for the member's buffers. Unused for <c>TPM_ALG_NULL</c>.</param>
    /// <returns>The created signature union; the caller owns and disposes it.</returns>
    /// <exception cref="NotSupportedException"><paramref name="sigAlg"/> is not a supported signing algorithm.</exception>
    /// <exception cref="ArgumentException">
    /// An ECDSA <paramref name="signature"/> has odd length, so it cannot be canonical P1363 <c>r ‖ s</c>; or
    /// <paramref name="sigAlg"/> is <c>TPM_ALG_HMAC</c> and <paramref name="hashAlg"/> is <c>TPM_ALG_NULL</c> or
    /// has no known digest size, which <see cref="Parse"/> could never produce from the wire.
    /// </exception>
    public static TpmuSignature Create(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> signature, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return sigAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_ECDSA => CreateEcdsa(sigAlg, hashAlg, signature, pool),
            TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS => new TpmuSignature(sigAlg, hashAlg, Tpm2bPublicKeyRsa.Create(signature, pool)),
            TpmAlgIdConstants.TPM_ALG_HMAC => CreateHmac(sigAlg, hashAlg, signature, pool),
            TpmAlgIdConstants.TPM_ALG_NULL => Null,
            TpmAlgIdConstants.TPM_ALG_ERROR or
            TpmAlgIdConstants.TPM_ALG_RSA or
            TpmAlgIdConstants.TPM_ALG_TDES or
            TpmAlgIdConstants.TPM_ALG_SHA or
            TpmAlgIdConstants.TPM_ALG_AES or
            TpmAlgIdConstants.TPM_ALG_MGF1 or
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH or
            TpmAlgIdConstants.TPM_ALG_XOR or
            TpmAlgIdConstants.TPM_ALG_SHA256 or
            TpmAlgIdConstants.TPM_ALG_SHA384 or
            TpmAlgIdConstants.TPM_ALG_SHA512 or
            TpmAlgIdConstants.TPM_ALG_SHA256_192 or
            TpmAlgIdConstants.TPM_ALG_SM3_256 or
            TpmAlgIdConstants.TPM_ALG_SM4 or
            TpmAlgIdConstants.TPM_ALG_RSAES or
            TpmAlgIdConstants.TPM_ALG_OAEP or
            TpmAlgIdConstants.TPM_ALG_ECDH or
            TpmAlgIdConstants.TPM_ALG_ECDAA or
            TpmAlgIdConstants.TPM_ALG_SM2 or
            TpmAlgIdConstants.TPM_ALG_ECSCHNORR or
            TpmAlgIdConstants.TPM_ALG_ECMQV or
            TpmAlgIdConstants.TPM_ALG_HKDF or
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A or
            TpmAlgIdConstants.TPM_ALG_KDF2 or
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 or
            TpmAlgIdConstants.TPM_ALG_ECC or
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
                throw new NotSupportedException($"Signing algorithm '{sigAlg}' is not supported."),
            _ => throw new NotSupportedException($"Signing algorithm '{sigAlg}' is not supported.")
        };

        static TpmuSignature CreateHmac(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> signature, BaseMemoryPool pool)
        {
            TpmiAlgHash hash = TpmiAlgHash.FromValue(hashAlg);
            if(hash.DigestSize is null)
            {
                throw new ArgumentException($"An HMAC signature member requires a hash algorithm with a known digest size; '{hashAlg}' has none, so no wire parse could ever produce it.", nameof(hashAlg));
            }

            return new TpmuSignature(sigAlg, TpmtHa.Create(hash, signature, pool));
        }

        static TpmuSignature CreateEcdsa(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> signature, BaseMemoryPool pool)
        {
            //r and s are the equal-width halves of the IEEE P1363 signature (each the curve field width), so its
            //length is even and the split at the midpoint is exact.
            if((signature.Length & 1) != 0)
            {
                throw new ArgumentException($"An ECDSA signature must be IEEE P1363 r ‖ s of even length so r and s are equal width; got {signature.Length} octets.", nameof(signature));
            }

            int fieldWidth = signature.Length / 2;
            Tpm2bEccParameter r = Tpm2bEccParameter.Create(signature[..fieldWidth], pool);
            try
            {
                Tpm2bEccParameter s = Tpm2bEccParameter.Create(signature[fieldWidth..], pool);

                return new TpmuSignature(sigAlg, hashAlg, r, s);
            }
            catch
            {
                r.Dispose();
                throw;
            }
        }
    }

    /// <summary>
    /// Creates an ECDSA signature member directly from its independently-sized <c>signatureR</c>/<c>signatureS</c>
    /// components — the true <c>TPMS_SIGNATURE_ECC</c> wire shape (Part 2, clause 11.3.2, Table 214), where the
    /// two <c>TPM2B_ECC_PARAMETER</c> buffers are unrelated in length, each independently leading-zero-stripped.
    /// </summary>
    /// <remarks>
    /// Unlike <see cref="Create"/>'s single concatenated <c>r ‖ s</c> input — built for a signing effect's
    /// P1363 output, which is always equal-width by construction — this overload takes the two components as
    /// already-parsed spans, so a wire-valid pair whose combined length happens to be odd (one component
    /// carrying a stripped leading zero the other lacks) is accepted exactly as the reference unmarshaler
    /// accepts it: nothing in <c>TPMS_SIGNATURE_ECC</c> (Table 214) relates <c>signatureR</c>'s size to
    /// <c>signatureS</c>'s.
    /// </remarks>
    /// <param name="hashAlg">The hash algorithm the signature was made with, carried in the member's <c>hash</c> field.</param>
    /// <param name="signatureR">The <c>signatureR</c> component.</param>
    /// <param name="signatureS">The <c>signatureS</c> component.</param>
    /// <param name="pool">The memory pool for the member's buffers.</param>
    /// <returns>The created signature union; the caller owns and disposes it.</returns>
    public static TpmuSignature CreateEcdsaFromComponents(TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> signatureR, ReadOnlySpan<byte> signatureS, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        Tpm2bEccParameter r = Tpm2bEccParameter.Create(signatureR, pool);
        try
        {
            Tpm2bEccParameter s = Tpm2bEccParameter.Create(signatureS, pool);

            return new TpmuSignature(TpmAlgIdConstants.TPM_ALG_ECDSA, hashAlg, r, s);
        }
        catch
        {
            r.Dispose();
            throw;
        }
    }

    /// <summary>
    /// Gets the serialized size of the selected member: its <c>hash</c> field followed by the member's buffers.
    /// </summary>
    /// <returns>The number of octets <see cref="WriteTo"/> produces.</returns>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return Type switch
        {
            TpmAlgIdConstants.TPM_ALG_ECDSA => sizeof(ushort) + SignatureR!.SerializedSize + SignatureS!.SerializedSize,
            TpmAlgIdConstants.TPM_ALG_HMAC => HmacSignature!.SerializedSize,
            TpmAlgIdConstants.TPM_ALG_NULL => 0,
            TpmAlgIdConstants.TPM_ALG_ERROR or
            TpmAlgIdConstants.TPM_ALG_RSA or
            TpmAlgIdConstants.TPM_ALG_TDES or
            TpmAlgIdConstants.TPM_ALG_SHA or
            TpmAlgIdConstants.TPM_ALG_AES or
            TpmAlgIdConstants.TPM_ALG_MGF1 or
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH or
            TpmAlgIdConstants.TPM_ALG_XOR or
            TpmAlgIdConstants.TPM_ALG_SHA256 or
            TpmAlgIdConstants.TPM_ALG_SHA384 or
            TpmAlgIdConstants.TPM_ALG_SHA512 or
            TpmAlgIdConstants.TPM_ALG_SHA256_192 or
            TpmAlgIdConstants.TPM_ALG_SM3_256 or
            TpmAlgIdConstants.TPM_ALG_SM4 or
            TpmAlgIdConstants.TPM_ALG_RSASSA or
            TpmAlgIdConstants.TPM_ALG_RSAES or
            TpmAlgIdConstants.TPM_ALG_RSAPSS or
            TpmAlgIdConstants.TPM_ALG_OAEP or
            TpmAlgIdConstants.TPM_ALG_ECDH or
            TpmAlgIdConstants.TPM_ALG_ECDAA or
            TpmAlgIdConstants.TPM_ALG_SM2 or
            TpmAlgIdConstants.TPM_ALG_ECSCHNORR or
            TpmAlgIdConstants.TPM_ALG_ECMQV or
            TpmAlgIdConstants.TPM_ALG_HKDF or
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A or
            TpmAlgIdConstants.TPM_ALG_KDF2 or
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 or
            TpmAlgIdConstants.TPM_ALG_ECC or
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
            TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => sizeof(ushort) + RsaSignature.SerializedSize,
            _ => sizeof(ushort) + RsaSignature.SerializedSize
        };
    }

    /// <summary>
    /// Writes the selected member to a TPM writer: the <c>hash</c> field, then <c>signatureR</c> and
    /// <c>signatureS</c> for ECDSA, <c>sig</c> for an RSA scheme, or the digest for HMAC — whose member is a
    /// self-contained TPMT_HA, already carrying its own <c>hashAlg</c>. Writes nothing for <c>TPM_ALG_NULL</c>,
    /// which selects no member. The selector itself belongs to the enclosing <see cref="TpmtSignature"/>.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        switch(Type)
        {
            case TpmAlgIdConstants.TPM_ALG_ECDSA:
            {
                writer.WriteUInt16((ushort)HashAlgorithm);
                SignatureR!.WriteTo(ref writer);
                SignatureS!.WriteTo(ref writer);

                break;
            }
            case TpmAlgIdConstants.TPM_ALG_HMAC:
            {
                HmacSignature!.WriteTo(ref writer);

                break;
            }
            case TpmAlgIdConstants.TPM_ALG_NULL:
            {
                //TPM_ALG_NULL selects no member: nothing follows the sigAlg selector the enclosing
                //TPMT_SIGNATURE already wrote.
                break;
            }
            case TpmAlgIdConstants.TPM_ALG_ERROR:
            case TpmAlgIdConstants.TPM_ALG_RSA:
            case TpmAlgIdConstants.TPM_ALG_TDES:
            case TpmAlgIdConstants.TPM_ALG_SHA:
            case TpmAlgIdConstants.TPM_ALG_AES:
            case TpmAlgIdConstants.TPM_ALG_MGF1:
            case TpmAlgIdConstants.TPM_ALG_KEYEDHASH:
            case TpmAlgIdConstants.TPM_ALG_XOR:
            case TpmAlgIdConstants.TPM_ALG_SHA256:
            case TpmAlgIdConstants.TPM_ALG_SHA384:
            case TpmAlgIdConstants.TPM_ALG_SHA512:
            case TpmAlgIdConstants.TPM_ALG_SHA256_192:
            case TpmAlgIdConstants.TPM_ALG_SM3_256:
            case TpmAlgIdConstants.TPM_ALG_SM4:
            case TpmAlgIdConstants.TPM_ALG_RSASSA:
            case TpmAlgIdConstants.TPM_ALG_RSAES:
            case TpmAlgIdConstants.TPM_ALG_RSAPSS:
            case TpmAlgIdConstants.TPM_ALG_OAEP:
            case TpmAlgIdConstants.TPM_ALG_ECDH:
            case TpmAlgIdConstants.TPM_ALG_ECDAA:
            case TpmAlgIdConstants.TPM_ALG_SM2:
            case TpmAlgIdConstants.TPM_ALG_ECSCHNORR:
            case TpmAlgIdConstants.TPM_ALG_ECMQV:
            case TpmAlgIdConstants.TPM_ALG_HKDF:
            case TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A:
            case TpmAlgIdConstants.TPM_ALG_KDF2:
            case TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108:
            case TpmAlgIdConstants.TPM_ALG_ECC:
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
                writer.WriteUInt16((ushort)HashAlgorithm);
                RsaSignature.WriteTo(ref writer);

                break;
            }
        }
    }

    /// <summary>
    /// Parses a signature union from a TPM reader using the supplied algorithm selector.
    /// </summary>
    /// <param name="sigAlg">The signing algorithm selector from the enclosing TPMT_SIGNATURE.</param>
    /// <param name="reader">The reader positioned at the start of the signature member (its hash field).</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed signature union.</returns>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="sigAlg"/> is not a supported signing algorithm.</exception>
    /// <remarks>
    /// <paramref name="sigAlg"/> <c>TPM_ALG_NULL</c> reads nothing at all — unlike every other selector, it has
    /// no <c>hash</c> field either — and returns the shared <see cref="Null"/> instance directly.
    /// </remarks>
    public static TpmuSignature Parse(TpmAlgIdConstants sigAlg, ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(sigAlg == TpmAlgIdConstants.TPM_ALG_NULL)
        {
            return Null;
        }

        if(sigAlg == TpmAlgIdConstants.TPM_ALG_HMAC)
        {
            return new TpmuSignature(sigAlg, TpmtHa.Parse(ref reader, pool));
        }

        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        return sigAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_ECDSA => ParseEcdsa(sigAlg, hashAlg, ref reader, pool),
            TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS => ParseRsa(sigAlg, hashAlg, ref reader, pool),
            TpmAlgIdConstants.TPM_ALG_ERROR or
            TpmAlgIdConstants.TPM_ALG_RSA or
            TpmAlgIdConstants.TPM_ALG_TDES or
            TpmAlgIdConstants.TPM_ALG_SHA or
            TpmAlgIdConstants.TPM_ALG_HMAC or
            TpmAlgIdConstants.TPM_ALG_AES or
            TpmAlgIdConstants.TPM_ALG_MGF1 or
            TpmAlgIdConstants.TPM_ALG_KEYEDHASH or
            TpmAlgIdConstants.TPM_ALG_XOR or
            TpmAlgIdConstants.TPM_ALG_SHA256 or
            TpmAlgIdConstants.TPM_ALG_SHA384 or
            TpmAlgIdConstants.TPM_ALG_SHA512 or
            TpmAlgIdConstants.TPM_ALG_SHA256_192 or
            TpmAlgIdConstants.TPM_ALG_NULL or
            TpmAlgIdConstants.TPM_ALG_SM3_256 or
            TpmAlgIdConstants.TPM_ALG_SM4 or
            TpmAlgIdConstants.TPM_ALG_RSAES or
            TpmAlgIdConstants.TPM_ALG_OAEP or
            TpmAlgIdConstants.TPM_ALG_ECDH or
            TpmAlgIdConstants.TPM_ALG_ECDAA or
            TpmAlgIdConstants.TPM_ALG_SM2 or
            TpmAlgIdConstants.TPM_ALG_ECSCHNORR or
            TpmAlgIdConstants.TPM_ALG_ECMQV or
            TpmAlgIdConstants.TPM_ALG_HKDF or
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A or
            TpmAlgIdConstants.TPM_ALG_KDF2 or
            TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 or
            TpmAlgIdConstants.TPM_ALG_ECC or
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
                throw new NotSupportedException($"Signing algorithm '{sigAlg}' is not supported for parsing."),
            _ => throw new NotSupportedException($"Signing algorithm '{sigAlg}' is not supported for parsing.")
        };

        static TpmuSignature ParseEcdsa(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ref TpmReader reader, BaseMemoryPool pool)
        {
            Tpm2bEccParameter r = Tpm2bEccParameter.Parse(ref reader, pool);
            try
            {
                Tpm2bEccParameter s = Tpm2bEccParameter.Parse(ref reader, pool);

                return new TpmuSignature(sigAlg, hashAlg, r, s);
            }
            catch
            {
                //A truncated or oversized s must not orphan the rental the already-parsed r holds.
                r.Dispose();
                throw;
            }
        }

        static TpmuSignature ParseRsa(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ref TpmReader reader, BaseMemoryPool pool)
        {
            Tpm2bPublicKeyRsa rsa = Tpm2bPublicKeyRsa.Parse(ref reader, pool);

            return new TpmuSignature(sigAlg, hashAlg, rsa);
        }
    }

    /// <summary>
    /// Releases the memory owned by this structure. A no-op for the shared <see cref="Null"/> instance, which
    /// owns no buffer, so that instance stays usable for every holder regardless of how many dispose it.
    /// </summary>
    public void Dispose()
    {
        if(!disposed && Type != TpmAlgIdConstants.TPM_ALG_NULL)
        {
            SignatureR?.Dispose();
            SignatureS?.Dispose();
            RsaSignature.Dispose();
            HmacSignature?.Dispose();
            disposed = true;
        }
    }

    /// <summary>The debugger display string.</summary>
    private string DebuggerDisplay => Type switch
    {
        TpmAlgIdConstants.TPM_ALG_ECDSA => $"TPMU_SIGNATURE(ECDSA, {HashAlgorithm}, R={SignatureR?.Length ?? 0} bytes, S={SignatureS?.Length ?? 0} bytes)",
        TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS => $"TPMU_SIGNATURE({Type}, {HashAlgorithm}, {RsaSignature.Size} bytes)",
        TpmAlgIdConstants.TPM_ALG_HMAC => $"TPMU_SIGNATURE(HMAC, {HashAlgorithm}, {HmacSignature?.Size ?? 0} bytes)",
        TpmAlgIdConstants.TPM_ALG_NULL => "TPMU_SIGNATURE(NULL)",
        TpmAlgIdConstants.TPM_ALG_ERROR or
        TpmAlgIdConstants.TPM_ALG_RSA or
        TpmAlgIdConstants.TPM_ALG_TDES or
        TpmAlgIdConstants.TPM_ALG_SHA or
        TpmAlgIdConstants.TPM_ALG_AES or
        TpmAlgIdConstants.TPM_ALG_MGF1 or
        TpmAlgIdConstants.TPM_ALG_KEYEDHASH or
        TpmAlgIdConstants.TPM_ALG_XOR or
        TpmAlgIdConstants.TPM_ALG_SHA256 or
        TpmAlgIdConstants.TPM_ALG_SHA384 or
        TpmAlgIdConstants.TPM_ALG_SHA512 or
        TpmAlgIdConstants.TPM_ALG_SHA256_192 or
        TpmAlgIdConstants.TPM_ALG_SM3_256 or
        TpmAlgIdConstants.TPM_ALG_SM4 or
        TpmAlgIdConstants.TPM_ALG_RSAES or
        TpmAlgIdConstants.TPM_ALG_OAEP or
        TpmAlgIdConstants.TPM_ALG_ECDH or
        TpmAlgIdConstants.TPM_ALG_ECDAA or
        TpmAlgIdConstants.TPM_ALG_SM2 or
        TpmAlgIdConstants.TPM_ALG_ECSCHNORR or
        TpmAlgIdConstants.TPM_ALG_ECMQV or
        TpmAlgIdConstants.TPM_ALG_HKDF or
        TpmAlgIdConstants.TPM_ALG_KDF1_SP800_56A or
        TpmAlgIdConstants.TPM_ALG_KDF2 or
        TpmAlgIdConstants.TPM_ALG_KDF1_SP800_108 or
        TpmAlgIdConstants.TPM_ALG_ECC or
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
        TpmAlgIdConstants.TPM_ALG_HASH_MLDSA => $"TPMU_SIGNATURE({Type})",
        _ => $"TPMU_SIGNATURE({Type})"
    };

    /// <summary>
    /// Returns the same metadata-only summary the debugger shows — the algorithm and the
    /// signature components' octet lengths, never the signature bytes — so an enclosing type's
    /// own diagnostic string interpolation renders this instance meaningfully instead of its
    /// type name.
    /// </summary>
    public override string ToString() => DebuggerDisplay;
}
