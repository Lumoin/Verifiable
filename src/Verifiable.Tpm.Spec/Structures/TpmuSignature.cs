using System;
using System.Buffers;
using System.Diagnostics;
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
///   <item><description>TPM_ALG_ECDSA: TPMS_SIGNATURE_ECC (hash + signatureR + signatureS), Part 2, Section 11.3.2, Table 205.</description></item>
///   <item><description>TPM_ALG_RSASSA / TPM_ALG_RSAPSS: TPMS_SIGNATURE_RSA (hash + sig), Part 2, Section 11.3.1, Table 203.</description></item>
/// </list>
/// <para>
/// Specification reference: TPM 2.0 Library Part 2, Section 11.3.3, Table 207 (TPMU_SIGNATURE).
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class TpmuSignature: IDisposable
{
    private bool disposed;

    /// <summary>
    /// Gets the signing algorithm selector (for example TPM_ALG_ECDSA, TPM_ALG_RSASSA, or TPM_ALG_RSAPSS).
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
    /// Initializes an ECDSA signature member.
    /// </summary>
    private TpmuSignature(TpmAlgIdConstants type, TpmAlgIdConstants hashAlgorithm, Tpm2bEccParameter signatureR, Tpm2bEccParameter signatureS)
    {
        Type = type;
        HashAlgorithm = hashAlgorithm;
        SignatureR = signatureR;
        SignatureS = signatureS;
        RsaSignature = Tpm2bPublicKeyRsa.Empty;
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
    }

    /// <summary>
    /// Creates a signature union from a raw signature value under the supplied algorithm selector.
    /// </summary>
    /// <param name="sigAlg">The signing-algorithm selector of the enclosing TPMT_SIGNATURE.</param>
    /// <param name="hashAlg">The hash algorithm the signature was made with, carried in the member's <c>hash</c> field.</param>
    /// <param name="signature">
    /// The raw signature value: for <c>TPM_ALG_ECDSA</c> the IEEE P1363 <c>r ‖ s</c> concatenation, whose two
    /// equal-width halves become <c>signatureR</c> and <c>signatureS</c>; for an RSA scheme the signature octets,
    /// which become <c>sig</c> whole.
    /// </param>
    /// <param name="pool">The memory pool for the member's buffers.</param>
    /// <returns>The created signature union; the caller owns and disposes it.</returns>
    /// <exception cref="NotSupportedException"><paramref name="sigAlg"/> is not a supported signing algorithm.</exception>
    /// <exception cref="ArgumentException">An ECDSA <paramref name="signature"/> has odd length, so it cannot be canonical P1363 <c>r ‖ s</c>.</exception>
    public static TpmuSignature Create(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ReadOnlySpan<byte> signature, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);

        return sigAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_ECDSA => CreateEcdsa(sigAlg, hashAlg, signature, pool),
            TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS => new TpmuSignature(sigAlg, hashAlg, Tpm2bPublicKeyRsa.Create(signature, pool)),
            _ => throw new NotSupportedException($"Signing algorithm '{sigAlg}' is not supported.")
        };

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
    /// Gets the serialized size of the selected member: its <c>hash</c> field followed by the member's buffers.
    /// </summary>
    /// <returns>The number of octets <see cref="WriteTo"/> produces.</returns>
    public int GetSerializedSize()
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        int memberSize = Type == TpmAlgIdConstants.TPM_ALG_ECDSA
            ? SignatureR!.SerializedSize + SignatureS!.SerializedSize
            : RsaSignature.SerializedSize;

        return sizeof(ushort) + memberSize;
    }

    /// <summary>
    /// Writes the selected member to a TPM writer: the <c>hash</c> field, then <c>signatureR</c> and
    /// <c>signatureS</c> for ECDSA or <c>sig</c> for an RSA scheme. The selector itself belongs to the enclosing
    /// <see cref="TpmtSignature"/>.
    /// </summary>
    /// <param name="writer">The writer.</param>
    public void WriteTo(ref TpmWriter writer)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        writer.WriteUInt16((ushort)HashAlgorithm);

        if(Type == TpmAlgIdConstants.TPM_ALG_ECDSA)
        {
            SignatureR!.WriteTo(ref writer);
            SignatureS!.WriteTo(ref writer);

            return;
        }

        RsaSignature.WriteTo(ref writer);
    }

    /// <summary>
    /// Parses a signature union from a TPM reader using the supplied algorithm selector.
    /// </summary>
    /// <param name="sigAlg">The signing algorithm selector from the enclosing TPMT_SIGNATURE.</param>
    /// <param name="reader">The reader positioned at the start of the signature member (its hash field).</param>
    /// <param name="pool">The memory pool for parameter buffer allocation.</param>
    /// <returns>The parsed signature union.</returns>
    /// <exception cref="NotSupportedException">Thrown when <paramref name="sigAlg"/> is not a supported signing algorithm.</exception>
    public static TpmuSignature Parse(TpmAlgIdConstants sigAlg, ref TpmReader reader, BaseMemoryPool pool)
    {
        ArgumentNullException.ThrowIfNull(pool);
        var hashAlg = (TpmAlgIdConstants)reader.ReadUInt16();

        return sigAlg switch
        {
            TpmAlgIdConstants.TPM_ALG_ECDSA => ParseEcdsa(sigAlg, hashAlg, ref reader, pool),
            TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS => ParseRsa(sigAlg, hashAlg, ref reader, pool),
            _ => throw new NotSupportedException($"Signing algorithm '{sigAlg}' is not supported for parsing.")
        };

        static TpmuSignature ParseEcdsa(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ref TpmReader reader, BaseMemoryPool pool)
        {
            Tpm2bEccParameter r = Tpm2bEccParameter.Parse(ref reader, pool);
            Tpm2bEccParameter s = Tpm2bEccParameter.Parse(ref reader, pool);

            return new TpmuSignature(sigAlg, hashAlg, r, s);
        }

        static TpmuSignature ParseRsa(TpmAlgIdConstants sigAlg, TpmAlgIdConstants hashAlg, ref TpmReader reader, BaseMemoryPool pool)
        {
            Tpm2bPublicKeyRsa rsa = Tpm2bPublicKeyRsa.Parse(ref reader, pool);

            return new TpmuSignature(sigAlg, hashAlg, rsa);
        }
    }

    /// <summary>
    /// Releases the memory owned by this structure.
    /// </summary>
    public void Dispose()
    {
        if(!disposed)
        {
            SignatureR?.Dispose();
            SignatureS?.Dispose();
            RsaSignature.Dispose();
            disposed = true;
        }
    }

    private string DebuggerDisplay => Type switch
    {
        TpmAlgIdConstants.TPM_ALG_ECDSA => $"TPMU_SIGNATURE(ECDSA, {HashAlgorithm}, R={SignatureR?.Length ?? 0} bytes, S={SignatureS?.Length ?? 0} bytes)",
        TpmAlgIdConstants.TPM_ALG_RSASSA or TpmAlgIdConstants.TPM_ALG_RSAPSS => $"TPMU_SIGNATURE({Type}, {HashAlgorithm}, {RsaSignature.Size} bytes)",
        _ => $"TPMU_SIGNATURE({Type})"
    };
}
