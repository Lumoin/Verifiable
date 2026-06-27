using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Tpm.Infrastructure.Spec.Constants;
using Verifiable.Tpm.Infrastructure.Spec.Structures;

namespace Verifiable.Tpm;

/// <summary>
/// Projects TPM-specific cryptographic outputs into the neutral <c>Verifiable.Cryptography</c> carriers
/// (<see cref="Signature"/>, <see cref="PublicKeyMemory"/>).
/// </summary>
/// <remarks>
/// <para>
/// A TPM signature (from <c>TPM2_Sign</c>) or attestation signature (from <c>TPM2_Quote</c>/<c>TPM2_Certify</c>)
/// and the signer's public key arrive in TPM-specific shapes (<see cref="TpmuSignature"/>,
/// <see cref="TpmsEccPoint"/>). Projecting them here lets a TPM attestation be verified through the same seam the
/// rest of the library uses for X.509, DID, and mdoc signatures — the verification delegate resolved from
/// <c>CryptoFunctionRegistry</c> — with no TPM types leaking past this boundary. This is the foundation on which
/// a higher layer can treat a quote or certify as an attestation log entry whose proof is the neutral
/// <see cref="Signature"/> and whose signer is the neutral <see cref="PublicKeyMemory"/>.
/// </para>
/// </remarks>
public static class TpmCryptographicProjections
{
    /// <summary>
    /// Projects a TPM signature union into a neutral <see cref="Signature"/>: ECDSA as IEEE P1363
    /// (<c>r || s</c>, each component left-padded to <paramref name="ecdsaComponentSize"/>); RSASSA/RSAPSS as the
    /// raw signature octets.
    /// </summary>
    /// <param name="signature">The TPM signature union to project.</param>
    /// <param name="ecdsaComponentSize">The fixed width in bytes of each ECDSA <c>r</c>/<c>s</c> component (the curve order size); ignored for RSA.</param>
    /// <param name="tag">The tag to stamp on the produced <see cref="Signature"/> (for example <see cref="CryptoTags.P256Signature"/>).</param>
    /// <param name="pool">The memory pool backing the returned signature.</param>
    /// <returns>The neutral signature; the caller owns it and must dispose it.</returns>
    /// <exception cref="NotSupportedException">The signature algorithm is not one this projection supports.</exception>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned Signature transfers to the caller.")]
    public static Signature ToSignature(this TpmuSignature signature, int ecdsaComponentSize, Tag tag, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        switch(signature.Type)
        {
            case(TpmAlgIdConstants.TPM_ALG_ECDSA):
            {
                //IEEE P1363: r and s each left-padded to the curve order size, concatenated.
                IMemoryOwner<byte> owner = pool.Rent(2 * ecdsaComponentSize);
                Span<byte> destination = owner.Memory.Span;
                LeftPadInto(signature.SignatureR!.AsReadOnlySpan(), destination[..ecdsaComponentSize]);
                LeftPadInto(signature.SignatureS!.AsReadOnlySpan(), destination.Slice(ecdsaComponentSize, ecdsaComponentSize));

                return new Signature(owner, tag);
            }
            case(TpmAlgIdConstants.TPM_ALG_RSASSA):
            case(TpmAlgIdConstants.TPM_ALG_RSAPSS):
            {
                //RSA: the signature is the raw octet string from TPM2B_PUBLIC_KEY_RSA.
                ReadOnlySpan<byte> rsa = signature.RsaSignature.Buffer;
                IMemoryOwner<byte> owner = pool.Rent(rsa.Length);
                rsa.CopyTo(owner.Memory.Span);

                return new Signature(owner, tag);
            }
            default:
            {
                throw new NotSupportedException($"Signature algorithm '{signature.Type}' cannot be projected to a Signature.");
            }
        }
    }

    /// <summary>
    /// Projects a TPM ECC public point into a <see cref="PublicKeyMemory"/> carrying the compressed SEC1
    /// encoding the library's elliptic-curve verifiers expect.
    /// </summary>
    /// <param name="point">The TPM-exported public point (for example an attestation key's <c>OutPublic</c> unique point).</param>
    /// <param name="componentSize">The curve coordinate size in bytes (32 for NIST P-256).</param>
    /// <param name="tag">The tag to stamp on the produced key (for example <see cref="CryptoTags.P256PublicKey"/>).</param>
    /// <param name="pool">The memory pool backing the returned key.</param>
    /// <returns>The neutral public key; the caller owns it and must dispose it.</returns>
    [SuppressMessage("Microsoft.Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the returned PublicKeyMemory transfers to the caller.")]
    public static PublicKeyMemory ToCompressedPublicKeyMemory(this TpmsEccPoint point, int componentSize, Tag tag, MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(point);
        ArgumentNullException.ThrowIfNull(tag);
        ArgumentNullException.ThrowIfNull(pool);

        //The TPM returns TPM2B coordinates that may omit leading zero bytes; the compressed encoding needs them
        //fixed-width. Coordinates are public key material, so the stack staging buffers carry no secret.
        Span<byte> x = stackalloc byte[componentSize];
        Span<byte> y = stackalloc byte[componentSize];
        LeftPadInto(point.X.AsReadOnlySpan(), x);
        LeftPadInto(point.Y.AsReadOnlySpan(), y);

        byte[] compressed = EllipticCurveUtilities.Compress(x, y);
        IMemoryOwner<byte> owner = pool.Rent(compressed.Length);
        compressed.CopyTo(owner.Memory.Span);

        return new PublicKeyMemory(owner, tag);
    }

    /// <summary>
    /// Left-pads a big-endian value into a fixed-width destination, zero-filling the leading bytes.
    /// </summary>
    /// <param name="value">The big-endian value (the TPM may omit leading zero bytes).</param>
    /// <param name="destination">The fixed-width destination span.</param>
    private static void LeftPadInto(ReadOnlySpan<byte> value, Span<byte> destination)
    {
        destination.Clear();
        if(value.Length <= destination.Length)
        {
            value.CopyTo(destination[(destination.Length - value.Length)..]);
        }
        else
        {
            value[^destination.Length..].CopyTo(destination);
        }
    }
}
