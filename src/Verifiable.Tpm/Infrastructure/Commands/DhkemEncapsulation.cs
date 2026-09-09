using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;
using Verifiable.Tpm.Automata;
using Verifiable.Tpm.Spec.Constants;
using Verifiable.Tpm.Spec.Structures;

namespace Verifiable.Tpm.Infrastructure.Commands;

/// <summary>
/// The host-side half of DHKEM(P-256, HKDF-SHA256) encapsulation (TPM 2.0 Library Part 1, clause 44.4.2;
/// <see href="https://www.rfc-editor.org/rfc/rfc9180">RFC 9180</see> Section 4.1 <c>Encap(pkR)</c>): the
/// same derivation <c>TPM2_Encapsulate()</c> performs, available to a caller that wants the shared
/// secret/ciphertext pair without round-tripping through a TPM — reproducing an RFC 9180 Appendix A.3.1
/// test vector, or a future non-TPM HPKE-consuming surface composing over the same primitive.
/// </summary>
/// <remarks>
/// Mirrors <see cref="StartAuthSessionInputExtensions"/>'s salted-session cores: the ephemeral key pair and
/// the Diffie-Hellman shared value both come from caller-supplied delegates rather than a baked-in
/// provider, so a test can inject RFC 9180's own vector ephemeral through <c>generateKey</c> and still run
/// the real derivation path end to end — no test seam in production. The KDF stage composes over
/// <see cref="Dhkem.ExtractAndExpandAsync"/> under <see cref="Dhkem.P256HkdfSha256"/>, the one suite this
/// library's ECC KEM path wires (TPM 2.0 Library Part 2, Table 229: "Currently, TPM_ALG_HKDF is the only
/// supported KDF for DHKEM").
/// </remarks>
public static class DhkemEncapsulation
{
    /// <summary>
    /// Performs DHKEM(P-256, HKDF-SHA256) encapsulation against a KEM key's public point (Part 1, clause
    /// 44.4.2 steps 1-6; RFC 9180 Section 4.1 <c>Encap(pkR)</c>): draws a fresh ephemeral key pair
    /// (<c>skE</c>, <c>pkE</c>), computes the Diffie-Hellman shared value <c>dh = skE · pkR</c>, and derives
    /// the shared secret through the DHKEM core over <c>kem_context = pkE_serialized || pkR_serialized</c>.
    /// </summary>
    /// <param name="recipientPublicPoint">The KEM key's public point <c>pkR</c>, SEC 1 uncompressed (<c>0x04 || X || Y</c>, 65 octets for P-256).</param>
    /// <param name="generateKey">Generates the one-time ephemeral key pair step 1 draws — the same delegate shape the simulator's own ECC backend supplies.</param>
    /// <param name="computeSharedSecret">Computes the Diffie-Hellman shared value <c>dh</c> (step 2) from the ephemeral private scalar and <paramref name="recipientPublicPoint"/>.</param>
    /// <param name="pool">The memory pool for the ephemeral key, the shared value, the <c>kem_context</c> scratch buffer, and the returned secret/ciphertext.</param>
    /// <param name="cancellationToken">A token observed across the ECDH exchange and the DHKEM core.</param>
    /// <returns>
    /// The DHKEM shared secret (<see cref="Dhkem.P256HkdfSha256"/>'s 32-octet <c>Nsecret</c>) and the
    /// ciphertext — the bare <c>pkE_serialized</c> point (step 3/step 6), not a marshaled
    /// <c>TPMS_ECC_POINT</c> — the same pair <c>TPM2_Encapsulate()</c> returns as
    /// <c>sharedSecret</c>/<c>ciphertext</c> (Part 3, Table 61). Both are pool-owned; the caller disposes them.
    /// </returns>
    /// <exception cref="ArgumentException"><paramref name="recipientPublicPoint"/> is not a 65-octet SEC 1 uncompressed P-256 point, or its coordinates are out of range or off the curve — RFC 9180, Section 7.1.4: "the sender MUST validate the recipient's public key pkR" with partial public-key validation.</exception>
    /// <exception cref="InvalidOperationException"><paramref name="generateKey"/> returned an ephemeral public point that is not a 65-octet SEC 1 uncompressed P-256 point.</exception>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the shared-secret and ciphertext carriers transfers to the caller through the returned tuple; a failing ciphertext rental releases the already-adopted shared secret in the catch below before rethrowing.")]
    public static async ValueTask<(Tpm2bSharedSecret SharedSecret, Tpm2bKemCiphertext Ciphertext)> EncapsulateAsync(
        ReadOnlyMemory<byte> recipientPublicPoint,
        TpmEccKeyGenerationDelegate generateKey,
        TpmEccSharedSecretDelegate computeSharedSecret,
        BaseMemoryPool pool,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(generateKey);
        ArgumentNullException.ThrowIfNull(computeSharedSecret);
        ArgumentNullException.ThrowIfNull(pool);

        if(recipientPublicPoint.Length != EllipticCurveConstants.P256.UncompressedPointByteCount || recipientPublicPoint.Span[0] != 0x04)
        {
            throw new ArgumentException(
                $"The recipient public point must be a {EllipticCurveConstants.P256.UncompressedPointByteCount}-octet SEC 1 uncompressed P-256 point (0x04 || X || Y).",
                nameof(recipientPublicPoint));
        }

        int fieldWidth = EllipticCurveConstants.P256.PointArrayLength;

        //RFC 9180, Section 7.1.4: "the sender MUST validate the recipient's public key pkR" — for the NIST
        //curves, partial public-key validation (coordinates in range, on the curve, not the point at infinity),
        //which CheckPointOnCurve performs on the affine coordinates before any scalar multiplication.
        if(!EllipticCurveUtilities.CheckPointOnCurve(recipientPublicPoint.Span.Slice(1, fieldWidth), recipientPublicPoint.Span.Slice(1 + fieldWidth, fieldWidth), EllipticCurveTypes.P256))
        {
            throw new ArgumentException("The recipient public point is not a valid point on P-256 (RFC 9180, Section 7.1.4 partial public-key validation).", nameof(recipientPublicPoint));
        }

        using TpmGeneratedEccKey ephemeral = await generateKey(TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, cancellationToken).ConfigureAwait(false);

        //pkE_serialized rides the ephemeral key's own SensitiveMemory carrier; the private scalar rides its
        //own carrier straight into computeSharedSecret — no .ToArray() copy of either. The point becomes the
        //wire ciphertext (step 6), so a delegate handing back anything but a SEC 1 uncompressed P-256 point is a
        //contract violation caught here rather than framed for a peer that could never decapsulate it.
        ReadOnlyMemory<byte> pkE = ephemeral.PublicPoint.AsReadOnlyMemory();
        if(pkE.Length != EllipticCurveConstants.P256.UncompressedPointByteCount || pkE.Span[0] != 0x04)
        {
            throw new InvalidOperationException($"The ephemeral key generator must return a {EllipticCurveConstants.P256.UncompressedPointByteCount}-octet SEC 1 uncompressed P-256 point.");
        }

        using IMemoryOwner<byte> dh = await computeSharedSecret(
            ephemeral.PrivateScalar.AsReadOnlyMemory(), recipientPublicPoint, TpmEccCurveConstants.TPM_ECC_NIST_P256, pool, cancellationToken).ConfigureAwait(false);

        //kem_context = pkE_serialized || pkR_serialized (Part 1, clause 44.4.2 step 4; RFC 9180 Section 4.1).
        //Not secret (both parties independently reconstruct it), but still zeroed before its rental returns
        //to the pool, matching Dhkem's own treatment of its public label/context buffers.
        int kemContextLength = pkE.Length + recipientPublicPoint.Length;
        IMemoryOwner<byte> kemContextOwner = pool.Rent(kemContextLength);
        Memory<byte> kemContext = kemContextOwner.Memory[..kemContextLength];
        Tpm2bSharedSecret sharedSecret;
        try
        {
            pkE.CopyTo(kemContext);
            recipientPublicPoint.CopyTo(kemContext[pkE.Length..]);

            IMemoryOwner<byte> sharedSecretOwner = await Dhkem.ExtractAndExpandAsync(
                Dhkem.P256HkdfSha256.HashAlgorithm, dh.Memory[..fieldWidth], kemContext, Dhkem.P256HkdfSha256.KemId, Dhkem.P256HkdfSha256.NSecret, pool, cancellationToken).ConfigureAwait(false);
            sharedSecret = new Tpm2bSharedSecret(sharedSecretOwner);
        }
        finally
        {
            kemContext.Span.Clear();
            kemContextOwner.Dispose();
        }

        //The shared-secret carrier is already adopted; a refusing ciphertext rental must not orphan it, so it
        //is released in the catch before the exception continues outward — one risky call per statement.
        try
        {
            return (sharedSecret, Tpm2bKemCiphertext.Create(pkE.Span, pool));
        }
        catch
        {
            sharedSecret.Dispose();
            throw;
        }
    }
}
