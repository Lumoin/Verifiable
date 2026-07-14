using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.Fido2;

/// <summary>
/// Converts a WebAuthn wire-format ECDSA <c>sig</c> value into the fixed-width IEEE P1363
/// encoding this library's registered EC verification seam expects. Shared by every WebAuthn L3
/// verifier that checks an ECDSA signature — <see cref="Fido2AssertionVerifier"/> and
/// <see cref="PackedAttestation"/> alike — so the DER-to-P1363 conversion has exactly one
/// implementation.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/webauthn-3/#sctn-signature-attestation-types">W3C Web
/// Authentication Level 3 section 6.5.5, Signature Formats for Packed Attestation, FIDO U2F
/// Attestation, and Assertion Signatures</see> requires an ECDSA <c>sig</c> value
/// (<c>COSEAlgorithmIdentifier</c> -7/-35/-36/-47, ES256/ES384/ES512/ES256K) to be encoded as an ASN.1 DER
/// <c>Ecdsa-Sig-Value</c> (<see href="https://datatracker.ietf.org/doc/html/rfc3279#section-2.2.3">RFC
/// 3279 section 2.2.3</see>), while the registered EC verification seam expects the fixed-width
/// IEEE P1363 <c>r ‖ s</c> encoding. <see cref="WrapWireSignatureForVerification"/> converts an EC
/// wire signature from DER to P1363, via <see cref="EcdsaSignatureEncoding.ConvertDerToP1363"/>,
/// before it reaches the registered verifier. RSA and EdDSA signatures carry no such conversion —
/// section 6.5.5 leaves them "not ASN.1 wrapped" — so they pass through unchanged.
/// </remarks>
internal static class Fido2EcdsaWireSignature
{
    /// <summary>
    /// Determines whether <paramref name="algorithm"/> is one of the ECDSA curves whose WebAuthn
    /// wire signature (section 6.5.5) requires ASN.1 DER encoding, and if so, its field
    /// width in bytes.
    /// </summary>
    /// <param name="algorithm">The verification key's algorithm tag.</param>
    /// <param name="fieldWidth">
    /// The curve's field width in bytes (32 for P-256 and secp256k1, 48 for P-384, 66 for P-521) when
    /// <paramref name="algorithm"/> is an ECDSA curve; otherwise zero.
    /// </param>
    /// <returns><see langword="true"/> when <paramref name="algorithm"/> is P-256, P-384, P-521, or secp256k1 (RFC 8812 §3, COSE alg ES256K).</returns>
    internal static bool TryGetEcFieldWidth(CryptoAlgorithm algorithm, out int fieldWidth)
    {
        (bool isEc, int width) = algorithm switch
        {
            var a when a.Equals(CryptoAlgorithm.P256) => (true, EllipticCurveConstants.P256.PointArrayLength),
            var a when a.Equals(CryptoAlgorithm.P384) => (true, EllipticCurveConstants.P384.PointArrayLength),
            var a when a.Equals(CryptoAlgorithm.P521) => (true, EllipticCurveConstants.P521.PointArrayLength),
            var a when a.Equals(CryptoAlgorithm.Secp256k1) => (true, EllipticCurveConstants.Secp256k1.PointArrayLength),
            _ => (false, 0)
        };

        fieldWidth = width;

        return isEc;
    }


    /// <summary>
    /// Wraps a WebAuthn wire-format signature into a pooled <see cref="Signature"/> carrier ready
    /// for the registered verification seam: an ECDSA <paramref name="algorithm"/> wire value is
    /// converted from ASN.1 DER to fixed-width IEEE P1363, via
    /// <see cref="EcdsaSignatureEncoding.ConvertDerToP1363"/>; every other algorithm is copied
    /// through unchanged.
    /// </summary>
    /// <param name="wireSignature">The raw signature bytes as they appear on the wire (<c>sig</c>).</param>
    /// <param name="algorithm">The verification key's algorithm tag.</param>
    /// <param name="pool">The memory pool the returned carrier's buffer rents from.</param>
    /// <returns>A pooled <see cref="Signature"/> carrier ready for verification. The caller owns and disposes it.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">A decoded DER coordinate exceeds the curve field width.</exception>
    /// <exception cref="System.Formats.Asn1.AsnContentException"><paramref name="wireSignature"/> is not a well-formed DER <c>Ecdsa-Sig-Value</c>.</exception>
    internal static Signature WrapWireSignatureForVerification(ReadOnlySpan<byte> wireSignature, CryptoAlgorithm algorithm, MemoryPool<byte> pool)
    {
        if(TryGetEcFieldWidth(algorithm, out int fieldWidth))
        {
            IMemoryOwner<byte> p1363Owner = EcdsaSignatureEncoding.ConvertDerToP1363(wireSignature, fieldWidth, pool, out _);

            return new Signature(p1363Owner, CryptoTags.AlgorithmAgnosticSignature);
        }

        return CopySignature(wireSignature, pool);
    }


    /// <summary>
    /// Copies a signature value into a pooled <see cref="Signature"/> carrier; the algorithm is
    /// determined by the verification key, so the carrier is tagged algorithm-agnostically.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented buffer transfers to the returned Signature; the catch disposes it on failure.")]
    private static Signature CopySignature(ReadOnlySpan<byte> value, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(value.Length);
        try
        {
            value.CopyTo(owner.Memory.Span);

            return new Signature(owner, CryptoTags.AlgorithmAgnosticSignature);
        }
        catch
        {
            owner.Dispose();
            throw;
        }
    }
}
