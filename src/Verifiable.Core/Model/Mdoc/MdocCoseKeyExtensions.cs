using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;

namespace Verifiable.Core.Model.Mdoc;

/// <summary>
/// Conversions from the parsed <see cref="MdocCoseKey"/> view to the typed,
/// tagged <see cref="PublicKeyMemory"/> the cryptographic verify functions
/// consume.
/// </summary>
/// <remarks>
/// <para>
/// A verifier that trusts an mdoc MSO (its issuer signature verified) can trust
/// the device key the MSO binds to — <c>mso.DeviceKeyInfo.DeviceKey</c> — as the
/// public half that authenticates the wallet's <c>DeviceAuth</c>. This converter
/// turns that COSE_Key into the <see cref="PublicKeyMemory"/> the device-signed
/// verifier takes, so the verification key is derived from the issuer commitment
/// rather than supplied out of band.
/// </para>
/// <para>
/// The conversion mirrors the JWK path in
/// <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/>: EC2 keys
/// are normalised to the canonical compressed SEC1 point, and the algorithm tag
/// is resolved through <see cref="CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter"/>.
/// It carries no serialization or VP-protocol dependency — it is the inverse of
/// the COSE_Key reader and is reusable wherever a parsed COSE_Key must become a
/// verification key.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "C# 14 lowers extension(X) blocks into synthetic nested classes whose names differ only by case; the source-level extension host is clearly distinct.")]
public static class MdocCoseKeyExtensions
{
    extension(MdocCoseKey coseKey)
    {
        /// <summary>
        /// Converts this COSE_Key into a verification-purpose
        /// <see cref="PublicKeyMemory"/> — the public half a verifier checks a
        /// device signature against.
        /// </summary>
        /// <param name="pool">Memory pool the returned key's carrier rents from. Caller owns and disposes the result.</param>
        /// <returns>The tagged public key in the codebase's canonical internal form (compressed SEC1 for EC2; raw bytes for OKP).</returns>
        /// <exception cref="InvalidOperationException">Thrown when the COSE_Key omits coordinates required to reconstruct the public point.</exception>
        /// <exception cref="NotSupportedException">Thrown when the key type / curve is not one the algorithm converter recognises.</exception>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented carrier transfers to the returned PublicKeyMemory; the caller disposes it.")]
        public PublicKeyMemory ToPublicKeyMemory(MemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(coseKey);
            ArgumentNullException.ThrowIfNull(pool);

            //The device key authenticates the wallet's DeviceAuth, so it resolves to a
            //verification-purpose tag (e.g. CryptoTags.P256PublicKey for EC2/P-256).
            Tag tag = CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(
                coseKey.Kty, coseKey.Curve, Purpose.Verification);

            byte[] keyMaterial = BuildKeyMaterial(coseKey);

            IMemoryOwner<byte> owner = pool.Rent(keyMaterial.Length);
            keyMaterial.CopyTo(owner.Memory.Span);

            return new PublicKeyMemory(owner, tag);
        }
    }


    private static byte[] BuildKeyMaterial(MdocCoseKey coseKey)
    {
        //EC2 (kty=2): normalise to the compressed SEC1 point — the canonical internal
        //form the JWK reconstruction path also produces (DecodeEcKey -> Compress).
        if(coseKey.Kty == MdocCoseKeyTypes.Ec2)
        {
            if(coseKey.X is not ReadOnlyMemory<byte> x)
            {
                throw new InvalidOperationException(
                    "EC2 COSE_Key is missing the mandatory x coordinate per RFC 9052 §7.1.");
            }

            //Uncompressed form: both coordinates present — compress them.
            if(coseKey.Y is ReadOnlyMemory<byte> y)
            {
                return EllipticCurveUtilities.Compress(x.Span, y.Span);
            }

            //Compressed form: x plus the y parity sign. The compressed SEC1 point is
            //[0x02|0x03] || x directly, so no Y recovery is needed.
            if(coseKey.EncodedYCompressionSign is bool ySign)
            {
                byte[] compressed = new byte[x.Length + 1];
                compressed[0] = ySign ? EllipticCurveUtilities.OddYCoordinate : EllipticCurveUtilities.EvenYCoordinate;
                x.Span.CopyTo(compressed.AsSpan(1));

                return compressed;
            }

            throw new InvalidOperationException(
                "EC2 COSE_Key carries neither an uncompressed y coordinate nor a y sign bit per RFC 9052 §7.1.");
        }

        //OKP (kty=1): the public key is the raw x byte string (Ed25519 / X25519).
        if(coseKey.Kty == MdocCoseKeyTypes.Okp)
        {
            if(coseKey.X is not ReadOnlyMemory<byte> x)
            {
                throw new InvalidOperationException(
                    "OKP COSE_Key is missing the mandatory x public-key bytes per RFC 9052 §7.2.");
            }

            return x.Span.ToArray();
        }

        throw new NotSupportedException(
            $"COSE_Key kty={coseKey.Kty.ToString(System.Globalization.CultureInfo.InvariantCulture)} is not supported " +
            "for public-key conversion; only EC2 (2) and OKP (1) are.");
    }
}
