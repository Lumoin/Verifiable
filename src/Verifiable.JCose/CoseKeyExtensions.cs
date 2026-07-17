using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Formats.Asn1;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// Conversions from the parsed <see cref="CoseKey"/> view to the typed,
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
/// RSA keys (<c>kty = 3</c>) are handled separately: that converter rejects
/// <c>kty = 3</c> by design (RFC 9052 §7 gives RSA no curve to dispatch on), so
/// <see cref="ResolveRsaTag"/> resolves the tag from the COSE_Key's <c>alg</c>
/// parameter when present (the padding/hash family the credential itself
/// declares), falling back to modulus length only when <c>alg</c> is absent —
/// mirroring the JWK RSA path in <see cref="CryptoFormatConversions.DefaultJwkToAlgorithmConverter"/>.
/// It carries no serialization or VP-protocol dependency — it is the inverse of
/// the COSE_Key reader and is reusable wherever a parsed COSE_Key must become a
/// verification key.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "Analyzer is not yet up to date with new extension syntax.")]
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "C# 14 lowers extension(X) blocks into synthetic nested classes whose names differ only by case; the source-level extension host is clearly distinct.")]
public static class CoseKeyExtensions
{
    extension(CoseKey coseKey)
    {
        /// <summary>
        /// Converts this COSE_Key into a verification-purpose
        /// <see cref="PublicKeyMemory"/> — the public half a verifier checks a
        /// device signature against.
        /// </summary>
        /// <param name="pool">Memory pool the returned key's carrier rents from. Caller owns and disposes the result.</param>
        /// <returns>The tagged public key in the codebase's canonical internal form (compressed SEC1 for EC2; raw bytes for OKP; DER PKCS#1 RSAPublicKey for RSA).</returns>
        /// <exception cref="ArgumentException">Thrown when an RSA COSE_Key omits its mandatory <c>n</c>/<c>e</c> parameters, or carries a modulus length no registered tag covers.</exception>
        /// <exception cref="InvalidOperationException">Thrown when the COSE_Key omits coordinates required to reconstruct the public point.</exception>
        /// <exception cref="NotSupportedException">Thrown when the key type / curve is not one the algorithm converter recognises.</exception>
        [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership of the rented carrier transfers to the returned PublicKeyMemory; the caller disposes it.")]
        public PublicKeyMemory ToPublicKeyMemory(MemoryPool<byte> pool)
        {
            ArgumentNullException.ThrowIfNull(coseKey);
            ArgumentNullException.ThrowIfNull(pool);

            //The device key authenticates the wallet's DeviceAuth, so it resolves to a
            //verification-purpose tag (e.g. CryptoTags.P256PublicKey for EC2/P-256).
            Tag tag = coseKey.Kty == CoseKeyTypes.Rsa
                ? ResolveRsaTag(coseKey)
                : CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter(coseKey.Kty, coseKey.Curve, Purpose.Verification);

            byte[] keyMaterial = BuildKeyMaterial(coseKey);

            IMemoryOwner<byte> owner = pool.Rent(keyMaterial.Length);
            keyMaterial.CopyTo(owner.Memory.Span);

            return new PublicKeyMemory(owner, tag);
        }
    }


    /// <summary>
    /// Resolves the verification-purpose <see cref="Tag"/> for an RSA COSE_Key. When the COSE_Key
    /// carries an <c>alg</c> parameter naming an RSA padding/hash family (RFC 8812 §2 PKCS#1 v1.5;
    /// RFC 8230 §2 PSS), the tag is built from that algorithm — the credential's declared <c>alg</c>
    /// is authoritative (WebAuthn L3 relying parties allowlist <c>pubKeyCredParams</c> and the
    /// credential key carries <c>alg</c>), so a PS256/384/512 or RS384/512 key resolves to its own
    /// padding/hash rather than being silently verified as PKCS#1 v1.5 SHA-256/512. When <c>alg</c>
    /// is absent, the tag falls back to modulus-length resolution, since
    /// <see cref="CryptoFormatConversions.DefaultCoseKeyToAlgorithmConverter"/> has no curve to
    /// dispatch RSA on and rejects <c>kty = 3</c> by design.
    /// </summary>
    /// <param name="coseKey">The RSA COSE_Key to resolve a tag for.</param>
    /// <returns>
    /// The alg-resolved RSA public-key tag when <c>alg</c> names an RSA family; otherwise the
    /// registered public-key tag matching the modulus length.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when the mandatory <c>n</c> (modulus) parameter is missing, or (with no usable <c>alg</c>) its length matches no registered RSA key size.</exception>
    private static Tag ResolveRsaTag(CoseKey coseKey)
    {
        int modulusLength = coseKey.N?.Length
            ?? throw new ArgumentException(
                "RSA COSE_Key is missing the mandatory n (modulus) parameter per RFC 8230 §4.", nameof(coseKey));

        if(coseKey.Alg is int alg && ResolveRsaFamilyTag(CryptoFormatConversions.CoseAlgorithmToCryptoAlgorithm(alg)) is Tag algorithmTag)
        {
            return algorithmTag;
        }

        return modulusLength switch
        {
            256 => CryptoTags.Rsa2048PublicKey,
            512 => CryptoTags.Rsa4096PublicKey,
            _ => throw new ArgumentException($"Unsupported RSA modulus length: '{modulusLength}' bytes.", nameof(coseKey))
        };


        static Tag? ResolveRsaFamilyTag(CryptoAlgorithm? algorithm) => algorithm switch
        {
            null => null,
            CryptoAlgorithm a when a.Equals(CryptoAlgorithm.RsaSha256) => CryptoTags.RsaSha256PublicKey,
            CryptoAlgorithm a when a.Equals(CryptoAlgorithm.RsaSha256Pss) => CryptoTags.RsaSha256PssPublicKey,
            CryptoAlgorithm a when a.Equals(CryptoAlgorithm.RsaSha384) => CryptoTags.RsaSha384PublicKey,
            CryptoAlgorithm a when a.Equals(CryptoAlgorithm.RsaSha384Pss) => CryptoTags.RsaSha384PssPublicKey,
            CryptoAlgorithm a when a.Equals(CryptoAlgorithm.RsaSha512) => CryptoTags.RsaSha512PublicKey,
            CryptoAlgorithm a when a.Equals(CryptoAlgorithm.RsaSha512Pss) => CryptoTags.RsaSha512PssPublicKey,
            //Non-RSA CryptoAlgorithm values (e.g. an EC alg misencoded onto an RSA kty) fall through
            //to the caller's modulus-length fallback rather than being silently mismapped here.
            _ => null
        };
    }


    /// <summary>
    /// Builds the canonical internal key-material bytes for the COSE_Key: compressed
    /// SEC1 point for EC2 (RFC 9052 §7.1), raw public-key bytes for OKP (RFC 9052 §7.2),
    /// DER PKCS#1 <c>RSAPublicKey</c> for RSA (RFC 8230 §4).
    /// </summary>
    /// <param name="coseKey">The parsed COSE_Key to convert.</param>
    /// <returns>The key material in the form the tagged verify functions consume.</returns>
    private static byte[] BuildKeyMaterial(CoseKey coseKey)
    {
        //EC2 (kty=2): normalise to the compressed SEC1 point — the canonical internal
        //form the JWK reconstruction path also produces (DecodeEcKey -> Compress).
        if(coseKey.Kty == CoseKeyTypes.Ec2)
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
        if(coseKey.Kty == CoseKeyTypes.Okp)
        {
            if(coseKey.X is not ReadOnlyMemory<byte> x)
            {
                throw new InvalidOperationException(
                    "OKP COSE_Key is missing the mandatory x public-key bytes per RFC 9052 §7.2.");
            }

            return x.Span.ToArray();
        }

        //RSA (kty=3): the public key is a DER PKCS#1 RSAPublicKey — SEQUENCE { modulus
        //INTEGER, publicExponent INTEGER } — built from the n/e labels per RFC 8230 §4.
        //DER (not the raw modulus) is required because the framework's raw-import
        //fallback hardcodes the exponent to 65537, silently ignoring a COSE_Key that
        //carries a different one.
        if(coseKey.Kty == CoseKeyTypes.Rsa)
        {
            if(coseKey.N is not ReadOnlyMemory<byte> n || n.Length == 0)
            {
                throw new ArgumentException(
                    "RSA COSE_Key is missing the mandatory n (modulus) parameter per RFC 8230 §4.", nameof(coseKey));
            }

            if(coseKey.E is not ReadOnlyMemory<byte> e || e.Length == 0)
            {
                throw new ArgumentException(
                    "RSA COSE_Key is missing the mandatory e (exponent) parameter per RFC 8230 §4.", nameof(coseKey));
            }

            AsnWriter writer = new(AsnEncodingRules.DER);
            using(writer.PushSequence())
            {
                writer.WriteIntegerUnsigned(n.Span);
                writer.WriteIntegerUnsigned(e.Span);
            }

            return writer.Encode();
        }

        throw new NotSupportedException(
            $"COSE_Key kty={coseKey.Kty.ToString(System.Globalization.CultureInfo.InvariantCulture)} is not supported " +
            "for public-key conversion; only EC2 (2), OKP (1) and RSA (3) are.");
    }
}
