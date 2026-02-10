using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.Jose;


namespace Verifiable.JCose
{
    /// <summary>
    /// Delegate for converting algorithm and key material to JWK format.
    /// </summary>
    public delegate Dictionary<string, object> AlgorithmToJwkDelegate(CryptoAlgorithm algorithm, Purpose purpose, ReadOnlySpan<byte> keyMaterial, EncodeDelegate base64UrlEncoder);

    /// <summary>
    /// Delegate for converting algorithm and key material to Base58 format.
    /// </summary>
    public delegate string AlgorithmToBase58Delegate(CryptoAlgorithm algorithm, Purpose purpose, ReadOnlySpan<byte> keyMaterial, EncodeDelegate base58Encoder);

    /// <summary>
    /// Delegate for converting JWK to algorithm representation.
    /// </summary>
    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte>) JwkToAlgorithmDelegate(Dictionary<string, object> jwk, MemoryPool<byte> memoryPool, DecodeDelegate base64UrlDecoder);

    /// <summary>
    /// Delegate for converting Base58 key to algorithm representation.
    /// </summary>
    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> keyMaterial) Base58ToAlgorithmDelegate(string base58Key, MemoryPool<byte> memoryPool, DecodeDelegate base58Decoder);

    /// <summary>
    /// Delegate for converting a JWA algorithm identifier to a <see cref="Tag"/>.
    /// </summary>
    /// <param name="jwaAlgorithm">The JWA algorithm identifier (e.g., "ES256", "RS256").</param>
    /// <param name="purpose">The intended purpose (signing or verification).</param>
    /// <returns>The corresponding <see cref="Tag"/>.</returns>
    public delegate Tag JwaToTagDelegate(string jwaAlgorithm, Purpose purpose);

    /// <summary>
    /// Delegate for converting a <see cref="Tag"/> to a JWA algorithm identifier.
    /// </summary>
    /// <param name="tag">The tag containing algorithm information.</param>
    /// <returns>The JWA algorithm identifier.</returns>
    public delegate string TagToJwaDelegate(Tag tag);

    /// <summary>
    /// Delegate for converting a <see cref="Tag"/> to a COSE algorithm identifier.
    /// </summary>
    /// <param name="tag">The tag containing algorithm information.</param>
    /// <returns>The COSE algorithm identifier (a negative integer per IANA COSE Algorithms).</returns>
    public delegate int TagToCoseDelegate(Tag tag);

    /// <summary>
    /// Delegate for converting a COSE algorithm identifier to a <see cref="Tag"/>.
    /// </summary>
    /// <param name="coseAlgorithm">The COSE algorithm identifier.</param>
    /// <param name="purpose">The intended purpose (signing or verification).</param>
    /// <returns>The corresponding <see cref="Tag"/>.</returns>
    public delegate Tag CoseToTagDelegate(int coseAlgorithm, Purpose purpose);


    /// <summary>
    /// This class defines default conversions from <em>Verifiable</em> internal representation to others
    /// and from <em>Verifiable</em> representation to other formats.
    /// </summary>
    public static class CryptoFormatConversions
    {
        /// <summary>
        /// Default converter from JWA algorithm identifier to <see cref="Tag"/>.
        /// </summary>
        public static JwaToTagDelegate DefaultJwaToTagConverter => (jwaAlgorithm, purpose) =>
        {
            if(string.IsNullOrEmpty(jwaAlgorithm))
            {
                throw new ArgumentException("JWA algorithm cannot be null or empty.", nameof(jwaAlgorithm));
            }

            return (jwaAlgorithm, purpose) switch
            {
                //ECDSA signing.
                (string alg, Purpose p) when WellKnownJwaValues.IsEs256(alg) && p.Equals(Purpose.Signing) => CryptoTags.P256PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEs384(alg) && p.Equals(Purpose.Signing) => CryptoTags.P384PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEs512(alg) && p.Equals(Purpose.Signing) => CryptoTags.P521PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEs256k1(alg) && p.Equals(Purpose.Signing) => CryptoTags.Secp256k1PrivateKey,

                //ECDSA verification.
                (string alg, Purpose p) when WellKnownJwaValues.IsEs256(alg) && p.Equals(Purpose.Verification) => CryptoTags.P256PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEs384(alg) && p.Equals(Purpose.Verification) => CryptoTags.P384PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEs512(alg) && p.Equals(Purpose.Verification) => CryptoTags.P521PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEs256k1(alg) && p.Equals(Purpose.Verification) => CryptoTags.Secp256k1PublicKey,

                //EdDSA signing and verification.
                (string alg, Purpose p) when WellKnownJwaValues.IsEdDsa(alg) && p.Equals(Purpose.Signing) => CryptoTags.Ed25519PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEdDsa(alg) && p.Equals(Purpose.Verification) => CryptoTags.Ed25519PublicKey,

                //RSA PKCS#1 signing.
                (string alg, Purpose p) when WellKnownJwaValues.IsRs256(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsRs384(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsRs512(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,

                //RSA PKCS#1 verification.
                (string alg, Purpose p) when WellKnownJwaValues.IsRs256(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsRs384(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsRs512(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,

                //RSA PSS signing.
                (string alg, Purpose p) when WellKnownJwaValues.IsPs256(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsPs384(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsPs512(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,

                //RSA PSS verification.
                (string alg, Purpose p) when WellKnownJwaValues.IsPs256(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsPs384(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsPs512(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,

                //ML-DSA signing.
                (string alg, Purpose p) when WellKnownJwaValues.IsMlDsa44(alg) && p.Equals(Purpose.Signing) => CryptoTags.MlDsa44PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsMlDsa65(alg) && p.Equals(Purpose.Signing) => CryptoTags.MlDsa65PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsMlDsa87(alg) && p.Equals(Purpose.Signing) => CryptoTags.MlDsa87PrivateKey,

                //ML-DSA verification.
                (string alg, Purpose p) when WellKnownJwaValues.IsMlDsa44(alg) && p.Equals(Purpose.Verification) => CryptoTags.MlDsa44PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsMlDsa65(alg) && p.Equals(Purpose.Verification) => CryptoTags.MlDsa65PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsMlDsa87(alg) && p.Equals(Purpose.Verification) => CryptoTags.MlDsa87PublicKey,

                _ => throw new NotSupportedException($"JWA algorithm '{jwaAlgorithm}' with purpose '{purpose}' is not supported.")
            };
        };


        /// <summary>
        /// Default converter from <see cref="Tag"/> to JWA algorithm identifier.
        /// </summary>
        /// <remarks>
        /// For RSA algorithms, this returns the SHA-256 variant (RS256) by default.
        /// Use <see cref="GetJwaAlgorithm(Tag, string?, bool)"/> for explicit hash algorithm selection.
        /// </remarks>
        public static TagToJwaDelegate DefaultTagToJwaConverter => tag =>
        {
            ArgumentNullException.ThrowIfNull(tag);

            CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();
            return algorithm switch
            {
                var a when a.Equals(CryptoAlgorithm.P256) => WellKnownJwaValues.Es256,
                var a when a.Equals(CryptoAlgorithm.P384) => WellKnownJwaValues.Es384,
                var a when a.Equals(CryptoAlgorithm.P521) => WellKnownJwaValues.Es512,
                var a when a.Equals(CryptoAlgorithm.Secp256k1) => WellKnownJwaValues.Es256k1,
                var a when a.Equals(CryptoAlgorithm.Ed25519) => WellKnownJwaValues.EdDsa,
                var a when a.Equals(CryptoAlgorithm.Rsa2048) || a.Equals(CryptoAlgorithm.Rsa4096) => WellKnownJwaValues.Rs256,
                var a when a.Equals(CryptoAlgorithm.MlDsa44) => WellKnownJwaValues.MlDsa44,
                var a when a.Equals(CryptoAlgorithm.MlDsa65) => WellKnownJwaValues.MlDsa65,
                var a when a.Equals(CryptoAlgorithm.MlDsa87) => WellKnownJwaValues.MlDsa87,
                _ => throw new NotSupportedException($"CryptoAlgorithm '{algorithm}' does not have a JWA mapping.")
            };
        };


        /// <summary>
        /// Gets the JWA algorithm identifier from a <see cref="Tag"/> with explicit hash algorithm selection for RSA.
        /// </summary>
        /// <param name="tag">The tag containing algorithm information.</param>
        /// <param name="hashAlgorithm">The hash algorithm name for RSA signatures (e.g., "SHA256", "SHA384", "SHA512").</param>
        /// <param name="usePss">Whether to use RSA-PSS padding instead of PKCS#1 v1.5.</param>
        /// <returns>The JWA algorithm identifier.</returns>
        /// <exception cref="NotSupportedException">Thrown when the tag does not map to a JWA algorithm.</exception>
        public static string GetJwaAlgorithm(Tag tag, string? hashAlgorithm = null, bool usePss = false)
        {
            ArgumentNullException.ThrowIfNull(tag);

            CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();
            if(algorithm.Equals(CryptoAlgorithm.P256))
            {
                return WellKnownJwaValues.Es256;
            }

            if(algorithm.Equals(CryptoAlgorithm.P384))
            {
                return WellKnownJwaValues.Es384;
            }

            if(algorithm.Equals(CryptoAlgorithm.P521))
            {
                return WellKnownJwaValues.Es512;
            }

            if(algorithm.Equals(CryptoAlgorithm.Secp256k1))
            {
                return WellKnownJwaValues.Es256k1;
            }

            if(algorithm.Equals(CryptoAlgorithm.Ed25519))
            {
                return WellKnownJwaValues.EdDsa;
            }

            if(algorithm.Equals(CryptoAlgorithm.Rsa2048) || algorithm.Equals(CryptoAlgorithm.Rsa4096))
            {
                return (hashAlgorithm, usePss) switch
                {
                    ("SHA384", false) => WellKnownJwaValues.Rs384,
                    ("SHA512", false) => WellKnownJwaValues.Rs512,
                    (_, false) => WellKnownJwaValues.Rs256,
                    ("SHA384", true) => WellKnownJwaValues.Ps384,
                    ("SHA512", true) => WellKnownJwaValues.Ps512,
                    (_, true) => WellKnownJwaValues.Ps256
                };
            }

            throw new NotSupportedException($"CryptoAlgorithm '{algorithm}' does not have a JWA mapping.");
        }


        /// <summary>
        /// Default converter from <see cref="Tag"/> to COSE algorithm identifier.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Maps internal <see cref="CryptoAlgorithm"/> values to COSE integer algorithm identifiers
        /// as defined in <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms</see>.
        /// </para>
        /// <para>
        /// For RSA algorithms, this returns the SHA-256 PSS variant (PS256 / -37) by default.
        /// </para>
        /// </remarks>
        public static TagToCoseDelegate DefaultTagToCoseConverter => tag =>
        {
            ArgumentNullException.ThrowIfNull(tag);

            CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();
            return algorithm switch
            {
                var a when a.Equals(CryptoAlgorithm.P256) => WellKnownCoseAlgorithms.Es256,
                var a when a.Equals(CryptoAlgorithm.P384) => WellKnownCoseAlgorithms.Es384,
                var a when a.Equals(CryptoAlgorithm.P521) => WellKnownCoseAlgorithms.Es512,
                var a when a.Equals(CryptoAlgorithm.Ed25519) => WellKnownCoseAlgorithms.EdDsa,
                var a when a.Equals(CryptoAlgorithm.Rsa2048) || a.Equals(CryptoAlgorithm.Rsa4096) => WellKnownCoseAlgorithms.Ps256,
                var a when a.Equals(CryptoAlgorithm.MlDsa44) => WellKnownCoseAlgorithms.MlDsa44,
                var a when a.Equals(CryptoAlgorithm.MlDsa65) => WellKnownCoseAlgorithms.MlDsa65,
                var a when a.Equals(CryptoAlgorithm.MlDsa87) => WellKnownCoseAlgorithms.MlDsa87,
                _ => throw new NotSupportedException($"CryptoAlgorithm '{algorithm}' does not have a COSE algorithm mapping.")
            };
        };


        /// <summary>
        /// Default converter from COSE algorithm identifier to <see cref="Tag"/>.
        /// </summary>
        public static CoseToTagDelegate DefaultCoseToTagConverter => (coseAlgorithm, purpose) =>
        {
            return (coseAlgorithm, purpose) switch
            {
                //ECDSA signing.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEs256(alg) && p.Equals(Purpose.Signing) => CryptoTags.P256PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEs384(alg) && p.Equals(Purpose.Signing) => CryptoTags.P384PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEs512(alg) && p.Equals(Purpose.Signing) => CryptoTags.P521PrivateKey,

                //ECDSA verification.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEs256(alg) && p.Equals(Purpose.Verification) => CryptoTags.P256PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEs384(alg) && p.Equals(Purpose.Verification) => CryptoTags.P384PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEs512(alg) && p.Equals(Purpose.Verification) => CryptoTags.P521PublicKey,

                //EdDSA signing and verification.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEdDsa(alg) && p.Equals(Purpose.Signing) => CryptoTags.Ed25519PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEdDsa(alg) && p.Equals(Purpose.Verification) => CryptoTags.Ed25519PublicKey,

                //RSA PSS signing.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsPs256(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsPs384(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsPs512(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,

                //RSA PSS verification.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsPs256(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsPs384(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsPs512(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,

                //ML-DSA signing.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsMlDsa44(alg) && p.Equals(Purpose.Signing) => CryptoTags.MlDsa44PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsMlDsa65(alg) && p.Equals(Purpose.Signing) => CryptoTags.MlDsa65PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsMlDsa87(alg) && p.Equals(Purpose.Signing) => CryptoTags.MlDsa87PrivateKey,

                //ML-DSA verification.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsMlDsa44(alg) && p.Equals(Purpose.Verification) => CryptoTags.MlDsa44PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsMlDsa65(alg) && p.Equals(Purpose.Verification) => CryptoTags.MlDsa65PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsMlDsa87(alg) && p.Equals(Purpose.Verification) => CryptoTags.MlDsa87PublicKey,

                _ => throw new NotSupportedException($"COSE algorithm '{coseAlgorithm}' with purpose '{purpose}' is not supported.")
            };
        };


        /// <summary>
        /// Gets the signing <see cref="Tag"/> for the specified JWA algorithm.
        /// </summary>
        /// <param name="jwaAlgorithm">The JWA algorithm identifier.</param>
        /// <returns>The corresponding signing tag.</returns>
        public static Tag GetSigningTag(string jwaAlgorithm)
        {
            return DefaultJwaToTagConverter(jwaAlgorithm, Purpose.Signing);
        }


        /// <summary>
        /// Gets the verification <see cref="Tag"/> for the specified JWA algorithm.
        /// </summary>
        /// <param name="jwaAlgorithm">The JWA algorithm identifier.</param>
        /// <returns>The corresponding verification tag.</returns>
        public static Tag GetVerificationTag(string jwaAlgorithm)
        {
            return DefaultJwaToTagConverter(jwaAlgorithm, Purpose.Verification);
        }


        /// <summary>
        /// Gets the signature <see cref="Tag"/> for the specified JWA algorithm.
        /// </summary>
        /// <param name="jwaAlgorithm">The JWA algorithm identifier.</param>
        /// <returns>The corresponding signature tag.</returns>
        public static Tag GetSignatureTag(string jwaAlgorithm)
        {
            if(string.IsNullOrEmpty(jwaAlgorithm))
            {
                throw new ArgumentException("JWA algorithm cannot be null or empty.", nameof(jwaAlgorithm));
            }

            if(WellKnownJwaValues.IsEs256(jwaAlgorithm))
            {
                return CryptoTags.P256Signature;
            }

            if(WellKnownJwaValues.IsEs384(jwaAlgorithm))
            {
                return CryptoTags.P384Signature;
            }

            if(WellKnownJwaValues.IsEs512(jwaAlgorithm))
            {
                return CryptoTags.P521Signature;
            }

            if(WellKnownJwaValues.IsEs256k1(jwaAlgorithm))
            {
                return CryptoTags.Secp256k1Signature;
            }

            if(WellKnownJwaValues.IsEdDsa(jwaAlgorithm))
            {
                return CryptoTags.Ed25519Signature;
            }

            //RSA and HMAC signatures don't have specific tags defined in Tag class.
            //Return Empty for now; could be extended later.
            if(WellKnownJwaValues.IsRs256(jwaAlgorithm) || WellKnownJwaValues.IsRs384(jwaAlgorithm) || WellKnownJwaValues.IsRs512(jwaAlgorithm))
            {
                return Tag.Empty;
            }

            if(WellKnownJwaValues.IsPs256(jwaAlgorithm) || WellKnownJwaValues.IsPs384(jwaAlgorithm) || WellKnownJwaValues.IsPs512(jwaAlgorithm))
            {
                return Tag.Empty;
            }

            throw new NotSupportedException($"JWA algorithm '{jwaAlgorithm}' is not supported for signature tags.");
        }


        /// <summary>
        /// Default converter from algorithm and key material to JWK format.
        /// </summary>
        public static AlgorithmToJwkDelegate DefaultAlgorithmToJwkConverter => (algorithm, purpose, keyMaterial, base64UrlEncoder) =>
        {
            static Dictionary<string, object> AddEcHeaders(string alg, string crv, ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers, EllipticCurveTypes curveType, EncodeDelegate encoder)
            {
                ReadOnlySpan<byte> compressedXAndY = keyMaterial;
                byte[] uncompressedY = EllipticCurveUtilities.Decompress(compressedXAndY, curveType);
                ReadOnlySpan<byte> uncompressedX = compressedXAndY.Slice(1);

                var jwtX = EncodeForJwk(uncompressedX, encoder);
                var jwtY = EncodeForJwk(uncompressedY, encoder);

                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Ec);
                headers.Add(JwkProperties.Alg, alg);
                headers.Add(JwkProperties.Crv, crv);
                headers.Add(JwkProperties.X, jwtX);
                headers.Add(JwkProperties.Y, jwtY);

                return headers;
            }

            static Dictionary<string, object> AddRsaHeaders(string alg, ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers, Tag keyTag, EncodeDelegate encoder)
            {
                var encodingScheme = keyTag.Get<EncodingScheme>();
                byte[] rawModulus = encodingScheme switch
                {
                    EncodingScheme enc when enc.Equals(EncodingScheme.Der) => RsaUtilities.Decode(keyMaterial),
                    EncodingScheme enc when enc.Equals(EncodingScheme.Raw) => keyMaterial.ToArray(),
                    _ => throw new ArgumentException($"Unsupported encoding scheme for RSA: {encodingScheme}")
                };

                ReadOnlySpan<byte> keyBytes = rawModulus;
                var base64UrlencodedKeyBytes = EncodeForJwk(keyBytes, encoder);

                headers.Add(JwkProperties.Alg, alg);
                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Rsa);
                headers.Add(JwkProperties.E, RsaUtilities.DefaultExponent);
                headers.Add(JwkProperties.N, base64UrlencodedKeyBytes);

                return headers;
            }

            static Dictionary<string, object> AddEd25519Headers(ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers, EncodeDelegate encoder)
            {
                var base64UrlencodedKeyBytes = EncodeForJwk(keyMaterial, encoder);

                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Okp);
                headers.Add(JwkProperties.Alg, WellKnownJwaValues.EdDsa);
                headers.Add(JwkProperties.Crv, WellKnownCurveValues.Ed25519);
                headers.Add(JwkProperties.X, base64UrlencodedKeyBytes);

                return headers;
            }

            static Dictionary<string, object> AddX25519Headers(ReadOnlySpan<byte> keyMaterial, Dictionary<string, object> headers, EncodeDelegate encoder)
            {
                var base64UrlencodedKeyBytes = EncodeForJwk(keyMaterial, encoder);

                headers.Add(JwkProperties.Kty, WellKnownKeyTypeValues.Okp);
                headers.Add(JwkProperties.Crv, WellKnownCurveValues.X25519);
                headers.Add(JwkProperties.X, base64UrlencodedKeyBytes);

                return headers;
            }

            //Helper method to encode data for JWK using the provided encoder.
            static string EncodeForJwk(ReadOnlySpan<byte> data, EncodeDelegate encoder)
            {
                return encoder(data);
            }

            var jwkHeaders = new Dictionary<string, object>();
            return (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es256, WellKnownCurveValues.P256, keyMaterial, jwkHeaders, EllipticCurveTypes.P256, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es384, WellKnownCurveValues.P384, keyMaterial, jwkHeaders, EllipticCurveTypes.P384, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es512, WellKnownCurveValues.P521, keyMaterial, jwkHeaders, EllipticCurveTypes.P521, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) => AddEcHeaders(WellKnownJwaValues.Es256k1, WellKnownCurveValues.Secp256k1, keyMaterial, jwkHeaders, EllipticCurveTypes.Secp256k1, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => AddRsaHeaders(WellKnownJwaValues.Rs256, keyMaterial, jwkHeaders, CryptoTags.Rsa2048PublicKey, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => AddRsaHeaders(WellKnownJwaValues.Rs256, keyMaterial, jwkHeaders, CryptoTags.Rsa4096PublicKey, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => AddEd25519Headers(keyMaterial, jwkHeaders, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) => AddX25519Headers(keyMaterial, jwkHeaders, base64UrlEncoder),
                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: \"{algorithm}\", \"{purpose}\".")
            };
        };

        /// <summary>
        /// Default converter from algorithm and key material to Base58 format.
        /// </summary>
        public static AlgorithmToBase58Delegate DefaultAlgorithmToBase58Converter => (algorithm, purpose, keyMaterial, base58Encoder) =>
        {
            static string EncodeKey(ReadOnlySpan<byte> keyMaterial, ReadOnlySpan<byte> multicodecHeader, EncodeDelegate encoder)
            {
                return MultibaseSerializer.Encode(keyMaterial, multicodecHeader, MultibaseAlgorithms.Base58Btc, encoder, SensitiveMemoryPool<byte>.Shared);
            }

            return (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.P256PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.P384PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.P521PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.Secp256k1PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.RsaPublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.RsaPublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Bls12381G1) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.Bls12381G1PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) => EncodeKey(keyMaterial, MulticodecHeaders.Ed25519PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) => EncodeKey(keyMaterial, MulticodecHeaders.X25519PublicKey, base58Encoder),
                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: \"{algorithm}\", \"{purpose}\".")
            };
        };

        /// <summary>
        /// Default converter from JWK to algorithm representation.
        /// </summary>
        public static JwkToAlgorithmDelegate DefaultJwkToAlgorithmConverter => static (jwk, memoryPool, base64UrlDecoder) =>
        {
            if(jwk == null)
            {
                throw new ArgumentNullException(nameof(jwk), "JWK cannot be null.");
            }

            if(!jwk.TryGetValue(JwkProperties.Kty, out var kty) || kty is not string keyType)
            {
                throw new ArgumentException($"JWK must contain a valid '{JwkProperties.Kty}' field.", nameof(jwk));
            }

            //Check for required fields based on key type.
            ValidateRequiredFields(jwk, keyType);

            //Make 'alg' optional with fallback logic.
            string algorithm = string.Empty;
            if(jwk.TryGetValue(JwkProperties.Alg, out var alg) && alg is string algString)
            {
                algorithm = algString;
            }

            var keyMaterial = DecodeKeyMaterial(jwk, keyType, base64UrlDecoder);
            var (cryptoAlgorithm, purpose) = MapToAlgorithmAndPurpose(keyType, algorithm, keyMaterial.Length);

            IMemoryOwner<byte> keyMaterialOwner = memoryPool.Rent(keyMaterial.Length);
            keyMaterial.CopyTo(keyMaterialOwner.Memory.Span);

            return (cryptoAlgorithm, purpose, EncodingScheme.Raw, keyMaterialOwner);

            static void ValidateRequiredFields(Dictionary<string, object> jwk, string keyType)
            {
                switch(keyType)
                {
                    case string key when WellKnownKeyTypeValues.IsEc(key):
                        //EC keys require 'x' and 'y' coordinates.
                        if(!jwk.TryGetValue(JwkProperties.X, out var ecX) || ecX is not string)
                        {
                            throw new ArgumentException($"EC JWK must contain a valid '{JwkProperties.X}' field.", nameof(jwk));
                        }
                        if(!jwk.TryGetValue(JwkProperties.Y, out var ecY) || ecY is not string)
                        {
                            throw new ArgumentException($"EC JWK must contain a valid '{JwkProperties.Y}' field.", nameof(jwk));
                        }
                        break;

                    case string key when WellKnownKeyTypeValues.IsOkp(key):
                        //OKP keys require 'x' coordinate.
                        if(!jwk.TryGetValue(JwkProperties.X, out var okpX) || okpX is not string)
                        {
                            throw new ArgumentException($"OKP JWK must contain a valid '{JwkProperties.X}' field.", nameof(jwk));
                        }
                        break;

                    case string key when WellKnownKeyTypeValues.IsRsa(key):
                        //RSA keys require 'n' (modulus) and 'e' (exponent).
                        if(!jwk.TryGetValue(JwkProperties.N, out var rsaN) || rsaN is not string)
                        {
                            throw new ArgumentException($"RSA JWK must contain a valid '{JwkProperties.N}' field.", nameof(jwk));
                        }
                        if(!jwk.TryGetValue(JwkProperties.E, out var rsaE) || rsaE is not string)
                        {
                            throw new ArgumentException($"RSA JWK must contain a valid '{JwkProperties.E}' field.", nameof(jwk));
                        }
                        break;

                    default:
                        throw new ArgumentException($"Unsupported key type: '{keyType}'.");
                }
            }

            static byte[] DecodeKeyMaterial(Dictionary<string, object> jwk, string keyType, DecodeDelegate decoder)
            {
                return keyType switch
                {
                    string key when WellKnownKeyTypeValues.IsEc(key) => DecodeEcKey(jwk, decoder),
                    string key when WellKnownKeyTypeValues.IsOkp(key) => DecodeOkpKey(jwk, decoder),
                    string key when WellKnownKeyTypeValues.IsRsa(key) => DecodeRsaKey(jwk, decoder),
                    _ => throw new ArgumentException($"Unsupported key type: '{keyType}'.")
                };
            }

            static byte[] DecodeEcKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                //Fields already validated by ValidateRequiredFields.
                using var xBytes = DecodeForJwk((string)jwk[JwkProperties.X], decoder);
                using var yBytes = DecodeForJwk((string)jwk[JwkProperties.Y], decoder);

                return EllipticCurveUtilities.Compress(xBytes.Memory.Span, yBytes.Memory.Span);
            }

            static byte[] DecodeOkpKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                //Fields already validated by ValidateRequiredFields.
                using var decoded = DecodeForJwk((string)jwk[JwkProperties.X], decoder);
                return decoded.Memory.Span.ToArray();
            }

            static byte[] DecodeRsaKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                //Fields already validated by ValidateRequiredFields.
                //Return only the modulus for now.
                using var decoded = DecodeForJwk((string)jwk[JwkProperties.N], decoder);
                return decoded.Memory.Span.ToArray();
            }

            //Helper method to decode JWK data using the provided decoder.
            static IMemoryOwner<byte> DecodeForJwk(string encodedData, DecodeDelegate decoder)
            {
                //For JWK, we don't have codec headers, so pass 0 as header length.
                return decoder(encodedData, SensitiveMemoryPool<byte>.Shared);
            }

            static CryptoAlgorithm DetermineRsaAlgorithm(int keyLength)
            {
                return keyLength switch
                {
                    256 => CryptoAlgorithm.Rsa2048,  //2048 bits = 256 bytes.
                    512 => CryptoAlgorithm.Rsa4096,  //4096 bits = 512 bytes.
                    _ => throw new ArgumentException($"Unsupported RSA key size: '{keyLength}' bytes.")
                };
            }

            static (CryptoAlgorithm, Purpose) MapToAlgorithmAndPurpose(string keyType, string algorithm, int keyMaterialLength)
            {
                return (keyType, algorithm) switch
                {
                    //EC keys.
                    (string kt, string alg) when WellKnownKeyTypeValues.IsEc(kt) && WellKnownJwaValues.IsEs256(alg) => (CryptoAlgorithm.P256, Purpose.Verification),
                    (string kt, string alg) when WellKnownKeyTypeValues.IsEc(kt) && WellKnownJwaValues.IsEs384(alg) => (CryptoAlgorithm.P384, Purpose.Verification),
                    (string kt, string alg) when WellKnownKeyTypeValues.IsEc(kt) && WellKnownJwaValues.IsEs512(alg) => (CryptoAlgorithm.P521, Purpose.Verification),
                    (string kt, string alg) when WellKnownKeyTypeValues.IsEc(kt) && WellKnownJwaValues.IsEs256k1(alg) => (CryptoAlgorithm.Secp256k1, Purpose.Verification),

                    //OKP keys.
                    (string kt, string alg) when WellKnownKeyTypeValues.IsOkp(kt) && WellKnownJwaValues.IsEdDsa(alg) => (CryptoAlgorithm.Ed25519, Purpose.Verification),
                    (string kt, string alg) when WellKnownKeyTypeValues.IsOkp(kt) && WellKnownJwaValues.IsEcdha(alg) => (CryptoAlgorithm.X25519, Purpose.Exchange),

                    //RSA keys - determine algorithm based on key size if no algorithm specified.
                    (string kt, _) when WellKnownKeyTypeValues.IsRsa(kt) => (DetermineRsaAlgorithm(keyMaterialLength), Purpose.Verification),

                    _ => throw new ArgumentException($"Unsupported key type or algorithm: '{keyType}', '{algorithm}'.")
                };
            }
        };

        /// <summary>
        /// Default converter from Base58 key to algorithm representation.
        /// </summary>
        public static Base58ToAlgorithmDelegate DefaultBase58ToAlgorithmConverter => (base58Key, memoryPool, base58Decoder) =>
        {
            if(string.IsNullOrWhiteSpace(base58Key))
            {
                throw new ArgumentNullException(nameof(base58Key), "Base58 key cannot be null or empty.");
            }
            if(!base58Key[0].Equals(MultibaseAlgorithms.Base58Btc))
            {
                throw new ArgumentException($"Base58 key must start with '{MultibaseAlgorithms.Base58Btc}' for multibase format.", nameof(base58Key));
            }
            //Validate and fetch canonicalized header.
            ReadOnlySpan<char> header = Base58BtcEncodedMulticodecHeaders.GetCanonicalizedHeader(base58Key.AsSpan(0, 4));
            if(header.SequenceEqual(base58Key))
            {
                throw new ArgumentException("Unknown or unsupported multicodec header.", nameof(base58Key));
            }

            //Determine codec header length based on the detected header type.
            int codecHeaderLength = Base58BtcEncodedMulticodecHeaders.GetMulticodecHeaderLength(header);
            var decodedKeyMaterialWithoutHeader = MultibaseSerializer.Decode(base58Key, codecHeaderLength, base58Decoder, memoryPool);
            return header switch
            {
                var h when Base58BtcEncodedMulticodecHeaders.IsSecp256k1PublicKey(h) => (CryptoAlgorithm.Secp256k1, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsEd25519PublicKey(h) => (CryptoAlgorithm.Ed25519, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsX25519PublicKey(h) => (CryptoAlgorithm.X25519, Purpose.Exchange, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsP256PublicKey(h) => (CryptoAlgorithm.P256, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsP384PublicKey(h) => (CryptoAlgorithm.P384, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsP521PublicKey(h) => (CryptoAlgorithm.P521, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsRsaPublicKey2048(h) => (CryptoAlgorithm.Rsa2048, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                var h when Base58BtcEncodedMulticodecHeaders.IsRsaPublicKey4096(h) => (CryptoAlgorithm.Rsa4096, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterialWithoutHeader),
                _ => throw new ArgumentException($"Unsupported header: {header}", nameof(base58Key))
            };
        };
    }
}