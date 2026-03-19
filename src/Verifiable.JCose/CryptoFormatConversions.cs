using System.Buffers;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;


namespace Verifiable.JCose
{
    /// <summary>
    /// Delegate for converting algorithm and key material to a
    /// <see cref="JsonWebKey"/>.
    /// </summary>
    public delegate JsonWebKey AlgorithmToJwkDelegate(CryptoAlgorithm algorithm, Purpose purpose, ReadOnlySpan<byte> keyMaterial, EncodeDelegate base64UrlEncoder);

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
    /// <param name="jwaAlgorithm">The JWA algorithm identifier (e.g., <c>ES256</c>, <c>RS256</c>).</param>
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
    /// Delegate for converting a <see cref="Tag"/> to a JWK elliptic curve name string
    /// for use in JWE EPK headers.
    /// </summary>
    /// <param name="tag">The tag containing algorithm information.</param>
    /// <returns>
    /// The JWK curve name, e.g. <c>P-256</c>, <c>P-384</c>, or <c>P-521</c>, as defined in
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1">RFC 7518 §6.2.1.1</see>.
    /// </returns>
    public delegate string TagToEpkCrvDelegate(Tag tag);

    /// <summary>
    /// Delegate for converting a JWK elliptic curve name string from a JWE EPK header to a
    /// <see cref="Tag"/> and its corresponding <see cref="EllipticCurveTypes"/> value.
    /// </summary>
    /// <param name="crv">
    /// The JWK curve name, e.g. <c>P-256</c>, <c>P-384</c>, or <c>P-521</c>, as defined in
    /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1">RFC 7518 §6.2.1.1</see>.
    /// </param>
    /// <returns>
    /// The corresponding exchange <see cref="Tag"/> for the EPK public key and the
    /// <see cref="EllipticCurveTypes"/> value needed for point-on-curve validation.
    /// </returns>
    public delegate (Tag EpkTag, EllipticCurveTypes CurveType) EpkCrvToTagDelegate(string crv);


    /// <summary>
    /// Default conversions between the internal cryptographic representation and external
    /// formats such as JWK, Base58/Multibase, JWA, and COSE.
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

                //ECDH key exchange — private keys (curve determined at call site from crv).
                (string alg, Purpose p) when WellKnownJwaValues.IsEcdha(alg) && p.Equals(Purpose.Exchange) => CryptoTags.P256ExchangePrivateKey,

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
        /// For RSA algorithms, returns the SHA-256 variant (RS256) by default.
        /// Use <see cref="CryptoFormatConversionsExtensions.GetJwaAlgorithm"/> for explicit
        /// hash algorithm selection.
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
        /// Default converter from <see cref="Tag"/> to COSE algorithm identifier.
        /// </summary>
        /// <remarks>
        /// Maps internal <see cref="CryptoAlgorithm"/> values to COSE integer algorithm
        /// identifiers as defined in
        /// <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms</see>.
        /// For RSA algorithms, returns the SHA-256 PSS variant (PS256 / -37) by default.
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
        /// Default converter from algorithm and key material to a
        /// <see cref="JsonWebKey"/>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Supports signing/verification keys for P-256, P-384, P-521, Secp256k1,
        /// RSA-2048, RSA-4096, Ed25519, and X25519, ECDH exchange keys for P-256,
        /// P-384, and P-521, and post-quantum signing keys for ML-DSA-44, ML-DSA-65,
        /// and ML-DSA-87. Exchange keys are emitted without an <c>alg</c> field since
        /// the curve name alone identifies them. ML-DSA keys are emitted with
        /// <c>kty=AKP</c>, an <c>alg</c> identifying the variant, and the raw
        /// public-key bytes under the <c>pub</c> parameter.
        /// </para>
        /// <para>
        /// The converter sets the cryptographic fields only. Callers layer
        /// <c>kid</c> and <c>use</c> on top by assigning the corresponding
        /// properties on the returned <see cref="JsonWebKey"/>.
        /// </para>
        /// </remarks>
        public static AlgorithmToJwkDelegate DefaultAlgorithmToJwkConverter => (algorithm, purpose, keyMaterial, base64UrlEncoder) =>
        {
            static JsonWebKey BuildEc(
                ReadOnlySpan<byte> keyMaterial,
                EllipticCurveTypes curveType,
                string crv,
                string? alg,
                EncodeDelegate encoder)
            {
                EllipticCurveUtilities.ExtractCoordinates(
                    keyMaterial, curveType, out ReadOnlySpan<byte> x, out ReadOnlySpan<byte> y);

                return new JsonWebKey
                {
                    Kty = WellKnownKeyTypeValues.Ec,
                    Alg = alg,
                    Crv = crv,
                    X = encoder(x),
                    Y = encoder(y)
                };
            }

            static JsonWebKey BuildRsa(
                ReadOnlySpan<byte> keyMaterial,
                Tag keyTag,
                EncodeDelegate encoder)
            {
                EncodingScheme encodingScheme = keyTag.Get<EncodingScheme>();
                byte[] rawModulus = encodingScheme switch
                {
                    EncodingScheme enc when enc.Equals(EncodingScheme.Der) => RsaUtilities.Decode(keyMaterial),
                    EncodingScheme enc when enc.Equals(EncodingScheme.Raw) => keyMaterial.ToArray(),
                    _ => throw new ArgumentException($"Unsupported encoding scheme for RSA: {encodingScheme}.")
                };

                return new JsonWebKey
                {
                    Kty = WellKnownKeyTypeValues.Rsa,
                    Alg = WellKnownJwaValues.Rs256,
                    N = encoder(rawModulus),
                    E = RsaUtilities.DefaultExponent
                };
            }

            static JsonWebKey BuildEd25519(
                ReadOnlySpan<byte> keyMaterial,
                EncodeDelegate encoder) => new()
                {
                    Kty = WellKnownKeyTypeValues.Okp,
                    Alg = WellKnownJwaValues.EdDsa,
                    Crv = WellKnownCurveValues.Ed25519,
                    X = encoder(keyMaterial)
                };

            static JsonWebKey BuildX25519(
                ReadOnlySpan<byte> keyMaterial,
                EncodeDelegate encoder) => new()
                {
                    //Exchange keys carry no alg — crv alone identifies them per RFC 7518 §6.2.
                    Kty = WellKnownKeyTypeValues.Okp,
                    Crv = WellKnownCurveValues.X25519,
                    X = encoder(keyMaterial)
                };

            static JsonWebKey BuildMlDsa(
                ReadOnlySpan<byte> keyMaterial,
                string alg,
                EncodeDelegate encoder) => new()
                {
                    Kty = WellKnownKeyTypeValues.Akp,
                    Alg = alg,
                    Pub = encoder(keyMaterial)
                };

            return (algorithm, purpose) switch
            {
                //Signing/verification EC keys — compressed storage, alg emitted.
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.P256, WellKnownCurveValues.P256, WellKnownJwaValues.Es256, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.P384, WellKnownCurveValues.P384, WellKnownJwaValues.Es384, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.P521, WellKnownCurveValues.P521, WellKnownJwaValues.Es512, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.Secp256k1, WellKnownCurveValues.Secp256k1, WellKnownJwaValues.Es256k1, base64UrlEncoder),

                //ECDH exchange keys — uncompressed storage, no alg emitted.
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Exchange) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.P256, WellKnownCurveValues.P256, null, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Exchange) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.P384, WellKnownCurveValues.P384, null, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Exchange) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.P521, WellKnownCurveValues.P521, null, base64UrlEncoder),

                //RSA keys.
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) =>
                    BuildRsa(keyMaterial, CryptoTags.Rsa2048PublicKey, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) =>
                    BuildRsa(keyMaterial, CryptoTags.Rsa4096PublicKey, base64UrlEncoder),

                //OKP keys.
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) =>
                    BuildEd25519(keyMaterial, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) =>
                    BuildX25519(keyMaterial, base64UrlEncoder),

                //ML-DSA signing/verification keys — emitted as kty=AKP with the raw
                //public-key bytes under the "pub" parameter per the emerging
                //post-quantum JWK drafts.
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa44) && p.Equals(Purpose.Verification) =>
                    BuildMlDsa(keyMaterial, WellKnownJwaValues.MlDsa44, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa65) && p.Equals(Purpose.Verification) =>
                    BuildMlDsa(keyMaterial, WellKnownJwaValues.MlDsa65, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.MlDsa87) && p.Equals(Purpose.Verification) =>
                    BuildMlDsa(keyMaterial, WellKnownJwaValues.MlDsa87, base64UrlEncoder),

                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: '{algorithm}', '{purpose}'.")
            };
        };


        /// <summary>
        /// Default converter from algorithm and key material to Base58 format.
        /// </summary>
        public static AlgorithmToBase58Delegate DefaultAlgorithmToBase58Converter => (algorithm, purpose, keyMaterial, base58Encoder) =>
        {
            static string EncodeKey(
                ReadOnlySpan<byte> keyMaterial,
                ReadOnlySpan<byte> multicodecHeader,
                EncodeDelegate encoder)
            {
                return MultibaseSerializer.Encode(
                    keyMaterial,
                    multicodecHeader,
                    MultibaseAlgorithms.Base58Btc,
                    encoder,
                    SensitiveMemoryPool<byte>.Shared);
            }

            return (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.P256PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.P384PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.P521PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.Secp256k1PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.RsaPublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.RsaPublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Bls12381G1) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.Bls12381G1PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.Ed25519PublicKey, base58Encoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.X25519PublicKey, base58Encoder),

                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: '{algorithm}', '{purpose}'.")
            };
        };


        /// <summary>
        /// Default converter from JWK to algorithm representation.
        /// </summary>
        /// <remarks>
        /// Resolves <see cref="Purpose"/> from the optional JWK <c>use</c> field
        /// (<c>sig</c> → <see cref="Purpose.Verification"/>,
        /// <c>enc</c> → <see cref="Purpose.Exchange"/>). When absent, defaults to
        /// <see cref="Purpose.Verification"/> for EC and OKP keys, consistent with
        /// the most common use case.
        /// </remarks>
        public static JwkToAlgorithmDelegate DefaultJwkToAlgorithmConverter => static (jwk, memoryPool, base64UrlDecoder) =>
        {
            ArgumentNullException.ThrowIfNull(jwk);

            if(!jwk.TryGetValue(WellKnownJwkValues.Kty, out object? kty) || kty is not string keyType)
            {
                throw new ArgumentException($"JWK must contain a valid '{WellKnownJwkValues.Kty}' field.", nameof(jwk));
            }

            ValidateRequiredFields(jwk, keyType);

            string algorithm = string.Empty;
            if(jwk.TryGetValue(WellKnownJwkValues.Alg, out object? alg) && alg is string algString)
            {
                algorithm = algString;
            }

            string crv = string.Empty;
            if(jwk.TryGetValue(WellKnownJwkValues.Crv, out object? crvObj) && crvObj is string crvString)
            {
                crv = crvString;
            }

            //Resolve purpose from the optional 'use' field; default to Verification.
            Purpose explicitPurpose = Purpose.Verification;
            if(jwk.TryGetValue(WellKnownJwkValues.Use, out object? useObj) && useObj is string use)
            {
                explicitPurpose = use switch
                {
                    string u when WellKnownJwkValues.Equals(u, WellKnownJwkValues.UseEnc) => Purpose.Exchange,
                    _ => Purpose.Verification
                };
            }

            byte[] keyMaterial = DecodeKeyMaterial(jwk, keyType, base64UrlDecoder);
            (CryptoAlgorithm cryptoAlgorithm, Purpose purpose) =
                MapToAlgorithmAndPurpose(keyType, algorithm, crv, explicitPurpose, keyMaterial.Length);

            IMemoryOwner<byte> keyMaterialOwner = memoryPool.Rent(keyMaterial.Length);
            keyMaterial.CopyTo(keyMaterialOwner.Memory.Span);

            return (cryptoAlgorithm, purpose, EncodingScheme.Raw, keyMaterialOwner);


            static void ValidateRequiredFields(Dictionary<string, object> jwk, string keyType)
            {
                if(WellKnownKeyTypeValues.IsEc(keyType))
                {
                    if(!jwk.TryGetValue(WellKnownJwkValues.X, out object? ecX) || ecX is not string)
                    {
                        throw new ArgumentException($"EC JWK must contain a valid '{WellKnownJwkValues.X}' field.", nameof(jwk));
                    }

                    if(!jwk.TryGetValue(WellKnownJwkValues.Y, out object? ecY) || ecY is not string)
                    {
                        throw new ArgumentException($"EC JWK must contain a valid '{WellKnownJwkValues.Y}' field.", nameof(jwk));
                    }
                }
                else if(WellKnownKeyTypeValues.IsOkp(keyType))
                {
                    if(!jwk.TryGetValue(WellKnownJwkValues.X, out object? okpX) || okpX is not string)
                    {
                        throw new ArgumentException($"OKP JWK must contain a valid '{WellKnownJwkValues.X}' field.", nameof(jwk));
                    }
                }
                else if(WellKnownKeyTypeValues.IsRsa(keyType))
                {
                    if(!jwk.TryGetValue(WellKnownJwkValues.N, out object? rsaN) || rsaN is not string)
                    {
                        throw new ArgumentException($"RSA JWK must contain a valid '{WellKnownJwkValues.N}' field.", nameof(jwk));
                    }

                    if(!jwk.TryGetValue(WellKnownJwkValues.E, out object? rsaE) || rsaE is not string)
                    {
                        throw new ArgumentException($"RSA JWK must contain a valid '{WellKnownJwkValues.E}' field.", nameof(jwk));
                    }
                }
                else
                {
                    throw new ArgumentException($"Unsupported key type: '{keyType}'.");
                }
            }


            static byte[] DecodeKeyMaterial(
                Dictionary<string, object> jwk,
                string keyType,
                DecodeDelegate decoder)
            {
                if(WellKnownKeyTypeValues.IsEc(keyType)) { return DecodeEcKey(jwk, decoder); }
                if(WellKnownKeyTypeValues.IsOkp(keyType)) { return DecodeOkpKey(jwk, decoder); }
                if(WellKnownKeyTypeValues.IsRsa(keyType)) { return DecodeRsaKey(jwk, decoder); }

                throw new ArgumentException($"Unsupported key type: '{keyType}'.");
            }


            static byte[] DecodeEcKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                using IMemoryOwner<byte> xBytes = decoder((string)jwk[WellKnownJwkValues.X], SensitiveMemoryPool<byte>.Shared);
                using IMemoryOwner<byte> yBytes = decoder((string)jwk[WellKnownJwkValues.Y], SensitiveMemoryPool<byte>.Shared);

                //Compressed format is the canonical internal form for all EC public keys.
                //Backend functions accept both compressed and uncompressed SEC1 encoding.
                return EllipticCurveUtilities.Compress(xBytes.Memory.Span, yBytes.Memory.Span);
            }


            static byte[] DecodeOkpKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                using IMemoryOwner<byte> decoded = decoder((string)jwk[WellKnownJwkValues.X], SensitiveMemoryPool<byte>.Shared);

                return decoded.Memory.Span.ToArray();
            }


            static byte[] DecodeRsaKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                using IMemoryOwner<byte> decoded = decoder((string)jwk[WellKnownJwkValues.N], SensitiveMemoryPool<byte>.Shared);

                return decoded.Memory.Span.ToArray();
            }


            static (CryptoAlgorithm, Purpose) MapToAlgorithmAndPurpose(
                string keyType,
                string algorithm,
                string crv,
                Purpose explicitPurpose,
                int keyMaterialLength)
            {
                if(WellKnownKeyTypeValues.IsEc(keyType))
                {
                    //Prefer crv for EC key identification per RFC 7518 §6.2.1.1; fall back to alg.
                    if(WellKnownCurveValues.IsP256(crv)) { return (CryptoAlgorithm.P256, explicitPurpose); }
                    if(WellKnownCurveValues.IsP384(crv)) { return (CryptoAlgorithm.P384, explicitPurpose); }
                    if(WellKnownCurveValues.IsP521(crv)) { return (CryptoAlgorithm.P521, explicitPurpose); }
                    if(WellKnownCurveValues.IsSecp256k1(crv) || WellKnownJwaValues.IsEs256k1(algorithm))
                    {
                        return (CryptoAlgorithm.Secp256k1, Purpose.Verification);
                    }

                    //Fall back to alg when crv is absent.
                    if(WellKnownJwaValues.IsEs256(algorithm)) { return (CryptoAlgorithm.P256, explicitPurpose); }
                    if(WellKnownJwaValues.IsEs384(algorithm)) { return (CryptoAlgorithm.P384, explicitPurpose); }
                    if(WellKnownJwaValues.IsEs512(algorithm)) { return (CryptoAlgorithm.P521, explicitPurpose); }
                }

                if(WellKnownKeyTypeValues.IsOkp(keyType))
                {
                    if(WellKnownCurveValues.IsEd25519(crv) || WellKnownJwaValues.IsEdDsa(algorithm))
                    {
                        return (CryptoAlgorithm.Ed25519, Purpose.Verification);
                    }

                    if(WellKnownCurveValues.IsX25519(crv) || WellKnownJwaValues.IsEcdha(algorithm))
                    {
                        return (CryptoAlgorithm.X25519, Purpose.Exchange);
                    }
                }

                if(WellKnownKeyTypeValues.IsRsa(keyType))
                {
                    return keyMaterialLength switch
                    {
                        256 => (CryptoAlgorithm.Rsa2048, Purpose.Verification),
                        512 => (CryptoAlgorithm.Rsa4096, Purpose.Verification),
                        _ => throw new ArgumentException($"Unsupported RSA key size: '{keyMaterialLength}' bytes.")
                    };
                }

                throw new ArgumentException($"Unsupported key type or algorithm: '{keyType}', '{algorithm}'.");
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
                throw new ArgumentException(
                    $"Base58 key must start with '{MultibaseAlgorithms.Base58Btc}' for multibase format.",
                    nameof(base58Key));
            }

            ReadOnlySpan<char> header = Base58BtcEncodedMulticodecHeaders.GetCanonicalizedHeader(base58Key.AsSpan(0, 4));
            if(header.SequenceEqual(base58Key))
            {
                throw new ArgumentException("Unknown or unsupported multicodec header.", nameof(base58Key));
            }

            int codecHeaderLength = Base58BtcEncodedMulticodecHeaders.GetMulticodecHeaderLength(header);
            IMemoryOwner<byte> decodedKeyMaterial =
                MultibaseSerializer.Decode(base58Key, codecHeaderLength, base58Decoder, memoryPool);

            return header switch
            {
                var h when Base58BtcEncodedMulticodecHeaders.IsSecp256k1PublicKey(h) => (CryptoAlgorithm.Secp256k1, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterial),
                var h when Base58BtcEncodedMulticodecHeaders.IsEd25519PublicKey(h) => (CryptoAlgorithm.Ed25519, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterial),
                var h when Base58BtcEncodedMulticodecHeaders.IsX25519PublicKey(h) => (CryptoAlgorithm.X25519, Purpose.Exchange, EncodingScheme.Raw, decodedKeyMaterial),
                var h when Base58BtcEncodedMulticodecHeaders.IsP256PublicKey(h) => (CryptoAlgorithm.P256, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterial),
                var h when Base58BtcEncodedMulticodecHeaders.IsP384PublicKey(h) => (CryptoAlgorithm.P384, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterial),
                var h when Base58BtcEncodedMulticodecHeaders.IsP521PublicKey(h) => (CryptoAlgorithm.P521, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterial),
                var h when Base58BtcEncodedMulticodecHeaders.IsRsaPublicKey2048(h) => (CryptoAlgorithm.Rsa2048, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterial),
                var h when Base58BtcEncodedMulticodecHeaders.IsRsaPublicKey4096(h) => (CryptoAlgorithm.Rsa4096, Purpose.Verification, EncodingScheme.Raw, decodedKeyMaterial),
                _ => throw new ArgumentException($"Unsupported header: {header}", nameof(base58Key))
            };
        };


        /// <summary>
        /// Default converter from a <see cref="Tag"/> to a JWK elliptic curve name string
        /// for embedding in a JWE <c>epk</c> header parameter.
        /// </summary>
        /// <remarks>
        /// Covers both signing/verification and ECDH exchange tags for P-256, P-384, and P-521.
        /// </remarks>
        public static TagToEpkCrvDelegate DefaultTagToEpkCrvConverter => tag =>
        {
            ArgumentNullException.ThrowIfNull(tag);

            CryptoAlgorithm algorithm = tag.Get<CryptoAlgorithm>();
            return algorithm switch
            {
                var a when a.Equals(CryptoAlgorithm.P256) => WellKnownCurveValues.P256,
                var a when a.Equals(CryptoAlgorithm.P384) => WellKnownCurveValues.P384,
                var a when a.Equals(CryptoAlgorithm.P521) => WellKnownCurveValues.P521,
                _ => throw new NotSupportedException(
                    $"CryptoAlgorithm '{algorithm}' does not have a JWK curve name mapping. " +
                    $"Only EC curves P-256, P-384, and P-521 are supported.")
            };
        };


        /// <summary>
        /// Default converter from a JWK elliptic curve name string in a JWE <c>epk</c> header
        /// to a <see cref="Tag"/> and <see cref="EllipticCurveTypes"/> value.
        /// </summary>
        /// <remarks>
        /// Returns the exchange variant of the tag for all supported curves. The curve type
        /// is used for point-on-curve validation against invalid curve and small subgroup attacks.
        /// </remarks>
        public static EpkCrvToTagDelegate DefaultEpkCrvToTagConverter => crv =>
        {
            ArgumentNullException.ThrowIfNull(crv);

            return crv switch
            {
                var c when WellKnownCurveValues.IsP256(c) => (CryptoTags.P256ExchangePublicKey, EllipticCurveTypes.P256),
                var c when WellKnownCurveValues.IsP384(c) => (CryptoTags.P384ExchangePublicKey, EllipticCurveTypes.P384),
                var c when WellKnownCurveValues.IsP521(c) => (CryptoTags.P521ExchangePublicKey, EllipticCurveTypes.P521),
                _ => throw new NotSupportedException(
                    $"JWK curve name '{crv}' does not have a mapping. " +
                    $"Only EC curves P-256, P-384, and P-521 are supported.")
            };
        };
    }
}
