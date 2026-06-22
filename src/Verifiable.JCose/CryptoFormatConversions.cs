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
    /// Delegate for converting a COSE_Key (RFC 9052 §7) into a
    /// <see cref="Tag"/> describing the corresponding internal key material.
    /// Parallels <c>JwkToAlgorithmDelegate</c> for the COSE side.
    /// </summary>
    /// <param name="kty">
    /// The COSE_Key <c>kty</c> parameter (RFC 9052 §7.1). <c>1 = OKP</c>,
    /// <c>2 = EC2</c>, <c>3 = RSA</c>, <c>4 = Symmetric</c>.
    /// </param>
    /// <param name="curve">
    /// The COSE_Key <c>crv</c> parameter (IANA COSE Elliptic Curves
    /// registry) for EC2 and OKP keys; pass <see langword="null"/> for key
    /// types where curve is not applicable.
    /// </param>
    /// <param name="purpose">
    /// The intended purpose — <see cref="Purpose.Verification"/> for public
    /// keys carried in MSO <c>DeviceKeyInfo</c>, <see cref="Purpose.Signing"/>
    /// for private keys, <see cref="Purpose.Exchange"/> for X25519/X448 OKP
    /// agreement keys.
    /// </param>
    /// <returns>The corresponding <see cref="Tag"/> for the key material.</returns>
    public delegate Tag CoseKeyToAlgorithmDelegate(int kty, int? curve, Purpose purpose);


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
                (string alg, Purpose p) when WellKnownJwaValues.IsEs256K(alg) && p.Equals(Purpose.Signing) => CryptoTags.Secp256k1PrivateKey,

                //ECDSA verification.
                (string alg, Purpose p) when WellKnownJwaValues.IsEs256(alg) && p.Equals(Purpose.Verification) => CryptoTags.P256PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEs384(alg) && p.Equals(Purpose.Verification) => CryptoTags.P384PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEs512(alg) && p.Equals(Purpose.Verification) => CryptoTags.P521PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEs256K(alg) && p.Equals(Purpose.Verification) => CryptoTags.Secp256k1PublicKey,

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

                //RFC 9784 / draft-ietf-jose-fully-specified-algorithms Brainpool ECDSA signing.
                (string alg, Purpose p) when WellKnownJwaValues.IsEsb256(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP256r1PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEsb320(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP320r1PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEsb384(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP384r1PrivateKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEsb512(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP512r1PrivateKey,

                //Brainpool ECDSA verification.
                (string alg, Purpose p) when WellKnownJwaValues.IsEsb256(alg) && p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP256r1PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEsb320(alg) && p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP320r1PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEsb384(alg) && p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP384r1PublicKey,
                (string alg, Purpose p) when WellKnownJwaValues.IsEsb512(alg) && p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP512r1PublicKey,

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
                var a when a.Equals(CryptoAlgorithm.Secp256k1) => WellKnownJwaValues.Es256K,
                var a when a.Equals(CryptoAlgorithm.Ed25519) => WellKnownJwaValues.EdDsa,
                var a when a.Equals(CryptoAlgorithm.Rsa2048) || a.Equals(CryptoAlgorithm.Rsa4096) => WellKnownJwaValues.Rs256,
                var a when a.Equals(CryptoAlgorithm.MlDsa44) => WellKnownJwaValues.MlDsa44,
                var a when a.Equals(CryptoAlgorithm.MlDsa65) => WellKnownJwaValues.MlDsa65,
                var a when a.Equals(CryptoAlgorithm.MlDsa87) => WellKnownJwaValues.MlDsa87,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP256r1) => WellKnownJwaValues.Esb256,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP320r1) => WellKnownJwaValues.Esb320,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP384r1) => WellKnownJwaValues.Esb384,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP512r1) => WellKnownJwaValues.Esb512,
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
                var a when a.Equals(CryptoAlgorithm.BrainpoolP256r1) => WellKnownCoseAlgorithms.Esb256,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP320r1) => WellKnownCoseAlgorithms.Esb320,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP384r1) => WellKnownCoseAlgorithms.Esb384,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP512r1) => WellKnownCoseAlgorithms.Esb512,
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

                //RFC 9784 fully-specified ECDSA (signing). Maps to the same
                //P-curve key tags as the non-fully-specified ES variants —
                //ESP pins the hash explicitly but the key material is the
                //same EC key on the same curve.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp256(alg) && p.Equals(Purpose.Signing) => CryptoTags.P256PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp384(alg) && p.Equals(Purpose.Signing) => CryptoTags.P384PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp512(alg) && p.Equals(Purpose.Signing) => CryptoTags.P521PrivateKey,

                //RFC 9784 fully-specified ECDSA (verification).
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp256(alg) && p.Equals(Purpose.Verification) => CryptoTags.P256PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp384(alg) && p.Equals(Purpose.Verification) => CryptoTags.P384PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp512(alg) && p.Equals(Purpose.Verification) => CryptoTags.P521PublicKey,

                //RFC 9784 Brainpool ECDSA (signing). Hash binding per RFC 9784 §5:
                //ESB256 → SHA-256, ESB320 → SHA-384, ESB384 → SHA-384, ESB512 → SHA-512.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb256(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP256r1PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb320(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP320r1PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb384(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP384r1PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb512(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP512r1PrivateKey,

                //RFC 9784 Brainpool ECDSA (verification).
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb256(alg) && p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP256r1PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb320(alg) && p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP320r1PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb384(alg) && p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP384r1PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb512(alg) && p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP512r1PublicKey,

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
                EncodeDelegate encoder)
            {
                //Decode handles both raw and DER-encoded modulus input — raw
                //pass-through for keys reconstructed from a JWK, DER-strip for
                //keys generated through System.Security.Cryptography. The
                //previous EncodingScheme switch hardcoded the DER path via
                //the well-known CryptoTags.RsaXxxxPublicKey tag literal,
                //which broke the JWK round-trip path; collapse to the single
                //RsaUtilities.Decode call now that the function is length-
                //tolerant.
                byte[] rawModulus = RsaUtilities.Decode(keyMaterial);

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
                    BuildEc(keyMaterial, EllipticCurveTypes.Secp256k1, WellKnownCurveValues.Secp256k1, WellKnownJwaValues.Es256K, base64UrlEncoder),

                //Brainpool ECDSA verification keys per RFC 5639 / RFC 9784.
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP256r1) && p.Equals(Purpose.Verification) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.BrainpoolP256r1, WellKnownCurveValues.BrainpoolP256r1, WellKnownJwaValues.Esb256, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP320r1) && p.Equals(Purpose.Verification) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.BrainpoolP320r1, WellKnownCurveValues.BrainpoolP320r1, WellKnownJwaValues.Esb320, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP384r1) && p.Equals(Purpose.Verification) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.BrainpoolP384r1, WellKnownCurveValues.BrainpoolP384r1, WellKnownJwaValues.Esb384, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.BrainpoolP512r1) && p.Equals(Purpose.Verification) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.BrainpoolP512r1, WellKnownCurveValues.BrainpoolP512r1, WellKnownJwaValues.Esb512, base64UrlEncoder),

                //ECDH exchange keys — uncompressed storage, no alg emitted.
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Exchange) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.P256, WellKnownCurveValues.P256, null, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Exchange) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.P384, WellKnownCurveValues.P384, null, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Exchange) =>
                    BuildEc(keyMaterial, EllipticCurveTypes.P521, WellKnownCurveValues.P521, null, base64UrlEncoder),

                //RSA keys.
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) =>
                    BuildRsa(keyMaterial, base64UrlEncoder),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) =>
                    BuildRsa(keyMaterial, base64UrlEncoder),

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
                    BaseMemoryPool.Shared);
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
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Bls12381G2) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.Bls12381G2PublicKey, base58Encoder),
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

            if(!jwk.TryGetValue(WellKnownJwkMemberNames.Kty, out object? kty) || kty is not string keyType)
            {
                throw new ArgumentException($"JWK must contain a valid '{WellKnownJwkMemberNames.Kty}' field.", nameof(jwk));
            }

            ValidateRequiredFields(jwk, keyType);

            string algorithm = string.Empty;
            if(jwk.TryGetValue(WellKnownJwkMemberNames.Alg, out object? alg) && alg is string algString)
            {
                algorithm = algString;
            }

            string crv = string.Empty;
            if(jwk.TryGetValue(WellKnownJwkMemberNames.Crv, out object? crvObj) && crvObj is string crvString)
            {
                crv = crvString;
            }

            //Resolve purpose from the optional 'use' field; default to Verification.
            Purpose explicitPurpose = Purpose.Verification;
            if(jwk.TryGetValue(WellKnownJwkMemberNames.Use, out object? useObj) && useObj is string use)
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

            //EC keys are decoded to a compressed SEC1 point (see DecodeEcKey -> EllipticCurveUtilities.Compress),
            //so the tag MUST say EcCompressed — consumers that build a JWK or run point-on-curve / key agreement
            //rely on the EncodingScheme reflecting the actual bytes. OKP (Ed25519/X25519) and other key types
            //carry raw single-coordinate / opaque material.
            EncodingScheme encodingScheme = WellKnownKeyTypeValues.IsEc(keyType)
                ? EncodingScheme.EcCompressed
                : EncodingScheme.Raw;

            return (cryptoAlgorithm, purpose, encodingScheme, keyMaterialOwner);


            static void ValidateRequiredFields(Dictionary<string, object> jwk, string keyType)
            {
                if(WellKnownKeyTypeValues.IsEc(keyType))
                {
                    if(!jwk.TryGetValue(WellKnownJwkMemberNames.X, out object? ecX) || ecX is not string)
                    {
                        throw new ArgumentException($"EC JWK must contain a valid '{WellKnownJwkMemberNames.X}' field.", nameof(jwk));
                    }

                    if(!jwk.TryGetValue(WellKnownJwkMemberNames.Y, out object? ecY) || ecY is not string)
                    {
                        throw new ArgumentException($"EC JWK must contain a valid '{WellKnownJwkMemberNames.Y}' field.", nameof(jwk));
                    }
                }
                else if(WellKnownKeyTypeValues.IsOkp(keyType))
                {
                    if(!jwk.TryGetValue(WellKnownJwkMemberNames.X, out object? okpX) || okpX is not string)
                    {
                        throw new ArgumentException($"OKP JWK must contain a valid '{WellKnownJwkMemberNames.X}' field.", nameof(jwk));
                    }
                }
                else if(WellKnownKeyTypeValues.IsRsa(keyType))
                {
                    if(!jwk.TryGetValue(WellKnownJwkMemberNames.N, out object? rsaN) || rsaN is not string)
                    {
                        throw new ArgumentException($"RSA JWK must contain a valid '{WellKnownJwkMemberNames.N}' field.", nameof(jwk));
                    }

                    if(!jwk.TryGetValue(WellKnownJwkMemberNames.E, out object? rsaE) || rsaE is not string)
                    {
                        throw new ArgumentException($"RSA JWK must contain a valid '{WellKnownJwkMemberNames.E}' field.", nameof(jwk));
                    }
                }
                else if(WellKnownKeyTypeValues.IsAkp(keyType))
                {
                    if(!jwk.TryGetValue(WellKnownJwkMemberNames.Pub, out object? akpPub) || akpPub is not string)
                    {
                        throw new ArgumentException($"AKP JWK must contain a valid '{WellKnownJwkMemberNames.Pub}' field.", nameof(jwk));
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
                if(WellKnownKeyTypeValues.IsAkp(keyType)) { return DecodeAkpKey(jwk, decoder); }

                throw new ArgumentException($"Unsupported key type: '{keyType}'.");
            }


            static byte[] DecodeEcKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                using IMemoryOwner<byte> xBytes = decoder((string)jwk[WellKnownJwkMemberNames.X], BaseMemoryPool.Shared);
                using IMemoryOwner<byte> yBytes = decoder((string)jwk[WellKnownJwkMemberNames.Y], BaseMemoryPool.Shared);

                //Compressed format is the canonical internal form for all EC public keys.
                //Backend functions accept both compressed and uncompressed SEC1 encoding.
                return EllipticCurveUtilities.Compress(xBytes.Memory.Span, yBytes.Memory.Span);
            }


            static byte[] DecodeOkpKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                using IMemoryOwner<byte> decoded = decoder((string)jwk[WellKnownJwkMemberNames.X], BaseMemoryPool.Shared);

                return decoded.Memory.Span.ToArray();
            }


            static byte[] DecodeRsaKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                using IMemoryOwner<byte> decoded = decoder((string)jwk[WellKnownJwkMemberNames.N], BaseMemoryPool.Shared);

                return decoded.Memory.Span.ToArray();
            }


            static byte[] DecodeAkpKey(Dictionary<string, object> jwk, DecodeDelegate decoder)
            {
                using IMemoryOwner<byte> decoded = decoder((string)jwk[WellKnownJwkMemberNames.Pub], BaseMemoryPool.Shared);

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
                    if(WellKnownCurveValues.IsSecp256k1(crv) || WellKnownJwaValues.IsEs256K(algorithm))
                    {
                        return (CryptoAlgorithm.Secp256k1, Purpose.Verification);
                    }

                    //Brainpool curves per RFC 5639. ESB JWA fallback mirrors the ES* path
                    //above — alg alone identifies the curve when crv is absent.
                    if(WellKnownCurveValues.IsBrainpoolP256r1(crv)) { return (CryptoAlgorithm.BrainpoolP256r1, explicitPurpose); }
                    if(WellKnownCurveValues.IsBrainpoolP320r1(crv)) { return (CryptoAlgorithm.BrainpoolP320r1, explicitPurpose); }
                    if(WellKnownCurveValues.IsBrainpoolP384r1(crv)) { return (CryptoAlgorithm.BrainpoolP384r1, explicitPurpose); }
                    if(WellKnownCurveValues.IsBrainpoolP512r1(crv)) { return (CryptoAlgorithm.BrainpoolP512r1, explicitPurpose); }

                    //Fall back to alg when crv is absent.
                    if(WellKnownJwaValues.IsEs256(algorithm)) { return (CryptoAlgorithm.P256, explicitPurpose); }
                    if(WellKnownJwaValues.IsEs384(algorithm)) { return (CryptoAlgorithm.P384, explicitPurpose); }
                    if(WellKnownJwaValues.IsEs512(algorithm)) { return (CryptoAlgorithm.P521, explicitPurpose); }
                    if(WellKnownJwaValues.IsEsb256(algorithm)) { return (CryptoAlgorithm.BrainpoolP256r1, explicitPurpose); }
                    if(WellKnownJwaValues.IsEsb320(algorithm)) { return (CryptoAlgorithm.BrainpoolP320r1, explicitPurpose); }
                    if(WellKnownJwaValues.IsEsb384(algorithm)) { return (CryptoAlgorithm.BrainpoolP384r1, explicitPurpose); }
                    if(WellKnownJwaValues.IsEsb512(algorithm)) { return (CryptoAlgorithm.BrainpoolP512r1, explicitPurpose); }
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

                if(WellKnownKeyTypeValues.IsAkp(keyType))
                {
                    //An Algorithm Key Pair carries its algorithm in the REQUIRED alg member —
                    //there is no curve dimension to dispatch on.
                    if(WellKnownJwaValues.IsMlDsa44(algorithm)) { return (CryptoAlgorithm.MlDsa44, Purpose.Verification); }
                    if(WellKnownJwaValues.IsMlDsa65(algorithm)) { return (CryptoAlgorithm.MlDsa65, Purpose.Verification); }
                    if(WellKnownJwaValues.IsMlDsa87(algorithm)) { return (CryptoAlgorithm.MlDsa87, Purpose.Verification); }
                }

                throw new ArgumentException($"Unsupported key type or algorithm: '{keyType}', '{algorithm}'.");
            }
        };


        /// <summary>
        /// Default converter from a multibase-encoded <c>did:key</c> suffix to its algorithm
        /// representation. Accepts the two multibase forms the <c>did:key</c> ABNF
        /// <c>mb-value := z(base58btc) | u(base64url)</c> permits: the base58btc <c>z</c> form
        /// (the canonical form, decoded with the supplied <paramref name="multibaseDecoder"/>)
        /// and the base64url <c>u</c> form (decoded inline, since the supplied decoder is the
        /// base58 one). Both forms decode to the same <c>multicodec-varint || raw-key</c> bytes,
        /// which a single classifier maps to the algorithm and validates the raw-key length
        /// against (the <c>did:key</c> <c>invalidPublicKeyLength</c> check).
        /// </summary>
        public static Base58ToAlgorithmDelegate DefaultBase58ToAlgorithmConverter => (multibaseKey, memoryPool, multibaseDecoder) =>
        {
            if(string.IsNullOrWhiteSpace(multibaseKey))
            {
                throw new ArgumentNullException(nameof(multibaseKey), "Multibase key cannot be null or empty.");
            }

            char multibasePrefix = multibaseKey[0];

            //Decode the multibase payload (everything after the prefix character) into the raw
            //multicodec-prefixed bytes. The base58btc form goes through the supplied decoder; the
            //base64url form is decoded inline because the did:key ABNF allows it and the supplied
            //decoder is base58-only.
            IMemoryOwner<byte> prefixedBytes = multibasePrefix switch
            {
                var p when p.Equals(MultibaseAlgorithms.Base58Btc) => multibaseDecoder(multibaseKey.AsSpan(1), memoryPool),
                var p when p.Equals(MultibaseAlgorithms.Base64Url) => DecodeBase64UrlPayload(multibaseKey.AsSpan(1), memoryPool),
                _ => throw new ArgumentException(
                    $"Multibase key must start with '{MultibaseAlgorithms.Base58Btc}' (base58btc) or '{MultibaseAlgorithms.Base64Url}' (base64url).",
                    nameof(multibaseKey))
            };

            using(prefixedBytes)
            {
                return ClassifyMulticodecPublicKey(prefixedBytes.Memory.Span, memoryPool);
            }
        };


        //Decodes a base64url-encoded multibase payload into pooled memory, mirroring the shape the
        //base58 DecodeDelegate produces (the full multicodec-prefixed key bytes).
        private static IMemoryOwner<byte> DecodeBase64UrlPayload(ReadOnlySpan<char> payload, MemoryPool<byte> memoryPool)
        {
            int maxLength = System.Buffers.Text.Base64Url.GetMaxDecodedLength(payload.Length);
            IMemoryOwner<byte> buffer = memoryPool.Rent(maxLength);
            try
            {
                if(System.Buffers.Text.Base64Url.DecodeFromChars(payload, buffer.Memory.Span, out _, out int bytesWritten) != System.Buffers.OperationStatus.Done)
                {
                    throw new FormatException("The base64url 'u' multibase payload is not valid base64url.");
                }

                IMemoryOwner<byte> exact = memoryPool.Rent(bytesWritten);
                buffer.Memory.Span[..bytesWritten].CopyTo(exact.Memory.Span);

                return exact;
            }
            finally
            {
                buffer.Dispose();
            }
        }


        //Maps the leading multicodec varint of a decoded did:key payload to its algorithm, strips the
        //header, validates the remaining raw-key length against the spec's expected length for the key
        //type (the did:key invalidPublicKeyLength check), and copies the raw key into its own pooled buffer.
        private static (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> KeyMaterial) ClassifyMulticodecPublicKey(
            ReadOnlySpan<byte> prefixedBytes,
            MemoryPool<byte> memoryPool)
        {
            //All registered did:key multicodec headers are two bytes. A payload shorter than that cannot
            //carry a header plus a key body, so it is malformed input rather than an unknown algorithm.
            const int MulticodecHeaderLength = 2;
            if(prefixedBytes.Length < MulticodecHeaderLength)
            {
                throw new ArgumentException("Decoded did:key payload is too short to carry a multicodec header.");
            }

            ReadOnlySpan<byte> header = prefixedBytes[..MulticodecHeaderLength];
            int rawLength = prefixedBytes.Length - MulticodecHeaderLength;

            //EC multicodec public keys are compressed SEC1 points (e.g. p256-pub is 33 bytes), so the
            //tag carries EcCompressed; the OKP keys (Ed25519/X25519) and RSA/BLS stay Raw.
            (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, int ExpectedRawLength) classified = header switch
            {
                var h when MulticodecHeaders.IsSecp256k1PublicKey(h) => (CryptoAlgorithm.Secp256k1, Purpose.Verification, EncodingScheme.EcCompressed, 33),
                var h when MulticodecHeaders.IsEd25519PublicKey(h) => (CryptoAlgorithm.Ed25519, Purpose.Verification, EncodingScheme.Raw, 32),
                var h when MulticodecHeaders.IsX25519PublicKey(h) => (CryptoAlgorithm.X25519, Purpose.Exchange, EncodingScheme.Raw, 32),
                var h when MulticodecHeaders.IsP256PublicKey(h) => (CryptoAlgorithm.P256, Purpose.Verification, EncodingScheme.EcCompressed, 33),
                var h when MulticodecHeaders.IsP384PublicKey(h) => (CryptoAlgorithm.P384, Purpose.Verification, EncodingScheme.EcCompressed, 49),
                var h when MulticodecHeaders.IsP521PublicKey(h) => (CryptoAlgorithm.P521, Purpose.Verification, EncodingScheme.EcCompressed, 67),
                var h when MulticodecHeaders.IsBls12381G2PublicKey(h) => (CryptoAlgorithm.Bls12381G2, Purpose.Verification, EncodingScheme.Raw, 96),

                //RSA public keys are DER-encoded RSAPublicKey structures whose length is the modulus length
                //plus DER framing rather than a fixed coordinate width, so the two registered sizes are matched
                //against the actual modulus-derived encoding length (270 bytes for 2048-bit, 526 for 4096-bit).
                var h when MulticodecHeaders.IsRsaPublicKey(h) => ClassifyRsa(rawLength),
                _ => throw new ArgumentException("Unknown or unsupported multicodec header.")
            };

            //invalidPublicKeyLength per did:key §Decode/§Signature Method: a recognized header with a
            //wrong-length body MUST be rejected rather than surfaced as a malformed verification method.
            if(rawLength != classified.ExpectedRawLength)
            {
                throw new ArgumentException(
                    $"Decoded public key length '{rawLength}' does not match the expected length '{classified.ExpectedRawLength}' for '{classified.Algorithm}'.");
            }

            IMemoryOwner<byte> rawKey = memoryPool.Rent(rawLength);
            prefixedBytes[MulticodecHeaderLength..].CopyTo(rawKey.Memory.Span);

            return (classified.Algorithm, classified.Purpose, classified.Scheme, rawKey);
        }


        //RSA did:key payloads share one multicodec header (rsa-pub) across modulus sizes; the registered
        //sizes are distinguished by the DER-encoded RSAPublicKey length (270 bytes for a 2048-bit modulus,
        //526 for a 4096-bit modulus). An unrecognized length is rejected as invalidPublicKeyLength.
        private static (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, int ExpectedRawLength) ClassifyRsa(int rawLength) => rawLength switch
        {
            270 => (CryptoAlgorithm.Rsa2048, Purpose.Verification, EncodingScheme.Raw, 270),
            526 => (CryptoAlgorithm.Rsa4096, Purpose.Verification, EncodingScheme.Raw, 526),
            _ => throw new ArgumentException($"Unsupported RSA public key encoding length: '{rawLength}' bytes.")
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

                //Brainpool ECDH-ES exchange curves (RFC 5639). The crv name is
                //purpose-independent, so the same mapping serves both the signing tags
                //and the exchange tags.
                var a when a.Equals(CryptoAlgorithm.BrainpoolP256r1) => WellKnownCurveValues.BrainpoolP256r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP320r1) => WellKnownCurveValues.BrainpoolP320r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP384r1) => WellKnownCurveValues.BrainpoolP384r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP512r1) => WellKnownCurveValues.BrainpoolP512r1,

                //X25519 ECDH-ES exchange (RFC 8037 OKP). The crv name carries it; the OKP
                //single-coordinate JWK shape is decided from the key's EncodingScheme.Raw tag.
                var a when a.Equals(CryptoAlgorithm.X25519) => WellKnownCurveValues.X25519,
                _ => throw new NotSupportedException(
                    $"CryptoAlgorithm '{algorithm}' does not have a JWK curve name mapping. " +
                    $"Only EC curves P-256, P-384, P-521, Brainpool P-256r1/P-320r1/P-384r1/P-512r1 and X25519 are supported.")
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

                //Brainpool ECDH-ES exchange curves (RFC 5639). The curve type drives the
                //point-on-curve validation that guards against invalid-curve attacks.
                var c when WellKnownCurveValues.IsBrainpoolP256r1(c) => (CryptoTags.BrainpoolP256r1ExchangePublicKey, EllipticCurveTypes.BrainpoolP256r1),
                var c when WellKnownCurveValues.IsBrainpoolP320r1(c) => (CryptoTags.BrainpoolP320r1ExchangePublicKey, EllipticCurveTypes.BrainpoolP320r1),
                var c when WellKnownCurveValues.IsBrainpoolP384r1(c) => (CryptoTags.BrainpoolP384r1ExchangePublicKey, EllipticCurveTypes.BrainpoolP384r1),
                var c when WellKnownCurveValues.IsBrainpoolP512r1(c) => (CryptoTags.BrainpoolP512r1ExchangePublicKey, EllipticCurveTypes.BrainpoolP512r1),

                //X25519 (RFC 8037 OKP). EllipticCurveTypes.None signals "no EC point-on-curve
                //check"; the Raw-encoded tag drives the OKP single-coordinate decode path.
                var c when WellKnownCurveValues.IsX25519(c) => (CryptoTags.X25519PublicKey, EllipticCurveTypes.None),
                _ => throw new NotSupportedException(
                    $"JWK curve name '{crv}' does not have a mapping. " +
                    $"Only EC curves P-256, P-384, P-521, Brainpool P-256r1/P-320r1/P-384r1/P-512r1 and X25519 are supported.")
            };
        };


        /// <summary>
        /// Default converter from a COSE_Key's (<c>kty</c>, <c>crv</c>) tuple
        /// to a <see cref="Tag"/> describing the corresponding internal key
        /// material. Used by the mdoc MSO <c>DeviceKeyInfo</c> path to bridge
        /// the parsed COSE_Key view onto the registry-resolvable tags the
        /// crypto pipeline expects.
        /// </summary>
        /// <remarks>
        /// <para>
        /// COSE Key Types and Elliptic Curves use the integer assignments
        /// from RFC 9052 §7 and the IANA COSE Elliptic Curves registry. The
        /// converter accepts both EC2 (NIST P-curves, secp256k1, Brainpool
        /// r1) and OKP (Ed25519, X25519, X448) keys. RSA mapping is included
        /// for completeness but cannot pick a key size from <c>kty</c> alone —
        /// the caller resolves size from the modulus length downstream.
        /// </para>
        /// </remarks>
        public static CoseKeyToAlgorithmDelegate DefaultCoseKeyToAlgorithmConverter => (kty, curve, purpose) =>
        {
            //EC2 keys (RFC 9052 §7.1, kty = 2): curve discriminator is required.
            const int Kty_Okp = 1;
            const int Kty_Ec2 = 2;
            const int Kty_Rsa = 3;

            //COSE Elliptic Curves registry assignments. X448/Ed448 are kept
            //alongside in the registry but no corresponding CryptoTags exist
            //today; they fall through to the NotSupportedException arm.
            const int Crv_P256 = 1;
            const int Crv_P384 = 2;
            const int Crv_P521 = 3;
            const int Crv_X25519 = 4;
            const int Crv_Ed25519 = 6;
            const int Crv_Secp256k1 = 8;
            const int Crv_BrainpoolP256r1 = 256;
            const int Crv_BrainpoolP320r1 = 257;
            const int Crv_BrainpoolP384r1 = 258;
            const int Crv_BrainpoolP512r1 = 259;

            return (kty, curve, purpose) switch
            {
                //EC2 — NIST P-curves with signing purpose pick private-key tags,
                //verification picks public-key tags. Brainpool follows the same
                //pattern landed in Q.2.
                (Kty_Ec2, Crv_P256, var p) when p.Equals(Purpose.Signing) => CryptoTags.P256PrivateKey,
                (Kty_Ec2, Crv_P256, var p) when p.Equals(Purpose.Verification) => CryptoTags.P256PublicKey,
                (Kty_Ec2, Crv_P384, var p) when p.Equals(Purpose.Signing) => CryptoTags.P384PrivateKey,
                (Kty_Ec2, Crv_P384, var p) when p.Equals(Purpose.Verification) => CryptoTags.P384PublicKey,
                (Kty_Ec2, Crv_P521, var p) when p.Equals(Purpose.Signing) => CryptoTags.P521PrivateKey,
                (Kty_Ec2, Crv_P521, var p) when p.Equals(Purpose.Verification) => CryptoTags.P521PublicKey,
                (Kty_Ec2, Crv_Secp256k1, var p) when p.Equals(Purpose.Signing) => CryptoTags.Secp256k1PrivateKey,
                (Kty_Ec2, Crv_Secp256k1, var p) when p.Equals(Purpose.Verification) => CryptoTags.Secp256k1PublicKey,
                (Kty_Ec2, Crv_BrainpoolP256r1, var p) when p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP256r1PrivateKey,
                (Kty_Ec2, Crv_BrainpoolP256r1, var p) when p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP256r1PublicKey,
                (Kty_Ec2, Crv_BrainpoolP320r1, var p) when p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP320r1PrivateKey,
                (Kty_Ec2, Crv_BrainpoolP320r1, var p) when p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP320r1PublicKey,
                (Kty_Ec2, Crv_BrainpoolP384r1, var p) when p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP384r1PrivateKey,
                (Kty_Ec2, Crv_BrainpoolP384r1, var p) when p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP384r1PublicKey,
                (Kty_Ec2, Crv_BrainpoolP512r1, var p) when p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP512r1PrivateKey,
                (Kty_Ec2, Crv_BrainpoolP512r1, var p) when p.Equals(Purpose.Verification) => CryptoTags.BrainpoolP512r1PublicKey,

                //OKP — Ed25519 / X25519. Ed25519 is signing/verification;
                //X25519 is exchange. Ed448 / X448 are recognised on the COSE
                //side but not currently registered in CryptoTags.
                (Kty_Okp, Crv_Ed25519, var p) when p.Equals(Purpose.Signing) => CryptoTags.Ed25519PrivateKey,
                (Kty_Okp, Crv_Ed25519, var p) when p.Equals(Purpose.Verification) => CryptoTags.Ed25519PublicKey,
                (Kty_Okp, Crv_X25519, var p) when p.Equals(Purpose.Exchange) => CryptoTags.X25519PublicKey,

                //RSA — kty alone can't pick size; caller resolves from modulus.
                //Surface the mismatch rather than guessing.
                (Kty_Rsa, _, _) => throw new NotSupportedException(
                    "COSE_Key kty=3 (RSA) requires modulus-length resolution outside this delegate."),

                _ => throw new NotSupportedException(
                    $"COSE_Key (kty={kty.ToString(System.Globalization.CultureInfo.InvariantCulture)}, " +
                    $"crv={curve?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "n/a"}, " +
                    $"purpose={purpose}) is not supported.")
            };
        };
    }
}
