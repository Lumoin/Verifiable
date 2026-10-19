using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
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
    public delegate string AlgorithmToBase58Delegate(CryptoAlgorithm algorithm, Purpose purpose, ReadOnlySpan<byte> keyMaterial, EncodeDelegate base58Encoder, BaseMemoryPool pool);

    /// <summary>
    /// Delegate for converting JWK to algorithm representation.
    /// </summary>
    public delegate JwkKeyReconstruction JwkToAlgorithmDelegate(Dictionary<string, object> jwk, BaseMemoryPool memoryPool, DecodeDelegate base64UrlDecoder);

    /// <summary>
    /// Delegate for converting Base58 key to algorithm representation.
    /// </summary>
    public delegate (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> keyMaterial) Base58ToAlgorithmDelegate(string base58Key, BaseMemoryPool memoryPool, DecodeDelegate base58Decoder);

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

                //RFC 9864 / draft-ietf-jose-fully-specified-algorithms Brainpool ECDSA signing.
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

            return ResolveJwaAlgorithm(tag) is { IsNamed: true, Algorithm: string named }
                ? named
                : throw new NotSupportedException($"CryptoAlgorithm '{tag.Get<CryptoAlgorithm>()}' does not have a JWA mapping.");
        };


        /// <summary>
        /// Resolves the JWA algorithm the library names a key of <paramref name="tag"/> by, the one table
        /// <see cref="DefaultTagToJwaConverter"/> reads: a key type the table names no algorithm for resolves as
        /// <see cref="JwaAlgorithmResolution.NoneNamed"/> rather than raising.
        /// </summary>
        /// <param name="tag">The tag containing algorithm information.</param>
        /// <returns>The algorithm the library names the key type by, or the resolution naming none.</returns>
        public static JwaAlgorithmResolution ResolveJwaAlgorithm(Tag tag)
        {
            ArgumentNullException.ThrowIfNull(tag);

            var algorithm = tag.Get<CryptoAlgorithm>();

            return algorithm switch
            {
                var a when a.Equals(CryptoAlgorithm.P256) => JwaAlgorithmResolution.Named(WellKnownJwaValues.Es256),
                var a when a.Equals(CryptoAlgorithm.P384) => JwaAlgorithmResolution.Named(WellKnownJwaValues.Es384),
                var a when a.Equals(CryptoAlgorithm.P521) => JwaAlgorithmResolution.Named(WellKnownJwaValues.Es512),
                var a when a.Equals(CryptoAlgorithm.Secp256k1) => JwaAlgorithmResolution.Named(WellKnownJwaValues.Es256K),
                var a when a.Equals(CryptoAlgorithm.Ed25519) => JwaAlgorithmResolution.Named(WellKnownJwaValues.EdDsa),
                var a when a.Equals(CryptoAlgorithm.Rsa2048) || a.Equals(CryptoAlgorithm.Rsa4096) => JwaAlgorithmResolution.Named(WellKnownJwaValues.Rs256),
                var a when a.Equals(CryptoAlgorithm.MlDsa44) => JwaAlgorithmResolution.Named(WellKnownJwaValues.MlDsa44),
                var a when a.Equals(CryptoAlgorithm.MlDsa65) => JwaAlgorithmResolution.Named(WellKnownJwaValues.MlDsa65),
                var a when a.Equals(CryptoAlgorithm.MlDsa87) => JwaAlgorithmResolution.Named(WellKnownJwaValues.MlDsa87),
                var a when a.Equals(CryptoAlgorithm.BrainpoolP256r1) => JwaAlgorithmResolution.Named(WellKnownJwaValues.Esb256),
                var a when a.Equals(CryptoAlgorithm.BrainpoolP320r1) => JwaAlgorithmResolution.Named(WellKnownJwaValues.Esb320),
                var a when a.Equals(CryptoAlgorithm.BrainpoolP384r1) => JwaAlgorithmResolution.Named(WellKnownJwaValues.Esb384),
                var a when a.Equals(CryptoAlgorithm.BrainpoolP512r1) => JwaAlgorithmResolution.Named(WellKnownJwaValues.Esb512),
                _ => JwaAlgorithmResolution.NoneNamed
            };
        }


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

                //RFC 9864 fully-specified ECDSA (signing). Maps to the same
                //P-curve key tags as the non-fully-specified ES variants —
                //ESP pins the hash explicitly but the key material is the
                //same EC key on the same curve.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp256(alg) && p.Equals(Purpose.Signing) => CryptoTags.P256PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp384(alg) && p.Equals(Purpose.Signing) => CryptoTags.P384PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp512(alg) && p.Equals(Purpose.Signing) => CryptoTags.P521PrivateKey,

                //RFC 9864 fully-specified ECDSA (verification).
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp256(alg) && p.Equals(Purpose.Verification) => CryptoTags.P256PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp384(alg) && p.Equals(Purpose.Verification) => CryptoTags.P384PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsp512(alg) && p.Equals(Purpose.Verification) => CryptoTags.P521PublicKey,

                //RFC 9864 Brainpool ECDSA (signing). Hash binding per RFC 9864 §5:
                //ESB256 → SHA-256, ESB320 → SHA-384, ESB384 → SHA-384, ESB512 → SHA-512.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb256(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP256r1PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb320(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP320r1PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb384(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP384r1PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsEsb512(alg) && p.Equals(Purpose.Signing) => CryptoTags.BrainpoolP512r1PrivateKey,

                //RFC 9864 Brainpool ECDSA (verification).
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

                //RSA PKCS#1 v1.5 signing. As with RSA PSS above, the tag names the
                //2048-bit key; the actual modulus size is resolved where the modulus
                //is visible (CoseKeyExtensions), not from the algorithm identifier alone.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsRs256(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsRs384(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsRs512(alg) && p.Equals(Purpose.Signing) => CryptoTags.Rsa2048PrivateKey,

                //RSA PKCS#1 v1.5 verification.
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsRs256(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsRs384(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,
                (int alg, Purpose p) when WellKnownCoseAlgorithms.IsRs512(alg) && p.Equals(Purpose.Verification) => CryptoTags.Rsa2048PublicKey,

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
        /// Maps a COSE algorithm identifier to the corresponding <see cref="CryptoAlgorithm"/>.
        /// </summary>
        /// <param name="algorithm">
        /// The COSE algorithm identifier, as registered in the
        /// <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms</see>
        /// registry (e.g. <c>-7</c> for ES256, <c>-257</c> for RS256).
        /// </param>
        /// <returns>
        /// The corresponding <see cref="CryptoAlgorithm"/>, or <see langword="null"/> if
        /// <paramref name="algorithm"/> has no mapping.
        /// </returns>
        /// <remarks>
        /// See <see href="https://www.rfc-editor.org/rfc/rfc9053">RFC 9053 - COSE Algorithms</see>,
        /// <see href="https://www.rfc-editor.org/rfc/rfc8812">RFC 8812</see>, and the
        /// <see href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">IANA COSE Algorithms</see>
        /// registry. The RSA arms (<see cref="CryptoAlgorithm.RsaSha256"/>,
        /// <see cref="CryptoAlgorithm.RsaSha256Pss"/>, <see cref="CryptoAlgorithm.RsaSha384"/>,
        /// <see cref="CryptoAlgorithm.RsaSha384Pss"/>, <see cref="CryptoAlgorithm.RsaSha512"/>,
        /// <see cref="CryptoAlgorithm.RsaSha512Pss"/>) identify a padding-and-hash family only —
        /// they carry no key size. The modulus size (2048 vs 4096 bit) is resolved separately,
        /// where the modulus bytes are visible (<see cref="CoseKeyExtensions"/>).
        /// </remarks>
        public static CryptoAlgorithm? CoseAlgorithmToCryptoAlgorithm(int algorithm) => algorithm switch
        {
            var a when WellKnownCoseAlgorithms.IsEs256(a) => CryptoAlgorithm.P256,
            var a when WellKnownCoseAlgorithms.IsEs384(a) => CryptoAlgorithm.P384,
            var a when WellKnownCoseAlgorithms.IsEs512(a) => CryptoAlgorithm.P521,
            var a when WellKnownCoseAlgorithms.IsEs256K(a) => CryptoAlgorithm.Secp256k1,
            var a when WellKnownCoseAlgorithms.IsRs256(a) => CryptoAlgorithm.RsaSha256,
            var a when WellKnownCoseAlgorithms.IsPs256(a) => CryptoAlgorithm.RsaSha256Pss,
            var a when WellKnownCoseAlgorithms.IsRs384(a) => CryptoAlgorithm.RsaSha384,
            var a when WellKnownCoseAlgorithms.IsPs384(a) => CryptoAlgorithm.RsaSha384Pss,
            var a when WellKnownCoseAlgorithms.IsRs512(a) => CryptoAlgorithm.RsaSha512,
            var a when WellKnownCoseAlgorithms.IsPs512(a) => CryptoAlgorithm.RsaSha512Pss,
            var a when WellKnownCoseAlgorithms.IsEdDsa(a) => CryptoAlgorithm.Ed25519,
            _ => null
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
                (byte[] modulus, byte[] exponent) = RsaPublicKeyEncoding.Decode(keyMaterial);

                return new JsonWebKey
                {
                    Kty = WellKnownKeyTypeValues.Rsa,
                    Alg = WellKnownJwaValues.Rs256,
                    N = encoder(modulus),
                    E = encoder(exponent)
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

                //Brainpool ECDSA verification keys per RFC 5639 / RFC 9864.
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
        public static AlgorithmToBase58Delegate DefaultAlgorithmToBase58Converter => (algorithm, purpose, keyMaterial, base58Encoder, pool) =>
        {
            static string EncodeKey(
                ReadOnlySpan<byte> keyMaterial,
                ReadOnlySpan<byte> multicodecHeader,
                EncodeDelegate encoder,
                BaseMemoryPool pool)
            {
                return MultibaseSerializer.Encode(
                    keyMaterial,
                    multicodecHeader,
                    MultibaseAlgorithms.Base58Btc,
                    encoder,
                    pool);
            }

            return (algorithm, purpose) switch
            {
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P256) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.P256PublicKey, base58Encoder, pool),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P384) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.P384PublicKey, base58Encoder, pool),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.P521) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.P521PublicKey, base58Encoder, pool),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Secp256k1) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.Secp256k1PublicKey, base58Encoder, pool),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa2048) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.RsaPublicKey, base58Encoder, pool),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Rsa4096) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.RsaPublicKey, base58Encoder, pool),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Bls12381G1) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.Bls12381G1PublicKey, base58Encoder, pool),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Bls12381G2) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.Bls12381G2PublicKey, base58Encoder, pool),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.Ed25519) && p.Equals(Purpose.Verification) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.Ed25519PublicKey, base58Encoder, pool),
                (CryptoAlgorithm a, Purpose p) when a.Equals(CryptoAlgorithm.X25519) && p.Equals(Purpose.Exchange) =>
                    EncodeKey(keyMaterial, MulticodecHeaders.X25519PublicKey, base58Encoder, pool),

                _ => throw new ArgumentException($"Unknown combination of algorithm and purpose: '{algorithm}', '{purpose}'.")
            };
        };


        /// <summary>
        /// Default converter from JWK to algorithm representation. The key's type is read first and each type's members once: an
        /// EC or OKP key's curve is REQUIRED (RFC 7518 section 6.2.1.1, RFC 8037 section 2) and is resolved once, before any
        /// coordinate is decoded, to the one curve the conversion then uses; an <c>alg</c> the library recognizes for no key of
        /// that curve contradicts it, and an <c>alg</c> never stands in for an absent or unknown curve. The reconstructed key is
        /// answered as <see cref="JwkKeyReconstructed"/>, which hands the caller its material; the converter's refusal of a JWK as
        /// <see cref="JwkKeyRefused"/> with its <see cref="JwkPublicKeyFailureKind"/>: a member its type requires absent or of
        /// another JSON type, a member the decoder refuses as no base64url text (its <see cref="FormatException"/>), a type or curve
        /// it reconstructs no key of, a curve and an algorithm that contradict each other, an algorithm or size it reconstructs no
        /// key of, EC coordinates that are not each the full width of the curve's coordinate or name no point of it (RFC 7518
        /// sections 6.2.1.2 and 6.2.1.3), judged before the point is compressed, or an RSA modulus or public exponent no RSA key
        /// has. Any other failure of the decoder or of the allocator is theirs and surfaces as it is.
        /// </summary>
        /// <remarks>
        /// Resolves <see cref="Purpose"/> from the optional JWK <c>use</c> field
        /// (<c>sig</c> → <see cref="Purpose.Verification"/>,
        /// <c>enc</c> → <see cref="Purpose.Exchange"/>). When absent, defaults to
        /// <see cref="Purpose.Verification"/> for EC and OKP keys, consistent with
        /// the most common use case.
        /// </remarks>
        public static JwkToAlgorithmDelegate DefaultJwkToAlgorithmConverter => static (jwk, memoryPool, base64UrlDecoder) =>
            ReconstructJwk(jwk, memoryPool, base64UrlDecoder);


        /// <summary>The reconstruction <see cref="DefaultJwkToAlgorithmConverter"/> answers.</summary>
        /// <param name="jwk">The JWK's members.</param>
        /// <param name="memoryPool">The pool the key material is rented from.</param>
        /// <param name="decoder">The decoder of the key's base64url members.</param>
        /// <returns>The key reconstructed, or the refusal.</returns>
        private static JwkKeyReconstruction ReconstructJwk(Dictionary<string, object> jwk, BaseMemoryPool memoryPool, DecodeDelegate decoder)
        {
            ArgumentNullException.ThrowIfNull(jwk);
            ArgumentNullException.ThrowIfNull(memoryPool);
            ArgumentNullException.ThrowIfNull(decoder);

            if(!TryRequiredMember(jwk, WellKnownJwkMemberNames.Kty, "A JWK", out var keyType, out var refusal)
                || !TryOptionalMember(jwk, WellKnownJwkMemberNames.Alg, out var algorithm, out refusal))
            {
                return refusal;
            }

            //Resolve purpose from the optional 'use' field; default to Verification.
            var explicitPurpose = Purpose.Verification;
            if(jwk.TryGetValue(WellKnownJwkMemberNames.Use, out var useObj) && useObj is string use)
            {
                explicitPurpose = WellKnownJwkValues.Equals(use, WellKnownJwkValues.UseEnc) ? Purpose.Exchange : Purpose.Verification;
            }

            var reconstruction = keyType switch
            {
                var kt when WellKnownKeyTypeValues.IsEc(kt) => ReconstructEcKey(jwk, algorithm, explicitPurpose, decoder, memoryPool),
                var kt when WellKnownKeyTypeValues.IsOkp(kt) => ReconstructOkpKey(jwk, algorithm, decoder, memoryPool),
                var kt when WellKnownKeyTypeValues.IsRsa(kt) => ReconstructRsaKey(jwk, decoder, memoryPool),
                var kt when WellKnownKeyTypeValues.IsAkp(kt) => ReconstructAkpKey(jwk, algorithm, decoder, memoryPool),
                _ => new ReconstructionRefused(new JwkKeyRefused(JwkPublicKeyFailureKind.UnsupportedKeyType, $"Unsupported key type: '{keyType}'."))
            };

            if(reconstruction is ReconstructionRefused refused)
            {
                return refused.Refusal;
            }

            if(reconstruction is not ReconstructedJwkKey reconstructed)
            {
                throw new InvalidOperationException("The reconstruction of a key type answered a reconstruction it never answers.");
            }

            var keyMaterialOwner = memoryPool.Rent(reconstructed.KeyMaterial.Length);
            reconstructed.KeyMaterial.CopyTo(keyMaterialOwner.Memory.Span);

            //EC keys are decoded to a compressed SEC1 point (see ReconstructEcKey -> EllipticCurveUtilities.Compress),
            //so the tag MUST say EcCompressed — consumers that build a JWK or run point-on-curve / key agreement
            //rely on the EncodingScheme reflecting the actual bytes. RSA carries both parameters in DER;
            //OKP (Ed25519/X25519) and other key types carry raw single-coordinate / opaque material.
            var encodingScheme = WellKnownKeyTypeValues.IsEc(keyType)
                ? EncodingScheme.EcCompressed
                : WellKnownKeyTypeValues.IsRsa(keyType) ? EncodingScheme.Der : EncodingScheme.Raw;

            return new JwkKeyReconstructed(reconstructed.Algorithm, reconstructed.Purpose, encodingScheme, keyMaterialOwner);
        }


        /// <summary>
        /// The EC key a JWK states. RFC 7518 sections 6.2.1.2 and 6.2.1.3: x and y are each the full width of the curve's
        /// coordinate, and the point they name lies on the curve (NIST SP 800-186 appendix D.1.1.1), judged on the coordinates as
        /// supplied before the point is compressed: compression keeps x and the parity of y alone, which would turn coordinates
        /// naming no point into a point.
        /// </summary>
        /// <param name="jwk">The JWK's members.</param>
        /// <param name="algorithm">The JWK's <c>alg</c>, empty when absent.</param>
        /// <param name="explicitPurpose">The purpose the JWK's <c>use</c> states.</param>
        /// <param name="decoder">The decoder of the coordinates.</param>
        /// <param name="pool">The pool the coordinates are rented from.</param>
        /// <returns>The key, or the refusal.</returns>
        private static KeyReconstruction ReconstructEcKey(Dictionary<string, object> jwk, string algorithm, Purpose explicitPurpose, DecodeDelegate decoder, BaseMemoryPool pool)
        {
            if(!TryRequiredMember(jwk, WellKnownJwkMemberNames.Crv, "An EC JWK", out var crv, out var refusal)
                || !TryRequiredMember(jwk, WellKnownJwkMemberNames.X, "An EC JWK", out var x, out refusal)
                || !TryRequiredMember(jwk, WellKnownJwkMemberNames.Y, "An EC JWK", out var y, out refusal)
                || !TryEcCurveOf(crv, algorithm, out var curve, out refusal))
            {
                return new ReconstructionRefused(refusal);
            }

            using var xBytes = DecodedMemberOrNone(decoder, x, pool);
            using var yBytes = DecodedMemberOrNone(decoder, y, pool);

            if(xBytes is null || yBytes is null)
            {
                return NotBase64UrlText(xBytes is null ? WellKnownJwkMemberNames.X : WellKnownJwkMemberNames.Y);
            }

            if(!EllipticCurveUtilities.CheckPointOnCurve(xBytes.Memory.Span, yBytes.Memory.Span, EllipticCurveUtilities.CurveTypeFor(curve)))
            {
                return new ReconstructionRefused(new JwkKeyRefused(
                    JwkPublicKeyFailureKind.NotAPointOfTheCurve, $"The EC JWK's coordinates are not of the width of curve '{crv}' or name no point of it."));
            }

            //Compressed format is the canonical internal form for all EC public keys. Backend functions accept both compressed and
            //uncompressed SEC1 encoding. secp256k1 keys verify only: the library performs no key agreement on that curve.
            var purpose = curve.Equals(CryptoAlgorithm.Secp256k1) ? Purpose.Verification : explicitPurpose;

            return new ReconstructedJwkKey(curve, purpose, EllipticCurveUtilities.Compress(xBytes.Memory.Span, yBytes.Memory.Span));
        }


        /// <summary>The OKP key a JWK states (RFC 8037 section 2).</summary>
        /// <param name="jwk">The JWK's members.</param>
        /// <param name="algorithm">The JWK's <c>alg</c>, empty when absent.</param>
        /// <param name="decoder">The decoder of the public key.</param>
        /// <param name="pool">The pool the public key is rented from.</param>
        /// <returns>The key, or the refusal.</returns>
        private static KeyReconstruction ReconstructOkpKey(Dictionary<string, object> jwk, string algorithm, DecodeDelegate decoder, BaseMemoryPool pool)
        {
            if(!TryRequiredMember(jwk, WellKnownJwkMemberNames.Crv, "An OKP JWK", out var crv, out var refusal)
                || !TryRequiredMember(jwk, WellKnownJwkMemberNames.X, "An OKP JWK", out var x, out refusal)
                || !TryOkpCurveOf(crv, algorithm, out var curve, out refusal))
            {
                return new ReconstructionRefused(refusal);
            }

            using var decoded = DecodedMemberOrNone(decoder, x, pool);

            return decoded is null
                ? NotBase64UrlText(WellKnownJwkMemberNames.X)
                : new ReconstructedJwkKey(curve.Algorithm, curve.Purpose, decoded.Memory.Span.ToArray());
        }


        /// <summary>
        /// The RSA key a JWK states (RFC 7518 section 6.3.1): its modulus and public exponent, an RSA key's only when the modulus
        /// is positive and the exponent odd with <c>3 &lt;= e &lt; n</c>, encoded together as a DER PKCS#1 public key.
        /// </summary>
        /// <param name="jwk">The JWK's members.</param>
        /// <param name="decoder">The decoder of the parameters.</param>
        /// <param name="pool">The pool the parameters are rented from.</param>
        /// <returns>The key, or the refusal.</returns>
        private static KeyReconstruction ReconstructRsaKey(Dictionary<string, object> jwk, DecodeDelegate decoder, BaseMemoryPool pool)
        {
            if(!TryRequiredMember(jwk, WellKnownJwkMemberNames.N, "An RSA JWK", out var n, out var refusal)
                || !TryRequiredMember(jwk, WellKnownJwkMemberNames.E, "An RSA JWK", out var e, out refusal))
            {
                return new ReconstructionRefused(refusal);
            }

            using var modulus = DecodedMemberOrNone(decoder, n, pool);
            using var exponent = DecodedMemberOrNone(decoder, e, pool);

            if(modulus is null || exponent is null)
            {
                return NotBase64UrlText(modulus is null ? WellKnownJwkMemberNames.N : WellKnownJwkMemberNames.E);
            }

            if(RsaPublicKeyEncoding.ParameterDefectOf(modulus.Memory.Span, exponent.Memory.Span) is { } parameterDefect)
            {
                return new ReconstructionRefused(parameterDefect == RsaPublicKeyFailureKind.InvalidModulus
                    ? new JwkKeyRefused(JwkPublicKeyFailureKind.RsaModulusInvalid, "The RSA JWK's modulus is not a positive integer.")
                    : new JwkKeyRefused(JwkPublicKeyFailureKind.RsaPublicExponentInvalid, "The RSA JWK's public exponent is not odd with 3 <= e < n."));
            }

            var keyMaterial = RsaPublicKeyEncoding.Encode(modulus.Memory.Span, exponent.Memory.Span);
            var keySize = new BigInteger(modulus.Memory.Span, isUnsigned: true, isBigEndian: true).GetByteCount(isUnsigned: true);

            return keySize switch
            {
                256 => new ReconstructedJwkKey(CryptoAlgorithm.Rsa2048, Purpose.Verification, keyMaterial),
                512 => new ReconstructedJwkKey(CryptoAlgorithm.Rsa4096, Purpose.Verification, keyMaterial),
                _ => new ReconstructionRefused(new JwkKeyRefused(JwkPublicKeyFailureKind.UnsupportedCurveOrAlgorithm, $"Unsupported RSA key size: '{keySize}' bytes."))
            };
        }


        /// <summary>
        /// The Algorithm Key Pair key a JWK states: it carries its algorithm in the REQUIRED <c>alg</c> member, with no curve
        /// dimension to dispatch on.
        /// </summary>
        /// <param name="jwk">The JWK's members.</param>
        /// <param name="algorithm">The JWK's <c>alg</c>, empty when absent.</param>
        /// <param name="decoder">The decoder of the public key.</param>
        /// <param name="pool">The pool the public key is rented from.</param>
        /// <returns>The key, or the refusal.</returns>
        private static KeyReconstruction ReconstructAkpKey(Dictionary<string, object> jwk, string algorithm, DecodeDelegate decoder, BaseMemoryPool pool)
        {
            if(!TryRequiredMember(jwk, WellKnownJwkMemberNames.Pub, "An AKP JWK", out var pub, out var refusal))
            {
                return new ReconstructionRefused(refusal);
            }

            CryptoAlgorithm? cryptoAlgorithm = algorithm switch
            {
                var a when WellKnownJwaValues.IsMlDsa44(a) => CryptoAlgorithm.MlDsa44,
                var a when WellKnownJwaValues.IsMlDsa65(a) => CryptoAlgorithm.MlDsa65,
                var a when WellKnownJwaValues.IsMlDsa87(a) => CryptoAlgorithm.MlDsa87,
                _ => null
            };

            if(cryptoAlgorithm is not { } akpAlgorithm)
            {
                return new ReconstructionRefused(new JwkKeyRefused(JwkPublicKeyFailureKind.UnsupportedCurveOrAlgorithm, $"Unsupported AKP algorithm: '{algorithm}'."));
            }

            using var decoded = DecodedMemberOrNone(decoder, pub, pool);

            return decoded is null
                ? NotBase64UrlText(WellKnownJwkMemberNames.Pub)
                : new ReconstructedJwkKey(akpAlgorithm, Purpose.Verification, decoded.Memory.Span.ToArray());
        }


        /// <summary>
        /// Resolves an EC JWK's curve once from its <c>crv</c> (RFC 7518 section 6.2.1.1), refusing a curve the library reconstructs
        /// no key of and an <c>alg</c> the library recognizes for no key of that curve; an <c>alg</c> the library does not recognize
        /// names no curve and is not judged.
        /// </summary>
        /// <param name="crv">The JWK's curve.</param>
        /// <param name="algorithm">The JWK's <c>alg</c>, empty when absent.</param>
        /// <param name="curve">The curve, when it resolves.</param>
        /// <param name="refusal">The refusal, when the curve is unsupported or the algorithm contradicts it.</param>
        /// <returns><see langword="true"/> when the curve resolves.</returns>
        private static bool TryEcCurveOf(
            string crv,
            string algorithm,
            out CryptoAlgorithm curve,
            [NotNullWhen(false)] out JwkKeyRefused? refusal)
        {
            CryptoAlgorithm? named = crv switch
            {
                var c when WellKnownCurveValues.IsP256(c) => CryptoAlgorithm.P256,
                var c when WellKnownCurveValues.IsP384(c) => CryptoAlgorithm.P384,
                var c when WellKnownCurveValues.IsP521(c) => CryptoAlgorithm.P521,
                var c when WellKnownCurveValues.IsSecp256k1(c) => CryptoAlgorithm.Secp256k1,
                var c when WellKnownCurveValues.IsBrainpoolP224r1(c) => CryptoAlgorithm.BrainpoolP224r1,
                var c when WellKnownCurveValues.IsBrainpoolP256r1(c) => CryptoAlgorithm.BrainpoolP256r1,
                var c when WellKnownCurveValues.IsBrainpoolP320r1(c) => CryptoAlgorithm.BrainpoolP320r1,
                var c when WellKnownCurveValues.IsBrainpoolP384r1(c) => CryptoAlgorithm.BrainpoolP384r1,
                var c when WellKnownCurveValues.IsBrainpoolP512r1(c) => CryptoAlgorithm.BrainpoolP512r1,
                _ => null
            };

            if(named is not { } resolved)
            {
                curve = default;
                refusal = new JwkKeyRefused(JwkPublicKeyFailureKind.UnsupportedCurveOrAlgorithm, $"The EC JWK's curve '{crv}' is none the library reconstructs a key of.");

                return false;
            }

            //RFC 7518 section 3.4: each ECDSA algorithm names its one curve; ECDH-ES (section 4.6) agrees on any EC curve.
            var contradicts = algorithm switch
            {
                var a when WellKnownJwaValues.IsEs256(a) => !resolved.Equals(CryptoAlgorithm.P256),
                var a when WellKnownJwaValues.IsEs384(a) => !resolved.Equals(CryptoAlgorithm.P384),
                var a when WellKnownJwaValues.IsEs512(a) => !resolved.Equals(CryptoAlgorithm.P521),
                var a when WellKnownJwaValues.IsEs256K(a) => !resolved.Equals(CryptoAlgorithm.Secp256k1),
                var a when WellKnownJwaValues.IsEsb256(a) => !resolved.Equals(CryptoAlgorithm.BrainpoolP256r1),
                var a when WellKnownJwaValues.IsEsb320(a) => !resolved.Equals(CryptoAlgorithm.BrainpoolP320r1),
                var a when WellKnownJwaValues.IsEsb384(a) => !resolved.Equals(CryptoAlgorithm.BrainpoolP384r1),
                var a when WellKnownJwaValues.IsEsb512(a) => !resolved.Equals(CryptoAlgorithm.BrainpoolP512r1),
                var a when WellKnownJwaValues.IsEcdha(a) => false,
                var a => IsAlgorithmOfNoEllipticCurve(a) || WellKnownJwaValues.IsEdDsa(a)
            };

            if(contradicts)
            {
                curve = default;
                refusal = new JwkKeyRefused(JwkPublicKeyFailureKind.CurveAndAlgorithmContradict, $"The EC JWK's algorithm '{algorithm}' is for no key of its curve '{crv}'.");

                return false;
            }

            curve = resolved;
            refusal = null;

            return true;
        }


        /// <summary>
        /// Resolves an OKP JWK's curve once from its <c>crv</c> (RFC 8037 section 2), refusing a curve the library reconstructs no
        /// key of and an <c>alg</c> the library recognizes for no key of that curve: <c>EdDSA</c> signs with Ed25519 and
        /// <c>ECDH-ES</c> agrees with X25519 (RFC 8037 sections 3.1 and 3.2).
        /// </summary>
        /// <param name="crv">The JWK's curve.</param>
        /// <param name="algorithm">The JWK's <c>alg</c>, empty when absent.</param>
        /// <param name="curve">The curve's algorithm and the purpose its keys serve, when it resolves.</param>
        /// <param name="refusal">The refusal, when the curve is unsupported or the algorithm contradicts it.</param>
        /// <returns><see langword="true"/> when the curve resolves.</returns>
        private static bool TryOkpCurveOf(
            string crv,
            string algorithm,
            [NotNullWhen(true)] out JwkKeyAlgorithm? curve,
            [NotNullWhen(false)] out JwkKeyRefused? refusal)
        {
            curve = crv switch
            {
                var c when WellKnownCurveValues.IsEd25519(c) => new JwkKeyAlgorithm(CryptoAlgorithm.Ed25519, Purpose.Verification),
                var c when WellKnownCurveValues.IsX25519(c) => new JwkKeyAlgorithm(CryptoAlgorithm.X25519, Purpose.Exchange),
                _ => null
            };

            if(curve is null)
            {
                refusal = new JwkKeyRefused(JwkPublicKeyFailureKind.UnsupportedCurveOrAlgorithm, $"The OKP JWK's curve '{crv}' is none the library reconstructs a key of.");

                return false;
            }

            var resolved = curve.Algorithm;
            var contradicts = algorithm switch
            {
                var a when WellKnownJwaValues.IsEdDsa(a) => !resolved.Equals(CryptoAlgorithm.Ed25519),
                var a when WellKnownJwaValues.IsEcdha(a) => !resolved.Equals(CryptoAlgorithm.X25519),
                var a => IsAlgorithmOfNoEllipticCurve(a) || WellKnownJwaValues.IsEcdsa(a) || WellKnownJwaValues.IsEsb(a)
            };

            if(contradicts)
            {
                curve = null;
                refusal = new JwkKeyRefused(JwkPublicKeyFailureKind.CurveAndAlgorithmContradict, $"The OKP JWK's algorithm '{algorithm}' is for no key of its curve '{crv}'.");

                return false;
            }

            refusal = null;

            return true;
        }


        /// <summary>
        /// Whether the library recognizes an algorithm as one of a key with no elliptic curve: an RSA signature, an HMAC, an ML-DSA
        /// signature or <c>none</c>.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <returns><see langword="true"/> when it is such an algorithm.</returns>
        private static bool IsAlgorithmOfNoEllipticCurve(string algorithm) =>
            WellKnownJwaValues.IsRs256(algorithm) || WellKnownJwaValues.IsRs384(algorithm) || WellKnownJwaValues.IsRs512(algorithm)
            || WellKnownJwaValues.IsPs256(algorithm) || WellKnownJwaValues.IsPs384(algorithm) || WellKnownJwaValues.IsPs512(algorithm)
            || WellKnownJwaValues.IsHs256(algorithm) || WellKnownJwaValues.IsHs384(algorithm) || WellKnownJwaValues.IsHs512(algorithm)
            || WellKnownJwaValues.IsMlDsa(algorithm) || WellKnownJwaValues.IsNone(algorithm);


        /// <summary>
        /// The string value of a member a JWK's type requires, refused as absent when the JWK carries no such member and as of the
        /// wrong type when it carries the member as no JSON string.
        /// </summary>
        /// <param name="jwk">The JWK's members.</param>
        /// <param name="name">The member's name.</param>
        /// <param name="whose">The JWK's description for the refusal's description.</param>
        /// <param name="value">The member's string value, when it is one.</param>
        /// <param name="refusal">The refusal, when the member is absent or no string.</param>
        /// <returns><see langword="true"/> when the member is a string.</returns>
        private static bool TryRequiredMember(
            Dictionary<string, object> jwk,
            string name,
            string whose,
            [NotNullWhen(true)] out string? value,
            [NotNullWhen(false)] out JwkKeyRefused? refusal)
        {
            if(!jwk.TryGetValue(name, out var member))
            {
                value = null;
                refusal = new JwkKeyRefused(JwkPublicKeyFailureKind.MemberAbsent, $"{whose} must contain the '{name}' member.");

                return false;
            }

            value = member as string;
            refusal = value is null ? new JwkKeyRefused(JwkPublicKeyFailureKind.MemberNotAString, $"{whose} carries its '{name}' member as no string.") : null;

            return value is not null;
        }


        /// <summary>
        /// The string value of an optional JWK member, empty when the JWK carries no such member, refused as of the wrong type when
        /// it carries the member as no JSON string.
        /// </summary>
        /// <param name="jwk">The JWK's members.</param>
        /// <param name="name">The member's name.</param>
        /// <param name="value">The member's string value, or empty when absent.</param>
        /// <param name="refusal">The refusal, when the member is present and no string.</param>
        /// <returns><see langword="true"/> when the member is absent or a string.</returns>
        private static bool TryOptionalMember(
            Dictionary<string, object> jwk,
            string name,
            out string value,
            [NotNullWhen(false)] out JwkKeyRefused? refusal)
        {
            if(!jwk.TryGetValue(name, out var member))
            {
                value = string.Empty;
                refusal = null;

                return true;
            }

            value = member as string ?? string.Empty;
            refusal = member is string ? null : new JwkKeyRefused(JwkPublicKeyFailureKind.MemberNotAString, $"A JWK carries its '{name}' member as no string.");

            return refusal is null;
        }


        /// <summary>
        /// The bytes of a JWK member's base64url text, or <see langword="null"/> when the decoder refuses the text as no base64url,
        /// its <see cref="FormatException"/>; any other failure of the decoder or of the allocator is theirs and surfaces as it is.
        /// </summary>
        /// <param name="decoder">The decoder.</param>
        /// <param name="text">The member's text.</param>
        /// <param name="pool">The pool the bytes are rented from.</param>
        /// <returns>The bytes, which the caller disposes, or <see langword="null"/>.</returns>
        private static IMemoryOwner<byte>? DecodedMemberOrNone(DecodeDelegate decoder, string text, BaseMemoryPool pool)
        {
            try
            {
                return decoder(text, pool);
            }
            catch(FormatException)
            {
                return null;
            }
        }


        /// <summary>The refusal of a JWK member the decoder refuses as no base64url text.</summary>
        /// <param name="name">The member's name.</param>
        /// <returns>The refusal.</returns>
        private static ReconstructionRefused NotBase64UrlText(string name) =>
            new(new JwkKeyRefused(JwkPublicKeyFailureKind.MemberNotBase64UrlText, $"A JWK carries its '{name}' member as no base64url text."));


        /// <summary>The algorithm a JWK's key is of and the purpose it serves.</summary>
        /// <param name="Algorithm">The key's algorithm.</param>
        /// <param name="Purpose">The purpose the key serves.</param>
        private sealed record JwkKeyAlgorithm(CryptoAlgorithm Algorithm, Purpose Purpose);


        /// <summary>What the reconstruction of one key type answers before the key material is rented.</summary>
        private abstract record KeyReconstruction;


        /// <summary>The public key a JWK states, reconstructed.</summary>
        /// <param name="Algorithm">The key's algorithm.</param>
        /// <param name="Purpose">The purpose the key serves.</param>
        /// <param name="KeyMaterial">The key's material in the encoding its type carries.</param>
        private sealed record ReconstructedJwkKey(CryptoAlgorithm Algorithm, Purpose Purpose, byte[] KeyMaterial) : KeyReconstruction;


        /// <summary>The refusal of the JWK.</summary>
        /// <param name="Refusal">The refusal.</param>
        private sealed record ReconstructionRefused(JwkKeyRefused Refusal) : KeyReconstruction;


        /// <summary>
        /// Default converter from a multibase-encoded <c>did:key</c> suffix to its algorithm
        /// representation. Accepts the two multibase forms the <c>did:key</c> ABNF
        /// <c>mb-value := z(base58btc) | u(base64url)</c> permits: the base58btc <c>z</c> form
        /// (the canonical form, decoded with the supplied <c>multibaseDecoder</c>)
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
                var p when p == MultibaseAlgorithms.Base58Btc => multibaseDecoder(multibaseKey.AsSpan(1), memoryPool),
                var p when p == MultibaseAlgorithms.Base64Url => DecodeBase64UrlPayload(multibaseKey.AsSpan(1), memoryPool),
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
        private static IMemoryOwner<byte> DecodeBase64UrlPayload(ReadOnlySpan<char> payload, BaseMemoryPool memoryPool)
        {
            int maxLength = System.Buffers.Text.Base64Url.GetMaxDecodedLength(payload.Length);
            using IMemoryOwner<byte> buffer = memoryPool.Rent(maxLength);
            if(System.Buffers.Text.Base64Url.DecodeFromChars(payload, buffer.Memory.Span, out _, out int bytesWritten) != System.Buffers.OperationStatus.Done)
            {
                throw new FormatException("The base64url 'u' multibase payload is not valid base64url.");
            }

            IMemoryOwner<byte> exact = memoryPool.Rent(bytesWritten);
            buffer.Memory.Span[..bytesWritten].CopyTo(exact.Memory.Span);

            return exact;
        }


        /// <summary>
        /// Classifies the multicodec public key, validates its size and copies its material into pooled memory.
        /// RSA size is determined from the modulus, independently of the public exponent's encoded length.
        /// </summary>
        /// <param name="prefixedBytes">The multicodec header followed by the public key.</param>
        /// <param name="memoryPool">The pool for the returned key material.</param>
        /// <returns>The algorithm, purpose, encoding and owned public-key material.</returns>
        /// <exception cref="ArgumentException">
        /// The payload is too short for a header, its header is not a registered one, its body is not the key the
        /// header names, or its length is not the length that key has.
        /// </exception>
        private static (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, IMemoryOwner<byte> KeyMaterial) ClassifyMulticodecPublicKey(
            ReadOnlySpan<byte> prefixedBytes,
            BaseMemoryPool memoryPool)
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
            //tag carries EcCompressed; RSA carries DER, and OKP/BLS carry Raw.
            (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, int ExpectedRawLength) classified = header switch
            {
                var h when MulticodecHeaders.IsSecp256k1PublicKey(h) => (CryptoAlgorithm.Secp256k1, Purpose.Verification, EncodingScheme.EcCompressed, 33),
                var h when MulticodecHeaders.IsEd25519PublicKey(h) => (CryptoAlgorithm.Ed25519, Purpose.Verification, EncodingScheme.Raw, 32),
                var h when MulticodecHeaders.IsX25519PublicKey(h) => (CryptoAlgorithm.X25519, Purpose.Exchange, EncodingScheme.Raw, 32),
                var h when MulticodecHeaders.IsP256PublicKey(h) => (CryptoAlgorithm.P256, Purpose.Verification, EncodingScheme.EcCompressed, 33),
                var h when MulticodecHeaders.IsP384PublicKey(h) => (CryptoAlgorithm.P384, Purpose.Verification, EncodingScheme.EcCompressed, 49),
                var h when MulticodecHeaders.IsP521PublicKey(h) => (CryptoAlgorithm.P521, Purpose.Verification, EncodingScheme.EcCompressed, 67),
                var h when MulticodecHeaders.IsBls12381G2PublicKey(h) => (CryptoAlgorithm.Bls12381G2, Purpose.Verification, EncodingScheme.Raw, 96),

                //The exponent's length varies, so parse the DER key before classifying its modulus size.
                var h when MulticodecHeaders.IsRsaPublicKey(h) => ClassifyRsa(prefixedBytes[MulticodecHeaderLength..]),
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


        /// <summary>
        /// Classifies an RSA multicodec payload by its decoded modulus size while retaining its exponent. A payload
        /// that is no DER PKCS#1 public key is refused the way every other malformed body is, so the caller's
        /// refusal handling answers it.
        /// </summary>
        /// <param name="keyMaterial">The DER PKCS#1 public key.</param>
        /// <returns>The registered RSA algorithm, verification purpose, DER encoding and payload length.</returns>
        /// <exception cref="ArgumentException">
        /// The payload is not a valid DER PKCS#1 RSA public key (the typed <see cref="RsaPublicKeyException"/> is the
        /// inner exception), or its modulus size is not a registered one.
        /// </exception>
        private static (CryptoAlgorithm Algorithm, Purpose Purpose, EncodingScheme Scheme, int ExpectedRawLength) ClassifyRsa(ReadOnlySpan<byte> keyMaterial)
        {
            int modulusLength;
            try
            {
                modulusLength = RsaPublicKeyEncoding.Decode(keyMaterial).Modulus.Length;
            }
            catch(RsaPublicKeyException exception)
            {
                throw new ArgumentException($"The RSA multicodec body is not a DER PKCS#1 public key: '{exception.FailureKind}'.", exception);
            }

            return modulusLength switch
            {
                256 => (CryptoAlgorithm.Rsa2048, Purpose.Verification, EncodingScheme.Der, keyMaterial.Length),
                512 => (CryptoAlgorithm.Rsa4096, Purpose.Verification, EncodingScheme.Der, keyMaterial.Length),
                _ => throw new ArgumentException($"Unsupported RSA modulus length: '{modulusLength}' bytes.")
            };
        }


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
                var a when a.Equals(CryptoAlgorithm.BrainpoolP224r1) => WellKnownCurveValues.BrainpoolP224r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP256r1) => WellKnownCurveValues.BrainpoolP256r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP320r1) => WellKnownCurveValues.BrainpoolP320r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP384r1) => WellKnownCurveValues.BrainpoolP384r1,
                var a when a.Equals(CryptoAlgorithm.BrainpoolP512r1) => WellKnownCurveValues.BrainpoolP512r1,

                //X25519 ECDH-ES exchange (RFC 8037 OKP). The crv name carries it; the OKP
                //single-coordinate JWK shape is decided from the key's EncodingScheme.Raw tag.
                var a when a.Equals(CryptoAlgorithm.X25519) => WellKnownCurveValues.X25519,
                _ => throw new NotSupportedException(
                    $"CryptoAlgorithm '{algorithm}' does not have a JWK curve name mapping. " +
                    $"Only EC curves P-256, P-384, P-521, Brainpool P-224r1/P-256r1/P-320r1/P-384r1/P-512r1 and X25519 are supported.")
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
                var c when WellKnownCurveValues.IsBrainpoolP224r1(c) => (CryptoTags.BrainpoolP224r1ExchangePublicKey, EllipticCurveTypes.BrainpoolP224r1),
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
