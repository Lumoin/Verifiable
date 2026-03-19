using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.JCose;

/// <summary>
/// Provides static factory methods for constructing <see cref="JwtHeader"/> instances
/// populated with well-known parameter sets.
/// </summary>
/// <remarks>
/// <para>
/// Factory methods are surfaced directly on the <see cref="JwtHeader"/> type through C#
/// extension syntax, giving full IntelliSense discoverability without modifying the type
/// itself. Library users can define their own extension class and the methods appear
/// alongside the library-provided ones in IntelliSense:
/// </para>
/// <code>
/// public static class MyHeaderExtensions
/// {
///     extension(JwtHeader)
///     {
///         public static JwtHeader ForMyProtocol(string keyId) =>
///             new JwtHeader
///             {
///                 [JwkProperties.Alg] = WellKnownJwaValues.Es256,
///                 [JwkProperties.Typ] = "my-protocol+jwt",
///                 [JwkProperties.Kid] = keyId
///             };
///     }
/// }
/// </code>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The analyzer is not yet up to date with extension syntax.")]
public static class JwtHeaderExtensions
{
    extension(JwtHeader)
    {
        /// <summary>
        /// Creates a header for a signed JWT, populated with <c>alg</c>, <c>typ</c>,
        /// and <c>kid</c>.
        /// </summary>
        /// <param name="algorithm">
        /// The JWA algorithm identifier, e.g. <see cref="WellKnownJwaValues.Es256"/>.
        /// See <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.1">RFC 7518 §3.1</see>.
        /// </param>
        /// <param name="mediaType">
        /// The <c>typ</c> value declaring the media type of the JWT.
        /// See <see href="https://www.rfc-editor.org/rfc/rfc7519#section-5.1">RFC 7519 §5.1</see>.
        /// </param>
        /// <param name="keyId">
        /// The <c>kid</c> value identifying the signing key, typically a DID URL.
        /// See <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.5">RFC 7517 §4.5</see>.
        /// </param>
        /// <returns>A <see cref="JwtHeader"/> ready for use in an <see cref="UnsignedJwt"/>.</returns>
        public static JwtHeader ForSigning(string algorithm, string mediaType, string keyId) =>
            new(capacity: 3)
            {
                [WellKnownJwkValues.Alg] = algorithm,
                [WellKnownJwkValues.Typ] = mediaType,
                [WellKnownJwkValues.Kid] = keyId
            };


        /// <summary>
        /// Creates a header for an OAuth 2.0 JWT access token per
        /// <see href="https://www.rfc-editor.org/rfc/rfc9068">RFC 9068</see>, populated
        /// with <c>alg</c>, <c>typ</c> set to <see cref="WellKnownMediaTypes.Jwt.AtJwt"/>,
        /// and <c>kid</c>.
        /// </summary>
        /// <remarks>
        /// RFC 9068 §2.1 mandates the explicit <c>at+jwt</c> type to prevent confusion
        /// between access tokens and other JWT profiles. Consumers that filter JWTs by
        /// <c>typ</c> rely on this discriminator.
        /// </remarks>
        /// <param name="algorithm">The JWA algorithm identifier.</param>
        /// <param name="keyId">The <c>kid</c> value identifying the signing key.</param>
        /// <returns>A <see cref="JwtHeader"/> for an OAuth 2.0 JWT access token.</returns>
        public static JwtHeader ForAccessToken(string algorithm, string keyId) =>
            new(capacity: 3)
            {
                [WellKnownJwkValues.Alg] = algorithm,
                [WellKnownJwkValues.Typ] = WellKnownMediaTypes.Jwt.AtJwt,
                [WellKnownJwkValues.Kid] = keyId
            };


        /// <summary>
        /// Creates a header for an OpenID Connect ID Token per
        /// <see href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">OIDC Core §2</see>,
        /// populated with <c>alg</c>, <c>typ</c> set to <see cref="WellKnownJwkValues.TypeJwt"/>,
        /// and <c>kid</c>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// OIDC Core does not mandate a profile-specific <c>typ</c> value; the recommended
        /// value <c>JWT</c> is used per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-5.1">RFC 7519 §5.1</see>.
        /// </para>
        /// </remarks>
        /// <param name="algorithm">The JWA algorithm identifier.</param>
        /// <param name="keyId">The <c>kid</c> value identifying the signing key.</param>
        /// <returns>A <see cref="JwtHeader"/> for an OpenID Connect ID Token.</returns>
        public static JwtHeader ForIdToken(string algorithm, string keyId) =>
            new(capacity: 3)
            {
                [WellKnownJwkValues.Alg] = algorithm,
                [WellKnownJwkValues.Typ] = WellKnownJwkValues.TypeJwt,
                [WellKnownJwkValues.Kid] = keyId
            };


        /// <summary>
        /// Creates a header for a JWT Authorization Request (JAR) per
        /// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>, populated with
        /// <c>alg</c>, <c>typ</c> set to <see cref="WellKnownMediaTypes.Jwt.OauthAuthzReqJwt"/>,
        /// and <c>kid</c>.
        /// </summary>
        /// <param name="algorithm">The JWA algorithm identifier.</param>
        /// <param name="keyId">The <c>kid</c> value identifying the signing key.</param>
        /// <returns>A <see cref="JwtHeader"/> for a JAR JWT.</returns>
        public static JwtHeader ForJar(string algorithm, string keyId) =>
            new(capacity: 3)
            {
                [WellKnownJwkValues.Alg] = algorithm,
                [WellKnownJwkValues.Typ] = WellKnownMediaTypes.Jwt.OauthAuthzReqJwt,
                [WellKnownJwkValues.Kid] = keyId
            };


        /// <summary>
        /// Creates a header for an SD-JWT Verifiable Credential per
        /// <see href="https://www.rfc-editor.org/rfc/rfc9901">RFC 9901</see>, populated with
        /// <c>alg</c>, <c>typ</c> set to <see cref="WellKnownMediaTypes.Jwt.DcSdJwt"/>,
        /// and <c>kid</c>.
        /// </summary>
        /// <param name="algorithm">The JWA algorithm identifier.</param>
        /// <param name="keyId">The <c>kid</c> value identifying the signing key.</param>
        /// <returns>A <see cref="JwtHeader"/> for an SD-JWT VC.</returns>
        public static JwtHeader ForSdJwtVc(string algorithm, string keyId) =>
            new(capacity: 3)
            {
                [WellKnownJwkValues.Alg] = algorithm,
                [WellKnownJwkValues.Typ] = WellKnownMediaTypes.Jwt.DcSdJwt,
                [WellKnownJwkValues.Kid] = keyId
            };


        /// <summary>
        /// Creates a header for an SD-JWT Key Binding JWT (KB-JWT) per
        /// <see href="https://www.rfc-editor.org/rfc/rfc9901#section-4.3">RFC 9901 §4.3</see>,
        /// populated with <c>alg</c> and <c>typ</c> set to
        /// <see cref="WellKnownMediaTypes.Jwt.KbJwt"/>.
        /// </summary>
        /// <param name="algorithm">The JWA algorithm identifier.</param>
        /// <returns>A <see cref="JwtHeader"/> for a KB-JWT.</returns>
        public static JwtHeader ForKeyBinding(string algorithm) =>
            new(capacity: 2)
            {
                [WellKnownJwkValues.Alg] = algorithm,
                [WellKnownJwkValues.Typ] = WellKnownMediaTypes.Jwt.KbJwt
            };


        /// <summary>
        /// Creates a header for a JWE using ECDH-ES key agreement per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">RFC 7518 §4.6</see>,
        /// populated with <c>alg</c>, <c>enc</c>, and <c>epk</c>.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The <paramref name="ephemeralPublicKey"/> must carry an uncompressed point encoding
        /// (<c>0x04 || X || Y</c>) as produced by <c>CreateP256ExchangeKeys</c> on either
        /// <c>BouncyCastleKeyMaterialCreator</c> or <c>MicrosoftKeyMaterialCreator</c>.
        /// </para>
        /// <para>
        /// X and Y coordinates are sliced via <see cref="EllipticCurveUtilities"/> and encoded
        /// with <paramref name="base64UrlEncoder"/>. The curve name for the <c>crv</c> JWK
        /// parameter is resolved from the key's <see cref="Tag"/> by
        /// <paramref name="tagToCrvConverter"/>, defaulting to
        /// <see cref="CryptoFormatConversions.DefaultTagToCrvConverter"/>.
        /// </para>
        /// <para>
        /// HAIP 1.0 requires ECDH-ES with P-256 and either <c>A128GCM</c> or <c>A256GCM</c>.
        /// </para>
        /// </remarks>
        /// <param name="contentEncryptionAlgorithm">
        /// The content encryption algorithm identifier.
        /// See <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.1">RFC 7518 §5.1</see>.
        /// </param>
        /// <param name="ephemeralPublicKey">
        /// The sender's ephemeral public key carrying <see cref="EncodingScheme.EcUncompressed"/>
        /// encoding, as returned by <c>CreateP256ExchangeKeys(pool).PublicKey</c>.
        /// </param>
        /// <param name="base64UrlEncoder">Delegate for Base64url encoding the X and Y coordinates.</param>
        /// <param name="tagToCrvConverter">
        /// Delegate that maps the key's <see cref="Tag"/> to a JWK curve name string.
        /// Pass <see cref="CryptoFormatConversions.DefaultTagToCrvConverter"/> for standard curves.
        /// </param>
        /// <returns>A <see cref="JwtHeader"/> for an ECDH-ES JWE.</returns>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the public key does not carry uncompressed EC point encoding.
        /// </exception>
        public static JwtHeader ForEcdhEsJwe(
            string contentEncryptionAlgorithm,
            PublicKeyMemory ephemeralPublicKey,
            EncodeDelegate base64UrlEncoder,
            TagToEpkCrvDelegate tagToCrvConverter)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(contentEncryptionAlgorithm);
            ArgumentNullException.ThrowIfNull(ephemeralPublicKey);
            ArgumentNullException.ThrowIfNull(base64UrlEncoder);
            ArgumentNullException.ThrowIfNull(tagToCrvConverter);

            EncodingScheme encoding = ephemeralPublicKey.Tag.Get<EncodingScheme>();

            if(!encoding.Equals(EncodingScheme.EcUncompressed))
            {
                throw new InvalidOperationException(
                    "The ephemeral public key must use uncompressed EC point encoding " +
                    "(0x04 || X || Y) as produced by CreateP256ExchangeKeys.");
            }

            string crv = tagToCrvConverter(ephemeralPublicKey.Tag);

            ReadOnlySpan<byte> uncompressed = ephemeralPublicKey.AsReadOnlySpan();
            string xB64 = base64UrlEncoder(EllipticCurveUtilities.SliceXCoordinate(uncompressed));
            string yB64 = base64UrlEncoder(EllipticCurveUtilities.SliceYCoordinate(uncompressed));

            var epk = new Dictionary<string, string>(4)
            {
                [WellKnownJwkValues.Kty] = WellKnownKeyTypeValues.Ec,
                [WellKnownJwkValues.Crv] = crv,
                [WellKnownJwkValues.X] = xB64,
                [WellKnownJwkValues.Y] = yB64
            };

            return new JwtHeader(capacity: 3)
            {
                [WellKnownJwkValues.Alg] = WellKnownJweAlgorithms.EcdhEs,
                [WellKnownJwkValues.Enc] = contentEncryptionAlgorithm,
                [WellKnownJwkValues.Epk] = epk
            };
        }


        /// <summary>
        /// Creates a header for a DPoP proof JWT per
        /// <see href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449</see>,
        /// populated with <c>typ</c>, <c>alg</c>, and <c>jwk</c>.
        /// </summary>
        /// <param name="algorithm">The JWA algorithm identifier.</param>
        /// <param name="publicKeyJwk">
        /// The sender's public key as a JWK object embedded as the <c>jwk</c> header value.
        /// The private key must not be present.
        /// </param>
        /// <returns>A <see cref="JwtHeader"/> for a DPoP proof JWT.</returns>
        public static JwtHeader ForDpop(string algorithm, object publicKeyJwk) =>
            new(capacity: 3)
            {
                [WellKnownJwkValues.Typ] = WellKnownMediaTypes.Jwt.DpopJwt,
                [WellKnownJwkValues.Alg] = algorithm,
                [WellKnownJwkValues.Jwk] = publicKeyJwk
            };


        /// <summary>
        /// Creates a header for an X.509-secured JWT using the <c>x5c</c> certificate chain
        /// per <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.7">RFC 7517 §4.7</see>,
        /// populated with <c>alg</c>, <c>typ</c>, and <c>x5c</c>.
        /// </summary>
        /// <remarks>
        /// HAIP 1.0 requires the <c>x5c</c> header for issuer key resolution in the
        /// <c>x509_hash</c> client identifier scheme.
        /// </remarks>
        /// <param name="algorithm">The JWA algorithm identifier.</param>
        /// <param name="mediaType">The <c>typ</c> value.</param>
        /// <param name="x5c">
        /// The certificate chain as Base64-encoded (not Base64url) DER values. The first
        /// element must contain the signing key.
        /// </param>
        /// <returns>A <see cref="JwtHeader"/> carrying an X.509 certificate chain.</returns>
        public static JwtHeader ForX5c(string algorithm, string mediaType, string[] x5c) =>
            new(capacity: 3)
            {
                [WellKnownJwkValues.Alg] = algorithm,
                [WellKnownJwkValues.Typ] = mediaType,
                [WellKnownJwkValues.X5c] = x5c
            };


        /// <summary>
        /// Creates a header for a Verifier Attestation JWT per
        /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>,
        /// populated with <c>alg</c> and <c>typ</c> set to
        /// <see cref="WellKnownMediaTypes.Jwt.VerifierAttestationJwt"/>.
        /// </summary>
        /// <param name="algorithm">The JWA algorithm identifier.</param>
        /// <returns>A <see cref="JwtHeader"/> for a Verifier Attestation JWT.</returns>
        public static JwtHeader ForVerifierAttestation(string algorithm) =>
            new(capacity: 2)
            {
                [WellKnownJwkValues.Alg] = algorithm,
                [WellKnownJwkValues.Typ] = WellKnownMediaTypes.Jwt.VerifierAttestationJwt
            };


        /// <summary>
        /// Creates a header for a JAR carrying a Verifier Attestation JWT in the
        /// <c>jwt</c> JOSE header parameter per
        /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-12">OID4VP 1.0 §12</see>,
        /// populated with <c>alg</c>, <c>typ</c> set to
        /// <see cref="WellKnownMediaTypes.Jwt.OauthAuthzReqJwt"/>, and <c>jwt</c>.
        /// </summary>
        /// <param name="algorithm">The JWA algorithm identifier.</param>
        /// <param name="attestationCompactJwt">
        /// The Verifier Attestation JWT compact string to embed in the <c>jwt</c> header.
        /// </param>
        /// <returns>A <see cref="JwtHeader"/> for a JAR with embedded Verifier Attestation.</returns>
        public static JwtHeader ForJarWithAttestation(string algorithm, string attestationCompactJwt) =>
            new(capacity: 3)
            {
                [WellKnownJwkValues.Alg] = algorithm,
                [WellKnownJwkValues.Typ] = WellKnownMediaTypes.Jwt.OauthAuthzReqJwt,
                [WellKnownJwkValues.Jwt] = attestationCompactJwt
            };
    }
}
