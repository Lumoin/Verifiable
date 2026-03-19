using System.Diagnostics.CodeAnalysis;

namespace Verifiable.JCose;

/// <summary>
/// Provides static factory methods for constructing <see cref="JwtHeader"/> instances
/// populated with well-known parameter sets.
/// </summary>
/// <remarks>
/// <para>
/// The extension methods follow the same pattern as <c>CryptosuiteInfoExtensions</c>:
/// factory methods are surfaced directly on the <see cref="JwtHeader"/> type through
/// C# extension syntax, giving full IntelliSense discoverability without modifying
/// the type itself.
/// </para>
/// <para>
/// Each factory method populates only the parameters that are normatively required or
/// strongly recommended for its use case. Callers may add further parameters to the
/// returned header before signing.
/// </para>
/// <para>
/// Library users can define their own header sets in a separate extension class and
/// they will appear alongside the library-provided ones in IntelliSense:
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
[SuppressMessage("Naming", "CA1708:Identifiers should differ by more than case", Justification = "The analyzer is not yet up to date with extension syntax.")]
public static class JwtHeaderExtensions
{
    extension(JwtHeader)
    {
        /// <summary>
        /// Creates a header for a signed JWT using an EC key, populated with
        /// <c>alg</c>, <c>typ</c>, and <c>kid</c>.
        /// </summary>
        /// <param name="algorithm">
        /// The JWA algorithm identifier (e.g., <see cref="WellKnownJwaValues.Es256"/>).
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
                [JwkProperties.Alg] = algorithm,
                [JwkProperties.Typ] = mediaType,
                [JwkProperties.Kid] = keyId
            };


        /// <summary>
        /// Creates a header for a JWT Authorization Request (JAR) per
        /// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>, populated with
        /// <c>alg</c>, <c>typ</c> set to <see cref="WellKnownMediaTypes.Jwt.OauthAuthzReqJwt"/>,
        /// and <c>kid</c>.
        /// </summary>
        /// <param name="algorithm">
        /// The JWA algorithm identifier (e.g., <see cref="WellKnownJwaValues.Es256"/>).
        /// </param>
        /// <param name="keyId">The <c>kid</c> value identifying the signing key.</param>
        /// <returns>A <see cref="JwtHeader"/> for a JAR JWT.</returns>
        public static JwtHeader ForJar(string algorithm, string keyId) =>
            new(capacity: 3)
            {
                [JwkProperties.Alg] = algorithm,
                [JwkProperties.Typ] = WellKnownMediaTypes.Jwt.OauthAuthzReqJwt,
                [JwkProperties.Kid] = keyId
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
                [JwkProperties.Alg] = algorithm,
                [JwkProperties.Typ] = WellKnownMediaTypes.Jwt.DcSdJwt,
                [JwkProperties.Kid] = keyId
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
                [JwkProperties.Alg] = algorithm,
                [JwkProperties.Typ] = WellKnownMediaTypes.Jwt.KbJwt
            };


        /// <summary>
        /// Creates a header for a JWE using ECDH-ES key agreement per
        /// <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">RFC 7518 §4.6</see>,
        /// populated with <c>alg</c> set to <see cref="WellKnownJweAlgorithms.EcdhEs"/>,
        /// <c>enc</c>, and <c>epk</c>.
        /// </summary>
        /// <remarks>
        /// HAIP 1.0 requires ECDH-ES with P-256 and either
        /// <see cref="WellKnownJweEncryptionAlgorithms.A128Gcm"/> or
        /// <see cref="WellKnownJweEncryptionAlgorithms.A256Gcm"/> for encrypting
        /// direct_post.jwt responses.
        /// </remarks>
        /// <param name="contentEncryptionAlgorithm">
        /// The content encryption algorithm identifier.
        /// See <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.1">RFC 7518 §5.1</see>.
        /// </param>
        /// <param name="ephemeralPublicKeyJwk">
        /// The sender's ephemeral public key as a JWK object. Embedded as the <c>epk</c> header value.
        /// </param>
        /// <returns>A <see cref="JwtHeader"/> for an ECDH-ES JWE.</returns>
        public static JwtHeader ForEcdhEsJwe(
            string contentEncryptionAlgorithm,
            object ephemeralPublicKeyJwk) =>
            new(capacity: 3)
            {
                [JwkProperties.Alg] = WellKnownJweAlgorithms.EcdhEs,
                [JwkProperties.Enc] = contentEncryptionAlgorithm,
                [JwkProperties.Epk] = ephemeralPublicKeyJwk
            };


        /// <summary>
        /// Creates a header for a DPoP proof JWT per
        /// <see href="https://www.rfc-editor.org/rfc/rfc9449">RFC 9449</see>,
        /// populated with <c>typ</c> set to <see cref="WellKnownMediaTypes.Jwt.DpopJwt"/>,
        /// <c>alg</c>, and <c>jwk</c> carrying the sender's public key.
        /// </summary>
        /// <param name="algorithm">The JWA algorithm identifier (e.g., <see cref="WellKnownJwaValues.Es256"/>).</param>
        /// <param name="publicKeyJwk">
        /// The sender's public key as a JWK object, embedded as the <c>jwk</c> header value.
        /// The private key MUST NOT be present.
        /// </param>
        /// <returns>A <see cref="JwtHeader"/> for a DPoP proof JWT.</returns>
        public static JwtHeader ForDpop(string algorithm, object publicKeyJwk) =>
            new(capacity: 3)
            {
                [JwkProperties.Typ] = WellKnownMediaTypes.Jwt.DpopJwt,
                [JwkProperties.Alg] = algorithm,
                [JwkProperties.Jwk] = publicKeyJwk
            };


        /// <summary>
        /// Creates a header for an X.509-secured JWT using the <c>x5c</c> certificate chain
        /// per <see href="https://www.rfc-editor.org/rfc/rfc7517#section-4.7">RFC 7517 §4.7</see>,
        /// populated with <c>alg</c>, <c>typ</c>, and <c>x5c</c>.
        /// </summary>
        /// <remarks>
        /// HAIP 1.0 requires the <c>x5c</c> header for issuer key resolution in
        /// the <c>x509_hash</c> client identifier scheme.
        /// </remarks>
        /// <param name="algorithm">The JWA algorithm identifier.</param>
        /// <param name="mediaType">The <c>typ</c> value.</param>
        /// <param name="x5c">
        /// The certificate chain as an array of Base64-encoded (not Base64url) DER values.
        /// The first element MUST contain the signing key.
        /// </param>
        /// <returns>A <see cref="JwtHeader"/> carrying an X.509 certificate chain.</returns>
        public static JwtHeader ForX5c(string algorithm, string mediaType, string[] x5c) =>
            new(capacity: 3)
            {
                [JwkProperties.Alg] = algorithm,
                [JwkProperties.Typ] = mediaType,
                [JwkProperties.X5c] = x5c
            };
    }
}