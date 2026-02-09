namespace Verifiable.JCose
{
    /// <summary>
    /// Class containing the well-known key type (kty) values used in JSON Web Key (JWK).
    /// These values are used to identify the cryptographic algorithm family used with the key.
    /// See more at <see href="https://datatracker.ietf.org/doc/html/rfc7518#section-6">RFC 7518 - Section 6</see>.
    /// </summary>
    /// <remarks>As per definition parameters are case-sensitive.</remarks>
    public static class WellKnownKeyTypeValues
    {
        /// <summary>
        /// Elliptic Curve key type.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1">RFC 7518 - Section 6.2.1</see>.</remarks>
        public static readonly string Ec = "EC";

        /// <summary>
        /// Symmetric key type.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.4">RFC 7518 - Section 6.4</see>.</remarks>
        public static readonly string Oct = "oct";

        /// <summary>
        /// Octet Key Pair key type.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc8037">RFC 8037</see>.</remarks>
        public static readonly string Okp = "OKP";

        /// <summary>
        /// RSA key type.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.3.1">RFC 7518 §6.3.1</see>.</remarks>
        public static readonly string Rsa = "RSA";

        /// <summary>
        /// Algorithm Key Pair (AKP) key type for post-quantum algorithms.
        /// </summary>
        /// <remarks>
        /// See <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">ML-DSA for JOSE and COSE</see>.
        /// Used for ML-DSA and other algorithms where the key structure is algorithm-specific.
        /// The <c>pub</c> and <c>priv</c> parameters carry the raw public and private key bytes.
        /// </remarks>
        public static readonly string Akp = "AKP";


        /// <summary>
        /// If <paramref name="kty"/> is <see cref="Rsa"/> or not.
        /// </summary>
        /// <param name="kty">The key type.</param>
        /// <returns><see langword="true" /> if <paramref name="kty"/> is <see cref="Rsa"/>; otherwise, <see langword="false" />.</returns>
        public static bool IsRsa(string kty) => Equals(kty, Rsa);


        /// <summary>
        /// If <paramref name="kty"/> is <see cref="Oct"/> or not.
        /// </summary>
        /// <param name="kty">The key type.</param>
        /// <returns><see langword="true" /> if <paramref name="kty"/> is <see cref="Oct"/>; otherwise, <see langword="false" />.</returns>
        public static bool IsOct(string kty) => Equals(kty, Oct);

        /// <summary>
        /// If <paramref name="kty"/> is <see cref="Ec"/> or not.
        /// </summary>
        /// <param name="kty">The key type.</param>
        /// <returns><see langword="true" /> if <paramref name="kty"/> is <see cref="Ec"/>; otherwise, <see langword="false" />.</returns>
        public static bool IsEc(string kty) => Equals(kty, Ec);


        /// <summary>
        /// If <paramref name="kty"/> is <see cref="Okp"/> or not.
        /// </summary>
        /// <param name="kty">The key type.</param>
        /// <returns><see langword="true" /> if <paramref name="kty"/> is <see cref="Okp"/>; otherwise, <see langword="false" />.</returns>
        public static bool IsOkp(string kty) => Equals(kty, Okp);


        /// <summary>
        /// If <paramref name="kty"/> is <see cref="Akp"/> or not.
        /// </summary>
        /// <param name="kty">The key type.</param>
        /// <returns><see langword="true" /> if <paramref name="kty"/> is <see cref="Akp"/>; otherwise, <see langword="false" />.</returns>
        public static bool IsAkp(string kty) => Equals(kty, Akp);


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="property">The property to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="property"/>, or the original instance if none match.</returns>

        public static string GetCanonicalizedValue(string kty) => kty switch
        {
            string _ when IsEc(kty) => Ec,
            string _ when IsOct(kty) => Oct,
            string _ when IsOkp(kty) => Okp,
            string _ when IsRsa(kty) => Rsa,
            string _ when IsAkp(kty) => Akp,
            string _ => kty
        };


        /// <summary>
        /// Returns a value that indicates if the properties are the same.
        /// </summary>
        /// <param name="ktyA">The first key type to compare.</param>
        /// <param name="ktyB">The second key type to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the key types are the same; otherwise, <see langword="false" />.
        /// </returns>
        /// <remarks>This comparison is case-sensitive. See at <see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>.</remarks>
        public static bool Equals(string ktyA, string ktyB)
        {
            return object.ReferenceEquals(ktyA, ktyB) || StringComparer.InvariantCulture.Equals(ktyA, ktyB);
        }
    }
}