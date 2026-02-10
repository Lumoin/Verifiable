namespace Verifiable.JCose
{
    /// <summary>
    /// Well-known names of JSON Web Key (JWK) Elliptic Curve "crv" (Curve) parameter values
    /// as defined in <see href="https://www.rfc-editor.org/rfc/rfc7518">RFC 7518</see>.
    /// Additional curve names are defined in other specifications.
    /// </summary>
    /// <remarks>As per definition parameters are case-sensitive.</remarks>
    public static class WellKnownCurveValues
    {
        /// <summary>
        /// P-256 curve.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.1">P-256</see>.</remarks>
        public static readonly string P256 = "P-256";

        /// <summary>
        /// P-384 curve.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.2">P-384</see>.</remarks>
        public static readonly string P384 = "P-384";

        /// <summary>
        /// P-521 curve.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.3">P-521</see>.</remarks>
        public static readonly string P521 = "P-521";

        /// <summary>
        /// secp256k1 curve.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-6.2.1.4">secp256k1</see>.</remarks>
        public static readonly string Secp256k1 = "secp256k1";

        /// <summary>
        /// Ed25519 curve.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc8037#section-2">Ed25519</see>.</remarks>
        public static readonly string Ed25519 = "Ed25519";

        /// <summary>
        /// Ed448 curve.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc8037#section-2">Ed448</see>.</remarks>
        public static readonly string Ed448 = "Ed448";

        /// <summary>
        /// X25519 curve for ECDH key agreement.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7748">X25519</see>.</remarks>
        public static readonly string X25519 = "X25519";

        /// <summary>
        /// X448 curve for ECDH key agreement.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7748">X448</see>.</remarks>
        public static readonly string X448 = "X448";


        /// <summary>
        /// If <paramref name="crv"/> is <see cref="P256"/> or not.
        /// </summary>
        /// <param name="crv">The curve type.</param>
        /// <returns><see langword="true" /> if <paramref name="crv"/> is <see cref="P256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsP256(string crv) => Equals(crv, P256);


        /// <summary>
        /// If <paramref name="crv"/> is <see cref="P384"/> or not.
        /// </summary>
        /// <param name="crv">The curve type.</param>
        /// <returns><see langword="true" /> if <paramref name="crv"/> is <see cref="P384"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsP384(string crv) => Equals(crv, P384);


        /// <summary>
        /// If <paramref name="crv"/> is <see cref="P521"/> or not.
        /// </summary>
        /// <param name="crv">The curve type.</param>
        /// <returns><see langword="true" /> if <paramref name="crv"/> is <see cref="P521"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsP521(string crv) => Equals(crv, P521);


        /// <summary>
        /// If <paramref name="crv"/> is <see cref="Secp256k1"/> or not.
        /// </summary>
        /// <param name="crv">The curve type.</param>
        /// <returns><see langword="true" /> if <paramref name="crv"/> is <see cref="Secp256k1"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsSecp256k1(string crv) => Equals(crv, Secp256k1);


        /// <summary>
        /// If <paramref name="crv"/> is <see cref="Ed25519"/> or not.
        /// </summary>
        /// <param name="crv">The curve type.</param>
        /// <returns><see langword="true" /> if <paramref name="crv"/> is <see cref="Ed25519"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEd25519(string crv) => Equals(crv, Ed25519);


        /// <summary>
        /// If <paramref name="crv"/> is <see cref="Ed448"/> or not.
        /// </summary>
        /// <param name="crv">The curve type.</param>
        /// <returns><see langword="true" /> if <paramref name="crv"/> is <see cref="Ed448"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEd448(string crv) => Equals(crv, Ed448);


        /// <summary>
        /// If <paramref name="crv"/> is <see cref="X25519"/> or not.
        /// </summary>
        /// <param name="crv">The curve type.</param>
        /// <returns><see langword="true" /> if <paramref name="crv"/> is <see cref="X25519"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsX25519(string crv) => Equals(crv, X25519);


        /// <summary>
        /// If <paramref name="crv"/> is <see cref="X448"/> or not.
        /// </summary>
        /// <param name="crv">The curve type.</param>
        /// <returns><see langword="true" /> if <paramref name="crv"/> is <see cref="X448"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsX448(string crv) => Equals(crv, X448);


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="property">The property to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="property"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string crv) => crv switch
        {
            string _ when IsEd25519(crv) => Ed25519,
            string _ when IsEd448(crv) => Ed448,
            string _ when IsP256(crv) => P256,
            string _ when IsP384(crv) => P384,
            string _ when IsP521(crv) => P521,
            string _ when IsSecp256k1(crv) => Secp256k1,
            string _ when IsX25519(crv) => X25519,
            string _ when IsX448(crv) => X448,
            string _ => crv
        };


        /// <summary>
        /// Returns a value that indicates if the properties are the same.
        /// </summary>
        /// <param name="crvA">The first key type to compare.</param>
        /// <param name="crv">The second key type to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the key types are the same; otherwise, <see langword="false" />.
        /// </returns>
        /// <remarks>This comparison is case-sensitive. See at <see href="https://www.rfc-editor.org/rfc/rfc7517">RFC 7517</see>.</remarks>
        public static bool Equals(string crvA, string crv)
        {
            return object.ReferenceEquals(crvA, crv) || StringComparer.InvariantCulture.Equals(crvA, crv);
        }
    }
}
