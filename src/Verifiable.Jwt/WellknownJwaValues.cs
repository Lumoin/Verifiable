namespace Verifiable.Jwt
{
    /// <summary>    
    /// JSON Web Algorithms (JWA) as defined in <see href="https://www.rfc-editor.org/rfc/rfc7518">RFC 7518</see>.
    /// </summary>
    /// <remarks>As per definition parameters are case-sensitive.</remarks>
    public static class WellKnownJwaValues
    {
        /// <summary>
        /// No digital signature or encryption applied.
        /// </summary>
        /// <remarks>
        /// Use of 'none' algorithm should be restricted to specific circumstances, as it implies that the JWTs are not signed or encrypted.
        /// This can expose security vulnerabilities by allowing unauthorized modifications.
        /// More details can be found in <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.6">RFC 7518 Section 3.6</see>.
        /// </remarks>
        public static readonly string None = "none";

        /// <summary>
        /// HMAC using SHA-256.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.2">HMAC with SHA-2 Functions</see>.</remarks>
        public static readonly string Hs256 = "HS256";

        /// <summary>
        /// HMAC using SHA-384.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.2">HMAC with SHA-2 Functions</see>.</remarks>
        public static readonly string Hs384 = "HS384";

        /// <summary>
        /// HMAC using SHA-512.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.2">HMAC with SHA-2 Functions</see>.</remarks>
        public static readonly string Hs512 = "HS512";

        /// <summary>
        /// ECDSA using P-256 and SHA-256.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Es256 = "ES256";

        /// <summary>
        /// ECDSA using P-384 and SHA-384.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Es384 = "ES384";

        /// <summary>
        /// ECDSA using P-521 and SHA-512.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Es512 = "ES512";

        /// <summary>
        /// ECDSA using secp256k1 and SHA-256.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.4">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Es256k1 = "ES256K1";

        /// <summary>
        /// RSASSA-PSS using SHA-256 and MGF1 with SHA-256.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Ps256 = "PS256";

        /// <summary>
        /// RSASSA-PSS using SHA-256 and MGF1 with SHA-384.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Ps384 = "PS384";

        /// <summary>
        /// RSASSA-PSS using SHA-256 and MGF1 with SHA-512.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.5">Digital Signature with ECDSA</see>.</remarks>
        public static readonly string Ps512 = "PS512";

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA-256.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">Digital Signature with RSASSA-PKCS1-v1_5</see>.</remarks>
        public static readonly string Rs256 = "RS256";

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using using SHA-384.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">Digital Signature with RSASSA-PKCS1-v1_5</see>.</remarks>
        public static readonly string Rs384 = "RS384";

        /// <summary>
        /// RSASSA-PKCS1-v1_5 using using SHA-512.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-3.3">Digital Signature with RSASSA-PKCS1-v1_5</see>.</remarks>
        public static readonly string Rs512 = "RS512";

        /// <summary>
        /// EdDSA using Ed25519.
        /// </summary>
        /// <remarks>
        /// See more at <a href="https://datatracker.ietf.org/doc/html/rfc8037">RFC 8037 - CFRG Elliptic Curve Diffie-Hellman (ECDH) and Signaturesin JSON Object Signing and Encryption(JOSE)</a>.
        /// </remarks>

        public static readonly string EdDsa = "EdDSA";


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="None"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="None"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsNone(string alg)
        {
            return Equals(None, alg);
        }

        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Hs256"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Hs256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsHs256(string alg)
        {
            return Equals(Hs256, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Hs384"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Hs384"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsHs384(string alg)
        {
            return Equals(Hs384, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Hs512"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Hs512"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsHs512(string alg)
        {
            return Equals(Hs512, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Es256"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Es256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEs256(string alg)
        {
            return Equals(Es256, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Es384"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Es384"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEs384(string alg)
        {
            return Equals(Es384, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Es512"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Es512"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEs512(string alg)
        {
            return Equals(Es512, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Es256k1"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Es256k1"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEs256k1(string alg)
        {
            return Equals(Es256k1, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Ps256"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Ps256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsPs256(string alg)
        {
            return Equals(Ps256, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Ps384"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Ps384"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsPs384(string alg)
        {
            return Equals(Ps384, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Ps512"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Ps512"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsPs512(string alg)
        {
            return Equals(Ps512, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Rs256"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Rs256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsRs256(string alg)
        {
            return Equals(Rs256, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Rs384"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Rs384"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsRs384(string alg)
        {
            return Equals(Rs384, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="Rs512"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if  <paramref name="alg"/> is <see cref="Rs512"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsRs512(string alg)
        {
            return Equals(Rs512, alg);
        }


        /// <summary>
        /// If <paramref name="alg"/> is <see cref="EdDsa"/> or not.
        /// </summary>
        /// <param name="alg">The algorithm</param>.
        /// <returns><see langword="true" /> if <paramref name="alg"/> is <see cref="Rs512"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEdDsa(string alg)
        {
            return Equals(EdDsa, alg);
        }


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="alg">The property to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="alg"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string alg) => alg switch
        {
            string _ when IsNone(alg) => None,
            string _ when IsHs256(alg) => Hs256,
            string _ when IsHs384(alg) => Hs384,
            string _ when IsHs512(alg) => Hs512,
            string _ when IsEs256(alg) => Es256,
            string _ when IsEs384(alg) => Es384,
            string _ when IsEs512(alg) => Es512,
            string _ when IsEs256k1(alg) => Es256k1,
            string _ when IsPs256(alg) => Ps256,
            string _ when IsPs384(alg) => Ps384,
            string _ when IsPs512(alg) => Ps512,
            string _ when IsRs256(alg) => Rs256,
            string _ when IsRs384(alg) => Rs384,
            string _ when IsRs512(alg) => Rs512,
            string _ when IsEdDsa(alg) => EdDsa,
            string _ => alg
        };


        /// <summary>
        /// Returns a value that indicates if the algs are the same.
        /// </summary>
        /// <param name="algA">The first alg to compare.</param>
        /// <param name="algB">The second alg to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the <paramref name="algA"/> and <paramref name="algB"/> are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(string algA, string algB)
        {
            return object.ReferenceEquals(algA, algB) || StringComparer.InvariantCulture.Equals(algA, algB);
        }
    }
}
