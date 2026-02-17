namespace Verifiable.JCose
{
    /// <summary>    
    /// JSON Web Algorithms (JWA) for JSON Web Encryption (JWE) key management algorithms as defined in <see href="https://www.rfc-editor.org/rfc/rfc7518">RFC 7518</see>.
    /// Additional algorithms are defined in other specifications.
    /// </summary>
    /// <remarks>As per definition parameters are case-sensitive.</remarks>
    public static class WellKnownJweAlgorithms
    {
        /// <summary>
        /// RSAES-PKCS1-V1_5 encryption.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.2">RSAES-PKCS1-v1_5</see>.</remarks>
        public static readonly string Rsa15 = "RSA1_5";

        /// <summary>
        /// RSAES OAEP encryption.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.3">RSAES OAEP</see>.</remarks>
        public static readonly string RsaOaep = "RSA-OAEP";

        /// <summary>
        /// RSAES OAEP encryption with SHA-256.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.3">RSAES OAEP</see>.</remarks>
        public static readonly string RsaOaep256 = "RSA-OAEP-256";

        /// <summary>
        /// AES key wrap encryption with 128-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.4">AES Key Wrap</see>.</remarks>
        public static readonly string A128Kw = "A128KW";

        /// <summary>
        /// AES key wrap encryption with 192-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.4">AES Key Wrap</see>.</remarks>
        public static readonly string A192Kw = "A192KW";

        /// <summary>
        /// AES key wrap encryption with 256-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.4">AES Key Wrap</see>.</remarks>
        public static readonly string A256Kw = "A256KW";

        /// <summary>
        /// Direct shared symmetric key encryption.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">Direct Key Agreement</see>.</remarks>
        public static readonly string Dir = "dir";

        /// <summary>
        /// Elliptic Curve Diffie-Hellman key agreement.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">ECDH-ES</see>.</remarks>
        public static readonly string EcdhEs = "ECDH-ES";

        /// <summary>
        /// Elliptic Curve Diffie-Hellman key agreement with AES key wrap encryption with 128-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">ECDH-ES+A128KW</see>.</remarks>
        public static readonly string EcdhEsA128Kw = "ECDH-ES+A128KW";

        /// <summary>
        /// Elliptic Curve Diffie-Hellman key agreement with AES key wrap encryption with 192-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">ECDH-ES+A192KW</see>.</remarks>
        public static readonly string EcdhEsA192Kw = "ECDH-ES+A192KW";

        /// <summary>
        /// Elliptic Curve Diffie-Hellman key agreement with AES key wrap encryption with 256-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.6">ECDH-ES+A256KW</see>.</remarks>
        public static readonly string EcdhEsA256Kw = "ECDH-ES+A256KW";

        /// <summary>
        /// Elliptic Curve Diffie-Hellman key agreement with authenticated encryption.
        /// </summary>
        /// <remarks>See more at <see href="https://datatracker.ietf.org/doc/draft-madden-jose-ecdh-1pu-04/">ECDH-1PU</see>.</remarks>
        public static readonly string Ecdh1Pu = "ECDH-1PU";

        /// <summary>
        /// Elliptic Curve Diffie-Hellman key agreement with authenticated encryption and AES key wrap encryption with 128-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://datatracker.ietf.org/doc/draft-madden-jose-ecdh-1pu-04/">ECDH-1PU+A128KW</see>.</remarks>
        public static readonly string Ecdh1PuA128Kw = "ECDH-1PU+A128KW";

        /// <summary>
        /// Elliptic Curve Diffie-Hellman key agreement with authenticated encryption and AES key wrap encryption with 192-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://datatracker.ietf.org/doc/draft-madden-jose-ecdh-1pu-04/">ECDH-1PU+A192KW</see>.</remarks>
        public static readonly string Ecdh1PuA192Kw = "ECDH-1PU+A192KW";

        /// <summary>
        /// Elliptic Curve Diffie-Hellman key agreement with authenticated encryption and AES key wrap encryption with 256-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://datatracker.ietf.org/doc/draft-madden-jose-ecdh-1pu-04/">ECDH-1PU+A256KW</see>.</remarks>
        public static readonly string Ecdh1PuA256Kw = "ECDH-1PU+A256KW";

        /// <summary>
        /// AES GCM key encryption with 128-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.7">A128GCMKW</see>.</remarks>
        public static readonly string A128GcmKw = "A128GCMKW";

        /// <summary>
        /// AES GCM key encryption with 192-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.7">A192GCMKW</see>.</remarks>
        public static readonly string A192GcmKw = "A192GCMKW";

        /// <summary>
        /// AES GCM key encryption with 256-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.7">A256GCMKW</see>.</remarks>
        public static readonly string A256GcmKw = "A256GCMKW";

        /// <summary>
        /// PBES2 key encryption with SHA-256 and AES key wrap with 128-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.8.1.2">PBES2-HS256+A128KW</see>.</remarks>
        public static readonly string Pbes2Hs256A128Kw = "PBES2-HS256+A128KW";

        /// <summary>
        /// PBES2 key encryption with SHA-384 and AES key wrap with 192-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.8.1.2">PBES2-HS384+A192KW</see>.</remarks>
        public static readonly string Pbes2Hs384A192Kw = "PBES2-HS384+A192KW";

        /// <summary>
        /// PBES2 key encryption with SHA-512 and AES key wrap with 256-bit key.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-4.8.1.2">PBES2-HS512+A256KW</see>.</remarks>
        public static readonly string Pbes2Hs512A256Kw = "PBES2-HS512+A256KW";


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="Rsa15"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="Rsa15"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsRsa15(string algorithm)
        {
            return Equals(Rsa15, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="RsaOaep"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="RsaOaep"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsRsaOaep(string algorithm)
        {
            return Equals(RsaOaep, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="RsaOaep256"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="RsaOaep256"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsRsaOaep256(string algorithm)
        {
            return Equals(RsaOaep256, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A128Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="A128Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsA128Kw(string algorithm)
        {
            return Equals(A128Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A192Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="A192Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsA192Kw(string algorithm)
        {
            return Equals(A192Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A256Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="A256Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsA256Kw(string algorithm)
        {
            return Equals(A256Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="Dir"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="Dir"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsDir(string algorithm)
        {
            return Equals(Dir, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="EcdhEs"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="EcdhEs"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEcdhEs(string algorithm)
        {
            return Equals(EcdhEs, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="EcdhEsA128Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="EcdhEsA128Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEcdhEsA128Kw(string algorithm)
        {
            return Equals(EcdhEsA128Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="EcdhEsA192Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="EcdhEsA192Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEcdhEsA192Kw(string algorithm)
        {
            return Equals(EcdhEsA192Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="EcdhEsA256Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="EcdhEsA256Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEcdhEsA256Kw(string algorithm)
        {
            return Equals(EcdhEsA256Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="Ecdh1Pu"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="Ecdh1Pu"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEcdh1Pu(string algorithm)
        {
            return Equals(Ecdh1Pu, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="Ecdh1PuA128Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="Ecdh1PuA128Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEcdh1PuA128Kw(string algorithm)
        {
            return Equals(Ecdh1PuA128Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="Ecdh1PuA192Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="Ecdh1PuA192Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEcdh1PuA192Kw(string algorithm)
        {
            return Equals(Ecdh1PuA192Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="Ecdh1PuA256Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="Ecdh1PuA256Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsEcdh1PuA256Kw(string algorithm)
        {
            return Equals(Ecdh1PuA256Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A128GcmKw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="A128GcmKw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsA128GcmKw(string algorithm)
        {
            return Equals(A128GcmKw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A192GcmKw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="A192GcmKw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsA192GcmKw(string algorithm)
        {
            return Equals(A192GcmKw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A256GcmKw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="A256GcmKw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsA256GcmKw(string algorithm)
        {
            return Equals(A256GcmKw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="Pbes2Hs256A128Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="Pbes2Hs256A128Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsPbes2Hs256A128Kw(string algorithm)
        {
            return Equals(Pbes2Hs256A128Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="Pbes2Hs384A192Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="Pbes2Hs384A192Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsPbes2Hs384A192Kw(string algorithm)
        {
            return Equals(Pbes2Hs384A192Kw, algorithm);
        }


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="Pbes2Hs512A256Kw"/> or not.
        /// </summary>
        /// <param name="algorithm"></param>
        /// <returns><see langword="true" /> if is <see cref="Pbes2Hs512A256Kw"/>; otherwise, <see langword="false" /></returns>.
        public static bool IsPbes2Hs512A256Kw(string algorithm)
        {
            return Equals(Pbes2Hs512A256Kw, algorithm);
        }


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="algorithm">The property to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="algorithm"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string algorithm) => algorithm switch
        {
            string _ when IsRsa15(algorithm) => Rsa15,
            string _ when IsRsaOaep(algorithm) => RsaOaep,
            string _ when IsRsaOaep256(algorithm) => RsaOaep256,
            string _ when IsA128Kw(algorithm) => A128Kw,
            string _ when IsA192Kw(algorithm) => A192Kw,
            string _ when IsA256Kw(algorithm) => A256Kw,
            string _ when IsDir(algorithm) => Dir,
            string _ when IsEcdhEs(algorithm) => EcdhEs,
            string _ when IsEcdhEsA128Kw(algorithm) => EcdhEsA128Kw,
            string _ when IsEcdhEsA192Kw(algorithm) => EcdhEsA192Kw,
            string _ when IsEcdhEsA256Kw(algorithm) => EcdhEsA256Kw,
            string _ when IsEcdh1Pu(algorithm) => Ecdh1Pu,
            string _ when IsEcdh1PuA128Kw(algorithm) => Ecdh1PuA128Kw,
            string _ when IsEcdh1PuA192Kw(algorithm) => Ecdh1PuA192Kw,
            string _ when IsEcdh1PuA256Kw(algorithm) => Ecdh1PuA256Kw,
            string _ when IsA128GcmKw(algorithm) => A128GcmKw,
            string _ when IsA192GcmKw(algorithm) => A192GcmKw,
            string _ when IsA256GcmKw(algorithm) => A256GcmKw,
            string _ when IsPbes2Hs256A128Kw(algorithm) => Pbes2Hs256A128Kw,
            string _ when IsPbes2Hs384A192Kw(algorithm) => Pbes2Hs384A192Kw,
            string _ when IsPbes2Hs512A256Kw(algorithm) => Pbes2Hs512A256Kw,
            string _ => algorithm
        };


        /// <summary>
        /// Returns a value that indicates if the algorithms are the same.
        /// </summary>
        /// <param name="algorithmA">The first algorithm to compare.</param>
        /// <param name="algorithmB">The second algorithm to compare.</param>
        /// <returns>
        /// <see langword="true" /> if the <paramref name="algorithmA"/> and <paramref name="algorithmB"/> are the same; otherwise, <see langword="false" />.
        /// </returns>
        public static bool Equals(string algorithmA, string algorithmB)
        {
            return object.ReferenceEquals(algorithmA, algorithmB) || StringComparer.InvariantCulture.Equals(algorithmA, algorithmB);
        }
    }
}
