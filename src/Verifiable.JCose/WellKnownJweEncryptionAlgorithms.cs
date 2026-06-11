using Verifiable.Cryptography.Text;


namespace Verifiable.JCose
{
    /// <summary>    
    /// JSON Web Algorithms (JWA) for JSON Web Encryption (JWE) content encryption algorithms
    /// as defined in <see href="https://www.rfc-editor.org/rfc/rfc7518">RFC 7518</see>.
    /// Additional algorithms are defined in other specifications.
    /// </summary>
    /// <remarks>As per definition parameters are case-sensitive.</remarks>
    public static class WellKnownJweEncryptionAlgorithms
    {
        // <summary>
        /// <summary>The UTF-8 source literal of <see cref="A128CbcHs256"/>.</summary>
        public static ReadOnlySpan<byte> A128CbcHs256Utf8 => "A128CBC-HS256"u8;

        /// AES/CBC/HMAC/SHA authenticated encryption.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">AES_128_CBC_HMAC_SHA_256</see>.</remarks>
        public static readonly string A128CbcHs256 = Utf8Constants.ToInternedString(A128CbcHs256Utf8);

        /// <summary>The UTF-8 source literal of <see cref="A192CbcHs384"/>.</summary>
        public static ReadOnlySpan<byte> A192CbcHs384Utf8 => "A192CBC-HS384"u8;

        /// <summary>
        /// AES_192_CBC_HMAC_SHA_384 authenticated encryption.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">AES_192_CBC_HMAC_SHA_384</see>.</remarks>
        public static readonly string A192CbcHs384 = Utf8Constants.ToInternedString(A192CbcHs384Utf8);

        /// <summary>The UTF-8 source literal of <see cref="A256CbcHs512"/>.</summary>
        public static ReadOnlySpan<byte> A256CbcHs512Utf8 => "A256CBC-HS512"u8;

        /// <summary>
        /// AES_256_CBC_HMAC_SHA_512 authenticated encryption.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.2">AES_256_CBC_HMAC_SHA_512</see>.</remarks>
        public static readonly string A256CbcHs512 = Utf8Constants.ToInternedString(A256CbcHs512Utf8);

        /// <summary>The UTF-8 source literal of <see cref="A128Gcm"/>.</summary>
        public static ReadOnlySpan<byte> A128GcmUtf8 => "A128GCM"u8;

        /// <summary>
        /// AES/GCM authenticated encryption.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.3">AES_GCM</see>.</remarks>
        public static readonly string A128Gcm = Utf8Constants.ToInternedString(A128GcmUtf8);

        /// <summary>The UTF-8 source literal of <see cref="A192Gcm"/>.</summary>
        public static ReadOnlySpan<byte> A192GcmUtf8 => "A192GCM"u8;

        /// <summary>
        /// AES_192/GCM authenticated encryption.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.3">AES_192_GCM</see>.</remarks>
        public static readonly string A192Gcm = Utf8Constants.ToInternedString(A192GcmUtf8);

        /// <summary>The UTF-8 source literal of <see cref="A256Gcm"/>.</summary>
        public static ReadOnlySpan<byte> A256GcmUtf8 => "A256GCM"u8;

        /// <summary>
        /// AES_256/GCM authenticated encryption.
        /// </summary>
        /// <remarks>See more at <see href="https://www.rfc-editor.org/rfc/rfc7518#section-5.3">AES_256_GCM</see>.</remarks>
        public static readonly string A256Gcm = Utf8Constants.ToInternedString(A256GcmUtf8);
               
        /// <summary>The UTF-8 source literal of <see cref="XC20P"/>.</summary>
        public static ReadOnlySpan<byte> XC20PUtf8 => "XC20P"u8;

        /// <summary>
        /// Extended nonce ChaCha20-Poly1305
        /// </summary>
        /// <remarks>See more at <see href="https://tools.ietf.org/html/draft-amringer-jose-chacha-02">ChaCha20-Poly1305</see>.</remarks>
        public static readonly string XC20P = Utf8Constants.ToInternedString(XC20PUtf8);


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A128CbcHs256"/> or not.
        /// </summary>
        /// <param name="algorithm">The algorithm</param>.
        /// <returns><see langword="true" /> if <paramref name="algorithm"/> is <see cref="A128CbcHs256"/>; otherwise, <see langword="false" /></returns>.        
        public static bool IsA128CbcHs256(string algorithm) => Equals(algorithm, A128CbcHs256);


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A192CbcHs384"/> or not.
        /// </summary>
        /// <param name="algorithm">The algorithm</param>.
        /// <returns><see langword="true" /> if <paramref name="algorithm"/> is <see cref="A192CbcHs384"/>; otherwise, <see langword="false" /></returns>.        
        public static bool IsA192CbcHs384(string algorithm) => Equals(algorithm, A192CbcHs384);


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A256CbcHs512"/> or not.
        /// </summary>
        /// <param name="algorithm">The algorithm</param>.
        /// <returns><see langword="true" /> if <paramref name="algorithm"/> is <see cref="A256CbcHs512"/>; otherwise, <see langword="false" /></returns>.        
        public static bool IsA256CbcHs512(string algorithm) => Equals(algorithm, A256CbcHs512);


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A128Gcm"/> or not.
        /// </summary>
        /// <param name="algorithm">The algorithm</param>.
        /// <returns><see langword="true" /> if <paramref name="algorithm"/> is <see cref="A128Gcm"/>; otherwise, <see langword="false" /></returns>.        
        public static bool IsA128Gcm(string algorithm) => Equals(algorithm, A128Gcm);


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A192Gcm"/> or not.
        /// </summary>
        /// <param name="algorithm">The algorithm</param>.
        /// <returns><see langword="true" /> if is <see cref="A192Gcm"/>; otherwise, <see langword="false" /></returns>.        
        public static bool IsA192Gcm(string algorithm) => Equals(algorithm, A192Gcm);


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="A256Gcm"/> or not.
        /// </summary>
        /// <param name="algorithm">The algorithm</param>.
        /// <returns><see langword="true" /> if <paramref name="algorithm"/> is <see cref="A256Gcm"/>; otherwise, <see langword="false" /></returns>.        
        public static bool IsA256Gcm(string algorithm) => Equals(algorithm, A256Gcm);


        /// <summary>
        /// If <paramref name="algorithm"/> is <see cref="XC20P"/> or not.
        /// </summary>
        /// <param name="algorithm">The algorithm</param>.
        /// <returns><see langword="true" /> if <paramref name="algorithm"/> is <see cref="XC20P"/>; otherwise, <see langword="false" /></returns>.        
        public static bool IsXC20P(string algorithm) => Equals(algorithm, XC20P);


        /// <summary>
        /// Returns the equivalent static instance, or the original instance if none match.
        /// This conversion is optional but allows for performance optimizations when comparing method values elsewhere.
        /// </summary>
        /// <param name="algorithm">The property to canocalize.</param>
        /// <returns>The equivalent static instance of <paramref name="algorithm"/>, or the original instance if none match.</returns>
        public static string GetCanonicalizedValue(string algorithm) => algorithm switch
        {
            string _ when IsA128CbcHs256(algorithm) => A128CbcHs256,
            string _ when IsA192CbcHs384(algorithm) => A192CbcHs384,
            string _ when IsA256CbcHs512(algorithm) => A256CbcHs512,
            string _ when IsA128Gcm(algorithm) => A128Gcm,
            string _ when IsA192Gcm(algorithm) => A192Gcm,
            string _ when IsA256Gcm(algorithm) => A256Gcm,
            string _ when IsXC20P(algorithm) => XC20P,
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
            return object.ReferenceEquals(algorithmA, algorithmB) || StringComparer.Ordinal.Equals(algorithmA, algorithmB);
        }
    }
}
