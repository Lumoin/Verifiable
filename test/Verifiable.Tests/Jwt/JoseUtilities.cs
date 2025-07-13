using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Jwt;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Provides cryptographic utilities for JSON Web Key (JWK) operations according to <see href="https://tools.ietf.org/html/rfc7517">RFC 7517</see> and <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>.
    /// Implements JWK thumbprint computation as specified in <see href="https://tools.ietf.org/html/rfc7638#section-3">RFC 7638 Section 3</see>.
    /// All operations use secure memory management and support multiple cryptographic backends.
    /// </summary>
    public static class JoseUtilities
    {
        //Default memory pool for sensitive cryptographic operations.
        private static MemoryPool<byte> DefaultPool { get; } = SensitiveMemoryPool<byte>.Shared;

        //SHA-256 hash size in bytes as defined by <see href="https://tools.ietf.org/html/rfc6234">RFC 6234</see>.
        private const int Sha256HashSize = 32;

        //Maximum size for stack allocation to avoid stack overflow.
        private const int StackAllocThreshold = 1024;

        /// <summary>
        /// Computes the JWK thumbprint for an Elliptic Curve key according to <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>.
        /// Uses the default sensitive memory pool for secure operations.
        /// </summary>
        /// <param name="crv">The curve name (e.g., "P-256", "P-384", "P-521", "secp256k1").</param>
        /// <param name="kty">The key type, must be "EC" for elliptic curve keys.</param>
        /// <param name="x">The x coordinate of the public key point, base64url-encoded.</param>
        /// <param name="y">The y coordinate of the public key point, base64url-encoded.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeECThumbprint(string crv, string kty, string x, string y) => ComputeECThumbprint(DefaultPool, crv, kty, x, y);

        /// <summary>
        /// Computes the JWK thumbprint for an Elliptic Curve Diffie-Hellman key according to <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>.
        /// Uses the default sensitive memory pool for secure operations.
        /// </summary>
        /// <param name="crv">The curve name (e.g., "X25519", "X448").</param>
        /// <param name="kty">The key type, must be "OKP" for Octet Key Pair.</param>
        /// <param name="x">The public key value, base64url-encoded.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeEcdhThumbprint(string crv, string kty, string x) => ComputeEcdhThumbprint(DefaultPool, crv, kty, x);

        /// <summary>
        /// Computes the JWK thumbprint for an Edwards Digital Signature Algorithm key according to <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>.
        /// Uses the default sensitive memory pool for secure operations.
        /// </summary>
        /// <param name="crv">The curve name (e.g., "Ed25519", "Ed448").</param>
        /// <param name="kty">The key type, must be "OKP" for Octet Key Pair.</param>
        /// <param name="x">The public key value, base64url-encoded.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeEdDsaThumbprint(string crv, string kty, string x) => ComputeEdDsaThumbprint(DefaultPool, crv, kty, x);

        /// <summary>
        /// Computes the JWK thumbprint for an RSA key according to <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>.
        /// Uses the default sensitive memory pool for secure operations.
        /// </summary>
        /// <param name="e">The public exponent, base64url-encoded (typically "AQAB" for 65537).</param>
        /// <param name="kty">The key type, must be "RSA" for RSA keys.</param>
        /// <param name="n">The modulus, base64url-encoded.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeRsaThumbprint(string e, string kty, string n) => ComputeRsaThumbprint(DefaultPool, e, kty, n);

        /// <summary>
        /// Computes the JWK thumbprint for a symmetric key according to <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>.
        /// Uses the default sensitive memory pool for secure operations.
        /// </summary>
        /// <param name="k">The symmetric key value, base64url-encoded.</param>
        /// <param name="kty">The key type, must be "oct" for octet sequences.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeOctThumbprint(string k, string kty) => ComputeOctThumbprint(DefaultPool, k, kty);

        /// <summary>
        /// Computes the JWK thumbprint for an Elliptic Curve key using a custom memory pool.
        /// The canonical JSON representation follows <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see> with lexicographically sorted keys.
        /// Format: {"crv":"curve","kty":"EC","x":"x-coordinate","y":"y-coordinate"}
        /// </summary>
        /// <param name="pool">The memory pool to use for secure memory allocation.</param>
        /// <param name="crv">The curve name (e.g., "P-256", "P-384", "P-521", "secp256k1").</param>
        /// <param name="kty">The key type, must be "EC" for elliptic curve keys.</param>
        /// <param name="x">The x coordinate of the public key point, base64url-encoded.</param>
        /// <param name="y">The y coordinate of the public key point, base64url-encoded.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeECThumbprint(MemoryPool<byte> pool, string crv, string kty, string x, string y)
        {
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(crv);
            ArgumentNullException.ThrowIfNull(kty);
            ArgumentNullException.ThrowIfNull(x);
            ArgumentNullException.ThrowIfNull(y);

            //Calculate exact buffer size for JSON: {"crv":"","kty":"","x":"","y":""}.
            var exactLength = JwkTemplateConstants.EcTemplateOverhead + crv.Length + kty.Length + x.Length + y.Length;

            using var tempBuffer = pool.Rent(exactLength);
            var buffer = tempBuffer.Memory.Span;
            var position = 0;

            //Build canonical JSON representation with lexicographically sorted keys.
            WriteUtf8Literal(buffer, ref position, "{\"");
            WriteUtf8String(buffer, ref position, JwkProperties.Crv);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, crv);
            WriteUtf8Literal(buffer, ref position, "\",\"");
            WriteUtf8String(buffer, ref position, JwkProperties.Kty);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, kty);
            WriteUtf8Literal(buffer, ref position, "\",\"");
            WriteUtf8String(buffer, ref position, JwkProperties.X);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, x);
            WriteUtf8Literal(buffer, ref position, "\",\"");
            WriteUtf8String(buffer, ref position, JwkProperties.Y);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, y);
            WriteUtf8Literal(buffer, ref position, "\"}");

            return ComputeSha256Hash(pool, buffer[..position]);
        }

        /// <summary>
        /// Computes the JWK thumbprint for an Elliptic Curve Diffie-Hellman key using a custom memory pool.
        /// The canonical JSON representation follows <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see> with lexicographically sorted keys.
        /// Format: {"crv":"curve","kty":"OKP","x":"public-key"}
        /// </summary>
        /// <param name="pool">The memory pool to use for secure memory allocation.</param>
        /// <param name="crv">The curve name (e.g., "X25519", "X448").</param>
        /// <param name="kty">The key type, must be "OKP" for Octet Key Pair.</param>
        /// <param name="x">The public key value, base64url-encoded.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeEcdhThumbprint(MemoryPool<byte> pool, string crv, string kty, string x)
        {
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(crv);
            ArgumentNullException.ThrowIfNull(kty);
            ArgumentNullException.ThrowIfNull(x);

            //Calculate exact buffer size for JSON: {"crv":"","kty":"","x":""}.
            var exactLength = JwkTemplateConstants.OkpTemplateOverhead + crv.Length + kty.Length + x.Length;

            using var tempBuffer = pool.Rent(exactLength);
            var buffer = tempBuffer.Memory.Span;
            var position = 0;

            //Build canonical JSON representation with lexicographically sorted keys.
            WriteUtf8Literal(buffer, ref position, "{\"");
            WriteUtf8String(buffer, ref position, JwkProperties.Crv);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, crv);
            WriteUtf8Literal(buffer, ref position, "\",\"");
            WriteUtf8String(buffer, ref position, JwkProperties.Kty);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, kty);
            WriteUtf8Literal(buffer, ref position, "\",\"");
            WriteUtf8String(buffer, ref position, JwkProperties.X);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, x);
            WriteUtf8Literal(buffer, ref position, "\"}");

            return ComputeSha256Hash(pool, buffer[..position]);
        }

        /// <summary>
        /// Computes the JWK thumbprint for an Edwards Digital Signature Algorithm key using a custom memory pool.
        /// The canonical JSON representation follows <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see> with lexicographically sorted keys.
        /// Format: {"crv":"curve","kty":"OKP","x":"public-key"}
        /// </summary>
        /// <param name="pool">The memory pool to use for secure memory allocation.</param>
        /// <param name="crv">The curve name (e.g., "Ed25519", "Ed448").</param>
        /// <param name="kty">The key type, must be "OKP" for Octet Key Pair.</param>
        /// <param name="x">The public key value, base64url-encoded.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeEdDsaThumbprint(MemoryPool<byte> pool, string crv, string kty, string x)
        {
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(crv);
            ArgumentNullException.ThrowIfNull(kty);
            ArgumentNullException.ThrowIfNull(x);

            //Same structure as ECDH: {"crv":"","kty":"","x":""}.
            var exactLength = JwkTemplateConstants.OkpTemplateOverhead + crv.Length + kty.Length + x.Length;

            using var tempBuffer = pool.Rent(exactLength);
            var buffer = tempBuffer.Memory.Span;
            var position = 0;

            //Build canonical JSON representation with lexicographically sorted keys.
            WriteUtf8Literal(buffer, ref position, "{\"");
            WriteUtf8String(buffer, ref position, JwkProperties.Crv);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, crv);
            WriteUtf8Literal(buffer, ref position, "\",\"");
            WriteUtf8String(buffer, ref position, JwkProperties.Kty);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, kty);
            WriteUtf8Literal(buffer, ref position, "\",\"");
            WriteUtf8String(buffer, ref position, JwkProperties.X);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, x);
            WriteUtf8Literal(buffer, ref position, "\"}");

            return ComputeSha256Hash(pool, buffer[..position]);
        }

        /// <summary>
        /// Computes the JWK thumbprint for an RSA key using a custom memory pool.
        /// The canonical JSON representation follows <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see> with lexicographically sorted keys.
        /// Format: {"e":"exponent","kty":"RSA","n":"modulus"}
        /// </summary>
        /// <param name="pool">The memory pool to use for secure memory allocation.</param>
        /// <param name="e">The public exponent, base64url-encoded (typically "AQAB" for 65537).</param>
        /// <param name="kty">The key type, must be "RSA" for RSA keys.</param>
        /// <param name="n">The modulus, base64url-encoded.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeRsaThumbprint(MemoryPool<byte> pool, string e, string kty, string n)
        {
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(e);
            ArgumentNullException.ThrowIfNull(kty);
            ArgumentNullException.ThrowIfNull(n);

            //Calculate exact buffer size for JSON: {"e":"","kty":"","n":""}.
            var exactLength = JwkTemplateConstants.RsaTemplateOverhead + e.Length + kty.Length + n.Length;

            using var tempBuffer = pool.Rent(exactLength);
            var buffer = tempBuffer.Memory.Span;
            var position = 0;

            //Build canonical JSON representation with lexicographically sorted keys.
            WriteUtf8Literal(buffer, ref position, "{\"");
            WriteUtf8String(buffer, ref position, JwkProperties.E);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, e);
            WriteUtf8Literal(buffer, ref position, "\",\"");
            WriteUtf8String(buffer, ref position, JwkProperties.Kty);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, kty);
            WriteUtf8Literal(buffer, ref position, "\",\"");
            WriteUtf8String(buffer, ref position, JwkProperties.N);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, n);
            WriteUtf8Literal(buffer, ref position, "\"}");

            return ComputeSha256Hash(pool, buffer[..position]);
        }

        /// <summary>
        /// Computes the JWK thumbprint for a symmetric key using a custom memory pool.
        /// The canonical JSON representation follows <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see> with lexicographically sorted keys.
        /// Format: {"k":"key-value","kty":"oct"}
        /// </summary>
        /// <param name="pool">The memory pool to use for secure memory allocation.</param>
        /// <param name="k">The symmetric key value, base64url-encoded.</param>
        /// <param name="kty">The key type, must be "oct" for octet sequences.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeOctThumbprint(MemoryPool<byte> pool, string k, string kty)
        {
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(k);
            ArgumentNullException.ThrowIfNull(kty);

            //Calculate exact buffer size for JSON: {"k":"","kty":""}.
            var exactLength = JwkTemplateConstants.OctTemplateOverhead + k.Length + kty.Length;

            using var tempBuffer = pool.Rent(exactLength);
            var buffer = tempBuffer.Memory.Span;
            var position = 0;

            //Build canonical JSON representation with lexicographically sorted keys.
            WriteUtf8Literal(buffer, ref position, "{\"");
            WriteUtf8String(buffer, ref position, JwkProperties.K);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, k);
            WriteUtf8Literal(buffer, ref position, "\",\"");
            WriteUtf8String(buffer, ref position, JwkProperties.Kty);
            WriteUtf8Literal(buffer, ref position, "\":\"");
            WriteUtf8String(buffer, ref position, kty);
            WriteUtf8Literal(buffer, ref position, "\"}");

            return ComputeSha256Hash(pool, buffer[..position]);
        }

        /// <summary>
        /// Computes the JWK thumbprint for any key type using a generic approach.
        /// This method handles arbitrary JWK parameters and ensures proper lexicographical ordering according to <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see>.
        /// </summary>
        /// <param name="pool">The memory pool to use for secure memory allocation.</param>
        /// <param name="jwkParameters">Dictionary containing JWK parameters to include in thumbprint computation.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        /// <exception cref="ArgumentNullException">Thrown when pool or jwkParameters is null.</exception>
        /// <exception cref="ArgumentException">Thrown when jwkParameters is empty.</exception>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        public static IMemoryOwner<byte> ComputeGenericThumbprint(MemoryPool<byte> pool, IDictionary<string, string> jwkParameters)
        {
            ArgumentNullException.ThrowIfNull(pool);
            ArgumentNullException.ThrowIfNull(jwkParameters);

            if(jwkParameters.Count == 0)
            {
                throw new ArgumentException("JWK parameters cannot be empty.", nameof(jwkParameters));
            }

            //Sort parameters lexicographically as required by RFC 7638.
            var sortedParams = jwkParameters.OrderBy(kvp => kvp.Key, StringComparer.Ordinal).ToList();

            //Calculate exact buffer size needed for JSON representation.
            var exactLength = CalculateJsonLength(sortedParams);

            using var tempBuffer = pool.Rent(exactLength);
            var buffer = tempBuffer.Memory.Span;
            var position = 0;

            //Build canonical JSON representation.
            WriteUtf8Literal(buffer, ref position, "{");
            for(int i = 0; i < sortedParams.Count; i++)
            {
                if(i > 0)
                {
                    WriteUtf8Literal(buffer, ref position, ",");
                }

                WriteUtf8Literal(buffer, ref position, "\"");
                WriteUtf8String(buffer, ref position, sortedParams[i].Key);
                WriteUtf8Literal(buffer, ref position, "\":\"");
                WriteUtf8String(buffer, ref position, sortedParams[i].Value);
                WriteUtf8Literal(buffer, ref position, "\"");
            }
            WriteUtf8Literal(buffer, ref position, "}");

            return ComputeSha256Hash(pool, buffer[..position]);
        }

        /// <summary>
        /// Computes the JWK thumbprint for any key type using the default memory pool.
        /// </summary>
        /// <param name="jwkParameters">Dictionary containing JWK parameters to include in thumbprint computation.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
        public static IMemoryOwner<byte> ComputeGenericThumbprint(IDictionary<string, string> jwkParameters)
            => ComputeGenericThumbprint(DefaultPool, jwkParameters);

        /// <summary>
        /// Computes SHA-256 hash of the input data using the specified memory pool.
        /// </summary>
        /// <param name="pool">The memory pool to use for hash output allocation.</param>
        /// <param name="input">The input data to hash.</param>
        /// <returns>An IMemoryOwner containing the SHA-256 hash result.</returns>
        /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
        private static IMemoryOwner<byte> ComputeSha256Hash(MemoryPool<byte> pool, ReadOnlySpan<byte> input)
        {
            var owner = pool.Rent(Sha256HashSize);

            if(!SHA256.TryHashData(input, owner.Memory.Span, out var bytesWritten) || bytesWritten != Sha256HashSize)
            {
                owner.Dispose();
                throw new InvalidOperationException("Failed to compute SHA-256 hash.");
            }

            return owner;
        }

        /// <summary>
        /// Writes a UTF-8 string literal to the buffer at the specified position.
        /// </summary>
        /// <param name="buffer">The destination buffer.</param>
        /// <param name="position">The current position in the buffer, updated after writing.</param>
        /// <param name="literal">The string literal to write.</param>
        private static void WriteUtf8Literal(Span<byte> buffer, ref int position, string literal)
        {
            var bytesWritten = Encoding.UTF8.GetBytes(literal, buffer.Slice(position));
            position += bytesWritten;
        }

        /// <summary>
        /// Writes a UTF-8 string to the buffer at the specified position.
        /// </summary>
        /// <param name="buffer">The destination buffer.</param>
        /// <param name="position">The current position in the buffer, updated after writing.</param>
        /// <param name="value">The string value to write.</param>
        private static void WriteUtf8String(Span<byte> buffer, ref int position, string value)
        {
            var bytesWritten = Encoding.UTF8.GetBytes(value, buffer.Slice(position));
            position += bytesWritten;
        }

        /// <summary>
        /// Calculates the exact length needed for JSON representation of sorted JWK parameters.
        /// </summary>
        /// <param name="sortedParams">The sorted JWK parameters.</param>
        /// <returns>The exact byte length needed for JSON representation.</returns>
        private static int CalculateJsonLength(IList<KeyValuePair<string, string>> sortedParams)
        {
            var length = 2; // '{' and '}'
            for(int i = 0; i < sortedParams.Count; i++)
            {
                if(i > 0)
                {
                    length += 1; // ','
                }
                length += 5; // '"', '"', ':', '"', '"'
                length += sortedParams[i].Key.Length + sortedParams[i].Value.Length;
            }

            return length;
        }
    }

    /// <summary>
    /// Contains constants for JWK template overhead calculations and standard parameter values.
    /// These values are used to optimize memory allocation for JWK thumbprint computations.
    /// All constants align with the well-known values from <see cref="JwkProperties"/>, <see cref="WellKnownKeyTypeValues"/>, and <see cref="WellKnownCurveValues"/>.
    /// </summary>
    public static class JwkTemplateConstants
    {
        /// <summary>
        /// Template overhead for EC keys: {"crv":"","kty":"","x":"","y":""}.
        /// </summary>
        public const int EcTemplateOverhead = 46;

        /// <summary>
        /// Template overhead for OKP keys: {"crv":"","kty":"","x":""}.
        /// </summary>
        public const int OkpTemplateOverhead = 32;

        /// <summary>
        /// Template overhead for RSA keys: {"e":"","kty":"","n":""}.
        /// </summary>
        public const int RsaTemplateOverhead = 32;

        /// <summary>
        /// Template overhead for oct keys: {"k":"","kty":""}.
        /// </summary>
        public const int OctTemplateOverhead = 20;

        /// <summary>
        /// Standard RSA public exponent (65537) in base64url encoding.
        /// </summary>
        public const string RsaStandardExponent = "AQAB";

        /// <summary>
        /// Expected coordinate length for P-256 curve (43 base64url characters).
        /// </summary>
        public const int P256CoordinateLength = 43;

        /// <summary>
        /// Expected coordinate length for P-384 curve (64 base64url characters).
        /// </summary>
        public const int P384CoordinateLength = 64;

        /// <summary>
        /// Expected coordinate length for P-521 curve (88 base64url characters).
        /// </summary>
        public const int P521CoordinateLength = 88;

        /// <summary>
        /// Expected coordinate length for secp256k1 curve (43 base64url characters).
        /// </summary>
        public const int Secp256k1CoordinateLength = 43;

        /// <summary>
        /// Expected key length for Ed25519 (43 base64url characters).
        /// </summary>
        public const int Ed25519KeyLength = 43;

        /// <summary>
        /// Expected key length for X25519 (43 base64url characters).
        /// </summary>
        public const int X25519KeyLength = 43;
    }
}