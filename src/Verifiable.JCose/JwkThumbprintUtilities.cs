using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Jose;

namespace Verifiable.JCose;

/// <summary>
/// Provides cryptographic utilities for JSON Web Key (JWK) operations according to <see href="https://tools.ietf.org/html/rfc7517">RFC 7517</see> and <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>.
/// Implements JWK thumbprint computation as specified in <see href="https://tools.ietf.org/html/rfc7638#section-3">RFC 7638 Section 3</see>.
/// All operations use secure memory management and support multiple cryptographic backends.
/// </summary>
public static class JwkThumbprintUtilities
{
    /// <summary>
    /// Default memory pool for exact length (and potentially sensitive) memory operations.
    /// </summary>
    private static MemoryPool<byte> DefaultPool { get; } = SensitiveMemoryPool<byte>.Shared;

    /// <summary>
    /// SHA-256 hash size in bytes as defined by <see href="https://tools.ietf.org/html/rfc6234">RFC 6234</see>
    /// </summary>
    private const int Sha256HashSize = 32;


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
    /// Computes the JWK thumbprint for an ML-DSA key according to <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/">draft-ietf-cose-dilithium</see>.
    /// Uses the default sensitive memory pool for secure operations.
    /// </summary>
    /// <param name="alg">The algorithm identifier (e.g., "MLDSA44", "MLDSA65", "MLDSA87").</param>
    /// <param name="kty">The key type, must be "MLDSA" for ML-DSA keys.</param>
    /// <param name="x">The public key value, base64url-encoded.</param>
    /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
    public static IMemoryOwner<byte> ComputeMlDsaThumbprint(string alg, string kty, string x) => ComputeMlDsaThumbprint(DefaultPool, alg, kty, x);

    /// <summary>
    /// Computes the JWK thumbprint for an ML-KEM key according to <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-kyber/">draft-ietf-cose-kyber</see>.
    /// Uses the default sensitive memory pool for secure operations.
    /// </summary>
    /// <param name="alg">The algorithm identifier (e.g., "MLKEM512", "MLKEM768", "MLKEM1024").</param>
    /// <param name="kty">The key type, must be "MLKEM" for ML-KEM keys.</param>
    /// <param name="x">The encapsulation key, base64url-encoded.</param>
    /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
    public static IMemoryOwner<byte> ComputeMlKemThumbprint(string alg, string kty, string x) => ComputeMlKemThumbprint(DefaultPool, alg, kty, x);

    /// <summary>
    /// Computes the JWK thumbprint for an SLH-DSA key according to <see href="https://datatracker.ietf.org/doc/draft-ietf-cose-sphincs-plus/">draft-ietf-cose-sphincs-plus</see>.
    /// Uses the default sensitive memory pool for secure operations.
    /// </summary>
    /// <param name="alg">The algorithm identifier (e.g., "SLHDSA128f", "SLHDSA128s", "SLHDSA192f", "SLHDSA192s", "SLHDSA256f", "SLHDSA256s").</param>
    /// <param name="kty">The key type, must be "SLHDSA" for SLH-DSA keys.</param>
    /// <param name="x">The public key value, base64url-encoded.</param>
    /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
    public static IMemoryOwner<byte> ComputeSlhDsaThumbprint(string alg, string kty, string x) => ComputeSlhDsaThumbprint(DefaultPool, alg, kty, x);

    /// <summary>
    /// Computes the JWK thumbprint for any key type using the default memory pool.
    /// This method handles arbitrary JWK parameters and ensures proper lexicographical ordering according to <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see>.
    /// </summary>
    /// <param name="jwkParameters">Dictionary containing JWK parameters to include in thumbprint computation.</param>
    /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when jwkParameters is null.</exception>
    /// <exception cref="ArgumentException">Thrown when jwkParameters is empty.</exception>
    /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
    public static IMemoryOwner<byte> ComputeGenericThumbprint(IDictionary<string, string> jwkParameters) => ComputeGenericThumbprint(DefaultPool, jwkParameters);

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
        var exactLength = JwkTemplateConstants.EcTemplateOverhead +
            Encoding.UTF8.GetByteCount(crv) +
            Encoding.UTF8.GetByteCount(kty) +
            Encoding.UTF8.GetByteCount(x) +
            Encoding.UTF8.GetByteCount(y);

        using var tempBuffer = pool.Rent(exactLength);
        var buffer = tempBuffer.Memory.Span;
        var writer = new JsonWriter(buffer);

        //Build canonical JSON representation with lexicographically sorted keys.
        writer.WriteObjectStart();
        writer.WriteProperty(JwkProperties.Crv, crv);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.Kty, kty);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.X, x);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.Y, y);
        writer.WriteObjectEnd();

        return ComputeSha256Hash(pool, buffer[..writer.Position]);
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
        var exactLength = JwkTemplateConstants.OkpTemplateOverhead +
            Encoding.UTF8.GetByteCount(crv) +
            Encoding.UTF8.GetByteCount(kty) +
            Encoding.UTF8.GetByteCount(x);

        using var tempBuffer = pool.Rent(exactLength);
        var buffer = tempBuffer.Memory.Span;
        var writer = new JsonWriter(buffer);

        //Build canonical JSON representation with lexicographically sorted keys.
        writer.WriteObjectStart();
        writer.WriteProperty(JwkProperties.Crv, crv);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.Kty, kty);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.X, x);
        writer.WriteObjectEnd();

        return ComputeSha256Hash(pool, buffer[..writer.Position]);
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
        var exactLength = JwkTemplateConstants.OkpTemplateOverhead +
            Encoding.UTF8.GetByteCount(crv) +
            Encoding.UTF8.GetByteCount(kty) +
            Encoding.UTF8.GetByteCount(x);

        using var tempBuffer = pool.Rent(exactLength);
        var buffer = tempBuffer.Memory.Span;
        var writer = new JsonWriter(buffer);

        //Build canonical JSON representation with lexicographically sorted keys.
        writer.WriteObjectStart();
        writer.WriteProperty(JwkProperties.Crv, crv);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.Kty, kty);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.X, x);
        writer.WriteObjectEnd();

        return ComputeSha256Hash(pool, buffer[..writer.Position]);
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
        var exactLength = JwkTemplateConstants.RsaTemplateOverhead +
            Encoding.UTF8.GetByteCount(e) +
            Encoding.UTF8.GetByteCount(kty) +
            Encoding.UTF8.GetByteCount(n);

        using var tempBuffer = pool.Rent(exactLength);
        var buffer = tempBuffer.Memory.Span;
        var writer = new JsonWriter(buffer);

        //Build canonical JSON representation with lexicographically sorted keys.
        writer.WriteObjectStart();
        writer.WriteProperty(JwkProperties.E, e);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.Kty, kty);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.N, n);
        writer.WriteObjectEnd();

        return ComputeSha256Hash(pool, buffer[..writer.Position]);
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
        var exactLength = JwkTemplateConstants.OctTemplateOverhead +
            Encoding.UTF8.GetByteCount(k) +
            Encoding.UTF8.GetByteCount(kty);

        using var tempBuffer = pool.Rent(exactLength);
        var buffer = tempBuffer.Memory.Span;
        var writer = new JsonWriter(buffer);

        //Build canonical JSON representation with lexicographically sorted keys.
        writer.WriteObjectStart();
        writer.WriteProperty(JwkProperties.K, k);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.Kty, kty);
        writer.WriteObjectEnd();

        return ComputeSha256Hash(pool, buffer[..writer.Position]);
    }

    /// <summary>
    /// Computes the JWK thumbprint for an ML-DSA (Dilithium) key using a custom memory pool.
    /// The canonical JSON representation follows <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see> with lexicographically sorted keys.
    /// Format: {"alg":"algorithm","kty":"MLDSA","x":"public-key"}
    /// </summary>
    /// <param name="pool">The memory pool to use for secure memory allocation.</param>
    /// <param name="alg">The algorithm identifier (e.g., "MLDSA44", "MLDSA65", "MLDSA87").</param>
    /// <param name="kty">The key type, must be "MLDSA" for ML-DSA keys.</param>
    /// <param name="x">The public key value, base64url-encoded.</param>
    /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
    public static IMemoryOwner<byte> ComputeMlDsaThumbprint(MemoryPool<byte> pool, string alg, string kty, string x)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(alg);
        ArgumentNullException.ThrowIfNull(kty);
        ArgumentNullException.ThrowIfNull(x);

        //Calculate exact buffer size for JSON: {"alg":"","kty":"","x":""}.
        var exactLength = JwkTemplateConstants.PqcTemplateOverhead +
            Encoding.UTF8.GetByteCount(alg) +
            Encoding.UTF8.GetByteCount(kty) +
            Encoding.UTF8.GetByteCount(x);

        using var tempBuffer = pool.Rent(exactLength);
        var buffer = tempBuffer.Memory.Span;
        var writer = new JsonWriter(buffer);

        //Build canonical JSON representation with lexicographically sorted keys.
        writer.WriteObjectStart();
        writer.WriteProperty(JwkProperties.Alg, alg);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.Kty, kty);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.X, x);
        writer.WriteObjectEnd();

        return ComputeSha256Hash(pool, buffer[..writer.Position]);
    }

    /// <summary>
    /// Computes the JWK thumbprint for an ML-KEM (Kyber) key using a custom memory pool.
    /// The canonical JSON representation follows <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see> with lexicographically sorted keys.
    /// Format: {"alg":"algorithm","kty":"MLKEM","x":"encapsulation-key"}
    /// </summary>
    /// <param name="pool">The memory pool to use for secure memory allocation.</param>
    /// <param name="alg">The algorithm identifier (e.g., "MLKEM512", "MLKEM768", "MLKEM1024").</param>
    /// <param name="kty">The key type, must be "MLKEM" for ML-KEM keys.</param>
    /// <param name="x">The encapsulation key, base64url-encoded.</param>
    /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
    public static IMemoryOwner<byte> ComputeMlKemThumbprint(MemoryPool<byte> pool, string alg, string kty, string x)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(alg);
        ArgumentNullException.ThrowIfNull(kty);
        ArgumentNullException.ThrowIfNull(x);

        //Same structure as ML-DSA: {"alg":"","kty":"","x":""}.
        var exactLength = JwkTemplateConstants.PqcTemplateOverhead +
            Encoding.UTF8.GetByteCount(alg) +
            Encoding.UTF8.GetByteCount(kty) +
            Encoding.UTF8.GetByteCount(x);

        using var tempBuffer = pool.Rent(exactLength);
        var buffer = tempBuffer.Memory.Span;
        var writer = new JsonWriter(buffer);

        //Build canonical JSON representation with lexicographically sorted keys.
        writer.WriteObjectStart();
        writer.WriteProperty(JwkProperties.Alg, alg);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.Kty, kty);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.X, x);
        writer.WriteObjectEnd();

        return ComputeSha256Hash(pool, buffer[..writer.Position]);
    }

    /// <summary>
    /// Computes the JWK thumbprint for an SLH-DSA (SPHINCS+) key using a custom memory pool.
    /// The canonical JSON representation follows <see href="https://tools.ietf.org/html/rfc7638#section-3.1">RFC 7638 Section 3.1</see> with lexicographically sorted keys.
    /// Format: {"alg":"algorithm","kty":"SLHDSA","x":"public-key"}
    /// </summary>
    /// <param name="pool">The memory pool to use for secure memory allocation.</param>
    /// <param name="alg">The algorithm identifier (e.g., "SLHDSA128f", "SLHDSA128s", "SLHDSA192f", "SLHDSA192s", "SLHDSA256f", "SLHDSA256s").</param>
    /// <param name="kty">The key type, must be "SLHDSA" for SLH-DSA keys.</param>
    /// <param name="x">The public key value, base64url-encoded.</param>
    /// <returns>An IMemoryOwner containing the SHA-256 hash of the canonical JWK representation.</returns>
    /// <exception cref="ArgumentNullException">Thrown when any parameter is null.</exception>
    /// <exception cref="InvalidOperationException">Thrown when hash computation fails.</exception>
    public static IMemoryOwner<byte> ComputeSlhDsaThumbprint(MemoryPool<byte> pool, string alg, string kty, string x)
    {
        ArgumentNullException.ThrowIfNull(pool);
        ArgumentNullException.ThrowIfNull(alg);
        ArgumentNullException.ThrowIfNull(kty);
        ArgumentNullException.ThrowIfNull(x);

        //Same structure as ML-DSA and ML-KEM: {"alg":"","kty":"","x":""}.
        var exactLength = JwkTemplateConstants.PqcTemplateOverhead +
            Encoding.UTF8.GetByteCount(alg) +
            Encoding.UTF8.GetByteCount(kty) +
            Encoding.UTF8.GetByteCount(x);

        using var tempBuffer = pool.Rent(exactLength);
        var buffer = tempBuffer.Memory.Span;
        var writer = new JsonWriter(buffer);

        //Build canonical JSON representation with lexicographically sorted keys.
        writer.WriteObjectStart();
        writer.WriteProperty(JwkProperties.Alg, alg);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.Kty, kty);
        writer.WritePropertySeparator();
        writer.WriteProperty(JwkProperties.X, x);
        writer.WriteObjectEnd();

        return ComputeSha256Hash(pool, buffer[..writer.Position]);
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
        var writer = new JsonWriter(buffer);

        //Build canonical JSON representation.
        writer.WriteObjectStart();
        for(int i = 0; i < sortedParams.Count; i++)
        {
            if(i > 0)
            {
                writer.WritePropertySeparator();
            }
            writer.WriteProperty(sortedParams[i].Key, sortedParams[i].Value);
        }
        writer.WriteObjectEnd();

        return ComputeSha256Hash(pool, buffer[..writer.Position]);
    }


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
    /// Calculates the exact length needed for JSON representation of sorted JWK parameters.
    /// </summary>
    /// <param name="sortedParams">The sorted JWK parameters.</param>
    /// <returns>The exact byte length needed for JSON representation.</returns>
    private static int CalculateJsonLength(List<KeyValuePair<string, string>> sortedParams)
    {
        var length = 2; //'{' and '}'.
        for(int i = 0; i < sortedParams.Count; i++)
        {
            if(i > 0)
            {
                length += 1; //','.
            }
            length += 5; //'"', '"', ':', '"', '"'.
            length += Encoding.UTF8.GetByteCount(sortedParams[i].Key) + Encoding.UTF8.GetByteCount(sortedParams[i].Value);
        }

        return length;
    }

    /// <summary>
    /// Lightweight JSON writer for constructing canonical JWK representations.
    /// Optimized for minimal allocations and precise control over output format.
    /// </summary>
    private ref struct JsonWriter
    {
        /// <summary>
        /// The buffer to write JSON output to.
        /// </summary>
        private readonly Span<byte> buffer;

        /// <summary>
        /// The current write position in the buffer.
        /// </summary>
        private int position;

        /// <summary>
        /// Gets the current write position in the buffer.
        /// </summary>
        public readonly int Position => position;

        /// <summary>
        /// Initializes a new instance of the <see cref="JsonWriter"/> struct with the specified buffer.
        /// </summary>
        /// <param name="buffer">The buffer to write JSON output to.</param>
        public JsonWriter(Span<byte> buffer)
        {
            this.buffer = buffer;
            position = 0;
        }

        /// <summary>
        /// Writes the JSON object start character ('{') to the buffer.
        /// </summary>
        public void WriteObjectStart() => WriteLiteral("{"u8);

        /// <summary>
        /// Writes the JSON object end character ('}') to the buffer.
        /// </summary>
        public void WriteObjectEnd() => WriteLiteral("}"u8);

        /// <summary>
        /// Writes the JSON property separator character (',') to the buffer.
        /// </summary>
        public void WritePropertySeparator() => WriteLiteral(","u8);

        /// <summary>
        /// Writes a JSON property (key-value pair) to the buffer in the format "key":"value".
        /// </summary>
        /// <param name="key">The property key.</param>
        /// <param name="value">The property value.</param>
        public void WriteProperty(string key, string value)
        {
            WriteLiteral("\""u8);
            WriteString(key);
            WriteLiteral("\":\""u8);
            WriteString(value);
            WriteLiteral("\""u8);
        }

        /// <summary>
        /// Writes a UTF-8 encoded literal byte sequence to the buffer.
        /// </summary>
        /// <param name="utf8Literal">The UTF-8 encoded literal to write.</param>
        private void WriteLiteral(ReadOnlySpan<byte> utf8Literal)
        {
            utf8Literal.CopyTo(buffer.Slice(position));
            position += utf8Literal.Length;
        }

        /// <summary>
        /// Writes a UTF-8 encoded string to the buffer.
        /// </summary>
        /// <param name="value">The string value to encode and write.</param>
        private void WriteString(string value)
        {
            var bytesWritten = Encoding.UTF8.GetBytes(value, buffer.Slice(position));
            position += bytesWritten;
        }
    }


    /// <summary>
    /// Contains constants for JWK template overhead calculations and standard parameter values.
    /// These values are used to optimize memory allocation for JWK thumbprint computations.
    /// All constants align with the well-known values from <see cref="JwkProperties"/>, <see cref="WellKnownKeyTypeValues"/>, and <see cref="WellKnownCurveValues"/>.
    /// </summary>
    internal static class JwkTemplateConstants
    {
        /// <summary>
        /// SHA-256 hash output size in bytes as defined by <see href="https://tools.ietf.org/html/rfc6234">RFC 6234</see>.
        /// Used for JWK thumbprint computation per <see href="https://tools.ietf.org/html/rfc7638">RFC 7638</see>.
        /// </summary>
        public const int Sha256HashSizeInBytes = 32;

        /// <summary>
        /// Template overhead for EC keys: {"crv":"","kty":"","x":"","y":""}.
        /// Calculated as: 1 ('{') + 7 ('"crv":"') + 7 ('","kty":') + 6 ('","x":') + 6 ('","y":') + 2 ('"}') = 29 base chars + quotes.
        /// </summary>
        public const int EcTemplateOverhead = 46;

        /// <summary>
        /// Template overhead for OKP keys: {"crv":"","kty":"","x":""}.
        /// Calculated as: 1 ('{') + 7 ('"crv":"') + 7 ('","kty":') + 6 ('","x":') + 2 ('"}') = 23 base chars + quotes.
        /// </summary>
        public const int OkpTemplateOverhead = 32;

        /// <summary>
        /// Template overhead for RSA keys: {"e":"","kty":"","n":""}.
        /// Calculated as: 1 ('{') + 5 ('"e":"') + 7 ('","kty":') + 6 ('","n":') + 2 ('"}') = 21 base chars + quotes.
        /// </summary>
        public const int RsaTemplateOverhead = 32;

        /// <summary>
        /// Template overhead for oct keys: {"k":"","kty":""}.
        /// Calculated as: 1 ('{') + 5 ('"k":"') + 7 ('","kty":') + 2 ('"}') = 15 base chars + quotes.
        /// </summary>
        public const int OctTemplateOverhead = 20;

        /// <summary>
        /// Template overhead for post-quantum cryptography keys: {"alg":"","kty":"","x":""}.
        /// Used for ML-DSA, ML-KEM, and SLH-DSA keys.
        /// Calculated as: 1 ('{') + 7 ('"alg":"') + 7 ('","kty":') + 6 ('","x":') + 2 ('"}') = 23 base chars + quotes.
        /// </summary>
        public const int PqcTemplateOverhead = 32;

        /// <summary>
        /// Standard RSA public exponent (65537) in base64url encoding.
        /// </summary>
        public const string RsaStandardExponent = "AQAB";

        /// <summary>
        /// Expected coordinate length for P-256 curve (43 base64url characters for 32 bytes).
        /// </summary>
        public const int P256CoordinateLength = 43;

        /// <summary>
        /// Expected coordinate length for P-384 curve (64 base64url characters for 48 bytes).
        /// </summary>
        public const int P384CoordinateLength = 64;

        /// <summary>
        /// Expected coordinate length for P-521 curve (88 base64url characters for 66 bytes).
        /// </summary>
        public const int P521CoordinateLength = 88;

        /// <summary>
        /// Expected coordinate length for secp256k1 curve (43 base64url characters for 32 bytes).
        /// </summary>
        public const int Secp256k1CoordinateLength = 43;

        /// <summary>
        /// Expected key length for Ed25519 (43 base64url characters for 32 bytes).
        /// </summary>
        public const int Ed25519KeyLength = 43;

        /// <summary>
        /// Expected key length for X25519 (43 base64url characters for 32 bytes).
        /// </summary>
        public const int X25519KeyLength = 43;
    }
}