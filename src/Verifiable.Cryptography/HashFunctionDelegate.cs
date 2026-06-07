namespace Verifiable.Cryptography;

/// <summary>
/// Computes a hash digest over <paramref name="source"/> and writes the result
/// into <paramref name="destination"/>, returning the number of bytes written.
/// </summary>
/// <param name="source">The input bytes to hash.</param>
/// <param name="destination">The span to receive the digest bytes.</param>
/// <returns>The number of bytes written to <paramref name="destination"/>.</returns>
/// <remarks>
/// This delegate matches the signature of the standard .NET static hash methods,
/// enabling direct method group usage:
/// <code>
/// HashFunctionDelegate sha256 = SHA256.HashData;
/// HashFunctionDelegate sha384 = SHA384.HashData;
/// HashFunctionDelegate sha512 = SHA512.HashData;
/// </code>
/// The destination span must be sized to match the algorithm output:
/// 32 bytes for SHA-256, 48 bytes for SHA-384, 64 bytes for SHA-512.
/// </remarks>
public delegate int HashFunctionDelegate(ReadOnlySpan<byte> source, Span<byte> destination);