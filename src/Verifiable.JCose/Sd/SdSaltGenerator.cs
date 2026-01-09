using System.Buffers;
using System.Security.Cryptography;

namespace Verifiable.JCose.Sd;

/// <summary>
/// Generates cryptographic salt values for selective disclosures.
/// </summary>
/// <remarks>
/// <para>
/// Per RFC 9901 Section 4.2.2, the salt should be at least 128 bits (16 bytes)
/// of cryptographically secure random data.
/// </para>
/// </remarks>
public static class SdSaltGenerator
{
    /// <summary>
    /// Generates a cryptographic salt using the specified memory pool.
    /// </summary>
    /// <param name="pool">The memory pool for allocation.</param>
    /// <param name="length">The salt length in bytes (default: 16 bytes / 128 bits).</param>
    /// <returns>A memory owner containing the salt bytes.</returns>
    public static IMemoryOwner<byte> Generate(MemoryPool<byte> pool, int length = SdConstants.DefaultSaltLengthBytes)
    {
        ArgumentNullException.ThrowIfNull(pool);

        if(length < SdConstants.MinimumSaltLengthBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length),
                $"Salt length must be at least {SdConstants.MinimumSaltLengthBytes} bytes.");
        }

        IMemoryOwner<byte> owner = pool.Rent(length);
        RandomNumberGenerator.Fill(owner.Memory.Span[..length]);

        return owner;
    }


    /// <summary>
    /// Generates a cryptographic salt as a byte array.
    /// </summary>
    /// <param name="length">The salt length in bytes (default: 16 bytes / 128 bits).</param>
    /// <returns>A new byte array containing the salt.</returns>
    public static byte[] Generate(int length = SdConstants.DefaultSaltLengthBytes)
    {
        if(length < SdConstants.MinimumSaltLengthBytes)
        {
            throw new ArgumentOutOfRangeException(
                nameof(length),
                $"Salt length must be at least {SdConstants.MinimumSaltLengthBytes} bytes.");
        }

        return RandomNumberGenerator.GetBytes(length);
    }
}