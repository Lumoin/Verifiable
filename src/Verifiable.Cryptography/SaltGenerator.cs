using System.Security.Cryptography;

namespace Verifiable.Cryptography;

/// <summary>
/// Delegate for generating cryptographically secure salt values as encoded strings.
/// </summary>
/// <returns>A base64url-encoded salt string with sufficient entropy.</returns>
public delegate string SaltGeneratorDelegate();


/// <summary>
/// Delegate for generating cryptographically secure raw salt bytes.
/// </summary>
/// <returns>A new byte array containing the salt.</returns>
public delegate byte[] SaltFactoryDelegate();


/// <summary>
/// Provides salt generation utilities for cryptographic operations.
/// </summary>
public static class SaltGenerator
{
    /// <summary>
    /// The default salt length in bytes (128 bits).
    /// </summary>
    public const int DefaultSaltLengthBytes = 16;


    /// <summary>
    /// Creates a salt generator that produces cryptographically secure random salts.
    /// </summary>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <param name="saltLengthBytes">The length of the salt in bytes. Defaults to 16 (128 bits).</param>
    /// <returns>A salt generator delegate.</returns>
    /// <remarks>
    /// The generated salts contain cryptographically secure random data,
    /// base64url-encoded to produce a string representation.
    /// </remarks>
    public static SaltGeneratorDelegate Create(EncodeDelegate base64UrlEncoder, int saltLengthBytes = DefaultSaltLengthBytes)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));
        ArgumentOutOfRangeException.ThrowIfLessThan(saltLengthBytes, 1, nameof(saltLengthBytes));

        return () =>
        {
            byte[] saltBytes = new byte[saltLengthBytes];
            RandomNumberGenerator.Fill(saltBytes);

            return base64UrlEncoder(saltBytes);
        };
    }


    /// <summary>
    /// Creates a salt generator that returns a fixed sequence of salts.
    /// </summary>
    /// <param name="salts">The sequence of salts to return.</param>
    /// <returns>A salt generator delegate.</returns>
    /// <remarks>
    /// This is intended for testing only, to produce deterministic outputs
    /// that match test vectors.
    /// </remarks>
    /// <exception cref="InvalidOperationException">
    /// Thrown when all provided salts have been consumed.
    /// </exception>
    public static SaltGeneratorDelegate CreateDeterministic(IEnumerable<string> salts)
    {
        ArgumentNullException.ThrowIfNull(salts, nameof(salts));

        var saltQueue = new Queue<string>(salts);

        return () =>
        {
            if(saltQueue.Count == 0)
            {
                throw new InvalidOperationException("No more salts available in deterministic generator.");
            }

            return saltQueue.Dequeue();
        };
    }


    /// <summary>
    /// Generates cryptographically secure random salt bytes using the default length (128 bits).
    /// </summary>
    /// <returns>A new byte array containing the salt.</returns>
    /// <remarks>
    /// <para>
    /// This parameterless overload is compatible with <see cref="SaltFactoryDelegate"/> for
    /// direct method group usage:
    /// </para>
    /// <code>
    /// SdJwtIssuance.IssueAsync(payload, paths, SaltGenerator.Create, ...);
    /// </code>
    /// </remarks>
    public static byte[] Create()
    {
        return RandomNumberGenerator.GetBytes(DefaultSaltLengthBytes);
    }


    /// <summary>
    /// Generates cryptographically secure random salt bytes.
    /// </summary>
    /// <param name="lengthBytes">The salt length in bytes. Defaults to 16 (128 bits).</param>
    /// <returns>A new byte array containing the salt.</returns>
    public static byte[] Create(int lengthBytes)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(lengthBytes, 1, nameof(lengthBytes));

        return RandomNumberGenerator.GetBytes(lengthBytes);
    }


    /// <summary>
    /// Creates a salt generator that always returns the same salt value.
    /// </summary>
    /// <param name="salt">The salt value to return.</param>
    /// <returns>A salt generator delegate.</returns>
    /// <remarks>
    /// This is intended for testing only.
    /// </remarks>
    public static SaltGeneratorDelegate CreateFixed(string salt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(salt, nameof(salt));

        return () => salt;
    }
}