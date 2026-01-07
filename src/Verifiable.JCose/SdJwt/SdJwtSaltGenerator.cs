using System.Security.Cryptography;
using Verifiable.Cryptography;

namespace Verifiable.Jose.SdJwt;

/// <summary>
/// Provides default salt generation for SD-JWT disclosures.
/// </summary>
public static class SdJwtSaltGenerator
{
    /// <summary>
    /// Creates a salt generator that produces cryptographically secure random salts.
    /// </summary>
    /// <param name="base64UrlEncoder">Delegate for base64url encoding.</param>
    /// <returns>A salt generator delegate.</returns>
    /// <remarks>
    /// The generated salts contain 128 bits (16 bytes) of cryptographically secure random data,
    /// base64url-encoded to produce a 22-character string (without padding).
    /// </remarks>
    public static SaltGeneratorDelegate Create(EncodeDelegate base64UrlEncoder)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder, nameof(base64UrlEncoder));

        return () =>
        {
            Span<byte> saltBytes = stackalloc byte[SdJwtConstants.RecommendedSaltLengthBytes];
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
    /// This is intended for testing only, to produce deterministic disclosures
    /// that match RFC 9901 test vectors.
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
}