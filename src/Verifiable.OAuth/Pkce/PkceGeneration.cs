using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.OAuth.Pkce;

/// <summary>
/// Generates PKCE parameter pairs for use in the Authorization Code flow.
/// </summary>
/// <remarks>
/// PKCE (Proof Key for Code Exchange) is specified in
/// <see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</see>.
/// The S256 challenge method is mandatory per
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>.
/// </remarks>
public static class PkceGeneration
{
    /// <summary>
    /// The number of random bytes to generate for the PKCE verifier.
    /// RFC 7636 §4.1 requires between 32 and 96 octets before Base64url encoding,
    /// producing between 43 and 128 characters without padding. 32 bytes is the minimum
    /// and provides 256 bits of entropy.
    /// </summary>
    private const int VerifierByteLength = 32;

    /// <summary>
    /// The number of bytes in a raw SHA-256 digest. Base64url encodes to exactly
    /// 43 characters without padding, which is always the challenge length for S256.
    /// </summary>
    private const int ChallengeSha256ByteLength = 32;


    /// <summary>
    /// Generates a PKCE S256 parameter pair using the registered entropy and
    /// digest providers from <see cref="CryptographicKeyEvents"/>.
    /// </summary>
    /// <param name="base64UrlEncoder">
    /// Base64url encoder without padding. Encodes both the verifier and the
    /// challenge for transmission.
    /// </param>
    /// <param name="pool">Memory pool for all byte allocations.</param>
    /// <returns>
    /// A <see cref="PkceParameters"/> carrying the Base64url-encoded verifier
    /// and challenge as plain strings. The raw bytes used during generation
    /// are zeroed and returned to the pool before this method returns.
    /// Any <see cref="CryptoEvent"/> produced by the registered providers is
    /// emitted to <see cref="CryptographicKeyEvents.Events"/>.
    /// </returns>
    public static PkceParameters Generate(
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        Tag verifierTag = Tag.Create(
            (typeof(Purpose), Purpose.Nonce),
            (typeof(EntropySource), EntropySource.Csprng));

        string encodedVerifier;
        using(Nonce verifier = CryptographicKeyEvents.GenerateNonce(
            VerifierByteLength, verifierTag, pool))
        {
            encodedVerifier = base64UrlEncoder(verifier.UseNonce());
        }

        //SHA-256 of the ASCII bytes of the Base64url-encoded verifier per RFC 7636 §4.2.
        //S256 is not configurable — always SHA-256.
        int inputByteCount = Encoding.ASCII.GetByteCount(encodedVerifier);
        IMemoryOwner<byte> inputOwner = pool.Rent(inputByteCount);
        try
        {
            Span<byte> inputBytes = inputOwner.Memory.Span[..inputByteCount];
            Encoding.ASCII.GetBytes(encodedVerifier, inputBytes);

            Tag challengeTag = Tag.Create(
                (typeof(Purpose), Purpose.Digest),
                (typeof(HashAlgorithmName), HashAlgorithmName.SHA256));

            string encodedChallenge;
            using(DigestValue challenge = CryptographicKeyEvents.ComputeDigest(
                inputBytes,
                ChallengeSha256ByteLength,
                challengeTag,
                pool))
            {
                encodedChallenge = base64UrlEncoder(challenge.AsReadOnlySpan());
            }

            return new PkceParameters(encodedVerifier, encodedChallenge, PkceMethod.S256);
        }
        finally
        {
            inputOwner.Dispose();
        }
    }
}