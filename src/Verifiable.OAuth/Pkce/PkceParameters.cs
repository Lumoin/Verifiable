using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.OAuth.Pkce;

/// <summary>
/// The verifier and its derived challenge for one PKCE exchange.
/// </summary>
/// <remarks>
/// <para>
/// PKCE (Proof Key for Code Exchange) is specified in
/// <see href="https://www.rfc-editor.org/rfc/rfc7636">RFC 7636</see>.
/// The verifier is a cryptographically random nonce held by the initiating
/// party throughout the exchange. Only the challenge — the SHA-256 digest
/// of the Base64url-encoded verifier — is transmitted to the authorization
/// server. The verifier is presented at the token endpoint to prove the two
/// requests originate from the same party.
/// </para>
/// <para>
/// <strong>Generation.</strong>
/// Use <see cref="Generate(FillEntropyDelegate, EntropyHealthObservation, EncodeDelegate, MemoryPool{byte})"/>
/// to produce a cryptographically valid pair from any entropy source — OS
/// CSPRNG, TPM, or HSM. The challenge is always derived via SHA-256; the
/// <c>S256</c> method is mandatory per
/// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-2.1.1">RFC 9700 §2.1.1</see>.
/// </para>
/// <para>
/// This type owns both the <see cref="Verifier"/> and <see cref="Challenge"/>
/// and must be disposed when the flow completes or is abandoned.
/// </para>
/// </remarks>
[DebuggerDisplay("PkceParameters Method={Method}")]
public sealed class PkceParameters: IDisposable, IEquatable<PkceParameters>
{
    private bool disposed;

    //RFC 7636 §4.1 — verifier must be 32–96 octets before Base64url encoding,
    //producing 43–128 Base64url characters without padding.
    private const int VerifierByteLength = 32;

    //SHA-256 always produces 32 bytes — Base64url encodes to exactly 43 characters.
    private const int ChallengeSha256ByteLength = 32;


    /// <summary>
    /// The PKCE code verifier as a <see cref="Nonce"/>. Raw bytes whose
    /// Base64url-encoded form is between 43 and 128 characters per RFC 7636 §4.1.
    /// Must never leave the initiating party.
    /// </summary>
    public Nonce Verifier { get; }

    /// <summary>
    /// The SHA-256 digest of the UTF-8 encoded Base64url verifier, as a
    /// <see cref="DigestValue"/>. Base64url-encodes to exactly 43 characters.
    /// Safe to transmit to the authorization server.
    /// </summary>
    public DigestValue Challenge { get; }

    /// <summary>
    /// The challenge method. Always <see cref="PkceMethod.S256"/> per RFC 9700 §2.1.1.
    /// </summary>
    public PkceMethod Method { get; }

    /// <summary>
    /// The Base64url-encoded verifier string, ready for the token endpoint
    /// <c>code_verifier</c> parameter per RFC 7636 §4.5.
    /// </summary>
    public string EncodedVerifier { get; }

    /// <summary>
    /// The Base64url-encoded challenge string, ready for the authorization
    /// request <c>code_challenge</c> parameter per RFC 7636 §4.2.
    /// </summary>
    public string EncodedChallenge { get; }


    private PkceParameters(
        Nonce verifier,
        DigestValue challenge,
        string encodedVerifier,
        string encodedChallenge)
    {
        Verifier = verifier;
        Challenge = challenge;
        Method = PkceMethod.S256;
        EncodedVerifier = encodedVerifier;
        EncodedChallenge = encodedChallenge;
    }


    /// <summary>
    /// Generates a new PKCE parameter pair using the supplied entropy source.
    /// </summary>
    /// <param name="fillEntropy">
    /// The entropy source for the verifier. Must produce cryptographically
    /// strong random bytes. Use <see cref="RandomNumberGenerator.Fill"/> for
    /// CSPRNG or a TPM/HSM delegate for hardware entropy.
    /// </param>
    /// <param name="health">
    /// Health observation for the entropy source at generation time.
    /// </param>
    /// <param name="base64UrlEncoder">
    /// Delegate for Base64url encoding without padding. Used to encode both
    /// the verifier and the challenge for transmission.
    /// </param>
    /// <param name="pool">Memory pool for all allocations.</param>
    /// <returns>A new <see cref="PkceParameters"/> pair. The caller must dispose it.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope", Justification = "Ownership transfers to PkceParameters on success. Disposed in catch on failure.")]
    public static PkceParameters Generate(
        FillEntropyDelegate fillEntropy,
        EntropyHealthObservation health,
        EncodeDelegate base64UrlEncoder,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(fillEntropy);
        ArgumentNullException.ThrowIfNull(health);
        ArgumentNullException.ThrowIfNull(base64UrlEncoder);
        ArgumentNullException.ThrowIfNull(pool);

        Tag verifierTag = Tag.Create(
            (typeof(Purpose), Purpose.Nonce),
            (typeof(EntropySource), EntropySource.Csprng));

        Nonce verifier = Nonce.Generate(VerifierByteLength, verifierTag, fillEntropy, health, pool);
        try
        {
            string encodedVerifier = base64UrlEncoder(verifier.AsReadOnlySpan());

            //SHA-256 is not configurable in PKCE S256 — always SHA-256 of the
            //ASCII bytes of the Base64url-encoded verifier per RFC 7636 §4.2.
            int inputByteCount = Encoding.ASCII.GetByteCount(encodedVerifier);
            byte[] inputBytes = new byte[inputByteCount];
            Encoding.ASCII.GetBytes(encodedVerifier, inputBytes);

            Tag challengeTag = Tag.Create(
                (typeof(Purpose), Purpose.Digest),
                (typeof(HashAlgorithmName), HashAlgorithmName.SHA256));

            DigestValue challenge = DigestValue.Compute(
                inputBytes,
                SHA256.HashData,
                ChallengeSha256ByteLength,
                challengeTag,
                pool);
            try
            {
                string encodedChallenge = base64UrlEncoder(challenge.AsReadOnlySpan());
                return new PkceParameters(verifier, challenge, encodedVerifier, encodedChallenge);
            }
            catch
            {
                challenge.Dispose();
                throw;
            }
        }
        catch
        {
            verifier.Dispose();
            throw;
        }
    }


    /// <summary>
    /// Generates a new PKCE parameter pair using the OS CSPRNG.
    /// Convenience overload for the common case.
    /// </summary>
    public static PkceParameters Generate(EncodeDelegate base64UrlEncoder, MemoryPool<byte> pool) =>
        Generate(RandomNumberGenerator.Fill, EntropyHealthObservation.Unknown, base64UrlEncoder, pool);


    /// <inheritdoc/>
    public void Dispose()
    {
        if(!disposed)
        {
            Verifier.Dispose();
            Challenge.Dispose();
            disposed = true;
        }
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(PkceParameters? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return Method == other.Method
            && EncodedVerifier == other.EncodedVerifier
            && EncodedChallenge == other.EncodedChallenge;
    }

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is PkceParameters other && Equals(other);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode() =>
        HashCode.Combine(Method, EncodedVerifier, EncodedChallenge);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(PkceParameters? left, PkceParameters? right) =>
        left is null ? right is null : left.Equals(right);

    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(PkceParameters? left, PkceParameters? right) =>
        !(left == right);
}