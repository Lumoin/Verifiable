using System.Buffers;
using System.Diagnostics;

namespace Verifiable.Cryptography.Secdsa;

/// <summary>
/// Represents the encrypted and signed instruction produced by the wallet
/// and sent to the Wallet Secure Cryptographic Application (WSCA).
/// </summary>
/// <remarks>
/// <para>
/// The Wallet Secure Cryptographic Application (WSCA) is the wallet provider's
/// trusted application that interfaces with the Hardware Security Module (HSM)
/// and authenticates user instructions as defined in the EUDI Wallet architecture.
/// This type corresponds to the output of Algorithm 36 of the SECDSA specification.
/// </para>
/// <para>
/// The instruction bundles:
/// </para>
/// <list type="bullet">
///   <item><description>A Schnorr challenge Chal(SN) signed with the Native Cryptographic Hardware (NCH) private key u (Algorithm 21). The NCH is the hardware-bound key store on the user device, such as a TPM, Secure Enclave, or StrongBox.</description></item>
///   <item><description>The encrypted payload ciphertext C and authentication tag T.</description></item>
///   <item><description>The SECDSA nonce point R in uncompressed form.</description></item>
///   <item><description>The ECDH verification point R' = aU·R in uncompressed form, valid when the correct PIN was used.</description></item>
///   <item><description>The outer sequence number for early replay detection at the wallet provider perimeter.</description></item>
/// </list>
/// <para>
/// Specification reference: SECDSA specification, Algorithm 36.
/// </para>
/// </remarks>
[DebuggerDisplay("{DebuggerDisplay,nq}")]
public sealed class BlindedSecdsaInstruction: IDisposable
{
    /// <summary>Tracks whether this instance has been disposed.</summary>
    private bool Disposed { get; set; }

    /// <summary>Owns the memory backing <see cref="Challenge"/>.</summary>
    private IMemoryOwner<byte> ChallengeOwner { get; }

    /// <summary>Owns the memory backing <see cref="Ciphertext"/>.</summary>
    private IMemoryOwner<byte> CiphertextOwner { get; }

    /// <summary>Owns the memory backing <see cref="AuthenticationTag"/>.</summary>
    private IMemoryOwner<byte> TagOwner { get; }

    /// <summary>
    /// Gets the outer sequence number for early replay detection.
    /// </summary>
    /// <remarks>
    /// The wallet provider perimeter validates this number before the instruction
    /// reaches the WSCA, allowing cheap rejection of replayed or out-of-order instructions.
    /// </remarks>
    public ulong SequenceNumber { get; }

    /// <summary>
    /// Gets the serialized Schnorr challenge Chal(SN) produced by Algorithm 21.
    /// </summary>
    /// <remarks>
    /// Signed with the Native Cryptographic Hardware (NCH) private key u.
    /// The wallet provider perimeter verifies this signature using the NCH public key U
    /// from the Internal Certificate before passing the instruction to the WSCA.
    /// </remarks>
    public ReadOnlyMemory<byte> Challenge { get; }

    /// <summary>
    /// Gets the SECDSA nonce point R in uncompressed encoding (0x04 || X || Y).
    /// </summary>
    public EcPointBytes NoncePoint { get; }

    /// <summary>
    /// Gets the ECDH verification point R' = aU·R in uncompressed encoding (0x04 || X || Y).
    /// </summary>
    /// <remarks>
    /// This point equals aU·R if and only if the correct PIN was entered during signing.
    /// The WSCA uses this to verify PIN correctness without the wallet provider ever
    /// learning the PIN or the raw SECDSA public key Y.
    /// </remarks>
    public EcPointBytes VerificationPoint { get; }

    /// <summary>
    /// Gets the authenticated encryption ciphertext C.
    /// </summary>
    public ReadOnlyMemory<byte> Ciphertext { get; }

    /// <summary>
    /// Gets the AES-GCM authentication tag T covering the ciphertext.
    /// </summary>
    public ReadOnlyMemory<byte> AuthenticationTag { get; }

    /// <summary>
    /// Creates a <see cref="BlindedSecdsaInstruction"/> from its component parts.
    /// </summary>
    /// <param name="sequenceNumber">The outer sequence number for replay detection.</param>
    /// <param name="challengeBytes">The serialized Schnorr challenge bytes.</param>
    /// <param name="noncePoint">The SECDSA nonce point R. Ownership transfers to this instance.</param>
    /// <param name="verificationPoint">The ECDH verification point R'. Ownership transfers to this instance.</param>
    /// <param name="ciphertextBytes">The authenticated encryption ciphertext bytes.</param>
    /// <param name="authTagBytes">The AES-GCM authentication tag bytes.</param>
    /// <param name="pool">The memory pool for buffer allocation.</param>
    /// <returns>A new <see cref="BlindedSecdsaInstruction"/>.</returns>
    public static BlindedSecdsaInstruction Create(
        ulong sequenceNumber,
        ReadOnlySpan<byte> challengeBytes,
        EcPointBytes noncePoint,
        EcPointBytes verificationPoint,
        ReadOnlySpan<byte> ciphertextBytes,
        ReadOnlySpan<byte> authTagBytes,
        MemoryPool<byte> pool)
    {
        ArgumentNullException.ThrowIfNull(noncePoint);
        ArgumentNullException.ThrowIfNull(verificationPoint);
        ArgumentNullException.ThrowIfNull(pool);

        IMemoryOwner<byte> challengeOwner = pool.Rent(challengeBytes.Length);
        challengeBytes.CopyTo(challengeOwner.Memory.Span);

        IMemoryOwner<byte> ciphertextOwner = pool.Rent(ciphertextBytes.Length);
        ciphertextBytes.CopyTo(ciphertextOwner.Memory.Span);

        IMemoryOwner<byte> tagOwner = pool.Rent(authTagBytes.Length);
        authTagBytes.CopyTo(tagOwner.Memory.Span);

        return new BlindedSecdsaInstruction(
            sequenceNumber,
            challengeOwner,
            challengeOwner.Memory.Slice(0, challengeBytes.Length),
            noncePoint,
            verificationPoint,
            ciphertextOwner,
            ciphertextOwner.Memory.Slice(0, ciphertextBytes.Length),
            tagOwner,
            tagOwner.Memory.Slice(0, authTagBytes.Length));
    }

    private BlindedSecdsaInstruction(
        ulong sequenceNumber,
        IMemoryOwner<byte> challengeOwner,
        ReadOnlyMemory<byte> challenge,
        EcPointBytes noncePoint,
        EcPointBytes verificationPoint,
        IMemoryOwner<byte> ciphertextOwner,
        ReadOnlyMemory<byte> ciphertext,
        IMemoryOwner<byte> tagOwner,
        ReadOnlyMemory<byte> authenticationTag)
    {
        SequenceNumber = sequenceNumber;
        ChallengeOwner = challengeOwner;
        Challenge = challenge;
        NoncePoint = noncePoint;
        VerificationPoint = verificationPoint;
        CiphertextOwner = ciphertextOwner;
        Ciphertext = ciphertext;
        TagOwner = tagOwner;
        AuthenticationTag = authenticationTag;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if(!Disposed)
        {
            ChallengeOwner.Dispose();
            NoncePoint.Dispose();
            VerificationPoint.Dispose();
            CiphertextOwner.Dispose();
            TagOwner.Dispose();
            Disposed = true;
        }
    }

    private string DebuggerDisplay =>
        $"BlindedSecdsaInstruction(SN={SequenceNumber}, Ciphertext={Ciphertext.Length} bytes, Tag={AuthenticationTag.Length} bytes)";
}
