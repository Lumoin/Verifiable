using System.Buffers;
using System.Collections.Frozen;

namespace Verifiable.Cryptography;

/// <summary>
/// Signs a message with a digital signature scheme that gives <em>message recovery</em> — the signature
/// itself carries (recovers) a leading part of the message — such as ISO/IEC 9796-2 Digital Signature
/// scheme 1, the RSA scheme ICAO Doc 9303 Part 11 §6.1 Active Authentication uses.
/// </summary>
/// <param name="privateKeyBytes">The signer's private key material.</param>
/// <param name="nonRecoverableMessage">
/// The part of the message that is <em>not</em> carried in the signature and must be supplied to the
/// verifier out of band. In eMRTD Active Authentication this is the terminal's challenge RND.IFD. The
/// recoverable part (a random block sized to the key) is produced by the implementation, so it is not a
/// parameter — this is why a message-recovery signature does not fit the plain
/// <see cref="SigningDelegate"/> shape, whose <c>dataToSign</c> is the whole detached-signed message.
/// </param>
/// <param name="signaturePool">Memory pool for allocating the signature buffer.</param>
/// <param name="context">Optional context parameters for the signing operation.</param>
/// <param name="cancellationToken">Cancellation token for async operations.</param>
/// <returns>
/// The signature as pooled memory that the caller must dispose, paired with an optional
/// <see cref="SignatureProducedEvent"/> describing the operation — the same tuple shape wave 4 gave
/// <see cref="SigningDelegate"/>, completing the CryptoEvent seam for the last sign/verify delegate family
/// that lacked it (ISO/IEC 9796-2 message recovery has no detached-signature contract to share the plain
/// delegate pair, so it was given its own registry, but the event shape now matches).
/// </returns>
public delegate ValueTask<(Signature Signature, CryptoEvent? Event)> RecoverableSigningDelegate(
    ReadOnlyMemory<byte> privateKeyBytes,
    ReadOnlyMemory<byte> nonRecoverableMessage,
    MemoryPool<byte> signaturePool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);


/// <summary>
/// Verifies a digital signature with message recovery: the verifier supplies only the non-recovered part of
/// the message, the implementation recovers the rest from the signature, and the embedded hash is checked.
/// </summary>
/// <param name="nonRecoverableMessage">
/// The part of the message that is not carried in the signature (in eMRTD Active Authentication, the
/// terminal's challenge RND.IFD). The implementation recovers the leading part from the signature and
/// verifies the embedded hash over the recovered part followed by this one.
/// </param>
/// <param name="signature">The signature to verify.</param>
/// <param name="publicKeyMaterial">The public key material.</param>
/// <param name="context">Optional context parameters for the verification operation.</param>
/// <param name="cancellationToken">Cancellation token for async operations.</param>
/// <returns>
/// <see langword="true"/> if the signature is valid; otherwise <see langword="false"/>, paired with an
/// optional <see cref="VerificationCompletedEvent"/> describing the operation. See
/// <see cref="RecoverableSigningDelegate"/> for the tuple rationale.
/// </returns>
public delegate ValueTask<(bool IsVerified, CryptoEvent? Event)> RecoverableVerificationDelegate(
    ReadOnlyMemory<byte> nonRecoverableMessage,
    ReadOnlyMemory<byte> signature,
    ReadOnlyMemory<byte> publicKeyMaterial,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);


/// <summary>
/// Selects a <see cref="RecoverableSigningDelegate"/> based on algorithm, purpose, and optional qualifier.
/// </summary>
public delegate RecoverableSigningDelegate RecoverableSigningPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Selects a <see cref="RecoverableVerificationDelegate"/> based on algorithm, purpose, and optional qualifier.
/// </summary>
public delegate RecoverableVerificationDelegate RecoverableVerificationPatternMatcher<TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null);


/// <summary>
/// Central dispatch mechanism for routing digital-signature-with-message-recovery operations to backend
/// implementations — the message-recovery counterpart of <see cref="CryptoFunctionRegistry{T1, T2}"/>.
/// </summary>
/// <remarks>
/// <para>
/// A message-recovery scheme such as ISO/IEC 9796-2 does not fit the detached
/// <see cref="SigningDelegate"/>/<see cref="VerificationDelegate"/> contract — the signature carries part of
/// the message, the signer produces the recoverable part itself, and the hash is identified by the signature
/// trailer rather than chosen by the caller — so it is given its own delegate pair and registry, the same way
/// key agreement, key derivation, and AEAD each have their own. The only consumer today is eMRTD RSA Active
/// Authentication (Doc 9303 Part 11 §6.1), which resolves through this registry exactly as the elliptic-curve
/// path resolves ECDSA through <see cref="CryptoFunctionRegistry{T1, T2}"/>.
/// </para>
/// <para>
/// <see cref="Initialize"/> is not thread-safe; call it once during application startup before concurrent
/// access begins. The registered matchers are immutable thereafter and safe for concurrent read access.
/// </para>
/// </remarks>
/// <typeparam name="TDiscriminator1">First discriminator type, typically <see cref="Context.CryptoAlgorithm"/>.</typeparam>
/// <typeparam name="TDiscriminator2">Second discriminator type, typically <see cref="Context.Purpose"/>.</typeparam>
public static class RecoverableSignatureFunctionRegistry<TDiscriminator1, TDiscriminator2>
{
    private static RecoverableSigningPatternMatcher<TDiscriminator1, TDiscriminator2>? SigningMatcher { get; set; }

    private static RecoverableVerificationPatternMatcher<TDiscriminator1, TDiscriminator2>? VerificationMatcher { get; set; }


    /// <summary>
    /// Initializes the registry with signing and verification pattern matchers.
    /// </summary>
    /// <param name="signingMatcher">Pattern matcher that selects message-recovery signing functions.</param>
    /// <param name="verificationMatcher">Pattern matcher that selects message-recovery verification functions.</param>
    /// <remarks>
    /// Not thread-safe. Call only during application startup before concurrent access begins.
    /// </remarks>
    public static void Initialize(
        RecoverableSigningPatternMatcher<TDiscriminator1, TDiscriminator2> signingMatcher,
        RecoverableVerificationPatternMatcher<TDiscriminator1, TDiscriminator2> verificationMatcher)
    {
        SigningMatcher = signingMatcher;
        VerificationMatcher = verificationMatcher;
    }


    /// <summary>
    /// Resolves a message-recovery signing function for the specified algorithm and purpose.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if the registry has not been initialized.</exception>
    public static RecoverableSigningDelegate ResolveSigning(TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(SigningMatcher == null)
        {
            throw new InvalidOperationException(
                "Recoverable signing matcher has not been initialized. " +
                "Call RecoverableSignatureFunctionRegistry.Initialize during application startup.");
        }

        return SigningMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>
    /// Resolves a message-recovery verification function for the specified algorithm and purpose.
    /// </summary>
    /// <exception cref="InvalidOperationException">Thrown if the registry has not been initialized.</exception>
    public static RecoverableVerificationDelegate ResolveVerification(TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(VerificationMatcher == null)
        {
            throw new InvalidOperationException(
                "Recoverable verification matcher has not been initialized. " +
                "Call RecoverableSignatureFunctionRegistry.Initialize during application startup.");
        }

        return VerificationMatcher(algorithm, purpose, qualifier);
    }
}
