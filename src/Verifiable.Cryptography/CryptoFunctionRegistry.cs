using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Cryptography;

/// <summary>
/// Delegate for signing data with a private key via registry dispatch.
/// </summary>
/// <param name="privateKeyBytes">The private key material.</param>
/// <param name="dataToSign">The data to sign.</param>
/// <param name="signaturePool">Memory pool for allocating the signature buffer.</param>
/// <param name="context">Optional context parameters for the signing operation.</param>
/// <param name="cancellationToken">Cancellation token for async operations.</param>
/// <returns>
/// The signature as pooled memory that the caller must dispose, paired with an optional
/// <see cref="SignatureProducedEvent"/> describing the operation. A backend that does not
/// support observability returns <see langword="null"/> for the event; every currently
/// registered backend constructs one using the <c>Backend</c>/<c>Algorithm</c> it already
/// has in scope from its Activity-span instrumentation. This mirrors the entropy/digest/HMAC
/// delegate shape (<see cref="ComputeDigestDelegate"/>, <see cref="ComputeHmacDelegate"/>) and
/// is unwrapped at <see cref="PrivateKey.SignAsync"/> for key-object-mediated signing, which emits
/// the event through <see cref="CryptographicKeyEvents.Events"/>; a caller that invokes a resolved
/// delegate directly instead emits through its own <see cref="CryptoEventSink"/> parameter — see
/// <see cref="CryptoEventSink"/> for the two-route rationale. The event allocates a
/// <see cref="Guid"/> and a record per call whenever constructed — accepted deliberately,
/// since the asymmetric-signing cost this wraps dwarfs one record allocation.
/// </returns>
/// <remarks>
/// <para>
/// <strong>Dual-Delegate Design</strong>
/// </para>
/// <para>
/// This library provides two parallel sets of cryptographic function delegates:
/// </para>
/// <code>
/// +------------------------------------------------------------------+
/// |                    Registry Delegates                            |
/// |              (CryptoFunctionRegistry.cs)                         |
/// +------------------------------------------------------------------+
/// | SigningDelegate, VerificationDelegate:                           |
/// | - Use ReadOnlyMemory&lt;byte&gt; for async safety.               |
/// | - Can be stored and passed across async boundaries.              |
/// | - Include FrozenDictionary context parameter.                    |
/// | - Used by: Jws.SignAsync, CredentialJwsExtensions.               |
/// +------------------------------------------------------------------+
///
/// +------------------------------------------------------------------+
/// |                  Bound Key Delegates                             |
/// |                (SensitiveMemory.cs)                              |
/// +------------------------------------------------------------------+
/// | SigningFunction&lt;T&gt;, VerificationFunction&lt;T&gt;:         |
/// | - Use ReadOnlyMemory&lt;byte&gt; for async safety.               |
/// | - Can be stored in PublicKey/PrivateKey objects.                 |
/// | - Generic type parameters for flexibility.                       |
/// | - Used by: PublicKey.VerifyAsync, PrivateKey.SignAsync.          |
/// +------------------------------------------------------------------+
/// </code>
/// <para>
/// <strong>Why Two Sets?</strong>
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>Registry pattern</strong> resolves a function at call time, invokes it immediately,
/// and discards it. Functions return <see cref="Signature"/> which wraps the signature bytes
/// with metadata about the algorithm used.
/// </description></item>
/// <item><description>
/// <strong>Bound key pattern</strong> stores a function inside a <see cref="PublicKey"/> or
/// <see cref="PrivateKey"/> object for repeated use. <c>ReadOnlyMemory</c> can be stored and
/// passed across async boundaries.
/// </description></item>
/// </list>
/// <para>
/// <strong>Bridging the Two</strong>
/// </para>
/// <para>
/// The <see cref="CryptographicKeyFactory"/> bridges these patterns by resolving functions
/// (using the bound-key delegate signature) and combining them with key material to create
/// ready-to-use key objects.
/// </para>
/// </remarks>
public delegate ValueTask<(Signature Signature, CryptoEvent? Event)> SigningDelegate(
    ReadOnlyMemory<byte> privateKeyBytes,
    ReadOnlyMemory<byte> dataToSign,
    BaseMemoryPool signaturePool,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);


/// <summary>
/// Delegate for verifying a signature with a public key.
/// </summary>
/// <param name="dataToVerify">The original data that was signed.</param>
/// <param name="signature">The signature to verify.</param>
/// <param name="publicKeyMaterial">The public key material.</param>
/// <param name="context">Optional context parameters for the verification operation.</param>
/// <param name="cancellationToken">Cancellation token for async operations.</param>
/// <returns>
/// <see langword="true"/> if the signature is valid; otherwise <see langword="false"/>, paired
/// with an optional <see cref="VerificationCompletedEvent"/> describing the operation. See the
/// <see cref="SigningDelegate"/> remarks for the tuple rationale; the matching choke point is
/// <see cref="PublicKey.VerifyAsync"/>.
/// </returns>
public delegate ValueTask<(bool IsVerified, CryptoEvent? Event)> VerificationDelegate(
    ReadOnlyMemory<byte> dataToVerify,
    ReadOnlyMemory<byte> signature,
    ReadOnlyMemory<byte> publicKeyMaterial,
    FrozenDictionary<string, object>? context = null,
    CancellationToken cancellationToken = default);


/// <summary>
/// Delegate that selects a cryptographic function based on algorithm, purpose, and optional qualifier.
/// </summary>
/// <typeparam name="T">The delegate type to return (e.g., <see cref="SigningDelegate"/>).</typeparam>
/// <typeparam name="TDiscriminator1">First discriminator type, typically <see cref="Context.CryptoAlgorithm"/>.</typeparam>
/// <typeparam name="TDiscriminator2">Second discriminator type, typically <see cref="Context.Purpose"/>.</typeparam>
/// <param name="algorithm">The cryptographic algorithm.</param>
/// <param name="purpose">The purpose of the operation.</param>
/// <param name="qualifier">Optional qualifier for backend selection or other routing decisions.</param>
/// <returns>
/// A delegate that performs the cryptographic operation, or <see langword="null"/> for a pair the backend does
/// not serve.
/// </returns>
/// <remarks>
/// A <see langword="null"/> answer names a pair the backend does not serve, and a matcher never throws for
/// such a pair: the pair can come from presented input (a public key a verifier reads from a token header), and
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}.TryResolveVerification"/> turns the
/// <see langword="null"/> into a "no function" answer the verifier refuses with. A matcher's last arm answers
/// <see langword="null"/>; a matcher that throws for an unserved pair faults its caller instead.
/// </remarks>
public delegate T? PatternMatcher<T, TDiscriminator1, TDiscriminator2>(
    TDiscriminator1 algorithm,
    TDiscriminator2 purpose,
    string? qualifier = null) where T : Delegate;


/// <summary>
/// Central dispatch mechanism for routing cryptographic operations to backend implementations.
/// </summary>
/// <remarks>
/// <para>
/// This registry maps algorithm/purpose combinations to concrete signing and verification
/// functions. It enables format-independent cryptographic operations where the same high-level
/// code can work with different backends (BouncyCastle, Microsoft CNG, Libsodium, TPM) based on
/// runtime configuration.
/// </para>
/// <para>
/// <strong>An unserved pair is a value.</strong> A registered <see cref="PatternMatcher{T, TDiscriminator1, TDiscriminator2}"/>
/// answers <see langword="null"/> for an (algorithm, purpose) pair its backend does not serve.
/// <see cref="TryResolveVerification"/> answers <see langword="false"/> for such a pair and for a registry
/// that has not been initialized, so a verifier whose pair comes from presented input (a public key read from
/// a token header) and that resolves through it refuses the input as not verified:
/// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see> says "All
/// cryptographic operations used in the JWT MUST be validated and the entire JWT MUST be rejected if any of
/// them fail to validate."
/// </para>
/// <para>
/// <see cref="ResolveSigning"/> and <see cref="ResolveVerification"/> take the pair as the caller's argument
/// and throw <see cref="ArgumentException"/> naming the algorithm, the purpose and the qualifier when the
/// matcher answers <see langword="null"/>. A caller that resolves a pair read from presented input through
/// <see cref="ResolveVerification"/> fails closed only where it catches that <see cref="ArgumentException"/>,
/// which is why the type is <see cref="ArgumentException"/>. A registry that has not been initialized makes
/// both throw <see cref="InvalidOperationException"/>: that is the deployment's composition, never input.
/// An application's matcher that throws for an unserved pair faults every caller, a verifier of presented
/// input through <see cref="TryResolveVerification"/> included; its last arm answers <see langword="null"/>.
/// </para>
/// </remarks>
/// <typeparam name="TDiscriminator1">First discriminator type, typically <see cref="Context.CryptoAlgorithm"/>.</typeparam>
/// <typeparam name="TDiscriminator2">Second discriminator type, typically <see cref="Context.Purpose"/>.</typeparam>
public static class CryptoFunctionRegistry<TDiscriminator1, TDiscriminator2>
{
    private static PatternMatcher<VerificationDelegate, TDiscriminator1, TDiscriminator2>? VerificationMatcher { get; set; }

    private static PatternMatcher<SigningDelegate, TDiscriminator1, TDiscriminator2>? SigningMatcher { get; set; }


    /// <summary>
    /// Initializes the registry with signing and verification pattern matchers.
    /// </summary>
    /// <param name="signingMatcher">Pattern matcher that selects signing functions.</param>
    /// <param name="verificationMatcher">Pattern matcher that selects verification functions.</param>
    /// <remarks>
    /// <para>
    /// This method is not thread-safe. Call it only during application startup before
    /// concurrent access begins, such as in static initializers or early in <c>Program.cs</c>.
    /// The registered matchers are immutable after initialization and safe for concurrent
    /// read access.
    /// </para>
    /// </remarks>
    public static void Initialize(
        PatternMatcher<SigningDelegate, TDiscriminator1, TDiscriminator2> signingMatcher,
        PatternMatcher<VerificationDelegate, TDiscriminator1, TDiscriminator2> verificationMatcher)
    {
        SigningMatcher = signingMatcher;
        VerificationMatcher = verificationMatcher;
    }


    /// <summary>
    /// Initializes the registry with matchers that handle key material transformations.
    /// </summary>
    /// <param name="signingMatcher">Pattern matcher that selects signing functions with transformation support.</param>
    /// <param name="verificationMatcher">Pattern matcher that selects verification functions with transformation support.</param>
    public static void InitializeWithTransformers(
        PatternMatcher<SigningDelegate, TDiscriminator1, TDiscriminator2> signingMatcher,
        PatternMatcher<VerificationDelegate, TDiscriminator1, TDiscriminator2> verificationMatcher)
    {
        SigningMatcher = signingMatcher;
        VerificationMatcher = verificationMatcher;
    }


    /// <summary>
    /// Resolves a signing function for the specified algorithm and purpose.
    /// </summary>
    /// <param name="algorithm">The cryptographic algorithm.</param>
    /// <param name="purpose">The purpose of the operation.</param>
    /// <param name="qualifier">Optional qualifier for backend selection.</param>
    /// <returns>A delegate that performs the signing operation.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the registry has not been initialized.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when the registered matcher answers <see langword="null"/> for the pair: the pair is the
    /// caller's argument, and the message names the algorithm, the purpose and the qualifier.
    /// </exception>
    public static SigningDelegate ResolveSigning(TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(SigningMatcher == null)
        {
            throw new InvalidOperationException(
                "Signing matcher has not been initialized. " +
                "Call CryptoFunctionRegistry.Initialize() during application startup.");
        }

        return SigningMatcher(algorithm, purpose, qualifier)
            ?? throw new ArgumentException(
                $"No signing function is registered for algorithm '{algorithm}', purpose '{purpose}' and qualifier '{qualifier}'.");
    }


    /// <summary>
    /// Resolves a verification function for the specified algorithm and purpose.
    /// </summary>
    /// <param name="algorithm">The cryptographic algorithm.</param>
    /// <param name="purpose">The purpose of the operation.</param>
    /// <param name="qualifier">Optional qualifier for backend selection.</param>
    /// <returns>A delegate that performs the verification operation.</returns>
    /// <remarks>
    /// The pair is the caller's argument. A verifier of presented input resolves through
    /// <see cref="TryResolveVerification"/>, which answers an unserved pair as a value; a caller that resolves
    /// a pair read from presented input through this member fails closed only where it catches the
    /// <see cref="ArgumentException"/> this member throws for an unserved pair.
    /// </remarks>
    /// <exception cref="InvalidOperationException">Thrown if the registry has not been initialized.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown when the registered matcher answers <see langword="null"/> for the pair; the message names the
    /// algorithm, the purpose and the qualifier.
    /// </exception>
    public static VerificationDelegate ResolveVerification(TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(VerificationMatcher == null)
        {
            throw new InvalidOperationException(
                "Verification matcher has not been initialized. " +
                "Call CryptoFunctionRegistry.Initialize() during application startup.");
        }

        return VerificationMatcher(algorithm, purpose, qualifier)
            ?? throw new ArgumentException(
                $"No verification function is registered for algorithm '{algorithm}', purpose '{purpose}' and qualifier '{qualifier}'.");
    }


    /// <summary>
    /// Resolves a verification function for the specified algorithm and purpose when the registered
    /// matcher serves the pair, answering a pair it does not serve as a value rather than a fault.
    /// </summary>
    /// <param name="algorithm">The cryptographic algorithm.</param>
    /// <param name="purpose">The purpose of the operation.</param>
    /// <param name="verification">
    /// The function that performs the verification when the pair is served; otherwise <see langword="null"/>.
    /// </param>
    /// <param name="qualifier">Optional qualifier for backend selection.</param>
    /// <returns>
    /// <see langword="true"/> when the matcher serves the pair; <see langword="false"/> when it answers
    /// <see langword="null"/> for the pair or when the registry has not been initialized.
    /// </returns>
    /// <remarks>
    /// The resolution for a verifier whose pair comes from presented input: an unserved pair is an answer the
    /// verifier refuses the input with, never an exception, so
    /// <see href="https://www.rfc-editor.org/rfc/rfc8725#section-3.3">RFC 8725 Section 3.3</see>'s rejection is
    /// the verifier's own outcome. An exception the registered matcher raises is not caught: a matcher that
    /// throws for an unserved pair faults this caller, which is why a matcher's last arm answers
    /// <see langword="null"/>.
    /// </remarks>
    public static bool TryResolveVerification(
        TDiscriminator1 algorithm,
        TDiscriminator2 purpose,
        [NotNullWhen(true)] out VerificationDelegate? verification,
        string? qualifier = null)
    {
        verification = VerificationMatcher?.Invoke(algorithm, purpose, qualifier);

        return verification is not null;
    }


    /// <summary>
    /// Gets whether <see cref="Initialize"/> (or <see cref="InitializeWithTransformers"/>) has
    /// registered this registry's signing and verification matchers.
    /// </summary>
    public static bool IsInitialized
    {
        get => SigningMatcher is not null && VerificationMatcher is not null;
    }
}
