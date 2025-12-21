using System.Buffers;
using System.Collections.Frozen;

namespace Verifiable.Cryptography;

/// <summary>
/// Delegate for signing data with a private key via registry dispatch.
/// </summary>
/// <param name="privateKeyBytes">The private key material.</param>
/// <param name="dataToSign">The data to sign.</param>
/// <param name="signaturePool">Memory pool for allocating the signature buffer.</param>
/// <param name="context">Optional context parameters for the signing operation.</param>
/// <returns>The signature as pooled memory that the caller must dispose.</returns>
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
/// | - Use ReadOnlySpan&lt;byte&gt; for zero-allocation dispatch.     |
/// | - Cannot be stored (span is stack-only).                         |
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
/// and discards it. <c>ReadOnlySpan</c> enables zero-allocation access to key bytes but cannot
/// cross <c>await</c> boundaries or be stored in fields.
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
public delegate ValueTask<IMemoryOwner<byte>> SigningDelegate(
    ReadOnlySpan<byte> privateKeyBytes,
    ReadOnlySpan<byte> dataToSign,
    MemoryPool<byte> signaturePool,
    FrozenDictionary<string, object>? context = null);


/// <summary>
/// Delegate for verifying a signature with a public key.
/// </summary>
/// <param name="dataToVerify">The original data that was signed.</param>
/// <param name="signature">The signature to verify.</param>
/// <param name="publicKeyMaterial">The public key material.</param>
/// <param name="context">Optional context parameters for the verification operation.</param>
/// <returns><see langword="true"/> if the signature is valid; otherwise <see langword="false"/>.</returns>
public delegate ValueTask<bool> VerificationDelegate(
    ReadOnlySpan<byte> dataToVerify,
    ReadOnlySpan<byte> signature,
    ReadOnlySpan<byte> publicKeyMaterial,
    FrozenDictionary<string, object>? context = null);


/// <summary>
/// Delegate that selects a cryptographic function based on algorithm, purpose, and optional qualifier.
/// </summary>
/// <typeparam name="T">The delegate type to return (e.g., <see cref="SigningDelegate"/>).</typeparam>
/// <typeparam name="TDiscriminator1">First discriminator type, typically <see cref="Context.CryptoAlgorithm"/>.</typeparam>
/// <typeparam name="TDiscriminator2">Second discriminator type, typically <see cref="Context.Purpose"/>.</typeparam>
/// <param name="algorithm">The cryptographic algorithm.</param>
/// <param name="purpose">The purpose of the operation.</param>
/// <param name="qualifier">Optional qualifier for backend selection or other routing decisions.</param>
/// <returns>A delegate that performs the cryptographic operation.</returns>
public delegate T PatternMatcher<T, TDiscriminator1, TDiscriminator2>(
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
/// code can work with different backends (BouncyCastle, Microsoft CNG, NSec, TPM) based on
/// runtime configuration.
/// </para>
///
/// <para>
/// <strong>Architecture Overview</strong>
/// </para>
/// <code>
/// +-----------------------------------------------------------------------+
/// |                         Application Code                              |
/// |            (Jws.SignAsync, CredentialJwsExtensions, etc.)             |
/// +----------------------------------+------------------------------------+
///                                    |
///                                    | ResolveSigning(algorithm, purpose)
///                                    | ResolveVerification(algorithm, purpose)
///                                    v
/// +-----------------------------------------------------------------------+
/// |                      CryptoFunctionRegistry                           |
/// |                                                                       |
/// |   PatternMatcher selects appropriate delegate based on:               |
/// |   - CryptoAlgorithm (P256, P384, P521, Ed25519, RSA, etc.)            |
/// |   - Purpose (Signing, Verification, KeyAgreement, etc.)               |
/// |   - Optional qualifier (backend preference, key format, etc.)         |
/// +----------------------------------+------------------------------------+
///                                    |
///                                    | Returns SigningDelegate or
///                                    | VerificationDelegate
///                                    v
/// +---------------+---------------+---------------+---------------+
/// |  BouncyCastle |   Microsoft   |     NSec      |      TPM      |
/// |    Backend    |     CNG       |    Backend    |    Backend    |
/// +---------------+---------------+---------------+---------------+
/// </code>
///
/// <para>
/// <strong>Discriminator Design</strong>
/// </para>
/// <para>
/// The registry uses two primary discriminators for function selection:
/// </para>
/// <list type="bullet">
/// <item><description>
/// <strong>CryptoAlgorithm</strong>: Identifies the cryptographic algorithm (P-256, P-384,
/// Ed25519, RSA-2048, etc.). This determines which mathematical operations are performed.
/// </description></item>
/// <item><description>
/// <strong>Purpose</strong>: Identifies the operation type (Signing, Verification, KeyAgreement,
/// Encryption, Decryption). This allows the same key material to be used for different operations
/// with appropriate function routing.
/// </description></item>
/// </list>
///
/// <para>
/// <strong>Future: MaterialSemantics as Third Discriminator</strong>
/// </para>
/// <para>
/// A future enhancement may add <c>MaterialSemantics</c> as a third routing parameter to
/// distinguish how key bytes should be interpreted:
/// </para>
/// <code>
/// +------------------+--------------------------------------------------------+
/// | MaterialSemantics| Meaning                                                |
/// +------------------+--------------------------------------------------------+
/// | Direct           | Bytes are the actual cryptographic key material.       |
/// |                  | Route to software backends (CNG, BouncyCastle, NSec).  |
/// +------------------+--------------------------------------------------------+
/// | TpmHandle        | Bytes are a TPM handle reference, not extractable key. |
/// |                  | Route to TPM backend for hardware-bound operations.    |
/// +------------------+--------------------------------------------------------+
/// | HsmReference     | Bytes are an HSM key identifier or session reference.  |
/// |                  | Route to HSM backend (PKCS#11, cloud KMS, etc.).       |
/// +------------------+--------------------------------------------------------+
/// </code>
/// <para>
/// This would enable the same high-level signing code to transparently work with both
/// software keys and hardware-protected keys without caller awareness of the distinction.
/// </para>
///
/// <para>
/// <strong>Initialization</strong>
/// </para>
/// <para>
/// Call <see cref="Initialize"/> during application startup before any concurrent access.
/// This method is not thread-safe by design to avoid synchronization overhead in the
/// hot path. Typical initialization occurs in <c>Program.cs</c> or a static constructor.
/// </para>
/// <code>
/// // During application startup:
/// CryptoFunctionRegistry&lt;CryptoAlgorithm, Purpose&gt;.Initialize(
///     signingMatcher: (algorithm, purpose, qualifier) =&gt; algorithm switch
///     {
///         var a when a == CryptoAlgorithm.P256 =&gt; EcdsaP256SigningDelegate,
///         var a when a == CryptoAlgorithm.Ed25519 =&gt; Ed25519SigningDelegate,
///         _ =&gt; throw new NotSupportedException($"Algorithm {algorithm} not supported.")
///     },
///     verificationMatcher: (algorithm, purpose, qualifier) =&gt; ...
/// );
/// </code>
///
/// <para>
/// <strong>Relationship to Other Components</strong>
/// </para>
/// <code>
/// +---------------------------+       +---------------------------+
/// |   CryptoFunctionRegistry  | &lt;---- |  CryptographicKeyFactory  |
/// |   (Function dispatch)     |       |  (Creates bound keys)     |
/// +---------------------------+       +---------------------------+
///              ^
///              |
/// +---------------------------+
/// |   KeyMaterialResolver /   |
/// |   KeyMaterialBinder       |
/// |   (Three-step key flow)   |
/// +---------------------------+
/// </code>
/// <list type="bullet">
/// <item><description>
/// <see cref="CryptographicKeyFactory"/> creates bound key objects (<see cref="PublicKey"/>,
/// <see cref="PrivateKey"/>) by combining key material with functions resolved from this registry.
/// </description></item>
/// <item><description>
/// <c>KeyMaterialResolver</c> and <c>KeyMaterialBinder</c> delegates handle the three-step
/// key resolution flow (identify, load, bind) for complex scenarios like DID resolution or
/// database-backed key storage.
/// </description></item>
/// <item><description>
/// <see cref="DefaultCoderSelector"/> handles encoding/decoding of key formats but is
/// independent of this registry's function dispatch.
/// </description></item>
/// </list>
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
    /// <remarks>
    /// <para>
    /// This is a specialized version of <see cref="Initialize"/> for delegates that need to
    /// transform key material formats before performing cryptographic operations. For example,
    /// converting compressed elliptic curve points to uncompressed format, or extracting raw
    /// key bytes from a PKCS#8 container.
    /// </para>
    /// <para>
    /// This method is not thread-safe. Call it only during application startup.
    /// </para>
    /// </remarks>
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
    public static SigningDelegate ResolveSigning(TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(SigningMatcher == null)
        {
            throw new InvalidOperationException(
                "Signing matcher has not been initialized. " +
                "Call CryptoFunctionRegistry.Initialize() during application startup.");
        }

        return SigningMatcher(algorithm, purpose, qualifier);
    }


    /// <summary>
    /// Resolves a verification function for the specified algorithm and purpose.
    /// </summary>
    /// <param name="algorithm">The cryptographic algorithm.</param>
    /// <param name="purpose">The purpose of the operation.</param>
    /// <param name="qualifier">Optional qualifier for backend selection.</param>
    /// <returns>A delegate that performs the verification operation.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the registry has not been initialized.</exception>
    public static VerificationDelegate ResolveVerification(TDiscriminator1 algorithm, TDiscriminator2 purpose, string? qualifier = null)
    {
        if(VerificationMatcher == null)
        {
            throw new InvalidOperationException(
                "Verification matcher has not been initialized. " +
                "Call CryptoFunctionRegistry.Initialize() during application startup.");
        }

        return VerificationMatcher(algorithm, purpose, qualifier);
    }
}