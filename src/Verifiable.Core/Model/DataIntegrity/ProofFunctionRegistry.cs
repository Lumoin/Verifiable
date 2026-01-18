using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Creates a Data Integrity proof for document bytes.
/// </summary>
/// <remarks>
/// <para>
/// This delegate operates on already-canonicalized bytes, keeping serialization
/// concerns separate from proof creation. The caller is responsible for:
/// </para>
/// <list type="number">
/// <item><description>Serializing the document to JSON.</description></item>
/// <item><description>Canonicalizing the JSON using the appropriate algorithm.</description></item>
/// <item><description>Passing the canonical bytes to this delegate.</description></item>
/// </list>
/// </remarks>
/// <param name="canonicalDocument">The canonicalized document bytes.</param>
/// <param name="canonicalProofOptions">The canonicalized proof options bytes.</param>
/// <param name="options">Proof creation options specifying verification method, purpose, etc.</param>
/// <param name="privateKey">The private key for signing.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The created proof structure.</returns>
public delegate ValueTask<DataIntegrityProof> CreateProofDelegate(
    ReadOnlyMemory<byte> canonicalDocument,
    ReadOnlyMemory<byte> canonicalProofOptions,
    ProofOptions options,
    PrivateKeyMemory privateKey,
    MemoryPool<byte> memoryPool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Verifies a Data Integrity proof on document bytes.
/// </summary>
/// <remarks>
/// <para>
/// This delegate operates on already-canonicalized bytes, keeping serialization
/// concerns separate from proof verification.
/// </para>
/// </remarks>
/// <param name="canonicalDocument">The canonicalized document bytes (without proof).</param>
/// <param name="canonicalProofOptions">The canonicalized proof options bytes.</param>
/// <param name="proof">The proof to verify.</param>
/// <param name="publicKey">The public key for verification.</param>
/// <param name="memoryPool">Memory pool for allocations.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns><c>true</c> if the proof is valid; otherwise <c>false</c>.</returns>
public delegate ValueTask<bool> VerifyProofDelegate(
    ReadOnlyMemory<byte> canonicalDocument,
    ReadOnlyMemory<byte> canonicalProofOptions,
    DataIntegrityProof proof,
    PublicKeyMemory publicKey,
    MemoryPool<byte> memoryPool,
    CancellationToken cancellationToken = default);


/// <summary>
/// Pattern matcher for resolving proof creation delegates based on cryptosuite information.
/// </summary>
/// <param name="cryptosuiteInfo">The cryptosuite information.</param>
/// <param name="qualifier">Optional qualifier for specialized implementations.</param>
/// <returns>The proof creation delegate for the specified cryptosuite.</returns>
public delegate CreateProofDelegate CreateProofMatcher(
    CryptosuiteInfo cryptosuiteInfo,
    string? qualifier = null);


/// <summary>
/// Pattern matcher for resolving proof verification delegates based on cryptosuite information.
/// </summary>
/// <param name="cryptosuiteInfo">The cryptosuite information.</param>
/// <param name="qualifier">Optional qualifier for specialized implementations.</param>
/// <returns>The proof verification delegate for the specified cryptosuite.</returns>
public delegate VerifyProofDelegate VerifyProofMatcher(
    CryptosuiteInfo cryptosuiteInfo,
    string? qualifier = null);


/// <summary>
/// Registry for Data Integrity proof creation and verification functions.
/// Follows the same pattern as <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>.
/// </summary>
/// <remarks>
/// <para>
/// This registry routes proof creation and verification to the appropriate
/// implementation based on the cryptosuite. The cryptosuite determines the
/// hashing and signature algorithms used.
/// </para>
/// <para>
/// <strong>Separation of Concerns:</strong>
/// </para>
/// <para>
/// Canonicalization is handled separately in the <see cref="Verifiable.Core.Serialization"/>
/// namespace via <see cref="CanonicalizationDelegate"/>. This registry only handles
/// the cryptographic operations on already-canonicalized bytes.
/// </para>
/// <para>
/// <strong>Initialization:</strong>
/// </para>
/// <para>
/// The registry must be initialized before use, typically during application startup.
/// </para>
/// <code>
/// ProofFunctionRegistry.Initialize(
///     createProofMatcher: (cryptosuiteInfo, qualifier) =>
///     {
///         return cryptosuiteInfo.CryptosuiteName switch
///         {
///             "eddsa-rdfc-2022" => EddsaProofFunctions.CreateProof,
///             "eddsa-jcs-2022" => EddsaProofFunctions.CreateProof,
///             _ => throw new ArgumentException($"Unknown cryptosuite: {cryptosuiteInfo.CryptosuiteName}")
///         };
///     },
///     verifyProofMatcher: (cryptosuiteInfo, qualifier) =>
///     {
///         return cryptosuiteInfo.CryptosuiteName switch
///         {
///             "eddsa-rdfc-2022" => EddsaProofFunctions.VerifyProof,
///             "eddsa-jcs-2022" => EddsaProofFunctions.VerifyProof,
///             _ => throw new ArgumentException($"Unknown cryptosuite: {cryptosuiteInfo.CryptosuiteName}")
///         };
///     });
/// </code>
/// <para>
/// See <see href="https://www.w3.org/TR/vc-data-integrity/">
/// W3C Verifiable Credentials Data Integrity</see>.
/// </para>
/// </remarks>
public static class ProofFunctionRegistry
{
    private static CreateProofMatcher? CreateProofMatcherDelegate { get; set; }

    private static VerifyProofMatcher? VerifyProofMatcherDelegate { get; set; }


    /// <summary>
    /// Initializes the registry with pattern matchers for proof operations.
    /// </summary>
    /// <param name="createProofMatcher">Matcher for resolving proof creation delegates.</param>
    /// <param name="verifyProofMatcher">Matcher for resolving proof verification delegates.</param>
    /// <exception cref="ArgumentNullException">Thrown when either matcher is null.</exception>
    public static void Initialize(
        CreateProofMatcher createProofMatcher,
        VerifyProofMatcher verifyProofMatcher)
    {
        ArgumentNullException.ThrowIfNull(createProofMatcher);
        ArgumentNullException.ThrowIfNull(verifyProofMatcher);

        CreateProofMatcherDelegate = createProofMatcher;
        VerifyProofMatcherDelegate = verifyProofMatcher;
    }


    /// <summary>
    /// Resolves a proof creation delegate for the specified cryptosuite.
    /// </summary>
    /// <param name="cryptosuiteInfo">The cryptosuite information.</param>
    /// <param name="qualifier">Optional qualifier for specialized implementations.</param>
    /// <returns>The proof creation delegate.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the registry has not been initialized.</exception>
    public static CreateProofDelegate ResolveCreateProof(
        CryptosuiteInfo cryptosuiteInfo,
        string? qualifier = null)
    {
        if(CreateProofMatcherDelegate is null)
        {
            throw new InvalidOperationException(
                $"The {nameof(ProofFunctionRegistry)} has not been initialized. " +
                $"Call {nameof(Initialize)} before resolving proof functions.");
        }

        return CreateProofMatcherDelegate(cryptosuiteInfo, qualifier);
    }


    /// <summary>
    /// Resolves a proof verification delegate for the specified cryptosuite.
    /// </summary>
    /// <param name="cryptosuiteInfo">The cryptosuite information.</param>
    /// <param name="qualifier">Optional qualifier for specialized implementations.</param>
    /// <returns>The proof verification delegate.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the registry has not been initialized.</exception>
    public static VerifyProofDelegate ResolveVerifyProof(
        CryptosuiteInfo cryptosuiteInfo,
        string? qualifier = null)
    {
        if(VerifyProofMatcherDelegate is null)
        {
            throw new InvalidOperationException(
                $"The {nameof(ProofFunctionRegistry)} has not been initialized. " +
                $"Call {nameof(Initialize)} before resolving proof functions.");
        }

        return VerifyProofMatcherDelegate(cryptosuiteInfo, qualifier);
    }


    /// <summary>
    /// Gets a value indicating whether the registry has been initialized.
    /// </summary>
    public static bool IsInitialized =>
        CreateProofMatcherDelegate is not null && VerifyProofMatcherDelegate is not null;
}