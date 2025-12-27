using System;
using System.Buffers;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core.Cryptography;

namespace Verifiable.Core.Model.Proofs
{
    /// <summary>
    /// Canonicalizes a JSON document to a deterministic byte representation
    /// suitable for hashing and signing.
    /// </summary>
    /// <param name="document">The JSON document to canonicalize.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The canonicalized bytes owned by the caller. The caller must dispose the returned memory.</returns>
    public delegate ValueTask<IMemoryOwner<byte>> CanonicalizationDelegate(
        JsonDocument document,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default);


    /// <summary>
    /// Creates a Data Integrity proof for a document.
    /// </summary>
    /// <param name="document">The JSON document to create a proof for.</param>
    /// <param name="options">Proof creation options specifying verification method, purpose, etc.</param>
    /// <param name="privateKey">The private key for signing.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The created proof structure.</returns>
    public delegate ValueTask<DataIntegrityProof> CreateProofDelegate(
        JsonDocument document,
        ProofOptions options,
        PrivateKeyMemory privateKey,
        MemoryPool<byte> memoryPool,
        CancellationToken cancellationToken = default);


    /// <summary>
    /// Verifies a Data Integrity proof on a document.
    /// </summary>
    /// <param name="document">The JSON document with the proof property removed.</param>
    /// <param name="proof">The proof to verify.</param>
    /// <param name="publicKey">The public key for verification.</param>
    /// <param name="memoryPool">Memory pool for allocations.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns><c>true</c> if the proof is valid; otherwise <c>false</c>.</returns>
    public delegate ValueTask<bool> VerifyProofDelegate(
        JsonDocument document,
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
    /// canonicalization, hashing, and signature algorithms used.
    /// </para>
    /// <para>
    /// <strong>Initialization:</strong>
    /// </para>
    /// <para>
    /// The registry must be initialized before use, typically during application startup.
    /// The initialization provides pattern matchers that resolve cryptosuite information
    /// to concrete proof creation and verification delegates.
    /// </para>
    /// <code>
    /// ProofFunctionRegistry.Initialize(
    ///     createProofMatcher: (cryptosuiteInfo, qualifier) =>
    ///     {
    ///         return cryptosuiteInfo.CryptosuiteName switch
    ///         {
    ///             "eddsa-rdfc-2022" => EddsaRdfc2022ProofFunctions.CreateProof(
    ///                 DotNetRdfCanonicalization.Canonicalize),
    ///             _ => throw new ArgumentException($"Unknown cryptosuite: {cryptosuiteInfo.CryptosuiteName}")
    ///         };
    ///     },
    ///     verifyProofMatcher: (cryptosuiteInfo, qualifier) =>
    ///     {
    ///         return cryptosuiteInfo.CryptosuiteName switch
    ///         {
    ///             "eddsa-rdfc-2022" => EddsaRdfc2022ProofFunctions.VerifyProof(
    ///                 DotNetRdfCanonicalization.Canonicalize),
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
                throw new InvalidOperationException("Proof function registry has not been initialized.");
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
                throw new InvalidOperationException("Proof function registry has not been initialized.");
            }

            return VerifyProofMatcherDelegate(cryptosuiteInfo, qualifier);
        }
    }
}