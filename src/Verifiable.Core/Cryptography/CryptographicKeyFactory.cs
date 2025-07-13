using System;
using System.Collections.Generic;
using System.Collections.Frozen;
using System.Threading.Tasks;

namespace Verifiable.Core.Cryptography
{
    /// <summary>
    /// Factory responsible for creating cryptographic key objects with appropriate signing and verification functions.
    /// This factory serves as a high-level abstraction over cryptographic operations, allowing for flexible
    /// implementations while maintaining a consistent interface.
    /// </summary>
    public static class CryptographicKeyFactory
    {
        private static Func<Tag, string?, VerificationFunction<byte, byte, Signature, ValueTask<bool>>>? VerificationMapping { get; set; }

        private static Func<Tag, string?, SigningFunction<byte, byte, ValueTask<Signature>>>? SigningMapping { get; set; }

        private static Dictionary<(Type KeyType, string? Qualifier), object> CustomFunctionMappings { get; } = [];

        /// <summary>
        /// Initializes the factory with the specified mapping functions for verification and signing operations.
        /// </summary>
        /// <param name="verificationMapping">A function that maps a Tag and optional qualifier to a verification function.</param>
        /// <param name="signingMapping">A function that maps a Tag and optional qualifier to a signing function.</param>
        public static void Initialize(
            Func<Tag, string?, VerificationFunction<byte, byte, Signature, ValueTask<bool>>> verificationMapping,
            Func<Tag, string?, SigningFunction<byte, byte, ValueTask<Signature>>> signingMapping)
        {
            VerificationMapping = verificationMapping;
            SigningMapping = signingMapping;
        }

        /// <summary>
        /// Creates a public key object using the mapped verification function.
        /// </summary>
        /// <param name="publicKeyMemory">The memory containing the public key material.</param>
        /// <param name="keyIdentifier">A unique identifier for the key.</param>
        /// <param name="tag">Metadata describing the key and its properties.</param>
        /// <param name="selector">An optional qualifier to further specify the key's context or purpose.</param>
        /// <returns>A PublicKey object that encapsulates the key material and verification function.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the factory has not been initialized.</exception>
        /// <exception cref="ArgumentException">Thrown if no verification function is registered for the given tag and qualifier.</exception>
        public static PublicKey CreatePublicKey(
            PublicKeyMemory publicKeyMemory,
            string keyIdentifier,
            Tag tag,
            string? selector = null)
        {
            if(VerificationMapping == null)
            {
                throw new InvalidOperationException("Verification mapping has not been initialized.");
            }

            var verificationFunction = VerificationMapping(tag, selector) ?? throw new ArgumentException($"No verification function registered for {tag}, {selector}.");

            return new PublicKey(publicKeyMemory, keyIdentifier, verificationFunction);
        }

        /// <summary>
        /// Creates a private key object using the mapped signing function.
        /// </summary>
        /// <param name="privateKeyMemory">The memory containing the private key material.</param>
        /// <param name="keyIdentifier">A unique identifier for the key.</param>
        /// <param name="tag">Metadata describing the key and its properties.</param>
        /// <param name="selector">An optional qualifier to further specify the key's context or purpose.</param>
        /// <returns>A PrivateKey object that encapsulates the key material and signing function.</returns>
        /// <exception cref="InvalidOperationException">Thrown if the factory has not been initialized.</exception>
        /// <exception cref="ArgumentException">Thrown if no signing function is registered for the given tag and qualifier.</exception>
        public static PrivateKey CreatePrivateKey(
            PrivateKeyMemory privateKeyMemory,
            string keyIdentifier,
            Tag tag,
            string? selector = null)
        {
            if(SigningMapping == null)
            {
                throw new InvalidOperationException("Signing mapping has not been initialized.");
            }

            var signingFunction = SigningMapping(tag, selector) ?? throw new ArgumentException($"No signing function registered for {tag}, {selector}.");

            return new PrivateKey(privateKeyMemory, keyIdentifier, signingFunction);
        }

        /// <summary>
        /// Creates a public key using algorithm and purpose parameters instead of a Tag.
        /// This is a convenience method that creates a Tag internally.
        /// </summary>
        /// <param name="publicKeyMemory">The memory containing the public key material.</param>
        /// <param name="keyIdentifier">A unique identifier for the key.</param>
        /// <param name="algorithm">The cryptographic algorithm associated with the key.</param>
        /// <param name="purpose">The purpose of the key (verification, signing, etc.).</param>
        /// <returns>A PublicKey object.</returns>
        public static PublicKey CreatePublicKey(
            PublicKeyMemory publicKeyMemory,
            string keyIdentifier,
            Context.CryptoAlgorithm algorithm,
            Context.Purpose purpose)
        {
            var tag = new Tag(new Dictionary<Type, object>
            {
                [typeof(Context.CryptoAlgorithm)] = algorithm,
                [typeof(Context.Purpose)] = purpose
            });

            return CreatePublicKey(publicKeyMemory, keyIdentifier, tag);
        }

        /// <summary>
        /// Creates a private key using algorithm and purpose parameters instead of a Tag.
        /// This is a convenience method that creates a Tag internally.
        /// </summary>
        /// <param name="privateKeyMemory">The memory containing the private key material.</param>
        /// <param name="keyIdentifier">A unique identifier for the key.</param>
        /// <param name="algorithm">The cryptographic algorithm associated with the key.</param>
        /// <param name="purpose">The purpose of the key (verification, signing, etc.).</param>
        /// <returns>A PrivateKey object.</returns>
        public static PrivateKey CreatePrivateKey(
            PrivateKeyMemory privateKeyMemory,
            string keyIdentifier,
            Context.CryptoAlgorithm algorithm,
            Context.Purpose purpose)
        {
            var tag = new Tag(new Dictionary<Type, object>
            {
                [typeof(Context.CryptoAlgorithm)] = algorithm,
                [typeof(Context.Purpose)] = purpose
            });

            return CreatePrivateKey(privateKeyMemory, keyIdentifier, tag);
        }

        /// <summary>
        /// Registers a custom function for a specific key type and optional qualifier.
        /// </summary>
        /// <typeparam name="TFunction">The type of function to register.</typeparam>
        /// <param name="functionType">The type that identifies the function category.</param>
        /// <param name="function">The function to register.</param>
        /// <param name="qualifier">An optional qualifier to further specify the function's context.</param>
        public static void RegisterFunction<TFunction>(Type functionType, TFunction function, string? qualifier = null) where TFunction: Delegate
        {
            CustomFunctionMappings[(functionType, qualifier)] = function;
        }

        /// <summary>
        /// Retrieves a registered custom function.
        /// </summary>
        /// <typeparam name="TFunction">The type of function to retrieve.</typeparam>
        /// <param name="functionType">The type that identifies the function category.</param>
        /// <param name="qualifier">An optional qualifier to further specify the function's context.</param>
        /// <returns>The registered function, or null if not found.</returns>
        public static TFunction? GetFunction<TFunction>(Type functionType, string? qualifier = null) where TFunction: Delegate
        {
            if(CustomFunctionMappings.TryGetValue((functionType, qualifier), out var function))
            {
                return (TFunction)function;
            }

            return null;
        }

        /// <summary>
        /// Creates a dictionary of parameters that can be frozen and used with cryptographic functions.
        /// </summary>
        /// <param name="parameters">The parameters to include in the dictionary.</param>
        /// <returns>A frozen dictionary containing the specified parameters.</returns>
        public static FrozenDictionary<string, object> CreateParameters(params (string Key, object Value)[] parameters)
        {
            var dict = new Dictionary<string, object>(parameters.Length);
            foreach(var (key, value) in parameters)
            {
                dict[key] = value;
            }

            return dict.ToFrozenDictionary();
        }
    }
}
