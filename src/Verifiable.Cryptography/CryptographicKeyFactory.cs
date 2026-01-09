using System.Collections.Frozen;
using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// Factory for creating cryptographic key objects with bound signing and verification functions.
/// </summary>
/// <remarks>
/// <para>
/// This factory creates <see cref="PublicKey"/> and <see cref="PrivateKey"/> objects by combining
/// key material with appropriate cryptographic functions resolved from 
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>.
/// </para>
///
/// <para>
/// <strong>Key Creation Flow</strong>
/// </para>
/// <code>
/// +-------------------+     +-------------------------+     +------------------+
/// |   Key Material    | --> | CryptographicKeyFactory | --> |   Bound Key      |
/// | (PublicKeyMemory) |     |                         |     | (PublicKey with  |
/// | (PrivateKeyMemory)|     |  Extracts Algorithm &amp;  |     |  verify delegate)|
/// +-------------------+     |  Purpose from Tag       |     +------------------+
///                           +------------+------------+
///                                        |
///                                        | Resolves function from
///                                        v
///                           +-------------------------+
///                           | CryptoFunctionRegistry  |
///                           | (Algorithm, Purpose) -> |
///                           | SigningDelegate or      |
///                           | VerificationDelegate    |
///                           +------------+------------+
///                                        |
///                                        v
///                           +-------------------------+
///                           |  Backend Implementation |
///                           | (BouncyCastle, CNG, etc)|
///                           +-------------------------+
/// </code>
///
/// <para>
/// <strong>Relationship to CryptoFunctionRegistry</strong>
/// </para>
/// <para>
/// This factory uses <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> internally
/// to resolve cryptographic functions. The <see cref="Tag"/> attached to key material contains
/// <see cref="CryptoAlgorithm"/> and <see cref="Purpose"/> discriminators which are extracted
/// and used for registry lookup.
/// </para>
///
/// <para>
/// <strong>Initialization</strong>
/// </para>
/// <para>
/// This factory does not require separate initialization. It uses the already-initialized
/// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>. Ensure the registry
/// is initialized before using this factory.
/// </para>
///
/// <para>
/// <strong>Custom Function Registration</strong>
/// </para>
/// <para>
/// For specialized scenarios that don't fit the standard signing/verification pattern,
/// use <see cref="RegisterFunction{TFunction}"/> to register custom functions.
/// These can be retrieved with <see cref="GetFunction{TFunction}"/>.
/// </para>
/// </remarks>
public static class CryptographicKeyFactory
{
    /// <summary>
    /// Storage for custom function mappings that don't fit the standard signing/verification pattern.
    /// </summary>
    private static Dictionary<(Type KeyType, string? Qualifier), object> CustomFunctionMappings { get; } = [];


    /// <summary>
    /// Creates a public key object with a bound verification function.
    /// </summary>
    /// <param name="publicKeyMemory">The memory containing the public key material.</param>
    /// <param name="keyIdentifier">A unique identifier for the key (e.g., DID URL, key ID).</param>
    /// <param name="tag">Metadata describing the key's algorithm and purpose.</param>
    /// <param name="qualifier">An optional qualifier for selecting among multiple implementations.</param>
    /// <param name="defaultContext">Optional default context for verification operations.</param>
    /// <returns>A <see cref="PublicKey"/> object ready for verification operations.</returns>
    /// <exception cref="InvalidOperationException">Thrown if <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> has not been initialized.</exception>
    /// <exception cref="ArgumentException">Thrown if no verification function is registered for the algorithm/purpose.</exception>
    /// <remarks>
    /// <para>
    /// The returned <see cref="PublicKey"/> takes ownership of the <paramref name="publicKeyMemory"/>.
    /// Dispose the <see cref="PublicKey"/> to release the underlying memory.
    /// </para>
    /// <para>
    /// The <paramref name="tag"/> must contain <see cref="CryptoAlgorithm"/> and <see cref="Purpose"/>
    /// components for function resolution.
    /// </para>
    /// </remarks>
    public static PublicKey CreatePublicKey(
        PublicKeyMemory publicKeyMemory,
        string keyIdentifier,
        Tag tag,
        string? qualifier = null,
        FrozenDictionary<string, object>? defaultContext = null)
    {
        var algorithm = tag.Get<CryptoAlgorithm>();
        var purpose = tag.Get<Purpose>();

        var verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose, qualifier);

        return new PublicKey(publicKeyMemory, keyIdentifier, verificationDelegate, defaultContext);
    }


    /// <summary>
    /// Creates a private key object with a bound signing function.
    /// </summary>
    /// <param name="privateKeyMemory">The memory containing the private key material.</param>
    /// <param name="keyIdentifier">A unique identifier for the key (e.g., DID URL, key ID).</param>
    /// <param name="tag">Metadata describing the key's algorithm and purpose.</param>
    /// <param name="qualifier">An optional qualifier for selecting among multiple implementations.</param>
    /// <param name="defaultContext">Optional default context for signing operations.</param>
    /// <returns>A <see cref="PrivateKey"/> object ready for signing operations.</returns>
    /// <exception cref="InvalidOperationException">Thrown if <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> has not been initialized.</exception>
    /// <exception cref="ArgumentException">Thrown if no signing function is registered for the algorithm/purpose.</exception>
    /// <remarks>
    /// <para>
    /// The returned <see cref="PrivateKey"/> takes ownership of the <paramref name="privateKeyMemory"/>.
    /// Dispose the <see cref="PrivateKey"/> to release the underlying memory.
    /// </para>
    /// <para>
    /// The <paramref name="tag"/> must contain <see cref="CryptoAlgorithm"/> and <see cref="Purpose"/>
    /// components for function resolution.
    /// </para>
    /// </remarks>
    public static PrivateKey CreatePrivateKey(
        PrivateKeyMemory privateKeyMemory,
        string keyIdentifier,
        Tag tag,
        string? qualifier = null,
        FrozenDictionary<string, object>? defaultContext = null)
    {
        var algorithm = tag.Get<CryptoAlgorithm>();
        var purpose = tag.Get<Purpose>();

        var signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose, qualifier);

        return new PrivateKey(privateKeyMemory, keyIdentifier, signingDelegate, defaultContext);
    }


    /// <summary>
    /// Creates a public key using algorithm and purpose parameters directly.
    /// </summary>
    /// <param name="publicKeyMemory">The memory containing the public key material.</param>
    /// <param name="keyIdentifier">A unique identifier for the key.</param>
    /// <param name="algorithm">The cryptographic algorithm associated with the key.</param>
    /// <param name="purpose">The purpose of the key.</param>
    /// <param name="qualifier">An optional qualifier for selecting among multiple implementations.</param>
    /// <param name="defaultContext">Optional default context for verification operations.</param>
    /// <returns>A <see cref="PublicKey"/> object.</returns>
    /// <remarks>
    /// <para>
    /// This is a convenience method that resolves the verification function directly from
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> without requiring a Tag.
    /// </para>
    /// </remarks>
    public static PublicKey CreatePublicKey(
        PublicKeyMemory publicKeyMemory,
        string keyIdentifier,
        CryptoAlgorithm algorithm,
        Purpose purpose,
        string? qualifier = null,
        FrozenDictionary<string, object>? defaultContext = null)
    {
        var verificationDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveVerification(algorithm, purpose, qualifier);

        return new PublicKey(publicKeyMemory, keyIdentifier, verificationDelegate, defaultContext);
    }


    /// <summary>
    /// Creates a private key using algorithm and purpose parameters directly.
    /// </summary>
    /// <param name="privateKeyMemory">The memory containing the private key material.</param>
    /// <param name="keyIdentifier">A unique identifier for the key.</param>
    /// <param name="algorithm">The cryptographic algorithm associated with the key.</param>
    /// <param name="purpose">The purpose of the key.</param>
    /// <param name="qualifier">An optional qualifier for selecting among multiple implementations.</param>
    /// <param name="defaultContext">Optional default context for signing operations.</param>
    /// <returns>A <see cref="PrivateKey"/> object.</returns>
    /// <remarks>
    /// <para>
    /// This is a convenience method that resolves the signing function directly from
    /// <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> without requiring a Tag.
    /// </para>
    /// </remarks>
    public static PrivateKey CreatePrivateKey(
        PrivateKeyMemory privateKeyMemory,
        string keyIdentifier,
        CryptoAlgorithm algorithm,
        Purpose purpose,
        string? qualifier = null,
        FrozenDictionary<string, object>? defaultContext = null)
    {
        var signingDelegate = CryptoFunctionRegistry<CryptoAlgorithm, Purpose>.ResolveSigning(algorithm, purpose, qualifier);

        return new PrivateKey(privateKeyMemory, keyIdentifier, signingDelegate, defaultContext);
    }


    /// <summary>
    /// Registers a custom function for specialized cryptographic operations.
    /// </summary>
    /// <typeparam name="TFunction">The delegate type of the function.</typeparam>
    /// <param name="functionType">A type that identifies the function category.</param>
    /// <param name="function">The function to register.</param>
    /// <param name="qualifier">An optional qualifier for distinguishing multiple implementations.</param>
    /// <remarks>
    /// <para>
    /// Use this method to register functions that don't fit the standard signing/verification
    /// pattern, such as key derivation functions, key agreement operations, or format-specific
    /// transformations.
    /// </para>
    /// <para>
    /// Example usage for key agreement:
    /// </para>
    /// <code>
    /// CryptographicKeyFactory.RegisterFunction(
    ///     typeof(X25519KeyAgreement),
    ///     BouncyCastleCryptographicFunctions.DeriveX25519SharedSecretAsync,
    ///     "bouncy-castle");
    /// </code>
    /// </remarks>
    public static void RegisterFunction<TFunction>(Type functionType, TFunction function, string? qualifier = null)
        where TFunction : Delegate
    {
        CustomFunctionMappings[(functionType, qualifier)] = function;
    }


    /// <summary>
    /// Retrieves a previously registered custom function.
    /// </summary>
    /// <typeparam name="TFunction">The delegate type of the function.</typeparam>
    /// <param name="functionType">The type that identifies the function category.</param>
    /// <param name="qualifier">The qualifier used when registering the function.</param>
    /// <returns>The registered function, or <see langword="null"/> if not found.</returns>
    /// <remarks>
    /// <para>
    /// Use this to retrieve custom functions registered with <see cref="RegisterFunction{TFunction}"/>.
    /// </para>
    /// </remarks>
    public static TFunction? GetFunction<TFunction>(Type functionType, string? qualifier = null)
        where TFunction : Delegate
    {
        if(CustomFunctionMappings.TryGetValue((functionType, qualifier), out var function))
        {
            return (TFunction)function;
        }

        return null;
    }


    /// <summary>
    /// Creates a frozen dictionary of parameters for use with cryptographic function context.
    /// </summary>
    /// <param name="parameters">Key-value pairs to include in the dictionary.</param>
    /// <returns>An immutable dictionary suitable for passing to cryptographic delegates.</returns>
    /// <remarks>
    /// <para>
    /// The returned <see cref="FrozenDictionary{TKey, TValue}"/> is optimized for read-heavy
    /// scenarios and is safe for concurrent access. Use this for passing algorithm-specific
    /// parameters to signing and verification delegates.
    /// </para>
    /// <para>
    /// Example usage:
    /// </para>
    /// <code>
    /// var context = CryptographicKeyFactory.CreateParameters(
    ///     ("hashAlgorithm", HashAlgorithmName.SHA256),
    ///     ("padding", RSASignaturePadding.Pss));
    /// 
    /// var signature = await privateKey.SignAsync(data, pool, context);
    /// </code>
    /// </remarks>
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