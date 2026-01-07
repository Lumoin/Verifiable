using System.Collections.Frozen;

namespace Verifiable.Cryptography;

/// <summary>
/// Factory for creating cryptographic key objects with bound signing and verification functions.
/// </summary>
/// <remarks>
/// <para>
/// This factory creates <see cref="PublicKey"/> and <see cref="PrivateKey"/> objects by combining
/// key material with appropriate cryptographic functions. It provides a higher-level abstraction
/// than <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/>, producing ready-to-use
/// key objects rather than raw function delegates.
/// </para>
///
/// <para>
/// <strong>Key Creation Flow</strong>
/// </para>
/// <code>
/// +-------------------+     +-------------------------+     +------------------+
/// |   Key Material    | --> | CryptographicKeyFactory | --> |   Bound Key      |
/// | (PublicKeyMemory) |     |                         |     | (PublicKey with  |
/// | (PrivateKeyMemory)|     |  Combines material with |     |  verify function)|
/// +-------------------+     |  functions from mapping |     +------------------+
///                           +-------------------------+
///                                       |
///                                       | Uses mapping functions
///                                       | to select appropriate
///                                       | crypto operations
///                                       v
///                           +-------------------------+
///                           |  Backend Implementation |
///                           | (BouncyCastle, CNG, etc)|
///                           +-------------------------+
/// </code>
///
/// <para>
/// <strong>Difference from CryptoFunctionRegistry</strong>
/// </para>
/// <para>
/// While <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> dispatches based on
/// <c>CryptoAlgorithm</c> and <c>Purpose</c> discriminators, this factory uses <see cref="Tag"/>
/// metadata attached to key material. The Tag encapsulates the same information but is bound
/// to the key itself, enabling a more object-oriented usage pattern.
/// </para>
/// <code>
/// // CryptoFunctionRegistry approach (function-oriented):
/// SigningDelegate sign = CryptoFunctionRegistry&lt;CryptoAlgorithm, Purpose&gt;
///     .ResolveSigning(CryptoAlgorithm.P256, Purpose.Signing);
/// var signature = await sign(privateKeyBytes, data, pool);
///
/// // CryptographicKeyFactory approach (object-oriented):
/// PrivateKey key = CryptographicKeyFactory.CreatePrivateKey(
///     privateKeyMemory, "key-1", Tag.P256PrivateKey);
/// var signature = await key.SignAsync(data, pool);
/// </code>
///
/// <para>
/// <strong>Initialization</strong>
/// </para>
/// <para>
/// Call <see cref="Initialize"/> during application startup to register the mapping functions.
/// This method is not thread-safe; call it before any concurrent access.
/// </para>
///
/// <para>
/// <strong>Custom Function Registration</strong>
/// </para>
/// <para>
/// For specialized scenarios, use <see cref="RegisterFunction{TFunction}"/> to register custom
/// functions that don't fit the standard signing/verification pattern. These can be retrieved
/// with <see cref="GetFunction{TFunction}"/>.
/// </para>
/// </remarks>
public static class CryptographicKeyFactory
{
    private static Func<Tag, string?, VerificationFunction<byte, byte, Signature, ValueTask<bool>>>? VerificationMapping { get; set; }

    private static Func<Tag, string?, SigningFunction<byte, byte, ValueTask<Signature>>>? SigningMapping { get; set; }

    private static Dictionary<(Type KeyType, string? Qualifier), object> CustomFunctionMappings { get; } = [];


    /// <summary>
    /// Initializes the factory with mapping functions for verification and signing operations.
    /// </summary>
    /// <param name="verificationMapping">
    /// A function that maps a <see cref="Tag"/> and optional qualifier to a verification function.
    /// </param>
    /// <param name="signingMapping">
    /// A function that maps a <see cref="Tag"/> and optional qualifier to a signing function.
    /// </param>
    /// <remarks>
    /// <para>
    /// This method is not thread-safe. Call it only during application startup before
    /// concurrent access begins, such as in static initializers or early in <c>Program.cs</c>.
    /// </para>
    /// </remarks>
    public static void Initialize(
        Func<Tag, string?, VerificationFunction<byte, byte, Signature, ValueTask<bool>>> verificationMapping,
        Func<Tag, string?, SigningFunction<byte, byte, ValueTask<Signature>>> signingMapping)
    {
        VerificationMapping = verificationMapping;
        SigningMapping = signingMapping;
    }


    /// <summary>
    /// Creates a public key object with a bound verification function.
    /// </summary>
    /// <param name="publicKeyMemory">The memory containing the public key material.</param>
    /// <param name="keyIdentifier">A unique identifier for the key (e.g., DID URL, key ID).</param>
    /// <param name="tag">Metadata describing the key's algorithm and purpose.</param>
    /// <param name="selector">An optional qualifier for selecting among multiple implementations.</param>
    /// <returns>A <see cref="PublicKey"/> object ready for verification operations.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the factory has not been initialized.</exception>
    /// <exception cref="ArgumentException">Thrown if no verification function is registered for the tag.</exception>
    /// <remarks>
    /// <para>
    /// The returned <see cref="PublicKey"/> takes ownership of the <paramref name="publicKeyMemory"/>.
    /// Dispose the <see cref="PublicKey"/> to release the underlying memory.
    /// </para>
    /// </remarks>
    public static PublicKey CreatePublicKey(
        PublicKeyMemory publicKeyMemory,
        string keyIdentifier,
        Tag tag,
        string? selector = null)
    {
        if(VerificationMapping == null)
        {
            throw new InvalidOperationException(
                "Verification mapping has not been initialized. " +
                "Call CryptographicKeyFactory.Initialize() during application startup.");
        }

        var verificationFunction = VerificationMapping(tag, selector)
            ?? throw new ArgumentException($"No verification function registered for tag {tag} with selector '{selector}'.");

        return new PublicKey(publicKeyMemory, keyIdentifier, verificationFunction);
    }


    /// <summary>
    /// Creates a private key object with a bound signing function.
    /// </summary>
    /// <param name="privateKeyMemory">The memory containing the private key material.</param>
    /// <param name="keyIdentifier">A unique identifier for the key (e.g., DID URL, key ID).</param>
    /// <param name="tag">Metadata describing the key's algorithm and purpose.</param>
    /// <param name="selector">An optional qualifier for selecting among multiple implementations.</param>
    /// <returns>A <see cref="PrivateKey"/> object ready for signing operations.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the factory has not been initialized.</exception>
    /// <exception cref="ArgumentException">Thrown if no signing function is registered for the tag.</exception>
    /// <remarks>
    /// <para>
    /// The returned <see cref="PrivateKey"/> takes ownership of the <paramref name="privateKeyMemory"/>.
    /// Dispose the <see cref="PrivateKey"/> to release the underlying memory.
    /// </para>
    /// </remarks>
    public static PrivateKey CreatePrivateKey(
        PrivateKeyMemory privateKeyMemory,
        string keyIdentifier,
        Tag tag,
        string? selector = null)
    {
        if(SigningMapping == null)
        {
            throw new InvalidOperationException(
                "Signing mapping has not been initialized. " +
                "Call CryptographicKeyFactory.Initialize() during application startup.");
        }

        var signingFunction = SigningMapping(tag, selector)
            ?? throw new ArgumentException($"No signing function registered for tag {tag} with selector '{selector}'.");

        return new PrivateKey(privateKeyMemory, keyIdentifier, signingFunction);
    }


    /// <summary>
    /// Creates a public key using algorithm and purpose parameters instead of a Tag.
    /// </summary>
    /// <param name="publicKeyMemory">The memory containing the public key material.</param>
    /// <param name="keyIdentifier">A unique identifier for the key.</param>
    /// <param name="algorithm">The cryptographic algorithm associated with the key.</param>
    /// <param name="purpose">The purpose of the key.</param>
    /// <returns>A <see cref="PublicKey"/> object.</returns>
    /// <remarks>
    /// <para>
    /// This is a convenience method that constructs a <see cref="Tag"/> internally from the
    /// provided algorithm and purpose. Use the <see cref="CreatePublicKey(PublicKeyMemory, string, Tag, string?)"/>
    /// overload when you already have a Tag or need additional Tag components.
    /// </para>
    /// </remarks>
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
    /// </summary>
    /// <param name="privateKeyMemory">The memory containing the private key material.</param>
    /// <param name="keyIdentifier">A unique identifier for the key.</param>
    /// <param name="algorithm">The cryptographic algorithm associated with the key.</param>
    /// <param name="purpose">The purpose of the key.</param>
    /// <returns>A <see cref="PrivateKey"/> object.</returns>
    /// <remarks>
    /// <para>
    /// This is a convenience method that constructs a <see cref="Tag"/> internally from the
    /// provided algorithm and purpose. Use the <see cref="CreatePrivateKey(PrivateKeyMemory, string, Tag, string?)"/>
    /// overload when you already have a Tag or need additional Tag components.
    /// </para>
    /// </remarks>
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