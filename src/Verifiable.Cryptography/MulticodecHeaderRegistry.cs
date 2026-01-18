using Verifiable.Cryptography.Context;

namespace Verifiable.Cryptography;

/// <summary>
/// Delegate for resolving multicodec headers from cryptographic algorithms.
/// </summary>
/// <param name="algorithm">The cryptographic algorithm.</param>
/// <returns>The multicodec header bytes for the algorithm.</returns>
/// <remarks>
/// <para>
/// Implementations should throw <see cref="ArgumentException"/> for unsupported algorithms
/// to allow fallback to default mappings when used with <see cref="MulticodecHeaderRegistry"/>.
/// </para>
/// </remarks>
public delegate ReadOnlyMemory<byte> MulticodecHeaderResolverDelegate(CryptoAlgorithm algorithm);


/// <summary>
/// Registry for resolving multicodec headers from cryptographic algorithms.
/// </summary>
/// <remarks>
/// <para>
/// This registry maps <see cref="CryptoAlgorithm"/> values to their corresponding
/// multicodec headers as defined in the multicodec table.
/// </para>
/// <para>
/// <strong>Default Mappings:</strong> The registry includes built-in support for standard
/// algorithms (P-256, P-384, P-521, Ed25519, X25519, secp256k1, RSA). Call <see cref="Initialize()"/>
/// without parameters to use only defaults.
/// </para>
/// <para>
/// <strong>Extensibility:</strong> Applications can provide a custom resolver via
/// <see cref="Initialize(MulticodecHeaderResolverDelegate)"/>. The custom resolver is tried first,
/// and if it throws <see cref="ArgumentException"/> or returns empty, the registry falls back
/// to the default mappings.
/// </para>
/// <para>
/// <strong>Test Isolation:</strong> Use <see cref="CurrentResolver"/> to save the current state
/// before tests and restore it afterward via <see cref="Initialize(MulticodecHeaderResolverDelegate)"/>.
/// </para>
/// <para>
/// <strong>Initialization:</strong> Call <see cref="Initialize()"/> during application
/// startup before any cryptographic operations. This follows the same pattern as
/// <see cref="CryptoFunctionRegistry{TAlgorithm, TPurpose}"/>.
/// </para>
/// <para>
/// <strong>TODO:</strong> Look for a mechanism to reduce the manual labor required to keep
/// <see cref="MulticodecHeaders"/> constants, <see cref="CryptoAlgorithm"/> values, and
/// resolver transformations matched. Potential approaches include source generators,
/// attribute-based registration, or a declarative mapping table.
/// </para>
/// <para>
/// See <see href="https://github.com/multiformats/multicodec">multicodec (GitHub)</see>.
/// </para>
/// </remarks>
/// <example>
/// <code>
/// //Initialize with defaults only.
/// MulticodecHeaderRegistry.Initialize();
///
/// //Or initialize with custom resolver that extends defaults.
/// MulticodecHeaderRegistry.Initialize(algorithm => algorithm switch
/// {
///     _ when algorithm.Equals(MyCustomAlgorithm) => MyCustomHeader.ToArray(),
///     _ => throw new ArgumentException($"Unknown algorithm '{algorithm}'.") //Falls back to defaults.
/// });
///
/// //Later, resolve headers.
/// ReadOnlySpan&lt;byte&gt; header = MulticodecHeaderRegistry.Resolve(CryptoAlgorithm.P256);
///
/// //Test isolation: save and restore state.
/// var savedResolver = MulticodecHeaderRegistry.CurrentResolver;
/// try
/// {
///     MulticodecHeaderRegistry.Initialize(testResolver);
///     //Run tests...
/// }
/// finally
/// {
///     MulticodecHeaderRegistry.SetResolver(savedResolver);
/// }
/// </code>
/// </example>
public static class MulticodecHeaderRegistry
{
    /// <summary>
    /// The resolver delegate for mapping algorithms to multicodec headers.
    /// </summary>
    private static MulticodecHeaderResolverDelegate? Resolver { get; set; }


    /// <summary>
    /// Gets the current resolver delegate, or <see langword="null"/> if not initialized.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Use this property to save the current state before modifying the registry,
    /// then restore it via <see cref="SetResolver"/> after tests complete.
    /// </para>
    /// </remarks>
    public static MulticodecHeaderResolverDelegate? CurrentResolver
    {
        get => Resolver;
    }


    /// <summary>
    /// Sets the resolver delegate directly, bypassing the default fallback logic.
    /// </summary>
    /// <param name="resolver">The resolver to set, or <see langword="null"/> to clear.</param>
    /// <remarks>
    /// <para>
    /// This method is primarily intended for restoring a previously saved resolver
    /// during test cleanup. For normal initialization, use <see cref="Initialize()"/>
    /// or <see cref="Initialize(MulticodecHeaderResolverDelegate)"/>.
    /// </para>
    /// </remarks>
    public static void SetResolver(MulticodecHeaderResolverDelegate? resolver)
    {
        Resolver = resolver;
    }


    /// <summary>
    /// Initializes the registry with default multicodec header mappings.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The default mappings cover standard algorithms: P-256, P-384, P-521, Ed25519,
    /// X25519, secp256k1, and RSA.
    /// </para>
    /// </remarks>
    public static void Initialize()
    {
        Initialize(customResolver: null);
    }


    /// <summary>
    /// Initializes the registry with a custom resolver that falls back to defaults.
    /// </summary>
    /// <param name="customResolver">
    /// Custom resolver for additional algorithms. Throw <see cref="ArgumentException"/>
    /// to fall back to default mappings. Pass <see langword="null"/> to use only defaults.
    /// </param>
    /// <remarks>
    /// <para>
    /// The resolution order is:
    /// </para>
    /// <list type="number">
    /// <item><description>Custom resolver (if provided and returns non-empty result).</description></item>
    /// <item><description>Default mappings for standard algorithms.</description></item>
    /// <item><description>Throws <see cref="ArgumentException"/> if no mapping found.</description></item>
    /// </list>
    /// </remarks>
    public static void Initialize(MulticodecHeaderResolverDelegate? customResolver)
    {
        Resolver = algorithm =>
        {
            //Try custom resolver first if provided.
            if(customResolver is not null)
            {
                try
                {
                    var result = customResolver(algorithm);
                    if(result.Length > 0)
                    {
                        return result;
                    }
                }
                catch(ArgumentException)
                {
                    //Fall through to defaults.
                }
            }

            //Default mappings.
            return ResolveDefault(algorithm);
        };
    }


    /// <summary>
    /// Resolves the multicodec header for the specified algorithm.
    /// </summary>
    /// <param name="algorithm">The cryptographic algorithm.</param>
    /// <returns>The multicodec header bytes.</returns>
    /// <exception cref="InvalidOperationException">Thrown if the registry is not initialized.</exception>
    /// <exception cref="ArgumentException">Thrown if no header is registered for the algorithm.</exception>
    public static ReadOnlySpan<byte> Resolve(CryptoAlgorithm algorithm)
    {
        if(Resolver is null)
        {
            throw new InvalidOperationException(
                $"{nameof(MulticodecHeaderRegistry)} has not been initialized. " +
                $"Call {nameof(Initialize)} during application startup.");
        }

        return Resolver(algorithm).Span;
    }


    /// <summary>
    /// Attempts to resolve the multicodec header for the specified algorithm.
    /// </summary>
    /// <param name="algorithm">The cryptographic algorithm.</param>
    /// <param name="header">When successful, contains the multicodec header bytes.</param>
    /// <returns><see langword="true"/> if the header was resolved; otherwise <see langword="false"/>.</returns>
    public static bool TryResolve(CryptoAlgorithm algorithm, out ReadOnlyMemory<byte> header)
    {
        if(Resolver is null)
        {
            header = default;
            return false;
        }

        try
        {
            header = Resolver(algorithm);
            return true;
        }
        catch(ArgumentException)
        {
            header = default;
            return false;
        }
    }


    /// <summary>
    /// Gets whether the registry has been initialized.
    /// </summary>
    public static bool IsInitialized
    {
        get => Resolver is not null;
    }


    /// <summary>
    /// Resolves the default multicodec header for standard algorithms.
    /// </summary>
    /// <param name="algorithm">The cryptographic algorithm.</param>
    /// <returns>The multicodec header bytes.</returns>
    /// <exception cref="ArgumentException">Thrown if the algorithm is not in the default set.</exception>
    /// <remarks>
    /// <para>
    /// This method provides direct access to the default mappings without requiring
    /// the registry to be initialized. Useful for custom resolvers that want to
    /// explicitly delegate to defaults for specific algorithms.
    /// </para>
    /// </remarks>
    public static ReadOnlyMemory<byte> ResolveDefault(CryptoAlgorithm algorithm)
    {
        return algorithm switch
        {
            _ when algorithm.Equals(CryptoAlgorithm.Secp256k1) => MulticodecHeaders.Secp256k1PublicKey.ToArray(),
            _ when algorithm.Equals(CryptoAlgorithm.Ed25519) => MulticodecHeaders.Ed25519PublicKey.ToArray(),
            _ when algorithm.Equals(CryptoAlgorithm.P256) => MulticodecHeaders.P256PublicKey.ToArray(),
            _ when algorithm.Equals(CryptoAlgorithm.P384) => MulticodecHeaders.P384PublicKey.ToArray(),
            _ when algorithm.Equals(CryptoAlgorithm.P521) => MulticodecHeaders.P521PublicKey.ToArray(),
            _ when algorithm.Equals(CryptoAlgorithm.X25519) => MulticodecHeaders.X25519PublicKey.ToArray(),
            _ when algorithm.Equals(CryptoAlgorithm.Rsa2048) => MulticodecHeaders.RsaPublicKey.ToArray(),
            _ when algorithm.Equals(CryptoAlgorithm.Rsa4096) => MulticodecHeaders.RsaPublicKey.ToArray(),
            _ => throw new ArgumentException($"No multicodec header registered for algorithm '{algorithm}'.")
        };
    }
}