namespace Verifiable.Cryptography;

/// <summary>
/// Delegate that selects an encoder based on a given key format type.
/// </summary>
/// <param name="keyFormatType">The type representing the key format (e.g., <c>typeof(Base64Url)</c>).</param>
/// <returns>An encoding delegate for the specified format.</returns>
public delegate EncodeDelegate EncoderSelector(Type keyFormatType);


/// <summary>
/// Delegate that selects a decoder based on a given key format type.
/// </summary>
/// <param name="keyFormatType">The type representing the key format (e.g., <c>typeof(Base64Url)</c>).</param>
/// <returns>A decoding delegate for the specified format.</returns>
public delegate DecodeDelegate DecoderSelector(Type keyFormatType);


/// <summary>
/// Provides format-specific encoder and decoder selection for cryptographic key material.
/// </summary>
/// <remarks>
/// <para>
/// Cryptographic keys can be represented in various formats (Base64, Base64Url, Base58, Hex,
/// Multibase, etc.). This class provides a central mechanism for selecting the appropriate
/// encoder or decoder based on the target format.
/// </para>
///
/// <para>
/// <strong>Architecture context.</strong>
/// </para>
/// <code>
/// +------------------------------------------------------------------+
/// |                    Key Format Layer                              |
/// |  (JWK, DID Document, X.509, COSE_Key, etc.)                      |
/// +-----------------------------+------------------------------------+
///                               |
///                               | Needs to encode/decode key bytes
///                               v
/// +------------------------------------------------------------------+
/// |                   DefaultCoderSelector                           |
/// |                                                                  |
/// |   SelectEncoder(typeof(Base64Url)) --> EncodeDelegate            |
/// |   SelectDecoder(typeof(Base64Url)) --> DecodeDelegate            |
/// +-----------------------------+------------------------------------+
///                               |
///                               v
/// +---------------+---------------+---------------+---------------+
/// |   Base64Url   |    Base58     |   Multibase   |     Hex       |
/// |   Encoder     |    Encoder    |    Encoder    |    Encoder    |
/// +---------------+---------------+---------------+---------------+
/// </code>
///
/// <para>
/// <strong>Relationship to other registries.</strong>
/// While <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> handles
/// signing and verification, and <see cref="CryptographicKeyFactory"/> holds entropy
/// and digest delegates, this class handles format transformations only. They are
/// independent but complementary: a caller might decode a Base64Url-encoded key,
/// then use the registries to sign data with it.
/// </para>
///
/// <para>
/// <strong>Hashing has moved.</strong> Earlier versions of this class also held a
/// <c>DefaultHashFunctionSelector</c> exposing a <c>HashFunction</c> delegate
/// (<c>byte[] → byte[]</c>). That surface has been deleted. Hashing now flows
/// through <see cref="DigestValue.Compute"/> with a span-based, pool-aware
/// <see cref="HashFunctionDelegate"/>; the operation-level entry point with
/// telemetry, CBOM stamping, and event emission is
/// <see cref="ComputeDigestDelegate"/>, registered by delegate type on
/// <see cref="CryptographicKeyFactory"/>. Callers that previously called
/// <c>DefaultHashFunctionSelector.Select(...)</c> directly should accept a
/// <see cref="ComputeDigestDelegate"/> as a parameter from above instead of
/// reaching into a global selector.
/// </para>
///
/// <para>
/// <strong>Initialization.</strong>
/// </para>
/// <para>
/// Initialize using <see cref="CryptoLibrary.InitializeProviders"/> before first use.
/// If not initialized, accessing the selectors throws <see cref="InvalidOperationException"/>.
/// </para>
/// <code>
/// CryptoLibrary.InitializeProviders(
///     encoderSelector: format => format switch
///     {
///         var t when t == typeof(Base64Url) => Base64UrlEncode,
///         var t when t == typeof(Base58Btc) => Base58BtcEncode,
///         _ => throw new NotSupportedException($"Format {format} not supported.")
///     },
///     decoderSelector: format => ...);
/// </code>
/// </remarks>
public static class DefaultCoderSelector
{
    /// <summary>
    /// Gets or sets the delegate that selects an encoder based on key format type.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This property must be initialized via <see cref="CryptoLibrary.InitializeProviders"/>
    /// before use. The default implementation throws <see cref="InvalidOperationException"/>.
    /// </para>
    /// </remarks>
    public static EncoderSelector SelectEncoder { get; set; } = (Type keyFormatType) =>
    {
        throw new InvalidOperationException(
            $"The {nameof(SelectEncoder)} delegate has not been initialized. " +
            $"Call {nameof(CryptoLibrary)}.{nameof(CryptoLibrary.InitializeProviders)}() during application startup.");
    };


    /// <summary>
    /// Gets or sets the delegate that selects a decoder based on key format type.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This property must be initialized via <see cref="CryptoLibrary.InitializeProviders"/>
    /// before use. The default implementation throws <see cref="InvalidOperationException"/>.
    /// </para>
    /// </remarks>
    public static DecoderSelector SelectDecoder { get; set; } = (Type keyFormatType) =>
    {
        throw new InvalidOperationException(
            $"The {nameof(SelectDecoder)} delegate has not been initialized. " +
            $"Call {nameof(CryptoLibrary)}.{nameof(CryptoLibrary.InitializeProviders)}() during application startup.");
    };
}


/// <summary>
/// Initialization point for the format-encoder/decoder selectors.
/// </summary>
/// <remarks>
/// <para>
/// Call <see cref="InitializeProviders"/> early in application startup, before any
/// code path that needs encoder or decoder selection runs.
/// </para>
///
/// <para>
/// <strong>Initialization order.</strong>
/// </para>
/// <para>
/// When setting up the library, initialize in this order:
/// </para>
/// <code>
/// // 1. Format encoders and decoders.
/// CryptoLibrary.InitializeProviders(encoderSelector, decoderSelector);
///
/// // 2. Signing and verification registry.
/// CryptoFunctionRegistry&lt;CryptoAlgorithm, Purpose&gt;.Initialize(signingMatcher, verificationMatcher);
///
/// // 3. Entropy and digest delegates registered by delegate type.
/// CryptographicKeyFactory.RegisterFunction(typeof(GenerateNonceDelegate), MicrosoftEntropyFunctions.GenerateNonce);
/// CryptographicKeyFactory.RegisterFunction(typeof(GenerateSaltDelegate),  MicrosoftEntropyFunctions.GenerateSalt);
/// CryptographicKeyFactory.RegisterFunction(typeof(ComputeDigestDelegate), MicrosoftEntropyFunctions.ComputeDigest);
///
/// // 4. Key agreement registry, where used.
/// KeyAgreementFunctionRegistry&lt;CryptoAlgorithm, Purpose&gt;.Initialize(...);
/// </code>
/// </remarks>
public static class CryptoLibrary
{
    /// <summary>
    /// Initializes the format-encoder/decoder selectors.
    /// </summary>
    /// <param name="encoderSelector">A delegate that selects encoders based on key format type.</param>
    /// <param name="decoderSelector">A delegate that selects decoders based on key format type.</param>
    /// <remarks>
    /// <para>
    /// This method is not thread-safe. Call it only during application startup before
    /// concurrent access begins.
    /// </para>
    /// <para>
    /// Earlier versions accepted a third <c>hashFunctionSelector</c> parameter wiring a
    /// global <c>HashFunction</c> delegate (<c>byte[] → byte[]</c>). That surface has been
    /// deleted; hashing flows through
    /// <see cref="CryptographicKeyFactory"/>-registered
    /// <see cref="ComputeDigestDelegate"/> instances, threaded down from the high layer
    /// that resolves them.
    /// </para>
    /// </remarks>
    public static void InitializeProviders(
        EncoderSelector encoderSelector,
        DecoderSelector decoderSelector)
    {
        ArgumentNullException.ThrowIfNull(encoderSelector);
        ArgumentNullException.ThrowIfNull(decoderSelector);

        DefaultCoderSelector.SelectEncoder = encoderSelector;
        DefaultCoderSelector.SelectDecoder = decoderSelector;
    }
}
