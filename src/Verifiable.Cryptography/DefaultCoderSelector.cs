using System.Security.Cryptography;

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
/// <strong>Architecture Context</strong>
/// </para>
/// <code>
/// +------------------------------------------------------------------+
/// |                    Key Format Layer                              |
/// |  (JWK, DID Document, X.509, COSE_Key, etc.)                     |
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
/// <strong>Relationship to CryptoFunctionRegistry</strong>
/// </para>
/// <para>
/// While <see cref="CryptoFunctionRegistry{TDiscriminator1, TDiscriminator2}"/> handles
/// cryptographic operations (signing, verification), this class handles format transformations.
/// They are independent but complementary: you might decode a Base64Url-encoded key, then
/// use the registry to sign data with it.
/// </para>
///
/// <para>
/// <strong>Initialization</strong>
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
///     decoderSelector: format => ...,
///     hashFunctionSelector: algorithm => ...
/// );
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
/// Delegate that computes a cryptographic hash of the input data.
/// </summary>
/// <param name="input">The data to hash.</param>
/// <returns>The hash digest.</returns>
public delegate byte[] HashFunction(byte[] input);


/// <summary>
/// Delegate that selects a hash function based on algorithm name.
/// </summary>
/// <param name="hashAlgorithm">The hash algorithm to use.</param>
/// <returns>A hash function for the specified algorithm.</returns>
public delegate HashFunction HashFunctionSelector(HashAlgorithmName hashAlgorithm);


/// <summary>
/// Provides hash function selection based on algorithm name.
/// </summary>
/// <remarks>
/// <para>
/// This class follows the same pattern as <see cref="DefaultCoderSelector"/> but for
/// hash functions. It provides a default implementation for SHA-256 but can be extended
/// via <see cref="CryptoLibrary.InitializeProviders"/> to support additional algorithms.
/// </para>
/// </remarks>
public static class DefaultHashFunctionSelector
{
    /// <summary>
    /// Gets or sets the delegate that selects a hash function based on algorithm.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The default implementation supports SHA-256. Override via
    /// <see cref="CryptoLibrary.InitializeProviders"/> to add support for other algorithms.
    /// </para>
    /// </remarks>
    public static HashFunctionSelector Select { get; set; } = (HashAlgorithmName hashAlgorithm) =>
    {
        if(hashAlgorithm.Equals(HashAlgorithmName.SHA256))
        {
            return SHA256.HashData;
        }

        throw new ArgumentException($"No hash function available for algorithm: {hashAlgorithm}.");
    };
}


/// <summary>
/// Initialization point for cryptographic providers used throughout the library.
/// </summary>
/// <remarks>
/// <para>
/// This class serves as the central initialization point for all selector-based
/// cryptographic infrastructure. Call <see cref="InitializeProviders"/> early in
/// application startup, before any cryptographic operations are performed.
/// </para>
///
/// <para>
/// <strong>Initialization Order</strong>
/// </para>
/// <para>
/// When setting up the library, initialize in this order:
/// </para>
/// <code>
/// // 1. Initialize format encoders/decoders and hash functions
/// CryptoLibrary.InitializeProviders(encoderSelector, decoderSelector, hashSelector);
///
/// // 2. Initialize cryptographic function registry
/// CryptoFunctionRegistry&lt;CryptoAlgorithm, Purpose&gt;.Initialize(signingMatcher, verificationMatcher);
///
/// // 3. Initialize key factory (optional, if using object-oriented key API)
/// CryptographicKeyFactory.Initialize(verificationMapping, signingMapping);
/// </code>
/// </remarks>
public static class CryptoLibrary
{
    /// <summary>
    /// Initializes the cryptographic providers with the specified selectors.
    /// </summary>
    /// <param name="encoderSelector">A delegate that selects encoders based on key format type.</param>
    /// <param name="decoderSelector">A delegate that selects decoders based on key format type.</param>
    /// <param name="hashFunctionSelector">A delegate that selects hash functions based on algorithm.</param>
    /// <remarks>
    /// <para>
    /// This method is not thread-safe. Call it only during application startup before
    /// concurrent access begins.
    /// </para>
    /// </remarks>
    public static void InitializeProviders(
        EncoderSelector encoderSelector,
        DecoderSelector decoderSelector,
        HashFunctionSelector hashFunctionSelector)
    {
        DefaultCoderSelector.SelectEncoder = encoderSelector;
        DefaultCoderSelector.SelectDecoder = decoderSelector;
        DefaultHashFunctionSelector.Select = hashFunctionSelector;
    }
}