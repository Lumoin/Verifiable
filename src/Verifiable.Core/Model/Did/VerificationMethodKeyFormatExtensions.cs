using System;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;

namespace Verifiable.Core.Model.Did
{
    /// <summary>
    /// Defines the contract for selecting the appropriate key format type for a given verification method and public key combination.
    /// This delegate allows customization of how key formats are chosen based on the verification method type and key material.
    /// </summary>
    /// <param name="vmType">
    /// The verification method type information that defines the cryptographic suite and its supported key formats.
    /// This contains metadata about the verification method including its default key format type and any additional
    /// compatible formats.
    /// </param>
    /// <param name="key">
    /// The public key material for which a format type needs to be selected. The key contains algorithm and purpose
    /// metadata through its Tag system, which can be used to make informed format selection decisions.
    /// </param>
    /// <returns>
    /// The <see cref="Type"/> representing the key format that should be used to encode the given public key
    /// for the specified verification method. This must be a type that derives from <see cref="KeyFormat"/>.
    /// </returns>
    /// <remarks>
    /// <para>
    /// This delegate enables flexible key format selection strategies. The default implementation simply returns
    /// the verification method's <see cref="VerificationMethodTypeInfo.DefaultKeyFormatType"/>, but library users
    /// can provide custom logic to select different formats based on:
    /// </para>
    /// <list type="bullet">
    /// <item><description>The specific cryptographic algorithm of the key.</description></item>
    /// <item><description>The intended purpose of the key (signing, key agreement, etc.).</description></item>
    /// <item><description>Application-specific requirements or preferences.</description></item>
    /// <item><description>Interoperability considerations with external systems.</description></item>
    /// </list>
    /// <para>
    /// <strong>Example custom selector:</strong>
    /// </para>
    /// <code>
    /// KeyFormatTypeSelector customSelector = (vmType, key) =>
    /// {
    ///     //Use JWK format for RSA keys regardless of verification method default.
    ///     var algorithm = key.Tag.Get&lt;CryptoAlgorithm&gt;();
    ///     if (algorithm == CryptoAlgorithm.Rsa2048 || algorithm == CryptoAlgorithm.Rsa4096)
    ///     {
    ///         return typeof(PublicKeyJwk);
    ///     }
    ///
    ///     //Use default for all other cases.
    ///     return vmType.DefaultKeyFormatType;
    /// };
    /// </code>
    /// </remarks>
    public delegate Type KeyFormatTypeSelector(VerificationMethodTypeInfo vmType, PublicKeyMemory key);


    /// <summary>
    /// Provides the default key format type selection strategy for verification methods.
    /// This class contains the global default selector that can be customized by library users to change
    /// format selection behavior across the entire application.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class implements the strategy pattern for key format selection, allowing the behavior to be
    /// modified globally without changing individual verification method implementations. The default
    /// strategy simply returns each verification method's configured default format type, but this can
    /// be overridden to implement custom selection logic.
    /// </para>
    /// <para>
    /// <strong>Default Behavior:</strong>
    /// </para>
    /// <para>
    /// The default selector returns <see cref="VerificationMethodTypeInfo.DefaultKeyFormatType"/> for any
    /// given verification method and key combination. This ensures predictable behavior where each
    /// verification method type uses its intended default format.
    /// </para>
    /// <para>
    /// <strong>Customization:</strong>
    /// </para>
    /// <para>
    /// Library users can replace the default selector to implement application-specific logic:
    /// </para>
    /// <code>
    /// //Example: Prefer JWK format for RSA keys regardless of verification method.
    /// VerificationMethodTypeInfoKeyFormatSelector.Default = (vmType, key) =>
    /// {
    ///     //Use JWK format for RSA keys regardless of verification method default.
    ///     var algorithm = key.Tag.Get&lt;CryptoAlgorithm&gt;();
    ///     if (algorithm == CryptoAlgorithm.Rsa2048 || algorithm == CryptoAlgorithm.Rsa4096)
    ///     {
    ///         return typeof(PublicKeyJwk);
    ///     }
    ///
    ///     //Use default for all other cases.
    ///     return vmType.DefaultKeyFormatType;
    /// };
    /// </code>
    /// <para>
    /// <strong>Thread Safety:</strong>
    /// </para>
    /// <para>
    /// The <see cref="Default"/> property is static and should be set once during application initialization.
    /// Changing the selector after initialization may lead to inconsistent behavior if multiple threads
    /// are creating verification methods simultaneously.
    /// </para>
    /// </remarks>
    public static class VerificatioMethodTypeInfoKeyFormatSelector
    {
        /// <summary>
        /// Gets or sets the default key format type selector used throughout the application.
        /// </summary>
        /// <value>
        /// A <see cref="KeyFormatTypeSelector"/> delegate that determines which key format type to use
        /// for a given verification method and key combination. The default implementation returns
        /// the verification method's <see cref="VerificationMethodTypeInfo.DefaultKeyFormatType"/>.
        /// </value>
        /// <remarks>
        /// <para>
        /// This property allows global customization of key format selection behavior. When set,
        /// all calls to <see cref="VerificationMethodTypeInfoExtensions.SelectKeyFormatType"/> will
        /// use the specified selector logic.
        /// </para>
        /// <para>
        /// <strong>Default Behavior:</strong>
        /// </para>
        /// <para>
        /// Returns the <see cref="VerificationMethodTypeInfo.DefaultKeyFormatType"/> for any verification
        /// method, ensuring that each verification method uses its configured default format.
        /// </para>
        /// <para>
        /// <strong>Setting Custom Behavior:</strong>
        /// </para>
        /// <code>
        /// //Set during application startup.
        /// VerificationMethodTypeInfoKeyFormatSelector.Default = (vmType, key) =>
        /// {
        ///     //Custom logic here.
        ///     return someFormatType;
        /// };
        /// </code>
        /// </remarks>
        public static KeyFormatTypeSelector Default { get; set; } = (vmType, key) => vmType.DefaultKeyFormatType;
    }


    /// <summary>
    /// Provides extension methods for <see cref="VerificationMethodTypeInfo"/> that enable key format operations.
    /// These extensions implement the key format selection and creation pipeline, providing a fluent API
    /// for working with verification method types and their associated key formats.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This class bridges the gap between verification method type definitions and the actual creation
    /// of key format instances. It provides two main operations:
    /// </para>
    /// <list type="number">
    /// <item><description>
    /// <strong>Format Type Selection:</strong> Determining which key format type should be used
    /// for a given verification method and key combination using the configurable selection strategy.
    /// </description></item>
    /// <item><description>
    /// <strong>Format Instance Creation:</strong> Creating the actual key format instance with the
    /// encoded key material using the selected format type.
    /// </description></item>
    /// </list>
    /// <para>
    /// <strong>Integration with Builder Pattern:</strong>
    /// </para>
    /// <para>
    /// These extensions are designed to work seamlessly with the library's builder pattern,
    /// particularly in DID document builders where verification methods need to be created
    /// with appropriate key formats. The extensions handle the complexity of format selection
    /// and creation while allowing customization through the selector delegates.
    /// </para>
    /// <para>
    /// <strong>Usage in Builders:</strong>
    /// </para>
    /// <code>
    /// //In a DID builder transformation.
    /// var keyFormat = verificationMethodType.CreateKeyFormat(publicKey);
    /// var verificationMethod = new VerificationMethod
    /// {
    ///     Type = verificationMethodType.TypeName,
    ///     KeyFormat = keyFormat,
    ///     // ... other properties
    /// };
    /// </code>
    /// <para>
    /// <strong>Customization Points:</strong>
    /// </para>
    /// <para>
    /// The behavior of these extensions can be customized by modifying the underlying selector delegates:
    /// </para>
    /// <list type="bullet">
    /// <item><description>
    /// <see cref="VerificationMethodTypeInfoKeyFormatSelector.Default"/> - Controls format type selection.
    /// </description></item>
    /// <item><description>
    /// <see cref="KeyFormatFactory.DefaultKeyFormatCreator"/> - Controls format instance creation.
    /// </description></item>
    /// </list>
    /// </remarks>
    public static class VerificationMethodKeyFormatExtensions
    {
        /// <summary>
        /// Selects the appropriate key format type for the given verification method type and public key.
        /// This method uses the configurable selection strategy to determine which format type should be used.
        /// </summary>
        /// <param name="vmType">
        /// The verification method type information that defines the available key format options.
        /// </param>
        /// <param name="key">
        /// The public key material for which a format type needs to be selected. The key's algorithm
        /// and purpose metadata may influence the selection decision.
        /// </param>
        /// <returns>
        /// The <see cref="Type"/> representing the key format that should be used to encode the given key.
        /// This will be a type that derives from <see cref="KeyFormat"/>.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method delegates to the current <see cref="VerificationMethodTypeInfoKeyFormatSelector.Default"/>
        /// selector, allowing the selection logic to be customized globally. By default, it returns the
        /// verification method's <see cref="VerificationMethodTypeInfo.DefaultKeyFormatType"/>.
        /// </para>
        /// <para>
        /// <strong>Default Behavior:</strong>
        /// </para>
        /// <para>
        /// Returns the default key format type configured for the verification method, ensuring predictable
        /// behavior that follows the verification method's intended design.
        /// </para>
        /// <para>
        /// <strong>Custom Selection:</strong>
        /// </para>
        /// <para>
        /// When custom selection logic is configured via <see cref="VerificationMethodTypeInfoKeyFormatSelector.Default"/>,
        /// this method will apply that logic to determine the most appropriate format type based on the
        /// specific verification method and key characteristics.
        /// </para>
        /// <para>
        /// <strong>Usage:</strong>
        /// </para>
        /// <code>
        /// var formatType = verificationMethodType.SelectKeyFormatType(publicKey);
        /// //FormatType might be typeof(PublicKeyJwk), typeof(PublicKeyMultibase), etc.
        /// </code>
        /// </remarks>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="vmType"/> or <paramref name="key"/> is null.
        /// </exception>
        /// <seealso cref="CreateKeyFormat"/>
        /// <seealso cref="VerificationMethodTypeInfoKeyFormatSelector.Default"/>
        public static Type SelectKeyFormatType(this VerificationMethodTypeInfo vmType, PublicKeyMemory key)
        {
            return VerificatioMethodTypeInfoKeyFormatSelector.Default(vmType, key);
        }


        /// <summary>
        /// Creates a complete key format instance for the given verification method type and public key.
        /// This method combines format type selection and format instance creation into a single operation.
        /// </summary>
        /// <param name="vmType">
        /// The verification method type information that defines how the key should be formatted.
        /// </param>
        /// <param name="key">
        /// The public key material to be encoded into the key format. This includes both the raw
        /// key bytes and associated metadata such as algorithm and purpose information.
        /// </param>
        /// <returns>
        /// A fully configured <see cref="KeyFormat"/> instance containing the encoded key material
        /// in the appropriate format for the verification method type.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method provides a high-level API for creating key formats by combining two operations:
        /// </para>
        /// <list type="number">
        /// <item><description>
        /// <strong>Format Type Selection:</strong> Uses <see cref="SelectKeyFormatType"/> to determine
        /// which key format type should be used based on the verification method and key characteristics.
        /// </description></item>
        /// <item><description>
        /// <strong>Format Instance Creation:</strong> Uses <see cref="KeyFormatFactory.DefaultKeyFormatCreator"/>
        /// to create the actual format instance with the encoded key material.
        /// </description></item>
        /// </list>
        /// <para>
        /// <strong>Format Types:</strong>
        /// </para>
        /// <para>
        /// The returned key format will be one of the supported types such as:
        /// </para>
        /// <list type="bullet">
        /// <item><description><see cref="PublicKeyJwk"/> - JSON Web Key format with Base64Url encoding.</description></item>
        /// <item><description><see cref="PublicKeyMultibase"/> - Multibase format with algorithm-specific encoding.</description></item>
        /// <item><description>Other formats as supported by the verification method type.</description></item>
        /// </list>
        /// <para>
        /// <strong>Algorithm and Purpose Handling:</strong>
        /// </para>
        /// <para>
        /// The method automatically extracts the cryptographic algorithm and purpose information from
        /// the key's metadata and applies the appropriate encoding rules for the selected format type.
        /// This ensures that the resulting format contains all necessary information for key operations.
        /// </para>
        /// <para>
        /// <strong>Usage in DID Builders:</strong>
        /// </para>
        /// <code>
        /// //Create a verification method with appropriate key format.
        /// var verificationMethod = new VerificationMethod
        /// {
        ///     Id = verificationMethodId,
        ///     Type = verificationMethodType.TypeName,
        ///     Controller = controllerId,
        ///     KeyFormat = verificationMethodType.CreateKeyFormat(publicKey)
        /// };
        /// </code>
        /// <para>
        /// <strong>Customization:</strong>
        /// </para>
        /// <para>
        /// The behavior of this method can be customized by modifying the underlying delegates:
        /// </para>
        /// <list type="bullet">
        /// <item><description>
        /// Modify <see cref="VerificationMethodTypeInfoKeyFormatSelector.Default"/> to change format type selection.
        /// </description></item>
        /// <item><description>
        /// Modify <see cref="KeyFormatFactory.DefaultKeyFormatCreator"/> to change format creation logic.
        /// </description></item>
        /// </list>
        /// </remarks>
        /// <exception cref="ArgumentNullException">
        /// Thrown when <paramref name="vmType"/> or <paramref name="key"/> is null.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// Thrown when the selected format type is not supported by the key format creator, or when
        /// the key material is invalid for the selected format type.
        /// </exception>
        /// <exception cref="InvalidOperationException">
        /// Thrown when the format creation process fails due to incompatible algorithm or encoding issues.
        /// </exception>
        /// <seealso cref="SelectKeyFormatType"/>
        /// <seealso cref="KeyFormatFactory.DefaultKeyFormatCreator"/>
        public static KeyFormat CreateKeyFormat(this VerificationMethodTypeInfo vmType, PublicKeyMemory key)
        {
            Type formatType = vmType.SelectKeyFormatType(key);
            return KeyFormatFactory.DefaultKeyFormatCreator(formatType, key);
        }
    }
}
