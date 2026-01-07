namespace Verifiable.Core.Model.Proofs;

/// <summary>
/// Provides extension accessors for discovering available cryptosuite types.
/// </summary>
/// <remarks>
/// <para>
/// This extension class allows accessing cryptosuite instances using a clean, discoverable
/// syntax directly on the <see cref="CryptosuiteInfo"/> type. Instead of accessing instances
/// through their concrete class names, users can access them through the base type with
/// IntelliSense support.
/// </para>
/// <para>
/// <strong>Usage:</strong>
/// </para>
/// <code>
/// //Instead of: EddsaRdfc2022CryptosuiteInfo.Instance
/// var eddsaSuite = CryptosuiteInfo.EddsaRdfc2022;
///
/// //Instead of: EddsaJcs2022CryptosuiteInfo.Instance
/// var jcsSuite = CryptosuiteInfo.EddsaJcs2022;
///
/// //Resolve by name at runtime.
/// var suite = CryptosuiteInfo.FromName("eddsa-rdfc-2022");
/// </code>
/// <para>
/// <strong>Extensibility:</strong>
/// </para>
/// <para>
/// Library users can define their own cryptosuite extensions following the same pattern.
/// This enables custom cryptosuites to appear alongside the library-provided ones in
/// IntelliSense, providing a consistent and discoverable API.
/// </para>
/// <code>
/// //In user's code, define the cryptosuite info class:
/// public sealed class MyCustomCryptosuiteInfo: CryptosuiteInfo
/// {
///     public static MyCustomCryptosuiteInfo Instance { get; } = new()
///     {
///         CryptosuiteName = "my-custom-suite-2024",
///         Canonicalization = CanonicalizationAlgorithm.Jcs,
///         HashAlgorithm = "SHA-256",
///         SignatureAlgorithm = CryptoAlgorithm.P256,
///         Contexts = new[] { "https://example.org/my-suite/v1" }.AsReadOnly(),
///         IsCompatibleWith = vm => vm.TypeName == "JsonWebKey2020"
///     };
/// }
///
/// //Then add the extension:
/// public static class MyCustomCryptosuiteExtensions
/// {
///     extension(CryptosuiteInfo)
///     {
///         public static MyCustomCryptosuiteInfo MyCustomSuite => MyCustomCryptosuiteInfo.Instance;
///     }
/// }
///
/// //For deserialization, provide a custom factory to the converter:
/// var converter = new DataIntegrityProofConverter(name =>
///     name == CryptosuiteInfo.MyCustomSuite.CryptosuiteName
///         ? CryptosuiteInfo.MyCustomSuite
///         : CryptosuiteInfo.FromName(name));
/// </code>
/// <para>
/// After defining such an extension, <c>CryptosuiteInfo.MyCustomSuite</c> becomes available
/// alongside the library-provided cryptosuites, maintaining consistency in the API and
/// enabling discovery through IntelliSense.
/// </para>
/// <para>
/// This pattern provides discoverability through IntelliSense while maintaining type safety
/// and allowing seamless integration of custom cryptosuite types without modifying library code.
/// </para>
/// </remarks>
public static class CryptosuiteInfoExtensions
{
    extension(CryptosuiteInfo)
    {
        /// <summary>
        /// EdDSA cryptosuite using Ed25519 signatures with RDFC-1.0 canonicalization.
        /// See <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-rdfc-2022">EdDSA Cryptosuites §3.1</see>.
        /// </summary>
        public static EddsaRdfc2022CryptosuiteInfo EddsaRdfc2022 => EddsaRdfc2022CryptosuiteInfo.Instance;

        /// <summary>
        /// EdDSA cryptosuite using Ed25519 signatures with JCS canonicalization.
        /// See <see href="https://www.w3.org/TR/vc-di-eddsa/#eddsa-jcs-2022">EdDSA Cryptosuites §3.2</see>.
        /// </summary>
        public static EddsaJcs2022CryptosuiteInfo EddsaJcs2022 => EddsaJcs2022CryptosuiteInfo.Instance;

        /// <summary>
        /// Resolves a cryptosuite name to its corresponding <see cref="CryptosuiteInfo"/> instance.
        /// </summary>
        /// <param name="cryptosuiteName">The cryptosuite identifier from a proof's <c>cryptosuite</c> property.</param>
        /// <returns>
        /// The corresponding <see cref="CryptosuiteInfo"/> singleton for known cryptosuites,
        /// or an <see cref="UnknownCryptosuiteInfo"/> instance for unrecognized names.
        /// </returns>
        /// <remarks>
        /// <para>
        /// This method enables runtime resolution of cryptosuite names to their metadata.
        /// It supports the parse-as-far-as-possible pattern by returning an
        /// <see cref="UnknownCryptosuiteInfo"/> for unrecognized cryptosuites rather than throwing.
        /// </para>
        /// <para>
        /// For custom cryptosuites, provide a factory delegate to
        /// <see cref="Serialization.Json.DataIntegrityProofConverter"/> that chains to this method:
        /// </para>
        /// <code>
        /// var converter = new DataIntegrityProofConverter(name =>
        ///     name == CryptosuiteInfo.MyCustomSuite.CryptosuiteName
        ///         ? CryptosuiteInfo.MyCustomSuite
        ///         : CryptosuiteInfo.FromName(name));
        /// </code>
        /// </remarks>
        public static CryptosuiteInfo FromName(string cryptosuiteName) => cryptosuiteName switch
        {
            var n when n == EddsaRdfc2022CryptosuiteInfo.Instance.CryptosuiteName => EddsaRdfc2022CryptosuiteInfo.Instance,
            var n when n == EddsaJcs2022CryptosuiteInfo.Instance.CryptosuiteName => EddsaJcs2022CryptosuiteInfo.Instance,
            _ => new UnknownCryptosuiteInfo(cryptosuiteName)
        };
    }
}