namespace Verifiable.Core.Model.DataIntegrity;

/// <summary>
/// Factory delegate for resolving cryptosuite names to <see cref="CryptosuiteInfo"/> instances.
/// </summary>
/// <param name="cryptosuiteName">The cryptosuite identifier from the proof's <c>cryptosuite</c> property.</param>
/// <returns>The corresponding <see cref="CryptosuiteInfo"/> instance.</returns>
/// <remarks>
/// <para>
/// Implementations should return an <see cref="UnknownCryptosuiteInfo"/> for unrecognized
/// cryptosuite names rather than throwing, enabling the parse-as-far-as-possible pattern.
/// </para>
/// </remarks>
public delegate CryptosuiteInfo CryptosuiteInfoFactoryDelegate(string cryptosuiteName);


/// <summary>
/// Provides the default factory for resolving cryptosuite names to instances.
/// </summary>
/// <remarks>
/// <para>
/// The default factory uses <see cref="CryptosuiteInfo.FromName"/> to resolve
/// cryptosuite names. For unknown cryptosuites, it returns an <see cref="UnknownCryptosuiteInfo"/>
/// to enable round-tripping of documents with unsupported cryptosuites.
/// </para>
/// <para>
/// <strong>Extending with Custom Cryptosuites:</strong>
/// </para>
/// <para>
/// To support additional cryptosuites, create a custom factory that chains
/// to <see cref="CryptosuiteInfo.FromName"/> for known types:
/// </para>
/// <code>
/// CryptosuiteInfoFactoryDelegate customFactory = name =>
///     name == CryptosuiteInfo.MyCustomSuite.CryptosuiteName
///         ? CryptosuiteInfo.MyCustomSuite
///         : CryptosuiteInfo.FromName(name);
///
/// var options = new JsonSerializerOptions();
/// options.Converters.Add(new DataIntegrityProofConverter(customFactory));
/// </code>
/// </remarks>
public static class CryptosuiteInfoFactory
{
    /// <summary>
    /// The default factory that resolves cryptosuite names using <see cref="CryptosuiteInfo.FromName"/>.
    /// </summary>
    public static CryptosuiteInfoFactoryDelegate Default { get; } = CryptosuiteInfo.FromName;
}