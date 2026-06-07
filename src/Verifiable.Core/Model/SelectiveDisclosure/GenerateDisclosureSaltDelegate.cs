namespace Verifiable.Cryptography;

/// <summary>
/// Generates a freshly-allocated <see cref="Salt"/> for use as the salt of a
/// selective-disclosure element.
/// </summary>
/// <remarks>
/// <para>
/// The application supplies an implementation that:
/// </para>
/// <list type="bullet">
/// <item><description>Allocates from a pool the application controls.</description></item>
/// <item><description>Fills the salt with cryptographically secure random bytes
/// of an application-chosen length (RFC 9901 §4.2.2 requires at least 128 bits).</description></item>
/// <item><description>Stamps the resulting <see cref="Salt"/>'s
/// <see cref="SensitiveData.Tag"/> with the appropriate
/// <c>Purpose</c>, <c>ProviderLibrary</c>, <c>CryptoLibrary</c>,
/// <c>ProviderClass</c>, and <c>ProviderOperation</c> entries for CBOM provenance.</description></item>
/// <item><description>Optionally starts an OTel <see cref="System.Diagnostics.Activity"/>
/// to bracket the salt's operational lifetime.</description></item>
/// </list>
/// <para>
/// Each call returns a new <see cref="Salt"/> instance. The selective-disclosure
/// pipeline takes ownership of the returned salt and disposes it via the owning
/// disclosure when the disclosure is disposed.
/// </para>
/// <para>
/// Both test and production wiring bind to the application's entropy backend (e.g.,
/// <c>MicrosoftEntropyFunctions.GenerateSalt</c> or
/// <c>BouncyCastleEntropyFunctions.GenerateSalt</c>), which records CBOM provenance and
/// entropy-tracking events; there is no convenience that fills from the OS CSPRNG directly.
/// </para>
/// </remarks>
/// <returns>A freshly-allocated <see cref="Salt"/>.</returns>
public delegate Salt GenerateDisclosureSaltDelegate();
