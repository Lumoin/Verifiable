using System.Diagnostics;

namespace Verifiable.Cryptography.Provider;

/// <summary>
/// Identifies the class within the provider library that performed the operation.
/// </summary>
/// <remarks>
/// Examples: <c>MicrosoftEntropyFunctions</c>, <c>BouncyCastleEntropyFunctions</c>.
/// </remarks>
[DebuggerDisplay("ProviderClass {Name}")]
public sealed record ProviderClass(string Name);
