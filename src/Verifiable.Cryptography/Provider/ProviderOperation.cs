using System.Diagnostics;

namespace Verifiable.Cryptography.Provider;

/// <summary>
/// Identifies the specific method that was called to produce the cryptographic value.
/// </summary>
/// <remarks>
/// Examples: <c>GenerateNonce</c>, <c>GenerateSalt</c>, <c>ComputeDigest</c>.
/// </remarks>
[DebuggerDisplay("ProviderOperation {Name}")]
public sealed record ProviderOperation(string Name);
