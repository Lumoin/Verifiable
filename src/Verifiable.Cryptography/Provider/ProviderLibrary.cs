using System.Diagnostics;

namespace Verifiable.Cryptography.Provider;

/// <summary>
/// Identifies the provider library that created a cryptographic value — the
/// abstraction layer within the Verifiable library family.
/// </summary>
/// <remarks>
/// Examples: <c>Verifiable.Microsoft</c>, <c>Verifiable.BouncyCastle</c>.
/// Used as a <see cref="Verifiable.Cryptography.Tag"/> key so that any code
/// holding a <see cref="Verifiable.Cryptography.SensitiveMemory"/> instance
/// can retrieve the full provenance chain without an event subscription.
/// </remarks>
[DebuggerDisplay("ProviderLibrary {Name} {Version}")]
public sealed record ProviderLibrary(string Name, string Version);
