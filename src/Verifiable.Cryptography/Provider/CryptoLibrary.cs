using System.Diagnostics;

namespace Verifiable.Cryptography.Provider;

/// <summary>
/// Identifies the underlying cryptographic library that performed the actual
/// cryptographic work — distinct from the provider abstraction layer.
/// </summary>
/// <remarks>
/// <para>
/// This is the library that matters most for CBOM purposes. Examples:
/// </para>
/// <list type="bullet">
///   <item>
///     <description>
///       <c>System.Security.Cryptography</c> — .NET platform crypto. Its version
///       equals the .NET runtime version.
///     </description>
///   </item>
///   <item>
///     <description>
///       <c>Org.BouncyCastle.Cryptography</c> — independently versioned NuGet package.
///     </description>
///   </item>
///   <item>
///     <description>
///       <c>libsodium</c> — native library wrapped by NSec; version reflects the
///       native binary.
///     </description>
///   </item>
///   <item>
///     <description>
///       <c>TPM 2.0</c> — firmware-level entropy; version reflects TPM firmware.
///     </description>
///   </item>
/// </list>
/// <para>
/// Populated as a static field in each backend so the assembly version is resolved
/// once at class initialization — AOT-safe and zero-cost at operation time.
/// </para>
/// </remarks>
[DebuggerDisplay("CryptoLibrary {Name} {Version}")]
public sealed record CryptoLibrary(string Name, string Version);
