using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Resolves the Verifier's JAR signing public key from a parsed
/// <see cref="VerifierAttestationJwt"/> extracted from the JAR's <c>jwt</c> JOSE header.
/// </summary>
/// <remarks>
/// <para>
/// Implementations must:
/// </para>
/// <list type="number">
///   <item><description>
///     Verify the attestation JWT's signature against the trust anchor's published key.
///   </description></item>
///   <item><description>
///     Verify that the <c>sub</c> claim equals the expected Client Identifier (the part
///     of <c>client_id</c> after the <c>verifier_attestation:</c> prefix).
///   </description></item>
///   <item><description>
///     Extract and return the public key from the <c>cnf</c> claim. This key is then
///     used by the Wallet to verify the JAR signature.
///   </description></item>
/// </list>
/// <para>
/// The delegate must throw <see cref="System.Security.SecurityException"/> or
/// <see cref="InvalidOperationException"/> if the attestation is invalid, expired,
/// or not trusted. It must never return <see langword="null"/>.
/// </para>
/// </remarks>
/// <param name="attestation">The Verifier Attestation JWT from the JAR header.</param>
/// <param name="expectedClientId">
/// The Client Identifier value (without the prefix) that the attestation's <c>sub</c>
/// claim must equal.
/// </param>
/// <param name="pool">Memory pool for key material allocations.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The Verifier's JAR signing public key extracted from the attestation's <c>cnf</c>
/// claim. The caller owns the returned <see cref="PublicKeyMemory"/> and must dispose it.
/// </returns>
public delegate ValueTask<PublicKeyMemory> ResolveKeyFromVerifierAttestationDelegate(
    VerifierAttestationJwt attestation,
    string expectedClientId,
    MemoryPool<byte> pool,
    CancellationToken cancellationToken);
