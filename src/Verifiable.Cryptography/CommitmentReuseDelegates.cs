using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Cryptography;

/// <summary>
/// Asks the application whether a commitment has been seen before — the lookup half of the
/// reuse-detection seam.
/// </summary>
/// <remarks>
/// <para>
/// Modelled on the DPoP-JTI replay seam: the library stays stateless and the application owns the
/// store, its keying, and its scope (process-local, per-tenant, distributed — the library does not
/// care). It is context-neutral: it takes only the commitment, never an OAuth or protocol type, so any
/// caller can wire it.
/// </para>
/// <para>
/// The argument is a <see cref="DigestValue"/> commitment, not the raw value, so the store never holds
/// the value itself. A <see cref="Salt"/> commitment (<see cref="Salt.ComputeCommitment"/>) is one kind
/// of committed value; a JTI, a nonce, or a key thumbprint is another. A return of <see langword="true"/>
/// means a value with this commitment was recorded earlier — i.e. a reuse.
/// </para>
/// </remarks>
/// <param name="commitment">The privacy-preserving commitment to the value under test.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns><see langword="true"/> if a value with this commitment was seen before; otherwise <see langword="false"/>.</returns>
public delegate ValueTask<bool> IsCommitmentSeenDelegate(DigestValue commitment, CancellationToken cancellationToken);


/// <summary>
/// Records that a commitment has now been seen — the persistence half of the reuse-detection seam.
/// See <see cref="IsCommitmentSeenDelegate"/> for the seam's shape and rationale.
/// </summary>
/// <param name="commitment">The commitment to record as seen.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask RecordCommitmentDelegate(DigestValue commitment, CancellationToken cancellationToken);
