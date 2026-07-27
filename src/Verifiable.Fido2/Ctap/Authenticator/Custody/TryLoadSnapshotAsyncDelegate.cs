using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Attempts to load a previously persisted CTAP authenticator state-custody snapshot for
/// <paramref name="runId"/> from whatever backend a <see cref="CtapStateCustody"/> bundle composes.
/// </summary>
/// <param name="runId">
/// The stable identifier of the authenticator instance to load a snapshot for — the SAME value passed as
/// <c>runId</c> to <see cref="Automata.CtapAuthenticatorSimulator"/>'s construction, and the explicit
/// per-call context parameter this delegate takes instead of closing over any caller state (contract
/// R-3, house rule: no closure capture).
/// </param>
/// <param name="pool">The memory pool the returned snapshot bytes carrier rents from.</param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The persisted snapshot bytes, copied into a pooled carrier the caller owns and must dispose, or
/// <see langword="null"/> when no snapshot has ever been persisted for <paramref name="runId"/> — contract
/// R-1: "No snapshot present ⇒ Initial (first boot)."
/// </returns>
/// <remarks>
/// A backend-neutral seam: any store (a file, a database row, an in-memory dictionary, or — package C's
/// TPM-backed adapter — a sealed TPM object) may implement this delegate. Implementations SHOULD treat a
/// missing/never-written entry as the ordinary "first boot" case above rather than throwing; a genuine
/// I/O failure should still propagate as an exception, distinct from "nothing was ever persisted."
/// </remarks>
public delegate ValueTask<PooledMemory?> TryLoadSnapshotAsyncDelegate(string runId, MemoryPool<byte> pool, CancellationToken cancellationToken);
