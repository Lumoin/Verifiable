using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Deletes whatever TPM-sealed snapshot blob bytes are stored for <paramref name="runId"/>, so a later
/// <see cref="TryFetchSealedSnapshotBlobAsyncDelegate"/> call observes nothing stored — the caller-supplied
/// I/O half of <see cref="TpmSealedStateCustody"/>'s wipe step (contract R-7, R-1: the next
/// rehydrate-without-snapshot IS the factory image).
/// </summary>
/// <param name="runId">
/// The stable identifier of the authenticator instance whose sealed blob should be deleted — the explicit
/// per-call context parameter this delegate takes instead of closing over any caller state (contract R-3,
/// house rule: no closure capture).
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <remarks>
/// Implementations SHOULD treat deleting an already-absent entry as a no-op rather than throwing, mirroring
/// <see cref="WipeSnapshotAsyncDelegate"/>'s identical contract.
/// </remarks>
public delegate ValueTask DeleteSealedSnapshotBlobAsyncDelegate(string runId, CancellationToken cancellationToken);
