using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Deletes whatever CTAP authenticator state-custody snapshot is persisted for <paramref name="runId"/>,
/// so a later <see cref="TryLoadSnapshotAsyncDelegate"/> call observes "no snapshot" (contract R-1: the
/// next rehydrate-without-snapshot IS the factory image).
/// </summary>
/// <param name="runId">
/// The stable identifier of the authenticator instance whose snapshot should be wiped — the explicit
/// per-call context parameter this delegate takes instead of closing over any caller state (contract R-3,
/// house rule: no closure capture).
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <remarks>
/// Contract R-4: <see cref="Automata.CtapAuthenticatorSimulator"/> drives this delegate — never
/// <see cref="PersistSnapshotAsyncDelegate"/> — for <c>authenticatorReset</c>'s own custody consequence
/// (wipe-only); every state change that follows a reset persists as usual again. Implementations SHOULD
/// treat wiping an already-absent snapshot as a no-op rather than throwing.
/// </remarks>
public delegate ValueTask WipeSnapshotAsyncDelegate(string runId, CancellationToken cancellationToken);
