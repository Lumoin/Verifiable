using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Persists a CTAP authenticator state-custody snapshot for <paramref name="runId"/> to whatever backend a
/// <see cref="CtapStateCustody"/> bundle composes, overwriting whatever was previously persisted for the
/// same identifier.
/// </summary>
/// <param name="runId">
/// The stable identifier of the authenticator instance this snapshot belongs to — the explicit per-call
/// context parameter this delegate takes instead of closing over any caller state (contract R-3, house
/// rule: no closure capture).
/// </param>
/// <param name="snapshot">
/// The encoded snapshot bytes, already copied into an independent pooled carrier at the custody seam's
/// boundary (contract R-3) — never a live reference into a <see cref="Automata.CtapAuthenticatorState"/>
/// record's own owned memory. Ownership stays with the caller: an implementation that must retain the
/// bytes beyond this call copies what it needs, mirroring <see cref="PersistVerifiedMetadataBlobAsyncDelegate"/>'s
/// identical ownership contract.
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <remarks>
/// Contract R-4 (persist-then-respond): <see cref="Automata.CtapAuthenticatorSimulator"/> awaits this
/// delegate to completion after every command that changed the persistent subset, BEFORE framing that
/// command's response — a crash between this call starting and completing must also lose the response,
/// so a relying party can never observe a wire-visible consequence (for example, an incremented
/// <c>signCount</c>) that custody has not durably recorded.
/// </remarks>
public delegate ValueTask PersistSnapshotAsyncDelegate(string runId, PooledMemory snapshot, CancellationToken cancellationToken);
