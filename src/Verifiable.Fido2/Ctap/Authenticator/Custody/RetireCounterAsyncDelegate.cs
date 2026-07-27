using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Retires the counter identified by <paramref name="creationSequence"/>, so a LATER
/// <see cref="EnsureCounterAsyncDelegate"/> call that reuses the same identity (an
/// <c>authenticatorReset</c> restarts the mint-order sequence at zero, so a post-reset credential can
/// collide with a pre-reset one's identity) seeds strictly above every value the retired counter ever held
/// (contract R-9, wavenv).
/// </summary>
/// <param name="creationSequence">
/// The removed credential's own <see cref="Automata.CtapCredentialRecord.CreationSequence"/> value — the
/// SAME identity <see cref="EnsureCounterAsyncDelegate"/> minted the counter under, threaded as an explicit
/// per-call context parameter instead of a closure capture (house rule: no closure capture).
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <remarks>
/// Driven by <see cref="Automata.CtapAuthenticatorSimulator"/> for every credential that disappears from
/// <see cref="Automata.CtapAuthenticatorState.CredentialsByCredentialId"/> across one command — a
/// <c>deleteCredential</c> removal, a same-(rp, account) resident overwrite, or (one call per surviving
/// resident credential) an <c>authenticatorReset</c> factory wipe — never only the explicit
/// <c>credentialManagement</c> path. Implementations SHOULD treat retiring an already-retired or
/// never-minted identity as a no-op rather than throwing, mirroring
/// <see cref="WipeSnapshotAsyncDelegate"/>'s identical idempotency guidance.
/// </remarks>
public delegate ValueTask RetireCounterAsyncDelegate(ulong creationSequence, CancellationToken cancellationToken);
