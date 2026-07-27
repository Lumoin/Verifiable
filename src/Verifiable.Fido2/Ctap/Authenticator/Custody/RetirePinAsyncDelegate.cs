using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Retires the persistent tier entirely — <see cref="Automata.CtapAuthenticatorSimulator"/>'s
/// <c>authenticatorReset</c> effect drives this in the same post-command retirement slot
/// <c>ApplySignatureCounterRetirementPostCommandAsync</c> (contract R-9, wavenv) uses for per-credential
/// signature counters, so a factory-reset authenticator's later fresh <c>setPIN</c> provisions onto a
/// tier with no memory of any pre-reset PIN or retry count (CTAP 2.3 §6.6, lines 6329-6359: reset is the
/// PIN lockout's sole spec-named recovery).
/// </summary>
/// <param name="cancellationToken">A cancellation token.</param>
/// <remarks>
/// Implementations SHOULD treat retiring an already-retired or never-provisioned tier as a no-op rather
/// than throwing, mirroring <see cref="RetireCounterAsyncDelegate"/>'s identical idempotency guidance.
/// </remarks>
public delegate ValueTask RetirePinAsyncDelegate(CancellationToken cancellationToken);
