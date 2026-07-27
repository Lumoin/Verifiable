using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Reads the persistent tier's current retry budget WITHOUT recording an attempt — the administrative,
/// non-authorization read <see cref="Automata.CtapAuthenticatorSimulator.CreateWithCustodyAsync"/> uses
/// to re-synchronize <see cref="Automata.CtapAuthenticatorState.PinRetries"/>'s demoted-cache mirror
/// (contract R-4, wavepin) at construction time, OVERRIDING whatever a rehydrated whole-snapshot's own
/// <c>PinRetries</c> field said — the exact move that closes the stale-snapshot rollback hole a bare
/// whole-snapshot mirror alone cannot (contract R-2's rollback consequence).
/// </summary>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The current verdict: <see cref="CtapPinAttemptVerdict.IsMatch"/> is always <see langword="false"/>
/// (no candidate was ever presented), <see cref="CtapPinAttemptVerdict.RetriesRemaining"/>/
/// <see cref="CtapPinAttemptVerdict.IsBlocked"/> report the tier's CURRENT state, untouched by this
/// call.
/// </returns>
public delegate ValueTask<CtapPinAttemptVerdict> ReadRetriesAsyncDelegate(CancellationToken cancellationToken);
