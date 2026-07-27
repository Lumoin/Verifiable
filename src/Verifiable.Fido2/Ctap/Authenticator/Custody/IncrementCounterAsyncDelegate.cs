using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Atomically advances the counter identified by <paramref name="creationSequence"/> by one and returns the
/// fresh count — the AUTHORITATIVE value <see cref="Automata.CtapAuthenticatorSimulator"/> embeds in a
/// signed assertion's <c>authData</c> and persists back into the credential record (contract R-9, wavenv).
/// </summary>
/// <param name="creationSequence">
/// The asserting credential's own <see cref="Automata.CtapCredentialRecord.CreationSequence"/> value — the
/// SAME identity <see cref="EnsureCounterAsyncDelegate"/> minted the counter under, threaded as an explicit
/// per-call context parameter instead of a closure capture (house rule: no closure capture).
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>The counter's fresh count immediately after this call.</returns>
/// <remarks>
/// <para>
/// Contract R-9(3)(a)/(b): the returned value is what the SIGNED authenticator data carries — never the
/// pure transition's own <c>SignCount + 1</c> once this delegate is composed — and this call happens
/// BEFORE the assertion's response is framed. A thrown exception here fails the whole
/// <c>authenticatorGetAssertion</c>/<c>authenticatorGetNextAssertion</c> command on the wire: no response
/// ever carries a count this call did not durably advance to (increment-before-response, the wavect R-4
/// persist-then-respond discipline's exact analogue for a per-assertion counter rather than a
/// whole-snapshot persist).
/// </para>
/// <para>
/// Never called for a credential <see cref="EnsureCounterAsyncDelegate"/> has not already minted a counter
/// for in this authenticator's current lifetime.
/// </para>
/// </remarks>
public delegate ValueTask<ulong> IncrementCounterAsyncDelegate(ulong creationSequence, CancellationToken cancellationToken);
