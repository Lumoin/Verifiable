using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Ensures a monotonic counter exists for the credential identified by <paramref name="creationSequence"/>,
/// minting it if this is the first time the credential has ever been seen, and returns its current count —
/// the value <see cref="Automata.CtapAuthenticatorSimulator"/> installs as a freshly minted credential's
/// INITIAL signature counter (contract R-9, wavenv).
/// </summary>
/// <param name="creationSequence">
/// The minting credential's own <see cref="Automata.CtapCredentialRecord.CreationSequence"/> value — the
/// stable identity a <see cref="CtapSignatureCounterCustody"/> bundle's three delegates key a counter by,
/// threaded as an explicit per-call context parameter instead of a closure capture (house rule: no closure
/// capture). This value CAN repeat across the lifetime of one authenticator instance (an
/// <c>authenticatorReset</c> restarts the mint-order sequence at zero) — an implementation backed by a
/// rollback-protected counter primitive (for example a TPM Counter Index, TPM 2.0 Library Part 1, Section
/// 37.2.6.3's phantom-counter mechanism) is exactly what makes that reuse safe: a counter identified by a
/// previously retired <paramref name="creationSequence"/> seeds strictly above every value it held before
/// retirement.
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The counter's current count immediately after this call — never a value already reported by a PRIOR
/// counter that shared the same <paramref name="creationSequence"/> before being retired.
/// </returns>
/// <remarks>
/// Contract R-9(3)(c): the returned value IS the registration's stored and wire-visible signature counter —
/// never re-derived from it. This delegate is never called for an ALREADY-minted credential; see
/// <see cref="IncrementCounterAsyncDelegate"/> for the assertion-time counterpart.
/// </remarks>
public delegate ValueTask<ulong> EnsureCounterAsyncDelegate(ulong creationSequence, CancellationToken cancellationToken);
