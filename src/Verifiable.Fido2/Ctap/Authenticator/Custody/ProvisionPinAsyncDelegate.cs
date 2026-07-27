using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Provisions <paramref name="pinHash"/> as the persistent tier's current PIN — the authoritative value
/// <see cref="Automata.CtapAuthenticatorSimulator"/> installs at <c>setPIN</c> establishment (CTAP 2.3
/// §6.5.5.5) and at a successful <c>changePIN</c>'s own PIN rotation (§6.5.5.6), each call completely
/// replacing whatever the persistent tier held before and resetting its retry budget to maximum
/// (contract R-2, wavepin).
/// </summary>
/// <param name="pinHash">
/// The new stored PIN hash — <c>LEFT(SHA-256(newPin), 16)</c> (CTAP 2.3, lines 5592/5710), computed by
/// the already-shipped <c>ComputeStoredPinHash</c> seam. The custody layer never sees a raw PIN.
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <remarks>
/// Contract R-2's rollback consequence: an implementation backed by a rollback-protected primitive (for
/// example a TPM <c>TPM_NT_PIN_FAIL</c> Index, package C's <c>TpmNvPinRetriesCustody</c>) ROTATES its
/// own authorization secret at this call — never merely records the hash alongside an unrelated counter
/// — so a later replayed stale snapshot's own <c>CurrentStoredPin</c> field can never resurrect a
/// superseded PIN: the persistent tier's own authoritative secret has already moved on.
/// </remarks>
public delegate ValueTask ProvisionPinAsyncDelegate(ReadOnlyMemory<byte> pinHash, CancellationToken cancellationToken);
