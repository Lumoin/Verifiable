using System;
using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Verifies one PIN-guess attempt against the persistent tier's currently provisioned PIN, atomically
/// recording the outcome in the SAME call (contract R-2, wavepin: "the compare and the counter move are
/// one atomic TPM command — no TOCTOU between compare and record") — the sole authority for the
/// current-PIN check once this seam is composed, REPLACING the local constant-time compare
/// <see cref="Automata.CtapAuthenticatorSimulator"/>'s <c>changePIN</c>/<c>getPinToken</c>/
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c> effects otherwise run.
/// </summary>
/// <param name="candidatePinHash">
/// The just-decrypted candidate PIN hash (CTAP 2.3 §6.5.5.6/§6.5.5.7.1/§6.5.5.7.2's own
/// <c>decrypt(sharedSecret, pinHashEnc)</c> result) — never the authenticator's own stored value; the
/// custody bundle (or, for package C, the TPM Index's own authValue resolution) holds that.
/// </param>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The verdict: whether <paramref name="candidatePinHash"/> matched, the persistent-tier retry budget
/// immediately after this attempt, and whether the tier is now exhausted.
/// </returns>
public delegate ValueTask<CtapPinAttemptVerdict> VerifyPinAttemptAsyncDelegate(ReadOnlyMemory<byte> candidatePinHash, CancellationToken cancellationToken);
