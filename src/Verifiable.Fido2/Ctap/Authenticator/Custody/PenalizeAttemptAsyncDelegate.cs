using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap.Authenticator.Custody;

/// <summary>
/// Records a failed PIN-guess attempt WITHOUT a candidate hash to compare — the persistent-tier
/// counterpart of a decrypt failure (CTAP 2.3 lines 5671/5883/5985: "If an error results, or a mismatch
/// is detected, the authenticator performs the following operations"; contract R-2/R-3, wavepin): called
/// instead of <see cref="VerifyPinAttemptAsyncDelegate"/> whenever <c>changePIN</c>/<c>getPinToken</c>/
/// <c>getPinUvAuthTokenUsingPinWithPermissions</c>'s own <c>decrypt(sharedSecret, pinHashEnc)</c> step
/// fails before a candidate hash ever exists to present.
/// </summary>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The verdict immediately after this penalty: <see cref="CtapPinAttemptVerdict.IsMatch"/> is always
/// <see langword="false"/>, the persistent-tier retry budget has been decremented exactly as a decoded
/// mismatch would decrement it, and <see cref="CtapPinAttemptVerdict.IsBlocked"/> reflects whether that
/// decrement exhausted the tier.
/// </returns>
public delegate ValueTask<CtapPinAttemptVerdict> PenalizeAttemptAsyncDelegate(CancellationToken cancellationToken);
