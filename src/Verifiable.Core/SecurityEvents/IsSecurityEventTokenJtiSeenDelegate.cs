using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// Returns <see langword="true"/> when a Security Event Token's <c>jti</c> has
/// already been seen by this receiver, so the SET is a replay and MUST be
/// rejected.
/// </summary>
/// <remarks>
/// <para>
/// SET delivery is at-least-once: a Transmitter may re-send a SET the Receiver
/// already acknowledged, and an attacker may capture and replay one. The
/// <c>jti</c> is the per-token unique identifier (RFC 8417 §2.2) used to
/// de-duplicate. The replay window and its storage are the application's
/// concern; this seam is the single decision point the verification pipeline
/// consults, kept context-neutral so any party (receiver, wallet, AS) can supply
/// its own tracker. The per-call <see cref="ExchangeContext"/> carries whatever
/// scope (tenant, stream) the tracker needs, threaded rather than captured.
/// </para>
/// </remarks>
/// <param name="jti">The <c>jti</c> claim of the SET being verified.</param>
/// <param name="context">The per-call exchange context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
public delegate ValueTask<bool> IsSecurityEventTokenJtiSeenDelegate(
    string jti,
    ExchangeContext context,
    CancellationToken cancellationToken);
