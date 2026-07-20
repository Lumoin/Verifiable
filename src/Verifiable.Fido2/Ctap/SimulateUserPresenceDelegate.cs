using System.Threading;
using System.Threading.Tasks;

namespace Verifiable.Fido2.Ctap;

/// <summary>
/// Simulates one user-presence collection (CTAP 2.3 :2840: "This refers to a timeout that occurs when
/// the authenticator is waiting for direct action from the user, like a touch. (I.e. not a command from
/// the platform.)").
/// </summary>
/// <param name="cancellationToken">A cancellation token.</param>
/// <returns>
/// The collection's outcome — see <see cref="CtapUserPresenceDecision"/>.
/// </returns>
/// <remarks>
/// A composition-time <see cref="Ctap.Authenticator.Automata.CtapAuthenticatorSimulator"/> personalization
/// knob mirroring <see cref="SimulateBuiltInUvDelegate"/>'s own production-personalization posture, never
/// a test-only hook: the shipped default always reports <see cref="CtapUserPresenceDecision.Granted"/>,
/// and a caller supplies a closure returning a scripted sequence per call to exercise decline, deferral,
/// or timeout paths. Asynchronous and cancellable, unlike <see cref="SimulateBuiltInUvDelegate"/>: a
/// deferring caller may poll this delegate repeatedly across separate wire round trips (test providers
/// count polls via closure state — no poll-count parameter). Consumed by <c>authenticatorMakeCredential</c>'s
/// and <c>authenticatorGetAssertion</c>'s own user-presence collection points.
/// </remarks>
public delegate ValueTask<CtapUserPresenceDecision> SimulateUserPresenceDelegate(CancellationToken cancellationToken);
