using Verifiable.OAuth;

namespace Verifiable.OAuth.Oid4Vp.Server;

/// <summary>
/// Action produced by <see cref="States.VerifierJarReady"/> indicating that the JAR
/// has been served at the <c>request_uri</c> endpoint and must be acknowledged as
/// fetched before the flow advances to <see cref="States.VerifierJarServedState"/>.
/// </summary>
/// <remarks>
/// Serving the JAR and acknowledging the fetch happen in the same HTTP request —
/// the Wallet fetches the JAR, the server serves it, and the flow advances to
/// <see cref="States.VerifierJarServedState"/> immediately. No external input is needed.
/// </remarks>
public sealed record JarFetchedAction: OAuthAction;
