using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Signals that the JAR has been fetched from the <c>request_uri</c> endpoint.
/// Transitions from <see cref="Verifiable.OAuth.Oid4Vp.States.JarReadyState"/> to <see cref="Verifiable.OAuth.Oid4Vp.States.JarServedState"/>.
/// </summary>
/// <param name="FetchedAt">The UTC instant of the incoming fetch request.</param>
[DebuggerDisplay("JarFetched FetchedAt={FetchedAt}")]
public sealed record JarFetched(DateTimeOffset FetchedAt): FlowInput;
