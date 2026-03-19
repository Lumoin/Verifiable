using System;
using System.Diagnostics;
using Verifiable.OAuth;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Signals that the JAR has been fetched from the <c>request_uri</c> endpoint.
/// Transitions from <see cref="JarReady"/> to <see cref="JarServed"/>.
/// </summary>
/// <param name="FetchedAt">The UTC instant of the incoming fetch request.</param>
[DebuggerDisplay("JarFetched FetchedAt={FetchedAt}")]
public sealed record JarFetched(DateTimeOffset FetchedAt): OAuthFlowInput;
