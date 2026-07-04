using System.Diagnostics.CodeAnalysis;
using Verifiable.Server;

namespace Verifiable.WebFinger;

/// <summary>
/// Convenience accessor that reaches the WebFinger family integration registered on a neutral
/// <see cref="EndpointServer"/>.
/// </summary>
/// <remarks>
/// WebFinger registers its <see cref="WebFingerIntegration"/> through the host's integration registry
/// (<see cref="EndpointServer.AddIntegration{T}"/>); <see cref="WebFinger(EndpointServer)"/> retrieves it
/// with <see cref="EndpointServer.GetIntegration{T}"/> — exactly how the OAuth and W3C VCALM families
/// reach their own integrations. WebFinger depends on neither.
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class EndpointServerWebFingerExtensions
{
    extension(EndpointServer server)
    {
        /// <summary>
        /// Returns the WebFinger family integration registered on this host.
        /// </summary>
        public WebFingerIntegration WebFinger() =>
            server.GetIntegration<WebFingerIntegration>();
    }
}
