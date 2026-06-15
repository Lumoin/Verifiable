using System.Diagnostics.CodeAnalysis;
using Verifiable.Server;

namespace Verifiable.Vcalm;

/// <summary>
/// Convenience accessor that reaches the W3C VCALM family integration registered on a neutral
/// <see cref="EndpointServer"/>.
/// </summary>
/// <remarks>
/// The VCALM family registers its <see cref="VcalmIntegration"/> through the host's integration
/// registry; <see cref="Vcalm(EndpointServer)"/> retrieves it. The family seams the VCALM endpoints
/// read — the parse seams, the Data Integrity verification / issuance configuration, the challenge
/// and issued-credential stores, and the request-size cap — live on that integration.
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class EndpointServerVcalmExtensions
{
    extension(EndpointServer server)
    {
        /// <summary>
        /// Returns the W3C VCALM family integration registered on this host.
        /// </summary>
        public VcalmIntegration Vcalm() =>
            server.GetIntegration<VcalmIntegration>();
    }
}
