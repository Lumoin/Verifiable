using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Server;

namespace Verifiable.OAuth.Server;

/// <summary>
/// Convenience accessors that reach the OAuth/OpenID family integration registered on a
/// neutral <see cref="EndpointServer"/>, and forward the registration-lifecycle event
/// emission to it.
/// </summary>
/// <remarks>
/// The OAuth family registers its <see cref="AuthorizationServerIntegration"/> through the
/// host's integration registry; <see cref="OAuth(EndpointServer)"/> retrieves it. The
/// family configuration the OAuth endpoints read — cryptography, codecs, token producers,
/// the claim issuer, the action executor, timings — lives on that integration.
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class EndpointServerOAuthExtensions
{
    extension(EndpointServer server)
    {
        /// <summary>
        /// Returns the OAuth/OpenID family integration registered on this host.
        /// </summary>
        public AuthorizationServerIntegration OAuth() =>
            server.GetIntegration<AuthorizationServerIntegration>();


        /// <summary>
        /// The instance-scoped event stream for client registration lifecycle events,
        /// forwarded from the OAuth family integration.
        /// </summary>
        public IObservable<ClientRegistrationEvent> Events =>
            server.GetIntegration<AuthorizationServerIntegration>().Events;


        /// <summary>Emits a <see cref="ClientRegistered"/> event on the OAuth family integration.</summary>
        public void RegisterClient(
            ClientRecord registration,
            RegistrationAccessToken accessToken,
            ExchangeContext context)
        {
            server.GetIntegration<AuthorizationServerIntegration>()
                .RegisterClient(registration, accessToken, context, server.TimeProvider);
        }


        /// <summary>Emits a <see cref="ClientUpdated"/> event on the OAuth family integration.</summary>
        public void UpdateClient(
            ClientRecord previous,
            ClientRecord current,
            ExchangeContext context)
        {
            server.GetIntegration<AuthorizationServerIntegration>()
                .UpdateClient(previous, current, context, server.TimeProvider);
        }


        /// <summary>Emits a <see cref="ClientDeregistered"/> event on the OAuth family integration.</summary>
        public void DeregisterClient(
            ClientRecord registration,
            string reason,
            ExchangeContext context)
        {
            server.GetIntegration<AuthorizationServerIntegration>()
                .DeregisterClient(registration, reason, context, server.TimeProvider);
        }


        /// <summary>Emits a <see cref="CapabilityGranted"/> event on the OAuth family integration.</summary>
        public void GrantCapability(
            ClientRecord registration,
            CapabilityIdentifier capability,
            ExchangeContext context)
        {
            server.GetIntegration<AuthorizationServerIntegration>()
                .GrantCapability(registration, capability, context, server.TimeProvider);
        }


        /// <summary>Emits a <see cref="CapabilityRevoked"/> event on the OAuth family integration.</summary>
        public void RevokeCapability(
            ClientRecord registration,
            CapabilityIdentifier capability,
            string reason,
            ExchangeContext context)
        {
            server.GetIntegration<AuthorizationServerIntegration>()
                .RevokeCapability(registration, capability, reason, context, server.TimeProvider);
        }
    }
}
