using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;

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


        /// <summary>Notifies optional observers with a <see cref="ClientRegistered"/> event on the OAuth family integration.</summary>
        /// <remarks>The caller commits storage before notification. Capability events require an application state effect; observer failures are isolated and inspected.</remarks>
        public ValueTask RegisterClientAsync(
            ClientRecord registration,
            ExchangeContext context)
        {

            return server.GetIntegration<AuthorizationServerIntegration>()
                .RegisterClientAsync(registration, context, server.TimeProvider);
        }


        /// <summary>Notifies optional observers with a <see cref="ClientUpdated"/> event on the OAuth family integration.</summary>
        /// <remarks>The caller commits storage before notification. Capability events require an application state effect; observer failures are isolated and inspected.</remarks>
        public ValueTask UpdateClientAsync(
            ClientRecord previous,
            ClientRecord current,
            ExchangeContext context)
        {

            return server.GetIntegration<AuthorizationServerIntegration>()
                .UpdateClientAsync(previous, current, context, server.TimeProvider);
        }


        /// <summary>Emits a tombstone one revision beyond the final record removed atomically by the required store.</summary>
        /// <remarks>The caller passes the authoritative deletion result after commitment. Consumers retain its next revision to reject delayed updates.</remarks>
        public ValueTask DeregisterClientAsync(
            ClientRecord registration,
            string reason,
            ExchangeContext context)
        {

            return server.GetIntegration<AuthorizationServerIntegration>()
                .DeregisterClientAsync(registration, reason, context, server.TimeProvider);
        }


        /// <summary>Notifies optional observers with a <see cref="CapabilityGranted"/> event on the OAuth family integration.</summary>
        /// <remarks>The application applies the signal to its granted-capability state before reachability changes; observer failures are isolated and inspected.</remarks>
        public ValueTask GrantCapabilityAsync(
            ClientRecord registration,
            CapabilityIdentifier capability,
            ExchangeContext context)
        {

            return server.GetIntegration<AuthorizationServerIntegration>()
                .GrantCapabilityAsync(registration, capability, context, server.TimeProvider);
        }


        /// <summary>Notifies optional observers with a <see cref="CapabilityRevoked"/> event on the OAuth family integration.</summary>
        /// <remarks>The application applies the signal to its granted-capability state before reachability changes; observer failures are isolated and inspected.</remarks>
        public ValueTask RevokeCapabilityAsync(
            ClientRecord registration,
            CapabilityIdentifier capability,
            string reason,
            ExchangeContext context)
        {

            return server.GetIntegration<AuthorizationServerIntegration>()
                .RevokeCapabilityAsync(registration, capability, reason, context, server.TimeProvider);
        }
    }
}
