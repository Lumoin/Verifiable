using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The dynamic registration sub-client of <see cref="OAuthClient"/>. A
/// per-call handle over an <see cref="OAuthClientInfrastructure"/> that
/// drives RFC 7591 client registration and RFC 7592 management.
/// </summary>
/// <remarks>
/// Constructed via the <c>OAuthClient.DynamicRegistration</c>
/// extension property. The struct is cheap to materialise (one reference
/// field) and carries no per-call state of its own.
/// </remarks>
[SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "OAuthDynamicRegistrationClient is a service-shaped wrapper around a single reference; value equality would compare reference identity of the underlying infrastructure, which is not a meaningful operation for callers.")]
public readonly struct OAuthDynamicRegistrationClient
{
    /// <summary>The long-lived infrastructure this client reads delegates from.</summary>
    public OAuthClientInfrastructure Infrastructure { get; }


    /// <summary>Internal constructor — use <c>OAuthClient.DynamicRegistration</c>.</summary>
    internal OAuthDynamicRegistrationClient(OAuthClientInfrastructure infrastructure)
    {
        ArgumentNullException.ThrowIfNull(infrastructure);

        Infrastructure = infrastructure;
    }


    /// <summary>
    /// Registers a new client with the authorization server per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7591">RFC 7591</see>.
    /// POSTs the metadata, parses the response, and constructs a runtime
    /// <see cref="ClientRegistration"/> binding the AS-issued identifier
    /// to the application's locally-held key material.
    /// </summary>
    public ValueTask<DynamicRegistrationResult> RegisterAsync(
        RegisterClientOptions options,
        CancellationToken cancellationToken) =>
        RegisterAsync(options, [], cancellationToken);


    /// <inheritdoc cref="RegisterAsync(RegisterClientOptions, CancellationToken)"/>
    /// <param name="options">The client metadata to register.</param>
    /// <param name="context">The per-operation exchange context threaded into the JSON transport delegate.</param>
    /// <param name="cancellationToken">The token to observe while the registration request is outstanding.</param>
    public ValueTask<DynamicRegistrationResult> RegisterAsync(
        RegisterClientOptions options,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(context);

        return DynamicRegistrationHandlers.HandleRegisterAsync(
            options, Infrastructure, context, cancellationToken);
    }


    /// <summary>
    /// Reads the current client metadata at the registration's
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.1">RFC 7592 §2.1</see>
    /// management endpoint. Returns the AS's echoed
    /// <see cref="ClientMetadata"/>.
    /// </summary>
    /// <remarks>
    /// GETs <see cref="ClientRegistration.ManagementUri"/> bearing
    /// <see cref="ClientRegistration.AccessToken"/>, via
    /// <see cref="DynamicRegistrationHandlers.HandleReadAsync"/>.
    /// </remarks>
    public ValueTask<ClientMetadata> ReadAsync(
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        ReadAsync(registration, [], cancellationToken);


    /// <inheritdoc cref="ReadAsync(ClientRegistration, CancellationToken)"/>
    /// <param name="registration">The registration whose management endpoint is read.</param>
    /// <param name="context">The per-operation exchange context threaded into the JSON transport delegate.</param>
    /// <param name="cancellationToken">The token to observe while the read request is outstanding.</param>
    public ValueTask<ClientMetadata> ReadAsync(
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        return DynamicRegistrationHandlers.HandleReadAsync(
            registration, Infrastructure, context, cancellationToken);
    }


    /// <summary>
    /// Updates the client metadata at the registration's
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.2">RFC 7592 §2.2</see>
    /// management endpoint via PUT, returning the AS's echoed
    /// <see cref="ClientMetadata"/> after the update.
    /// </summary>
    /// <remarks>
    /// PUTs <paramref name="newMetadata"/> — with <c>client_id</c> pinned to
    /// <see cref="ClientRegistration.ClientId"/> — to
    /// <see cref="ClientRegistration.ManagementUri"/> bearing
    /// <see cref="ClientRegistration.AccessToken"/>, via
    /// <see cref="DynamicRegistrationHandlers.HandleUpdateAsync"/>.
    /// </remarks>
    public ValueTask<ClientMetadata> UpdateAsync(
        ClientRegistration registration,
        ClientMetadata newMetadata,
        CancellationToken cancellationToken) =>
        UpdateAsync(registration, newMetadata, [], cancellationToken);


    /// <inheritdoc cref="UpdateAsync(ClientRegistration, ClientMetadata, CancellationToken)"/>
    /// <param name="registration">The registration whose management endpoint is updated.</param>
    /// <param name="newMetadata">The replacement client metadata to PUT.</param>
    /// <param name="context">The per-operation exchange context threaded into the JSON transport delegate.</param>
    /// <param name="cancellationToken">The token to observe while the update request is outstanding.</param>
    public ValueTask<ClientMetadata> UpdateAsync(
        ClientRegistration registration,
        ClientMetadata newMetadata,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(newMetadata);
        ArgumentNullException.ThrowIfNull(context);

        return DynamicRegistrationHandlers.HandleUpdateAsync(
            registration, newMetadata, Infrastructure, context, cancellationToken);
    }


    /// <summary>
    /// Deregisters the client at the registration's
    /// <see href="https://www.rfc-editor.org/rfc/rfc7592#section-2.3">RFC 7592 §2.3</see>
    /// management endpoint via DELETE. After a successful call the registration is no
    /// longer usable; the application should drop the local
    /// <see cref="ClientRegistration"/>.
    /// </summary>
    /// <remarks>
    /// DELETEs <see cref="ClientRegistration.ManagementUri"/> bearing
    /// <see cref="ClientRegistration.AccessToken"/>, via
    /// <see cref="DynamicRegistrationHandlers.HandleDeregisterAsync"/>.
    /// </remarks>
    public ValueTask DeregisterAsync(
        ClientRegistration registration,
        CancellationToken cancellationToken) =>
        DeregisterAsync(registration, [], cancellationToken);


    /// <inheritdoc cref="DeregisterAsync(ClientRegistration, CancellationToken)"/>
    /// <param name="registration">The registration whose management endpoint is deleted.</param>
    /// <param name="context">The per-operation exchange context threaded into the JSON transport delegate.</param>
    /// <param name="cancellationToken">The token to observe while the deregistration request is outstanding.</param>
    public ValueTask DeregisterAsync(
        ClientRegistration registration,
        ExchangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(context);

        return DynamicRegistrationHandlers.HandleDeregisterAsync(
            registration, Infrastructure, context, cancellationToken);
    }
}
