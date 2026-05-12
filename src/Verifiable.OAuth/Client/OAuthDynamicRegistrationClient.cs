using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The dynamic registration sub-client of <see cref="OAuthClient"/>. A
/// per-call handle over an <see cref="OAuthClientInfrastructure"/> that
/// drives RFC 7591 client registration and RFC 7592 management.
/// </summary>
/// <remarks>
/// Constructed via the <see cref="OAuthClient.DynamicRegistration"/>
/// extension property. The struct is cheap to materialise (one reference
/// field) and carries no per-call state of its own.
/// </remarks>
[DebuggerDisplay("OAuthDynamicRegistrationClient")]
[SuppressMessage("Performance", "CA1815:Override equals and operator equals on value types", Justification = "OAuthDynamicRegistrationClient is a service-shaped wrapper around a single reference; value equality would compare reference identity of the underlying infrastructure, which is not a meaningful operation for callers.")]
public readonly struct OAuthDynamicRegistrationClient
{
    /// <summary>The long-lived infrastructure this client reads delegates from.</summary>
    public OAuthClientInfrastructure Infrastructure { get; }


    /// <summary>Internal constructor — use <see cref="OAuthClient.DynamicRegistration"/>.</summary>
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
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(options);

        return DynamicRegistrationHandlers.HandleRegisterAsync(
            options, Infrastructure, cancellationToken);
    }


    /// <summary>
    /// Reads the current client metadata at the registration's RFC 7592
    /// management endpoint. Returns the AS's echoed
    /// <see cref="ClientMetadata"/>.
    /// </summary>
    /// <remarks>
    /// Phase 4 stub — the underlying
    /// <see cref="DynamicRegistrationHandlers.HandleReadAsync"/> throws
    /// <see cref="NotImplementedException"/> pending the
    /// <c>SendJsonGetDelegate</c> transport delegate phase 5 ships.
    /// </remarks>
    public ValueTask<ClientMetadata> ReadAsync(
        ClientRegistration registration,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);

        return DynamicRegistrationHandlers.HandleReadAsync(
            registration, Infrastructure, cancellationToken);
    }


    /// <summary>
    /// Updates the client metadata at the registration's RFC 7592 management
    /// endpoint via PUT, returning the AS's echoed
    /// <see cref="ClientMetadata"/> after the update.
    /// </summary>
    /// <remarks>
    /// Phase 4 stub — the underlying
    /// <see cref="DynamicRegistrationHandlers.HandleUpdateAsync"/> throws
    /// <see cref="NotImplementedException"/> pending the
    /// <c>SendJsonPutDelegate</c> transport delegate phase 5 ships.
    /// </remarks>
    public ValueTask<ClientMetadata> UpdateAsync(
        ClientRegistration registration,
        ClientMetadata newMetadata,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(newMetadata);

        return DynamicRegistrationHandlers.HandleUpdateAsync(
            registration, newMetadata, Infrastructure, cancellationToken);
    }


    /// <summary>
    /// Deregisters the client at the registration's RFC 7592 management
    /// endpoint via DELETE. After a successful call the registration is no
    /// longer usable; the application should drop the local
    /// <see cref="ClientRegistration"/>.
    /// </summary>
    /// <remarks>
    /// Phase 4 stub — the underlying
    /// <see cref="DynamicRegistrationHandlers.HandleDeregisterAsync"/>
    /// throws <see cref="NotImplementedException"/> pending the
    /// <c>SendJsonDeleteDelegate</c> transport delegate phase 5 ships.
    /// </remarks>
    public ValueTask DeregisterAsync(
        ClientRegistration registration,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(registration);

        return DynamicRegistrationHandlers.HandleDeregisterAsync(
            registration, Infrastructure, cancellationToken);
    }
}
