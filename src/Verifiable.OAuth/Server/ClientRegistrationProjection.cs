using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;

namespace Verifiable.OAuth.Server;

/// <summary>
/// An immutable selection of committed client data for event delivery and retention.
/// It contains identifiers, revision, public metadata and signing-key identifiers, with no request
/// context, credentials, key material, arbitrary metadata dictionaries or application objects.
/// </summary>
public sealed record ClientRegistrationProjection
{
    /// <summary>The client identifier within the tenant.</summary>
    public required string ClientId { get; init; }


    /// <summary>The tenant owning this registration.</summary>
    public required TenantId TenantId { get; init; }


    /// <summary>
    /// The application-assigned display identifier for the owning tenant, safe for delivery to
    /// observers. <see langword="null"/> when the application assigned none.
    /// </summary>
    public TenantHandle? TenantHandle { get; init; }


    /// <summary>The committed per-registration revision.</summary>
    public required long Revision { get; init; }


    /// <summary>The selected display name.</summary>
    public string? ClientName { get; init; }


    /// <summary>The selected client information URI.</summary>
    public Uri? ClientUri { get; init; }


    /// <summary>The immutable registered redirect URI set.</summary>
    public required ImmutableHashSet<Uri> RedirectUris { get; init; }


    /// <summary>The immutable allowed scope set.</summary>
    public required ImmutableHashSet<string> Scopes { get; init; }


    /// <summary>The immutable registered capability set.</summary>
    public required ImmutableHashSet<CapabilityIdentifier> Capabilities { get; init; }


    /// <summary>The copied default signing-key identifier for each registered usage.</summary>
    public required ImmutableDictionary<KeyUsageContext, KeyId> SigningKeyIds { get; init; }


    /// <summary>Copies selected data without retaining mutable registration members.</summary>
    /// <param name="registration">The committed record whose public data is projected.</param>
    internal static ClientRegistrationProjection From(ClientRecord registration) => new()
    {
        ClientId = registration.ClientId,
        TenantId = registration.TenantId,
        TenantHandle = registration.TenantHandle,
        Revision = registration.Revision,
        ClientName = registration.ClientName,
        ClientUri = registration.ClientUri,
        RedirectUris = registration.AllowedRedirectUris,
        Scopes = registration.AllowedScopes,
        Capabilities = registration.AllowedCapabilities,
        SigningKeyIds = registration.SigningKeys
            .Where(entry => !entry.Value.Current.IsEmpty)
            .ToImmutableDictionary(entry => entry.Key, entry => entry.Value.Current[0])
    };
}
