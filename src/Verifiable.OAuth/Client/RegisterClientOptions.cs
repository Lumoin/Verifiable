using System.Diagnostics;
using Verifiable.Cryptography;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Per-call inputs for
/// <see cref="OAuthDynamicRegistrationClient.RegisterAsync"/>. Carries the
/// AS endpoint to POST to, the metadata to publish, and the locally-held
/// key material the resulting <see cref="ClientRegistration"/> binds to.
/// </summary>
/// <remarks>
/// The locally-held key material is supplied by the application before the
/// registration call so that the AS-issued <c>client_id</c> can be bound to
/// keys the application already controls. RFC 7591 §2 supports either an
/// inline JWKS in the metadata body or a <c>jwks_uri</c> the AS fetches;
/// the application picks one when populating
/// <see cref="Metadata"/>.
/// </remarks>
[DebuggerDisplay("RegisterClientOptions Endpoint={RegistrationEndpoint}")]
public sealed record RegisterClientOptions
{
    /// <summary>The AS's RFC 7591 §3 registration endpoint URL.</summary>
    public required Uri RegistrationEndpoint { get; init; }

    /// <summary>
    /// The AS's issuer identifier, populated onto the resulting
    /// <see cref="ClientRegistration.AuthorizationServerIssuer"/>. Typically
    /// the same string the application configured for metadata resolution.
    /// </summary>
    public required Uri AuthorizationServerIssuer { get; init; }

    /// <summary>The metadata to publish to the AS.</summary>
    public required ClientMetadata Metadata { get; init; }

    /// <summary>
    /// The authentication method the resulting registration uses. Populated
    /// onto <see cref="ClientRegistration.AuthenticationMethod"/>.
    /// </summary>
    public required ClientAuthenticationMethod AuthenticationMethod { get; init; }

    /// <summary>
    /// Locally-held signing key material. Populated onto
    /// <see cref="ClientRegistration.SigningKeyMaterial"/>. Non-owning
    /// reference; the application retains lifecycle ownership.
    /// </summary>
    public PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>? SigningKeyMaterial { get; init; }

    /// <summary>
    /// Locally-held client-authentication key material. Populated onto
    /// <see cref="ClientRegistration.AuthenticationKeyMaterial"/>.
    /// </summary>
    public PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory>? AuthenticationKeyMaterial { get; init; }

    /// <summary>
    /// The security profile the resulting registration runs under.
    /// <see langword="null"/> means the library default
    /// (<see cref="PolicyProfile.Fapi20"/>).
    /// </summary>
    public PolicyProfile? Profile { get; init; }
}
