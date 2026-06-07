using System.Diagnostics;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The result of a successful
/// <see cref="OAuthDynamicRegistrationClient.RegisterAsync"/> call. Carries
/// both the AS's raw <see cref="RegistrationResponse"/> and the constructed
/// runtime <see cref="ClientRegistration"/> that combines that response
/// with the application's locally-held key material from
/// <see cref="RegisterClientOptions"/>.
/// </summary>
/// <remarks>
/// Applications typically persist the <see cref="Registration"/> directly
/// and discard the raw response. The response is exposed for audit logging
/// and for the rare deployment that needs the AS-echoed metadata
/// independently of the runtime record.
/// </remarks>
[DebuggerDisplay("DynamicRegistrationResult ClientId={Registration.ClientId}")]
public sealed record DynamicRegistrationResult
{
    /// <summary>The parsed RFC 7591 §3.2.1 response from the AS.</summary>
    public required RegistrationResponse Response { get; init; }

    /// <summary>The constructed runtime registration ready to use in protocol calls.</summary>
    public required ClientRegistration Registration { get; init; }
}
