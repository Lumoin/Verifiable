using System.Diagnostics;

namespace Verifiable.OAuth.Client;

/// <summary>
/// The typed shape returned by <see cref="ParseRegistrationResponseDelegate"/>.
/// Combines the echoed client metadata with the AS-assigned identifier and
/// RFC 7592 management bits per
/// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591 §3.2.1</see>.
/// </summary>
/// <remarks>
/// Distinct from <see cref="ClientRegistration"/>: this is the wire-format
/// response. The caller of
/// <c>OAuthDynamicRegistrationClient.RegisterAsync</c> combines this with the
/// locally-held key material (the application's own signing key it
/// generated before sending the registration request) into a
/// <see cref="ClientRegistration"/> for runtime use.
/// </remarks>
[DebuggerDisplay("RegistrationResponse ClientId={ClientId}")]
public sealed record RegistrationResponse
{
    /// <summary>The AS-assigned client identifier.</summary>
    public required ClientId ClientId { get; init; }

    /// <summary>The echoed (possibly server-adjusted) client metadata.</summary>
    public required ClientMetadata Metadata { get; init; }

    /// <summary>
    /// The RFC 7591 §3.2.1 <c>registration_access_token</c>, when the AS
    /// supports RFC 7592 management.
    /// </summary>
    public RegistrationAccessToken? AccessToken { get; init; }

    /// <summary>
    /// The RFC 7591 §3.2.1 <c>registration_client_uri</c>, when the AS
    /// supports RFC 7592 management.
    /// </summary>
    public Uri? ManagementUri { get; init; }

    /// <summary>
    /// The RFC 7591 §3.2.1 <c>client_id_issued_at</c> timestamp.
    /// </summary>
    public DateTimeOffset? IssuedAt { get; init; }

    /// <summary>
    /// The RFC 7591 §3.2.1 <c>client_secret_expires_at</c> timestamp.
    /// </summary>
    public DateTimeOffset? ExpiresAt { get; init; }
}
