using System.Diagnostics;

namespace Verifiable.Vcalm;

/// <summary>
/// The neutral, parser-produced view of a W3C VCALM 1.0 §3.6.1 workflow <c>authorization</c> object —
/// the OAuth2 authorization-scheme configuration a <see cref="VcalmWorkflowConfiguration"/> carries.
/// The specification's <c>authorization</c> object admits only the <c>oauth2</c> scheme this type
/// models; any other member is refused under §2.4 as an unknown option. The JSON-side parser
/// materializes it so the <c>Verifiable.Vcalm</c> serialization firewall keeps
/// <c>System.Text.Json</c> out of the library.
/// </summary>
/// <remarks>
/// §3.6.1: "authorization [object] An OPTIONAL property that specifies authorization scheme
/// information for the endpoint, such as an OAuth2 configuration. It MUST be an object of the
/// following form: oauth2 [object] OAuth2 configuration."
/// </remarks>
[DebuggerDisplay("VcalmWorkflowAuthorization OAuth2={OAuth2}")]
public sealed record VcalmWorkflowAuthorization
{
    /// <summary>
    /// The §3.6.1 <c>oauth2</c> member, or <see langword="null"/> when the workflow's
    /// <c>authorization</c> object carries no OAuth2 configuration.
    /// </summary>
    public VcalmOAuth2Authorization? OAuth2 { get; init; }
}


/// <summary>
/// The neutral, parser-produced view of a W3C VCALM 1.0 §3.6.1 <c>authorization.oauth2</c> object —
/// the OAuth2 configuration a coordinator's exchange requests are authorized against.
/// </summary>
/// <remarks>
/// <see href="https://www.w3.org/TR/vcalm-1.0/#create-workflow">VCALM 1.0 §3.6.1</see>: "oauth2
/// [object] OAuth2 configuration. It MUST be an object of the following form: issuerConfigUrl
/// [string] OAuth2 issuer config URL."
/// <see href="https://www.rfc-editor.org/rfc/rfc8414#section-3">RFC 8414 §3</see>: the authorization
/// server's metadata document "MUST use the 'https' scheme", so <see cref="IssuerConfigUrl"/> is
/// carried as an absolute <c>https</c> <see cref="System.Uri"/> rather than a bare string.
/// </remarks>
[DebuggerDisplay("VcalmOAuth2Authorization IssuerConfigUrl={IssuerConfigUrl}")]
public sealed record VcalmOAuth2Authorization
{
    /// <summary>
    /// The §3.6.1 <c>issuerConfigUrl</c> member — the OAuth2 issuer's metadata URL, an absolute
    /// <c>https</c> URL per RFC 8414 §3.
    /// </summary>
    public required Uri IssuerConfigUrl { get; init; }
}
