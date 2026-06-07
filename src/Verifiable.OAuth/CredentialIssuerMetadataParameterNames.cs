namespace Verifiable.OAuth;

/// <summary>
/// Well-known parameter NAMES for the OpenID for Verifiable Credential
/// Issuance (OID4VCI) credential-issuer metadata document. These are
/// JSON keys appearing in the credential issuer's metadata document.
/// </summary>
/// <remarks>
/// These are the NAMES of credential-issuer metadata parameters (e.g.,
/// <c>"credential_endpoint"</c>, <c>"deferred_credential_endpoint"</c>),
/// not their VALUES. Values are deployment-specific URLs.
/// </remarks>
public static class CredentialIssuerMetadataParameterNames
{
    /// <summary>
    /// URL of the credential issuer's credential endpoint.
    /// </summary>
    public static readonly string CredentialEndpoint = "credential_endpoint";

    /// <summary>
    /// URL of the credential issuer's batch credential endpoint.
    /// </summary>
    public static readonly string BatchCredentialEndpoint = "batch_credential_endpoint";

    /// <summary>
    /// URL of the credential issuer's deferred credential endpoint.
    /// </summary>
    public static readonly string DeferredCredentialEndpoint = "deferred_credential_endpoint";

    /// <summary>
    /// URL of the credential issuer's notification endpoint.
    /// </summary>
    public static readonly string NotificationEndpoint = "notification_endpoint";
}
