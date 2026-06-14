using System.Diagnostics;
using Verifiable.Server;

namespace Verifiable.OAuth.Oid4Vci;

/// <summary>
/// Application-supplied values for the OID4VCI 1.0 §12.2 Credential Issuer Metadata document —
/// everything the library cannot derive from the endpoint chain. Returned from the
/// <see cref="Server.ContributeCredentialIssuerMetadataDelegate"/> seam. The library derives
/// <c>credential_issuer</c> (the resolved issuer identity), <c>credential_endpoint</c>, and
/// <c>nonce_endpoint</c> (read off the chain) itself.
/// </summary>
/// <remarks>
/// <para>
/// The open-ended §12.2.4 structures — <c>credential_configurations_supported</c> (with its
/// format-specific <c>format</c> / <c>scope</c> / <c>proof_types_supported</c> / <c>display</c>
/// / <c>claims</c> sub-objects), <c>display</c>, and <c>batch_credential_issuance</c> — are
/// carried as structured object trees (<see cref="System.Collections.Generic.Dictionary{TKey,TValue}"/>
/// of <see cref="string"/> to <see cref="object"/>, and lists of the same). The library walks
/// them through <c>JsonAppender</c> for the plain document and threads the same values into the
/// signed-metadata claim set, so the two cannot diverge — and the <c>Verifiable.OAuth</c>
/// serialization firewall is preserved (no <c>System.Text.Json</c> reaches the library).
/// </para>
/// <para>
/// A <see langword="null"/> member simply does not appear on the wire, except
/// <see cref="CredentialConfigurationsSupported"/>, which §12.2.4 marks REQUIRED — the endpoint
/// emits an empty object rather than omit it when the contribution leaves it unset.
/// </para>
/// </remarks>
[DebuggerDisplay("CredentialIssuerMetadataContribution Configurations={CredentialConfigurationsSupported?.Count}")]
public sealed record CredentialIssuerMetadataContribution
{
    /// <summary>The empty contribution — only the derivable members (and an empty configurations object) are emitted.</summary>
    public static CredentialIssuerMetadataContribution Empty { get; } = new();

    /// <summary>
    /// The §12.2.4 <c>credential_configurations_supported</c> (REQUIRED): a map from each
    /// supported Credential Configuration identifier to its metadata object tree.
    /// </summary>
    public IReadOnlyDictionary<string, object>? CredentialConfigurationsSupported { get; init; }

    /// <summary>The §12.2.4 <c>authorization_servers</c> identifiers (OPTIONAL).</summary>
    public IReadOnlyList<string>? AuthorizationServers { get; init; }

    /// <summary>The §12.2.4 <c>display</c> array of per-language Credential Issuer display objects (OPTIONAL).</summary>
    public IReadOnlyList<object>? Display { get; init; }

    /// <summary>The §12.2.4 <c>batch_credential_issuance</c> object (OPTIONAL).</summary>
    public IReadOnlyDictionary<string, object>? BatchCredentialIssuance { get; init; }

    /// <summary>
    /// The §12.2.4 <c>credential_request_encryption</c> object (OPTIONAL): the Issuer's
    /// request-encryption support — <c>jwks</c>, <c>enc_values_supported</c>,
    /// <c>zip_values_supported</c>, <c>encryption_required</c>. Application data: the keys and
    /// the algorithm policy live with the deployment's
    /// <see cref="Server.AuthorizationServerIntegration.DecryptCredentialRequestAsync"/> seam.
    /// </summary>
    public IReadOnlyDictionary<string, object>? CredentialRequestEncryption { get; init; }

    /// <summary>
    /// The §12.2.4 <c>credential_response_encryption</c> object (OPTIONAL): the Issuer's
    /// response-encryption support — <c>alg_values_supported</c>, <c>enc_values_supported</c>,
    /// <c>zip_values_supported</c>, <c>encryption_required</c>. Application data: the algorithm
    /// policy lives with the deployment's
    /// <see cref="Server.AuthorizationServerIntegration.EncryptCredentialResponseAsync"/> seam.
    /// </summary>
    public IReadOnlyDictionary<string, object>? CredentialResponseEncryption { get; init; }
}
