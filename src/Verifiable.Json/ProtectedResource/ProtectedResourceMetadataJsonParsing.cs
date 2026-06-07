using System;
using System.Text.Json;
using Verifiable.OAuth.ProtectedResource;

namespace Verifiable.Json;

/// <summary>
/// Default <c>System.Text.Json</c> parser for the OAuth 2.0 Protected Resource
/// Metadata document (<c>/.well-known/oauth-protected-resource</c>, RFC 9728
/// §3.2) — the JSON side the <c>Verifiable.OAuth</c> serialization firewall
/// keeps out of the library.
/// </summary>
/// <remarks>
/// <para>
/// Parsing is <strong>faithful and strict</strong>: it reads with
/// <see cref="JsonDocument"/> so string values stay strings. <c>resource</c>
/// is required (§2); a body that is not a JSON object, lacks <c>resource</c>,
/// or carries a wrongly-typed known field yields <see langword="null"/>.
/// Metadata parameters that are not understood are ignored per §3.2. It never
/// throws to the caller.
/// </para>
/// <para>
/// Parsing does not validate: the consumer MUST still run the §3.3 checks —
/// <see cref="ProtectedResourceMetadataValidation.IsResourceMatch"/> against
/// the identifier the metadata URL was derived from, and signature
/// verification of any <c>signed_metadata</c> it intends to honour.
/// </para>
/// </remarks>
public static class ProtectedResourceMetadataJsonParsing
{
    /// <summary>
    /// Parses a Protected Resource Metadata document. Returns
    /// <see langword="null"/> on any structural or conformance failure.
    /// </summary>
    /// <param name="metadataJson">The fetched metadata document.</param>
    public static ProtectedResourceMetadata? ParseProtectedResourceMetadata(string metadataJson)
    {
        ArgumentNullException.ThrowIfNull(metadataJson);

        try
        {
            using JsonDocument document = JsonDocument.Parse(metadataJson, SsfJsonReadHelpers.DocumentOptions);
            JsonElement root = document.RootElement;
            if(root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            string? resource = SsfJsonReadHelpers.ReadOptionalString(root, ProtectedResourceMetadataParameterNames.Resource);
            if(string.IsNullOrEmpty(resource))
            {
                return null;
            }

            return new ProtectedResourceMetadata
            {
                Resource = resource,
                AuthorizationServers = SsfJsonReadHelpers.ReadStringArray(root, ProtectedResourceMetadataParameterNames.AuthorizationServers),
                JwksUri = SsfJsonReadHelpers.ReadOptionalString(root, ProtectedResourceMetadataParameterNames.JwksUri),
                ScopesSupported = SsfJsonReadHelpers.ReadStringArray(root, ProtectedResourceMetadataParameterNames.ScopesSupported),
                BearerMethodsSupported = SsfJsonReadHelpers.ReadStringArray(root, ProtectedResourceMetadataParameterNames.BearerMethodsSupported),
                ResourceSigningAlgValuesSupported = SsfJsonReadHelpers.ReadStringArray(root, ProtectedResourceMetadataParameterNames.ResourceSigningAlgValuesSupported),
                ResourceName = SsfJsonReadHelpers.ReadOptionalString(root, ProtectedResourceMetadataParameterNames.ResourceName),
                ResourceDocumentation = SsfJsonReadHelpers.ReadOptionalString(root, ProtectedResourceMetadataParameterNames.ResourceDocumentation),
                ResourcePolicyUri = SsfJsonReadHelpers.ReadOptionalString(root, ProtectedResourceMetadataParameterNames.ResourcePolicyUri),
                ResourceTosUri = SsfJsonReadHelpers.ReadOptionalString(root, ProtectedResourceMetadataParameterNames.ResourceTosUri),
                TlsClientCertificateBoundAccessTokens = SsfJsonReadHelpers.ReadOptionalBool(root, ProtectedResourceMetadataParameterNames.TlsClientCertificateBoundAccessTokens),
                AuthorizationDetailsTypesSupported = SsfJsonReadHelpers.ReadStringArray(root, ProtectedResourceMetadataParameterNames.AuthorizationDetailsTypesSupported),
                DpopSigningAlgValuesSupported = SsfJsonReadHelpers.ReadStringArray(root, ProtectedResourceMetadataParameterNames.DpopSigningAlgValuesSupported),
                DpopBoundAccessTokensRequired = SsfJsonReadHelpers.ReadOptionalBool(root, ProtectedResourceMetadataParameterNames.DpopBoundAccessTokensRequired),
                SignedMetadata = SsfJsonReadHelpers.ReadOptionalString(root, ProtectedResourceMetadataParameterNames.SignedMetadata)
            };
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }
}
