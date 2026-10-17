using System.Text.Json;
using System.Text.Unicode;
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

            return ReadDocument(document.RootElement);
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    /// <summary>
    /// Parses a Protected Resource Metadata document from its original UTF-8 bytes, by the same strict reading as
    /// <see cref="ParseProtectedResourceMetadata(string)"/>: <see langword="null"/> for a body that is not valid UTF-8,
    /// is not a JSON object, lacks <c>resource</c> or carries a wrongly-typed known field; a member the reading does not
    /// know is ignored (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-3.2">RFC 9728 Section 3.2</see>: "any
    /// metadata parameters that are not understood MUST be ignored"). The implementation of
    /// <see cref="ParseProtectedResourceMetadataDelegate"/>. It never throws to the caller.
    /// </summary>
    /// <param name="document">The fetched metadata document, the response body's original bytes.</param>
    /// <returns>The document as read, or <see langword="null"/> on any structural or conformance failure.</returns>
    public static ProtectedResourceMetadata? ParseProtectedResourceMetadata(ReadOnlyMemory<byte> document)
    {
        //RFC 8259 Section 8.1: "JSON text exchanged between systems that are not part of a closed ecosystem MUST be
        //encoded using UTF-8". The reader decodes only the strings the reading asks for, so the whole body is checked
        //here, an invalid octet in a member the reading never reads included.
        if(!Utf8.IsValid(document.Span))
        {
            return null;
        }

        try
        {
            //The body is valid UTF-8; the reader holds it to the JSON grammar under the shared options (no comment, no
            //trailing comma, a depth of at most 32) and raises a JsonException on any departure.
            using JsonDocument parsed = JsonDocument.Parse(document, SsfJsonReadHelpers.DocumentOptions);

            return ReadDocument(parsed.RootElement);
        }
        catch(Exception ex) when(SsfJsonReadHelpers.IsParseFailure(ex))
        {
            return null;
        }
    }


    /// <summary>
    /// Reads the members of a parsed Protected Resource Metadata document, the one strict reading both overloads share:
    /// <see langword="null"/> for a root that is not a JSON object or that lacks a non-empty <c>resource</c>
    /// (<see href="https://www.rfc-editor.org/rfc/rfc9728#section-2">RFC 9728 Section 2</see>: "resource REQUIRED."); a
    /// known member of the wrong type raises the parse failure the callers turn into <see langword="null"/>; every member
    /// it does not know is left unread.
    /// </summary>
    /// <param name="root">The document's root element.</param>
    /// <returns>The document as read, or <see langword="null"/>.</returns>
    private static ProtectedResourceMetadata? ReadDocument(JsonElement root)
    {
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
}
