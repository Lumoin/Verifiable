using System.Diagnostics;
using System.Text;
using Verifiable.JCose;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.WellKnown;

namespace Verifiable.OAuth.Server.Pipeline;

/// <summary>
/// Conformance defects <see cref="ClientIdMetadataDocumentReader.Parse"/> detects in a fetched
/// Client ID Metadata Document per
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html">
/// draft-ietf-oauth-client-id-metadata-document-02</see>. A non-<see cref="None"/> value means the
/// document is not usable as client metadata; the resolver that owns network policy (
/// <c>ClientIdMetadataDocuments.BuildResolving</c>) maps any set flag to the
/// <c>ClientIdMetadataResolutionOutcome.InvalidDocument</c> outcome and never caches the result.
/// </summary>
[Flags]
public enum ClientIdMetadataDocumentDefects
{
    /// <summary>No defect — the document parsed as a conformant Client ID Metadata Document.</summary>
    None = 0,

    /// <summary>
    /// The document has no <c>client_id</c> property (draft-ietf-oauth-client-id-metadata-document-02
    /// §4, CIMD-013 — "The Client ID Metadata Document MUST contain a client_id property").
    /// </summary>
    MissingClientId = 1 << 0,

    /// <summary>
    /// The document carries a <c>client_secret</c> or <c>client_secret_expires_at</c> property
    /// (draft-ietf-oauth-client-id-metadata-document-02 §4.1, CIMD-022 — "the client_secret and
    /// client_secret_expires_at properties MUST NOT be used"). There is no way to establish a shared
    /// secret with a document served from a URL the client controls, so either property's presence is
    /// itself a conformance defect.
    /// </summary>
    ClientSecretFieldsPresent = 1 << 1,

    /// <summary>
    /// The document's <c>token_endpoint_auth_method</c> names a method based around a shared symmetric
    /// secret — <c>client_secret_post</c>, <c>client_secret_basic</c>, or <c>client_secret_jwt</c>
    /// (draft-ietf-oauth-client-id-metadata-document-02 §4.1, CIMD-021).
    /// </summary>
    SymmetricAuthMethod = 1 << 2,

    /// <summary>
    /// The document's <c>token_endpoint_auth_method</c> names a method
    /// <see cref="ClientAuthenticationMethodNames.TryParse"/> does not recognize. Rejected fail-closed:
    /// the authorization server cannot enforce
    /// draft-ietf-oauth-client-id-metadata-document-02 §8.2 (CIMD-049/CIMD-050) client authentication
    /// for a method it does not understand.
    /// </summary>
    UnknownAuthMethod = 1 << 3,

    /// <summary>
    /// The document's <c>jwks</c> contains a JWK carrying a private or symmetric member (<c>d</c>,
    /// <c>p</c>, <c>q</c>, <c>dp</c>, <c>dq</c>, <c>qi</c>, <c>oth</c>, or <c>k</c>)
    /// (draft-ietf-oauth-client-id-metadata-document-02 §4.1, CIMD-023 — "private key material MUST
    /// NOT be included in the Client ID Metadata Document; only public keys ... are permitted").
    /// </summary>
    PrivateKeyMaterialInJwks = 1 << 4,

    /// <summary>
    /// The document's <c>jwks_uri</c> is present but does not parse as an absolute <c>https</c> URI
    /// (draft-ietf-oauth-client-id-metadata-document-02 §8.6, CIMD-058).
    /// </summary>
    InvalidJwksUri = 1 << 5,

    /// <summary>
    /// The document's <c>logo_uri</c> is present but does not parse as an absolute <c>https</c> URI
    /// (draft-ietf-oauth-client-id-metadata-document-02 §8.6, CIMD-058 — rejects schemes such as
    /// <c>javascript:</c>).
    /// </summary>
    InvalidLogoUri = 1 << 6,

    /// <summary>
    /// The document's <c>client_uri</c> is present but does not parse as an absolute <c>https</c> URI
    /// (draft-ietf-oauth-client-id-metadata-document-02 §8.6, CIMD-058).
    /// </summary>
    InvalidClientUri = 1 << 7,

    /// <summary>
    /// One or more entries of the document's <c>redirect_uris</c> array do not parse as an absolute
    /// URI (draft-ietf-oauth-client-id-metadata-document-02 §4.2/§8.6, CIMD-058).
    /// </summary>
    InvalidRedirectUri = 1 << 8
}


/// <summary>
/// The outcome of <see cref="ClientIdMetadataDocumentReader.Parse"/>: the extracted <c>client_id</c>,
/// the best-effort parsed <see cref="ClientMetadata"/>, and every conformance defect found.
/// </summary>
/// <remarks>
/// <see cref="Metadata"/> is populated from every field present in the document regardless of
/// <see cref="Defects"/> — the reader never throws and never partially stops extraction on the first
/// defect, so a caller doing diagnostics sees the whole document. The resolver that owns network and
/// caching policy is the layer that decides a non-<see cref="ClientIdMetadataDocumentDefects.None"/>
/// result must not be used or cached.
/// </remarks>
public sealed record ClientIdMetadataDocumentReadResult
{
    /// <summary>The document's <c>client_id</c> property value, or <see langword="null"/> if absent.</summary>
    public string? ClientId { get; init; }

    /// <summary>The client metadata extracted from the document.</summary>
    public ClientMetadata? Metadata { get; init; }

    /// <summary>Every conformance defect <see cref="ClientIdMetadataDocumentReader.Parse"/> found.</summary>
    public ClientIdMetadataDocumentDefects Defects { get; init; }

    /// <summary>Whether <see cref="Defects"/> carries any flag.</summary>
    public bool HasDefects => Defects != ClientIdMetadataDocumentDefects.None;
}


/// <summary>
/// Span-based reader for a fetched Client ID Metadata Document per
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html">
/// draft-ietf-oauth-client-id-metadata-document-02</see> §4.
/// </summary>
/// <remarks>
/// <para>
/// Follows the <see cref="Oid4Vp.Server.WalletMetadataReader"/> precedent: UTF-8 span parsing on
/// <see cref="JwkJsonReader"/> primitives, not <c>System.Text.Json</c>. The CIMD-013/021/022/023/058
/// checks in <see cref="ClientIdMetadataDocumentDefects"/> are library obligations the resolver
/// enforces on every fetched document regardless of which JSON library an application wires into
/// <see cref="AuthorizationServerIntegration.ParseClientMetadataAsync"/> — that delegate parses RFC
/// 7591 registration request bodies, a distinct trust boundary from a document fetched from a URL the
/// client controls.
/// </para>
/// <para>
/// Field extraction beyond the defect checks is best-effort: an array entry or scalar this reader does
/// not recognize (an unknown <c>grant_types</c> or <c>response_types</c> wire value) is skipped rather
/// than treated as a defect, since draft-ietf-oauth-client-id-metadata-document-02 places no
/// conformance requirement on such fields.
/// </para>
/// </remarks>
[DebuggerDisplay("ClientIdMetadataDocumentReader")]
public static class ClientIdMetadataDocumentReader
{
    /// <summary>
    /// Parses a fetched Client ID Metadata Document, extracting <c>client_id</c>, every field
    /// <see cref="ClientMetadata"/> carries, and every conformance defect in
    /// <see cref="ClientIdMetadataDocumentDefects"/>.
    /// </summary>
    /// <param name="document">The document body as fetched, UTF-8 encoded.</param>
    public static ClientIdMetadataDocumentReadResult Parse(ReadOnlySpan<byte> document)
    {
        ClientIdMetadataDocumentDefects defects = ClientIdMetadataDocumentDefects.None;

        string? clientId = JwkJsonReader.ExtractStringValue(document, "client_id"u8);
        if(clientId is null)
        {
            defects |= ClientIdMetadataDocumentDefects.MissingClientId;
        }

        if(JwkJsonReader.ContainsKey(document, "client_secret"u8)
            || JwkJsonReader.ContainsKey(document, "client_secret_expires_at"u8))
        {
            defects |= ClientIdMetadataDocumentDefects.ClientSecretFieldsPresent;
        }

        (ClientAuthenticationMethod? tokenEndpointAuthMethod, ClientIdMetadataDocumentDefects authMethodDefect) =
            ExtractTokenEndpointAuthMethod(document);
        defects |= authMethodDefect;

        string? jwks = JwkJsonReader.ExtractObjectAsString(document, "jwks"u8);
        if(jwks is not null && JwksContainsPrivateOrSymmetricMember(Encoding.UTF8.GetBytes(jwks)))
        {
            defects |= ClientIdMetadataDocumentDefects.PrivateKeyMaterialInJwks;
        }

        (Uri? jwksUri, ClientIdMetadataDocumentDefects jwksUriDefect) =
            ExtractStrictHttpsUri(document, "jwks_uri"u8, ClientIdMetadataDocumentDefects.InvalidJwksUri);
        (Uri? logoUri, ClientIdMetadataDocumentDefects logoUriDefect) =
            ExtractStrictHttpsUri(document, "logo_uri"u8, ClientIdMetadataDocumentDefects.InvalidLogoUri);
        (Uri? clientUri, ClientIdMetadataDocumentDefects clientUriDefect) =
            ExtractStrictHttpsUri(document, "client_uri"u8, ClientIdMetadataDocumentDefects.InvalidClientUri);
        (List<Uri> redirectUris, ClientIdMetadataDocumentDefects redirectUriDefect) =
            ExtractAbsoluteUris(document, "redirect_uris"u8, ClientIdMetadataDocumentDefects.InvalidRedirectUri);
        (List<Uri> postLogoutRedirectUris, _) =
            ExtractAbsoluteUris(document, "post_logout_redirect_uris"u8, ClientIdMetadataDocumentDefects.None);

        defects |= jwksUriDefect | logoUriDefect | clientUriDefect | redirectUriDefect;

        ClientMetadata metadata = new()
        {
            ClientName = JwkJsonReader.ExtractStringValue(document, "client_name"u8),
            ClientUri = clientUri,
            LogoUri = logoUri,
            RedirectUris = redirectUris,
            GrantTypes = ExtractGrantTypes(document),
            ResponseTypes = ExtractResponseTypes(document),
            TokenEndpointAuthMethod = tokenEndpointAuthMethod,
            TokenEndpointAuthSigningAlg = JwkJsonReader.ExtractStringValue(document, "token_endpoint_auth_signing_alg"u8),
            Scope = JwkJsonReader.ExtractStringValue(document, "scope"u8),
            AuthorizationDetailsTypes = JwkJsonReader.ExtractStringArrayProperty(
                document, AuthorizationDetailsParameterNames.AuthorizationDetailsTypesUtf8),
            AuthorizationGrantProfilesSupported = JwkJsonReader.ExtractStringArrayProperty(
                document, AuthorizationServerMetadataParameterNames.AuthorizationGrantProfilesSupportedUtf8),
            JwksUri = jwksUri,
            Jwks = jwks,
            ApplicationType = JwkJsonReader.ExtractStringValue(document, "application_type"u8),
            IdTokenSignedResponseAlg = JwkJsonReader.ExtractStringValue(document, "id_token_signed_response_alg"u8),
            RequestObjectSigningAlg = JwkJsonReader.ExtractStringValue(document, "request_object_signing_alg"u8),
            RequestObjectEncryptionAlg = JwkJsonReader.ExtractStringValue(document, "request_object_encryption_alg"u8),
            PostLogoutRedirectUris = postLogoutRedirectUris,
            BackchannelLogoutUri = ExtractAbsoluteUri(document, "backchannel_logout_uri"u8),
            BackchannelLogoutSessionRequired = ExtractBoolean(document, "backchannel_logout_session_required"u8),
            FrontchannelLogoutUri = ExtractAbsoluteUri(document, "frontchannel_logout_uri"u8),
            FrontchannelLogoutSessionRequired = ExtractBoolean(document, "frontchannel_logout_session_required"u8),
            SoftwareStatement = JwkJsonReader.ExtractStringValue(document, "software_statement"u8)
        };

        return new ClientIdMetadataDocumentReadResult
        {
            ClientId = clientId,
            Metadata = metadata,
            Defects = defects
        };
    }


    private static (ClientAuthenticationMethod? Method, ClientIdMetadataDocumentDefects Defect) ExtractTokenEndpointAuthMethod(
        ReadOnlySpan<byte> document)
    {
        string? wireValue = JwkJsonReader.ExtractStringValue(document, "token_endpoint_auth_method"u8);
        if(wireValue is null)
        {
            return (null, ClientIdMetadataDocumentDefects.None);
        }

        return wireValue switch
        {
            _ when IsSymmetricAuthMethod(wireValue) =>
                (null, ClientIdMetadataDocumentDefects.SymmetricAuthMethod),
            _ when ClientAuthenticationMethodNames.TryParse(wireValue, out ClientAuthenticationMethod parsed) =>
                (parsed, ClientIdMetadataDocumentDefects.None),
            _ => (null, ClientIdMetadataDocumentDefects.UnknownAuthMethod)
        };
    }


    private static bool IsSymmetricAuthMethod(string wireValue) =>
        WellKnownClientAuthenticationMethods.IsClientSecretPost(wireValue)
        || WellKnownClientAuthenticationMethods.IsClientSecretBasic(wireValue)
        || WellKnownClientAuthenticationMethods.IsClientSecretJwt(wireValue);


    //Walks the "keys" array of a JWKS object's JSON text (braces included) and reports whether any
    //element carries a private or symmetric JWK member. Mirrors the array-walking pattern
    //JwkJsonReader.ExtractNestedStringValuesFromArray uses internally, composed here with
    //JwkJsonReader.GetTopLevelKeyNames (a JwkJsonReader primitive) per element since JwkJsonReader has
    //no existing primitive that returns member names for every element of an object array.
    private static bool JwksContainsPrivateOrSymmetricMember(ReadOnlySpan<byte> jwksDocument)
    {
        int keysStart = JwkJsonReader.IndexOfKey(jwksDocument, WellKnownJwkMemberNames.KeysUtf8);
        if(keysStart < 0)
        {
            return false;
        }

        int afterKeysKey = keysStart + WellKnownJwkMemberNames.KeysUtf8.Length + 1;
        afterKeysKey = JwkJsonReader.SkipWhitespaceAndColon(jwksDocument, afterKeysKey);
        if(afterKeysKey < 0 || afterKeysKey >= jwksDocument.Length || jwksDocument[afterKeysKey] != (byte)'[')
        {
            return false;
        }

        int cursor = afterKeysKey + 1;
        while(cursor < jwksDocument.Length)
        {
            while(cursor < jwksDocument.Length && IsArraySeparator(jwksDocument[cursor]))
            {
                cursor++;
            }

            if(cursor >= jwksDocument.Length || jwksDocument[cursor] == (byte)']')
            {
                return false;
            }

            if(jwksDocument[cursor] != (byte)'{')
            {
                return false;
            }

            int objectStart = cursor;
            int objectEnd = FindObjectEnd(jwksDocument, objectStart);
            if(objectEnd < 0)
            {
                return false;
            }

            List<string> memberNames = JwkJsonReader.GetTopLevelKeyNames(
                jwksDocument[(objectStart + 1)..(objectEnd - 1)]);
            if(WellKnownJwkMemberNames.ContainsPrivateOrSymmetricMember(memberNames))
            {
                return true;
            }

            cursor = objectEnd;
        }

        return false;
    }


    //Returns the index one past the '}' that closes the object opening at objectStart, or -1 when the
    //braces never balance. String content is skipped so a brace inside a quoted value never biases
    //the depth counter.
    private static int FindObjectEnd(ReadOnlySpan<byte> json, int objectStart)
    {
        int depth = 1;
        int pos = objectStart + 1;

        while(pos < json.Length && depth > 0)
        {
            byte current = json[pos];
            if(current == (byte)'{')
            {
                depth++;
            }
            else if(current == (byte)'}')
            {
                depth--;
            }
            else if(current == (byte)'"')
            {
                pos++;
                while(pos < json.Length && json[pos] != (byte)'"')
                {
                    if(json[pos] == (byte)'\\')
                    {
                        pos++;
                    }

                    pos++;
                }
            }

            pos++;
        }

        return depth == 0 ? pos : -1;
    }


    private static bool IsArraySeparator(byte value) =>
        value is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or (byte)',';


    //jwks_uri/logo_uri/client_uri (CIMD-058) are strict-https: a scheme mismatch — including
    //javascript: and every non-https scheme — is the defect, not merely a malformed URI string.
    private static (Uri? Value, ClientIdMetadataDocumentDefects Defect) ExtractStrictHttpsUri(
        ReadOnlySpan<byte> document, ReadOnlySpan<byte> key, ClientIdMetadataDocumentDefects invalidDefect)
    {
        string? raw = JwkJsonReader.ExtractStringValue(document, key);
        if(raw is null)
        {
            return (null, ClientIdMetadataDocumentDefects.None);
        }

        return Uri.TryCreate(raw, UriKind.Absolute, out Uri? uri) && uri.Scheme == Uri.UriSchemeHttps
            ? (uri, ClientIdMetadataDocumentDefects.None)
            : (null, invalidDefect);
    }


    //redirect_uris (CIMD-058) are shape-checked as absolute URIs, admitting https and the native custom
    //invocation schemes general OAuth clients use, but rejecting the dangerous pseudo-schemes §8.6 names
    //(javascript:) and their siblings (data:, vbscript:): those are never a legitimate redirect target and
    //a fetched document that carries one — which would then pass the exact-match redirect check and be
    //emitted as the authorization-response target — is treated as defective. post_logout_redirect_uris
    //reuses this with ClientIdMetadataDocumentDefects.None since this wave's ledger scope gates only
    //redirect_uris; a dangerous-scheme entry is still dropped rather than registered.
    private static (List<Uri> Values, ClientIdMetadataDocumentDefects Defect) ExtractAbsoluteUris(
        ReadOnlySpan<byte> document, ReadOnlySpan<byte> key, ClientIdMetadataDocumentDefects invalidEntryDefect)
    {
        List<string>? raw = JwkJsonReader.ExtractStringArrayProperty(document, key);
        if(raw is null)
        {
            return ([], ClientIdMetadataDocumentDefects.None);
        }

        List<Uri> uris = [];
        bool hasInvalidEntry = false;
        foreach(string entry in raw)
        {
            if(Uri.TryCreate(entry, UriKind.Absolute, out Uri? uri) && !IsDangerousScheme(uri.Scheme))
            {
                uris.Add(uri);
            }
            else
            {
                hasInvalidEntry = true;
            }
        }

        return (uris, hasInvalidEntry ? invalidEntryDefect : ClientIdMetadataDocumentDefects.None);
    }


    //draft-ietf-oauth-client-id-metadata-document-02 §8.6: the authorization server SHOULD only parse
    //URLs with known and supported URI schemes, naming javascript: as the compromise vector. These
    //script-bearing pseudo-schemes are rejected wherever a document URL could later be rendered or
    //dereferenced.
    private static bool IsDangerousScheme(string scheme) =>
        scheme.Equals("javascript", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("data", StringComparison.OrdinalIgnoreCase)
        || scheme.Equals("vbscript", StringComparison.OrdinalIgnoreCase);


    //Logout URIs carry no CIMD-058 defect gate in this wave's ledger scope; a malformed value is
    //simply omitted from the extracted metadata.
    private static Uri? ExtractAbsoluteUri(ReadOnlySpan<byte> document, ReadOnlySpan<byte> key)
    {
        string? raw = JwkJsonReader.ExtractStringValue(document, key);

        return raw is not null && Uri.TryCreate(raw, UriKind.Absolute, out Uri? uri) ? uri : null;
    }


    private static bool ExtractBoolean(ReadOnlySpan<byte> document, ReadOnlySpan<byte> key) =>
        JwkJsonReader.TryExtractBooleanValue(document, key, out bool value) && value;


    private static List<GrantType> ExtractGrantTypes(ReadOnlySpan<byte> document)
    {
        List<string>? raw = JwkJsonReader.ExtractStringArrayProperty(document, "grant_types"u8);
        if(raw is null)
        {
            return [];
        }

        List<GrantType> grantTypes = [];
        foreach(string wireValue in raw)
        {
            if(GrantTypeNames.TryParse(wireValue, out GrantType grantType))
            {
                grantTypes.Add(grantType);
            }
        }

        return grantTypes;
    }


    private static List<ResponseType> ExtractResponseTypes(ReadOnlySpan<byte> document)
    {
        List<string>? raw = JwkJsonReader.ExtractStringArrayProperty(document, "response_types"u8);
        if(raw is null)
        {
            return [];
        }

        List<ResponseType> responseTypes = [];
        foreach(string wireValue in raw)
        {
            if(ResponseTypeNames.TryParse(wireValue, out ResponseType responseType))
            {
                responseTypes.Add(responseType);
            }
        }

        return responseTypes;
    }
}
