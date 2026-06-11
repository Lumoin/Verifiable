using Verifiable.Cryptography.Text;


namespace Verifiable.OAuth;

/// <summary>
/// Well-known JSON member NAMES inside an RFC 9396 authorization details object — the common
/// data fields every authorization details type shares per
/// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2.2">RFC 9396 §2/§2.2</see>.
/// The <c>authorization_details</c> request/response parameter name itself lives in
/// <see cref="OAuthRequestParameterNames.AuthorizationDetails"/>; type-specific fields live
/// with their type (for <c>openid_credential</c>, in
/// <see cref="Oid4Vci.Oid4VciCredentialParameterNames"/>).
/// </summary>
public static class AuthorizationDetailsParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="Type"/>.</summary>
    public static ReadOnlySpan<byte> TypeUtf8 => "type"u8;

    /// <summary>
    /// <c>type</c> — REQUIRED (RFC 9396 §2). The authorization details type that determines
    /// the object's allowable contents; see <see cref="AuthorizationDetailsTypeValues"/>.
    /// </summary>
    public static readonly string Type = Utf8Constants.ToInternedString(TypeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Locations"/>.</summary>
    public static ReadOnlySpan<byte> LocationsUtf8 => "locations"u8;

    /// <summary>
    /// <c>locations</c> — OPTIONAL common field (RFC 9396 §2.2). The resource server(s) the
    /// authorization applies to. OID4VCI 1.0 §5.1.1: MUST be set to the Credential Issuer
    /// Identifier when the Credential Issuer metadata carries <c>authorization_servers</c>.
    /// </summary>
    public static readonly string Locations = Utf8Constants.ToInternedString(LocationsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Actions"/>.</summary>
    public static ReadOnlySpan<byte> ActionsUtf8 => "actions"u8;

    /// <summary>
    /// <c>actions</c> — OPTIONAL common field (RFC 9396 §2.2). An array of strings naming the
    /// kinds of actions to be taken at the resource.
    /// </summary>
    public static readonly string Actions = Utf8Constants.ToInternedString(ActionsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DataTypes"/>.</summary>
    public static ReadOnlySpan<byte> DataTypesUtf8 => "datatypes"u8;

    /// <summary>
    /// <c>datatypes</c> — OPTIONAL common field (RFC 9396 §2.2). An array of strings naming the
    /// kinds of data being requested from the resource.
    /// </summary>
    public static readonly string DataTypes = Utf8Constants.ToInternedString(DataTypesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Identifier"/>.</summary>
    public static ReadOnlySpan<byte> IdentifierUtf8 => "identifier"u8;

    /// <summary>
    /// <c>identifier</c> — OPTIONAL common field (RFC 9396 §2.2). A string identifying a
    /// specific resource available at the API.
    /// </summary>
    public static readonly string Identifier = Utf8Constants.ToInternedString(IdentifierUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Privileges"/>.</summary>
    public static ReadOnlySpan<byte> PrivilegesUtf8 => "privileges"u8;

    /// <summary>
    /// <c>privileges</c> — OPTIONAL common field (RFC 9396 §2.2). An array of strings naming the
    /// types or levels of privilege being requested at the resource.
    /// </summary>
    public static readonly string Privileges = Utf8Constants.ToInternedString(PrivilegesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationDetailsTypes"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationDetailsTypesUtf8 => "authorization_details_types"u8;

    /// <summary>
    /// <c>authorization_details_types</c> — the client registration metadata parameter a client
    /// uses to indicate the authorization details types it will use, a JSON array, per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-10">RFC 9396 §10</see> and
    /// registered in the IANA OAuth Dynamic Client Registration Metadata registry by
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-14.5">RFC 9396 §14.5</see>
    /// ("Indicates what authorization details types the client uses."). The matching AS metadata
    /// parameter advertising the server's supported types is
    /// <see cref="AuthorizationServerMetadataParameterNames.AuthorizationDetailsTypesSupported"/>.
    /// </summary>
    public static readonly string AuthorizationDetailsTypes = Utf8Constants.ToInternedString(AuthorizationDetailsTypesUtf8);


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>authorization_details_types</c>, the RFC 9396 §10/§14.5 client registration metadata
    /// parameter name.
    /// </summary>
    /// <param name="value">The candidate JSON member name.</param>
    /// <returns><see langword="true"/> on an exact ordinal match; otherwise <see langword="false"/>.</returns>
    public static bool IsAuthorizationDetailsTypes(string value) =>
        string.Equals(value, AuthorizationDetailsTypes, StringComparison.Ordinal);
}


/// <summary>
/// The authorization details <c>type</c> values the library processes.
/// </summary>
public static class AuthorizationDetailsTypeValues
{
    /// <summary>The UTF-8 source literal of <see cref="OpenIdCredential"/>.</summary>
    public static ReadOnlySpan<byte> OpenIdCredentialUtf8 => "openid_credential"u8;

    /// <summary>
    /// <c>openid_credential</c> — requests authorization to issue a Credential of a
    /// <c>credential_configuration_id</c>, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html">OID4VCI 1.0 §5.1.1</see>.
    /// </summary>
    public static readonly string OpenIdCredential = Utf8Constants.ToInternedString(OpenIdCredentialUtf8);
}
