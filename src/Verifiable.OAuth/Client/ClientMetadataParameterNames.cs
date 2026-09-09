using System.Diagnostics.CodeAnalysis;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Client;

/// <summary>
/// Client metadata member NAMES a Client ID Metadata Document, an RFC 7591 registration
/// request/response body, or a software statement is made of, per
/// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2">RFC 7591, Section 2</see>
/// (the request/response fields), <see href="https://www.rfc-editor.org/rfc/rfc7591#section-2.3">
/// RFC 7591, Section 2.3</see> (the software statement) and
/// <see href="https://www.rfc-editor.org/rfc/rfc7591#section-3.2.1">RFC 7591, Section 3.2.1</see>
/// (the server-issued identity fields). Every reader or writer of one of these members —
/// <c>ClientIdMetadataDocumentReader</c>, <c>DynamicRegistrationHandlers</c>,
/// <c>RegistrationEndpoints</c> — spells it through this table rather than an inline UTF-8 or
/// interned-string literal, so the wire spelling has one home.
/// </summary>
public static class ClientMetadataParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="RedirectUris"/>.</summary>
    public static ReadOnlySpan<byte> RedirectUrisUtf8 => "redirect_uris"u8;

    /// <summary>
    /// RFC 7591, Section 2: array of redirection URI strings for use in redirect-based flows
    /// such as the authorization code and implicit flows.
    /// </summary>
    public static string RedirectUris { get; } = Utf8Constants.ToInternedString(RedirectUrisUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>redirect_uris</c>.</summary>
    public static bool IsRedirectUris(string value) =>
        string.Equals(value, RedirectUris, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="TokenEndpointAuthMethod"/>.</summary>
    public static ReadOnlySpan<byte> TokenEndpointAuthMethodUtf8 => "token_endpoint_auth_method"u8;

    /// <summary>
    /// RFC 7591, Section 2: string indicator of the requested authentication method for the
    /// token endpoint (<c>none</c>, <c>client_secret_post</c>, <c>client_secret_basic</c>, or a
    /// value from the IANA OAuth Token Endpoint Authentication Methods registry).
    /// </summary>
    public static string TokenEndpointAuthMethod { get; } = Utf8Constants.ToInternedString(TokenEndpointAuthMethodUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>token_endpoint_auth_method</c>.</summary>
    public static bool IsTokenEndpointAuthMethod(string value) =>
        string.Equals(value, TokenEndpointAuthMethod, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="GrantTypes"/>.</summary>
    public static ReadOnlySpan<byte> GrantTypesUtf8 => "grant_types"u8;

    /// <summary>
    /// RFC 7591, Section 2: array of OAuth 2.0 grant type strings that the client can use at
    /// the token endpoint.
    /// </summary>
    public static string GrantTypes { get; } = Utf8Constants.ToInternedString(GrantTypesUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>grant_types</c>.</summary>
    public static bool IsGrantTypes(string value) =>
        string.Equals(value, GrantTypes, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="ResponseTypes"/>.</summary>
    public static ReadOnlySpan<byte> ResponseTypesUtf8 => "response_types"u8;

    /// <summary>
    /// RFC 7591, Section 2: array of the OAuth 2.0 response type strings that the client can
    /// use at the authorization endpoint.
    /// </summary>
    public static string ResponseTypes { get; } = Utf8Constants.ToInternedString(ResponseTypesUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>response_types</c>.</summary>
    public static bool IsResponseTypes(string value) =>
        string.Equals(value, ResponseTypes, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="ClientName"/>.</summary>
    public static ReadOnlySpan<byte> ClientNameUtf8 => "client_name"u8;

    /// <summary>
    /// RFC 7591, Section 2: human-readable string name of the client to be presented to the
    /// end-user during authorization.
    /// </summary>
    public static string ClientName { get; } = Utf8Constants.ToInternedString(ClientNameUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>client_name</c>.</summary>
    public static bool IsClientName(string value) =>
        string.Equals(value, ClientName, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="ClientUri"/>.</summary>
    public static ReadOnlySpan<byte> ClientUriUtf8 => "client_uri"u8;

    /// <summary>
    /// RFC 7591, Section 2: URL string of a web page providing information about the client.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "This member is the JSON claim NAME literal 'client_uri' (a wire key compared and serialised as a string), not a dereferenceable System.Uri.")]
    public static string ClientUri { get; } = Utf8Constants.ToInternedString(ClientUriUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>client_uri</c>.</summary>
    public static bool IsClientUri(string value) =>
        string.Equals(value, ClientUri, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="LogoUri"/>.</summary>
    public static ReadOnlySpan<byte> LogoUriUtf8 => "logo_uri"u8;

    /// <summary>
    /// RFC 7591, Section 2: URL string that references a logo for the client.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "This member is the JSON claim NAME literal 'logo_uri' (a wire key compared and serialised as a string), not a dereferenceable System.Uri.")]
    public static string LogoUri { get; } = Utf8Constants.ToInternedString(LogoUriUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>logo_uri</c>.</summary>
    public static bool IsLogoUri(string value) =>
        string.Equals(value, LogoUri, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="Scope"/>.</summary>
    public static ReadOnlySpan<byte> ScopeUtf8 => "scope"u8;

    /// <summary>
    /// RFC 7591, Section 2: string containing a space-separated list of scope values that the
    /// client can use when requesting access tokens.
    /// </summary>
    public static string Scope { get; } = Utf8Constants.ToInternedString(ScopeUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>scope</c>.</summary>
    public static bool IsScope(string value) =>
        string.Equals(value, Scope, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="Contacts"/>.</summary>
    public static ReadOnlySpan<byte> ContactsUtf8 => "contacts"u8;

    /// <summary>
    /// RFC 7591, Section 2: array of strings representing ways to contact people responsible
    /// for the client, typically email addresses.
    /// </summary>
    public static string Contacts { get; } = Utf8Constants.ToInternedString(ContactsUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>contacts</c>.</summary>
    public static bool IsContacts(string value) =>
        string.Equals(value, Contacts, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="TosUri"/>.</summary>
    public static ReadOnlySpan<byte> TosUriUtf8 => "tos_uri"u8;

    /// <summary>
    /// RFC 7591, Section 2: URL string that points to a human-readable terms of service
    /// document for the client.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "This member is the JSON claim NAME literal 'tos_uri' (a wire key compared and serialised as a string), not a dereferenceable System.Uri.")]
    public static string TosUri { get; } = Utf8Constants.ToInternedString(TosUriUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>tos_uri</c>.</summary>
    public static bool IsTosUri(string value) =>
        string.Equals(value, TosUri, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="PolicyUri"/>.</summary>
    public static ReadOnlySpan<byte> PolicyUriUtf8 => "policy_uri"u8;

    /// <summary>
    /// RFC 7591, Section 2: URL string that points to a human-readable privacy policy document
    /// describing how the deployment organization collects, uses, retains, and discloses
    /// personal data.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "This member is the JSON claim NAME literal 'policy_uri' (a wire key compared and serialised as a string), not a dereferenceable System.Uri.")]
    public static string PolicyUri { get; } = Utf8Constants.ToInternedString(PolicyUriUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>policy_uri</c>.</summary>
    public static bool IsPolicyUri(string value) =>
        string.Equals(value, PolicyUri, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="JwksUri"/>.</summary>
    public static ReadOnlySpan<byte> JwksUriUtf8 => "jwks_uri"u8;

    /// <summary>
    /// RFC 7591, Section 2: URL string referencing the client's JSON Web Key Set document,
    /// which contains the client's public keys. Mutually exclusive with <see cref="Jwks"/>.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "This member is the JSON claim NAME literal 'jwks_uri' (a wire key compared and serialised as a string), not a dereferenceable System.Uri.")]
    public static string JwksUri { get; } = Utf8Constants.ToInternedString(JwksUriUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>jwks_uri</c>.</summary>
    public static bool IsJwksUri(string value) =>
        string.Equals(value, JwksUri, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="Jwks"/>.</summary>
    public static ReadOnlySpan<byte> JwksUtf8 => "jwks"u8;

    /// <summary>
    /// RFC 7591, Section 2: the client's JSON Web Key Set document value, containing the
    /// client's public keys. Mutually exclusive with <see cref="JwksUri"/>.
    /// </summary>
    public static string Jwks { get; } = Utf8Constants.ToInternedString(JwksUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>jwks</c>.</summary>
    public static bool IsJwks(string value) =>
        string.Equals(value, Jwks, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="SoftwareId"/>.</summary>
    public static ReadOnlySpan<byte> SoftwareIdUtf8 => "software_id"u8;

    /// <summary>
    /// RFC 7591, Section 2: a unique identifier string assigned by the client developer or
    /// software publisher, identifying the client software across registered instances.
    /// </summary>
    public static string SoftwareId { get; } = Utf8Constants.ToInternedString(SoftwareIdUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>software_id</c>.</summary>
    public static bool IsSoftwareId(string value) =>
        string.Equals(value, SoftwareId, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="SoftwareVersion"/>.</summary>
    public static ReadOnlySpan<byte> SoftwareVersionUtf8 => "software_version"u8;

    /// <summary>
    /// RFC 7591, Section 2: a version identifier string for the client software identified by
    /// <see cref="SoftwareId"/>.
    /// </summary>
    public static string SoftwareVersion { get; } = Utf8Constants.ToInternedString(SoftwareVersionUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>software_version</c>.</summary>
    public static bool IsSoftwareVersion(string value) =>
        string.Equals(value, SoftwareVersion, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="SoftwareStatement"/>.</summary>
    public static ReadOnlySpan<byte> SoftwareStatementUtf8 => "software_statement"u8;

    /// <summary>
    /// RFC 7591, Section 3.1.1: a software statement containing client metadata values about
    /// the client software as claims — a string value carrying the entire signed JWT (Section
    /// 2.3 defines the software statement's own shape and signing requirement).
    /// </summary>
    public static string SoftwareStatement { get; } = Utf8Constants.ToInternedString(SoftwareStatementUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>software_statement</c>.</summary>
    public static bool IsSoftwareStatement(string value) =>
        string.Equals(value, SoftwareStatement, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="ClientId"/>.</summary>
    public static ReadOnlySpan<byte> ClientIdUtf8 => "client_id"u8;

    /// <summary>
    /// RFC 7591, Section 3.2.1: REQUIRED. The OAuth 2.0 client identifier string issued by the
    /// authorization server.
    /// </summary>
    public static string ClientId { get; } = Utf8Constants.ToInternedString(ClientIdUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>client_id</c>.</summary>
    public static bool IsClientId(string value) =>
        string.Equals(value, ClientId, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="ClientSecret"/>.</summary>
    public static ReadOnlySpan<byte> ClientSecretUtf8 => "client_secret"u8;

    /// <summary>
    /// RFC 7591, Section 3.2.1: OPTIONAL. The OAuth 2.0 client secret string a confidential
    /// client uses to authenticate to the token endpoint.
    /// </summary>
    public static string ClientSecret { get; } = Utf8Constants.ToInternedString(ClientSecretUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>client_secret</c>.</summary>
    public static bool IsClientSecret(string value) =>
        string.Equals(value, ClientSecret, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="ClientIdIssuedAt"/>.</summary>
    public static ReadOnlySpan<byte> ClientIdIssuedAtUtf8 => "client_id_issued_at"u8;

    /// <summary>
    /// RFC 7591, Section 3.2.1: OPTIONAL. The time the client identifier was issued, as seconds
    /// since 1970-01-01T00:00:00Z UTC.
    /// </summary>
    public static string ClientIdIssuedAt { get; } = Utf8Constants.ToInternedString(ClientIdIssuedAtUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>client_id_issued_at</c>.</summary>
    public static bool IsClientIdIssuedAt(string value) =>
        string.Equals(value, ClientIdIssuedAt, StringComparison.Ordinal);


    /// <summary>The UTF-8 source literal of <see cref="ClientSecretExpiresAt"/>.</summary>
    public static ReadOnlySpan<byte> ClientSecretExpiresAtUtf8 => "client_secret_expires_at"u8;

    /// <summary>
    /// RFC 7591, Section 3.2.1: REQUIRED if <see cref="ClientSecret"/> is issued. The time the
    /// client secret will expire, or 0 if it will not expire, as seconds since
    /// 1970-01-01T00:00:00Z UTC.
    /// </summary>
    public static string ClientSecretExpiresAt { get; } = Utf8Constants.ToInternedString(ClientSecretExpiresAtUtf8);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly
    /// <c>client_secret_expires_at</c>.</summary>
    public static bool IsClientSecretExpiresAt(string value) =>
        string.Equals(value, ClientSecretExpiresAt, StringComparison.Ordinal);
}
