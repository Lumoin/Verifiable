namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The member NAMES (JSON object keys) that appear inside a Subject Identifier,
/// across all formats defined by
/// <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3">RFC 9493 §3</see>
/// and OpenID Shared Signals Framework 1.0 §3.5.
/// </summary>
/// <remarks>
/// These are NAMES, not values; the format VALUES that select which members
/// apply live in <see cref="SubjectIdentifierFormats"/>. Several names
/// (<c>iss</c>, <c>sub</c>, <c>jti</c>) are defined by reference to RFC 7519 but
/// are reproduced here because, inside a Subject Identifier, they are members of
/// the identifier object rather than top-level JWT claims.
/// </remarks>
public static class SubjectIdentifierMemberNames
{
    /// <summary>The reserved <c>format</c> member naming the Subject Identifier Format.</summary>
    public static readonly string Format = "format";

    /// <summary>The <c>uri</c> member (Account and URI formats).</summary>
    public static readonly string Uri = "uri";

    /// <summary>The <c>email</c> member (Email format).</summary>
    public static readonly string Email = "email";

    /// <summary>The <c>iss</c> member (Issuer-and-Subject and JWT-ID formats).</summary>
    public static readonly string Iss = "iss";

    /// <summary>The <c>sub</c> member (Issuer-and-Subject format).</summary>
    public static readonly string Sub = "sub";

    /// <summary>The <c>id</c> member (Opaque format).</summary>
    public static readonly string Id = "id";

    /// <summary>The <c>phone_number</c> member (Phone Number format).</summary>
    public static readonly string PhoneNumber = "phone_number";

    /// <summary>The <c>url</c> member (DID format) — a DID or DID URL.</summary>
    public static readonly string Url = "url";

    /// <summary>The <c>identifiers</c> member (Aliases format) — an array of Subject Identifiers.</summary>
    public static readonly string Identifiers = "identifiers";

    /// <summary>The <c>jti</c> member (JWT-ID format) — the identified JWT's <c>jti</c> claim.</summary>
    public static readonly string Jti = "jti";

    /// <summary>The <c>issuer</c> member (SAML Assertion ID format) — the SAML assertion's Issuer.</summary>
    public static readonly string Issuer = "issuer";

    /// <summary>The <c>assertion_id</c> member (SAML Assertion ID format) — the SAML assertion's ID.</summary>
    public static readonly string AssertionId = "assertion_id";

    /// <summary>
    /// The <c>ip-addresses</c> member (IP Addresses format) — an array of IP-address strings.
    /// Hyphenated to match the (hyphenated) format name.
    /// </summary>
    public static readonly string IpAddresses = "ip-addresses";
}
