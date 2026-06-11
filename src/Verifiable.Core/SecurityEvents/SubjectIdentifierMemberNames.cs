using System;
using Verifiable.Cryptography.Text;

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
    /// <summary>The UTF-8 source literal of <see cref="Format"/>.</summary>
    public static ReadOnlySpan<byte> FormatUtf8 => "format"u8;

    /// <summary>The reserved <c>format</c> member naming the Subject Identifier Format.</summary>
    public static readonly string Format = Utf8Constants.ToInternedString(FormatUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Uri"/>.</summary>
    public static ReadOnlySpan<byte> UriUtf8 => "uri"u8;

    /// <summary>The <c>uri</c> member (Account and URI formats).</summary>
    public static readonly string Uri = Utf8Constants.ToInternedString(UriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Email"/>.</summary>
    public static ReadOnlySpan<byte> EmailUtf8 => "email"u8;

    /// <summary>The <c>email</c> member (Email format).</summary>
    public static readonly string Email = Utf8Constants.ToInternedString(EmailUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Iss"/>.</summary>
    public static ReadOnlySpan<byte> IssUtf8 => "iss"u8;

    /// <summary>The <c>iss</c> member (Issuer-and-Subject and JWT-ID formats).</summary>
    public static readonly string Iss = Utf8Constants.ToInternedString(IssUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Sub"/>.</summary>
    public static ReadOnlySpan<byte> SubUtf8 => "sub"u8;

    /// <summary>The <c>sub</c> member (Issuer-and-Subject format).</summary>
    public static readonly string Sub = Utf8Constants.ToInternedString(SubUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Id"/>.</summary>
    public static ReadOnlySpan<byte> IdUtf8 => "id"u8;

    /// <summary>The <c>id</c> member (Opaque format).</summary>
    public static readonly string Id = Utf8Constants.ToInternedString(IdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PhoneNumber"/>.</summary>
    public static ReadOnlySpan<byte> PhoneNumberUtf8 => "phone_number"u8;

    /// <summary>The <c>phone_number</c> member (Phone Number format).</summary>
    public static readonly string PhoneNumber = Utf8Constants.ToInternedString(PhoneNumberUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Url"/>.</summary>
    public static ReadOnlySpan<byte> UrlUtf8 => "url"u8;

    /// <summary>The <c>url</c> member (DID format) — a DID or DID URL.</summary>
    public static readonly string Url = Utf8Constants.ToInternedString(UrlUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Identifiers"/>.</summary>
    public static ReadOnlySpan<byte> IdentifiersUtf8 => "identifiers"u8;

    /// <summary>The <c>identifiers</c> member (Aliases format) — an array of Subject Identifiers.</summary>
    public static readonly string Identifiers = Utf8Constants.ToInternedString(IdentifiersUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Jti"/>.</summary>
    public static ReadOnlySpan<byte> JtiUtf8 => "jti"u8;

    /// <summary>The <c>jti</c> member (JWT-ID format) — the identified JWT's <c>jti</c> claim.</summary>
    public static readonly string Jti = Utf8Constants.ToInternedString(JtiUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Issuer"/>.</summary>
    public static ReadOnlySpan<byte> IssuerUtf8 => "issuer"u8;

    /// <summary>The <c>issuer</c> member (SAML Assertion ID format) — the SAML assertion's Issuer.</summary>
    public static readonly string Issuer = Utf8Constants.ToInternedString(IssuerUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AssertionId"/>.</summary>
    public static ReadOnlySpan<byte> AssertionIdUtf8 => "assertion_id"u8;

    /// <summary>The <c>assertion_id</c> member (SAML Assertion ID format) — the SAML assertion's ID.</summary>
    public static readonly string AssertionId = Utf8Constants.ToInternedString(AssertionIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IpAddresses"/>.</summary>
    public static ReadOnlySpan<byte> IpAddressesUtf8 => "ip-addresses"u8;

    /// <summary>
    /// The <c>ip-addresses</c> member (IP Addresses format) — an array of IP-address strings.
    /// Hyphenated to match the (hyphenated) format name.
    /// </summary>
    public static readonly string IpAddresses = Utf8Constants.ToInternedString(IpAddressesUtf8);
}
