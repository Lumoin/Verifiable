using System;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The <c>format</c> VALUES that name a Subject Identifier Format — the names a
/// Subject Identifier's <c>format</c> member carries to declare which schema its
/// remaining members follow.
/// </summary>
/// <remarks>
/// <para>
/// The first eight are the IANA-registered formats defined by
/// <see href="https://www.rfc-editor.org/rfc/rfc9493">RFC 9493 §3</see>; the last
/// three are added by OpenID Shared Signals Framework 1.0 §3.5. These are NAMES
/// (the <c>format</c> value), not the member names that accompany them — those
/// live in <see cref="SubjectIdentifierMemberNames"/>.
/// </para>
/// </remarks>
public static class SubjectIdentifierFormats
{
    /// <summary>The UTF-8 source literal of <see cref="Account"/>.</summary>
    public static ReadOnlySpan<byte> AccountUtf8 => "account"u8;

    /// <summary>
    /// The Account Identifier Format (<c>account</c>) — identifies a subject by an
    /// <c>acct</c> URI in the <see cref="SubjectIdentifierMemberNames.Uri"/> member.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.1">RFC 9493 §3.2.1</see>.
    /// </summary>
    public static readonly string Account = Utf8Constants.ToInternedString(AccountUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Email"/>.</summary>
    public static ReadOnlySpan<byte> EmailUtf8 => "email"u8;

    /// <summary>
    /// The Email Identifier Format (<c>email</c>) — identifies a subject by an email
    /// address in the <see cref="SubjectIdentifierMemberNames.Email"/> member.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.2">RFC 9493 §3.2.2</see>.
    /// </summary>
    public static readonly string Email = Utf8Constants.ToInternedString(EmailUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IssuerSubject"/>.</summary>
    public static ReadOnlySpan<byte> IssuerSubjectUtf8 => "iss_sub"u8;

    /// <summary>
    /// The Issuer and Subject Identifier Format (<c>iss_sub</c>) — identifies a subject
    /// by the <see cref="SubjectIdentifierMemberNames.Iss"/> and
    /// <see cref="SubjectIdentifierMemberNames.Sub"/> pair.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.3">RFC 9493 §3.2.3</see>.
    /// </summary>
    public static readonly string IssuerSubject = Utf8Constants.ToInternedString(IssuerSubjectUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Opaque"/>.</summary>
    public static ReadOnlySpan<byte> OpaqueUtf8 => "opaque"u8;

    /// <summary>
    /// The Opaque Identifier Format (<c>opaque</c>) — identifies a subject by an opaque
    /// string in the <see cref="SubjectIdentifierMemberNames.Id"/> member.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.4">RFC 9493 §3.2.4</see>.
    /// </summary>
    public static readonly string Opaque = Utf8Constants.ToInternedString(OpaqueUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PhoneNumber"/>.</summary>
    public static ReadOnlySpan<byte> PhoneNumberUtf8 => "phone_number"u8;

    /// <summary>
    /// The Phone Number Identifier Format (<c>phone_number</c>) — identifies a subject by a
    /// telephone number in the <see cref="SubjectIdentifierMemberNames.PhoneNumber"/> member.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.5">RFC 9493 §3.2.5</see>.
    /// </summary>
    public static readonly string PhoneNumber = Utf8Constants.ToInternedString(PhoneNumberUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DecentralizedIdentifier"/>.</summary>
    public static ReadOnlySpan<byte> DecentralizedIdentifierUtf8 => "did"u8;

    /// <summary>
    /// The Decentralized Identifier (DID) Format (<c>did</c>) — identifies a subject by a
    /// DID URL in the <see cref="SubjectIdentifierMemberNames.Url"/> member.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.6">RFC 9493 §3.2.6</see>.
    /// </summary>
    public static readonly string DecentralizedIdentifier = Utf8Constants.ToInternedString(DecentralizedIdentifierUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Uri"/>.</summary>
    public static ReadOnlySpan<byte> UriUtf8 => "uri"u8;

    /// <summary>
    /// The URI Identifier Format (<c>uri</c>) — identifies a subject by a URI in the
    /// <see cref="SubjectIdentifierMemberNames.Uri"/> member.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.7">RFC 9493 §3.2.7</see>.
    /// </summary>
    public static readonly string Uri = Utf8Constants.ToInternedString(UriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Aliases"/>.</summary>
    public static ReadOnlySpan<byte> AliasesUtf8 => "aliases"u8;

    /// <summary>
    /// The Aliases Identifier Format (<c>aliases</c>) — identifies a subject by an array of
    /// other Subject Identifiers in the <see cref="SubjectIdentifierMemberNames.Identifiers"/>
    /// member.
    /// See <see href="https://www.rfc-editor.org/rfc/rfc9493#section-3.2.8">RFC 9493 §3.2.8</see>.
    /// </summary>
    public static readonly string Aliases = Utf8Constants.ToInternedString(AliasesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="JwtId"/>.</summary>
    public static ReadOnlySpan<byte> JwtIdUtf8 => "jwt_id"u8;

    /// <summary>
    /// The JWT ID Identifier Format (<c>jwt_id</c>) — identifies a JWT by its
    /// <see cref="SubjectIdentifierMemberNames.Iss"/> and
    /// <see cref="SubjectIdentifierMemberNames.Jti"/> members. Added by OpenID SSF 1.0 §3.5.1.
    /// </summary>
    public static readonly string JwtId = Utf8Constants.ToInternedString(JwtIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="SamlAssertionId"/>.</summary>
    public static ReadOnlySpan<byte> SamlAssertionIdUtf8 => "saml_assertion_id"u8;

    /// <summary>
    /// The SAML Assertion ID Identifier Format (<c>saml_assertion_id</c>) — identifies a
    /// SAML 2.0 assertion by its <see cref="SubjectIdentifierMemberNames.Issuer"/> and
    /// <see cref="SubjectIdentifierMemberNames.AssertionId"/> members. Added by OpenID SSF 1.0 §3.5.2.
    /// </summary>
    public static readonly string SamlAssertionId = Utf8Constants.ToInternedString(SamlAssertionIdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IpAddresses"/>.</summary>
    public static ReadOnlySpan<byte> IpAddressesUtf8 => "ip-addresses"u8;

    /// <summary>
    /// The IP Addresses Identifier Format (<c>ip-addresses</c>) — identifies a subject by an
    /// array of IP-address strings in the <see cref="SubjectIdentifierMemberNames.IpAddresses"/>
    /// member. Added by OpenID SSF 1.0 §3.5.3. Note the format name and its member are both
    /// hyphenated (<c>ip-addresses</c>), unlike the underscore-separated RFC 9493 formats.
    /// </summary>
    public static readonly string IpAddresses = Utf8Constants.ToInternedString(IpAddressesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Complex"/>.</summary>
    public static ReadOnlySpan<byte> ComplexUtf8 => "complex"u8;

    /// <summary>
    /// The Complex Subject Format (<c>complex</c>) — groups one or more named Simple
    /// Subject Members (for example <c>user</c>, <c>device</c>, <c>tenant</c>), each itself
    /// a Subject Identifier, that all describe the same Subject Principal. Defined by
    /// OpenID Shared Signals Framework 1.0 §3.3; member names are in
    /// <see cref="ComplexSubjectMemberNames"/>.
    /// </summary>
    public static readonly string Complex = Utf8Constants.ToInternedString(ComplexUtf8);


    /// <summary>Whether <paramref name="format"/> is <see cref="Account"/>.</summary>
    public static bool IsAccount(string format) => Equals(format, Account);

    /// <summary>Whether <paramref name="format"/> is <see cref="Email"/>.</summary>
    public static bool IsEmail(string format) => Equals(format, Email);

    /// <summary>Whether <paramref name="format"/> is <see cref="IssuerSubject"/>.</summary>
    public static bool IsIssuerSubject(string format) => Equals(format, IssuerSubject);

    /// <summary>Whether <paramref name="format"/> is <see cref="Opaque"/>.</summary>
    public static bool IsOpaque(string format) => Equals(format, Opaque);

    /// <summary>Whether <paramref name="format"/> is <see cref="PhoneNumber"/>.</summary>
    public static bool IsPhoneNumber(string format) => Equals(format, PhoneNumber);

    /// <summary>Whether <paramref name="format"/> is <see cref="DecentralizedIdentifier"/>.</summary>
    public static bool IsDecentralizedIdentifier(string format) => Equals(format, DecentralizedIdentifier);

    /// <summary>Whether <paramref name="format"/> is <see cref="Uri"/>.</summary>
    public static bool IsUri(string format) => Equals(format, Uri);

    /// <summary>Whether <paramref name="format"/> is <see cref="Aliases"/>.</summary>
    public static bool IsAliases(string format) => Equals(format, Aliases);

    /// <summary>Whether <paramref name="format"/> is <see cref="JwtId"/>.</summary>
    public static bool IsJwtId(string format) => Equals(format, JwtId);

    /// <summary>Whether <paramref name="format"/> is <see cref="SamlAssertionId"/>.</summary>
    public static bool IsSamlAssertionId(string format) => Equals(format, SamlAssertionId);

    /// <summary>Whether <paramref name="format"/> is <see cref="IpAddresses"/>.</summary>
    public static bool IsIpAddresses(string format) => Equals(format, IpAddresses);

    /// <summary>Whether <paramref name="format"/> is <see cref="Complex"/>.</summary>
    public static bool IsComplex(string format) => Equals(format, Complex);


    /// <summary>
    /// Returns the interned constant for a known format name, or the original string
    /// if unrecognized. Enables reference-equality fast paths downstream.
    /// </summary>
    public static string GetCanonicalizedValue(string format) => format switch
    {
        _ when IsAccount(format) => Account,
        _ when IsEmail(format) => Email,
        _ when IsIssuerSubject(format) => IssuerSubject,
        _ when IsOpaque(format) => Opaque,
        _ when IsPhoneNumber(format) => PhoneNumber,
        _ when IsDecentralizedIdentifier(format) => DecentralizedIdentifier,
        _ when IsUri(format) => Uri,
        _ when IsAliases(format) => Aliases,
        _ when IsJwtId(format) => JwtId,
        _ when IsSamlAssertionId(format) => SamlAssertionId,
        _ when IsIpAddresses(format) => IpAddresses,
        _ when IsComplex(format) => Complex,
        _ => format
    };


    /// <summary>
    /// Compares two format names for equality. Format names are case-sensitive, matching
    /// the JSON member-value comparison rules of the SET specifications.
    /// </summary>
    public static bool Equals(string formatA, string formatB) =>
        object.ReferenceEquals(formatA, formatB) || System.StringComparer.Ordinal.Equals(formatA, formatB);
}
