using System;
using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.Model.Dcql;

/// <summary>
/// Member NAMES of the DCQL (Digital Credentials Query Language) wire objects per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6">OID4VP 1.0 §6</see>.
/// </summary>
/// <remarks>
/// <para>
/// One well-known class for every DCQL member name, replacing the per-model
/// <c>*PropertyName</c> constants the query types used to carry. The DCQL converters
/// in <c>Verifiable.Json</c> reference these. Where the same wire token appears in more
/// than one object (e.g. <c>id</c> in both a Credential Query and a Claims Query;
/// <c>values</c> in both a Claims Query and a Trusted Authorities Query), a single
/// constant serves all — the token is the same on the wire.
/// </para>
/// <para>
/// Declared <see langword="static readonly"/> (not <see langword="const"/>) — matching
/// <see cref="Oid4VpAuthorizationRequestParameterNames"/> and
/// <c>Oid4VpClientMetadataParameterNames</c>, and avoiding cross-assembly const
/// inlining. The converters match them with the <c>Is*</c> ordinal helpers in a guarded
/// <c>switch</c> rather than <c>case</c> labels.
/// </para>
/// </remarks>
[DebuggerDisplay("DcqlParameterNames")]
public static class DcqlParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="Id"/>.</summary>
    public static ReadOnlySpan<byte> IdUtf8 => "id"u8;

    /// <summary>The <c>id</c> member (Credential Query / Claims Query identifier).</summary>
    public static readonly string Id = Utf8Constants.ToInternedString(IdUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Format"/>.</summary>
    public static ReadOnlySpan<byte> FormatUtf8 => "format"u8;

    /// <summary>The <c>format</c> member of a Credential Query.</summary>
    public static readonly string Format = Utf8Constants.ToInternedString(FormatUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Meta"/>.</summary>
    public static ReadOnlySpan<byte> MetaUtf8 => "meta"u8;

    /// <summary>The <c>meta</c> member of a Credential Query (§6.1).</summary>
    public static readonly string Meta = Utf8Constants.ToInternedString(MetaUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Claims"/>.</summary>
    public static ReadOnlySpan<byte> ClaimsUtf8 => "claims"u8;

    /// <summary>The <c>claims</c> member of a Credential Query.</summary>
    public static readonly string Claims = Utf8Constants.ToInternedString(ClaimsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClaimSets"/>.</summary>
    public static ReadOnlySpan<byte> ClaimSetsUtf8 => "claim_sets"u8;

    /// <summary>The <c>claim_sets</c> member of a Credential Query.</summary>
    public static readonly string ClaimSets = Utf8Constants.ToInternedString(ClaimSetsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TrustedAuthorities"/>.</summary>
    public static ReadOnlySpan<byte> TrustedAuthoritiesUtf8 => "trusted_authorities"u8;

    /// <summary>The <c>trusted_authorities</c> member of a Credential Query (§6.1.1).</summary>
    public static readonly string TrustedAuthorities = Utf8Constants.ToInternedString(TrustedAuthoritiesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Multiple"/>.</summary>
    public static ReadOnlySpan<byte> MultipleUtf8 => "multiple"u8;

    /// <summary>The <c>multiple</c> member of a Credential Query.</summary>
    public static readonly string Multiple = Utf8Constants.ToInternedString(MultipleUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequireCryptographicHolderBinding"/>.</summary>
    public static ReadOnlySpan<byte> RequireCryptographicHolderBindingUtf8 => "require_cryptographic_holder_binding"u8;

    /// <summary>The <c>require_cryptographic_holder_binding</c> member of a Credential Query.</summary>
    public static readonly string RequireCryptographicHolderBinding = Utf8Constants.ToInternedString(RequireCryptographicHolderBindingUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Path"/>.</summary>
    public static ReadOnlySpan<byte> PathUtf8 => "path"u8;

    /// <summary>The <c>path</c> member of a Claims Query.</summary>
    public static readonly string Path = Utf8Constants.ToInternedString(PathUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Values"/>.</summary>
    public static ReadOnlySpan<byte> ValuesUtf8 => "values"u8;

    /// <summary>The <c>values</c> member (Claims Query value constraint / Trusted Authorities values).</summary>
    public static readonly string Values = Utf8Constants.ToInternedString(ValuesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="IntentToRetain"/>.</summary>
    public static ReadOnlySpan<byte> IntentToRetainUtf8 => "intent_to_retain"u8;

    /// <summary>The <c>intent_to_retain</c> member of a Claims Query.</summary>
    public static readonly string IntentToRetain = Utf8Constants.ToInternedString(IntentToRetainUtf8);

    /// <summary>The UTF-8 source literal of <see cref="VctValues"/>.</summary>
    public static ReadOnlySpan<byte> VctValuesUtf8 => "vct_values"u8;

    /// <summary>The <c>vct_values</c> member of a Credential Query's meta (SD-JWT VC).</summary>
    public static readonly string VctValues = Utf8Constants.ToInternedString(VctValuesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DoctypeValue"/>.</summary>
    public static ReadOnlySpan<byte> DoctypeValueUtf8 => "doctype_value"u8;

    /// <summary>The <c>doctype_value</c> member of a Credential Query's meta (ISO mdoc).</summary>
    public static readonly string DoctypeValue = Utf8Constants.ToInternedString(DoctypeValueUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Options"/>.</summary>
    public static ReadOnlySpan<byte> OptionsUtf8 => "options"u8;

    /// <summary>The <c>options</c> member of a Credential Set Query.</summary>
    public static readonly string Options = Utf8Constants.ToInternedString(OptionsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Required"/>.</summary>
    public static ReadOnlySpan<byte> RequiredUtf8 => "required"u8;

    /// <summary>The <c>required</c> member of a Credential Set Query.</summary>
    public static readonly string Required = Utf8Constants.ToInternedString(RequiredUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Purpose"/>.</summary>
    public static ReadOnlySpan<byte> PurposeUtf8 => "purpose"u8;

    /// <summary>The <c>purpose</c> member of a Credential Set Query.</summary>
    public static readonly string Purpose = Utf8Constants.ToInternedString(PurposeUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Credentials"/>.</summary>
    public static ReadOnlySpan<byte> CredentialsUtf8 => "credentials"u8;

    /// <summary>The <c>credentials</c> member of a DCQL Query.</summary>
    public static readonly string Credentials = Utf8Constants.ToInternedString(CredentialsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="CredentialSets"/>.</summary>
    public static ReadOnlySpan<byte> CredentialSetsUtf8 => "credential_sets"u8;

    /// <summary>The <c>credential_sets</c> member of a DCQL Query.</summary>
    public static readonly string CredentialSets = Utf8Constants.ToInternedString(CredentialSetsUtf8);

    /// <summary>The UTF-8 source literal of <see cref="Type"/>.</summary>
    public static ReadOnlySpan<byte> TypeUtf8 => "type"u8;

    /// <summary>The <c>type</c> member of a Trusted Authorities Query.</summary>
    public static readonly string Type = Utf8Constants.ToInternedString(TypeUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>id</c>.</summary>
    public static bool IsId(string value) => string.Equals(value, Id, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>format</c>.</summary>
    public static bool IsFormat(string value) => string.Equals(value, Format, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>meta</c>.</summary>
    public static bool IsMeta(string value) => string.Equals(value, Meta, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>claims</c>.</summary>
    public static bool IsClaims(string value) => string.Equals(value, Claims, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>claim_sets</c>.</summary>
    public static bool IsClaimSets(string value) => string.Equals(value, ClaimSets, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>trusted_authorities</c>.</summary>
    public static bool IsTrustedAuthorities(string value) => string.Equals(value, TrustedAuthorities, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>multiple</c>.</summary>
    public static bool IsMultiple(string value) => string.Equals(value, Multiple, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>require_cryptographic_holder_binding</c>.</summary>
    public static bool IsRequireCryptographicHolderBinding(string value) => string.Equals(value, RequireCryptographicHolderBinding, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>path</c>.</summary>
    public static bool IsPath(string value) => string.Equals(value, Path, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>values</c>.</summary>
    public static bool IsValues(string value) => string.Equals(value, Values, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>intent_to_retain</c>.</summary>
    public static bool IsIntentToRetain(string value) => string.Equals(value, IntentToRetain, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>vct_values</c>.</summary>
    public static bool IsVctValues(string value) => string.Equals(value, VctValues, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>doctype_value</c>.</summary>
    public static bool IsDoctypeValue(string value) => string.Equals(value, DoctypeValue, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>options</c>.</summary>
    public static bool IsOptions(string value) => string.Equals(value, Options, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>required</c>.</summary>
    public static bool IsRequired(string value) => string.Equals(value, Required, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>purpose</c>.</summary>
    public static bool IsPurpose(string value) => string.Equals(value, Purpose, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>credentials</c>.</summary>
    public static bool IsCredentials(string value) => string.Equals(value, Credentials, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>credential_sets</c>.</summary>
    public static bool IsCredentialSets(string value) => string.Equals(value, CredentialSets, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>type</c>.</summary>
    public static bool IsType(string value) => string.Equals(value, Type, StringComparison.Ordinal);
}
