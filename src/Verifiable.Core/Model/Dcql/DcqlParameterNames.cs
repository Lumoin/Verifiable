using System.Diagnostics;

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
    /// <summary>The <c>id</c> member (Credential Query / Claims Query identifier).</summary>
    public static readonly string Id = "id";

    /// <summary>The <c>format</c> member of a Credential Query.</summary>
    public static readonly string Format = "format";

    /// <summary>The <c>meta</c> member of a Credential Query (§6.1).</summary>
    public static readonly string Meta = "meta";

    /// <summary>The <c>claims</c> member of a Credential Query.</summary>
    public static readonly string Claims = "claims";

    /// <summary>The <c>claim_sets</c> member of a Credential Query.</summary>
    public static readonly string ClaimSets = "claim_sets";

    /// <summary>The <c>trusted_authorities</c> member of a Credential Query (§6.1.1).</summary>
    public static readonly string TrustedAuthorities = "trusted_authorities";

    /// <summary>The <c>multiple</c> member of a Credential Query.</summary>
    public static readonly string Multiple = "multiple";

    /// <summary>The <c>require_cryptographic_holder_binding</c> member of a Credential Query.</summary>
    public static readonly string RequireCryptographicHolderBinding = "require_cryptographic_holder_binding";

    /// <summary>The <c>path</c> member of a Claims Query.</summary>
    public static readonly string Path = "path";

    /// <summary>The <c>values</c> member (Claims Query value constraint / Trusted Authorities values).</summary>
    public static readonly string Values = "values";

    /// <summary>The <c>intent_to_retain</c> member of a Claims Query.</summary>
    public static readonly string IntentToRetain = "intent_to_retain";

    /// <summary>The <c>vct_values</c> member of a Credential Query's meta (SD-JWT VC).</summary>
    public static readonly string VctValues = "vct_values";

    /// <summary>The <c>doctype_value</c> member of a Credential Query's meta (ISO mdoc).</summary>
    public static readonly string DoctypeValue = "doctype_value";

    /// <summary>The <c>options</c> member of a Credential Set Query.</summary>
    public static readonly string Options = "options";

    /// <summary>The <c>required</c> member of a Credential Set Query.</summary>
    public static readonly string Required = "required";

    /// <summary>The <c>purpose</c> member of a Credential Set Query.</summary>
    public static readonly string Purpose = "purpose";

    /// <summary>The <c>credentials</c> member of a DCQL Query.</summary>
    public static readonly string Credentials = "credentials";

    /// <summary>The <c>credential_sets</c> member of a DCQL Query.</summary>
    public static readonly string CredentialSets = "credential_sets";

    /// <summary>The <c>type</c> member of a Trusted Authorities Query.</summary>
    public static readonly string Type = "type";


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
