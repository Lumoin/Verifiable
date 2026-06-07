using System.Diagnostics;

namespace Verifiable.OAuth.Server.Metadata;

/// <summary>
/// Application-contributed fields merged into the Authorization Server's
/// discovery document after the library writes its base fields.
/// </summary>
/// <remarks>
/// <para>
/// The contribution is a typed record carrying an ordered list of
/// <see cref="DiscoveryField"/> items rather than a raw dictionary. This
/// lets the library dispatch on the field's record type at JSON-emission
/// time instead of doing a runtime CLR-type test on
/// <see cref="object"/>-valued dictionary entries, and forces application
/// authors to construct field instances of types the library can serialize.
/// </para>
/// <para>
/// Order is significant: fields are emitted in the order they appear in
/// <see cref="Fields"/>. The library's base discovery fields are written
/// first; contributed fields follow. The contribution is strictly additive
/// — the library's base fields take precedence over any contributed field
/// with a duplicate name.
/// </para>
/// </remarks>
[DebuggerDisplay("DiscoveryDocumentContribution Fields={Fields.Count}")]
public sealed record DiscoveryDocumentContribution(IReadOnlyList<DiscoveryField> Fields)
{
    /// <summary>
    /// An empty contribution. Use this from
    /// <see cref="ContributeDiscoveryFieldsDelegate"/> implementations that
    /// have nothing to add for a given request.
    /// </summary>
    public static readonly DiscoveryDocumentContribution Empty =
        new(Array.Empty<DiscoveryField>());
}


/// <summary>
/// Base type for typed discovery-document fields. Subtypes are an exhaustive
/// closed hierarchy reflecting the JSON value shapes the library knows how
/// to serialize: string, boolean, number, and string-array.
/// </summary>
/// <remarks>
/// <para>
/// The hierarchy is intentionally narrow. Discovery-document field values
/// per
/// <see href="https://www.rfc-editor.org/rfc/rfc8414">RFC 8414</see>
/// and the OIDC Discovery profile that extends it are primitive scalars or
/// arrays of strings; nested objects are not used for the fields the
/// metadata-keys classes name. A future field shape (e.g., an object value
/// that lists per-algorithm signing parameters) is added here as a new
/// subtype, keeping the dispatch surface explicit.
/// </para>
/// </remarks>
[DebuggerDisplay("DiscoveryField Name={Name,nq}")]
public abstract record DiscoveryField(string Name);


/// <summary>
/// A discovery field whose value is a JSON string. Typically a URL keyed
/// to one of <see cref="AuthorizationServerMetadataParameterNames"/>,
/// <see cref="OpenIdProviderMetadataParameterNames"/>,
/// <see cref="FederationMetadataParameterNames"/>,
/// <see cref="CredentialIssuerMetadataParameterNames"/>, or
/// <see cref="AuthZenMetadataParameterNames"/>; or a single value field such as
/// <c>service_documentation</c> or <c>op_policy_uri</c>.
/// </summary>
/// <param name="Name">The JSON property name.</param>
/// <param name="Value">The JSON property value, written as a JSON string.</param>
[DebuggerDisplay("DiscoveryStringField {Name,nq} = {Value,nq}")]
public sealed record DiscoveryStringField(string Name, string Value): DiscoveryField(Name);


/// <summary>
/// A discovery field whose value is a JSON boolean. Typical examples are
/// the OIDC <c>require_request_uri_registration</c> or FAPI
/// <c>tls_client_certificate_bound_access_tokens</c>.
/// </summary>
/// <param name="Name">The JSON property name.</param>
/// <param name="Value">The JSON property value, written as a JSON boolean.</param>
[DebuggerDisplay("DiscoveryBooleanField {Name,nq} = {Value}")]
public sealed record DiscoveryBooleanField(string Name, bool Value): DiscoveryField(Name);


/// <summary>
/// A discovery field whose value is a JSON integer. Typical examples are
/// FAPI 2.0 <c>request_object_max_age</c> or per-deployment lifetime
/// advertisements.
/// </summary>
/// <remarks>
/// JSON discovery numerics are integer-valued in every spec-defined field;
/// fractional values would be surprising in this context and are not
/// representable through this type. A future fractional-valued field (none
/// known at this time) would be added as a separate subtype rather than
/// widening this one.
/// </remarks>
/// <param name="Name">The JSON property name.</param>
/// <param name="Value">The JSON property value, written as a JSON integer.</param>
[DebuggerDisplay("DiscoveryNumberField {Name,nq} = {Value}")]
public sealed record DiscoveryNumberField(string Name, long Value): DiscoveryField(Name);


/// <summary>
/// A discovery field whose value is a JSON array of strings. Typical
/// examples are <c>scopes_supported</c>, <c>response_types_supported</c>,
/// <c>grant_types_supported</c>, and the various
/// <c>*_signing_alg_values_supported</c> fields.
/// </summary>
/// <param name="Name">The JSON property name.</param>
/// <param name="Values">The JSON array values, written as a JSON array of strings.</param>
[DebuggerDisplay("DiscoveryStringArrayField {Name,nq} = [{Values.Count}]")]
public sealed record DiscoveryStringArrayField(
    string Name,
    IReadOnlyList<string> Values): DiscoveryField(Name);
