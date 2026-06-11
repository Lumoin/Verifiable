using System.Diagnostics;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The JSON wire shape a strict RFC 9396 authorization details handler requires of one
/// type-specific field — the coarse type the field's raw JSON value is matched against to detect
/// the §5 "wrong type of a field" abort cause. A field declared <see cref="Any"/> accepts any
/// well-formed JSON value (its constraints, if any, are expressed by a value check instead).
/// </summary>
public enum AuthorizationDetailFieldShape
{
    /// <summary>A JSON string.</summary>
    String = 0,

    /// <summary>A JSON array whose every element is a JSON string.</summary>
    StringArray,

    /// <summary>A JSON number.</summary>
    Number,

    /// <summary>A JSON boolean.</summary>
    Boolean,

    /// <summary>A JSON object.</summary>
    Object,

    /// <summary>A JSON array of any element shape.</summary>
    Array,

    /// <summary>Any well-formed JSON value.</summary>
    Any
}


/// <summary>
/// Inspects the value of one strictly-validated type-specific field — its raw JSON text from
/// <see cref="AuthorizationDetail.ExtensionData"/> — for the RFC 9396 §5 "invalid value" abort
/// cause, after the field's <see cref="AuthorizationDetailFieldRule.Shape"/> has already been
/// confirmed. Returns <see langword="null"/> when the value is acceptable, or the
/// <c>error_description</c> text otherwise.
/// </summary>
/// <param name="rawJsonValue">The raw JSON text of the field's value.</param>
/// <returns><see langword="null"/> when the value is acceptable; the error description otherwise.</returns>
public delegate string? ValidateAuthorizationDetailFieldValueDelegate(string rawJsonValue);


/// <summary>
/// One type-specific field a strict RFC 9396 authorization details handler knows about: its JSON
/// member name, whether it is required, the JSON <see cref="Shape"/> its value must have, and an
/// optional <see cref="ValidateValue"/> for the §5 "invalid value" check. The §2 <c>type</c> and
/// the §2.2 common fields are always known and are not declared here.
/// </summary>
[DebuggerDisplay("AuthorizationDetailFieldRule Name={Name} Shape={Shape} IsRequired={IsRequired}")]
public sealed record AuthorizationDetailFieldRule
{
    /// <summary>The JSON member name of the field, as it appears on the wire.</summary>
    public required string Name { get; init; }

    /// <summary>
    /// Whether the field MUST be present. A required field that is absent is the RFC 9396 §5
    /// "missing required fields" abort cause.
    /// </summary>
    public bool IsRequired { get; init; }

    /// <summary>
    /// The JSON wire shape the field's value MUST have. A present field whose value has a
    /// different shape is the RFC 9396 §5 "wrong type of a field" abort cause.
    /// </summary>
    public AuthorizationDetailFieldShape Shape { get; init; } = AuthorizationDetailFieldShape.Any;

    /// <summary>
    /// An optional check of the field's value for the RFC 9396 §5 "invalid value" abort cause,
    /// run only after the value's <see cref="Shape"/> is confirmed, or <see langword="null"/>
    /// when the shape alone constrains the field.
    /// </summary>
    public ValidateAuthorizationDetailFieldValueDelegate? ValidateValue { get; init; }
}


/// <summary>
/// Builds a strict <see cref="ValidateAuthorizationDetailShapeDelegate"/> from a closed set of
/// <see cref="AuthorizationDetailFieldRule"/>s — the framework half of RFC 9396 §5 strict
/// per-type validation. The produced delegate refuses, with an <c>invalid_authorization_details</c>
/// error description, every §5 abort cause an object of the type can exhibit beyond the unknown
/// <c>type</c> the registry already refuses: an unknown field, a common or type-specific field of
/// the wrong type, a field with an invalid value, and a missing required field. A handler opts
/// into strictness by composing its <see cref="AuthorizationDetailHandler.ValidateShape"/> from
/// this builder; a handler that does not (for example the lenient <c>openid_credential</c>
/// profile, which OID4VCI 1.0 §5.1.1 declares never invalid due to unknown fields) keeps its own
/// validation and is unaffected.
/// </summary>
/// <remarks>
/// The known fields are the declared rules plus the §2 <c>type</c> and the §2.2 common fields
/// (<c>locations</c>/<c>actions</c>/<c>datatypes</c>/<c>identifier</c>/<c>privileges</c>), which
/// are always permitted; a strict handler that wants a common field present or absent expresses
/// that in its own composed validation, since the common fields live in typed slots on
/// <see cref="AuthorizationDetail"/> rather than in <see cref="AuthorizationDetail.ExtensionData"/>.
/// Type-specific members arrive verbatim in <see cref="AuthorizationDetail.ExtensionData"/>, so
/// any extension-data key not naming a declared rule is the §5 "unknown field" abort cause.
/// </remarks>
public static class AuthorizationDetailStrictFieldValidation
{
    /// <summary>
    /// Builds the strict shape validator for the type-specific <paramref name="fieldRules"/>.
    /// The returned delegate enforces unknown-field, wrong-type, invalid-value, and
    /// missing-required-field aborts; it does not assert any common-field requirement, which a
    /// composing handler adds.
    /// </summary>
    /// <param name="fieldRules">The known type-specific fields of the type.</param>
    /// <returns>A strict shape validator for the type.</returns>
    public static ValidateAuthorizationDetailShapeDelegate ForFields(
        params AuthorizationDetailFieldRule[] fieldRules)
    {
        ArgumentNullException.ThrowIfNull(fieldRules);

        Dictionary<string, AuthorizationDetailFieldRule> rulesByName = new(StringComparer.Ordinal);
        foreach(AuthorizationDetailFieldRule rule in fieldRules)
        {
            ArgumentNullException.ThrowIfNull(rule);
            rulesByName.Add(rule.Name, rule);
        }

        return (detail, validation) => Validate(rulesByName, detail);
    }


    /// <summary>
    /// Enforces the RFC 9396 §5 abort causes a strict type can exhibit against the parsed
    /// <paramref name="detail"/>, in the spec's listed order: wrong-typed common field, unknown
    /// field, then per declared rule the wrong-typed or invalid-valued or missing-required field.
    /// </summary>
    private static string? Validate(
        IReadOnlyDictionary<string, AuthorizationDetailFieldRule> rulesByName,
        AuthorizationDetail detail)
    {
        //RFC 9396 §5: "contains fields of the wrong type for the authorization details type."
        //The parser records a §2.2 common field that was present with the wrong JSON type here;
        //a strict type refuses it (the lenient openid_credential profile ignores it instead).
        if(detail.MalformedCommonFields.Count > 0)
        {
            return $"The common field '{detail.MalformedCommonFields[0]}' has the wrong JSON type "
                + $"for the '{detail.Type}' authorization details type.";
        }

        //RFC 9396 §5: "is an object of known type but containing unknown fields." Every member
        //that is not the type or a common field arrives in the extension data; a key naming no
        //declared rule is an unknown field.
        foreach(string memberName in detail.ExtensionData.Keys)
        {
            if(!rulesByName.ContainsKey(memberName))
            {
                return $"The field '{memberName}' is not a known field of the '{detail.Type}' "
                    + "authorization details type.";
            }
        }

        foreach(AuthorizationDetailFieldRule rule in rulesByName.Values)
        {
            if(!detail.ExtensionData.TryGetValue(rule.Name, out string? rawValue))
            {
                //RFC 9396 §5: "is missing required fields for the authorization details type."
                if(rule.IsRequired)
                {
                    return $"The required field '{rule.Name}' is missing from the '{detail.Type}' "
                        + "authorization details type.";
                }

                continue;
            }

            //RFC 9396 §5: "contains fields of the wrong type for the authorization details type."
            if(!MatchesShape(rule.Shape, rawValue))
            {
                return $"The field '{rule.Name}' has the wrong JSON type for the '{detail.Type}' "
                    + "authorization details type.";
            }

            //RFC 9396 §5: "contains fields with invalid values for the authorization details type."
            string? valueError = rule.ValidateValue?.Invoke(rawValue);
            if(valueError is not null)
            {
                return valueError;
            }
        }

        return null;
    }


    /// <summary>
    /// Whether the raw JSON value <paramref name="rawJsonValue"/> matches the expected
    /// <paramref name="shape"/>.
    /// </summary>
    private static bool MatchesShape(AuthorizationDetailFieldShape shape, string rawJsonValue)
    {
        return shape switch
        {
            AuthorizationDetailFieldShape.String => JsonScalarText.ClassifyKind(rawJsonValue) == JsonValueShape.String,
            AuthorizationDetailFieldShape.StringArray => JsonScalarText.IsArrayOfStrings(rawJsonValue),
            AuthorizationDetailFieldShape.Number => JsonScalarText.ClassifyKind(rawJsonValue) == JsonValueShape.Number,
            AuthorizationDetailFieldShape.Boolean => JsonScalarText.ClassifyKind(rawJsonValue) == JsonValueShape.Boolean,
            AuthorizationDetailFieldShape.Object => JsonScalarText.ClassifyKind(rawJsonValue) == JsonValueShape.Object,
            AuthorizationDetailFieldShape.Array => JsonScalarText.ClassifyKind(rawJsonValue) == JsonValueShape.Array,
            AuthorizationDetailFieldShape.Any => JsonScalarText.ClassifyKind(rawJsonValue) != JsonValueShape.Malformed,
            _ => false
        };
    }
}
