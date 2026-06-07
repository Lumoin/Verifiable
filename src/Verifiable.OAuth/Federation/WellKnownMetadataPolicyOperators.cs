using System.Diagnostics;

namespace Verifiable.OAuth.Federation;

/// <summary>
/// The seven standard <see cref="MetadataPolicyOperator"/> instances per
/// OpenID Federation 1.0 §6.1.2. Extension operators (registered in
/// <c>metadata_policy_crit</c>) instantiate
/// <see cref="MetadataPolicyOperator"/> directly via its constructor.
/// </summary>
/// <remarks>
/// <para>
/// Operator semantics (summary; full text in
/// <see href="https://openid.net/specs/openid-federation-1_0.html#section-6.1.2">§6.1.2</see>):
/// </para>
/// <list type="bullet">
///   <item><description><see cref="Value"/> — replaces the subject's declared value with the operator's value.</description></item>
///   <item><description><see cref="Add"/> — appends the operator's values to the subject's declared array.</description></item>
///   <item><description><see cref="Default"/> — supplies a value when the subject did not declare one.</description></item>
///   <item><description><see cref="OneOf"/> — restricts the subject's value to one of the operator's enumerated values.</description></item>
///   <item><description><see cref="SubsetOf"/> — requires the subject's array to be a subset of the operator's value set.</description></item>
///   <item><description><see cref="SupersetOf"/> — requires the subject's array to be a superset of the operator's value set.</description></item>
///   <item><description><see cref="Essential"/> — when <see langword="true"/>, the parameter MUST be present in the effective metadata after application.</description></item>
/// </list>
/// </remarks>
[DebuggerDisplay("WellKnownMetadataPolicyOperators")]
public static class WellKnownMetadataPolicyOperators
{
    /// <summary><c>value</c> — replaces the parameter's value.</summary>
    public static readonly MetadataPolicyOperator Value = new("value");

    /// <summary><c>add</c> — appends to an array parameter.</summary>
    public static readonly MetadataPolicyOperator Add = new("add");

    /// <summary><c>default</c> — value when subject did not declare one.</summary>
    public static readonly MetadataPolicyOperator Default = new("default");

    /// <summary><c>one_of</c> — restricts to an enumerated set.</summary>
    public static readonly MetadataPolicyOperator OneOf = new("one_of");

    /// <summary><c>subset_of</c> — array must be a subset of the listed values.</summary>
    public static readonly MetadataPolicyOperator SubsetOf = new("subset_of");

    /// <summary><c>superset_of</c> — array must be a superset of the listed values.</summary>
    public static readonly MetadataPolicyOperator SupersetOf = new("superset_of");

    /// <summary><c>essential</c> — boolean flag; parameter MUST be present.</summary>
    public static readonly MetadataPolicyOperator Essential = new("essential");
}
