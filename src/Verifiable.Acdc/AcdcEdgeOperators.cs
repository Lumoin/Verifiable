using System.Collections.Generic;

namespace Verifiable.Acdc;

/// <summary>
/// The ACDC edge operator tokens: the unary operators that modulate a single edge's validation and the m-ary
/// operators that aggregate an edge-group's members. An operator value travels in an edge or edge-group's operator,
/// <c>o</c>, field; this centralizes the tokens so the edge evaluation, a reader, and the tests agree on them.
/// </summary>
/// <remarks>
/// <para>
/// Anchored on the ACDC specification's <see href="https://trustoverip.github.io/kswg-acdc-specification/#operator-o-field-1">
/// unary edge operators</see> and <see href="https://trustoverip.github.io/kswg-acdc-specification/#operator-o-field">
/// m-ary edge-group operators</see>. The unary operators express the chain-of-authority relationship between a near
/// node ACDC and the far node its edge points to; the m-ary operators express the validity logic over a group of
/// edges. The defaults — <c>AND</c> for an absent m-ary operator, and <c>I2I</c> or <c>NI2I</c> for an absent unary
/// operator depending on whether the far node is targeted — let the operator field be omitted in the common cases.
/// </para>
/// </remarks>
public static class AcdcEdgeOperators
{
    /// <summary>Issuer-To-Issuee <c>I2I</c>: the near node's Issuer AID MUST be the Issuee AID of the targeted far node. The default unary operator for a targeted far node.</summary>
    public static string IssuerToIssuee { get; } = "I2I";

    /// <summary>Not-Issuer-To-Issuee <c>NI2I</c>: the near node's Issuer need not be the far node's Issuee. The default unary operator for an untargeted far node.</summary>
    public static string NotIssuerToIssuee { get; } = "NI2I";

    /// <summary>Delegated-Issuer-To-Issuee <c>DI2I</c>: the near node's Issuer MUST be the Issuee or a delegated AID of the Issuee of the targeted far node.</summary>
    public static string DelegatedIssuerToIssuee { get; } = "DI2I";

    /// <summary>Logical NOT <c>NOT</c>: inverts the validity of the far node the edge points to.</summary>
    public static string Not { get; } = "NOT";

    /// <summary>Logical AND <c>AND</c>: the edge-group is valid only if all members are valid. The default m-ary operator.</summary>
    public static string And { get; } = "AND";

    /// <summary>Logical OR <c>OR</c>: the edge-group is valid if at least one member is valid.</summary>
    public static string Or { get; } = "OR";

    /// <summary>Logical NAND <c>NAND</c>: the edge-group is valid only if not all members are valid.</summary>
    public static string Nand { get; } = "NAND";

    /// <summary>Logical NOR <c>NOR</c>: the edge-group is valid only if all members are invalid.</summary>
    public static string Nor { get; } = "NOR";

    /// <summary>Arithmetic average <c>AVG</c>: averages a member property; requires a numeric property to average.</summary>
    public static string Average { get; } = "AVG";

    /// <summary>Weighted arithmetic average <c>WAVG</c>: a weighted average of a member property using the weight, <c>w</c>, field.</summary>
    public static string WeightedAverage { get; } = "WAVG";


    /// <summary>
    /// The unary operators that constrain the issuer relationship between a near node and its targeted far node:
    /// <c>I2I</c>, <c>NI2I</c>, and <c>DI2I</c>. Exactly one is in effect for a given edge (the last one present when
    /// more than one appears, or the default when none does); <c>NOT</c> is independent of these.
    /// </summary>
    private static HashSet<string> IssuerConstraints { get; } = new(System.StringComparer.Ordinal)
    {
        IssuerToIssuee, NotIssuerToIssuee, DelegatedIssuerToIssuee
    };


    /// <summary>
    /// Whether an operator token is one of the unary issuer-constraint operators (<c>I2I</c>, <c>NI2I</c>, or
    /// <c>DI2I</c>).
    /// </summary>
    /// <param name="operatorToken">The operator token to test.</param>
    /// <returns><see langword="true"/> when the token is an issuer-constraint operator.</returns>
    public static bool IsIssuerConstraint(string operatorToken)
    {
        ArgumentNullException.ThrowIfNull(operatorToken);

        return IssuerConstraints.Contains(operatorToken);
    }
}
