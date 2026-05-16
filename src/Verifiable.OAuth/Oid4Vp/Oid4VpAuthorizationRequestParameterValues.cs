namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Well-known VALUES for OID4VP-specific authorization request parameters.
/// Distinct from <see cref="Oid4VpAuthorizationRequestParameterNames"/>
/// which holds the NAMES of those parameters; this class holds the
/// enumerated-set values for OID4VP name-constrained parameters
/// (currently only <c>response_type</c>).
/// </summary>
/// <remarks>
/// Most OID4VP parameter values are flow-specific (a DCQL query JSON,
/// a response URI, an inline client metadata object) and don't have
/// well-known canonical forms. Only the parameters whose values are
/// constrained to a small enumerated set have entries here.
/// </remarks>
public static class Oid4VpAuthorizationRequestParameterValues
{
    //response_type values — OID4VP 1.0 §5.1.

    /// <summary>
    /// The <c>vp_token</c> value for the OAuth <c>response_type</c>
    /// parameter, which triggers the OID4VP flow per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1">OID4VP 1.0 §5.1</see>.
    /// </summary>
    public static readonly string ResponseTypeVpToken = "vp_token";


    /// <summary>
    /// Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <see cref="ResponseTypeVpToken"/>.
    /// </summary>
    public static bool IsResponseTypeVpToken(string value) =>
        string.Equals(value, ResponseTypeVpToken, StringComparison.Ordinal);
}
