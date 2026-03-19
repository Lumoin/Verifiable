using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp.Formats;

/// <summary>
/// Well-known property name constants for the <c>jwt_vc_json</c> and
/// <c>jwt_vp_json</c> format entries within <c>vp_formats_supported</c>,
/// as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.1">OID4VP 1.0 Appendix B.1</see>.
/// </summary>
[DebuggerDisplay("WellKnownJwtVcFormatProperties")]
public static class WellKnownJwtVcFormatProperties
{
    /// <summary>
    /// The <c>alg_values_supported</c> property. A JSON array of JWS algorithm
    /// identifiers supported for signing JWT VCs and JWT VPs.
    /// Per OID4VP 1.0 Appendix B.1.
    /// </summary>
    public const string AlgValuesSupported = "alg_values_supported";


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>alg_values_supported</c>.</summary>
    public static bool IsAlgValuesSupported(string value) =>
        string.Equals(value, AlgValuesSupported, StringComparison.Ordinal);

    /// <summary>
    /// Returns the canonical form of a known property name, or the original
    /// value when not recognized. Comparison is case-sensitive per OID4VP 1.0.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsAlgValuesSupported(value) => AlgValuesSupported,
        _ => value
    };
}
