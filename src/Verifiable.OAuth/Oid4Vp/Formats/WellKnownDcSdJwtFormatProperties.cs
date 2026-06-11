using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Oid4Vp.Formats;

/// <summary>
/// Well-known property name constants for the <c>dc+sd-jwt</c> format entry
/// within <c>vp_formats_supported</c>, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-B.3">OID4VP 1.0 Appendix B.3</see>.
/// </summary>
[DebuggerDisplay("WellKnownDcSdJwtFormatProperties")]
public static class WellKnownDcSdJwtFormatProperties
{
    /// <summary>The UTF-8 source literal of <see cref="SdJwtAlgValues"/>.</summary>
    public static ReadOnlySpan<byte> SdJwtAlgValuesUtf8 => "sd-jwt_alg_values"u8;

    /// <summary>
    /// The <c>sd-jwt_alg_values</c> property. A JSON array of JWS algorithm
    /// identifiers supported for the SD-JWT component. The presented SD-JWT's
    /// <c>alg</c> JOSE header MUST match one of these values when present.
    /// Per OID4VP 1.0 Appendix B.3.
    /// </summary>
    public static readonly string SdJwtAlgValues = Utf8Constants.ToInternedString(SdJwtAlgValuesUtf8);

    /// <summary>The UTF-8 source literal of <see cref="KbJwtAlgValues"/>.</summary>
    public static ReadOnlySpan<byte> KbJwtAlgValuesUtf8 => "kb-jwt_alg_values"u8;

    /// <summary>
    /// The <c>kb-jwt_alg_values</c> property. A JSON array of JWS algorithm
    /// identifiers supported for the Key Binding JWT component. The presented
    /// KB-JWT's <c>alg</c> JOSE header MUST match one of these values when present.
    /// Per OID4VP 1.0 Appendix B.3.
    /// </summary>
    public static readonly string KbJwtAlgValues = Utf8Constants.ToInternedString(KbJwtAlgValuesUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>sd-jwt_alg_values</c>.</summary>
    public static bool IsSdJwtAlgValues(string value) =>
        string.Equals(value, SdJwtAlgValues, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>kb-jwt_alg_values</c>.</summary>
    public static bool IsKbJwtAlgValues(string value) =>
        string.Equals(value, KbJwtAlgValues, StringComparison.Ordinal);

    /// <summary>
    /// Returns the canonical form of a known property name, or the original
    /// value when not recognized. Comparison is case-sensitive per OID4VP 1.0.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsSdJwtAlgValues(value) => SdJwtAlgValues,
        _ when IsKbJwtAlgValues(value) => KbJwtAlgValues,
        _ => value
    };
}
