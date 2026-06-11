using System.Diagnostics;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// Well-known VALUES for SIOPv2 authorization request parameters. Distinct from
/// <see cref="SiopAuthorizationRequestParameterNames"/> which holds the NAMES of
/// SIOPv2-native parameters.
/// </summary>
[DebuggerDisplay("SiopAuthorizationRequestParameterValues")]
public static class SiopAuthorizationRequestParameterValues
{
    //response_type values — SIOPv2 §9 / §10.

    /// <summary>The UTF-8 source literal of <see cref="ResponseTypeIdToken"/>.</summary>
    public static ReadOnlySpan<byte> ResponseTypeIdTokenUtf8 => "id_token"u8;

    /// <summary>
    /// The <c>id_token</c> value for the OAuth <c>response_type</c> parameter — the
    /// Self-Issued OP returns the Self-Issued ID Token directly in the Authorization
    /// Response. Combine with
    /// <see cref="Oid4Vp.Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken"/>
    /// (space-separated) when requesting Verifiable Presentations alongside the ID
    /// Token per SIOPv2 §12 / OID4VP.
    /// </summary>
    public static readonly string ResponseTypeIdToken = Utf8Constants.ToInternedString(ResponseTypeIdTokenUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <see cref="ResponseTypeIdToken"/>.</summary>
    public static bool IsResponseTypeIdToken(string value) =>
        string.Equals(value, ResponseTypeIdToken, StringComparison.Ordinal);


    //aud values for Request Objects — SIOPv2 §9.1.

    /// <summary>The UTF-8 source literal of <see cref="StaticDiscoveryRequestObjectAudience"/>.</summary>
    public static ReadOnlySpan<byte> StaticDiscoveryRequestObjectAudienceUtf8 => "https://self-issued.me/v2"u8;

    /// <summary>
    /// The <c>aud</c> claim value of a Request Object when Static Self-Issued OP
    /// Discovery Metadata is used (§9.1): <c>https://self-issued.me/v2</c>. When
    /// Dynamic Discovery is performed, <c>aud</c> is instead the discovered
    /// <c>issuer</c> value.
    /// </summary>
    public static readonly string StaticDiscoveryRequestObjectAudience = Utf8Constants.ToInternedString(StaticDiscoveryRequestObjectAudienceUtf8);
}
