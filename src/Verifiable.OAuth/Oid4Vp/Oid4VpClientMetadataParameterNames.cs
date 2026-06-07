using System.Diagnostics;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Member NAMES of the OID4VP <c>client_metadata</c> (Verifier Metadata) object per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-11">OID4VP 1.0 §11</see>.
/// </summary>
/// <remarks>
/// <para>
/// The sibling of <see cref="Oid4VpAuthorizationRequestParameterNames"/>: that class
/// names the top-level Authorization Request parameters (§5), this one names the
/// members carried INSIDE the <c>client_metadata</c> parameter's value (§11.1, §8.3).
/// All are snake_case per the spec; the <c>Verifiable.OAuth</c> POCO
/// (<see cref="VerifierClientMetadata"/>) carries no serialization attributes, so its
/// wire member names live here and are consumed by the converter in
/// <c>Verifiable.Json</c>.
/// </para>
/// <para>
/// Declared <see langword="static readonly"/> (not <see langword="const"/>) to match
/// <see cref="Oid4VpAuthorizationRequestParameterNames"/> and avoid cross-assembly const
/// inlining; the converter matches them with ordinal string comparison rather than
/// <c>case</c> labels.
/// </para>
/// </remarks>
[DebuggerDisplay("Oid4VpClientMetadataParameterNames")]
public static class Oid4VpClientMetadataParameterNames
{
    /// <summary>The <c>client_id</c> member echoing the Verifier's client identifier.</summary>
    public static readonly string ClientId = "client_id";

    /// <summary>The <c>jwks</c> member carrying the Verifier's response-encryption keys (§8.3).</summary>
    public static readonly string Jwks = "jwks";

    /// <summary>The <c>vp_formats_supported</c> member — the credential-format support map (§11.1).</summary>
    public static readonly string VpFormatsSupported = "vp_formats_supported";

    /// <summary>The <c>encrypted_response_enc_values_supported</c> member — JWE <c>enc</c> algorithms.</summary>
    public static readonly string EncryptedResponseEncValuesSupported = "encrypted_response_enc_values_supported";

    /// <summary>The <c>encrypted_response_alg_values_supported</c> member — JWE <c>alg</c> algorithms.</summary>
    public static readonly string EncryptedResponseAlgValuesSupported = "encrypted_response_alg_values_supported";


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>client_id</c>.</summary>
    public static bool IsClientId(string value) =>
        string.Equals(value, ClientId, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>jwks</c>.</summary>
    public static bool IsJwks(string value) =>
        string.Equals(value, Jwks, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>vp_formats_supported</c>.</summary>
    public static bool IsVpFormatsSupported(string value) =>
        string.Equals(value, VpFormatsSupported, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>encrypted_response_enc_values_supported</c>.</summary>
    public static bool IsEncryptedResponseEncValuesSupported(string value) =>
        string.Equals(value, EncryptedResponseEncValuesSupported, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is exactly <c>encrypted_response_alg_values_supported</c>.</summary>
    public static bool IsEncryptedResponseAlgValuesSupported(string value) =>
        string.Equals(value, EncryptedResponseAlgValuesSupported, StringComparison.Ordinal);
}
