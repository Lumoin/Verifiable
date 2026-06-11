using System.Diagnostics;
using System.Text;
using Verifiable.Cryptography.Text;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// Authorization Request parameter NAMES native to OpenID for Verifiable
/// Presentations 1.0 per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5">OID4VP 1.0 §5</see>.
/// </summary>
/// <remarks>
/// <para>
/// These are the NAMES of OID4VP-native request parameters
/// (<c>"response_uri"</c>, <c>"dcql_query"</c>,
/// <c>"client_metadata"</c>), not their VALUES. Parameter values
/// constrained to a small enumerated set (currently only the
/// <c>response_type</c> value <c>"vp_token"</c>) live in
/// <see cref="Oid4VpAuthorizationRequestParameterValues"/>; most other
/// values are flow-specific (DCQL queries, URIs, inline client metadata
/// objects).
/// </para>
/// <para>
/// Contains only parameters that do not exist in base OAuth 2.0.
/// Parameters inherited from OAuth 2.0 without semantic change —
/// <c>response_type</c>, <c>client_id</c>, <c>state</c>, <c>response_mode</c> —
/// are defined in <see cref="Verifiable.OAuth.OAuthRequestParameterNames"/>.
/// JWT claim names used in JAR payloads — <c>iss</c>, <c>aud</c>,
/// <c>nonce</c>, <c>client_id</c> — are defined in
/// <see cref="Verifiable.JCose.WellKnownJwtClaimNames"/>.
/// </para>
/// <para>
/// Used when constructing or parsing a JAR JWT payload, or when encoding a
/// direct (non-JAR) authorization request as form or query parameters.
/// </para>
/// </remarks>
[DebuggerDisplay("Oid4VpAuthorizationRequestParameterNames")]
public static class Oid4VpAuthorizationRequestParameterNames
{
    //The draft-era standalone client_id_scheme request parameter was REMOVED in
    //OID4VP 1.0 final; the Client Identifier Prefix is carried inside client_id
    //(<prefix>:<id>, §5.9.1). No constant for it — see WellKnownClientIdPrefixes.

    /// <summary>The UTF-8 source literal of <see cref="ResponseUri"/>.</summary>
    public static ReadOnlySpan<byte> ResponseUriUtf8 => "response_uri"u8;

    /// <summary>The <c>response_uri</c> parameter — the endpoint to POST the response to.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-7.2">OID4VP 1.0 §7.2</see>.</remarks>
    public static readonly string ResponseUri = Utf8Constants.ToInternedString(ResponseUriUtf8);

    /// <summary>The UTF-8 source literal of <see cref="DcqlQuery"/>.</summary>
    public static ReadOnlySpan<byte> DcqlQueryUtf8 => "dcql_query"u8;

    /// <summary>The <c>dcql_query</c> parameter carrying the DCQL query object.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6">OID4VP 1.0 §6</see>.</remarks>
    public static readonly string DcqlQuery = Utf8Constants.ToInternedString(DcqlQueryUtf8);

    /// <summary>The UTF-8 source literal of <see cref="ClientMetadata"/>.</summary>
    public static ReadOnlySpan<byte> ClientMetadataUtf8 => "client_metadata"u8;

    /// <summary>The <c>client_metadata</c> parameter carrying inline verifier metadata.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.11">OID4VP 1.0 §5.11</see>.</remarks>
    public static readonly string ClientMetadata = Utf8Constants.ToInternedString(ClientMetadataUtf8);

    /// <summary>The UTF-8 source literal of <see cref="TransactionData"/>.</summary>
    public static ReadOnlySpan<byte> TransactionDataUtf8 => "transaction_data"u8;

    /// <summary>The <c>transaction_data</c> parameter carrying base64url-encoded
    /// transaction-data descriptors the Wallet must bind into the KB-JWT.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4">OID4VP 1.0 §8.4</see>.</remarks>
    public static readonly string TransactionData = Utf8Constants.ToInternedString(TransactionDataUtf8);

    /// <summary>The UTF-8 source literal of <see cref="RequestUriMethod"/>.</summary>
    public static ReadOnlySpan<byte> RequestUriMethodUtf8 => "request_uri_method"u8;

    /// <summary>The <c>request_uri_method</c> parameter — <c>"get"</c> (default)
    /// or <c>"post"</c> — that signals which HTTP method the Wallet uses to
    /// fetch the JAR from the <c>request_uri</c>.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>.</remarks>
    public static readonly string RequestUriMethod = Utf8Constants.ToInternedString(RequestUriMethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="WalletNonce"/>.</summary>
    public static ReadOnlySpan<byte> WalletNonceUtf8 => "wallet_nonce"u8;

    /// <summary>The <c>wallet_nonce</c> form-body parameter the Wallet sends in
    /// its POST to <c>request_uri</c>, and that the Verifier echoes as a
    /// claim in the signed JAR for replay-binding.</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.1">OID4VP 1.0 §5.10.1</see>.</remarks>
    public static readonly string WalletNonce = Utf8Constants.ToInternedString(WalletNonceUtf8);

    /// <summary>The UTF-8 source literal of <see cref="WalletMetadata"/>.</summary>
    public static ReadOnlySpan<byte> WalletMetadataUtf8 => "wallet_metadata"u8;

    /// <summary>The <c>wallet_metadata</c> form-body parameter the Wallet sends
    /// in its POST to <c>request_uri</c>, carrying the Wallet's metadata so
    /// the Verifier can tailor the JAR (e.g. choose supported formats /
    /// algorithms).</summary>
    /// <remarks>See <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10.1">OID4VP 1.0 §5.10.1</see>.</remarks>
    public static readonly string WalletMetadata = Utf8Constants.ToInternedString(WalletMetadataUtf8);


    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>response_uri</c>.</summary>
    public static bool IsResponseUri(string value) =>
        string.Equals(value, ResponseUri, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>dcql_query</c>.</summary>
    public static bool IsDcqlQuery(string value) =>
        string.Equals(value, DcqlQuery, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>client_metadata</c>.</summary>
    public static bool IsClientMetadata(string value) =>
        string.Equals(value, ClientMetadata, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>transaction_data</c>.</summary>
    public static bool IsTransactionData(string value) =>
        string.Equals(value, TransactionData, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>request_uri_method</c>.</summary>
    public static bool IsRequestUriMethod(string value) =>
        string.Equals(value, RequestUriMethod, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>wallet_nonce</c>.</summary>
    public static bool IsWalletNonce(string value) =>
        string.Equals(value, WalletNonce, StringComparison.Ordinal);

    /// <summary>Returns <see langword="true"/> when <paramref name="value"/> is
    /// exactly <c>wallet_metadata</c>.</summary>
    public static bool IsWalletMetadata(string value) =>
        string.Equals(value, WalletMetadata, StringComparison.Ordinal);


    /// <summary>
    /// Returns the canonical form of a well-known OID4VP-native Authorization
    /// Request parameter name, or the original value when not recognized.
    /// Comparison is case-sensitive per OID4VP 1.0 §5.
    /// </summary>
    public static string GetCanonicalizedValue(string value) => value switch
    {
        _ when IsResponseUri(value) => ResponseUri,
        _ when IsDcqlQuery(value) => DcqlQuery,
        _ when IsClientMetadata(value) => ClientMetadata,
        _ when IsTransactionData(value) => TransactionData,
        _ when IsRequestUriMethod(value) => RequestUriMethod,
        _ when IsWalletNonce(value) => WalletNonce,
        _ when IsWalletMetadata(value) => WalletMetadata,
        _ => value
    };
}
