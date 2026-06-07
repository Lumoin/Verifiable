using System.Diagnostics;
using Verifiable.Core.Model.Dcql;

namespace Verifiable.OAuth.Oid4Vp;

/// <summary>
/// A typed Authorization Request Object (JAR payload) for the OID4VP cross-device
/// flow, as defined in
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5">OID4VP 1.0 §5</see>
/// and
/// <see href="https://www.rfc-editor.org/rfc/rfc9101">RFC 9101</see>.
/// </summary>
/// <remarks>
/// <para>
/// Represents the claims set of the signed JWT served at the <c>request_uri</c>
/// endpoint with media type <c>application/oauth-authz-req+jwt</c>
/// (<see cref="Verifiable.JCose.WellKnownMediaTypes.Application.OauthAuthzReqJwt"/>).
/// The Wallet fetches and parses this object to determine what credentials to
/// present and where to POST the Authorization Response.
/// </para>
/// <para>
/// Authorization Request parameter name constants are in
/// <see cref="Oid4VpAuthorizationRequestParameterNames"/>. Profile-specific factory methods
/// are in <see cref="HaipProfile"/>. Serialization lives in <c>Verifiable.Json</c>.
/// </para>
/// <para>
/// Property names <see cref="Iat"/>, <see cref="Nbf"/>, <see cref="Exp"/> match
/// the JWT claim abbreviations defined in
/// <see href="https://www.rfc-editor.org/rfc/rfc7519">RFC 7519 §4.1.4–§4.1.6</see>.
/// All three are required because
/// <see href="https://openid.net/specs/fapi-2_0-security-profile.html">FAPI 2.0 Security Profile §5.2.2</see>
/// Clause 13 mandates an <c>exp</c> claim and constrains the <c>exp - nbf</c>
/// window. Setting them unconditionally keeps the library conformant with the
/// most demanding profile it supports;
/// <see cref="Server.TimingPolicy.Oid4VpRequestObjectLifetime"/> controls the
/// chosen window.
/// </para>
/// <para>
/// The <see cref="State"/> claim is OPTIONAL per OID4VP 1.0 §5 / RFC 6749 §4.1.1 — a
/// Wallet MUST accept a request that omits it (parse is decision-gated per call; see
/// the <c>requireState</c> parameter on the parse entry points). When present it
/// carries the per-flow opaque token the Wallet echoes in the direct_post per
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §6.1</see>,
/// letting the Verifier map the inbound response back to the correct flow without
/// leaking the internal flow identifier. The library's own Verifier always emits it
/// (it is the correlation key), so emit stays strict; only parse is relaxed.
/// </para>
/// </remarks>
[DebuggerDisplay("AuthorizationRequestObject ClientId={ClientId} ResponseMode={ResponseMode}")]
public sealed class AuthorizationRequestObject: IEquatable<AuthorizationRequestObject>
{
    /// <summary>
    /// The verifier's client identifier. REQUIRED.
    /// Identifies the Verifier per OID4VP 1.0 §5.9.
    /// </summary>
    /// <remarks>
    /// In OID4VP 1.0 final the Client Identifier Prefix (e.g. <c>x509_san_dns</c>)
    /// is carried INSIDE this value as <c>&lt;prefix&gt;:&lt;id&gt;</c> per §5.9.1;
    /// the draft-era standalone <c>client_id_scheme</c> request parameter was
    /// removed. Derive the prefix via <see cref="WellKnownClientIdPrefixes.TryReadPrefix"/>.
    /// </remarks>
    public required string ClientId { get; init; }

    /// <summary>
    /// The response type. REQUIRED. Always
    /// <see cref="Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken"/> for OID4VP.
    /// </summary>
    public required string ResponseType { get; init; }

    /// <summary>
    /// The response mode. REQUIRED for cross-device flow.
    /// <see cref="WellKnownResponseModes.DirectPostJwt"/> for HAIP 1.0 encrypted responses.
    /// </summary>
    public required string ResponseMode { get; init; }

    /// <summary>
    /// The URI to which the Wallet POSTs the Authorization Response. REQUIRED
    /// when <see cref="ResponseMode"/> is <c>direct_post</c> or <c>direct_post.jwt</c>
    /// per OID4VP 1.0 §8.2.
    /// </summary>
    public required Uri ResponseUri { get; init; }

    /// <summary>
    /// A fresh nonce for replay protection and Key Binding JWT binding.
    /// REQUIRED per OID4VP 1.0 §5.2.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// The opaque per-flow token the Wallet echoes verbatim in the direct_post
    /// response per <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OID4VP 1.0 §6.1</see>
    /// and <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.1">RFC 6749 §4.1.1</see>.
    /// OPTIONAL — <see langword="null"/> when the Verifier omitted it; the Wallet echoes
    /// it only when present.
    /// </summary>
    /// <remarks>
    /// In the OID4VP server flow this value equals the per-flow token the PAR
    /// endpoint generated. The Verifier's
    /// <see cref="Server.AuthorizationServerIntegration.ResolveCorrelationKeyAsync"/>
    /// maps the echoed value back to the internal flow identifier on the
    /// inbound direct_post.
    /// </remarks>
    public string? State { get; init; }

    /// <summary>
    /// The instant the Authorization Request Object was issued. REQUIRED.
    /// Serialized as the <c>iat</c> JWT claim per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6">RFC 7519 §4.1.6</see>.
    /// </summary>
    public required DateTimeOffset Iat { get; init; }

    /// <summary>
    /// The earliest instant the Authorization Request Object is valid. REQUIRED.
    /// Serialized as the <c>nbf</c> JWT claim per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5">RFC 7519 §4.1.5</see>.
    /// </summary>
    public required DateTimeOffset Nbf { get; init; }

    /// <summary>
    /// The instant after which the Authorization Request Object MUST NOT be
    /// accepted. REQUIRED per
    /// <see href="https://openid.net/specs/fapi-2_0-security-profile.html">FAPI 2.0 §5.2.2</see>
    /// Clause 13. Serialized as the <c>exp</c> JWT claim per
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4">RFC 7519 §4.1.4</see>.
    /// </summary>
    public required DateTimeOffset Exp { get; init; }

    /// <summary>
    /// The DCQL query specifying the requested credentials. REQUIRED when neither
    /// <c>presentation_definition</c> nor a scope representing a query is present
    /// per OID4VP 1.0 §5.1.
    /// </summary>
    public DcqlQuery? DcqlQuery { get; init; }

    /// <summary>
    /// Inline Verifier metadata. OPTIONAL. Contains the JWKS for response
    /// encryption and supported formats per OID4VP 1.0 §5.1 and §11.
    /// </summary>
    public VerifierClientMetadata? ClientMetadata { get; init; }

    /// <summary>
    /// The issuer identifier of the Verifier. OPTIONAL per RFC 9101.
    /// When present the Wallet MUST ignore it to avoid breaking JAR
    /// implementations per OID4VP 1.0 §5.8.
    /// </summary>
    public string? Iss { get; init; }

    /// <summary>
    /// The intended audience. REQUIRED in signed Request Objects per OID4VP 1.0 §5.8.
    /// Set to the authorization server issuer identifier when Dynamic Discovery is
    /// used, or to <c>https://self-issued.me/v2</c> when Static Discovery is used.
    /// </summary>
    public string? Aud { get; init; }

    /// <summary>
    /// The <c>transaction_data</c> parameter per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4">OID4VP 1.0 §8.4</see>.
    /// OPTIONAL.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each entry is the verbatim base64url-encoded JSON string the Verifier
    /// sent — the Wallet hashes the original ASCII bytes (not the decoded
    /// JSON) into the KB-JWT's <c>transaction_data_hashes</c> claim. Storing
    /// the wire form here keeps that hash deterministic across decode/re-encode
    /// round trips and any whitespace normalisation a JSON parser might apply.
    /// </para>
    /// <para>
    /// The Wallet decodes each entry to inspect the <c>type</c> and
    /// <c>credential_ids</c> fields for consent purposes; the encoded form
    /// remains authoritative for hashing.
    /// </para>
    /// </remarks>
    public IReadOnlyList<string>? TransactionData { get; init; }

    /// <summary>
    /// The <c>wallet_nonce</c> claim echoed by the Verifier per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.10">OID4VP 1.0 §5.10</see>
    /// when the Wallet fetched the JAR via <c>request_uri_method=post</c>.
    /// OPTIONAL — present only on the JAR served in response to a wallet POST.
    /// </summary>
    /// <remarks>
    /// The Wallet generates this nonce locally, sends it in the POST body to
    /// <c>request_uri</c>, and verifies the value echoed in the JAR matches
    /// what it sent. The echo prevents an attacker from replaying a stale JAR
    /// from a prior wallet-initiated exchange.
    /// </remarks>
    public string? WalletNonce { get; init; }


    /// <inheritdoc/>
    public bool Equals(AuthorizationRequestObject? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(ClientId, other.ClientId, StringComparison.Ordinal)
            && string.Equals(ResponseType, other.ResponseType, StringComparison.Ordinal)
            && string.Equals(ResponseMode, other.ResponseMode, StringComparison.Ordinal)
            && ResponseUri == other.ResponseUri
            && string.Equals(Nonce, other.Nonce, StringComparison.Ordinal)
            && string.Equals(State, other.State, StringComparison.Ordinal)
            && Iat == other.Iat
            && Nbf == other.Nbf
            && Exp == other.Exp
            && string.Equals(Iss, other.Iss, StringComparison.Ordinal)
            && string.Equals(Aud, other.Aud, StringComparison.Ordinal)
            && Equals(ClientMetadata, other.ClientMetadata)
            && TransactionDataSequenceEquals(TransactionData, other.TransactionData)
            && string.Equals(WalletNonce, other.WalletNonce, StringComparison.Ordinal);
    }


    private static bool TransactionDataSequenceEquals(
        IReadOnlyList<string>? left, IReadOnlyList<string>? right)
    {
        if(ReferenceEquals(left, right))
        {
            return true;
        }

        if(left is null || right is null)
        {
            return false;
        }

        if(left.Count != right.Count)
        {
            return false;
        }

        for(int i = 0; i < left.Count; i++)
        {
            if(!string.Equals(left[i], right[i], StringComparison.Ordinal))
            {
                return false;
            }
        }

        return true;
    }

    /// <inheritdoc/>
    public override bool Equals(object? obj) =>
        obj is AuthorizationRequestObject other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode() =>
        HashCode.Combine(ClientId, ResponseType, ResponseMode, ResponseUri, Nonce, State, Exp);

    /// <summary>Determines whether two instances are equal.</summary>
    public static bool operator ==(
        AuthorizationRequestObject? left,
        AuthorizationRequestObject? right) =>
        left is null ? right is null : left.Equals(right);

    /// <summary>Determines whether two instances differ.</summary>
    public static bool operator !=(
        AuthorizationRequestObject? left,
        AuthorizationRequestObject? right) =>
        !(left == right);
}
