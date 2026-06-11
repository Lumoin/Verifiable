using System.Diagnostics;

namespace Verifiable.OAuth.Siop;

/// <summary>
/// The neutral information model of a Self-Issued OP Authorization Request the RP
/// composes per
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-9">SIOPv2 §9</see>.
/// Serialize it with <see cref="SiopRequestSerializer"/>.
/// </summary>
/// <remarks>
/// This is the direct (non-JAR) request form, where every parameter rides the request
/// URL — the shape behind QR codes and deep links. An RP that signs its request per
/// RFC 9101 instead sends <c>client_id</c> plus <c>request</c>/<c>request_uri</c> and
/// composes the Request Object through the existing JAR machinery, with <c>aud</c> per
/// §9.1 (<see cref="SiopAuthorizationRequestParameterValues.StaticDiscoveryRequestObjectAudience"/>
/// under static discovery).
/// </remarks>
[DebuggerDisplay("SiopRequest ClientId={ClientId}")]
public sealed record SiopRequest
{
    /// <summary>The <c>client_id</c> of the RP (REQUIRED).</summary>
    public required string ClientId { get; init; }

    /// <summary>
    /// The <c>redirect_uri</c> the Self-Issued OP delivers the Authorization Response
    /// to (REQUIRED) — in the cross-device flow (§9.2) the endpoint the OP POSTs the
    /// response to.
    /// </summary>
    public required Uri RedirectUri { get; init; }

    /// <summary>
    /// The <c>nonce</c> (REQUIRED): §9 — RPs MUST send a nonce with every Self-Issued
    /// OP Authorization Request as the basis for replay detection.
    /// </summary>
    public required string Nonce { get; init; }

    /// <summary>
    /// The <c>scope</c>; defaults to <c>openid</c>, which a Self-Issued OP MUST
    /// support (§6.1).
    /// </summary>
    public string Scope { get; init; } = WellKnownScopes.OpenId;

    /// <summary>
    /// The <c>id_token_type</c> parameter — space-separated
    /// <see cref="SiopIdTokenTypes"/> values in order of preference — or
    /// <see langword="null"/> to accept the default
    /// (<see cref="SiopIdTokenTypes.AttesterSignedIdToken"/>).
    /// </summary>
    public string? IdTokenType { get; init; }

    /// <summary>The <c>state</c> parameter, or <see langword="null"/>.</summary>
    public string? State { get; init; }

    /// <summary>
    /// The <c>response_mode</c> — in the cross-device flow (§9.2) the
    /// <c>direct_post</c> value of
    /// <see cref="Oid4Vp.WellKnownResponseModes.DirectPost"/> — or
    /// <see langword="null"/> for the default mode of the response type.
    /// </summary>
    public string? ResponseMode { get; init; }

    /// <summary>
    /// The inline §7.3 <c>client_metadata</c> for a non-pre-registered RP, or
    /// <see langword="null"/>. Mutually exclusive with
    /// <see cref="ClientMetadataUri"/> (§9).
    /// </summary>
    public SiopRelyingPartyMetadata? ClientMetadata { get; init; }

    /// <summary>
    /// The <c>client_metadata_uri</c> a non-pre-registered RP serves its metadata
    /// from, or <see langword="null"/>. Mutually exclusive with
    /// <see cref="ClientMetadata"/> (§9).
    /// </summary>
    public Uri? ClientMetadataUri { get; init; }
}
