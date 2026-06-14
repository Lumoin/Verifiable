using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.Vcalm;

/// <summary>
/// The W3C VCALM 1.0 §3.7.4 protocols map an interaction supports — protocol identifier → initiation
/// URL. The coordinator's <c>ResolveVcalmInteractionProtocolsAsync</c> seam produces it for a
/// §3.7.1 interaction id; the §3.7.4 endpoint renders it as the <c>{protocols:{…}}</c> JSON body when
/// the client accepts <c>application/json</c>.
/// </summary>
/// <remarks>
/// <para>
/// §3.7.4: the response "MUST be returned where each key is a protocol identifier and each value is a
/// URL that can be used to initiate the interaction." The named members map to the §3.7.4 /
/// §3.6.4-mirrored protocol identifiers: <see cref="InviteRequestUrl"/> (§3.7.5 holder-initiated),
/// <see cref="VcapiUrl"/> (§3.7.6 — addresses a §3.6 exchange's §3.6.5 participate URL),
/// <see cref="OpenId4VpUrl"/>, <see cref="OpenId4VciUrl"/>, and <see cref="InteractUrl"/>. Every member
/// is OPTIONAL; the §3.7.4 examples show a degenerate map carrying only <c>inviteRequest</c>, so the
/// coordinator advertises exactly the protocols it (or a delegated partner) supports for the
/// interaction. The §3.7.6 cross-protocol bridges (OID4VP / OID4VCI / DIDComm) are deferred by the spec
/// to "Appendix TBD"; the coordinator ADVERTISES their URLs here when it supports them but the library
/// implements only the vcapi entry's §3.6 exchange and the inviteRequest entry.
/// </para>
/// </remarks>
[DebuggerDisplay("VcalmInteractionProtocols")]
public sealed record VcalmInteractionProtocols
{
    /// <summary>
    /// The §3.7.4 <c>inviteRequest</c> URL — where the local system POSTs a §3.7.5 invitation request,
    /// or <see langword="null"/> when the interaction does not offer the holder-initiated protocol.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "The §3.7.4 protocol URLs are verbatim wire strings the coordinator's resolver composed; they ride through to the response body unparsed.")]
    public string? InviteRequestUrl { get; init; }

    /// <summary>
    /// The §3.7.4 / §3.7.6 <c>vcapi</c> URL — the §3.6.5 participate URL of the §3.6 exchange this
    /// interaction initiates ("The vcapi interaction protocol is used to initiate a specific exchange
    /// as described in Section 3.6.5"), or <see langword="null"/> when the interaction does not offer
    /// the vcapi protocol.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "The §3.7.4 protocol URLs are verbatim wire strings the coordinator's resolver composed; they ride through to the response body unparsed.")]
    public string? VcapiUrl { get; init; }

    /// <summary>
    /// The §3.7.4 <c>OID4VP</c> URL — the URL to use when initiating an OID4VP presentation, or
    /// <see langword="null"/> when not offered. The library only ADVERTISES it (the §3.7.6 OID4VP
    /// bridge is spec-deferred); a deployment supplies the verbatim <c>openid4vp://</c> URL.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "The §3.7.4 OID4VP URL is a verbatim wire string (itself a non-http openid4vp:// URI) the coordinator composed; System.Uri would force a round-trip that loses its exact shape.")]
    public string? OpenId4VpUrl { get; init; }

    /// <summary>
    /// The §3.7.4 <c>OID4VCI</c> URL — the URL to use when initiating an OID4VCI issuance, or
    /// <see langword="null"/> when not offered. The library only ADVERTISES it (the §3.7.6 OID4VCI
    /// bridge is spec-deferred).
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "The §3.7.4 OID4VCI URL is a verbatim wire string the coordinator composed; it rides through to the response body unparsed.")]
    public string? OpenId4VciUrl { get; init; }

    /// <summary>
    /// The §3.7.4 <c>interact</c> URL — "A URL that can be used during exchange flows with a human in
    /// the loop", or <see langword="null"/> when not offered.
    /// </summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "The §3.7.4 interact URL is a verbatim wire string the coordinator composed; it rides through to the response body unparsed.")]
    public string? InteractUrl { get; init; }


    /// <summary>
    /// Whether the map advertises at least one protocol. §3.7.4 requires a non-empty
    /// <c>protocols</c> object (the degenerate case still carries one entry); a map with no protocols
    /// is an interaction the coordinator cannot bootstrap, which the §3.7.4 endpoint surfaces rather
    /// than rendering an empty object.
    /// </summary>
    public bool HasAnyProtocol =>
        InviteRequestUrl is not null
        || VcapiUrl is not null
        || OpenId4VpUrl is not null
        || OpenId4VciUrl is not null
        || InteractUrl is not null;
}
