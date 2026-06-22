using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Core.Model.Did;

namespace Verifiable.DidComm;

/// <summary>
/// A single parsed <c>serviceEndpoint</c> object of a <c>DIDCommMessaging</c> service — the transport
/// <c>uri</c> and its associated <c>accept</c> profiles and <c>routingKeys</c>, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#service-endpoint">DIDComm Messaging v2.1 §Service Endpoint</see>.
/// </summary>
/// <remarks>
/// This is the data view of a declared endpoint, not a verification proof: a service endpoint is freely-constructible
/// configuration read from a (untrusted) DID document, so it is a plain record. The <see cref="Uri"/> is either a
/// transport URI the sender delivers to, or a mediator DID that is resolved to its own DIDCommMessaging endpoint
/// (<see cref="IsDidUri"/>); endpoint selection and that mediator indirection are resolved by
/// <see cref="DidCommServiceEndpointExtensions"/>.
/// </remarks>
public sealed record DidCommServiceEndpoint
{
    /// <summary>REQUIRED. The endpoint <c>uri</c> — a transport URI, or a mediator DID (DIDComm v2.1 §Service Endpoint).</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "A serviceEndpoint uri is an opaque DIDComm token carried verbatim — it may be a mediator DID (e.g. 'did:example:somemediator') rather than a dereferenceable System.Uri.")]
    public required string Uri { get; init; }

    /// <summary>
    /// OPTIONAL. The <c>accept</c> media-type/profile preferences of the endpoint, or <see langword="null"/> when
    /// the endpoint declares none (DIDComm v2.1 §Service Endpoint).
    /// </summary>
    public IReadOnlyList<string>? Accept { get; init; }

    /// <summary>
    /// The <c>routingKeys</c> for the forward wrap, in order; empty when the endpoint declares none
    /// (DIDComm v2.1 §Service Endpoint).
    /// </summary>
    public IReadOnlyList<string> RoutingKeys { get; init; } = [];


    /// <summary>
    /// Whether this endpoint accepts the <c>didcomm/v2</c> profile (DIDComm v2.1 §Service Endpoint, §Negotiating
    /// Compatibility). An absent or empty <c>accept</c> is treated as accepting — the <c>DIDCommMessaging</c> type
    /// already declares DIDComm support and the spec says "If accept is not specified, the sender uses its preferred
    /// choice" (spec §Service Endpoint, accept OPTIONAL); a present <c>accept</c> that lacks <c>didcomm/v2</c>
    /// advertises a different profile and is not a v2 endpoint. This follows the spec's optional-accept rule and is
    /// deliberately more lenient than the didcomm-python reference, whose service selection requires an explicit
    /// <c>didcomm/v2</c> in <c>accept</c> and so skips an absent-accept (including bare-string) endpoint.
    /// </summary>
    public bool AcceptsDidCommV2
    {
        get
        {
            if(Accept is not { Count: > 0 } profiles)
            {
                return true;
            }

            foreach(string profile in profiles)
            {
                if(string.Equals(profile, WellKnownRoutingNames.Profile, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }
    }


    /// <summary>
    /// Whether the endpoint <see cref="Uri"/> is itself a DID (a mediator indirection) rather than a transport URI
    /// (DIDComm v2.1 §Service Endpoint §Using a DID as an endpoint). A DID <c>uri</c> is resolved to the mediator's
    /// own DIDCommMessaging endpoint.
    /// </summary>
    public bool IsDidUri => IsDidOrDidUrl(Uri);


    //Whether the value parses as a DID or DID URL carrying a method and method-specific id (a key id with a fragment
    //is allowed). Mirrors the recipient/routing-key identifier test used by the routing forward path.
    private static bool IsDidOrDidUrl(string identifier)
    {
        return !string.IsNullOrEmpty(identifier)
            && DidUrl.TryParse(identifier, out DidUrl? didUrl)
            && didUrl.IsAbsolute
            && !string.IsNullOrEmpty(didUrl.Method)
            && !string.IsNullOrEmpty(didUrl.MethodSpecificId);
    }
}
