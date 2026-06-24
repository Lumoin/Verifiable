using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Resolvers;

namespace Verifiable.DidComm.Routing;

/// <summary>
/// Reads and resolves a recipient's <c>DIDCommMessaging</c> service endpoints — parsing the declared endpoints from a
/// DID document and resolving the concrete delivery targets a sender transmits to, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#service-endpoint">DIDComm Messaging v2.1 §Service Endpoint</see>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="GetDidCommServiceEndpoints"/> is the pure read: it parses every <c>DIDCommMessaging</c> service's
/// <c>serviceEndpoint</c> — the single-object, array-of-objects, and bare-string forms — into
/// <see cref="DidCommServiceEndpoint"/>s in the document's preference order, keeping those that accept the
/// <c>didcomm/v2</c> profile. <see cref="ResolveDeliveryTargetsAsync"/> is the sender-facing resolution: for each
/// endpoint it produces a <see cref="DidCommDeliveryTarget"/> (a concrete transport URI plus the routing keys), with a
/// mediator-DID <c>uri</c> resolved to the mediator's own transport URI and the mediator DID prepended to the routing
/// keys (DIDComm v2.1 §Service Endpoint §Using a DID as an endpoint).
/// </para>
/// <para>
/// Resolution is fail-soft over untrusted DID-document input: an unresolvable recipient or mediator, a mediator with no
/// <c>didcomm/v2</c> endpoint, or a recursive alternative endpoint (a mediator whose own <c>uri</c> is again a DID,
/// which the spec says SHOULD NOT occur) yields that target being skipped rather than a thrown exception, so the sender
/// receives the usable targets in failover order (DIDComm v2.1 §Failover).
/// </para>
/// </remarks>
public static class DidCommServiceEndpointExtensions
{
    /// <summary>
    /// Parses the <c>DIDCommMessaging</c> service endpoints advertised by <paramref name="document"/>, in preference
    /// order, keeping those that accept the <c>didcomm/v2</c> profile.
    /// </summary>
    /// <param name="document">The DID document to read.</param>
    /// <returns>The declared endpoints in document order; empty when none are advertised.</returns>
    public static IReadOnlyList<DidCommServiceEndpoint> GetDidCommServiceEndpoints(this DidDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var endpoints = new List<DidCommServiceEndpoint>();
        foreach(Service service in document.FindServicesByType(WellKnownDidCommServiceNames.DidCommMessagingServiceType))
        {
            ParseServiceEndpoints(service, endpoints);
        }

        return endpoints;
    }


    /// <summary>
    /// Resolves the ordered delivery targets for <paramref name="to"/> — each a concrete transport URI and the routing
    /// keys the message is wrapped for — selecting the recipient's <c>DIDCommMessaging</c> endpoints and resolving any
    /// mediator-DID <c>uri</c> to the mediator's transport URI (DIDComm v2.1 §Service Endpoint).
    /// </summary>
    /// <param name="to">The recipient DID (or DID URL) whose service endpoints are resolved.</param>
    /// <param name="didResolver">Resolver for the recipient and any mediator DID documents.</param>
    /// <param name="exchangeContext">The per-operation exchange context threaded to resolution.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The usable delivery targets in the document's preference order (for failover); empty when none resolve.</returns>
    public static async ValueTask<IReadOnlyList<DidCommDeliveryTarget>> ResolveDeliveryTargetsAsync(
        string to,
        DidResolver didResolver,
        ExchangeContext exchangeContext,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(to);
        ArgumentNullException.ThrowIfNull(didResolver);
        ArgumentNullException.ThrowIfNull(exchangeContext);

        DidDocument? recipientDocument = await ResolveDocumentAsync(BaseDidOf(to), didResolver, exchangeContext, cancellationToken).ConfigureAwait(false);
        if(recipientDocument is null)
        {
            return [];
        }

        var targets = new List<DidCommDeliveryTarget>();
        foreach(DidCommServiceEndpoint endpoint in recipientDocument.GetDidCommServiceEndpoints())
        {
            if(!endpoint.IsDidUri)
            {
                //A direct transport endpoint: deliver to its URI, wrapping for its own routing keys. The helper
                //rejects a non-absolute uri at resolution time (defense-in-depth above the SSRF-policed
                //OutboundFetch backstop): a transport endpoint MUST be an absolute URI, so a relative or malformed
                //value is dropped rather than carried forward as a bogus delivery target.
                AddDeliveryTargetIfAbsolute(targets, endpoint.Uri, endpoint.Accept, endpoint.RoutingKeys);

                continue;
            }

            //A mediator-DID uri: resolve the mediator's first didcomm/v2 endpoint and use its transport URI. The
            //mediator DID is prepended to the routing keys so the outer forward is wrapped for the mediator's
            //keyAgreement keys (DIDComm v2.1 §Service Endpoint §Using a DID as an endpoint). Only ONE hop is
            //followed: a mediator whose own endpoint is again a DID is a recursive alternative endpoint and is
            //skipped (spec §Using a DID as an endpoint: a mediator SHOULD NOT use alternative endpoints). An
            //unresolvable mediator, or one with no didcomm/v2 endpoint, drops the WHOLE target (a delivery with no
            //resolvable transport is unusable) and the sender fails over to the recipient's next endpoint.
            DidDocument? mediatorDocument = await ResolveDocumentAsync(BaseDidOf(endpoint.Uri), didResolver, exchangeContext, cancellationToken).ConfigureAwait(false);
            if(mediatorDocument is null)
            {
                continue;
            }

            IReadOnlyList<DidCommServiceEndpoint> mediatorEndpoints = mediatorDocument.GetDidCommServiceEndpoints();
            if(mediatorEndpoints.Count == 0 || mediatorEndpoints[0].IsDidUri)
            {
                continue;
            }

            var routingKeys = new List<string>(endpoint.RoutingKeys.Count + 1) { endpoint.Uri };
            routingKeys.AddRange(endpoint.RoutingKeys);

            //The accept set is the mediator endpoint's: that is the transport actually transmitted to (the outer
            //forward envelope is delivered to the mediator), and §Service Endpoint scopes accept to "sending a
            //message to the endpoint". The same absolute-URI guard the direct branch applies is applied here: a
            //mediator's resolved transport uri comes from a second untrusted DID document.
            AddDeliveryTargetIfAbsolute(targets, mediatorEndpoints[0].Uri, mediatorEndpoints[0].Accept, routingKeys);
        }

        return targets;
    }


    //Emits a delivery target only when the transport uri is an absolute URI: a relative or malformed value from
    //an (untrusted) DID document is dropped rather than carried forward as a bogus target whose scheme cannot be
    //derived — defense-in-depth above the SSRF-policed OutboundFetch backstop. Applied to BOTH the recipient's
    //own endpoint and a mediator's resolved endpoint (each comes from an untrusted document).
    private static void AddDeliveryTargetIfAbsolute(List<DidCommDeliveryTarget> targets, string transportUri, IReadOnlyList<string>? accept, IReadOnlyList<string> routingKeys)
    {
        if(!Uri.TryCreate(transportUri, UriKind.Absolute, out _))
        {
            return;
        }

        targets.Add(new DidCommDeliveryTarget { TransportUri = transportUri, Accept = accept, RoutingKeys = routingKeys });
    }


    //Parses every serviceEndpoint form a service may carry into endpoints, keeping the didcomm/v2 ones. The three
    //forms are mutually exclusive per service — the DID converter populates exactly one of ServiceEndpoint /
    //ServiceEndpointMap / ServiceEndpoints from the single serviceEndpoint JSON value — so iterating the services in
    //document order (FindServicesByType) and the array elements in order preserves the spec's preference order.
    private static void ParseServiceEndpoints(Service service, List<DidCommServiceEndpoint> into)
    {
        //The bare-string endpoint form (Service.ServiceEndpoint): a URI with no accept/routingKeys.
        if(service.ServiceEndpoint is { Length: > 0 } bareUri)
        {
            AddIfDidCommV2(into, new DidCommServiceEndpoint { Uri = bareUri });
        }

        //The single-object form (Service.ServiceEndpointMap).
        if(service.ServiceEndpointMap is { } map && ParseEndpointMap(map) is DidCommServiceEndpoint endpoint)
        {
            AddIfDidCommV2(into, endpoint);
        }

        //The array-of-objects form (Service.ServiceEndpoints): each element an object map or a bare URI string.
        if(service.ServiceEndpoints is { } list)
        {
            foreach(object element in list)
            {
                DidCommServiceEndpoint? parsed = element switch
                {
                    string s when s.Length > 0 => new DidCommServiceEndpoint { Uri = s },
                    IDictionary<string, object> elementMap => ParseEndpointMap(elementMap),
                    _ => null
                };

                if(parsed is not null)
                {
                    AddIfDidCommV2(into, parsed);
                }
            }
        }
    }


    private static void AddIfDidCommV2(List<DidCommServiceEndpoint> into, DidCommServiceEndpoint endpoint)
    {
        if(endpoint.AcceptsDidCommV2)
        {
            into.Add(endpoint);
        }
    }


    //Parses a serviceEndpoint object map into an endpoint, or null when it lacks the REQUIRED uri.
    private static DidCommServiceEndpoint? ParseEndpointMap(IDictionary<string, object> map)
    {
        if(!map.TryGetValue(WellKnownDidCommServiceNames.Uri, out object? uriValue) || uriValue is not string uri || uri.Length == 0)
        {
            return null;
        }

        return new DidCommServiceEndpoint
        {
            Uri = uri,
            Accept = ReadStringList(map, WellKnownDidCommServiceNames.Accept),
            RoutingKeys = ReadStringList(map, WellKnownDidCommServiceNames.RoutingKeys) ?? []
        };
    }


    //Reads a string-array member from a serviceEndpoint map. The DID converter materializes a JSON array as a
    //List<object> of strings; a directly-constructed model may use List<string>. A non-string element is dropped.
    private static IReadOnlyList<string>? ReadStringList(IDictionary<string, object> map, string key)
    {
        if(!map.TryGetValue(key, out object? value) || value is null)
        {
            return null;
        }

        return value switch
        {
            IReadOnlyList<string> list => list,
            IEnumerable<string> sequence => [.. sequence],
            IEnumerable<object> boxed => ProjectStrings(boxed),
            _ => null
        };
    }


    private static List<string> ProjectStrings(IEnumerable<object> values)
    {
        var result = new List<string>();
        foreach(object value in values)
        {
            if(value is string text)
            {
                result.Add(text);
            }
        }

        return result;
    }


    private static async ValueTask<DidDocument?> ResolveDocumentAsync(string did, DidResolver didResolver, ExchangeContext exchangeContext, CancellationToken cancellationToken)
    {
        DidResolutionResult resolution = await didResolver
            .ResolveAsync(did, exchangeContext, options: null, cancellationToken)
            .ConfigureAwait(false);

        return resolution.IsSuccessful ? resolution.Document : null;
    }


    //The base DID of a DID or DID URL: the value stripped of path/query/fragment, or verbatim when already a bare DID.
    private static string BaseDidOf(string didOrDidUrl) =>
        DidUrl.TryParse(didOrDidUrl, out DidUrl? didUrl) && didUrl.BaseDid is string baseDid
            ? baseDid
            : didOrDidUrl;
}
