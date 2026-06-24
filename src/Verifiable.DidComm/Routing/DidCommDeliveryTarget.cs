using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Verifiable.Foundation;

namespace Verifiable.DidComm.Routing;

/// <summary>
/// A resolved DIDComm delivery option for a recipient — the concrete transport URI to transmit to, and the ordered
/// routing keys the message is wrapped for, per
/// <see href="https://identity.foundation/didcomm-messaging/spec/v2.1/#service-endpoint">DIDComm Messaging v2.1 §Service Endpoint</see>.
/// </summary>
/// <remarks>
/// <para>
/// Produced by <see cref="DidCommServiceEndpointExtensions.ResolveDeliveryTargetsAsync"/>: a recipient's
/// DIDCommMessaging endpoints, with any mediator-DID <c>uri</c> resolved to the mediator's transport URI and the
/// mediator DID prepended to the routing keys (DIDComm v2.1 §Service Endpoint §Using a DID as an endpoint). The sender
/// wraps the packed message for <see cref="RoutingKeys"/> via
/// <see cref="RoutingForwardExtensions.WrapInForwardAsync(DidCommEncryptedMessage, string, System.Collections.Generic.IReadOnlyList{string}, Verifiable.Core.Resolvers.DidResolver, Verifiable.Cryptography.Context.ExchangeContext, Verifiable.Cryptography.EphemeralKeyPairFactory, string, Verifiable.DidComm.DidCommMessageSerializer, Verifiable.JCose.JwtHeaderSerializer, Verifiable.Cryptography.EncodeDelegate, Verifiable.Cryptography.TagToEpkCrvDelegate, Verifiable.Cryptography.GenerateNonceDelegate, System.Buffers.MemoryPool{byte}, System.Threading.CancellationToken)"/>
/// and transmits the result to <see cref="TransportUri"/>; the transmission itself is the application's transport
/// concern (this project carries no <c>System.Net</c>).
/// </para>
/// <para>
/// This is data, not a verification proof — a plain record. When a recipient advertises several endpoints, the
/// resolver returns the targets in the DID document's preference order so the sender can fail over to the next one
/// if transmission fails (DIDComm v2.1 §Failover).
/// </para>
/// </remarks>
public sealed record DidCommDeliveryTarget
{
    /// <summary>REQUIRED. The concrete (non-DID) transport URI the wrapped message is transmitted to.</summary>
    [SuppressMessage("Design", "CA1056:URI-like properties should not be strings",
        Justification = "The transport URI is an opaque endpoint token carried verbatim for the application's transport layer; it is not parsed or dereferenced here.")]
    public required string TransportUri { get; init; }

    /// <summary>
    /// The endpoint's <c>accept</c> media types in preference order, or <see langword="null"/> when the endpoint
    /// declared none (DIDComm v2.1 §Service Endpoint: "An array of media types in the order of preference for
    /// sending a message to the endpoint"). A sender uses these — alongside <see cref="Scheme"/> — to choose which
    /// transport and profile to deliver with.
    /// </summary>
    public IReadOnlyList<string>? Accept { get; init; }

    /// <summary>
    /// The ordered routing keys the message is wrapped for — the recipient's <c>routingKeys</c>, with any mediator
    /// DID prepended (its keyAgreement keys wrap the outer forward). Empty when no forwarding is needed.
    /// </summary>
    public IReadOnlyList<string> RoutingKeys { get; init; } = [];


    /// <summary>
    /// The parsed absolute transport endpoint, or <see langword="null"/> when <see cref="TransportUri"/> is not an
    /// absolute URI. A sender reads this once to BOTH dispatch by <see cref="System.Uri.Scheme"/> and obtain the
    /// <see cref="System.Uri"/> it transmits to, rather than parsing the string twice. Derived from the verbatim
    /// <see cref="TransportUri"/> rather than stored, so the record stays a faithful carrier of what the DID
    /// document declared.
    /// </summary>
    public Uri? TransportEndpoint => Uri.TryCreate(TransportUri, UriKind.Absolute, out Uri? uri) ? uri : null;

    /// <summary>
    /// The URI scheme of <see cref="TransportUri"/> (e.g. <c>https</c>, <c>wss</c>, <c>didcomm</c>), or
    /// <see langword="null"/> when the URI is not absolute. A sender dispatches to the matching transport by this
    /// scheme — the spec's <c>uri</c> selects the transport from the §Transports section (DIDComm v2.1 §Service
    /// Endpoint: the <c>uri</c> "MUST contain a URI for a transport specified in the [transports] section").
    /// </summary>
    public string? Scheme => TransportEndpoint?.Scheme;


    /// <summary>
    /// Determines whether this delivery target equals <paramref name="other"/> by value: <see cref="TransportUri"/>
    /// by ordinal comparison and the <see cref="Accept"/>/<see cref="RoutingKeys"/> lists element-wise in order. The
    /// computed <see cref="TransportEndpoint"/>/<see cref="Scheme"/> are derived from <see cref="TransportUri"/>, so
    /// they are not compared independently.
    /// </summary>
    /// <param name="other">The delivery target to compare with, or <see langword="null"/>.</param>
    /// <returns><see langword="true"/> when the two targets are value-equal.</returns>
    public bool Equals(DidCommDeliveryTarget? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        return string.Equals(TransportUri, other.TransportUri, StringComparison.Ordinal)
            && StructuralEquality.SequenceEqual(Accept, other.Accept)
            && StructuralEquality.SequenceEqual(RoutingKeys, other.RoutingKeys);
    }


    /// <inheritdoc/>
    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(TransportUri, StringComparer.Ordinal);
        hash.Add(StructuralEquality.SequenceHashCode(Accept));
        hash.Add(StructuralEquality.SequenceHashCode(RoutingKeys));

        return hash.ToHashCode();
    }
}
