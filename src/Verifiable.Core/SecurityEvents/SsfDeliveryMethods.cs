using System;
using Verifiable.Cryptography.Text;

namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The delivery-method URIs and the <c>delivery</c> object member NAMES used in a
/// stream configuration, per OpenID Shared Signals Framework 1.0 §6.1. Each
/// delivery method is identified by the <see cref="SsfDeliveryParameterNames.Method"/>
/// member carrying one of these URIs.
/// </summary>
public static class SsfDeliveryMethods
{
    /// <summary>The UTF-8 source literal of <see cref="PushHttp"/>.</summary>
    public static ReadOnlySpan<byte> PushHttpUtf8 => "urn:ietf:rfc:8935"u8;

    /// <summary>
    /// Push delivery over HTTP (<c>urn:ietf:rfc:8935</c>) — the Transmitter POSTs each SET to
    /// the Receiver's <c>endpoint_url</c>. SSF §6.1.1 / RFC 8935.
    /// </summary>
    public static readonly string PushHttp = Utf8Constants.ToInternedString(PushHttpUtf8);

    /// <summary>The UTF-8 source literal of <see cref="PollHttp"/>.</summary>
    public static ReadOnlySpan<byte> PollHttpUtf8 => "urn:ietf:rfc:8936"u8;

    /// <summary>
    /// Poll delivery over HTTP (<c>urn:ietf:rfc:8936</c>) — the Receiver polls the Transmitter's
    /// <c>endpoint_url</c> for SETs. SSF §6.1.2 / RFC 8936.
    /// </summary>
    public static readonly string PollHttp = Utf8Constants.ToInternedString(PollHttpUtf8);


    /// <summary>Whether <paramref name="method"/> is <see cref="PushHttp"/>.</summary>
    public static bool IsPushHttp(string method) => Equals(method, PushHttp);

    /// <summary>Whether <paramref name="method"/> is <see cref="PollHttp"/>.</summary>
    public static bool IsPollHttp(string method) => Equals(method, PollHttp);


    /// <summary>
    /// Returns the interned constant for a known delivery-method URI, or the original
    /// string if unrecognized.
    /// </summary>
    public static string GetCanonicalizedValue(string method) => method switch
    {
        _ when IsPushHttp(method) => PushHttp,
        _ when IsPollHttp(method) => PollHttp,
        _ => method
    };


    /// <summary>Compares two delivery-method URIs for equality (case-sensitive).</summary>
    public static bool Equals(string methodA, string methodB) =>
        object.ReferenceEquals(methodA, methodB) || System.StringComparer.Ordinal.Equals(methodA, methodB);
}


/// <summary>
/// The member NAMES of a stream configuration's <c>delivery</c> object, per OpenID
/// Shared Signals Framework 1.0 §6.1.
/// </summary>
public static class SsfDeliveryParameterNames
{
    /// <summary>The UTF-8 source literal of <see cref="Method"/>.</summary>
    public static ReadOnlySpan<byte> MethodUtf8 => "method"u8;

    /// <summary><c>method</c> — the delivery-method URI (see <see cref="SsfDeliveryMethods"/>).</summary>
    public static readonly string Method = Utf8Constants.ToInternedString(MethodUtf8);

    /// <summary>The UTF-8 source literal of <see cref="EndpointUrl"/>.</summary>
    public static ReadOnlySpan<byte> EndpointUrlUtf8 => "endpoint_url"u8;

    /// <summary>
    /// <c>endpoint_url</c> — for push, the Receiver-set URL events are POSTed to; for poll,
    /// the Transmitter-set URL events are retrieved from.
    /// </summary>
    public static readonly string EndpointUrl = Utf8Constants.ToInternedString(EndpointUrlUtf8);

    /// <summary>The UTF-8 source literal of <see cref="AuthorizationHeader"/>.</summary>
    public static ReadOnlySpan<byte> AuthorizationHeaderUtf8 => "authorization_header"u8;

    /// <summary>
    /// <c>authorization_header</c> — OPTIONAL (push) authorization header value the Transmitter
    /// MUST include on every POST to the Receiver's <c>endpoint_url</c>.
    /// </summary>
    public static readonly string AuthorizationHeader = Utf8Constants.ToInternedString(AuthorizationHeaderUtf8);
}
