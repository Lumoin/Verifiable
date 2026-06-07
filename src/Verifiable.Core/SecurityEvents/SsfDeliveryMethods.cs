namespace Verifiable.Core.SecurityEvents;

/// <summary>
/// The delivery-method URIs and the <c>delivery</c> object member NAMES used in a
/// stream configuration, per OpenID Shared Signals Framework 1.0 §6.1. Each
/// delivery method is identified by the <see cref="SsfDeliveryParameterNames.Method"/>
/// member carrying one of these URIs.
/// </summary>
public static class SsfDeliveryMethods
{
    /// <summary>
    /// Push delivery over HTTP (<c>urn:ietf:rfc:8935</c>) — the Transmitter POSTs each SET to
    /// the Receiver's <c>endpoint_url</c>. SSF §6.1.1 / RFC 8935.
    /// </summary>
    public static readonly string PushHttp = "urn:ietf:rfc:8935";

    /// <summary>
    /// Poll delivery over HTTP (<c>urn:ietf:rfc:8936</c>) — the Receiver polls the Transmitter's
    /// <c>endpoint_url</c> for SETs. SSF §6.1.2 / RFC 8936.
    /// </summary>
    public static readonly string PollHttp = "urn:ietf:rfc:8936";


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
    /// <summary><c>method</c> — the delivery-method URI (see <see cref="SsfDeliveryMethods"/>).</summary>
    public static readonly string Method = "method";

    /// <summary>
    /// <c>endpoint_url</c> — for push, the Receiver-set URL events are POSTed to; for poll,
    /// the Transmitter-set URL events are retrieved from.
    /// </summary>
    public static readonly string EndpointUrl = "endpoint_url";

    /// <summary>
    /// <c>authorization_header</c> — OPTIONAL (push) authorization header value the Transmitter
    /// MUST include on every POST to the Receiver's <c>endpoint_url</c>.
    /// </summary>
    public static readonly string AuthorizationHeader = "authorization_header";
}
