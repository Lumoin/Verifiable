using System.Diagnostics;

namespace Verifiable.OAuth;

/// <summary>
/// HTTP method name constants used by the Authorization Server's matchers.
/// </summary>
/// <remarks>
/// <para>
/// The library's matchers test the inbound <see cref="Verifiable.OAuth.Server.IncomingRequest.Method"/>
/// against these constants. Centralising the names here keeps the matchers
/// across <c>AuthCodeEndpoints</c>, <c>Oid4VpEndpoints</c>, and
/// <c>MetadataEndpoints</c> referring to one source of truth rather than each
/// file declaring its own private constants.
/// </para>
/// <para>
/// Only the methods the library currently dispatches on are listed. Other HTTP
/// methods (PUT, PATCH, DELETE) are not added speculatively — they appear here
/// when a matcher actually needs them.
/// </para>
/// </remarks>
[DebuggerDisplay("WellKnownHttpMethods")]
public static class WellKnownHttpMethods
{
    /// <summary>
    /// The HTTP <c>GET</c> method per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#name-get">RFC 9110 §9.3.1</see>.
    /// </summary>
    public static readonly string Get = "GET";

    /// <summary>
    /// The HTTP <c>POST</c> method per
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#name-post">RFC 9110 §9.3.3</see>.
    /// </summary>
    public static readonly string Post = "POST";
}
