namespace Verifiable.OAuth.Server;

/// <summary>
/// Handles an inbound server request and returns a <see cref="ServerHttpResponse"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each <see cref="ServerEndpoint"/> carries one of these delegates. The ASP.NET skin
/// extracts form fields or query parameters into <paramref name="fields"/>, places
/// request-scoped data into <paramref name="context"/>, and calls the delegate.
/// </para>
/// <para>
/// The library never sees <c>HttpContext</c> or any ASP.NET type. The skin is
/// responsible for translating between the HTTP framework and these neutral types.
/// </para>
/// <para>
/// <paramref name="context"/> carries whatever the application chooses to surface —
/// tenant identifier, remote IP, trace context, authenticated user identity. The
/// delegate and the delegates in <see cref="AuthorizationServerOptions"/> read from
/// it as needed. Typed accessors on <see cref="RequestContext"/> provide discoverable
/// access without string key lookups.
/// </para>
/// </remarks>
/// <param name="fields">
/// The parsed request fields. For POST endpoints these come from the form body;
/// for GET endpoints from the query string. The skin populates both the same way.
/// </param>
/// <param name="context">Application-defined request context parameter bag.</param>
/// <param name="options">The server options carrying all I/O delegates.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The HTTP response to return to the caller.</returns>
public delegate ValueTask<ServerHttpResponse> HandleRequestDelegate(
    RequestFields fields,
    RequestContext context,
    AuthorizationServerOptions options,
    CancellationToken cancellationToken);
