namespace Verifiable.OAuth.Server;

/// <summary>
/// Extracts the <see cref="TenantId"/> from the inbound request.
/// </summary>
/// <remarks>
/// <para>
/// Called by the dispatcher at the start of every request before any other
/// delegate. The implementation reads whatever signal identifies the tenant in
/// the deployment — path segment, subdomain, HTTP header, client-certificate
/// subject/SAN, a claim in an upstream JWT, or a combination — and returns the
/// resulting <see cref="TenantId"/>.
/// </para>
/// <para>
/// The delegate is async so the implementation can perform I/O when resolution
/// requires storage access, certificate-chain verification, or any other
/// non-local operation. Sync implementations return an already-completed
/// <see cref="ValueTask{TResult}"/> with no allocation overhead.
/// </para>
/// <para>
/// Returning <see langword="null"/> indicates the request carries no
/// identifiable tenant. The dispatcher responds with <c>400 invalid_request</c>
/// without invoking any further delegates. Returning a non-null
/// <see cref="TenantId"/> that does not map to a known registration is a
/// separate failure mode — <see cref="LoadClientRegistrationDelegate"/>
/// returns <see langword="null"/> in that case and the dispatcher responds
/// with <c>invalid_client</c>.
/// </para>
/// </remarks>
/// <param name="context">The per-request context bag carrying whatever signals
/// the ASP.NET skin surfaced — typically Host, path, headers, client
/// certificate.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The extracted <see cref="TenantId"/>, or <see langword="null"/> when no
/// tenant identifier can be determined from the request.
/// </returns>
public delegate ValueTask<TenantId?> ExtractTenantIdDelegate(
    RequestContext context,
    CancellationToken cancellationToken);
