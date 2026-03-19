namespace Verifiable.OAuth.Server;

/// <summary>
/// Resolves an external correlation handle to the stable internal flow identifier
/// used as the primary persistence key, scoped by tenant.
/// </summary>
/// <remarks>
/// <para>
/// Multi-step OAuth flows emit external handles at various steps — <c>request_uri</c>
/// tokens from PAR, authorization codes from the authorize endpoint, <c>device_code</c>
/// from device authorization. When these handles arrive in subsequent requests, the
/// server must resolve them back to the internal <c>flowId</c> that identifies the
/// persisted flow state.
/// </para>
/// <para>
/// The internal <c>flowId</c> never crosses process boundaries. It is a primary key
/// in the persistence layer. External handles are secondary indexed values — opaque,
/// random, and independently generated.
/// </para>
/// <para>
/// The <paramref name="tenantId"/> scopes the resolution to the tenant the request
/// belongs to. A handle from one tenant must never resolve to a flow stored under
/// another, even when handles collide (which is mathematically negligible for opaque
/// random values, but the type-level guarantee is what matters). Storage layers key
/// secondary indexes by <c>(tenantId, externalHandle)</c>.
/// </para>
/// <para>
/// The application provides this delegate. The resolution strategy depends on the
/// persistence layer:
/// </para>
/// <list type="bullet">
///   <item><description>
///     In-memory: secondary dictionaries mapping <c>(tenantId, handle)</c> pairs to
///     <c>flowId</c>.
///   </description></item>
///   <item><description>
///     SQL: <c>SELECT flow_id FROM flows WHERE tenant_id = @tenantId AND
///     (request_uri_token = @key OR code = @key OR device_code = @key)</c>.
///   </description></item>
///   <item><description>
///     Self-contained: the handle itself is an encrypted or signed blob containing
///     both the <c>tenantId</c> and the <c>flowId</c>, eliminating the need for a
///     secondary lookup. The application verifies the embedded tenant matches
///     <paramref name="tenantId"/> before returning the flow id.
///   </description></item>
/// </list>
/// <para>
/// Returns <see langword="null"/> when the handle cannot be resolved within
/// <paramref name="tenantId"/> — the server responds with "flow not found" without
/// revealing whether the handle exists in some other tenant.
/// </para>
/// </remarks>
/// <param name="tenantId">
/// The tenant identifier the resolution is scoped to. Resolved by the dispatcher's
/// <see cref="ExtractTenantIdDelegate"/> before this delegate is invoked.
/// </param>
/// <param name="flowKind">
/// The flow kind, allowing flow-specific resolution logic.
/// </param>
/// <param name="externalHandle">
/// The opaque handle extracted from the inbound request by the endpoint's
/// <see cref="ServerEndpoint.ExtractCorrelationKey"/> delegate.
/// </param>
/// <param name="context">The request context.</param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>
/// The internal <c>flowId</c>, or <see langword="null"/> if the handle cannot be
/// resolved within the given tenant.
/// </returns>
public delegate ValueTask<string?> ResolveCorrelationKeyDelegate(
    TenantId tenantId,
    FlowKind flowKind,
    string externalHandle,
    RequestContext context,
    CancellationToken cancellationToken);
