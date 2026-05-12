using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

namespace Verifiable.OAuth.Server;

/// <summary>
/// The application-defined request context parameter bag that flows through every
/// delegate in the Authorization Server request lifecycle.
/// </summary>
/// <remarks>
/// <para>
/// Per-request bag populated at dispatch entry by the application skin. Lives
/// until response. Carries edge values (HTTP fields, headers, route values)
/// plus dispatch-time resolved values (issuer URL, time provider snapshot,
/// resolved policy via
/// <see cref="PolicyRequestContextExtensions"/>). Cross-request data lives in
/// <see cref="OAuthFlowState"/>; stage-bounded refined views live in
/// <see cref="Verifiable.OAuth.IssuanceContext"/> and
/// <see cref="Verifiable.OAuth.Validation.ValidationContext"/>.
/// </para>
/// <para>
/// Each per-request context shape's lifetime maps to a stage of request
/// processing — the pipeline-stage separation is real, not incidental:
/// <see cref="RequestContext"/> covers the whole request;
/// <see cref="Verifiable.OAuth.IssuanceContext"/> exists only during a token
/// producer / claim contributor walk;
/// <see cref="Verifiable.OAuth.Validation.ValidationContext"/> exists only
/// during a single validation-check run. Per-request data lives here via
/// typed extensions; stage-bounded data lives on the appropriate
/// stage-specific typed record; persistent cross-request data lives on
/// <see cref="OAuthFlowState"/>.
/// </para>
/// <para>
/// The ASP.NET skin constructs a <see cref="RequestContext"/> before calling
/// <see cref="AuthorizationServer.DispatchAsync(IncomingRequest, RequestContext, CancellationToken)"/>,
/// placing whatever request-scoped data the application needs: tenant
/// identifier, remote IP, trace context, authenticated user identity, billing
/// tier, regional affinity. The dispatcher enriches it with the resolved
/// <see cref="ClientRecord"/>, a consistent request timestamp, and the
/// resolved policy values populated by
/// <see cref="AuthorizationServerIntegration.ResolvePolicyAsync"/>. Every
/// delegate in the pipeline — endpoint builders, key resolvers, action
/// handlers — receives the same instance.
/// </para>
/// <para>
/// Typed access is provided by extension methods in
/// <see cref="RequestContextExtensions"/> and
/// <see cref="Oid4VpRequestContextExtensions"/> so that consumers do not need
/// to know the string key names or cast <see cref="object"/> values. Library users
/// add their own typed accessors using C# 13 extension syntax — the methods appear
/// alongside the library-provided ones in IntelliSense:
/// </para>
/// <code>
/// public static class MyContextExtensions
/// {
///     extension(RequestContext context)
///     {
///         public string? TenantId =>
///             context.TryGetValue("app.tenantId", out object? v) &amp;&amp; v is string s ? s : null;
///
///         public void SetTenantId(string tenantId) =>
///             context["app.tenantId"] = tenantId;
///     }
/// }
/// </code>
/// <para>
/// Inheriting from <see cref="Dictionary{TKey, TValue}"/> follows the same pattern
/// as <see cref="Verifiable.JCose.JwtHeader"/> and <see cref="Verifiable.JCose.JwtPayload"/>:
/// full dictionary API with type identity that prevents accidental argument swapping
/// at compile time.
/// </para>
/// </remarks>
[DebuggerDisplay("RequestContext({Count} entries)")]
public sealed class RequestContext: Dictionary<string, object>, IEquatable<RequestContext>
{
    /// <summary>
    /// Creates an empty <see cref="RequestContext"/> instance.
    /// </summary>
    public RequestContext() : base(StringComparer.Ordinal) { }

    /// <summary>
    /// Creates a <see cref="RequestContext"/> instance with the specified initial capacity.
    /// </summary>
    /// <param name="capacity">The initial number of entries the context can contain.</param>
    public RequestContext(int capacity) : base(capacity, StringComparer.Ordinal) { }

    /// <summary>
    /// Creates a <see cref="RequestContext"/> instance populated from any key-value
    /// enumerable, including <see cref="Dictionary{TKey, TValue}"/> and
    /// <see cref="IReadOnlyDictionary{TKey, TValue}"/>.
    /// </summary>
    /// <param name="entries">The key-value pairs to copy.</param>
    public RequestContext(IEnumerable<KeyValuePair<string, object>> entries)
        : base(entries, StringComparer.Ordinal) { }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public bool Equals(RequestContext? other)
    {
        if(other is null)
        {
            return false;
        }

        if(ReferenceEquals(this, other))
        {
            return true;
        }

        if(Count != other.Count)
        {
            return false;
        }

        foreach(KeyValuePair<string, object> kvp in this)
        {
            if(!other.TryGetValue(kvp.Key, out object? value)
                || !Equals(kvp.Value, value))
            {
                return false;
            }
        }

        return true;
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override bool Equals([NotNullWhen(true)] object? obj) =>
        obj is RequestContext other && Equals(other);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public override int GetHashCode()
    {
        var hash = new HashCode();
        foreach(KeyValuePair<string, object> kvp in this.OrderBy(
            static x => x.Key, StringComparer.Ordinal))
        {
            hash.Add(kvp.Key, StringComparer.Ordinal);
            hash.Add(kvp.Value);
        }

        return hash.ToHashCode();
    }


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator ==(RequestContext? left, RequestContext? right) =>
        left is null ? right is null : left.Equals(right);


    /// <inheritdoc/>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static bool operator !=(RequestContext? left, RequestContext? right) =>
        !(left == right);
}
