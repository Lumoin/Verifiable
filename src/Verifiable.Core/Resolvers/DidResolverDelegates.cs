using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;

namespace Verifiable.Core.Resolvers;

/// <summary>
/// A method-specific DID resolution handler. Called by <see cref="DidResolver"/> after
/// DID syntax validation and method dispatch.
/// </summary>
/// <param name="did">The DID string to resolve.</param>
/// <param name="options">The resolution options.</param>
/// <param name="context">
/// The per-operation <see cref="ExchangeContext"/>. A method resolver that dereferences
/// a URL over the network (rather than returning a <see cref="DidResolutionKind.DocumentUrl"/>
/// for the caller to fetch) routes it through the guarded outbound fetch, which reads the
/// SSRF <c>OutboundFetchPolicy</c> off this context — so the policy reaches the resolver as
/// an explicit per-call argument rather than a captured closure.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The resolution result.</returns>
/// <remarks>
/// <para>
/// Implementations should be registered as static method groups to avoid closure allocations:
/// </para>
/// <code>
/// DidMethodSelectors.FromResolvers(
///     (WellKnownDidMethodPrefixes.WebDidMethodPrefix, WebDidResolver.ResolveAsync),
///     (WellKnownDidMethodPrefixes.CheqdDidMethodPrefix, CheqdDidResolver.ResolveAsync)
/// );
/// </code>
/// </remarks>
public delegate ValueTask<DidResolutionResult> DidMethodResolverDelegate(
    string did,
    DidResolutionOptions options,
    ExchangeContext context,
    CancellationToken cancellationToken);

/// <summary>
/// A method-specific DID URL dereferencer. Called when a DID URL has path or query
/// components that require method-specific processing.
/// </summary>
/// <param name="baseDid">The base DID (without path, query, or fragment).</param>
/// <param name="path">The path component of the DID URL, or <see langword="null"/>.</param>
/// <param name="query">The query component of the DID URL, or <see langword="null"/>.</param>
/// <param name="options">The dereferencing options.</param>
/// <param name="context">
/// The per-operation <see cref="ExchangeContext"/> carrying the SSRF
/// <c>OutboundFetchPolicy</c> for any network dereference. See
/// <see cref="DidMethodResolverDelegate"/>.
/// </param>
/// <param name="cancellationToken">Cancellation token.</param>
/// <returns>The dereferencing result.</returns>
public delegate ValueTask<DidDereferencingResult> DidMethodDereferencerDelegate(
    string baseDid,
    string? path,
    string? query,
    DidDereferencingOptions options,
    ExchangeContext context,
    CancellationToken cancellationToken);

/// <summary>
/// Selects a method-specific resolver delegate for the given DID method name segment.
/// Returns <see langword="null"/> when the method is not supported.
/// </summary>
/// <param name="methodName">The DID method name segment, e.g., <c>"web"</c> or <c>"cheqd"</c>.</param>
/// <returns>The resolver delegate, or <see langword="null"/> if not supported.</returns>
public delegate DidMethodResolverDelegate? SelectMethodResolverDelegate(string methodName);

/// <summary>
/// Selects a method-specific dereferencer delegate for the given DID method name segment.
/// Returns <see langword="null"/> when no custom dereferencer is registered, in which case
/// the default resolution-then-fragment path is used.
/// </summary>
/// <param name="methodName">The DID method name segment.</param>
/// <returns>The dereferencer delegate, or <see langword="null"/>.</returns>
public delegate DidMethodDereferencerDelegate? SelectMethodDereferencerDelegate(string methodName);
