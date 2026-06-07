using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;

namespace Verifiable.OAuth.Server.Routing;

/// <summary>
/// Typed accessor for the inbound <see cref="IncomingRequest"/> on a
/// <see cref="ExchangeContext"/>. Separate from
/// <see cref="ExchangeContextServerExtensions"/> so it can land additively
/// without touching the existing accessor surface.
/// </summary>
/// <remarks>
/// <para>
/// Phase 4 introduces <see cref="IncomingRequest"/> as the typed envelope
/// the skin produces. The dispatcher reads it once and threads it through
/// the pipeline by setting it on the context; matchers and handlers read
/// it through the accessor on this class.
/// </para>
/// <para>
/// During the Phase 4 transition, the existing <c>Path</c>,
/// <c>HttpMethod</c>, <c>RouteValues</c>, and <c>Capability</c> accessors
/// on <see cref="ExchangeContextServerExtensions"/> remain in use by the current
/// dispatcher and matchers. They are scheduled for removal once matchers
/// migrate to read from <see cref="IncomingRequest"/> directly.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class ExchangeContextIncomingRequestExtensions
{
    /// <summary>
    /// The well-known key under which the typed <see cref="IncomingRequest"/>
    /// is stored on a <see cref="ExchangeContext"/>.
    /// </summary>
    public const string IncomingRequestKey = "server.incomingRequest";


    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets the typed <see cref="IncomingRequest"/> for this request. Set
        /// once by the dispatcher entry point; read by matchers and handlers.
        /// </summary>
        /// <returns>
        /// The incoming request envelope, or <see langword="null"/> when the
        /// dispatcher has not placed one (typical only in pre-dispatch
        /// pipeline stages or in tests that bypass the dispatcher).
        /// </returns>
        public IncomingRequest? IncomingRequest =>
            context.TryGetValue(IncomingRequestKey, out object? v)
                && v is IncomingRequest req ? req : null;


        /// <summary>
        /// Sets the typed <see cref="IncomingRequest"/> on the request context.
        /// Called by <see cref="AuthorizationServer.DispatchAsync"/> before
        /// any matcher runs.
        /// </summary>
        /// <param name="request">The incoming request envelope.</param>
        public void SetIncomingRequest(IncomingRequest request)
        {
            ArgumentNullException.ThrowIfNull(request);
            context[IncomingRequestKey] = request;
        }
    }
}
