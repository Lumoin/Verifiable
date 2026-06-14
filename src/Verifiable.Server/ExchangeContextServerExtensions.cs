using System.Diagnostics.CodeAnalysis;
using Verifiable.Core;
using Verifiable.Server.Pipeline;
using Verifiable.Server.Routing;

namespace Verifiable.Server;

/// <summary>
/// Typed accessor extensions for the host-generic entries in a
/// <see cref="ExchangeContext"/> used by the dispatch host and endpoint delegates.
/// </summary>
/// <remarks>
/// <para>
/// These extension methods eliminate the need for callers to know string key names or
/// cast <see cref="object"/> values. The underlying keys are defined in
/// <see cref="ServerContextKeys"/>. A protocol family adds its own typed accessors over
/// the same context using C# 14 extension syntax; the methods appear alongside these in
/// IntelliSense.
/// </para>
/// </remarks>
[SuppressMessage("Design", "CA1034:Nested types should not be visible",
    Justification = "C# 14 extension blocks are surfaced as nested types by the analyzer but are not nested types in the language sense.")]
public static class ExchangeContextServerExtensions
{
    extension(ExchangeContext context)
    {
        /// <summary>
        /// Gets the capability of the matched endpoint, placed by the dispatcher after
        /// the matcher walk completes.
        /// </summary>
        public CapabilityIdentifier? Capability =>
            context.TryGetValue(ServerContextKeys.CapabilityKey, out object? v)
                && v is CapabilityIdentifier c ? c : default(CapabilityIdentifier?);

        /// <summary>Sets the capability of the matched endpoint. Called by the dispatcher.</summary>
        public void SetCapability(CapabilityIdentifier capability)
        {
            context[ServerContextKeys.CapabilityKey] = capability;
        }


        /// <summary>Gets the server issuer URI placed by the skin or resolved per request.</summary>
        public Uri? Issuer =>
            context.TryGetValue(ServerContextKeys.IssuerKey, out object? v)
                && v is Uri u ? u : null;

        /// <summary>Sets the server issuer URI.</summary>
        public void SetIssuer(Uri issuer)
        {
            ArgumentNullException.ThrowIfNull(issuer);
            context[ServerContextKeys.IssuerKey] = issuer;
        }


        /// <summary>Gets the authenticated subject identifier placed by the application's authentication middleware.</summary>
        public string? SubjectId =>
            context.TryGetValue(ServerContextKeys.SubjectIdKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the authenticated subject identifier.</summary>
        public void SetSubjectId(string subjectId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
            context[ServerContextKeys.SubjectIdKey] = subjectId;
        }


        /// <summary>Gets the authentication time placed by the application's authentication middleware.</summary>
        public DateTimeOffset? AuthTime =>
            context.TryGetValue(ServerContextKeys.AuthTimeKey, out object? v)
                && v is DateTimeOffset dt ? dt : null;

        /// <summary>Sets the authentication time.</summary>
        public void SetAuthTime(DateTimeOffset authTime)
        {
            context[ServerContextKeys.AuthTimeKey] = authTime;
        }


        /// <summary>Gets the End-User's authentication session identifier (<c>sid</c>).</summary>
        public string? SessionId =>
            context.TryGetValue(ServerContextKeys.SessionIdKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the authentication session identifier (<c>sid</c>).</summary>
        public void SetSessionId(string sessionId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
            context[ServerContextKeys.SessionIdKey] = sessionId;
        }


        /// <summary>Gets the Authentication Context Class Reference (<c>acr</c>).</summary>
        public string? Acr =>
            context.TryGetValue(ServerContextKeys.AcrKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the Authentication Context Class Reference (<c>acr</c>).</summary>
        public void SetAcr(string acr)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(acr);
            context[ServerContextKeys.AcrKey] = acr;
        }


        /// <summary>
        /// Gets the registration resolved by the dispatcher at the start of each request,
        /// as its host-generic <see cref="IRegistrationRecord"/> projection.
        /// </summary>
        public IRegistrationRecord? Registration =>
            context.TryGetValue(ServerContextKeys.RegistrationKey, out object? v)
                && v is IRegistrationRecord r ? r : null;

        /// <summary>Sets the resolved registration. Called by the dispatcher after resolving it by tenant identifier.</summary>
        public void SetRegistration(IRegistrationRecord registration)
        {
            ArgumentNullException.ThrowIfNull(registration);
            context[ServerContextKeys.RegistrationKey] = registration;
        }


        /// <summary>Gets the flow identifier written by a continuing-flow endpoint.</summary>
        public string? FlowId =>
            context.TryGetValue(ServerContextKeys.FlowIdKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the flow identifier.</summary>
        public void SetFlowId(string flowId)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(flowId);
            context[ServerContextKeys.FlowIdKey] = flowId;
        }


        /// <summary>
        /// Gets the correlation key generated by a new-flow endpoint, read by the
        /// dispatcher after the delegate runs to determine the storage key.
        /// </summary>
        public string? CorrelationKey =>
            context.TryGetValue(ServerContextKeys.CorrelationKeyOutputKey, out object? v)
                && v is string s && !string.IsNullOrWhiteSpace(s) ? s : null;

        /// <summary>Sets the correlation key generated for a new flow.</summary>
        public void SetCorrelationKey(string correlationKey)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(correlationKey);
            context[ServerContextKeys.CorrelationKeyOutputKey] = correlationKey;
        }


        /// <summary>
        /// Gets the UTC instant stamped by the dispatcher at the start of effectful work,
        /// so all effectful operations within a request use one consistent timestamp.
        /// </summary>
        public DateTimeOffset? VerifiedAt =>
            context.TryGetValue(ServerContextKeys.VerifiedAtKey, out object? v)
                && v is DateTimeOffset dt ? dt : null;

        /// <summary>Sets the request timestamp.</summary>
        public void SetVerifiedAt(DateTimeOffset verifiedAt)
        {
            context[ServerContextKeys.VerifiedAtKey] = verifiedAt;
        }


        /// <summary>
        /// Gets the typed <see cref="MatchPayload"/> the dispatcher placed on the context
        /// after the chain walk selected the matched endpoint.
        /// </summary>
        public MatchPayload? MatchPayload =>
            context.TryGetValue(ServerContextKeys.MatchPayloadKey, out object? v)
                && v is MatchPayload payload ? payload : null;

        /// <summary>Sets the matched <see cref="MatchPayload"/> on the request context.</summary>
        public void SetMatchPayload(MatchPayload payload)
        {
            ArgumentNullException.ThrowIfNull(payload);
            context[ServerContextKeys.MatchPayloadKey] = payload;
        }


        /// <summary>
        /// Gets the active <see cref="EndpointServer"/> placed on the context at dispatch
        /// entry. Every per-request delegate reads backend access from here rather than
        /// receiving the host as a separate parameter.
        /// </summary>
        public EndpointServer? Server =>
            context.TryGetValue(ServerContextKeys.ServerKey, out object? v)
                && v is EndpointServer server ? server : null;

        /// <summary>Sets the active dispatch host on the request context. Called by the dispatcher.</summary>
        public void SetServer(EndpointServer server)
        {
            ArgumentNullException.ThrowIfNull(server);
            context[ServerContextKeys.ServerKey] = server;
        }


        /// <summary>Gets the per-request <see cref="EndpointChain"/> the dispatcher built.</summary>
        public EndpointChain? EndpointChain =>
            context.TryGetValue(ServerContextKeys.EndpointChainKey, out object? v)
                && v is EndpointChain chain ? chain : null;

        /// <summary>Sets the per-request <see cref="EndpointChain"/>. Called by the dispatcher.</summary>
        public void SetEndpointChain(EndpointChain chain)
        {
            ArgumentNullException.ThrowIfNull(chain);
            context[ServerContextKeys.EndpointChainKey] = chain;
        }


        /// <summary>
        /// Gets the per-request set of allowed capabilities returned by the capability
        /// resolver during chain build.
        /// </summary>
        public IReadOnlySet<CapabilityIdentifier>? ResolvedCapabilities =>
            context.TryGetValue(ServerContextKeys.ResolvedCapabilitiesKey, out object? v)
                && v is IReadOnlySet<CapabilityIdentifier> caps ? caps : null;

        /// <summary>Sets the per-request resolved capability set. Called by the chain build.</summary>
        public void SetResolvedCapabilities(IReadOnlySet<CapabilityIdentifier> capabilities)
        {
            ArgumentNullException.ThrowIfNull(capabilities);
            context[ServerContextKeys.ResolvedCapabilitiesKey] = capabilities;
        }
    }
}
