using System.Diagnostics;

namespace Verifiable.Server.Pipeline;

/// <summary>
/// Well-known context bag key constants for the host-generic values the dispatch host
/// and its pipeline place on the <see cref="Verifiable.Core.ExchangeContext"/>.
/// </summary>
/// <remarks>
/// <para>
/// The context bag is typed as <see cref="System.Collections.Generic.Dictionary{TKey, TValue}"/>
/// of <see cref="string"/> to <see cref="object"/> to avoid coupling the host to any HTTP
/// framework. The dispatcher and the application's resolution delegates read these via the
/// typed accessors on <see cref="ExchangeContextServerExtensions"/>. A protocol family adds
/// its own keys in its own internal key holder and surfaces them through its own accessors.
/// </para>
/// </remarks>
[DebuggerDisplay("ServerContextKeys")]
internal static class ServerContextKeys
{
    /// <summary>Key for the capability of the matched endpoint. Value type: <see cref="CapabilityIdentifier"/>.</summary>
    public const string CapabilityKey = "server.capability";

    /// <summary>Key for the server issuer URI. Value type: <see cref="System.Uri"/>.</summary>
    public const string IssuerKey = "server.issuer";

    /// <summary>Key for the authenticated subject identifier. Value type: <see cref="string"/>.</summary>
    public const string SubjectIdKey = "server.subjectId";

    /// <summary>Key for the authentication time. Value type: <see cref="System.DateTimeOffset"/>.</summary>
    public const string AuthTimeKey = "server.authTime";

    /// <summary>Key for the End-User's authentication session identifier. Value type: <see cref="string"/>.</summary>
    public const string SessionIdKey = "server.sessionId";

    /// <summary>Key for the Authentication Context Class Reference. Value type: <see cref="string"/>.</summary>
    public const string AcrKey = "server.acr";

    /// <summary>Key for the registration resolved at the start of each request. Value type: <see cref="IRegistrationRecord"/>.</summary>
    public const string RegistrationKey = "server.registration";

    /// <summary>Key for the flow identifier. Value type: <see cref="string"/>.</summary>
    public const string FlowIdKey = "server.flowId";

    /// <summary>Output key for the correlation key generated on new-flow endpoints. Value type: <see cref="string"/>.</summary>
    public const string CorrelationKeyOutputKey = "server.correlationKey";

    /// <summary>Key for the UTC instant stamped at the start of effectful work. Value type: <see cref="System.DateTimeOffset"/>.</summary>
    public const string VerifiedAtKey = "server.verifiedAt";

    /// <summary>Key for the matched <see cref="Routing.MatchPayload"/>.</summary>
    public const string MatchPayloadKey = "server.matchPayload";

    /// <summary>Key for the active <see cref="EndpointServer"/> placed on the context at dispatch entry.</summary>
    public const string ServerKey = "server.endpointServer";

    /// <summary>Key for the per-request <see cref="EndpointChain"/> built during dispatch.</summary>
    public const string EndpointChainKey = "server.endpointChain";

    /// <summary>Key for the per-request set of allowed capabilities returned by the capability resolver.</summary>
    public const string ResolvedCapabilitiesKey = "server.resolvedCapabilities";
}
