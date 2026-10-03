using System.Collections.Concurrent;
using Verifiable.JCose;
using Verifiable.OAuth.Server;
using Verifiable.Server.Routing;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// An endpoint family an application composes beside the library's own builders through
/// <see cref="ServerConfiguration.EndpointBuilders"/>: one builder whose candidates share a name across HTTP method
/// or flow kind, one of them behind a gate that reads a second capability of the registration while the candidate
/// carries one. Each candidate answers <c>200</c> with a literal JSON body of its own and records its label when its
/// handler runs, so a row reads which candidate served a request from the wire and from the record.
/// </summary>
/// <remarks>
/// The builder yields, for a registration that allows <see cref="Served"/>, the first candidate named
/// <see cref="Name"/>, by POST, of the stateless flow kind, at <see cref="ComposePath"/>; for a registration that
/// also allows <see cref="Gate"/>, a second candidate of the same name under <see cref="Served"/> with the method,
/// path extension and flow kind the row chooses; and for a registration that allows <see cref="LoadedOnly"/>, a
/// candidate named <see cref="LoadedOnlyName"/> under that capability that matches the second candidate's request.
/// The last is how a request the second candidate alone matches among the family's candidates of
/// <see cref="Name"/> matches an endpoint of a registration that does not allow <see cref="Gate"/>: the dispatcher
/// asks the application's materialization only for a request the loaded registration's chain matches. A second
/// builder of the family (<see cref="CreateClientAuthenticatingBuilder"/>) serves an application's
/// client-authenticating endpoint under a capability the row names, composed with the library's public parts.
/// </remarks>
internal static class SyntheticEndpointFamily
{
    /// <summary>
    /// The capability the family's two candidates of <see cref="Name"/> carry.
    /// </summary>
    public static CapabilityIdentifier Served { get; } = CapabilityIdentifier.Create("urn:example:capability:synthetic:served");


    /// <summary>
    /// The capability the gate of the second candidate of <see cref="Name"/> reads beside <see cref="Served"/>; no
    /// candidate carries it.
    /// </summary>
    public static CapabilityIdentifier Gate { get; } = CapabilityIdentifier.Create("urn:example:capability:synthetic:gate");


    /// <summary>
    /// The capability the candidate named <see cref="LoadedOnlyName"/> carries.
    /// </summary>
    public static CapabilityIdentifier LoadedOnly { get; } = CapabilityIdentifier.Create("urn:example:capability:synthetic:loaded-only");


    /// <summary>
    /// The name the family's two candidates under <see cref="Served"/> share.
    /// </summary>
    public static string Name { get; } = "Synthetic.Echo";


    /// <summary>
    /// The name of the candidate under <see cref="LoadedOnly"/>, which no candidate under <see cref="Served"/> shares.
    /// </summary>
    public static string LoadedOnlyName { get; } = "Synthetic.LoadedOnly";


    /// <summary>
    /// The label the first candidate of <see cref="Name"/> records and answers.
    /// </summary>
    public static string FirstLabel { get; } = "first";


    /// <summary>
    /// The label the second candidate of <see cref="Name"/> records and answers.
    /// </summary>
    public static string SecondLabel { get; } = "second";


    /// <summary>
    /// The label the candidate named <see cref="LoadedOnlyName"/> records and answers.
    /// </summary>
    public static string LoadedOnlyLabel { get; } = "loaded-only";


    /// <summary>
    /// The address the family's endpoints resolve to apart from the path: the matchers compare the path alone.
    /// </summary>
    private static Uri AddressBase { get; } = new("https://synthetic-family.example/");


    /// <summary>
    /// The path every candidate of the family resolves to at the tenant <paramref name="tenantSegment"/>: the
    /// fixture's <c>/connect/{segment}/</c> shape, which the listener stamps the tenant from. A candidate matches
    /// this path followed by its own path extension.
    /// </summary>
    /// <param name="tenantSegment">The tenant segment of the registration.</param>
    /// <returns>The absolute path.</returns>
    public static string ComposePath(string tenantSegment) => $"/connect/{tenantSegment}/synthetic-family";


    /// <summary>
    /// The body a candidate of the family answers: a JSON object naming its label.
    /// </summary>
    /// <param name="label">The candidate's label.</param>
    /// <returns>The literal body.</returns>
    public static string BodyOf(string label) => $$"""{"candidate":"{{label}}"}""";


    /// <summary>
    /// The family's builder, for the second candidate of <see cref="Name"/> by <paramref name="secondHttpMethod"/>,
    /// at <see cref="ComposePath"/> followed by <paramref name="secondPathExtension"/>, of
    /// <paramref name="secondKind"/>. The candidate named <see cref="LoadedOnlyName"/> matches the same method and
    /// path, of the stateless flow kind.
    /// </summary>
    /// <param name="secondHttpMethod">The HTTP method of the second candidate.</param>
    /// <param name="secondPathExtension">The path extension of the second candidate, the empty text for none.</param>
    /// <param name="secondKind">The flow kind of the second candidate.</param>
    /// <param name="handlersRun">The labels of the candidates whose handlers ran, in order.</param>
    /// <returns>The builder an application composes into its configuration.</returns>
    public static EndpointBuilderDelegate CreateBuilder(
        string secondHttpMethod,
        string secondPathExtension,
        FlowKind secondKind,
        ConcurrentQueue<string> handlersRun) =>
        (registration, _, _) =>
        {
            List<EndpointCandidate> candidates = [];
            if(registration.AllowedCapabilities.Contains(Served))
            {
                candidates.Add(CreateCandidate(
                    Name, Served, WellKnownHttpMethods.Post, string.Empty, StatelessFlowKind.Instance, FirstLabel, handlersRun));

                //The gate reads a second capability of the registration while the candidate carries the first.
                if(registration.AllowedCapabilities.Contains(Gate))
                {
                    candidates.Add(CreateCandidate(
                        Name, Served, secondHttpMethod, secondPathExtension, secondKind, SecondLabel, handlersRun));
                }
            }

            if(registration.AllowedCapabilities.Contains(LoadedOnly))
            {
                candidates.Add(CreateCandidate(
                    LoadedOnlyName, LoadedOnly, secondHttpMethod, secondPathExtension, StatelessFlowKind.Instance, LoadedOnlyLabel, handlersRun));
            }

            return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
        };


    /// <summary>
    /// The configuration <paramref name="configuration"/> with <paramref name="builder"/> composed after its own
    /// builders. A configuration that declares its capabilities declares the family's three as well, so the
    /// declaration admits the family's candidates; one that declares none is left declaring none. The
    /// client-authenticating candidate's capability, the one its builder is created with, is not among the three: a
    /// configuration that declares capabilities admits that candidate only when it declares that capability already, and
    /// a configuration that declares none admits it as it admits every candidate.
    /// </summary>
    /// <param name="configuration">The configuration the family is composed into.</param>
    /// <param name="builder">The family's builder.</param>
    /// <returns>The composed configuration.</returns>
    public static ServerConfiguration ComposeInto(ServerConfiguration configuration, EndpointBuilderDelegate builder) =>
        configuration with
        {
            EndpointBuilders = new EndpointBuilderSet([.. configuration.EndpointBuilders, builder]),
            DeclaredCapabilities = configuration.DeclaredCapabilities?.Union([Served, Gate, LoadedOnly])
        };


    /// <summary>
    /// Wraps the endpoint-address resolution <paramref name="integration"/> carries so the family's names resolve
    /// to <see cref="ComposePath"/> at the registration's tenant and every other name reaches the wrapped resolution.
    /// </summary>
    /// <param name="integration">The integration whose endpoint-address resolution is wrapped.</param>
    public static void ResolveItsAddresses(ServerIntegration integration)
    {
        ResolveEndpointUriDelegate? resolve = integration.ResolveEndpointUriAsync;
        integration.ResolveEndpointUriAsync = (endpointKey, registration, context, cancellationToken) =>
            string.Equals(endpointKey, Name, StringComparison.Ordinal)
                || string.Equals(endpointKey, LoadedOnlyName, StringComparison.Ordinal)
                || string.Equals(endpointKey, ClientAuthenticatingName, StringComparison.Ordinal)
                ? ValueTask.FromResult<Uri?>(new Uri(AddressBase, ComposePath(registration.TenantId.Value)))
                : resolve is null
                    ? ValueTask.FromResult<Uri?>(null)
                    : resolve(endpointKey, registration, context, cancellationToken);
    }


    /// <summary>
    /// One candidate of the family: it matches a request by <paramref name="httpMethod"/> to its resolved path
    /// followed by <paramref name="pathExtension"/>, and its handler records <paramref name="label"/> and answers
    /// <c>200</c> with <see cref="BodyOf"/> of it from its input step, before any flow step, which the dispatcher
    /// answers directly for a stateless candidate and for a candidate that starts a flow of a stateful kind.
    /// </summary>
    /// <param name="name">The candidate's name.</param>
    /// <param name="capability">The capability the candidate carries.</param>
    /// <param name="httpMethod">The HTTP method the candidate serves.</param>
    /// <param name="pathExtension">The path extension after <see cref="ComposePath"/>, the empty text for none.</param>
    /// <param name="kind">The candidate's flow kind.</param>
    /// <param name="label">The label the candidate records and answers.</param>
    /// <param name="handlersRun">The labels of the candidates whose handlers ran, in order.</param>
    /// <returns>The candidate.</returns>
    private static EndpointCandidate CreateCandidate(
        string name,
        CapabilityIdentifier capability,
        string httpMethod,
        string pathExtension,
        FlowKind kind,
        string label,
        ConcurrentQueue<string> handlersRun) =>
        new()
        {
            Name = name,
            Capability = capability,
            HttpMethod = httpMethod,
            Kind = kind,
            StartsNewFlow = true,
            MatchesRequest = MatchesAt(httpMethod, pathExtension),
            BuildInputAsync = (_, _, _, _) =>
            {
                handlersRun.Enqueue(label);

                return ValueTask.FromResult<(FlowInput? Input, ServerHttpResponse? EarlyExit)>(
                    (null, ServerHttpResponse.Ok(BodyOf(label), WellKnownMediaTypes.Application.Json)));
            },
            BuildResponse = static (_, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "The family's candidates answer from their input step.")
        };


    /// <summary>
    /// The match every candidate of the family makes: a request by <paramref name="httpMethod"/> to the candidate's
    /// resolved path followed by <paramref name="pathExtension"/>.
    /// </summary>
    /// <param name="httpMethod">The HTTP method the candidate serves.</param>
    /// <param name="pathExtension">The path extension after the resolved path, the empty text for none.</param>
    /// <returns>The candidate's match.</returns>
    private static MatchRequestDelegate MatchesAt(string httpMethod, string pathExtension) =>
        (_, context, endpoint, _) =>
            ValueTask.FromResult<MatchPayload?>(
                context.IncomingRequest is IncomingRequest request
                && string.Equals(request.Method, httpMethod, StringComparison.OrdinalIgnoreCase)
                && string.Equals(request.Path, endpoint.ResolvedUri.AbsolutePath + pathExtension, StringComparison.Ordinal)
                    ? MatchPayload.Empty
                    : null);


    /// <summary>
    /// The name of the family's client-authenticating candidate, which no other candidate shares.
    /// </summary>
    public static string ClientAuthenticatingName { get; } = "Synthetic.ClientAuthenticating";


    /// <summary>
    /// The path extension after <see cref="ComposePath"/> at which the client-authenticating candidate serves.
    /// </summary>
    public static string ClientAuthenticatingPathExtension { get; } = "/client-authenticating";


    /// <summary>
    /// The path the client-authenticating candidate serves at the tenant <paramref name="tenantSegment"/>:
    /// <see cref="ComposePath"/> followed by <see cref="ClientAuthenticatingPathExtension"/>.
    /// </summary>
    /// <param name="tenantSegment">The tenant segment of the registration.</param>
    /// <returns>The absolute path.</returns>
    public static string ComposeClientAuthenticatingPath(string tenantSegment) =>
        ComposePath(tenantSegment) + ClientAuthenticatingPathExtension;


    /// <summary>
    /// The body the client-authenticating candidate answers: whether the registration its handler saw is the one
    /// a Client ID Metadata Document materialized, and whether the client authentication seam accepted the request's
    /// credential.
    /// </summary>
    /// <param name="isClientMetadataMaterialized">Whether the registration the handler saw was materialized.</param>
    /// <param name="isAuthenticated">Whether the client authentication seam accepted the credential.</param>
    /// <returns>The literal body.</returns>
    public static string ClientAuthenticatingBodyOf(bool isClientMetadataMaterialized, bool isAuthenticated) =>
        $$"""{"client_metadata_materialized":{{(isClientMetadataMaterialized ? "true" : "false")}},"authenticated":{{(isAuthenticated ? "true" : "false")}}}""";


    /// <summary>
    /// The builder of an application's client-authenticating endpoint under <paramref name="capability"/>, composed
    /// with the library's public parts: for a registration that allows <paramref name="capability"/>, one candidate
    /// named <see cref="ClientAuthenticatingName"/>, by POST, of the stateless flow kind, at
    /// <see cref="ComposeClientAuthenticatingPath"/>. Its handler records the registration the request's context
    /// holds (<see cref="Verifiable.OAuth.Server.ExchangeContextServerExtensions"/>) in
    /// <paramref name="registrationsSeen"/>, reads the request's client credentials through
    /// <see cref="ClientCredentialReading.Read"/>, hands a reading that presents a credential and that registration
    /// to the server's <see cref="AuthorizationServerIntegration.ValidateClientCredentialsAsync"/>, and answers
    /// <c>200</c> with <see cref="ClientAuthenticatingBodyOf"/> of what it saw and judged, from its input step.
    /// </summary>
    /// <param name="capability">The capability the candidate carries.</param>
    /// <param name="registrationsSeen">The registrations the handler saw, in order.</param>
    /// <returns>The builder an application composes into its configuration.</returns>
    public static EndpointBuilderDelegate CreateClientAuthenticatingBuilder(
        CapabilityIdentifier capability,
        ConcurrentQueue<ClientRecord?> registrationsSeen) =>
        (registration, _, _) =>
        {
            List<EndpointCandidate> candidates = [];
            if(registration.AllowedCapabilities.Contains(capability))
            {
                candidates.Add(new EndpointCandidate
                {
                    Name = ClientAuthenticatingName,
                    Capability = capability,
                    HttpMethod = WellKnownHttpMethods.Post,
                    Kind = StatelessFlowKind.Instance,
                    StartsNewFlow = true,
                    MatchesRequest = MatchesAt(WellKnownHttpMethods.Post, ClientAuthenticatingPathExtension),
                    BuildInputAsync = async (fields, context, _, cancellationToken) =>
                    {
                        ClientRecord? seen = context.ClientRegistration;
                        registrationsSeen.Enqueue(seen);
                        ClientCredentialReading reading = ClientCredentialReading.Read(
                            context.IncomingRequest?.Headers ?? RequestHeaders.Empty, fields);
                        ValidateClientCredentialsDelegate? validate = context.RequestServer?.OAuth().ValidateClientCredentialsAsync;
                        bool isAuthenticated = reading is { IsMalformed: false, HasCredentials: true }
                            && seen is not null
                            && validate is not null
                            && await validate(reading, seen, context, cancellationToken).ConfigureAwait(false);

                        return (null, ServerHttpResponse.Ok(
                            ClientAuthenticatingBodyOf(seen is { IsClientMetadataMaterialized: true }, isAuthenticated),
                            WellKnownMediaTypes.Application.Json));
                    },
                    BuildResponse = static (_, _, _) =>
                        ServerHttpResponse.ServerError(ServerErrors.ServerError, "The family's candidates answer from their input step.")
                });
            }

            return ValueTask.FromResult<IReadOnlyList<EndpointCandidate>>(candidates);
        };
}
