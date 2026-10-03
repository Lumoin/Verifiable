using System.Collections.Concurrent;
using Verifiable.JCose;
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
/// asks the application's materialization only for a request the loaded registration's chain matches.
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
    /// declaration admits the family's candidates; one that declares none is left declaring none.
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
    /// Wraps the endpoint-address resolution <paramref name="integration"/> carries so the family's two names resolve
    /// to <see cref="ComposePath"/> at the registration's tenant and every other name reaches the wrapped resolution.
    /// </summary>
    /// <param name="integration">The integration whose endpoint-address resolution is wrapped.</param>
    public static void ResolveItsAddresses(ServerIntegration integration)
    {
        ResolveEndpointUriDelegate? resolve = integration.ResolveEndpointUriAsync;
        integration.ResolveEndpointUriAsync = (endpointKey, registration, context, cancellationToken) =>
            string.Equals(endpointKey, Name, StringComparison.Ordinal)
                || string.Equals(endpointKey, LoadedOnlyName, StringComparison.Ordinal)
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
            MatchesRequest = (_, context, endpoint, _) =>
                ValueTask.FromResult<MatchPayload?>(
                    context.IncomingRequest is IncomingRequest request
                    && string.Equals(request.Method, httpMethod, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(request.Path, endpoint.ResolvedUri.AbsolutePath + pathExtension, StringComparison.Ordinal)
                        ? MatchPayload.Empty
                        : null),
            BuildInputAsync = (_, _, _, _) =>
            {
                handlersRun.Enqueue(label);

                return ValueTask.FromResult<(FlowInput? Input, ServerHttpResponse? EarlyExit)>(
                    (null, ServerHttpResponse.Ok(BodyOf(label), WellKnownMediaTypes.Application.Json)));
            },
            BuildResponse = static (_, _, _) =>
                ServerHttpResponse.ServerError(ServerErrors.ServerError, "The family's candidates answer from their input step.")
        };
}
