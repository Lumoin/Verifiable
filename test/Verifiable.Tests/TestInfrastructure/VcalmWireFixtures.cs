using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Server.Routing;
using Verifiable.Tests.OAuth;
using Verifiable.Vcalm;

namespace Verifiable.Tests.TestInfrastructure;

/// <summary>
/// Shared VCALM §3 credential/presentation wire assembly for the issuer, holder, and multi-tenant flow
/// test corpus — the fixed "ExampleAlumniCredential" shape those tests issue and derive against — and the
/// real-wire POST helpers every VCALM endpoint test reaches its endpoint through.
/// </summary>
/// <remarks>
/// <para>
/// Serialization is not baked in here: each caller wires its own <see cref="CredentialSerializeDelegate"/>/
/// <see cref="PresentationSerializeDelegate"/> (its own composition root's <c>JsonSerializerOptions</c>),
/// so this class only assembles the object graph and formats the request-body wrapper JSON.
/// </para>
/// <para>
/// The wire helpers send an actual HTTPS request to the loopback host
/// <see cref="TestHostShell.StartHttpHostAsync(CancellationToken)"/> serves, so a request crosses the same
/// transport, request-body reading and response writing a deployed endpoint does, not only the in-process
/// dispatcher.
/// </para>
/// <para>
/// Every test that proves a specification problem type posts through these helpers, so the wire itself is under test.
/// The in-process dispatch helpers some VCALM test classes still carry, which call
/// <c>TestHostShell.DispatchAtEndpointAsync</c> directly, are listed for conversion to these helpers and are not the
/// pattern a new test follows.
/// </para>
/// </remarks>
internal static class VcalmWireFixtures
{
    /// <summary>
    /// POSTs <paramref name="body"/> as <c>application/json</c> over the real wire to <paramref name="path"/> on the
    /// loopback HTTPS host of <paramref name="app"/>, starting the host when it is not yet listening, and returns the
    /// parsed response body after checking the response status.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    internal static async Task<JsonDocument> PostJsonWireAsync(
        TestHostShell app, string path, string body, int expectedStatus, CancellationToken cancellationToken) =>
        JsonDocument.Parse(await PostWireAsync(app, path, body, expectedStatus, cancellationToken).ConfigureAwait(false));


    /// <summary>
    /// POSTs <paramref name="body"/> as <c>application/json</c> over the real wire to <paramref name="path"/> on the
    /// loopback HTTPS host of <paramref name="app"/>, starting the host when it is not yet listening, and returns the
    /// response body text after checking the response status; for an endpoint whose success answer carries no body.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The response body text, empty when the response carries none.</returns>
    internal static async Task<string> PostWireAsync(
        TestHostShell app, string path, string body, int expectedStatus, CancellationToken cancellationToken)
    {
        (int statusCode, _, string responseBody) = await PostWireResponseAsync(app, path, body, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(expectedStatus, statusCode, responseBody);

        return responseBody;
    }


    /// <summary>
    /// POSTs <paramref name="body"/> as <c>application/json</c> over the real wire to <paramref name="path"/> on the
    /// loopback HTTPS host of <paramref name="app"/>, starting the host when it is not yet listening, and returns the
    /// response's status, the media type its <c>Content-Type</c> header names and its body text, unchecked: the
    /// primitive every POST helper of this class sends through, and the form a refusal whose own media type is
    /// asserted is proven through.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The request body JSON text.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>
    /// The response status code, the media type its <c>Content-Type</c> header names (or <see langword="null"/> when it
    /// carries none), and its body text.
    /// </returns>
    internal static async Task<(int StatusCode, string? MediaType, string Body)> PostWireResponseAsync(
        TestHostShell app, string path, string body, CancellationToken cancellationToken)
    {
        await app.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri url = new(host.HttpBaseAddress!, path);
        using StringContent content = new(body, Encoding.UTF8, "application/json");
        using HttpResponseMessage response = await host.SharedHttpClient!.PostAsync(url, content, cancellationToken).ConfigureAwait(false);
        string responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, response.Content.Headers.ContentType?.MediaType, responseBody);
    }


    /// <summary>
    /// POSTs <paramref name="body"/> over the real wire to the endpoint named <paramref name="endpointName"/> of the
    /// tenant <paramref name="segment"/>, at the path <see cref="TestHostShell.ComposeEndpointPath"/> gives it.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The tenant segment the endpoint is registered under.</param>
    /// <param name="endpointName">The well-known endpoint name.</param>
    /// <param name="body">The request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    internal static Task<JsonDocument> PostEndpointWireAsync(
        TestHostShell app, string segment, string endpointName, string body, int expectedStatus, CancellationToken cancellationToken) =>
        PostJsonWireAsync(app, TestHostShell.ComposeEndpointPath(endpointName, segment), body, expectedStatus, cancellationToken);


    /// <summary>POSTs a §3.3.1 <c>/credentials/verify</c> request over the real wire.</summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The verifier tenant segment.</param>
    /// <param name="body">The verify request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    internal static Task<JsonDocument> PostCredentialWireAsync(
        TestHostShell app, string segment, string body, int expectedStatus, CancellationToken cancellationToken) =>
        PostEndpointWireAsync(app, segment, WellKnownVcalmEndpointNames.VcalmCredentialsVerify, body, expectedStatus, cancellationToken);


    /// <summary>POSTs a §3.3.2 <c>/presentations/verify</c> request over the real wire.</summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The verifier tenant segment.</param>
    /// <param name="body">The verify request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    internal static Task<JsonDocument> PostPresentationWireAsync(
        TestHostShell app, string segment, string body, int expectedStatus, CancellationToken cancellationToken) =>
        PostEndpointWireAsync(app, segment, WellKnownVcalmEndpointNames.VcalmPresentationsVerify, body, expectedStatus, cancellationToken);


    /// <summary>POSTs a §3.5.1 <c>/credentials/derive</c> request over the real wire.</summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The holder tenant segment.</param>
    /// <param name="body">The derive request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    internal static Task<JsonDocument> PostDeriveWireAsync(
        TestHostShell app, string segment, string body, int expectedStatus, CancellationToken cancellationToken) =>
        PostEndpointWireAsync(app, segment, WellKnownVcalmEndpointNames.VcalmCredentialsDerive, body, expectedStatus, cancellationToken);


    /// <summary>POSTs a §3.5.2 <c>/presentations</c> create-presentation request over the real wire.</summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The holder tenant segment.</param>
    /// <param name="body">The create-presentation request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    internal static Task<JsonDocument> PostCreatePresentationWireAsync(
        TestHostShell app, string segment, string body, int expectedStatus, CancellationToken cancellationToken) =>
        PostEndpointWireAsync(app, segment, WellKnownVcalmEndpointNames.VcalmCreatePresentation, body, expectedStatus, cancellationToken);


    /// <summary>POSTs a §3.2.1 <c>/credentials/issue</c> request over the real wire.</summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The issuer tenant segment.</param>
    /// <param name="body">The issue request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    internal static Task<JsonDocument> PostIssueWireAsync(
        TestHostShell app, string segment, string body, int expectedStatus, CancellationToken cancellationToken) =>
        PostEndpointWireAsync(app, segment, WellKnownVcalmEndpointNames.VcalmCredentialsIssue, body, expectedStatus, cancellationToken);


    /// <summary>
    /// POSTs a §3.6.5 participate message over the real wire to the exchange <paramref name="exchangeId"/> of the
    /// tenant <paramref name="segment"/>.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The exchange tenant segment.</param>
    /// <param name="exchangeId">The exchange the message participates in.</param>
    /// <param name="body">The message body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    internal static Task<JsonDocument> PostExchangeWireAsync(
        TestHostShell app, string segment, string exchangeId, string body, int expectedStatus, CancellationToken cancellationToken) =>
        PostJsonWireAsync(app, ComposeExchangePath(segment, exchangeId), body, expectedStatus, cancellationToken);


    /// <summary>
    /// POSTs a §3.6.5 participate message over the real wire to the exchange <paramref name="exchangeId"/> of the
    /// tenant <paramref name="segment"/> through <see cref="PostWireResponseAsync"/>, returning the response unchecked
    /// with the media type it carries, for a test that asserts a refusal's status, media type and body itself.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The exchange tenant segment.</param>
    /// <param name="exchangeId">The exchange the message participates in.</param>
    /// <param name="body">The message body JSON text.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The response status code, the media type its <c>Content-Type</c> header names, and its body text.</returns>
    internal static Task<(int StatusCode, string? MediaType, string Body)> PostExchangeMessageWireAsync(
        TestHostShell app, string segment, string exchangeId, string body, CancellationToken cancellationToken) =>
        PostWireResponseAsync(app, ComposeExchangePath(segment, exchangeId), body, cancellationToken);


    /// <summary>
    /// GETs the §3.6.6 state of the exchange <paramref name="exchangeId"/> of the tenant <paramref name="segment"/> over
    /// the real wire, presenting <see cref="CoordinatorToken"/> against the REQUIRED §3.6.6 coordinator authorization
    /// seam, starting the host when it is not yet listening, and returns the parsed state after checking the response
    /// status.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The exchange tenant segment.</param>
    /// <param name="exchangeId">The exchange whose state is read.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed exchange state; the caller disposes it.</returns>
    internal static async Task<JsonDocument> GetExchangeWireAsync(
        TestHostShell app, string segment, string exchangeId, int expectedStatus, CancellationToken cancellationToken)
    {
        (int statusCode, _, string responseBody) = await SendWireAsync(
            app, "GET", ComposeExchangePath(segment, exchangeId), body: null,
            authorizationHeader: CoordinatorAuthorizationHeader, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(expectedStatus, statusCode, responseBody);

        return JsonDocument.Parse(responseBody);
    }


    /// <summary>
    /// POSTs a §3.6.3 create-exchange request over the real wire, presenting <see cref="CoordinatorToken"/> against the
    /// REQUIRED §3.6.3 coordinator authorization seam, and returns the parsed response after checking the response
    /// status.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The exchange tenant segment.</param>
    /// <param name="body">The create-exchange request body JSON text.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed response body; the caller disposes it.</returns>
    internal static async Task<JsonDocument> PostCreateExchangeWireAsync(
        TestHostShell app, string segment, string body, int expectedStatus, CancellationToken cancellationToken)
    {
        string path = TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmCreateExchange, segment);
        (int statusCode, _, string responseBody) = await SendWireAsync(
            app, "POST", path, body, authorizationHeader: CoordinatorAuthorizationHeader, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(expectedStatus, statusCode, responseBody);

        return JsonDocument.Parse(responseBody);
    }


    /// <summary>
    /// Sends an HTTP request of <paramref name="method"/> to <paramref name="path"/> on the loopback HTTPS host of
    /// <paramref name="app"/> over the real wire, starting the host when it is not yet listening, with an optional
    /// JSON <paramref name="body"/> and an optional <paramref name="authorizationHeader"/> value carried on the
    /// request's <c>Authorization</c> header — the primitive a REQUIRED-seam route's denial is proven through: RFC
    /// 6750 §3 requires the response carry a <c>WWW-Authenticate</c> challenge, which this returns unparsed
    /// alongside the status and body for the caller's own assertions.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="method">The HTTP method.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The request body JSON text, or <see langword="null"/> to send no body.</param>
    /// <param name="authorizationHeader">
    /// The <c>Authorization</c> header value to send, or <see langword="null"/> to send no <c>Authorization</c> header.
    /// </param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The response status code, its <c>WWW-Authenticate</c> header value (or <see langword="null"/> when absent), and its body text.</returns>
    internal static async Task<(int StatusCode, string? WwwAuthenticate, string Body)> SendWireAsync(
        TestHostShell app, string method, string path, string? body, string? authorizationHeader, CancellationToken cancellationToken)
    {
        await app.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri url = new(host.HttpBaseAddress!, path);

        using HttpRequestMessage request = new(new HttpMethod(method), url);
        if(body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        }

        if(authorizationHeader is not null)
        {
            _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, authorizationHeader);
        }

        using HttpResponseMessage response = await host.SharedHttpClient!.SendAsync(request, cancellationToken).ConfigureAwait(false);
        string responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        string? wwwAuthenticate = null;
        if(response.Headers.TryGetValues(WellKnownHttpHeaderNames.WwwAuthenticate, out IEnumerable<string>? values))
        {
            foreach(string value in values)
            {
                wwwAuthenticate = value;

                break;
            }
        }

        return ((int)response.StatusCode, wwwAuthenticate, responseBody);
    }


    /// <summary>The bearer token <see cref="AuthorizeTestCoordinator"/> permits a §3.6 coordinator operation for.</summary>
    internal static string CoordinatorToken { get; } = "vcalm-test-coordinator-token";

    /// <summary>The RFC 6750 §3 <c>WWW-Authenticate</c> challenge value <see cref="AuthorizeTestCoordinator"/> denies with.</summary>
    internal static string CoordinatorChallenge { get; } = "Bearer realm=\"vcalm-test\"";

    /// <summary>
    /// The <c>Authorization</c> header value a create-exchange or state-read helper presents to satisfy
    /// <see cref="AuthorizeTestCoordinator"/> — reused directly by a caller that composes its own request
    /// over the real wire instead of one of this fixture's own send helpers.
    /// </summary>
    internal static string CoordinatorAuthorizationHeader { get; } = $"Bearer {CoordinatorToken}";

    /// <summary>
    /// The <see cref="RequestHeaders"/> an in-process create-exchange or state-read dispatch carries so its request
    /// satisfies <see cref="AuthorizeTestCoordinator"/> — the <see cref="TestHostShell"/> dispatch helpers' headers
    /// argument, for tests that reach the §3.6.3 / §3.6.6 REQUIRED coordinator authorization seam without the real wire.
    /// </summary>
    internal static RequestHeaders CoordinatorAuthorizationHeaders { get; } = new(
        new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = [CoordinatorAuthorizationHeader]
        });

    /// <summary>
    /// An <see cref="AuthorizeVcalmCoordinatorDelegate"/> permitting a §3.6 coordinator operation whose request
    /// presents <c>Authorization: {CoordinatorAuthorizationHeader}</c>, denying every other request with
    /// <see cref="CoordinatorChallenge"/> — VCALM 1.0 A4016 / A4758's "401 Not Authorized",
    /// RFC 6750 §3's <c>WWW-Authenticate</c> challenge.
    /// </summary>
    internal static AuthorizeVcalmCoordinatorDelegate AuthorizeTestCoordinator { get; } = (request, context, cancellationToken) =>
    {
        bool isPermitted = context.IncomingRequest is { } incoming
            && incoming.Headers.TryGetSingle(WellKnownHttpHeaderNames.Authorization, out string? authorizationHeader)
            && string.Equals(authorizationHeader, CoordinatorAuthorizationHeader, StringComparison.Ordinal);

        return ValueTask.FromResult(isPermitted ? VcalmCoordinatorDecision.Permit : VcalmCoordinatorDecision.Deny(CoordinatorChallenge));
    };


    /// <summary>
    /// GETs the §3.6.2 configuration of the workflow <paramref name="workflowId"/> of the tenant
    /// <paramref name="segment"/> over the real wire, starting the host when it is not yet listening, and
    /// returns the parsed configuration after checking the response status.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="segment">The workflow tenant segment.</param>
    /// <param name="workflowId">The workflow whose configuration is read.</param>
    /// <param name="expectedStatus">The HTTP status the response must carry.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The parsed workflow configuration; the caller disposes it.</returns>
    internal static async Task<JsonDocument> GetWorkflowWireAsync(
        TestHostShell app, string segment, string workflowId, int expectedStatus, CancellationToken cancellationToken)
    {
        await app.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        string collectionPath = TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmGetWorkflow, segment);
        Uri url = new(host.HttpBaseAddress!, $"{collectionPath}/{Uri.EscapeDataString(workflowId)}");
        using HttpResponseMessage response = await host.SharedHttpClient!.GetAsync(url, cancellationToken).ConfigureAwait(false);
        string responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(expectedStatus, (int)response.StatusCode, responseBody);

        return JsonDocument.Parse(responseBody);
    }


    /// <summary>The absolute path of the exchange <paramref name="exchangeId"/> of the tenant <paramref name="segment"/>.</summary>
    /// <param name="segment">The exchange tenant segment.</param>
    /// <param name="exchangeId">The exchange id, escaped as one path segment.</param>
    /// <returns>The exchange's path on the host.</returns>
    private static string ComposeExchangePath(string segment, string exchangeId) =>
        TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmParticipateInExchange, segment) + "/" + Uri.EscapeDataString(exchangeId);


    /// <summary>
    /// Whether the verification <paramref name="response"/>'s <c>problemDetails</c> holds a ProblemDetail whose
    /// <c>type</c> is <paramref name="type"/>, compared as the literal type URL, and, when
    /// <paramref name="detailEnding"/> is given, whose <c>detail</c> ends with it; a response without
    /// <c>problemDetails</c> holds none.
    /// </summary>
    /// <param name="response">The parsed verification response.</param>
    /// <param name="type">The literal problem type URL looked for.</param>
    /// <param name="detailEnding">The ending the problem's <c>detail</c> must carry, or <see langword="null"/> for any detail.</param>
    /// <returns><see langword="true"/> when a ProblemDetail of that type, and detail ending when given, is present.</returns>
    internal static bool HasProblemOfType(JsonDocument response, string type, string? detailEnding = null)
    {
        if(!response.RootElement.TryGetProperty(VcalmParameterNames.ProblemDetails, out JsonElement problems))
        {
            return false;
        }

        foreach(JsonElement problem in problems.EnumerateArray())
        {
            if(problem.TryGetProperty(VcalmParameterNames.ProblemType, out JsonElement problemType)
                && string.Equals(problemType.GetString(), type, StringComparison.Ordinal)
                && (detailEnding is null
                    || (problem.TryGetProperty("detail", out JsonElement detail)
                        && detail.GetString() is { } detailText
                        && detailText.EndsWith(detailEnding, StringComparison.Ordinal))))
            {
                return true;
            }
        }

        return false;
    }


    /// <summary>
    /// Stands in for a dependency that keeps the request waiting until its caller abandons it: records that the
    /// dependency was entered, then completes only when <paramref name="cancellationToken"/> cancels, never on a
    /// clock, recording that the cancellation was observed before rethrowing it.
    /// </summary>
    /// <param name="hasEntered">Completed as soon as the dependency is entered.</param>
    /// <param name="hasObservedCancellation">Completed when the dependency observes its token's cancellation.</param>
    /// <param name="cancellationToken">The token the server passed to the dependency.</param>
    internal static async Task HangUntilCancelledAsync(
        TaskCompletionSource hasEntered, TaskCompletionSource hasObservedCancellation, CancellationToken cancellationToken)
    {
        _ = hasEntered.TrySetResult();

        TaskCompletionSource hangUntilCancelled = new(TaskCreationOptions.RunContinuationsAsynchronously);
        using CancellationTokenRegistration registration = cancellationToken.Register(
            () => hangUntilCancelled.TrySetCanceled(cancellationToken));
        try
        {
            await hangUntilCancelled.Task.ConfigureAwait(false);
        }
        catch(OperationCanceledException) when(cancellationToken.IsCancellationRequested)
        {
            _ = hasObservedCancellation.TrySetResult();
            throw;
        }
    }


    /// <summary>
    /// POSTs <paramref name="body"/> over the real wire to the endpoint named <paramref name="endpointName"/>, abandons
    /// the request once the dependency under test has been entered, and asserts that the request ended as its caller's
    /// cancellation, through
    /// <see cref="AssertAbandonedRequestProducesNoResponseAsync(TestHostShell, Func{HostedAuthorizationServer, CancellationToken, Task{HttpResponseMessage}}, Task, Task, CancellationToken)"/>.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request; it is disposed by this helper.</param>
    /// <param name="segment">The tenant segment the endpoint is registered under.</param>
    /// <param name="endpointName">The well-known endpoint name.</param>
    /// <param name="body">The request body JSON text.</param>
    /// <param name="hasEnteredDependency">Completes when the dependency under test has been entered.</param>
    /// <param name="hasObservedCancellation">Completes when the dependency has observed the abandonment.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>A task completing when the assertions have run.</returns>
    internal static Task AssertAbandonedRequestProducesNoResponseAsync(
        TestHostShell app,
        string segment,
        string endpointName,
        string body,
        Task hasEnteredDependency,
        Task hasObservedCancellation,
        CancellationToken cancellationToken) =>
        AssertAbandonedRequestProducesNoResponseAsync(
            app,
            async (host, callerToken) =>
            {
                using StringContent content = new(body, Encoding.UTF8, "application/json");
                Uri url = new(host.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(endpointName, segment));

                return await host.SharedHttpClient!.PostAsync(url, content, callerToken).ConfigureAwait(false);
            },
            hasEnteredDependency,
            hasObservedCancellation,
            cancellationToken);


    /// <summary>
    /// Sends the request <paramref name="sendRequest"/> makes over the real wire to the loopback HTTPS host of
    /// <paramref name="app"/>, whichever endpoint of the host it names, abandons it once the dependency under test has
    /// been entered, and asserts that the request ended as its caller's cancellation: the host recorded no fault
    /// escaping the endpoint (<see cref="HostedAuthorizationServer.HttpFaults"/>, where the host answers an
    /// <see cref="InvalidOperationException"/> the dispatch lets escape), and the server built no response for it at
    /// all, since every response passes the outgoing inspection stage before it is written. Stopping the listener waits
    /// for the abandoned request's processing to finish, so a fault or a response for it would be on record.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request; it is disposed by this helper.</param>
    /// <param name="sendRequest">Sends the request to the started host under the caller's token it is given.</param>
    /// <param name="hasEnteredDependency">Completes when the dependency under test has been entered.</param>
    /// <param name="hasObservedCancellation">Completes when the dependency has observed the abandonment.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>A task completing when the assertions have run.</returns>
    internal static async Task AssertAbandonedRequestProducesNoResponseAsync(
        TestHostShell app,
        Func<HostedAuthorizationServer, CancellationToken, Task<HttpResponseMessage>> sendRequest,
        Task hasEnteredDependency,
        Task hasObservedCancellation,
        CancellationToken cancellationToken)
    {
        await app.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        ConcurrentQueue<OutgoingResponseStage> responses = await RecordAtResponseAsync(app, static (outgoing, _) => outgoing).ConfigureAwait(false);

        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task<HttpResponseMessage> request = sendRequest(host, caller.Token);
        await hasEnteredDependency.WaitAsync(cancellationToken).ConfigureAwait(false);
        await caller.CancelAsync().ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => request).ConfigureAwait(false);
        await hasObservedCancellation.WaitAsync(cancellationToken).ConfigureAwait(false);

        await host.HttpHost!.StopAsync(cancellationToken).ConfigureAwait(false);
        Assert.IsEmpty(host.ConsumeHttpFaults(), "An abandoned request must end as its caller's cancellation, never as a fault the host records.");
        await app.DisposeAsync().ConfigureAwait(false);
        Assert.IsEmpty(responses, "An abandoned request must not produce a response.");
    }


    /// <summary>
    /// Records, for every response the host of <paramref name="app"/> builds from now on, what <paramref name="read"/>
    /// takes from that response and its request's own <see cref="ExchangeContext"/> at the outgoing inspection stage,
    /// the stage every response passes before it is written, after the endpoint has done its work. A test reads through it
    /// the per-request state the response itself does not carry, and whether a response was built at all.
    /// </summary>
    /// <typeparam name="T">What is recorded per response.</typeparam>
    /// <param name="app">The host shell whose responses are observed.</param>
    /// <param name="read">Reads the recorded value from the outgoing stage and the request's context.</param>
    /// <returns>The values recorded, one per response, in the order the responses were built.</returns>
    internal static async Task<ConcurrentQueue<T>> RecordAtResponseAsync<T>(
        TestHostShell app, Func<OutgoingResponseStage, ExchangeContext, T> read)
    {
        ConcurrentQueue<T> recorded = new();
        await TestHostShell.AlterAsync(app.Server, integration =>
        {
            InspectDelegate previous = integration.InspectAsync!;
            integration.InspectAsync = (stage, context, inspectCancellationToken) =>
            {
                if(stage is OutgoingResponseStage outgoing)
                {
                    recorded.Enqueue(read(outgoing, context));
                }

                return previous(stage, context, inspectCancellationToken);
            };
        }).ConfigureAwait(false);

        return recorded;
    }

    /// <summary>The known <c>@context</c> a verifier checks <see cref="BuildCredential"/>'s output against.</summary>
    internal static Context CredentialKnownContext { get; } =
        Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl);

    /// <summary>The known <c>@context</c> a verifier checks <see cref="SerializeUnproofedPresentation"/>'s output against.</summary>
    internal static Context PresentationKnownContext { get; } = Context.FromIris(Context.Credentials20);


    /// <summary>Builds the fixed "ExampleAlumniCredential" test credential.</summary>
    /// <param name="issuerDid">The issuer DID.</param>
    /// <param name="credentialId">The credential's <c>id</c>, or <see langword="null"/> to omit it.</param>
    /// <returns>The assembled credential.</returns>
    internal static VerifiableCredential BuildCredential(string issuerDid, string? credentialId) =>
        new()
        {
            Context = Context.FromIris(Context.Credentials20, CanonicalizationTestUtilities.CredentialsExamplesV2ContextUrl),
            Id = credentialId,
            Type = ["VerifiableCredential", "ExampleAlumniCredential"],
            Issuer = new Issuer { Id = issuerDid },
            ValidFrom = "2023-01-01T00:00:00Z",
            ValidUntil = "2030-01-01T00:00:00Z",
            CredentialSubject =
            [
                new CredentialSubject
                {
                    Id = "did:example:alumni-subject",
                    AdditionalData = new Dictionary<string, object>(StringComparer.Ordinal)
                    {
                        ["alumniOf"] = "The School of Examples"
                    }
                }
            ]
        };


    /// <summary>
    /// Builds the VCALM §3.2 <c>/credentials/issue</c> request body wrapping
    /// <see cref="BuildCredential"/>'s serialization: <c>{"credential":...}</c>.
    /// </summary>
    /// <param name="issuerDid">The issuer DID.</param>
    /// <param name="credentialId">The credential's <c>id</c>, or <see langword="null"/> to omit it.</param>
    /// <param name="serializeCredential">The caller's own credential serialization delegate.</param>
    /// <returns>The issue-request body JSON text.</returns>
    internal static string BuildIssueRequestBody(string issuerDid, string? credentialId, CredentialSerializeDelegate serializeCredential) =>
        "{\"credential\":" + serializeCredential(BuildCredential(issuerDid, credentialId)) + "}";


    /// <summary>Builds and serializes a bare (unproofed) <c>VerifiablePresentation</c> for <paramref name="holderDid"/>.</summary>
    /// <param name="holderDid">The presentation's <c>holder</c>.</param>
    /// <param name="serializePresentation">The caller's own presentation serialization delegate.</param>
    /// <param name="presentationId">The presentation's <c>id</c>, or <see langword="null"/> to omit it.</param>
    /// <returns>The serialized presentation JSON text.</returns>
    internal static string SerializeUnproofedPresentation(string holderDid, PresentationSerializeDelegate serializePresentation, string? presentationId = null) =>
        serializePresentation(new VerifiablePresentation
        {
            Context = Context.FromIris(Context.Credentials20),
            Id = presentationId,
            Type = ["VerifiablePresentation"],
            Holder = holderDid
        });
}
