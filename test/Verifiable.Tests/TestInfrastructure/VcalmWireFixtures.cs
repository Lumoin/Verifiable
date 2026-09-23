using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
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
        await app.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri url = new(host.HttpBaseAddress!, path);
        using StringContent content = new(body, Encoding.UTF8, "application/json");
        using HttpResponseMessage response = await host.SharedHttpClient!.PostAsync(url, content, cancellationToken).ConfigureAwait(false);
        string responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(expectedStatus, (int)response.StatusCode, responseBody);

        return responseBody;
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
        PostJsonWireAsync(
            app,
            TestHostShell.ComposeEndpointPath(WellKnownVcalmEndpointNames.VcalmParticipateInExchange, segment) + "/" + Uri.EscapeDataString(exchangeId),
            body,
            expectedStatus,
            cancellationToken);


    /// <summary>
    /// Whether the verification <paramref name="response"/>'s <c>problemDetails</c> holds a ProblemDetail whose
    /// <c>type</c> is <paramref name="type"/>, compared as the literal type URL; a response without
    /// <c>problemDetails</c> holds none.
    /// </summary>
    /// <param name="response">The parsed verification response.</param>
    /// <param name="type">The literal problem type URL looked for.</param>
    /// <returns><see langword="true"/> when a ProblemDetail of that type is present.</returns>
    internal static bool HasProblemOfType(JsonDocument response, string type)
    {
        if(!response.RootElement.TryGetProperty(VcalmParameterNames.ProblemDetails, out JsonElement problems))
        {
            return false;
        }

        foreach(JsonElement problem in problems.EnumerateArray())
        {
            if(problem.TryGetProperty(VcalmParameterNames.ProblemType, out JsonElement problemType)
                && string.Equals(problemType.GetString(), type, StringComparison.Ordinal))
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
    /// the request once the dependency under test has been entered, and asserts that the server built no response for
    /// it at all: every response passes the outgoing inspection stage before it is written, and stopping the host
    /// waits for the abandoned request's processing to finish, so a response built for it would be on record.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request; it is disposed by this helper.</param>
    /// <param name="segment">The tenant segment the endpoint is registered under.</param>
    /// <param name="endpointName">The well-known endpoint name.</param>
    /// <param name="body">The request body JSON text.</param>
    /// <param name="hasEnteredDependency">Completes when the dependency under test has been entered.</param>
    /// <param name="hasObservedCancellation">Completes when the dependency has observed the abandonment.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    internal static async Task AssertAbandonedRequestProducesNoResponseAsync(
        TestHostShell app,
        string segment,
        string endpointName,
        string body,
        Task hasEnteredDependency,
        Task hasObservedCancellation,
        CancellationToken cancellationToken)
    {
        await app.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri url = new(host.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(endpointName, segment));

        ConcurrentQueue<OutgoingResponseStage> responses = new();
        await TestHostShell.AlterAsync(app.Server, integration =>
        {
            InspectDelegate previous = integration.InspectAsync!;
            integration.InspectAsync = (stage, context, inspectCancellationToken) =>
            {
                if(stage is OutgoingResponseStage outgoing)
                {
                    responses.Enqueue(outgoing);
                }

                return previous(stage, context, inspectCancellationToken);
            };
        }).ConfigureAwait(false);

        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        async Task<HttpResponseMessage> PostAbandonedRequestAsync()
        {
            using StringContent content = new(body, Encoding.UTF8, "application/json");

            return await host.SharedHttpClient!.PostAsync(url, content, caller.Token).ConfigureAwait(false);
        }

        Task<HttpResponseMessage> request = PostAbandonedRequestAsync();
        await hasEnteredDependency.WaitAsync(cancellationToken).ConfigureAwait(false);
        await caller.CancelAsync().ConfigureAwait(false);
        _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(() => request).ConfigureAwait(false);
        await hasObservedCancellation.WaitAsync(cancellationToken).ConfigureAwait(false);

        await app.DisposeAsync().ConfigureAwait(false);
        Assert.IsEmpty(responses, "An abandoned request must not produce a response.");
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
