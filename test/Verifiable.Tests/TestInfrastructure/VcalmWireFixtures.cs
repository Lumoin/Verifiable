using System.Collections.Concurrent;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.Core.Did.Methods.Key;
using Verifiable.Core.Model.Common;
using Verifiable.Core.Model.Credentials;
using Verifiable.Core.Model.DataIntegrity;
using Verifiable.Core.Model.Did;
using Verifiable.Core.Model.Did.CryptographicSuites;
using Verifiable.Cryptography;
using Verifiable.Server.Routing;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
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
    /// The payload cap, in bytes, <see cref="PostOneByteOverCapWireAsync"/> configures as
    /// <see cref="VcalmIntegration.VcalmMaxRequestBytes"/>: small, so the body one byte over it stays small.
    /// </summary>
    internal static int OverCapRowPayloadCap { get; } = 1024;


    /// <summary>
    /// Lowers <see cref="VcalmIntegration.VcalmMaxRequestBytes"/> of <paramref name="app"/> to
    /// <see cref="OverCapRowPayloadCap"/> and POSTs a JSON object of exactly that cap plus one UTF-8 bytes, labelled
    /// <c>application/json</c>, over the real wire to <paramref name="path"/>: the smallest body the VCALM payload cap
    /// refuses, the request a row proving the answer to a body over the cap sends. Every such answer is asserted here
    /// to be HTTP 413 whose <c>detail</c> is the literal sentence
    /// "The request body exceeds the configured maximum payload size." and whose body holds no digit, so the
    /// configured cap is never disclosed.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="authorizationHeader">
    /// The <c>Authorization</c> header value to send, or <see langword="null"/> to send no <c>Authorization</c> header.
    /// </param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The response status code and its body text.</returns>
    internal static async Task<(int StatusCode, string Body)> PostOneByteOverCapWireAsync(
        TestHostShell app, string path, string? authorizationHeader, CancellationToken cancellationToken)
    {
        await TestHostShell.AlterVcalmAsync(app.Server, candidateIntegration =>
        {
            candidateIntegration.VcalmMaxRequestBytes = OverCapRowPayloadCap;
        }).ConfigureAwait(false);

        //The object {"x":"aa...a"} carries eight bytes of structure around its ASCII padding, so its UTF-8 form is
        //exactly the cap plus one byte long.
        string body = "{\"x\":\"" + new string('a', OverCapRowPayloadCap + 1 - 8) + "\"}";
        Assert.AreEqual(OverCapRowPayloadCap + 1, Encoding.UTF8.GetByteCount(body),
            "The request body is exactly one byte over the configured payload cap.");

        (int statusCode, _, string responseBody) = await SendWireAsync(
            app, "POST", path, body, authorizationHeader, cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(413, statusCode, responseBody);
        using JsonDocument problem = JsonDocument.Parse(responseBody);
        Assert.AreEqual("The request body exceeds the configured maximum payload size.",
            problem.RootElement.GetProperty(VcalmParameterNames.ProblemDetail).GetString(), responseBody);
        Assert.IsFalse(responseBody.AsSpan().ContainsAnyInRange('0', '9'),
            $"The answer to a body over the cap holds no digit, so the configured cap is not disclosed: {responseBody}");

        return (statusCode, responseBody);
    }


    /// <summary>
    /// POSTs the raw <paramref name="body"/> bytes labelled <c>application/json</c> over the real wire to
    /// <paramref name="path"/> and asserts the answer to a body that is not a JSON text: HTTP 400 with an
    /// <c>application/json</c> ProblemDetails whose <c>type</c> is the literal
    /// <c>https://www.w3.org/TR/vc-data-model#PARSING_ERROR</c> and whose <c>title</c> is the literal
    /// <c>PARSING_ERROR</c>, the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#PARSING_ERROR">VC Data Model 2.0 Section 7.2</see> defines
    /// as "There was an error while parsing input."
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The raw request body bytes, sent as they are.</param>
    /// <param name="authorizationHeader">
    /// The <c>Authorization</c> header value to send, or <see langword="null"/> to send no <c>Authorization</c> header.
    /// </param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>A task completing when the assertions have run.</returns>
    internal static Task AssertPostAnswersParsingErrorWireAsync(
        TestHostShell app, string path, byte[] body, string? authorizationHeader, CancellationToken cancellationToken) =>
        AssertPostAnswersProblemWireAsync(
            app,
            path,
            body,
            "application/json",
            authorizationHeader,
            "https://www.w3.org/TR/vc-data-model#PARSING_ERROR",
            "PARSING_ERROR",
            cancellationToken);


    /// <summary>
    /// POSTs the JSON text <paramref name="body"/> labelled <c>application/json</c> over the real wire to
    /// <paramref name="path"/> and asserts the answer to a JSON text whose content the endpoint refuses: HTTP 400 with
    /// an <c>application/json</c> ProblemDetails whose <c>type</c> is the literal
    /// <c>https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR</c> and whose <c>title</c> is the literal
    /// <c>MALFORMED_VALUE_ERROR</c>, the type the
    /// <see href="https://www.w3.org/TR/vc-data-model-2.0/#MALFORMED_VALUE_ERROR">VC Data Model 2.0 Section 7.2</see>
    /// defines as "The value associated with a particular property is malformed."
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The request body JSON text, sent as UTF-8.</param>
    /// <param name="authorizationHeader">
    /// The <c>Authorization</c> header value to send, or <see langword="null"/> to send no <c>Authorization</c> header.
    /// </param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>A task completing when the assertions have run.</returns>
    internal static Task AssertPostAnswersMalformedValueErrorWireAsync(
        TestHostShell app, string path, string body, string? authorizationHeader, CancellationToken cancellationToken) =>
        AssertPostAnswersProblemWireAsync(
            app,
            path,
            Encoding.UTF8.GetBytes(body),
            "application/json",
            authorizationHeader,
            "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            "MALFORMED_VALUE_ERROR",
            cancellationToken);


    /// <summary>
    /// The value a row wiring its own parse delegate gives the parse result's <c>Failure</c>: a
    /// <see cref="VcalmParseFailure"/> outside the members the enumeration names, a value an application's own parse
    /// delegate can return and an endpoint does not understand.
    /// </summary>
    internal static VcalmParseFailure UnnamedParseFailure { get; } = (VcalmParseFailure)99;


    /// <summary>
    /// POSTs the body text <paramref name="body"/>, sent as UTF-8, labelled <paramref name="mediaType"/> or carrying no
    /// <c>Content-Type</c> header at all, over the real wire to <paramref name="path"/>, and asserts the answer of the
    /// endpoint's request boundary: HTTP 400 with an <c>application/json</c> ProblemDetails whose <c>title</c> is the
    /// literal <paramref name="expectedTitle"/> and whose <c>type</c> is the literal data model URL of that title.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The request body text, sent as UTF-8; the empty string sends zero bytes.</param>
    /// <param name="mediaType">The media type the body is labelled with, or <see langword="null"/> to send no <c>Content-Type</c> header.</param>
    /// <param name="expectedTitle">The literal title, <c>PARSING_ERROR</c> or <c>MALFORMED_VALUE_ERROR</c>, the answer carries.</param>
    /// <param name="authorizationHeader">The <c>Authorization</c> header value, or <see langword="null"/> to send none.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>A task completing when the assertions have run.</returns>
    internal static Task AssertBoundaryAnswerWireAsync(
        TestHostShell app,
        string path,
        string body,
        string? mediaType,
        string expectedTitle,
        string? authorizationHeader,
        CancellationToken cancellationToken)
    {
        string expectedType = expectedTitle switch
        {
            "PARSING_ERROR" => "https://www.w3.org/TR/vc-data-model#PARSING_ERROR",
            "MALFORMED_VALUE_ERROR" => "https://www.w3.org/TR/vc-data-model#MALFORMED_VALUE_ERROR",
            _ => throw new ArgumentOutOfRangeException(nameof(expectedTitle), expectedTitle, "A boundary answer is the parsing error or the malformed value.")
        };

        return AssertPostAnswersProblemWireAsync(
            app, path, Encoding.UTF8.GetBytes(body), mediaType, authorizationHeader, expectedType, expectedTitle, cancellationToken);
    }


    /// <summary>
    /// The shared send and assertions of <see cref="AssertPostAnswersParsingErrorWireAsync"/>,
    /// <see cref="AssertPostAnswersMalformedValueErrorWireAsync"/> and <see cref="AssertBoundaryAnswerWireAsync"/>: one
    /// POST of the raw <paramref name="body"/> bytes labelled <paramref name="requestMediaType"/>, after which the host
    /// has recorded no fault escaping the endpoint, answered with HTTP 400, an <c>application/json</c> body, and a
    /// ProblemDetails whose <c>type</c> and <c>title</c> equal the expected literals.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The raw request body bytes.</param>
    /// <param name="requestMediaType">The media type the body is labelled with, or <see langword="null"/> to send no <c>Content-Type</c> header.</param>
    /// <param name="authorizationHeader">The <c>Authorization</c> header value, or <see langword="null"/> to send none.</param>
    /// <param name="expectedType">The literal problem type URL the answer carries.</param>
    /// <param name="expectedTitle">The literal problem title the answer carries.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>A task completing when the assertions have run.</returns>
    private static async Task AssertPostAnswersProblemWireAsync(
        TestHostShell app,
        string path,
        byte[] body,
        string? requestMediaType,
        string? authorizationHeader,
        string expectedType,
        string expectedTitle,
        CancellationToken cancellationToken)
    {
        (int statusCode, string? mediaType, string responseBody) = await SendRawBytesWireAsync(
            app, "POST", path, body, requestMediaType, authorizationHeader, cancellationToken).ConfigureAwait(false);

        //The faults are consumed before any other assertion, so a fault is what the row reports rather than the
        //status it caused, and the host's teardown finds none left over.
        Exception[] faults = app.Host("default").ConsumeHttpFaults();
        Assert.IsEmpty(faults, $"A request body must not escape the endpoint as a fault the host records. Response: {responseBody}");
        Assert.AreEqual(400, statusCode, responseBody);
        Assert.AreEqual("application/json", mediaType, responseBody);
        using JsonDocument problem = JsonDocument.Parse(responseBody);
        Assert.AreEqual(expectedType, problem.RootElement.GetProperty(VcalmParameterNames.ProblemType).GetString(), responseBody);
        Assert.AreEqual(expectedTitle, problem.RootElement.GetProperty(VcalmParameterNames.ProblemTitle).GetString(), responseBody);
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
    internal static Task<(int StatusCode, string? WwwAuthenticate, string Body)> SendWireAsync(
        TestHostShell app, string method, string path, string? body, string? authorizationHeader, CancellationToken cancellationToken) =>
        SendWireCoreAsync(app, method, path, body, "application/json", authorizationHeader, cancellationToken);


    /// <summary>
    /// Sends an HTTP request of <paramref name="method"/> to <paramref name="path"/> on the loopback HTTPS host of
    /// <paramref name="app"/> over the real wire, starting the host when it is not yet listening, with the body text
    /// <paramref name="body"/> labelled <paramref name="mediaType"/> — the primitive a test proves a body-shape or
    /// media-type refusal through, since it can send a body the <c>application/json</c> helpers never would: a body
    /// labelled with any media type, or a body carrying no <c>Content-Type</c> header at all.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="method">The HTTP method.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The request body text, sent as UTF-8, or <see langword="null"/> to send no body.</param>
    /// <param name="mediaType">
    /// The media type the <c>Content-Type</c> header names, or <see langword="null"/> to send the body with no
    /// <c>Content-Type</c> header.
    /// </param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The response status code, its <c>WWW-Authenticate</c> header value (or <see langword="null"/> when absent), and its body text.</returns>
    internal static Task<(int StatusCode, string? WwwAuthenticate, string Body)> SendBodyWireAsync(
        TestHostShell app, string method, string path, string? body, string? mediaType, CancellationToken cancellationToken) =>
        SendWireCoreAsync(app, method, path, body, mediaType, authorizationHeader: null, cancellationToken);


    /// <summary>
    /// The shared send of <see cref="SendWireAsync"/> and <see cref="SendBodyWireAsync"/>: one HTTP request over the
    /// real wire to the loopback HTTPS host of <paramref name="app"/>, with an optional body, the media type its
    /// <c>Content-Type</c> header names, and an optional <c>Authorization</c> header value.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="method">The HTTP method.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="body">The request body text, sent as UTF-8, or <see langword="null"/> to send no body.</param>
    /// <param name="mediaType">
    /// The media type the <c>Content-Type</c> header names, or <see langword="null"/> to send the body with no
    /// <c>Content-Type</c> header: the content's own default header is cleared, so none reaches the wire.
    /// </param>
    /// <param name="authorizationHeader">
    /// The <c>Authorization</c> header value to send, or <see langword="null"/> to send no <c>Authorization</c> header.
    /// </param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The response status code, its <c>WWW-Authenticate</c> header value (or <see langword="null"/> when absent), and its body text.</returns>
    private static async Task<(int StatusCode, string? WwwAuthenticate, string Body)> SendWireCoreAsync(
        TestHostShell app,
        string method,
        string path,
        string? body,
        string? mediaType,
        string? authorizationHeader,
        CancellationToken cancellationToken)
    {
        await app.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri url = new(host.HttpBaseAddress!, path);

        using HttpRequestMessage request = new(new HttpMethod(method), url);
        if(body is not null)
        {
            request.Content = new StringContent(body, Encoding.UTF8, mediaType);

            //A StringContent labels itself text/plain when given no media type; clearing the header sends the body
            //with no Content-Type at all.
            if(mediaType is null)
            {
                request.Content.Headers.ContentType = null;
            }
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


    /// <summary>
    /// Sends an HTTP request of <paramref name="method"/> to <paramref name="path"/> on the loopback HTTPS host of
    /// <paramref name="app"/> over the real wire, with raw <paramref name="bytes"/> labelled <paramref name="mediaType"/>
    /// — the primitive a test proves a byte-level body refusal through, since a <see cref="string"/> body cannot carry
    /// bytes that are not valid UTF-8 (every C# string re-encodes to valid UTF-8 when sent).
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="method">The HTTP method.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="bytes">The raw request body bytes.</param>
    /// <param name="mediaType">The media type the <c>Content-Type</c> header names.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The response status code and its body text.</returns>
    internal static async Task<(int StatusCode, string Body)> SendRawBytesWireAsync(
        TestHostShell app, string method, string path, byte[] bytes, string mediaType, CancellationToken cancellationToken)
    {
        (int statusCode, _, string responseBody) = await SendRawBytesWireAsync(
            app, method, path, bytes, mediaType, authorizationHeader: null, cancellationToken).ConfigureAwait(false);

        return (statusCode, responseBody);
    }


    /// <summary>
    /// Sends an HTTP request of <paramref name="method"/> to <paramref name="path"/> on the loopback HTTPS host of
    /// <paramref name="app"/> over the real wire, with raw <paramref name="bytes"/> labelled <paramref name="mediaType"/>
    /// or carrying no <c>Content-Type</c> header at all, and an optional <paramref name="authorizationHeader"/> value on
    /// the request's <c>Authorization</c> header, and returns the media type the response's <c>Content-Type</c> header
    /// names beside its status and body: the form a byte-level body refusal is proven through on a route authorized
    /// before its body is read, wherever the refusal's own media type is asserted, and for a body sent with no media type.
    /// </summary>
    /// <param name="app">The host shell whose default host serves the request.</param>
    /// <param name="method">The HTTP method.</param>
    /// <param name="path">The absolute path of the endpoint on the host.</param>
    /// <param name="bytes">The raw request body bytes.</param>
    /// <param name="mediaType">
    /// The media type the <c>Content-Type</c> header names, or <see langword="null"/> to send the bytes with no
    /// <c>Content-Type</c> header.
    /// </param>
    /// <param name="authorizationHeader">
    /// The <c>Authorization</c> header value to send, or <see langword="null"/> to send no <c>Authorization</c> header.
    /// </param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>
    /// The response status code, the media type its <c>Content-Type</c> header names (or <see langword="null"/> when it
    /// carries none), and its body text.
    /// </returns>
    internal static async Task<(int StatusCode, string? MediaType, string Body)> SendRawBytesWireAsync(
        TestHostShell app,
        string method,
        string path,
        byte[] bytes,
        string? mediaType,
        string? authorizationHeader,
        CancellationToken cancellationToken)
    {
        await app.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);
        HostedAuthorizationServer host = app.Host("default");
        Uri url = new(host.HttpBaseAddress!, path);

        //A ByteArrayContent carries no Content-Type header of its own, so leaving it unset sends the bytes with none.
        using HttpRequestMessage request = new(new HttpMethod(method), url)
        {
            Content = new ByteArrayContent(bytes)
        };
        if(mediaType is not null)
        {
            request.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
        }

        if(authorizationHeader is not null)
        {
            _ = request.Headers.TryAddWithoutValidation(WellKnownHttpHeaderNames.Authorization, authorizationHeader);
        }

        using HttpResponseMessage response = await host.SharedHttpClient!.SendAsync(request, cancellationToken).ConfigureAwait(false);
        string responseBody = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, response.Content.Headers.ContentType?.MediaType, responseBody);
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
    internal static string ComposeExchangePath(string segment, string exchangeId) =>
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
        await HookEntryWait.WaitForEntryAsync(hasEnteredDependency, request, cancellationToken).ConfigureAwait(false);
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


    /// <summary>Builds the did:key documents of the holders <see cref="CreateHolderPresentationSigningAsync"/> creates.</summary>
    private static KeyDidBuilder HolderKeyDidBuilder { get; } = new();


    /// <summary>
    /// Builds a holder's eddsa-jcs-2022 presentation-signing configuration, the VCALM §3.5.2 presentation-signing
    /// seam, under a fresh did:key holder a did:key resolver resolves locally, and returns it with the holder DID the
    /// presentations it signs claim. The public half is not retained on the configuration and is disposed here; the
    /// private key lives on the configuration for the host's lifetime and is added to <paramref name="ownedKeys"/> so
    /// the caller disposes it at cleanup, after the host that holds the configuration is torn down.
    /// </summary>
    /// <param name="canonicalize">The JCS canonicalizer the presentations are signed over.</param>
    /// <param name="serializePresentation">The caller's own presentation serialization delegate.</param>
    /// <param name="deserializePresentation">The caller's own presentation deserialization delegate.</param>
    /// <param name="serializeProofOptions">The caller's own proof options serialization delegate.</param>
    /// <param name="pool">The memory pool the key material and the signing rent from.</param>
    /// <param name="ownedKeys">Receives the private key the caller disposes at cleanup.</param>
    /// <param name="cancellationToken">The test's own cancellation token.</param>
    /// <returns>The presentation-signing configuration and the holder DID.</returns>
    internal static async Task<(VcalmPresentationSigning Signing, string HolderDid)> CreateHolderPresentationSigningAsync(
        CanonicalizationDelegate canonicalize,
        PresentationSerializeDelegate serializePresentation,
        PresentationDeserializeDelegate deserializePresentation,
        ProofOptionsSerializeDelegate serializeProofOptions,
        BaseMemoryPool pool,
        ICollection<IDisposable> ownedKeys,
        CancellationToken cancellationToken)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keyPair =
            TestKeyMaterialProvider.CreateEd25519KeyMaterial();

        DidDocument holderDidDocument = await HolderKeyDidBuilder.BuildAsync(
            keyPair.PublicKey,
            MultikeyVerificationMethodTypeInfo.Instance,
            pool,
            includeDefaultContext: false,
            cancellationToken: cancellationToken).ConfigureAwait(false);

        string verificationMethodId = holderDidDocument.VerificationMethod![0].Id!;
        string holderDid = holderDidDocument.Id!.ToString();

        //The public half is not retained on the signing configuration; dispose it. The private key lives on
        //the signing configuration for the host's lifetime and is disposed by the caller at cleanup.
        keyPair.PublicKey.Dispose();
        ownedKeys.Add(keyPair.PrivateKey);

        VcalmPresentationSigning signing = new()
        {
            PrivateKey = keyPair.PrivateKey,
            DefaultVerificationMethodId = verificationMethodId,
            Cryptosuite = EddsaJcs2022CryptosuiteInfo.Instance,
            Canonicalize = canonicalize,
            ContextResolver = null,
            EncodeProofValue = ProofValueCodecs.EncodeBase58Btc,
            SerializePresentation = serializePresentation,
            DeserializePresentation = deserializePresentation,
            SerializeProofOptions = serializeProofOptions,
            Encoder = TestSetup.Base58Encoder,
            ComputeDigest = MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
            MemoryPool = pool
        };

        return (signing, holderDid);
    }
}
