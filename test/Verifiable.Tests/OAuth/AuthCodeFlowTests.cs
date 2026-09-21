using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using Verifiable.Core;
using Verifiable.Core.Assessment;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.Validation;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;


[TestClass]
internal sealed class AuthCodeFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>
    /// The entropy source every <see cref="OAuthClientInfrastructure"/> this class constructs draws its
    /// state/nonce/PKCE bytes from — ONE continuously-advancing counter stream per test-class instance
    /// (MSTest constructs a fresh instance per test method), so two infrastructures built within the SAME
    /// test draw different byte sequences.
    /// </summary>
    private FillEntropyDelegate ClientEntropy { get; } = TestEntropy.NewCounterStream();

    private static Uri DefaultRedirectUri { get; } = new("https://client.example.com/callback");


    [TestMethod]
    public async Task HandleParAsyncReturnsRedirectOnSuccess()
    {
        var store = new Dictionary<string, FlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store, parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:abc", 60));

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string> { [OAuthRequestParameterNames.Scope] = "openid" },
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, result.Outcome);
        Assert.IsNotNull(result.RedirectUri);
        Assert.Contains("request_uri", result.RedirectUri.ToString(), StringComparison.Ordinal);
        Assert.HasCount(1, store, "PAR success must persist exactly one flow state.");
        ParCompletedState state = Assert.IsInstanceOfType<ParCompletedState>(TestDictionaryHelpers.GetFirstValue(store));
        Assert.AreEqual(TimeProvider.GetUtcNow(), state.EnteredAt,
            "ParCompletedState.EnteredAt is infrastructure.TimeProvider.GetUtcNow() at the PAR call — the " +
            "OAuthClientInfrastructure's own injected clock, never the system clock.");
    }


    [TestMethod]
    public async Task HandleParAsyncReturnsInternalErrorWhenHttpFails()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store: [],
            httpException: new InvalidOperationException("Network unreachable."));

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome);
        Assert.AreEqual("server_error", result.ErrorCode);
    }


    /// <summary>
    /// A <see cref="ResolveAuthorizationServerMetadataDelegate"/> answering
    /// <see cref="AuthorizationServerMetadataResolutionOutcome.FetchFailed"/> maps to this flow's own
    /// <c>server_error</c> failure without throwing, and without sending the PAR request or persisting
    /// any flow state — the resolution failed before the flow had a PAR endpoint to send to.
    /// </summary>
    [TestMethod]
    public async Task HandleParAsyncReturnsServerErrorWhenMetadataFetchFails()
    {
        Dictionary<string, FlowState> store = [];
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store,
            metadataResolutionOutcome: AuthorizationServerMetadataResolutionOutcome.FetchFailed,
            metadataResolutionDefect: "simulated transport failure");

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome);
        Assert.AreEqual("server_error", result.ErrorCode);
        Assert.IsEmpty(store, "A failed metadata resolution must not reach the PAR send or state save.");
    }


    /// <summary>
    /// A <see cref="ResolveAuthorizationServerMetadataDelegate"/> answering
    /// <see cref="AuthorizationServerMetadataResolutionOutcome.IssuerMismatch"/> maps to this flow's own
    /// <c>server_error</c> failure without throwing, the same channel a fetch failure takes.
    /// </summary>
    [TestMethod]
    public async Task HandleParAsyncReturnsServerErrorWhenMetadataIssuerMismatches()
    {
        Dictionary<string, FlowState> store = [];
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store,
            metadataResolutionOutcome: AuthorizationServerMetadataResolutionOutcome.IssuerMismatch,
            metadataResolutionDefect: "simulated issuer mismatch");

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome);
        Assert.AreEqual("server_error", result.ErrorCode);
        Assert.IsEmpty(store, "A failed metadata resolution must not reach the PAR send or state save.");
    }


    /// <summary>
    /// A transport-delegate <see cref="OperationCanceledException"/> thrown while sending the pushed
    /// authorization request propagates as-is instead of being folded into a
    /// <c>server_error</c> <see cref="AuthCodeFlowEndpointResult"/>: the PAR-send catch arms rethrow
    /// cancellation before the generic exception arm that produces the server-error outcome runs.
    /// </summary>
    [TestMethod]
    public async Task HandleParAsyncSurfacesCancellationInsteadOfServerError()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store: [],
            httpException: new OperationCanceledException());

        _ = await Assert.ThrowsExactlyAsync<OperationCanceledException>(async () =>
        {
            _ = await AuthCodeFlowHandlers.HandleParAsync(
                new Dictionary<string, string>(),
                DefaultRedirectUri,
                infrastructure,
                registration,
                TestContext.CancellationToken).ConfigureAwait(false);
        }).ConfigureAwait(false);
    }


    [TestMethod]
    public async Task HandleParAsyncReturnsBadRequestWhenServerReturnsProtocolError()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store: [],
            parResponse: /*lang=json,strict*/ "{\"error\":\"invalid_client\"}");

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("invalid_client", result.ErrorCode,
            "A well-formed OAuth error response must surface the server error code directly.");
    }


    [TestMethod]
    public async Task HandleParAsyncReturnsInternalErrorWhenResponseIsMalformed()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store: [],
            parResponse: "<html>502 Bad Gateway</html>");

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome);
        Assert.AreEqual("server_error", result.ErrorCode,
            "An HTML error page or unparseable body must map to server_error.");
    }


    //RFC 8414 §3.3 — the client-side metadata-consumption seam
    //(ResolveValidatedAuthorizationServerMetadataAsync) verifies a resolved
    //AuthorizationServerMetadata.Issuer against the pinned ClientRegistration.
    //AuthorizationServerIssuer before any flow handler uses the metadata's endpoints,
    //so a resolver returning metadata for the wrong authorization server is caught before
    //any request is sent to it.

    [TestMethod]
    public async Task HandleParAsyncRejectsWhenMetadataIssuerDoesNotMatchPinnedRegistration()
    {
        Uri pinnedIssuer = new("https://as.example.com");
        Uri divergentMetadataIssuer = new("https://different-as.example.com");

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = divergentMetadataIssuer,
            PushedAuthorizationRequestEndpoint = new Uri("https://as.example.com/par"),
            AuthorizationEndpoint = new Uri("https://as.example.com/authorize"),
            TokenEndpoint = new Uri("https://as.example.com/token")
        };

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (_, _, _, _, _) =>
                throw new InvalidOperationException(
                    "Must not send a PAR request when the metadata issuer fails validation."),
            saveStateAsync: (_, _, _) => ValueTask.CompletedTask,
            loadStateAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            loadStateByRequestUriAsync: (_, _, _) => ValueTask.FromResult<FlowState?>(null),
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("Test does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
                ValueTask.FromResult(new AuthorizationServerMetadataResolution
                {
                    Outcome = AuthorizationServerMetadataResolutionOutcome.Resolved,
                    Metadata = metadata
                }),
            resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: BaseMemoryPool.Shared,
            timeProvider: TimeProvider,
            fillEntropy: ClientEntropy,
            generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, ClientEntropy, BaseMemoryPool.Shared));

        ClientRegistration registration = new()
        {
            ClientId = new ClientId("test-client"),
            AuthorizationServerIssuer = pinnedIssuer,
            RedirectUris = [DefaultRedirectUri],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = PolicyProfile.Haip10
        };

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "A metadata issuer diverging from the pinned AuthorizationServerIssuer must be rejected " +
            "before any request is sent to the (potentially wrong) authorization server.");
        Assert.AreEqual("invalid_request", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleCallbackAsyncReturnsBadRequestWhenMissingParameters()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration([]);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string> { [OAuthRequestParameterNames.Code] = "abc" },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("invalid_request", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleCallbackAsyncReturnsBadRequestWhenFlowNotFound()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration([]);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Code] = "auth-code-xyz",
                [OAuthRequestParameterNames.State] = "unknown-flow-id",
                [OAuthRequestParameterNames.Iss] = "https://as.example.com"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("invalid_request", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleCallbackAsyncReturnsBadRequestOnIssuerMismatch()
    {
        var store = new Dictionary<string, FlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store, parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:x", 60));
        _ = await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);

        string flowId = GetSingleFlowId(store);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Code] = "code-abc",
                [OAuthRequestParameterNames.State] = flowId,
                [OAuthRequestParameterNames.Iss] = "https://attacker.example.com"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("invalid_request", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleCallbackAsyncPersistsCodeStateOnSuccess()
    {
        var store = new Dictionary<string, FlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store, parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:y", 60));
        _ = await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);

        string flowId = GetSingleFlowId(store);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Code] = "code-xyz",
                [OAuthRequestParameterNames.State] = flowId,
                [OAuthRequestParameterNames.Iss] = "https://as.example.com"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
        _ = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(store[flowId],
            "Callback success must replace ParCompleted with AuthorizationCodeReceived in the store.");
    }


    [TestMethod]
    public async Task HandleTokenAsyncReturnsBadRequestWhenFlowIdMissing()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration([]);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string>(),
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("invalid_request", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleTokenAsyncReturnsBadRequestWhenNoCodePending()
    {
        var store = new Dictionary<string, FlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store, parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:z", 60));
        _ = await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);

        string flowId = GetSingleFlowId(store);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = flowId },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome,
            "Token exchange with ParCompleted state (no code yet) must be rejected.");
    }


    [TestMethod]
    public async Task HandleTokenAsyncReturnsOkWithTokensOnFullHappyPath()
    {
        var store = new Dictionary<string, FlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store,
            parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:happy", 60),
            tokenResponse: OAuthJsonResponseFixtures.BuildTokenJson("at.abc", "Bearer", 3600, "rt.xyz"));

        _ = await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);
        string flowId = GetSingleFlowId(store);

        _ = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Code] = "code-happy",
                [OAuthRequestParameterNames.State] = flowId,
                [OAuthRequestParameterNames.Iss] = "https://as.example.com"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = flowId },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
        Assert.IsNotNull(result.Body);
        Assert.AreEqual("at.abc", result.Body["access_token"]);
        Assert.AreEqual("Bearer", result.Body["token_type"]);
        _ = Assert.IsInstanceOfType<TokenReceivedState>(store[flowId],
            "Token exchange success must persist TokenReceived in the store.");
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>: "the endpoints a client POSTs to — an OAuth/RFC 9728 token
    /// endpoint, a PAR endpoint — are themselves taken from discovered metadata, so a malicious or
    /// misconfigured metadata document could point them at an internal, loopback, or
    /// cloud-metadata address ... The OutboundFetchPolicy must therefore gate every method." A
    /// <c>token_endpoint</c> naming a loopback IP literal is refused before the §6 form POST is
    /// ever sent.
    /// </summary>
    [TestMethod]
    public async Task HandleTokenAsyncRefusesLoopbackTokenEndpointBeforeAnyDial()
    {
        var store = new Dictionary<string, FlowState>();
        List<Uri> invocations = [];
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store,
            parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:loopback-token", 60),
            tokenEndpointOverride: new Uri("https://127.0.0.1/token"),
            sendFormPostInvocations: invocations);

        _ = await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);
        string flowId = GetSingleFlowId(store);

        _ = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Code] = "code-loopback-token",
                [OAuthRequestParameterNames.State] = flowId,
                [OAuthRequestParameterNames.Iss] = "https://as.example.com"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The PAR endpoint above is not loopback and is legitimately dialed; only the token
        //endpoint's own denial is under test here, so the spy is reset immediately before it.
        invocations.Clear();

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = flowId },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome,
            "A token_endpoint naming a loopback IP literal must be refused, never dialed.");
        Assert.IsEmpty(invocations, "The transport spy must record ZERO invocations when the policy denies the endpoint.");
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>'s SSRF remark applies identically to the cloud-metadata
    /// literal <c>169.254.169.254</c>: a <c>token_endpoint</c> naming it is refused before any
    /// dial, exactly as the loopback case is.
    /// </summary>
    [TestMethod]
    public async Task HandleTokenAsyncRefusesCloudMetadataTokenEndpointBeforeAnyDial()
    {
        var store = new Dictionary<string, FlowState>();
        List<Uri> invocations = [];
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            store,
            parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:cloud-token", 60),
            tokenEndpointOverride: new Uri("https://169.254.169.254/token"),
            sendFormPostInvocations: invocations);

        _ = await AuthCodeFlowHandlers.HandleParAsync(new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);
        string flowId = GetSingleFlowId(store);

        _ = await AuthCodeFlowHandlers.HandleCallbackAsync(
            new Dictionary<string, string>
            {
                [OAuthRequestParameterNames.Code] = "code-cloud-token",
                [OAuthRequestParameterNames.State] = flowId,
                [OAuthRequestParameterNames.Iss] = "https://as.example.com"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        //The PAR endpoint above is not loopback and is legitimately dialed; only the token
        //endpoint's own denial is under test here, so the spy is reset immediately before it.
        invocations.Clear();

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleTokenAsync(
            new Dictionary<string, string> { [AuthCodeFlowRoutes.FlowIdField] = flowId },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome,
            "A token_endpoint naming the cloud-metadata literal must be refused, never dialed.");
        Assert.IsEmpty(invocations, "The transport spy must record ZERO invocations when the policy denies the endpoint.");
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>'s SSRF remark names the PAR endpoint alongside the token
    /// endpoint as an equally-discovered, equally-gated target: a
    /// <c>pushed_authorization_request_endpoint</c> naming a loopback IP literal is refused before
    /// the PAR form POST is ever sent.
    /// </summary>
    [TestMethod]
    public async Task HandleParAsyncRefusesLoopbackParEndpointBeforeAnyDial()
    {
        List<Uri> invocations = [];
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            [],
            pushedAuthorizationRequestEndpointOverride: new Uri("https://127.0.0.1/par"),
            sendFormPostInvocations: invocations);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome,
            "A pushed_authorization_request_endpoint naming a loopback IP literal must be refused, never dialed.");
        Assert.IsEmpty(invocations, "The transport spy must record ZERO invocations when the policy denies the endpoint.");
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>'s SSRF remark applies identically to the PAR endpoint naming
    /// the cloud-metadata literal <c>169.254.169.254</c>.
    /// </summary>
    [TestMethod]
    public async Task HandleParAsyncRefusesCloudMetadataParEndpointBeforeAnyDial()
    {
        List<Uri> invocations = [];
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            [],
            pushedAuthorizationRequestEndpointOverride: new Uri("https://169.254.169.254/par"),
            sendFormPostInvocations: invocations);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome,
            "A pushed_authorization_request_endpoint naming the cloud-metadata literal must be refused, never dialed.");
        Assert.IsEmpty(invocations, "The transport spy must record ZERO invocations when the policy denies the endpoint.");
    }


    /// <summary>
    /// <see cref="OAuthClientInfrastructure.OutboundFetchPolicy"/> governs a dial whose
    /// <see cref="ExchangeContext"/> carries no policy of its own: a loopback token endpoint
    /// refuses under the infrastructure's default and dials once the infrastructure names a
    /// loopback-allowing policy — proving the configuration, not just the hard-coded secure
    /// default, is consulted.
    /// </summary>
    [TestMethod]
    public async Task HandleTokenAsyncConsultsInfrastructurePolicyWhenContextCarriesNone()
    {
        Uri loopbackParEndpoint = new("https://127.0.0.1/par");
        OutboundFetchPolicy loopbackAllowing = OutboundFetchPolicy.SecureDefault with { BlockPrivateAndLoopback = false };

        var deniedStore = new Dictionary<string, FlowState>();
        (OAuthClientInfrastructure deniedInfrastructure, ClientRegistration deniedRegistration) = CreateInfrastructureAndRegistration(
            deniedStore,
            pushedAuthorizationRequestEndpointOverride: loopbackParEndpoint);

        AuthCodeFlowEndpointResult deniedResult = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(), DefaultRedirectUri, deniedInfrastructure, deniedRegistration, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, deniedResult.Outcome,
            "The infrastructure's default (SecureDefault) must refuse the loopback PAR endpoint.");

        var allowedStore = new Dictionary<string, FlowState>();
        (OAuthClientInfrastructure allowedInfrastructure, ClientRegistration allowedRegistration) = CreateInfrastructureAndRegistration(
            allowedStore,
            parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:cfg-loopback", 60),
            pushedAuthorizationRequestEndpointOverride: loopbackParEndpoint,
            outboundFetchPolicy: loopbackAllowing);

        AuthCodeFlowEndpointResult allowedResult = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(), DefaultRedirectUri, allowedInfrastructure, allowedRegistration, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, allowedResult.Outcome,
            "Naming a loopback-allowing policy on the infrastructure must let the same loopback endpoint dial.");
    }


    /// <summary>
    /// A policy set explicitly on the call's <see cref="ExchangeContext"/> overrides
    /// <see cref="OAuthClientInfrastructure.OutboundFetchPolicy"/>: an infrastructure configured to
    /// allow loopback still refuses when the per-call context names the stricter secure default.
    /// </summary>
    [TestMethod]
    public async Task HandleParAsyncContextPolicyOverridesInfrastructurePolicy()
    {
        Uri loopbackParEndpoint = new("https://127.0.0.1/par");
        OutboundFetchPolicy loopbackAllowing = OutboundFetchPolicy.SecureDefault with { BlockPrivateAndLoopback = false };

        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            [],
            pushedAuthorizationRequestEndpointOverride: loopbackParEndpoint,
            outboundFetchPolicy: loopbackAllowing);

        ExchangeContext strictContext = [];
        strictContext.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(), DefaultRedirectUri, infrastructure, registration, strictContext, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, result.Outcome,
            "The context's explicit SecureDefault must override the infrastructure's loopback-allowing configuration.");
    }


    [TestMethod]
    public async Task HandleRevocationAsyncReturnsBadRequestWhenEndpointMissing()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            [],
            useDefaultRevocationEndpoint: false);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleRevocationAsync(
            new Dictionary<string, string> { ["token"] = "some-token" },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, result.Outcome);
        Assert.AreEqual("unsupported_token_type", result.ErrorCode);
    }


    [TestMethod]
    public async Task HandleRevocationAsyncReturnsOkWhenEndpointPresent()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            []);

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.HandleRevocationAsync(
            new Dictionary<string, string> { ["token"] = "some-token" },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
    }


    [TestMethod]
    public async Task RefreshAsyncReturnsOkWithNewTokens()
    {
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(
            [],
            tokenResponse: OAuthJsonResponseFixtures.BuildTokenJson("at.new", "Bearer", 3600, "rt.new"));

        AuthCodeFlowEndpointResult result = await AuthCodeFlowHandlers.RefreshAsync(
            new RefreshTokenRequest
            {
                ClientId = "test-client",
                RefreshToken = "rt.old"
            },
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, result.Outcome);
        Assert.IsNotNull(result.Body);
        Assert.AreEqual("at.new", result.Body["access_token"]);
        Assert.AreEqual("rt.new", result.Body["refresh_token"]);
    }


    [TestMethod]
    public async Task PkceVerifierIsBase64UrlEncodedWithCorrectLength()
    {
        var store = new Dictionary<string, FlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store,
            parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:pkce1", 60));

        _ = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        ParCompletedState state = Assert.IsInstanceOfType<ParCompletedState>(
            TestDictionaryHelpers.GetFirstValue(store));

        Assert.AreEqual(43, state.Pkce.EncodedVerifier.Length,
            "PKCE verifier must be exactly 43 Base64url characters for 32 bytes.");
        Assert.AreEqual(43, state.Pkce.EncodedChallenge.Length,
            "PKCE S256 challenge must be exactly 43 Base64url characters.");
        Assert.IsLessThan(0, state.Pkce.EncodedVerifier.AsSpan().IndexOf('+'),
            "Verifier must not contain + character.");
        Assert.IsLessThan(0, state.Pkce.EncodedVerifier.AsSpan().IndexOf('/'),
            "Verifier must not contain / character.");
        Assert.IsLessThan(0, state.Pkce.EncodedVerifier.AsSpan().IndexOf('='),
            "Verifier must not contain padding.");
        Assert.IsLessThan(0, state.Pkce.EncodedChallenge.AsSpan().IndexOf('+'));
        Assert.IsLessThan(0, state.Pkce.EncodedChallenge.AsSpan().IndexOf('/'));
        Assert.IsLessThan(0, state.Pkce.EncodedChallenge.AsSpan().IndexOf('='));
    }


    [TestMethod]
    public async Task EachParRequestProducesUniqueVerifierAndChallenge()
    {
        var store1 = new Dictionary<string, FlowState>();
        var store2 = new Dictionary<string, FlowState>();

        (OAuthClientInfrastructure infrastructure1, ClientRegistration registration1) = CreateInfrastructureAndRegistration(store1,
            parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:u1", 60));
        (OAuthClientInfrastructure infrastructure2, ClientRegistration registration2) = CreateInfrastructureAndRegistration(store2,
            parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:u2", 60));

        _ = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(), DefaultRedirectUri, infrastructure1, registration1,
            TestContext.CancellationToken).ConfigureAwait(false);
        _ = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(), DefaultRedirectUri, infrastructure2, registration2,
            TestContext.CancellationToken).ConfigureAwait(false);

        ParCompletedState state1 = Assert.IsInstanceOfType<ParCompletedState>(
            TestDictionaryHelpers.GetFirstValue(store1));
        ParCompletedState state2 = Assert.IsInstanceOfType<ParCompletedState>(
            TestDictionaryHelpers.GetFirstValue(store2));

        Assert.AreNotEqual(state1.Pkce.EncodedVerifier, state2.Pkce.EncodedVerifier,
            "Each PAR request must produce a unique PKCE verifier.");
        Assert.AreNotEqual(state1.Pkce.EncodedChallenge, state2.Pkce.EncodedChallenge,
            "Different verifiers must produce different challenges.");
    }


    [TestMethod]
    public async Task ParResponsePopulatesExpiresAtFromExpiresIn()
    {
        const int expiresIn = 90;
        var store = new Dictionary<string, FlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store,
            parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:exp", expiresIn));

        DateTimeOffset before = TimeProvider.GetUtcNow();

        _ = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        ParCompletedState state = Assert.IsInstanceOfType<ParCompletedState>(
            TestDictionaryHelpers.GetFirstValue(store));

        Assert.AreEqual(expiresIn, state.Par.ExpiresIn,
            "PAR expires_in must be stored from the response.");
        Assert.IsGreaterThan(before, state.ExpiresAt,
            "ExpiresAt must be in the future relative to the PAR request.");
        Assert.AreEqual(before.AddSeconds(expiresIn), state.ExpiresAt,
            "ExpiresAt must be exactly now + expires_in seconds.");
    }


    [TestMethod]
    public async Task EntropyEventsAreEmittedDuringPkceGeneration()
    {
        var observer = new TestObserver<CryptoEvent>();
        using IDisposable subscription = CryptographicKeyEvents.Events.Subscribe(observer);

        var store = new Dictionary<string, FlowState>();
        (OAuthClientInfrastructure infrastructure, ClientRegistration registration) = CreateInfrastructureAndRegistration(store,
            parResponse: OAuthJsonResponseFixtures.BuildParJson("urn:ietf:params:oauth:request_uri:obs", 60));

        _ = await AuthCodeFlowHandlers.HandleParAsync(
            new Dictionary<string, string>(),
            DefaultRedirectUri,
            infrastructure,
            registration,
            TestContext.CancellationToken).ConfigureAwait(false);

        System.Collections.Generic.List<EntropyConsumedEvent> entropyEvents =
            observer.Received.OfType<EntropyConsumedEvent>().ToList();

        Assert.IsGreaterThanOrEqualTo(1, entropyEvents.Count,
            "At least one EntropyConsumedEvent must be emitted during PKCE generation.");
        Assert.AreEqual(32, entropyEvents[0].ByteCount,
            "PKCE verifier must consume exactly 32 bytes of entropy.");
    }


    private (OAuthClientInfrastructure Infrastructure, ClientRegistration Registration) CreateInfrastructureAndRegistration(
        Dictionary<string, FlowState> store,
        string? parResponse = null,
        string? tokenResponse = null,
        Exception? httpException = null,
        Uri? revocationEndpoint = null,
        bool useDefaultRevocationEndpoint = true,
        AuthorizationServerMetadataResolutionOutcome? metadataResolutionOutcome = null,
        string? metadataResolutionDefect = null,
        Uri? pushedAuthorizationRequestEndpointOverride = null,
        Uri? tokenEndpointOverride = null,
        List<Uri>? sendFormPostInvocations = null,
        OutboundFetchPolicy? outboundFetchPolicy = null)
    {
        Uri? resolvedRevocationEndpoint = revocationEndpoint
            ?? (useDefaultRevocationEndpoint ? new Uri("https://as.example.com/revoke") : null);

        Uri issuerUri = new("https://as.example.com");

        AuthorizationServerMetadata metadata = new()
        {
            Issuer = issuerUri,
            PushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpointOverride ?? new Uri("https://as.example.com/par"),
            AuthorizationEndpoint = new Uri("https://as.example.com/authorize"),
            TokenEndpoint = tokenEndpointOverride ?? new Uri("https://as.example.com/token"),
            RevocationEndpoint = resolvedRevocationEndpoint
        };

        OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
            sendFormPostAsync: (endpoint, _, _, _, __) =>
            {
                sendFormPostInvocations?.Add(endpoint);

                if(httpException is not null)
                {
                    throw httpException;
                }
                bool isTokenEndpoint = endpoint.AbsolutePath.EndsWith("/token", StringComparison.Ordinal)
                                    || endpoint.AbsolutePath.EndsWith("/revoke", StringComparison.Ordinal);
                string body = isTokenEndpoint
                    ? tokenResponse ?? string.Empty
                    : parResponse ?? string.Empty;
                return ValueTask.FromResult(new HttpResponseData { Body = body, StatusCode = 200 });
            },
            saveStateAsync: (state, _, _) =>
            {
                store[state.FlowId] = state;
                return ValueTask.CompletedTask;
            },
            loadStateAsync: (flowId, _, _) =>
                ValueTask.FromResult(store.GetValueOrDefault(flowId)),
            loadStateByRequestUriAsync: (requestUri, _, _) =>
            {
                FlowState? found = null;
                foreach(FlowState s in store.Values)
                {
                    if(s is ParCompletedState pc
                        && string.Equals(pc.Par.RequestUri.ToString(), requestUri, StringComparison.Ordinal))
                    {
                        found = s;
                        break;
                    }
                }
                return ValueTask.FromResult(found);
            },
            parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
            parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
            parseRegistrationResponseAsync: (body, ct) =>
                throw new NotImplementedException("AuthCodeFlowTests does not exercise dynamic registration."),
            resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
                ValueTask.FromResult(metadataResolutionOutcome is AuthorizationServerMetadataResolutionOutcome outcome
                    ? new AuthorizationServerMetadataResolution { Outcome = outcome, Defect = metadataResolutionDefect }
                    : new AuthorizationServerMetadataResolution
                    {
                        Outcome = AuthorizationServerMetadataResolutionOutcome.Resolved,
                        Metadata = metadata
                    }),
            resolveCallbackValidator: (registration, timeProvider) =>
                new ClaimIssuer<ValidationContext>(
                    "test-callback-validator",
                    ValidationProfiles.CallbackHaip10Rules(),
                    timeProvider),
            base64UrlEncoder: TestSetup.Base64UrlEncoder,
            memoryPool: BaseMemoryPool.Shared,
            timeProvider: TimeProvider,
            fillEntropy: ClientEntropy,
            generateIdentifierAsync: DefaultIdentifierGenerator.For(TimeProvider, ClientEntropy, BaseMemoryPool.Shared),
            outboundFetchPolicy: outboundFetchPolicy);

        ClientRegistration registration = new()
        {
            ClientId = new ClientId("test-client"),
            AuthorizationServerIssuer = issuerUri,
            RedirectUris = [DefaultRedirectUri],
            AuthenticationMethod = ClientAuthenticationMethod.None,
            Profile = PolicyProfile.Haip10
        };

        return (infrastructure, registration);
    }

    private static string GetSingleFlowId(Dictionary<string, FlowState> store)
    {
        Assert.IsNotEmpty(store, "Store must contain at least one flow state.");
        return TestDictionaryHelpers.GetFirstKey(store);
    }
}

internal static class TestDictionaryHelpers
{
    public static TValue GetFirstValue<TKey, TValue>(Dictionary<TKey, TValue> dict)
        where TKey : notnull
    {
        foreach(TValue value in dict.Values)
        {
            return value;
        }

        throw new InvalidOperationException("Dictionary is empty.");
    }

    public static TKey GetFirstKey<TKey, TValue>(Dictionary<TKey, TValue> dict)
        where TKey : notnull
    {
        foreach(TKey key in dict.Keys)
        {
            return key;
        }

        throw new InvalidOperationException("Dictionary is empty.");
    }
}
