using System.Text;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.Core.StatusLists;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.StatusList;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>The guarded transport decision survives every metadata and status-list resolution.</summary>
[TestClass]
internal sealed class TransportFailureResolutionTests
{
    /// <summary>The runner's cancellation context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The issuer whose metadata is requested.</summary>
    private static Uri Issuer { get; } = new("https://issuer.example");

    /// <summary>The location used for client metadata, keys and status lists.</summary>
    private static Uri Target { get; } = new("https://issuer.example/metadata");

    /// <summary>The pipelines that must inherit the single guarded-fetch decision.</summary>
    private static IEnumerable<string> Resolvers =>
        ["GuardedFetch", "AuthorizationServer", "ClientId", "JwksUri", "JwtVcIssuer", "StatusListFetch", "StatusListResolution"];

    /// <summary>Single-parameter rows for each pipeline.</summary>
    public static IEnumerable<TestDataRow<string>> ResolverCases =>
        Resolvers.Select(resolver => new TestDataRow<string>(resolver));

    /// <summary>Bare and wrapped cancellation, synchronously thrown and asynchronously faulted.</summary>
    public static IEnumerable<(string Resolver, string Shape, bool FaultedTask)> CancellationCases
    {
        get
        {
            foreach(string resolver in Resolvers)
            {
                foreach(string shape in new[] { "OperationCanceled", "TaskCanceled", "Wrapped", "Aggregated" })
                {
                    yield return (resolver, shape, false);
                    yield return (resolver, shape, true);
                }
            }
        }
    }


    /// <summary>A transport cancellation with a live caller token is unreachable with a timeout kind.</summary>
    [TestMethod]
    [DynamicData(nameof(CancellationCases))]
    public async Task TransportCancellationWithLiveCallerIsUnreachableTimeout(string resolver, string shape, bool faultedTask)
    {
        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        Exception exception = Cancellation(shape, caller.Token);

        //Receives the caller's live token, then fails with its own cancellation, thrown or as a faulted task.
        ValueTask<OutboundTransportResult> transport(
            OutboundRequest request, ExchangeContext context, OutboundResponseReaderDelegate readResponse, CancellationToken token)
        {
            Assert.AreEqual(caller.Token, token);
            return faultedTask ? ValueTask.FromException<OutboundTransportResult>(exception) : throw exception;
        }

        object result = await ResolveAsync(resolver, transport, caller.Token).ConfigureAwait(false);

        Assert.IsFalse(caller.IsCancellationRequested);
        Assert.AreEqual(typeof(TimeoutException), UnreachableKind(result));
    }


    /// <summary>A caller cancelling during transport work still receives its own cancellation token.</summary>
    [TestMethod]
    [DynamicData(nameof(CancellationCases))]
    public async Task CallerCancellationDuringTransportPropagates(string resolver, string shape, bool faultedTask)
    {
        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        Task cancellation = Task.CompletedTask;

        //Requests the caller's cancellation while it runs, then fails with it, thrown or as a faulted task. The request
        //marks the token cancelled at once, so the transport stays synchronous; its completion is awaited after the call.
        ValueTask<OutboundTransportResult> transport(
            OutboundRequest request, ExchangeContext context, OutboundResponseReaderDelegate readResponse, CancellationToken token)
        {
            cancellation = caller.CancelAsync();
            Exception exception = Cancellation(shape, token);
            return faultedTask ? ValueTask.FromException<OutboundTransportResult>(exception) : throw exception;
        }

        OperationCanceledException caught = await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await ResolveAsync(resolver, transport, caller.Token).ConfigureAwait(false)).ConfigureAwait(false);
        await cancellation.ConfigureAwait(false);

        Assert.AreEqual(caller.Token, caught.CancellationToken);
    }


    /// <summary>Pre-cancelled calls stop before invoking even a transport that ignores cancellation.</summary>
    [TestMethod]
    [DynamicData(nameof(ResolverCases))]
    public async Task PreCancelledCallerDoesNotReachTransport(string resolver)
    {
        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        await caller.CancelAsync().ConfigureAwait(false);
        int calls = 0;

        //Counts every call that reaches it; a pre-cancelled caller must stop before it.
        ValueTask<OutboundTransportResult> transport(
            OutboundRequest request, ExchangeContext context, OutboundResponseReaderDelegate readResponse, CancellationToken token)
        {
            calls++;
            throw new IOException("The transport must not be reached.");
        }

        OperationCanceledException caught = await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await ResolveAsync(resolver, transport, caller.Token).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(caller.Token, caught.CancellationToken);
        Assert.AreEqual(0, calls);
    }


    /// <summary>An ordinary transport failure retains its kind, without being mistaken for size or timeout.</summary>
    [TestMethod]
    [DynamicData(nameof(ResolverCases))]
    public async Task OtherTransportFailureRetainsItsKind(string resolver)
    {
        object result = await ResolveAsync(resolver,
            static (_, _, _, _) => throw new IOException("Private transport diagnostics."),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(typeof(IOException), UnreachableKind(result));
    }


    /// <summary>The optional logo's timeout is nonfatal to metadata but remains a typed timeout.</summary>
    [TestMethod]
    public async Task LogoTransportTimeoutRetainsKindOnResolvedMetadata()
    {
        ClientIdMetadataResolution result = await ClientIdMetadataDocuments.ResolveAsync(
            Target, new ExchangeContext(), LogoTransport(static (_, _, _, _) => throw new TaskCanceledException()),
            new ClientIdMetadataDocumentResolverOptions { PrefetchLogo = true }, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(result.IsResolved);
        Assert.IsNull(result.PrefetchedLogo);
        Assert.AreEqual(typeof(TimeoutException), result.LogoFailureKind);
    }


    /// <summary>A caller cancelling during optional logo retrieval still cancels the resolution.</summary>
    [TestMethod]
    public async Task CallerCancellationDuringLogoFetchPropagates()
    {
        using CancellationTokenSource caller = CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
        OutboundTransportDelegate transport = LogoTransport(async (_, _, _, token) =>
        {
            await caller.CancelAsync().ConfigureAwait(false);
            throw new TaskCanceledException("Caller cancelled.", null, token);
        });

        OperationCanceledException caught = await Assert.ThrowsExactlyAsync<OperationCanceledException>(
            async () => await ClientIdMetadataDocuments.ResolveAsync(
                Target, new ExchangeContext(), transport, new ClientIdMetadataDocumentResolverOptions { PrefetchLogo = true },
                caller.Token).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.AreEqual(caller.Token, caught.CancellationToken);
    }


    /// <summary>Resolution retains the reader's exact size evidence and never invokes token verification.</summary>
    [TestMethod]
    [DataRow(false, false)]
    [DataRow(false, true)]
    [DataRow(true, false)]
    [DataRow(true, true)]
    public async Task OversizedStatusListResolutionRetainsLimitAndLength(bool declared, bool useHttpClient)
    {
        using StreamingOutboundTransport transport = new(new byte[4096], declared ? 4096 : null, useHttpClient);
        ResolveVerifiedStatusListTokenDelegate resolve = StatusResolver(transport.Delegate);

        StatusListTokenResolutionFailure failure = Assert.IsInstanceOfType<StatusListTokenResolutionFailure>(
            await resolve(StatusContext(), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(StatusListTokenResolutionFailureKind.TooLarge, failure.Kind);
        Assert.AreEqual(new OutboundResponseTooLarge(64, declared ? 4096 : 65,
            declared ? OutboundResponseLengthKind.Declared : OutboundResponseLengthKind.Observed), failure.TooLarge);
        Assert.AreEqual(Target, failure.RequestedUri);
        Assert.AreEqual(Target, failure.FinalUri);
        Assert.AreEqual(declared ? 0 : 65, transport.BytesRead);
        Assert.IsTrue(transport.IsDisposed);
        if(!useHttpClient)
        {
            Assert.IsNotNull(transport.Returned);
            Assert.AreSame(transport.Returned.TooLarge, failure.TooLarge);
        }
    }


    /// <summary>A refused redirect remains a typed resolution failure with its fetch provenance.</summary>
    [TestMethod]
    [DataRow(RedirectMode.None)]
    [DataRow(RedirectMode.SameOrigin)]
    public async Task RefusedStatusListRedirectRetainsResolutionProvenance(RedirectMode redirects)
    {
        ExchangeContext context = [];
        context.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault with { Redirects = redirects, MaxRedirects = 0 });
        ScriptedOutboundTransport transport = new(new()
        {
            [Target.OriginalString] = ScriptedOutboundResponse.RedirectTo(302, "https://issuer.example/moved")
        });
        ResolveVerifiedStatusListTokenDelegate resolve = StatusListTokenResolvers.BuildResolving(
            transport.Delegate, context,
            static (_, _) => throw new InvalidOperationException("A refused redirect must not resolve a key."),
            TestSetup.Base64UrlDecoder, JwtPartJson.Default, BaseMemoryPool.Shared, TimeProvider.System, 64);

        StatusListTokenResolutionFailure failure = Assert.IsInstanceOfType<StatusListTokenResolutionFailure>(
            await resolve(StatusContext(), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(StatusListTokenResolutionFailureKind.RedirectNotFollowed, failure.Kind);
        Assert.AreEqual(Target, failure.RequestedUri);
        Assert.AreEqual(Target, failure.FinalUri);
        Assert.AreEqual(0, failure.RedirectCount);
        Assert.IsNotNull(failure.DenyReason);
        Assert.IsNull(failure.FailureKind);
        Assert.IsNull(failure.TooLarge);
        Assert.HasCount(1, transport.Calls);
    }


    /// <summary>The status gate keeps a typed transport failure instead of throwing it again.</summary>
    [TestMethod]
    public async Task StatusGateReturnsTimeoutEvidenceWithoutAStatus()
    {
        ResolveVerifiedStatusListTokenDelegate resolve = StatusResolver(
            static (_, _, _, _) => throw new TaskCanceledException("Transport timeout."));

        Result<CredentialStatusOutcome, StatusListTokenResolutionFailure> result = await CredentialStatusGate.CheckAsync(
            StatusContext(), resolve, TimeProvider.System.GetUtcNow(), null, null, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsFalse(result.IsSuccess);
        Assert.IsNull(result.Value);
        Assert.IsNotNull(result.Error);
        Assert.AreEqual(StatusListTokenResolutionFailureKind.Unreachable, result.Error.Kind);
        Assert.AreEqual(typeof(TimeoutException), result.Error.FailureKind);
    }


    /// <summary>Builds each cancellation shape without relying on a timer or a network.</summary>
    private static Exception Cancellation(string shape, CancellationToken token) => shape switch
    {
        "OperationCanceled" => new OperationCanceledException("Transport timeout.", token),
        "TaskCanceled" => new TaskCanceledException("Transport timeout.", null, token),
        "Wrapped" => new IOException("Transport wrapper.", new OperationCanceledException(token)),
        "Aggregated" => new AggregateException(new IOException("First failure."), new TaskCanceledException()),
        _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, "Unknown cancellation shape.")
    };


    /// <summary>Reads the kind only from each pipeline's typed unreachable outcome.</summary>
    private static Type? UnreachableKind(object result) => result switch
    {
        OutboundFetchResult { Outcome: OutboundFetchOutcome.Unreachable } value => value.FailureKind,
        AuthorizationServerMetadataUnreachable value => value.FailureKind,
        ClientIdMetadataResolution { Outcome: ClientIdMetadataResolutionOutcome.Unreachable } value => value.FailureKind,
        JwksUriResolution { Outcome: JwksUriResolutionOutcome.Unreachable } value => value.FailureKind,
        JwtVcIssuerMetadataResolution { Outcome: JwtVcIssuerMetadataResolutionOutcome.Unreachable } value => value.FailureKind,
        StatusListTokenFetchResult { Outcome: StatusListTokenFetchOutcome.TransportFailed } value => value.FailureKind,
        StatusListTokenResolutionFailure { Kind: StatusListTokenResolutionFailureKind.Unreachable } value => value.FailureKind,
        _ => null
    };


    /// <summary>Invokes the actual pipeline named by a test row.</summary>
    private static async ValueTask<object> ResolveAsync(
        string resolver, OutboundTransportDelegate transport, CancellationToken cancellationToken)
    {
        ExchangeContext context = [];
        return resolver switch
        {
            "GuardedFetch" => await OutboundFetch.FetchAsync(
                new OutboundRequest { Target = Target, Method = WellKnownHttpMethods.Get }, context, transport,
                cancellationToken).ConfigureAwait(false),
            "AuthorizationServer" => await AuthorizationServerMetadataDocuments.ResolveAsync(
                Issuer, WellKnownPaths.OAuthAuthorizationServer, context, transport, AuthorizationServerMetadataJson.Parse,
                new AuthorizationServerMetadataResolverOptions(), cancellationToken).ConfigureAwait(false),
            "ClientId" => await ClientIdMetadataDocuments.ResolveAsync(
                Target, context, transport, new ClientIdMetadataDocumentResolverOptions(), cancellationToken).ConfigureAwait(false),
            "JwksUri" => await JwksUriResolver.ResolveAsync(
                Target, context, transport, new JwksUriResolverOptions(), cancellationToken).ConfigureAwait(false),
            "JwtVcIssuer" => await JwtVcIssuerMetadataDocuments.ResolveAsync(
                Issuer, context, transport, new JwtVcIssuerMetadataDocumentResolverOptions(), cancellationToken).ConfigureAwait(false),
            "StatusListFetch" => await StatusListTokenFetch.FetchAsync(
                Target, StatusListTokenFormat.Jwt, context, transport, 64, cancellationToken).ConfigureAwait(false),
            "StatusListResolution" => Assert.IsInstanceOfType<StatusListTokenResolution>(
                await StatusResolver(transport)(StatusContext(), cancellationToken).ConfigureAwait(false)),
            _ => throw new ArgumentOutOfRangeException(nameof(resolver), resolver, "Unknown resolver.")
        };
    }


    /// <summary>Builds a resolution whose verification seams must remain untouched on fetch failure.</summary>
    private static ResolveVerifiedStatusListTokenDelegate StatusResolver(OutboundTransportDelegate transport) =>
        StatusListTokenResolvers.BuildResolving(
            transport, new ExchangeContext(),
            static (_, _) => throw new InvalidOperationException("A failed fetch must not resolve a key."),
            TestSetup.Base64UrlDecoder, JwtPartJson.Default, BaseMemoryPool.Shared, TimeProvider.System, 64);


    /// <summary>Serves a valid client document before driving the supplied transport for its logo.</summary>
    private static OutboundTransportDelegate LogoTransport(OutboundTransportDelegate logoTransport) =>
        async (request, context, readResponse, cancellationToken) =>
        {
            if(request.Target != Target)
            {
                return await logoTransport(request, context, readResponse, cancellationToken).ConfigureAwait(false);
            }

            byte[] document = Encoding.UTF8.GetBytes(
                """{"client_id":"https://issuer.example/metadata","logo_uri":"https://issuer.example/logo"}""");
            using MemoryStream body = new(document, writable: false);
            return await readResponse(200, HttpHeaderSet.FromPairs(
                (WellKnownHttpHeaderNames.ContentType, WellKnownMediaTypes.Application.Json)), body, cancellationToken).ConfigureAwait(false);
        };


    /// <summary>The status reference passed to the real resolver.</summary>
    private static StatusListResolutionContext StatusContext() => StatusListFixtures.ContextFor(0, Target.OriginalString);
}
