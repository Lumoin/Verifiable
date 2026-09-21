using Microsoft.Extensions.Time.Testing;
using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Verifiable.Core;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.Server.States;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The test host's per-grant ordering gate
/// (<see cref="HostedAuthorizationServer.EnterGrantOrderGateAsync"/>): the application-side
/// coordination <see cref="LoadGrantFlowStatesDelegate"/>'s own
/// documentation describes as the library's expectation of its caller, demonstrated here as the
/// reference for an application's own ordering. Every test crosses the real loopback socket, exactly
/// as <see cref="AuthCodeParPkceRealWireFlowTests"/> does.
/// </summary>
[TestClass]
internal sealed class HostedAuthorizationServerOrderingTests
{
    /// <summary>MSTest's per-test context, supplying every socket call's cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the client share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>The client identifier registered with the host.</summary>
    private const string ClientId = "https://client.example.com";

    /// <summary>The authenticated end-user identifier the authorize step asserts.</summary>
    private const string SubjectId = "subject-hosted-ordering-01";

    /// <summary><see cref="ClientId"/> as a <see cref="Uri"/>.</summary>
    private static Uri ClientBaseUri { get; } = new(ClientId);

    /// <summary>The client's registered redirect URI.</summary>
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    /// <summary>The capabilities every test in this class registers its client with.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> Capabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OAuthRefreshToken,
            WellKnownCapabilityIdentifiers.OAuthTokenRevocation);


    /// <summary>What <see cref="SetupOneRotationAsync"/> hands every test in this class.</summary>
    /// <param name="Host">The owning shell; the caller disposes it (<see langword="await using"/>).</param>
    /// <param name="Material">The registered client's key material; the caller disposes it (<see langword="using"/>), after <see cref="Host"/>.</param>
    /// <param name="Hosted">The single hosted authorization server the shell started.</param>
    /// <param name="Record">The server-side registration, reusable for a second client drive on the SAME host.</param>
    /// <param name="Segment">The tenant path segment routing every raw wire push.</param>
    /// <param name="OldestRefreshToken">The retired (once-rotated-out) refresh token of the one grant this creates.</param>
    /// <param name="CurrentRefreshToken">The live refresh token of the one grant this creates.</param>
    /// <param name="CurrentFlowId">The live refresh record's own flow id.</param>
    /// <param name="GrantFlowId">The grant key shared by every record of this grant.</param>
    /// <param name="ExpectedAccessTokenJtis">
    /// Every access-token <c>jti</c> the fixture's own two token responses (the code exchange's, the
    /// rotation's) minted, read from those RESPONSES directly rather than reconstructed from the
    /// host's stores.
    /// </param>
    private sealed record OneRotationFixture(
        TestHostShell Host,
        VerifierKeyMaterial Material,
        HostedAuthorizationServer Hosted,
        ClientRecord Record,
        string Segment,
        string OldestRefreshToken,
        string CurrentRefreshToken,
        string CurrentFlowId,
        string GrantFlowId,
        ImmutableHashSet<string> ExpectedAccessTokenJtis);


    /// <summary>
    /// One registered client, one code-grant redemption, and one legitimate rotation: the shape
    /// every gate test and ordered race in this class starts from. Drains
    /// <see cref="HostedAuthorizationServer.GrantOrderObservations"/> as its last act, so the
    /// returned fixture hands every caller an EMPTY observation stream to build its own assertions
    /// from.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the host and its key material transfers to the returned fixture, which every caller disposes (await using / using) at its own method's end.")]
    private async Task<OneRotationFixture> SetupOneRotationAsync()
    {
        TestHostShell host = new(TimeProvider);
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        string oldestRefreshToken = (string)drive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];
        string firstAccessTokenJti = JwtPayloadReader.ReadJti(
            (string)drive.TokenResult.Body![OAuthRequestParameterNames.AccessToken])!;

        (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
            host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, StatusCode, Body);
        string currentRefreshToken;
        string rotationAccessTokenJti;
        using(JsonDocument rotationDoc = JsonDocument.Parse(Body))
        {
            currentRefreshToken = rotationDoc.RootElement.GetProperty(
                OAuthRequestParameterNames.RefreshToken).GetString()!;
            rotationAccessTokenJti = JwtPayloadReader.ReadJti(
                rotationDoc.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!)!;
        }

        string currentFlowId = hosted.RefreshTokenIndex[currentRefreshToken];
        string grantFlowId = hosted.ResolveGrantKey(currentFlowId);

        while(hosted.GrantOrderObservations.Reader.TryRead(out _))
        {
        }

        return new OneRotationFixture(
            host, material, hosted, material.Registration, segment, oldestRefreshToken, currentRefreshToken, currentFlowId, grantFlowId,
            ImmutableHashSet.Create(StringComparer.Ordinal, firstAccessTokenJti, rotationAccessTokenJti));
    }


    /// <summary>What <see cref="SetupOneCodeRedemptionAsync"/> hands every test racing a replayed code against a refresh.</summary>
    /// <param name="Host">The owning shell; the caller disposes it (<see langword="await using"/>).</param>
    /// <param name="Material">The registered client's key material; the caller disposes it (<see langword="using"/>), after <see cref="Host"/>.</param>
    /// <param name="Hosted">The single hosted authorization server the shell started.</param>
    /// <param name="Segment">The tenant path segment routing every raw wire push.</param>
    /// <param name="Code">The authorization code already redeemed once; still valid to replay.</param>
    /// <param name="PkceVerifier">The PKCE verifier the original authorize request bound to <see cref="Code"/>.</param>
    /// <param name="RefreshToken">The refresh token the code redemption minted, not yet presented again.</param>
    /// <param name="RefreshFlowId">The refresh record's own flow id.</param>
    /// <param name="GrantFlowId">The grant key shared by every record of this grant — the code's own flow id.</param>
    /// <param name="ExpectedAccessTokenJtis">
    /// Every access-token <c>jti</c> the fixture's own code exchange minted, read from that RESPONSE
    /// directly rather than reconstructed from the host's stores.
    /// </param>
    private sealed record OneCodeRedemptionFixture(
        TestHostShell Host,
        VerifierKeyMaterial Material,
        HostedAuthorizationServer Hosted,
        string Segment,
        string Code,
        string PkceVerifier,
        string RefreshToken,
        string RefreshFlowId,
        string GrantFlowId,
        ImmutableHashSet<string> ExpectedAccessTokenJtis);


    /// <summary>
    /// One registered client and one code-grant redemption, its code still valid to replay and its
    /// minted refresh token not yet presented again: the shape the second ordered-race pair starts
    /// from. Drains <see cref="HostedAuthorizationServer.GrantOrderObservations"/> as its last act,
    /// so the returned fixture hands every caller an EMPTY observation stream to build its own
    /// assertions from.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the host and its key material transfers to the returned fixture, which every caller disposes (await using / using) at its own method's end.")]
    private async Task<OneCodeRedemptionFixture> SetupOneCodeRedemptionAsync()
    {
        TestHostShell host = new(TimeProvider);
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, profile: PolicyProfile.Rfc6749WithPkce, capabilities: Capabilities).ConfigureAwait(false);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                profile: PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;

        using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
        (string flowId, string _) = await AuthCodeFlowDriver.DriveParAuthorizeAndCallbackAsync(
            hosted, client, registration, clientFlowStore, segment, RedirectUri, SubjectId, browserClient,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
        AuthorizationCodeReceivedState codeState = (AuthorizationCodeReceivedState)clientFlowStore[flowId];

        AuthCodeFlowEndpointResult exchange = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, exchange.Outcome,
            $"The code redemption must succeed. ErrorCode={exchange.ErrorCode}");
        string refreshToken = (string)exchange.Body![OAuthRequestParameterNames.RefreshToken];
        string accessTokenJti = JwtPayloadReader.ReadJti((string)exchange.Body![OAuthRequestParameterNames.AccessToken])!;

        string refreshFlowId = hosted.RefreshTokenIndex[refreshToken];
        string grantFlowId = hosted.ResolveGrantKey(refreshFlowId);

        while(hosted.GrantOrderObservations.Reader.TryRead(out _))
        {
        }

        return new OneCodeRedemptionFixture(
            host, material, hosted, segment, codeState.Code, codeState.Pkce.EncodedVerifier, refreshToken, refreshFlowId, grantFlowId,
            ImmutableHashSet.Create(StringComparer.Ordinal, accessTokenJti));
    }


    /// <summary>
    /// Reads <paramref name="hosted"/>'s NEXT gate observation — nothing filtered, nothing discarded
    /// — and asserts it is the expected <paramref name="kind"/> for the expected
    /// <paramref name="grantKey"/> (the failure message names both the expected and the actual pair).
    /// With a fixture's drain and the gate's own exclusivity, the stream of observations for one
    /// grant is deterministic, so a caller asserts every one of them this way rather than skip past
    /// ones it does not expect.
    /// </summary>
    private static async Task<GrantOrderObservation> ExpectObservationAsync(
        HostedAuthorizationServer hosted, GrantOrderEventKind kind, string grantKey, CancellationToken cancellationToken)
    {
        GrantOrderObservation observation = await hosted.GrantOrderObservations.Reader
            .ReadAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(kind, observation.Kind,
            $"Expected {kind} for grant key '{grantKey}'; observed {observation.Kind} for grant key '{observation.GrantKey}'.");
        Assert.AreEqual(grantKey, observation.GrantKey,
            $"Expected {kind} for grant key '{grantKey}'; observed {observation.Kind} for grant key '{observation.GrantKey}'.");

        return observation;
    }


    /// <summary>
    /// The gate itself: two refresh requests of ONE grant. The first is held inside the library
    /// (a wrapped <see cref="ServerIntegration.LoadFlowStateAsync"/>, as the race tests hold one);
    /// while it is held, the second is observed ENQUEUED and its own wrapped load has NOT been
    /// called; the first is released; the second is then ADMITTED — the admission order, read from
    /// the gate's own observations, matches the order the two requests were sent in, and matches the
    /// two responses (the presentation that runs first rotates; the one admitted after it, against
    /// the retired record, is refused as reuse). <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.4">RFC
    /// 6749 §10.4</see>: this FIFO admission is the application's own coordination, never an OAuth
    /// wire mechanism.
    /// </summary>
    [TestMethod]
    public async Task TwoRequestsOfOneGrantAreAdmittedInFifoOrderWhileTheFirstIsHeldAsync()
    {
        OneRotationFixture fixture = await SetupOneRotationAsync().ConfigureAwait(false);
        await using(fixture.Host)
        using(fixture.Material)
        {
            (TestHostShell host, _, HostedAuthorizationServer hosted, _, string segment,
                _, string currentRefreshToken, string currentFlowId, string grantFlowId, _) = fixture;

            int secondLoadCount = 0;
            TaskCompletionSource firstEnteredLibrary = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource releaseFirst = new(TaskCreationOptions.RunContinuationsAsynchronously);
            LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
                {
                    (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                    if(key == currentFlowId && state is ServerRefreshTokenIssuedState)
                    {
                        _ = Interlocked.Increment(ref secondLoadCount);
                        if(!firstEnteredLibrary.Task.IsCompleted)
                        {
                            _ = firstEnteredLibrary.TrySetResult();
                            await releaseFirst.Task.WaitAsync(ct).ConfigureAwait(false);
                        }
                    }

                    return (state, stepCount);
                };
            }).ConfigureAwait(false);

            Dictionary<string, string> refreshFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(
                ClientId, currentRefreshToken);

            Task<(int StatusCode, string Body)> firstTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, refreshFields, TestContext.CancellationToken);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            GrantOrderObservation firstAdmitted = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            await firstEnteredLibrary.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> secondTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, refreshFields, TestContext.CancellationToken);
            GrantOrderObservation secondEnqueued = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(1, Volatile.Read(ref secondLoadCount),
                "The second, still-queued presentation must not have reached the library's own load yet.");

            _ = releaseFirst.TrySetResult();
            (int FirstStatusCode, string FirstBody) = await firstTask.ConfigureAwait(false);

            GrantOrderObservation firstReleased = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            GrantOrderObservation secondAdmitted = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);

            (int SecondStatusCode, string SecondBody) = await secondTask.ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.LoadFlowStateAsync = originalLoad;
            }).ConfigureAwait(false);

            Assert.IsLessThan(secondEnqueued.Sequence, firstAdmitted.Sequence,
                "ADMISSION ORDER: the first request's own admission must precede the second's enqueue.");
            Assert.IsLessThan(firstReleased.Sequence, secondEnqueued.Sequence,
                "ADMISSION ORDER: the second request stays enqueued while the first is held.");
            Assert.IsLessThan(secondAdmitted.Sequence, firstReleased.Sequence,
                "ADMISSION ORDER: the second request is admitted only after the first is released.");

            Assert.AreEqual(200, FirstStatusCode, FirstBody);
            Assert.AreEqual(400, SecondStatusCode, SecondBody);
            Assert.Contains(OAuthErrors.InvalidGrant, SecondBody, StringComparison.Ordinal);
        }
    }


    /// <summary>
    /// The gate itself: two requests of DIFFERENT grants are both admitted while one is held —
    /// distinct grant keys never share a queue. <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.4">RFC
    /// 6749 §10.4</see>: this FIFO admission is the application's own coordination, never an OAuth
    /// wire mechanism.
    /// </summary>
    [TestMethod]
    public async Task TwoRequestsOfDifferentGrantsAreBothAdmittedWhileOneIsHeldAsync()
    {
        OneRotationFixture fixture = await SetupOneRotationAsync().ConfigureAwait(false);
        await using(fixture.Host)
        using(fixture.Material)
        {
            (TestHostShell host, _, HostedAuthorizationServer hosted, ClientRecord record, string segment,
                _, string firstGrantRefreshToken, string firstGrantFlowId, string firstGrantKey, _) = fixture;

            //A second, independent grant under the SAME registration: its own PAR -> authorize ->
            //callback -> token drive, reusing the host's own client-wiring helper exactly as the
            //first grant did, never touching firstGrantFlowId.
            (OAuthClient secondClient, ClientRegistration secondRegistration, Dictionary<string, FlowState> secondClientFlowStore) =
                await host.CreateOAuthClientAndRegistrationAsync(
                    record, RedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, TestContext.CancellationToken)
                    .ConfigureAwait(false);
            using HttpClient browserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.ServerCertificate);
            AuthCodeFlowDriveResult secondDrive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
                hosted, secondClient, secondRegistration, secondClientFlowStore, segment, RedirectUri, SubjectId, browserClient,
                cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            string secondGrantRefreshToken = (string)secondDrive.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];
            string secondGrantFlowId = hosted.RefreshTokenIndex[secondGrantRefreshToken];
            string secondGrantKey = hosted.ResolveGrantKey(secondGrantFlowId);
            Assert.AreNotEqual(firstGrantKey, secondGrantKey, "The two drives must mint two DIFFERENT grants.");

            TaskCompletionSource firstEnteredLibrary = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource releaseFirst = new(TaskCreationOptions.RunContinuationsAsynchronously);
            LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
                {
                    (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                    if(key == firstGrantFlowId && state is ServerRefreshTokenIssuedState)
                    {
                        _ = firstEnteredLibrary.TrySetResult();
                        await releaseFirst.Task.WaitAsync(ct).ConfigureAwait(false);
                    }

                    return (state, stepCount);
                };
            }).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> firstTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, firstGrantRefreshToken),
                TestContext.CancellationToken);
            await firstEnteredLibrary.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            //A request of the OTHER grant must be admitted and complete while the first is still held.
            (int SecondStatusCode, string SecondBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, secondGrantRefreshToken),
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, SecondStatusCode, SecondBody);

            _ = releaseFirst.TrySetResult();
            (int FirstStatusCode, string FirstBody) = await firstTask.ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.LoadFlowStateAsync = originalLoad;
            }).ConfigureAwait(false);

            Assert.AreEqual(200, FirstStatusCode, FirstBody);
        }
    }


    /// <summary>
    /// The gate itself, over the real wire: a waiter cancelled while queued leaves the queue without
    /// ever being admitted; the next waiter is admitted only after the cancelled one's own
    /// predecessor releases; and once every participant has finished, no gate entry remains for the
    /// key. <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.4">RFC 6749 §10.4</see>:
    /// this FIFO admission is the application's own coordination, never an OAuth wire mechanism.
    /// </summary>
    [TestMethod]
    public async Task CancelledWaiterLeavesTheQueueAndTheNextWaiterIsAdmittedAsync()
    {
        OneRotationFixture fixture = await SetupOneRotationAsync().ConfigureAwait(false);
        await using(fixture.Host)
        using(fixture.Material)
        {
            (TestHostShell host, _, HostedAuthorizationServer hosted, _, string segment,
                _, string currentRefreshToken, string currentFlowId, string grantFlowId, _) = fixture;

            TaskCompletionSource firstEnteredLibrary = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource releaseFirst = new(TaskCreationOptions.RunContinuationsAsynchronously);
            LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
                {
                    (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                    if(key == currentFlowId && state is ServerRefreshTokenIssuedState && !firstEnteredLibrary.Task.IsCompleted)
                    {
                        _ = firstEnteredLibrary.TrySetResult();
                        await releaseFirst.Task.WaitAsync(ct).ConfigureAwait(false);
                    }

                    return (state, stepCount);
                };
            }).ConfigureAwait(false);

            Dictionary<string, string> refreshFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(
                ClientId, currentRefreshToken);

            Task<(int StatusCode, string Body)> firstTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, refreshFields, TestContext.CancellationToken);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            await firstEnteredLibrary.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            using CancellationTokenSource cancelledWaiterSource =
                CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
            Task<(int StatusCode, string Body)> cancelledTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, refreshFields, cancelledWaiterSource.Token);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);

            await cancelledWaiterSource.CancelAsync().ConfigureAwait(false);
            _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(
                () => cancelledTask, "A waiter cancelled while queued must leave without being admitted.");

            //The host's own RequestAborted fires when the cancelled waiter's connection closes; Left
            //is that waiter's server-side departure. Bounded by the test's own token ALONE: a read
            //that never completes here means the host never observed the cancellation server-side,
            //which is a defect of the host and never a reason to bound this read by anything else.
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Left, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> thirdTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, refreshFields, TestContext.CancellationToken);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);

            _ = releaseFirst.TrySetResult();
            GrantOrderObservation firstReleased = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            GrantOrderObservation thirdAdmitted = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            (int FirstStatusCode, string FirstBody) = await firstTask.ConfigureAwait(false);
            (int ThirdStatusCode, string ThirdBody) = await thirdTask.ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Retired, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.LoadFlowStateAsync = originalLoad;
            }).ConfigureAwait(false);

            Assert.IsLessThan(thirdAdmitted.Sequence, firstReleased.Sequence,
                "ADMISSION ORDER: the next waiter is admitted only after the cancelled one's own predecessor is released — never blocked by the cancelled waiter itself.");
            Assert.AreEqual(200, FirstStatusCode, FirstBody);
            Assert.AreEqual(400, ThirdStatusCode, ThirdBody);
            Assert.IsFalse(hosted.HasGrantOrderGateEntry(new TenantId(segment), grantFlowId),
                "No gate entry may remain for the key once every participant has finished.");
        }
    }


    /// <summary>
    /// The gate itself, called directly with no wire
    /// (<see cref="HostedAuthorizationServer.EnterGrantOrderGateAsync"/> against one (tenant, grant
    /// key), three times): a cancelled waiter leaves without corrupting the order of the two
    /// participants around it, exactly as
    /// <see cref="CancelledWaiterLeavesTheQueueAndTheNextWaiterIsAdmittedAsync"/> proves over an
    /// actual connection. <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.4">RFC 6749
    /// §10.4</see>: this FIFO admission is the application's own coordination for
    /// <see cref="LoadGrantFlowStatesDelegate"/>'s documented expectation, never an OAuth wire
    /// mechanism.
    /// </summary>
    [TestMethod]
    public async Task CancelledWaiterLeavesTheQueueAndTheNextWaiterIsAdmittedDirectlyAsync()
    {
        OneRotationFixture fixture = await SetupOneRotationAsync().ConfigureAwait(false);
        await using(fixture.Host)
        using(fixture.Material)
        {
            (_, _, HostedAuthorizationServer hosted, _, string segment, _, _, _, string grantFlowId, _) = fixture;

            TenantId tenantId = new(segment);
            string key = grantFlowId + "-direct-cancel";

            IAsyncDisposable ticketA = await hosted.EnterGrantOrderGateAsync(
                tenantId, key, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, key, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, key, TestContext.CancellationToken).ConfigureAwait(false);

            //Task.WaitAsync(CancellationToken) — what EnterGrantOrderGateAsync awaits its
            //predecessor's turn with — throws TaskCanceledException for a cancelled token, exactly
            //as the HTTP client task does at the wire level.
            using CancellationTokenSource cancelledWaiterSource =
                CancellationTokenSource.CreateLinkedTokenSource(TestContext.CancellationToken);
            ValueTask<IAsyncDisposable> ticketBTask = hosted.EnterGrantOrderGateAsync(
                tenantId, key, cancelledWaiterSource.Token);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, key, TestContext.CancellationToken).ConfigureAwait(false);
            await cancelledWaiterSource.CancelAsync().ConfigureAwait(false);
            _ = await Assert.ThrowsExactlyAsync<TaskCanceledException>(
                async () => _ = await ticketBTask.ConfigureAwait(false),
                "A waiter cancelled while queued must leave without being admitted.");
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Left, key, TestContext.CancellationToken).ConfigureAwait(false);

            ValueTask<IAsyncDisposable> ticketCTask = hosted.EnterGrantOrderGateAsync(
                tenantId, key, TestContext.CancellationToken);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, key, TestContext.CancellationToken).ConfigureAwait(false);

            await ticketA.DisposeAsync().ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, key, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, key, TestContext.CancellationToken).ConfigureAwait(false);

            IAsyncDisposable ticketC = await ticketCTask.ConfigureAwait(false);
            await ticketC.DisposeAsync().ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, key, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Retired, key, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsFalse(hosted.HasGrantOrderGateEntry(tenantId, key),
                "No gate entry may remain for the key once every participant has finished.");
        }
    }


    /// <summary>
    /// The positive control alongside the gate's negative one: a PLACEABLE request produces the
    /// ordinary Enqueued / Admitted / Released / Retired shape any placeable request does, proving
    /// the channel is live; a request the ordering matrix cannot place (an unknown refresh token)
    /// then reaches the library directly and is answered unordered, with the channel staying empty.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.4">RFC 6749 §10.4</see>: this
    /// FIFO admission is the application's own coordination, never an OAuth wire mechanism.
    /// </summary>
    [TestMethod]
    public async Task RequestTheMatrixCannotPlaceIsNeverQueuedAsync()
    {
        OneRotationFixture fixture = await SetupOneRotationAsync().ConfigureAwait(false);
        await using(fixture.Host)
        using(fixture.Material)
        {
            (TestHostShell host, _, HostedAuthorizationServer hosted, _, string segment,
                _, string currentRefreshToken, _, string grantFlowId, _) = fixture;

            (int PlaceableStatusCode, string PlaceableBody) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
                TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, PlaceableStatusCode, PlaceableBody);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Retired, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);

            //An unknown refresh token resolves through no index at all — the matrix places nothing.
            Dictionary<string, string> unknownRefreshFields = RawAuthCodeWirePushers.BuildRefreshTokenFields(
                ClientId, "an-unknown-refresh-token-the-host-never-issued");

            (int StatusCode, string Body) = await RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, unknownRefreshFields, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(400, StatusCode, Body);
            Assert.Contains(OAuthErrors.InvalidGrant, Body, StringComparison.Ordinal);
            Assert.IsFalse(hosted.GrantOrderObservations.Reader.TryRead(out _),
                "A request the matrix cannot place must never be queued — no observation is emitted for it.");
        }
    }


    /// <summary>
    /// The ordered race: a valid reuse of a rotated-out refresh token and a legitimate rotation of
    /// the current one, sent together, with the REUSE forced admitted first through the gate's own
    /// observations. Both requests resolve to the SAME grant key (asserted before release). With the
    /// reuse admitted (and answered) first, the grant's ONE read sees and revokes every record —
    /// including the still-live current token — so the rotation, admitted after, finds nothing left
    /// to claim. <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see> and <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2">RFC
    /// 9700 §4.14.2</see>: the refused refresh token reuse revokes the whole grant.
    /// </summary>
    [TestMethod]
    public async Task OrderedReuseAdmittedFirstLeavesNothingOfTheGrantRedeemableAsync()
    {
        OneRotationFixture fixture = await SetupOneRotationAsync().ConfigureAwait(false);
        await using(fixture.Host)
        using(fixture.Material)
        {
            (TestHostShell host, _, HostedAuthorizationServer hosted, _, string segment,
                string oldestRefreshToken, string currentRefreshToken, string currentFlowId, string grantFlowId, _) = fixture;

            string oldestFlowId = hosted.RefreshTokenIndex[oldestRefreshToken];
            HashSet<string> expectedAccessTokenJtis = new(fixture.ExpectedAccessTokenJtis, StringComparer.Ordinal);
            ConcurrentBag<(string Jti, string TokenType)> revocationNotifications = [];
            int rotateLoadCount = 0;
            TaskCompletionSource reuseAdmittedAndHeld = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource releaseReuse = new(TaskCreationOptions.RunContinuationsAsynchronously);
            LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.RevokeIssuedTokenAsync = (jti, tokenType, _, _, _) =>
                {
                    revocationNotifications.Add((jti, tokenType));

                    return ValueTask.CompletedTask;
                };

                candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
                {
                    if(key == currentFlowId)
                    {
                        _ = Interlocked.Increment(ref rotateLoadCount);
                    }

                    (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                    if(key == oldestFlowId && ctx.FlowId == key)
                    {
                        _ = reuseAdmittedAndHeld.TrySetResult();
                        await releaseReuse.Task.WaitAsync(ct).ConfigureAwait(false);
                    }

                    return (state, stepCount);
                };
            }).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> reuseTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
                TestContext.CancellationToken);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            await reuseAdmittedAndHeld.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> rotateTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
                TestContext.CancellationToken);
            GrantOrderObservation rotateEnqueued = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(grantFlowId, rotateEnqueued.GrantKey,
                "BOTH requests must have been enqueued under the SAME grant key.");
            Assert.AreEqual(0, Volatile.Read(ref rotateLoadCount),
                "The rotation, still queued behind the reuse, must not have reached the library's own load yet.");

            _ = releaseReuse.TrySetResult();
            (int ReuseStatusCode, string ReuseBody) = await reuseTask.ConfigureAwait(false);
            GrantOrderObservation reuseReleased = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            GrantOrderObservation rotateAdmitted = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            (int RotateStatusCode, string RotateBody) = await rotateTask.ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.LoadFlowStateAsync = originalLoad;
            }).ConfigureAwait(false);

            Assert.IsLessThan(rotateAdmitted.Sequence, reuseReleased.Sequence,
                "ADMISSION ORDER: the rotation is admitted only after the reuse is released.");

            Assert.AreEqual(400, ReuseStatusCode, ReuseBody);
            Assert.Contains(OAuthErrors.InvalidGrant, ReuseBody, StringComparison.Ordinal);
            Assert.AreEqual(400, RotateStatusCode,
                $"The rotation, admitted after the reuse already revoked the whole grant, must find nothing to claim. Body={RotateBody}");
            Assert.Contains(OAuthErrors.InvalidGrant, RotateBody, StringComparison.Ordinal);

            GrantStateSnapshot grantState = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
            Assert.AreEqual(0, grantState.RedeemableRecordCount,
                $"With the reuse ordered first, no record of the grant may remain redeemable. Live refresh flow ids: {string.Join(", ", grantState.RedeemableRefreshFlowIds)}.");

            HashSet<string> notifiedAccessTokenJtis = revocationNotifications
                .Where(notification => string.Equals(notification.TokenType, WellKnownTokenTypes.AccessToken, StringComparison.Ordinal))
                .Select(notification => notification.Jti)
                .ToHashSet(StringComparer.Ordinal);
            Assert.IsTrue(expectedAccessTokenJtis.SetEquals(notifiedAccessTokenJtis),
                $"Every access token minted in the grant so far must be notified by identity. Expected: {string.Join(", ", expectedAccessTokenJtis)}; notified: {string.Join(", ", notifiedAccessTokenJtis)}.");
        }
    }


    /// <summary>
    /// The ordered race, the other admission order: the ROTATION forced admitted first. It answers
    /// 200 and publishes a fresh successor; the reuse, admitted after, presents a doubly-retired
    /// token whose one grant read sees that successor too, and revokes it along with everything
    /// else — winning the ordered race never lets a family member survive as an orphan.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1 draft-16
    /// §4.3.1</see> and <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2">RFC 9700
    /// §4.14.2</see>: the refused refresh token reuse revokes the whole grant.
    /// </summary>
    [TestMethod]
    public async Task OrderedRotationAdmittedFirstStillLeavesNothingOfTheGrantRedeemableAsync()
    {
        OneRotationFixture fixture = await SetupOneRotationAsync().ConfigureAwait(false);
        await using(fixture.Host)
        using(fixture.Material)
        {
            (TestHostShell host, _, HostedAuthorizationServer hosted, _, string segment,
                string oldestRefreshToken, string currentRefreshToken, string currentFlowId, string grantFlowId, _) = fixture;

            string oldestFlowId = hosted.RefreshTokenIndex[oldestRefreshToken];
            HashSet<string> expectedAccessTokenJtis = new(fixture.ExpectedAccessTokenJtis, StringComparer.Ordinal);
            ConcurrentBag<(string Jti, string TokenType)> revocationNotifications = [];
            int reuseLoadCount = 0;
            TaskCompletionSource rotationAdmittedAndHeld = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource releaseRotation = new(TaskCreationOptions.RunContinuationsAsynchronously);
            LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.RevokeIssuedTokenAsync = (jti, tokenType, _, _, _) =>
                {
                    revocationNotifications.Add((jti, tokenType));

                    return ValueTask.CompletedTask;
                };

                candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
                {
                    if(key == oldestFlowId)
                    {
                        _ = Interlocked.Increment(ref reuseLoadCount);
                    }

                    (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                    if(key == currentFlowId && ctx.FlowId == key)
                    {
                        _ = rotationAdmittedAndHeld.TrySetResult();
                        await releaseRotation.Task.WaitAsync(ct).ConfigureAwait(false);
                    }

                    return (state, stepCount);
                };
            }).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> rotateTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
                TestContext.CancellationToken);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            await rotationAdmittedAndHeld.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> reuseTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
                TestContext.CancellationToken);
            GrantOrderObservation reuseEnqueued = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(grantFlowId, reuseEnqueued.GrantKey,
                "BOTH requests must have been enqueued under the SAME grant key.");
            Assert.AreEqual(0, Volatile.Read(ref reuseLoadCount),
                "The reuse, still queued behind the rotation, must not have reached the library's own load yet.");

            _ = releaseRotation.TrySetResult();
            (int RotateStatusCode, string RotateBody) = await rotateTask.ConfigureAwait(false);
            GrantOrderObservation rotationReleased = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            GrantOrderObservation reuseAdmitted = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            (int ReuseStatusCode, string ReuseBody) = await reuseTask.ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.LoadFlowStateAsync = originalLoad;
            }).ConfigureAwait(false);

            Assert.IsLessThan(reuseAdmitted.Sequence, rotationReleased.Sequence,
                "ADMISSION ORDER: the reuse is admitted only after the rotation is released.");

            Assert.AreEqual(200, RotateStatusCode, RotateBody);
            using JsonDocument rotateDocument = JsonDocument.Parse(RotateBody);
            _ = expectedAccessTokenJtis.Add(JwtPayloadReader.ReadJti(
                rotateDocument.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!)!);

            Assert.AreEqual(400, ReuseStatusCode, ReuseBody);
            Assert.Contains(OAuthErrors.InvalidGrant, ReuseBody, StringComparison.Ordinal);

            GrantStateSnapshot grantState = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
            Assert.AreEqual(0, grantState.RedeemableRecordCount,
                $"With the rotation ordered first, the reuse admitted after it must still leave nothing of the grant redeemable — INCLUDING the successor the rotation returned. Live refresh flow ids: {string.Join(", ", grantState.RedeemableRefreshFlowIds)}.");

            HashSet<string> notifiedAccessTokenJtis = revocationNotifications
                .Where(notification => string.Equals(notification.TokenType, WellKnownTokenTypes.AccessToken, StringComparison.Ordinal))
                .Select(notification => notification.Jti)
                .ToHashSet(StringComparer.Ordinal);
            Assert.IsTrue(expectedAccessTokenJtis.SetEquals(notifiedAccessTokenJtis),
                $"Every access token minted in the grant so far, INCLUDING the successor's, must be notified by identity. Expected: {string.Join(", ", expectedAccessTokenJtis)}; notified: {string.Join(", ", notifiedAccessTokenJtis)}.");
        }
    }


    /// <summary>
    /// The second ordered-race pair: a REPLAYED authorization code (already redeemed once,
    /// presented again with its valid verifier) and a REFRESH of the grant that code minted, sent
    /// together, with the REPLAY forced admitted first through the gate's own observations. Both
    /// requests resolve to the SAME grant key (asserted before release): the code's own flow id IS
    /// the grant key before any token exists (<see cref="HostedAuthorizationServer.ResolveOrderingKey"/>'s
    /// authorization-code branch), and the refresh record's grant key
    /// (<see cref="HostedAuthorizationServer.ResolveGrantKey"/>) resolves to that same value. With
    /// the replay admitted (and answered) first, the grant's ONE
    /// read sees and revokes every record — including the still-live refresh token — so the
    /// refresh, admitted after, finds nothing left to claim.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.5.3">RFC 9700 §4.5.3</see>: the
    /// replayed authorization code revokes the whole grant.
    /// </summary>
    [TestMethod]
    public async Task OrderedCodeReplayAdmittedFirstLeavesNothingOfTheGrantRedeemableAsync()
    {
        OneCodeRedemptionFixture fixture = await SetupOneCodeRedemptionAsync().ConfigureAwait(false);
        await using(fixture.Host)
        using(fixture.Material)
        {
            (TestHostShell host, _, HostedAuthorizationServer hosted, string segment,
                string code, string pkceVerifier, string refreshToken, string refreshFlowId, string grantFlowId, _) = fixture;

            HashSet<string> expectedAccessTokenJtis = new(fixture.ExpectedAccessTokenJtis, StringComparer.Ordinal);
            ConcurrentBag<(string Jti, string TokenType)> revocationNotifications = [];
            int refreshLoadCount = 0;
            TaskCompletionSource replayAdmittedAndHeld = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource releaseReplay = new(TaskCreationOptions.RunContinuationsAsynchronously);
            LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.RevokeIssuedTokenAsync = (jti, tokenType, _, _, _) =>
                {
                    revocationNotifications.Add((jti, tokenType));

                    return ValueTask.CompletedTask;
                };

                candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
                {
                    if(key == refreshFlowId)
                    {
                        _ = Interlocked.Increment(ref refreshLoadCount);
                    }

                    (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                    if(key == grantFlowId && ctx.FlowId == key)
                    {
                        _ = replayAdmittedAndHeld.TrySetResult();
                        await releaseReplay.Task.WaitAsync(ct).ConfigureAwait(false);
                    }

                    return (state, stepCount);
                };
            }).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> replayTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkceVerifier, RedirectUri.OriginalString),
                TestContext.CancellationToken);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            await replayAdmittedAndHeld.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> refreshTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken),
                TestContext.CancellationToken);
            GrantOrderObservation refreshEnqueued = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(grantFlowId, refreshEnqueued.GrantKey,
                "BOTH requests must have been enqueued under the SAME grant key.");
            Assert.AreEqual(0, Volatile.Read(ref refreshLoadCount),
                "The refresh, still queued behind the replay, must not have reached the library's own load yet.");

            _ = releaseReplay.TrySetResult();
            (int ReplayStatusCode, string ReplayBody) = await replayTask.ConfigureAwait(false);
            GrantOrderObservation replayReleased = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            GrantOrderObservation refreshAdmitted = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            (int RefreshStatusCode, string RefreshBody) = await refreshTask.ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.LoadFlowStateAsync = originalLoad;
            }).ConfigureAwait(false);

            Assert.IsLessThan(refreshAdmitted.Sequence, replayReleased.Sequence,
                "ADMISSION ORDER: the refresh is admitted only after the replay is released.");

            Assert.AreEqual(400, ReplayStatusCode, ReplayBody);
            Assert.Contains(OAuthErrors.InvalidGrant, ReplayBody, StringComparison.Ordinal);
            Assert.AreEqual(400, RefreshStatusCode,
                $"The refresh, admitted after the replay already revoked the whole grant, must find nothing to claim. Body={RefreshBody}");
            Assert.Contains(OAuthErrors.InvalidGrant, RefreshBody, StringComparison.Ordinal);

            GrantStateSnapshot grantState = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
            Assert.AreEqual(0, grantState.RedeemableRecordCount,
                $"With the replay ordered first, no record of the grant may remain redeemable. Live refresh flow ids: {string.Join(", ", grantState.RedeemableRefreshFlowIds)}.");

            HashSet<string> notifiedAccessTokenJtis = revocationNotifications
                .Where(notification => string.Equals(notification.TokenType, WellKnownTokenTypes.AccessToken, StringComparison.Ordinal))
                .Select(notification => notification.Jti)
                .ToHashSet(StringComparer.Ordinal);
            Assert.IsTrue(expectedAccessTokenJtis.SetEquals(notifiedAccessTokenJtis),
                $"Every access token minted in the grant so far must be notified by identity. Expected: {string.Join(", ", expectedAccessTokenJtis)}; notified: {string.Join(", ", notifiedAccessTokenJtis)}.");
        }
    }


    /// <summary>
    /// The second ordered-race pair, the other admission order: the REFRESH of the grant the code
    /// minted forced admitted first. It answers 200 and publishes a fresh successor; the replayed
    /// code, admitted after, presents to a grant whose ONE read sees that successor too, and
    /// revokes it along with everything else — winning the ordered race never lets a family member
    /// survive as an orphan.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2">RFC 6749 §4.1.2</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.5.3">RFC 9700 §4.5.3</see>: the
    /// replayed authorization code revokes the whole grant.
    /// </summary>
    [TestMethod]
    public async Task OrderedRefreshOfCodeGrantAdmittedFirstStillLeavesNothingOfTheGrantRedeemableAsync()
    {
        OneCodeRedemptionFixture fixture = await SetupOneCodeRedemptionAsync().ConfigureAwait(false);
        await using(fixture.Host)
        using(fixture.Material)
        {
            (TestHostShell host, _, HostedAuthorizationServer hosted, string segment,
                string code, string pkceVerifier, string refreshToken, string refreshFlowId, string grantFlowId, _) = fixture;

            HashSet<string> expectedAccessTokenJtis = new(fixture.ExpectedAccessTokenJtis, StringComparer.Ordinal);
            ConcurrentBag<(string Jti, string TokenType)> revocationNotifications = [];
            int replayLoadCount = 0;
            TaskCompletionSource refreshAdmittedAndHeld = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource releaseRefresh = new(TaskCreationOptions.RunContinuationsAsynchronously);
            LoadServerFlowStateDelegate originalLoad = host.Server.OAuth().LoadFlowStateAsync!;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.RevokeIssuedTokenAsync = (jti, tokenType, _, _, _) =>
                {
                    revocationNotifications.Add((jti, tokenType));

                    return ValueTask.CompletedTask;
                };

                candidateIntegration.LoadFlowStateAsync = async (tenantId, key, ctx, ct) =>
                {
                    if(key == grantFlowId)
                    {
                        _ = Interlocked.Increment(ref replayLoadCount);
                    }

                    (FlowState? state, int stepCount) = await originalLoad(tenantId, key, ctx, ct).ConfigureAwait(false);
                    if(key == refreshFlowId && ctx.FlowId == key)
                    {
                        _ = refreshAdmittedAndHeld.TrySetResult();
                        await releaseRefresh.Task.WaitAsync(ct).ConfigureAwait(false);
                    }

                    return (state, stepCount);
                };
            }).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> refreshTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, refreshToken),
                TestContext.CancellationToken);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            await refreshAdmittedAndHeld.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> replayTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildTokenFields(ClientId, code, pkceVerifier, RedirectUri.OriginalString),
                TestContext.CancellationToken);
            GrantOrderObservation replayEnqueued = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(grantFlowId, replayEnqueued.GrantKey,
                "BOTH requests must have been enqueued under the SAME grant key.");
            Assert.AreEqual(0, Volatile.Read(ref replayLoadCount),
                "The replay, still queued behind the refresh, must not have reached the library's own load yet.");

            _ = releaseRefresh.TrySetResult();
            (int RefreshStatusCode, string RefreshBody) = await refreshTask.ConfigureAwait(false);
            GrantOrderObservation refreshReleased = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            GrantOrderObservation replayAdmitted = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            (int ReplayStatusCode, string ReplayBody) = await replayTask.ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.LoadFlowStateAsync = originalLoad;
            }).ConfigureAwait(false);

            Assert.IsLessThan(replayAdmitted.Sequence, refreshReleased.Sequence,
                "ADMISSION ORDER: the replay is admitted only after the refresh is released.");

            Assert.AreEqual(200, RefreshStatusCode, RefreshBody);
            using JsonDocument refreshDocument = JsonDocument.Parse(RefreshBody);
            _ = expectedAccessTokenJtis.Add(JwtPayloadReader.ReadJti(
                refreshDocument.RootElement.GetProperty(OAuthRequestParameterNames.AccessToken).GetString()!)!);

            Assert.AreEqual(400, ReplayStatusCode, ReplayBody);
            Assert.Contains(OAuthErrors.InvalidGrant, ReplayBody, StringComparison.Ordinal);

            GrantStateSnapshot grantState = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
            Assert.AreEqual(0, grantState.RedeemableRecordCount,
                $"With the refresh ordered first, the replay admitted after it must still leave nothing of the grant redeemable — INCLUDING the successor the refresh returned. Live refresh flow ids: {string.Join(", ", grantState.RedeemableRefreshFlowIds)}.");

            HashSet<string> notifiedAccessTokenJtis = revocationNotifications
                .Where(notification => string.Equals(notification.TokenType, WellKnownTokenTypes.AccessToken, StringComparison.Ordinal))
                .Select(notification => notification.Jti)
                .ToHashSet(StringComparer.Ordinal);
            Assert.IsTrue(expectedAccessTokenJtis.SetEquals(notifiedAccessTokenJtis),
                $"Every access token minted in the grant so far, INCLUDING the successor's, must be notified by identity. Expected: {string.Join(", ", expectedAccessTokenJtis)}; notified: {string.Join(", ", notifiedAccessTokenJtis)}.");
        }
    }


    /// <summary>
    /// The interleaving <see cref="AuthCodeParPkceRealWireFlowTests.RotationHeldBeforeSuccessorPublicationStillConvergesAfterOneFurtherPresentationAsync"/>
    /// records (a rotation held between its own claim and its successor's publication while an
    /// older token is reused) cannot occur with the per-grant ordering gate on (the default): the
    /// reuse is not admitted until the rotation has already answered, and the final state has no
    /// survivor. <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.4">RFC 6749
    /// §10.4</see>: this FIFO admission is the application's own coordination, never an OAuth wire
    /// mechanism; <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-16.txt">OAuth 2.1
    /// draft-16 §4.3.1</see> and <see href="https://www.rfc-editor.org/rfc/rfc9700#section-4.14.2">RFC
    /// 9700 §4.14.2</see>: the refused refresh token reuse revokes the whole grant.
    /// </summary>
    [TestMethod]
    public async Task OrderingOnPreventsTheRecordedInterleavingAndLeavesNoSurvivorAsync()
    {
        OneRotationFixture fixture = await SetupOneRotationAsync().ConfigureAwait(false);
        await using(fixture.Host)
        using(fixture.Material)
        {
            (TestHostShell host, _, HostedAuthorizationServer hosted, _, string segment,
                string oldestRefreshToken, string currentRefreshToken, string currentFlowId, string grantFlowId, _) = fixture;

            TaskCompletionSource rotationReachedSuccessorSave = new(TaskCreationOptions.RunContinuationsAsynchronously);
            TaskCompletionSource releaseRotation = new(TaskCreationOptions.RunContinuationsAsynchronously);
            SaveServerFlowStateDelegate originalSave = host.Server.OAuth().SaveFlowStateAsync!;
            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.SaveFlowStateAsync = async (tenantId, key, state, stepCount, ctx, ct) =>
                {
                    if(key != currentFlowId && state is ServerRefreshTokenIssuedState)
                    {
                        _ = rotationReachedSuccessorSave.TrySetResult();
                        await releaseRotation.Task.WaitAsync(ct).ConfigureAwait(false);
                    }

                    await originalSave(tenantId, key, state, stepCount, ctx, ct).ConfigureAwait(false);
                };
            }).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> rotationTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, currentRefreshToken),
                TestContext.CancellationToken);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            _ = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            await rotationReachedSuccessorSave.Task.WaitAsync(TestContext.CancellationToken).ConfigureAwait(false);

            Task<(int StatusCode, string Body)> reuseTask = RawAuthCodeWirePushers.PushRawTokenFieldsAsync(
                host, segment, RawAuthCodeWirePushers.BuildRefreshTokenFields(ClientId, oldestRefreshToken),
                TestContext.CancellationToken);
            GrantOrderObservation reuseEnqueued = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Enqueued, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(grantFlowId, reuseEnqueued.GrantKey,
                "BOTH requests must have been enqueued under the SAME grant key.");

            _ = releaseRotation.TrySetResult();
            (int RotationStatusCode, string RotationBody) = await rotationTask.ConfigureAwait(false);
            GrantOrderObservation rotationReleased = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Released, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            GrantOrderObservation reuseAdmitted = await ExpectObservationAsync(
                hosted, GrantOrderEventKind.Admitted, grantFlowId, TestContext.CancellationToken).ConfigureAwait(false);
            (int ReuseStatusCode, string ReuseBody) = await reuseTask.ConfigureAwait(false);

            await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
            {
                candidateIntegration.SaveFlowStateAsync = originalSave;
            }).ConfigureAwait(false);

            Assert.IsLessThan(reuseAdmitted.Sequence, rotationReleased.Sequence,
                "ADMISSION ORDER: the reuse is admitted only after the rotation is released — the interleaving that test records cannot occur under the gate.");
            Assert.AreEqual(200, RotationStatusCode, RotationBody);
            Assert.AreEqual(400, ReuseStatusCode, ReuseBody);
            Assert.Contains(OAuthErrors.InvalidGrant, ReuseBody, StringComparison.Ordinal);

            GrantStateSnapshot grantState = GrantStateOracle.SnapshotGrant(hosted, grantFlowId, ClientId);
            Assert.AreEqual(0, grantState.RedeemableRecordCount,
                $"With ordering on, the interleaving that test records cannot occur, and the final state has no survivor. Live refresh flow ids: {string.Join(", ", grantState.RedeemableRefreshFlowIds)}.");
        }
    }
}
