using Microsoft.Extensions.Time.Testing;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Mdoc;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Json;
using Verifiable.Json.StatusList;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.StatusList;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The OID4VP verifier seat evaluating a presented credential's Token Status List entry against a Status List
/// Token that genuinely crossed a socket: a Status Provider publishes the signed <c>statuslist+jwt</c> on an
/// in-process HTTPS listener, and the seat's resolver fetches and verifies it over the guarded outbound-fetch
/// chokepoint while the toy wallet drives a full cross-device presentation against the Response URI.
/// </summary>
/// <remarks>
/// <para>
/// The in-process twins — a resolver stub standing in for "whatever a deployment fetched and verified" — are
/// <see cref="Oid4VpFlowIntegrationTests.ExecutorSurfacesCredentialStatusOnPresentationVerified"/> for the SD-JWT
/// VC seat and <see cref="MdocCredentialStatusGateTests"/> for the mdoc one. This class is their real-wire
/// counterpart: nothing here hands the seat a token it did not fetch, so the fetch's own answers — a wrong media
/// type, a 404, a redirect, a target the outbound policy denies — are what the seat is asked to survive.
/// </para>
/// <para>
/// Every credential is minted through <see cref="SdJwtVpFixture.IssuePidCredentialWithClaimsAsync"/> and every flow
/// driven through <see cref="TestHostShell"/>, so the presentations are the ones the sibling OID4VP flow tests
/// present; only the status resolution differs.
/// </para>
/// </remarks>
[TestClass]
internal sealed class StatusListTokenSeatFlowTests
{
    /// <summary>Supplies the ambient cancellation token and the test identity.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock every host, credential, Status List Token and evaluation in this class shares.</summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>The Verifier's client identifier, as registered on the host.</summary>
    private const string VerifierClientId = "https://verifier.example.com";

    /// <summary>The Verifier's base URI, from which its endpoint paths are composed.</summary>
    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    /// <summary>The issuer identifier every PID in this class is issued under and trusted as.</summary>
    private const string IssuerId = "https://issuer.example.com";

    /// <summary>The key identifier the issuer's signature over each PID carries.</summary>
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    /// <summary>The path the Status Provider publishes its Status List Token at.</summary>
    private const string StatusListPath = "/statuslists/1";

    /// <summary>The path a redirecting Status Provider moves its Status List Token to.</summary>
    private const string RedirectedStatusListPath = "/statuslists/1/current";

    /// <summary>The <c>kid</c> the Status List Token's protected header carries.</summary>
    private const string StatusIssuerKeyId = "https://issuer.example/statuslist#key-1";

    /// <summary>Entry capacity of the Status Lists these tests publish.</summary>
    private const int StatusListCapacity = 64;

    /// <summary>The Status List index the presented credential references.</summary>
    private const int CredentialIndex = 42;

    /// <summary>The pool every buffer in this class is rented from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The capabilities a Verifier host must advertise to serve the OID4VP flow.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token Status
    /// List, Section 8.2</see>: "A successful response that contains a Status List Token MUST use an HTTP status
    /// code in the 2xx range." and "In the successful response, the Status Provider MUST use the following
    /// content-type: * "application/statuslist+jwt" for Status List Token in JWT format", whose entry
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Section
    /// 7.1</see> reads as "0x00 - "VALID" - The status of the Referenced Token is valid, correct or legal." The
    /// verified presentation surfaces that outcome, and the Status Provider was dialed exactly once — the byte the
    /// seat evaluated is the byte that crossed the socket, not a locally-held copy.
    /// </summary>
    [TestMethod]
    public async Task AValidStatusServedOverTheWireReachesPresentationVerified()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolution.Resolve);

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-valid").ConfigureAwait(false);

        Assert.IsNull(refusalDetail,
            "A presentation whose Status List entry reads 0x00 VALID is answered by the Response URI, not refused.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "A determinable, valid status leaves the verifier's flow in its verified terminal state.");

        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsNotNull(verified.CredentialStatuses,
            "The seat surfaces the outcomes it read when a status resolver is wired.");
        Assert.IsTrue(verified.CredentialStatuses!.TryGetValue(new CredentialQueryId(DcqlFixtures.PidCredentialId), out CredentialStatusOutcome? outcome),
            "The surfaced outcomes are keyed by the DCQL credential query identifier.");
        Assert.IsNotNull(outcome);
        Assert.IsTrue(outcome.IsValid, "Section 7.1's 0x00 VALID reads as a valid credential.");
        Assert.AreEqual(StatusTypes.Valid, outcome.Status,
            "The outcome carries the raw Section 7.1 status value the fetched list held at the credential's index.");

        Assert.IsTrue(statusProvider.WasRequested(StatusListPath),
            "The status evaluation MUST have crossed the socket to the published Status List Token path.");
        Assert.AreEqual(1, statusProvider.TotalRequests,
            "One presented credential referencing one Status List Token is exactly one Section 8.1 request.");
        Assert.AreEqual(1, resolution.ResolutionCount,
            "The seat resolved the Status List Token once for the one credential that referenced it.");
    }


    /// <summary>
    /// <see cref="ResolvedStatusListToken.IsTokenOwned"/> declares an over-the-wire resolution owned: the
    /// pooled Status List <see cref="StatusListTokenClaims.TryFromPayload"/> decoded is
    /// released once <see cref="CredentialStatusGate.CheckAsync"/> has read it, so a verified presentation
    /// over the real wire leaves the resolver's own pool with no outstanding rentals — the RED symptom
    /// before ownership was declared, where every status check leaked one pooled buffer.
    /// </summary>
    [TestMethod]
    public async Task AVerifiedPresentationOverTheWireLeavesTheResolversPoolBalanced()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using var metered = new MeteredHousePool();
        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(statusHttpClient);
        ExchangeContext context = TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy);
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (_, _) =>
            ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(statusIssuerPublic));
        ResolveVerifiedStatusListTokenDelegate resolve = StatusListTokenResolvers.BuildResolving(
            transport, context, resolveIssuerKey, TestSetup.Base64UrlDecoder, JwtPartJson.Default, metered.Pool, TimeProvider);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolve);

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-pool-balance").ConfigureAwait(false);

        Assert.IsNull(refusalDetail, "A determinable, valid status is answered by the Response URI, not refused.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State);
        Assert.AreEqual(0L, metered.OutstandingCount,
            "The resolver's own pool must carry no outstanding rentals once the gate has released the owned resolution it read.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token Status
    /// List, Section 7.1</see>: "0x01 - "INVALID" - The status of the Referenced Token is revoked, annulled, taken
    /// back, recalled or cancelled." A relying party running <see cref="CredentialStatusPolicies.RefuseNotValid"/>
    /// over a status it fetched itself refuses the presentation, and the Response URI borrows
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>access_denied</c>, "The resource owner or authorization server denied the request." The wire carries only
    /// the one generic sentence; the credential query, the raw status value and the not-valid state it read ride the
    /// typed refusal on the failed flow state instead.
    /// </summary>
    [TestMethod]
    public async Task ARevokedStatusServedOverTheWireIsRefusedAsAccessDenied()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[CredentialIndex] = StatusTypes.Invalid;

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: resolution.Resolve,
            credentialStatusPolicy: CredentialStatusPolicies.RefuseNotValid);

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-revoked").ConfigureAwait(false);

        Assert.IsNotNull(refusalDetail,
            "The Response URI answered the refused presentation with a non-200, which the Wallet client raises.");
        Assert.Contains("status 400", refusalDetail!, StringComparison.Ordinal,
            "OID4VP 1.0 Section 8.2 reserves 200 for a successfully processed Authorization Response; a refusal " +
            "answers RFC 6749 Section 4.1.2.1's error shape as HTTP 400, never 500.");
        Assert.Contains(OAuthErrors.AccessDenied, refusalDetail!, StringComparison.Ordinal,
            "RFC 6749 Section 4.1.2.1's access_denied is the code for a request the relying party denied.");

        Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
            "A policy that rejects a not-valid credential status refuses the presentation.");

        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;
        Assert.AreEqual(VerifierFlowRefusalKind.PolicyRefused, failed.Refusal!.Value.Kind,
            "A relying-party policy refusal is the refusal kind that answers access_denied.");
        Assert.AreEqual("The presentation was refused by relying-party policy.", failed.Refusal!.Value.Description,
            "The wire carries one fixed, generic sentence for the refusal kind.");
        Assert.IsNotNull(failed.CredentialStatusRefusal,
            "The detail the wire withholds rides the failed state as the typed credential-status refusal.");
        Assert.HasCount(1, failed.CredentialStatusRefusal!.Credentials,
            "The one presented credential is the one the refusal names.");
        Assert.AreEqual(DcqlFixtures.PidCredentialId, failed.CredentialStatusRefusal.Credentials[0].CredentialQueryId.Value,
            "The typed refusal names the credential query the wire description does not.");
        Assert.AreEqual(StatusTypes.Invalid, failed.CredentialStatusRefusal.Credentials[0].Outcome.Status,
            "The typed refusal carries the raw Section 7.1 status value the fetched list held.");
        Assert.AreEqual(CredentialStatusDisposition.Revoked, failed.CredentialStatusRefusal.Credentials[0].Disposition,
            "Section 7.1 reads 0x01 INVALID as revoked.");

        Assert.AreEqual(1, statusProvider.TotalRequests,
            "The refused status was read from the Status List Token this presentation fetched.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-18.html#section-4.2.2.2">SD-JWT VC,
    /// status claim</see>: "When the status claim is present and using the status_list mechanism, the associated
    /// Status List Token MUST be in JWT format." A Status Provider that answers the SD-JWT VC seat's request with
    /// the CWT media type of
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Section
    /// 8.2</see> — the body here is the very same valid JWT, so the media type is the only discrepancy — leaves the
    /// status undeterminable rather than being silently accepted as the other format. The Response URI answers
    /// RFC 6749 Section 4.1.2.1 <c>invalid_request</c> as HTTP 400, never a fault.
    /// </summary>
    [TestMethod]
    public async Task ACwtTypedAnswerToTheJwtSeatLeavesTheStatusUndeterminable()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListCwt).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolution.Resolve);

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-cwt-typed").ConfigureAwait(false);

        AssertUndeterminableOnTheWire(app, parHandle, refusalDetail);

        Assert.IsTrue(statusProvider.WasRequested(StatusListPath),
            "The media type was read off a real answer, so the Status Provider was dialed.");
        Assert.AreEqual(0, resolution.ResolutionCount,
            "A Status List Token in the other format is never handed on as a resolved token.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token Status
    /// List, Section 8.2</see>: "A successful response that contains a Status List Token MUST use an HTTP status
    /// code in the 2xx range." A Status Provider that answers 404 for the credential's <c>uri</c> gives the seat no
    /// Status List Token, so — Section 8.3's closing sentence, "If any of these checks fails, no statement about the
    /// status of the Referenced Token can be made and the Referenced Token SHOULD be rejected" — the presentation
    /// fails closed as <c>invalid_request</c> rather than being accepted with an unread status.
    /// </summary>
    [TestMethod]
    public async Task ANotFoundAnswerFromTheStatusProviderLeavesTheStatusUndeterminable()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        //Nothing is published at the credential's uri, so the host's own unknown-path answer is the 404 the
        //seat must survive.
        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolution.Resolve);

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-not-found").ConfigureAwait(false);

        AssertUndeterminableOnTheWire(app, parHandle, refusalDetail);

        Assert.AreEqual(1, statusProvider.TotalRequests,
            "The seat asked the Status Provider once and took its non-2xx answer as final.");
        Assert.AreEqual(0, resolution.ResolutionCount,
            "A non-2xx answer yields no resolved Status List Token.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 4.b: "If the Relying Party has local policies regarding the freshness of the
    /// Status List Token, it SHOULD check the issued at claim (iat or 6)". A relying party that wired such a policy
    /// onto its seat refuses a Status List Token whose <c>iat</c> is older than the policy allows — the closing
    /// "no statement about the status of the Referenced Token can be made" outcome, answered <c>invalid_request</c>.
    /// </summary>
    [TestMethod]
    public async Task AStatusListTokenOlderThanTheFreshnessPolicyLeavesTheStatusUndeterminable()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow() - TimeSpan.FromHours(2), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: resolution.Resolve,
            statusListFreshnessPolicy: new StatusListFreshnessPolicy(TimeSpan.FromHours(1)));

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-stale").ConfigureAwait(false);

        AssertUndeterminableOnTheWire(app, parHandle, refusalDetail);

        Assert.AreEqual(1, resolution.ResolutionCount,
            "The Status List Token verified and resolved; only step 4.b's freshness check refused it.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 4.b is conditional — "If the Relying Party has local policies regarding the
    /// freshness of the Status List Token, it SHOULD check the issued at claim (iat or 6)" — so the very same
    /// Status List Token, served from the very same Status Provider to a seat that wired no freshness policy, is a
    /// determinable status and the presentation stands. The age of <c>iat</c> is never a refusal a relying party
    /// did not ask for.
    /// </summary>
    [TestMethod]
    public async Task TheSameOldStatusListTokenWithoutAFreshnessPolicyReachesPresentationVerified()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow() - TimeSpan.FromHours(2), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolution.Resolve);

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-old-no-policy").ConfigureAwait(false);

        Assert.IsNull(refusalDetail,
            "Without a freshness policy the token's age is not a reason to refuse the presentation.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "The same Status List Token that step 4.b refuses under a policy is determinable without one.");

        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.CredentialStatuses!.TryGetValue(new CredentialQueryId(DcqlFixtures.PidCredentialId), out CredentialStatusOutcome? outcome),
            "The surfaced outcomes are keyed by the DCQL credential query identifier.");
        Assert.IsNotNull(outcome);
        Assert.IsTrue(outcome.IsValid, "The fetched list's entry for the credential still reads 0x00 VALID.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 4.d: "If the Relying Party is using a system for caching the Status List Token,
    /// it SHOULD check the ttl claim of the Status List Token and retrieve a fresh copy if (time status was
    /// resolved + ttl &lt; current time)", bounded by
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.5">Section
    /// 11.5</see>: "Clients SHOULD check that both values are within reasonable ranges before requesting new Status
    /// List Tokens based on these values to prevent accidentally creating unreasonable amounts of requests for a
    /// specific URL." A resolution reporting itself as made long before the configured floor still yields a
    /// determinable, valid status — the refresh is a flag on the outcome the relying party reads, never a refusal.
    /// </summary>
    /// <remarks>
    /// The Status Issuer's own <c>ttl</c> is one hour, above the five-minute ceiling these bounds configure, and the
    /// resolution is ten minutes old: the Status Issuer's value alone would pin the cached list for another fifty
    /// minutes, while the clamped interval says a fresh copy should be retrieved. The clamp is therefore what
    /// decides the answer, not merely present.
    /// </remarks>
    [TestMethod]
    public async Task AResolutionOlderThanTheClampedTimeToLiveIsFlaggedForRefresh()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: 3600,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.FromMinutes(10));

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: resolution.Resolve,
            statusListCachingBounds: new StatusListCachingBounds(TimeSpan.FromSeconds(30), TimeSpan.FromMinutes(5)));

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-refresh").ConfigureAwait(false);

        Assert.IsNull(refusalDetail,
            "A cached-too-long Status List Token is a refresh hint, not a reason to refuse the presentation.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "Step 4.d never turns a determinable status into a refusal.");

        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.CredentialStatuses!.TryGetValue(new CredentialQueryId(DcqlFixtures.PidCredentialId), out CredentialStatusOutcome? outcome),
            "The surfaced outcomes are keyed by the DCQL credential query identifier.");
        Assert.IsNotNull(outcome);
        Assert.IsTrue(outcome.IsValid, "The fetched list's entry for the credential reads 0x00 VALID.");
        Assert.IsTrue(outcome.ShouldRefresh,
            "The resolution instant plus the Section 11.5 ceiling the relying party configured lies before the " +
            "current time, so a fresh copy should be retrieved even though the Status Issuer's own ttl has not " +
            "elapsed.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token Status
    /// List, Section 8.2</see>: "A response MAY also choose to redirect the client to another URI using an HTTP
    /// status code in the 3xx range, which clients SHOULD follow." Following it is bounded by
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4">Section
    /// 11.4</see>: "HTTP clients MUST follow the guidance provided in Section 15.4 of [RFC9110] for handling
    /// redirects", where <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.4">RFC 9110, Section
    /// 15.4</see> describes "Redirects that indicate this resource might be available at a different URI, as
    /// provided by the Location header field, as in the status codes 301 (Moved Permanently), 302 (Found), 307
    /// (Temporary Redirect), and 308 (Permanent Redirect)." A relying party that opted into same-origin
    /// redirect-following reaches the moved Status List Token and evaluates it.
    /// </summary>
    [TestMethod]
    public async Task ASameOriginRedirectToTheStatusListTokenIsFollowedWhenTheRelyingPartyOptedIn()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        ConcurrentDictionary<string, int> requestCounts = new(StringComparer.Ordinal);
        await using MinimalHttpHost statusProvider = await StartRedirectingStatusProviderAsync(
            requestCounts, statusIssuerPrivate).ConfigureAwait(false);

        string statusListUri = new Uri(statusProvider.BaseAddress, StatusListPath).ToString();

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackRedirectFollowingOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolution.Resolve);

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-redirect-followed").ConfigureAwait(false);

        Assert.IsNull(refusalDetail,
            "A followed redirect ends at a 2xx Status List Token, so the presentation is answered, not refused.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "The Status List Token the redirect pointed at is the one the seat evaluated.");

        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsTrue(verified.CredentialStatuses!.TryGetValue(new CredentialQueryId(DcqlFixtures.PidCredentialId), out CredentialStatusOutcome? outcome),
            "The surfaced outcomes are keyed by the DCQL credential query identifier.");
        Assert.IsNotNull(outcome);
        Assert.IsTrue(outcome.IsValid, "The moved list's entry for the credential reads 0x00 VALID.");

        Assert.AreEqual(1, requestCounts.GetValueOrDefault(StatusListPath),
            "The credential's own uri was dialed first and answered 302 Found.");
        Assert.AreEqual(1, requestCounts.GetValueOrDefault(RedirectedStatusListPath),
            "The Location the 302 named was dialed as the second hop.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.4">Token Status
    /// List, Section 11.4</see>: "HTTP clients that follow 3xx (Redirection) status codes MUST be aware of the
    /// possible dangers of redirects, such as infinite redirection loops, since they can be used for
    /// denial-of-service attacks on clients." Section 8.2's "which clients SHOULD follow" is therefore a relying
    /// party's own opt-in: under the secure default's no-redirect stance the identical 302 answer is not followed,
    /// the Location is never dialed, and the presentation fails closed as <c>invalid_request</c> rather than being
    /// accepted with an unread status.
    /// </summary>
    [TestMethod]
    public async Task TheSameRedirectIsNotFollowedUnderTheDefaultNoRedirectStance()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        ConcurrentDictionary<string, int> requestCounts = new(StringComparer.Ordinal);
        await using MinimalHttpHost statusProvider = await StartRedirectingStatusProviderAsync(
            requestCounts, statusIssuerPrivate).ConfigureAwait(false);

        string statusListUri = new Uri(statusProvider.BaseAddress, StatusListPath).ToString();

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolution.Resolve);

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-redirect-refused").ConfigureAwait(false);

        AssertUndeterminableOnTheWire(app, parHandle, refusalDetail);

        Assert.AreEqual(1, requestCounts.GetValueOrDefault(StatusListPath),
            "The credential's own uri was dialed once and answered 302 Found.");
        Assert.AreEqual(0, requestCounts.GetValueOrDefault(RedirectedStatusListPath),
            "The Location the 302 named is never dialed when the relying party follows no redirects.");
        Assert.AreEqual(0, resolution.ResolutionCount,
            "An unfollowed redirect yields no resolved Status List Token.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 2, "Resolve the Status List Token from the provided URI", and the section's
    /// closing sentence, "If any of these checks fails, no statement about the status of the Referenced Token can
    /// be made and the Referenced Token SHOULD be rejected": the <c>uri</c> is issuer-controlled input, so a
    /// credential naming a target the relying party's outbound policy denies — here the same listener over
    /// cleartext <c>http</c>, which the policy's HTTPS-only scheme set refuses — is refused before any connection
    /// is attempted. The Status Provider is never dialed at all.
    /// </summary>
    [TestMethod]
    public async Task AStatusUriTheOutboundPolicyDeniesIsRefusedWithoutDialingTheStatusProvider()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string deniedStatusListUri = $"http://127.0.0.1:{statusProvider.BaseAddress.Port}{StatusListPath}";

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        //The Status List Token is published, and its subject is the denied uri, so the only reason the seat
        //cannot read it is the outbound policy's refusal to dial that target.
        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, deniedStatusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolution.Resolve);

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, deniedStatusListUri, "nonce-status-wire-policy-denied").ConfigureAwait(false);

        AssertUndeterminableOnTheWire(app, parHandle, refusalDetail);

        Assert.AreEqual(0, statusProvider.TotalRequests,
            "A denied target is refused before any connection is attempted, so the listener never sees a request.");
        Assert.AreEqual(0, resolution.ResolutionCount,
            "A denied target yields no resolved Status List Token.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see>: "The processing rules for Referenced Tokens (such as JWT or CWT) MUST precede any
    /// evaluation of a Referenced Token's status." and "If the validation procedures for the Referenced Token
    /// determine it is invalid, further procedures regarding Status List MUST NOT be performed, e.g. fetching a
    /// Status List Token, unless the Referenced Token procedures or the use case require further evaluation." A
    /// presentation the verifier's own verdict already refuses — here a claim <c>values</c> constraint the disclosed
    /// <c>family_name</c> does not meet — never reaches the Status Provider at all, which the listener's own
    /// request counter proves over the wire rather than through an in-process resolver stub.
    /// </summary>
    [TestMethod]
    public async Task AnUnverifiablePresentationNeverFetchesTheStatusListToken()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[CredentialIndex] = StatusTypes.Invalid;

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: resolution.Resolve,
            credentialStatusPolicy: CredentialStatusPolicies.RefuseNotValid);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidAsync(new StatusListReference(CredentialIndex, statusListUri)).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        //A reveal-all wallet discloses the real family_name, so the DCQL values constraint — and not
        //over-disclosure — is the single reason the verifier's verdict comes out negative.
        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys,
            TestHostShell.BuildSdJwtProduceDelegateRevealingAll(serializedSdJwt, holderKey),
            TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey),
            TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, _) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNameValueConstraintPrepared("Schmidt"),
            "nonce-status-wire-unverifiable").ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
            "A presentation that does not satisfy the Authorization Request's DCQL query is refused.");

        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;
        Assert.AreEqual(VerifierFlowRefusalKind.Unverifiable, failed.Refusal!.Value.Kind,
            "The verification verdict, not the credential's status, is the reason the presentation is refused.");

        Assert.AreEqual(0, statusProvider.TotalRequests,
            "A Referenced Token its own processing rules reject never causes a Status List Token to be fetched.");
        Assert.AreEqual(0, resolution.ResolutionCount,
            "No status evaluation was performed, so no Status List Token was resolved.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Token Status
    /// List, Section 11.3</see>: "If the Issuer of the Referenced Token is the same entity as the Status Issuer,
    /// then the same key that is embedded into the Referenced Token may be used for the Status List Token." That
    /// recommendation is only reachable behind the key-resolution seam if the seat says what the Referenced Token
    /// was, so the verifier hands the resolution the presented credential's verified <c>iss</c> and the very key
    /// its issuer signature verified under — facts a resolver would otherwise have to replace with an inference
    /// from the list URL's authority, which is a DNS fact and not a cryptographic one.
    /// </summary>
    [TestMethod]
    public async Task TheSeatTellsTheKeyResolutionWhichCredentialsStatusIsBeingRead()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        //Minted before the resolver closure so the closure compares against the credential's own issuer
        //key, handed back by the fixture rather than recovered through the key-material cache.
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory credentialIssuerPublic, PrivateKeyMemory unusedCredentialIssuerPrivate) =
            await IssuePidWithIssuerKeyAsync(new StatusListReference(CredentialIndex, statusListUri)).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = credentialIssuerPublic;
        using PrivateKeyMemory unusedIssuerPrivateKey = unusedCredentialIssuerPrivate;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        //The Referenced Token's key is lent for the resolution call only — the seat releases it when the
        //credential's flow step ends — so what it carried is read here, inside the call, rather than from a
        //recorded context afterwards.
        int keyResolutions = 0;
        string? seenStatusListUri = null;
        string? seenReferencedTokenIssuer = null;
        bool isReferencedKeyPresent = false;
        bool isReferencedKeyTheCredentialIssuers = false;

        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (context, cancellationToken) =>
        {
            keyResolutions++;
            seenStatusListUri = context.StatusListUri;
            seenReferencedTokenIssuer = context.ReferencedTokenIssuer;
            isReferencedKeyPresent = context.ReferencedTokenIssuerKey is not null;
            isReferencedKeyTheCredentialIssuers = context.ReferencedTokenIssuerKey is { } referencedKey
                && referencedKey.AsReadOnlySpan().SequenceEqual(issuerKey.AsReadOnlySpan());

            return ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(statusIssuerPublic));
        };

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, resolveIssuerKey, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolution.Resolve);

        (string parHandle, string? refusalDetail) = await PresentMintedPidAsync(
            app, serializedSdJwt, holderKey, issuerKey, "nonce-status-wire-referenced-facts").ConfigureAwait(false);

        Assert.IsNull(refusalDetail, "The status resolves and reads valid, so the Response URI answers the presentation.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "A determinable, valid status leaves the verifier's flow in its verified terminal state.");

        Assert.AreEqual(1, keyResolutions, "One presented credential referencing one Status List Token is one key decision.");
        Assert.AreEqual(statusListUri, seenStatusListUri,
            "The key decision is keyed on the uri the credential's own status_list claim named.");
        Assert.AreEqual(IssuerId, seenReferencedTokenIssuer,
            "Section 11.3's web-based alternative resolves on the Referenced Token's issuer, which for an SD-JWT VC is its verified iss.");
        Assert.IsTrue(isReferencedKeyPresent,
            "The status step runs only after the credential's issuer signature verified, so the key it verified under is in hand.");
        Assert.IsTrue(isReferencedKeyTheCredentialIssuers,
            "'the same key that is embedded into the Referenced Token' is the key the seat resolved for the credential, byte for byte.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Token Status
    /// List, Section 11.3</see>'s first recommendation, composed and driven over the real wire: a relying party
    /// that already trusts the credential issuer's key needs no separate Status Issuer key at all. A Status List
    /// Token that issuer signed verifies under the key the credential itself verified under, so the status is
    /// read and surfaced, and the application's own key resolution is never consulted.
    /// </summary>
    [TestMethod]
    public async Task AStatusListTheCredentialIssuerSignedResolvesWithNoSeparateStatusIssuerKey()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string statusListUri = StatusListUriOn(statusProvider);

        //Minted before the Status Provider signs, so the Status Provider signs with the very key the
        //fixture just handed back — the credential issuer's own private key — which is what "the same
        //entity" means on the wire.
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory credentialIssuerPublic, PrivateKeyMemory credentialIssuerPrivate) =
            await IssuePidWithIssuerKeyAsync(new StatusListReference(CredentialIndex, statusListUri)).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = credentialIssuerPublic;
        using PrivateKeyMemory issuerPrivateKey = credentialIssuerPrivate;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, issuerPrivateKey,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(
                statusHttpClient,
                StatusListIssuerKeys.FromReferencedToken(NoSeparateStatusIssuerKey()),
                TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolution.Resolve);

        (string parHandle, string? refusalDetail) = await PresentMintedPidAsync(
            app, serializedSdJwt, holderKey, issuerKey, "nonce-status-wire-same-key").ConfigureAwait(false);

        Assert.IsNull(refusalDetail,
            "A Status List Token the credential's own issuer signed verifies, so the Response URI answers the presentation.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "A determinable, valid status leaves the verifier's flow in its verified terminal state.");

        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsNotNull(verified.CredentialStatuses, "The seat surfaces the outcome it read.");
        Assert.IsTrue(verified.CredentialStatuses!.TryGetValue(new CredentialQueryId(DcqlFixtures.PidCredentialId), out CredentialStatusOutcome? outcome),
            "The surfaced outcomes are keyed by the DCQL credential query identifier.");
        Assert.IsTrue(outcome!.IsValid, "Section 7.1's 0x00 VALID reads as a valid credential.");
        Assert.AreEqual(1, statusProvider.TotalRequests,
            "The same-key composition removes a key resolution, not the Section 8.1 request for the list itself.");
    }


    /// <summary>
    /// The limit of the same-key composition, over the real wire. An ecosystem whose Status Issuer is a separate
    /// entity, or whose lists are signed by another key of the same issuer, does not satisfy
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Section
    /// 11.3</see>'s "If the Issuer of the Referenced Token is the same entity as the Status Issuer", so the
    /// fetched token does not verify under the answered key. It fails CLOSED —
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section
    /// 8.3</see>'s "no statement about the status of the Referenced Token can be made and the Referenced Token
    /// SHOULD be rejected" — as HTTP 400 <c>invalid_request</c>, never a server fault and never a pass.
    /// </summary>
    [TestMethod]
    public async Task AStatusListAnotherKeySignedIsRefusedAsAnUndeterminableStatus()
    {
        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //A Status Issuer that is a different entity from the credential's issuer: a key the credential never
        //verified under, which is exactly what the composition must refuse rather than reach past.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> separateStatusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory unusedSeparateStatusIssuerPublic = separateStatusIssuerKeys.PublicKey;
        using PrivateKeyMemory separateStatusIssuerPrivate = separateStatusIssuerKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, separateStatusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(
                statusHttpClient,
                StatusListIssuerKeys.FromReferencedToken(NoSeparateStatusIssuerKey()),
                TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: resolution.Resolve);

        (string parHandle, string? refusalDetail) = await PresentPidReferencingAsync(
            app, statusListUri, "nonce-status-wire-foreign-key").ConfigureAwait(false);

        AssertUndeterminableOnTheWire(app, parHandle, refusalDetail);

        Assert.AreEqual(1, statusProvider.TotalRequests,
            "The token was fetched and then refused on its signature; the composition never dials again for a second key.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Token Status
    /// List, Section 11.3</see> keys its recommendations on the Referenced Token's issuer and its key, and an
    /// ISO mdoc carries no issuer claim at all — its issuer identity is the IssuerAuth <c>x5chain</c> leaf's own
    /// subject — so the seat states the issuer as absent rather than inventing one. The key is a different
    /// matter:
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section
    /// 8.3</see> orders the steps — "Upon receiving a Referenced Token, a Relying Party MUST first perform the
    /// validation of the Referenced Token" and only then evaluate its status — so an mdoc reaches the status step
    /// only after its IssuerAuth verified under a key the seat resolved, and that key is in the context like any
    /// other format's.
    /// </summary>
    [TestMethod]
    public async Task TheContextTheSeatBuildsForAnMdocNamesNoReferencedTokenIssuerButCarriesItsKey()
    {
        const int mdocCredentialIndex = 17;

        await using StaticContentHost statusProvider = await StaticContentHost
            .StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory statusIssuerPrivate = statusIssuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> mdocIssuerKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory mdocIssuerPublic = mdocIssuerKeys.PublicKey;
        using PrivateKeyMemory mdocIssuerPrivate = mdocIssuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> deviceKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory devicePublic = deviceKeys.PublicKey;
        using PrivateKeyMemory devicePrivate = deviceKeys.PrivateKey;

        string statusListUri = StatusListUriOn(statusProvider);

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await PublishStatusListTokenAsync(
            statusProvider, StatusListPath, statusListUri, statusList, statusIssuerPrivate,
            issuedAt: TimeProvider.GetUtcNow(), timeToLive: null,
            contentType: StatusListMediaTypes.StatusListJwtContentType).ConfigureAwait(false);

        using HttpClient statusHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(statusProvider.Certificate);
        using RecordedStatusListResolution resolution = new(
            BuildWireResolver(statusHttpClient, statusIssuerPublic, TestHostShell.LoopbackOutboundFetchPolicy),
            resolvedAtShift: TimeSpan.Zero);

        //The Referenced Token's key is lent for the resolution call only, so the context's contents are read
        //inside the call rather than from a recorded context the seat has since released.
        int resolutions = 0;
        string? seenReferenceUri = null;
        string? seenReferencedTokenIssuer = null;
        bool isReferencedKeyPresent = false;
        bool isReferencedKeyTheMdocIssuers = false;

        ResolveVerifiedStatusListTokenDelegate resolver = (context, cancellationToken) =>
        {
            resolutions++;
            seenReferenceUri = context.Reference.Uri;
            seenReferencedTokenIssuer = context.ReferencedTokenIssuer;
            isReferencedKeyPresent = context.ReferencedTokenIssuerKey is not null;
            isReferencedKeyTheMdocIssuers = context.ReferencedTokenIssuerKey is { } referencedKey
                && referencedKey.AsReadOnlySpan().SequenceEqual(mdocIssuerPublic.AsReadOnlySpan());

            return resolution.Resolve(context, cancellationToken);
        };

        await using TestHostShell app = new(
            TimeProvider,
            mdocSeams: MdocVpFixture.BuildSeams(mdocIssuerPublic),
            resolveVerifiedStatusListToken: resolver);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        using MdocDocument issued = await MdocVpFixture.IssueAsync(
            mdocIssuerKeys, deviceKeys, new StatusListReference(mdocCredentialIndex, statusListUri),
            TestContext.CancellationToken).ConfigureAwait(false);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys,
            MdocVpFixture.BuildMdocProduceDelegate(issued, devicePrivate),
            TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey),
            TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, string? refusalDetail) = await PresentAsync(
            app, verifierKeys, walletClient, MdocVpFixture.BuildMdocPreparedQuery(),
            "nonce-status-wire-mdoc-context").ConfigureAwait(false);

        Assert.IsNull(refusalDetail, "The mdoc's status resolves and reads valid, so the Response URI answers the presentation.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "A determinable, valid status leaves the verifier's flow in its verified terminal state.");

        Assert.AreEqual(1, resolutions, "One presented mdoc referencing one Status List Token is one resolution.");
        Assert.AreEqual(statusListUri, seenReferenceUri,
            "The resolution is asked for the uri the Mobile Security Object's own status structure named.");
        Assert.IsNull(seenReferencedTokenIssuer,
            "An mdoc carries no issuer claim, so the seat states the Referenced Token's issuer as absent rather than inventing one.");
        Assert.IsTrue(isReferencedKeyPresent,
            "Section 8.3 evaluates status only after the Referenced Token validated, so the key its IssuerAuth verified under is in hand for an mdoc too.");
        Assert.IsTrue(isReferencedKeyTheMdocIssuers,
            "The key the context carries is the one the seat's own mdoc issuer-key resolution answered, byte for byte.");
    }


    /// <summary>
    /// A Status Issuer key resolution that fails the test if it is ever reached — how "this relying party has no
    /// Status Issuer key of its own, only the credential issuer's" is expressed as a delegate.
    /// </summary>
    /// <returns>The resolution that must not be consulted.</returns>
    private static ResolveStatusListIssuerKeyDelegate NoSeparateStatusIssuerKey() =>
        (_, _) => throw new AssertFailedException(
            "Section 11.3's first recommendation answers the Referenced Token's own key, so no separate Status Issuer key is resolved.");


    /// <summary>
    /// The Status List Token <c>uri</c> a credential served by <paramref name="statusProvider"/> references.
    /// </summary>
    /// <param name="statusProvider">The listener publishing the Status List Token.</param>
    /// <returns>The absolute URI of <see cref="StatusListPath"/> on that listener.</returns>
    private static string StatusListUriOn(StaticContentHost statusProvider) =>
        new Uri(statusProvider.BaseAddress, StatusListPath).ToString();


    /// <summary>
    /// Composes, signs and publishes a Section 5.1 Status List Token on <paramref name="statusProvider"/>, through
    /// the library's own composition rather than a hand-minted JWT.
    /// </summary>
    /// <param name="statusProvider">The listener that serves the token.</param>
    /// <param name="path">The path the token is served at.</param>
    /// <param name="subject">The token's <c>sub</c> claim, equal to the <c>uri</c> the credential references.</param>
    /// <param name="statusList">The Status List the token embeds.</param>
    /// <param name="signingKey">The Status Issuer's signing key.</param>
    /// <param name="issuedAt">The token's <c>iat</c> claim.</param>
    /// <param name="timeToLive">The token's <c>ttl</c> claim in seconds, or <see langword="null"/> for none.</param>
    /// <param name="contentType">The content type the token is served with.</param>
    private static async Task PublishStatusListTokenAsync(
        StaticContentHost statusProvider,
        string path,
        string subject,
        StatusListType statusList,
        PrivateKeyMemory signingKey,
        DateTimeOffset issuedAt,
        long? timeToLive,
        string contentType)
    {
        string compactJwt = await ComposeStatusListTokenAsync(subject, statusList, signingKey, issuedAt, timeToLive)
            .ConfigureAwait(false);
        statusProvider.Publish(path, Encoding.ASCII.GetBytes(compactJwt), contentType);
    }


    /// <summary>
    /// Composes and signs the compact <c>statuslist+jwt</c> for a Status List, through
    /// <see cref="StatusListTokenJwtFixtures.IssueJwtAsync"/> — the shared fixture riding the library's own
    /// composition.
    /// </summary>
    /// <param name="subject">The token's <c>sub</c> claim.</param>
    /// <param name="statusList">The Status List the token embeds.</param>
    /// <param name="signingKey">The Status Issuer's signing key.</param>
    /// <param name="issuedAt">The token's <c>iat</c> claim.</param>
    /// <param name="timeToLive">The token's <c>ttl</c> claim in seconds, or <see langword="null"/> for none.</param>
    /// <returns>The compact-serialized Status List Token JWT.</returns>
    private static Task<string> ComposeStatusListTokenAsync(
        string subject,
        StatusListType statusList,
        PrivateKeyMemory signingKey,
        DateTimeOffset issuedAt,
        long? timeToLive)
    {
        StatusListToken token = new(subject, issuedAt, statusList) { TimeToLive = timeToLive };

        return StatusListTokenJwtFixtures.IssueJwtAsync(token, signingKey, StatusIssuerKeyId, CancellationToken.None);
    }


    /// <summary>
    /// Builds the JWT-format resolver the seat is wired with: the library's own fetch-and-verify composition over a
    /// guarded single-hop transport pinned to the Status Provider's certificate.
    /// </summary>
    /// <param name="statusHttpClient">The pinned, redirect-surfacing client dialing the Status Provider.</param>
    /// <param name="statusIssuerPublic">The Status Issuer's public key every signature is verified against.</param>
    /// <param name="policy">The outbound-fetch policy the guarded chokepoint evaluates every hop against.</param>
    /// <returns>The resolver a host is built with.</returns>
    private ResolveVerifiedStatusListTokenDelegate BuildWireResolver(
        HttpClient statusHttpClient, PublicKeyMemory statusIssuerPublic, OutboundFetchPolicy policy)
    {
        return BuildWireResolver(
            statusHttpClient,
            (_, _) => ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(statusIssuerPublic)),
            policy);
    }


    /// <summary>
    /// Builds the JWT-format resolver the seat is wired with, over a caller-supplied key decision — the shape
    /// a test needs when what it is proving is what the seat tells that decision, or that the decision is
    /// <see cref="StatusListIssuerKeys.FromReferencedToken"/> and needs no Status Issuer key of its own.
    /// </summary>
    /// <param name="statusHttpClient">The pinned, redirect-surfacing client dialing the Status Provider.</param>
    /// <param name="resolveIssuerKey">The relying party's decision about which key the Status List Token is verified under.</param>
    /// <param name="policy">The outbound-fetch policy the guarded chokepoint evaluates every hop against.</param>
    /// <returns>The resolver a host is built with.</returns>
    private ResolveVerifiedStatusListTokenDelegate BuildWireResolver(
        HttpClient statusHttpClient, ResolveStatusListIssuerKeyDelegate resolveIssuerKey, OutboundFetchPolicy policy)
    {
        OutboundTransportDelegate transport = GuardedHttpClientTransport.BuildSingleHopTransport(statusHttpClient);
        ExchangeContext context = TestHostShell.ExchangeContextWith(policy);

        return StatusListTokenResolvers.BuildResolving(
            transport, context, resolveIssuerKey, TestSetup.Base64UrlDecoder, JwtPartJson.Default, Pool, TimeProvider);
    }


    /// <summary>
    /// Starts a Status Provider that answers <see cref="StatusListPath"/> with 302 Found naming
    /// <see cref="RedirectedStatusListPath"/> on its own origin, and serves the signed Status List Token there.
    /// </summary>
    /// <param name="requestCounts">Records how often each path was dialed.</param>
    /// <param name="signingKey">The Status Issuer's signing key.</param>
    /// <returns>The started listener.</returns>
    private async Task<MinimalHttpHost> StartRedirectingStatusProviderAsync(
        ConcurrentDictionary<string, int> requestCounts, PrivateKeyMemory signingKey)
    {
        //The token's subject is the uri the credential references — the path the redirect leads away from —
        //because Section 5.1's sub claim names the Status List Token, not the location it was moved to.
        string? compactJwt = null;
        Uri? baseAddress = null;

        MinimalHttpHost host = await MinimalHttpHost.StartAsync(
            (request, cancellationToken) =>
            {
                requestCounts.AddOrUpdate(request.Path, 1, static (_, count) => count + 1);

                MinimalHttpResponse response = request.Path switch
                {
                    StatusListPath => new MinimalHttpResponse
                    {
                        StatusCode = 302,
                        Headers = new Dictionary<string, string>(StringComparer.Ordinal)
                        {
                            ["Location"] = new Uri(baseAddress!, RedirectedStatusListPath).OriginalString
                        }
                    },
                    RedirectedStatusListPath => new MinimalHttpResponse
                    {
                        StatusCode = 200,
                        ContentType = StatusListMediaTypes.StatusListJwtContentType,
                        Body = compactJwt
                    },
                    _ => new MinimalHttpResponse { StatusCode = 404 }
                };

                return Task.FromResult(response);
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        baseAddress = host.BaseAddress;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        compactJwt = await ComposeStatusListTokenAsync(
            new Uri(host.BaseAddress, StatusListPath).ToString(), statusList, signingKey,
            TimeProvider.GetUtcNow(), timeToLive: null).ConfigureAwait(false);

        return host;
    }


    /// <summary>
    /// Mints a PID SD-JWT VC referencing <paramref name="status"/> through the shared fixture under this class's
    /// issuer identity, key id and pool.
    /// </summary>
    /// <param name="status">The Status List entry the credential references.</param>
    /// <returns>The serialized credential, the holder's private key and the issuer's public key.</returns>
    private async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)>
        IssuePidAsync(StatusListReference status)
    {
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey, PrivateKeyMemory issuerPrivateKey) =
            await IssuePidWithIssuerKeyAsync(status).ConfigureAwait(false);
        issuerPrivateKey.Dispose();

        return (serializedSdJwt, holderPrivateKey, issuerPublicKey);
    }


    /// <summary>
    /// <see cref="IssuePidAsync"/>, additionally handing the caller the credential issuer's own private
    /// key — the Section 11.3 same-key tests sign or compare against it directly, rather than recovering
    /// it through <see cref="TestKeyMaterialProvider.CreateP256KeyMaterial"/>'s documented same-pair
    /// caching. The caller owns the returned issuer private key, alongside the holder private key, and
    /// must dispose both.
    /// </summary>
    /// <param name="status">The Status List entry the credential references.</param>
    /// <returns>The serialized credential, the holder's private key and the issuer's public and private keys.</returns>
    private ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey, PrivateKeyMemory IssuerPrivateKey)>
        IssuePidWithIssuerKeyAsync(StatusListReference status) =>
        SdJwtVpFixture.IssuePidCredentialWithClaimsAndIssuerKeyAsync(
            TimeProvider, "Erika", "Mustermann", IssuerId, IssuerKeyId, Pool, status,
            TestContext.CancellationToken);


    /// <summary>
    /// Registers a Verifier client on <paramref name="app"/>, mints a PID carrying <paramref name="rawStatusObject"/>
    /// verbatim as its <c>status</c> claim — a shape <see cref="StatusListReference"/>'s own constructor would
    /// refuse to hold — and drives one full cross-device presentation of it.
    /// </summary>
    /// <param name="app">The Verifier host shell.</param>
    /// <param name="rawStatusObject">The hand-built <c>status</c> claim object.</param>
    /// <param name="nonce">The transaction nonce binding the presentation to this request.</param>
    /// <returns>The flow's external handle, and the Wallet-side detail of a non-200 Response URI answer.</returns>
    private async Task<(string ParHandle, string? RefusalDetail)> PresentPidWithRawStatusAsync(
        TestHostShell app, IReadOnlyDictionary<string, object> rawStatusObject, string nonce)
    {
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await SdJwtVpFixture.IssuePidCredentialWithClaimsAsync(
                TimeProvider, "Erika", "Mustermann", IssuerId, IssuerKeyId, Pool, status: null,
                TestContext.CancellationToken, rawStatusObject).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        return await PresentAsync(
            app, verifierKeys, walletClient, DcqlFixtures.PidFamilyNamePrepared(), nonce).ConfigureAwait(false);
    }


    /// <summary>
    /// "1. Check for the existence of a status claim, check for the existence of a status_list claim within
    /// the status claim and validate that the content of status_list adheres to the rules defined in Section
    /// 6.2 for JOSE-based Referenced Tokens" — a <c>status_list</c> naming a relative <c>uri</c> does not
    /// adhere to Section 6.2's "The value of uri MUST be a URI conforming to [RFC3986]", so the presentation
    /// is refused as malformed rather than degraded to "not referenced".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task AStatusListReferenceWithARelativeUriIsRefusedAsMalformed()
    {
        int resolverCalls = 0;
        Verifiable.Core.StatusList.ResolveVerifiedStatusListTokenDelegate countingResolver = (context, cancellationToken) =>
        {
            resolverCalls++;

            return ValueTask.FromResult<ResolvedStatusListToken?>(null);
        };

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: countingResolver);

        var rawStatusObject = new Dictionary<string, object>
        {
            [StatusListJsonConstants.StatusList] = new Dictionary<string, object>
            {
                [StatusListJsonConstants.Index] = (long)CredentialIndex,
                [StatusListJsonConstants.Uri] = "/statuslists/1"
            }
        };

        (string parHandle, string? refusalDetail) = await PresentPidWithRawStatusAsync(
            app, rawStatusObject, "nonce-status-relative-uri").ConfigureAwait(false);

        Assert.IsNotNull(refusalDetail, "A malformed status_list reference is refused at the parse boundary.");
        Assert.Contains("status 400", refusalDetail!, StringComparison.Ordinal, "A malformed presentation answers HTTP 400, never 500.");
        Assert.Contains(OAuthErrors.InvalidRequest, refusalDetail!, StringComparison.Ordinal,
            "The refusal carries RFC 6749 Section 4.1.2.1's invalid_request error code.");

        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "A status_list reference that does not adhere to Section 6.2 is a malformed presentation, not an undeterminable status.");
        Assert.AreEqual(0, resolverCalls, "A malformed reference is refused before any Status List Token would be resolved.");
    }


    /// <summary>
    /// The same Section 6.2 refusal for a negative <c>idx</c>: "idx: REQUIRED. … MUST specify a non-negative
    /// Integer".
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token
    /// Status List, Section 6.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AStatusListReferenceWithANegativeIndexIsRefusedAsMalformed()
    {
        int resolverCalls = 0;
        Verifiable.Core.StatusList.ResolveVerifiedStatusListTokenDelegate countingResolver = (context, cancellationToken) =>
        {
            resolverCalls++;

            return ValueTask.FromResult<ResolvedStatusListToken?>(null);
        };

        await using TestHostShell app = new(TimeProvider, resolveVerifiedStatusListToken: countingResolver);

        var rawStatusObject = new Dictionary<string, object>
        {
            [StatusListJsonConstants.StatusList] = new Dictionary<string, object>
            {
                [StatusListJsonConstants.Index] = -1L,
                [StatusListJsonConstants.Uri] = "https://issuer.example/statuslists/1"
            }
        };

        (string parHandle, string? refusalDetail) = await PresentPidWithRawStatusAsync(
            app, rawStatusObject, "nonce-status-negative-idx").ConfigureAwait(false);

        Assert.IsNotNull(refusalDetail, "A malformed status_list reference is refused at the parse boundary.");
        Assert.Contains("status 400", refusalDetail!, StringComparison.Ordinal, "A malformed presentation answers HTTP 400, never 500.");

        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "A negative idx does not adhere to Section 6.2, so the presentation is refused as malformed.");
        Assert.AreEqual(0, resolverCalls, "A malformed reference is refused before any Status List Token would be resolved.");
    }


    /// <summary>
    /// A <c>status</c> object naming only an unmodelled mechanism — no <c>status_list</c> member at all —
    /// leaves the Verifier unable to make any statement: "If any of these checks fails, no statement about
    /// the status of the Referenced Token can be made and the Referenced Token SHOULD be rejected."
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>. SHOULD, not MUST, is what lets a Relying Party that evaluates the named
    /// mechanism out of band ask for it to be surfaced instead
    /// (<see cref="Verifiable.Core.StatusList.UnsupportedStatusMechanismDisposition.Surface"/>); this proves
    /// that choice's behaviour — the presentation completes, no status outcome is recorded because none was
    /// read, and no Status List Token is ever fetched.
    /// </summary>
    [TestMethod]
    public async Task AStatusObjectNamingOnlyAnUnmodelledMechanismIsNotCheckedWhenSurfacingIsChosen()
    {
        int resolverCalls = 0;
        Verifiable.Core.StatusList.ResolveVerifiedStatusListTokenDelegate countingResolver = (context, cancellationToken) =>
        {
            resolverCalls++;

            return ValueTask.FromResult<ResolvedStatusListToken?>(null);
        };

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: countingResolver,
            unsupportedStatusMechanisms: Verifiable.Core.StatusList.UnsupportedStatusMechanismDisposition.Surface);

        var rawStatusObject = new Dictionary<string, object>
        {
            ["other_mechanism"] = new Dictionary<string, object> { ["uri"] = "https://issuer.example/other" }
        };

        (string parHandle, string? refusalDetail) = await PresentPidWithRawStatusAsync(
            app, rawStatusObject, "nonce-status-unmodelled").ConfigureAwait(false);

        Assert.IsNull(refusalDetail, "Surfacing an unevaluable status mechanism completes the presentation instead of refusing it.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State);

        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;
        Assert.IsNull(verified.CredentialStatuses, "A credential with no status_list reference carries no status outcome to surface.");
        Assert.AreEqual(0, resolverCalls, "No status_list reference means no Status List Token is ever resolved.");
    }


    /// <summary>
    /// Registers a Verifier client on <paramref name="app"/>, mints a PID referencing
    /// <paramref name="statusListUri"/> at <see cref="CredentialIndex"/>, and drives one full cross-device
    /// presentation of it.
    /// </summary>
    /// <param name="app">The Verifier host shell.</param>
    /// <param name="statusListUri">The Status List Token URI the credential's status claim carries.</param>
    /// <param name="nonce">The transaction nonce binding the presentation to this request.</param>
    /// <returns>The flow's external handle, and the Wallet-side detail of a non-200 Response URI answer.</returns>
    private async Task<(string ParHandle, string? RefusalDetail)> PresentPidReferencingAsync(
        TestHostShell app, string statusListUri, string nonce)
    {
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidAsync(new StatusListReference(CredentialIndex, statusListUri)).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        return await PresentAsync(
            app, verifierKeys, walletClient, DcqlFixtures.PidFamilyNamePrepared(), nonce).ConfigureAwait(false);
    }


    /// <summary>
    /// Registers a Verifier client on <paramref name="app"/> and drives one full cross-device
    /// presentation of an already-minted PID, in the same shape <see cref="PresentPidReferencingAsync"/>
    /// drives — split out so a caller that must mint the credential itself (to read the issuer key
    /// before presenting, as the Section 11.3 same-key tests do) still shares the registration, trust
    /// and wallet-client wiring rather than re-deriving it.
    /// </summary>
    /// <param name="app">The Verifier host shell.</param>
    /// <param name="serializedSdJwt">The already-minted, stored credential the wallet presents.</param>
    /// <param name="holderPrivateKey">The holder key the credential's <c>cnf</c> binds to.</param>
    /// <param name="issuerPublicKey">The credential issuer's public key, registered as trusted.</param>
    /// <param name="nonce">The transaction nonce binding the presentation to this request.</param>
    /// <returns>The flow's external handle, and the Wallet-side detail of a non-200 Response URI answer.</returns>
    private async Task<(string ParHandle, string? RefusalDetail)> PresentMintedPidAsync(
        TestHostShell app,
        string serializedSdJwt,
        PrivateKeyMemory holderPrivateKey,
        PublicKeyMemory issuerPublicKey,
        string nonce)
    {
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        app.RegisterIssuerTrust(IssuerId, issuerPublicKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderPrivateKey, TestContext.CancellationToken).ConfigureAwait(false);

        return await PresentAsync(
            app, verifierKeys, walletClient, DcqlFixtures.PidFamilyNamePrepared(), nonce).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives one full cross-device presentation over the in-process listener: the Verifier's PAR, the Wallet's JAR
    /// fetch, and the Wallet's Authorization Response POST to the Response URI.
    /// </summary>
    /// <param name="app">The Verifier host shell.</param>
    /// <param name="verifierKeys">The Verifier's registered key material.</param>
    /// <param name="walletClient">The Wallet driving the presentation.</param>
    /// <param name="query">The DCQL query the Authorization Request carries.</param>
    /// <param name="nonce">The transaction nonce binding the presentation to this request.</param>
    /// <returns>
    /// The flow's external handle, and the Wallet-side detail of a non-200 answer from the Response URI when the
    /// Verifier refused the presentation.
    /// </returns>
    private async Task<(string ParHandle, string? RefusalDetail)> PresentAsync(
        TestHostShell app,
        VerifierKeyMaterial verifierKeys,
        Oid4VpWalletClient walletClient,
        PreparedDcqlQuery query,
        string nonce)
    {
        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce(nonce),
            query,
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        string? refusalDetail = null;
        try
        {
            _ = await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                    FlowId = $"wallet-{nonce}-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(InvalidOperationException exception)
        {
            //The Response URI answered a non-200; the Wallet client raises the status and body it read.
            refusalDetail = exception.Message;
        }

        return (parHandle, refusalDetail);
    }


    /// <summary>
    /// Asserts the shared shape of a status the Verifier could not determine: HTTP 400 carrying RFC 6749
    /// Section 4.1.2.1's <c>invalid_request</c> and its one generic sentence, and a failed flow state whose typed
    /// refusal names the undeterminable status without a relying-party policy decision behind it.
    /// </summary>
    /// <param name="app">The Verifier host shell.</param>
    /// <param name="parHandle">The flow's external handle.</param>
    /// <param name="refusalDetail">The Wallet-side detail of the Response URI's non-200 answer.</param>
    private static void AssertUndeterminableOnTheWire(TestHostShell app, string parHandle, string? refusalDetail)
    {
        Assert.IsNotNull(refusalDetail,
            "The Response URI answered the refused presentation with a non-200, which the Wallet client raises.");
        Assert.Contains("status 400", refusalDetail!, StringComparison.Ordinal,
            "A credential whose status the verifier cannot determine answers HTTP 400, never 500.");
        Assert.Contains(OAuthErrors.InvalidRequest, refusalDetail!, StringComparison.Ordinal,
            "The real-wire refusal body carries RFC 6749 Section 4.1.2.1's invalid_request error code.");

        Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
            "An undeterminable credential status fails closed, so the verifier refuses the presentation.");

        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;
        Assert.AreEqual(VerifierFlowRefusalKind.StatusUndeterminable, failed.Refusal!.Value.Kind,
            "No statement about the status could be made, which is the verifier's own rejection.");
        Assert.AreEqual("The presentation's credential status could not be determined.", failed.Refusal!.Value.Description,
            "The wire carries one fixed, generic sentence for the refusal kind.");
        Assert.IsNull(failed.CredentialStatusRefusal,
            "The typed credential-status refusal is a policy's product; an undeterminable status carries none.");
    }


    /// <summary>
    /// Wraps a <see cref="ResolveVerifiedStatusListTokenDelegate"/> so a test owns the pooled
    /// <see cref="StatusListType"/> every resolution mints off the wire, counts the resolutions, and can report a
    /// resolution as having been made earlier than it was — the caching relying party Section 8.3 step 4.d
    /// describes, expressed as a decorator rather than a second resolver.
    /// </summary>
    /// <param name="inner">The resolver whose answers are recorded and re-stamped.</param>
    /// <param name="resolvedAtShift">How far back the reported resolution instant is moved.</param>
    private sealed class RecordedStatusListResolution(
        ResolveVerifiedStatusListTokenDelegate inner, TimeSpan resolvedAtShift): IDisposable
    {
        /// <summary>The tokens this decorator has seen, each owning a pooled Status List it must release.</summary>
        private List<StatusListToken> ResolvedTokens { get; } = [];

        /// <summary>How many Status List Tokens the wrapped resolver has handed back.</summary>
        public int ResolutionCount => ResolvedTokens.Count;

        /// <summary>The resolver a host is built with.</summary>
        public ResolveVerifiedStatusListTokenDelegate Resolve => async (context, cancellationToken) =>
        {
            ResolvedStatusListToken? resolved = await inner(context, cancellationToken).ConfigureAwait(false);
            if(resolved is null)
            {
                return null;
            }

            ResolvedTokens.Add(resolved.Token);

            return new ResolvedStatusListToken
            {
                Token = resolved.Token,
                ResolvedAt = resolved.ResolvedAt - resolvedAtShift,
                IsTokenOwned = resolved.IsTokenOwned
            };
        };

        /// <summary>Releases every pooled Status List this decorator recorded.</summary>
        public void Dispose()
        {
            foreach(StatusListToken token in ResolvedTokens)
            {
                token.StatusList.Dispose();
            }

            ResolvedTokens.Clear();
        }
    }
}
