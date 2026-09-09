using System;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth.StatusList;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Tests for <see cref="StatusListTokenResolvers.BuildResolving"/> — the composition of the Section
/// 8.1/8.2 fetch with the Section 5.1 read that a Relying Party wires as its
/// <see cref="ResolveVerifiedStatusListTokenDelegate"/>. Steps 2 and 3 of the status procedure live here
/// ("Resolve the Status List Token from the provided URI" and the JWT's own validity), and everything the
/// composition cannot establish is one outcome: no verified Status List Token, so "no statement about the
/// status of the Referenced Token can be made". A Status List Token reached through an SD-JWT VC's
/// <c>status</c> claim is a JWT-format token only — "When the status claim is present and using the
/// status_list mechanism, the associated Status List Token MUST be in JWT format."
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
/// Status List, Section 8.3</see> and
/// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-18.html#section-4.2.2.2">SD-JWT
/// VC, the status claim</see>.
/// </summary>
[TestClass]
internal sealed class StatusListTokenResolversTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The Status List Token URL the scripted Status Provider publishes at.</summary>
    private const string ListUrl = StatusListTestConstants.ExampleTokenSubject;

    /// <summary>The JWT-format media type, from Section 8.1's list of media types.</summary>
    private const string StatusListJwtMediaType = "application/statuslist+jwt";

    /// <summary>The CWT-format media type, from Section 8.1's list of media types.</summary>
    private const string StatusListCwtMediaType = "application/statuslist+cwt";

    /// <summary>The Section 5.1 header parameter naming the token's type.</summary>
    private const string TypeHeaderParameter = "typ";

    /// <summary>The header parameter naming the signing key, as in Section 5.1's example header.</summary>
    private const string KeyIdHeaderParameter = "kid";

    /// <summary>The <c>typ</c> value a Status List Token in JWT format carries.</summary>
    private const string StatusListJwtType = "statuslist+jwt";

    /// <summary>The bit-array capacity of the published Status List.</summary>
    private const int Capacity = 16;

    /// <summary>The revoked index inside the published Status List.</summary>
    private const int RevokedIndex = 3;

    /// <summary>An untouched, still-valid index inside the published Status List.</summary>
    private const int ValidIndex = 7;

    /// <summary>The issuer signing key's identifier, carried as the Status List Token's <c>kid</c>.</summary>
    private const string KeyId = "https://issuer.example/statuslist#key-1";

    /// <summary>How far the clock moves between building the resolver and calling it.</summary>
    private static TimeSpan FetchDelay => TimeSpan.FromMinutes(5);


    /// <summary>The memory pool every pooled carrier in this class is rented from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// A resolution is "Resolve the Status List Token from the provided URI" (step 2) followed by the
    /// Section 5.1 read of what came back, so what the caller receives is the Status Provider's own token —
    /// its subject, its issuance instant, and the very bits it published — stamped with the instant the
    /// resolution was made, which is what makes step 4.d's "ttl … maximum amount of time … that the Status
    /// List Token can be cached by a consumer before a fresh copy SHOULD be retrieved" answerable at all.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Section
    /// 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task AResolutionCarriesThePublishedTokenAndTheInstantItWasMade()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        FakeTimeProvider clock = new(TestClock.CanonicalEpoch);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), clock);

        clock.Advance(FetchDelay);

        ResolvedStatusListToken? resolved = await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(resolved, "A published, conforming Status List Token resolves.");

        using StatusListType fetched = resolved.Token.StatusList;

        Assert.AreEqual(ListUrl, resolved.Token.Subject,
            "The resolved token's sub is the uri it was published at, as Section 5.1 requires.");
        Assert.AreEqual(TestClock.CanonicalEpoch, resolved.Token.IssuedAt,
            "The resolved token's iat is the instant the Status Issuer issued it, not the instant it was fetched.");
        Assert.AreEqual(StatusListBitSize.OneBit, fetched.BitSize, "The published list's bits survive the resolution.");
        Assert.AreEqual(StatusTypes.Invalid, fetched[RevokedIndex], "The published revoked index reads back as revoked.");
        Assert.AreEqual(StatusTypes.Valid, fetched[ValidIndex], "An untouched published index reads back as valid.");
        Assert.AreEqual(TestClock.CanonicalEpoch + FetchDelay, resolved.ResolvedAt,
            "The resolution reports the instant the fetch was made, read from the caller's clock at that moment.");
    }


    /// <summary>
    /// Which key verifies a Status List Token is the Relying Party's own trust decision, and Section 5.1's
    /// example header shows what it has to decide from: <c>{"alg":"ES256","kid":"12","typ":"statuslist+jwt"}</c>
    /// beside the uri the token was fetched for — "The sub (subject) claim MUST specify the URI of the Status
    /// List Token. The value MUST be equal to that of the uri claim contained in the status_list claim of the
    /// Referenced Token." Both reach the application's key resolver, before any signature has been checked.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task TheFetchedUriAndTheProtectedHeaderReachTheIssuerKeyResolver()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        string? offeredUri = null;
        string? offeredType = null;
        string? offeredKeyId = null;
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (context, cancellationToken) =>
        {
            offeredUri = context.StatusListUri;
            offeredType = context.Header.TryGetValue(TypeHeaderParameter, out object? type) ? type as string : null;
            offeredKeyId = context.Header.TryGetValue(KeyIdHeaderParameter, out object? keyId) ? keyId as string : null;

            return ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(issuerPublic));
        };

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolvedStatusListToken? resolved = await ResolverOver(transport.Delegate, resolveIssuerKey, Clock())(
            ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(resolved, "The key resolver answered, so the token resolves.");

        using StatusListType fetched = resolved.Token.StatusList;

        Assert.AreEqual(ListUrl, offeredUri, "The uri the token was fetched for is what the key resolver keys its trust on.");
        Assert.AreEqual(StatusListJwtType, offeredType, "The protected header offered names the token's type.");
        Assert.AreEqual(KeyId, offeredKeyId, "The protected header offered names the signing key, as Section 5.1's example header does.");
    }


    /// <summary>
    /// The uri a Status List Token is fetched from arrives inside a token minted by someone else, so a target
    /// the Relying Party's outbound policy refuses is a uri no verified Status List Token can be obtained for
    /// — "If any of these checks fails, no statement about the status of the Referenced Token can be made and
    /// the Referenced Token SHOULD be rejected" — and the refusal names the uri rather than escaping as an
    /// unclassified fault.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ARefusedTargetIsAResolutionFailureNamingTheUri()
    {
        const string refusedUrl = "http://example.com/statuslists/1";

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(refusedUrl, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        ScriptedOutboundTransport transport = Serving(refusedUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(refusedUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(refusedUrl, caught.Uri, "The resolution failure names the uri no verified token could be obtained for.");
        Assert.IsEmpty(transport.Calls, "A refused target MUST NOT be contacted.");
    }


    /// <summary>
    /// "A successful response that contains a Status List Token MUST use an HTTP status code in the 2xx
    /// range." — an answer outside it carried no Status List Token, so the resolution failed.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AnUnsuccessfulStatusIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        ScriptedOutboundTransport transport = new(new() { [ListUrl] = ScriptedOutboundResponse.WithStatus(404) });
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri that answered outside the 2xx range.");
    }


    /// <summary>
    /// "When the status claim is present and using the status_list mechanism, the associated Status List Token
    /// MUST be in JWT format." A Status Provider answering with "application/statuslist+cwt" has answered a
    /// different format than the one an SD-JWT VC's status reference may be resolved through, so the
    /// resolution fails rather than silently falling back to the CWT read.
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-18.html#section-4.2.2.2">SD-JWT
    /// VC, the status claim</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task ACwtAnswerToAJwtResolutionIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListCwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri that answered in the other format.");
    }


    /// <summary>
    /// A Status Provider that cannot be reached leaves the Relying Party with no Status List Token, which is
    /// the same "no statement about the status of the Referenced Token can be made" outcome every other
    /// resolution failure is — reported as a resolution failure, not as a transport exception the seat above
    /// would have to know about.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task ATransportFailureIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        OutboundTransportDelegate failing = (request, context, cancellationToken) =>
            throw new InvalidOperationException("The Status Provider refused the connection.");
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(failing, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri that could not be reached.");
    }


    /// <summary>
    /// "The JWT MUST be secured using a cryptographic signature or MAC algorithm. Relying Parties MUST reject
    /// JWTs with an invalid signature." A Relying Party that trusts no key for the uri cannot check that
    /// signature at all, so the token is unverifiable and the resolution fails rather than handing back an
    /// unchecked list.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task AnUnresolvedIssuerKeyIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(null), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri no trusted key could be found for.");
    }


    /// <summary>
    /// "Relying Parties MUST reject JWTs with an invalid signature." A Status List Token signed by a key other
    /// than the one the Relying Party trusts for the uri does not verify, so no status may be read from it.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ASignatureFromAnotherKeyIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> trustedKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory trustedPublic = trustedKeys.PublicKey;
        using PrivateKeyMemory trustedPrivate = trustedKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> otherKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory otherPublic = otherKeys.PublicKey;
        using PrivateKeyMemory otherPrivate = otherKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, otherPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(trustedPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri whose token did not verify.");
    }


    /// <summary>
    /// "typ: REQUIRED. The JWT type MUST be statuslist+jwt." A JWT typed as anything else is not a Status List
    /// Token, however well it verifies, so the resolution fails on the type before its claims mean anything.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see> and
    /// <see href="https://www.rfc-editor.org/rfc/rfc7519#section-5.1">RFC 7519, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task AJwtTypedAsSomethingElseIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        JwtPayload payload = StatusListTokenClaims.ToPayload(token, TestSetup.Base64UrlEncoder);
        string compactJws = await SignCompactAsync(payload, issuerPrivate, "jwt", TestContext.CancellationToken).ConfigureAwait(false);

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri that answered with a JWT of another type.");
    }


    /// <summary>
    /// "sub: REQUIRED." / "iat: REQUIRED." / "status_list: REQUIRED." — a Status List Token missing any one of
    /// them fails Section 8.3's step 3.b, "Check for the existence of the required claims", so no status may be
    /// read from it.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section
    /// 8.3</see>.
    /// </summary>
    /// <param name="claim">The REQUIRED claim withheld from the otherwise valid token.</param>
    [TestMethod]
    [DataRow("sub")]
    [DataRow("iat")]
    [DataRow("status_list")]
    public async Task AMissingRequiredClaimIsAResolutionFailureNamingTheUri(string claim)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        JwtPayload payload = StatusListTokenClaims.ToPayload(token, TestSetup.Base64UrlEncoder);
        Assert.IsTrue(payload.Remove(claim), $"The composed claims set carries '{claim}' before it is withheld.");

        string compactJws = await SignCompactAsync(payload, issuerPrivate, StatusListJwtType, TestContext.CancellationToken).ConfigureAwait(false);
        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, $"The resolution failure names the uri whose token withheld '{claim}'.");
    }


    /// <summary>
    /// "The sub (subject) claim MUST specify the URI of the Status List Token. The value MUST be equal to that
    /// of the uri claim contained in the status_list claim of the Referenced Token." A token served at one uri
    /// but claiming another is a list for something else, so it may not be read for the credential that
    /// pointed here.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-5.1">Token
    /// Status List, Section 5.1</see>.
    /// </summary>
    [TestMethod]
    public async Task ASubjectOtherThanTheFetchedUriIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(StatusListTestConstants.MismatchedSubject, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri the token was fetched for, not the sub it claimed.");
    }


    /// <summary>
    /// "The default Status List request and response mechanism uses HTTP semantics", and the HTTP is the
    /// application's: every request the resolution makes goes through the transport the caller handed in, as an
    /// HTTP GET negotiating the JWT format's media type, so a deployment keeps its own pinning, proxying and
    /// policing rather than having a client opened underneath it.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.1">Token
    /// Status List, Section 8.1</see>.
    /// </summary>
    [TestMethod]
    public async Task EveryRequestTheResolutionMakesGoesThroughTheCallersTransport()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        ResolvedStatusListToken? first = await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false);
        ResolvedStatusListToken? second = await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(first, "The first resolution succeeded.");
        Assert.IsNotNull(second, "The second resolution succeeded.");

        using StatusListType firstList = first.Token.StatusList;
        using StatusListType secondList = second.Token.StatusList;

        Assert.HasCount(2, transport.Calls, "Both resolutions were made through the caller's transport and nothing else.");
        Assert.AreEqual("GET", transport.Calls[0].Method, "The Status Provider is asked with an HTTP GET.");
        Assert.AreEqual(new Uri(ListUrl), transport.Calls[0].Target, "The request goes to the uri being resolved.");
        Assert.AreEqual(StatusListJwtMediaType, transport.Calls[0].Headers.Accept,
            "The JWT format's media type is what the resolution negotiates for.");
    }


    /// <summary>
    /// A resolution that fetches fresh on every call owns the pooled Status List it mints: nothing else
    /// holds a reference to it, so <see cref="CredentialStatusGate.CheckAsync"/> is the only thing that
    /// releases it. <see cref="StatusListTokenResolvers.BuildResolving"/> always fetches fresh, so every
    /// resolution it returns MUST declare ownership.
    /// </summary>
    [TestMethod]
    public async Task AResolutionIsOwned()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        using ResolvedStatusListToken? resolved = await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(resolved);
        Assert.IsTrue(resolved.IsTokenOwned, "A per-call fetch-and-verify resolution mints a Status List nothing else references, so it must be owned.");
    }


    /// <summary>
    /// "In the case of "application/statuslist+jwt", the response MUST be of type JWT" — the body it carries is
    /// "the JWS Compact Serialization form", so a Status Provider that answers 2xx with no body at all handed
    /// back no token to read.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see>.
    /// </summary>
    [TestMethod]
    public async Task AnEmptyBodyIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, string.Empty);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri that answered with no body.");
    }


    /// <summary>
    /// <see cref="Core.OutboundFetch.OutboundRequest.MaxResponseBytes"/>'s own doc: the transport MAY ignore
    /// the hint, so a response body over the bound is re-checked once the fetch returns rather than trusted to
    /// have been enforced upstream.
    /// </summary>
    [TestMethod]
    public async Task ABodyOverTheBoundIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = StatusListTokenResolvers.BuildResolving(
            transport.Delegate,
            TestHostShell.ExchangeContextWith(OutboundFetchPolicy.SecureDefault),
            KeyOf(issuerPublic),
            TestSetup.Base64UrlDecoder,
            JwtPartJson.Default,
            Pool,
            Clock(),
            maxResponseBytes: compactJws.Length - 1);

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri whose answer exceeded the configured bound.");
    }


    /// <summary>
    /// RFC 7515 §7.1: the JWS Compact Serialization is base64url segments joined by <c>'.'</c>, entirely
    /// within the ASCII range — a byte outside it is never silently mapped to <c>'?'</c> and read on as if it
    /// were part of the token.
    /// </summary>
    [TestMethod]
    public async Task ANonAsciiByteInTheBodyIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;

        ScriptedOutboundTransport transport = new(new()
        {
            [ListUrl] = ScriptedOutboundResponse.WithBody(
                200,
                HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, StatusListJwtMediaType)),
                new TaggedMemory<byte>([0x61, 0x2E, 0x62, 0x2E, 0xFF], Tag.Empty))
        });
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri whose answer carried a non-ASCII byte.");
    }


    /// <summary>
    /// A served <c>lst</c> that is not a ZLIB stream is unreadable, and Section 8.3's closing SHOULD makes
    /// that a resolution failure like any other — never the raw <see cref="System.IO.InvalidDataException"/>
    /// the decompressor itself raises.
    /// </summary>
    [TestMethod]
    public async Task AServedTokenWhoseListIsNotZlibIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        JwtPayload payload = StatusListTokenClaims.ToPayload(token, TestSetup.Base64UrlEncoder);
        var statusListClaim = (Dictionary<string, object>)payload[WellKnownJwtClaimNames.StatusList];
        statusListClaim[StatusListMemberNames.List] = TestSetup.Base64UrlEncoder([0x00, 0x01, 0x02, 0x03]);

        string compactJws = await SignCompactAsync(payload, issuerPrivate, StatusListJwtType, TestContext.CancellationToken).ConfigureAwait(false);
        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri whose token's lst was not a ZLIB stream.");
    }


    /// <summary>
    /// A served <c>lst</c> engineered to inflate past <see cref="StatusListType.DefaultMaxDecompressedByteCount"/>
    /// — a remote decompression bomb — is a resolution failure like any other malformed <c>lst</c>, never an
    /// unbounded allocation.
    /// </summary>
    [TestMethod]
    public async Task AServedTokenWhoseListInflatesPastTheCeilingIsAResolutionFailureNamingTheUri()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        JwtPayload payload = StatusListTokenClaims.ToPayload(token, TestSetup.Base64UrlEncoder);
        var statusListClaim = (Dictionary<string, object>)payload[WellKnownJwtClaimNames.StatusList];
        statusListClaim[StatusListMemberNames.List] = TestSetup.Base64UrlEncoder(CompressedZeros(StatusListType.DefaultMaxDecompressedByteCount + 1024));

        string compactJws = await SignCompactAsync(payload, issuerPrivate, StatusListJwtType, TestContext.CancellationToken).ConfigureAwait(false);
        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(transport.Delegate, KeyOf(issuerPublic), Clock());

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(ContextFor(ListUrl), TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri, "The resolution failure names the uri whose token's lst inflated past the ceiling.");
    }


    /// <summary>
    /// "2.  Resolve the Status List Token from the provided URI" and "3. a. … This step might require the
    /// resolution of a public key as described in Section 11.3." are the two steps this composition performs,
    /// and both read the Referenced Token's own facts out of the resolution it is handed: the fetch goes to
    /// the <c>uri</c> the credential's <c>status_list</c> claim named, and the key decision behind the seam is
    /// told the Referenced Token's verified issuer and the very key its issuer signature verified under — the
    /// inputs Section 11.3's recommendations are stated in terms of, which a resolver would otherwise have to
    /// replace with an inference from the list URI's authority.
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Section 11.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TheReferencedTokensIssuerAndKeyReachTheIssuerKeyResolver()
    {
        const string referencedTokenIssuer = "https://issuer.example/pid";

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> referencedTokenKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory referencedTokenIssuerKey = referencedTokenKeys.PublicKey;
        using PrivateKeyMemory unusedReferencedTokenPrivate = referencedTokenKeys.PrivateKey;

        using StatusListType published = PublishedList();
        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);
        string compactJws = await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);

        (ResolveStatusListIssuerKeyDelegate resolveIssuerKey, IReadOnlyList<StatusListKeyResolutionContext> seen) =
            StatusListFixtures.RecordingKeyResolverFor(KeyOf(issuerPublic));

        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);
        ResolvedStatusListToken? resolved = await ResolverOver(transport.Delegate, resolveIssuerKey, Clock())(
            StatusListFixtures.ContextFor(new StatusListReference(RevokedIndex, ListUrl), referencedTokenIssuer, referencedTokenIssuerKey),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(resolved, "The key resolver answered, so the token resolves.");

        using StatusListType fetched = resolved.Token.StatusList;

        Assert.HasCount(1, transport.Calls, "Step 2 resolves the Status List Token from the provided URI once.");
        Assert.AreEqual(ListUrl, transport.Calls[0].Target.AbsoluteUri,
            "The uri the fetch goes to is the one the Referenced Token's status_list claim named, not one the composition chose.");
        Assert.HasCount(1, seen, "The composition asks for the Status Issuer's key exactly once.");
        Assert.AreEqual(ListUrl, seen[0].StatusListUri,
            "The key decision is keyed on the same uri the fetch used, which step 4.a compares the verified sub against.");
        Assert.AreEqual(referencedTokenIssuer, seen[0].ReferencedTokenIssuer,
            "Section 11.3's web-based alternative resolves on the Referenced Token's issuer, so the composition threads it through.");
        Assert.AreSame(referencedTokenIssuerKey, seen[0].ReferencedTokenIssuerKey,
            "Section 11.3's same-key recommendation answers the Referenced Token's own key, so the composition lends that very carrier.");
    }


    /// <summary>
    /// Builds a ZLIB-compressed run of <paramref name="decompressedByteCount"/> zero bytes — cheap to
    /// construct and highly compressible, the same decompression-bomb shape a hostile Status Provider
    /// would publish.
    /// </summary>
    /// <param name="decompressedByteCount">How many zero bytes the compressed stream inflates to.</param>
    /// <returns>The compressed bytes.</returns>
    private static byte[] CompressedZeros(int decompressedByteCount)
    {
        using var output = new System.IO.MemoryStream();
        using(var zlib = new System.IO.Compression.ZLibStream(output, System.IO.Compression.CompressionLevel.SmallestSize, leaveOpen: true))
        {
            zlib.Write(new byte[decompressedByteCount]);
        }

        return output.ToArray();
    }


    /// <summary>
    /// The one-bit Status List this class's Status Provider publishes, with <see cref="RevokedIndex"/> marked
    /// invalid and <see cref="ValidIndex"/> left untouched. The caller owns the returned pooled list.
    /// </summary>
    /// <returns>The published Status List.</returns>
    private static StatusListType PublishedList()
    {
        StatusListType statusList = StatusListType.Create(Capacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[RevokedIndex] = StatusTypes.Invalid;

        return statusList;
    }


    /// <summary>A clock reading the suite's canonical instant.</summary>
    /// <returns>The clock the resolution stamps its instant from.</returns>
    private static FakeTimeProvider Clock() => new(TestClock.CanonicalEpoch);


    /// <summary>
    /// A scripted Status Provider publishing <paramref name="compactJws"/> at <paramref name="url"/> with
    /// <paramref name="contentType"/>, the Section 8.2 response shape ("The body of such an HTTP response
    /// contains the raw Status List Token").
    /// </summary>
    /// <param name="url">The absolute URL the Status List Token is published at.</param>
    /// <param name="contentType">The <c>Content-Type</c> the answer carries.</param>
    /// <param name="compactJws">The compact-serialized Status List Token to serve.</param>
    /// <returns>The scripted transport.</returns>
    private static ScriptedOutboundTransport Serving(string url, string contentType, string compactJws) =>
        new(new()
        {
            [url] = ScriptedOutboundResponse.WithBody(
                200,
                HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, contentType)),
                new TaggedMemory<byte>(Encoding.ASCII.GetBytes(compactJws), Tag.Empty))
        });


    /// <summary>
    /// The JWT-format resolution composed over <paramref name="transport"/> and
    /// <paramref name="resolveIssuerKey"/>, under the secure outbound default.
    /// </summary>
    /// <param name="transport">The caller's single-hop transport.</param>
    /// <param name="resolveIssuerKey">The Relying Party's trust decision about the Status Issuer's key.</param>
    /// <param name="timeProvider">The clock the resolution instant is read from.</param>
    /// <returns>The resolve delegate under test.</returns>
    private static ResolveVerifiedStatusListTokenDelegate ResolverOver(
        OutboundTransportDelegate transport,
        ResolveStatusListIssuerKeyDelegate resolveIssuerKey,
        TimeProvider timeProvider) =>
        StatusListTokenResolvers.BuildResolving(
            transport,
            TestHostShell.ExchangeContextWith(OutboundFetchPolicy.SecureDefault),
            resolveIssuerKey,
            TestSetup.Base64UrlDecoder,
            JwtPartJson.Default,
            Pool,
            timeProvider);


    /// <summary>
    /// A Relying Party that trusts exactly <paramref name="key"/> for every Status List Token uri, or trusts
    /// no key at all when it is <see langword="null"/>.
    /// </summary>
    /// <param name="key">The trusted Status Issuer key, or <see langword="null"/> for no trusted key.</param>
    /// <returns>The issuer-key resolver.</returns>
    private static ResolveStatusListIssuerKeyDelegate KeyOf(PublicKeyMemory? key) =>
        (context, cancellationToken) => ValueTask.FromResult(
            key is null ? null : ResolvedStatusListIssuerKey.Borrowed(key));


    /// <summary>
    /// The resolution context a resolve call carries for a token published at <paramref name="url"/>, at the
    /// published list's revoked index.
    /// </summary>
    /// <param name="url">The uri the Status List Token is resolved for.</param>
    /// <returns>The resolution context.</returns>
    private static StatusListResolutionContext ContextFor(string url) =>
        StatusListFixtures.ContextFor(RevokedIndex, url);


    /// <summary>
    /// Signs <paramref name="payload"/> into a compact JWS whose protected header carries
    /// <paramref name="tokenType"/> as <c>typ</c> — the hand-built wire artifact the read cases need, composed
    /// straight over the signing seams rather than through the Status List Token composition, so what is read
    /// is never merely what that composition happened to write.
    /// </summary>
    /// <param name="payload">The claims set to sign.</param>
    /// <param name="signingKey">The key to sign with.</param>
    /// <param name="tokenType">The <c>typ</c> header parameter value.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact JWS.</returns>
    private static async Task<string> SignCompactAsync(
        JwtPayload payload, PrivateKeyMemory signingKey, string tokenType, CancellationToken cancellationToken)
    {
        UnsignedJwt unsigned = UnsignedJwt.ForSigning(signingKey, KeyId, payload, tokenType);

        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            JwtClaimsJson.HeaderSerializer,
            JwtClaimsJson.PayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }
}
