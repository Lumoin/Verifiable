using System;
using System.Collections.Generic;
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
/// Tests for <see cref="StatusListIssuerKeys"/> — the shipped composition of
/// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Token Status
/// List, Section 11.3</see>'s first key-resolution recommendation: "If the Issuer of the Referenced Token is
/// the same entity as the Status Issuer, then the same key that is embedded into the Referenced Token may be
/// used for the Status List Token." The section's second recommendation — "Alternatively, the Status Issuer
/// may use the same web-based key resolution that is used for the Referenced Token." — is an application's own
/// resolution and stays its delegate, which is what this composition falls back to.
/// </summary>
/// <remarks>
/// The recommendation is a MAY, so what the composition must never do is widen what verifies: an ecosystem
/// whose Status Issuer signs with a different key fails closed under it, which the resolution cases here drive
/// end to end through <see cref="StatusListTokenResolvers.BuildResolving"/> rather than asserting on the
/// delegate's answer alone.
/// </remarks>
[TestClass]
internal sealed class StatusListIssuerKeysTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The Status List Token URL the scripted Status Provider publishes at.</summary>
    private const string ListUrl = StatusListTestConstants.ExampleTokenSubject;

    /// <summary>The JWT-format media type, from Section 8.1's list of media types.</summary>
    private const string StatusListJwtMediaType = "application/statuslist+jwt";

    /// <summary>The <c>typ</c> value a Status List Token in JWT format carries.</summary>
    private const string StatusListJwtType = "statuslist+jwt";

    /// <summary>The Status Issuer's key identifier, carried as the Status List Token's <c>kid</c>.</summary>
    private const string KeyId = "https://issuer.example/statuslist#key-1";

    /// <summary>The Referenced Token's verified issuer identifier.</summary>
    private const string ReferencedTokenIssuer = "https://issuer.example/pid";

    /// <summary>The bit-array capacity of the published Status List.</summary>
    private const int Capacity = 16;

    /// <summary>The revoked index inside the published Status List.</summary>
    private const int RevokedIndex = 3;

    /// <summary>The memory pool every pooled carrier in this class is rented from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;


    /// <summary>
    /// "If the Issuer of the Referenced Token is the same entity as the Status Issuer, then the same key that
    /// is embedded into the Referenced Token may be used for the Status List Token." — the composition answers
    /// that key itself, and answers it BORROWED: the verifier seat that resolved it owns its lifetime for the
    /// whole flow step, so a verification that released it would return a buffer the seat still holds. The
    /// resolution's own disposal is therefore a no-op, which the pool's accounting is what shows.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Token
    /// Status List, Section 11.3</see>.
    /// </summary>
    [TestMethod]
    public async Task TheReferencedTokensKeyIsAnsweredAsABorrowedKey()
    {
        using var metered = new MeteredHousePool();

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> referencedTokenKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory referencedTokenIssuerKey = StatusListFixtures.BorrowedKeyOver(referencedTokenKeys.PublicKey, metered.Pool).Key;
        using PublicKeyMemory unusedSourcePublic = referencedTokenKeys.PublicKey;
        using PrivateKeyMemory unusedSourcePrivate = referencedTokenKeys.PrivateKey;

        ResolveStatusListIssuerKeyDelegate resolve = StatusListIssuerKeys.FromReferencedToken(NeverConsulted());

        ResolvedStatusListIssuerKey? answered = await resolve(
            KeyContextWith(referencedTokenIssuerKey), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(answered, "The context carries the Referenced Token's key, so Section 11.3's first recommendation has an answer.");
        Assert.AreSame(referencedTokenIssuerKey, answered.Key,
            "'the same key that is embedded into the Referenced Token' is answered as the very carrier the seat lent, not a copy of it.");
        Assert.IsFalse(answered.IsKeyOwned,
            "The seat owns the Referenced Token's key for the flow step, so the verification only borrows it.");

        answered.Dispose();

        Assert.AreEqual(1L, metered.OutstandingCount,
            "Disposing a borrowed resolution MUST leave the seat's own key carrier intact, since the seat is still holding it.");
        Assert.IsTrue(referencedTokenIssuerKey.AsReadOnlySpan().SequenceEqual(referencedTokenKeys.PublicKey.AsReadOnlySpan()),
            "The lent key is still readable after the resolution was disposed, which is what 'borrowed' means.");
    }


    /// <summary>
    /// "Alternatively, the Status Issuer may use the same web-based key resolution that is used for the
    /// Referenced Token." — the second recommendation is the application's own resolution, so a context with
    /// no Referenced Token key (one built before or without a verified credential) is handed to it verbatim,
    /// once, and whatever it answers is passed through: the composition adds a shortcut, it does not take
    /// the decision away.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Token
    /// Status List, Section 11.3</see>.
    /// </summary>
    [TestMethod]
    public async Task AContextWithoutTheReferencedTokensKeyDefersToTheSuppliedResolutionOnce()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> statusIssuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory statusIssuerPublic = statusIssuerKeys.PublicKey;
        using PrivateKeyMemory unusedStatusIssuerPrivate = statusIssuerKeys.PrivateKey;

        ResolvedStatusListIssuerKey fallbackAnswer = ResolvedStatusListIssuerKey.Borrowed(statusIssuerPublic);
        (ResolveStatusListIssuerKeyDelegate whenAbsent, IReadOnlyList<StatusListKeyResolutionContext> seen) =
            StatusListFixtures.RecordingKeyResolverFor((_, _) => ValueTask.FromResult<ResolvedStatusListIssuerKey?>(fallbackAnswer));

        ResolveStatusListIssuerKeyDelegate resolve = StatusListIssuerKeys.FromReferencedToken(whenAbsent);
        StatusListKeyResolutionContext context = KeyContextWith(referencedTokenIssuerKey: null);

        ResolvedStatusListIssuerKey? answered = await resolve(context, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, seen, "The application's own resolution is consulted exactly once for the one key decision.");
        Assert.AreSame(context, seen[0],
            "The application's resolution decides from the same context, including the Referenced Token's issuer its web-based resolution is keyed on.");
        Assert.AreSame(fallbackAnswer, answered,
            "The application's answer is passed through unchanged; the composition never substitutes its own.");
    }


    /// <summary>
    /// The composition is a fallback around another resolution, so there is no meaningful shape of it without
    /// one: a context built without a verified credential would otherwise leave the Status List Token with no
    /// key decision at all, which is a caller error rather than a wire answer.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Token
    /// Status List, Section 11.3</see>.
    /// </summary>
    [TestMethod]
    public void ACompositionWithoutAFallbackResolutionIsRefused()
    {
        _ = Assert.ThrowsExactly<ArgumentNullException>(() => StatusListIssuerKeys.FromReferencedToken(null!),
            "A composition with nothing to defer to when the Referenced Token's key is absent cannot answer at all.");
    }


    /// <summary>
    /// The whole point of the recommendation, end to end: a relying party that trusts the credential's issuer
    /// key already needs no separate Status Issuer key at all. A Status List Token the credential's own issuer
    /// signed verifies under the key the credential verified under — "the same key that is embedded into the
    /// Referenced Token may be used for the Status List Token" — so the resolution completes and the status is
    /// readable, with the application's own resolution never consulted.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Token
    /// Status List, Section 11.3</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task AStatusListTokenTheReferencedTokensIssuerSignedResolvesWithNoSeparateStatusIssuerKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> referencedTokenKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory referencedTokenIssuerKey = referencedTokenKeys.PublicKey;
        using PrivateKeyMemory referencedTokenIssuerPrivate = referencedTokenKeys.PrivateKey;

        string compactJws = await PublishedTokenSignedByAsync(referencedTokenIssuerPrivate).ConfigureAwait(false);
        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);

        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(
            transport.Delegate, StatusListIssuerKeys.FromReferencedToken(NeverConsulted()));

        ResolvedStatusListToken? resolved = await resolve(
            StatusListFixtures.ContextFor(new StatusListReference(RevokedIndex, ListUrl), ReferencedTokenIssuer, referencedTokenIssuerKey),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(resolved, "A Status List Token the Referenced Token's own issuer signed verifies under that same key.");

        using StatusListType fetched = resolved.Token.StatusList;

        Assert.AreEqual(StatusTypes.Invalid, fetched[RevokedIndex],
            "The published entry reads back, so the composition carried the whole resolution and not merely the key decision.");
    }


    /// <summary>
    /// The limit of the recommendation, and why the limit is safe. An ecosystem whose Status Issuer is a
    /// separate entity, or whose lists are signed by another key, does not satisfy "If the Issuer of the
    /// Referenced Token is the same entity as the Status Issuer", so the token does not verify under the key
    /// the composition answers. It fails CLOSED — the resolution raises
    /// <see cref="StatusListResolutionException"/>, which is Section 8.3's "no statement about the status of
    /// the Referenced Token can be made" — and never falls through to the application's resolution to try
    /// again, which would turn a same-key composition into an any-key one.
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-11.3">Token
    /// Status List, Section 11.3</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task AStatusListTokenAnotherKeySignedIsAResolutionFailureAndNeverFallsThrough()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> referencedTokenKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory referencedTokenIssuerKey = referencedTokenKeys.PublicKey;
        using PrivateKeyMemory unusedReferencedTokenPrivate = referencedTokenKeys.PrivateKey;

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> separateStatusIssuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory unusedSeparateStatusIssuerPublic = separateStatusIssuerKeys.PublicKey;
        using PrivateKeyMemory separateStatusIssuerPrivate = separateStatusIssuerKeys.PrivateKey;

        string compactJws = await PublishedTokenSignedByAsync(separateStatusIssuerPrivate).ConfigureAwait(false);
        ScriptedOutboundTransport transport = Serving(ListUrl, StatusListJwtMediaType, compactJws);

        (ResolveStatusListIssuerKeyDelegate whenAbsent, IReadOnlyList<StatusListKeyResolutionContext> seen) =
            StatusListFixtures.RecordingKeyResolverFor(NeverConsulted());

        ResolveVerifiedStatusListTokenDelegate resolve = ResolverOver(
            transport.Delegate, StatusListIssuerKeys.FromReferencedToken(whenAbsent));

        StatusListResolutionException caught = await Assert.ThrowsExactlyAsync<StatusListResolutionException>(
            async () => await resolve(
                StatusListFixtures.ContextFor(new StatusListReference(RevokedIndex, ListUrl), ReferencedTokenIssuer, referencedTokenIssuerKey),
                TestContext.CancellationToken).ConfigureAwait(false));

        Assert.AreEqual(ListUrl, caught.Uri,
            "The refusal names the uri whose Status List Token did not verify under the Referenced Token's key.");
        Assert.IsEmpty(seen,
            "The context carried the Referenced Token's key, so the composition answered it and never fell through to a second key.");
    }


    /// <summary>
    /// A key resolution that fails the test if it is ever reached — what "the composition answered the
    /// Referenced Token's key itself" looks like as a delegate.
    /// </summary>
    /// <returns>The resolution that must not be consulted.</returns>
    private static ResolveStatusListIssuerKeyDelegate NeverConsulted() =>
        (_, _) => throw new AssertFailedException(
            "Section 11.3's first recommendation answers from the Referenced Token's own key, so no second key resolution runs.");


    /// <summary>
    /// The key-resolution context a Status List Token read at <see cref="ListUrl"/> carries, with the
    /// Referenced Token's issuer stated and its key supplied or withheld.
    /// </summary>
    /// <param name="referencedTokenIssuerKey">The key the Referenced Token verified under, or <see langword="null"/> for a context built without one.</param>
    /// <returns>The key-resolution context.</returns>
    private static StatusListKeyResolutionContext KeyContextWith(PublicKeyMemory? referencedTokenIssuerKey) =>
        new()
        {
            StatusListUri = ListUrl,
            Header = new UnverifiedJwtHeader(new Dictionary<string, object>(StringComparer.Ordinal)
            {
                [WellKnownJwkMemberNames.Alg] = WellKnownJwaValues.Es256,
                [WellKnownJoseHeaderNames.Typ] = StatusListJwtType,
                [WellKnownJwkMemberNames.Kid] = KeyId
            }),
            ReferencedTokenIssuer = ReferencedTokenIssuer,
            ReferencedTokenIssuerKey = referencedTokenIssuerKey
        };


    /// <summary>
    /// Composes and signs the Status List Token this class publishes — one revoked entry at
    /// <see cref="RevokedIndex"/> — under <paramref name="signingKey"/>.
    /// </summary>
    /// <param name="signingKey">The key that signs the published token.</param>
    /// <returns>The compact serialization.</returns>
    private async Task<string> PublishedTokenSignedByAsync(PrivateKeyMemory signingKey)
    {
        using StatusListType published = StatusListType.Create(Capacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        published[RevokedIndex] = StatusTypes.Invalid;

        var token = new StatusListToken(ListUrl, TestClock.CanonicalEpoch, published);

        return await StatusListTokenJwtFixtures.IssueJwtAsync(
            token, signingKey, KeyId, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// A scripted Status Provider publishing <paramref name="compactJws"/> at <paramref name="url"/> with
    /// <paramref name="contentType"/> — Section 8.2's response shape, "The body of such an HTTP response
    /// contains the raw Status List Token".
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
    /// <param name="resolveIssuerKey">The key decision the resolution drives.</param>
    /// <returns>The resolve delegate the composition is exercised through.</returns>
    private static ResolveVerifiedStatusListTokenDelegate ResolverOver(
        OutboundTransportDelegate transport, ResolveStatusListIssuerKeyDelegate resolveIssuerKey) =>
        StatusListTokenResolvers.BuildResolving(
            transport,
            TestHostShell.ExchangeContextWith(OutboundFetchPolicy.SecureDefault),
            resolveIssuerKey,
            TestSetup.Base64UrlDecoder,
            JwtPartJson.Default,
            Pool,
            new FakeTimeProvider(TestClock.CanonicalEpoch));
}
