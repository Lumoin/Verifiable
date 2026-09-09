using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Foundation;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.StatusList;
using Verifiable.Tests.OAuth;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.StatusList;

/// <summary>
/// Real-wire capstones for the Token Status List wire formats (draft-ietf-oauth-status-list §5): a
/// <see cref="StatusListToken"/> is issued, signed, and served over a genuine loopback socket with the exact
/// <c>application/statuslist+jwt</c> (and, since <see cref="Verifiable.Cbor.StatusList.StatusListTokenCborConverter"/>
/// shows the type also supports the CWT Claims Set, <c>application/statuslist+cwt</c>) media type; a Relying
/// Party fetches it over a real HTTP GET, verifies the signature, and evaluates a Referenced Token's status —
/// the "is it still valid now" gate (<see cref="CredentialStatusGate"/>) run end to end over the wire.
/// </summary>
[TestClass]
internal sealed class StatusListTokenHttpFlowTests
{
    /// <summary>The test framework's per-test context, including the cooperative cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The wall clock used to timestamp issued Status List Tokens and evaluate their status.</summary>
    private static TimeProvider Clock => new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>The bit-array capacity of the published Status List.</summary>
    private const int Capacity = 16;

    /// <summary>The revoked index inside the published Status List.</summary>
    private const int RevokedIndex = 3;

    /// <summary>An untouched, still-valid index inside the published Status List.</summary>
    private const int ValidIndex = 7;

    /// <summary>The issuer signing key's identifier, carried as the Status List Token's <c>kid</c>.</summary>
    private const string KeyId = "https://issuer.example/statuslist#key-1";


    /// <summary>
    /// The JWT leg: the Relying Party fetches the Status List Token over HTTP with the exact
    /// <c>application/statuslist+jwt</c> media type, verifies its JWS signature, and evaluates two Referenced
    /// Tokens — one at a revoked index and one at a still-valid index — proving the status evaluated is the
    /// byte that crossed the socket, not a locally-held copy. "In the successful response, the Status Provider
    /// MUST use the following content-type: * "application/statuslist+jwt" for Status List Token in JWT
    /// format" (Section 8.1/8.2) and "6. Retrieve the status value of the index specified in the Referenced
    /// Token as described in Section 4." (Section 8.3).
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task EvaluatesReferencedTokenStatusFromRealHttpFetchOverJwt()
    {
        await using StaticContentHost host = await StaticContentHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = StatusListType.Create(Capacity, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.LeastSignificantFirst);
        statusList[RevokedIndex] = StatusTypes.Invalid;

        string subject = new Uri(host.BaseAddress, "/statuslist/1").ToString();
        var token = new StatusListToken(subject, Clock.GetUtcNow(), statusList);

        string compactJwt = await StatusListTokenJwtFixtures.IssueJwtAsync(token, issuerPrivate, KeyId, TestContext.CancellationToken).ConfigureAwait(false);
        host.Publish("/statuslist/1", Encoding.ASCII.GetBytes(compactJwt), StatusListMediaTypes.StatusListJwtContentType);

        using HttpClient httpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(host.Certificate);
        (OutboundTransportDelegate transport, Func<IReadOnlyList<string?>> contentTypes) = RecordingOutboundTransport.Wrap(
            GuardedHttpClientTransport.BuildSingleHopTransport(httpClient));
        ExchangeContext context = TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy);

        ResolveStatusListIssuerKeyDelegate resolveIssuerKey = (_, _) =>
            ValueTask.FromResult<ResolvedStatusListIssuerKey?>(ResolvedStatusListIssuerKey.Borrowed(issuerPublic));
        ResolveVerifiedStatusListTokenDelegate resolveVerified = StatusListTokenResolvers.BuildResolving(
            transport, context, resolveIssuerKey, TestSetup.Base64UrlDecoder, JwtPartJson.Default, BaseMemoryPool.Shared, Clock);

        var fetchedTokens = new List<StatusListToken>();
        ResolveVerifiedStatusListTokenDelegate resolve = async (context, cancellationToken) =>
        {
            ResolvedStatusListToken? resolved = await resolveVerified(context, cancellationToken).ConfigureAwait(false);
            if(resolved is not null)
            {
                fetchedTokens.Add(resolved.Token);
            }

            return resolved;
        };

        try
        {
            CredentialStatusOutcome revoked = await CredentialStatusGate.CheckAsync(
                StatusListFixtures.ContextFor(RevokedIndex, subject), resolve, Clock.GetUtcNow(), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(revoked.IsValid, "The revoked index MUST evaluate as not valid from the fetched token.");
            Assert.AreEqual(StatusTypes.Invalid, revoked.Status);

            CredentialStatusOutcome valid = await CredentialStatusGate.CheckAsync(
                StatusListFixtures.ContextFor(ValidIndex, subject), resolve, Clock.GetUtcNow(), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsTrue(valid.IsValid, "An untouched index MUST evaluate as valid from the fetched token.");
            Assert.AreEqual(StatusTypes.Valid, valid.Status);

            Assert.IsTrue(host.WasRequested("/statuslist/1"), "The status evaluation MUST have crossed the socket to the published path.");
            Assert.AreEqual(2, host.TotalRequests, "Each evaluation MUST fetch the token over its own real HTTP request.");
            Assert.HasCount(2, contentTypes(), "Each evaluation's fetch produced its own recorded response.");
            Assert.IsTrue(contentTypes().All(contentType => string.Equals(contentType, StatusListMediaTypes.StatusListJwtContentType, StringComparison.Ordinal)),
                "The Status List Token MUST be served with the exact statuslist+jwt media type.");
        }
        finally
        {
            foreach(StatusListToken fetched in fetchedTokens)
            {
                fetched.StatusList.Dispose();
            }
        }
    }


    /// <summary>
    /// The CWT leg: the same evaluation, this time the Status List Token is issued as a COSE_Sign1 CWT and
    /// served with the exact <c>application/statuslist+cwt</c> media type. "In the successful response, the
    /// Status Provider MUST use the following content-type: * "application/statuslist+cwt" for Status List
    /// Token in CWT format" (Section 8.1/8.2) and "6. Retrieve the status value of the index specified in the
    /// Referenced Token as described in Section 4." (Section 8.3).
    /// See <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.2">Token
    /// Status List, Section 8.2</see> and
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Section 8.3</see>.
    /// </summary>
    [TestMethod]
    public async Task EvaluatesReferencedTokenStatusFromRealHttpFetchOverCwt()
    {
        await using StaticContentHost host = await StaticContentHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);

        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory issuerPublic = issuerKeys.PublicKey;
        using PrivateKeyMemory issuerPrivate = issuerKeys.PrivateKey;

        using StatusListType statusList = StatusListType.Create(Capacity, StatusListBitSize.OneBit, BaseMemoryPool.Shared, BitOrder.LeastSignificantFirst);
        statusList[RevokedIndex] = StatusTypes.Invalid;

        string subject = new Uri(host.BaseAddress, "/statuslist/1").ToString();
        var token = new StatusListToken(subject, Clock.GetUtcNow(), statusList);

        ReadOnlyMemory<byte> cwtBytes = await StatusListTokenCwtFixtures.IssueCwtAsync(token, issuerPrivate, TestContext.CancellationToken).ConfigureAwait(false);
        host.Publish("/statuslist/1", cwtBytes, StatusListMediaTypes.StatusListCwt);

        using HttpClient httpClient = LoopbackTls.CreatePinnedHttpClient(host.Certificate);
        StatusListToken? fetchedToken = null;

        try
        {
            (string? contentType, StatusListToken fetched) = await StatusListTokenCwtFixtures
                .FetchAndParseCwtAsync(httpClient, subject, issuerPublic, TestContext.CancellationToken).ConfigureAwait(false);
            fetchedToken = fetched;
            Assert.AreEqual(StatusListMediaTypes.StatusListCwt, contentType, "The Status List Token MUST be served with the exact statuslist+cwt media type.");

            //fetched is disposed by this method's own finally block below, so the resolution does not
            //own it — CheckAsync's own disposal of a not-owned resolution is a no-op.
            ResolveVerifiedStatusListTokenDelegate resolve = (_, _) => ValueTask.FromResult<ResolvedStatusListToken?>(
                new ResolvedStatusListToken { Token = fetched, ResolvedAt = Clock.GetUtcNow(), IsTokenOwned = false });

            CredentialStatusOutcome revoked = await CredentialStatusGate.CheckAsync(
                StatusListFixtures.ContextFor(RevokedIndex, subject), resolve, Clock.GetUtcNow(), cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);
            Assert.IsFalse(revoked.IsValid, "The revoked index MUST evaluate as not valid from the CWT-fetched token.");
            Assert.AreEqual(StatusTypes.Invalid, revoked.Status);

            Assert.IsTrue(host.WasRequested("/statuslist/1"), "The status evaluation MUST have crossed the socket to the published path.");
        }
        finally
        {
            fetchedToken?.StatusList.Dispose();
        }
    }
}
