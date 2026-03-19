using System.Collections.Immutable;
using System.Text.Json;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Exercises the rotation-lifecycle semantics of <see cref="SigningKeySet"/> —
/// the publication status of Incoming, Retiring, and Historical slots in JWKS
/// output, and the events emitted as a key transitions through the full lifecycle.
/// </summary>
/// <remarks>
/// <para>
/// The rotation model reflects the operational reality of running an OAuth server
/// with relying parties that cache JWKS:
/// </para>
/// <list type="bullet">
///   <item><description><see cref="SigningKeySet.Incoming"/> — pre-published in JWKS ahead of activation so relying parties cache the key before the first token signed with it appears.</description></item>
///   <item><description><see cref="SigningKeySet.Current"/> — actively signing, published in JWKS.</description></item>
///   <item><description><see cref="SigningKeySet.Retiring"/> — no longer signing but still published during the grace window so in-flight tokens remain verifiable.</description></item>
///   <item><description><see cref="SigningKeySet.Historical"/> — retained for post-publication verification but not emitted in JWKS.</description></item>
/// </list>
/// </remarks>
[TestClass]
internal sealed class JwksRotationTests
{
    private const string ClientId = "https://verifier.example.com/rotation";

    private static readonly Uri BaseUri = new("https://verifier.example.com/rotation");

    private static readonly ImmutableHashSet<ServerCapabilityName> VerifierCapabilities =
        ImmutableHashSet.Create(
            ServerCapabilityName.VerifiablePresentation,
            ServerCapabilityName.JwksEndpoint);


    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } =
        new(DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));


    [TestMethod]
    public async Task JwksIncludesIncomingKeysBeforeActivation()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(ClientId, BaseUri, VerifierCapabilities);

        string segment = keys.Registration.TenantId;
        KeyId currentKid = keys.SigningKeyId;
        KeyId incomingKid = app.AllocateSigningKey();

        app.UpdateSigningKeys(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [currentKid],
                Incoming = [incomingKid]
            }
        });

        string[] kids = await FetchJwksKidsAsync(app, segment, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.HasCount(2, kids,
            "JWKS must publish both Current and Incoming keys ahead of activation.");
        Assert.Contains(currentKid.Value, kids,
            "JWKS must continue to publish the Current key during pre-publication.");
        Assert.Contains(incomingKid.Value, kids,
            "JWKS must publish the Incoming key so relying parties can cache it ahead of activation.");
    }


    [TestMethod]
    public async Task JwksIncludesRetiringKeysInGraceWindow()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(ClientId, BaseUri, VerifierCapabilities);

        string segment = keys.Registration.TenantId;
        KeyId retiringKid = keys.SigningKeyId;
        KeyId newCurrentKid = app.AllocateSigningKey();

        app.UpdateSigningKeys(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [newCurrentKid],
                Retiring = [retiringKid]
            }
        });

        string[] kids = await FetchJwksKidsAsync(app, segment, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.HasCount(2, kids,
            "JWKS must publish both Current and Retiring keys during the grace window.");
        Assert.Contains(newCurrentKid.Value, kids,
            "JWKS must publish the new Current key after activation.");
        Assert.Contains(retiringKid.Value, kids,
            "JWKS must continue to publish the Retiring key so in-flight tokens remain verifiable.");
    }


    [TestMethod]
    public async Task JwksOmitsHistoricalKeys()
    {
        using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial keys = app.RegisterClient(ClientId, BaseUri, VerifierCapabilities);

        string segment = keys.Registration.TenantId;
        KeyId currentKid = keys.SigningKeyId;
        KeyId historicalKid = app.AllocateSigningKey();

        app.UpdateSigningKeys(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [currentKid],
                Historical = [historicalKid]
            }
        });

        string[] kids = await FetchJwksKidsAsync(app, segment, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.HasCount(1, kids,
            "JWKS must not publish Historical keys — they are retained for verification only.");
        Assert.Contains(currentKid.Value, kids,
            "JWKS must continue to publish the Current key.");
        Assert.DoesNotContain(historicalKid.Value, kids,
            "JWKS must omit Historical keys from the wire output even though they remain resolvable.");
    }


    [TestMethod]
    public async Task RotationLifecycleEmitsClientUpdatedAtEveryTransition()
    {
        using TestHostShell app = new(TimeProvider);

        List<ClientRegistrationEvent> received = [];
        using IDisposable subscription = app.Server.Events.Subscribe(
            new CollectingObserver<ClientRegistrationEvent>(received));

        using VerifierKeyMaterial keys = app.RegisterClient(ClientId, BaseUri, VerifierCapabilities);

        string segment = keys.Registration.TenantId;
        KeyId keyA = keys.SigningKeyId;
        KeyId keyB = app.AllocateSigningKey();

        //Stage 1 → Stage 2: Pre-publish. Current = [A], Incoming = [B].
        app.UpdateSigningKeys(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [keyA],
                Incoming = [keyB]
            }
        });

        string[] stage2Kids = await FetchJwksKidsAsync(app, segment, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.HasCount(2, stage2Kids,
            "Stage 2: JWKS must publish both Current (A) and Incoming (B).");

        //Stage 2 → Stage 3: Activate. Current = [B], Retiring = [A].
        app.UpdateSigningKeys(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [keyB],
                Retiring = [keyA]
            }
        });

        string[] stage3Kids = await FetchJwksKidsAsync(app, segment, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.HasCount(2, stage3Kids,
            "Stage 3: JWKS must still publish both B (now Current) and A (now Retiring).");

        //Stage 3 → Stage 4: Drop. Current = [B], Historical = [A].
        app.UpdateSigningKeys(segment, new Dictionary<KeyUsageContext, SigningKeySet>
        {
            [KeyUsageContext.JarSigning] = new SigningKeySet
            {
                Current = [keyB],
                Historical = [keyA]
            }
        });

        string[] stage4Kids = await FetchJwksKidsAsync(app, segment, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.HasCount(1, stage4Kids,
            "Stage 4: JWKS must publish only the Current key — Historical keys are not emitted.");
        Assert.Contains(keyB.Value, stage4Kids,
            "Stage 4: Current key B must remain in JWKS after A is dropped to Historical.");

        //One ClientRegistered from RegisterClient plus three ClientUpdated from the
        //three transitions, filtered to this segment. The static event subject is
        //shared across tests so filter by segment.
        ClientRegistrationEvent[] forThisSegment = received
            .Where(e => string.Equals(e.TenantId, segment, StringComparison.Ordinal))
            .ToArray();

        Assert.HasCount(4, forThisSegment,
            "Each rotation transition must emit a ClientRegistrationEvent (one initial register, three updates).");
        Assert.IsInstanceOfType<ClientRegistered>(forThisSegment[0],
            "The first event for a segment must be ClientRegistered.");

        for(int i = 1; i <= 3; i++)
        {
            Assert.IsInstanceOfType<ClientUpdated>(forThisSegment[i],
                $"Transition {i} must emit ClientUpdated so cache subscribers can invalidate.");
        }
    }


    [TestMethod]
    public void GetDefaultSigningKeyIdThrowsWhenUsageContextHasNoEntry()
    {
        ClientRegistration registration = BuildRegistrationWithAccessTokenIssuanceKey(
            new KeyId("urn:uuid:any"));

        KeyNotFoundException thrown = Assert.ThrowsExactly<KeyNotFoundException>(
            () => registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning));

        Assert.Contains("JarSigning", thrown.Message,
            "Exception message should identify the missing usage context.");
    }


    [TestMethod]
    public void GetDefaultSigningKeyIdThrowsWhenCurrentIsEmpty()
    {
        ClientRegistration registration = new()
        {
            ClientId = ClientId,
            TenantId = "test",
            AllowedCapabilities = ImmutableHashSet<ServerCapabilityName>.Empty,
            AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
            AllowedScopes = ImmutableHashSet<string>.Empty,
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.AccessTokenIssuance, new SigningKeySet { Current = [] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty
        };

        InvalidOperationException thrown = Assert.ThrowsExactly<InvalidOperationException>(
            () => registration.GetDefaultSigningKeyId(KeyUsageContext.AccessTokenIssuance));

        Assert.Contains("empty", thrown.Message,
            "Exception message should indicate the Current list is empty.");
    }


    private static async Task<string[]> FetchJwksKidsAsync(
        TestHostShell app,
        string segment,
        CancellationToken cancellationToken)
    {
        RequestContext context = new();
        context.SetTenantId(segment);
        context.SetIssuer(BaseUri);

        ServerHttpResponse response = await app.DispatchBySegmentAsync(
            segment,
            ServerCapabilityName.JwksEndpoint,
            "GET",
            new RequestFields(),
            context,
            cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"JWKS endpoint must return HTTP 200, got {response.StatusCode}.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement keysArray = doc.RootElement.GetProperty(WellKnownJwkValues.Keys);

        return keysArray.EnumerateArray()
            .Select(k => k.GetProperty(WellKnownJwkValues.Kid).GetString()!)
            .ToArray();
    }


    private static ClientRegistration BuildRegistrationWithAccessTokenIssuanceKey(KeyId keyId) =>
        new()
        {
            ClientId = ClientId,
            TenantId = "test",
            AllowedCapabilities = ImmutableHashSet<ServerCapabilityName>.Empty,
            AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
            AllowedScopes = ImmutableHashSet<string>.Empty,
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.AccessTokenIssuance, new SigningKeySet { Current = [keyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty
        };


    private sealed class CollectingObserver<T>(List<T> collected): IObserver<T>
    {
        public void OnNext(T value) => collected.Add(value);
        public void OnError(Exception error) { }
        public void OnCompleted() { }
    }
}
