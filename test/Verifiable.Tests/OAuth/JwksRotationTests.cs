using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Text.Json;
using Verifiable.Core;
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
    /// <summary>
    /// The shared rotation client identifier used by key-publication and live-alteration fixtures.
    /// </summary>
    internal const string ClientId = "https://verifier.example.com/rotation";


    /// <summary>
    /// The shared rotation issuer URI used by key-publication and live-alteration fixtures.
    /// </summary>
    internal static Uri BaseUri { get; } = new("https://verifier.example.com/rotation");


    /// <summary>
    /// The immutable presentation and JWKS capabilities shared by key-publication and live-alteration fixtures.
    /// </summary>
    internal static ImmutableHashSet<CapabilityIdentifier> VerifierCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint);


    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } =
        new(DateTimeOffset.Parse("2026-01-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture));


    [TestMethod]
    public async Task JwksIncludesIncomingKeysBeforeActivation()
    {
        await using TestHostShell app = new(TimeProvider);
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
        await using TestHostShell app = new(TimeProvider);
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
        await using TestHostShell app = new(TimeProvider);
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
    public void GetDefaultSigningKeyIdThrowsWhenUsageContextHasNoEntry()
    {
        ClientRecord registration = BuildRegistrationWithAccessTokenIssuanceKey(
            new KeyId("urn:uuid:any"));

        KeyNotFoundException thrown = Assert.ThrowsExactly<KeyNotFoundException>(
            () => registration.GetDefaultSigningKeyId(KeyUsageContext.JarSigning));

        Assert.Contains("JarSigning", thrown.Message,
            "Exception message should identify the missing usage context.");
    }


    [TestMethod]
    public void GetDefaultSigningKeyIdThrowsWhenCurrentIsEmpty()
    {
        ClientRecord registration = new()
        {
            ClientId = ClientId,
            TenantId = "test",
            AllowedCapabilities = ImmutableHashSet<CapabilityIdentifier>.Empty,
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


    /// <summary>
    /// The in-process JWKS lookup shared by key-publication and live-alteration fixtures.
    /// It dispatches to the tenant endpoint and extracts key identifiers from its successful response.
    /// </summary>
    /// <param name="app">The host serving the registration.</param>
    /// <param name="segment">The registration tenant identifier.</param>
    /// <param name="cancellationToken">Cancellation for the dispatch.</param>
    /// <returns>The key identifiers published by the tenant JWKS endpoint.</returns>
    internal static async Task<string[]> FetchJwksKidsAsync(
        TestHostShell app,
        string segment,
        CancellationToken cancellationToken)
    {
        ExchangeContext context = [];
        context.SetTenantId(segment);
        context.SetIssuer(BaseUri);

        ServerHttpResponse response = await app.DispatchAtEndpointAsync(
            segment,
            WellKnownEndpointNames.MetadataJwks,
            "GET",
            new RequestFields(),
            context,
            cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            $"JWKS endpoint must return HTTP 200, got {response.StatusCode}.");

        using JsonDocument doc = JsonDocument.Parse(response.Body);
        JsonElement keysArray = doc.RootElement.GetProperty(WellKnownJwkMemberNames.Keys);

        return keysArray.EnumerateArray()
            .Select(k => k.GetProperty(WellKnownJwkMemberNames.Kid).GetString()!)
            .ToArray();
    }


    private static ClientRecord BuildRegistrationWithAccessTokenIssuanceKey(KeyId keyId) =>
        new()
        {
            ClientId = ClientId,
            TenantId = "test",
            AllowedCapabilities = ImmutableHashSet<CapabilityIdentifier>.Empty,
            AllowedRedirectUris = ImmutableHashSet<Uri>.Empty,
            AllowedScopes = ImmutableHashSet<string>.Empty,
            SigningKeys = ImmutableDictionary<KeyUsageContext, SigningKeySet>.Empty
                .Add(KeyUsageContext.AccessTokenIssuance, new SigningKeySet { Current = [keyId] }),
            TokenLifetimes = ImmutableDictionary<string, TimeSpan>.Empty
        };
}
