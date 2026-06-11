using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Routing;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// End-to-end SIOPv2 Relying-Party flow for the §8 Decentralized Identifier Subject Syntax Type,
/// driven through the real dispatch chain. The Wallet mints a DID-subject Self-Issued ID Token
/// (<c>iss</c>/<c>sub</c> = the DID, header <c>kid</c> = the verification-method id, no
/// <c>sub_jwk</c>), the RP's response endpoint runs the §11.1 validation through the shared action
/// executor, and the validator resolves the DID's verification key via the
/// <see cref="ResolveDidVerificationKeyDelegate"/> the test host wires from its shared DID trust
/// map. Mirrors <see cref="SiopFlowIntegrationTests"/> for the JWK Thumbprint type.
/// </summary>
[TestClass]
internal sealed class SiopDidSubjectFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private const string RelyingPartyClientId = "https://rp.example.com";
    private const string SiopNonce = "n-siop-did-01";
    private const string WalletDid = "did:example:NzbLsXh8uDCcd6MNwXF4W7noWXFZAfHkxZsRGC9Xs";
    private const string WalletKeyId = WalletDid + "#key-1";

    private static readonly Uri RelyingPartyBaseUri = new("https://rp.example.com");

    private static readonly ImmutableHashSet<CapabilityIdentifier> SiopCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.SiopSelfIssuedOp);

    private static readonly string[] AllowedSiopAlgorithms = [WellKnownJwaValues.Es256];

    private static readonly JwtHeaderSerializer HeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static readonly JwtPayloadSerializer PayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    [TestMethod]
    public async Task DidSubjectIdTokenPostReachesVerifiedState()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        //Seed the shared DID trust map so the host's resolver returns this DID's verification key
        //when the validator resolves the token's sub by its header kid.
        host.RegisterSiopDidTrust(WalletDid, WalletKeyId, siopPublic);

        //=== Step 1: the RP prepares the transaction. ===
        string requestHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsInstanceOfType<SiopRequestPreparedState>(host.GetFlowState(requestHandle).State);

        //=== Step 2: the Wallet mints a DID-subject Self-Issued ID Token bound to the transaction. ===
        string idToken = await SelfIssuedIdTokenIssuance.IssueWithDecentralizedIdentifierAsync(
            siopPrivate, WalletDid, WalletKeyId, RelyingPartyClientId, SiopNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        //=== Step 3: the Wallet POSTs id_token + state to the SIOP Response endpoint. ===
        ServerHttpResponse response = await PostIdTokenAsync(host, tenant, idToken, requestHandle)
            .ConfigureAwait(false);

        //=== Step 4: 200 and the terminal verified state with the DID subject + DID syntax type. ===
        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

        SelfIssuedAuthenticationVerifiedState verified =
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(
                host.GetFlowState(requestHandle).State);
        Assert.AreEqual(SiopSubjectSyntaxType.DecentralizedIdentifier, verified.SubjectSyntaxType);
        Assert.AreEqual(WalletDid, verified.Subject);
        Assert.AreEqual(SiopNonce, verified.Nonce);
    }


    [TestMethod]
    public async Task DidSubjectIdTokenFailsClosedWhenTrustMapHasNoEntry()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        //No RegisterSiopDidTrust call: the resolver returns null for this DID, so the §11.1
        //subject binding cannot be confirmed and the signature is never verified — fail closed.
        string requestHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithDecentralizedIdentifierAsync(
            siopPrivate, WalletDid, WalletKeyId, RelyingPartyClientId, SiopNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await PostIdTokenAsync(host, tenant, idToken, requestHandle)
            .ConfigureAwait(false);

        Assert.AreNotEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
        Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(host.GetFlowState(requestHandle).State);
    }


    private async Task<ServerHttpResponse> PostIdTokenAsync(
        TestHostShell host, string tenant, string idToken, string requestHandle) =>
        await host.DispatchAtEndpointAsync(
            tenant,
            WellKnownEndpointNames.SiopResponse,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.IdToken] = idToken,
                [OAuthRequestParameterNames.State] = requestHandle
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
}
