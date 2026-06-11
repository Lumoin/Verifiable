using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.OAuth;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Siop;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The dispatched analog of <see cref="SiopCombinedResponseTests"/>: the SIOPv2 §12 combined
/// response (<c>id_token</c> + <c>vp_token</c> in one Authorization Response) driven through the
/// real SIOP RP-as-server dispatch chain. The RP prepares a transaction (nonce + client_id), the
/// wallet mints BOTH a JWK-Thumbprint Self-Issued ID Token (bound to the nonce/client_id) AND a
/// vp_token (SD-JWT VC + KB-JWT bound to the same nonce/client_id), and the SIOP response endpoint
/// receives both, runs the §11.1 id_token validation, the vp_token presentation verification, and
/// the §12 binding checks through the shared action executor, reaching the terminal
/// <see cref="SelfIssuedAuthenticationVerifiedState"/>.
/// </summary>
/// <remarks>
/// SIOPv2 §2.2.1: the SIOP subject key (a fresh P-256 pair) and the credential's holder binding (an
/// Ed25519 cnf key) are unrelated — the verified subject is the P-256 thumbprint URI, never derived
/// from the credential.
/// </remarks>
[TestClass]
internal sealed class SiopCombinedResponseFlowTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private const string RelyingPartyClientId = "https://rp.example.com";
    private const string SiopNonce = "n-siop-combined-01";

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

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
    public async Task CombinedResponsePostReachesVerifiedStateBindingBothArtifacts()
    {
        //=== Issuance time (out of band): the End-User holds an issuer-attested PID. ===
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync("Alice", "Smith").ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            await using TestHostShell host = new(TimeProvider);

            using VerifierKeyMaterial rpKeys = host.RegisterClient(
                RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
            string tenant = rpKeys.Registration.TenantId.Value;

            //The verifier trusts the credential issuer for the vp_token signature check.
            host.RegisterIssuerTrust(IssuerId, issuerPublicKey);

            //=== Step 1: the RP prepares the transaction and learns the handle to echo as state. ===
            string requestHandle = await host.HandleSiopRequestPreparationAsync(
                rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.IsInstanceOfType<SiopRequestPreparedState>(host.GetFlowState(requestHandle).State);

            //=== Step 2: the wallet mints BOTH artifacts for this one transaction. ===
            var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PublicKeyMemory siopPublic = siopKeys.PublicKey;
            using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

            string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
                siopPrivate, siopPublic, RelyingPartyClientId, SiopNonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            string vpToken = await PresentWithKeyBindingAsync(
                serializedSdJwt, holderPrivateKey, SiopNonce, RelyingPartyClientId)
                .ConfigureAwait(false);

            string expectedSubject = SelfIssuedSubjectThumbprint(siopPublic);

            //=== Step 3: the wallet POSTs id_token + vp_token + state to the SIOP Response endpoint. ===
            ServerHttpResponse response = await host.DispatchAtEndpointAsync(
                tenant,
                WellKnownEndpointNames.SiopResponse,
                "POST",
                new RequestFields
                {
                    [OAuthRequestParameterNames.IdToken] = idToken,
                    [AuthorizationResponseParameters.VpToken] = vpToken,
                    [OAuthRequestParameterNames.State] = requestHandle
                },
                new ExchangeContext(),
                TestContext.CancellationToken).ConfigureAwait(false);

            //=== Step 4: 200 and the terminal verified state with the expected subject + nonce. ===
            Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

            (OAuthFlowState state, _) = host.GetFlowState(requestHandle);
            SelfIssuedAuthenticationVerifiedState verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);
            Assert.AreEqual(expectedSubject, verified.Subject);
            Assert.AreEqual(SiopNonce, verified.Nonce);
            Assert.AreEqual(SiopSubjectSyntaxType.JwkThumbprint, verified.SubjectSyntaxType);
        }
    }


    [TestMethod]
    public async Task ReplayedCombinedResponseReachesFailedStateNamingNonceMiss()
    {
        //An attacker replays artifacts minted for an earlier transaction against the fresh request:
        //the signatures still verify, but BOTH nonce bindings miss. The §12 / §11.1 checks stop the
        //replay through the dispatched flow, and the failure names the nonce-binding miss.
        const string StaleNonce = "n-earlier-transaction";

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync("Alice", "Smith").ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            await using TestHostShell host = new(TimeProvider);

            using VerifierKeyMaterial rpKeys = host.RegisterClient(
                RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
            string tenant = rpKeys.Registration.TenantId.Value;

            host.RegisterIssuerTrust(IssuerId, issuerPublicKey);

            string requestHandle = await host.HandleSiopRequestPreparationAsync(
                rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
                TestContext.CancellationToken).ConfigureAwait(false);

            var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            using PublicKeyMemory siopPublic = siopKeys.PublicKey;
            using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

            //Both artifacts minted for the STALE nonce — cryptographically intact, wrong transaction.
            string staleIdToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
                siopPrivate, siopPublic, RelyingPartyClientId, StaleNonce,
                issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
                TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            string staleVpToken = await PresentWithKeyBindingAsync(
                serializedSdJwt, holderPrivateKey, StaleNonce, RelyingPartyClientId)
                .ConfigureAwait(false);

            ServerHttpResponse response = await host.DispatchAtEndpointAsync(
                tenant,
                WellKnownEndpointNames.SiopResponse,
                "POST",
                new RequestFields
                {
                    [OAuthRequestParameterNames.IdToken] = staleIdToken,
                    [AuthorizationResponseParameters.VpToken] = staleVpToken,
                    [OAuthRequestParameterNames.State] = requestHandle
                },
                new ExchangeContext(),
                TestContext.CancellationToken).ConfigureAwait(false);

            //The flow must not succeed; it reaches terminal failure naming the nonce miss. The
            //id_token §11.1 nonce check fails first (it runs before the vp_token), so the failure
            //reason carries the §11.1 nonce=False signal.
            Assert.AreNotEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

            (OAuthFlowState state, _) = host.GetFlowState(requestHandle);
            SiopVerifierFlowFailedState failed =
                Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(state);
            Assert.Contains("nonce=False", failed.Reason);
        }
    }


    [TestMethod]
    public async Task IdTokenOnlyResponsePostStillReachesVerifiedState()
    {
        //Proves the id_token-only path is unchanged: a POST with id_token + state (no vp_token)
        //emits SiopResponsePosted and reaches the verified state exactly as SiopFlowIntegrationTests.
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            RelyingPartyClientId, RelyingPartyBaseUri, SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        string requestHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, SiopNonce, RelyingPartyClientId, AllowedSiopAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);

        var siopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory siopPublic = siopKeys.PublicKey;
        using PrivateKeyMemory siopPrivate = siopKeys.PrivateKey;

        string idToken = await SelfIssuedIdTokenIssuance.IssueWithJwkThumbprintAsync(
            siopPrivate, siopPublic, RelyingPartyClientId, SiopNonce,
            issuedAt: TimeProvider.GetUtcNow(), lifetime: TimeSpan.FromMinutes(5),
            TestSetup.Base64UrlEncoder, HeaderSerializer, PayloadSerializer, Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        string expectedSubject = SelfIssuedSubjectThumbprint(siopPublic);

        ServerHttpResponse response = await host.DispatchAtEndpointAsync(
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

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

        (OAuthFlowState state, _) = host.GetFlowState(requestHandle);
        SelfIssuedAuthenticationVerifiedState verified =
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);
        Assert.AreEqual(expectedSubject, verified.Subject);
        Assert.AreEqual(SiopNonce, verified.Nonce);
    }


    //The RFC 9278 sha-256 JWK Thumbprint URI the validator confirms the sub against — the same
    //projection SelfIssuedIdTokenIssuance uses, recomputed from the public key alone.
    private static string SelfIssuedSubjectThumbprint(PublicKeyMemory publicKey)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(publicKey.Tag);
        IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
            publicKey, algorithm, TestSetup.Base64UrlEncoder);
        string thumbprint = DpopJwkUtilities.ComputeThumbprintFromJwk(
            jwk, TestSetup.Base64UrlEncoder, Pool);

        return SiopSubjectSyntaxTypes.JwkThumbprintSha256Prefix + thumbprint;
    }


    /// <summary>
    /// Issues an EUDI PID SD-JWT VC with the holder's Ed25519 public key in <c>cnf.jwk</c>. Copied
    /// from <see cref="SiopCombinedResponseTests"/> — the issuance-time half every presentation
    /// builds on.
    /// </summary>
    private async ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)>
        IssuePidCredentialAsync(string givenName, string familyName)
    {
        var issuerKeys = TestKeyMaterialProvider.CreateP256KeyMaterial();
        using PrivateKeyMemory issuerPrivateKey = issuerKeys.PrivateKey;

        var holderKeys = TestKeyMaterialProvider.CreateEd25519KeyMaterial();
        using PublicKeyMemory holderPublicKey = holderKeys.PublicKey;

        Dictionary<string, object> holderJwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            holderPublicKey.Tag.Get<CryptoAlgorithm>(),
            holderPublicKey.Tag.Get<Purpose>(),
            holderPublicKey.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        JwtPayload payload = JwtPayload.ForSdJwtVcIssuance(
            issuer: IssuerId,
            verifiableCredentialType: EudiPid.SdJwtVct,
            issuedAt: TimeProvider.GetUtcNow(),
            holderConfirmation: holderJwk,
            claims:
            [
                new(EudiPid.SdJwt.GivenName, givenName),
                new(EudiPid.SdJwt.FamilyName, familyName)
            ]);

        var disclosablePaths = new HashSet<CredentialPath>
        {
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}"),
            CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")
        };

        SdTokenResult result = await payload.IssueSdJwtAsync(
            c => JsonSerializerExtensions.SerializeToUtf8Bytes(c, TestSetup.DefaultSerializationOptions),
            SdJwtIssuance.IssueVerboseAsync,
            disclosablePaths, TestSalts.DefaultGenerator(),
            issuerPrivateKey, IssuerKeyId, Pool,
            mediaType: WellKnownMediaTypes.Jwt.VcSdJwt,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        string compactJws = Encoding.UTF8.GetString(result.SignedToken.Span);
        using SdToken<string> issuedToken = new(compactJws, result.Disclosures.ToList());
        string serializedSdJwt = SdJwtSerializer.SerializeToken(issuedToken, TestSetup.Base64UrlEncoder);

        return (serializedSdJwt, holderKeys.PrivateKey, issuerKeys.PublicKey);
    }


    /// <summary>
    /// The wallet-side presentation step: parse the stored SD-JWT, sign a KB-JWT over its hash input
    /// with the holder key bound to the request's <c>nonce</c> and the verifier's Client ID, and
    /// serialise the presentation with key binding per RFC 9901 §4.3. Copied from
    /// <see cref="SiopCombinedResponseTests"/>.
    /// </summary>
    private async ValueTask<string> PresentWithKeyBindingAsync(
        string sdJwtWithoutKb, PrivateKeyMemory holderPrivateKey, string nonce, string audience)
    {
        using SdToken<string> token = SdJwtSerializer.ParseToken(
            sdJwtWithoutKb, TestSetup.Base64UrlDecoder, Pool, TestSalts.TestSaltTag);

        string hashInput = SdJwtSerializer.GetSdJwtForHashing(token, TestSetup.Base64UrlEncoder);

        string compactKbJwt = await KbJwtIssuance.IssueAsync(
            Encoding.UTF8.GetBytes(hashInput),
            holderPrivateKey,
            nonce,
            audience,
            TimeProvider.GetUtcNow(),
            TestSetup.Base64UrlEncoder,
            HeaderSerializer,
            PayloadSerializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        using SdToken<string> tokenWithKb = token.WithKeyBinding(compactKbJwt, Pool);

        return SdJwtSerializer.SerializeToken(tokenWithKb, TestSetup.Base64UrlEncoder);
    }
}
