using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Siop.Server;
using Verifiable.OAuth.Siop.Server.States;
using Verifiable.OAuth.Siop.Wallet;
using Verifiable.Server;
using Verifiable.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// What the SIOPv2 Section 12 combined-response seat publishes about the credential it verified: the
/// per-credential record on <see cref="SelfIssuedAuthenticationVerifiedState.Credentials"/>, keyed by the
/// <see cref="CredentialQueryId"/> the seat presented the <c>vp_token</c> under, in parity with the OID4VP
/// <c>direct_post</c> seat's own map.
/// </summary>
/// <remarks>
/// <para>
/// The transaction shape — preparation, the two artifacts bound to one nonce and Client ID, and the POST to
/// the SIOP response endpoint — is the one <see cref="SiopCombinedResponseFlowTests"/> drives; this class
/// varies only what the relying party reads off the terminal state afterward.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SiopCombinedResponseCredentialsTests
{
    /// <summary>The per-test cancellation token and diagnostic surface MSTest supplies.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock every issued token and the transaction's freshness checks read from.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The pool every issuance and presentation step in this class rents transient buffers from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The given name this class's PID credential carries.</summary>
    private const string GivenName = "Erika";

    /// <summary>The family name this class's PID credential carries.</summary>
    private const string FamilyName = "Mustermann";

    /// <summary>The Status List Token URI this class's status-bearing credential references.</summary>
    private const string StatusListUri = "https://issuer.example/statuslists/1";

    /// <summary>The index within the Status List this class's status-bearing credential claims.</summary>
    private const int CredentialIndex = 42;

    /// <summary>The bit capacity of the Status List this class resolves against.</summary>
    private const int StatusListCapacity = 64;


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-12">Self-Issued
    /// OpenID Provider v2, Section 12</see>: "Self-Issued OP and the RP that wish to support request and
    /// presentation of cryptographically verifiable claims issued by trusted third-party sources (Verifiable
    /// Presentations) MUST be compliant with OpenID for Verifiable Presentations [OpenID4VP]." Compliance
    /// includes how the verified presentation is published:
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OpenID for
    /// Verifiable Presentations 1.0, Section 8.1</see> keys a <c>vp_token</c> by "the id value used for a
    /// Credential Query in the DCQL query", so the combined response's single credential is published under
    /// this seat's own <see cref="SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId"/>, carrying the
    /// released claims at their paths, the credential's declared type and its verified issuer.
    /// </summary>
    [TestMethod]
    public async Task TheCombinedResponsePublishesItsCredentialUnderTheSeatsCredentialQueryId()
    {
        await using TestHostShell host = new(TimeProvider);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(status: null).ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey, "n-siop-credentials-01",
                SiopCombinedResponseFixture.RelyingPartyClientId, TimeProvider, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

            SelfIssuedAuthenticationVerifiedState verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);

            Assert.IsNotNull(verified.Credentials,
                "Section 12's compliance MUST makes the verified presentation the relying party's to read, " +
                "so a combined response that carried a vp_token publishes its credential.");
            Assert.IsTrue(
                verified.Credentials!.TryGetValue(
                    SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId,
                    out VpCredentialClaims? credential),
                "Section 8.1 keys the presentation by the credential query identifier, which on this seat is " +
                "the identifier it presented the single vp_token under.");
            Assert.IsNotNull(credential);

            Assert.AreEqual(FamilyName,
                credential.Extracted[CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.FamilyName}")],
                "The published record states each released claim at the path it occupies in the " +
                "issuer-signed structure.");
            Assert.AreEqual(GivenName,
                credential.Extracted[CredentialPath.FromJsonPointer($"/{EudiPid.SdJwt.GivenName}")],
                "Every claim the presentation released is stated, not only the first.");
            Assert.AreEqual(EudiPid.SdJwtVct, credential.CredentialType,
                "The published record states the credential's own declared type.");
            Assert.AreEqual(SiopCombinedResponseFixture.IssuerId, credential.Issuer,
                "The published record states the issuer identifier the seat resolved the signing key for.");
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-12">Self-Issued
    /// OpenID Provider v2, Section 12</see> governs a response that presents "cryptographically verifiable
    /// claims issued by trusted third-party sources (Verifiable Presentations)". A Self-Issued OpenID Provider
    /// v2 Section 11.1 response that carries an <c>id_token</c> alone presents none, so the seat publishes no
    /// credential record at all rather than an empty map a relying party could mistake for a verified
    /// presentation carrying nothing.
    /// </summary>
    [TestMethod]
    public async Task AnIdTokenOnlyResponsePublishesNoCredentials()
    {
        await using TestHostShell host = new(TimeProvider);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            SiopCombinedResponseFixture.RelyingPartyClientId, SiopCombinedResponseFixture.RelyingPartyBaseUri, SiopCombinedResponseFixture.SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        const string Nonce = "n-siop-credentials-id-token-only";
        string requestHandle = await host.HandleSiopRequestPreparationAsync(
            rpKeys, Nonce, SiopCombinedResponseFixture.RelyingPartyClientId, SiopCombinedResponseFixture.AllowedSiopAlgorithms,
            TestContext.CancellationToken).ConfigureAwait(false);

        string idToken = await SiopCombinedResponseFixture.IssueSelfIssuedIdTokenAsync(
            Nonce, TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

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

        SelfIssuedAuthenticationVerifiedState verified =
            Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(
                host.GetFlowState(requestHandle).State);

        Assert.IsNull(verified.Credentials,
            "A response presenting no Verifiable Presentation leaves Section 12's credential surface unset, " +
            "so a relying party can tell 'no presentation was made' from 'a presentation released nothing'.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OpenID for
    /// Verifiable Presentations 1.0, Section 8.1</see>: "the key is the id value used for a Credential Query in
    /// the DCQL query". The library's own
    /// <see cref="SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId"/> is only the default; a relying
    /// party whose deployment names its own Credential Query states that identifier at registration and the
    /// seat publishes the presentation under it, so the key stays the deployment's own rather than the
    /// library's.
    /// </summary>
    [TestMethod]
    public async Task ASeatGivenItsOwnCredentialQueryIdentifierPublishesThePresentationUnderIt()
    {
        CredentialQueryId deploymentCredentialQueryId = new("rp_pid");

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(status: null).ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            OAuthActionExecutor executor = SiopVerifierExecutor.Create(
                TestSetup.Base64UrlDecoder,
                TestSetup.Base64UrlEncoder,
                SiopCombinedResponseFixture.HeaderSerializer,
                SiopCombinedResponseFixture.PayloadSerializer,
                Pool,
                TimeProvider,
                resolveIssuerKey: issuerId =>
                    string.Equals(issuerId, SiopCombinedResponseFixture.IssuerId, StringComparison.Ordinal) ? issuerPublicKey : null,
                parseSdJwtToken: static s => SdJwtSerializer.ParseToken(
                    s, TestSetup.Base64UrlDecoder, TestSetup.Base64UrlEncoder,
                    BaseMemoryPool.Shared, TestSalts.TestSaltTag),
                computeSdJwtHashInput: static t => SdJwtSerializer.GetSdJwtForHashing(
                    t, TestSetup.Base64UrlEncoder),
                computeDigest: MicrosoftCryptographicFunctionsAdapter.ComputeDigestAsync,
                vpTokenCredentialQueryId: deploymentCredentialQueryId);

            const string Nonce = "n-siop-credentials-own-id";
            string idToken = await SiopCombinedResponseFixture.IssueSelfIssuedIdTokenAsync(
                Nonce, TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);
            string vpToken = await SiopCombinedResponseFixture.PresentWithKeyBindingAsync(
                serializedSdJwt, holderPrivateKey, Nonce, SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            FlowInput input = await executor.ExecuteAsync(
                new ValidateCombinedSiopResponse(
                    idToken, vpToken, SiopCombinedResponseFixture.RelyingPartyClientId, Nonce, SiopCombinedResponseFixture.AllowedSiopAlgorithms),
                new ExchangeContext(),
                TestContext.CancellationToken).ConfigureAwait(false);

            SelfIssuedAuthenticationVerified verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerified>(input);

            Assert.IsNotNull(verified.Credentials,
                "The combined response carried a vp_token, so its credential is published.");
            Assert.IsTrue(
                verified.Credentials!.ContainsKey(deploymentCredentialQueryId),
                "Section 8.1's key is the id the deployment's own Credential Query used, which is the " +
                "identifier this seat was registered with.");
            Assert.IsFalse(
                verified.Credentials!.ContainsKey(
                    SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId),
                "A deployment that named its own credential query identifier is never published under the " +
                "library's default one as well.");
        }
    }


    /// <summary>
    /// <see cref="ASeatGivenItsOwnCredentialQueryIdentifierPublishesThePresentationUnderIt"/> proves the
    /// explicit <see cref="CredentialQueryId"/> in process, against a seat built directly through
    /// <see cref="SiopVerifierExecutor.Create"/>. A hosted deployment configures the same identifier one
    /// level up, on <see cref="TestHostShell"/>'s own <c>vpTokenCredentialQueryId</c> parameter — threaded
    /// to <see cref="HostedAuthorizationServer.Build"/> and <see cref="SiopVerifierExecutor.Register"/> —
    /// so the identifier reaches the seat identically over the real wire.
    /// </summary>
    [TestMethod]
    public async Task AHostedSeatGivenItsOwnCredentialQueryIdentifierPublishesThePresentationUnderItOverTheWire()
    {
        CredentialQueryId deploymentCredentialQueryId = new("rp_pid");

        await using TestHostShell host = new(TimeProvider, vpTokenCredentialQueryId: deploymentCredentialQueryId);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(status: null).ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey, "n-siop-credentials-hosted-own-id",
                SiopCombinedResponseFixture.RelyingPartyClientId, TimeProvider, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

            SelfIssuedAuthenticationVerifiedState verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);

            Assert.IsNotNull(verified.Credentials,
                "The combined response carried a vp_token, so its credential is published.");
            Assert.IsTrue(
                verified.Credentials!.ContainsKey(deploymentCredentialQueryId),
                "Section 8.1's key is the id the hosted deployment configured its Credential Query with.");
            Assert.IsFalse(
                verified.Credentials!.ContainsKey(
                    SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId),
                "A hosted deployment that named its own credential query identifier is never published " +
                "under the library's default one as well.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> runs its status steps per Referenced Token, and
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.1">OpenID for
    /// Verifiable Presentations 1.0, Section 8.1</see> gives the Referenced Token exactly one name in the
    /// response — the Credential Query's id. The credential and its status outcome are therefore published
    /// under the same <see cref="CredentialQueryId"/>, so a relying party reading a not-valid outcome can name
    /// the credential it belongs to without matching on anything else.
    /// </summary>
    [TestMethod]
    public async Task TheCredentialAndItsStatusOutcomeArePublishedUnderTheSameCredentialQueryId()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await using TestHostShell host = new(
            TimeProvider,
            resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider));

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(new StatusListReference(CredentialIndex, StatusListUri))
                .ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey, "n-siop-credentials-status",
                SiopCombinedResponseFixture.RelyingPartyClientId, TimeProvider, Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

            SelfIssuedAuthenticationVerifiedState verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);

            CredentialQueryId credentialQueryId = SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId;

            Assert.IsNotNull(verified.Credentials,
                "The combined response carried a vp_token, so its credential is published.");
            Assert.IsTrue(
                verified.Credentials!.TryGetValue(credentialQueryId, out VpCredentialClaims? credential),
                "Section 8.1 names the Referenced Token by the credential query identifier.");
            Assert.IsNotNull(credential);

            Assert.IsNotNull(verified.CredentialStatuses,
                "The credential carried a status claim, so Section 8.3's status steps ran and recorded an outcome.");
            Assert.IsTrue(
                verified.CredentialStatuses!.ContainsKey(credentialQueryId),
                "The outcome is published under the same identifier the credential itself is published under, " +
                "so the two maps are read together without a second correlation.");

            Assert.IsNotNull(credential.Status,
                "Section 8.3 step 1 checks for the existence of a status claim; this credential carries one.");
            Assert.AreEqual(
                new StatusListReference(CredentialIndex, StatusListUri),
                credential.Status!.StatusList,
                "The published record states the Section 6.2 reference the credential's issuer wrote, so the " +
                "relying party reads the same entry the status step resolved.");
        }
    }


    /// <summary>
    /// Issues an EUDI PID SD-JWT VC with the holder's public key in <c>cnf.jwk</c> and, when
    /// <paramref name="status"/> is supplied, the Token Status List reference the seat reads. Delegates to the
    /// shared <see cref="SdJwtVpFixture.IssuePidCredentialWithClaimsAsync"/>, the one minter every SD-JWT VC
    /// seat shares.
    /// </summary>
    /// <param name="status">The credential's <c>status.status_list</c> reference, or <see langword="null"/> for a credential carrying no status claim.</param>
    /// <returns>The serialized credential, the holder key its <c>cnf</c> binds to, and the issuer's public key.</returns>
    private ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)>
        IssuePidCredentialAsync(StatusListReference? status) =>
        SdJwtVpFixture.IssuePidCredentialWithClaimsAsync(
            TimeProvider, GivenName, FamilyName, SiopCombinedResponseFixture.IssuerId, SiopCombinedResponseFixture.IssuerKeyId, Pool,
            status, TestContext.CancellationToken);
}
