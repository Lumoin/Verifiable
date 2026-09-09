using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.Json;
using Verifiable.Json.Sd;
using Verifiable.Json.StatusList;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Wallet;
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
/// The credential-status step on the SIOPv2 Section 12 combined-response seat: the wallet answers one
/// transaction with a JWK-Thumbprint Self-Issued ID Token and a status-bearing SD-JWT VC presentation, and
/// the relying party reads the credential's IETF Token Status List entry through the same
/// <see cref="CredentialStatusGate"/> step the OID4VP <c>direct_post</c> seat runs, after the presentation's
/// own verification, under the deployment's <see cref="CredentialStatusPolicy"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-12">Self-Issued OpenID
/// Provider v2, Section 12</see>: "Self-Issued OP and the RP that wish to support request and presentation of
/// cryptographically verifiable claims issued by trusted third-party sources (Verifiable Presentations) MUST
/// be compliant with OpenID for Verifiable Presentations [OpenID4VP]." A seat that verifies a presentation
/// therefore evaluates its status the way the OID4VP seat does.
/// </para>
/// <para>
/// The transaction shape — preparation, the two artifacts bound to one nonce and Client ID, and the POST to
/// the SIOP response endpoint — is the one <see cref="SiopCombinedResponseFlowTests"/> drives; this class
/// varies only the credential's <c>status</c> claim, the wired resolver and the wired policy.
/// </para>
/// </remarks>
[TestClass]
internal sealed class SiopCombinedResponseStatusTests
{
    /// <summary>The per-test cancellation token and diagnostic surface MSTest supplies.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock every issued token, status resolution and freshness check reads from.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The pool every issuance, presentation and status step in this class rents transient buffers from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The Status List Token URI this class's <c>status_list</c>-referencing credentials name.</summary>
    private const string StatusListUri = "https://issuer.example/statuslists/1";

    /// <summary>The index within the Status List this class's <c>status_list</c>-referencing credentials claim.</summary>
    private const int CredentialIndex = 42;

    /// <summary>The bit capacity of the Status List this class resolves against.</summary>
    private const int StatusListCapacity = 64;

    /// <summary>The identifier list an <c>identifier_list</c>-only credential in this class names.</summary>
    private const string IdentifierListUri = "https://issuer.example/identifierlists/1";

    /// <summary>The entry an <c>identifier_list</c>-only credential in this class claims inside that list.</summary>
    private const string IdentifierListEntryId = "d7d1c0f0";


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-12">Self-Issued
    /// OpenID Provider v2, Section 12</see>: "Self-Issued OP and the RP that wish to support request and
    /// presentation of cryptographically verifiable claims issued by trusted third-party sources (Verifiable
    /// Presentations) MUST be compliant with OpenID for Verifiable Presentations [OpenID4VP]." Composed with
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>: "If the validation was successful, the Relying Party MUST perform the
    /// following validation steps to evaluate the status of the Referenced Token", ending in "7. Check the
    /// status value as described in Section 7", where Section 7.1 defines "0x00 - "VALID" - The status of the
    /// Referenced Token is valid, correct or legal." A combined response whose credential reads <c>0x00</c>
    /// verifies and carries that outcome on the terminal state.
    /// </summary>
    [TestMethod]
    public async Task ValidCredentialStatusIsSurfacedOnTheVerifiedCombinedResponse()
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
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-valid", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

            SelfIssuedAuthenticationVerifiedState verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);

            Assert.IsNotNull(verified.CredentialStatuses,
                "Section 12's MUST composed with Token Status List Section 8.3 step 7 requires the SIOP seat "
                + "to evaluate the presented credential's status and carry the outcome forward.");
            Assert.IsTrue(
                verified.CredentialStatuses!.TryGetValue(
                    SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId,
                    out CredentialStatusOutcome? outcome),
                "The Section 12 combined response presents one credential, keyed by the seat's credential query id.");
            Assert.IsNotNull(outcome);
            Assert.AreEqual(StatusTypes.Valid, outcome.Status,
                "Token Status List Section 7.1: an unset entry reads 0x00 VALID.");
            Assert.IsTrue(outcome.IsValid,
                "Token Status List Section 7.1: 0x00 is valid, correct or legal.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18">SD-JWT VC</see>: "If
    /// status is present in the verified payload of the SD-JWT, the status SHOULD be checked. Verifier policy
    /// decides whether to reject or accept a presentation of a SD-JWT VC based on the status of the Verifiable
    /// Digital Credential." Under the shipped default policy the relying party accepts, so a revoked
    /// credential — <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List</see>, Section 7.1's "0x01 - "INVALID" - The status of the Referenced Token is revoked,
    /// annulled, taken back, recalled or cancelled" — is surfaced on the verified state rather than refused.
    /// </summary>
    [TestMethod]
    public async Task RevokedCredentialStatusIsSurfacedWhenThePolicyOnlySurfaces()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[CredentialIndex] = StatusTypes.Invalid;

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
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-revoked-surface", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

            SelfIssuedAuthenticationVerifiedState verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);

            Assert.IsNotNull(verified.CredentialStatuses,
                "A determinable revoked status is surfaced, not refused, when the deployment's policy only surfaces.");
            Assert.IsTrue(
                verified.CredentialStatuses!.TryGetValue(
                    SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId,
                    out CredentialStatusOutcome? outcome),
                "The Section 12 combined response presents one credential, keyed by the seat's credential query id.");
            Assert.IsNotNull(outcome);
            Assert.AreEqual(StatusTypes.Invalid, outcome.Status,
                "Token Status List Section 7.1: a revoked entry reads 0x01 INVALID.");
            Assert.IsFalse(outcome.IsValid,
                "Only 0x00 is valid; Verifier policy decides whether to reject or accept the rest.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18">SD-JWT VC</see>:
    /// "Verifier policy decides whether to reject or accept a presentation of a SD-JWT VC based on the status
    /// of the Verifiable Digital Credential." A deployment whose policy refuses a not-valid status answers
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>access_denied</c> — "The resource owner or authorization server denied the request." — as HTTP 400,
    /// while <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for
    /// Verifiable Presentations 1.0, Section 15.9</see> — "Error responses SHOULD avoid including sensitive or
    /// detailed contextual information that could be used to infer the End-User's data." — keeps the query id,
    /// the raw status value and its disposition off the wire and on the terminal state instead.
    /// </summary>
    [TestMethod]
    public async Task RevokedCredentialStatusIsRefusedWhenThePolicyRefusesNotValid()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[CredentialIndex] = StatusTypes.Invalid;

        await using TestHostShell host = new(
            TimeProvider,
            resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: CredentialStatusPolicies.RefuseNotValid);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(new StatusListReference(CredentialIndex, StatusListUri))
                .ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-revoked-refused", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode,
                "Section 4.1.2.1's error vocabulary is answered as HTTP 400, never as a 500 server fault.");
            Assert.Contains($"\"{OAuthErrors.AccessDenied}\"", response.Body,
                "A relying-party policy refusal is Section 4.1.2.1's access_denied: the resource owner or "
                + "authorization server denied the request.");

            Assert.DoesNotContain(
                SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId, response.Body,
                "Section 15.9: the wire error response must not name which credential query was refused.");
            Assert.DoesNotContain("revoked", response.Body,
                "Section 15.9: the wire error response must not reveal the credential's disposition.");
            Assert.DoesNotContain("0x01", response.Body,
                "Section 15.9: the wire error response must not reveal the raw status value.");

            SiopVerifierFlowFailedState failed = Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(state);
            Assert.IsNotNull(failed.Refusal, "A policy refusal carries a typed refusal onto the failed state.");
            Assert.AreEqual(VerifierFlowRefusalKind.PolicyRefused, failed.Refusal!.Value.Kind,
                "Verifier policy decides whether to reject or accept — a rejection is a policy refusal.");
            Assert.AreEqual(OAuthErrors.AccessDenied, failed.Refusal!.Value.ErrorCode,
                "Section 4.1.2.1: a denial is answered with access_denied.");

            Assert.IsNotNull(failed.CredentialStatusRefusal,
                "The relying party's own detail rides the state, since Section 15.9 keeps it off the wire.");
            Assert.HasCount(1, failed.CredentialStatusRefusal!.Credentials);
            Assert.AreEqual(
                SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId,
                failed.CredentialStatusRefusal!.Credentials[0].CredentialQueryId,
                "The typed refusal names the credential query whose status the policy refused.");
            Assert.AreEqual(
                CredentialStatusDisposition.Revoked,
                failed.CredentialStatusRefusal!.Credentials[0].Disposition,
                "Token Status List Section 7.1: 0x01 INVALID reads as revoked.");
            Assert.AreEqual(
                "credential_status_not_valid: credential query "
                + $"'{SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId}' reads status 0x01 (revoked)",
                failed.CredentialStatusRefusal!.Description,
                "The typed refusal composes the query id, the raw status and its disposition for the relying party.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> step 4.a: "The subject claim (sub or 2) of the Status List Token MUST be
    /// equal to the uri claim in the status_list object of the Referenced Token", and "If any of these checks
    /// fails, no statement about the status of the Referenced Token can be made and the Referenced Token SHOULD
    /// be rejected." A resolved list whose subject does not match the credential's reference therefore fails
    /// the combined response closed, answered as
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> with HTTP 400.
    /// </summary>
    [TestMethod]
    public async Task UndeterminableCredentialStatusRefusesTheCombinedResponseAsInvalidRequest()
    {
        const string DifferentSubjectUri = "https://issuer.example/statuslists/2";

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await using TestHostShell host = new(
            TimeProvider,
            resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(DifferentSubjectUri, statusList, TimeProvider));

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(new StatusListReference(CredentialIndex, StatusListUri))
                .ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-undeterminable", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode,
                "An undeterminable status is a refusal of the Wallet's response, answered as HTTP 400.");
            Assert.Contains($"\"{OAuthErrors.InvalidRequest}\"", response.Body,
                "Section 4.1.2.1: an unverifiable Authorization Response is answered with invalid_request.");

            SiopVerifierFlowFailedState failed = Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(state);
            Assert.IsNotNull(failed.Refusal,
                "No statement about the status can be made, which is a typed refusal, not a server fault.");
            Assert.AreEqual(VerifierFlowRefusalKind.StatusUndeterminable, failed.Refusal!.Value.Kind,
                "Step 4.a's subject mismatch leaves the status undeterminable, so the presentation fails closed.");
            Assert.IsNull(failed.CredentialStatusRefusal,
                "An undeterminable status is not a policy refusal, so it names no refused credential status.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> step 1: "Check for the existence of a status claim, check for the
    /// existence of a status_list claim within the status claim". A credential carrying no status claim ends
    /// the status procedure at step 1 — step 2's "Resolve the Status List Token from the provided URI" never
    /// runs — so the resolver is never invoked and the verified state carries no outcome.
    /// </summary>
    [TestMethod]
    public async Task CredentialWithoutAStatusClaimIsNeverResolvedAgainstAStatusList()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell host = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(status: null).ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-absent", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

            SelfIssuedAuthenticationVerifiedState verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);
            Assert.IsNull(verified.CredentialStatuses,
                "A credential with no status claim yields no status outcome to carry forward.");
            Assert.AreEqual(0, resolverInvocations(),
                "Step 1 finds no status claim, so step 2's resolution of a Status List Token never runs.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> step 2: "Resolve the Status List Token from the provided URI", and "If
    /// any of these checks fails, no statement about the status of the Referenced Token can be made and the
    /// Referenced Token SHOULD be rejected." A seat that cannot perform step 2 at all — the credential
    /// references a list but the deployment wired no resolver — is a configuration fault: the request neither
    /// verifies nor is answered as a Wallet-attributable refusal.
    /// </summary>
    [TestMethod]
    public async Task StatusBearingCredentialWithNoResolverWiredIsAConfigurationFault()
    {
        await using TestHostShell host = new(TimeProvider);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(new StatusListReference(CredentialIndex, StatusListUri))
                .ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            InvalidOperationException fault = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
                async () => await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                    host, serializedSdJwt, holderPrivateKey,
                    "n-siop-status-noresolver", SiopCombinedResponseFixture.RelyingPartyClientId,
                    TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false));

            Assert.Contains(StatusListUri, fault.Message,
                "The configuration fault names the list the credential's issuer gated its validity on.");
            Assert.DoesNotContain(OAuthErrors.InvalidRequest, fault.Message,
                "A verifier-side misconfiguration is not a Wallet-attributable refusal code.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>: "The processing rules for Referenced Tokens (such as JWT or CWT) MUST
    /// precede any evaluation of a Referenced Token's status" and "If the validation procedures for the
    /// Referenced Token determine it is invalid, further procedures regarding Status List MUST NOT be
    /// performed, e.g. fetching a Status List Token". A combined response whose key-binding JWT is bound to a
    /// different audience than the relying party's Client ID fails the
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-12">Self-Issued
    /// OpenID Provider v2, Section 12</see> binding — "any Verifiable Presentations presented in a Self-Issued
    /// OP protocol flow MUST be bound to the nonce provided by the RP and the Client ID of the RP" — so no
    /// Status List Token is ever resolved.
    /// </summary>
    [TestMethod]
    public async Task AFailedVpTokenBindingStopsBeforeAnyStatusListProcedure()
    {
        const string WrongAudience = "https://attacker.example.com";

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell host = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(new StatusListReference(CredentialIndex, StatusListUri))
                .ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-ordering", WrongAudience,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body,
                "Section 4.1.2.1: a key-binding JWT bound to another audience misses Section 12's Client ID "
                + "binding, refused as invalid_request rather than surfacing as a Verifier fault.");
            Assert.Contains($"\"{OAuthErrors.InvalidRequest}\"", response.Body,
                "Section 4.1.2.1: a negative Section 12 binding verdict is invalid_request.");

            SiopVerifierFlowFailedState failed = Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(state,
                "The Referenced Token's own validation determines it invalid, so the flow fails there.");
            Assert.IsNotNull(failed.Refusal,
                "Section 12's binding conjunction is a classified refusal, not an unclassified server fault.");
            Assert.AreEqual(VerifierFlowRefusalKind.Unverifiable, failed.Refusal!.Value.Kind,
                "A negative Section 12 binding verdict is the Unverifiable refusal class.");
            Assert.AreEqual(0, resolverInvocations(),
                "Further procedures regarding Status List MUST NOT be performed once the Referenced Token is "
                + "determined invalid — fetching a Status List Token included.");
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-12">Self-Issued
    /// OpenID Provider v2, Section 12</see> governs a flow that carries "Verifiable Presentations"; a response
    /// carrying only the Self-Issued ID Token presents none, so no Referenced Token exists for
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>'s "Upon receiving a Referenced Token" to apply to, and the verified state
    /// carries no status outcome.
    /// </summary>
    [TestMethod]
    public async Task IdTokenOnlyResponseCarriesNoCredentialStatuses()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell host = new(
            TimeProvider,
            resolveVerifiedStatusListToken: countingResolver,
            credentialStatusPolicy: CredentialStatusPolicies.RefuseNotValid);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            SiopCombinedResponseFixture.RelyingPartyClientId, SiopCombinedResponseFixture.RelyingPartyBaseUri, SiopCombinedResponseFixture.SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        const string Nonce = "n-siop-status-idtoken-only";
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
        Assert.AreEqual(Nonce, verified.Nonce);
        Assert.IsNull(verified.CredentialStatuses,
            "A response presenting no Verifiable Presentation has no Referenced Token whose status to evaluate.");
        Assert.AreEqual(0, resolverInvocations(),
            "No Referenced Token means no Status List Token resolution, whatever policy the deployment wired.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-11.2">Self-Issued
    /// OpenID Provider v2, Section 11.2</see>: "Additionally, the RP MUST check whether the nonce Claim value
    /// provided in the ID Token is known to the RP and was not used before in an Authorization Response." A
    /// second combined response replaying an already-consumed nonce is a Wallet-attributable input the RP
    /// cannot verify a second time, refused with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> as an HTTP 400 body rather than surfacing as a Verifier fault.
    /// </summary>
    [TestMethod]
    public async Task AReplayedCombinedResponseIsRefusedAsInvalidRequest()
    {
        const string ReplayedNonce = "n-siop-status-replayed";

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

            using VerifierKeyMaterial rpKeys = host.RegisterClient(
                SiopCombinedResponseFixture.RelyingPartyClientId, SiopCombinedResponseFixture.RelyingPartyBaseUri, SiopCombinedResponseFixture.SiopCapabilities);
            string tenant = rpKeys.Registration.TenantId.Value;

            async Task<(string RequestHandle, ServerHttpResponse Response)> PostOnceAsync()
            {
                string requestHandle = await host.HandleSiopRequestPreparationAsync(
                    rpKeys, ReplayedNonce, SiopCombinedResponseFixture.RelyingPartyClientId, SiopCombinedResponseFixture.AllowedSiopAlgorithms,
                    TestContext.CancellationToken).ConfigureAwait(false);

                string idToken = await SiopCombinedResponseFixture.IssueSelfIssuedIdTokenAsync(
                    ReplayedNonce, TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);
                string vpToken = await SiopCombinedResponseFixture.PresentWithKeyBindingAsync(
                    serializedSdJwt, holderPrivateKey, ReplayedNonce, SiopCombinedResponseFixture.RelyingPartyClientId,
                    TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

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

                return (requestHandle, response);
            }

            (string _, ServerHttpResponse firstResponse) = await PostOnceAsync().ConfigureAwait(false);
            Assert.AreEqual((int)HttpStatusCode.OK, firstResponse.StatusCode, firstResponse.Body);

            (string replayedRequestHandle, ServerHttpResponse replayedResponse) = await PostOnceAsync().ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.BadRequest, replayedResponse.StatusCode, replayedResponse.Body);
            Assert.Contains($"\"{OAuthErrors.InvalidRequest}\"", replayedResponse.Body,
                "Section 4.1.2.1: a replayed nonce is a Wallet-attributable input the RP cannot re-verify, invalid_request.");

            SiopVerifierFlowFailedState failed = Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(
                host.GetFlowState(replayedRequestHandle).State);
            Assert.IsNotNull(failed.Refusal,
                "Section 11.2's replay check is a classified refusal, not an unclassified server fault.");
            Assert.AreEqual(VerifierFlowRefusalKind.Unverifiable, failed.Refusal!.Value.Kind,
                "A replayed nonce is a negative verification verdict — the Unverifiable refusal class.");
            Assert.AreEqual(OAuthErrors.InvalidRequest, failed.Refusal!.Value.ErrorCode,
                "Section 4.1.2.1: the Unverifiable refusal's error code is invalid_request.");
            Assert.IsNull(failed.CredentialStatusRefusal,
                "A replay refusal never reaches the credential-status step, so it names no refused credential status.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>
    /// reserves <c>server_error</c> for "The authorization server encountered an unexpected condition that
    /// prevented it from fulfilling the request", distinct from the classified refusal codes. A terminal
    /// <see cref="SiopVerifierFlowFailedState"/> carrying no typed <see cref="VerifierFlowRefusal"/> — a
    /// genuine Verifier fault, not a Wallet-attributable one — is answered as HTTP 500 <c>server_error</c> by
    /// the response endpoint's own <c>BuildResponse</c>, proved directly over a hand-built state the same way
    /// <see cref="Oid4VpDirectPostRefusalTests"/> proves the OID4VP seat's identical 500 arm.
    /// </summary>
    [TestMethod]
    public async Task AnUnclassifiedCombinedResponseFailureAnswersServerError()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            SiopCombinedResponseFixture.RelyingPartyClientId, SiopCombinedResponseFixture.RelyingPartyBaseUri, SiopCombinedResponseFixture.SiopCapabilities);

        ExchangeContext context = new();
        context.SetTenantId(rpKeys.Registration.TenantId);

        EndpointChain chain = await host.GetEndpointsAsync(rpKeys.Registration, context).ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        SiopVerifierFlowFailedState unclassified = new()
        {
            FlowId = "flow-siop-unclassified",
            ExpectedIssuer = SiopCombinedResponseFixture.RelyingPartyClientId,
            EnteredAt = now,
            ExpiresAt = now.AddMinutes(5),
            Kind = FlowKind.SiopVerifierServer,
            Reason = "A Verifier-side fault carrying no client-safe classification.",
            FailedAt = now
        };

        int siopResponseCandidates = 0;
        foreach(ServerEndpoint endpoint in chain)
        {
            if(!string.Equals(endpoint.Name, WellKnownEndpointNames.SiopResponse, StringComparison.Ordinal))
            {
                continue;
            }

            siopResponseCandidates++;

            ServerHttpResponse response = endpoint.BuildResponse(
                unclassified, FlowKind.SiopVerifierServer.Name, context);

            Assert.AreEqual((int)HttpStatusCode.InternalServerError, response.StatusCode, response.Body);
            Assert.Contains($"\"{OAuthErrors.ServerError}\"", response.Body,
                "Section 4.1.2.1's server_error names an unexpected condition, the arm a failure carrying no "
                + "typed refusal falls to.");
        }

        Assert.AreNotEqual(0, siopResponseCandidates,
            "The SIOP response endpoint must expose at least one candidate for this assertion to mean anything.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> step 1: "Check for the existence of a status claim, check for the
    /// existence of a status_list claim within the status claim and validate that the content of
    /// status_list adheres to the rules defined in Section 6.2 for JOSE-based Referenced Tokens." A
    /// <c>status_list</c> naming a relative <c>uri</c> does not adhere to Section 6.2's "The value of uri
    /// MUST be a URI conforming to [RFC3986]", so the SIOPv2 §12 combined response is refused as
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>'s
    /// <c>invalid_request</c>, the same Malformed classification the OID4VP <c>direct_post</c> seat gives
    /// the identical Section 6.2 refusal, rather than surfacing as a Verifier fault.
    /// </summary>
    [TestMethod]
    public async Task AStatusListReferenceWithARelativeUriIsRefusedAsMalformedOnTheCombinedResponse()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell host = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);

        var rawStatusObject = new Dictionary<string, object>
        {
            [StatusListJsonConstants.StatusList] = new Dictionary<string, object>
            {
                [StatusListJsonConstants.Index] = (long)CredentialIndex,
                [StatusListJsonConstants.Uri] = "/statuslists/1"
            }
        };

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await SdJwtVpFixture.IssuePidCredentialWithClaimsAsync(
                TimeProvider, "Alice", "Smith", SiopCombinedResponseFixture.IssuerId, SiopCombinedResponseFixture.IssuerKeyId, Pool, status: null,
                TestContext.CancellationToken, rawStatusObject).ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-relative-uri", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body,
                "Section 4.1.2.1: a status_list reference that fails Section 6.2 is answered as HTTP 400, "
                + "never as a 500 server fault.");
            Assert.Contains($"\"{OAuthErrors.InvalidRequest}\"", response.Body,
                "Section 4.1.2.1: a malformed vp_token presentation is answered with invalid_request.");

            SiopVerifierFlowFailedState failed = Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(state);
            Assert.IsNotNull(failed.Refusal,
                "A status_list reference that does not adhere to Section 6.2 is a classified refusal.");
            Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
                "A relative uri fails Section 6.2's RFC 3986 conformance rule, refused as Malformed.");
            Assert.AreEqual(0, resolverInvocations(),
                "A malformed reference is refused at the parse boundary, before any Status List Token would be resolved.");
        }
    }


    /// <summary>
    /// The same Section 6.2 refusal for a negative <c>idx</c>: "idx: REQUIRED. … MUST specify a
    /// non-negative Integer." Answered on the SIOPv2 §12 combined response the same way as a relative
    /// <c>uri</c> — <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749
    /// §4.1.2.1</see>'s <c>invalid_request</c>, the Malformed refusal class, never a 500.
    /// </summary>
    [TestMethod]
    public async Task AStatusListReferenceWithANegativeIndexIsRefusedAsMalformedOnTheCombinedResponse()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell host = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialWithRawStatusAsync(SdJwtVpFixture.NegativeIndexStatusObject(StatusListUri))
                .ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-negative-idx", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body,
                "Section 4.1.2.1: a status_list reference that fails Section 6.2 is answered as HTTP 400, "
                + "never as a 500 server fault.");
            Assert.Contains($"\"{OAuthErrors.InvalidRequest}\"", response.Body,
                "Section 4.1.2.1: a malformed vp_token presentation is answered with invalid_request.");

            SiopVerifierFlowFailedState failed = Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(state);
            Assert.IsNotNull(failed.Refusal,
                "A negative idx does not adhere to Section 6.2, so the presentation is a classified refusal.");
            Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
                "A negative idx fails Section 6.2's non-negative-Integer rule, refused as Malformed.");
            Assert.AreEqual(0, resolverInvocations(),
                "A malformed reference is refused at the parse boundary, before any Status List Token would be resolved.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status
    /// List, Section 6.1</see>: "The status (status) claim MUST specify a JSON Object that contains at least one
    /// reference to a status mechanism." The SIOPv2 §12 combined response answers a credential whose <c>status</c>
    /// claim is the literal <c>{}</c> exactly as the OID4VP <c>direct_post</c> seat does: the claim is present and
    /// names nothing, so it is a malformed presentation refused with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>'s
    /// <c>invalid_request</c>, never accepted as a credential that was simply not status-checked.
    /// </summary>
    [TestMethod]
    public async Task AStatusClaimCarryingNoMechanismIsRefusedAsMalformedOnTheCombinedResponse()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell host = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialWithRawStatusAsync(SdJwtVpFixture.EmptyStatusObject()).ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-empty-object", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body,
                "Section 4.1.2.1: a status claim that fails Section 6.1 is answered as HTTP 400, "
                + "never as a 500 server fault.");
            Assert.Contains($"\"{OAuthErrors.InvalidRequest}\"", response.Body,
                "Section 4.1.2.1: a malformed vp_token presentation is answered with invalid_request.");

            SiopVerifierFlowFailedState failed = Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(state);
            Assert.IsNotNull(failed.Refusal,
                "A status claim naming no mechanism does not adhere to Section 6.1, so the presentation is a classified refusal.");
            Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
                "Section 6.1: an empty status object is a malformed presentation, not a status the verifier cannot evaluate.");
            Assert.AreEqual(0, resolverInvocations(),
                "The refusal happens at the parse boundary, before any Status List Token would be resolved.");
        }
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-12">Self-Issued
    /// OpenID Provider v2, Section 12</see> combined response carrying a <c>vp_token</c> with
    /// no dot-separated issuer-JWT/disclosure structure at all is a shape no conformant Wallet would
    /// produce; <see cref="Verifiable.Json.Sd.SdJwtSerializer.ParseToken"/> normalizes the rejection to
    /// <see cref="FormatException"/> (RFC 9901's own wire-shape vocabulary), so the response is refused as
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749 §4.1.2.1</see>'s
    /// <c>invalid_request</c> — the Malformed refusal class the OID4VP <c>direct_post</c> seat gives the
    /// identical shape of defect — rather than surfacing as a 500 Verifier fault.
    /// </summary>
    [TestMethod]
    public async Task ACorruptVpTokenIsRefusedAsMalformedOnTheCombinedResponse()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell host = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);

        using VerifierKeyMaterial rpKeys = host.RegisterClient(
            SiopCombinedResponseFixture.RelyingPartyClientId, SiopCombinedResponseFixture.RelyingPartyBaseUri, SiopCombinedResponseFixture.SiopCapabilities);
        string tenant = rpKeys.Registration.TenantId.Value;

        const string Nonce = "n-siop-status-corrupt-vp-token";
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
                [AuthorizationResponseParameters.VpToken] = "not-a-vp-token",
                [OAuthRequestParameterNames.State] = requestHandle
            },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body,
            "Section 4.1.2.1: an unparseable vp_token is answered as HTTP 400, never as a 500 server fault.");
        Assert.Contains($"\"{OAuthErrors.InvalidRequest}\"", response.Body,
            "Section 4.1.2.1: a malformed vp_token presentation is answered with invalid_request.");

        SiopVerifierFlowFailedState failed = Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(
            host.GetFlowState(requestHandle).State);
        Assert.IsNotNull(failed.Refusal,
            "An unparseable vp_token is a classified refusal, not an unclassified server fault.");
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "A vp_token with no issuer-JWT/disclosure structure is the Malformed refusal class.");
        Assert.AreEqual(0, resolverInvocations(),
            "The parse fails before any status claim is ever read, so the resolver is never invoked.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> closing: "If any of these checks fails, no statement about the status
    /// of the Referenced Token can be made and the Referenced Token SHOULD be rejected." A <c>status</c>
    /// claim naming only a mechanism this verifier cannot evaluate passes step 1's existence check and fails
    /// its <c>status_list</c> check, so the
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-12">Self-Issued
    /// OpenID Provider v2, Section 12</see> combined response is rejected the same way the OID4VP
    /// <c>direct_post</c> seat rejects it — <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC
    /// 6749, Section 4.1.2.1</see>'s <c>invalid_request</c> as HTTP 400 — with the credential query and the
    /// mechanism the issuer named kept off the wire per OID4VP 1.0 Section 15.9 and carried on the failed
    /// state instead.
    /// </summary>
    [TestMethod]
    public async Task AStatusNamingOnlyAnUnevaluableMechanismRefusesTheCombinedResponse()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell host = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialWithRawStatusAsync(
                SdJwtVpFixture.IdentifierListOnlyStatusObject(IdentifierListEntryId, IdentifierListUri))
                .ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-identifier-list-refused", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body,
                "No statement about the credential's status can be made, which is answered as HTTP 400 rather "
                + "than as a 500 server fault.");
            Assert.Contains($"\"{OAuthErrors.InvalidRequest}\"", response.Body,
                "Section 4.1.2.1: a presentation whose status cannot be determined rides invalid_request, "
                + "never access_denied.");
            Assert.DoesNotContain(
                SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId.Value, response.Body,
                "Section 15.9: the wire error response must not name the credential query.");
            Assert.DoesNotContain(StatusMechanismNames.IdentifierList, response.Body,
                "Section 15.9: the wire error response must not name the mechanism the issuer stated.");

            SiopVerifierFlowFailedState failed = Assert.IsInstanceOfType<SiopVerifierFlowFailedState>(state);
            Assert.IsNotNull(failed.Refusal,
                "A status the verifier cannot evaluate is a classified refusal, not an unclassified fault.");
            Assert.AreEqual(VerifierFlowRefusalKind.StatusUndeterminable, failed.Refusal!.Value.Kind,
                "A claim naming only unevaluable mechanisms is the same undeterminable rejection an unreadable "
                + "Status List Token is.");
            Assert.IsNull(failed.CredentialStatusRefusal,
                "An undeterminable status is not a policy refusal, so it names no refused credential status.");
            Assert.Contains(
                SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId.Value, failed.Reason,
                StringComparison.Ordinal,
                "The detail Section 15.9 keeps off the wire rides the state, naming the credential query.");
            Assert.Contains(StatusMechanismNames.IdentifierList, failed.Reason, StringComparison.Ordinal,
                "The detail Section 15.9 keeps off the wire rides the state, naming the mechanism this verifier "
                + "does not evaluate.");
            Assert.AreEqual(0, resolverInvocations(),
                "Step 1 finds no status_list within the status claim, so step 2's resolution never runs.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see>'s closing rejection is a SHOULD, so a relying party that evaluates the
    /// named mechanism out of band may accept the presentation — and then needs what the issuer stated. The
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-12">Self-Issued
    /// OpenID Provider v2, Section 12</see> seat therefore carries the verified credential's <c>status</c>
    /// claim onto its terminal state, keyed by the credential query the combined response's single
    /// presentation answers, with its mechanism names and no reference — and records no status outcome,
    /// because it evaluated none.
    /// </summary>
    [TestMethod]
    public async Task AStatusNamingOnlyAnUnevaluableMechanismIsSurfacedOnTheCombinedResponse()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell host = new(
            TimeProvider,
            resolveVerifiedStatusListToken: countingResolver,
            unsupportedStatusMechanisms: UnsupportedStatusMechanismDisposition.Surface);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialWithRawStatusAsync(
                SdJwtVpFixture.IdentifierListOnlyStatusObject(IdentifierListEntryId, IdentifierListUri))
                .ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-identifier-list-surfaced", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

            SelfIssuedAuthenticationVerifiedState verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);

            Assert.IsNotNull(verified.Credentials,
                "Section 12's combined response carried a vp_token, so the seat surfaces what it verified.");
            Assert.IsTrue(verified.Credentials!.TryGetValue(
                SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId,
                out VpCredentialClaims? credential),
                "The verified credential is keyed by the credential query the seat presents it under.");
            Assert.IsNotNull(credential!.Status,
                "Token Status List Section 6.1 requires at least one mechanism and the issuer named one, so "
                + "the credential carries a status claim.");
            Assert.IsNull(credential.Status!.StatusList,
                "The claim names no status_list mechanism, so there is no reference to resolve.");
            Assert.HasCount(1, credential.Status.Mechanisms,
                "The issuer named exactly one mechanism, so exactly one is surfaced.");
            Assert.Contains(StatusMechanismNames.IdentifierList, credential.Status.Mechanisms,
                "The mechanism reaches the relying party by name, which is what makes its own out-of-band "
                + "evaluation possible.");
            Assert.IsNull(verified.CredentialStatuses,
                "The verifier evaluated no status, so it records no outcome: naming a mechanism is a statement "
                + "about what the issuer said, never about the credential's status.");
            Assert.AreEqual(0, resolverInvocations(),
                "Step 2's resolution is for a status_list reference; a claim carrying none reaches no resolver.");
        }
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> step 1 begins "Check for the existence of a status claim". Rejecting a
    /// status claim the verifier cannot evaluate is a decision about a claim that exists: a credential whose
    /// issuer published no status information carries none, and the
    /// <see href="https://openid.net/specs/openid-connect-self-issued-v2-1_0.html#section-12">Self-Issued
    /// OpenID Provider v2, Section 12</see> combined response verifies unchanged, surfacing the credential
    /// with no status claim on it.
    /// </summary>
    [TestMethod]
    public async Task ACredentialCarryingNoStatusClaimIsSurfacedWithNoStatusClaimOnIt()
    {
        await using TestHostShell host = new(TimeProvider);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidCredentialAsync(status: null).ConfigureAwait(false);

        using(holderPrivateKey)
        using(issuerPublicKey)
        {
            host.RegisterIssuerTrust(SiopCombinedResponseFixture.IssuerId, issuerPublicKey);

            (ServerHttpResponse response, FlowState state) = await SiopCombinedResponseFixture.PostCombinedResponseAsync(
                host, serializedSdJwt, holderPrivateKey,
                "n-siop-status-absent-default", SiopCombinedResponseFixture.RelyingPartyClientId,
                TimeProvider, Pool, TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);

            SelfIssuedAuthenticationVerifiedState verified =
                Assert.IsInstanceOfType<SelfIssuedAuthenticationVerifiedState>(state);

            Assert.IsNotNull(verified.Credentials,
                "Section 12's combined response carried a vp_token, so the seat surfaces what it verified.");
            Assert.IsTrue(verified.Credentials!.TryGetValue(
                SiopVerifierExecutor.SiopCombinedResponseCredentialQueryId,
                out VpCredentialClaims? credential),
                "The verified credential is keyed by the credential query the seat presents it under.");
            Assert.IsNull(credential!.Status,
                "Step 1's existence check found no status claim, so the credential surfaces none — which is "
                + "what separates it from one naming a mechanism this verifier cannot evaluate.");
            Assert.IsNull(verified.CredentialStatuses,
                "Nothing was evaluated, so no outcome is recorded.");
        }
    }


    /// <summary>
    /// Issues an EUDI PID SD-JWT VC with the holder's Ed25519 public key in <c>cnf.jwk</c> and, when
    /// <paramref name="status"/> is supplied, the Token Status List reference the verifier reads. Delegates to
    /// the shared <see cref="SdJwtVpFixture.IssuePidCredentialWithClaimsAsync"/>, the one minter every SD-JWT
    /// VC seat shares.
    /// </summary>
    /// <param name="status">The credential's <c>status.status_list</c> reference, or <see langword="null"/> for a credential carrying no status claim.</param>
    private ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)>
        IssuePidCredentialAsync(StatusListReference? status) =>
        SdJwtVpFixture.IssuePidCredentialWithClaimsAsync(
            TimeProvider, "Alice", "Smith", SiopCombinedResponseFixture.IssuerId, SiopCombinedResponseFixture.IssuerKeyId, Pool,
            status, TestContext.CancellationToken);


    /// <summary>
    /// Issues the same PID with its <c>status</c> claim written verbatim from
    /// <paramref name="rawStatusObject"/> — the shapes <see cref="StatusListReference"/> cannot hold, which is
    /// every shape beyond a well-formed <c>status_list</c> reference.
    /// </summary>
    /// <param name="rawStatusObject">The <c>status</c> object to write into the issuer-signed payload.</param>
    private ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)>
        IssuePidCredentialWithRawStatusAsync(IReadOnlyDictionary<string, object> rawStatusObject) =>
        SdJwtVpFixture.IssuePidCredentialWithClaimsAsync(
            TimeProvider, "Alice", "Smith", SiopCombinedResponseFixture.IssuerId, SiopCombinedResponseFixture.IssuerKeyId, Pool,
            status: null, TestContext.CancellationToken, rawStatusObject);


}
