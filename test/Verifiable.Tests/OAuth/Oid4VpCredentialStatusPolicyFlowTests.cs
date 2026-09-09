using Microsoft.Extensions.Time.Testing;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Verifiable.Core.Dcql;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The relying party's credential-status policy on the OID4VP verifier seat, driven end to end over the
/// in-process listener: a real issuer mints a status-bearing PID, the toy wallet presents it to the Response URI,
/// and the deployment's <see cref="CredentialStatusPolicy"/> decides whether the presentation stands.
/// </summary>
/// <remarks>
/// <para>
/// The shipped default is <see cref="CredentialStatusPolicies.Surface"/> — a determinable revoked status reaches
/// <see cref="PresentationVerifiedState"/> with the outcome surfaced for the relying party to read, which
/// <see cref="Oid4VpFlowIntegrationTests.ExecutorSurfacesCredentialStatusOnPresentationVerified"/> proves on the
/// same wire. These tests are its counterpart: what changes when the deployment wires
/// <see cref="CredentialStatusPolicies.RefuseNotValid"/> instead, where in the verification order the policy runs,
/// and what the Response URI then answers.
/// </para>
/// <para>
/// Every credential here is minted through <see cref="SdJwtVpFixture.IssuePidCredentialWithClaimsAsync"/> and every
/// flow driven through <see cref="TestHostShell"/>, so the presentations are the ones the sibling OID4VP flow tests
/// present.
/// </para>
/// </remarks>
[TestClass]
internal sealed class Oid4VpCredentialStatusPolicyFlowTests
{
    /// <summary>Supplies the ambient cancellation token and the test identity.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock every host, credential and status list in this class shares.</summary>
    private FakeTimeProvider TimeProvider { get; } = new FakeTimeProvider(TestClock.CanonicalEpoch);

    /// <summary>The Verifier's client identifier, as registered on the host.</summary>
    private const string VerifierClientId = "https://verifier.example.com";

    /// <summary>The Verifier's base URI, from which its endpoint paths are composed.</summary>
    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    /// <summary>The issuer identifier every PID in this class is issued under and trusted as.</summary>
    private const string IssuerId = "https://issuer.example.com";

    /// <summary>The key identifier the issuer's signature over each PID carries.</summary>
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    /// <summary>The Status List Token URI every status-bearing credential in this class references.</summary>
    private const string StatusListUri = "https://issuer.example/statuslists/1";

    /// <summary>Entry capacity of the status lists these tests build.</summary>
    private const int StatusListCapacity = 64;

    /// <summary>The identifier list an <c>identifier_list</c>-only credential in this class names.</summary>
    private const string IdentifierListUri = "https://issuer.example/identifierlists/1";

    /// <summary>The entry an <c>identifier_list</c>-only credential in this class claims inside that list.</summary>
    private const string IdentifierListEntryId = "d7d1c0f0";

    /// <summary>The pool every buffer in this class is rented from.</summary>
    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>The capabilities a Verifier host must advertise to serve the OID4VP flow.</summary>
    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-18">SD-JWT VC</see>: "Verifier
    /// policy decides whether to reject or accept a presentation of a SD-JWT VC based on the status of the
    /// Verifiable Digital Credential." The decision is one decision over the whole presentation, not one per
    /// credential: a two-credential presentation whose second credential's
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token Status
    /// List, Section 7.1</see> entry reads <c>0x01</c> "INVALID" consults the policy exactly once, over a map
    /// holding both credentials, and the refusal names only the credential query that read not valid.
    /// </summary>
    [TestMethod]
    public async Task PolicyIsConsultedOnceOverBothCredentialsAndRefusesOnlyTheRevokedOne()
    {
        const int primaryIndex = 11;
        const int secondaryIndex = 12;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[secondaryIndex] = StatusTypes.Invalid;

        CountingCredentialStatusPolicy policy = new(CredentialStatusPolicies.RefuseNotValid);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: policy.Decide);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string primarySdJwt, PrivateKeyMemory primaryHolder, PublicKeyMemory primaryIssuer) =
            await IssuePidAsync("Erika", "Mustermann", new StatusListReference(primaryIndex, StatusListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory primaryHolderKey = primaryHolder;
        using PublicKeyMemory primaryIssuerKey = primaryIssuer;

        (string secondarySdJwt, PrivateKeyMemory secondaryHolder, PublicKeyMemory secondaryIssuer) =
            await IssuePidAsync("Hans", "Schmidt", new StatusListReference(secondaryIndex, StatusListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory secondaryHolderKey = secondaryHolder;
        using PublicKeyMemory secondaryIssuerKey = secondaryIssuer;

        app.RegisterIssuerTrust(IssuerId, primaryIssuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [DcqlFixtures.PidPrimaryCredentialId] = primarySdJwt,
                [DcqlFixtures.PidSecondaryCredentialId] = secondarySdJwt
            },
            primaryHolderKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, _) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidPrimaryAndSecondaryFamilyNamePrepared(),
            "nonce-policy-one-revoked").ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
            "A policy that rejects a not-valid credential status refuses the presentation.");
        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;

        Assert.AreEqual(1, policy.ConsultationCount,
            "The policy decides once over the complete presentation, not once per presented credential.");
        Assert.HasCount(2, policy.StatusesAt(0),
            "Both presented credentials carried a status claim, so both outcomes reach the one decision.");
        Assert.Contains(new CredentialQueryId(DcqlFixtures.PidPrimaryCredentialId), policy.StatusesAt(0).Keys,
            "The outcome map is keyed by DCQL credential query identifier.");
        Assert.Contains(new CredentialQueryId(DcqlFixtures.PidSecondaryCredentialId), policy.StatusesAt(0).Keys,
            "The outcome map is keyed by DCQL credential query identifier.");

        Assert.IsNotNull(failed.CredentialStatusRefusal,
            "A credential-status refusal rides the failed state as typed detail for the relying party.");
        Assert.HasCount(1, failed.CredentialStatusRefusal!.Credentials,
            "Only the credential whose entry read 0x01 INVALID is refused; the valid one is passed over.");
        Assert.AreEqual(DcqlFixtures.PidSecondaryCredentialId,
            failed.CredentialStatusRefusal.Credentials[0].CredentialQueryId.Value,
            "The refusal names the revoked credential by the credential query it answered.");
        Assert.AreEqual(StatusTypes.Invalid, failed.CredentialStatusRefusal.Credentials[0].Outcome.Status,
            "The refusal carries the raw Section 7.1 status value the gate read.");
        Assert.AreEqual(CredentialStatusDisposition.Revoked,
            failed.CredentialStatusRefusal.Credentials[0].Disposition,
            "Section 7.1 reads 0x01 INVALID as revoked.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token Status
    /// List, Section 7.1</see>: "0x00 - "VALID" - The status of the Referenced Token is valid, correct or legal."
    /// A presentation whose credentials all read that value stands even under the refusing policy, and the outcome
    /// the verifier read for each credential is surfaced on the verified state so the relying party never re-parses
    /// the verified <c>vp_token</c> to learn it.
    /// </summary>
    [TestMethod]
    public async Task PolicyAcceptsATwoCredentialPresentationWhoseCredentialsBothReadValid()
    {
        const int primaryIndex = 11;
        const int secondaryIndex = 12;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        CountingCredentialStatusPolicy policy = new(CredentialStatusPolicies.RefuseNotValid);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: policy.Decide);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string primarySdJwt, PrivateKeyMemory primaryHolder, PublicKeyMemory primaryIssuer) =
            await IssuePidAsync("Erika", "Mustermann", new StatusListReference(primaryIndex, StatusListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory primaryHolderKey = primaryHolder;
        using PublicKeyMemory primaryIssuerKey = primaryIssuer;

        (string secondarySdJwt, PrivateKeyMemory secondaryHolder, PublicKeyMemory secondaryIssuer) =
            await IssuePidAsync("Hans", "Schmidt", new StatusListReference(secondaryIndex, StatusListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory secondaryHolderKey = secondaryHolder;
        using PublicKeyMemory secondaryIssuerKey = secondaryIssuer;

        app.RegisterIssuerTrust(IssuerId, primaryIssuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys,
            new Dictionary<string, string>(StringComparer.Ordinal)
            {
                [DcqlFixtures.PidPrimaryCredentialId] = primarySdJwt,
                [DcqlFixtures.PidSecondaryCredentialId] = secondarySdJwt
            },
            primaryHolderKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, string? refusalDetail) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidPrimaryAndSecondaryFamilyNamePrepared(),
            "nonce-policy-both-valid").ConfigureAwait(false);

        Assert.IsNull(refusalDetail,
            "Both credentials read 0x00 VALID, so the Response URI answers the OID4VP 1.0 Section 8.2 success.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "A presentation the policy accepts reaches the verified terminal state.");
        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;

        Assert.AreEqual(1, policy.ConsultationCount,
            "The policy decides once over the complete presentation.");
        Assert.IsNotNull(verified.CredentialStatuses,
            "The outcomes the verifier read are surfaced on the verified state.");
        Assert.HasCount(2, verified.CredentialStatuses!,
            "Both presented credentials carried a status claim, so both outcomes are surfaced.");
        Assert.IsTrue(verified.CredentialStatuses[new CredentialQueryId(DcqlFixtures.PidPrimaryCredentialId)].IsValid,
            "An unset entry reads 0x00 VALID.");
        Assert.IsTrue(verified.CredentialStatuses[new CredentialQueryId(DcqlFixtures.PidSecondaryCredentialId)].IsValid,
            "An unset entry reads 0x00 VALID.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> makes step 1 "Check for the existence of a status claim": a credential carrying no
    /// status claim yields no status value for step 7's "Check the status value as described in Section 7", so it
    /// never enters the outcome map and the policy is not consulted at all — a deployment that refuses not-valid
    /// statuses does not thereby refuse credentials whose issuer published no status list.
    /// </summary>
    [TestMethod]
    public async Task PolicyIsNotConsultedWhenNoPresentedCredentialCarriesAStatusClaim()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        CountingCredentialStatusPolicy policy = new(CredentialStatusPolicies.RefuseNotValid);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: policy.Decide);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidAsync("Alice", "Smith", status: null).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, string? refusalDetail) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNamePrepared(),
            "nonce-policy-no-status").ConfigureAwait(false);

        Assert.IsNull(refusalDetail,
            "A credential with no status claim has no status to refuse, so the Response URI answers 200.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "A credential carrying no status claim verifies under the refusing policy unchanged.");
        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;

        Assert.AreEqual(0, policy.ConsultationCount,
            "Nothing was checked, so there is no outcome map to decide over and the policy is not consulted.");
        Assert.IsNull(verified.CredentialStatuses,
            "A credential without a status claim is never an entry in the surfaced outcome map.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 6: "If the provided index is out of bounds of the Status List, no statement
    /// about the status of the Referenced Token can be made and the Referenced Token MUST be rejected", and closing
    /// the section: "If any of these checks fails, no statement about the status of the Referenced Token can be
    /// made and the Referenced Token SHOULD be rejected." The rejection is the verifier's own, taken before any
    /// relying-party policy is asked: an undeterminable status never reaches a decision a policy could accept.
    /// </summary>
    [TestMethod]
    public async Task AnUndeterminableStatusIsRefusedBeforeThePolicyIsConsulted()
    {
        const int outOfBoundsIndex = 999;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        CountingCredentialStatusPolicy policy = new(CredentialStatusPolicies.RefuseNotValid);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: policy.Decide);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidAsync("Alice", "Smith", new StatusListReference(outOfBoundsIndex, StatusListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, _) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNamePrepared(),
            "nonce-policy-undeterminable").ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
            "An index outside the Status List leaves the status undeterminable, which fails closed.");
        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;

        Assert.AreEqual(VerifierFlowRefusalKind.StatusUndeterminable, failed.Refusal!.Value.Kind,
            "An undeterminable status is the verifier's own rejection, not a relying-party policy refusal.");
        Assert.AreEqual(0, policy.ConsultationCount,
            "No statement about the status could be made, so no outcome reaches the policy to decide over.");
        Assert.IsNull(failed.CredentialStatusRefusal,
            "The typed credential-status refusal is the policy's product; an undeterminable status carries none.");
    }


    /// <summary>
    /// <see href="https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.html#section-8.3">Token
    /// Status List, Section 8.3</see> step 2, "Resolve the Status List Token from the provided URI": a
    /// resolver that could not obtain the Status List Token at all — signaled with
    /// <see cref="StatusListResolutionException"/> — is the same "no statement about the status … can be
    /// made" outcome an out-of-bounds index or a subject mismatch is, refused before any relying-party
    /// policy is consulted.
    /// </summary>
    [TestMethod]
    public async Task AResolutionFailureIsRefusedBeforeThePolicyIsConsulted()
    {
        const int credentialIndex = 55;

        ResolveVerifiedStatusListTokenDelegate failingResolver = (context, ct) =>
            throw new StatusListResolutionException(context.Reference.Uri, "The status list host refused the connection.");

        CountingCredentialStatusPolicy policy = new(CredentialStatusPolicies.RefuseNotValid);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: failingResolver,
            credentialStatusPolicy: policy.Decide);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidAsync("Alice", "Smith", new StatusListReference(credentialIndex, StatusListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, _) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNamePrepared(),
            "nonce-policy-resolution-failure").ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
            "A Status List Token the verifier could not obtain leaves the status undeterminable, which fails closed.");
        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;

        Assert.AreEqual(VerifierFlowRefusalKind.StatusUndeterminable, failed.Refusal!.Value.Kind,
            "A resolution failure is answered invalid_request the same way any other undeterminable status is.");
        Assert.AreEqual(0, policy.ConsultationCount,
            "No statement about the status could be made, so no outcome reaches the policy to decide over.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see>: "The processing rules for Referenced Tokens ... MUST precede any evaluation of a
    /// Referenced Token's status" and "If the validation procedures for the Referenced Token determine it is
    /// invalid, further procedures regarding Status List MUST NOT be performed." A presentation the DCQL verdict
    /// already refuses — here a claim <c>values</c> constraint the disclosed <c>family_name</c> does not meet — is
    /// answered as unverifiable with no status evaluation and therefore no policy decision, even though the
    /// credential's status list entry reads <c>0x01</c> "INVALID".
    /// </summary>
    [TestMethod]
    public async Task PolicyIsNotConsultedWhenTheVerificationVerdictAlreadyRefusesThePresentation()
    {
        const int credentialIndex = 21;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[credentialIndex] = StatusTypes.Invalid;

        CountingCredentialStatusPolicy policy = new(CredentialStatusPolicies.RefuseNotValid);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: policy.Decide);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidAsync("Erika", "Mustermann", new StatusListReference(credentialIndex, StatusListUri))
                .ConfigureAwait(false);
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
            "nonce-policy-unsatisfied-query").ConfigureAwait(false);

        Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
            "A presentation that does not satisfy the Authorization Request's DCQL query is refused.");
        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;

        Assert.AreEqual(VerifierFlowRefusalKind.Unverifiable, failed.Refusal!.Value.Kind,
            "The verification verdict, not the credential's status, is the reason the presentation is refused.");
        Assert.AreEqual(0, policy.ConsultationCount,
            "The Referenced Token's own processing rules precede its status evaluation, so a negative verdict " +
            "means no status is evaluated and no policy decision is taken.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 8.2</see> defines only the success answer of the Response URI, so a refusal
    /// borrows the authorization-error vocabulary of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>, where
    /// <c>access_denied</c> is "The resource owner or authorization server denied the request." — the code for a
    /// relying party that denies an otherwise verifiable presentation on its own policy. Section 15.9 of OID4VP
    /// governs what rides beside it: "Error responses SHOULD avoid including sensitive or detailed contextual
    /// information that could be used to infer the End-User's data", so the <c>error_description</c> names neither
    /// the credential query, nor the raw status value, nor which not-valid state it read; that detail rides the
    /// failed flow state instead.
    /// </summary>
    [TestMethod]
    public async Task TheResponseUriAnswersAPolicyRefusalAsAccessDeniedCarryingNoEndUserDetail()
    {
        const int credentialIndex = 42;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[credentialIndex] = StatusTypes.Invalid;

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: CredentialStatusPolicies.RefuseNotValid);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidAsync("Alice", "Smith", new StatusListReference(credentialIndex, StatusListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        //Starting the wallet client aligns the registration onto the in-process listener's base address, so
        //the Response URI the test posts to and the one the wallet binds its presentation to are the same.
        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        ClientRecord alignedRegistration =
            app.Host("default").Registrations[verifierKeys.Registration.TenantId.Value];
        Uri responseUri = alignedRegistration.ResponseUri!;
        string clientIdRedirectUri =
            $"{WellKnownClientIdPrefixes.RedirectUri.Value}:{responseUri.OriginalString}";

        //OID4VP 1.0 §5.9.3: under the redirect_uri prefix the prefixed form is the canonical client_id, which
        //the verifier's KB-JWT aud check reads off the registration.
        app.Host("default").Registrations[alignedRegistration.TenantId.Value] =
            alignedRegistration with { ClientId = clientIdRedirectUri };

        const string Nonce = "nonce-policy-wire";
        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce(Nonce),
            DcqlFixtures.PidFamilyNamePrepared(),
            transactionData: null,
            jarAdditionalHeaderClaims: null,
            responseMode: WellKnownResponseModes.DirectPost,
            TestContext.CancellationToken).ConfigureAwait(false);

        //RFC 6749 §3.1.2 query response mode: the wallet composes the response URL rather than POSTing it, so
        //the test itself is the party that reaches the Response URI and reads what the Verifier wrote there.
        string dcqlQueryJson = JsonSerializer.Serialize(
            DcqlFixtures.PidFamilyName(), TestSetup.DefaultSerializationOptions);

        Dictionary<string, string> inlineParameters = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.ClientId] = clientIdRedirectUri,
            [OAuthRequestParameterNames.ResponseType] =
                Oid4VpAuthorizationRequestParameterValues.ResponseTypeVpToken,
            [OAuthRequestParameterNames.ResponseMode] = WellKnownResponseModes.Query,
            [Oid4VpAuthorizationRequestParameterNames.ResponseUri] = responseUri.OriginalString,
            [WellKnownJwtClaimNames.Nonce] = Nonce,
            [OAuthRequestParameterNames.State] = parHandle,
            [Oid4VpAuthorizationRequestParameterNames.DcqlQuery] = dcqlQueryJson
        };

        PresentationResult result = await walletClient.PresentJarAsync(
            new PresentJarOptions
            {
                CompactJar = null,
                RequestUri = responseUri,
                ExpectedVerifierClientId = clientIdRedirectUri,
                InlineAuthorizationParameters = inlineParameters,
                FlowId = $"wallet-policy-wire-{Guid.NewGuid():N}"
            },
            TestContext.CancellationToken).ConfigureAwait(false);

        string vpTokenJson = ReadRedirectParameter(
            result.PostedResponseArtifact, AuthorizationResponseParameters.VpToken);

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new KeyValuePair<string, string>(AuthorizationResponseParameters.VpToken, vpTokenJson),
                new KeyValuePair<string, string>(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "OID4VP 1.0 Section 8.2 reserves 200 for a successfully processed Authorization Response; a refusal " +
            "answers RFC 6749 Section 4.1.2.1's error shape as HTTP 400.");
        Assert.IsNotNull(contentType, "The Response URI answers with a media type on every answer it composes.");
        Assert.Contains("application/json", contentType!, StringComparison.Ordinal,
            "The Response URI's answers are JSON objects.");
        Assert.Contains($"\"{OAuthRequestParameterNames.Error}\":\"{OAuthErrors.AccessDenied}\"", body,
            StringComparison.Ordinal,
            "RFC 6749 Section 4.1.2.1's access_denied is the code for a request the relying party denied.");

        string errorDescription = ReadJsonMember(body, OAuthRequestParameterNames.ErrorDescription);
        Assert.DoesNotContain(DcqlFixtures.PidCredentialId, errorDescription, StringComparison.Ordinal,
            "OID4VP 1.0 Section 15.9 keeps the credential query out of the wire description.");
        Assert.DoesNotContain("0x01", errorDescription, StringComparison.Ordinal,
            "OID4VP 1.0 Section 15.9 keeps the raw status value out of the wire description.");
        Assert.DoesNotContain("revoked", errorDescription, StringComparison.OrdinalIgnoreCase,
            "OID4VP 1.0 Section 15.9 keeps which not-valid state was read out of the wire description.");
        Assert.DoesNotContain("suspended", errorDescription, StringComparison.OrdinalIgnoreCase,
            "OID4VP 1.0 Section 15.9 keeps which not-valid state was read out of the wire description.");

        Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
            "The refused presentation leaves the verifier's flow in its failed terminal state.");
        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;

        Assert.AreEqual(VerifierFlowRefusalKind.PolicyRefused, failed.Refusal!.Value.Kind,
            "A relying-party policy refusal is the refusal kind that answers access_denied.");
        Assert.AreEqual(OAuthErrors.AccessDenied, failed.Refusal!.Value.ErrorCode,
            "The typed refusal selects the RFC 6749 Section 4.1.2.1 code the wire carries.");
        Assert.IsNotNull(failed.CredentialStatusRefusal,
            "The detail the wire withholds rides the failed state as the typed credential-status refusal.");
        Assert.AreEqual(DcqlFixtures.PidCredentialId,
            failed.CredentialStatusRefusal!.Credentials[0].CredentialQueryId.Value,
            "The typed refusal names the credential query the wire description does not.");
        Assert.AreEqual(StatusTypes.Invalid, failed.CredentialStatusRefusal.Credentials[0].Outcome.Status,
            "The typed refusal carries the raw status value the wire description does not.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> closing: "If any of these checks fails, no statement about the status of the
    /// Referenced Token can be made and the Referenced Token SHOULD be rejected." Step 1's check is "Check for the
    /// existence of a status claim, check for the existence of a status_list claim within the status claim" — a
    /// <c>status</c> object naming only a mechanism this verifier cannot evaluate passes the first half and fails
    /// the second, so no statement is possible and the presentation is rejected. The rejection borrows
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> — "The request is missing a required parameter, includes an invalid parameter value,
    /// includes a parameter more than once, or is otherwise malformed." — as HTTP 400, while
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 15.9</see>'s "Error responses SHOULD avoid including sensitive or detailed
    /// contextual information that could be used to infer the End-User's data." keeps the credential query and the
    /// mechanism the issuer named off the wire; both ride the flow state's log-only reason instead.
    /// </summary>
    [TestMethod]
    public async Task AStatusNamingOnlyAnUnevaluableMechanismIsRefusedAsUndeterminable()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        CountingCredentialStatusPolicy policy = new(CredentialStatusPolicies.RefuseNotValid);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: countingResolver,
            credentialStatusPolicy: policy.Decide);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidWithRawStatusAsync(
                SdJwtVpFixture.IdentifierListOnlyStatusObject(IdentifierListEntryId, IdentifierListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, string? refusalDetail) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNamePrepared(),
            "nonce-policy-identifier-list-refused").ConfigureAwait(false);

        Assert.IsNotNull(refusalDetail,
            "No statement about the credential's status can be made, so the Response URI answers a non-200.");
        OAuthErrorAssertions.AssertWireStatusCode(400, refusalDetail!,
            "RFC 6749 Section 4.1.2.1's error vocabulary is answered as HTTP 400, never as a 500 server fault.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(refusalDetail!);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "A presentation whose status cannot be determined is not a relying-party denial: it rides " +
            "invalid_request, never access_denied.");
        Assert.IsFalse(string.IsNullOrWhiteSpace(wireDescription),
            "RFC 6749 Section 4.1.2.1's error_description is the human-readable text a refused client reads.");
        Assert.DoesNotContain(DcqlFixtures.PidCredentialId, wireDescription, StringComparison.Ordinal,
            "OID4VP 1.0 Section 15.9 keeps the credential query out of the wire description.");
        Assert.DoesNotContain(StatusMechanismNames.IdentifierList, wireDescription, StringComparison.Ordinal,
            "OID4VP 1.0 Section 15.9 keeps the mechanism the issuer named out of the wire description.");

        Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
            "A status about which no statement can be made fails the presentation closed.");
        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;

        Assert.AreEqual(VerifierFlowRefusalKind.StatusUndeterminable, failed.Refusal!.Value.Kind,
            "A status claim the verifier cannot evaluate is the same undeterminable rejection an unreadable " +
            "Status List Token is, not a policy refusal.");
        Assert.IsNull(failed.CredentialStatusRefusal,
            "The typed credential-status refusal is the policy's product; an undeterminable status carries none.");
        Assert.Contains(DcqlFixtures.PidCredentialId, failed.Reason, StringComparison.Ordinal,
            "The detail Section 15.9 keeps off the wire rides the flow state, naming the credential query.");
        Assert.Contains(StatusMechanismNames.IdentifierList, failed.Reason, StringComparison.Ordinal,
            "The detail Section 15.9 keeps off the wire rides the flow state, naming the mechanism the issuer " +
            "stated and this verifier does not evaluate.");
        Assert.AreEqual(0, resolverInvocations(),
            "Step 1 finds no status_list within the status claim, so step 2's resolution never runs.");
        Assert.AreEqual(0, policy.ConsultationCount,
            "No statement about the status could be made, so no outcome reaches the policy to decide over.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> closing states a SHOULD, not a MUST: "If any of these checks fails, no statement
    /// about the status of the Referenced Token can be made and the Referenced Token SHOULD be rejected." A
    /// relying party that evaluates the named mechanism out of band takes the exception the SHOULD admits, and
    /// then needs what the issuer stated: the presentation verifies and the credential's <c>status</c> claim is
    /// surfaced with its mechanism names and no reference, distinct both from a credential carrying no status
    /// claim and from one carrying a resolvable <c>status_list</c>. It is surfaced as a claim, not as a status
    /// outcome — the verifier evaluated nothing, so it states nothing about the credential's status.
    /// </summary>
    [TestMethod]
    public async Task AStatusNamingOnlyAnUnevaluableMechanismIsSurfacedWhenSurfacingIsChosen()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: countingResolver,
            unsupportedStatusMechanisms: UnsupportedStatusMechanismDisposition.Surface);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidWithRawStatusAsync(
                SdJwtVpFixture.IdentifierListOnlyStatusObject(IdentifierListEntryId, IdentifierListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, string? refusalDetail) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNamePrepared(),
            "nonce-policy-identifier-list-surfaced").ConfigureAwait(false);

        Assert.IsNull(refusalDetail,
            "The relying party took the SHOULD's exception, so the Response URI answers the OID4VP 1.0 " +
            "Section 8.2 success.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "A presentation the relying party chose to accept reaches the verified terminal state.");
        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;

        Assert.IsTrue(verified.Credentials.TryGetValue(
            new CredentialQueryId(DcqlFixtures.PidCredentialId), out VpCredentialClaims? credential),
            "The verified credentials are keyed by the DCQL credential query identifier each answered.");
        Assert.IsNotNull(credential!.Status,
            "Token Status List Section 6.1 requires the status claim to name at least one mechanism, and the " +
            "issuer named one, so the credential carries a status claim.");
        Assert.IsNull(credential.Status!.StatusList,
            "The claim names no status_list mechanism, so there is no reference for the relying party to resolve.");
        Assert.HasCount(1, credential.Status.Mechanisms,
            "The issuer named exactly one mechanism, so exactly one is surfaced.");
        Assert.Contains(StatusMechanismNames.IdentifierList, credential.Status.Mechanisms,
            "The mechanism reaches the relying party by name, which is what makes an out-of-band evaluation " +
            "possible at all.");
        Assert.IsNull(verified.CredentialStatuses,
            "The verifier evaluated no status, so it records no outcome — a surfaced mechanism is a statement " +
            "about what the issuer said, never about the credential's status.");
        Assert.AreEqual(0, resolverInvocations(),
            "Step 2's resolution is for a status_list reference; a claim carrying none reaches no resolver.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token Status
    /// List, Section 8.3</see> step 1 begins "Check for the existence of a status claim". Refusing a status claim
    /// this verifier cannot evaluate is a decision about a claim that exists: a credential whose issuer published
    /// no status information at all carries no claim, ends the status procedure at step 1, and verifies
    /// unchanged — the absent state of the three the step-1 check separates.
    /// </summary>
    [TestMethod]
    public async Task ACredentialCarryingNoStatusClaimIsNotRefusedUnderTheDefault()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell app = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidAsync("Alice", "Smith", status: null).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, string? refusalDetail) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNamePrepared(),
            "nonce-policy-status-absent-default").ConfigureAwait(false);

        Assert.IsNull(refusalDetail,
            "A credential with no status claim has no status to reject, so the Response URI answers 200.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "The fail-closed default applies to a status claim that exists, not to a credential without one.");
        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;

        Assert.IsTrue(verified.Credentials.TryGetValue(
            new CredentialQueryId(DcqlFixtures.PidCredentialId), out VpCredentialClaims? credential),
            "The verified credentials are keyed by the DCQL credential query identifier each answered.");
        Assert.IsNull(credential!.Status,
            "Step 1's existence check found no status claim, so the credential surfaces none.");
        Assert.IsNull(verified.CredentialStatuses,
            "Nothing was evaluated, so no outcome is recorded.");
        Assert.AreEqual(0, resolverInvocations(),
            "Step 1 ends the procedure, so step 2's resolution of a Status List Token never runs.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status
    /// List, Section 6.2</see>: "status_list: REQUIRED when the status mechanism defined in this specification is
    /// used." The disposition of a claim naming only mechanisms the verifier cannot evaluate governs that case
    /// alone: a credential whose <c>status</c> claim does name <c>status_list</c> is resolved and evaluated
    /// through Section 8.3 steps 2 to 7 exactly as before, under the same fail-closed default.
    /// </summary>
    [TestMethod]
    public async Task TheFailClosedDefaultLeavesAStatusListReferencingCredentialEvaluated()
    {
        const int credentialIndex = 31;

        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[credentialIndex] = StatusTypes.Invalid;

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell app = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidAsync("Alice", "Smith", new StatusListReference(credentialIndex, StatusListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, string? refusalDetail) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNamePrepared(),
            "nonce-policy-status-list-still-evaluated").ConfigureAwait(false);

        Assert.IsNull(refusalDetail,
            "A determinable status is a statement the verifier can make, so no deployment default refuses it " +
            "on the wire; the relying party's own policy decides.");
        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "A credential naming status_list is evaluated, not rejected for naming a mechanism.");
        var verified = (PresentationVerifiedState)app.GetFlowState(parHandle).State;

        Assert.AreEqual(1, resolverInvocations(),
            "Step 2 resolves the Status List Token from the provided URI for the one reference presented.");
        Assert.IsNotNull(verified.CredentialStatuses,
            "Step 7's status value is the outcome the verifier records for the relying party.");
        Assert.IsTrue(verified.CredentialStatuses!.TryGetValue(
            new CredentialQueryId(DcqlFixtures.PidCredentialId), out CredentialStatusOutcome? outcome),
            "The outcomes are keyed by the DCQL credential query identifier the credential answered.");
        Assert.AreEqual(StatusTypes.Invalid, outcome!.Status,
            "Section 7.1: the entry set to 0x01 INVALID reads back as the value the issuer set.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.2">Token Status
    /// List, Section 6.2</see>: "idx: REQUIRED. The idx (index) claim MUST specify a non-negative Integer that
    /// represents the index to check for status information in the Status List for the current Referenced Token."
    /// A <c>status</c> claim that names <c>status_list</c> and then carries a negative <c>idx</c> fails Section 8.3
    /// step 1's "validate that the content of status_list adheres to the rules defined in Section 6.2" — which is
    /// a malformed presentation, not an unevaluable mechanism: it is refused at the parse boundary as
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c>, never degraded to "this verifier cannot evaluate that mechanism".
    /// </summary>
    [TestMethod]
    public async Task AStatusListReferenceWithANegativeIndexIsRefusedAsMalformed()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell app = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidWithRawStatusAsync(SdJwtVpFixture.NegativeIndexStatusObject(StatusListUri))
                .ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, string? refusalDetail) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNamePrepared(),
            "nonce-policy-negative-index").ConfigureAwait(false);

        Assert.IsNotNull(refusalDetail,
            "A status_list that does not adhere to Section 6.2 is not a presentation the verifier accepts.");
        OAuthErrorAssertions.AssertWireStatusCode(400, refusalDetail!,
            "RFC 6749 Section 4.1.2.1's error vocabulary is answered as HTTP 400, never as a 500 server fault.");

        (string wireError, _) = OAuthErrorAssertions.ReadOAuthErrorBody(refusalDetail!);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "Section 4.1.2.1: a malformed vp_token presentation is answered with invalid_request.");

        Assert.IsInstanceOfType<VerifierFlowFailedState>(app.GetFlowState(parHandle).State,
            "A presentation carrying a status_list that fails Section 6.2 is refused.");
        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;

        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "A negative idx fails Section 6.2's non-negative-Integer rule, which is a malformed presentation " +
            "rather than a status the verifier merely cannot evaluate.");
        Assert.AreEqual(0, resolverInvocations(),
            "The refusal happens at the parse boundary, before any Status List Token would be resolved.");
    }


    /// <summary>
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-6.1">Token Status
    /// List, Section 6.1</see>: "The status (status) claim MUST specify a JSON Object that contains at least one
    /// reference to a status mechanism." A credential whose <c>status</c> claim is the literal <c>{}</c> carries
    /// the claim and names nothing in it, which Section 8.3 step 1's "Check for the existence of a status claim"
    /// answers as a present claim that fails validation — a malformed presentation refused with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c>, never accepted as a credential that was simply not status-checked.
    /// </summary>
    [TestMethod]
    public async Task AStatusClaimCarryingNoMechanismIsRefusedAsMalformed()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell app = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidWithRawStatusAsync(SdJwtVpFixture.EmptyStatusObject()).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, serializedSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, string? refusalDetail) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNamePrepared(),
            "nonce-policy-empty-status").ConfigureAwait(false);

        Assert.IsNotNull(refusalDetail,
            "Section 6.1: a status claim naming no mechanism is not a presentation the verifier accepts.");
        OAuthErrorAssertions.AssertWireStatusCode(400, refusalDetail!,
            "RFC 6749 Section 4.1.2.1's error vocabulary is answered as HTTP 400, never as a 500 server fault.");

        (string wireError, _) = OAuthErrorAssertions.ReadOAuthErrorBody(refusalDetail!);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "Section 4.1.2.1: a malformed vp_token presentation is answered with invalid_request.");

        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "Section 6.1: an empty status object is a malformed presentation, not a status the verifier cannot evaluate.");
        Assert.AreEqual(0, resolverInvocations(),
            "The refusal happens at the parse boundary, before any Status List Token would be resolved.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259, Section 4</see>: "The names within an
    /// object SHOULD be unique." and "When the names within an object are not unique, the behavior of software that
    /// receives such an object is unpredictable." A presented credential whose issuer-signed payload repeats a
    /// top-level claim shows a span-scanning reader one value and a serializer-based reader another, so the seat
    /// refuses the payload before reading any claim from it — HTTP 400 <c>invalid_request</c> per
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>, never a
    /// 500 fault and never one of the two values silently winning.
    /// </summary>
    [TestMethod]
    public async Task AnIssuerPayloadRepeatingTheStatusClaimIsRefusedAsMalformed()
    {
        using StatusListType statusList = StatusListType.Create(
            StatusListCapacity, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        (ResolveVerifiedStatusListTokenDelegate countingResolver, Func<int> resolverInvocations) =
            StatusListFixtures.CountingResolverFor(StatusListUri, statusList, TimeProvider);

        await using TestHostShell app = new(
            TimeProvider, resolveVerifiedStatusListToken: countingResolver);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await IssuePidAsync("Alice", "Smith", new StatusListReference(0, StatusListUri)).ConfigureAwait(false);
        using PrivateKeyMemory holderKey = holderPrivateKey;
        using PublicKeyMemory issuerKey = issuerPublicKey;
        app.RegisterIssuerTrust(IssuerId, issuerKey);

        string repeatedStatusSdJwt = SdJwtVpFixture.AppendTopLevelClaimToIssuerPayload(
            serializedSdJwt,
            WellKnownJwtClaimNames.Status,
            $$$"""{"status_list":{"idx":1,"uri":"{{{StatusListUri}}}"}}""");

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys, repeatedStatusSdJwt, holderKey, TestContext.CancellationToken).ConfigureAwait(false);

        (string parHandle, string? refusalDetail) = await PresentAsync(
            app, verifierKeys, walletClient,
            DcqlFixtures.PidFamilyNamePrepared(),
            "nonce-policy-repeated-status").ConfigureAwait(false);

        Assert.IsNotNull(refusalDetail,
            "A payload repeating a top-level claim is not a presentation the verifier accepts.");
        OAuthErrorAssertions.AssertWireStatusCode(400, refusalDetail!,
            "RFC 6749 Section 4.1.2.1's error vocabulary is answered as HTTP 400, never as a 500 server fault.");

        (string wireError, _) = OAuthErrorAssertions.ReadOAuthErrorBody(refusalDetail!);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "Section 4.1.2.1: a malformed vp_token presentation is answered with invalid_request.");

        var failed = (VerifierFlowFailedState)app.GetFlowState(parHandle).State;
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "RFC 8259 Section 4: a repeated top-level claim name makes the payload's reading unpredictable, which is malformed.");
        Assert.AreEqual(0, resolverInvocations(),
            "The refusal happens before any claim is read, so no Status List Token is resolved.");
    }


    /// <summary>
    /// Wraps a <see cref="CredentialStatusPolicy"/> and records every outcome map it is asked to decide over, so a
    /// test can assert not only what the policy answered but that the verifier consulted it exactly as often as the
    /// verification order allows — once per presentation, and never before the presentation verified.
    /// </summary>
    /// <param name="inner">The policy whose verdict <see cref="Decide"/> returns unchanged.</param>
    private sealed class CountingCredentialStatusPolicy(CredentialStatusPolicy inner)
    {
        /// <summary>The recorded outcome maps, one per consultation, in the order they were decided.</summary>
        private List<IReadOnlyDictionary<CredentialQueryId, CredentialStatusOutcome>> Consultations { get; } = [];

        /// <summary>How many times the verifier asked this policy to decide.</summary>
        public int ConsultationCount => Consultations.Count;

        /// <summary>
        /// The outcome map of one consultation.
        /// </summary>
        /// <param name="index">The consultation, in the order the verifier took them.</param>
        /// <returns>The map that consultation decided over.</returns>
        public IReadOnlyDictionary<CredentialQueryId, CredentialStatusOutcome> StatusesAt(int index) =>
            Consultations[index];

        /// <summary>
        /// Records <paramref name="statuses"/> and answers with the wrapped policy's verdict over it.
        /// </summary>
        /// <param name="statuses">The per-credential outcomes the verifier surfaced.</param>
        /// <returns>The wrapped policy's verdict.</returns>
        public CredentialStatusRefusal? Decide(IReadOnlyDictionary<CredentialQueryId, CredentialStatusOutcome> statuses)
        {
            Consultations.Add(statuses);

            return inner(statuses);
        }
    }




    /// <summary>
    /// Mints a PID SD-JWT VC through the shared fixture under this class's issuer identity, key id and pool.
    /// </summary>
    /// <param name="givenName">The value of the disclosable <c>given_name</c> claim.</param>
    /// <param name="familyName">The value of the disclosable <c>family_name</c> claim.</param>
    /// <param name="status">The Status List entry the credential references, or <see langword="null"/> for none.</param>
    /// <returns>The serialized credential, the holder's private key and the issuer's public key.</returns>
    private ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)>
        IssuePidAsync(string givenName, string familyName, StatusListReference? status) =>
        SdJwtVpFixture.IssuePidCredentialWithClaimsAsync(
            TimeProvider, givenName, familyName, IssuerId, IssuerKeyId, Pool, status,
            TestContext.CancellationToken);


    /// <summary>
    /// Mints a PID SD-JWT VC whose <c>status</c> claim is written verbatim from
    /// <paramref name="rawStatusObject"/> — the shapes <see cref="StatusListReference"/> cannot hold, which is
    /// every shape this class needs beyond a well-formed <c>status_list</c> reference.
    /// </summary>
    /// <param name="rawStatusObject">The <c>status</c> object to write into the issuer-signed payload.</param>
    /// <returns>The serialized credential, the holder's private key and the issuer's public key.</returns>
    private ValueTask<(string SerializedSdJwt, PrivateKeyMemory HolderPrivateKey, PublicKeyMemory IssuerPublicKey)>
        IssuePidWithRawStatusAsync(IReadOnlyDictionary<string, object> rawStatusObject) =>
        SdJwtVpFixture.IssuePidCredentialWithClaimsAsync(
            TimeProvider, "Alice", "Smith", IssuerId, IssuerKeyId, Pool, status: null,
            TestContext.CancellationToken, rawStatusObject);


    /// <summary>
    /// Drives one full cross-device presentation over the in-process listener: the Verifier's PAR, the Wallet's
    /// JAR fetch, and the Wallet's Authorization Response POST to the Response URI.
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
    private async ValueTask<(string ParHandle, string? RefusalDetail)> PresentAsync(
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
    /// Reads one percent-encoded parameter out of the response URL a query-mode Wallet composes.
    /// </summary>
    /// <param name="redirectUrl">The URL the Wallet returned as its response artifact.</param>
    /// <param name="name">The parameter to read.</param>
    /// <returns>The decoded parameter value.</returns>
    private static string ReadRedirectParameter(string redirectUrl, string name)
    {
        int queryStart = redirectUrl.IndexOf('?', StringComparison.Ordinal);
        Assert.IsGreaterThan(-1, queryStart, "A query-mode response URL carries its parameters in a query string.");

        foreach(string pair in redirectUrl[(queryStart + 1)..].Split('&'))
        {
            int separator = pair.IndexOf('=', StringComparison.Ordinal);
            if(separator > 0 && string.Equals(pair[..separator], name, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(separator + 1)..]);
            }
        }

        Assert.Fail($"The response URL carries no '{name}' parameter.");

        return string.Empty;
    }


    /// <summary>
    /// Reads one string member out of the JSON object the Response URI answered with.
    /// </summary>
    /// <param name="body">The response body.</param>
    /// <param name="memberName">The member to read.</param>
    /// <returns>The member's value.</returns>
    private static string ReadJsonMember(string body, string memberName)
    {
        using JsonDocument document = JsonDocument.Parse(body);
        Assert.IsTrue(document.RootElement.TryGetProperty(memberName, out JsonElement member),
            $"The answer's JSON object carries a '{memberName}' member.");

        return member.GetString() ?? string.Empty;
    }
}
