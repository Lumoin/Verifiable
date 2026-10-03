using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using Verifiable.BouncyCastle;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Aead;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vci.Wallet;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The reusable <see cref="Oid4VciWalletClient"/> driving OID4VCI 1.0 issuance over REAL
/// Kestrel HTTP: §6 Pre-Authorized Code Token Request → §7 Nonce Request → §8 Credential
/// Request carrying a verified §7.2.1 holder key proof. Two flavours are exercised — a plain
/// Bearer-authorized, plaintext-response issuance, and a §10 ECDH-ES encrypted-response
/// issuance the wallet decrypts. These replace the hand-rolled raw-<see cref="HttpClient"/>
/// issuance flow with a single client call.
/// </summary>
[TestClass]
internal sealed class Oid4VciWalletClientTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://wallet.client.test";
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");
    private const string ConfigurationId = "eu.europa.ec.eudi.pid.1";
    private const string PreAuthorizedCode = "SplxlOBeZQQYbYS6WxSbIA";
    private const string EndUserSubject = "urn:uuid:end-user-42";
    private const string IssuedCredential = "issued-credential-opaque-42";

    private const string OfferId = "GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM";

    private static ImmutableHashSet<CapabilityIdentifier> IssuerCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciDeferredCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciNotificationEndpoint);

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);

    //Mints the DPoP proof's jti the same way the AuthCode fixtures do — the library default bound
    //to this fixture's own clock, entropy, and pool — whenever a test wires a DpopKey.
    private GenerateIdentifierDelegate DpopJtiGenerator =>
        DefaultIdentifierGenerator.For(TimeProvider, TestEntropy.NewCounterStream(), Pool);


    /// <summary>
    /// Pre-Authorized Code → plain Bearer → plaintext response: the wallet client drives §6/§7/§8
    /// over a real socket and returns the issued Credential, and the issuer seam confirms it
    /// verified the holder proof signature and its c_nonce.
    /// </summary>
    [TestMethod]
    public async Task IssuesCredentialOverPlainBearerAndPlaintextResponse()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        //OID4VCI 1.0 §13.10: keep the plain-bearer credential token within the long-lived
        //threshold ("Long-lived Access Tokens giving access to Credentials MUST not be issued
        //unless sender-constrained"; lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        CredentialOffer offer = ComposeOffer(material);
        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        Result<string, Oid4VciRequestFailure> issued = await walletClient.IssuePreAuthorizedAsync(
            offer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(issued.IsSuccess, "The issuance must succeed over the wire.");
        Assert.AreEqual(IssuedCredential, issued.Value,
            "The wallet client must return the credential the Issuer minted over the wire.");
        Assert.IsTrue(observations.IsProofVerified,
            "The issuance seam must have verified the holder proof signature and its c_nonce.");
        Assert.AreEqual(material.Registration.IssuerUri!.OriginalString, observations.ProofAudience,
            "The minted proof must carry the Credential Issuer identifier as aud.");
    }


    /// <summary>
    /// A Pre-Authorized Code journey whose Token Response returns two <c>credential_identifiers</c> for
    /// the requested configuration spends the token on a Credential Request naming the first of them,
    /// with no <c>credential_configuration_id</c>, and the wallet holds the credential the Issuer minted.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </summary>
    [TestMethod]
    public async Task APreAuthorizedJourneyRequestsByTheGrantedIdentifier()
    {
        const string GrantedIdentifier = "pid-dataset-1";

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await WireCredentialAuthorizationAsync(host, ConfigurationId, GrantedIdentifier, "pid-dataset-2").ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            tokenRequestAuthorizationDetails:
                "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + ConfigurationId + "\"}]");

        Result<string, Oid4VciRequestFailure> issued = await walletClient.IssuePreAuthorizedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(issued.IsSuccess, "The issuance by the granted identifier must succeed over the wire.");
        Assert.AreEqual(IssuedCredential, issued.Value);
        Assert.AreEqual(GrantedIdentifier, observations.RequestedIdentifier,
            "The Credential Request must name the identifier the Token Response returned.");
        Assert.IsNull(observations.RequestedConfigurationId,
            "The Credential Request must not name a credential_configuration_id beside the identifier.");
    }


    /// <summary>
    /// A Pre-Authorized Code Token Response whose <c>credential_identifiers</c> belong to another
    /// configuration than the one the wallet was asked to request leaves the wallet no conformant
    /// Credential Request for it: the wallet answers a malformed-response failure and sends none.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "credential_configuration_id: REQUIRED if a credential_identifiers parameter was not returned
    /// from the Token Response as part of the authorization_details parameter. It MUST NOT be used
    /// otherwise."
    /// </summary>
    [TestMethod]
    public async Task APreAuthorizedTokenGrantingAnotherConfigurationIsNotSpentOnIt()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await WireCredentialAuthorizationAsync(host, "eu.europa.ec.eudi.mdl.1", "mdl-dataset-1").ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            tokenRequestAuthorizationDetails:
                "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + ConfigurationId + "\"}]");

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A token granting another configuration must not be spent on this one.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(0, observations.IssuanceRequests, "No Credential Request may reach the Issuer.");
    }


    /// <summary>
    /// A Token Response granting the requested configuration a <c>credential_identifiers</c> value that is
    /// empty or white space names no Credential Dataset: the wallet answers a malformed-response failure,
    /// raises nothing and sends no Credential Request.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "credential_identifiers: REQUIRED. A non-empty array of strings, each uniquely identifying a
    /// Credential Dataset that can be issued using the Access Token returned in this response."
    /// </summary>
    /// <param name="grantedIdentifier">The identifier the Authorization Server grants.</param>
    [TestMethod]
    [DataRow("")]
    [DataRow(" \t")]
    public async Task AGrantedIdentifierThatNamesNoDatasetIsAMalformedTokenResponse(string grantedIdentifier)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await WireCredentialAuthorizationAsync(host, ConfigurationId, grantedIdentifier).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            tokenRequestAuthorizationDetails:
                "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + ConfigurationId + "\"}]");

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A granted identifier naming no dataset must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(0, observations.IssuanceRequests, "No Credential Request may reach the Issuer.");
    }


    /// <summary>
    /// A Token Response whose <c>authorization_details</c> carry a valid grant for the requested
    /// configuration followed by an entry that is not a conformant <c>openid_credential</c> object (a
    /// scalar, or an object without <c>credential_identifiers</c>) is malformed as a whole: the wallet
    /// answers a malformed-response failure and sends no further request. The library's Authorization
    /// Server emits no such entry, so the response is delivered through the wallet's transport delegate.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "It is a non-empty array of objects, as defined in Section 7 of [RFC9396]." And:
    /// "credential_identifiers: REQUIRED."
    /// </summary>
    /// <param name="trailingEntry">The entry that follows the valid grant.</param>
    [TestMethod]
    [DataRow("42")]
    [DataRow("{\"type\":\"openid_credential\",\"credential_configuration_id\":\"eu.europa.ec.eudi.mdl.1\"}")]
    public async Task AMalformedEntryAfterAValidGrantIsAMalformedTokenResponse(string trailingEntry)
    {
        GrantedDetailsIssuance issuance = await IssueOverGrantedDetailsAsync(
            "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + ConfigurationId + "\","
            + "\"credential_identifiers\":[\"pid-dataset-1\"]}," + trailingEntry + "]").ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "A malformed authorization_details member must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>authorization_details</c> member is an empty array is malformed: the
    /// wallet answers a malformed-response failure and sends no Nonce or Credential Request, by the
    /// configuration or otherwise. The library's Authorization Server emits no such member, so the
    /// response is delivered through the wallet's transport delegate.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "It is a non-empty array of objects, as defined in Section 7 of [RFC9396]."
    /// </summary>
    [TestMethod]
    public async Task AnEmptyAuthorizationDetailsArrayIsAMalformedTokenResponse()
    {
        GrantedDetailsIssuance issuance = await IssueOverGrantedDetailsAsync("[]").ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "An empty authorization_details member must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>authorization_details</c> hold an entry without a <c>type</c>, or whose
    /// <c>type</c> is not a JSON string, is malformed wherever that entry stands beside a valid grant
    /// for the requested configuration: the wallet answers a malformed-response failure and sends no
    /// Nonce or Credential Request. The library's Authorization Server emits no such entry, so the
    /// response is delivered through the wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
    /// "type: An identifier for the authorization details type as a string. The value of the type field
    /// determines the allowable contents of the object that contains it. The value is unique for the
    /// described API in the context of the AS. This field is REQUIRED."
    /// </summary>
    /// <param name="authorizationDetails">The whole <c>authorization_details</c> member the Token Response returns.</param>
    [TestMethod]
    [DataRow("[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"eu.europa.ec.eudi.pid.1\",\"credential_identifiers\":[\"pid-dataset-1\"]},{}]")]
    [DataRow("[{},{\"type\":\"openid_credential\",\"credential_configuration_id\":\"eu.europa.ec.eudi.pid.1\",\"credential_identifiers\":[\"pid-dataset-1\"]}]")]
    [DataRow("[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"eu.europa.ec.eudi.pid.1\",\"credential_identifiers\":[\"pid-dataset-1\"]},{\"type\":42}]")]
    public async Task AnEntryWithoutAStringTypeIsAMalformedTokenResponse(string authorizationDetails)
    {
        GrantedDetailsIssuance issuance = await IssueOverGrantedDetailsAsync(authorizationDetails).ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "An entry without a string type must not be skipped as another type.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>authorization_details</c> hold an entry of another authorization details
    /// type beside a valid <c>openid_credential</c> grant for the requested configuration is read for
    /// that grant: the entry of the other type is skipped and the Credential Request names the granted
    /// identifier alone. The library's Authorization Server emits no such entry, so the response is
    /// delivered through the wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
    /// "type: An identifier for the authorization details type as a string. The value of the type field
    /// determines the allowable contents of the object that contains it. The value is unique for the
    /// described API in the context of the AS. This field is REQUIRED."
    /// </summary>
    [TestMethod]
    public async Task AnEntryOfAnotherTypeBesideAValidGrantIsSkipped()
    {
        GrantedDetailsIssuance issuance = await IssueOverGrantedDetailsAsync(
            "[{\"type\":\"payment_initiation\"},"
            + "{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + ConfigurationId + "\","
            + "\"credential_identifiers\":[\"pid-dataset-1\"]}]").ConfigureAwait(false);

        Assert.IsTrue(issuance.Outcome.IsSuccess, "The valid grant beside an entry of another type must be spent.");
        Assert.HasCount(1, issuance.CredentialRequestBodies, "Exactly one Credential Request must be sent.");
        byte[] credentialRequest = Encoding.UTF8.GetBytes(issuance.CredentialRequestBodies[0]);
        Assert.AreEqual("pid-dataset-1", JwkJsonReader.ExtractStringValue(credentialRequest, "credential_identifier"u8));
        Assert.IsFalse(JwkJsonReader.ContainsKey(credentialRequest, "credential_configuration_id"u8),
            "The Credential Request must not name a credential_configuration_id beside the identifier.");
    }


    /// <summary>
    /// A configuration identifier carrying a quotation mark and a reverse solidus reaches the Issuer as the
    /// wallet was given it, alone: the Credential Request body escapes the value and names no
    /// <c>credential_identifier</c>.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 Section 7</see>:
    /// "All Unicode characters may be placed within the quotation marks, except for the characters that
    /// MUST be escaped: quotation mark, reverse solidus, and the control characters (U+0000 through
    /// U+001F)."
    /// </summary>
    [TestMethod]
    public async Task AConfigurationIdentifierIsWrittenAloneAndEscaped()
    {
        const string QuotedConfigurationId = "eu.europa.ec.eudi.pid.1\"quoted\\path";

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host, QuotedConfigurationId).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);
        Result<string, Oid4VciRequestFailure> issued = await walletClient.IssuePreAuthorizedAsync(
            ComposeOffer(material),
            QuotedConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(issued.IsSuccess, "The escaped Credential Request must be issued over the wire.");
        Assert.AreEqual(QuotedConfigurationId, observations.RequestedConfigurationId);
        Assert.IsNull(observations.RequestedIdentifier,
            "The Credential Request must not name a credential_identifier beside the configuration.");
    }


    /// <summary>
    /// §6.3: a Pre-Authorized Code Token Request the hosted Issuer refuses over the real wire
    /// answers the Issuer's own <c>invalid_grant</c> error as a value, rather than throwing. The
    /// Issuer's <see cref="ValidatePreAuthorizedCodeDelegate"/> seam denies the wrong code with
    /// <see cref="PreAuthorizedCodeDenialReason.InvalidCode"/>, which the library maps to
    /// <see cref="OAuthErrors.InvalidGrant"/>.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestRefusedOverRealWireAnswersTheIssuersOwnErrorValueAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        CredentialOffer offer = new()
        {
            CredentialIssuer = material.Registration.IssuerUri!,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant { PreAuthorizedCode = "wrong-pre-authorized-code" }
        };
        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            offer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "The wrong pre-authorized code must be a refusal over the real wire.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.InvalidGrant, outcome.Error.ErrorCode,
            "The hosted Issuer's own §6.3 mapping of InvalidCode must ride the failure value verbatim.");
    }


    /// <summary>
    /// Pre-Authorized Code → DPoP-bound token → plaintext response, over real Kestrel HTTP, with
    /// the wallet's DPoP wired (<see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>,
    /// <see cref="Oid4VciWalletConfiguration.DpopKey"/>,
    /// <see cref="Oid4VciWalletConfiguration.GenerateIdentifierAsync"/>). A HAIP 1.0 registration
    /// mandates DPoP, so the Issuer challenges the wallet's first §6 Token Request with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 §8</see>
    /// <c>use_dpop_nonce</c>; the wallet's own retry (already exercised in-process by
    /// <see cref="TokenRequestRetriesOnceOnUseDpopNonceChallengeAndUsesTheSecondAnswer"/>) must
    /// complete it end to end against the real Issuer without the code-validation seam being
    /// consulted on the challenged attempt — proven here by the seam being consulted exactly once
    /// despite the two dials the retry makes.
    /// </summary>
    [TestMethod]
    public async Task IssuesCredentialOverDpopBoundTokenWithNonceRetryOverRealWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        int preAuthorizedSeamInvocations = 0;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            ValidatePreAuthorizedCodeDelegate original = candidateIntegration.ValidatePreAuthorizedCodeAsync!;
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                {
                    preAuthorizedSeamInvocations++;

                    return original(code, txCode, clientId, registration, context, ct);
                };

            //HAIP 1.0's AccessTokenAudPolicy.Required needs a resolved audience; the seam's
            //granted openid scope is dropped by RFC 6749 §3.3 narrowing before it ever reaches
            //ClientRecord.ScopeToAudience. Fixed resource-server audience, matching the one
            //ScopeToAudience already carries.
            candidateIntegration.ResolveAccessTokenAudienceAsync = static (registration, issuance, ct) =>
                ValueTask.FromResult<IReadOnlyList<string>?>(["https://rs.example.com"]);
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey walletDpopKey = new(walletDpopKeys, WellKnownJwaValues.Es256);

        static ValueTask<string> ConstructWalletDpopProofAsync(
            DpopProofClaims claims, DpopKey key, CancellationToken ct) =>
            DpopProofConstruction.BuildAsync(
                claims, key, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, Pool, ct);

        CredentialOffer offer = ComposeOffer(material);
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host, constructDpopProofAsync: ConstructWalletDpopProofAsync, dpopKey: walletDpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> resultOutcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            offer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(resultOutcome.IsSuccess, "The issuance must succeed over the wire.");
        CredentialIssuanceResult result = resultOutcome.Value;

        Assert.AreEqual(WellKnownAuthenticationSchemes.DPoP, result.TokenType,
            "RFC 9449 §5 binds this grant's access token the same way it binds every other grant's; a HAIP 1.0 registration mandates it.");
        Assert.IsTrue(result.IsIssued, "The Credential Request must succeed once presented with a proof for the bound token.");
        Assert.AreEqual(IssuedCredential, result.Credentials[0],
            "The wallet client must return the credential the Issuer minted, having completed the RFC 9449 §8 nonce-challenge retry on the token endpoint.");
        Assert.IsTrue(observations.IsProofVerified,
            "The issuance seam must have verified the holder proof signature and its c_nonce.");
        Assert.AreEqual(1, preAuthorizedSeamInvocations,
            "The nonce-challenged first token attempt must never consult the code-validation seam — only the successful retry does, despite two dials.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 §9</see>: "Resource servers
    /// use an HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and
    /// DPoP-Nonce value to accomplish this." and §8: "The client will typically retry the request with
    /// the new nonce value supplied upon receiving a use_dpop_nonce error with an accompanying nonce
    /// value." Pre-Authorized Code → DPoP-bound token → Credential Request over real
    /// Kestrel HTTP, where the server rotates its nonce key after the token was issued (the old key
    /// archived), so the nonce the wallet carries from the token endpoint is not one the Credential
    /// Endpoint accepts. The Credential Endpoint answers the first request with its 401 nonce challenge;
    /// the wallet retries exactly once with the nonce that challenge supplied, and the Credential is issued.
    /// </summary>
    [TestMethod]
    public async Task IssuesCredentialAfterRetryingOnTheCredentialEndpointNonceChallengeOverRealWireAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        string credentialPath = TestHostShell.ComposeEndpointPath(
            WellKnownEndpointNames.Oid4VciCredential, material.Registration.TenantId.Value);
        int credentialProofPresentations = 0;
        bool isNonceKeyRotated = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            //HAIP 1.0's AccessTokenAudPolicy.Required needs a resolved audience.
            candidateIntegration.ResolveAccessTokenAudienceAsync = static (registration, issuance, ct) =>
                ValueTask.FromResult<IReadOnlyList<string>?>(["https://rs.example.com"]);

            ValidateDpopProofDelegate validateProof = candidateIntegration.ValidateDpopProofAsync!;
            candidateIntegration.ValidateDpopProofAsync = (request, ct) =>
            {
                if(request.HttpUrl.EndsWith(credentialPath, StringComparison.Ordinal))
                {
                    _ = Interlocked.Increment(ref credentialProofPresentations);
                }

                return validateProof(request, ct);
            };

            //The wallet asks the Nonce Endpoint for its c_nonce after the token response and before the
            //Credential Request: the server rotates its DPoP nonce key there, archiving the key the
            //token endpoint's nonce was minted under.
            IssueCredentialNonceDelegate issueCredentialNonce = candidateIntegration.IssueCredentialNonceAsync!;
            candidateIntegration.IssueCredentialNonceAsync = (context, ct) =>
            {
                if(!isNonceKeyRotated)
                {
                    isNonceKeyRotated = true;
                    _ = host.RotateDpopHmacKey("test-hmac-2");
                    host.ArchiveRetiringDpopHmacKey(new KeyId("test-hmac-1"));
                }

                return issueCredentialNonce(context, ct);
            };
        }).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey walletDpopKey = new(walletDpopKeys, WellKnownJwaValues.Es256);

        static ValueTask<string> ConstructWalletDpopProofAsync(
            DpopProofClaims claims, DpopKey key, CancellationToken ct) =>
            DpopProofConstruction.BuildAsync(
                claims, key, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
                MicrosoftCryptographicFunctionsAdapter.SignP256Async, Pool, ct);

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host, constructDpopProofAsync: ConstructWalletDpopProofAsync, dpopKey: walletDpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> resultOutcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(isNonceKeyRotated, "The nonce key must have been rotated between the token response and the Credential Request.");
        Assert.IsTrue(resultOutcome.IsSuccess,
            $"The issuance must succeed after the wallet answers the Credential Endpoint's 401 nonce challenge; got {(resultOutcome.IsSuccess ? string.Empty : resultOutcome.Error.Kind + " " + resultOutcome.Error.StatusCode + " " + resultOutcome.Error.ErrorCode)}.");
        Assert.IsTrue(resultOutcome.Value.IsIssued);
        Assert.AreEqual(IssuedCredential, resultOutcome.Value.Credentials[0]);
        Assert.AreEqual(2, credentialProofPresentations,
            "Exactly one retry: the first proof carries the rotated-out nonce and is challenged, the second carries the challenge's nonce.");
    }


    /// <summary>
    /// Pre-Authorized Code → §10 ECDH-ES encrypted response: the wallet asks for response
    /// encryption, the issuer seam composes the JWE with real ECDH-ES + AES-GCM, and the wallet's
    /// DecryptResponse drop-out opens it and reads the credential.
    /// </summary>
    [TestMethod]
    public async Task IssuesCredentialOverEncryptedResponse()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        //OID4VCI 1.0 §13.10: keep the plain-bearer credential token within the long-lived
        //threshold ("Long-lived Access Tokens giving access to Credentials MUST not be issued
        //unless sender-constrained"; lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        //The wallet's §10 response-encryption key pair: the public side rides the
        //credential_response_encryption ask, the private side opens the JWE.
        var responseKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory responsePublic = responseKeys.PublicKey;
        using PrivateKeyMemory responsePrivate = responseKeys.PrivateKey;

        //§8.2: a request carrying credential_response_encryption MUST itself be encrypted. The
        //issuer's request-decryption key pair (advertised via credential_request_encryption.jwks)
        //opens what the wallet's EncryptRequest seam seals.
        var requestKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory requestPublic = requestKeys.PublicKey;
        using PrivateKeyMemory requestPrivate = requestKeys.PrivateKey;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
                await DecryptAsync(jwe, requestPrivate, ct).ConfigureAwait(false);
        }).ConfigureAwait(false);

        CredentialOffer offer = ComposeOffer(material);
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            decryptResponse: (compactJwe, ct) => DecryptAsync(compactJwe, responsePrivate, ct),
            encryptRequest: (requestBody, ct) => EncryptToIssuerAsync(requestBody, requestPublic, ct));

        CredentialResponseEncryption responseEncryption = new()
        {
            Jwk = EcJwkMembers(responsePublic),
            Enc = WellKnownJweEncryptionAlgorithms.A256Gcm
        };

        Result<string, Oid4VciRequestFailure> issued = await walletClient.IssuePreAuthorizedAsync(
            offer,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(issued.IsSuccess, "The encrypted-response issuance must succeed over the wire.");
        Assert.AreEqual(IssuedCredential, issued.Value,
            "The wallet must decrypt the §10 JWE response and read the credential.");
        Assert.IsTrue(observations.IsProofVerified,
            "The issuance seam must have verified the holder proof even on the encrypted path.");
    }


    /// <summary>
    /// A response-encryption JWK member whose value carries a quotation mark and a reverse solidus
    /// reaches the Issuer as the wallet was given it: the Credential Request body escapes the
    /// <c>credential_response_encryption</c> object's members, so the Issuer parses the request and
    /// issues.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 Section 7</see>:
    /// "All Unicode characters may be placed within the quotation marks, except for the characters that
    /// MUST be escaped: quotation mark, reverse solidus, and the control characters (U+0000 through
    /// U+001F)."
    /// </summary>
    [TestMethod]
    public async Task AResponseEncryptionJwkMemberIsWrittenEscaped()
    {
        const string QuotedKeyId = "wallet\"response\\key";

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await WireResponseEncryptionSeamAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        var responseKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory responsePublic = responseKeys.PublicKey;
        using PrivateKeyMemory responsePrivate = responseKeys.PrivateKey;

        var requestKeys = TestKeyMaterialProvider.CreateFreshP256ExchangeKeyMaterial();
        using PublicKeyMemory requestPublic = requestKeys.PublicKey;
        using PrivateKeyMemory requestPrivate = requestKeys.PrivateKey;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.DecryptCredentialRequestAsync = async (jwe, _, _, ct) =>
                await DecryptAsync(jwe, requestPrivate, ct).ConfigureAwait(false);
        }).ConfigureAwait(false);

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            decryptResponse: (compactJwe, ct) => DecryptAsync(compactJwe, responsePrivate, ct),
            encryptRequest: (requestBody, ct) => EncryptToIssuerAsync(requestBody, requestPublic, ct));

        Dictionary<string, object> responseJwk = EcJwkMembers(responsePublic);
        responseJwk[WellKnownJwkMemberNames.Kid] = QuotedKeyId;
        CredentialResponseEncryption responseEncryption = new()
        {
            Jwk = responseJwk,
            Enc = WellKnownJweEncryptionAlgorithms.A256Gcm
        };

        Result<string, Oid4VciRequestFailure> issued = await walletClient.IssuePreAuthorizedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(issued.IsSuccess, "The Credential Request with the escaped response-encryption JWK must be issued over the wire.");
        Assert.AreEqual(QuotedKeyId, observations.ResponseEncryptionKeyId,
            "The Issuer must read the response-encryption JWK member the wallet was given.");
    }


    /// <summary>
    /// §4.1.3: "the Wallet MUST send an HTTP GET request to the URI to retrieve the referenced
    /// Credential Offer Object ... and parse it to recreate the Credential Offer parameters." The
    /// wallet client accepts a by-reference Pre-Authorized offer link, GETs the offer off the real
    /// Issuer endpoint, and drives the fetched offer through to issuance — proving the §4.1.3 fetch
    /// feeds the same downstream §6/§7/§8 path as a directly-composed offer.
    /// </summary>
    [TestMethod]
    public async Task FetchedByReferenceOfferDrivesIssuanceEndToEnd()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        //OID4VCI 1.0 §13.10: keep the plain-bearer credential token within the long-lived
        //threshold ("Long-lived Access Tokens giving access to Credentials MUST not be issued
        //unless sender-constrained"; lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        //The Issuer stores the by-reference offer the wallet will fetch and drive to issuance.
        CredentialOffer storedOffer = ComposeOffer(material);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCredentialOfferAsync =
                (offerId, context, ct) => ValueTask.FromResult<CredentialOffer?>(
                    string.Equals(offerId, OfferId, StringComparison.Ordinal) ? storedOffer : null);
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Uri offerEndpoint = TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!,
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredentialOffer);
        Uri credentialOfferUri = new($"{offerEndpoint}?{CredentialOfferParameterNames.Id}={OfferId}");
        string byReferenceLink = CredentialOfferSerializer.ToByReferenceDeepLink(credentialOfferUri);

        HttpClient httpClient = host.Host("default").SharedHttpClient!;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host, fetchCredentialOffer: GuardedHttpClientTransport.BuildSingleHopTransport(httpClient));

        //§4.1.3: resolve the by-reference link to the offer (GET + parse), then drive issuance off
        //the fetched offer — the same call shape the by-value tests use.
        Result<CredentialOffer, Oid4VciRequestFailure> fetchedOfferOutcome = await walletClient.AcceptCredentialOfferAsync(
            byReferenceLink, TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(fetchedOfferOutcome.IsSuccess, "The by-reference offer fetch must succeed over the wire.");

        Result<string, Oid4VciRequestFailure> issued = await walletClient.IssuePreAuthorizedAsync(
            fetchedOfferOutcome.Value,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(issued.IsSuccess, "The issuance driven off the fetched offer must succeed over the wire.");
        Assert.AreEqual(IssuedCredential, issued.Value,
            "The fetched by-reference offer must drive issuance to the same credential as a composed offer.");
        Assert.IsTrue(observations.IsProofVerified,
            "The issuance seam must have verified the holder proof minted from the fetched offer.");
        Assert.AreEqual(material.Registration.IssuerUri!.OriginalString, observations.ProofAudience,
            "The fetched offer's credential_issuer must carry through as the proof aud.");
    }


    /// <summary>
    /// The detailed result surfaces every Credential of a §8.2 batch response and the §8.3
    /// <c>notification_id</c> — both of which the single-string overload drops.
    /// </summary>
    [TestMethod]
    public async Task DetailedResultSurfacesBatchCredentialsAndNotificationId()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        const string NotificationId = "notif-batch-7Qm2";
        const string FirstCredential = "issued-credential-1";
        const string SecondCredential = "issued-credential-2";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue(
                    [FirstCredential, SecondCredential], NotificationId));
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> resultOutcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(resultOutcome.IsSuccess, "The batch issuance must succeed over the wire.");
        CredentialIssuanceResult result = resultOutcome.Value;

        Assert.IsFalse(result.IsDeferred, "A direct issuance is not deferred.");
        Assert.HasCount(2, result.Credentials, "Both batch Credentials must be surfaced.");
        Assert.AreEqual(FirstCredential, result.Credentials[0]);
        Assert.AreEqual(SecondCredential, result.Credentials[1]);
        Assert.AreEqual(NotificationId, result.NotificationId, "The §8.3 notification_id must be surfaced.");
        Assert.IsFalse(string.IsNullOrEmpty(result.AccessToken), "The access token for follow-up legs must be carried.");
    }


    /// <summary>
    /// A §8.3 deferral (HTTP 202) surfaces as a deferred result carrying the <c>transaction_id</c> and
    /// <c>interval</c>; polling the §9 Deferred Credential Endpoint with that <c>transaction_id</c> then
    /// returns the issued Credential.
    /// </summary>
    [TestMethod]
    public async Task DeferredIssuanceThenPollReturnsCredential()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        const string TransactionId = "txn-deferred-7Qm2";
        const string NotificationId = "notif-deferred-7Qm2";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Defer(TransactionId, intervalSeconds: 5));

            candidateIntegration.ResolveDeferredCredentialAsync = (_, _, _, _, _) =>
                ValueTask.FromResult(DeferredCredentialDecision.Issue([IssuedCredential], NotificationId));
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> deferredOutcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(deferredOutcome.IsSuccess, "The deferred issuance must succeed over the wire.");
        CredentialIssuanceResult deferred = deferredOutcome.Value;

        Assert.IsTrue(deferred.IsDeferred, "An HTTP 202 deferral must surface as deferred.");
        Assert.AreEqual(TransactionId, deferred.TransactionId);
        Assert.AreEqual(5, deferred.DeferredIntervalSeconds, "The §8.3 interval must be surfaced.");
        Assert.IsEmpty(deferred.Credentials, "A deferral carries no Credentials yet.");

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> pollResult = await walletClient.PollDeferredCredentialAsync(
            deferred.TransactionId!,
            deferred.AccessToken,
            deferred.TokenType,
            deferred.ExpiresAt,
            ResolveDeferredEndpoint(host, material),
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pollResult.IsSuccess, "The ready poll must succeed, not refuse.");
        CredentialIssuanceResult polled = pollResult.Value;
        Assert.IsFalse(polled.IsDeferred, "The poll returned the ready Credential.");
        Assert.HasCount(1, polled.Credentials);
        Assert.AreEqual(IssuedCredential, polled.Credentials[0]);
        Assert.AreEqual(NotificationId, polled.NotificationId);
    }


    /// <summary>
    /// After issuance, the Wallet reports a §11 <c>credential_accepted</c> Notification with the
    /// <c>notification_id</c> the response carried; the Issuer's notification seam receives the matching
    /// id and event.
    /// </summary>
    [TestMethod]
    public async Task NotificationReportsCredentialAccepted()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        const string NotificationId = "notif-accept-7Qm2";
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential], NotificationId));
        }).ConfigureAwait(false);

        CredentialNotification? observed = null;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ProcessCredentialNotificationAsync = (notification, _, _, _, _) =>
            {
                observed = notification;

                return ValueTask.FromResult(CredentialNotificationDecision.Accept);
            };
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> resultOutcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(resultOutcome.IsSuccess, "The issuance must succeed over the wire.");
        CredentialIssuanceResult result = resultOutcome.Value;

        Assert.AreEqual(NotificationId, result.NotificationId);

        Oid4VciRequestFailure? notificationFailure = await walletClient.SendCredentialNotificationAsync(
            result.NotificationId!,
            Oid4VciNotificationEvents.CredentialAccepted,
            result.AccessToken,
            result.TokenType,
            ResolveNotificationEndpoint(host, material),
            eventDescription: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNull(notificationFailure, "The Issuer must acknowledge the notification (§11.2 HTTP 204).");
        Assert.IsNotNull(observed, "The Issuer's notification seam must have received the report.");
        Assert.AreEqual(NotificationId, observed!.NotificationId);
        Assert.AreEqual(Oid4VciNotificationEvents.CredentialAccepted, observed.Event);
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>: "the endpoints a client POSTs to ... are themselves taken
    /// from discovered metadata, so a malicious or misconfigured metadata document could point
    /// them at an internal, loopback, or cloud-metadata address ... The OutboundFetchPolicy must
    /// therefore gate every method." A §4.1.3 <c>credential_offer_uri</c> naming a loopback address
    /// is refused before the GET is ever sent.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetRefusesLoopbackCredentialOfferUri()
    {
        List<Uri> invocations = [];
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
            {
                invocations.Add(request.Target);
                throw new InvalidOperationException("The offer GET must never be dialed once the policy denies it.");
            });

        string byReferenceLink = CredentialOfferSerializer.ToByReferenceDeepLink(new Uri("https://127.0.0.1/credential-offer"));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.AcceptCredentialOfferAsync(
            byReferenceLink, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A loopback credential_offer_uri under the secure default must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No response was received; the policy denied the endpoint before any dial.");
        Assert.IsEmpty(invocations, "The transport spy must record ZERO invocations when the policy denies credential_offer_uri.");
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>'s SSRF remark applies to §12.2 metadata's
    /// <c>credential_endpoint</c>: a loopback address is refused before the §8 Credential Request
    /// is ever sent, even though the preceding §7 Nonce Request (a benign endpoint) already
    /// succeeded.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestRefusesLoopbackCredentialEndpointBeforeAnyDial()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://127.0.0.1/credential");
        List<Uri> jsonPostInvocations = [];

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPostInvocations.Add(endpoint);

                if(endpoint == nonceEndpoint)
                {
                    return ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"nonce-value\"}"));
                }

                throw new InvalidOperationException("The credential request must never be dialed once the policy denies it.");
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssueWithAccessTokenDetailedAsync(
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com"),
            CredentialRequestTarget.ForConfiguration(ConfigurationId),
            holderPrivate,
            holderPublic,
            new Oid4VciIssuanceEndpoints
            {
                TokenEndpoint = new Uri("https://issuer.example.com/token"),
                NonceEndpoint = nonceEndpoint,
                CredentialEndpoint = credentialEndpoint
            },
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A loopback credential_endpoint under the secure default must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No response was received; the policy denied the endpoint before any dial.");
        Assert.HasCount(1, jsonPostInvocations, "Only the benign §7 Nonce Request may reach the transport; the §8 Credential Request must not.");
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>'s SSRF remark applies to §12.2 metadata's
    /// <c>nonce_endpoint</c>: a loopback address is refused before the §7 Nonce Request is ever
    /// sent.
    /// </summary>
    [TestMethod]
    public async Task NonceRequestRefusesLoopbackNonceEndpointBeforeAnyDial()
    {
        List<Uri> jsonPostInvocations = [];

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPostInvocations.Add(endpoint);
                throw new InvalidOperationException("The nonce request must never be dialed once the policy denies it.");
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssueWithAccessTokenDetailedAsync(
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com"),
            CredentialRequestTarget.ForConfiguration(ConfigurationId),
            holderPrivate,
            holderPublic,
            new Oid4VciIssuanceEndpoints
            {
                TokenEndpoint = new Uri("https://issuer.example.com/token"),
                NonceEndpoint = new Uri("https://127.0.0.1/nonce"),
                CredentialEndpoint = new Uri("https://issuer.example.com/credential")
            },
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A loopback nonce_endpoint under the secure default must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No response was received; the policy denied the endpoint before any dial.");
        Assert.IsEmpty(jsonPostInvocations, "The transport spy must record ZERO invocations when the policy denies nonce_endpoint.");
    }


    /// <summary>
    /// <see cref="OutboundRequest"/>'s SSRF remark applies to a §9
    /// <c>deferred_credential_endpoint</c> carried over from a prior deferral: a loopback address
    /// is refused before the §9 poll is ever sent.
    /// </summary>
    [TestMethod]
    public async Task DeferredPollRefusesLoopbackDeferredCredentialEndpointBeforeAnyDial()
    {
        List<Uri> jsonPostInvocations = [];
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPostInvocations.Add(endpoint);
                throw new InvalidOperationException("The deferred poll must never be dialed once the policy denies it.");
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.PollDeferredCredentialAsync(
            "txn-loopback",
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://127.0.0.1/deferred"),
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A loopback deferred_credential_endpoint under the secure default must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No response was received; the policy denied the endpoint before any dial.");
        Assert.IsEmpty(jsonPostInvocations, "The transport spy must record ZERO invocations when the policy denies deferred_credential_endpoint.");
    }


    /// <summary>
    /// RFC 9449 §5: "the client MUST provide a valid DPoP proof JWT in a DPoP header when making an
    /// access token request ... applicable for all access token requests regardless of grant type."
    /// The §6 Pre-Authorized Code Token Request carries a <c>DPoP</c> header bound to the token
    /// endpoint (<c>htm=POST</c>, <c>htu=</c> the token endpoint) when the configuration carries a
    /// DPoP key, and no <c>DPoP</c> header at all when it does not.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestCarriesDpopHeaderWhenKeyConfiguredAndNoneWhenAbsent()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        string? capturedProofHeader = null;
        string? capturedHtm = null;
        string? capturedHtu = null;

        Oid4VciWalletClient dpopClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, headers, _, _) =>
            {
                _ = headers.Values.TryGetValue(WellKnownHttpHeaderNames.DPoP, out capturedProofHeader);

                return ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok-dpop\",\"token_type\":\"DPoP\"}"));
            },
            sendJsonPost: CredentialFlowStub(nonceEndpoint, credentialEndpoint),
            constructDpopProofAsync: (claims, _, _) =>
            {
                //Nonce and Credential proofs are minted too; only the §6 Token Request's proof is
                //under test here, identified by its htu.
                if(claims.Htu == tokenEndpoint.GetLeftPart(UriPartial.Path))
                {
                    capturedHtm = claims.Htm;
                    capturedHtu = claims.Htu;
                }

                return ValueTask.FromResult("fake-dpop-proof");
            },
            dpopKey: dpopKey);

        _ = await IssueViaTokenEndpointAsync(dpopClient, tokenEndpoint, nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.AreEqual("fake-dpop-proof", capturedProofHeader, "A configured DPoP key must attach a DPoP header to the §6 Token Request.");
        Assert.AreEqual(WellKnownHttpMethods.Post, capturedHtm, "The proof's htm claim must be POST.");
        Assert.AreEqual(tokenEndpoint.GetLeftPart(UriPartial.Path), capturedHtu, "The proof's htu claim must be bound to the token endpoint.");

        string? capturedHeaderWithoutDpop = "not-yet-called";
        Oid4VciWalletClient bearerClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, headers, _, _) =>
            {
                capturedHeaderWithoutDpop = headers.Values.TryGetValue(WellKnownHttpHeaderNames.DPoP, out string? proof) ? proof : null;

                return ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok-bearer\",\"token_type\":\"Bearer\"}"));
            },
            sendJsonPost: CredentialFlowStub(nonceEndpoint, credentialEndpoint));

        _ = await IssueViaTokenEndpointAsync(bearerClient, tokenEndpoint, nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsNull(capturedHeaderWithoutDpop, "No DPoP key configured must mean no DPoP header on the §6 Token Request.");
    }


    /// <summary>
    /// RFC 9449 §8.1: a token endpoint answering <c>use_dpop_nonce</c> with a <c>DPoP-Nonce</c>
    /// header is retried exactly once with the nonce embedded in a fresh proof, and the retry's
    /// answer is used.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestRetriesOnceOnUseDpopNonceChallengeAndUsesTheSecondAnswer()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        int formPostInvocations = 0;
        string? secondProofNonceClaim = null;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, headers, _, _) =>
            {
                formPostInvocations++;

                return formPostInvocations == 1
                    ? ValueTask.FromResult(JsonResponse(
                        400, "{\"error\":\"use_dpop_nonce\"}", (WellKnownHttpHeaderNames.DPoPNonce, "as-nonce-1")))
                    : ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"DPoP\"}"));
            },
            sendJsonPost: CredentialFlowStub(nonceEndpoint, credentialEndpoint),
            constructDpopProofAsync: (claims, _, _) =>
            {
                if(formPostInvocations == 1)
                {
                    secondProofNonceClaim = claims.Nonce;
                }

                return ValueTask.FromResult("fake-dpop-proof");
            },
            dpopKey: dpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, tokenEndpoint, nonceEndpoint, credentialEndpoint).ConfigureAwait(false);

        Assert.AreEqual(2, formPostInvocations, "Exactly one retry: the token endpoint must be dialed twice, not three times.");
        Assert.AreEqual("as-nonce-1", secondProofNonceClaim, "The retry's proof must embed the nonce the first challenge supplied.");
        Assert.IsTrue(outcome.IsSuccess, "The retried token request must succeed.");
        Assert.IsFalse(outcome.Value.IsDeferred);
    }


    /// <summary>
    /// RFC 6749 §5.2: a second <c>use_dpop_nonce</c> challenge after the one allowed retry answers
    /// the §6.3 Token Error Response value — never a third request.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestFailsOnSecondUseDpopNonceChallengeRatherThanRetryingAgain()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        int formPostInvocations = 0;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
            {
                formPostInvocations++;

                return ValueTask.FromResult(JsonResponse(
                    400, "{\"error\":\"use_dpop_nonce\"}", (WellKnownHttpHeaderNames.DPoPNonce, $"as-nonce-{formPostInvocations}")));
            },
            constructDpopProofAsync: (_, _, _) => ValueTask.FromResult("fake-dpop-proof"),
            dpopKey: dpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, tokenEndpoint, tokenEndpoint, tokenEndpoint).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A repeated challenge must be surfaced as a failure after ONE retry, not dialed a third time.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.UseDpopNonce, outcome.Error.ErrorCode);
        Assert.AreEqual(2, formPostInvocations, "A repeated challenge must be surfaced as a failure after ONE retry, not dialed a third time.");
    }


    /// <summary>
    /// RFC 9449 §5's sender-constraining obligation binds <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>
    /// and <see cref="Oid4VciWalletConfiguration.DpopKey"/> together: a configuration wiring the proof
    /// constructor without the signing key is refused at construction rather than silently degrading
    /// to a plain Bearer request.
    /// </summary>
    [TestMethod]
    public void ConstructWithDpopProofConstructorButNoDpopKeyThrows()
    {
        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            SendJsonPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            ConstructDpopProofAsync = (_, _, _) => ValueTask.FromResult("fake-dpop-proof")
        };

        ArgumentException error = Assert.ThrowsExactly<ArgumentException>(
            () => _ = new Oid4VciWalletClient(configuration));

        Assert.Contains(nameof(Oid4VciWalletConfiguration.DpopKey), error.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 9449 §5's sender-constraining obligation binds <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>
    /// and <see cref="Oid4VciWalletConfiguration.DpopKey"/> together: a configuration wiring the
    /// signing key without the proof constructor is refused at construction rather than silently
    /// degrading to a plain Bearer request.
    /// </summary>
    [TestMethod]
    public void ConstructWithDpopKeyButNoProofConstructorThrows()
    {
        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            SendJsonPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            DpopKey = dpopKey
        };

        ArgumentException error = Assert.ThrowsExactly<ArgumentException>(
            () => _ = new Oid4VciWalletClient(configuration));

        Assert.Contains(nameof(Oid4VciWalletConfiguration.ConstructDpopProofAsync), error.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 9449 §5's sender-constraining obligation binds <see cref="Oid4VciWalletConfiguration.ConstructDpopProofAsync"/>,
    /// <see cref="Oid4VciWalletConfiguration.DpopKey"/>, and
    /// <see cref="Oid4VciWalletConfiguration.GenerateIdentifierAsync"/> together: a configuration
    /// wiring the proof constructor and the signing key without the jti generator is refused at
    /// construction rather than silently degrading to a plain Bearer request.
    /// </summary>
    [TestMethod]
    public void ConstructWithDpopKeyAndProofConstructorButNoGeneratorThrows()
    {
        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            SendJsonPost = (_, _, _, _, _) => throw new InvalidOperationException("No transport is expected in this test."),
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            ConstructDpopProofAsync = (_, _, _) => ValueTask.FromResult("fake-dpop-proof"),
            DpopKey = dpopKey
        };

        ArgumentException error = Assert.ThrowsExactly<ArgumentException>(
            () => _ = new Oid4VciWalletClient(configuration));

        Assert.Contains(nameof(Oid4VciWalletConfiguration.GenerateIdentifierAsync), error.Message, StringComparison.Ordinal);
    }


    /// <summary>
    /// RFC 9449 §9: the Credential Endpoint's own <c>use_dpop_nonce</c> challenge (this Issuer's
    /// wire shape: HTTP 400 with the error in the JSON body, the same shape the §6 Token Endpoint
    /// uses) is retried exactly once with the nonce embedded in a fresh proof.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestRetriesOnceOnUseDpopNonceChallengeAndUsesTheSecondAnswer()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        int credentialInvocations = 0;
        string? secondProofNonceClaim = null;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"DPoP\"}")),
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                if(endpoint == nonceEndpoint)
                {
                    return ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"));
                }

                credentialInvocations++;

                return credentialInvocations == 1
                    ? ValueTask.FromResult(JsonResponse(
                        400, "{\"error\":\"use_dpop_nonce\"}", (WellKnownHttpHeaderNames.DPoPNonce, "rs-nonce-1")))
                    : ValueTask.FromResult(JsonResponse(200, "{\"credentials\":[{\"credential\":\"cred-after-retry\"}]}"));
            },
            constructDpopProofAsync: (claims, _, _) =>
            {
                if(credentialInvocations == 1 && claims.Htu == credentialEndpoint.GetLeftPart(UriPartial.Path))
                {
                    secondProofNonceClaim = claims.Nonce;
                }

                return ValueTask.FromResult("fake-dpop-proof");
            },
            dpopKey: dpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.AreEqual(2, credentialInvocations, "Exactly one retry: the credential endpoint must be dialed twice, not three times.");
        Assert.AreEqual("rs-nonce-1", secondProofNonceClaim, "The retry's proof must embed the nonce the first challenge supplied.");
        Assert.IsTrue(outcome.IsSuccess, "The retried credential request must succeed.");
        Assert.AreEqual("cred-after-retry", outcome.Value.Credentials[0]);
    }


    /// <summary>
    /// The §8.3.1 Credential Error Response shape: a second §9 <c>use_dpop_nonce</c> challenge at
    /// the Credential Endpoint after the one allowed retry answers the failure value — never a
    /// third request.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestFailsOnSecondUseDpopNonceChallengeRatherThanRetryingAgain()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        int credentialInvocations = 0;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"DPoP\"}")),
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                if(endpoint == nonceEndpoint)
                {
                    return ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"));
                }

                credentialInvocations++;

                return ValueTask.FromResult(JsonResponse(
                    400, "{\"error\":\"use_dpop_nonce\"}", (WellKnownHttpHeaderNames.DPoPNonce, $"rs-nonce-{credentialInvocations}")));
            },
            constructDpopProofAsync: (_, _, _) => ValueTask.FromResult("fake-dpop-proof"),
            dpopKey: dpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A repeated challenge must be surfaced as a failure after ONE retry, not dialed a third time.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.UseDpopNonce, outcome.Error.ErrorCode);
        Assert.AreEqual(2, credentialInvocations, "A repeated challenge must be surfaced as a failure after ONE retry, not dialed a third time.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 §9</see>: "Resource servers
    /// use an HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and
    /// DPoP-Nonce value to accomplish this." A Credential Endpoint answering the first request with that
    /// form (401, <c>WWW-Authenticate: DPoP error="use_dpop_nonce", algs="…"</c> and a
    /// <c>DPoP-Nonce</c>) is retried exactly once, with the nonce embedded in a fresh proof.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestRetriesOnceOnAResourceNonceChallengeAndUsesTheSecondAnswer()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        int credentialInvocations = 0;
        string? secondProofNonceClaim = null;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"DPoP\"}")),
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                if(endpoint == nonceEndpoint)
                {
                    return ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"));
                }

                credentialInvocations++;

                return credentialInvocations == 1
                    ? ValueTask.FromResult(JsonResponse(
                        401, "{\"error\":\"use_dpop_nonce\"}",
                        (WellKnownHttpHeaderNames.WwwAuthenticate, ResourceDpopProofs.DpopChallenge("use_dpop_nonce")),
                        (WellKnownHttpHeaderNames.DPoPNonce, "rs-nonce-1")))
                    : ValueTask.FromResult(JsonResponse(200, "{\"credentials\":[{\"credential\":\"cred-after-retry\"}]}"));
            },
            constructDpopProofAsync: (claims, _, _) =>
            {
                if(credentialInvocations == 1 && claims.Htu == credentialEndpoint.GetLeftPart(UriPartial.Path))
                {
                    secondProofNonceClaim = claims.Nonce;
                }

                return ValueTask.FromResult("fake-dpop-proof");
            },
            dpopKey: dpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.AreEqual(2, credentialInvocations, "Exactly one retry: the credential endpoint must be dialed twice, not three times.");
        Assert.AreEqual("rs-nonce-1", secondProofNonceClaim, "The retry's proof must embed the nonce the first challenge supplied.");
        Assert.IsTrue(outcome.IsSuccess, "The retried credential request must succeed.");
        Assert.AreEqual("cred-after-retry", outcome.Value.Credentials[0]);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 §9</see>'s resource form of the
    /// nonce challenge (401, <c>WWW-Authenticate: DPoP error="use_dpop_nonce", algs="…"</c> and a
    /// <c>DPoP-Nonce</c>) answered again after the one allowed retry is surfaced as the failure value,
    /// status 401 and error <c>use_dpop_nonce</c>: never a third request.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestFailsOnASecondResourceNonceChallengeRatherThanRetryingAgain()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        var dpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        DpopKey dpopKey = new(dpopKeys, WellKnownJwaValues.Es256);

        int credentialInvocations = 0;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"DPoP\"}")),
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                if(endpoint == nonceEndpoint)
                {
                    return ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"));
                }

                credentialInvocations++;

                return ValueTask.FromResult(JsonResponse(
                    401, "{\"error\":\"use_dpop_nonce\"}",
                    (WellKnownHttpHeaderNames.WwwAuthenticate, ResourceDpopProofs.DpopChallenge("use_dpop_nonce")),
                    (WellKnownHttpHeaderNames.DPoPNonce, $"rs-nonce-{credentialInvocations}")));
            },
            constructDpopProofAsync: (_, _, _) => ValueTask.FromResult("fake-dpop-proof"),
            dpopKey: dpopKey);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A repeated challenge must be surfaced as a failure after ONE retry, not dialed a third time.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(401, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.UseDpopNonce, outcome.Error.ErrorCode);
        Assert.AreEqual(2, credentialInvocations, "A repeated challenge must be surfaced as a failure after ONE retry, not dialed a third time.");
    }


    /// <summary>
    /// RFC 6749 §5.2 / OID4VCI §6.3: a refused Pre-Authorized Code Token Request answers the
    /// <c>invalid_grant</c> Token Error Response as a value carrying the status and wire code.
    /// </summary>
    [TestMethod]
    public async Task TokenRequestRefusedAnswersErrorResponseWithStatusAndCode()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(400, "{\"error\":\"invalid_grant\"}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, tokenEndpoint, tokenEndpoint, tokenEndpoint).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A refused Token Request must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.InvalidGrant, outcome.Error.ErrorCode);
        Assert.AreEqual(tokenEndpoint, outcome.Error.Endpoint);
    }


    /// <summary>
    /// §6: a Token Response repeating <c>access_token</c> breaks the RFC 7519-style uniqueness
    /// posture this Wallet applies to a fetched JSON document; it answers MalformedResponse naming
    /// the rule rather than a value.
    /// </summary>
    [TestMethod]
    public async Task TokenResponseRepeatingAccessTokenAnswersMalformedResponse()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(
                    200, "{\"access_token\":\"tok-1\",\"access_token\":\"tok-2\",\"token_type\":\"Bearer\"}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, tokenEndpoint, tokenEndpoint, tokenEndpoint).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A repeated access_token member must be malformed, not a value.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.IsNull(outcome.Error.ErrorCode);
        Assert.Contains("duplicate member", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §7.1: a refused Nonce Request answers the endpoint's own error value — the status and
    /// whatever <c>error</c> the body carried — rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task NonceRequestRefusedAnswersErrorResponseWithStatusAndCode()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: (endpoint, _, _, _, _) => endpoint == nonceEndpoint
                ? ValueTask.FromResult(JsonResponse(401, "{\"error\":\"invalid_token\"}"))
                : throw new InvalidOperationException("The credential request must never be dialed once the nonce request is refused."));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A refused Nonce Request must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(401, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.InvalidToken, outcome.Error.ErrorCode);
    }


    /// <summary>
    /// §7.2: a Nonce Response carrying no REQUIRED <c>c_nonce</c> answers MalformedResponse naming
    /// the rule rather than a value.
    /// </summary>
    [TestMethod]
    public async Task NonceResponseWithoutCNonceAnswersMalformedResponse()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: (endpoint, _, _, _, _) => endpoint == nonceEndpoint
                ? ValueTask.FromResult(JsonResponse(200, "{}"))
                : throw new InvalidOperationException("The credential request must never be dialed once the nonce response is malformed."));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A Nonce Response carrying no c_nonce must be malformed, not a value.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("c_nonce", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §8.3.1.2: a refused Credential Request answers the <c>invalid_proof</c> Credential Error
    /// Response as a value carrying the status and wire code.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestRefusedAnswersErrorResponseWithStatusAndCode()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: (endpoint, _, _, _, _) => endpoint == nonceEndpoint
                ? ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"))
                : ValueTask.FromResult(JsonResponse(400, "{\"error\":\"invalid_proof\"}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A refused Credential Request must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(Oid4VciCredentialErrors.InvalidProof, outcome.Error.ErrorCode);
    }


    /// <summary>
    /// §8.3: a Credential Response carrying an empty <c>credentials</c> array answers
    /// MalformedResponse naming the rule rather than a value.
    /// </summary>
    [TestMethod]
    public async Task CredentialResponseWithEmptyCredentialsArrayAnswersMalformedResponse()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: (endpoint, _, _, _, _) => endpoint == nonceEndpoint
                ? ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"))
                : ValueTask.FromResult(JsonResponse(200, "{\"credentials\":[]}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "An empty credentials[] array must be malformed, not a value.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("credentials", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-11.3">§11.3</see>:
    /// "invalid_notification_id: The notification_id in the Notification Request was invalid." A
    /// refused Notification Request answers the value rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task NotificationRefusedAnswersErrorResponseWithStatusAndCode()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(400, "{\"error\":\"invalid_notification_id\"}")));

        Oid4VciRequestFailure? failure = await walletClient.SendCredentialNotificationAsync(
            "notif-unknown",
            Oid4VciNotificationEvents.CredentialAccepted,
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            new Uri("https://issuer.example.com/notification"),
            eventDescription: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(failure, "invalid_notification_id must answer a failure, not null.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, failure.Kind);
        Assert.AreEqual(400, failure.StatusCode);
        Assert.AreEqual(Oid4VciCredentialErrors.InvalidNotificationId, failure.ErrorCode);
    }


    /// <summary>
    /// §9.2: a Deferred Credential Endpoint still assembling the Credential answers HTTP 202, and
    /// the poll surfaces it as a deferred, not-yet-ready result rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task DeferredPollStillPendingReturnsDeferredOutcomeWithoutThrowing()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(202, "{\"transaction_id\":\"txn-1\",\"interval\":5}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> pollResult = await walletClient.PollDeferredCredentialAsync(
            "txn-1",
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com/deferred"),
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(pollResult.IsSuccess, "A still-pending 202 must not be a refusal.");
        Assert.IsTrue(pollResult.Value.IsDeferred, "The still-pending poll must surface as deferred.");
        Assert.AreEqual("txn-1", pollResult.Value.TransactionId);
    }


    /// <summary>
    /// §9.3: a Deferred Credential Request presenting a <c>transaction_id</c> the Issuer does not
    /// recognise answers <c>invalid_transaction_id</c> as a value — <see cref="Oid4VciRequestFailure"/>
    /// — rather than an exception.
    /// </summary>
    [TestMethod]
    public async Task DeferredPollInvalidTransactionIdReturnsRefusalWithoutThrowing()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(400, "{\"error\":\"invalid_transaction_id\"}")));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> pollResult = await walletClient.PollDeferredCredentialAsync(
            "txn-unknown",
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com/deferred"),
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(pollResult.IsSuccess, "invalid_transaction_id must be a refusal, not a success.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, pollResult.Error.Kind);
        Assert.AreEqual(400, pollResult.Error.StatusCode);
        Assert.AreEqual(Oid4VciCredentialErrors.InvalidTransactionId, pollResult.Error.ErrorCode);
    }


    /// <summary>
    /// <see cref="CredentialIssuanceResult.ExpiresAt"/> is the §6 Token Response's <c>expires_in</c>
    /// added to the instant the Wallet sent the Token Request, and <see langword="null"/> when the
    /// response carried no <c>expires_in</c>.
    /// </summary>
    [TestMethod]
    public async Task ExpiresAtEqualsRequestedAtPlusExpiresInWhenPresentAndIsNullWhenAbsent()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        Oid4VciWalletClient withExpiry = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"expires_in\":3600}")),
            sendJsonPost: CredentialFlowStub(nonceEndpoint, credentialEndpoint));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> withExpiryOutcome = await IssueViaTokenEndpointAsync(
            withExpiry, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsTrue(withExpiryOutcome.IsSuccess);
        Assert.AreEqual(TimeProvider.GetUtcNow().AddSeconds(3600), withExpiryOutcome.Value.ExpiresAt);

        Oid4VciWalletClient withoutExpiry = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: CredentialFlowStub(nonceEndpoint, credentialEndpoint));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> withoutExpiryOutcome = await IssueViaTokenEndpointAsync(
            withoutExpiry, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint)
            .ConfigureAwait(false);

        Assert.IsTrue(withoutExpiryOutcome.IsSuccess);
        Assert.IsNull(withoutExpiryOutcome.Value.ExpiresAt);
    }


    //Drives IssueWithAccessTokenDetailedAsync's sibling — the grant-based overload — far enough to
    //exercise the §6 Token Request through to a §8 Credential Response, over the in-process spy
    //delegates, so a token-step assertion can run without a live host.
    private async ValueTask<Result<CredentialIssuanceResult, Oid4VciRequestFailure>> IssueViaTokenEndpointAsync(
        Oid4VciWalletClient walletClient, Uri tokenEndpoint, Uri nonceEndpoint, Uri credentialEndpoint,
        CredentialResponseEncryption? responseEncryption = null)
    {
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        return await walletClient.IssuePreAuthorizedDetailedAsync(
            new PreAuthorizedCodeOfferGrant { PreAuthorizedCode = PreAuthorizedCode },
            new Uri("https://issuer.example.com"),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            new Oid4VciIssuanceEndpoints
            {
                TokenEndpoint = tokenEndpoint,
                NonceEndpoint = nonceEndpoint,
                CredentialEndpoint = credentialEndpoint
            },
            transactionCode: null,
            responseEncryption,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives a Pre-Authorized Code issuance over the in-process transport whose Token Response returns
    /// <paramref name="authorizationDetails"/> as its <c>authorization_details</c> member, and records
    /// every Nonce and Credential Request that follows it, answered by
    /// <see cref="CredentialFlowStub"/>.
    /// </summary>
    /// <param name="authorizationDetails">The whole <c>authorization_details</c> member, as JSON text.</param>
    /// <returns>The issuance outcome and the requests that followed the Token Request.</returns>
    private async ValueTask<GrantedDetailsIssuance> IssueOverGrantedDetailsAsync(string authorizationDetails)
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");
        List<Uri> laterRequests = [];
        List<string> credentialRequestBodies = [];
        Oid4VciJsonPostDelegate flow = CredentialFlowStub(nonceEndpoint, credentialEndpoint);

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(
                    200,
                    "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"authorization_details\":"
                    + authorizationDetails + "}")),
            sendJsonPost: (endpoint, jsonBody, headers, context, ct) =>
            {
                laterRequests.Add(endpoint);
                if(endpoint == credentialEndpoint)
                {
                    credentialRequestBodies.Add(jsonBody);
                }

                return flow(endpoint, jsonBody, headers, context, ct);
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, tokenEndpoint, nonceEndpoint, credentialEndpoint).ConfigureAwait(false);

        return new GrantedDetailsIssuance(outcome, laterRequests, credentialRequestBodies);
    }


    /// <summary>What <see cref="IssueOverGrantedDetailsAsync"/> observed of one issuance.</summary>
    /// <param name="Outcome">The issuance outcome the wallet answered.</param>
    /// <param name="LaterRequests">The endpoints of the Nonce and Credential Requests sent after the Token Request, in order.</param>
    /// <param name="CredentialRequestBodies">The bodies of the Credential Requests sent, in order.</param>
    private sealed record GrantedDetailsIssuance(
        Result<CredentialIssuanceResult, Oid4VciRequestFailure> Outcome,
        IReadOnlyList<Uri> LaterRequests,
        IReadOnlyList<string> CredentialRequestBodies);


    //A §7/§8 JSON-POST spy: the first call (the Nonce Request, empty body) answers c_nonce; every
    //other call (the Credential Request) answers one issued credential.
    private static Oid4VciJsonPostDelegate CredentialFlowStub(Uri nonceEndpoint, Uri credentialEndpoint) =>
        (endpoint, _, _, _, _) => ValueTask.FromResult(endpoint == nonceEndpoint
            ? JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}")
            : JsonResponse(200, "{\"credentials\":[{\"credential\":\"issued-credential\"}]}"));


    /// <summary>
    /// <see cref="Oid4VciWalletConfiguration.OutboundFetchPolicy"/> governs a §4.1.3 by-reference
    /// GET whose <see cref="ExchangeContext"/> carries no policy: a loopback
    /// <c>credential_offer_uri</c> refuses under the configuration's default and dials once the
    /// configuration names a loopback-allowing policy.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetConsultsConfigurationPolicyWhenContextCarriesNone()
    {
        Uri loopbackOfferUri = new("https://127.0.0.1/credential-offer");
        OutboundFetchPolicy loopbackAllowing = OutboundFetchPolicy.SecureDefault with { BlockPrivateAndLoopback = false };

        Oid4VciWalletClient deniedClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
                throw new InvalidOperationException("The offer GET must never be dialed once the policy denies it."));

        Result<CredentialOffer, Oid4VciRequestFailure> denial = await deniedClient.FetchCredentialOfferAsync(
            loopbackOfferUri, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsFalse(denial.IsSuccess, "A loopback credential_offer_uri under the configuration's secure default must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, denial.Error.Kind);

        CredentialOffer minimalOffer = new()
        {
            CredentialIssuer = new Uri("https://issuer.example.com"),
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant { PreAuthorizedCode = "pre-authorized-code" }
        };
        string offerJson = CredentialOfferSerializer.ToJson(minimalOffer);

        Oid4VciWalletClient allowedClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) => ScriptedOutboundTransport.ReadAsync(readResponse, JsonOfferResponse(offerJson), cancellationToken),
            outboundFetchPolicy: loopbackAllowing);

        Result<CredentialOffer, Oid4VciRequestFailure> allowed = await allowedClient.FetchCredentialOfferAsync(
            loopbackOfferUri, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(allowed.IsSuccess, "A loopback-allowing configuration policy must let the GET dial.");
        Assert.IsNotNull(allowed.Value);
    }


    /// <summary>
    /// A policy set explicitly on the call's <see cref="ExchangeContext"/> overrides
    /// <see cref="Oid4VciWalletConfiguration.OutboundFetchPolicy"/>: a configuration that allows
    /// loopback still refuses when the per-call context names the stricter secure default.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetContextPolicyOverridesConfigurationPolicy()
    {
        Uri loopbackOfferUri = new("https://127.0.0.1/credential-offer");
        OutboundFetchPolicy loopbackAllowing = OutboundFetchPolicy.SecureDefault with { BlockPrivateAndLoopback = false };

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
                throw new InvalidOperationException("The offer GET must never be dialed once the policy denies it."),
            outboundFetchPolicy: loopbackAllowing);

        ExchangeContext strictContext = [];
        strictContext.SetOutboundFetchPolicy(OutboundFetchPolicy.SecureDefault);

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            loopbackOfferUri, strictContext, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "The stricter per-call context policy must override the loopback-allowing configuration default.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
    }


    /// <summary>
    /// <see cref="OutboundFetchPolicy.SecureDefault"/>'s <see cref="OutboundFetchPolicy.Redirects"/>
    /// is <see cref="RedirectMode.None"/>. A §4.1.3 offer GET whose first hop answers a redirect is
    /// refused rather than followed: the guarded <see cref="OutboundFetch"/> chokepoint stops at the
    /// first hop, so the transport spy is invoked exactly once.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetDoesNotFollowRedirectUnderSecureDefault()
    {
        int invocationCount = 0;
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
            {
                invocationCount++;
                return ScriptedOutboundTransport.ReadAsync(readResponse, new OutboundResponse
                {
                    StatusCode = 302,
                    Headers = HttpHeaderSet.FromPairs(
                        (WellKnownHttpHeaderNames.Location, "https://elsewhere.example.com/credential-offer"))
                }, cancellationToken);
            });

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A redirect under the secure default's RedirectMode.None must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No terminal response was fetched; the redirect was refused, not followed.");
        Assert.AreEqual(1, invocationCount,
            "The transport spy must be invoked for the first hop only — the redirect is refused, not followed.");
    }


    /// <summary>
    /// The guarded reader rejects an offer exceeding
    /// <see cref="Oid4VciWalletConfiguration.MaximumCredentialOfferBytes"/> and the wallet preserves
    /// its declared or observed size evidence.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetRefusesOversizeBody()
    {
        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (_, _, _, _, _) => throw new InvalidOperationException("No §6 Token Request is expected in this test."),
            SendJsonPost = (_, _, _, _, _) => throw new InvalidOperationException("No §7/§8/§9 request is expected in this test."),
            FetchCredentialOffer = (request, _, readResponse, cancellationToken) => ScriptedOutboundTransport.ReadAsync(readResponse, new OutboundResponse
            {
                StatusCode = 200,
                Headers = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, "application/json")),
                Body = new TaggedMemory<byte>(new byte[128], Tag.Empty)
            }, cancellationToken),
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            MaximumCredentialOfferBytes = 64
        };
        Oid4VciWalletClient walletClient = new(configuration);

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A body exceeding MaximumCredentialOfferBytes must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.TooLarge, outcome.Error.Kind);
        Assert.AreEqual(new OutboundResponseTooLarge(64, 65, OutboundResponseLengthKind.Observed), outcome.Error.TooLarge);
    }


    /// <summary>
    /// §4.1.3 defines no error body for the Credential Offer GET; a non-<c>200</c> status still
    /// answers ErrorResponse but with no wire error code.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetNotFoundAnswersErrorResponseWithNullCode()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
                ScriptedOutboundTransport.ReadAsync(readResponse, new OutboundResponse { StatusCode = 404 }, cancellationToken));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A 404 Credential Offer GET must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, outcome.Error.Kind);
        Assert.AreEqual(404, outcome.Error.StatusCode);
        Assert.IsNull(outcome.Error.ErrorCode, "§4.1.3 defines no error body for this GET.");
    }


    /// <summary>
    /// §4.1.3: the by-reference GET answers <c>200</c> with <c>application/json</c>, but the body
    /// is not well-formed JSON — remote input, so it answers MalformedResponse naming the rule
    /// rather than throwing the <see cref="ArgumentException"/> <see cref="CredentialOfferSerializer.FromJson"/>
    /// raises for a caller-supplied offer.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithNonJsonBodyAnswersMalformedResponseNamingTheRule()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
                ScriptedOutboundTransport.ReadAsync(readResponse, JsonOfferResponse("not-a-json-object"), cancellationToken));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A by-reference offer body that is not well-formed JSON must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("well-formed JSON", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §4.1.1: <c>credential_issuer</c> is REQUIRED. A by-reference offer body that is well-formed
    /// JSON but carries none is remote input, so it answers MalformedResponse naming the rule
    /// rather than throwing.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithNoCredentialIssuerAnswersMalformedResponseNamingTheRule()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
                ScriptedOutboundTransport.ReadAsync(readResponse, JsonOfferResponse(
                    "{\"credential_configuration_ids\":[\"" + ConfigurationId + "\"]}"), cancellationToken));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A by-reference offer carrying no credential_issuer must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("credential_issuer", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §4.1.1: <c>credential_issuer</c> is "The URL of the Credential Issuer". A by-reference offer
    /// body whose <c>credential_issuer</c> is not a URI reference at all (a scheme with no
    /// authority) answers MalformedResponse naming the member; the body is what the remote party
    /// sent, so no exception leaves the fetch.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithUnparseableCredentialIssuerAnswersMalformedResponseNamingTheRule()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
                ScriptedOutboundTransport.ReadAsync(readResponse, JsonOfferResponse(
                    "{\"credential_issuer\":\"http://\",\"credential_configuration_ids\":[\"" + ConfigurationId + "\"]}"), cancellationToken));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A by-reference offer whose credential_issuer is not a URL must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("credential_issuer", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §4.1.3: "The response from the Credential Issuer that contains a Credential Offer Object MUST
    /// use the media type application/json." A response answered with a different media type is
    /// refused.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithWrongContentTypeAnswersMalformedResponse()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
                ScriptedOutboundTransport.ReadAsync(readResponse, OfferResponseWithContentType(MinimalOfferJson(), "text/html"), cancellationToken));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "§4.1.3: a response content type other than application/json must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("text/html", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>A 200 response carrying no Content-Type header is refused the same way a wrong one is.</summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithNoContentTypeHeaderAnswersMalformedResponse()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
                ScriptedOutboundTransport.ReadAsync(readResponse, OfferResponseWithContentType(MinimalOfferJson(), contentType: null), cancellationToken));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A missing Content-Type header must be a refusal, not a silent accept.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("application/json", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-8.3.1">RFC 9110 §8.3.1</see>: "The
    /// type/subtype MAY be followed by semicolon-delimited parameters." A charset parameter does not
    /// change the media type §4.1.3's exact-match gate compares against.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceOfferGetWithContentTypeParameterIsAccepted()
    {
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
                ScriptedOutboundTransport.ReadAsync(readResponse, OfferResponseWithContentType(MinimalOfferJson(), "application/json; charset=utf-8"), cancellationToken));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.FetchCredentialOfferAsync(
            new Uri("https://issuer.example.com/credential-offer"), new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, $"A charset parameter must not affect the media-type comparison. Defect: {outcome.Error?.ErrorDescription}");
    }


    /// <summary>
    /// §10: an encrypted-response ask requires the Credential Response to be a JWE with media type
    /// <c>application/jwt</c>; a response answered in clear (<c>application/json</c>) is remote
    /// input, so it answers MalformedResponse naming the rule rather than throwing. The decrypt
    /// delegate is never consulted — the content-type refusal answers before it would run.
    /// </summary>
    [TestMethod]
    public async Task CredentialResponseAnsweredInClearWhenEncryptionAskedAnswersMalformedResponse()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");

        CredentialResponseEncryption responseEncryption = new()
        {
            Jwk = new Dictionary<string, object> { [WellKnownJwkMemberNames.Kty] = "EC" },
            Enc = WellKnownJweEncryptionAlgorithms.A256Gcm
        };

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(200, "{\"access_token\":\"tok\",\"token_type\":\"Bearer\"}")),
            sendJsonPost: (endpoint, _, _, _, _) => endpoint == nonceEndpoint
                ? ValueTask.FromResult(JsonResponse(200, "{\"c_nonce\":\"c-nonce\"}"))
                : ValueTask.FromResult(JsonResponse(
                    200, "{\"credentials\":[{\"credential\":\"cred\"}]}",
                    (WellKnownHttpHeaderNames.ContentType, "application/json"))),
            encryptRequest: (requestBody, _) => ValueTask.FromResult(requestBody),
            decryptResponse: (_, _) => throw new InvalidOperationException(
                "The content-type refusal must answer before decryption is attempted."));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueViaTokenEndpointAsync(
            walletClient, new Uri("https://issuer.example.com/token"), nonceEndpoint, credentialEndpoint, responseEncryption)
            .ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A response answered in clear when encryption was asked for must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains("application/jwt", outcome.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// §9.2 / §10: the same clear-answer-to-an-encryption-ask rule applies to the Deferred
    /// Credential Endpoint's poll response as it does to the Credential Endpoint's.
    /// </summary>
    [TestMethod]
    public async Task DeferredPollAnsweredInClearWhenEncryptionAskedAnswersMalformedResponse()
    {
        CredentialResponseEncryption responseEncryption = new()
        {
            Jwk = new Dictionary<string, object> { [WellKnownJwkMemberNames.Kty] = "EC" },
            Enc = WellKnownJweEncryptionAlgorithms.A256Gcm
        };

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (_, _, _, _, _) =>
                ValueTask.FromResult(JsonResponse(
                    200, "{\"credentials\":[{\"credential\":\"cred\"}]}",
                    (WellKnownHttpHeaderNames.ContentType, "application/json"))),
            encryptRequest: (requestBody, _) => ValueTask.FromResult(requestBody),
            decryptResponse: (_, _) => throw new InvalidOperationException(
                "The content-type refusal must answer before decryption is attempted."));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> pollResult = await walletClient.PollDeferredCredentialAsync(
            "txn-1",
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com/deferred"),
            responseEncryption,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(pollResult.IsSuccess, "A deferred poll answered in clear when encryption was asked for must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, pollResult.Error.Kind);
        Assert.AreEqual(200, pollResult.Error.StatusCode);
        Assert.Contains("application/jwt", pollResult.Error.ErrorDescription!, StringComparison.OrdinalIgnoreCase);
    }


    /// <summary>
    /// The §6 Token Request carries the pre-authorized code, so a token endpoint answering it with a
    /// redirect is refused as <see cref="Oid4VciRequestFailureKind.RedirectRefused"/>: the request was sent
    /// once and nothing followed, neither to the location nor to any later step (RFC 9110 §15.4.8).
    /// </summary>
    [TestMethod]
    public async Task PreAuthorizedTokenRequestAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");
        List<Uri> formPosts = [];
        List<Uri> jsonPosts = [];

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (endpoint, _, _, _, _) =>
            {
                formPosts.Add(endpoint);

                return ValueTask.FromResult(RedirectResponse(TemporaryRedirectStatusCode));
            },
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPosts.Add(endpoint);

                throw new InvalidOperationException("Nothing may follow a refused §6 Token Request.");
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssuePreAuthorizedDetailedAsync(
            new CredentialOffer
            {
                CredentialIssuer = new Uri("https://issuer.example.com"),
                CredentialConfigurationIds = [ConfigurationId],
                PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant { PreAuthorizedCode = PreAuthorizedCode }
            },
            ConfigurationId,
            holderPrivate,
            holderPublic,
            new Oid4VciIssuanceEndpoints
            {
                TokenEndpoint = tokenEndpoint,
                NonceEndpoint = new Uri("https://issuer.example.com/nonce"),
                CredentialEndpoint = new Uri("https://issuer.example.com/credential")
            },
            transactionCode: null,
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess);
        AssertRedirectRefused(outcome.Error, tokenEndpoint, TemporaryRedirectStatusCode);
        Assert.HasCount(1, formPosts, "The pre-authorized code is sent once and nothing after the redirect.");
        Assert.IsEmpty(jsonPosts, "No later step follows a refused token request.");
    }


    /// <summary>
    /// The §7 Nonce Request carries the access token, so a nonce endpoint answering it with a redirect is
    /// refused as <see cref="Oid4VciRequestFailureKind.RedirectRefused"/>: the request was sent once and the
    /// §8 Credential Request never followed.
    /// </summary>
    [TestMethod]
    public async Task NonceRequestAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        List<Uri> jsonPosts = [];

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPosts.Add(endpoint);

                return ValueTask.FromResult(RedirectResponse(PermanentRedirectStatusCode));
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssueWithAccessTokenDetailedAsync(
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com"),
            CredentialRequestTarget.ForConfiguration(ConfigurationId),
            holderPrivate,
            holderPublic,
            new Oid4VciIssuanceEndpoints
            {
                TokenEndpoint = new Uri("https://issuer.example.com/token"),
                NonceEndpoint = nonceEndpoint,
                CredentialEndpoint = new Uri("https://issuer.example.com/credential")
            },
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess);
        AssertRedirectRefused(outcome.Error, nonceEndpoint, PermanentRedirectStatusCode);
        Assert.HasCount(1, jsonPosts, "The access token is sent once and nothing after the redirect.");
    }


    /// <summary>
    /// The §8 Credential Request carries the access token and the key proof, so a credential endpoint
    /// answering it with a redirect is refused as <see cref="Oid4VciRequestFailureKind.RedirectRefused"/>:
    /// after the §7 Nonce Request, the Credential Request was sent once and nothing followed.
    /// </summary>
    [TestMethod]
    public async Task CredentialRequestAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");
        List<Uri> jsonPosts = [];

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPosts.Add(endpoint);

                return ValueTask.FromResult(endpoint == nonceEndpoint
                    ? JsonResponse(200, "{\"c_nonce\":\"nonce-value\"}")
                    : RedirectResponse(TemporaryRedirectStatusCode));
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssueWithAccessTokenDetailedAsync(
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com"),
            CredentialRequestTarget.ForConfiguration(ConfigurationId),
            holderPrivate,
            holderPublic,
            new Oid4VciIssuanceEndpoints
            {
                TokenEndpoint = new Uri("https://issuer.example.com/token"),
                NonceEndpoint = nonceEndpoint,
                CredentialEndpoint = credentialEndpoint
            },
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess);
        AssertRedirectRefused(outcome.Error, credentialEndpoint, TemporaryRedirectStatusCode);
        Assert.HasCount(2, jsonPosts, "The nonce request and the one credential request, and nothing after the redirect.");
        Assert.AreEqual(credentialEndpoint, jsonPosts[1]);
    }


    /// <summary>
    /// The §9 Deferred Credential Request carries the access token, so a deferred credential endpoint
    /// answering it with a redirect is refused as <see cref="Oid4VciRequestFailureKind.RedirectRefused"/>
    /// and the poll was sent once.
    /// </summary>
    [TestMethod]
    public async Task DeferredPollAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        Uri deferredEndpoint = new("https://issuer.example.com/deferred");
        List<Uri> jsonPosts = [];
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPosts.Add(endpoint);

                return ValueTask.FromResult(RedirectResponse(TemporaryRedirectStatusCode));
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.PollDeferredCredentialAsync(
            "txn-redirected",
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            accessTokenExpiresAt: null,
            deferredEndpoint,
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess);
        AssertRedirectRefused(outcome.Error, deferredEndpoint, TemporaryRedirectStatusCode);
        Assert.HasCount(1, jsonPosts, "The access token is sent once and nothing after the redirect.");
    }


    /// <summary>
    /// The §11 Notification Request carries the access token, so a notification endpoint answering it with
    /// a redirect is refused as <see cref="Oid4VciRequestFailureKind.RedirectRefused"/> rather than read as
    /// acknowledged, and the notification was sent once.
    /// </summary>
    [TestMethod]
    public async Task NotificationAnsweredWithARedirectIsRefusedAndNothingFollows()
    {
        Uri notificationEndpoint = new("https://issuer.example.com/notification");
        List<Uri> jsonPosts = [];
        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                jsonPosts.Add(endpoint);

                return ValueTask.FromResult(RedirectResponse(PermanentRedirectStatusCode));
            });

        Oid4VciRequestFailure? failure = await walletClient.SendCredentialNotificationAsync(
            "notification-redirected",
            Oid4VciNotificationEvents.CredentialAccepted,
            "access-token",
            WellKnownAuthenticationSchemes.Bearer,
            notificationEndpoint,
            eventDescription: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(failure, "A redirect is not an acknowledgement.");
        AssertRedirectRefused(failure, notificationEndpoint, PermanentRedirectStatusCode);
        Assert.HasCount(1, jsonPosts, "The access token is sent once and nothing after the redirect.");
    }


    /// <summary>The 307 (Temporary Redirect) status, RFC 9110 §15.4.8.</summary>
    private const int TemporaryRedirectStatusCode = 307;

    /// <summary>The 308 (Permanent Redirect) status, RFC 9110 §15.4.9.</summary>
    private const int PermanentRedirectStatusCode = 308;

    /// <summary>The origin the redirect rows' answers name: another origin than the endpoint's.</summary>
    private const string ElsewhereLocation = "https://elsewhere.example.net/collect";


    /// <summary>Builds a redirect answer naming <see cref="ElsewhereLocation"/>.</summary>
    /// <param name="statusCode">The 3xx status.</param>
    /// <returns>The answer.</returns>
    private static HttpResponseData RedirectResponse(int statusCode) =>
        JsonResponse(statusCode, string.Empty, (WellKnownHttpHeaderNames.Location, ElsewhereLocation));


    /// <summary>
    /// Asserts <paramref name="failure"/> is the Wallet's refusal of a redirect from
    /// <paramref name="endpoint"/>, carrying the typed refusal with the status and the location.
    /// </summary>
    /// <param name="failure">The failure the request answered.</param>
    /// <param name="endpoint">The endpoint the request was sent to.</param>
    /// <param name="statusCode">The redirect status the endpoint answered with.</param>
    private static void AssertRedirectRefused(Oid4VciRequestFailure failure, Uri endpoint, int statusCode)
    {
        Assert.AreEqual(Oid4VciRequestFailureKind.RedirectRefused, failure.Kind);
        Assert.AreEqual(endpoint, failure.Endpoint);
        Assert.AreEqual(statusCode, failure.StatusCode);
        Assert.IsNotNull(failure.RedirectRefusal);
        Assert.AreEqual(endpoint, failure.RedirectRefusal.Endpoint);
        Assert.AreEqual(statusCode, failure.RedirectRefusal.StatusCode);
        Assert.AreEqual(ElsewhereLocation, failure.RedirectRefusal.Location);
    }


    //Builds a wallet client over in-process spy delegates that never touch the network — the
    //refusal proofs above assert on invocation counts, not wire behaviour, so no HTTP host is
    //needed. Unwired seams default to a delegate that fails loudly if reached.
    private Oid4VciWalletClient BuildInProcessWalletClient(
        Oid4VciFormPostDelegate? sendFormPost = null,
        Oid4VciJsonPostDelegate? sendJsonPost = null,
        OutboundTransportDelegate? fetchCredentialOffer = null,
        OutboundFetchPolicy? outboundFetchPolicy = null,
        ConstructDpopProofDelegate? constructDpopProofAsync = null,
        DpopKey? dpopKey = null,
        Oid4VciEncryptRequestDelegate? encryptRequest = null,
        Oid4VciDecryptResponseDelegate? decryptResponse = null)
    {
        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = sendFormPost
                ?? ((_, _, _, _, _) => throw new InvalidOperationException("No §6 Token Request is expected in this test.")),
            SendJsonPost = sendJsonPost
                ?? ((_, _, _, _, _) => throw new InvalidOperationException("No §7/§8/§9 request is expected in this test.")),
            FetchCredentialOffer = fetchCredentialOffer,
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            OutboundFetchPolicy = outboundFetchPolicy ?? OutboundFetchPolicy.SecureDefault,
            ConstructDpopProofAsync = constructDpopProofAsync,
            DpopKey = dpopKey,
            GenerateIdentifierAsync = dpopKey is null ? null : DpopJtiGenerator,
            EncryptRequest = encryptRequest,
            DecryptResponse = decryptResponse
        };

        return new Oid4VciWalletClient(configuration);
    }


    //Builds an HttpResponseData carrying a JSON body and, optionally, response headers (e.g. a
    //DPoP-Nonce challenge header) — the in-process spy delegates' return shape.
    private static HttpResponseData JsonResponse(
        int statusCode, string body, params (string Name, string Value)[] headers) =>
        new()
        {
            StatusCode = statusCode,
            Body = body,
            Headers = headers.Length == 0
                ? ResponseHeaders.Empty
                : new ResponseHeaders { Headers = HttpHeaderSet.FromPairs(headers) }
        };


    /// <summary>Cross-step observations the issuer seams record for assertions.</summary>
    private sealed class IssuerSeamObservations
    {
        public bool IsProofVerified { get; set; }
        public string? ProofAudience { get; set; }

        /// <summary>The <c>credential_identifier</c> the last Credential Request named, if any.</summary>
        public string? RequestedIdentifier { get; set; }

        /// <summary>The <c>credential_configuration_id</c> the last Credential Request named, if any.</summary>
        public string? RequestedConfigurationId { get; set; }

        /// <summary>How many Credential Requests reached the issuance seam.</summary>
        public int IssuanceRequests { get; set; }

        /// <summary>The <c>kid</c> of the last Credential Request's response-encryption JWK, if any.</summary>
        public string? ResponseEncryptionKeyId { get; set; }
    }


    //Composes the §4 Credential Offer the Issuer hands the Wallet (by-value), carrying the
    //Pre-Authorized Code grant.
    private static CredentialOffer ComposeOffer(VerifierKeyMaterial material) =>
        new()
        {
            CredentialIssuer = material.Registration.IssuerUri!,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode
            }
        };


    //Resolves the Token / Nonce / Credential endpoint URLs against the started host's real
    //Kestrel base address using the fixture's /connect/{segment}/<suffix> URL shape.
    private static Oid4VciIssuanceEndpoints ResolveEndpoints(TestHostShell host, VerifierKeyMaterial material)
    {
        Uri baseUri = host.Host("default").HttpBaseAddress!;
        string segment = material.Registration.TenantId.Value;

        return new Oid4VciIssuanceEndpoints
        {
            TokenEndpoint = TestHostShell.ComposeEndpointUri(baseUri, segment, WellKnownEndpointNames.Oid4VciPreAuthorizedToken),
            NonceEndpoint = TestHostShell.ComposeEndpointUri(baseUri, segment, WellKnownEndpointNames.Oid4VciNonce),
            CredentialEndpoint = TestHostShell.ComposeEndpointUri(baseUri, segment, WellKnownEndpointNames.Oid4VciCredential)
        };
    }


    //Resolves the §9 Deferred Credential Endpoint URL against the started host's real Kestrel base
    //address using the fixture's /connect/{segment}/<suffix> URL shape.
    private static Uri ResolveDeferredEndpoint(TestHostShell host, VerifierKeyMaterial material) =>
        TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!,
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciDeferredCredential);


    //Resolves the §11 Notification Endpoint URL against the started host's real Kestrel base address.
    private static Uri ResolveNotificationEndpoint(TestHostShell host, VerifierKeyMaterial material) =>
        TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!,
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciNotification);


    /// <summary>
    /// Builds the wallet client over HttpClient-backed transport delegates that close over the started
    /// host's SharedHttpClient. The wallet library stays System.Net-free; the test reuses
    /// <see cref="HttpClientTransport"/> (the same real-HttpClient transport the authorization-code
    /// real-wire tests use) for wire-faithful status, body and header round-tripping, including the
    /// DPoP-Nonce response header the DPoP-bound cases read. A
    /// <paramref name="tokenRequestAuthorizationDetails"/> value rides every form post the wallet sends
    /// (its section 6 Token Request) as the section 6.1.1 <c>authorization_details</c> field, the way a
    /// wallet application's transport asks the Authorization Server for <c>credential_identifiers</c>.
    /// </summary>
    /// <param name="host">The started host whose SharedHttpClient carries every request.</param>
    /// <param name="decryptResponse">The wallet's response-decryption seam, or <see langword="null"/>.</param>
    /// <param name="encryptRequest">The wallet's request-encryption seam, or <see langword="null"/>.</param>
    /// <param name="fetchCredentialOffer">The by-reference Credential Offer transport, or <see langword="null"/>.</param>
    /// <param name="constructDpopProofAsync">The DPoP proof constructor, or <see langword="null"/>.</param>
    /// <param name="dpopKey">The DPoP signing pair, or <see langword="null"/>.</param>
    /// <param name="tokenRequestAuthorizationDetails">The <c>authorization_details</c> every form post carries, or <see langword="null"/>.</param>
    /// <returns>The wallet client.</returns>
    private Oid4VciWalletClient BuildWalletClient(
        TestHostShell host,
        Oid4VciDecryptResponseDelegate? decryptResponse = null,
        Oid4VciEncryptRequestDelegate? encryptRequest = null,
        OutboundTransportDelegate? fetchCredentialOffer = null,
        ConstructDpopProofDelegate? constructDpopProofAsync = null,
        DpopKey? dpopKey = null,
        string? tokenRequestAuthorizationDetails = null)
    {
        HttpClient httpClient = host.Host("default").SharedHttpClient!;

        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (endpoint, formFields, headers, _, ct) =>
                HttpClientTransport.SendFormPostAsync(
                    httpClient,
                    endpoint,
                    tokenRequestAuthorizationDetails is null
                        ? formFields
                        : new Dictionary<string, string>(formFields, StringComparer.Ordinal)
                        {
                            [OAuthRequestParameterNames.AuthorizationDetails] = tokenRequestAuthorizationDetails
                        },
                    headers,
                    ct),
            SendJsonPost = (endpoint, body, headers, _, ct) =>
                HttpClientTransport.SendJsonPostAsync(httpClient, endpoint, body, headers, ct),
            FetchCredentialOffer = fetchCredentialOffer,
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            DecryptResponse = decryptResponse,
            EncryptRequest = encryptRequest,
            OutboundFetchPolicy = TestHostShell.LoopbackOutboundFetchPolicy,
            ConstructDpopProofAsync = constructDpopProofAsync,
            DpopKey = dpopKey,
            GenerateIdentifierAsync = dpopKey is null ? null : DpopJtiGenerator
        };

        return new Oid4VciWalletClient(configuration);
    }


    //The wallet's §4.1.3 by-reference Credential Offer GET transport: a real HTTP GET over the
    //started host's SharedHttpClient. The library stays System.Net-free.
    //An in-process §4.1.3 offer GET response carrying the §4.1.3 mandated application/json content
    //type, for a fetchCredentialOffer spy that never touches the network.
    private static OutboundResponse JsonOfferResponse(string offerJson) =>
        new()
        {
            StatusCode = 200,
            Headers = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, "application/json")),
            Body = new TaggedMemory<byte>(Encoding.UTF8.GetBytes(offerJson), Tag.Empty)
        };


    //An in-process §4.1.3 offer GET response carrying the given Content-Type header value, or no
    //Content-Type header at all when contentType is null — for the content-type gate's refusal and
    //acceptance proofs, which need control over the header the mandated-content-type test does not.
    private static OutboundResponse OfferResponseWithContentType(string offerJson, string? contentType) =>
        new()
        {
            StatusCode = 200,
            Headers = contentType is null
                ? HttpHeaderSet.Empty
                : HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.ContentType, contentType)),
            Body = new TaggedMemory<byte>(Encoding.UTF8.GetBytes(offerJson), Tag.Empty)
        };


    //A minimal, otherwise-conformant §4.1.1 offer body — only what the content-type gate's proofs
    //need the parse to accept once the gate itself lets the response through.
    private static string MinimalOfferJson() =>
        CredentialOfferSerializer.ToJson(new CredentialOffer
        {
            CredentialIssuer = new Uri("https://issuer.example.com"),
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant { PreAuthorizedCode = "pre-authorized-code" }
        });


    //The wallet's §8.2 request-encryption seam: wraps the Credential Request body as a compact
    //JWE to the Issuer's published request-encryption key with real ECDH-ES + AES-GCM.
    private static async ValueTask<string> EncryptToIssuerAsync(
        string requestBody, PublicKeyMemory issuerPublic, CancellationToken cancellationToken)
    {
        return await HaipProfile.EncryptResponseAsync(
            issuerPublic,
            WellKnownJweEncryptionAlgorithms.A256Gcm,
            Encoding.UTF8.GetBytes(requestBody).AsMemory(),
            HeaderSerializer,
            CryptoFormatConversions.DefaultTagToEpkCrvConverter,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken: cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Installs the issuer delegates needed by the wallet credential-request cases: the Credential
    /// Issuer catalogue listing <paramref name="configurationId"/>, the request parser, the
    /// Pre-Authorized Code validation, the nonce and the issuance seam, which records what each
    /// Credential Request named.
    /// </summary>
    private static async Task<IssuerSeamObservations> WireIssuerSeamsAsync(
        TestHostShell host, string configurationId = ConfigurationId)
    {
        IssuerSeamObservations observations = new();
        string? mintedNonce = null;

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();

            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (_, _, _) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution
                {
                    CredentialConfigurationsSupported = TestHostShell.ListCredentialConfigurations(configurationId)
                });


            candidateIntegration.ValidatePreAuthorizedCodeAsync = (code, txCode, clientId, _, _, _) =>
                ValueTask.FromResult(string.Equals(code, PreAuthorizedCode, StringComparison.Ordinal)
                    ? PreAuthorizedCodeDecision.Grant(EndUserSubject, WellKnownScopes.OpenId)
                    : PreAuthorizedCodeDecision.Deny(PreAuthorizedCodeDenialReason.InvalidCode));


            candidateIntegration.IssueCredentialNonceAsync = (_, _) =>
            {
                mintedNonce = $"c-nonce-{Guid.NewGuid():N}";

                return ValueTask.FromResult(mintedNonce);
            };


            candidateIntegration.IssueCredentialAsync = async (request, _, _, _, ct) =>
            {
                observations.IssuanceRequests++;
                observations.RequestedIdentifier = request.CredentialIdentifier;
                observations.RequestedConfigurationId = request.CredentialConfigurationId;
                observations.ResponseEncryptionKeyId = request.ResponseEncryption?.Jwk is { } responseJwk
                    && responseJwk.TryGetValue(WellKnownJwkMemberNames.Kid, out object? keyId)
                        ? keyId as string
                        : null;
                string proof = request.Proofs[Oid4VciCredentialParameterNames.JwtProofType][0];
                (PublicKeyMemory proofKey, string? proofNonce, string? proofAudience) = ReadProof(proof);

                using(proofKey)
                {
                    bool isProofSignatureValid = await Jws.VerifyAsync(
                        proof, TestSetup.Base64UrlDecoder,
                        Pool,
                        proofKey, ct).ConfigureAwait(false);

                    if(!isProofSignatureValid
                        || mintedNonce is null
                        || !string.Equals(proofNonce, mintedNonce, StringComparison.Ordinal))
                    {

                        return CredentialIssuanceDecision.Deny(CredentialRequestError.InvalidProof);
                    }

                    observations.IsProofVerified = true;
                    observations.ProofAudience = proofAudience;

                    return CredentialIssuanceDecision.Issue([IssuedCredential]);
                }
            };
        }).ConfigureAwait(false);

        return observations;
    }


    /// <summary>
    /// Installs the section 6.1.1 authorization-details seams: the default parser and an authorization
    /// decision that grants <paramref name="grantedConfigurationId"/> with the
    /// <c>credential_identifiers</c> values <paramref name="grantedIdentifiers"/> in their order, whatever
    /// the Token Request asked for.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <param name="grantedConfigurationId">The configuration the granted object names.</param>
    /// <param name="grantedIdentifiers">The granted identifiers, in the order the Token Response returns them.</param>
    /// <returns>A task that completes when the alteration is applied.</returns>
    private static async Task WireCredentialAuthorizationAsync(
        TestHostShell host, string grantedConfigurationId, params string[] grantedIdentifiers)
    {
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync = (_, _, _, _, _) =>
                ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                [
                    new GrantedCredentialAuthorization
                    {
                        CredentialConfigurationId = grantedConfigurationId,
                        CredentialIdentifiers = grantedIdentifiers
                    }
                ]));
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Installs the response-encryption delegate so the wallet can exercise encrypted credential
    /// responses, and makes the catalogue the issuer seams wired advertise ECDH-ES with A256GCM for
    /// encrypted responses.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    private static async Task WireResponseEncryptionSeamAsync(TestHostShell host)
    {
        await TestHostShell.AdvertiseCredentialResponseEncryptionAsync(
            host.Server, [WellKnownJweAlgorithms.EcdhEs], [WellKnownJweEncryptionAlgorithms.A256Gcm]).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.EncryptCredentialResponseAsync = async (responseJson, encryption, _, _, ct) =>
            {
                Dictionary<string, object> jwkDict = new(StringComparer.Ordinal);
                foreach(KeyValuePair<string, object> member in encryption.Jwk!)
                {
                    jwkDict[member.Key] = member.Value;
                }

                var (algorithm, purpose, scheme, keyBytes) = CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
                    jwkDict, Pool, TestSetup.Base64UrlDecoder);
                Tag recipientTag = Tag.Create(algorithm).With(purpose).With(scheme);
                using PublicKeyMemory recipientKey = new(keyBytes, recipientTag);

                return await HaipProfile.EncryptResponseAsync(
                    recipientKey,
                    encryption.Enc!,
                    Encoding.UTF8.GetBytes(responseJson).AsMemory(),
                    HeaderSerializer,
                    CryptoFormatConversions.DefaultTagToEpkCrvConverter,
                    BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementEncryptP256Async,
                    ConcatKdf.DefaultKeyDerivationDelegate,
                    BouncyCastleKeyAgreementFunctions.AesGcmEncryptAsync,
                    TestSetup.Base64UrlEncoder,
                    Pool,
                    cancellationToken: ct).ConfigureAwait(false);
            };
        }).ConfigureAwait(false);
    }


    //The wallet's §10 decrypt drop-out: opens a compact JWE with the response private key.
    private static async ValueTask<string> DecryptAsync(
        string compactJwe, PrivateKeyMemory recipientPrivate, CancellationToken cancellationToken)
    {
        string headerSegment = compactJwe[..compactJwe.IndexOf('.', StringComparison.Ordinal)];
        using IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(headerSegment, Pool);
        string? enc = JwkJsonReader.ExtractStringValue(headerBytes.Memory.Span, "enc"u8);
        Assert.IsNotNull(enc, "JWE protected header must carry 'enc'.");

        using AeadMessage parsedJwe = JweParsing.ParseCompact(
            compactJwe, WellKnownJweAlgorithms.EcdhEs, enc, TestSetup.Base64UrlDecoder, Pool);
        using DecryptedContent decrypted = await parsedJwe.DecryptAsync(
            recipientPrivate,
            BouncyCastleKeyAgreementFunctions.EcdhKeyAgreementDecryptP256Async,
            ConcatKdf.DefaultKeyDerivationDelegate,
            BouncyCastleKeyAgreementFunctions.AesGcmDecryptAsync,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return Encoding.UTF8.GetString(decrypted.AsReadOnlySpan());
    }


    //Reads the holder key (header jwk), nonce, and aud off a proof JWT.
    private static (PublicKeyMemory ProofKey, string? Nonce, string? Audience) ReadProof(string proofJwt)
    {
        string headerJson = DecodeSegment(proofJwt, segmentIndex: 0);
        Dictionary<string, object>? jwk = JwkJsonReader.ExtractObjectProperties(
            Encoding.UTF8.GetBytes(headerJson), "jwk"u8);
        Assert.IsNotNull(jwk);

        var (algorithm, purpose, scheme, keyBytes) = CryptoFormatConversions.DefaultJwkToAlgorithmConverter(
            jwk, Pool, TestSetup.Base64UrlDecoder);
        Tag proofTag = Tag.Create(algorithm).With(purpose).With(scheme);
        PublicKeyMemory proofKey = new(keyBytes, proofTag);

        string payloadJson = DecodeSegment(proofJwt, segmentIndex: 1);
        ReadOnlySpan<byte> payloadBytes = Encoding.UTF8.GetBytes(payloadJson);
        string? nonce = JwkJsonReader.ExtractStringValue(payloadBytes, "nonce"u8);
        string? audience = JwkJsonReader.ExtractStringValue(payloadBytes, "aud"u8);

        return (proofKey, nonce, audience);
    }


    private static Dictionary<string, object> EcJwkMembers(PublicKeyMemory recipientPublic)
    {
        JsonWebKey jwk = CryptoFormatConversions.DefaultAlgorithmToJwkConverter(
            recipientPublic.Tag.Get<CryptoAlgorithm>(),
            recipientPublic.Tag.Get<Purpose>(),
            recipientPublic.AsReadOnlySpan(),
            TestSetup.Base64UrlEncoder);

        return new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [WellKnownJwkMemberNames.Kty] = jwk.Kty!,
            [WellKnownJwkMemberNames.Crv] = jwk.Crv!,
            [WellKnownJwkMemberNames.X] = jwk.X!,
            [WellKnownJwkMemberNames.Y] = jwk.Y!,
            [WellKnownJwkMemberNames.Alg] = WellKnownJweAlgorithms.EcdhEs
        };
    }


    private static string DecodeSegment(string compactJwt, int segmentIndex)
    {
        string[] parts = compactJwt.Split('.');
        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[segmentIndex], Pool);

        return Encoding.UTF8.GetString(bytes.Memory.Span).TrimEnd('\0');
    }
}
