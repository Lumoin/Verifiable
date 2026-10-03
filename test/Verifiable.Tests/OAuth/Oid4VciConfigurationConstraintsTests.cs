using Microsoft.Extensions.Time.Testing;
using System.Collections.Immutable;
using System.Net;
using System.Text.Json;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// OID4VCI 1.0 §8.2 scope↔credential_configuration_id binding and §12.2.4 batch ceiling,
/// enforced at the Credential Endpoint off the issuer metadata contribution. The gate runs
/// BEFORE the issuance seam, so a token scoped for one configuration cannot draw another and a
/// request cannot exceed (or assume unadvertised) batch issuance.
/// </summary>
[TestClass]
internal sealed class Oid4VciConfigurationConstraintsTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string ClientId = "https://wallet.client.test";
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");
    private const string OfferSubject = "urn:uuid:end-user-42";
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string ConfigurationScope = "UniversityDegree";
    private const string IssuedCredential = "eyJhbGciOiJFUzI1NiJ9.body.sig";

    /// <summary>The one section 6.2 <c>credential_identifiers</c> value the authorization seam grants.</summary>
    private static string GrantedIdentifier { get; } = "dataset-1";

    /// <summary>A configuration identifier the catalogue does not list.</summary>
    private static string UnlistedConfigurationId { get; } = "Unlisted_dc_sd_jwt";

    /// <summary>The second configuration a row's catalogue lists beside <see cref="ConfigurationId"/>.</summary>
    private static string OtherConfigurationId { get; } = "OtherConfiguration_dc_sd_jwt";

    /// <summary>The <c>scope</c> the catalogue declares for <see cref="OtherConfigurationId"/>.</summary>
    private static string OtherConfigurationScope { get; } = "OtherCredential";

    private static ImmutableHashSet<CapabilityIdentifier> IssuanceCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.Oid4VciPreAuthorizedCodeGrant,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialIssuerMetadata);


    [TestMethod]
    public async Task ScopeMatchingConfigurationIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        //The token is granted exactly the configuration's scope.
        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
    }


    [TestMethod]
    public async Task ScopeNotMatchingConfigurationIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        //The token is granted a DIFFERENT scope than the requested configuration declares.
        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: "SomeOtherCredential")
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidCredentialRequest, response.Body);
    }


    /// <summary>
    /// A request naming <c>credential_configuration_id</c> under an Access Token whose Token
    /// Response returned <c>credential_identifiers</c> for that configuration is an invalid Credential
    /// Request, the token's <c>scope</c> carrying the configuration's own scope, and the issuance seam
    /// is not consulted.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "credential_configuration_id: REQUIRED if a credential_identifiers parameter was not returned
    /// from the Token Response as part of the authorization_details parameter. It MUST NOT be used
    /// otherwise."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_credential_request: The Credential Request is missing a required parameter, includes an
    /// unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed."
    /// </summary>
    [TestMethod]
    public async Task ARequestByConfigurationUnderGrantedIdentifiersIsAnInvalidCredentialRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        SeamCalls issuanceCalls = new();
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, issuanceCalls).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        //The token's scope is the configuration's own, so the scope binding alone would serve the request.
        string accessToken = await MintAccessTokenWithAuthorizationDetailsAsync(
            host, material, credentialScope: ConfigurationScope, grantedConfigurationId: ConfigurationId)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.AreEqual("invalid_credential_request", ReadError(response.Body));
        Assert.AreEqual(
            "credential_configuration_id is not used when the Token Response returned credential_identifiers; "
            + "request by credential_identifier (section 8.2).",
            ReadErrorDescription(response.Body));
        Assert.AreEqual(0, issuanceCalls.Count, "A refused request must not reach the issuance seam.");
    }


    /// <summary>
    /// A request by <c>credential_identifier</c> is held to the configuration the identifier was
    /// granted for: when that configuration declares <c>key_attestations_required</c>, a request whose
    /// <c>jwt</c> proof carries no key attestation is refused with <c>invalid_proof</c> and the
    /// issuance seam is not consulted.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">OID4VCI 1.0 Section 12.2.4</see>:
    /// "key_attestations_required: OPTIONAL. Object that describes the requirement for key attestations
    /// as described in Appendix D, which the Credential Issuer expects the Wallet to send within the
    /// proof(s) of the Credential Request."
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierForAConfigurationRequiringKeyAttestationIsRefusedAPlainProof()
    {
        await using TestHostShell host = new(TimeProvider);
        SeamCalls issuanceCalls = new();
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, issuanceCalls).ConfigureAwait(false);
        await WireCatalogAsync(
            host, configurationScope: ConfigurationScope, batchSize: null, keyAttestationConfigurationId: ConfigurationId)
            .ConfigureAwait(false);

        string accessToken = await MintAccessTokenWithAuthorizationDetailsAsync(
            host, material, credentialScope: ConfigurationScope, grantedConfigurationId: ConfigurationId)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, IdentifierRequestBody(GrantedIdentifier, "proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.AreEqual("invalid_proof", ReadError(response.Body));
        Assert.AreEqual(0, issuanceCalls.Count, "A refused request must not reach the issuance seam.");
    }


    /// <summary>
    /// A request by <c>credential_identifier</c> whose granted configuration the Credential Issuer's
    /// <c>credential_configurations_supported</c> does not list is refused with
    /// <c>unknown_credential_configuration</c>, and the issuance seam is not consulted.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "unknown_credential_configuration: Requested Credential Configuration is unknown."
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierGrantedForAConfigurationTheCatalogueDoesNotListIsUnknown()
    {
        await using TestHostShell host = new(TimeProvider);
        SeamCalls issuanceCalls = new();
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, issuanceCalls).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        string accessToken = await MintAccessTokenWithAuthorizationDetailsAsync(
            host, material, credentialScope: ConfigurationScope, grantedConfigurationId: UnlistedConfigurationId)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, IdentifierRequestBody(GrantedIdentifier, "proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.AreEqual("unknown_credential_configuration", ReadError(response.Body));
        Assert.AreEqual(0, issuanceCalls.Count, "A refused request must not reach the issuance seam.");
    }


    /// <summary>
    /// An identifier the Access Token's grant lists under two configurations names no one Credential
    /// Dataset, so the request is answered 500 <c>server_error</c> with a fixed description (the
    /// grant is the application's inconsistency, not the caller's) and the issuance seam is not
    /// consulted; the configuration listed second here requires key attestation, which a plain proof
    /// does not carry.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "credential_identifiers: REQUIRED. A non-empty array of strings, each uniquely identifying a
    /// Credential Dataset that can be issued using the Access Token returned in this response."
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierGrantedUnderTwoConfigurationsIsAServerError()
    {
        await using TestHostShell host = new(TimeProvider);
        SeamCalls issuanceCalls = new();
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, issuanceCalls).ConfigureAwait(false);
        await WireCatalogAsync(
            host,
            configurationScope: ConfigurationScope,
            batchSize: null,
            keyAttestationConfigurationId: OtherConfigurationId,
            otherConfigurationScope: OtherConfigurationScope).ConfigureAwait(false);

        string accessToken = await MintAccessTokenWithAuthorizationDetailsAsync(
            host,
            material,
            credentialScope: ConfigurationScope,
            grantedConfigurationId: ConfigurationId,
            secondGrantedConfigurationId: OtherConfigurationId).ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, IdentifierRequestBody(GrantedIdentifier, "proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.InternalServerError, response.StatusCode, response.Body);
        Assert.AreEqual("server_error", ReadError(response.Body));
        Assert.AreEqual(
            "The Access Token's grant lists the credential_identifier under more than one Credential Configuration.",
            ReadErrorDescription(response.Body));
        Assert.AreEqual(0, issuanceCalls.Count, "A request the grant cannot resolve must not reach the issuance seam.");
    }


    /// <summary>
    /// An identifier is ambiguous only across distinct configurations: a grant listing one identifier in
    /// two <c>openid_credential</c> details that name the same configuration identifies one Credential
    /// Dataset of that configuration, so a request by that identifier is served and the issuance seam is
    /// consulted once.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "credential_identifiers: REQUIRED. A non-empty array of strings, each uniquely identifying a
    /// Credential Dataset that can be issued using the Access Token returned in this response."
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierGrantedTwiceUnderOneConfigurationIsServed()
    {
        await using TestHostShell host = new(TimeProvider);
        SeamCalls issuanceCalls = new();
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, issuanceCalls).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        string accessToken = await MintAccessTokenWithAuthorizationDetailsAsync(
            host,
            material,
            credentialScope: ConfigurationScope,
            grantedConfigurationId: ConfigurationId,
            secondGrantedConfigurationId: ConfigurationId).ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, IdentifierRequestBody(GrantedIdentifier, "proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
        Assert.AreEqual(/*lang=json,strict*/ "{\"credentials\":[{\"credential\":\"eyJhbGciOiJFUzI1NiJ9.body.sig\"}]}", response.Body);
        Assert.AreEqual(1, issuanceCalls.Count, "The request by the identifier granted twice must reach the issuance seam once.");
    }


    /// <summary>
    /// The scope binding is the authorization of a request by <c>credential_configuration_id</c>: a
    /// request by a granted <c>credential_identifier</c> is served although the token's <c>scope</c>
    /// does not carry the scope the identifier's configuration declares.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>,
    /// on <c>credential_configuration_id</c>: "The corresponding object in the
    /// credential_configurations_supported map MUST contain one of the value(s) used in the scope
    /// parameter in the Authorization Request." And: "credential_identifier: REQUIRED when an
    /// Authorization Details of type openid_credential was returned from the Token Response."
    /// </summary>
    [TestMethod]
    public async Task ARequestByIdentifierIsNotHeldToTheConfigurationScope()
    {
        await using TestHostShell host = new(TimeProvider);
        SeamCalls issuanceCalls = new();
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, issuanceCalls).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        string accessToken = await MintAccessTokenWithAuthorizationDetailsAsync(
            host, material, credentialScope: "SomeOtherCredential", grantedConfigurationId: ConfigurationId)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, IdentifierRequestBody(GrantedIdentifier, "proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
        Assert.AreEqual(1, issuanceCalls.Count, "The request by the granted identifier must reach the issuance seam.");
    }


    /// <summary>
    /// A request naming a <c>credential_identifier</c> that no <c>openid_credential</c> detail of
    /// the Access Token lists is refused with <c>unknown_credential_identifier</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "unknown_credential_identifier: Requested Credential identifier is unknown."
    /// </summary>
    [TestMethod]
    public async Task AnIdentifierTheTokenWasNotGrantedIsUnknown()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        string accessToken = await MintAccessTokenWithAuthorizationDetailsAsync(
            host, material, credentialScope: ConfigurationScope, grantedConfigurationId: ConfigurationId)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, IdentifierRequestBody("dataset-2", "proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.AreEqual("unknown_credential_identifier", ReadError(response.Body));
    }


    /// <summary>
    /// A request naming a <c>credential_identifier</c> under an Access Token whose Token Response
    /// returned no <c>openid_credential</c> authorization details (a token carrying a <c>scope</c>
    /// only) is an invalid Credential Request.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "credential_identifier: REQUIRED when an Authorization Details of type openid_credential was
    /// returned from the Token Response. It MUST NOT be used otherwise."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_credential_request: The Credential Request is missing a required parameter, includes an
    /// unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed."
    /// </summary>
    [TestMethod]
    public async Task ARequestByIdentifierUnderATokenWithoutDetailsIsAnInvalidCredentialRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, IdentifierRequestBody(GrantedIdentifier, "proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.AreEqual("invalid_credential_request", ReadError(response.Body));
    }


    /// <summary>
    /// An Access Token that carries no <c>scope</c> claim and no authorization details grants no
    /// scope, so a request by a configuration that declares a <c>scope</c> is an invalid Credential
    /// Request.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "The corresponding object in the credential_configurations_supported map MUST contain one of
    /// the value(s) used in the scope parameter in the Authorization Request."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_credential_request: The Credential Request is missing a required parameter, includes an
    /// unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed."
    /// </summary>
    [TestMethod]
    public async Task ATokenCarryingNoScopeIsRefusedAScopedConfiguration()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: null).ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.AreEqual("invalid_credential_request", ReadError(response.Body));
    }


    /// <summary>
    /// A request naming a <c>credential_configuration_id</c> the Credential Issuer's
    /// <c>credential_configurations_supported</c> does not list is refused with
    /// <c>unknown_credential_configuration</c>.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "unknown_credential_configuration: Requested Credential Configuration is unknown."
    /// </summary>
    [TestMethod]
    public async Task AConfigurationTheCatalogueDoesNotListIsUnknown()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, OtherConfigurationRequestBody(UnlistedConfigurationId, "proof-1"))
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.AreEqual("unknown_credential_configuration", ReadError(response.Body));
    }


    /// <summary>
    /// A server whose Credential Issuer metadata seam is not wired does not serve the Credential
    /// Endpoint: without the catalogue no request can be judged against the configuration it names.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">OID4VCI 1.0 Section 12.2.4</see>:
    /// "credential_configurations_supported: REQUIRED."
    /// </summary>
    [TestMethod]
    public async Task ACredentialEndpointWithoutTheCatalogueIsNotServed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = null;
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.NotFound, response.StatusCode, response.Body);
    }


    /// <summary>
    /// One Credential Request is judged against one catalogue: the Credential Issuer metadata seam
    /// is read once per request and every rule reads that answer, so a catalogue the application
    /// alters while the request is served cannot answer one rule from one catalogue and the next
    /// from another. The seam here answers the configuration's scope as the token's on its first
    /// read and as another scope on every later read.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "The corresponding object in the credential_configurations_supported map MUST contain one of
    /// the value(s) used in the scope parameter in the Authorization Request."
    /// </summary>
    [TestMethod]
    public async Task ACredentialRequestIsJudgedAgainstOneCatalogue()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        SeamCalls reads = new();
        await WireCatalogAsync(
            host, configurationScope: ConfigurationScope, batchSize: null, alteredScope: "AlteredCredential", reads: reads)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
        Assert.AreEqual(1, reads.Count, "The catalogue must be read once for the one request.");
    }


    /// <summary>
    /// A token whose authorization details granted <c>credential_identifiers</c> for one configuration
    /// authorizes no request by <c>credential_configuration_id</c> for another, the token's
    /// <c>scope</c> carrying that other configuration's own scope: the request is an invalid
    /// Credential Request and the issuance seam is not consulted.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "credential_configuration_id: REQUIRED if a credential_identifiers parameter was not returned
    /// from the Token Response as part of the authorization_details parameter. It MUST NOT be used
    /// otherwise."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OID4VCI 1.0 Section 8.3.1.2</see>:
    /// "invalid_credential_request: The Credential Request is missing a required parameter, includes an
    /// unsupported parameter or parameter value, repeats the same parameter, or is otherwise malformed."
    /// </summary>
    [TestMethod]
    public async Task ARequestByAnotherConfigurationUnderGrantedIdentifiersIsAnInvalidCredentialRequest()
    {
        await using TestHostShell host = new(TimeProvider);
        SeamCalls issuanceCalls = new();
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, issuanceCalls).ConfigureAwait(false);
        await WireCatalogAsync(
            host, configurationScope: ConfigurationScope, batchSize: null, otherConfigurationScope: OtherConfigurationScope)
            .ConfigureAwait(false);

        //The grant names ConfigurationId; the token's scope is the other configuration's own, so the
        //scope binding alone would serve the request by the other configuration.
        string accessToken = await MintAccessTokenWithAuthorizationDetailsAsync(
            host, material, credentialScope: OtherConfigurationScope, grantedConfigurationId: ConfigurationId)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, OtherConfigurationRequestBody(OtherConfigurationId, "proof-1"))
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.AreEqual("invalid_credential_request", ReadError(response.Body));
        Assert.AreEqual(
            "credential_configuration_id is not used when the Token Response returned credential_identifiers; "
            + "request by credential_identifier (section 8.2).",
            ReadErrorDescription(response.Body));
        Assert.AreEqual(0, issuanceCalls.Count, "A refused request must not reach the issuance seam.");
    }


    /// <summary>
    /// The Credential Endpoint serves a request only under a catalogue the Credential Issuer Metadata
    /// endpoint publishes: a Credential Request under a catalogue whose configuration carries no
    /// <c>format</c>, or whose <c>batch_credential_issuance</c> advertises a <c>batch_size</c> of 1, is
    /// answered exactly as the metadata endpoint answers for that catalogue, 500 <c>server_error</c> with
    /// the same body, and the issuance seam is not consulted. The token carries the configuration's own
    /// scope and the request one proof, so no rule of the request refuses it.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4">OID4VCI 1.0 Section 12.2.4</see>:
    /// "format: REQUIRED. A JSON string identifying the format of this Credential, i.e., jwt_vc_json or
    /// ldp_vc." And: "batch_size: REQUIRED. Integer value specifying the maximum array size for the proofs
    /// parameter in a Credential Request. It MUST be 2 or greater."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-15.6.1">RFC 9110 Section 15.6.1</see>:
    /// "The 500 (Internal Server Error) status code indicates that the server encountered an unexpected
    /// condition that prevented it from fulfilling the request."
    /// </summary>
    /// <param name="faultyMember">The catalogue member the metadata endpoint refuses.</param>
    /// <param name="expectedMetadataBody">The literal body the metadata endpoint answers for the catalogue.</param>
    [TestMethod]
    [DataRow("format", /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"credential_configurations_supported['UniversityDegree_dc_sd_jwt'] is missing the REQUIRED format member (12.2.4).\"}")]
    [DataRow("batch_size", /*lang=json,strict*/ "{\"error\":\"server_error\",\"error_description\":\"batch_credential_issuance.batch_size is 1; 12.2.4 requires it to be 2 or greater.\"}")]
    public async Task ACredentialRequestUnderACatalogueTheMetadataEndpointRefusesIsAServerError(
        string faultyMember, string expectedMetadataBody)
    {
        await using TestHostShell host = new(TimeProvider);
        SeamCalls issuanceCalls = new();
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host, issuanceCalls).ConfigureAwait(false);
        await (faultyMember switch
        {
            "format" => WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null, isFormatOmitted: true),
            "batch_size" => WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: 1),
            _ => throw new ArgumentOutOfRangeException(nameof(faultyMember), faultyMember, "No catalogue is composed for this member.")
        }).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        HttpResponseData response = await PostCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1")).ConfigureAwait(false);
        (int metadataStatusCode, string metadataBody) = await host.FetchCredentialIssuerMetadataOverWireAsync(
            material.Registration.TenantId.Value, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.InternalServerError, metadataStatusCode, metadataBody);
        Assert.AreEqual(expectedMetadataBody, metadataBody);
        Assert.AreEqual(metadataStatusCode, response.StatusCode, response.Body);
        Assert.AreEqual(metadataBody, response.Body);
        Assert.AreEqual(0, issuanceCalls.Count, "A request under a catalogue the metadata endpoint refuses must not reach the issuance seam.");
    }


    [TestMethod]
    public async Task BatchWithinAdvertisedSizeIssues()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: 3).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1", "proof-2", "proof-3"))
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, response.StatusCode, response.Body);
    }


    [TestMethod]
    public async Task BatchOverAdvertisedSizeIsRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: 2).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1", "proof-2", "proof-3"))
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
    }


    [TestMethod]
    public async Task MultipleProofsWithoutBatchSupportAreRefused()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterIssuerAsync(host).ConfigureAwait(false);
        //No batch_credential_issuance advertised.
        await WireCatalogAsync(host, configurationScope: ConfigurationScope, batchSize: null).ConfigureAwait(false);

        string accessToken = await MintAccessTokenAsync(host, material, credentialScope: ConfigurationScope)
            .ConfigureAwait(false);
        ServerHttpResponse response = await DispatchCredentialAsync(
            host, material, accessToken, CredentialRequestBody("proof-1", "proof-2"))
            .ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.BadRequest, response.StatusCode, response.Body);
        Assert.Contains(Oid4VciCredentialErrors.InvalidProof, response.Body);
    }


    /// <summary>
    /// Registers an issuer with the test capabilities and installs its issuance delegates; the
    /// issuance seam records each call in <paramref name="issuanceCalls"/> when one is given.
    /// </summary>
    /// <param name="host">The host the issuer is registered on.</param>
    /// <param name="issuanceCalls">The counter of issuance seam calls, or <see langword="null"/>.</param>
    /// <returns>The registered issuer's material.</returns>
    private static async Task<VerifierKeyMaterial> RegisterIssuerAsync(TestHostShell host, SeamCalls? issuanceCalls = null)
    {
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuanceCapabilities).ConfigureAwait(false);
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();


            candidateIntegration.IssueCredentialAsync = (_, _, _, _, _) =>
            {
                _ = issuanceCalls?.Record();

                return ValueTask.FromResult(CredentialIssuanceDecision.Issue([IssuedCredential]));
            };
        }).ConfigureAwait(false);

        return material;
    }


    /// <summary>
    /// Wires the metadata contribution with one configuration declaring <paramref name="configurationScope"/>
    /// and, when <paramref name="batchSize"/> is set, batch issuance advertised at that size. With
    /// <paramref name="alteredScope"/> set, the first read answers <paramref name="configurationScope"/> and every
    /// later read answers <paramref name="alteredScope"/>, the catalogue an application alters while a request is
    /// served; <paramref name="reads"/>, when given, counts the reads. With <paramref name="otherConfigurationScope"/>
    /// set, the catalogue also lists <see cref="OtherConfigurationId"/> declaring that scope; the configuration
    /// <paramref name="keyAttestationConfigurationId"/> names, when set, declares
    /// <c>proof_types_supported.jwt.key_attestations_required</c>. With <paramref name="isFormatOmitted"/> set,
    /// <see cref="ConfigurationId"/> carries no <c>format</c>, a catalogue the metadata endpoint refuses to publish.
    /// </summary>
    /// <param name="host">The host whose integration is altered.</param>
    /// <param name="configurationScope">The <c>scope</c> <see cref="ConfigurationId"/> declares.</param>
    /// <param name="batchSize">The advertised <c>batch_size</c>, or <see langword="null"/> for no batch issuance.</param>
    /// <param name="alteredScope">The scope every read after the first answers, or <see langword="null"/>.</param>
    /// <param name="reads">The counter of catalogue reads, or <see langword="null"/>.</param>
    /// <param name="keyAttestationConfigurationId">The configuration requiring key attestation, or <see langword="null"/>.</param>
    /// <param name="otherConfigurationScope">The <c>scope</c> of <see cref="OtherConfigurationId"/>, or <see langword="null"/> to list it not.</param>
    /// <param name="isFormatOmitted">Whether <see cref="ConfigurationId"/> carries no <c>format</c>.</param>
    private static async Task WireCatalogAsync(
        TestHostShell host,
        string configurationScope,
        int? batchSize,
        string? alteredScope = null,
        SeamCalls? reads = null,
        string? keyAttestationConfigurationId = null,
        string? otherConfigurationScope = null,
        bool isFormatOmitted = false)
    {
        SeamCalls counted = reads ?? new SeamCalls();
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ContributeCredentialIssuerMetadataAsync = (_, _, _) =>
            {
                int readNumber = counted.Record();
                string answeredScope = readNumber > 1 && alteredScope is not null ? alteredScope : configurationScope;
                Dictionary<string, object> configuration = ComposeConfiguration(
                    answeredScope, string.Equals(ConfigurationId, keyAttestationConfigurationId, StringComparison.Ordinal));
                if(isFormatOmitted)
                {
                    _ = configuration.Remove("format");
                }

                Dictionary<string, object> configurations = new(StringComparer.Ordinal)
                {
                    [ConfigurationId] = configuration
                };
                if(otherConfigurationScope is not null)
                {
                    configurations[OtherConfigurationId] = ComposeConfiguration(
                        otherConfigurationScope,
                        string.Equals(OtherConfigurationId, keyAttestationConfigurationId, StringComparison.Ordinal));
                }

                CredentialIssuerMetadataContribution contribution = new()
                {
                    CredentialConfigurationsSupported = configurations,
                    BatchCredentialIssuance = batchSize is int size
                        ? new Dictionary<string, object>(StringComparer.Ordinal) { ["batch_size"] = size }
                        : null
                };

                return ValueTask.FromResult(contribution);
            };
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Composes one SD-JWT VC configuration object declaring <paramref name="scope"/>; with
    /// <paramref name="isKeyAttestationRequired"/> its <c>jwt</c> proof type declares an empty
    /// <c>key_attestations_required</c> object, a key attestation needed without further constraints.
    /// </summary>
    /// <param name="scope">The configuration's <c>scope</c>.</param>
    /// <param name="isKeyAttestationRequired">Whether the configuration requires key attestation.</param>
    /// <returns>The configuration object.</returns>
    private static Dictionary<string, object> ComposeConfiguration(string scope, bool isKeyAttestationRequired)
    {
        Dictionary<string, object> configuration = new(StringComparer.Ordinal)
        {
            ["format"] = "dc+sd-jwt",
            ["scope"] = scope
        };
        if(isKeyAttestationRequired)
        {
            configuration["proof_types_supported"] = new Dictionary<string, object>(StringComparer.Ordinal)
            {
                ["jwt"] = new Dictionary<string, object>(StringComparer.Ordinal)
                {
                    ["proof_signing_alg_values_supported"] = new List<object> { "ES256" },
                    ["key_attestations_required"] = new Dictionary<string, object>(StringComparer.Ordinal)
                }
            };
        }

        return configuration;
    }


    private static string CredentialRequestBody(params string[] proofs) =>
        OtherConfigurationRequestBody(ConfigurationId, proofs);


    private static string OtherConfigurationRequestBody(string configurationId, params string[] proofs)
    {
        string proofArray = string.Join(",", proofs.Select(p => "\"" + p + "\""));

        return "{\"credential_configuration_id\":\"" + configurationId + "\","
            + "\"proofs\":{\"jwt\":[" + proofArray + "]}}";
    }


    /// <summary>
    /// Composes a section 8.2 Credential Request body that names <paramref name="credentialIdentifier"/> and no
    /// <c>credential_configuration_id</c>, carrying <paramref name="proofs"/> as its <c>jwt</c> proofs.
    /// </summary>
    /// <param name="credentialIdentifier">The <c>credential_identifier</c> the request names.</param>
    /// <param name="proofs">The compact <c>jwt</c> proofs.</param>
    /// <returns>The JSON request body.</returns>
    private static string IdentifierRequestBody(string credentialIdentifier, params string[] proofs)
    {
        string proofArray = string.Join(",", proofs.Select(p => "\"" + p + "\""));

        return "{\"credential_identifier\":\"" + credentialIdentifier + "\","
            + "\"proofs\":{\"jwt\":[" + proofArray + "]}}";
    }


    /// <summary>
    /// Sends a section 8.2 Credential Request over the real wire: starts the host's listener when it is not
    /// running, posts <paramref name="jsonBody"/> to the Credential Endpoint with <paramref name="accessToken"/>
    /// under the Bearer scheme, and answers the response as received.
    /// </summary>
    /// <param name="host">The host whose listener serves the request.</param>
    /// <param name="material">The registration whose Credential Endpoint is addressed.</param>
    /// <param name="accessToken">The Access Token presented under the Bearer scheme.</param>
    /// <param name="jsonBody">The Credential Request body.</param>
    /// <returns>The response as the wire delivered it.</returns>
    private async Task<HttpResponseData> PostCredentialAsync(
        TestHostShell host, VerifierKeyMaterial material, string accessToken, string jsonBody)
    {
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        Uri credentialEndpoint = TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!,
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredential);

        return await HttpClientTransport.SendJsonPostAsync(
            host.Host("default").SharedHttpClient!,
            credentialEndpoint,
            jsonBody,
            OutgoingHeaders.Empty.WithAuthorization(WellKnownAuthenticationSchemes.Bearer, accessToken),
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Reads the <c>error</c> member of a section 8.3.1.2 Credential Error Response body.</summary>
    /// <param name="responseBody">The error response body.</param>
    /// <returns>The <c>error</c> value.</returns>
    private static string? ReadError(string responseBody) => ReadStringMember(responseBody, "error");


    /// <summary>Reads the <c>error_description</c> member of a section 8.3.1.2 Credential Error Response body.</summary>
    /// <param name="responseBody">The error response body.</param>
    /// <returns>The <c>error_description</c> value.</returns>
    private static string? ReadErrorDescription(string responseBody) => ReadStringMember(responseBody, "error_description");


    /// <summary>Reads one string member of a JSON object response body.</summary>
    /// <param name="responseBody">The JSON object body.</param>
    /// <param name="memberName">The member to read.</param>
    /// <returns>The member's string value.</returns>
    private static string? ReadStringMember(string responseBody, string memberName)
    {
        using JsonDocument document = JsonDocument.Parse(responseBody);

        return document.RootElement.GetProperty(memberName).GetString();
    }


    private static RequestHeaders BearerHeaders(string accessToken) =>
        new(new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase)
        {
            [WellKnownHttpHeaderNames.Authorization] = ["Bearer " + accessToken]
        });


    private async Task<ServerHttpResponse> DispatchCredentialAsync(
        TestHostShell host, VerifierKeyMaterial material, string accessToken, string jsonBody)
    {
        return await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciCredential,
            "POST",
            new RequestFields(),
            BearerHeaders(accessToken),
            jsonBody,
            [],
            TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Completes the fixture token exchange and returns an access token for the credential endpoint request.
    /// </summary>
    private async Task<string> MintAccessTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string? credentialScope)
    {
        //openid keeps the RFC 9068 audience resolvable (ScopeToAudience maps it); the credential
        //scope rides alongside it and is what the section 8.2 binding matches against. Without a
        //credential scope the grant names no scope at all, and the token carries no scope claim.
        string? grantedScope = credentialScope is null ? null : $"{WellKnownScopes.OpenId} {credentialScope}";
        //OID4VCI 1.0 §13.10: "Long-lived Access Tokens giving access to Credentials MUST not be
        //issued unless sender-constrained." Keep this plain-bearer credential token within the
        //long-lived threshold (lifetimes longer than 5 minutes are considered long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, grantedScope));
        }).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA"
            },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    /// <summary>
    /// Mints a Bearer access token through the OID4VCI Pre-Authorized Code grant carrying
    /// <paramref name="credentialScope"/> as its granted scope AND an RFC 9396 §9.1
    /// <c>authorization_details</c> claim whose <c>openid_credential</c> detail grants
    /// <paramref name="grantedConfigurationId"/> with the one <c>credential_identifiers</c> value
    /// <see cref="GrantedIdentifier"/>, the Token Response that obliges the Wallet to request by that
    /// identifier. With <paramref name="secondGrantedConfigurationId"/> set, a second detail grants the
    /// same identifier for that configuration.
    /// </summary>
    /// <param name="host">The host whose token endpoint mints the token.</param>
    /// <param name="material">The registration the token is minted for.</param>
    /// <param name="credentialScope">The credential scope granted beside <c>openid</c>.</param>
    /// <param name="grantedConfigurationId">The configuration the first granted detail names.</param>
    /// <param name="secondGrantedConfigurationId">The configuration a second detail names, or <see langword="null"/>.</param>
    /// <returns>The minted access token.</returns>
    private async Task<string> MintAccessTokenWithAuthorizationDetailsAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        string credentialScope,
        string grantedConfigurationId,
        string? secondGrantedConfigurationId = null)
    {
        string grantedScope = $"{WellKnownScopes.OpenId} {credentialScope}";
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        List<string> grantedConfigurationIds = secondGrantedConfigurationId is null
            ? [grantedConfigurationId]
            : [grantedConfigurationId, secondGrantedConfigurationId];
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();

            candidateIntegration.ValidatePreAuthorizedCodeAsync =
                (code, txCode, clientId, registration, context, ct) =>
                    ValueTask.FromResult(PreAuthorizedCodeDecision.Grant(OfferSubject, grantedScope));

            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                    ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                        grantedConfigurationIds
                            .Select(configurationId => new GrantedCredentialAuthorization
                            {
                                CredentialConfigurationId = configurationId,
                                CredentialIdentifiers = [GrantedIdentifier]
                            })
                            .ToList()));
        }).ConfigureAwait(false);

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.Oid4VciPreAuthorizedToken,
            "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.PreAuthorizedCode,
                [OAuthRequestParameterNames.PreAuthorizedCode] = "SplxlOBeZQQYbYS6WxSbIA",
                [OAuthRequestParameterNames.AuthorizationDetails] =
                    "[" + string.Join(",", grantedConfigurationIds.Select(configurationId =>
                        "{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + configurationId + "\"}"))
                    + "]"
            },
            [],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual((int)HttpStatusCode.OK, tokenResponse.StatusCode, tokenResponse.Body);
        using JsonDocument doc = JsonDocument.Parse(tokenResponse.Body);

        return doc.RootElement.GetProperty(WellKnownTokenTypes.AccessToken).GetString()!;
    }


    /// <summary>
    /// Counts the calls of a seam a row wires (the Credential Issuer metadata seam or the issuance
    /// seam), so the row can state how many catalogues one request was judged against or whether a
    /// refused request reached issuance.
    /// </summary>
    private sealed class SeamCalls
    {
        /// <summary>The call count; a field because <see cref="Interlocked"/> updates it by reference.</summary>
        private int count;

        /// <summary>The number of calls recorded so far.</summary>
        public int Count => Volatile.Read(ref count);

        /// <summary>Records one call and answers its ordinal, the first call answering one.</summary>
        /// <returns>The ordinal of the recorded call.</returns>
        public int Record() => Interlocked.Increment(ref count);
    }
}
