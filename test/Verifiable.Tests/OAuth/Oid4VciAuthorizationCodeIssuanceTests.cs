using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.AuthCode.States;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vci.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The wallet-perspective Authorization Code issuance journey over REAL Kestrel HTTP, composed the
/// way OID4VCI 1.0 section 5.1.1 under HAIP prescribes: the section 5.1.1
/// <c>authorization_details</c> (composed by <see cref="CredentialAuthorizationDetailComposition"/>)
/// and the offer's <c>issuer_state</c> ride an RFC 9126 pushed authorization request with RFC 7636
/// PKCE through <see cref="AuthCodeClient"/>, the browser's authorize GET returns the code, the
/// callback and token exchange mint the access token, and
/// <see cref="Oid4VciWalletClient.IssueWithAccessTokenDetailedAsync"/> spends it on the section 7
/// Nonce Request, the section 7.2.1 holder key proof, and the section 8 Credential Request. The
/// server side of the details flow is pinned by <see cref="Oid4VciAuthorizationDetailsTests"/>;
/// this class pins the WALLET composition of the same journey end to end.
/// </summary>
[TestClass]
internal sealed class Oid4VciAuthorizationCodeIssuanceTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The clock the host and the client share.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The Wallet client identifier registered with the host.</summary>
    private const string ClientId = "https://wallet.client.test";

    /// <summary>The base URI the registered client is reachable at.</summary>
    private static Uri ClientBaseUri { get; } = new("https://wallet.client.test");

    /// <summary>The client's registered redirect URI; the code and state are read off its query string.</summary>
    private static Uri RedirectUri { get; } = new("https://client.example.com/callback");

    /// <summary>The authenticated End-User the authorize step asserts via the test subject header.</summary>
    private const string SubjectId = "urn:uuid:end-user-42";

    /// <summary>The Credential Configuration the wallet requests authorization for.</summary>
    private const string ConfigurationId = "eu.europa.ec.eudi.pid.1";

    /// <summary>The section 5.1.3 <c>issuer_state</c> the Credential Offer handed the wallet.</summary>
    private const string IssuerState = "issuer-state-jNQFyWQhSyM";

    /// <summary>The section 6.2 <c>credential_identifiers</c> entry the authorization seam grants.</summary>
    private const string CredentialIdentifier = "eu.europa.ec.eudi.pid.1-instance-1";

    /// <summary>The second section 6.2 <c>credential_identifiers</c> entry a grant of two identifiers lists.</summary>
    private static string SecondCredentialIdentifier => "eu.europa.ec.eudi.pid.1-instance-2";

    /// <summary>The opaque credential the issuer seam mints on a verified proof.</summary>
    private const string IssuedCredential = "issued-credential-authcode-42";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    /// <summary>
    /// The registration's capabilities: the Authorization Code grant with pushed authorization on
    /// the OAuth side, and the Nonce and Credential endpoints on the issuance side.
    /// </summary>
    private static ImmutableHashSet<CapabilityIdentifier> Capabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.Oid4VciNonceEndpoint,
            WellKnownCapabilityIdentifiers.Oid4VciCredentialEndpoint);

    private static JwtHeaderSerializer HeaderSerializer { get; } =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header,
            TestSetup.DefaultSerializationOptions);

    private static JwtPayloadSerializer PayloadSerializer { get; } =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload,
            TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// The whole journey: PAR carrying <c>authorization_details</c> + <c>issuer_state</c>, the
    /// authorize GET, the callback, the token exchange, and the token spent on nonce, proof, and a
    /// Credential Request naming the first <c>credential_identifiers</c> value the Token Response
    /// returned. The authorization seam sees the pushed details, the token result carries the
    /// granted authorization, the wallet chooses its target through
    /// <see cref="CredentialRequestTarget.FromGrantedAuthorizations"/> over that result, the
    /// issuance seam verifies the holder proof and receives the granted identifier with no
    /// configuration identifier, and the wallet holds the minted credential.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ParPkceAuthorizationCodeJourneyEndsInAnIssuedCredential()
    {
        JourneyOutcome journey = await DriveJourneyAsync([CredentialIdentifier]).ConfigureAwait(false);

        Assert.HasCount(1, journey.TokenResult.GrantedCredentialAuthorizations,
            "The token result must carry the one openid_credential authorization the Token Response granted.");
        Assert.AreEqual(ConfigurationId, journey.TokenResult.GrantedCredentialAuthorizations[0].CredentialConfigurationId);
        Assert.AreSequenceEqual(
            [CredentialIdentifier],
            journey.TokenResult.GrantedCredentialAuthorizations[0].CredentialIdentifiers.ToArray());

        Assert.IsTrue(journey.IssuedOutcome.IsSuccess, "The auth-code journey's issuance must succeed over the wire.");
        CredentialIssuanceResult issued = journey.IssuedOutcome.Value;

        Assert.HasCount(1, issued.Credentials, "The auth-code journey must end in exactly the one requested credential.");
        Assert.AreEqual(IssuedCredential, issued.Credentials[0],
            "The wallet must hold the credential the issuer minted over the wire.");
        Assert.IsTrue(journey.Observations.IsProofVerified,
            "The issuance seam must have verified the holder proof signature and its c_nonce.");
        Assert.AreEqual(journey.CredentialIssuer, journey.Observations.ProofAudience,
            "The minted proof must carry the Credential Issuer identifier as aud.");
        Assert.AreEqual(CredentialIdentifier, journey.Observations.RequestedIdentifier,
            "The Credential Request must name the identifier the Token Response returned.");
        Assert.IsNull(journey.Observations.RequestedConfigurationId,
            "The Credential Request must not name a credential_configuration_id beside the identifier.");
        Assert.IsNotNull(journey.Observations.AuthorizedDetails);
        Assert.AreEqual(ConfigurationId, journey.Observations.AuthorizedDetails[0].CredentialConfigurationId,
            "The authorization seam must have received the wallet-composed details.");
    }


    /// <summary>
    /// A Token Response granting two identifiers for the requested configuration reaches the
    /// wallet through the token result with both identifiers in their order, and the Credential
    /// Request names the first of them and no configuration.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "credential_identifiers: REQUIRED. A non-empty array of strings, each uniquely identifying a
    /// Credential Dataset that can be issued using the Access Token returned in this response. Each of
    /// these Credential Datasets corresponds to the Credential Configuration referenced in the
    /// credential_configuration_id parameter. The Wallet MUST use these identifiers together with an
    /// Access Token in subsequent Credential Requests."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ATokenResponseGrantingTwoIdentifiersIsSpentOnTheFirst()
    {
        JourneyOutcome journey = await DriveJourneyAsync([CredentialIdentifier, SecondCredentialIdentifier]).ConfigureAwait(false);

        Assert.HasCount(1, journey.TokenResult.GrantedCredentialAuthorizations,
            "The token result must carry the one openid_credential authorization the Token Response granted.");
        Assert.AreEqual(ConfigurationId, journey.TokenResult.GrantedCredentialAuthorizations[0].CredentialConfigurationId);
        Assert.AreSequenceEqual(
            [CredentialIdentifier, SecondCredentialIdentifier],
            journey.TokenResult.GrantedCredentialAuthorizations[0].CredentialIdentifiers.ToArray(),
            "The token result must list the granted identifiers in the order the Token Response lists them.");

        Assert.IsTrue(journey.IssuedOutcome.IsSuccess, "The issuance over the granted identifier must succeed over the wire.");
        Assert.AreEqual(IssuedCredential, journey.IssuedOutcome.Value.Credentials[0]);
        Assert.AreEqual(CredentialIdentifier, journey.Observations.RequestedIdentifier,
            "The Credential Request must name the first identifier the Token Response returned.");
        Assert.IsNull(journey.Observations.RequestedConfigurationId,
            "The Credential Request must not name a credential_configuration_id beside the identifier.");
    }


    /// <summary>
    /// A Token Response that returns no <c>authorization_details</c> leaves the token result's
    /// granted list empty, and the Credential Request names the configuration and no identifier.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.2">OID4VCI 1.0 Section 8.2</see>:
    /// "credential_configuration_id: REQUIRED if a credential_identifiers parameter was not returned
    /// from the Token Response as part of the authorization_details parameter. It MUST NOT be used
    /// otherwise."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ATokenResponseWithoutGrantedDetailsIsSpentOnTheConfiguration()
    {
        JourneyOutcome journey = await DriveJourneyAsync(grantedIdentifiers: null).ConfigureAwait(false);

        Assert.IsEmpty(journey.TokenResult.GrantedCredentialAuthorizations,
            "A Token Response without authorization_details grants no openid_credential authorization.");
        Assert.IsTrue(journey.IssuedOutcome.IsSuccess, "The issuance by configuration must succeed over the wire.");
        Assert.AreEqual(IssuedCredential, journey.IssuedOutcome.Value.Credentials[0]);
        Assert.AreEqual(ConfigurationId, journey.Observations.RequestedConfigurationId,
            "The Credential Request must name the configuration.");
        Assert.IsNull(journey.Observations.RequestedIdentifier,
            "The Credential Request must not name a credential_identifier no Token Response returned.");
    }


    /// <summary>
    /// A Token Response whose <c>authorization_details</c> member name is spelled with an escape (the
    /// underscore written as a six-char escape of U+005F) names the same member as the unescaped
    /// spelling: the wallet's authorization-code path reads the granted authorization from it, the
    /// token result carries the configuration and the identifier, and the Credential Request names that
    /// identifier and no configuration.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.3">RFC 8259 Section 8.3</see>:
    /// "Implementations that transform the textual representation into sequences of Unicode code units
    /// and then perform the comparison numerically, code unit by code unit, are interoperable in the
    /// sense that implementations will agree in all cases on equality or inequality of two strings."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnAuthorizationDetailsNameSpelledWithAnEscapeIsReadAsTheMemberOnTheAuthorizationCodePath()
    {
        //The library's Authorization Server writes the member name unescaped, so the Token Response is
        //rewritten after it crossed the wire and before the client reads it.
        TokenResponseRewrite rewrite = new();
        JourneyOutcome journey = await DriveJourneyAsync(
            [CredentialIdentifier],
            rewrite,
            body => body.Replace("\"authorization_details\":[", "\"authorization\\u005fdetails\":[", StringComparison.Ordinal))
            .ConfigureAwait(false);

        Assert.IsTrue(rewrite.IsRewritten, "The Token Response must have carried authorization_details to respell.");
        Assert.HasCount(1, journey.TokenResult.GrantedCredentialAuthorizations,
            "The token result must carry the authorization the escaped member name spells.");
        Assert.AreEqual(ConfigurationId, journey.TokenResult.GrantedCredentialAuthorizations[0].CredentialConfigurationId);
        Assert.AreSequenceEqual(
            [CredentialIdentifier],
            journey.TokenResult.GrantedCredentialAuthorizations[0].CredentialIdentifiers.ToArray(),
            "The token result must list the identifier the escaped member granted.");
        Assert.IsTrue(journey.IssuedOutcome.IsSuccess, "The issuance over the granted identifier must succeed over the wire.");
        Assert.AreEqual(CredentialIdentifier, journey.Observations.RequestedIdentifier,
            "The Credential Request must name the identifier the escaped member granted.");
        Assert.IsNull(journey.Observations.RequestedConfigurationId,
            "The Credential Request must not name a credential_configuration_id beside the identifier.");
    }

    /// <summary>
    /// A Token Response whose <c>authorization_details</c> member holds an entry that is not an
    /// object fails the token exchange as <c>invalid_response</c> naming the member: no token is
    /// surfaced, the flow keeps its code pending, and no Nonce or Credential Request is sent.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "It is a non-empty array of objects, as defined in Section 7 of [RFC9396]."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AMalformedAuthorizationDetailsMemberFailsTheTokenExchange()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        await GrantIdentifiersAsync(host, [CredentialIdentifier], observations).ConfigureAwait(false);

        //The library's Authorization Server emits no malformed member, so the Token Response is
        //rewritten after it crossed the wire and before the client reads it: the array gains a
        //leading entry that is not an object.
        TokenResponseRewrite rewrite = new();
        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host,
            material,
            isComposingAuthorizationDetails: true,
            RewriteTokenEndpointAnswer(
                host,
                material,
                body => body.Replace("\"authorization_details\":[", "\"authorization_details\":[7,", StringComparison.Ordinal),
                rewrite)).ConfigureAwait(false);

        Assert.IsTrue(rewrite.IsRewritten, "The Token Response must have carried authorization_details to rewrite.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, exchange.TokenResult.Outcome,
            $"A malformed authorization_details member must fail the token exchange. ErrorCode={exchange.TokenResult.ErrorCode}");
        Assert.AreEqual("invalid_response", exchange.TokenResult.ErrorCode);
        Assert.StartsWith("authorization_details:", exchange.TokenResult.ErrorDescription, StringComparison.Ordinal);
        Assert.IsNull(exchange.TokenResult.Body, "No token may be surfaced from a refused Token Response.");
        Assert.IsEmpty(exchange.TokenResult.GrantedCredentialAuthorizations);
        _ = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(exchange.ClientFlowStore[exchange.FlowId],
            "The flow must keep its code pending: no token state is saved from a refused Token Response.");
        Assert.IsFalse(observations.IsNonceIssued, "No Nonce Request may follow a refused Token Response.");
        Assert.AreEqual(0, observations.CredentialRequestCount, "No Credential Request may follow a refused Token Response.");
    }


    /// <summary>
    /// The refresh exchange's result carries the <c>openid_credential</c> authorizations its Token
    /// Response granted: after a code exchange granting two identifiers, the client's refresh over the
    /// loopback host surfaces the granted configuration with both identifiers in their order. The
    /// library's token endpoint writes the granted <c>authorization_details</c> on the refresh answer
    /// itself, so the answer reaches the client as sent.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-7">RFC 9396 Section 7</see>:
    /// "In addition to the token response parameters as defined in [RFC6749], the AS MUST also return
    /// the authorization_details as granted by the resource owner and assigned to the respective access
    /// token."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ARefreshedTokenResultCarriesTheGrantedAuthorizations()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        await GrantIdentifiersAsync(host, [CredentialIdentifier, SecondCredentialIdentifier], observations).ConfigureAwait(false);

        //The host's refresh exchange needs the grant to carry a scope, so the pushed request names one.
        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host, material, isComposingAuthorizationDetails: true, rewriteTokenResponse: null, WellKnownScopes.OpenId)
            .ConfigureAwait(false);
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, exchange.TokenResult.Outcome,
            $"Token exchange must succeed. ErrorCode={exchange.TokenResult.ErrorCode} ErrorDescription={exchange.TokenResult.ErrorDescription}");
        string refreshToken = (string)exchange.TokenResult.Body![OAuthRequestParameterNames.RefreshToken];
        Assert.IsFalse(string.IsNullOrEmpty(refreshToken), "The registration must be granted a refresh token.");

        AuthCodeFlowEndpointResult refreshResult = await exchange.Client.AuthCode.RefreshAsync(
            exchange.Registration,
            new RefreshTokenRequest { ClientId = ClientId, RefreshToken = refreshToken },
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, refreshResult.Outcome,
            $"Refresh must succeed over the real wire. ErrorCode={refreshResult.ErrorCode} ErrorDescription={refreshResult.ErrorDescription}");
        Assert.HasCount(1, refreshResult.GrantedCredentialAuthorizations,
            "The refresh result must carry the one openid_credential authorization the refresh Token Response granted.");
        Assert.AreEqual("eu.europa.ec.eudi.pid.1", refreshResult.GrantedCredentialAuthorizations[0].CredentialConfigurationId);
        Assert.AreSequenceEqual(
            ["eu.europa.ec.eudi.pid.1-instance-1", "eu.europa.ec.eudi.pid.1-instance-2"],
            refreshResult.GrantedCredentialAuthorizations[0].CredentialIdentifiers.ToArray(),
            "The refresh result must list the granted identifiers in the order the Token Response lists them.");
    }


    /// <summary>
    /// A Token Response that repeats its <c>access_token</c> member is not read: the token exchange
    /// answers <c>server_error</c> with no token surfaced, the flow keeps its code pending, and no Nonce
    /// or Credential Request is sent.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-4">RFC 8259 Section 4</see>:
    /// "When the names within an object are not unique, the behavior of software that receives such
    /// an object is unpredictable."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ATokenResponseRepeatingItsAccessTokenFailsTheTokenExchange()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        await GrantIdentifiersAsync(host, [CredentialIdentifier], observations).ConfigureAwait(false);

        //The library's Authorization Server repeats no member, so the Token Response is rewritten after
        //it crossed the wire and before the client reads it: a second access_token leads the object.
        TokenResponseRewrite rewrite = new();
        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host,
            material,
            isComposingAuthorizationDetails: true,
            RewriteTokenEndpointAnswer(
                host,
                material,
                body => body.StartsWith('{', StringComparison.Ordinal) ? "{\"access_token\":\"repeated-access-token\"," + body[1..] : body,
                rewrite)).ConfigureAwait(false);

        Assert.IsTrue(rewrite.IsRewritten, "The Token Response must have been a JSON object to rewrite.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, exchange.TokenResult.Outcome,
            $"A Token Response repeating a member must fail the token exchange. ErrorCode={exchange.TokenResult.ErrorCode}");
        Assert.AreEqual("server_error", exchange.TokenResult.ErrorCode);
        Assert.IsNull(exchange.TokenResult.Body, "No token may be surfaced from a refused Token Response.");
        _ = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(exchange.ClientFlowStore[exchange.FlowId],
            "The flow must keep its code pending: no token state is saved from a refused Token Response.");
        Assert.IsFalse(observations.IsNonceIssued, "No Nonce Request may follow a refused Token Response.");
        Assert.AreEqual(0, observations.CredentialRequestCount, "No Credential Request may follow a refused Token Response.");
    }


    /// <summary>
    /// The token the client surfaces is the Token Response's top-level <c>access_token</c>: a member of
    /// that name inside an unrecognized object that precedes it over the wire is not read as the token.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.1">RFC 6749 Section 5.1</see>:
    /// "The parameters are serialized into a JavaScript Object Notation (JSON) structure by adding each
    /// parameter at the highest structure level." And: "The client MUST ignore unrecognized value names
    /// in the response."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ANestedAccessTokenIsNotSurfacedAsTheToken()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        await GrantIdentifiersAsync(host, [CredentialIdentifier], observations).ConfigureAwait(false);

        //The library's Authorization Server nests no access_token, so the Token Response is rewritten
        //after it crossed the wire and before the client reads it: an unrecognized object carrying an
        //access_token member leads the response object.
        TokenResponseRewrite rewrite = new();
        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host,
            material,
            isComposingAuthorizationDetails: true,
            RewriteTokenEndpointAnswer(
                host,
                material,
                body => body.StartsWith('{', StringComparison.Ordinal) ? "{\"example_parameter\":{\"access_token\":\"nested-token\"}," + body[1..] : body,
                rewrite)).ConfigureAwait(false);

        Assert.IsTrue(rewrite.IsRewritten, "The Token Response must have been a JSON object to rewrite.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, exchange.TokenResult.Outcome,
            $"A Token Response with an unrecognized nested object must be read. ErrorCode={exchange.TokenResult.ErrorCode}");
        string? mintedAccessToken = JwkJsonReader.ExtractStringValue(
            Encoding.UTF8.GetBytes(rewrite.SentBody!), OAuthRequestParameterNames.AccessTokenUtf8);
        Assert.IsNotNull(mintedAccessToken, "The Authorization Server's answer must carry its access_token.");
        string surfacedAccessToken = (string)exchange.TokenResult.Body![OAuthRequestParameterNames.AccessToken];
        Assert.AreNotEqual("nested-token", surfacedAccessToken, "The nested member must not be surfaced as the token.");
        Assert.AreEqual(mintedAccessToken, surfacedAccessToken,
            "The surfaced token must be the access_token the Authorization Server minted, not the nested member.");
    }


    /// <summary>
    /// A Token Response whose <c>authorization_details</c> hold, beside the valid grant, an
    /// <c>openid_credential</c> entry with a white-space <c>credential_configuration_id</c> fails the token
    /// exchange as <c>invalid_response</c> naming the member: no token is surfaced and the flow keeps its
    /// code pending.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.1">OID4VCI 1.0 Section 5.1.1</see>:
    /// "credential_configuration_id: REQUIRED. String specifying a unique identifier of the Credential
    /// being described in the credential_configurations_supported map in the Credential Issuer Metadata
    /// as defined in Section 12.2.4."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AGrantedEntryNamingNoConfigurationFailsTheTokenExchange()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        await GrantIdentifiersAsync(host, [CredentialIdentifier], observations).ConfigureAwait(false);

        //The library's Authorization Server emits no blank configuration identifier, so the Token
        //Response is rewritten after it crossed the wire and before the client reads it: the array gains
        //a leading openid_credential entry whose configuration identifier is white space.
        TokenResponseRewrite rewrite = new();
        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host,
            material,
            isComposingAuthorizationDetails: true,
            RewriteTokenEndpointAnswer(
                host,
                material,
                body => body.Replace(
                    "\"authorization_details\":[",
                    "\"authorization_details\":[{\"type\":\"openid_credential\",\"credential_configuration_id\":\" \",\"credential_identifiers\":[\"blank-configuration-dataset\"]},",
                    StringComparison.Ordinal),
                rewrite)).ConfigureAwait(false);

        Assert.IsTrue(rewrite.IsRewritten, "The Token Response must have carried authorization_details to rewrite.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, exchange.TokenResult.Outcome,
            $"An entry naming no configuration must fail the token exchange. ErrorCode={exchange.TokenResult.ErrorCode}");
        Assert.AreEqual("invalid_response", exchange.TokenResult.ErrorCode);
        Assert.StartsWith("authorization_details:", exchange.TokenResult.ErrorDescription, StringComparison.Ordinal);
        Assert.IsNull(exchange.TokenResult.Body, "No token may be surfaced from a refused Token Response.");
        _ = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(exchange.ClientFlowStore[exchange.FlowId],
            "The flow must keep its code pending: no token state is saved from a refused Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>access_token</c> decodes to a value holding a carriage return and a line
    /// feed fails the token exchange as <c>invalid_response</c> naming the member: no token is surfaced to
    /// be composed into an Authorization header, the flow keeps its code pending, and no Nonce or
    /// Credential Request is sent.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.12">RFC 6749 Appendix A.12</see>:
    /// "access-token = 1*VSCHAR", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see> defines
    /// "VSCHAR     = %x20-7E".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnAccessTokenOutsideItsGrammarFailsTheTokenExchange()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        await GrantIdentifiersAsync(host, [CredentialIdentifier], observations).ConfigureAwait(false);

        //The library's Authorization Server mints no token outside its grammar, so the Token Response is
        //rewritten after it crossed the wire and before the client reads it: the access_token's value
        //gains a leading header line written with the JSON escapes for a carriage return and a line feed.
        TokenResponseRewrite rewrite = new();
        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host,
            material,
            isComposingAuthorizationDetails: true,
            RewriteTokenEndpointAnswer(
                host,
                material,
                body => body.Replace("\"access_token\":\"", "\"access_token\":\"X-Injected: yes\\r\\n", StringComparison.Ordinal),
                rewrite)).ConfigureAwait(false);

        Assert.IsTrue(rewrite.IsRewritten, "The Token Response must have carried an access_token to rewrite.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, exchange.TokenResult.Outcome,
            $"An access_token outside its grammar must fail the token exchange. ErrorCode={exchange.TokenResult.ErrorCode}");
        Assert.AreEqual("invalid_response", exchange.TokenResult.ErrorCode);
        Assert.StartsWith("access_token:", exchange.TokenResult.ErrorDescription, StringComparison.Ordinal);
        Assert.DoesNotContain("X-Injected", exchange.TokenResult.ErrorDescription, StringComparison.Ordinal);
        Assert.IsNull(exchange.TokenResult.Body, "No token may be surfaced from a refused Token Response.");
        _ = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(exchange.ClientFlowStore[exchange.FlowId],
            "The flow must keep its code pending: no token state is saved from a refused Token Response.");
        Assert.IsFalse(observations.IsNonceIssued, "No Nonce Request may follow a refused Token Response.");
        Assert.AreEqual(0, observations.CredentialRequestCount, "No Credential Request may follow a refused Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>scope</c> decodes to a value holding a carriage return and a line feed,
    /// outside Appendix A.4, fails the token exchange as <c>invalid_response</c> naming the member: no
    /// token is surfaced and the flow keeps its code pending.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.4">RFC 6749 Appendix A.4</see>:
    /// "scope       = scope-token *( SP scope-token )" and "scope-token = 1*NQCHAR", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see> defines
    /// "NQCHAR     = %x21 / %x23-5B / %x5D-7E".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AScopeOutsideItsGrammarFailsTheTokenExchange()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        await GrantIdentifiersAsync(host, [CredentialIdentifier], observations).ConfigureAwait(false);

        //The library's Authorization Server sends no scope outside its grammar, so the Token Response is
        //rewritten after it crossed the wire and before the client reads it: its scope is a value holding
        //the JSON escapes for a carriage return and a line feed.
        TokenResponseRewrite rewrite = new();
        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host,
            material,
            isComposingAuthorizationDetails: true,
            RewriteTokenEndpointAnswer(
                host,
                material,
                body => WithStringMember(body, OAuthRequestParameterNames.Scope, "openid\\r\\nX"),
                rewrite)).ConfigureAwait(false);

        Assert.IsTrue(rewrite.IsRewritten, "The Token Response must have been rewritten.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, exchange.TokenResult.Outcome,
            $"A scope outside its grammar must fail the token exchange. ErrorCode={exchange.TokenResult.ErrorCode}");
        Assert.AreEqual("invalid_response", exchange.TokenResult.ErrorCode);
        Assert.StartsWith("scope:", exchange.TokenResult.ErrorDescription, StringComparison.Ordinal);
        Assert.IsNull(exchange.TokenResult.Body, "No token may be surfaced from a refused Token Response.");
        _ = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(exchange.ClientFlowStore[exchange.FlowId],
            "The flow must keep its code pending: no token state is saved from a refused Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>refresh_token</c> is present and empty fails the token exchange as
    /// <c>invalid_response</c> naming the member: no token is surfaced and the flow keeps its code pending.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.17">RFC 6749 Appendix A.17</see>:
    /// "refresh-token = 1*VSCHAR".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task APresentEmptyRefreshTokenFailsTheTokenExchange()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        await GrantIdentifiersAsync(host, [CredentialIdentifier], observations).ConfigureAwait(false);

        //The library's Authorization Server sends no empty refresh token, so the Token Response is
        //rewritten after it crossed the wire and before the client reads it: its refresh_token is empty.
        TokenResponseRewrite rewrite = new();
        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host,
            material,
            isComposingAuthorizationDetails: true,
            RewriteTokenEndpointAnswer(
                host,
                material,
                body => WithStringMember(body, OAuthRequestParameterNames.RefreshToken, string.Empty),
                rewrite)).ConfigureAwait(false);

        Assert.IsTrue(rewrite.IsRewritten, "The Token Response must have been rewritten.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, exchange.TokenResult.Outcome,
            $"A present empty refresh_token must fail the token exchange. ErrorCode={exchange.TokenResult.ErrorCode}");
        Assert.AreEqual("invalid_response", exchange.TokenResult.ErrorCode);
        Assert.StartsWith("refresh_token:", exchange.TokenResult.ErrorDescription, StringComparison.Ordinal);
        Assert.IsNull(exchange.TokenResult.Body, "No token may be surfaced from a refused Token Response.");
        _ = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(exchange.ClientFlowStore[exchange.FlowId],
            "The flow must keep its code pending: no token state is saved from a refused Token Response.");
    }


    /// <summary>
    /// A token endpoint answer whose <c>error</c> is empty, as a 400 Token Error Response or as a 200 body
    /// carrying it beside the token members, carries no error code the client can act on: the token
    /// exchange answers <c>server_error</c>, no token is surfaced and the flow keeps its code pending.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.7">RFC 6749 Appendix A.7</see>:
    /// "error             = 1*NQSCHAR".
    /// </summary>
    /// <param name="statusCode">The status code the client receives.</param>
    /// <param name="isBesideTheTokenMembers">Whether the empty <c>error</c> is added to the body the server sent rather than replacing it.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(400, false)]
    [DataRow(200, true)]
    public async Task AnEmptyErrorCodeFailsTheTokenExchange(int statusCode, bool isBesideTheTokenMembers)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        await GrantIdentifiersAsync(host, [CredentialIdentifier], observations).ConfigureAwait(false);

        //The library's Authorization Server writes no empty error code, so the Token Response is rewritten
        //after it crossed the wire and before the client reads it: an empty error replaces the body or
        //leads the token members.
        TokenResponseRewrite rewrite = new();
        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host,
            material,
            isComposingAuthorizationDetails: true,
            RewriteTokenEndpointAnswer(
                host,
                material,
                body => isBesideTheTokenMembers ? WithStringMember(body, OAuthRequestParameterNames.Error, string.Empty) : "{\"error\":\"\"}",
                rewrite,
                statusCode)).ConfigureAwait(false);

        Assert.IsTrue(rewrite.IsRewritten, "The Token Response must have been rewritten.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.InternalError, exchange.TokenResult.Outcome,
            $"An empty error code must fail the token exchange. ErrorCode={exchange.TokenResult.ErrorCode}");
        Assert.AreEqual("server_error", exchange.TokenResult.ErrorCode);
        Assert.IsNull(exchange.TokenResult.Body, "No token may be surfaced from a refused Token Response.");
        _ = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(exchange.ClientFlowStore[exchange.FlowId],
            "The flow must keep its code pending: no token state is saved from a refused Token Response.");
        Assert.IsFalse(observations.IsNonceIssued, "No Nonce Request may follow a refused Token Response.");
        Assert.AreEqual(0, observations.CredentialRequestCount, "No Credential Request may follow a refused Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>id_token</c> decodes to a value holding a carriage return and a line feed,
    /// outside the JWS Compact Serialization's alphabet, fails the token exchange as
    /// <c>invalid_response</c> naming the member: no token is surfaced and the flow keeps its code pending.
    /// <see href="https://www.rfc-editor.org/rfc/rfc7515#section-7.1">RFC 7515 Section 7.1</see>:
    /// "The JWS Compact Serialization represents digitally signed or MACed content as a compact, URL-safe
    /// string."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnIdTokenOutsideTheCompactSerializationFailsTheTokenExchange()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        await GrantIdentifiersAsync(host, [CredentialIdentifier], observations).ConfigureAwait(false);

        //The library's Authorization Server sends no id_token here, so the Token Response is rewritten
        //after it crossed the wire and before the client reads it: an id_token holding the JSON escapes
        //for a carriage return and a line feed leads the object.
        TokenResponseRewrite rewrite = new();
        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host,
            material,
            isComposingAuthorizationDetails: true,
            RewriteTokenEndpointAnswer(
                host,
                material,
                body => WithStringMember(body, OAuthRequestParameterNames.IdToken, "a\\r\\nb"),
                rewrite)).ConfigureAwait(false);

        Assert.IsTrue(rewrite.IsRewritten, "The Token Response must have been rewritten.");
        Assert.AreEqual(AuthCodeFlowEndpointOutcome.BadRequest, exchange.TokenResult.Outcome,
            $"An id_token outside its grammar must fail the token exchange. ErrorCode={exchange.TokenResult.ErrorCode}");
        Assert.AreEqual("invalid_response", exchange.TokenResult.ErrorCode);
        Assert.StartsWith("id_token:", exchange.TokenResult.ErrorDescription, StringComparison.Ordinal);
        Assert.IsNull(exchange.TokenResult.Body, "No token may be surfaced from a refused Token Response.");
        _ = Assert.IsInstanceOfType<AuthorizationCodeReceivedState>(exchange.ClientFlowStore[exchange.FlowId],
            "The flow must keep its code pending: no token state is saved from a refused Token Response.");
    }


    /// <summary>
    /// A Token Response body whose top-level string member <paramref name="memberName"/> holds
    /// <paramref name="jsonValue"/>: the member's value is replaced where the body carries the member, and
    /// the member is added as the object's first member where it does not, so the body never repeats it.
    /// </summary>
    /// <param name="body">The Token Response body the Authorization Server sent.</param>
    /// <param name="memberName">The member to set.</param>
    /// <param name="jsonValue">The member's value as JSON string content.</param>
    /// <returns>The rewritten body.</returns>
    private static string WithStringMember(string body, string memberName, string jsonValue)
    {
        string memberStart = "\"" + memberName + "\":\"";
        int valueStart = body.IndexOf(memberStart, StringComparison.Ordinal);
        if(valueStart < 0)
        {
            return "{" + memberStart + jsonValue + "\"," + body[1..];
        }

        valueStart += memberStart.Length;
        int valueEnd = valueStart + body.AsSpan(valueStart).IndexOf('"');

        return string.Concat(body.AsSpan(0, valueStart), jsonValue, body.AsSpan(valueEnd));
    }


    /// <summary>
    /// What a journey that reached the Credential Endpoint observed: the token result, the issuance
    /// outcome, what the issuer's seams saw and the Credential Issuer identifier the proof names.
    /// </summary>
    /// <param name="TokenResult">The authorization-code client's token result.</param>
    /// <param name="IssuedOutcome">The wallet's issuance outcome over the target chosen from the token result.</param>
    /// <param name="Observations">What the issuer's seams recorded.</param>
    /// <param name="CredentialIssuer">The Credential Issuer identifier the holder proof carries as <c>aud</c>.</param>
    private sealed record JourneyOutcome(
        AuthCodeFlowEndpointResult TokenResult,
        Result<CredentialIssuanceResult, Oid4VciRequestFailure> IssuedOutcome,
        IssuerSeamObservations Observations,
        string CredentialIssuer);


    /// <summary>
    /// What the authorization-code leg of a journey left behind: the token result, the flow's
    /// identifier, the client's flow store, and the client with its registration for a later refresh.
    /// </summary>
    /// <param name="TokenResult">The authorization-code client's token result.</param>
    /// <param name="FlowId">The identifier of the flow the exchange ran under.</param>
    /// <param name="ClientFlowStore">The client's flow store after the exchange.</param>
    /// <param name="Client">The client the exchange ran on.</param>
    /// <param name="Registration">The registration the exchange ran under.</param>
    private sealed record TokenExchange(
        AuthCodeFlowEndpointResult TokenResult,
        string FlowId,
        Dictionary<string, FlowState> ClientFlowStore,
        OAuthClient Client,
        ClientRegistration Registration);


    /// <summary>What a rewrite of the token endpoint's answer saw and did.</summary>
    private sealed class TokenResponseRewrite
    {
        /// <summary>The body the Authorization Server sent, before the rewrite.</summary>
        public string? SentBody { get; set; }

        /// <summary>Whether the rewrite changed the body.</summary>
        public bool IsRewritten { get; set; }
    }


    /// <summary>
    /// The rewrite of the token endpoint's answer after it crossed the wire and before the client reads
    /// it: <paramref name="rewriteBody"/> maps the body the Authorization Server sent to the body the
    /// client receives, every other form-post answer passes unchanged, and <paramref name="rewrite"/>
    /// records the body sent and whether the rewrite changed it. A <paramref name="statusCode"/> replaces
    /// the token endpoint's status code; <see langword="null"/> keeps the status the server sent.
    /// </summary>
    /// <param name="host">The host serving the Authorization Server.</param>
    /// <param name="material">The registration whose token endpoint is rewritten.</param>
    /// <param name="rewriteBody">The rewrite of the token endpoint's body.</param>
    /// <param name="rewrite">Where the rewrite records what it saw and did.</param>
    /// <param name="statusCode">The status code the client receives, or <see langword="null"/> for the one sent.</param>
    /// <returns>The rewrite of each form-post answer.</returns>
    private static Func<Uri, HttpResponseData, HttpResponseData> RewriteTokenEndpointAnswer(
        TestHostShell host, VerifierKeyMaterial material, Func<string, string> rewriteBody, TokenResponseRewrite rewrite, int? statusCode = null)
    {
        string tokenPath = TestHostShell.ComposeEndpointPath(
            WellKnownEndpointNames.AuthCodeToken, material.Registration.TenantId.Value);

        return (endpoint, response) =>
        {
            if(endpoint != new Uri(host.Host("default").HttpBaseAddress!, tokenPath))
            {
                return response;
            }

            string rewritten = rewriteBody(response.Body);
            rewrite.SentBody = response.Body;
            rewrite.IsRewritten = !string.Equals(rewritten, response.Body, StringComparison.Ordinal);

            return response with { Body = rewritten, StatusCode = statusCode ?? response.StatusCode };
        };
    }


    /// <summary>
    /// Drives the whole journey over the real wire and spends the token on a Credential Request whose
    /// target the wallet chooses through <see cref="CredentialRequestTarget.FromGrantedAuthorizations"/>
    /// over the token result's <see cref="AuthCodeFlowEndpointResult.GrantedCredentialAuthorizations"/>.
    /// </summary>
    /// <param name="grantedIdentifiers">
    /// The identifiers the authorization seam grants for the pushed details, or <see langword="null"/>
    /// for a pushed request that carries no <c>authorization_details</c>.
    /// </param>
    /// <param name="rewrite">Where the rewrite of the Token Response records what it saw and did, or <see langword="null"/> for no rewrite.</param>
    /// <param name="rewriteBody">The rewrite of the Token Response body before the client reads it, or <see langword="null"/> for none.</param>
    /// <returns>What the journey observed.</returns>
    private async Task<JourneyOutcome> DriveJourneyAsync(
        IReadOnlyList<string>? grantedIdentifiers,
        TokenResponseRewrite? rewrite = null,
        Func<string, string>? rewriteBody = null)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await RegisterWalletAsync(host).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireCredentialSeamsAsync(host).ConfigureAwait(false);
        if(grantedIdentifiers is not null)
        {
            await GrantIdentifiersAsync(host, grantedIdentifiers, observations).ConfigureAwait(false);
        }

        TokenExchange exchange = await ExchangeAuthorizationCodeAsync(
            host,
            material,
            isComposingAuthorizationDetails: grantedIdentifiers is not null,
            rewriteTokenResponse: rewrite is not null && rewriteBody is not null
                ? RewriteTokenEndpointAnswer(host, material, rewriteBody, rewrite)
                : null)
            .ConfigureAwait(false);
        AuthCodeFlowEndpointResult tokenResult = exchange.TokenResult;

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token exchange must succeed. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");

        string accessToken = (string)tokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string tokenType = tokenResult.Body.TryGetValue(OAuthRequestParameterNames.TokenType, out object? typeValue)
            ? (string)typeValue
            : WellKnownAuthenticationSchemes.Bearer;

        CredentialRequestTarget? target = CredentialRequestTarget.FromGrantedAuthorizations(
            ConfigurationId, tokenResult.GrantedCredentialAuthorizations);
        Assert.IsNotNull(target, "The token result must leave the wallet a Credential Request target for the requested configuration.");

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);
        Result<CredentialIssuanceResult, Oid4VciRequestFailure> issuedOutcome = await walletClient.IssueWithAccessTokenDetailedAsync(
            accessToken,
            tokenType,
            accessTokenExpiresAt: null,
            material.Registration.IssuerUri!,
            target,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        return new JourneyOutcome(tokenResult, issuedOutcome, observations, material.Registration.IssuerUri!.OriginalString);
    }


    /// <summary>
    /// Registers the Wallet client with the host under RFC 6749 with PKCE and a five-minute access
    /// token lifetime.
    /// </summary>
    /// <param name="host">The host serving the Authorization Server.</param>
    /// <returns>The registration's material.</returns>
    private static async Task<VerifierKeyMaterial> RegisterWalletAsync(TestHostShell host)
    {
        VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, Capabilities).ConfigureAwait(false);

        //OID4VCI 1.0 section 13.10: a plain-bearer credential token stays within the
        //long-lived threshold (lifetimes over 5 minutes count as long lived).
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);

        return material;
    }


    /// <summary>
    /// Wires the authorization-details parser and the credential authorization seam, which grants
    /// <paramref name="grantedIdentifiers"/> for the first pushed configuration and records the
    /// pushed details in <paramref name="observations"/>.
    /// </summary>
    /// <param name="host">The host serving the Authorization Server.</param>
    /// <param name="grantedIdentifiers">The section 6.2 <c>credential_identifiers</c> the seam grants.</param>
    /// <param name="observations">Where the seam records the details it received.</param>
    /// <returns>A task that completes when the alteration is published.</returns>
    private static async Task GrantIdentifiersAsync(
        TestHostShell host, IReadOnlyList<string> grantedIdentifiers, IssuerSeamObservations observations)
    {
        //Both authorization-details seams are coupled changes and are published together in ONE
        //alteration (EndpointServer.RequestAlterationAsync's own doc): a candidate wiring only the
        //parser is itself a half-wired server the composition-time pairing check refuses.
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultAuthorizationDetailsJsonParsing();
            candidateIntegration.ResolveCredentialAuthorizationAsync =
                (details, subject, registration, context, ct) =>
                {
                    observations.AuthorizedDetails = details;

                    return ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                    [
                        new GrantedCredentialAuthorization
                        {
                            CredentialConfigurationId = details[0].CredentialConfigurationId!,
                            CredentialIdentifiers = grantedIdentifiers
                        }
                    ]));
                };
        }).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives the authorization-code leg of the journey over the real wire: the pushed request
    /// carrying the offer's <c>issuer_state</c> and, when asked, the wallet-composed
    /// <c>authorization_details</c>, the authorize GET, the callback and the token exchange.
    /// </summary>
    /// <param name="host">The host serving the Authorization Server.</param>
    /// <param name="material">The registration the journey runs under.</param>
    /// <param name="isComposingAuthorizationDetails">Whether the pushed request carries the composed <c>authorization_details</c>.</param>
    /// <param name="rewriteTokenResponse">The rewrite of each form-post response before the client reads it, or <see langword="null"/>.</param>
    /// <param name="scope">The <c>scope</c> the pushed request names, or <see langword="null"/> for none.</param>
    /// <returns>The token result, the flow's identifier, the client's flow store, the client and its registration.</returns>
    private async Task<TokenExchange> ExchangeAuthorizationCodeAsync(
        TestHostShell host,
        VerifierKeyMaterial material,
        bool isComposingAuthorizationDetails,
        Func<Uri, HttpResponseData, HttpResponseData>? rewriteTokenResponse,
        string? scope = null)
    {
        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateRewritingOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                PolicyProfile.Rfc6749WithPkce,
                rewriteTokenResponse,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Section 5.1.1: the wallet-composed authorization_details and the offer's issuer_state ride
        //the pushed request as additional fields; PKCE and state are the auth-code client's own.
        Dictionary<string, string> pushedFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.IssuerState] = IssuerState
        };

        if(isComposingAuthorizationDetails)
        {
            pushedFields[OAuthRequestParameterNames.AuthorizationDetails] =
                CredentialAuthorizationDetailComposition.Compose(ConfigurationId, material.Registration.IssuerUri);
        }

        if(scope is not null)
        {
            pushedFields[OAuthRequestParameterNames.Scope] = scope;
        }

        OAuthFormEncodedFields authorizationFields = new(pushedFields);

        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, RedirectUri, authorizationFields,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect over the real wire. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];
        await client.Infrastructure.SaveStateAsync(parState, [], TestContext.CancellationToken)
            .ConfigureAwait(false);

        HostedAuthorizationServer hosted = host.Host("default");
        string segment = material.Registration.TenantId.Value;
        (string code, string? iss) = await DriveAuthorizeAsync(
            hosted, segment, parState, host.ServerCertificate, TestContext.CancellationToken).ConfigureAwait(false);

        Dictionary<string, string> callbackFields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.Code] = code,
            [OAuthRequestParameterNames.State] = flowId
        };

        if(iss is not null)
        {
            callbackFields[OAuthRequestParameterNames.Iss] = iss;
        }

        AuthCodeFlowEndpointResult callbackResult = await client.AuthCode.HandleCallbackAsync(
            registration, new OAuthFormEncodedFields(callbackFields), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, callbackResult.Outcome,
            $"Callback must succeed. ErrorCode={callbackResult.ErrorCode} ErrorDescription={callbackResult.ErrorDescription}");

        AuthCodeFlowEndpointResult tokenResult = await client.AuthCode.ExchangeTokenAsync(
            registration, flowId, TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        return new TokenExchange(tokenResult, flowId, clientFlowStore, client, registration);
    }


    /// <summary>Observations the issuer's seams record for the assertions.</summary>
    private sealed class IssuerSeamObservations
    {
        /// <summary>The <c>authorization_details</c> the credential authorization seam received, if it ran.</summary>
        public IReadOnlyList<CredentialAuthorizationDetail>? AuthorizedDetails { get; set; }

        /// <summary>Whether the Nonce Endpoint issued a <c>c_nonce</c>.</summary>
        public bool IsNonceIssued { get; set; }

        /// <summary>How many Credential Requests reached the issuance seam.</summary>
        public int CredentialRequestCount { get; set; }

        /// <summary>Whether the seam verified the holder proof signature and its c_nonce.</summary>
        public bool IsProofVerified { get; set; }

        /// <summary>The <c>aud</c> the verified proof carried.</summary>
        public string? ProofAudience { get; set; }

        /// <summary>The <c>credential_identifier</c> the Credential Request named, if any.</summary>
        public string? RequestedIdentifier { get; set; }

        /// <summary>The <c>credential_configuration_id</c> the Credential Request named, if any.</summary>
        public string? RequestedConfigurationId { get; set; }
    }


    //Drives the browser's authorize GET: a real wire GET with auto-redirect disabled and the test
    //subject header standing in for an authenticated session; the code and iss are read off the
    //302 Location instead of following it toward the unreachable client callback origin.
    private static async Task<(string Code, string? Iss)> DriveAuthorizeAsync(
        HostedAuthorizationServer hosted,
        string segment,
        ParCompletedState parState,
        X509Certificate2 pinnedCertificate,
        CancellationToken cancellationToken)
    {
        Uri authorizeUrl = new(
            hosted.HttpBaseAddress!,
            $"{TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeAuthorize, segment)}" +
            $"?{OAuthRequestParameterNames.ClientId}={Uri.EscapeDataString(ClientId)}" +
            $"&{OAuthRequestParameterNames.RequestUri}={Uri.EscapeDataString(parState.Par.RequestUri.ToString())}");

        using SocketsHttpHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(pinnedCertificate);
        noRedirectHandler.AllowAutoRedirect = false;
        using HttpClient browserClient = new(noRedirectHandler) { BaseAddress = hosted.HttpBaseAddress };
        using HttpRequestMessage authorizeRequest = new(HttpMethod.Get, authorizeUrl);
        authorizeRequest.Headers.Add(AuthorizationServerHttpApplication.TestSubjectHeaderName, SubjectId);

        using HttpResponseMessage authorizeResponse = await browserClient
            .SendAsync(authorizeRequest, cancellationToken).ConfigureAwait(false);

        Assert.AreEqual(302, (int)authorizeResponse.StatusCode,
            "The authorize endpoint must redirect with the authorization code.");

        string location = authorizeResponse.Headers.Location!.ToString();
        string code = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Code)
            ?? throw new InvalidOperationException("Authorize redirect Location missing code.");
        string? iss = TestBrowser.ExtractQueryParam(location, OAuthRequestParameterNames.Iss);

        return (code, iss);
    }


    /// <summary>
    /// Installs credential parsing, the Credential Issuer catalogue listing <see cref="ConfigurationId"/>,
    /// proof and issuance delegates through a requested alteration.
    /// </summary>
    private static async Task<IssuerSeamObservations> WireCredentialSeamsAsync(TestHostShell host)
    {
        IssuerSeamObservations observations = new();
        string? mintedNonce = null;

        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            _ = candidateIntegration.UseDefaultCredentialRequestJsonParsing();

            candidateIntegration.ContributeCredentialIssuerMetadataAsync = static (_, _, _) =>
                ValueTask.FromResult(new CredentialIssuerMetadataContribution
                {
                    CredentialConfigurationsSupported = TestHostShell.ListCredentialConfigurations(ConfigurationId)
                });


            candidateIntegration.IssueCredentialNonceAsync = (_, _) =>
            {
                mintedNonce = $"c-nonce-{Guid.NewGuid():N}";
                observations.IsNonceIssued = true;

                return ValueTask.FromResult(mintedNonce);
            };


            candidateIntegration.IssueCredentialAsync = async (request, _, _, _, ct) =>
            {
                observations.CredentialRequestCount++;
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
                    observations.RequestedIdentifier = request.CredentialIdentifier;
                    observations.RequestedConfigurationId = request.CredentialConfigurationId;

                    return CredentialIssuanceDecision.Issue([IssuedCredential]);
                }
            };
        }).ConfigureAwait(false);

        return observations;
    }


    //Reads the holder key, nonce, and audience off a compact JWT proof for the seam's verification.
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


    //Decodes one base64url segment of a compact JWT.
    private static string DecodeSegment(string compactJwt, int segmentIndex)
    {
        string[] parts = compactJwt.Split('.');
        using IMemoryOwner<byte> bytes = TestSetup.Base64UrlDecoder(parts[segmentIndex], Pool);

        return Encoding.UTF8.GetString(bytes.Memory.Span).TrimEnd('\0');
    }


    //Resolves the endpoint URLs against the started host's real Kestrel base address. The token
    //endpoint is required by the record but unused here: this journey's token came from the
    //auth-code exchange.
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


    //Builds the wallet client over HttpClient-backed transport delegates that close over the
    //started host's SharedHttpClient. The wallet library stays System.Net-free.
    private Oid4VciWalletClient BuildWalletClient(TestHostShell host)
    {
        HttpClient httpClient = host.Host("default").SharedHttpClient!;

        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (endpoint, formFields, headers, _, ct) =>
                HttpClientTransport.SendFormPostAsync(httpClient, endpoint, formFields, headers, ct),
            SendJsonPost = (endpoint, body, headers, _, ct) =>
                HttpClientTransport.SendJsonPostAsync(httpClient, endpoint, body, headers, ct),
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            OutboundFetchPolicy = TestHostShell.LoopbackOutboundFetchPolicy
        };

        return new Oid4VciWalletClient(configuration);
    }


}
