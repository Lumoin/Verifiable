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
    /// A Pre-Authorized Code journey whose Token Response, after it crossed the wire, carries an
    /// <c>access_token</c> decoding to a value holding a carriage return and a line feed is not spent: the
    /// wallet answers a malformed-response failure, and neither a Nonce Request nor a Credential Request
    /// reaches the Issuer, so the token is never composed into an Authorization header.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.12">RFC 6749 Appendix A.12</see>:
    /// "access-token = 1*VSCHAR", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see> defines
    /// "VSCHAR     = %x20-7E".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task APreAuthorizedTokenAnswerHoldingALineBreakIsNotSpent()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        //The library's Authorization Server mints no token outside its grammar, so the Token Response is
        //rewritten after it crossed the wire and before the wallet reads it: the access_token's value
        //gains a leading header line written with the JSON escapes for a carriage return and a line feed.
        bool isRewritten = false;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            rewriteTokenAnswer: answer =>
            {
                string rewritten = answer.Body.Replace(
                    "\"access_token\":\"", "\"access_token\":\"X-Injected: yes\\r\\n", StringComparison.Ordinal);
                isRewritten = !string.Equals(rewritten, answer.Body, StringComparison.Ordinal);

                return answer with { Body = rewritten };
            });

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

        Assert.IsTrue(isRewritten, "The Token Response must have carried an access_token to rewrite.");
        Assert.IsFalse(outcome.IsSuccess, "An access_token outside its grammar must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(0, observations.NonceRequests, "No Nonce Request may follow a malformed Token Response.");
        Assert.AreEqual(0, observations.IssuanceRequests, "No Credential Request may reach the Issuer.");
    }


    /// <summary>
    /// A Pre-Authorized Code journey whose Token Response, after it crossed the wire, is a Token Error
    /// Response whose <c>error</c> decodes to a value holding a carriage return and a line feed carries no
    /// error code the wallet can act on: the wallet answers a malformed-response failure that echoes none
    /// of it, and neither a Nonce Request nor a Credential Request reaches the Issuer.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B /
    /// %x5D-7E."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task APreAuthorizedTokenErrorOutsideItsCharacterSetIsMalformed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        //The library's Authorization Server writes no error code outside its set, so the Token Response is
        //rewritten after it crossed the wire and before the wallet reads it: a 400 Token Error Response
        //whose error carries a header line written with the JSON escapes for a carriage return and a line
        //feed.
        bool isRewritten = false;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            rewriteTokenAnswer: answer =>
            {
                isRewritten = answer.StatusCode == 200;

                return answer with
                {
                    StatusCode = 400,
                    Body = "{\"error\":\"invalid_grant\\r\\nX-Injected: yes\"}"
                };
            });

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

        Assert.IsTrue(isRewritten, "The Token Request must have been answered over the wire before the rewrite.");
        Assert.IsFalse(outcome.IsSuccess, "A refused Token Request must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.ErrorCode, "An error code outside its set must not be surfaced.");
        Assert.DoesNotContain("X-Injected", outcome.Error.ToString(), StringComparison.Ordinal);
        Assert.AreEqual(0, observations.NonceRequests, "No Nonce Request may follow a refused Token Request.");
        Assert.AreEqual(0, observations.IssuanceRequests, "No Credential Request may reach the Issuer.");
    }


    /// <summary>
    /// A Pre-Authorized Code journey whose Token Response, after it crossed the wire, carries a
    /// <c>token_type</c> written as a URI-reference is spent: the wallet makes the Credential Request and
    /// surfaces the type as written.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.1">RFC 3986 Section 4.1</see> defines
    /// "URI-reference = URI / relative-ref".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task APreAuthorizedUriReferenceTokenTypeIsSpent()
    {
        const string UriReferenceTokenType = "urn:ietf:params:oauth:token-type:jwt";

        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        //The library's Authorization Server sends a type name, so the Token Response is rewritten after it
        //crossed the wire and before the wallet reads it: the token_type's value becomes the URI-reference.
        bool isRewritten = false;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            rewriteTokenAnswer: answer =>
            {
                const string TokenTypeMember = "\"token_type\":\"";
                int valueStart = answer.Body.IndexOf(TokenTypeMember, StringComparison.Ordinal);
                if(valueStart < 0)
                {
                    return answer;
                }

                valueStart += TokenTypeMember.Length;
                int valueEnd = valueStart + answer.Body.AsSpan(valueStart).IndexOf('"');
                isRewritten = true;

                return answer with
                {
                    Body = string.Concat(answer.Body.AsSpan(0, valueStart), UriReferenceTokenType, answer.Body.AsSpan(valueEnd))
                };
            });

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

        Assert.IsTrue(isRewritten, "The Token Response must have carried a token_type to rewrite.");
        Assert.IsTrue(outcome.IsSuccess, "A URI-reference token_type must be accepted.");
        Assert.AreEqual(UriReferenceTokenType, outcome.Value.TokenType, "The token_type must be surfaced as written.");
        Assert.AreEqual(1, observations.IssuanceRequests, "Exactly one Credential Request must reach the Issuer.");
    }


    /// <summary>
    /// A Pre-Authorized Code journey whose Token Response, after it crossed the wire, carries an
    /// <c>access_token</c> that is not a <c>token68</c> credential (white space, a space inside) cannot
    /// present it in an Authorization header: the wallet answers a malformed-response failure, and neither
    /// a Nonce Request nor a Credential Request reaches the Issuer.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>:
    /// "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="".
    /// </summary>
    /// <param name="accessToken">The <c>access_token</c> the rewritten Token Response carries, as JSON string content.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(" ")]
    [DataRow("a b")]
    public async Task APreAuthorizedAccessTokenOutsideToken68IsMalformed(string accessToken)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        //The library's Authorization Server mints only token68 tokens, so the Token Response is rewritten
        //after it crossed the wire and before the wallet reads it: the access_token's value is replaced.
        bool isRewritten = false;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            rewriteTokenAnswer: answer =>
            {
                string rewritten = WithStringMemberValue(answer.Body, OAuthRequestParameterNames.AccessToken, accessToken);
                isRewritten = !string.Equals(rewritten, answer.Body, StringComparison.Ordinal);

                return answer with { Body = rewritten };
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = default;
        Exception? escaped = null;
        try
        {
            outcome = await walletClient.IssuePreAuthorizedDetailedAsync(
                ComposeOffer(material),
                ConfigurationId,
                holderPrivate,
                holderPublic,
                ResolveEndpoints(host, material),
                transactionCode: null,
                responseEncryption: null,
                TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
                TestContext.CancellationToken).ConfigureAwait(false);
        }
        catch(Exception thrown)
        {
            //The issuance answers its refusal as a failure value; an exception escaping it is recorded so
            //that the assertion below, not the exception, fails the row.
            escaped = thrown;
        }

        Assert.IsNull(escaped, "Issuance must complete with a failure value, not an exception.");
        Assert.IsTrue(isRewritten, "The Token Response must have carried an access_token to rewrite.");
        Assert.IsFalse(outcome.IsSuccess, "An access_token outside token68 must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(0, observations.NonceRequests, "No Nonce Request may follow a malformed Token Response.");
        Assert.AreEqual(0, observations.IssuanceRequests, "No Credential Request may reach the Issuer.");
    }


    /// <summary>
    /// A Pre-Authorized Code journey whose Token Response, after it crossed the wire, carries a
    /// <c>token_type</c> holding a quotation mark, neither a type name nor an RFC 3986 URI-reference: the
    /// wallet answers a malformed-response failure, and no Credential Request reaches the Issuer.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", "type-name  = 1*name-char" and
    /// "name-char  = "-" / "." / "_" / DIGIT / ALPHA".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task APreAuthorizedTokenTypeOutsideItsGrammarIsMalformed()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, IssuerCapabilities).ConfigureAwait(false);
        await host.SetAccessTokenLifetimeAsync(material, TimeSpan.FromMinutes(5)).ConfigureAwait(false);
        IssuerSeamObservations observations = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        //The library's Authorization Server sends a type name, so the Token Response is rewritten after it
        //crossed the wire and before the wallet reads it: the token_type's value holds the JSON escape for
        //a quotation mark.
        bool isRewritten = false;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            rewriteTokenAnswer: answer =>
            {
                string rewritten = WithStringMemberValue(answer.Body, OAuthRequestParameterNames.TokenType, "a\\\"b");
                isRewritten = !string.Equals(rewritten, answer.Body, StringComparison.Ordinal);

                return answer with { Body = rewritten };
            });

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

        Assert.IsTrue(isRewritten, "The Token Response must have carried a token_type to rewrite.");
        Assert.IsFalse(outcome.IsSuccess, "A token_type outside its grammar must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(0, observations.IssuanceRequests, "No Credential Request may reach the Issuer.");
    }


    /// <summary>
    /// A Token Response body whose top-level string member <paramref name="memberName"/> holds
    /// <paramref name="jsonValue"/> where the body carries the member; a body without it is returned as it
    /// came.
    /// </summary>
    /// <param name="body">The Token Response body the Authorization Server sent.</param>
    /// <param name="memberName">The member whose value is replaced.</param>
    /// <param name="jsonValue">The member's value as JSON string content.</param>
    /// <returns>The rewritten body, or <paramref name="body"/> when it carries no such member.</returns>
    private static string WithStringMemberValue(string body, string memberName, string jsonValue)
    {
        string memberStart = "\"" + memberName + "\":\"";
        int valueStart = body.IndexOf(memberStart, StringComparison.Ordinal);
        if(valueStart < 0)
        {
            return body;
        }

        valueStart += memberStart.Length;
        int valueEnd = valueStart + body.AsSpan(valueStart).IndexOf('"');

        return string.Concat(body.AsSpan(0, valueStart), jsonValue, body.AsSpan(valueEnd));
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
    /// A Token Response whose <c>authorization_details</c> hold, beside a valid grant for the requested
    /// configuration, an <c>openid_credential</c> entry whose <c>credential_configuration_id</c> is empty
    /// or white space is malformed as a whole: the wallet answers a malformed-response failure and sends
    /// no Nonce or Credential Request. The library's Authorization Server emits no such entry, so the
    /// response is delivered through the wallet's transport delegate.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-5.1.1">OID4VCI 1.0 Section 5.1.1</see>:
    /// "credential_configuration_id: REQUIRED. String specifying a unique identifier of the Credential
    /// being described in the credential_configurations_supported map in the Credential Issuer Metadata
    /// as defined in Section 12.2.4."
    /// </summary>
    /// <param name="configurationId">The blank configuration identifier the second entry carries, as JSON string content.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("")]
    [DataRow(" \\t")]
    public async Task AnEntryWithABlankConfigurationIdentifierIsAMalformedTokenResponse(string configurationId)
    {
        GrantedDetailsIssuance issuance = await IssueOverGrantedDetailsAsync(
            "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + ConfigurationId + "\","
            + "\"credential_identifiers\":[\"pid-dataset-1\"]},"
            + "{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + configurationId + "\","
            + "\"credential_identifiers\":[\"pid-dataset-2\"]}]").ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "An entry naming no configuration must make the member malformed.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>access_token</c> decodes to a value holding a carriage return and a line
    /// feed is malformed: the wallet answers a malformed-response failure and sends no Nonce or Credential
    /// Request, so the token is never composed into an Authorization header. The library's Authorization
    /// Server mints no such token, so the response is delivered through the wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.12">RFC 6749 Appendix A.12</see>:
    /// "access-token = 1*VSCHAR", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A">RFC 6749 Appendix A</see> defines
    /// "VSCHAR     = %x20-7E".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnAccessTokenOutsideItsGrammarIsAMalformedTokenResponse()
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"access_token\":\"X-Injected: yes\\r\\ntok\",\"token_type\":\"Bearer\"}").ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "An access_token outside its grammar must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>token_type</c> decodes to a value holding a carriage return and a line
    /// feed, which neither a type name nor a URI-reference holds, is malformed: the wallet answers a
    /// malformed-response failure and sends no Nonce or Credential Request. The library's Authorization
    /// Server sends no such type, so the response is delivered through the wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", "type-name  = 1*name-char" and
    /// "name-char  = "-" / "." / "_" / DIGIT / ALPHA".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ATokenTypeOutsideItsGrammarIsAMalformedTokenResponse()
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"access_token\":\"tok\",\"token_type\":\"Bearer\\r\\nX-Injected: yes\"}").ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "A token_type outside its grammar must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>token_type</c> is an RFC 3986 URI-reference (a URI behind its scheme,
    /// whatever its authority's port, or a relative reference whose first segment holds no colon) is
    /// accepted: the wallet spends the token on one Credential Request and surfaces the type as written.
    /// The library's Authorization Server sends no such type, so the response is delivered through the
    /// wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.1">RFC 3986 Section 4.1</see> defines
    /// "URI-reference = URI / relative-ref".
    /// </summary>
    /// <param name="tokenType">The <c>token_type</c> the Token Response carries.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("urn:ietf:params:oauth:token-type:jwt")]
    [DataRow("https://as.example/types/bearer")]
    [DataRow("a:b")]
    [DataRow("a:b:c")]
    [DataRow("https://as.example:99999/t")]
    [DataRow("http://")]
    [DataRow("types/bearer")]
    public async Task AUriReferenceTokenTypeIsSpent(string tokenType)
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"access_token\":\"tok\",\"token_type\":\"" + tokenType + "\"}").ConfigureAwait(false);

        Assert.IsTrue(issuance.Outcome.IsSuccess, "A URI-reference token_type must be accepted.");
        Assert.HasCount(1, issuance.CredentialRequestBodies, "Exactly one Credential Request must be sent.");
        Assert.AreEqual(tokenType, issuance.Outcome.Value.TokenType, "The token_type must be surfaced as written.");
    }


    /// <summary>
    /// A Token Response whose <c>token_type</c> is neither a type name nor an RFC 3986 URI-reference (a
    /// quotation mark, a reverse solidus, a brace or a bracket outside an authority, a percent sign without
    /// two hex digits, a second number sign, or a first segment holding a colon behind no scheme) is
    /// malformed: the wallet answers a malformed-response failure and sends no Nonce or Credential Request.
    /// The library's Authorization Server sends no such type, so the response is delivered through the
    /// wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", where
    /// <see href="https://www.rfc-editor.org/rfc/rfc3986#section-4.2">RFC 3986 Section 4.2</see> holds:
    /// "A path segment that contains a colon character (e.g., "this:that") cannot be used as the first
    /// segment of a relative-path reference, as it would be mistaken for a scheme name."
    /// </summary>
    /// <param name="tokenType">The <c>token_type</c> the Token Response carries, as JSON string content.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("a\\\"b")]
    [DataRow("a\\\\b")]
    [DataRow("a%zz")]
    [DataRow("%")]
    [DataRow("a#b#c")]
    [DataRow("::")]
    [DataRow("1:x")]
    [DataRow(":a")]
    [DataRow("C:\\\\x")]
    [DataRow("\\\\\\\\server\\\\share")]
    [DataRow("a{b}")]
    [DataRow("[a]")]
    public async Task ATokenTypeOutsideTheUriReferenceGrammarIsAMalformedTokenResponse(string tokenType)
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"access_token\":\"tok\",\"token_type\":\"" + tokenType + "\"}").ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "A token_type outside its grammar must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>access_token</c> is not a <c>token68</c> credential (white space only, a
    /// space inside, a quotation mark) cannot be carried in an Authorization header: the wallet answers a
    /// malformed-response failure and sends no Nonce or Credential Request. The library's Authorization
    /// Server mints no such token, so the response is delivered through the wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>:
    /// "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="".
    /// <see href="https://www.rfc-editor.org/rfc/rfc6750#section-2.1">RFC 6750 Section 2.1</see>:
    /// "b64token    = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="".
    /// </summary>
    /// <param name="accessToken">The <c>access_token</c> the Token Response carries, as JSON string content.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(" ")]
    [DataRow("   ")]
    [DataRow("a b")]
    [DataRow("a\\\"b")]
    public async Task AnAccessTokenOutsideToken68IsAMalformedTokenResponse(string accessToken)
    {
        GrantedDetailsIssuance? issuance = null;
        Exception? escaped = null;
        try
        {
            issuance = await IssueOverTokenResponseAsync(
                "{\"access_token\":\"" + accessToken + "\",\"token_type\":\"Bearer\"}").ConfigureAwait(false);
        }
        catch(Exception thrown)
        {
            //The issuance answers its refusal as a failure value; an exception escaping it is recorded so
            //that the assertion below, not the exception, fails the row.
            escaped = thrown;
        }

        Assert.IsNull(escaped, "Issuance must complete with a failure value, not an exception.");
        Assert.IsNotNull(issuance);
        Assert.IsFalse(issuance.Outcome.IsSuccess, "An access_token outside token68 must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>access_token</c> is a <c>token68</c> credential holding every char of its
    /// alphabet beside the letters and digits, with trailing padding, is spent on one Credential Request.
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>:
    /// "token68        = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AToken68AccessTokenIsSpent()
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"access_token\":\"abc-._~+/==\",\"token_type\":\"Bearer\"}").ConfigureAwait(false);

        Assert.IsTrue(issuance.Outcome.IsSuccess, "A token68 access_token must be accepted.");
        Assert.HasCount(1, issuance.CredentialRequestBodies, "Exactly one Credential Request must be sent.");
        Assert.AreEqual("abc-._~+/==", issuance.Outcome.Value.AccessToken);
    }


    /// <summary>
    /// A Token Error Response whose <c>error</c> is empty or holds a char outside Section 5.2's set (a
    /// carriage return and a line feed, a quotation mark) carries no error code the wallet can act on: the
    /// wallet answers a malformed-response failure whose description echoes none of it, and sends no Nonce
    /// or Credential Request.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error" parameter MUST NOT include characters outside the set %x20-21 / %x23-5B /
    /// %x5D-7E."
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.7">RFC 6749 Appendix A.7</see>:
    /// "error             = 1*NQSCHAR".
    /// </summary>
    /// <param name="errorCode">The <c>error</c> the Token Error Response carries, as JSON string content.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("invalid_grant\\r\\nX-Injected: yes")]
    [DataRow("bad\\\"code")]
    [DataRow("")]
    public async Task ATokenErrorCodeOutsideItsCharacterSetIsAMalformedResponse(string errorCode)
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"error\":\"" + errorCode + "\"}", tokenStatusCode: 400).ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "A refused Token Request must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsNull(issuance.Outcome.Error.ErrorCode, "An error code outside its set must not be surfaced.");
        Assert.DoesNotContain("X-Injected", issuance.Outcome.Error.ToString(), StringComparison.Ordinal);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a refused Token Request.");
    }


    /// <summary>
    /// A Token Error Response whose <c>error_description</c> holds a char outside Section 5.2's set (a
    /// quotation mark, a carriage return and a line feed) is read without its description: the error
    /// stands with its code.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 Section 5.2</see>:
    /// "Values for the "error_description" parameter MUST NOT include characters outside the set %x20-21 /
    /// %x23-5B / %x5D-7E."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ATokenErrorDescriptionOutsideItsCharacterSetIsAbsent()
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"error\":\"invalid_grant\",\"error_description\":\"a\\\"b\\r\\nc\"}", tokenStatusCode: 400).ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "A refused Token Request must be a refusal.");
        Assert.AreEqual(Oid4VciRequestFailureKind.ErrorResponse, issuance.Outcome.Error.Kind);
        Assert.AreEqual(OAuthErrors.InvalidGrant, issuance.Outcome.Error.ErrorCode);
        Assert.IsNull(issuance.Outcome.Error.ErrorDescription, "A description outside its set must be read as absent.");
    }


    /// <summary>
    /// A Token Response whose <c>token_type</c> holds a space, which neither a type name nor a
    /// URI-reference holds, is malformed: the wallet answers a malformed-response failure and sends no
    /// Nonce or Credential Request. The library's Authorization Server sends no such type, so the response
    /// is delivered through the wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", "type-name  = 1*name-char" and
    /// "name-char  = "-" / "." / "_" / DIGIT / ALPHA".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ATokenTypeHoldingASpaceIsAMalformedTokenResponse()
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"access_token\":\"tok\",\"token_type\":\"Bearer Token\"}").ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "A token_type holding a space must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>token_type</c> is present and empty is malformed: the wallet answers a
    /// malformed-response failure and sends no Nonce or Credential Request. The library's Authorization
    /// Server sends no such type, so the response is delivered through the wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.13">RFC 6749 Appendix A.13</see>:
    /// "token-type = type-name / URI-reference", "type-name  = 1*name-char" and
    /// "name-char  = "-" / "." / "_" / DIGIT / ALPHA".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnEmptyTokenTypeIsAMalformedTokenResponse()
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"access_token\":\"tok\",\"token_type\":\"\"}").ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "An empty token_type must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// A Token Response whose <c>access_token</c> is present and empty is malformed: the wallet answers a
    /// malformed-response failure and sends no Nonce or Credential Request. The library's Authorization
    /// Server mints no such token, so the response is delivered through the wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#appendix-A.12">RFC 6749 Appendix A.12</see>:
    /// "access-token = 1*VSCHAR".
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task AnEmptyAccessTokenIsAMalformedTokenResponse()
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"access_token\":\"\",\"token_type\":\"Bearer\"}").ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "An empty access_token must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsEmpty(issuance.LaterRequests, "No Nonce or Credential Request may follow a malformed Token Response.");
    }


    /// <summary>
    /// The failure the wallet answers for an <c>access_token</c> outside its grammar names the rule and
    /// echoes none of the token in its description.
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-10.3">RFC 6749 Section 10.3</see>:
    /// "Access token credentials (as well as any confidential access token attributes) MUST be kept
    /// confidential in transit and storage, and only shared among the authorization server, the resource
    /// servers the access token is valid for, and the client to whom the access token is issued."
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task ARefusedAccessTokenIsNotEchoedInTheFailure()
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"access_token\":\"SlAV32hkKG\\r\\nX-Injected: yes\",\"token_type\":\"Bearer\"}").ConfigureAwait(false);

        Assert.IsFalse(issuance.Outcome.IsSuccess, "An access_token outside its grammar must not be spent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, issuance.Outcome.Error.Kind);
        Assert.IsNotNull(issuance.Outcome.Error.ErrorDescription);
        Assert.Contains("Appendix A.12", issuance.Outcome.Error.ErrorDescription, StringComparison.Ordinal);
        Assert.DoesNotContain("SlAV32hkKG", issuance.Outcome.Error.ErrorDescription, StringComparison.Ordinal);
        Assert.DoesNotContain("SlAV32hkKG", issuance.Outcome.Error.ToString(), StringComparison.Ordinal);
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
    /// A Token Response whose <c>authorization_details</c> member name is spelled with an escape is read as
    /// that member: the wallet spends the token on one Credential Request naming the identifier the member
    /// grants, alone. The library's Authorization Server writes the name without an escape, so the response
    /// is delivered through the wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-8.3">RFC 8259 Section 8.3</see>:
    /// "Implementations that transform the textual representation into sequences of Unicode code units and
    /// then perform the comparison numerically, code unit by code unit, are interoperable in the sense that
    /// implementations will agree in all cases on equality or inequality of two strings."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-6.2">OID4VCI 1.0 Section 6.2</see>:
    /// "The Wallet MUST use these identifiers together with an Access Token in subsequent Credential
    /// Requests."
    /// </summary>
    /// <param name="memberName">The member's name as the Token Response spells it, between its quotation marks.</param>
    [TestMethod]
    [DataRow("authorization\\u005fdetails")]
    [DataRow("\\u0061uthorization_details")]
    public async Task AnAuthorizationDetailsNameSpelledWithAnEscapeIsReadAsTheMember(string memberName)
    {
        GrantedDetailsIssuance issuance = await IssueOverTokenResponseAsync(
            "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"" + memberName + "\":"
            + "[{\"type\":\"openid_credential\",\"credential_configuration_id\":\"" + ConfigurationId + "\","
            + "\"credential_identifiers\":[\"pid-dataset-1\"]}]}").ConfigureAwait(false);

        Assert.IsTrue(issuance.Outcome.IsSuccess, "The grant under an escaped member name must be spent.");
        Assert.HasCount(1, issuance.CredentialRequestBodies, "Exactly one Credential Request must be sent.");
        byte[] credentialRequest = Encoding.UTF8.GetBytes(issuance.CredentialRequestBodies[0]);
        Assert.AreEqual("pid-dataset-1", JwkJsonReader.ExtractStringValue(credentialRequest, "credential_identifier"u8));
        Assert.IsFalse(JwkJsonReader.ContainsKey(credentialRequest, "credential_configuration_id"u8),
            "The Credential Request must not name a credential_configuration_id beside the identifier.");
    }


    /// <summary>
    /// An <c>openid_credential</c> entry whose <c>type</c> member is spelled with an escape, in its name or in
    /// its value, is read as an entry of that type: the wallet spends the token on one Credential Request
    /// naming the identifier the entry grants, alone. A pin: the entries are read by the reader that compares
    /// every name and every string as the text it spells. The library's Authorization Server writes the
    /// entry without an escape, so the response is delivered through the wallet's transport delegate.
    /// <see href="https://www.rfc-editor.org/rfc/rfc8259#section-7">RFC 8259 Section 7</see>: "Any character
    /// may be escaped."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9396#section-2">RFC 9396 Section 2</see>:
    /// "type: An identifier for the authorization details type as a string. The value of the type field
    /// determines the allowable contents of the object that contains it. The value is unique for the
    /// described API in the context of the AS. This field is REQUIRED."
    /// </summary>
    /// <param name="typeMember">The entry's <c>type</c> member, its name and its value, as the Token Response spells it.</param>
    [TestMethod]
    [DataRow("\"t\\u0079pe\":\"openid_credential\"")]
    [DataRow("\"type\":\"openid\\u005fcredential\"")]
    public async Task AnEntryTypeSpelledWithAnEscapeIsReadAsItsType(string typeMember)
    {
        GrantedDetailsIssuance issuance = await IssueOverGrantedDetailsAsync(
            "[{" + typeMember + ",\"credential_configuration_id\":\"" + ConfigurationId + "\","
            + "\"credential_identifiers\":[\"pid-dataset-1\"]}]").ConfigureAwait(false);

        Assert.IsTrue(issuance.Outcome.IsSuccess, "The grant of an entry whose type is escaped must be spent.");
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
            ValidateDpopProofDelegate validateProof = host.CurrentDpopProofValidation(candidateIntegration);
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
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-2">RFC 9449 Section 2</see>: "DPoP is not, however, a
    /// substitute for a secure transport and MUST always be used in conjunction with HTTPS." A wallet wired with a
    /// DPoP key under the secure default outbound policy, holding a DPoP-bound access token, is asked for a
    /// Credential at an Issuer whose Nonce and Credential Endpoint URLs are <c>http</c>: it dials neither, so no
    /// proof leaves the wallet outside HTTPS, and the request answers the outbound policy's refusal.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletNeverSendsAProofToAResourceOutsideHttpsAsync()
    {
        List<Uri> dialed = [];
        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendJsonPost: (endpoint, _, _, _, _) =>
            {
                dialed.Add(endpoint);

                return ValueTask.FromResult(JsonResponse(400, "{\"error\":\"invalid_request\"}"));
            },
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256));

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await walletClient.IssueWithAccessTokenDetailedAsync(
            "access-token",
            WellKnownAuthenticationSchemes.DPoP,
            accessTokenExpiresAt: null,
            new Uri("https://issuer.example.com"),
            CredentialRequestTarget.ForConfiguration(ConfigurationId),
            holderPrivate,
            holderPublic,
            new Oid4VciIssuanceEndpoints
            {
                TokenEndpoint = new Uri("http://issuer.example.com/token"),
                NonceEndpoint = new Uri("http://issuer.example.com/nonce"),
                CredentialEndpoint = new Uri("http://issuer.example.com/credential")
            },
            responseEncryption: null,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(dialed, "No request, and so no DPoP proof, is sent to an http endpoint.");
        Assert.IsFalse(outcome.IsSuccess, "The request is refused before any dial.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, <c>jti</c>: "The
    /// value MUST be assigned such that there is a negligible probability that the same value will be assigned to any
    /// other DPoP proof used in the same context during the time window of validity." A wallet wired with a DPoP key
    /// and the library's identifier generator drives a Pre-Authorized Code issuance over the wire against an Issuer
    /// that challenges its first Token Request for a nonce: every proof the Issuer receives carries a <c>jti</c> the
    /// generator handed out for that proof, no two of the proofs carry the same one, and the Credential is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletAssignsEveryProofItsOwnGeneratedJtiAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        List<(string HttpUrl, string Proof)> receivedProofs = await host.RecordReceivedDpopProofsAsync().ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        List<string> generated = [];
        GenerateIdentifierDelegate defaultGenerator = DpopJtiGenerator;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            generateIdentifierAsync: async (purpose, context, ct) =>
            {
                string identifier = await defaultGenerator(purpose, context, ct).ConfigureAwait(false);
                generated.Add(identifier);

                return identifier;
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, "The issuance succeeds over the wire.");
        Assert.IsGreaterThanOrEqualTo(3, receivedProofs.Count, "The Issuer received the challenged Token Request's proof, its retry's and the Credential Request's.");
        List<string?> jtis = [.. receivedProofs.Select(received => DpopWireReading.ReadPayloadClaim(received.Proof, "jti", Pool))];
        Assert.HasCount(receivedProofs.Count, jtis.Distinct(StringComparer.Ordinal), $"No two proofs carry the same jti: {string.Join(" ", jtis)}");
        foreach(string? jti in jtis)
        {
            Assert.Contains(jti, generated, "Each jti is a value the identifier generator handed out.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>, of the <c>DPoP</c>
    /// challenge: "Additional authentication parameters MAY be used, and unknown parameters MUST be ignored by
    /// recipients." The Credential Endpoint answers the wallet's first Credential Request with its 401 nonce
    /// challenge, to which an auth-param the wallet does not know is added after the challenge crossed the wire.
    /// The wallet ignores it: it reads the challenge's <c>use_dpop_nonce</c>, retries exactly once with the nonce the
    /// <c>DPoP-Nonce</c> field supplied, and the Credential is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletAnswersANonceChallengeCarryingAnUnknownParameterAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        List<string> credentialProofs = await ArrangeCredentialEndpointNonceChallengeAsync(host, material).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        int rewrittenChallenges = 0;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            rewriteResourceAnswer: answer =>
            {
                if(answer.StatusCode != 401 || !answer.Headers.Headers.TryGetValue(WellKnownHttpHeaderNames.WwwAuthenticate, out string? challenge))
                {
                    return answer;
                }

                rewrittenChallenges++;

                return WithChallenge(answer, challenge + ", x_unrecognized=\"an extension parameter\"");
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.AreEqual(1, rewrittenChallenges, "The Credential Endpoint's nonce challenge carried the unknown parameter.");
        Assert.IsTrue(outcome.IsSuccess,
            $"The wallet answers the nonce challenge whatever unknown parameter it carries; got {(outcome.IsSuccess ? string.Empty : outcome.Error.Kind + " " + outcome.Error.StatusCode + " " + outcome.Error.ErrorCode)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>, of the <c>DPoP</c>
    /// challenge: "Additional authentication parameters MAY be used, and unknown parameters MUST be ignored by
    /// recipients." The Credential Endpoint's 401 answer to the wallet's first Credential Request is rewritten after
    /// it crossed the wire into a challenge whose <c>error</c> is <c>invalid_token</c> and which carries an auth-param
    /// the wallet does not know whose value is the text <c>use_dpop_nonce</c>, the <c>DPoP-Nonce</c> field kept. A
    /// wallet that ignores the unknown parameter reads an <c>invalid_token</c> refusal, sends no retry, and answers the
    /// 401 error response.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletDoesNotReadAnUnknownParameterAsANonceChallengeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        List<string> credentialProofs = await ArrangeCredentialEndpointNonceChallengeAsync(host, material).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            rewriteResourceAnswer: answer => answer.StatusCode == 401
                ? WithChallenge(answer, $"DPoP error=\"invalid_token\", x_unrecognized=\"use_dpop_nonce\", algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"")
                : answer);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "An invalid_token refusal is no nonce challenge, whatever an unknown parameter's value reads.");
        Assert.AreEqual(401, outcome.Error.StatusCode);
        Assert.HasCount(1, credentialProofs, "The wallet sends no retry for an invalid_token refusal.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>: "Authentication
    /// parameters are name/value pairs, where the name token is matched case-insensitively". The Credential
    /// Endpoint's 401 nonce challenge is rewritten after it crossed the wire so that its parameter names are spelled
    /// <c>ERROR</c> and <c>ALGS</c>, the <c>DPoP-Nonce</c> field kept. The wallet reads <c>ERROR</c> as the
    /// <c>error</c> parameter: it retries exactly once with the supplied nonce and the Credential is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletMatchesTheChallengeErrorParameterNameCaseInsensitivelyAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        List<string> credentialProofs = await ArrangeCredentialEndpointNonceChallengeAsync(host, material).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            rewriteResourceAnswer: answer => answer.StatusCode == 401
                ? WithChallenge(answer, $"DPoP ERROR=\"use_dpop_nonce\", ALGS=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"")
                : answer);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess,
            $"The wallet reads ERROR as the challenge's error parameter; got {(outcome.IsSuccess ? string.Empty : outcome.Error.Kind + " " + outcome.Error.StatusCode + " " + outcome.Error.ErrorCode)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>: "Parameter values
    /// can be expressed either as "token" or as "quoted-string" (Section 5.6). Authentication scheme definitions need
    /// to accept both notations, both for senders and recipients". The Credential Endpoint's 401 nonce challenge is
    /// rewritten after it crossed the wire so that its <c>error</c> value is the token <c>use_dpop_nonce</c>, not a
    /// quoted-string, the <c>DPoP-Nonce</c> field kept. The wallet reads the challenge: it retries exactly once with
    /// the supplied nonce and the Credential is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletReadsTheChallengeErrorValueWrittenAsATokenAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        List<string> credentialProofs = await ArrangeCredentialEndpointNonceChallengeAsync(host, material).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            rewriteResourceAnswer: answer => answer.StatusCode == 401
                ? WithChallenge(answer, $"DPoP error=use_dpop_nonce, algs=\"{ResourceDpopProofs.AcceptedProofAlgorithms}\"")
                : answer);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess,
            $"The wallet reads the token use_dpop_nonce as the challenge's error; got {(outcome.IsSuccess ? string.Empty : outcome.Error.Kind + " " + outcome.Error.StatusCode + " " + outcome.Error.ErrorCode)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OpenID4VCI
    /// 1.0 Section 8.3.1.2</see>, the Credential Error Response: "the HTTP response MUST use the HTTP status code 400 (Bad
    /// Request) and set the content type to application/json with the following parameters in the JSON-encoded response
    /// body: error: REQUIRED." The code that body carries is its <c>error</c> member alone; the code <c>use_dpop_nonce</c>
    /// is the one <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see> names ("using
    /// use_dpop_nonce as the error code value"). That a Credential Endpoint signals a nonce in this 400 form, beside the
    /// 401 form <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see> gives a resource
    /// server, is the library's own rule. The Credential Endpoint's 401 answer to the wallet's first Credential Request
    /// is rewritten after it crossed the wire into a 400 error response whose <c>error</c> is
    /// <c>invalid_credential_request</c> and whose <c>error_description</c> is the text <c>use_dpop_nonce</c>, the
    /// <c>DPoP-Nonce</c> field kept. The error code is <c>invalid_credential_request</c>: the wallet sends no retry and
    /// answers the 400 error response with that code.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletDoesNotReadAnErrorDescriptionAsACredentialEndpointNonceChallengeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        List<string> credentialProofs = await ArrangeCredentialEndpointNonceChallengeAsync(host, material).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            rewriteResourceAnswer: answer => answer.StatusCode == 401
                ? AsErrorResponse(answer, "{\"error\":\"invalid_credential_request\",\"error_description\":\"use_dpop_nonce\"}")
                : answer);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "An error response whose error is not use_dpop_nonce is no nonce challenge, whatever its description reads.");
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(Oid4VciCredentialErrors.InvalidCredentialRequest, outcome.Error.ErrorCode);
        Assert.HasCount(1, credentialProofs, "The wallet sends no retry for an invalid_credential_request refusal.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-8.3.1.2">OpenID4VCI
    /// 1.0 Section 8.3.1.2</see>, the Credential Error Response: "the HTTP response MUST use the HTTP status code 400 (Bad
    /// Request) and set the content type to application/json with the following parameters in the JSON-encoded response
    /// body: error: REQUIRED." When that <c>error</c> member is the code
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see> names, "The client will
    /// typically retry the request with the new nonce value supplied upon receiving a use_dpop_nonce error with an
    /// accompanying nonce value." Reading a Credential Endpoint's 400 form as a nonce challenge, beside the 401 form
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see> gives a resource server, is
    /// the library's own rule. The Credential Endpoint's 401 nonce challenge is rewritten after it crossed the wire into
    /// that 400 form, its <c>error</c> member <c>use_dpop_nonce</c>, the <c>DPoP-Nonce</c> field kept. The wallet reads
    /// the error code: it retries exactly once with the supplied nonce and the Credential is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletRetriesACredentialEndpointNonceChallengeInTheErrorResponseFormAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        List<string> credentialProofs = await ArrangeCredentialEndpointNonceChallengeAsync(host, material).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            rewriteResourceAnswer: answer => answer.StatusCode == 401
                ? AsErrorResponse(answer, "{\"error\":\"use_dpop_nonce\",\"error_description\":\"Resource server requires nonce in DPoP proof\"}")
                : answer);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess,
            $"The wallet answers the use_dpop_nonce error response; got {(outcome.IsSuccess ? string.Empty : outcome.Error.Kind + " " + outcome.Error.StatusCode + " " + outcome.Error.ErrorCode)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: the nonce challenge is
    /// "an HTTP 400 (Bad Request) error response per Section 5.2 of [RFC6749] using use_dpop_nonce as the error code
    /// value." The Token Endpoint's 400 nonce challenge to the wallet's first Token Request is rewritten after it
    /// crossed the wire into an error response whose <c>error</c> is <c>invalid_grant</c> and whose
    /// <c>error_description</c> is the text <c>use_dpop_nonce</c>, the <c>DPoP-Nonce</c> field kept. The error code is
    /// <c>invalid_grant</c>: the wallet sends no second Token Request and answers the 400 error response with that
    /// code.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletDoesNotReadAnErrorDescriptionAsATokenEndpointNonceChallengeAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        int tokenAnswers = 0;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            rewriteTokenAnswer: answer =>
            {
                tokenAnswers++;

                return answer.StatusCode == 400
                    ? answer with { Body = "{\"error\":\"invalid_grant\",\"error_description\":\"use_dpop_nonce\"}" }
                    : answer;
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "An error response whose error is not use_dpop_nonce is no nonce challenge, whatever its description reads.");
        Assert.AreEqual(400, outcome.Error.StatusCode);
        Assert.AreEqual(OAuthErrors.InvalidGrant, outcome.Error.ErrorCode);
        Assert.AreEqual(1, tokenAnswers, "The wallet sends no second Token Request for an invalid_grant refusal.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.1">RFC 9449 Section 7.1</see>: "This authentication
    /// scheme is for origin-server authentication only. Therefore, this authentication scheme MUST NOT be used with
    /// the Proxy-Authenticate or Proxy-Authorization header fields." A wallet wired with a DPoP key drives a
    /// Pre-Authorized Code issuance over the wire: every resource request it sends with a <c>DPoP</c> field carries
    /// its access token in <c>Authorization: DPoP</c>, none carries a <c>Proxy-Authorization</c> field, and the
    /// Credential is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletPresentsItsAccessTokenUnderAuthorizationNeverProxyAuthorizationAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        List<OutgoingHeaders> dpopRequests = [];
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            observeResourceRequest: (_, headers) =>
            {
                if(headers.Values.ContainsKey(WellKnownHttpHeaderNames.DPoP))
                {
                    dpopRequests.Add(headers);
                }
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, "The issuance succeeds over the wire.");
        Assert.IsNotEmpty(dpopRequests, "The wallet sent its Credential Request with a DPoP proof.");
        foreach(OutgoingHeaders headers in dpopRequests)
        {
            Assert.IsTrue(headers.Values.TryGetValue(WellKnownHttpHeaderNames.Authorization, out string? authorization),
                "The access token rides the Authorization field.");
            Assert.StartsWith("DPoP ", authorization);
            Assert.IsFalse(headers.Values.ContainsKey("Proxy-Authorization"), "No Proxy-Authorization field is sent.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-7.3">RFC 9449 Section 7.3</see>: "It is RECOMMENDED
    /// that clients generate a unique DPoP proof, even when retrying idempotent requests in response to HTTP errors
    /// generally understood as transient." A wallet wired with a DPoP key drives a Pre-Authorized Code issuance over
    /// the wire, and the Credential Endpoint's first answer to its Credential Request, a POST and so no idempotent
    /// request (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-9.2.2">RFC 9110 Section 9.2.2</see>), is
    /// rewritten after it crossed the wire into 503 (Service
    /// Unavailable), an error generally understood as transient: the wallet answers that error to the application.
    /// The application asks again with the access token the first Credential Request presented, through
    /// <see cref="Oid4VciWalletClient.IssueWithAccessTokenDetailedAsync"/>: every proof the Credential Endpoint
    /// received carries a <c>jti</c> of its own, and the Credential is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletSendsAFreshProofWhenTheApplicationRetriesAfterATransientErrorAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);
        List<(string HttpUrl, string Proof)> receivedProofs = await host.RecordReceivedDpopProofsAsync().ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        Oid4VciIssuanceEndpoints endpoints = ResolveEndpoints(host, material);
        Uri? lastResourceEndpoint = null;
        string? presentedAccessToken = null;
        bool isTransientErrorAnswered = false;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            observeResourceRequest: (endpoint, headers) =>
            {
                lastResourceEndpoint = endpoint;
                if(endpoint == endpoints.CredentialEndpoint
                    && headers.Values.TryGetValue(WellKnownHttpHeaderNames.Authorization, out string? authorization))
                {
                    presentedAccessToken = authorization[(WellKnownAuthenticationSchemes.DPoP.Length + 1)..];
                }
            },
            rewriteResourceAnswer: answer =>
            {
                if(isTransientErrorAnswered || lastResourceEndpoint != endpoints.CredentialEndpoint)
                {
                    return answer;
                }

                isTransientErrorAnswered = true;

                return answer with { StatusCode = 503, Body = string.Empty, Headers = ResponseHeaders.Empty };
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> first = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);
        Assert.IsFalse(first.IsSuccess, "The Credential Endpoint's first answer is the transient error.");
        Assert.AreEqual(503, first.Error.StatusCode);
        Assert.IsNotNull(presentedAccessToken, "The first Credential Request presented a DPoP-bound access token.");

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> second = await walletClient.IssueWithAccessTokenDetailedAsync(
            presentedAccessToken,
            WellKnownAuthenticationSchemes.DPoP,
            accessTokenExpiresAt: null,
            material.Registration.IssuerUri!,
            CredentialRequestTarget.ForConfiguration(ConfigurationId),
            holderPrivate,
            holderPublic,
            endpoints,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);

        string credentialPath = TestHostShell.ComposeEndpointPath(
            WellKnownEndpointNames.Oid4VciCredential, material.Registration.TenantId.Value);
        List<string?> credentialJtis = [.. receivedProofs
            .Where(received => received.HttpUrl.EndsWith(credentialPath, StringComparison.Ordinal))
            .Select(received => DpopWireReading.ReadPayloadClaim(received.Proof, "jti", Pool))];
        Assert.IsGreaterThanOrEqualTo(2, credentialJtis.Count, "The Credential Endpoint received the request answered 503 and the application's retry.");
        Assert.HasCount(credentialJtis.Count, credentialJtis.Distinct(StringComparer.Ordinal),
            $"Every proof the Credential Endpoint received carries a jti of its own: {string.Join(" ", credentialJtis)}");
        Assert.IsTrue(second.IsSuccess, $"The application's retry is answered with the Credential; got {DescribeOutcome(second)}.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-4.2">RFC 9449 Section 4.2</see>, <c>ath</c>: "Hash of
    /// the access token. The value MUST be the result of a base64url encoding (as defined in Section 2 of [RFC7515])
    /// the SHA-256 [SHS] hash of the ASCII encoding of the associated access token's value." A wallet wired with a DPoP
    /// key drives a Pre-Authorized Code issuance over the wire: every proof the Credential Endpoint receives carries an
    /// <c>ath</c> equal to the base64url, without padding, of the SHA-256 of the ASCII bytes of the access token the
    /// request presented in its <c>Authorization</c> field, computed here from that definition, and the Credential is
    /// issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletBindsEveryResourceProofToTheAccessTokenItPresentsAsync()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        List<string> credentialProofs = await ArrangeCredentialEndpointNonceChallengeAsync(host, material).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        Oid4VciIssuanceEndpoints endpoints = ResolveEndpoints(host, material);
        List<string> presentedAccessTokens = [];
        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            observeResourceRequest: (endpoint, headers) =>
            {
                if(endpoint == endpoints.CredentialEndpoint
                    && headers.Values.TryGetValue(WellKnownHttpHeaderNames.Authorization, out string? authorization))
                {
                    presentedAccessTokens.Add(authorization[(WellKnownAuthenticationSchemes.DPoP.Length + 1)..]);
                }
            });

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, $"The issuance succeeds over the wire; got {DescribeOutcome(outcome)}.");
        Assert.HasCount(credentialProofs.Count, presentedAccessTokens, "Every Credential Request the endpoint received presented its access token.");
        Assert.IsNotEmpty(credentialProofs, "The Credential Endpoint received the wallet's proofs.");
        for(int request = 0; request < credentialProofs.Count; request++)
        {
            string expectedAth = await ResourceDpopProofs.ComputeAthAsync(presentedAccessTokens[request], TestContext.CancellationToken).ConfigureAwait(false);
            Assert.AreEqual(expectedAth, DpopWireReading.ReadPayloadClaim(credentialProofs[request], "ath", Pool),
                $"The ath of Credential Request {request} hashes the access token it presented.");
        }
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">RFC 9110 Section 11.6.1</see>:
    /// "WWW-Authenticate = #challenge" and "User agents are advised to take special care in parsing the field value, as
    /// it might contain more than one challenge, and each challenge can contain a comma-separated list of authentication
    /// parameters. Furthermore, the header field itself can occur multiple times." The Credential Endpoint's 401 nonce
    /// challenge is rewritten after it crossed the wire into a challenge list holding a <c>Bearer</c> challenge beside
    /// the <c>DPoP</c> nonce challenge, the <c>DPoP-Nonce</c> field kept. The wallet finds the <c>DPoP</c> challenge
    /// wherever the list places it: it retries exactly once with the supplied nonce and the Credential is issued. The
    /// rows: Bearer then DPoP on one field line; DPoP then Bearer on one field line; Bearer and DPoP on two field lines
    /// in each order; and a Bearer <c>realm</c> holding a comma inside its quoted-string before the DPoP challenge.
    /// </summary>
    /// <param name="row">How the challenge list places the DPoP challenge.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(BearerThenDpopRow)]
    [DataRow(DpopThenBearerRow)]
    [DataRow(BearerLineThenDpopLineRow)]
    [DataRow(DpopLineThenBearerLineRow)]
    [DataRow(CommaInsideQuotedStringRow)]
    public async Task WalletFindsTheDpopNonceChallengeAnywhereInTheChallengeListAsync(string row)
    {
        string[] challengeLines = row switch
        {
            BearerThenDpopRow => [$"Bearer realm=\"x\", {DpopNonceChallenge}"],
            DpopThenBearerRow => [$"{DpopNonceChallenge}, Bearer realm=\"x\""],
            BearerLineThenDpopLineRow => ["Bearer realm=\"x\"", DpopNonceChallenge],
            DpopLineThenBearerLineRow => [DpopNonceChallenge, "Bearer realm=\"x\""],
            CommaInsideQuotedStringRow => [$"Bearer realm=\"a, b\", {DpopNonceChallenge}"],
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown challenge list row.")
        };

        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(answer, challengeLines)).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, $"The wallet answers the DPoP nonce challenge the list holds; got {DescribeOutcome(outcome)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.2">RFC 9110 Section 5.6.1.2</see>: "A recipient
    /// MUST parse and ignore a reasonable number of empty list elements", the <c>#challenge</c> list of
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">Section 11.6.1</see> included. The Credential
    /// Endpoint's 401 nonce challenge is rewritten after it crossed the wire so that an empty list element precedes the
    /// <c>DPoP</c> challenge (<c>, DPoP error="use_dpop_nonce", algs="ES256"</c>), the <c>DPoP-Nonce</c> field kept.
    /// The wallet ignores the empty element: it retries exactly once with the supplied nonce and the Credential is
    /// issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletIgnoresAnEmptyElementOfTheChallengeListAsync()
    {
        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(answer, $", {DpopNonceChallenge}")).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, $"The wallet answers the DPoP nonce challenge after the empty element; got {DescribeOutcome(outcome)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.3">RFC 9110 Section 5.3</see>: "A recipient MAY
    /// combine multiple field lines within a field section that have the same field name into one field line, without
    /// changing the semantics of the message, by appending each subsequent field line value to the initial field line
    /// value in order, separated by a comma (",") and optional whitespace". <c>WWW-Authenticate</c> is a list-based
    /// field (<see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.6.1">Section 11.6.1</see>, "WWW-Authenticate =
    /// #challenge"), so its field lines are one field value and the auth-params of a challenge may continue on the next
    /// field line. The Credential Endpoint's 401 nonce challenge is rewritten after it crossed the wire into the rows'
    /// field lines, the <c>DPoP-Nonce</c> field kept: the wallet reads the one <c>DPoP</c> challenge of the combined
    /// value, retries exactly once with the supplied nonce and the Credential is issued. The rows:
    /// <c>DPoP error="use_dpop_nonce"</c> on one field line and <c>algs="ES256"</c> on the next;
    /// <c>DPoP algs="ES256"</c> on one field line and <c>error="use_dpop_nonce"</c> on the next; and the combined value
    /// <c>DPoP error="use_dpop_nonce", algs="ES256"</c> on one field line, which the two-line rows are equivalent to.
    /// </summary>
    /// <param name="row">How the challenge is spread over the field lines.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(AlgsOnTheNextFieldLineRow)]
    [DataRow(ErrorOnTheNextFieldLineRow)]
    [DataRow(CombinedOnOneFieldLineRow)]
    public async Task WalletReadsTheFieldLinesOfTheChallengeFieldAsOneValueAsync(string row)
    {
        string[] challengeLines = row switch
        {
            AlgsOnTheNextFieldLineRow => ["DPoP error=\"use_dpop_nonce\"", "algs=\"ES256\""],
            ErrorOnTheNextFieldLineRow => ["DPoP algs=\"ES256\"", "error=\"use_dpop_nonce\""],
            CombinedOnOneFieldLineRow => [DpopNonceChallenge],
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown field line row.")
        };

        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(answer, challengeLines)).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, $"The wallet answers the DPoP nonce challenge the combined field value holds; got {DescribeOutcome(outcome)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.2">RFC 9110 Section 5.6.1.2</see>: "a recipient
    /// MUST accept lists that satisfy the following syntax: #element => [ element ] *( OWS "," OWS [ element ] )", with
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.3">Section 5.6.3</see> "OWS = *( SP / HTAB )". In
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">Section 11.3</see>, "challenge = auth-scheme [
    /// 1*SP ( token68 / #auth-param ) ]", the content of a challenge is optional and only SP opens it, so a horizontal
    /// tab after a scheme and before a comma is the list's whitespace and the challenge ends at the scheme. The
    /// Credential Endpoint's 401 nonce challenge is rewritten after it crossed the wire into
    /// <c>Basic</c>, a horizontal tab, then <c>, DPoP error="use_dpop_nonce", algs="ES256"</c>, the <c>DPoP-Nonce</c>
    /// field kept: the value holds a <c>Basic</c> challenge with no content and the <c>DPoP</c> nonce challenge, the
    /// wallet retries exactly once with the supplied nonce and the Credential is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletReadsWhitespaceBeforeAListCommaAsTheEndOfAChallengeAsync()
    {
        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(answer, $"Basic\t, {DpopNonceChallenge}")).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, $"The wallet answers the DPoP nonce challenge after the Basic challenge; got {DescribeOutcome(outcome)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">RFC 9110 Section 11.3</see>: "challenge =
    /// auth-scheme [ 1*SP ( token68 / #auth-param ) ]", and
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.2">Section 5.6.1.2</see>: "Empty elements do not
    /// contribute to the count of elements present. A recipient MUST parse and ignore a reasonable number of empty list
    /// elements", so the <c>#auth-param</c> list after the scheme's SP may open with an empty element. The Credential
    /// Endpoint's 401 nonce challenge is rewritten after it crossed the wire into
    /// <c>DPoP , error="use_dpop_nonce", algs="ES256"</c>, the <c>DPoP-Nonce</c> field kept: the value is one
    /// <c>DPoP</c> challenge whose auth-params follow an empty element, the wallet retries exactly once with the supplied
    /// nonce and the Credential is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletSkipsAnEmptyElementBeforeTheFirstAuthParamAsync()
    {
        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(
                answer, "DPoP , error=\"use_dpop_nonce\", algs=\"ES256\"")).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, $"The wallet reads the auth-params after the empty element as the DPoP challenge's; got {DescribeOutcome(outcome)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.1.2">RFC 9110 Section 5.6.1.2</see>: "A recipient
    /// MUST parse and ignore a reasonable number of empty list elements", a recipient accepting "#element => [ element ]
    /// *( OWS "," OWS [ element ] )", and the content of a challenge is such a list,
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">Section 11.3</see>: "challenge = auth-scheme [
    /// 1*SP ( token68 / #auth-param ) ]", so an empty element may stand between two auth-params of one challenge. The
    /// Credential Endpoint's 401 nonce challenge is rewritten after it crossed the wire into the row's value, the
    /// <c>DPoP-Nonce</c> field kept: the value is one <c>DPoP</c> challenge whose <c>error</c> and <c>algs</c>
    /// auth-params have an empty element between them, the wallet retries exactly once with the supplied nonce and the
    /// Credential is issued. The rows: <c>DPoP error="use_dpop_nonce",, algs="ES256"</c> and
    /// <c>DPoP error="use_dpop_nonce", , algs="ES256"</c>.
    /// </summary>
    /// <param name="row">How the empty element between the two auth-params is written.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(EmptyElementWithoutWhitespaceRow)]
    [DataRow(EmptyElementHoldingASpaceRow)]
    public async Task WalletSkipsAnEmptyElementBetweenTwoAuthParamsAsync(string row)
    {
        string challenge = row switch
        {
            EmptyElementWithoutWhitespaceRow => "DPoP error=\"use_dpop_nonce\",, algs=\"ES256\"",
            EmptyElementHoldingASpaceRow => "DPoP error=\"use_dpop_nonce\", , algs=\"ES256\"",
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown empty element row.")
        };

        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(answer, challenge)).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, $"The wallet reads the auth-params on both sides of the empty element as the DPoP challenge's; got {DescribeOutcome(outcome)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.5">RFC 9110 Section 11.5</see>: "Note that a
    /// response can have multiple challenges with the same auth-scheme but with different realms." Which of two
    /// <c>DPoP</c> challenges carries the answer's nonce error is not stated by either, so the library's own rule reads
    /// two <c>DPoP</c> challenges as no nonce challenge. The Credential Endpoint's 401 answer is rewritten after it
    /// crossed the wire into two <c>DPoP</c> challenges, the first carrying <c>error="use_dpop_nonce"</c> and the second
    /// <c>error="invalid_token"</c>, the <c>DPoP-Nonce</c> field kept: the wallet sends no retry and answers the 401
    /// error response.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletDoesNotReadTwoDpopChallengesAsANonceChallengeAsync()
    {
        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(
                answer, $"{DpopNonceChallenge}, DPoP error=\"invalid_token\", algs=\"ES256\"")).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "Two DPoP challenges are no nonce challenge.");
        Assert.HasCount(1, credentialProofs, "The wallet sends no retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.3">RFC 9110 Section 11.3</see>: "challenge =
    /// auth-scheme [ 1*SP ( token68 / #auth-param ) ]": the scheme is a token, and a space separates it from what
    /// follows. The Credential Endpoint's 401 answer is rewritten after it crossed the wire into a value whose scheme is
    /// not followed by a space, the <c>DPoP-Nonce</c> field kept: no <c>DPoP</c> challenge is read, the wallet sends no
    /// retry and answers the 401 error response. The rows: <c>DPoPerror="use_dpop_nonce"</c>, where the scheme and the
    /// parameter name run together into one token; and <c>DPoP</c>, a horizontal tab, then
    /// <c>error="use_dpop_nonce"</c>.
    /// </summary>
    /// <param name="row">What follows the scheme in place of the space.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(NoSeparatorAfterSchemeRow)]
    [DataRow(TabAfterSchemeRow)]
    public async Task WalletDoesNotReadASchemeWithoutItsSpaceSeparatorAsANonceChallengeAsync(string row)
    {
        string challenge = row switch
        {
            NoSeparatorAfterSchemeRow => "DPoPerror=\"use_dpop_nonce\"",
            TabAfterSchemeRow => "DPoP\terror=\"use_dpop_nonce\"",
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown separator row.")
        };

        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(answer, challenge)).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A scheme not followed by a space starts no DPoP challenge.");
        Assert.HasCount(1, credentialProofs, "The wallet sends no retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 Section 5.6.4</see>: "quoted-string =
    /// DQUOTE *( qdtext / quoted-pair ) DQUOTE" with "qdtext = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text". The
    /// Credential Endpoint's 401 answer is rewritten after it crossed the wire into a <c>DPoP</c> challenge carrying a
    /// value outside that grammar, the <c>DPoP-Nonce</c> field kept: the challenge is malformed and read as no nonce
    /// challenge, the wallet sends no retry and answers the 401 error response. The rows: an <c>error</c> value whose
    /// closing DQUOTE is missing; and an <c>error_description</c> value holding the control character U+0001 beside an
    /// <c>error</c> of <c>use_dpop_nonce</c>.
    /// </summary>
    /// <param name="row">How the quoted-string leaves its grammar.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(UnterminatedQuotedStringRow)]
    [DataRow(ControlCharacterInQuotedStringRow)]
    public async Task WalletDoesNotReadAMalformedQuotedStringAsANonceChallengeAsync(string row)
    {
        string challenge = row switch
        {
            UnterminatedQuotedStringRow => "DPoP error=\"use_dpop_nonce",
            ControlCharacterInQuotedStringRow => "DPoP error=\"use_dpop_nonce\", error_description=\"a" + (char)0x01 + "b\"",
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown quoted-string row.")
        };

        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(answer, challenge)).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A challenge holding a malformed quoted-string is no nonce challenge.");
        Assert.HasCount(1, credentialProofs, "The wallet sends no retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-11.2">RFC 9110 Section 11.2</see>: "Authentication
    /// parameters are name/value pairs, where the name token is matched case-insensitively and each parameter name MUST
    /// only occur once per challenge." The Credential Endpoint's 401 answer is rewritten after it crossed the wire into
    /// a <c>DPoP</c> challenge naming <c>error</c> twice, first <c>invalid_token</c> and then <c>use_dpop_nonce</c>, the
    /// <c>DPoP-Nonce</c> field kept: the challenge is malformed and read as no nonce challenge, the wallet sends no
    /// retry and answers the 401 error response. The rows: the second name spelled <c>error</c>; and the second name
    /// spelled <c>ERROR</c>, the same name in another case.
    /// </summary>
    /// <param name="row">How the repeated name is spelled.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow(RepeatedParameterRow)]
    [DataRow(RepeatedParameterInAnotherCaseRow)]
    public async Task WalletDoesNotReadAChallengeNamingAParameterTwiceAsANonceChallengeAsync(string row)
    {
        string challenge = row switch
        {
            RepeatedParameterRow => "DPoP error=\"invalid_token\", error=\"use_dpop_nonce\", algs=\"ES256\"",
            RepeatedParameterInAnotherCaseRow => "DPoP error=\"invalid_token\", ERROR=\"use_dpop_nonce\", algs=\"ES256\"",
            _ => throw new ArgumentOutOfRangeException(nameof(row), row, "Unknown repeated parameter row.")
        };

        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(answer, challenge)).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A challenge naming a parameter twice is no nonce challenge.");
        Assert.HasCount(1, credentialProofs, "The wallet sends no retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 Section 5.6.4</see>: "Recipients that
    /// process the value of a quoted-string MUST handle a quoted-pair as if it were replaced by the octet following the
    /// backslash." The Credential Endpoint's 401 nonce challenge is rewritten after it crossed the wire so that its
    /// <c>error</c> value is <c>"use\_dpop_nonce"</c>, the underscore written as a quoted-pair, the <c>DPoP-Nonce</c>
    /// field kept. The value is <c>use_dpop_nonce</c>: the wallet retries exactly once with the supplied nonce and the
    /// Credential is issued.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletReadsAQuotedPairAsTheOctetItQuotesAsync()
    {
        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(
                answer, "DPoP error=\"use\\_dpop_nonce\", algs=\"ES256\"")).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, $"The quoted-pair stands for the octet it quotes; got {DescribeOutcome(outcome)}.");
        Assert.HasCount(2, credentialProofs, "The challenged Credential Request and its one retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9110#section-5.6.4">RFC 9110 Section 5.6.4</see>: "Recipients that
    /// process the value of a quoted-string MUST handle a quoted-pair as if it were replaced by the octet following the
    /// backslash." The Credential Endpoint's 401 answer is rewritten after it crossed the wire into a <c>DPoP</c>
    /// challenge whose <c>error</c> value is <c>"use\"_dpop_nonce"</c>, the <c>DPoP-Nonce</c> field kept. The value is
    /// <c>use"_dpop_nonce</c>, the quoted DQUOTE kept in it, which is not <c>use_dpop_nonce</c>: the wallet sends no
    /// retry and answers the 401 error response.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletKeepsTheOctetAQuotedPairQuotesInTheValueAsync()
    {
        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(
                answer, "DPoP error=\"use\\\"_dpop_nonce\", algs=\"ES256\"")).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "The value carries the quoted DQUOTE and is no use_dpop_nonce.");
        Assert.HasCount(1, credentialProofs, "The wallet sends no retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">RFC 9449 Section 9</see>: "Resource servers use an
    /// HTTP 401 (Unauthorized) error code with an accompanying WWW-Authenticate: DPoP value and DPoP-Nonce value to
    /// accomplish this." The Credential Endpoint's 401 answer is rewritten after it crossed the wire into the challenge
    /// <c>Bearer error="use_dpop_nonce"</c>, a <c>Bearer</c> challenge and no <c>DPoP</c> one, the <c>DPoP-Nonce</c>
    /// field kept: the wallet reads no DPoP nonce challenge, sends no retry and answers the 401 error response.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletDoesNotReadABearerChallengeAsADpopNonceChallengeAsync()
    {
        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer => WithChallengeLines(
                answer, "Bearer error=\"use_dpop_nonce\"")).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A Bearer challenge is no DPoP nonce challenge.");
        Assert.HasCount(1, credentialProofs, "The wallet sends no retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8">RFC 9449 Section 8</see>: "there MUST NOT be more
    /// than one DPoP-Nonce header", which <see href="https://www.rfc-editor.org/rfc/rfc9449#section-9">Section 9</see>
    /// extends to resource servers ("They provide the nonce using the DPoP-Nonce header in the same way that
    /// authorization servers do"). The clause binds the server; the library's own rule reads an answer carrying two
    /// <c>DPoP-Nonce</c> field lines as no nonce challenge, since it names no one nonce. The Credential Endpoint's 401
    /// nonce challenge is rewritten after it crossed the wire so that it carries its nonce on two <c>DPoP-Nonce</c>
    /// field lines: the wallet sends no retry and answers the 401 error response.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletDoesNotRetryOnAChallengeCarryingTwoDpopNonceFieldsAsync()
    {
        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer =>
            {
                string nonce = answer.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)!;

                return WithNonceLines(answer, nonce, nonce);
            }).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "An answer carrying two DPoP-Nonce field lines is no nonce challenge.");
        Assert.HasCount(1, credentialProofs, "The wallet sends no retry.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.2">RFC 9449 Section 8.2</see>: "The DPoP-Nonce HTTP
    /// header field uses the nonce syntax defined in Section 8.1."
    /// <see href="https://www.rfc-editor.org/rfc/rfc9449#section-8.1">Section 8.1</see>, Figure 22: <c>nonce =
    /// 1*NQCHAR</c>. The Credential Endpoint's 401 nonce challenge is rewritten after it crossed the wire so that a
    /// space, which is no NQCHAR, stands in the middle of its <c>DPoP-Nonce</c> value: the value is no nonce, the
    /// wallet neither stores nor embeds it, sends no retry and answers the 401 error response.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task WalletDoesNotRetryOnADpopNonceOutsideTheNonceSyntaxAsync()
    {
        (Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome, List<string> credentialProofs) =
            await IssueUnderARewrittenNonceChallengeAsync(answer =>
            {
                string nonce = answer.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)!;

                return WithNonceLines(answer, nonce.Insert(nonce.Length / 2, " "));
            }).ConfigureAwait(false);

        Assert.IsFalse(outcome.IsSuccess, "A DPoP-Nonce value outside 1*NQCHAR is no nonce.");
        Assert.HasCount(1, credentialProofs, "The wallet sends no retry.");
    }


    /// <summary>The row whose single field line holds a Bearer challenge and then the DPoP nonce challenge.</summary>
    private const string BearerThenDpopRow = "bearer-then-dpop";

    /// <summary>The row whose single field line holds the DPoP nonce challenge and then a Bearer challenge.</summary>
    private const string DpopThenBearerRow = "dpop-then-bearer";

    /// <summary>The row whose first field line holds a Bearer challenge and whose second holds the DPoP nonce challenge.</summary>
    private const string BearerLineThenDpopLineRow = "bearer-line-then-dpop-line";

    /// <summary>The row whose first field line holds the DPoP nonce challenge and whose second holds a Bearer challenge.</summary>
    private const string DpopLineThenBearerLineRow = "dpop-line-then-bearer-line";

    /// <summary>The row whose Bearer challenge carries a realm holding a comma inside its quoted-string.</summary>
    private const string CommaInsideQuotedStringRow = "comma-inside-quoted-string";

    /// <summary>The row whose first field line holds the DPoP challenge's error and whose second holds its algs auth-param.</summary>
    private const string AlgsOnTheNextFieldLineRow = "algs-on-the-next-field-line";

    /// <summary>The row whose first field line holds the DPoP challenge's algs and whose second holds its error auth-param.</summary>
    private const string ErrorOnTheNextFieldLineRow = "error-on-the-next-field-line";

    /// <summary>The row whose one field line holds the combined value of the two field line rows.</summary>
    private const string CombinedOnOneFieldLineRow = "combined-on-one-field-line";

    /// <summary>The row whose scheme runs into its parameter name with no separator.</summary>
    private const string NoSeparatorAfterSchemeRow = "no-separator-after-scheme";

    /// <summary>The row whose scheme is followed by a horizontal tab.</summary>
    private const string TabAfterSchemeRow = "tab-after-scheme";

    /// <summary>The row whose error value lacks its closing DQUOTE.</summary>
    private const string UnterminatedQuotedStringRow = "unterminated-quoted-string";

    /// <summary>The row whose error_description value holds a control character.</summary>
    private const string ControlCharacterInQuotedStringRow = "control-character-in-quoted-string";

    /// <summary>The row naming the error parameter twice in one spelling.</summary>
    private const string RepeatedParameterRow = "repeated-parameter";

    /// <summary>The row naming the error parameter twice, the second time in another case.</summary>
    private const string RepeatedParameterInAnotherCaseRow = "repeated-parameter-in-another-case";

    /// <summary>The row whose two auth-params have an empty element between them written as two commas.</summary>
    private const string EmptyElementWithoutWhitespaceRow = "empty-element-without-whitespace";

    /// <summary>The row whose two auth-params have an empty element between them written as a comma, a space and a comma.</summary>
    private const string EmptyElementHoldingASpaceRow = "empty-element-holding-a-space";

    /// <summary>The DPoP nonce challenge the challenge list rows place: RFC 9449 Section 9's form with an <c>algs</c> parameter.</summary>
    private static string DpopNonceChallenge { get; } = "DPoP error=\"use_dpop_nonce\", algs=\"ES256\"";


    /// <summary>
    /// Drives the Pre-Authorized Code issuance of <see cref="ComposeOffer"/> over the host's listener against an Issuer
    /// whose Credential Endpoint answers the wallet's first Credential Request with its 401 nonce challenge
    /// (<see cref="ArrangeCredentialEndpointNonceChallengeAsync"/>), every 401 answer rewritten by
    /// <paramref name="rewriteChallenge"/> after it crossed the wire and before the wallet reads it.
    /// </summary>
    /// <param name="rewriteChallenge">The rewrite of each 401 answer of the Credential Endpoint.</param>
    /// <returns>The issuance outcome and every proof the Credential Endpoint received, in arrival order.</returns>
    private async Task<(Result<CredentialIssuanceResult, Oid4VciRequestFailure> Outcome, List<string> CredentialProofs)> IssueUnderARewrittenNonceChallengeAsync(
        Func<HttpResponseData, HttpResponseData> rewriteChallenge)
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterDpopClientAsync(
            ClientId, ClientBaseUri, PolicyProfile.Haip10, IssuerCapabilities).ConfigureAwait(false);
        _ = await host.EnableDpopAsync().ConfigureAwait(false);
        List<string> credentialProofs = await ArrangeCredentialEndpointNonceChallengeAsync(host, material).ConfigureAwait(false);
        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);
        material.Registration = host.AlignRegistrationToHostHttpBase("default", material.Registration);

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;
        var walletDpopKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory walletDpopPublic = walletDpopKeys.PublicKey;
        using PrivateKeyMemory walletDpopPrivate = walletDpopKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(
            host,
            constructDpopProofAsync: BuildWalletDpopProofAsync,
            dpopKey: new DpopKey(walletDpopKeys, WellKnownJwaValues.Es256),
            rewriteResourceAnswer: answer => answer.StatusCode == 401 ? rewriteChallenge(answer) : answer);

        Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome = await IssueOverTheWireAsync(walletClient, host, material, holderPrivate, holderPublic).ConfigureAwait(false);

        return (outcome, credentialProofs);
    }


    /// <summary>States an issuance outcome for an assertion message: the Credential, or the failure's kind, status and code.</summary>
    /// <param name="outcome">The issuance outcome.</param>
    /// <returns>The statement.</returns>
    private static string DescribeOutcome(Result<CredentialIssuanceResult, Oid4VciRequestFailure> outcome) =>
        outcome.IsSuccess ? "the Credential" : $"{outcome.Error.Kind} {outcome.Error.StatusCode} {outcome.Error.ErrorCode}";


    /// <summary>
    /// Wires the Issuer, rotates the server's DPoP nonce key when the wallet asks for its <c>c_nonce</c>, archiving
    /// the HMAC key the Token Endpoint's nonce was made under, so the nonce the wallet carries into its first Credential
    /// Request is not one the Credential Endpoint accepts and that request meets the 401 nonce challenge, and records
    /// every proof the Credential Endpoint receives. <see cref="TestHostShell.EnableDpopAsync"/> must have been called.
    /// </summary>
    /// <param name="host">The host serving the Issuer.</param>
    /// <param name="material">The wallet's registration.</param>
    /// <returns>The proofs the Credential Endpoint receives, in arrival order.</returns>
    private static async Task<List<string>> ArrangeCredentialEndpointNonceChallengeAsync(TestHostShell host, VerifierKeyMaterial material)
    {
        _ = await WireIssuerSeamsAsync(host).ConfigureAwait(false);

        string credentialPath = TestHostShell.ComposeEndpointPath(
            WellKnownEndpointNames.Oid4VciCredential, material.Registration.TenantId.Value);
        List<string> credentialProofs = [];
        bool isNonceKeyRotated = false;
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            ValidateDpopProofDelegate validateProof = host.CurrentDpopProofValidation(candidateIntegration);
            candidateIntegration.ValidateDpopProofAsync = (request, ct) =>
            {
                if(request.HttpUrl.EndsWith(credentialPath, StringComparison.Ordinal))
                {
                    credentialProofs.Add(request.Proof);
                }

                return validateProof(request, ct);
            };

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

        return credentialProofs;
    }


    /// <summary>
    /// Drives the Pre-Authorized Code issuance of <see cref="ComposeOffer"/> over the host's listener under the
    /// loopback outbound policy.
    /// </summary>
    /// <param name="walletClient">The wallet.</param>
    /// <param name="host">The host serving the Issuer.</param>
    /// <param name="material">The wallet's registration.</param>
    /// <param name="holderPrivate">The private key the wallet proves possession of for the Credential.</param>
    /// <param name="holderPublic">The public key the Credential is bound to.</param>
    /// <returns>The issuance outcome.</returns>
    private async Task<Result<CredentialIssuanceResult, Oid4VciRequestFailure>> IssueOverTheWireAsync(
        Oid4VciWalletClient walletClient,
        TestHostShell host,
        VerifierKeyMaterial material,
        PrivateKeyMemory holderPrivate,
        PublicKeyMemory holderPublic) =>
        await walletClient.IssuePreAuthorizedDetailedAsync(
            ComposeOffer(material),
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            transactionCode: null,
            responseEncryption: null,
            TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy),
            TestContext.CancellationToken).ConfigureAwait(false);


    /// <summary>The wallet's proof construction: the library's DPoP proof builder over the test serializer and P-256 signing.</summary>
    /// <param name="claims">The proof's claims.</param>
    /// <param name="key">The DPoP key that signs the proof.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The compact proof.</returns>
    private static ValueTask<string> BuildWalletDpopProofAsync(DpopProofClaims claims, DpopKey key, CancellationToken cancellationToken) =>
        DpopProofConstruction.BuildAsync(
            claims, key, TestSetup.Base64UrlEncoder, DpopTestSupport.Serializer,
            MicrosoftCryptographicFunctionsAdapter.SignP256Async, Pool, cancellationToken);


    /// <summary>Returns <paramref name="answer"/> with its <c>WWW-Authenticate</c> field set to <paramref name="challenge"/>, every other field kept.</summary>
    /// <param name="answer">The answer that crossed the wire.</param>
    /// <param name="challenge">The challenge the wallet reads instead.</param>
    /// <returns>The rewritten answer.</returns>
    private static HttpResponseData WithChallenge(HttpResponseData answer, string challenge) =>
        answer with
        {
            Headers = new ResponseHeaders { Headers = answer.Headers.Headers.With(WellKnownHttpHeaderNames.WwwAuthenticate, challenge) }
        };


    /// <summary>
    /// Returns <paramref name="answer"/> with its <c>WWW-Authenticate</c> field lines set to
    /// <paramref name="challengeLines"/>, one field line each, in order, every other field kept.
    /// </summary>
    /// <param name="answer">The answer that crossed the wire.</param>
    /// <param name="challengeLines">The field lines the wallet reads instead.</param>
    /// <returns>The rewritten answer.</returns>
    private static HttpResponseData WithChallengeLines(HttpResponseData answer, params string[] challengeLines) =>
        answer with
        {
            Headers = new ResponseHeaders { Headers = answer.Headers.Headers.WithValues(WellKnownHttpHeaderNames.WwwAuthenticate, challengeLines) }
        };


    /// <summary>
    /// Returns <paramref name="answer"/> with its <c>DPoP-Nonce</c> field lines set to <paramref name="nonceLines"/>, one
    /// field line each, in order, every other field kept.
    /// </summary>
    /// <param name="answer">The answer that crossed the wire.</param>
    /// <param name="nonceLines">The field lines the wallet reads instead.</param>
    /// <returns>The rewritten answer.</returns>
    private static HttpResponseData WithNonceLines(HttpResponseData answer, params string[] nonceLines) =>
        answer with
        {
            Headers = new ResponseHeaders { Headers = answer.Headers.Headers.WithValues(WellKnownHttpHeaderNames.DPoPNonce, nonceLines) }
        };


    /// <summary>
    /// Returns <paramref name="answer"/> as an HTTP 400 error response whose body is <paramref name="body"/> and whose
    /// one field is the <c>DPoP-Nonce</c> the answer carried, so the wallet reads the error response form of a refusal.
    /// </summary>
    /// <param name="answer">The answer that crossed the wire, carrying a <c>DPoP-Nonce</c> field.</param>
    /// <param name="body">The JSON error object the wallet reads instead.</param>
    /// <returns>The rewritten answer.</returns>
    private static HttpResponseData AsErrorResponse(HttpResponseData answer, string body) =>
        answer with
        {
            StatusCode = 400,
            Body = body,
            Headers = new ResponseHeaders
            {
                Headers = HttpHeaderSet.FromPairs((WellKnownHttpHeaderNames.DPoPNonce, answer.Headers.TryGetSingle(WellKnownHttpHeaderNames.DPoPNonce)!))
            }
        };


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
    private ValueTask<GrantedDetailsIssuance> IssueOverGrantedDetailsAsync(string authorizationDetails) =>
        IssueOverTokenResponseAsync(
            "{\"access_token\":\"tok\",\"token_type\":\"Bearer\",\"authorization_details\":" + authorizationDetails + "}");


    /// <summary>
    /// Drives a Pre-Authorized Code issuance over the in-process transport whose Token Request is answered
    /// with <paramref name="tokenResponse"/> as written, and records every Nonce and Credential Request
    /// that follows it, answered by <see cref="CredentialFlowStub"/>.
    /// </summary>
    /// <param name="tokenResponse">The whole Token Response body, as JSON text.</param>
    /// <param name="tokenStatusCode">The HTTP status the Token Request is answered with.</param>
    /// <returns>The issuance outcome and the requests that followed the Token Request.</returns>
    private async ValueTask<GrantedDetailsIssuance> IssueOverTokenResponseAsync(string tokenResponse, int tokenStatusCode = 200)
    {
        Uri tokenEndpoint = new("https://issuer.example.com/token");
        Uri nonceEndpoint = new("https://issuer.example.com/nonce");
        Uri credentialEndpoint = new("https://issuer.example.com/credential");
        List<Uri> laterRequests = [];
        List<string> credentialRequestBodies = [];
        Oid4VciJsonPostDelegate flow = CredentialFlowStub(nonceEndpoint, credentialEndpoint);

        Oid4VciWalletClient walletClient = BuildInProcessWalletClient(
            sendFormPost: (_, _, _, _, _) => ValueTask.FromResult(JsonResponse(tokenStatusCode, tokenResponse)),
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


    /// <summary>
    /// What <see cref="IssueOverTokenResponseAsync"/> observed of one issuance, which
    /// <see cref="IssueOverGrantedDetailsAsync"/> answers through it.
    /// </summary>
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

        /// <summary>How many Nonce Requests reached the nonce seam.</summary>
        public int NonceRequests { get; set; }

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
    /// <param name="rewriteTokenAnswer">
    /// The rewrite of every form-post answer (the section 6 Token Response) after it crossed the wire and
    /// before the wallet reads it, or <see langword="null"/> to hand each answer over as it arrived.
    /// </param>
    /// <param name="rewriteResourceAnswer">
    /// The rewrite of every JSON-post answer (the Nonce, Credential, Deferred and Notification responses) after it
    /// crossed the wire and before the wallet reads it, or <see langword="null"/> to hand each answer over as it
    /// arrived.
    /// </param>
    /// <param name="observeResourceRequest">
    /// Sees the endpoint and the headers of every JSON post the wallet sends, before it crosses the wire, or
    /// <see langword="null"/> to observe none.
    /// </param>
    /// <param name="generateIdentifierAsync">
    /// The identifier generator the wallet draws its proofs' <c>jti</c> values from, or <see langword="null"/>
    /// for the library's default generator when a DPoP key is given.
    /// </param>
    /// <returns>The wallet client.</returns>
    private Oid4VciWalletClient BuildWalletClient(
        TestHostShell host,
        Oid4VciDecryptResponseDelegate? decryptResponse = null,
        Oid4VciEncryptRequestDelegate? encryptRequest = null,
        OutboundTransportDelegate? fetchCredentialOffer = null,
        ConstructDpopProofDelegate? constructDpopProofAsync = null,
        DpopKey? dpopKey = null,
        string? tokenRequestAuthorizationDetails = null,
        Func<HttpResponseData, HttpResponseData>? rewriteTokenAnswer = null,
        Func<HttpResponseData, HttpResponseData>? rewriteResourceAnswer = null,
        Action<Uri, OutgoingHeaders>? observeResourceRequest = null,
        GenerateIdentifierDelegate? generateIdentifierAsync = null)
    {
        HttpClient httpClient = host.Host("default").SharedHttpClient!;

        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = async (endpoint, formFields, headers, _, ct) =>
            {
                HttpResponseData answer = await HttpClientTransport.SendFormPostAsync(
                    httpClient,
                    endpoint,
                    tokenRequestAuthorizationDetails is null
                        ? formFields
                        : new Dictionary<string, string>(formFields, StringComparer.Ordinal)
                        {
                            [OAuthRequestParameterNames.AuthorizationDetails] = tokenRequestAuthorizationDetails
                        },
                    headers,
                    ct).ConfigureAwait(false);

                return rewriteTokenAnswer is null ? answer : rewriteTokenAnswer(answer);
            },
            SendJsonPost = async (endpoint, body, headers, _, ct) =>
            {
                observeResourceRequest?.Invoke(endpoint, headers);
                HttpResponseData answer = await HttpClientTransport.SendJsonPostAsync(
                    httpClient, endpoint, body, headers, ct).ConfigureAwait(false);

                return rewriteResourceAnswer is null ? answer : rewriteResourceAnswer(answer);
            },
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
            GenerateIdentifierAsync = dpopKey is null ? null : generateIdentifierAsync ?? DpopJtiGenerator
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
                observations.NonceRequests++;
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
