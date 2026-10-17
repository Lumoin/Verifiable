using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using Verifiable.Core;
using Verifiable.Core.Outbound;
using Verifiable.OAuth.Oid4Vci;
using Verifiable.OAuth.Oid4Vci.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Wallet-side OID4VCI 1.0 §4.1.2/§4.1.3 Credential Offer acceptance: the
/// <see cref="Oid4VciWalletClient"/> resolves a §4.1 Credential Offer link — carrying the offer
/// by value (<c>credential_offer</c>) or by reference (<c>credential_offer_uri</c>) — to the
/// <see cref="CredentialOffer"/> the issuance path consumes, parsing the §4.1.1 offer object via
/// <see cref="CredentialOfferSerializer.FromJson"/> and ignoring unrecognized parameters. The
/// by-reference flow GETs the offer over real Kestrel HTTP through the wallet's transport seam.
/// </summary>
[TestClass]
internal sealed class Oid4VciWalletOfferTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://issuer.client.test";
    private static Uri ClientBaseUri { get; } = new("https://issuer.client.test");
    private static Uri OfferIssuer { get; } = new("https://credential-issuer.example.com");
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string PreAuthorizedCode = "oaKazRN8I0IbtZ0C7JuMn5";

    /// <summary>The id the credential_offer_uri carries; the offer store is keyed by it.</summary>
    private const string OfferId = "GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM";

    private static ImmutableHashSet<CapabilityIdentifier> OfferCapabilities { get; } =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.Oid4VciCredentialOfferEndpoint);


    /// <summary>
    /// §4.1.2: "Sending Credential Offer by Value Using credential_offer Parameter." A
    /// <c>openid-credential-offer://?credential_offer=&lt;url-encoded JSON&gt;</c> deep link
    /// parses back to the same <see cref="CredentialOffer"/> the serializer composed — issuer,
    /// configuration ids, and the Pre-Authorized Code grant with its <c>tx_code</c>.
    /// </summary>
    [TestMethod]
    public async Task ByValueDeepLinkParsesToTheComposedOffer()
    {
        CredentialOffer original = BuildPreAuthorizedOffer();
        string deepLink = CredentialOfferSerializer.ToByValueDeepLink(original);

        Oid4VciWalletClient walletClient = BuildWalletClient(fetchCredentialOffer: null);
        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.AcceptCredentialOfferAsync(
            deepLink, TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, "A by-value deep link parses inline and never refuses.");
        AssertOfferEquivalent(original, outcome.Value);
    }


    /// <summary>
    /// §4.1: "The Credential Offer contains a single URI query parameter, either credential_offer
    /// or credential_offer_uri" — <c>credential_offer</c> "MUST NOT be present when the
    /// credential_offer_uri parameter is present." A link carrying both is malformed and rejected.
    /// </summary>
    [TestMethod]
    public async Task LinkCarryingBothByValueAndByReferenceIsRejected()
    {
        string both = CredentialOfferSerializer.DefaultScheme
            + "?" + CredentialOfferParameterNames.CredentialOffer + "="
            + Uri.EscapeDataString(CredentialOfferSerializer.ToJson(BuildPreAuthorizedOffer()))
            + "&" + CredentialOfferParameterNames.CredentialOfferUri + "="
            + Uri.EscapeDataString("https://server.example.com/credential-offer/" + OfferId);

        Oid4VciWalletClient walletClient = BuildWalletClient(fetchCredentialOffer: null);

        ArgumentException error = await Assert.ThrowsExactlyAsync<ArgumentException>(
            async () => await walletClient.AcceptCredentialOfferAsync(
                both, TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy), TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.Contains("single query parameter", error.Message,
            "§4.1: a link carrying both credential_offer and credential_offer_uri is rejected.");
    }


    /// <summary>
    /// §4.1.3: "Upon receipt of the credential_offer_uri, the Wallet MUST send an HTTP GET request
    /// to the URI to retrieve the referenced Credential Offer Object ... and parse it to recreate
    /// the Credential Offer parameters. ... The response from the Credential Issuer that contains a
    /// Credential Offer Object MUST use the media type application/json." The wallet client GETs the
    /// stored offer off the real Issuer endpoint and parses it to the expected offer.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceFetchGetsAndParsesTheStoredOffer()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = await host.RegisterClientAsync(ClientId, ClientBaseUri, OfferCapabilities).ConfigureAwait(false);
        string segment = material.Registration.TenantId.Value;

        CredentialOffer stored = BuildPreAuthorizedOffer();
        await TestHostShell.AlterAsync(host.Server, candidateIntegration =>
        {
            candidateIntegration.ResolveCredentialOfferAsync =
                (offerId, context, ct) => ValueTask.FromResult<CredentialOffer?>(
                    string.Equals(offerId, OfferId, StringComparison.Ordinal) ? stored : null);
        }).ConfigureAwait(false);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //§4.1.3: the credential_offer_uri is the https URL the Wallet GETs. The fixture serves the
        //offer endpoint at /connect/{segment}/credential_offer and addresses the stored offer by id.
        Uri offerEndpoint = TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!, segment, WellKnownEndpointNames.Oid4VciCredentialOffer);
        Uri credentialOfferUri = new($"{offerEndpoint}?{CredentialOfferParameterNames.Id}={OfferId}");
        string byReferenceLink = CredentialOfferSerializer.ToByReferenceDeepLink(credentialOfferUri);

        string? observedContentType = null;
        OutboundTransportDelegate innerTransport =
            GuardedHttpClientTransport.BuildSingleHopTransport(host.Host("default").SharedHttpClient!);
        Oid4VciWalletClient walletClient = BuildWalletClient(
            fetchCredentialOffer: async (request, context, readResponse, ct) =>
            {
                OutboundTransportResult response = await innerTransport(request, context, readResponse, ct).ConfigureAwait(false);
                observedContentType = response.Response?.Headers.ContentType;

                return response;
            });

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.AcceptCredentialOfferAsync(
            byReferenceLink, TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsTrue(outcome.IsSuccess, "The by-reference fetch must succeed over the wire.");
        AssertOfferEquivalent(stored, outcome.Value);
        Assert.AreEqual("application/json", observedContentType,
            "§4.1.3: the by-reference Credential Offer response MUST use the media type application/json.");
    }


    /// <summary>
    /// An offer JSON carrying an unrecognized top-level member and an unrecognized member inside the
    /// Pre-Authorized Code grant parses successfully; the unknown members are ignored and the
    /// recognized parameters beside them are read, the <c>tx_code</c> object's <c>length</c> 6 and
    /// <c>input_mode</c> <c>numeric</c> among them.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1">OID4VCI 1.0 Section 4.1.1</see>:
    /// "Additional Credential Offer parameters MAY be defined and used. The Wallet MUST ignore any
    /// unrecognized parameters.", "input_mode : OPTIONAL. String specifying the input character set."
    /// and "length: OPTIONAL. Integer specifying the length of the Transaction Code."
    /// </summary>
    [TestMethod]
    public void UnrecognizedTopLevelAndGrantParametersAreIgnored()
    {
        //A §4.1.1 offer object with an unknown top-level parameter ("vendor_extension") and an
        //unknown member inside the grant block ("vendor_grant_hint").
        string offerJson =
            "{"
            + "\"credential_issuer\":\"" + OfferIssuer.OriginalString + "\","
            + "\"vendor_extension\":{\"ignored\":true,\"nested\":[1,2,3]},"
            + "\"credential_configuration_ids\":[\"" + ConfigurationId + "\"],"
            + "\"grants\":{"
            + "\"" + WellKnownGrantTypes.PreAuthorizedCode + "\":{"
            + "\"pre-authorized_code\":\"" + PreAuthorizedCode + "\","
            + "\"vendor_grant_hint\":\"ignore-me\","
            + "\"tx_code\":{\"length\":6,\"input_mode\":\"numeric\"}"
            + "}}}";

        CredentialOffer parsed = CredentialOfferSerializer.FromJson(offerJson);

        Assert.AreEqual(OfferIssuer.OriginalString, parsed.CredentialIssuer.OriginalString);
        Assert.AreEqual(ConfigurationId, parsed.CredentialConfigurationIds[0]);
        Assert.IsNotNull(parsed.PreAuthorizedCodeGrant);
        Assert.AreEqual(PreAuthorizedCode, parsed.PreAuthorizedCodeGrant.PreAuthorizedCode);
        Assert.IsNotNull(parsed.PreAuthorizedCodeGrant.TxCode);
        Assert.AreEqual(6, parsed.PreAuthorizedCodeGrant.TxCode.Length);
        Assert.AreEqual("numeric", parsed.PreAuthorizedCodeGrant.TxCode.InputMode);
    }


    /// <summary>
    /// An <c>authorization_code</c> offer round-trips: the parser recreates the grant block with the
    /// opaque <c>issuer_state</c> the Wallet echoes in its subsequent Authorization Request (§4.1.1).
    /// </summary>
    [TestMethod]
    public void AuthorizationCodeOfferRoundTripsThroughTheSerializer()
    {
        CredentialOffer original = new()
        {
            CredentialIssuer = OfferIssuer,
            CredentialConfigurationIds = [ConfigurationId],
            AuthorizationCodeGrant = new AuthorizationCodeOfferGrant
            {
                IssuerState = "eyJhbGciOiJSU0Et...FYUaBy",
                AuthorizationServer = "https://as.example.com"
            }
        };

        CredentialOffer parsed = CredentialOfferSerializer.FromJson(CredentialOfferSerializer.ToJson(original));

        Assert.IsNull(parsed.PreAuthorizedCodeGrant, "An authorization_code-only offer carries no pre-authorized grant.");
        Assert.IsNotNull(parsed.AuthorizationCodeGrant);
        Assert.AreEqual("eyJhbGciOiJSU0Et...FYUaBy", parsed.AuthorizationCodeGrant.IssuerState);
        Assert.AreEqual("https://as.example.com", parsed.AuthorizationCodeGrant.AuthorizationServer);
    }


    /// <summary>
    /// §4.1.1: "tx_code: OPTIONAL. Object indicating that a Transaction Code is required if present,
    /// even if empty." An empty <c>tx_code</c> object still recreates a non-null
    /// <see cref="TxCodeRequirement"/> — its presence alone signals the requirement.
    /// </summary>
    [TestMethod]
    public void EmptyTxCodeObjectRecreatesANonNullRequirement()
    {
        CredentialOffer original = new()
        {
            CredentialIssuer = OfferIssuer,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode,
                TxCode = TxCodeRequirement.Empty
            }
        };

        CredentialOffer parsed = CredentialOfferSerializer.FromJson(CredentialOfferSerializer.ToJson(original));

        Assert.IsNotNull(parsed.PreAuthorizedCodeGrant!.TxCode,
            "An empty tx_code object still signals a required Transaction Code.");
        Assert.IsNull(parsed.PreAuthorizedCodeGrant.TxCode!.Length);
        Assert.IsNull(parsed.PreAuthorizedCodeGrant.TxCode.InputMode);
        Assert.IsNull(parsed.PreAuthorizedCodeGrant.TxCode.Description);
    }


    /// <summary>
    /// §4.1.3: when the Wallet accepts a by-reference link but no fetch transport is wired, the
    /// client surfaces the gap rather than silently failing — the GET the spec MANDATES cannot run.
    /// </summary>
    [TestMethod]
    public async Task ByReferenceWithoutFetchTransportSurfacesTheGap()
    {
        string byReferenceLink = CredentialOfferSerializer.ToByReferenceDeepLink(
            new Uri("https://server.example.com/credential-offer/" + OfferId));

        Oid4VciWalletClient walletClient = BuildWalletClient(fetchCredentialOffer: null);

        InvalidOperationException error = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await walletClient.AcceptCredentialOfferAsync(
                byReferenceLink, TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy), TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.Contains("FetchCredentialOffer", error.Message,
            "A by-reference offer needs the FetchCredentialOffer transport to run the §4.1.3 GET.");
    }


    /// <summary>
    /// A Credential Offer Object the Wallet fetches over the real wire by its
    /// <c>credential_offer_uri</c> is refused as a malformed response of status 200 whose
    /// description names the violated rule, and no offer reaches the caller, when the response's
    /// media type is not <c>application/json</c> (an HTML page, or an unsigned
    /// <c>application/jwt</c> with <c>"alg": "none"</c>; the description names
    /// <c>application/json</c>), when the body is not a JSON object, or when the object carries no
    /// <c>credential_issuer</c>, or when its <c>tx_code</c> object's <c>length</c> is no Integer from 0
    /// to 2147483647 (a negative Integer, one beyond 2147483647, a string, a fraction or
    /// <c>null</c>).
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.3">OID4VCI 1.0 Section 4.1.3</see>:
    /// "Upon receipt of the credential_offer_uri, the Wallet MUST send an HTTP GET request to the URI
    /// to retrieve the referenced Credential Offer Object, unless it is already cached, and parse it to
    /// recreate the Credential Offer parameters.", "The response from the Credential Issuer that
    /// contains a Credential Offer Object MUST use the media type application/json." and "When
    /// retrieving the Credential Offer from the Credential Offer URL, the application/json media type
    /// MUST be used. The Credential Offer cannot be signed and MUST NOT use application/jwt with
    /// "alg": "none"."
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1">OID4VCI 1.0 Section 4.1.1</see>:
    /// "credential_issuer: REQUIRED." and "length: OPTIONAL. Integer specifying the length of the
    /// Transaction Code."
    /// </summary>
    /// <param name="contentType">The media type the Credential Issuer's response carries.</param>
    /// <param name="body">The response body.</param>
    /// <param name="namedInDescription">The text the refusal's description names.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("text/html", "{\"credential_issuer\":\"https://credential-issuer.example.com\",\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"]}", "application/json")]
    [DataRow("application/jwt", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJjcmVkZW50aWFsX2lzc3VlciI6Imh0dHBzOi8vY3JlZGVudGlhbC1pc3N1ZXIuZXhhbXBsZS5jb20iLCJjcmVkZW50aWFsX2NvbmZpZ3VyYXRpb25faWRzIjpbIlVuaXZlcnNpdHlEZWdyZWVfZGNfc2Rfand0Il19.", "application/json")]
    [DataRow("application/json", "not-a-json-object", "well-formed JSON")]
    [DataRow("application/json", "{\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"]}", "credential_issuer")]
    [DataRow("application/json", "{\"credential_issuer\":\"https://credential-issuer.example.com\",\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"tx_code\":{\"length\":9999999999}}}}", "length")]
    [DataRow("application/json", "{\"credential_issuer\":\"https://credential-issuer.example.com\",\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"tx_code\":{\"length\":-1}}}}", "the offer carries a length that is no Integer from 0 to 2147483647")]
    [DataRow("application/json", "{\"credential_issuer\":\"https://credential-issuer.example.com\",\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"tx_code\":{\"length\":2147483648}}}}", "the offer carries a length that is no Integer from 0 to 2147483647")]
    [DataRow("application/json", "{\"credential_issuer\":\"https://credential-issuer.example.com\",\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"tx_code\":{\"length\":\"6\"}}}}", "the offer carries a length that is no Integer from 0 to 2147483647")]
    [DataRow("application/json", "{\"credential_issuer\":\"https://credential-issuer.example.com\",\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"tx_code\":{\"length\":1.5}}}}", "the offer carries a length that is no Integer from 0 to 2147483647")]
    [DataRow("application/json", "{\"credential_issuer\":\"https://credential-issuer.example.com\",\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"],\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"tx_code\":{\"length\":null}}}}", "the offer carries a length that is no Integer from 0 to 2147483647")]
    public async Task ByReferenceOfferRefusalsOverTheWireAsync(string contentType, string body, string namedInDescription)
    {
        (Result<CredentialOffer, Oid4VciRequestFailure> outcome, bool isFetched) = await FetchPublishedOfferAsync(
            contentType, body).ConfigureAwait(false);

        Assert.IsTrue(isFetched, "The Wallet's GET of the credential_offer_uri crossed the wire.");
        Assert.IsFalse(outcome.IsSuccess, "A Credential Offer Object outside its rules is refused.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains(namedInDescription, outcome.Error.ErrorDescription!, StringComparison.Ordinal, outcome.Error.ErrorDescription);
    }


    /// <summary>
    /// A Credential Offer Object fetched over the real wire whose <c>tx_code</c> object carries a
    /// <c>length</c> Integer at either end of the range a Transaction Code length is read in, 0 or
    /// 2147483647, is recreated with that exact length hint.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1">OID4VCI 1.0 Section 4.1.1</see>:
    /// "length: OPTIONAL. Integer specifying the length of the Transaction Code. This helps the Wallet
    /// to render the input screen and improve the user experience."
    /// </summary>
    /// <param name="lengthJson">The <c>length</c> member's JSON value.</param>
    /// <param name="expectedLength">The length hint the recreated offer carries.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("2147483647", 2147483647)]
    [DataRow("0", 0)]
    public async Task ByReferenceOfferTransactionCodeLengthIsReadAsTheHintAsync(string lengthJson, int expectedLength)
    {
        string offerJson = "{\"credential_issuer\":\"https://credential-issuer.example.com\","
            + "\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"],"
            + "\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{"
            + "\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\","
            + "\"tx_code\":{\"length\":" + lengthJson + "}}}}";

        (Result<CredentialOffer, Oid4VciRequestFailure> outcome, bool isFetched) = await FetchPublishedOfferAsync(
            "application/json", offerJson).ConfigureAwait(false);

        Assert.IsTrue(isFetched, "The Wallet's GET of the credential_offer_uri crossed the wire.");
        Assert.IsTrue(outcome.IsSuccess, $"A length Integer from 0 to 2147483647 is read: {outcome.Error?.ErrorDescription}");
        Assert.IsNotNull(outcome.Value.PreAuthorizedCodeGrant, "The offer carries the Pre-Authorized Code grant.");
        Assert.IsNotNull(outcome.Value.PreAuthorizedCodeGrant.TxCode, "The tx_code object signals a required Transaction Code.");
        Assert.AreEqual(expectedLength, outcome.Value.PreAuthorizedCodeGrant.TxCode.Length,
            "The length hint is the Integer the offer carries.");
    }


    /// <summary>
    /// A Credential Offer Object fetched over the real wire that carries an optional member of a JSON
    /// type its definition does not admit is refused as a malformed response of status 200 whose
    /// description names the member, and no offer reaches the caller: a <c>grants</c> that is no
    /// object, a Grant Type's value that is no object, a <c>tx_code</c> that is no object (a string, or
    /// <c>null</c>), and an <c>input_mode</c>, <c>description</c>, <c>authorization_server</c> (in
    /// either grant) or <c>issuer_state</c> that is no string. A member that is present is read by its
    /// definition and never as if it were absent.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1">OID4VCI 1.0 Section 4.1.1</see>:
    /// "grants: OPTIONAL. Object indicating to the Wallet the Grant Types the Credential Issuer's
    /// Authorization Server is prepared to process for this Credential Offer. Every grant is
    /// represented by a name/value pair. The name is the Grant Type identifier; the value is an object
    /// that contains parameters", "issuer_state: OPTIONAL. String value created by the Credential
    /// Issuer and opaque to the Wallet", "authorization_server: OPTIONAL string that the Wallet can use
    /// to identify the Authorization Server to use with this grant type", "tx_code: OPTIONAL. Object
    /// indicating that a Transaction Code is required if present, even if empty.", "input_mode :
    /// OPTIONAL. String specifying the input character set." and "description: OPTIONAL. String
    /// containing guidance for the Holder of the Wallet on how to obtain the Transaction Code".
    /// </summary>
    /// <param name="grantsJson">The <c>grants</c> member's JSON value.</param>
    /// <param name="namedInDescription">The text the refusal's description names.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"tx_code\":\"x\"}}", "the offer carries a tx_code member that is no object")]
    [DataRow("{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"tx_code\":null}}", "the offer carries a tx_code member that is no object")]
    [DataRow("\"x\"", "the offer carries a grants member that is no object")]
    [DataRow("{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":\"x\"}", "the offer carries the urn:ietf:params:oauth:grant-type:pre-authorized_code grant as a value that is no object")]
    [DataRow("{\"authorization_code\":[]}", "the offer carries the authorization_code grant as a value that is no object")]
    [DataRow("{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"tx_code\":{\"input_mode\":5}}}", "the offer carries an input_mode member that is no string")]
    [DataRow("{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"tx_code\":{\"description\":1}}}", "the offer carries a description member that is no string")]
    [DataRow("{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\",\"authorization_server\":true}}", "the offer carries an authorization_server member that is no string")]
    [DataRow("{\"authorization_code\":{\"authorization_server\":true}}", "the offer carries an authorization_server member that is no string")]
    [DataRow("{\"authorization_code\":{\"issuer_state\":7}}", "the offer carries an issuer_state member that is no string")]
    public async Task ByReferenceOfferCarryingAMemberOfAnotherJsonTypeIsRefusedAsync(string grantsJson, string namedInDescription)
    {
        string offerJson = "{\"credential_issuer\":\"https://credential-issuer.example.com\","
            + "\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"],"
            + "\"grants\":" + grantsJson + "}";

        (Result<CredentialOffer, Oid4VciRequestFailure> outcome, bool isFetched) = await FetchPublishedOfferAsync(
            "application/json", offerJson).ConfigureAwait(false);

        Assert.IsTrue(isFetched, "The Wallet's GET of the credential_offer_uri crossed the wire.");
        Assert.IsFalse(outcome.IsSuccess, "A present member of a JSON type its definition does not admit is refused, never read as absent.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains(namedInDescription, outcome.Error.ErrorDescription!, StringComparison.Ordinal, outcome.Error.ErrorDescription);
    }


    /// <summary>
    /// A Credential Offer Object fetched over the real wire that carries a top-level parameter and a
    /// Pre-Authorized Code grant parameter this specification does not define is recreated as if
    /// those parameters were absent: the offer's configuration is read and its <c>tx_code</c> signals
    /// a required Transaction Code whether the object is empty, giving no <c>length</c>,
    /// <c>description</c> or <c>input_mode</c>, or gives the <c>input_mode</c> <c>text</c>, which is
    /// read as the input character set.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1">OID4VCI 1.0 Section 4.1.1</see>:
    /// "Additional Credential Offer parameters MAY be defined and used. The Wallet MUST ignore any
    /// unrecognized parameters.", "tx_code: OPTIONAL. Object indicating that a Transaction Code is
    /// required if present, even if empty.", "If no length, description, or input_mode is given, this
    /// object MAY be empty." and "input_mode : OPTIONAL. String specifying the input character set.
    /// Possible values are numeric (only digits) and text (any characters). The default is numeric."
    /// </summary>
    /// <param name="txCodeJson">The <c>tx_code</c> member's JSON value.</param>
    /// <param name="expectedInputMode">The <c>input_mode</c> the object gives, or <see langword="null"/> when it gives none.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("{}", null)]
    [DataRow("{\"input_mode\":\"text\"}", "text")]
    public async Task ByReferenceOfferIgnoresUnrecognizedParametersOverTheWireAsync(string txCodeJson, string? expectedInputMode)
    {
        string offerJson =
            "{\"credential_issuer\":\"https://credential-issuer.example.com\","
            + "\"vendor_extension\":{\"ignored\":true,\"nested\":[1,2,3]},"
            + "\"credential_configuration_ids\":[\"UniversityDegree_dc_sd_jwt\"],"
            + "\"grants\":{\"urn:ietf:params:oauth:grant-type:pre-authorized_code\":{"
            + "\"pre-authorized_code\":\"oaKazRN8I0IbtZ0C7JuMn5\","
            + "\"vendor_grant_hint\":\"ignore-me\","
            + "\"tx_code\":" + txCodeJson + "}}}";

        (Result<CredentialOffer, Oid4VciRequestFailure> outcome, bool isFetched) = await FetchPublishedOfferAsync(
            "application/json", offerJson).ConfigureAwait(false);

        Assert.IsTrue(isFetched, "The Wallet's GET of the credential_offer_uri crossed the wire.");
        Assert.IsTrue(outcome.IsSuccess, $"Unrecognized parameters are ignored, not refused: {outcome.Error?.ErrorDescription}");
        Assert.AreSequenceEqual(["UniversityDegree_dc_sd_jwt"], outcome.Value.CredentialConfigurationIds.ToArray());
        Assert.IsNotNull(outcome.Value.PreAuthorizedCodeGrant);
        Assert.AreEqual("oaKazRN8I0IbtZ0C7JuMn5", outcome.Value.PreAuthorizedCodeGrant.PreAuthorizedCode);
        Assert.IsNotNull(outcome.Value.PreAuthorizedCodeGrant.TxCode,
            "The tx_code object signals a required Transaction Code, even if empty.");
        Assert.AreEqual(expectedInputMode, outcome.Value.PreAuthorizedCodeGrant.TxCode.InputMode,
            "The tx_code object's input_mode is read as the input character set, and an object giving none reads none.");
        Assert.IsNull(outcome.Value.PreAuthorizedCodeGrant.TxCode.Length, "The tx_code object gives no length.");
        Assert.IsNull(outcome.Value.PreAuthorizedCodeGrant.TxCode.Description, "The tx_code object gives no description.");
    }


    /// <summary>
    /// A Credential Offer Object fetched over the real wire whose <c>credential_configuration_ids</c>
    /// repeats an identifier, carries an empty one, carries an entry that is no string, or is no array,
    /// is refused as a malformed response whose description states the rule the value breaks and
    /// repeats none of the identifiers the offer carries, and no offer reaches the caller.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.1">OID4VCI 1.0 Section 4.1.1</see>:
    /// "credential_configuration_ids: REQUIRED. A non-empty array of unique strings that each identify
    /// one of the keys in the name/value pairs stored in the credential_configurations_supported
    /// Credential Issuer metadata." An empty string identifies no key.
    /// </summary>
    /// <param name="configurationIds">The JSON value the offer carries as <c>credential_configuration_ids</c>.</param>
    /// <param name="namedInDescription">The text the refusal's description names.</param>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    [DataRow("[\"x-echo-probe\",\"x-echo-probe\"]", "credential_configuration_ids entries are unique")]
    [DataRow("[\"x-echo-probe\",\"\"]", "every credential_configuration_ids entry is a non-empty string")]
    [DataRow("[\"x-echo-probe\",1]", "the offer carries a value that is no array of strings")]
    [DataRow("\"x-echo-probe\"", "the offer carries a value that is no array of strings")]
    public async Task ByReferenceOfferWithARepeatedOrEmptyConfigurationIdentifierIsRefusedAsync(string configurationIds, string namedInDescription)
    {
        string offerJson = "{\"credential_issuer\":\"https://credential-issuer.example.com\","
            + "\"credential_configuration_ids\":" + configurationIds + "}";

        (Result<CredentialOffer, Oid4VciRequestFailure> outcome, bool isFetched) = await FetchPublishedOfferAsync(
            "application/json", offerJson).ConfigureAwait(false);

        Assert.IsTrue(isFetched, "The Wallet's GET of the credential_offer_uri crossed the wire.");
        Assert.IsFalse(outcome.IsSuccess, "An offer whose credential_configuration_ids are not unique non-empty strings is refused.");
        Assert.AreEqual(Oid4VciRequestFailureKind.MalformedResponse, outcome.Error.Kind);
        Assert.AreEqual(200, outcome.Error.StatusCode);
        Assert.Contains(namedInDescription, outcome.Error.ErrorDescription!, StringComparison.Ordinal, outcome.Error.ErrorDescription);
        Assert.DoesNotContain("x-echo-probe", outcome.Error.ErrorDescription!, StringComparison.Ordinal,
            "The description states the rule and repeats no identifier the offer carries.");
    }


    /// <summary>
    /// A Credential Offer link whose <c>credential_offer_uri</c> uses the <c>http</c> scheme is refused
    /// under the secure default outbound policy before any request is sent: the outcome is a policy
    /// denial with no status code, and the Wallet's transport is never called.
    /// <see href="https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-4.1">OID4VCI 1.0 Section 4.1</see>:
    /// "credential_offer_uri: String that is a URL using the https scheme referencing a resource
    /// containing a JSON object with the Credential Offer parameters." The link is a value the
    /// End-User scans, so no exchange carries it; the refusal is shown at the transport the Wallet
    /// would dial.
    /// </summary>
    /// <returns>A task that completes when the assertions have run.</returns>
    [TestMethod]
    public async Task HttpCredentialOfferUriIsRefusedBeforeAnyDialAsync()
    {
        List<Uri> invocations = [];
        Oid4VciWalletClient walletClient = BuildWalletClient(
            fetchCredentialOffer: (request, _, readResponse, cancellationToken) =>
            {
                invocations.Add(request.Target);

                return ScriptedOutboundTransport.ReadAsync(readResponse, new OutboundResponse { StatusCode = 404 }, cancellationToken);
            });

        string httpLink = CredentialOfferSerializer.DefaultScheme
            + "?" + CredentialOfferParameterNames.CredentialOfferUri + "="
            + Uri.EscapeDataString("http://server.example.com/credential-offer");

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.AcceptCredentialOfferAsync(
            httpLink, TestHostShell.ExchangeContextWith(OutboundFetchPolicy.SecureDefault), TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsEmpty(invocations, "No request is sent to a credential_offer_uri that does not use the https scheme.");
        Assert.IsFalse(outcome.IsSuccess, "A credential_offer_uri that does not use the https scheme is refused.");
        Assert.AreEqual(Oid4VciRequestFailureKind.OutboundPolicyDenied, outcome.Error.Kind);
        Assert.IsNull(outcome.Error.StatusCode, "No response was received; the policy refused before any dial.");
    }


    /// <summary>
    /// Publishes <paramref name="body"/> as <paramref name="contentType"/> at a path of a loopback
    /// HTTPS host, composes the by-reference Credential Offer link to it, and has the Wallet accept
    /// the link over the real wire through a transport pinned to the host's certificate.
    /// </summary>
    /// <param name="contentType">The media type the response carries.</param>
    /// <param name="body">The response body.</param>
    /// <returns>The Wallet's outcome, and whether the host served the published path.</returns>
    private async Task<(Result<CredentialOffer, Oid4VciRequestFailure> Outcome, bool IsFetched)> FetchPublishedOfferAsync(
        string contentType, string body)
    {
        const string offerPath = "/credential-offer";
        await using StaticContentHost issuer = await StaticContentHost.StartAsync(TestContext.CancellationToken).ConfigureAwait(false);
        issuer.Publish(offerPath, Encoding.UTF8.GetBytes(body), contentType);

        using HttpClient httpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(issuer.Certificate);
        Oid4VciWalletClient walletClient = BuildWalletClient(
            fetchCredentialOffer: GuardedHttpClientTransport.BuildSingleHopTransport(httpClient));
        string byReferenceLink = CredentialOfferSerializer.ToByReferenceDeepLink(new Uri(issuer.BaseAddress, offerPath));

        Result<CredentialOffer, Oid4VciRequestFailure> outcome = await walletClient.AcceptCredentialOfferAsync(
            byReferenceLink, TestHostShell.ExchangeContextWith(TestHostShell.LoopbackOutboundFetchPolicy), TestContext.CancellationToken).ConfigureAwait(false);

        return (outcome, issuer.WasRequested(offerPath));
    }


    //A representative §4.1.1 Pre-Authorized Code offer with a fully-specified tx_code.
    private static CredentialOffer BuildPreAuthorizedOffer() =>
        new()
        {
            CredentialIssuer = OfferIssuer,
            CredentialConfigurationIds = [ConfigurationId],
            PreAuthorizedCodeGrant = new PreAuthorizedCodeOfferGrant
            {
                PreAuthorizedCode = PreAuthorizedCode,
                TxCode = new TxCodeRequirement
                {
                    InputMode = TxCodeInputModes.Numeric,
                    Length = 4,
                    Description = "Please provide the one-time code that was sent via e-mail"
                }
            }
        };


    //Asserts the parsed offer reproduces the composed offer's recognized §4.1.1 parameters.
    private static void AssertOfferEquivalent(CredentialOffer expected, CredentialOffer actual)
    {
        Assert.AreEqual(expected.CredentialIssuer.OriginalString, actual.CredentialIssuer.OriginalString);
        Assert.AreSequenceEqual(expected.CredentialConfigurationIds.ToArray(), actual.CredentialConfigurationIds.ToArray());

        Assert.AreEqual(expected.PreAuthorizedCodeGrant?.PreAuthorizedCode, actual.PreAuthorizedCodeGrant?.PreAuthorizedCode);
        Assert.AreEqual(expected.PreAuthorizedCodeGrant?.TxCode?.InputMode, actual.PreAuthorizedCodeGrant?.TxCode?.InputMode);
        Assert.AreEqual(expected.PreAuthorizedCodeGrant?.TxCode?.Length, actual.PreAuthorizedCodeGrant?.TxCode?.Length);
        Assert.AreEqual(expected.PreAuthorizedCodeGrant?.TxCode?.Description, actual.PreAuthorizedCodeGrant?.TxCode?.Description);

        Assert.AreEqual(expected.AuthorizationCodeGrant?.IssuerState, actual.AuthorizationCodeGrant?.IssuerState);
    }


    //Builds a wallet client whose issuance transports are unused here (the offer flow only needs
    //the FetchCredentialOffer seam). The POST seams throw if reached, proving the offer path drives
    //no issuance call on its own.
    private Oid4VciWalletClient BuildWalletClient(OutboundTransportDelegate? fetchCredentialOffer)
    {
        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (_, _, _, _, _) => throw new InvalidOperationException("The offer flow makes no §6 Token Request."),
            SendJsonPost = (_, _, _, _, _) => throw new InvalidOperationException("The offer flow makes no §7/§8 request."),
            JwtHeaderSerializer = static header => throw new InvalidOperationException("No proof is minted in the offer flow."),
            JwtPayloadSerializer = static payload => throw new InvalidOperationException("No proof is minted in the offer flow."),
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            FetchCredentialOffer = fetchCredentialOffer,
            OutboundFetchPolicy = TestHostShell.LoopbackOutboundFetchPolicy
        };

        return new Oid4VciWalletClient(configuration);
    }


}
