using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Net.Http;
using Verifiable.Cryptography;
using Verifiable.OAuth;
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

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private const string ClientId = "https://issuer.client.test";
    private static readonly Uri ClientBaseUri = new("https://issuer.client.test");
    private static readonly Uri OfferIssuer = new("https://credential-issuer.example.com");
    private const string ConfigurationId = "UniversityDegree_dc_sd_jwt";
    private const string PreAuthorizedCode = "oaKazRN8I0IbtZ0C7JuMn5";

    /// <summary>The id the credential_offer_uri carries; the offer store is keyed by it.</summary>
    private const string OfferId = "GkurKxf5T0Y-mnPFCHqWOMiZi4VS138cQO_V7PZHAdM";

    private static readonly ImmutableHashSet<CapabilityIdentifier> OfferCapabilities =
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
        CredentialOffer parsed = await walletClient.AcceptCredentialOfferAsync(
            deepLink, TestContext.CancellationToken).ConfigureAwait(false);

        AssertOfferEquivalent(original, parsed);
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
                both, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

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
        using VerifierKeyMaterial material = host.RegisterClient(ClientId, ClientBaseUri, OfferCapabilities);
        string segment = material.Registration.TenantId.Value;

        CredentialOffer stored = BuildPreAuthorizedOffer();
        host.Server.OAuth().ResolveCredentialOfferAsync =
            (offerId, context, ct) => ValueTask.FromResult<CredentialOffer?>(
                string.Equals(offerId, OfferId, StringComparison.Ordinal) ? stored : null);

        await host.StartHttpHostAsync(TestContext.CancellationToken).ConfigureAwait(false);

        //§4.1.3: the credential_offer_uri is the https URL the Wallet GETs. The fixture serves the
        //offer endpoint at /connect/{segment}/credential_offer and addresses the stored offer by id.
        Uri offerEndpoint = TestHostShell.ComposeEndpointUri(
            host.Host("default").HttpBaseAddress!, segment, WellKnownEndpointNames.Oid4VciCredentialOffer);
        Uri credentialOfferUri = new($"{offerEndpoint}?{CredentialOfferParameterNames.Id}={OfferId}");
        string byReferenceLink = CredentialOfferSerializer.ToByReferenceDeepLink(credentialOfferUri);

        string? observedContentType = null;
        Oid4VciWalletClient walletClient = BuildWalletClient(
            fetchCredentialOffer: (uri, ct) => FetchOfferAsync(
                host.Host("default").SharedHttpClient!, uri, contentType => observedContentType = contentType, ct));

        CredentialOffer parsed = await walletClient.AcceptCredentialOfferAsync(
            byReferenceLink, TestContext.CancellationToken).ConfigureAwait(false);

        AssertOfferEquivalent(stored, parsed);
        Assert.AreEqual("application/json", observedContentType,
            "§4.1.3: the by-reference Credential Offer response MUST use the media type application/json.");
    }


    /// <summary>
    /// §4.1.1: "Additional Credential Offer parameters MAY be defined and used. The Wallet MUST
    /// ignore any unrecognized parameters." An offer JSON carrying an unrecognized top-level member
    /// and an unrecognized member inside the Pre-Authorized Code grant parses successfully; the
    /// unknown members are ignored and the recognized parameters round-trip.
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
        Assert.AreEqual(PreAuthorizedCode, parsed.PreAuthorizedCodeGrant!.PreAuthorizedCode);
        Assert.IsNotNull(parsed.PreAuthorizedCodeGrant.TxCode);
        Assert.AreEqual(6, parsed.PreAuthorizedCodeGrant.TxCode!.Length);
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
        Assert.AreEqual("eyJhbGciOiJSU0Et...FYUaBy", parsed.AuthorizationCodeGrant!.IssuerState);
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
                byReferenceLink, TestContext.CancellationToken).ConfigureAwait(false)).ConfigureAwait(false);

        Assert.Contains("FetchCredentialOffer", error.Message,
            "A by-reference offer needs the FetchCredentialOffer transport to run the §4.1.3 GET.");
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
    private Oid4VciWalletClient BuildWalletClient(Oid4VciFetchCredentialOfferDelegate? fetchCredentialOffer)
    {
        Oid4VciWalletConfiguration configuration = new()
        {
            SendFormPost = (_, _, _) => throw new InvalidOperationException("The offer flow makes no §6 Token Request."),
            SendJsonPost = (_, _, _, _) => throw new InvalidOperationException("The offer flow makes no §7/§8 request."),
            JwtHeaderSerializer = static header => throw new InvalidOperationException("No proof is minted in the offer flow."),
            JwtPayloadSerializer = static payload => throw new InvalidOperationException("No proof is minted in the offer flow."),
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool,
            FetchCredentialOffer = fetchCredentialOffer
        };

        return new Oid4VciWalletClient(configuration);
    }


    //The wallet's §4.1.3 by-reference GET transport: a real HTTP GET over the started host's
    //SharedHttpClient. The library stays System.Net-free; the test supplies the plumbing and
    //surfaces the response Content-Type so the test can assert the §4.1.3 application/json contract.
    private static async ValueTask<(int StatusCode, string Body)> FetchOfferAsync(
        HttpClient httpClient,
        Uri credentialOfferUri,
        Action<string?> observeContentType,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await httpClient.GetAsync(
            credentialOfferUri, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        observeContentType(response.Content.Headers.ContentType?.MediaType);

        return ((int)response.StatusCode, body);
    }
}
