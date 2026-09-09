using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Immutable;
using System.Text;
using System.Text.Json;
using Verifiable.Cbor;
using Verifiable.Cbor.Mdoc;
using Verifiable.Cbor.Sd;
using Verifiable.Core;
using Verifiable.Core.Dcql;
using Verifiable.Core.Model.Dcql;
using Verifiable.Core.Model.SelectiveDisclosure;
using Verifiable.Core.StatusList;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.JCose.Eudi;
using Verifiable.OAuth;
using Verifiable.OAuth.Oid4Vp;
using Verifiable.OAuth.Oid4Vp.Server;
using Verifiable.OAuth.Oid4Vp.Server.States;
using Verifiable.OAuth.Oid4Vp.States;
using Verifiable.OAuth.Oid4Vp.Wallet;
using Verifiable.OAuth.Server;
using Verifiable.Server;
using Verifiable.Server.Pipeline;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

using StatusListType = Verifiable.Core.StatusList.StatusList;

namespace Verifiable.Tests.OAuth;


/// <summary>
/// The answers the OID4VP Response URI writes for a <c>direct_post</c> POST, each driven over the shell's
/// in-process HTTPS listener and asserted on both the wire and the Verifier's own terminal flow state.
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
/// Presentations 1.0, Section 8.2</see> defines only the success answer — "If the Response URI has
/// successfully processed the Authorization Response or Authorization Error Response, it MUST respond with an
/// HTTP status code of 200 with Content-Type of application/json and a JSON object in the response body." — so
/// a refused presentation borrows the authorization-error vocabulary of
/// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see> as an
/// HTTP 400 body, and HTTP 500 <c>server_error</c> stays reserved for a state the endpoint cannot classify.
/// </summary>
/// <remarks>
/// The wire <c>error_description</c> is one fixed generic sentence per refusal class because
/// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
/// Presentations 1.0, Section 15.9</see> says "Error responses SHOULD avoid including sensitive or detailed
/// contextual information that could be used to infer the End-User's data." The relying party's detail — which
/// credential query, the raw status, its disposition — rides the terminal state instead, which these tests
/// assert separately from the wire body.
/// </remarks>
[TestClass]
internal sealed class Oid4VpDirectPostRefusalTests
{
    public TestContext TestContext { get; set; } = null!;

    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    private const string VerifierClientId = "https://verifier.example.com";
    private static Uri VerifierBaseUri { get; } = new("https://verifier.example.com");

    private const string IssuerId = "https://issuer.example.com";
    private const string IssuerKeyId = "did:web:issuer.example.com#key-1";

    /// <summary>The DCQL credential query identifier every credential in this class is presented under.</summary>
    private const string PidCredentialQueryId = "pid";

    /// <summary>The Status List the status-bearing credentials of this class reference.</summary>
    private const string StatusListUri = "https://issuer.example/statuslists/1";

    private static BaseMemoryPool Pool => BaseMemoryPool.Shared;

    private static ImmutableHashSet<CapabilityIdentifier> Oid4VpCapabilities { get; } =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.VcVerifiablePresentation,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint);


    /// <summary>
    /// A presentation that does not satisfy the Authorization Request's DCQL query is refused with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> — "The request is missing a required parameter, includes an invalid
    /// parameter value, includes a parameter more than once, or is otherwise malformed." — as an HTTP 400
    /// body, and the wire description names neither the credential query nor any other contextual detail per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 15.9</see>: "Error responses SHOULD avoid including sensitive or detailed
    /// contextual information that could be used to infer the End-User's data."
    /// </summary>
    [TestMethod]
    public async Task AnUnsatisfiedQueryIsRefusedAsInvalidRequestWithAGenericDescription()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string parHandle, string compactJwe, PublicKeyMemory issuerPublicKey) = await DriveWalletToResponsePostAsync(
            app, verifierKeys, CreateQueryRequestingAnAbsentClaim(), status: null,
            nonce: "nonce-unsatisfied-query").ConfigureAwait(false);

        using PublicKeyMemory issuerKey = issuerPublicKey;

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.Response, compactJwe),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "RFC 6749 §4.1.2.1: an Authorization Response the Verifier cannot verify is answered with the error code as HTTP 400, never 500.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "The RFC 6749 §4.1.2.1 error object is a JSON body.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: a presentation that does not satisfy the request is invalid_request.");
        AssertDescriptionCarriesNoContextualDetail(wireDescription);
        Assert.AreEqual(
            VerifierFlowRefusal.For(VerifierFlowRefusalKind.Unverifiable).Description, wireDescription,
            "The Unverifiable refusal class's one fixed, canonical wire sentence.");

        VerifierFlowFailedState failed = ReadFailedState(app, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.Unverifiable, failed.Refusal!.Value.Kind,
            "A negative verification verdict is the Unverifiable refusal class.");
        Assert.AreEqual(OAuthErrors.InvalidRequest, failed.Refusal!.Value.ErrorCode,
            "RFC 6749 §4.1.2.1: the Unverifiable refusal's error code is invalid_request.");
    }


    /// <summary>
    /// An Authorization Response whose <c>response</c> parameter is not a decodable JWE is a shape no
    /// conformant Wallet produces, so it is refused with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> ("… or is otherwise malformed") as an HTTP 400 body rather than surfacing as a
    /// Verifier fault.
    /// </summary>
    [TestMethod]
    public async Task AnUndecodableEncryptedResponseIsRefusedAsInvalidRequestNotServerError()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-malformed-jwe"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.Response, "not-a-jwe"),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "RFC 6749 §4.1.2.1: a malformed Authorization Response is answered as HTTP 400, not as an HTTP 500 Verifier fault.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "The RFC 6749 §4.1.2.1 error object is a JSON body.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: an otherwise malformed request is invalid_request.");
        AssertDescriptionCarriesNoContextualDetail(wireDescription);
        Assert.AreEqual(
            VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed).Description, wireDescription,
            "The Malformed refusal class's one fixed, canonical wire sentence.");

        VerifierFlowFailedState failed = ReadFailedState(app, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "An undecodable response JWE is the Malformed refusal class.");
    }


    /// <summary>
    /// An unencrypted Authorization Response whose <c>vp_token</c> is not the
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 8.1</see> JSON object keyed by credential query identifier is likewise a
    /// Wallet-attributable malformed request, refused with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> as an HTTP 400 body.
    /// </summary>
    [TestMethod]
    public async Task AnUnparseableVpTokenIsRefusedAsInvalidRequestNotServerError()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-malformed-vp-token"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(AuthorizationResponseParameters.VpToken, "not-a-vp-token"),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "RFC 6749 §4.1.2.1: a malformed vp_token is answered as HTTP 400, not as an HTTP 500 Verifier fault.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "The RFC 6749 §4.1.2.1 error object is a JSON body.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: an otherwise malformed request is invalid_request.");
        AssertDescriptionCarriesNoContextualDetail(wireDescription);

        VerifierFlowFailedState failed = ReadFailedState(app, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "An unparseable vp_token is the Malformed refusal class.");
    }


    /// <summary>
    /// A presented SD-JWT whose issuer JWS payload segment decodes to bytes that are not valid JSON is
    /// structurally three dot-separated segments — extractable from <c>vp_token</c> under its credential
    /// query identifier — but fails <c>SdJwtSerializer.ParseToken</c>'s walk of the issuer-signed payload.
    /// That leaf normalizes the rejection to <see cref="FormatException"/> (RFC 9901's own wire-shape
    /// vocabulary), so the presentation is refused with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> as an HTTP 400 body rather than surfacing as a Verifier fault.
    /// </summary>
    [TestMethod]
    public async Task ASdJwtWhoseIssuerPayloadIsNotJsonIsRefusedAsInvalidRequestNotServerError()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-sdjwt-payload-not-json"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        //Three non-empty dot-separated segments — a structurally compact-JWS-shaped issuer JWT per
        //SdJwtSerializer.IsCompactJws — whose payload segment decodes to plain text, not a JSON object.
        string header = Base64UrlEncodeUtf8("""{"alg":"ES256","typ":"vc+sd-jwt"}""");
        string notJsonPayload = Base64UrlEncodeUtf8("this is not a JSON object");
        string signature = Base64UrlEncodeUtf8("signature-bytes-are-never-reached");
        string issuerJwtWithNonJsonPayload = $"{header}.{notJsonPayload}.{signature}";

        string vpTokenJson =
            $$"""{"{{PidCredentialQueryId}}":["{{issuerJwtWithNonJsonPayload}}~"]}""";

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(AuthorizationResponseParameters.VpToken, vpTokenJson),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "RFC 6749 §4.1.2.1: an SD-JWT whose issuer payload is not JSON is answered as HTTP 400, not as an HTTP 500 Verifier fault.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "The RFC 6749 §4.1.2.1 error object is a JSON body.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: an otherwise malformed request is invalid_request.");
        AssertDescriptionCarriesNoContextualDetail(wireDescription);

        VerifierFlowFailedState failed = ReadFailedState(app, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "An SD-JWT whose issuer payload is not JSON is the Malformed refusal class.");
    }


    /// <summary>
    /// An <c>mso_mdoc</c> presentation whose DeviceResponse CBOR is truncated — a
    /// well-formed base64url wrapping of malformed CBOR content — is a shape no conformant Wallet
    /// produces. <see cref="MdocCborDeviceResponseReader.Read"/> normalizes the CBOR reader's own
    /// rejection to <see cref="FormatException"/> at its own public boundary, so the presentation is
    /// refused with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section
    /// 4.1.2.1</see>'s <c>invalid_request</c> as an HTTP 400 body (the Malformed refusal class) rather
    /// than surfacing as a Verifier fault. mdoc's SessionTranscript binding requires the wallet's
    /// <c>mdoc_generated_nonce</c> to ride the response JWE's <c>apu</c> header (ISO/IEC 18013-7
    /// §B.4.4), so this drives the real encrypted <c>direct_post.jwt</c> cross-device flow —
    /// <see cref="Oid4VpMdocFlowIntegrationTests"/>'s own recipe — rather than the unencrypted
    /// candidate, wrapping the fixture's real <see cref="ProduceVpTokenPresentationsDelegate"/> to
    /// truncate only the assembled DeviceResponse value it returns.
    /// </summary>
    [TestMethod]
    public async Task ACorruptMdocDeviceResponseIsRefusedAsInvalidRequestNotServerError()
    {
        await using FormatRun run = await MdocVpFixture.Format.StartAsync(
            TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        TestHostShell app = run.App;

        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        ProduceVpTokenPresentationsDelegate corruptingProduce = async (context, cancellationToken) =>
        {
            Oid4VpPresentationSet valid = await run.Produce(context, cancellationToken).ConfigureAwait(false);

            using IMemoryOwner<byte> fullDeviceResponseBytes = Oid4VpMdocPresentation.DecodeVpTokenValue(
                valid.PresentationsByQueryId[PidCredentialQueryId], TestSetup.Base64UrlDecoder, context.MemoryPool);
            string corruptVpTokenValue = TestSetup.Base64UrlEncoder(
                fullDeviceResponseBytes.Memory.Span[..(fullDeviceResponseBytes.Memory.Length / 2)]);

            return new Oid4VpPresentationSet
            {
                PresentationsByQueryId = new Dictionary<string, string>(valid.PresentationsByQueryId, StringComparer.Ordinal)
                {
                    [PidCredentialQueryId] = corruptVpTokenValue
                },
                ResponseEncryptionApu = valid.ResponseEncryptionApu
            };
        };

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys,
            corruptingProduce,
            TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey),
            TestContext.CancellationToken).ConfigureAwait(false);

        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-mdoc-corrupt-device-response"),
            run.Query,
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        InvalidOperationException refusal = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                    FlowId = $"wallet-mdoc-corrupt-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false),
            "The Verifier refuses a truncated DeviceResponse over direct_post.jwt, so the wallet client "
            + "throws on the non-200 answer.").ConfigureAwait(false);

        Assert.Contains("returned status 400", refusal.Message, StringComparison.Ordinal,
            "RFC 6749 §4.1.2.1: a truncated mso_mdoc DeviceResponse is answered as HTTP 400, not as an HTTP 500 Verifier fault.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(
            refusal.Message[refusal.Message.IndexOf('{', StringComparison.Ordinal)..]);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: an otherwise malformed request is invalid_request.");
        AssertDescriptionCarriesNoContextualDetail(wireDescription);

        VerifierFlowFailedState failed = ReadFailedState(app, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "A truncated mso_mdoc DeviceResponse is the Malformed refusal class.");
    }


    /// <summary>
    /// An <c>mso_mdoc</c> response JWE whose protected header carries no <c>apu</c> —
    /// the wallet's <c>mdoc_generated_nonce</c>, required per ISO/IEC 18013-7 §B.4.4 to reconstruct
    /// the OID4VP SessionTranscript — is a shape no conformant Wallet produces for an mdoc
    /// presentation. The DeviceResponse itself is left perfectly valid; only the response-encryption
    /// <c>apu</c> binding is dropped, so <c>HaipOid4VpVerifierExecutor</c>'s own
    /// <see cref="FormatException"/> for the missing header routes the presentation to the Malformed
    /// refusal class (RFC 6749 §4.1.2.1 <c>invalid_request</c>, HTTP 400) rather than a Verifier
    /// fault.
    /// </summary>
    [TestMethod]
    public async Task AnMdocResponseJweWithoutApuIsRefusedAsInvalidRequestNotServerError()
    {
        await using FormatRun run = await MdocVpFixture.Format.StartAsync(
            TimeProvider, TestContext.CancellationToken).ConfigureAwait(false);
        TestHostShell app = run.App;

        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        ProduceVpTokenPresentationsDelegate produceWithoutApu = async (context, cancellationToken) =>
        {
            Oid4VpPresentationSet valid = await run.Produce(context, cancellationToken).ConfigureAwait(false);

            return new Oid4VpPresentationSet
            {
                PresentationsByQueryId = valid.PresentationsByQueryId,
                ResponseEncryptionApu = null
            };
        };

        Oid4VpWalletClient walletClient = await app.CreateHttpBackedOid4VpWalletClientAsync(
            verifierKeys,
            produceWithoutApu,
            TestHostShell.PinnedVerifierKeyResolver(verifierKeys.SigningPublicKey),
            TestContext.CancellationToken).ConfigureAwait(false);

        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-mdoc-no-apu"),
            run.Query,
            TestContext.CancellationToken).ConfigureAwait(false);

        using HttpResponseMessage jarResponse = await app.Host("default").SharedHttpClient!
            .GetAsync(requestUri, TestContext.CancellationToken).ConfigureAwait(false);
        jarResponse.EnsureSuccessStatusCode();
        string compactJar = await jarResponse.Content
            .ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        InvalidOperationException refusal = await Assert.ThrowsExactlyAsync<InvalidOperationException>(
            async () => await walletClient.PresentJarAsync(
                new PresentJarOptions
                {
                    CompactJar = compactJar,
                    RequestUri = requestUri,
                    ExpectedVerifierClientId = VerifierClientId,
                    FlowId = $"wallet-mdoc-no-apu-{Guid.NewGuid():N}"
                },
                TestContext.CancellationToken).ConfigureAwait(false),
            "The Verifier refuses an mso_mdoc response JWE carrying no apu, so the wallet client "
            + "throws on the non-200 answer.").ConfigureAwait(false);

        Assert.Contains("returned status 400", refusal.Message, StringComparison.Ordinal,
            "RFC 6749 §4.1.2.1: an mso_mdoc response JWE without apu is answered as HTTP 400, not as an HTTP 500 Verifier fault.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(
            refusal.Message[refusal.Message.IndexOf('{', StringComparison.Ordinal)..]);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: an otherwise malformed request is invalid_request.");
        AssertDescriptionCarriesNoContextualDetail(wireDescription);

        VerifierFlowFailedState failed = ReadFailedState(app, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "An mso_mdoc response JWE without apu is the Malformed refusal class.");
    }


    /// <summary>
    /// A <c>dc+sd-cwt</c> Key Binding Token whose protected header — the map
    /// carrying the embedded presentation SD-CWT under the <c>kcwt</c> (13) parameter per
    /// draft-ietf-spice-sd-cwt §7.1 — is truncated to half its byte length is a shape no
    /// conformant Wallet produces. The outer KBT COSE_Sign1 envelope stays structurally valid (its
    /// protected header is read as an opaque byte string, so <c>ParseCoseSign1</c> never inspects
    /// its content), but <see cref="SdCwtVpParsing.ExtractKcwt"/> — reading that content as CBOR —
    /// rejects the truncation and normalizes it to <see cref="FormatException"/> at its own public
    /// boundary, so the presentation is refused with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section
    /// 4.1.2.1</see>'s <c>invalid_request</c> as an HTTP 400 body (the Malformed refusal class)
    /// rather than surfacing as a Verifier fault.
    /// </summary>
    [TestMethod]
    public async Task ACorruptSdCwtKeyBindingTokenIsRefusedAsInvalidRequestNotServerError()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> issuerKeys =
            TestKeyMaterialProvider.CreateP256KeyMaterial();
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> holderKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();

        try
        {
            using SdToken<ReadOnlyMemory<byte>> issued = await SdCwtVpFixture.IssueSdCwtTokenAsync(
                TimeProvider, issuerKeys.PrivateKey, holderKeys.PublicKey, TestContext.CancellationToken)
                .ConfigureAwait(false);

            //Builds the real protected header (embedding the presentation SD-CWT under kcwt) and
            //truncates its bytes before the KBT is signed and serialized — the outer COSE_Sign1
            //array/lengths stay correct throughout, only the protected header's CBOR content is cut.
            BuildKbtProtectedHeaderDelegate truncateProtectedHeader = (coseAlgorithm, presentationToken, pool) =>
            {
                using EncodedCoseProtectedHeader validHeader =
                    SdKbtIssuance.BuildProtectedHeader(coseAlgorithm, presentationToken, pool);
                ReadOnlySpan<byte> validBytes = validHeader.AsReadOnlySpan();

                return EncodedCoseProtectedHeader.FromBytes(validBytes[..(validBytes.Length / 2)], pool);
            };

            using EncodedCoseSign1 corruptKbt = await KbCwtIssuance.IssueAsync(
                issued,
                holderKeys.PrivateKey,
                VerifierClientId,
                "nonce-sdcwt-corrupt-kbt",
                TimeProvider.GetUtcNow(),
                truncateProtectedHeader,
                SdKbtIssuance.BuildPayload,
                CoseSerialization.BuildSigStructure,
                CoseSerialization.SerializeCoseSign1,
                Pool,
                TestContext.CancellationToken).ConfigureAwait(false);

            string corruptVpTokenValue = TestSetup.Base64UrlEncoder(corruptKbt.AsReadOnlyMemory().Span);

            SdCwtVpVerificationSeams seams = SdCwtVpFixture.BuildSeams(issuerKeys.PublicKey);

            await using TestHostShell app = new(TimeProvider, sdCwtSeams: seams);
            using VerifierKeyMaterial verifierKeys = app.RegisterClient(
                VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

            (Uri _, string parHandle) = await app.HandleParAsync(
                verifierKeys,
                new TransactionNonce("nonce-sdcwt-corrupt-kbt-flow"),
                SdCwtVpFixture.BuildSdCwtPreparedQuery(),
                TestContext.CancellationToken).ConfigureAwait(false);

            _ = await app.HandleJarRequestAsync(
                verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

            string vpTokenJson = $$"""{"{{SdCwtVpFixture.EmployeeCwtCredentialQueryId}}":["{{corruptVpTokenValue}}"]}""";

            (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
                verifierKeys.Registration.TenantId.Value,
                [
                    new(AuthorizationResponseParameters.VpToken, vpTokenJson),
                    new(OAuthRequestParameterNames.State, parHandle)
                ],
                TestContext.CancellationToken).ConfigureAwait(false);

            Assert.AreEqual(400, statusCode,
                "RFC 6749 §4.1.2.1: a truncated SD-CWT Key Binding Token is answered as HTTP 400, not as an HTTP 500 Verifier fault.");
            Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
                "The RFC 6749 §4.1.2.1 error object is a JSON body.");

            (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
            Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
                "RFC 6749 §4.1.2.1: an otherwise malformed request is invalid_request.");
            AssertDescriptionCarriesNoContextualDetail(wireDescription);

            VerifierFlowFailedState failed = ReadFailedState(app, parHandle);
            Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
                "A truncated SD-CWT Key Binding Token protected header is the Malformed refusal class.");
        }
        finally
        {
            issuerKeys.PublicKey.Dispose();
            issuerKeys.PrivateKey.Dispose();
            holderKeys.PublicKey.Dispose();
            holderKeys.PrivateKey.Dispose();
        }
    }


    /// <summary>
    /// A credential whose Token Status List index lies outside the resolved list is refused:
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-8.3">Token
    /// Status List, Section 8.3</see> — "If the provided index is out of bounds of the Status List, no
    /// statement about the status of the Referenced Token can be made and the Referenced Token MUST be
    /// rejected." The wire answer is RFC 6749 §4.1.2.1's <c>invalid_request</c> as HTTP 400 with a description
    /// that reveals no cause, and the terminal state carries the undeterminable-status refusal class.
    /// </summary>
    [TestMethod]
    public async Task AnUndeterminableCredentialStatusIsRefusedAsInvalidRequestWithAGenericDescription()
    {
        const int outOfBoundsIndex = 999;

        using StatusListType statusList = StatusListType.Create(
            64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);

        await using TestHostShell app = new(
            TimeProvider, resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider));
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string parHandle, string compactJwe, PublicKeyMemory issuerPublicKey) = await DriveWalletToResponsePostAsync(
            app, verifierKeys, DcqlFixtures.PidFamilyNamePrepared(),
            status: new StatusListReference(outOfBoundsIndex, StatusListUri),
            nonce: "nonce-status-undeterminable").ConfigureAwait(false);

        using PublicKeyMemory issuerKey = issuerPublicKey;

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.Response, compactJwe),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "Token Status List §8.3: a status that cannot be determined rejects the Referenced Token, answered as RFC 6749 §4.1.2.1's HTTP 400.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "The RFC 6749 §4.1.2.1 error object is a JSON body.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: an undeterminable credential status is not a pass, so it is invalid_request.");
        AssertDescriptionCarriesNoContextualDetail(wireDescription);
        Assert.AreEqual(
            VerifierFlowRefusal.For(VerifierFlowRefusalKind.StatusUndeterminable).Description, wireDescription,
            "The StatusUndeterminable refusal class's one fixed, canonical wire sentence.");
        Assert.IsFalse(wireDescription.Contains("999", StringComparison.Ordinal),
            "OID4VP 1.0 §15.9: the wire description must not disclose the credential's Status List index.");

        VerifierFlowFailedState failed = ReadFailedState(app, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.StatusUndeterminable, failed.Refusal!.Value.Kind,
            "An out-of-bounds Status List index is the StatusUndeterminable refusal class.");
        Assert.IsNull(failed.CredentialStatusRefusal,
            "An undeterminable status yields no policy verdict — the typed status refusal is the policy's alone.");
    }


    /// <summary>
    /// A relying party whose policy refuses a determinable revoked credential answers RFC 6749 §4.1.2.1's
    /// <c>access_denied</c> — "The resource owner or authorization server denied the request." — as HTTP 400,
    /// while the detail (which credential query, status <c>0x01</c> "INVALID … revoked, annulled, taken back,
    /// recalled or cancelled" per
    /// <see href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-21#section-7.1">Token
    /// Status List, Section 7.1</see>) rides the terminal state and never the wire, per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 15.9</see>.
    /// </summary>
    [TestMethod]
    public async Task ARevokedCredentialRefusedByPolicyIsAnsweredAccessDeniedWithTheDetailOffTheWire()
    {
        const int credentialIndex = 42;

        using StatusListType statusList = StatusListType.Create(
            64, StatusListBitSize.OneBit, Pool, BitOrder.LeastSignificantFirst);
        statusList[credentialIndex] = StatusTypes.Invalid;

        await using TestHostShell app = new(
            TimeProvider,
            resolveVerifiedStatusListToken: StatusListFixtures.ResolverFor(StatusListUri, statusList, TimeProvider),
            credentialStatusPolicy: CredentialStatusPolicies.RefuseNotValid);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string parHandle, string compactJwe, PublicKeyMemory issuerPublicKey) = await DriveWalletToResponsePostAsync(
            app, verifierKeys, DcqlFixtures.PidFamilyNamePrepared(),
            status: new StatusListReference(credentialIndex, StatusListUri),
            nonce: "nonce-status-revoked").ConfigureAwait(false);

        using PublicKeyMemory issuerKey = issuerPublicKey;

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.Response, compactJwe),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "RFC 6749 §4.1.2.1: a relying-party refusal is answered with the error code as HTTP 400.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "The RFC 6749 §4.1.2.1 error object is a JSON body.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.AccessDenied, wireError,
            "RFC 6749 §4.1.2.1: a presentation the Verifier denies on authorization grounds is access_denied.");
        AssertDescriptionCarriesNoContextualDetail(wireDescription);
        Assert.AreEqual(
            VerifierFlowRefusal.For(VerifierFlowRefusalKind.PolicyRefused).Description, wireDescription,
            "The PolicyRefused refusal class's one fixed, canonical wire sentence.");
        Assert.IsFalse(wireDescription.Contains(CredentialStatusRefusal.ReasonCode, StringComparison.Ordinal),
            "OID4VP 1.0 §15.9: the machine-readable status reason is state and log detail, never the wire description.");
        Assert.IsFalse(wireDescription.Contains("0x01", StringComparison.OrdinalIgnoreCase),
            "OID4VP 1.0 §15.9: the wire description must not disclose the credential's raw status value.");
        Assert.IsFalse(wireDescription.Contains("revoked", StringComparison.OrdinalIgnoreCase),
            "OID4VP 1.0 §15.9: the wire description must not disclose the credential's status disposition.");

        VerifierFlowFailedState failed = ReadFailedState(app, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.PolicyRefused, failed.Refusal!.Value.Kind,
            "A status-policy refusal is the PolicyRefused refusal class.");
        Assert.AreEqual(OAuthErrors.AccessDenied, failed.Refusal!.Value.ErrorCode,
            "RFC 6749 §4.1.2.1: the PolicyRefused refusal's error code is access_denied.");

        CredentialStatusRefusal statusRefusal = failed.CredentialStatusRefusal!;
        Assert.IsNotNull(statusRefusal,
            "The relying party reads which credential its policy refused off the terminal state.");
        Assert.HasCount(1, statusRefusal.Credentials,
            "One presented credential was refused, so the typed refusal names exactly one.");
        Assert.AreEqual(PidCredentialQueryId, statusRefusal.Credentials[0].CredentialQueryId.Value,
            "The typed refusal is keyed by the DCQL credential query identifier the credential answered.");
        Assert.AreEqual(StatusTypes.Invalid, statusRefusal.Credentials[0].Outcome.Status,
            "Token Status List §7.1: 0x01 INVALID is the status the flipped bit reads as.");
        Assert.AreEqual(CredentialStatusDisposition.Revoked, statusRefusal.Credentials[0].Disposition,
            "Token Status List §7.1: 0x01 INVALID means the Referenced Token is revoked.");
        Assert.IsTrue(
            statusRefusal.Description.StartsWith(CredentialStatusRefusal.ReasonCode + ":", StringComparison.Ordinal),
            "The typed refusal opens with its machine-readable reason code so a state reader need not parse prose.");
    }


    /// <summary>
    /// A verified presentation is answered per
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 8.2</see>: "If the Response URI has successfully processed the Authorization
    /// Response or Authorization Error Response, it MUST respond with an HTTP status code of 200 with
    /// Content-Type of application/json and a JSON object in the response body." A deployment that configures
    /// no <c>redirect_uri</c> answers the empty JSON object, the <c>redirect_uri</c> member being OPTIONAL.
    /// </summary>
    [TestMethod]
    public async Task AVerifiedPresentationIsAnsweredTwoHundredWithAJsonObject()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string parHandle, string compactJwe, PublicKeyMemory issuerPublicKey) = await DriveWalletToResponsePostAsync(
            app, verifierKeys, DcqlFixtures.PidFamilyNamePrepared(), status: null,
            nonce: "nonce-verified-plain").ConfigureAwait(false);

        using PublicKeyMemory issuerKey = issuerPublicKey;

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.Response, compactJwe),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode,
            "OID4VP 1.0 §8.2: a successfully processed Authorization Response MUST be answered with HTTP 200.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "OID4VP 1.0 §8.2: the 200 answer carries Content-Type of application/json.");

        using JsonDocument answer = JsonDocument.Parse(body);
        Assert.AreEqual(JsonValueKind.Object, answer.RootElement.ValueKind,
            "OID4VP 1.0 §8.2: the 200 answer's body is a JSON object.");
        Assert.IsFalse(answer.RootElement.TryGetProperty(AuthorizationResponseParameters.RedirectUri, out JsonElement _),
            "OID4VP 1.0 §8.2: redirect_uri is OPTIONAL, so a deployment that configures none omits the member.");

        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "A presentation the Verifier accepted leaves the flow in its verified terminal state.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 8.2</see>: "redirect_uri: OPTIONAL. String containing a URI. When this
    /// parameter is present the Wallet MUST redirect the user agent to this URI." A deployment that configures
    /// one has it returned in the verified presentation's 200 JSON object.
    /// </summary>
    [TestMethod]
    public async Task AVerifiedPresentationCarriesTheConfiguredRedirectUriInIts200Answer()
    {
        Uri sameDeviceRedirectUri = new("https://verifier.example.com/complete?session=1f0c1c1d7a5b4e2f9a8c0d3b6e5f4a2c");

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string parHandle, string compactJwe, PublicKeyMemory issuerPublicKey) = await DriveWalletToResponsePostAsync(
            app, verifierKeys, DcqlFixtures.PidFamilyNamePrepared(), status: null,
            nonce: "nonce-verified-redirect").ConfigureAwait(false);

        using PublicKeyMemory issuerKey = issuerPublicKey;

        ServerHttpResponse response = await DispatchDirectPostAsync(
            app,
            verifierKeys,
            [
                new(OAuthRequestParameterNames.Response, compactJwe),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            sameDeviceRedirectUri).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "OID4VP 1.0 §8.2: a successfully processed Authorization Response MUST be answered with HTTP 200.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.ContentType,
            "OID4VP 1.0 §8.2: the 200 answer carries Content-Type of application/json.");
        Assert.AreEqual(sameDeviceRedirectUri.OriginalString, ReadRedirectUri(response.Body),
            "OID4VP 1.0 §8.2: the configured redirect_uri is returned in the Response Endpoint's JSON object.");

        Assert.IsInstanceOfType<PresentationVerifiedState>(app.GetFlowState(parHandle).State,
            "A presentation the Verifier accepted leaves the flow in its verified terminal state.");
    }


    /// <summary>
    /// The Wallet's Authorization Error Response — <c>error</c> plus <c>state</c>, the shape
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 8.2</see> gives as "error=invalid_request&amp; error_description=…&amp;
    /// state=…" — is successfully processed, so the Response URI "MUST respond with an HTTP status code of 200
    /// with Content-Type of application/json and a JSON object in the response body", and the Verifier records
    /// what the Wallet reported on its own terminal state.
    /// </summary>
    [TestMethod]
    public async Task AWalletAuthorizationErrorResponseIsRecordedAndAnsweredTwoHundred()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-wallet-error-jar-served"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.Error, OAuthErrors.AccessDenied),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode,
            "OID4VP 1.0 §8.2: a successfully processed Authorization Error Response MUST be answered with HTTP 200.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "OID4VP 1.0 §8.2: the 200 answer carries Content-Type of application/json.");

        using JsonDocument answer = JsonDocument.Parse(body);
        Assert.AreEqual(JsonValueKind.Object, answer.RootElement.ValueKind,
            "OID4VP 1.0 §8.2: the 200 answer's body is a JSON object.");

        VerifierWalletErrorReceivedState received = ReadWalletErrorState(app, parHandle);
        Assert.AreEqual(OAuthErrors.AccessDenied, received.Error,
            "The Verifier records the RFC 6749 §4.1.2.1 error code the Wallet reported.");
        Assert.IsNull(received.ErrorDescription,
            "RFC 6749 §4.1.2.1: error_description is OPTIONAL, so a Wallet that omits it leaves none recorded.");
    }


    /// <summary>
    /// The optional <c>error_description</c> of
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>
    /// ("OPTIONAL. Human-readable ASCII [USASCII] text providing additional information …") travels with the
    /// Wallet's Authorization Error Response and is recorded beside the error code. Proved on a flow that
    /// never served a JAR — the inline path of
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 5.9.3</see> — so the §8.2 error POST is processed from either state the
    /// Response URI can be reached in.
    /// </summary>
    [TestMethod]
    public async Task AWalletAuthorizationErrorResponseRecordsTheOptionalDescription()
    {
        const string walletErrorDescription = "The End-User declined to present the requested credential.";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-wallet-error-par-received"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.Error, OAuthErrors.AccessDenied),
                new(OAuthRequestParameterNames.ErrorDescription, walletErrorDescription),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(200, statusCode,
            "OID4VP 1.0 §8.2: a successfully processed Authorization Error Response MUST be answered with HTTP 200.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "OID4VP 1.0 §8.2: the 200 answer carries Content-Type of application/json.");

        using JsonDocument answer = JsonDocument.Parse(body);
        Assert.AreEqual(JsonValueKind.Object, answer.RootElement.ValueKind,
            "OID4VP 1.0 §8.2: the 200 answer's body is a JSON object.");

        VerifierWalletErrorReceivedState received = ReadWalletErrorState(app, parHandle);
        Assert.AreEqual(OAuthErrors.AccessDenied, received.Error,
            "The Verifier records the RFC 6749 §4.1.2.1 error code the Wallet reported.");
        Assert.AreEqual(walletErrorDescription, received.ErrorDescription,
            "The Verifier records the Wallet's optional RFC 6749 §4.1.2.1 error_description beside the code.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 8.2</see>: "The Response URI MAY return the redirect_uri parameter in
    /// response to successful Authorization Responses or for Error Responses." A deployment that configures
    /// one has it returned in the processed Wallet error response's 200 JSON object too.
    /// </summary>
    [TestMethod]
    public async Task AProcessedWalletAuthorizationErrorResponseCarriesTheConfiguredRedirectUri()
    {
        Uri sameDeviceRedirectUri = new("https://verifier.example.com/complete?session=9b3d7e6c5a4f2108d3c7b6a59e8f4d21");

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-wallet-error-redirect"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        ServerHttpResponse response = await DispatchDirectPostAsync(
            app,
            verifierKeys,
            [
                new(OAuthRequestParameterNames.Error, OAuthErrors.AccessDenied),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            sameDeviceRedirectUri).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "OID4VP 1.0 §8.2: a successfully processed Authorization Error Response MUST be answered with HTTP 200.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.ContentType,
            "OID4VP 1.0 §8.2: the 200 answer carries Content-Type of application/json.");
        Assert.AreEqual(sameDeviceRedirectUri.OriginalString, ReadRedirectUri(response.Body),
            "OID4VP 1.0 §8.2: the Response URI MAY return redirect_uri for Error Responses, and a configured one is returned.");

        VerifierWalletErrorReceivedState received = ReadWalletErrorState(app, parHandle);
        Assert.AreEqual(sameDeviceRedirectUri, received.RedirectUri,
            "The redirect_uri the Wallet is told to follow is the one recorded on the Verifier's terminal state.");
    }


    /// <summary>
    /// An Authorization Error Response POST that omits <c>state</c> cannot be correlated to a flow, so the
    /// Response URI never processes it as one: it is not answered with the HTTP 200 that
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 8.2</see> reserves for a successfully processed Authorization Response or
    /// Authorization Error Response, and the flow stays where it was.
    /// </summary>
    [TestMethod]
    public async Task AnErrorPostWithoutStateIsNotProcessedAsAnAuthorizationErrorResponse()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-error-without-state"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string _, string? _) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [new(OAuthRequestParameterNames.Error, OAuthErrors.AccessDenied)],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(200, statusCode,
            "OID4VP 1.0 §8.2: HTTP 200 answers a successfully processed Authorization Error Response, and an uncorrelatable POST is not one.");
        Assert.AreEqual(404, statusCode,
            "No Response URI shape matches a POST without state, so the request reaches no Response URI handler at all.");
        Assert.IsInstanceOfType<VerifierJarServedState>(app.GetFlowState(parHandle).State,
            "A POST the Response URI never processed leaves the flow untouched.");
    }


    /// <summary>
    /// A POST that carries <c>state</c> but neither a presentation (<c>response</c> or <c>vp_token</c>) nor an
    /// <c>error</c> is neither of the two shapes
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 8.2</see> defines, so it is not processed as a presentation and never
    /// answered with the 200 that section reserves.
    /// </summary>
    [TestMethod]
    public async Task APostCarryingNeitherAPresentationNorAnErrorIsNotProcessed()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-state-only"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string _, string? _) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [new(OAuthRequestParameterNames.State, parHandle)],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreNotEqual(200, statusCode,
            "OID4VP 1.0 §8.2: HTTP 200 answers a successfully processed Authorization Response or Authorization Error Response, and a bare state POST is neither.");
        Assert.AreEqual(404, statusCode,
            "No Response URI shape matches a POST carrying neither a presentation nor an error, so the request reaches no Response URI handler at all.");
        Assert.IsInstanceOfType<VerifierJarServedState>(app.GetFlowState(parHandle).State,
            "A POST the Response URI never processed leaves the flow untouched.");
    }


    /// <summary>
    /// A failure the Verifier cannot classify for the client — a terminal failure carrying no typed refusal —
    /// is not an <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section
    /// 4.1.2.1</see> client error but the section's <c>server_error</c>: "The authorization server
    /// encountered an unexpected condition that prevented it from fulfilling the request." Every
    /// <c>direct_post</c> endpoint candidate answers such a state with HTTP 500, so 500 stays reserved for a
    /// genuine Verifier fault and never answers a refusal.
    /// </summary>
    [TestMethod]
    public async Task AStateTheResponseEndpointCannotClassifyIsAnsweredServerError()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        ExchangeContext context = new();
        context.SetTenantId(verifierKeys.Registration.TenantId);

        EndpointChain chain = await app.GetEndpointsAsync(verifierKeys.Registration, context)
            .ConfigureAwait(false);

        DateTimeOffset now = TimeProvider.GetUtcNow();
        VerifierFlowFailedState unclassified = new()
        {
            FlowId = "flow-unclassified",
            ExpectedIssuer = VerifierClientId,
            EnteredAt = now,
            ExpiresAt = now.AddMinutes(5),
            Kind = FlowKind.Oid4VpVerifierServer,
            Reason = "A Verifier-side fault carrying no client-safe classification.",
            FailedAt = now
        };

        int directPostCandidates = 0;
        foreach(ServerEndpoint endpoint in chain)
        {
            if(!string.Equals(endpoint.Name, WellKnownEndpointNames.Oid4VpDirectPost, StringComparison.Ordinal))
            {
                continue;
            }

            directPostCandidates++;

            ServerHttpResponse response = endpoint.BuildResponse(
                unclassified, FlowKind.Oid4VpVerifierServer.Name, context);

            Assert.AreEqual(500, response.StatusCode,
                "RFC 6749 §4.1.2.1: an unexpected condition is server_error, answered as HTTP 500.");
            Assert.AreEqual(WellKnownMediaTypes.Application.Json, response.ContentType,
                "The RFC 6749 §4.1.2.1 error object is a JSON body.");

            (string wireError, string _) = OAuthErrorAssertions.ReadOAuthErrorBody(response.Body);
            Assert.AreEqual(OAuthErrors.ServerError, wireError,
                "RFC 6749 §4.1.2.1: a failure the Verifier cannot classify for the client is server_error.");
        }

        Assert.AreNotEqual(0, directPostCandidates,
            "The Response URI must expose at least one direct_post candidate for this assertion to mean anything.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>:
    /// "Values for the <c>error_description</c> parameter MUST NOT include characters outside the set %x20-21 /
    /// %x23-5B / %x5D-7E." A refusal carrying a character outside that set cannot be constructed, so no
    /// producer can put one on the wire.
    /// </summary>
    /// <param name="description">A description carrying one character the set excludes.</param>
    [TestMethod]
    [DataRow("back\\slash", DisplayName = "reverse solidus %x5C")]
    [DataRow("Ä-umlaut", DisplayName = "non-ASCII above %x7E")]
    [DataRow("delete\u007F", DisplayName = "control character %x7F")]
    [DataRow("line\nbreak", DisplayName = "control character %x0A")]
    public void ARefusalDescriptionOutsideTheRfc6749CharacterSetCannotBeConstructed(string description)
    {
        Assert.ThrowsExactly<ArgumentException>(
            () => _ = new VerifierFlowRefusal(VerifierFlowRefusalKind.Unverifiable, description),
            "RFC 6749 §4.1.2.1: error_description MUST NOT include characters outside %x20-21 / %x23-5B / %x5D-7E.");
    }


    /// <summary>
    /// Every refusal class the Response URI can answer with carries a description inside
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>%x20-21 / %x23-5B / %x5D-7E</c> set, so the wire body holds the character rule by construction for
    /// every answer the endpoint can write.
    /// </summary>
    /// <param name="kind">The refusal class whose canonical description is checked.</param>
    [TestMethod]
    [DataRow(VerifierFlowRefusalKind.Malformed)]
    [DataRow(VerifierFlowRefusalKind.Unverifiable)]
    [DataRow(VerifierFlowRefusalKind.PolicyRefused)]
    [DataRow(VerifierFlowRefusalKind.StatusUndeterminable)]
    public void EveryRefusalClassCarriesADescriptionInsideTheRfc6749CharacterSet(VerifierFlowRefusalKind kind)
    {
        VerifierFlowRefusal refusal = VerifierFlowRefusal.For(kind);

        Assert.IsFalse(string.IsNullOrWhiteSpace(refusal.Description),
            "RFC 6749 §4.1.2.1's error_description is the human-readable text a refused client reads.");

        foreach(char character in refusal.Description)
        {
            bool isInsideTheSet = character is
                (>= '\x20' and <= '\x21') or
                (>= '\x23' and <= '\x5B') or
                (>= '\x5D' and <= '\x7E');

            Assert.IsTrue(isInsideTheSet,
                $"RFC 6749 §4.1.2.1: error_description MUST NOT include characters outside %x20-21 / %x23-5B / %x5D-7E, but U+{(int)character:X4} is.");
        }
    }


    /// <summary>
    /// A <c>response</c> form field larger than
    /// <see cref="JweParsing.MaxCompactJweByteCount"/> is a shape no conformant Wallet produces for this
    /// deployment's advertised bound — the same Wallet-attributable Malformed classification an undecodable
    /// or unparseable response carries — so it is refused with
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>invalid_request</c> as an HTTP 400 body rather than the caller-contract
    /// <see cref="ArgumentException"/> <see cref="JweParsing.ParseCompact"/> itself throws for the same
    /// condition.
    /// </summary>
    [TestMethod]
    public async Task AnOversizedEncryptedResponseIsRefusedAsInvalidRequestNotServerError()
    {
        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-oversized-jwe"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        //Five dot-separated segments (a structurally compact-JWE-shaped string) whose total length exceeds
        //the bound by one byte — oversized before any structural or cryptographic check runs.
        int segmentLength = (JweParsing.MaxCompactJweByteCount / 4) + 1;
        string segment = new('A', segmentLength);
        string oversizedResponse = string.Join('.', segment, segment, segment, segment, segment);

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.Response, oversizedResponse),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "RFC 6749 §4.1.2.1: an over-sized Authorization Response is a malformed request, answered as HTTP 400, not as an HTTP 500 Verifier fault.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "The RFC 6749 §4.1.2.1 error object is a JSON body.");

        (string wireError, string wireDescription) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: an otherwise malformed request is invalid_request.");
        Assert.AreEqual(
            VerifierFlowRefusal.For(VerifierFlowRefusalKind.Malformed).Description, wireDescription,
            "An over-sized compact JWE is answered with the Malformed refusal class's canonical wire sentence.");

        VerifierFlowFailedState failed = ReadFailedState(app, parHandle);
        Assert.AreEqual(VerifierFlowRefusalKind.Malformed, failed.Refusal!.Value.Kind,
            "An over-sized compact JWE is the Malformed refusal class.");
    }


    /// <summary>
    /// <see href="https://openid.net/specs/openid-4-verifiable-presentations-1_0.html">OpenID for Verifiable
    /// Presentations 1.0, Section 8.2</see>: "The Response URI MAY return the redirect_uri parameter in
    /// response to successful Authorization Responses." A deployment-configured <c>redirect_uri</c> carrying
    /// a percent-encoded quote and a percent-encoded reverse solidus round-trips through the 200 answer as
    /// its exact configured <see cref="Uri.OriginalString"/> rather than the un-escaped form
    /// <see cref="Uri.ToString"/> would interpolate — which would break the JSON string literal.
    /// </summary>
    [TestMethod]
    public async Task AVerifiedPresentationEscapesAPercentEncodedQuoteInTheConfiguredRedirectUri()
    {
        Uri redirectUriWithReservedCharacters = new(
            "https://verifier.example.com/complete?session=%22x%22%20%5Cy", UriKind.Absolute);

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (string parHandle, string compactJwe, PublicKeyMemory issuerPublicKey) = await DriveWalletToResponsePostAsync(
            app, verifierKeys, DcqlFixtures.PidFamilyNamePrepared(), status: null,
            nonce: "nonce-verified-redirect-escaped").ConfigureAwait(false);

        using PublicKeyMemory issuerKey = issuerPublicKey;

        ServerHttpResponse response = await DispatchDirectPostAsync(
            app,
            verifierKeys,
            [
                new(OAuthRequestParameterNames.Response, compactJwe),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            redirectUriWithReservedCharacters).ConfigureAwait(false);

        Assert.AreEqual(200, response.StatusCode,
            "OID4VP 1.0 §8.2: a successfully processed Authorization Response MUST be answered with HTTP 200.");

        using JsonDocument answer = JsonDocument.Parse(response.Body);
        Assert.AreEqual(JsonValueKind.Object, answer.RootElement.ValueKind,
            "A percent-encoded quote in the configured redirect_uri must not break the 200 body's JSON shape.");
        Assert.AreEqual(
            redirectUriWithReservedCharacters.OriginalString,
            ReadRedirectUri(response.Body),
            "The redirect_uri member carries the deployment's exact configured OriginalString, not Uri.ToString()'s un-escaped form.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>'s
    /// <c>error</c> character rule ("MUST NOT include characters outside the set %x20-21 / %x23-5B /
    /// %x5D-7E") applies to a Wallet's own Authorization Error Response POST too: an <c>error</c> value
    /// carrying a double quote makes the POST itself malformed rather than one §8.2's 200 counts as
    /// successfully processed.
    /// </summary>
    [TestMethod]
    public async Task AWalletErrorContainingAQuoteIsRefusedAsInvalidRequest()
    {
        const string ErrorWithQuote = "access_denied\"";

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-wallet-error-quote"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.Error, ErrorWithQuote),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "A Wallet Authorization Error Response violating RFC 6749 §4.1.2.1's error character rule is "
            + "not successfully processed, so it is not answered with §8.2's 200.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "The RFC 6749 §4.1.2.1 error object is a JSON body.");

        (string wireError, string _) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: a malformed request is invalid_request.");

        Assert.IsInstanceOfType<VerifierJarServedState>(app.GetFlowState(parHandle).State,
            "A malformed Wallet error POST is rejected before it reaches VerifierWalletErrorReceivedState.");
    }


    /// <summary>
    /// <see href="https://www.rfc-editor.org/rfc/rfc6749#section-4.1.2.1">RFC 6749, Section 4.1.2.1</see>
    /// sets no length limit on <c>error_description</c>; the library's own storage bound protects the flow
    /// store from an unbounded value riding the terminal state for the flow's lifetime, so a value exceeding
    /// it makes the Wallet's Authorization Error Response POST itself malformed rather than one §8.2's 200
    /// counts as successfully processed.
    /// </summary>
    [TestMethod]
    public async Task AnOverLongWalletErrorDescriptionIsRefusedAsInvalidRequest()
    {
        string overLongErrorDescription = new('a', 1025);

        await using TestHostShell app = new(TimeProvider);
        using VerifierKeyMaterial verifierKeys = app.RegisterClient(
            VerifierClientId, VerifierBaseUri, Oid4VpCapabilities);

        (Uri _, string parHandle) = await app.HandleParAsync(
            verifierKeys,
            new TransactionNonce("nonce-wallet-error-overlong-description"),
            DcqlFixtures.PidFamilyNamePrepared(),
            TestContext.CancellationToken).ConfigureAwait(false);

        _ = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        (int statusCode, string body, string? contentType) = await app.PostDirectPostFormAsync(
            verifierKeys.Registration.TenantId.Value,
            [
                new(OAuthRequestParameterNames.Error, OAuthErrors.AccessDenied),
                new(OAuthRequestParameterNames.ErrorDescription, overLongErrorDescription),
                new(OAuthRequestParameterNames.State, parHandle)
            ],
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(400, statusCode,
            "A Wallet Authorization Error Response whose error_description exceeds the library's storage "
            + "bound is not successfully processed, so it is not answered with §8.2's 200.");
        Assert.AreEqual(WellKnownMediaTypes.Application.Json, contentType,
            "The RFC 6749 §4.1.2.1 error object is a JSON body.");

        (string wireError, string _) = OAuthErrorAssertions.ReadOAuthErrorBody(body);
        Assert.AreEqual(OAuthErrors.InvalidRequest, wireError,
            "RFC 6749 §4.1.2.1: a malformed request is invalid_request.");

        Assert.IsInstanceOfType<VerifierJarServedState>(app.GetFlowState(parHandle).State,
            "A malformed Wallet error POST is rejected before it reaches VerifierWalletErrorReceivedState.");
    }


    /// <summary>
    /// Runs a Wallet through PAR, the JAR request and presentation building against
    /// <paramref name="app"/>, and answers the flow's <c>state</c> handle together with the compact JWE the
    /// Wallet would POST to the Response URI. The POST itself is the caller's, so it reads the Response URI's
    /// own answer off the wire.
    /// </summary>
    /// <param name="app">The Verifier host the flow runs against.</param>
    /// <param name="verifierKeys">The registered Verifier's key material.</param>
    /// <param name="query">The prepared DCQL query the Authorization Request carries.</param>
    /// <param name="status">The Status List entry the presented credential references, or none.</param>
    /// <param name="nonce">The transaction nonce the Authorization Request binds the presentation to.</param>
    /// <returns>
    /// The flow's <c>state</c> handle, the compact JWE Authorization Response, and the issuer public key the
    /// Verifier's trust store now holds — the caller owns and disposes that key after the POST it drives.
    /// </returns>
    private async Task<(string ParHandle, string CompactJwe, PublicKeyMemory IssuerPublicKey)> DriveWalletToResponsePostAsync(
        TestHostShell app,
        VerifierKeyMaterial verifierKeys,
        PreparedDcqlQuery query,
        StatusListReference? status,
        string nonce)
    {
        (string serializedSdJwt, PrivateKeyMemory holderPrivateKey, PublicKeyMemory issuerPublicKey) =
            await SdJwtVpFixture.IssuePidCredentialWithClaimsAsync(
                TimeProvider, "Alice", "Smith", IssuerId, IssuerKeyId, Pool, status,
                TestContext.CancellationToken).ConfigureAwait(false);

        using PrivateKeyMemory holderKey = holderPrivateKey;
        app.RegisterIssuerTrust(IssuerId, issuerPublicKey);

        (Uri requestUri, string parHandle) = await app.HandleParAsync(
            verifierKeys, new TransactionNonce(nonce), query,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJar = await app.HandleJarRequestAsync(
            verifierKeys, parHandle, TestContext.CancellationToken).ConfigureAwait(false);

        TestWallet wallet = new(
            VerifierClientId,
            new Dictionary<string, string> { [PidCredentialQueryId] = serializedSdJwt },
            holderKey,
            TimeProvider);

        string walletFlowId = $"wallet-{nonce}";
        wallet.HandleQrScan(requestUri, walletFlowId);

        await wallet.HandleJarFetchAsync(
            walletFlowId, requestUri, compactJar, verifierKeys.SigningPublicKey,
            TestContext.CancellationToken).ConfigureAwait(false);

        string compactJwe = await wallet.HandleResponsePostAsync(
            walletFlowId, TestContext.CancellationToken).ConfigureAwait(false);

        return (parHandle, compactJwe, issuerPublicKey);
    }


    /// <summary>
    /// Dispatches a <c>direct_post</c> body at the Response URI with a deployment-configured
    /// <c>redirect_uri</c> on the exchange context, and answers what the Response URI wrote. The configured
    /// <c>redirect_uri</c> is an application-supplied value rather than a request field, so it reaches the
    /// endpoint through the context the way a deployment's own skin supplies it.
    /// </summary>
    /// <param name="app">The Verifier host the request is dispatched against.</param>
    /// <param name="verifierKeys">The registered Verifier's key material.</param>
    /// <param name="formFields">The Response URI POST body, sent verbatim.</param>
    /// <param name="redirectUri">The <c>redirect_uri</c> the deployment configured.</param>
    /// <returns>The response the Response URI composed.</returns>
    private async Task<ServerHttpResponse> DispatchDirectPostAsync(
        TestHostShell app,
        VerifierKeyMaterial verifierKeys,
        IReadOnlyCollection<KeyValuePair<string, string>> formFields,
        Uri redirectUri)
    {
        string segment = verifierKeys.Registration.TenantId.Value;

        ExchangeContext context = new();
        context.SetTenantId(verifierKeys.Registration.TenantId);
        context.SetOid4VpRedirectUri(redirectUri);

        RequestFields fields = new();
        foreach(KeyValuePair<string, string> field in formFields)
        {
            fields[field.Key] = field.Value;
        }

        IncomingRequest request = new(
            Path: TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.Oid4VpDirectPost, segment),
            Method: WellKnownHttpMethods.Post,
            Fields: fields,
            Headers: RequestHeaders.Empty,
            RouteValues: RouteValues.Empty);

        return await app.DispatchBySegmentAsync(
            segment, request, context, TestContext.CancellationToken).ConfigureAwait(false);
    }


    /// <summary>Base64url-encodes (no padding) the UTF-8 bytes of <paramref name="value"/>.</summary>
    /// <param name="value">The text to encode as one compact-JWS-shaped segment.</param>
    private static string Base64UrlEncodeUtf8(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');


    /// <summary>
    /// Reads the <c>redirect_uri</c> member of the Response URI's 200 JSON object, failing the test when the
    /// body does not carry one.
    /// </summary>
    /// <param name="body">The 200 response body the Response URI wrote.</param>
    /// <returns>The <c>redirect_uri</c> value.</returns>
    private static string ReadRedirectUri(string body)
    {
        using JsonDocument document = JsonDocument.Parse(body);

        Assert.AreEqual(JsonValueKind.Object, document.RootElement.ValueKind,
            "OID4VP 1.0 §8.2: the 200 answer's body is a JSON object.");
        Assert.IsTrue(
            document.RootElement.TryGetProperty(
                AuthorizationResponseParameters.RedirectUri, out JsonElement redirectUri),
            "OID4VP 1.0 §8.2: a configured redirect_uri is returned as a member of that object.");

        return redirectUri.GetString()!;
    }


    /// <summary>
    /// Asserts a wire <c>error_description</c> discloses none of the contextual detail OID4VP 1.0 §15.9 keeps
    /// out of an error response, and holds RFC 6749 §4.1.2.1's character rule.
    /// </summary>
    /// <param name="description">The description the Response URI wrote.</param>
    private static void AssertDescriptionCarriesNoContextualDetail(string description)
    {
        Assert.IsFalse(string.IsNullOrWhiteSpace(description),
            "RFC 6749 §4.1.2.1's error_description is the human-readable text a refused client reads.");
        Assert.IsFalse(description.Contains(PidCredentialQueryId, StringComparison.OrdinalIgnoreCase),
            "OID4VP 1.0 §15.9: the wire description must not name the credential query the refusal concerns.");
        Assert.IsFalse(description.Contains(IssuerId, StringComparison.OrdinalIgnoreCase),
            "OID4VP 1.0 §15.9: the wire description must not name the credential's issuer.");

        foreach(char character in description)
        {
            bool isInsideTheSet = character is
                (>= '\x20' and <= '\x21') or
                (>= '\x23' and <= '\x5B') or
                (>= '\x5D' and <= '\x7E');

            Assert.IsTrue(isInsideTheSet,
                $"RFC 6749 §4.1.2.1: error_description MUST NOT include characters outside %x20-21 / %x23-5B / %x5D-7E, but U+{(int)character:X4} is.");
        }
    }


    /// <summary>Reads the Verifier's terminal failure state for <paramref name="parHandle"/>.</summary>
    /// <param name="app">The Verifier host the flow ran against.</param>
    /// <param name="parHandle">The flow's <c>state</c> handle.</param>
    /// <returns>The terminal failure state carrying the typed refusal.</returns>
    private static VerifierFlowFailedState ReadFailedState(TestHostShell app, string parHandle)
    {
        FlowState state = app.GetFlowState(parHandle).State;

        Assert.IsInstanceOfType<VerifierFlowFailedState>(state,
            "A refused presentation leaves the Verifier's flow in its terminal failure state.");

        var failed = (VerifierFlowFailedState)state;
        Assert.IsNotNull(failed.Refusal,
            "A refusal the Response URI answers as RFC 6749 §4.1.2.1 carries its typed classification on the state.");

        return failed;
    }


    /// <summary>Reads the Verifier's terminal Wallet-error state for <paramref name="parHandle"/>.</summary>
    /// <param name="app">The Verifier host the flow ran against.</param>
    /// <param name="parHandle">The flow's <c>state</c> handle.</param>
    /// <returns>The terminal state recording what the Wallet reported.</returns>
    private static VerifierWalletErrorReceivedState ReadWalletErrorState(TestHostShell app, string parHandle)
    {
        FlowState state = app.GetFlowState(parHandle).State;

        Assert.IsInstanceOfType<VerifierWalletErrorReceivedState>(state,
            "OID4VP 1.0 §8.2: a processed Authorization Error Response is recorded on the Verifier's flow.");

        return (VerifierWalletErrorReceivedState)state;
    }


    /// <summary>
    /// A DCQL query under this class's credential query identifier asking for a claim the issued PID does not
    /// carry, so the presentation the Wallet builds cannot satisfy it.
    /// </summary>
    /// <returns>The prepared query no presentation of the fixture's PID satisfies.</returns>
    private static PreparedDcqlQuery CreateQueryRequestingAnAbsentClaim() =>
        DcqlPreparer.Prepare(new DcqlQuery
        {
            Credentials =
            [
                new CredentialQuery
                {
                    Id = PidCredentialQueryId,
                    Format = DcqlCredentialFormats.SdJwt,
                    Meta = new CredentialQueryMeta { VctValues = [EudiPid.SdJwtVct] },
                    Claims = [ClaimsQuery.ForPath([EudiPid.SdJwt.PhoneNumber])]
                }
            ]
        });
}
