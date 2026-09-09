using Microsoft.Extensions.Time.Testing;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
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
    /// authorize GET, the callback, the token exchange, and the token spent on nonce, proof, and
    /// Credential Request. The authorization seam sees the pushed details, the issuance seam
    /// verifies the holder proof, and the wallet holds the minted credential.
    /// </summary>
    [TestMethod]
    public async Task ParPkceAuthorizationCodeJourneyEndsInAnIssuedCredential()
    {
        await using TestHostShell host = new(TimeProvider);
        using VerifierKeyMaterial material = host.RegisterDpopClient(
            ClientId, ClientBaseUri, PolicyProfile.Rfc6749WithPkce, Capabilities);

        //OID4VCI 1.0 section 13.10: a plain-bearer credential token stays within the
        //long-lived threshold (lifetimes over 5 minutes count as long lived).
        host.SetAccessTokenLifetime(material, TimeSpan.FromMinutes(5));
        host.Server.OAuth().UseDefaultAuthorizationDetailsJsonParsing();

        IReadOnlyList<CredentialAuthorizationDetail>? grantedDetails = null;
        host.Server.OAuth().ResolveCredentialAuthorizationAsync =
            (details, subject, registration, context, ct) =>
            {
                grantedDetails = details;

                return ValueTask.FromResult(CredentialAuthorizationDecision.Grant(
                [
                    new GrantedCredentialAuthorization
                    {
                        CredentialConfigurationId = details[0].CredentialConfigurationId!,
                        CredentialIdentifiers = [CredentialIdentifier]
                    }
                ]));
            };

        IssuerSeamObservations observations = WireCredentialSeams(host);

        (OAuthClient client, ClientRegistration registration, Dictionary<string, FlowState> clientFlowStore) =
            await host.CreateOAuthClientAndRegistrationAsync(
                material.Registration,
                RedirectUri.OriginalString,
                PolicyProfile.Rfc6749WithPkce,
                TestContext.CancellationToken).ConfigureAwait(false);

        //Section 5.1.1: the wallet-composed authorization_details and the offer's issuer_state ride
        //the pushed request as additional fields; PKCE and state are the auth-code client's own.
        OAuthFormEncodedFields authorizationFields = new(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.AuthorizationDetails] =
                CredentialAuthorizationDetailComposition.Compose(ConfigurationId, material.Registration.IssuerUri),
            [OAuthRequestParameterNames.IssuerState] = IssuerState
        });

        AuthCodeFlowEndpointResult parResult = await client.AuthCode.StartParAsync(
            registration, RedirectUri, authorizationFields, new ExchangeContext(), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Redirect, parResult.Outcome,
            $"PAR must redirect over the real wire. ErrorCode={parResult.ErrorCode} ErrorDescription={parResult.ErrorDescription}");

        string flowId = clientFlowStore.Keys.Single();
        ParCompletedState parState = (ParCompletedState)clientFlowStore[flowId];
        await client.Infrastructure.SaveStateAsync(parState, new ExchangeContext(), TestContext.CancellationToken)
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
            registration, flowId, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(AuthCodeFlowEndpointOutcome.Ok, tokenResult.Outcome,
            $"Token exchange must succeed. ErrorCode={tokenResult.ErrorCode} ErrorDescription={tokenResult.ErrorDescription}");

        string accessToken = (string)tokenResult.Body![OAuthRequestParameterNames.AccessToken];
        string tokenType = tokenResult.Body.TryGetValue(OAuthRequestParameterNames.TokenType, out object? typeValue)
            ? (string)typeValue
            : WellKnownAuthenticationSchemes.Bearer;

        var holderKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory holderPublic = holderKeys.PublicKey;
        using PrivateKeyMemory holderPrivate = holderKeys.PrivateKey;

        Oid4VciWalletClient walletClient = BuildWalletClient(host);
        CredentialIssuanceResult issued = await walletClient.IssueWithAccessTokenDetailedAsync(
            accessToken,
            tokenType,
            material.Registration.IssuerUri!,
            ConfigurationId,
            holderPrivate,
            holderPublic,
            ResolveEndpoints(host, material),
            responseEncryption: null,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.HasCount(1, issued.Credentials, "The auth-code journey must end in exactly the one requested credential.");
        Assert.AreEqual(IssuedCredential, issued.Credentials[0],
            "The wallet must hold the credential the issuer minted over the wire.");
        Assert.IsTrue(observations.IsProofVerified,
            "The issuance seam must have verified the holder proof signature and its c_nonce.");
        Assert.AreEqual(material.Registration.IssuerUri!.OriginalString, observations.ProofAudience,
            "The minted proof must carry the Credential Issuer identifier as aud.");
        Assert.IsNotNull(grantedDetails);
        Assert.AreEqual(ConfigurationId, grantedDetails![0].CredentialConfigurationId,
            "The authorization seam must have received the wallet-composed details.");
    }


    /// <summary>Observations the issuance seam records for the assertions.</summary>
    private sealed class IssuerSeamObservations
    {
        /// <summary>Whether the seam verified the holder proof signature and its c_nonce.</summary>
        public bool IsProofVerified { get; set; }

        /// <summary>The <c>aud</c> the verified proof carried.</summary>
        public string? ProofAudience { get; set; }
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

        using HttpClientHandler noRedirectHandler = LoopbackTls.CreatePinnedHandler(pinnedCertificate);
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


    //Wires the issuance seams with real work: c_nonce minting and section 8 issuance that verifies
    //the holder proof signature + its c_nonce before issuing the opaque credential. The
    //pre-authorized-code seam stays unwired: this journey's authorization is the code grant.
    private static IssuerSeamObservations WireCredentialSeams(TestHostShell host)
    {
        IssuerSeamObservations observations = new();
        string? mintedNonce = null;

        host.Server.OAuth().UseDefaultCredentialRequestJsonParsing();

        host.Server.OAuth().IssueCredentialNonceAsync = (_, _) =>
        {
            mintedNonce = $"c-nonce-{Guid.NewGuid():N}";

            return ValueTask.FromResult(mintedNonce);
        };

        host.Server.OAuth().IssueCredentialAsync = async (request, _, _, _, ct) =>
        {
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
            jwk!, Pool, TestSetup.Base64UrlDecoder);
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
            SendFormPost = (endpoint, formFields, ct) => SendFormPostAsync(httpClient, endpoint, formFields, ct),
            SendJsonPost = (endpoint, body, headers, ct) => SendJsonPostAsync(httpClient, endpoint, body, headers, ct),
            JwtHeaderSerializer = HeaderSerializer,
            JwtPayloadSerializer = PayloadSerializer,
            Base64UrlEncoder = TestSetup.Base64UrlEncoder,
            TimeProvider = TimeProvider,
            MemoryPool = Pool
        };

        return new Oid4VciWalletClient(configuration);
    }


    //HttpClient form-POST transport (unused by this journey's issuance leg, wired for completeness).
    private static async ValueTask<(int StatusCode, string Body)> SendFormPostAsync(
        HttpClient httpClient,
        Uri endpoint,
        IReadOnlyDictionary<string, string> formFields,
        CancellationToken cancellationToken)
    {
        using FormUrlEncodedContent content = new(formFields);
        using HttpResponseMessage response = await httpClient.PostAsync(
            endpoint, content, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);

        return ((int)response.StatusCode, body);
    }


    //HttpClient JSON-POST transport for the Nonce and Credential Requests, attaching the
    //wallet-composed authorization headers and surfacing the response Content-Type.
    private static async ValueTask<(int StatusCode, string Body, string? ContentType)> SendJsonPostAsync(
        HttpClient httpClient,
        Uri endpoint,
        string jsonBody,
        IReadOnlyDictionary<string, string> headers,
        CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Post, endpoint);

        //The Nonce Request carries no body; only the Credential Request has one.
        if(jsonBody.Length > 0)
        {
            request.Content = new StringContent(jsonBody, Encoding.UTF8, WellKnownMediaTypes.Application.Json);
        }
        else
        {
            request.Content = new ByteArrayContent([]);
        }

        foreach(KeyValuePair<string, string> header in headers)
        {
            request.Headers.TryAddWithoutValidation(header.Key, header.Value);
        }

        using HttpResponseMessage response = await httpClient.SendAsync(
            request, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        string? contentType = response.Content.Headers.ContentType?.MediaType;

        return ((int)response.StatusCode, body, contentType);
    }
}
