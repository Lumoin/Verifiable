using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.OutboundFetch;
using Verifiable.Cryptography;
using Verifiable.Cryptography.Context;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Microsoft;
using Verifiable.OAuth;
using Verifiable.OAuth.AuthCode;
using Verifiable.OAuth.Client;
using Verifiable.OAuth.Dpop;
using Verifiable.OAuth.IdJag;
using Verifiable.OAuth.JwtBearer;
using Verifiable.OAuth.ProtectedResource;
using Verifiable.OAuth.Server;
using Verifiable.OAuth.Server.Pipeline;
using Verifiable.OAuth.TokenExchange;
using Verifiable.Server;
using Verifiable.Server.Diagnostics;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// The AIIM/Gartner interop event's composed agentic scenario as one real-wire E2E capstone:
/// one OAuth client (the "MCP client" — no MCP JSON-RPC framing anywhere; that composition is
/// app-side) drives RFC 9728 discovery at a resource server, RFC 8414 discovery and a CIMD
/// (draft-ietf-oauth-client-id-metadata-document-02) authorization-code + PKCE + OIDC flow at
/// one authorization server, an ID-JAG mint (draft-ietf-oauth-identity-assertion-authz-grant-04
/// §4.3) whose subject token is the REAL step-3 <c>id_token</c>, a cross-trust-domain redeem
/// (§4.4) at a second authorization server that knows the client ONLY through its Client ID
/// Metadata Document, and finally both protected resources — across six simultaneous Kestrel
/// hosts with six distinct TLS identities. The whole happy path runs under ONE root
/// <see cref="Activity"/> and must form one connected W3C Trace Context span tree
/// (<see cref="TraceTreeAssertions"/>).
/// </summary>
/// <remarks>
/// <para>
/// The six hosts: the CIMD document host and the client's <c>jwks_uri</c> host (the §8.2
/// canonical confidential-client shape publishes the key set at a separate origin), AS1
/// (auth-code + PKCE + OIDC id_token + token-exchange/ID-JAG mint, RFC 9207), RS1 (trusts AS1),
/// AS2 (jwt-bearer redeem, materializes the client via CIMD on the redeem's wire
/// <c>client_id</c>, <c>(issuer, jti)</c> replay-guarded), and RS2 (trusts AS2).
/// </para>
/// <para>
/// <c>[DoNotParallelize]</c> because the broad <see cref="TraceTreeCapture"/>
/// <see cref="ActivityListener"/> enables process-wide framework instrumentation
/// (<c>Microsoft.AspNetCore</c>, <c>System.Net.Http</c>), which would inject <c>traceparent</c>
/// headers into concurrently running tests' HTTP calls and capture their spans here;
/// serialization plus root-TraceId filtering keeps the suite deterministic.
/// </para>
/// <para>
/// DPoP is out of capstone scope (the event plan never mentions it; existing suites own it) —
/// Bearer tokens throughout, matching the event flow.
/// </para>
/// </remarks>
[TestClass]
[DoNotParallelize]
internal sealed class AgenticFlowCapstoneTests
{
    public TestContext TestContext { get; set; } = null!;

    private const string SubjectId = "subject-agentic-capstone-01";
    private const string ClientSigningKeyId = "agentic-client-signing-key-1";
    private const string DocumentPath = "/agentic-client";
    private const string JwksPath = "/agentic-client-keys";

    /// <summary>The scope RS1 requires on every token reaching its protected resource (RFC 6750 §3.1).</summary>
    private const string Rs1RequiredScope = "inventory.read";

    /// <summary>The scope RS2 requires; also the scope the step-5 ID-JAG mint requests.</summary>
    private const string Rs2RequiredScope = "reports.read";

    /// <summary>A scope AS1 never grants at step 3, used to prove the ICHAIN-024 ceiling.</summary>
    private const string ScopeBeyondGrant = "admin.write";

    /// <summary>The RFC 9068 <c>aud</c> AS1 stamps and RS1 expects.</summary>
    private const string Rs1Audience = "https://rs1.agentic.example";

    /// <summary>The RFC 9068 <c>aud</c> AS2 stamps and RS2 expects.</summary>
    private const string Rs2Audience = "https://rs2.agentic.example";

    private static readonly Uri ClientRedirectUri = new("https://agentic-client.example/callback");

    /// <summary>The step-3 scope request: <c>openid</c> for the id_token plus both resource scopes.</summary>
    private static readonly string Step3ScopeRequest =
        $"{WellKnownScopes.OpenId} {Rs1RequiredScope} {Rs2RequiredScope}";

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>Serialises a JWT protected header to UTF-8 JSON bytes for client-side signing.</summary>
    private static readonly JwtHeaderSerializer CapstoneHeaderSerializer =
        static header => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)header, TestSetup.DefaultSerializationOptions);

    /// <summary>Serialises a JWT payload to UTF-8 JSON bytes for client-side signing.</summary>
    private static readonly JwtPayloadSerializer CapstonePayloadSerializer =
        static payload => JsonSerializerExtensions.SerializeToUtf8Bytes(
            (Dictionary<string, object>)payload, TestSetup.DefaultSerializationOptions);


    /// <summary>
    /// Scenario steps 1–7 in one method under one root <see cref="Activity"/>: RS1 challenge →
    /// RFC 9728 OPRM discovery → AS1 (and AS2) RFC 8414 discovery with the metadata-continuity
    /// assertions → CIMD auth-code + PKCE with the RFC 9207 <c>iss</c> byte-exact and a REAL OIDC
    /// <c>id_token</c> → RS1 200 → <c>OAuthClient.IdJag.MintAsync</c> with that id_token as the
    /// subject token → cross-trust-domain <c>RedeemAsync</c> at AS2 (CIMD-materialized,
    /// <c>private_key_jwt</c>-authenticated) → RS2 200 — finishing with the D7 span-tree
    /// assertions over the six hosts.
    /// </summary>
    [TestMethod]
    public async Task AgenticFlowHappyPathAcrossSixHostsFormsOneConnectedTrace()
    {
        using TraceTreeCapture capture = new();
        await using CapstoneTopology topology = await CapstoneTopology.BuildAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        //Six distinct TLS identities — every host in the topology presents its own leaf certificate.
        string[] certificateThumbprints =
        [
            topology.DocumentHost.Certificate.Thumbprint,
            topology.JwksHost.Certificate.Thumbprint,
            topology.Shell.HostCertificate("default").Thumbprint,
            topology.Shell.HostCertificate(CapstoneTopology.As2HostName).Thumbprint,
            topology.Rs1.HttpCertificate!.Thumbprint,
            topology.Rs2.HttpCertificate!.Thumbprint
        ];
        Assert.HasCount(6, certificateThumbprints.Distinct(StringComparer.Ordinal),
            "The six hosts must present six distinct TLS identities.");

        using Activity root = new("agentic-flow-capstone");
        root.Start();

        //Step 1 — unauthenticated probe at RS1: 401, RFC 6750 §3 Bearer challenge WITHOUT an error
        //code, carrying the RFC 9728 §5.1 resource_metadata parameter that starts discovery.
        using HttpResponseMessage probe = await topology.Rs1Http.GetAsync(
            new Uri(topology.Rs1.HttpBaseAddress!, "/protected"), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(401, (int)probe.StatusCode, "An unauthenticated request must be challenged.");
        BearerTokenChallengeParameters probeChallenge = ParseBearerChallenge(probe);
        Assert.IsNull(probeChallenge.Error,
            "RFC 6750 §3: a request without authentication information gets a challenge without an error code.");
        Assert.IsNotNull(probeChallenge.ResourceMetadata,
            "The challenge must advertise the RFC 9728 §5.1 resource_metadata URL.");

        //Fetch the advertised OPRM document and learn RS1's one trusted authorization server.
        using HttpResponseMessage oprmResponse = await topology.Rs1Http.GetAsync(
            probeChallenge.ResourceMetadata, TestContext.CancellationToken).ConfigureAwait(false);
        string oprmBody = await oprmResponse.Content.ReadAsStringAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(200, (int)oprmResponse.StatusCode, oprmBody);
        ProtectedResourceMetadata? oprm = ProtectedResourceMetadataJsonParsing.ParseProtectedResourceMetadata(oprmBody);
        Assert.IsNotNull(oprm);
        Assert.IsTrue(ProtectedResourceMetadataValidation.IsResourceMatch(
            oprm!, topology.Rs1.ResourceIdentity!.OriginalString),
            "RFC 9728 §3.3 (first paragraph): the document's resource value must equal the resource identifier RS1 represents.");
        string discoveredAs1Issuer = oprm!.AuthorizationServers!.Single();
        Assert.AreEqual(topology.As1Issuer.OriginalString, discoveredAs1Issuer,
            "The OPRM document must name AS1 as RS1's one trusted authorization server.");

        //Step 2 — AS1 discovery from the OPRM-discovered issuer, plus the metadata-continuity set:
        //AS1 advertises CIMD support and the ID-JAG §7.1 identity-chaining token type; AS2
        //advertises CIMD support, the jwt-bearer grant, and the §7.2 id-jag grant profile.
        using JsonDocument as1Discovery = await FetchDiscoveryAsync(
            topology.As1.SharedHttpClient!, discoveredAs1Issuer, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(as1Discovery.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported).GetBoolean(),
            "AS1 must advertise client_id_metadata_document_supported: true.");
        string[] as1ChainingTokenTypes = ReadStringArray(
            as1Discovery.RootElement, AuthorizationServerMetadataParameterNames.IdentityChainingRequestedTokenTypesSupported);
        Assert.Contains(TokenTypeNames.GetName(TokenType.IdJag), as1ChainingTokenTypes,
            "ID-JAG §7.1 / ICHAIN-013: AS1 must advertise the id-jag requested token type.");
        string[] as1GrantTypes = ReadStringArray(
            as1Discovery.RootElement, AuthorizationServerMetadataParameterNames.GrantTypesSupported);
        Assert.Contains(WellKnownGrantTypes.TokenExchange, as1GrantTypes);

        using JsonDocument as2Discovery = await FetchDiscoveryAsync(
            topology.As2.SharedHttpClient!, topology.As2Issuer.OriginalString, TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.IsTrue(as2Discovery.RootElement.GetProperty(
            AuthorizationServerMetadataParameterNames.ClientIdMetadataDocumentSupported).GetBoolean(),
            "AS2 must advertise client_id_metadata_document_supported: true.");
        string[] as2GrantTypes = ReadStringArray(
            as2Discovery.RootElement, AuthorizationServerMetadataParameterNames.GrantTypesSupported);
        Assert.Contains(WellKnownGrantTypes.JwtBearer, as2GrantTypes,
            "ID-JAG §7.2: an AS advertising the id-jag grant profile must include the jwt-bearer grant type.");
        string[] as2GrantProfiles = ReadStringArray(
            as2Discovery.RootElement, AuthorizationServerMetadataParameterNames.AuthorizationGrantProfilesSupported);
        Assert.Contains(WellKnownGrantProfiles.IdJag, as2GrantProfiles,
            "ID-JAG §7.2: AS2 must advertise the id-jag authorization grant profile.");

        //Step 3 — CIMD authorization-code + PKCE at AS1 with a REAL OIDC id_token in the response.
        CapstoneStep3Result step3 = await topology.DriveStep3Async(Step3ScopeRequest, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsTrue(topology.DocumentHost.WasRequested(DocumentPath),
            "AS1 must have fetched the Client ID Metadata Document over the real wire (CIMD-029).");
        Assert.IsTrue(topology.JwksHost.WasRequested(JwksPath),
            "The §8.2 jwks_uri discovery must have fetched the client's key set over the real wire.");

        string? issParameter = TestBrowser.ExtractQueryParam(step3.AuthorizeLocation, OAuthRequestParameterNames.Iss);
        Assert.IsNotNull(issParameter, "RFC 9207: the authorization response must carry the iss parameter.");
        Assert.AreEqual(topology.As1Issuer.OriginalString, issParameter,
            "RFC 9207 §2: iss must byte-exactly equal the issuer identifier even though the client's "
            + "identity came from a fetched CIMD document.");

        using(JsonDocument accessClaims = DecodePayload(step3.AccessToken))
        {
            JsonElement claims = accessClaims.RootElement;
            Assert.AreEqual(topology.As1Issuer.OriginalString, claims.GetProperty(WellKnownJwtClaimNames.Iss).GetString());
            Assert.AreEqual(SubjectId, claims.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
            AssertAudienceClaim(claims, Rs1Audience);
            string tokenScope = claims.GetProperty(WellKnownJwtClaimNames.Scope).GetString()!;
            Assert.AreEqual(Step3ScopeRequest, tokenScope,
                "AS1 must have granted the full requested scope set at step 3.");
        }

        using(JsonDocument idTokenClaims = DecodePayload(step3.IdToken))
        {
            JsonElement claims = idTokenClaims.RootElement;
            Assert.AreEqual(topology.As1Issuer.OriginalString, claims.GetProperty(WellKnownJwtClaimNames.Iss).GetString());
            Assert.AreEqual(SubjectId, claims.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
            AssertAudienceClaim(claims, topology.ClientIdentifierUrl.OriginalString);
        }

        //Step 4 — RS1 accepts the AS1 access token: signature / iss / aud / exp via
        //JwsAccessTokenValidator plus required-scope enforcement.
        using(JsonDocument rs1Claims = await GetProtectedResourceAsync(
            topology.Rs1Http, topology.Rs1.HttpBaseAddress!, step3.AccessToken, TestContext.CancellationToken)
            .ConfigureAwait(false))
        {
            Assert.AreEqual(SubjectId, rs1Claims.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
            string rs1Scope = rs1Claims.RootElement.GetProperty(WellKnownJwtClaimNames.Scope).GetString()!;
            Assert.Contains(Rs1RequiredScope, rs1Scope.Split(' '),
                "The token reaching RS1 must carry RS1's required scope.");
        }

        //Step 5 — the client mints an ID-JAG at AS1 via OAuthClient.IdJag: the subject token is
        //the REAL step-3 id_token, the audience names AS2's issuer, and the requested JAG scope
        //sits inside the step-3 grant (ICHAIN-024 ceiling).
        var mintResult = await topology.As1Client.IdJag.MintAsync(
            topology.As1Registration,
            topology.BuildMintOptions(step3.IdToken, Rs2RequiredScope),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.IsTrue(mintResult.IsSuccess, mintResult.Error?.Support.Summary);
        Assert.AreEqual("N_A", mintResult.Value.TokenType, "ID-JAG §4.3.4: the minted grant is not an access token.");

        string jag = mintResult.Value.AccessToken;
        using(JsonDocument jagHeader = DecodeHeader(jag))
        {
            Assert.AreEqual("oauth-id-jag+jwt", jagHeader.RootElement.GetProperty(WellKnownJoseHeaderNames.Typ).GetString());
        }

        using(JsonDocument jagClaims = DecodePayload(jag))
        {
            JsonElement claims = jagClaims.RootElement;
            Assert.AreEqual(topology.As1Issuer.OriginalString, claims.GetProperty(WellKnownJwtClaimNames.Iss).GetString());
            Assert.AreEqual(SubjectId, claims.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
            Assert.AreEqual(topology.As2Issuer.OriginalString, claims.GetProperty(WellKnownJwtClaimNames.Aud).GetString(),
                "The JAG aud must name AS2's issuer identifier.");
            Assert.AreEqual(topology.ClientIdentifierUrl.OriginalString,
                claims.GetProperty(WellKnownJwtClaimNames.ClientId).GetString());
            Assert.IsFalse(string.IsNullOrEmpty(claims.GetProperty(WellKnownJwtClaimNames.Jti).GetString()));
            Assert.AreEqual(Rs2RequiredScope, claims.GetProperty(WellKnownJwtClaimNames.Scope).GetString());
        }

        //Step 6 — cross-trust-domain redeem at AS2: materialization triggers on the redeem's wire
        //client_id (proven by the fetch-count delta), the private_key_jwt assertion validates
        //against the materialized document jwks, and AS2 issues its OWN access token.
        int documentFetchesBeforeRedeem = topology.DocumentHost.TotalRequests;
        var redeemResult = await topology.As2Client.IdJag.RedeemAsync(
            topology.As2Registration, topology.BuildRedeemOptions(jag), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.IsTrue(redeemResult.IsSuccess, redeemResult.Error?.Support.Summary);
        Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, redeemResult.Value.TokenType);
        Assert.IsGreaterThan(documentFetchesBeforeRedeem, topology.DocumentHost.TotalRequests,
            "AS2 must have materialized the client from its CIMD document on the redeem's wire client_id.");

        string as2AccessToken = redeemResult.Value.AccessToken;
        using(JsonDocument as2Claims = DecodePayload(as2AccessToken))
        {
            JsonElement claims = as2Claims.RootElement;
            string as2TokenIssuer = claims.GetProperty(WellKnownJwtClaimNames.Iss).GetString()!;
            Assert.AreEqual(topology.As2Issuer.OriginalString, as2TokenIssuer);
            Assert.AreNotEqual(topology.As1Issuer.OriginalString, as2TokenIssuer,
                "The redeemed access token's issuer must be AS2, a different trust domain than AS1.");
            Assert.AreEqual(SubjectId, claims.GetProperty(WellKnownJwtClaimNames.Sub).GetString(),
                "The subject must survive the whole id_token → JAG → access-token chain.");
            Assert.AreEqual(Rs2RequiredScope, claims.GetProperty(WellKnownJwtClaimNames.Scope).GetString());
            AssertAudienceClaim(claims, Rs2Audience);
        }

        //Step 7 — RS2 accepts the AS2 token.
        using(JsonDocument rs2Claims = await GetProtectedResourceAsync(
            topology.Rs2Http, topology.Rs2.HttpBaseAddress!, as2AccessToken, TestContext.CancellationToken)
            .ConfigureAwait(false))
        {
            Assert.AreEqual(SubjectId, rs2Claims.RootElement.GetProperty(WellKnownJwtClaimNames.Sub).GetString());
        }

        Uri[] hostBaseAddresses =
        [
            topology.DocumentHost.BaseAddress,
            topology.JwksHost.BaseAddress,
            topology.As1.HttpBaseAddress!,
            topology.As2.HttpBaseAddress!,
            topology.Rs1.HttpBaseAddress!,
            topology.Rs2.HttpBaseAddress!
        ];

        root.Stop();

        //Stopping the hosts drains request processing, so every server span has stopped and is in
        //the capture before the tree is asserted.
        await topology.StopHostsAsync().ConfigureAwait(false);

        IReadOnlyList<Activity> captured = capture.StoppedActivities;
        TraceTreeAssertions.AssertSingleConnectedTree(captured, root);
        TraceTreeAssertions.AssertSpanForEachHost(captured, root, hostBaseAddresses);

        //The CIMD resolutions are wire fetches issued mid-dispatch: the client spans dialing the
        //document (and jwks_uri) hosts must sit under the owning AS's server.handle dispatch span.
        AssertWireFetchUnderDispatchSpan(captured, root, topology.DocumentHost.BaseAddress, topology.Segment1,
            "AS1's CIMD document resolution must attach under AS1's dispatch span.");
        AssertWireFetchUnderDispatchSpan(captured, root, topology.JwksHost.BaseAddress, topology.Segment1,
            "AS1's §8.2 jwks_uri discovery must attach under AS1's dispatch span.");
        AssertWireFetchUnderDispatchSpan(captured, root, topology.DocumentHost.BaseAddress, topology.Segment2,
            "AS2's CIMD document resolution must attach under AS2's dispatch span.");
    }


    /// <summary>
    /// Cross-domain confusion, first direction: the AS1 access token presented at RS2 is refused
    /// 401 with an RFC 6750 §3 <c>invalid_token</c> challenge — RS2 trusts only AS2's issuer.
    /// </summary>
    [TestMethod]
    public async Task As1AccessTokenAtRs2IsRefusedWithInvalidTokenChallenge()
    {
        await using CapstoneTopology topology = await CapstoneTopology.BuildAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        CapstoneStep3Result step3 = await topology.DriveStep3Async(Step3ScopeRequest, TestContext.CancellationToken)
            .ConfigureAwait(false);

        using HttpResponseMessage response = await SendBearerAsync(
            topology.Rs2Http, topology.Rs2.HttpBaseAddress!, step3.AccessToken, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, "RS2 must refuse a token minted by AS1.");
        BearerTokenChallengeParameters challenge = ParseBearerChallenge(response);
        Assert.AreEqual(OAuthErrors.InvalidToken, challenge.Error);
        Assert.AreEqual(topology.Rs2.MetadataUrl!.OriginalString, challenge.ResourceMetadata?.OriginalString,
            "The refusal challenge must still advertise RS2's own metadata URL (RFC 9728 §5.1).");
    }


    /// <summary>
    /// Cross-domain confusion, second direction: the AS2 access token obtained through the full
    /// mint + redeem chain is refused 401 <c>invalid_token</c> at RS1 — RS1 trusts only AS1.
    /// </summary>
    [TestMethod]
    public async Task As2AccessTokenAtRs1IsRefusedWithInvalidTokenChallenge()
    {
        await using CapstoneTopology topology = await CapstoneTopology.BuildAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        CapstoneStep3Result step3 = await topology.DriveStep3Async(Step3ScopeRequest, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string jag = await topology.MintJagAsync(step3.IdToken, Rs2RequiredScope, TestContext.CancellationToken)
            .ConfigureAwait(false);

        var redeemResult = await topology.As2Client.IdJag.RedeemAsync(
            topology.As2Registration, topology.BuildRedeemOptions(jag), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.IsTrue(redeemResult.IsSuccess, redeemResult.Error?.Support.Summary);

        using HttpResponseMessage response = await SendBearerAsync(
            topology.Rs1Http, topology.Rs1.HttpBaseAddress!, redeemResult.Value.AccessToken, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, "RS1 must refuse a token minted by AS2.");
        BearerTokenChallengeParameters challenge = ParseBearerChallenge(response);
        Assert.AreEqual(OAuthErrors.InvalidToken, challenge.Error);
        Assert.AreEqual(topology.Rs1.MetadataUrl!.OriginalString, challenge.ResourceMetadata?.OriginalString,
            "The refusal challenge must still advertise RS1's own metadata URL (RFC 9728 §5.1).");
    }


    /// <summary>
    /// Scope escalation at the resource: a fully valid AS1 token granted only <c>openid</c> is
    /// refused 403 at RS1 with the RFC 6750 §3.1 <c>insufficient_scope</c> challenge whose
    /// <c>scope</c> attribute names the needed scope.
    /// </summary>
    [TestMethod]
    public async Task TokenWithoutRs1ScopeIsRefusedWithInsufficientScopeChallenge()
    {
        await using CapstoneTopology topology = await CapstoneTopology.BuildAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        CapstoneStep3Result step3 = await topology.DriveStep3Async(WellKnownScopes.OpenId, TestContext.CancellationToken)
            .ConfigureAwait(false);

        using HttpResponseMessage response = await SendBearerAsync(
            topology.Rs1Http, topology.Rs1.HttpBaseAddress!, step3.AccessToken, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.AreEqual(403, (int)response.StatusCode,
            "RFC 6750 §3.1: insufficient_scope maps to 403, not 401.");
        BearerTokenChallengeParameters challenge = ParseBearerChallenge(response);
        Assert.AreEqual(OAuthErrors.InsufficientScope, challenge.Error);
        Assert.AreEqual(Rs1RequiredScope, challenge.Scope,
            "The challenge's scope attribute must name the scope necessary to access the resource.");
    }


    /// <summary>
    /// The ICHAIN-024 ceiling: a mint requesting a JAG scope outside the scopes AS1 granted
    /// alongside the id_token's issuance at step 3 is denied — the fixture's authorization seam
    /// enforces requested ⊆ ceiling, and a denied id-jag exchange maps to <c>invalid_grant</c>
    /// (ID-JAG §4.3.4.3).
    /// </summary>
    [TestMethod]
    public async Task MintRequestingScopeBeyondStep3GrantIsDenied()
    {
        await using CapstoneTopology topology = await CapstoneTopology.BuildAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        CapstoneStep3Result step3 = await topology.DriveStep3Async(Step3ScopeRequest, TestContext.CancellationToken)
            .ConfigureAwait(false);

        var mintResult = await topology.As1Client.IdJag.MintAsync(
            topology.As1Registration,
            topology.BuildMintOptions(step3.IdToken, ScopeBeyondGrant),
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(mintResult.IsSuccess,
            "A mint requesting scope beyond the step-3 grant must be denied (ICHAIN-024).");
        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(mintResult.Error);
        Assert.AreEqual(OAuthErrors.InvalidGrant, protocolError.ErrorCode);
    }


    /// <summary>
    /// Replay defense at AS2: the first redemption of a JAG succeeds and records its
    /// <c>(issuer, jti)</c>; presenting the SAME grant again is refused <c>invalid_grant</c> by
    /// the library's <see cref="JtiReplayGuard"/> over the host's shared store (RFC 7523 §3 rule 7).
    /// </summary>
    [TestMethod]
    public async Task ReplayedJagAtAs2IsRefusedWithInvalidGrant()
    {
        await using CapstoneTopology topology = await CapstoneTopology.BuildAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        CapstoneStep3Result step3 = await topology.DriveStep3Async(Step3ScopeRequest, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string jag = await topology.MintJagAsync(step3.IdToken, Rs2RequiredScope, TestContext.CancellationToken)
            .ConfigureAwait(false);

        var firstRedeem = await topology.As2Client.IdJag.RedeemAsync(
            topology.As2Registration, topology.BuildRedeemOptions(jag), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.IsTrue(firstRedeem.IsSuccess, firstRedeem.Error?.Support.Summary);

        var secondRedeem = await topology.As2Client.IdJag.RedeemAsync(
            topology.As2Registration, topology.BuildRedeemOptions(jag), TestContext.CancellationToken)
            .ConfigureAwait(false);
        Assert.IsFalse(secondRedeem.IsSuccess, "The second redemption of the same JAG must be refused.");
        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(secondRedeem.Error);
        Assert.AreEqual(OAuthErrors.InvalidGrant, protocolError.ErrorCode);
    }


    /// <summary>
    /// D2 on the redeem leg: the client's CIMD document declares
    /// <c>token_endpoint_auth_method: private_key_jwt</c>, so a redeem carrying NO client
    /// credentials at all is refused 401 <c>invalid_client</c> — CIMD-049's "any communication
    /// with the authorization server MUST include client authentication of the registered type",
    /// fail-closed against the materialized registration.
    /// </summary>
    [TestMethod]
    public async Task RedeemWithoutClientAuthenticationIsRefused()
    {
        await using CapstoneTopology topology = await CapstoneTopology.BuildAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        CapstoneStep3Result step3 = await topology.DriveStep3Async(Step3ScopeRequest, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string jag = await topology.MintJagAsync(step3.IdToken, Rs2RequiredScope, TestContext.CancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = topology.ClientIdentifierUrl.OriginalString,
            [OAuthRequestParameterNames.Assertion] = jag
        };
        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            topology.As2.SharedHttpClient!, topology.As2TokenEndpoint, fields, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        AssertWireErrorCode(OAuthErrors.InvalidClient, body);
    }


    /// <summary>
    /// A tampered <c>private_key_jwt</c> client assertion on the redeem fails RFC 7523 §2.2
    /// signature verification against the CIMD-materialized document jwks and is refused 401
    /// <c>invalid_client</c>.
    /// </summary>
    [TestMethod]
    public async Task RedeemWithTamperedClientAssertionIsRefused()
    {
        await using CapstoneTopology topology = await CapstoneTopology.BuildAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);
        CapstoneStep3Result step3 = await topology.DriveStep3Async(Step3ScopeRequest, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string jag = await topology.MintJagAsync(step3.IdToken, Rs2RequiredScope, TestContext.CancellationToken)
            .ConfigureAwait(false);

        string validAssertion = await topology.SignClientAssertionForAs2Async(TestContext.CancellationToken)
            .ConfigureAwait(false);

        Dictionary<string, string> fields = new(StringComparer.Ordinal)
        {
            [OAuthRequestParameterNames.GrantType] = WellKnownGrantTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientId] = topology.ClientIdentifierUrl.OriginalString,
            [OAuthRequestParameterNames.Assertion] = jag,
            [OAuthRequestParameterNames.ClientAssertionType] = WellKnownClientAssertionTypes.JwtBearer,
            [OAuthRequestParameterNames.ClientAssertion] = TamperSignature(validAssertion)
        };
        using HttpResponseMessage response = await OAuthTestTransport.PostFormAsync(
            topology.As2.SharedHttpClient!, topology.As2TokenEndpoint, fields, TestContext.CancellationToken)
            .ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(401, (int)response.StatusCode, body);
        AssertWireErrorCode(OAuthErrors.InvalidClient, body);
    }


    /// <summary>
    /// The §9.3 same-trust-domain rule: a JAG whose <c>iss</c> is AS2's own issuer — validly
    /// signed with a key AS2 itself publishes, so signature trust alone would admit it — is
    /// refused <c>invalid_grant</c> at AS2's redeem. Trust in the signing key must not permit
    /// redeeming a grant minted in the Resource Authorization Server's own domain.
    /// </summary>
    [TestMethod]
    public async Task SameTrustDomainJagIsRefusedWithInvalidGrant()
    {
        await using CapstoneTopology topology = await CapstoneTopology.BuildAsync(TestContext.CancellationToken)
            .ConfigureAwait(false);

        DateTimeOffset now = topology.Time.GetUtcNow();
        string sameDomainJag = await BuildForeignIdJagAsync(
            topology.As2TokenSigningKey,
            topology.As2TokenSigningKeyId.Value,
            issuer: topology.As2Issuer.OriginalString,
            subject: SubjectId,
            audience: topology.As2Issuer.OriginalString,
            clientId: topology.ClientIdentifierUrl.OriginalString,
            scope: Rs2RequiredScope,
            issuedAt: now,
            expiresAt: now.AddMinutes(5),
            TestContext.CancellationToken).ConfigureAwait(false);

        var redeemResult = await topology.As2Client.IdJag.RedeemAsync(
            topology.As2Registration, topology.BuildRedeemOptions(sameDomainJag), TestContext.CancellationToken)
            .ConfigureAwait(false);

        Assert.IsFalse(redeemResult.IsSuccess,
            "A JAG minted in AS2's own trust domain must not redeem at AS2 (§9.3).");
        OAuthProtocolError protocolError = Assert.IsInstanceOfType<OAuthProtocolError>(redeemResult.Error);
        Assert.AreEqual(OAuthErrors.InvalidGrant, protocolError.ErrorCode);
    }


    /// <summary>
    /// Reads the single <c>WWW-Authenticate</c> value and parses it under the RFC 6750 §3 grammar,
    /// failing the test when the header is absent or does not parse.
    /// </summary>
    private static BearerTokenChallengeParameters ParseBearerChallenge(HttpResponseMessage response)
    {
        Assert.IsTrue(response.Headers.TryGetValues("WWW-Authenticate", out IEnumerable<string>? challenges),
            "The refusal must carry a WWW-Authenticate challenge.");
        string challenge = challenges!.Single();
        Assert.IsTrue(BearerTokenChallenge.TryParse(challenge, out BearerTokenChallengeParameters parameters),
            $"The challenge must parse under the RFC 6750 §3 grammar. Header: {challenge}");

        return parameters;
    }


    /// <summary>Asserts the RFC 6749 §5.2 JSON error body carries exactly <paramref name="expectedErrorCode"/>.</summary>
    private static void AssertWireErrorCode(string expectedErrorCode, string responseBody)
    {
        using JsonDocument document = JsonDocument.Parse(responseBody);
        Assert.AreEqual(expectedErrorCode, document.RootElement.GetProperty("error").GetString(),
            $"The refusal body must carry the exact error code. Body: {responseBody}");
    }


    private static async Task<HttpResponseMessage> SendBearerAsync(
        HttpClient client, Uri resourceServerBase, string accessToken, CancellationToken cancellationToken)
    {
        using HttpRequestMessage request = new(HttpMethod.Get, new Uri(resourceServerBase, "/protected"));
        request.Headers.Authorization = new AuthenticationHeaderValue(WellKnownAuthenticationSchemes.Bearer, accessToken);

        return await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>Sends the bearer token to <c>/protected</c>, asserts 200, and returns the echoed claims.</summary>
    private static async Task<JsonDocument> GetProtectedResourceAsync(
        HttpClient client, Uri resourceServerBase, string accessToken, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendBearerAsync(
            client, resourceServerBase, accessToken, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        return JsonDocument.Parse(body);
    }


    /// <summary>
    /// Fetches the RFC 8414 §3 default-location metadata document for <paramref name="issuer"/> —
    /// the well-known suffix inserted between host and the issuer's path component — over the wire.
    /// </summary>
    private static async Task<JsonDocument> FetchDiscoveryAsync(
        HttpClient client, string issuer, CancellationToken cancellationToken)
    {
        Uri discoveryUrl = WellKnownPaths.OAuthAuthorizationServer.ComputeUri(issuer);
        using HttpResponseMessage response = await client.GetAsync(discoveryUrl, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, (int)response.StatusCode, body);

        return JsonDocument.Parse(body);
    }


    private static string[] ReadStringArray(JsonElement root, string propertyName) =>
        [.. root.GetProperty(propertyName).EnumerateArray().Select(static element => element.GetString()!)];


    /// <summary>
    /// Asserts the <c>aud</c> claim equals <paramref name="expected"/>, accepting the RFC 7519
    /// string shape and the single-element array shape.
    /// </summary>
    private static void AssertAudienceClaim(JsonElement claims, string expected)
    {
        JsonElement audience = claims.GetProperty(WellKnownJwtClaimNames.Aud);
        string? actual = audience.ValueKind == JsonValueKind.Array
            ? audience.EnumerateArray().Single().GetString()
            : audience.GetString();
        Assert.AreEqual(expected, actual);
    }


    private static JsonDocument DecodeHeader(string compactJws)
    {
        string[] segments = compactJws.Split('.');
        Assert.HasCount(3, segments);

        return JsonDocument.Parse(SecurityEventTestJson.DecodeSegment(segments[0], Pool));
    }


    private static JsonDocument DecodePayload(string compactJws)
    {
        string[] segments = compactJws.Split('.');
        Assert.HasCount(3, segments);

        return JsonDocument.Parse(SecurityEventTestJson.DecodeSegment(segments[1], Pool));
    }


    //Flips the FIRST character of the compact JWS's signature segment. The first base64url
    //character contributes six full bits to the decoded bytes, so the mutated signature always
    //decodes to different bytes — unlike the final character, whose low bits a lenient decoder
    //can discard, yielding a no-op "tamper" that still verifies.
    private static string TamperSignature(string compactJws)
    {
        int signatureStart = compactJws.LastIndexOf('.') + 1;
        char first = compactJws[signatureStart];
        char replacement = first == 'A' ? 'B' : 'A';

        return string.Concat(
            compactJws.AsSpan(0, signatureStart), replacement.ToString(), compactJws.AsSpan(signatureStart + 1));
    }


    /// <summary>
    /// Builds and signs an ID-JAG entirely outside the mint pipeline — raw §3.1 claims under a
    /// <c>typ=oauth-id-jag+jwt</c> header, signed with the supplied key — so the redeem path under
    /// test receives foreign wire bytes shaped exactly like a grant minted elsewhere.
    /// </summary>
    private static async Task<string> BuildForeignIdJagAsync(
        PrivateKeyMemory signingKey,
        string keyId,
        string issuer,
        string subject,
        string audience,
        string clientId,
        string scope,
        DateTimeOffset issuedAt,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken)
    {
        string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(signingKey.Tag);
        JwtHeader header = JwtHeader.ForSigning(algorithm, "oauth-id-jag+jwt", keyId);
        JwtPayload payload = new(capacity: 8)
        {
            [WellKnownJwtClaimNames.Iss] = issuer,
            [WellKnownJwtClaimNames.Sub] = subject,
            [WellKnownJwtClaimNames.Aud] = audience,
            [WellKnownJwtClaimNames.ClientId] = clientId,
            [WellKnownJwtClaimNames.Jti] = Guid.NewGuid().ToString("N"),
            [WellKnownJwtClaimNames.Iat] = issuedAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Exp] = expiresAt.ToUnixTimeSeconds(),
            [WellKnownJwtClaimNames.Scope] = scope
        };

        UnsignedJwt unsigned = new(header, payload);
        using JwsMessage jws = await unsigned.SignAsync(
            signingKey,
            CapstoneHeaderSerializer,
            CapstonePayloadSerializer,
            TestSetup.Base64UrlEncoder,
            Pool,
            cancellationToken).ConfigureAwait(false);

        return JwsSerialization.SerializeCompact(jws, TestSetup.Base64UrlEncoder);
    }


    /// <summary>
    /// Asserts that at least one HTTP client span dialing <paramref name="contentHostBase"/> is a
    /// descendant of a <c>server.handle</c> dispatch span whose <c>server.tenant.id</c> tag is
    /// <paramref name="tenantSegment"/> — the structural proof that the fetch was issued
    /// mid-dispatch by the owning authorization server, inside the same trace.
    /// </summary>
    private static void AssertWireFetchUnderDispatchSpan(
        IReadOnlyList<Activity> capturedActivities,
        Activity root,
        Uri contentHostBase,
        string tenantSegment,
        string message)
    {
        IReadOnlyList<Activity> inTrace = TraceTreeAssertions.FilterByTrace(capturedActivities, root.TraceId);

        Dictionary<ActivitySpanId, Activity> bySpanId = new(inTrace.Count);
        foreach(Activity activity in inTrace)
        {
            bySpanId[activity.SpanId] = activity;
        }

        HashSet<ActivitySpanId> dispatchSpanIds = [.. inTrace
            .Where(activity =>
                string.Equals(activity.OperationName, ServerActivityNames.Handle, StringComparison.Ordinal)
                && string.Equals(
                    activity.GetTagItem(ServerTagNames.TenantId)?.ToString(), tenantSegment, StringComparison.Ordinal))
            .Select(activity => activity.SpanId)];
        Assert.IsGreaterThan(0, dispatchSpanIds.Count,
            $"No server.handle dispatch span with tenant '{tenantSegment}' was captured in trace '{root.TraceId}'.");

        bool isUnderDispatch = inTrace.Any(activity =>
            activity.Kind == ActivityKind.Client
            && IsClientSpanDialing(activity, contentHostBase)
            && HasAncestorIn(activity, dispatchSpanIds, bySpanId));
        Assert.IsTrue(isUnderDispatch, message);
    }


    private static bool IsClientSpanDialing(Activity activity, Uri hostBase)
    {
        string? urlFull = activity.GetTagItem("url.full")?.ToString();

        return urlFull is not null
            && Uri.TryCreate(urlFull, UriKind.Absolute, out Uri? url)
            && string.Equals(url.Host, hostBase.Host, StringComparison.OrdinalIgnoreCase)
            && url.Port == hostBase.Port;
    }


    private static bool HasAncestorIn(
        Activity activity,
        HashSet<ActivitySpanId> ancestorSpanIds,
        Dictionary<ActivitySpanId, Activity> bySpanId)
    {
        HashSet<ActivitySpanId> visited = [activity.SpanId];
        ActivitySpanId parentSpanId = activity.ParentSpanId;
        while(visited.Add(parentSpanId))
        {
            if(ancestorSpanIds.Contains(parentSpanId))
            {
                return true;
            }

            if(!bySpanId.TryGetValue(parentSpanId, out Activity? parent))
            {
                return false;
            }

            parentSpanId = parent.ParentSpanId;
        }

        return false;
    }


    /// <summary>
    /// Whether every space-separated scope token in <paramref name="requestedScope"/> appears in
    /// <paramref name="grantedScope"/> — the ICHAIN-024 requested-⊆-ceiling comparison.
    /// </summary>
    private static bool IsScopeSubset(string requestedScope, string grantedScope)
    {
        HashSet<string> granted = new(
            grantedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries), StringComparer.Ordinal);
        foreach(string requested in requestedScope.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if(!granted.Contains(requested))
            {
                return false;
            }
        }

        return true;
    }


    //Builds a conformant Client ID Metadata Document (§4): client_id always present; other
    //members only when supplied, so an omitted property stays genuinely absent from the wire
    //JSON. Mirrors ClientIdMetadataDocumentCrossWireFlowTests' builder; the capstone's document
    //always takes the §8.2 canonical shape (private_key_jwt + jwks_uri at a separate origin).
    private static string BuildCimdDocumentJson(
        string clientId,
        IReadOnlyList<Uri>? redirectUris,
        string? tokenEndpointAuthMethod,
        string? jwksUri)
    {
        List<string> members = [$"\"client_id\":\"{clientId}\""];

        if(redirectUris is { Count: > 0 })
        {
            string uris = string.Join(',', redirectUris.Select(static uri => $"\"{uri.OriginalString}\""));
            members.Add($"\"redirect_uris\":[{uris}]");
        }

        if(tokenEndpointAuthMethod is not null)
        {
            members.Add($"\"token_endpoint_auth_method\":\"{tokenEndpointAuthMethod}\"");
        }

        if(jwksUri is not null)
        {
            members.Add($"\"jwks_uri\":\"{jwksUri}\"");
        }

        return "{" + string.Join(',', members) + "}";
    }


    //Hand-built JWKS document text from a DpopJwkUtilities.ToJwk dictionary, mirroring
    //PrivateKeyJwtClientAuthenticationTests.BuildJwksJson.
    private static string BuildJwksJson(IReadOnlyDictionary<string, string> jwk, string kid)
    {
        StringBuilder sb = new();
        sb.Append('{').Append('"').Append(WellKnownJwkMemberNames.Keys).Append("\":[{");
        foreach(KeyValuePair<string, string> member in jwk)
        {
            sb.Append('"').Append(member.Key).Append("\":\"").Append(member.Value).Append("\",");
        }

        sb.Append('"').Append(WellKnownJwkMemberNames.Kid).Append("\":\"").Append(kid).Append("\"}]}");

        return sb.ToString();
    }


    /// <summary>
    /// The step-3 artifacts a test builds on: the client-side flow identifier, the raw authorize
    /// redirect <c>Location</c> (for the RFC 9207 byte-exactness assertion), the AS1 access token,
    /// the REAL OIDC <c>id_token</c>, and the scope AS1 granted (read from the access token's own
    /// RFC 9068 <c>scope</c> claim — the value that becomes the ICHAIN-024 mint ceiling).
    /// </summary>
    private sealed record CapstoneStep3Result
    {
        public required string FlowId { get; init; }

        public required string AuthorizeLocation { get; init; }

        public required string AccessToken { get; init; }

        public required string IdToken { get; init; }

        public required string GrantedScope { get; init; }
    }


    /// <summary>
    /// The capstone's six-host topology and its seam wiring, built once per test: the CIMD
    /// document host and the client's <c>jwks_uri</c> host (two <see cref="StaticContentHost"/>s),
    /// one <see cref="TestHostShell"/> carrying AS1 (the <c>default</c> host) and AS2 (a named
    /// host with its own distinct certificate, <see cref="TestHostShell.AddHost(string, bool)"/>),
    /// and the two upgraded <see cref="TestResourceServerShell"/>s. Every adversarial companion
    /// runs against this same topology.
    /// </summary>
    /// <remarks>
    /// <para>
    /// AS1's seams: <c>ValidateTokenExchangeTokenAsync</c> VERIFIES the presented id_token —
    /// signature against AS1's own JWKS fetched over the wire at validation time, <c>aud</c>
    /// equal to the client_id (ID-JAG §4.3.3 / ICHAIN-017), issuer and expiry — never an
    /// opaque-literal acceptance, and surfaces the step-3 granted scopes as
    /// <see cref="ValidatedSecurityToken.Scope"/>; <c>AuthorizeTokenExchangeAsync</c> enforces the
    /// ICHAIN-024 ceiling (requested JAG scope ⊆ that grant). The honest ICHAIN-024 mapping for
    /// this profile is "ceiling = the scopes granted alongside that id_token's issuance", which
    /// AS1 knows because it minted both — modelled here by the topology recording the step-3
    /// grant from the access token AS1 itself issued.
    /// </para>
    /// <para>
    /// AS2's redeem seam resolves the JAG's signing key from the ISSUING authorization servers'
    /// published JWKS (fetched over the wire) and applies
    /// <see cref="IdJagAssertionValidation.Validate"/> — §4.4.1 typ/aud/client_id/temporal rules
    /// plus the §9.3 same-trust-domain rejection — surfacing <c>iss</c>/<c>jti</c>/<c>exp</c> so
    /// the jwt-bearer endpoint's <see cref="JtiReplayGuard"/> applies the replay defense. AS2's
    /// key set participates in the resolver precisely so the §9.3 test proves the rule does the
    /// rejecting, not a key-resolution failure.
    /// </para>
    /// <para>
    /// AS1 resolves policy as <see cref="PolicyProfile.Rfc6749WithPkce"/> with RFC 9207 emission
    /// switched ON — the capstone must assert <c>iss</c> byte-exact while DPoP stays out of scope,
    /// and the FAPI 2.0 / HAIP profiles that emit <c>iss</c> by default also mandate DPoP at the
    /// token endpoint.
    /// </para>
    /// </remarks>
    private sealed class CapstoneTopology: IAsyncDisposable
    {
        public const string As2HostName = "as2";

        private bool hasStoppedHosts;
        private bool isDisposed;

        private PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> ClientKeys { get; set; } = null!;

        private HttpClient ResolverHttpClient { get; set; } = null!;

        private Dictionary<string, PublicKeyMemory> As1JwksKeys { get; set; } = null!;

        private Dictionary<string, PublicKeyMemory> As2JwksKeys { get; set; } = null!;

        public FakeTimeProvider Time { get; } = new(TestClock.CanonicalEpoch);

        public StaticContentHost DocumentHost { get; private set; } = null!;

        public StaticContentHost JwksHost { get; private set; } = null!;

        public TestHostShell Shell { get; private set; } = null!;

        public HostedAuthorizationServer As1 { get; private set; } = null!;

        public HostedAuthorizationServer As2 { get; private set; } = null!;

        public TestResourceServerShell Rs1 { get; private set; } = null!;

        public TestResourceServerShell Rs2 { get; private set; } = null!;

        public OAuthClient As1Client { get; private set; } = null!;

        public ClientRegistration As1Registration { get; private set; } = null!;

        public Dictionary<string, FlowState> As1FlowStore { get; private set; } = null!;

        public OAuthClient As2Client { get; private set; } = null!;

        public ClientRegistration As2Registration { get; private set; } = null!;

        /// <summary>The client's https Client Identifier URL — the CIMD document's own location.</summary>
        public Uri ClientIdentifierUrl { get; private set; } = null!;

        public string Segment1 { get; private set; } = null!;

        public string Segment2 { get; private set; } = null!;

        public Uri As1Issuer { get; private set; } = null!;

        public Uri As2Issuer { get; private set; } = null!;

        public Uri As1TokenEndpoint { get; private set; } = null!;

        public Uri As2TokenEndpoint { get; private set; } = null!;

        /// <summary>The multi-pinned, auto-redirect-disabled browser stand-in for authorize hops.</summary>
        public HttpClient BrowserClient { get; private set; } = null!;

        public HttpClient Rs1Http { get; private set; } = null!;

        public HttpClient Rs2Http { get; private set; } = null!;

        /// <summary>AS2's own token-signing key identifier, published in AS2's JWKS.</summary>
        public KeyId As2TokenSigningKeyId { get; private set; }

        /// <summary>AS2's own token-signing private key (host-owned; never disposed here).</summary>
        public PrivateKeyMemory As2TokenSigningKey => As2.SigningKeys[As2TokenSigningKeyId];

        /// <summary>
        /// The scopes AS1 granted at step 3 — AS1's record of the grant issued alongside the
        /// id_token, read back from the access token it minted. The mint seams consult this as
        /// the ICHAIN-024 ceiling; while no step-3 grant exists the mint fails closed.
        /// </summary>
        public string? Step3GrantedScope { get; private set; }


        private CapstoneTopology()
        {
        }


        public static async Task<CapstoneTopology> BuildAsync(CancellationToken cancellationToken)
        {
            CapstoneTopology topology = new();
            await topology.InitializeAsync(cancellationToken).ConfigureAwait(false);

            return topology;
        }


        private async Task InitializeAsync(CancellationToken cancellationToken)
        {
            DocumentHost = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);
            JwksHost = await StaticContentHost.StartAsync(cancellationToken).ConfigureAwait(false);

            ClientKeys = TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
            string algorithm = CryptoFormatConversions.DefaultTagToJwaConverter(ClientKeys.PublicKey.Tag);
            IReadOnlyDictionary<string, string> jwk = DpopJwkUtilities.ToJwk(
                ClientKeys.PublicKey, algorithm, TestHostShell.Base64UrlEncoder);
            JwksHost.Publish(
                JwksPath, Encoding.UTF8.GetBytes(BuildJwksJson(jwk, ClientSigningKeyId)), "application/json");

            ClientIdentifierUrl = new Uri(DocumentHost.BaseAddress, DocumentPath);
            Uri jwksUrl = new(JwksHost.BaseAddress, JwksPath);
            string documentJson = BuildCimdDocumentJson(
                ClientIdentifierUrl.OriginalString,
                redirectUris: [ClientRedirectUri],
                tokenEndpointAuthMethod: WellKnownClientAuthenticationMethods.PrivateKeyJwt,
                jwksUri: jwksUrl.OriginalString);
            DocumentHost.Publish(DocumentPath, Encoding.UTF8.GetBytes(documentJson), "application/json");

            Shell = new TestHostShell(Time);
            As1 = Shell.Host("default");
            As2 = Shell.AddHost(As2HostName, useDistinctCertificate: true);

            ClientRecord stub1 = Shell.RegisterCimdStubClient(
                ClientIdentifierUrl,
                ImmutableHashSet.Create(
                    WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
                    WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
                    WellKnownCapabilityIdentifiers.OAuthTokenExchange,
                    WellKnownCapabilityIdentifiers.OAuthIdJag,
                    WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
                    WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                    WellKnownCapabilityIdentifiers.OAuthJwksEndpoint),
                profile: PolicyProfile.Rfc6749WithPkce);
            stub1 = ApplyStubUpdate(As1, stub1, AugmentAs1Stub(stub1));
            Segment1 = stub1.TenantId.Value;

            //AS2 is truly jwt-bearer-only: the RFC 9068 access-token producer's
            //RequiredCapability is null (an optional feature gate, not a grant-capability
            //proxy — see Rfc9068AccessTokenProducer's remarks), so the jwt-bearer redeem mints
            //an access token without AS2 ever declaring OAuthAuthorizationCode.
            ClientRecord stub2 = Shell.RegisterCimdStubClientOnHost(
                As2HostName,
                ClientIdentifierUrl,
                ImmutableHashSet.Create(
                    WellKnownCapabilityIdentifiers.OAuthJwtBearer,
                    WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
                    WellKnownCapabilityIdentifiers.OAuthJwksEndpoint),
                profile: PolicyProfile.Rfc6749WithPkce);
            stub2 = ApplyStubUpdate(As2, stub2, AugmentAs2Stub(stub2));
            Segment2 = stub2.TenantId.Value;
            As2TokenSigningKeyId = stub2.SigningKeys[KeyUsageContext.AccessTokenIssuance].Current[0];

            //RFC 9207 emission on the Rfc6749WithPkce baseline (see the class remarks for why the
            //profiles that emit iss by default cannot be used here).
            AuthorizationServerIntegration as1OAuth = As1.Server.OAuth();
            as1OAuth.ResolvePolicyAsync = async (registration, context, ct) =>
            {
                await PolicyProfiles.DefaultResolvePolicyAsync((ClientRecord)registration, context, ct)
                    .ConfigureAwait(false);
                context.SetEmitIssOnRedirect(true);
            };

            (OAuthClient as1Client, ClientRegistration as1Registration, Dictionary<string, FlowState> as1FlowStore) =
                await Shell.CreateOAuthClientAndRegistrationAsync(
                    stub1, ClientRedirectUri.OriginalString, profile: PolicyProfile.Rfc6749WithPkce, cancellationToken)
                    .ConfigureAwait(false);
            As1Client = as1Client;
            //The CIMD document declares private_key_jwt (see documentJson above); carrying the
            //matching AuthenticationMethod + AuthenticationKeyMaterial on the client-side
            //registration lets the real AuthCodeFlowHandlers.HandleTokenAsync (D6) attach the
            //client_assertion itself, rather than DriveStep3Async hand-signing one.
            As1Registration = as1Registration with
            {
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                AuthenticationKeyMaterial = ClientKeys
            };
            As1FlowStore = as1FlowStore;
            As1Issuer = as1Registration.AuthorizationServerIssuer;

            await Shell.StartHttpHostAsync(As2HostName, cancellationToken).ConfigureAwait(false);
            ClientRecord alignedStub2 = Shell.AlignRegistrationToHostHttpBase(As2HostName, stub2);
            As2Issuer = alignedStub2.IssuerUri!;
            (As2Client, As2Registration) = BuildOAuthClientForHost(As2, alignedStub2, Time);

            As1TokenEndpoint = new Uri(
                As1.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, Segment1));
            As2TokenEndpoint = new Uri(
                As2.HttpBaseAddress!, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, Segment2));

            //CIMD materialization on BOTH AS hosts. TestHostShell.WireCimdMaterialization pins the
            //resolver's transport to a SINGLE document-host certificate; the §8.2 topology needs
            //the resolver to reach the document host AND the separate jwks_uri host, so the
            //integration is wired directly over a two-certificate pinned, single-hop client —
            //mirroring WireCimdMaterialization's own body, including the scoped loopback
            //SSRF-policy relaxation on the live per-request ExchangeContext.
            ResolverHttpClient = LoopbackTls.CreateSingleHopPinnedHttpClient(
                [DocumentHost.Certificate, JwksHost.Certificate]);
            OutboundTransportDelegate resolverTransport =
                GuardedHttpClientTransport.BuildSingleHopTransport(ResolverHttpClient);
            ResolveClientMetadataDelegate resolve = ClientIdMetadataDocuments.BuildResolving(
                resolverTransport, new ClientIdMetadataDocumentResolverOptions(), Time);

            foreach(HostedAuthorizationServer host in new[] { As1, As2 })
            {
                AuthorizationServerIntegration oauth = host.Server.OAuth();
                oauth.MaterializeRegistrationAsync = ClientIdMetadataMaterialization.Build();
                oauth.ResolveClientMetadataAsync = (clientMetadataUri, context, ct) =>
                {
                    context.SetOutboundFetchPolicy(TestHostShell.LoopbackOutboundFetchPolicy);

                    return resolve(clientMetadataUri, context, ct);
                };
            }

            //RFC 7523 §3 item 3 accepts the token endpoint URL as an aud value; the
            //OAuthClient.IdJag flows sign their client assertions with exactly that audience.
            as1OAuth.ValidateClientCredentialsAsync = PrivateKeyJwtClientAuthentication.BuildValidator(
                additionalAcceptedAudiences: [As1TokenEndpoint.OriginalString]);
            As2.Server.OAuth().ValidateClientCredentialsAsync = PrivateKeyJwtClientAuthentication.BuildValidator(
                additionalAcceptedAudiences: [As2TokenEndpoint.OriginalString]);

            As1JwksKeys = await FetchJwksKeysAsync(
                As1.SharedHttpClient!, As1.HttpBaseAddress!, Segment1, cancellationToken).ConfigureAwait(false);
            As2JwksKeys = await FetchJwksKeysAsync(
                As2.SharedHttpClient!, As2.HttpBaseAddress!, Segment2, cancellationToken).ConfigureAwait(false);

            as1OAuth.ValidateTokenExchangeTokenAsync = (token, tokenType, registration, context, ct) =>
                ValidateStep3IdTokenAsync(token, tokenType, registration, ct);
            as1OAuth.AuthorizeTokenExchangeAsync = (subject, actor, request, registration, context, ct) =>
                AuthorizeMint(subject, request);

            As2.Server.OAuth().ValidateJwtBearerAssertionAsync = (assertion, requestedScope, registration, context, ct) =>
                ValidateJagForRedeemAsync(assertion, registration, ct);

            Rs1 = new TestResourceServerShell(
                trustedIssuer: As1Issuer,
                expectedAudience: Rs1Audience,
                resolveVerificationKey: BuildMapResolver(As1JwksKeys),
                verifySignature: MicrosoftCryptographicFunctions.VerifyP256Async,
                timeProvider: Time,
                requiredScope: Rs1RequiredScope);
            await Rs1.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);

            Rs2 = new TestResourceServerShell(
                trustedIssuer: As2Issuer,
                expectedAudience: Rs2Audience,
                resolveVerificationKey: BuildMapResolver(As2JwksKeys),
                verifySignature: MicrosoftCryptographicFunctions.VerifyP256Async,
                timeProvider: Time,
                requiredScope: Rs2RequiredScope);
            await Rs2.StartHttpHostAsync(cancellationToken).ConfigureAwait(false);

            BrowserClient = LoopbackTls.CreateSingleHopPinnedHttpClient(
                [Shell.HostCertificate("default"), Shell.HostCertificate(As2HostName)]);

            Rs1Http = LoopbackTls.CreatePinnedHttpClient(Rs1.HttpCertificate!, Rs1.HttpBaseAddress);
            Rs2Http = LoopbackTls.CreatePinnedHttpClient(Rs2.HttpCertificate!, Rs2.HttpBaseAddress);
        }


        /// <summary>
        /// Drives scenario step 3 entirely through the real client surface: PAR → authorize →
        /// callback → token exchange via the shared <see cref="AuthCodeFlowDriver"/>, whose token
        /// leg runs the production <see cref="AuthCodeFlowHandlers.HandleTokenAsync(IReadOnlyDictionary{string, string}, OAuthClientInfrastructure, ClientRegistration, ExchangeContext, ClientAssertionOptions?, System.Threading.CancellationToken)"/>
        /// path (D6) — the CIMD document declares <c>private_key_jwt</c>, so
        /// <see cref="As1Registration"/> carries a matching <see cref="ClientAssertionOptions"/>
        /// and the library itself signs and attaches the <c>client_assertion</c>; AS1's
        /// fail-closed declared-client-auth invariant refuses an unauthenticated token request.
        /// Records the granted scope from the minted access token as the ICHAIN-024 ceiling.
        /// </summary>
        public async Task<CapstoneStep3Result> DriveStep3Async(string scope, CancellationToken cancellationToken)
        {
            AuthCodeFlowDriveResult drive = await AuthCodeFlowDriver.DriveParAuthorizeCallbackAndTokenAsync(
                As1, As1Client, As1Registration, As1FlowStore, Segment1, ClientRedirectUri, SubjectId,
                BrowserClient, scope,
                clientAssertionOptions: new ClientAssertionOptions
                {
                    SigningKeyId = ClientSigningKeyId,
                    HeaderSerializer = CapstoneHeaderSerializer,
                    PayloadSerializer = CapstonePayloadSerializer
                },
                cancellationToken: cancellationToken).ConfigureAwait(false);

            IReadOnlyDictionary<string, object> body = drive.TokenResult.Body!;
            Assert.AreEqual(WellKnownAuthenticationSchemes.Bearer, (string)body[OAuthRequestParameterNames.TokenType]);
            string accessToken = (string)body[OAuthRequestParameterNames.AccessToken];

            Assert.IsTrue(
                body.TryGetValue(OAuthRequestParameterNames.IdToken, out object? idTokenObject)
                    && idTokenObject is string { Length: > 0 },
                "The step-3 token response must carry a REAL OIDC id_token.");
            string idToken = (string)idTokenObject!;

            string grantedScope;
            using(JsonDocument accessClaims = DecodePayload(accessToken))
            {
                grantedScope = accessClaims.RootElement.GetProperty(WellKnownJwtClaimNames.Scope).GetString()!;
            }

            Step3GrantedScope = grantedScope;

            return new CapstoneStep3Result
            {
                FlowId = drive.FlowId,
                AuthorizeLocation = drive.AuthorizeLocation,
                AccessToken = accessToken,
                IdToken = idToken,
                GrantedScope = grantedScope
            };
        }


        /// <summary>Mints a JAG via <c>OAuthClient.IdJag</c>, asserting success, and returns it.</summary>
        public async Task<string> MintJagAsync(string idToken, string scope, CancellationToken cancellationToken)
        {
            var mintResult = await As1Client.IdJag.MintAsync(
                As1Registration, BuildMintOptions(idToken, scope), cancellationToken).ConfigureAwait(false);
            Assert.IsTrue(mintResult.IsSuccess, mintResult.Error?.Support.Summary);

            return mintResult.Value.AccessToken;
        }


        public IdJagMintOptions BuildMintOptions(string idToken, string scope) => new()
        {
            Audience = As2Issuer.OriginalString,
            SubjectToken = idToken,
            SubjectTokenType = TokenType.IdToken,
            SigningKey = ClientKeys.PrivateKey,
            SigningKeyId = ClientSigningKeyId,
            HeaderSerializer = CapstoneHeaderSerializer,
            PayloadSerializer = CapstonePayloadSerializer,
            Scope = scope
        };


        public IdJagRedeemOptions BuildRedeemOptions(string jag) => new()
        {
            Assertion = jag,
            SigningKey = ClientKeys.PrivateKey,
            SigningKeyId = ClientSigningKeyId,
            HeaderSerializer = CapstoneHeaderSerializer,
            PayloadSerializer = CapstonePayloadSerializer
        };


        /// <summary>Signs a valid <c>private_key_jwt</c> client assertion addressed to AS2's token endpoint.</summary>
        public ValueTask<string> SignClientAssertionForAs2Async(CancellationToken cancellationToken) =>
            ClientAssertionSigning.SignAsync(
                ClientIdentifierUrl.OriginalString,
                As2TokenEndpoint.OriginalString,
                Guid.NewGuid().ToString("N"),
                Time.GetUtcNow(),
                Time.GetUtcNow().AddMinutes(5),
                ClientKeys.PrivateKey,
                ClientSigningKeyId,
                CapstoneHeaderSerializer,
                CapstonePayloadSerializer,
                TestSetup.Base64UrlEncoder,
                TestHostShell.MemoryPool,
                cancellationToken);


        /// <summary>
        /// Stops the six hosts (idempotent). The happy path calls this before the trace-tree
        /// assertions so every server span has stopped and reached the capture.
        /// </summary>
        public async ValueTask StopHostsAsync()
        {
            if(hasStoppedHosts)
            {
                return;
            }

            hasStoppedHosts = true;

            await Rs2.DisposeAsync().ConfigureAwait(false);
            await Rs1.DisposeAsync().ConfigureAwait(false);
            await Shell.DisposeAsync().ConfigureAwait(false);
            await JwksHost.DisposeAsync().ConfigureAwait(false);
            await DocumentHost.DisposeAsync().ConfigureAwait(false);
        }


        public async ValueTask DisposeAsync()
        {
            if(isDisposed)
            {
                return;
            }

            isDisposed = true;

            await StopHostsAsync().ConfigureAwait(false);

            BrowserClient.Dispose();
            Rs1Http.Dispose();
            Rs2Http.Dispose();
            ResolverHttpClient.Dispose();

            foreach(PublicKeyMemory key in As1JwksKeys.Values)
            {
                key.Dispose();
            }

            foreach(PublicKeyMemory key in As2JwksKeys.Values)
            {
                key.Dispose();
            }

            ClientKeys.PublicKey.Dispose();
            ClientKeys.PrivateKey.Dispose();
        }


        /// <summary>
        /// AS-owned facets the CIMD stub needs for this scenario, overlaid onto the registered
        /// record: the OIDC id_token signing key (reusing the tenant's token-signing key under
        /// <see cref="KeyUsageContext.IdTokenIssuance"/>), the resource scopes, and the
        /// scope→audience map the RFC 9068 producer stamps <c>aud</c> from. Client-data facets
        /// (redirect URIs, auth method, jwks) still arrive ONLY via materialization.
        /// </summary>
        private static ClientRecord AugmentAs1Stub(ClientRecord stub)
        {
            KeyId tokenSigningKeyId = stub.SigningKeys[KeyUsageContext.AccessTokenIssuance].Current[0];

            return stub with
            {
                AllowedScopes = stub.AllowedScopes.Union([Rs1RequiredScope, Rs2RequiredScope]),
                SigningKeys = stub.SigningKeys.ToImmutableDictionary().Add(
                    KeyUsageContext.IdTokenIssuance, new SigningKeySet { Current = [tokenSigningKeyId] }),
                ScopeToAudience = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
                {
                    [WellKnownScopes.OpenId] = new[] { Rs1Audience },
                    [Rs1RequiredScope] = new[] { Rs1Audience }
                }
            };
        }


        private static ClientRecord AugmentAs2Stub(ClientRecord stub) => stub with
        {
            AllowedScopes = stub.AllowedScopes.Union([Rs2RequiredScope]),
            ScopeToAudience = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
            {
                [Rs2RequiredScope] = new[] { Rs2Audience }
            }
        };


        private static ClientRecord ApplyStubUpdate(
            HostedAuthorizationServer host, ClientRecord original, ClientRecord updated)
        {
            host.Registrations[updated.TenantId.Value] = updated;
            host.Registrations[updated.ClientId] = updated;
            host.Server.UpdateClient(original, updated, new ExchangeContext());

            return updated;
        }


        /// <summary>
        /// The AS1 mint-side subject-token seam (ID-JAG §4.3.3 / ICHAIN-017): verifies the
        /// presented id_token's signature against AS1's JWKS fetched over the wire at validation
        /// time, checks <c>aud</c> equals the authenticated client_id, <c>iss</c> equals AS1's
        /// issuer, and the expiry, then surfaces the subject and the step-3 grant as the scope
        /// ceiling. Any failure — including an absent step-3 grant — returns
        /// <see langword="null"/>, refusing the exchange.
        /// </summary>
        private async ValueTask<ValidatedSecurityToken?> ValidateStep3IdTokenAsync(
            string token, TokenType tokenType, ClientRecord registration, CancellationToken cancellationToken)
        {
            if(tokenType != TokenType.IdToken)
            {
                return null;
            }

            string[] parts = token.Split('.');
            if(parts.Length != 3)
            {
                return null;
            }

            JwtHeader header;
            using(IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], Pool))
            {
                header = JwsAccessTokenTestSupport.Parser.ParseHeader(headerBytes.Memory);
            }

            if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidValue) || kidValue is not string kid)
            {
                return null;
            }

            Dictionary<string, PublicKeyMemory> liveKeys = await FetchJwksKeysAsync(
                As1.SharedHttpClient!, As1.HttpBaseAddress!, Segment1, cancellationToken).ConfigureAwait(false);
            try
            {
                if(!liveKeys.TryGetValue(kid, out PublicKeyMemory? verificationKey))
                {
                    return null;
                }

                bool isSignatureValid = await Jws.VerifyAsync(
                    token, TestSetup.Base64UrlDecoder, Pool, verificationKey,
                    MicrosoftCryptographicFunctions.VerifyP256Async, cancellationToken).ConfigureAwait(false);
                if(!isSignatureValid)
                {
                    return null;
                }
            }
            finally
            {
                foreach(PublicKeyMemory key in liveKeys.Values)
                {
                    key.Dispose();
                }
            }

            JwtPayload payload;
            using(IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool))
            {
                payload = JwsAccessTokenTestSupport.Parser.ParseClaims(payloadBytes.Memory);
            }

            //ID-JAG §4.3.3 / ICHAIN-017: the Identity Assertion's audience must be the
            //authenticating client — the aud OIDC stamped is the client_id.
            if(!payload.TryGetValue(WellKnownJwtClaimNames.Aud, out object? audienceRaw)
                || !IsAudienceExactly(audienceRaw, registration.ClientId))
            {
                return null;
            }

            if(!TryReadStringClaim(payload, WellKnownJwtClaimNames.Iss, out string? issuer)
                || !string.Equals(issuer, As1Issuer.OriginalString, StringComparison.Ordinal))
            {
                return null;
            }

            DateTimeOffset? expiresAt = ReadUnixSecondsClaim(payload, WellKnownJwtClaimNames.Exp);
            if(expiresAt is null || expiresAt.Value <= Time.GetUtcNow())
            {
                return null;
            }

            if(!TryReadStringClaim(payload, WellKnownJwtClaimNames.Sub, out string? subject))
            {
                return null;
            }

            string? grantedScope = Step3GrantedScope;
            if(grantedScope is null)
            {
                return null;
            }

            return new ValidatedSecurityToken
            {
                Subject = subject!,
                Issuer = issuer,
                Audience = [registration.ClientId],
                Scope = grantedScope,
                ExpiresAt = expiresAt
            };
        }


        /// <summary>
        /// The AS1 mint-side authorization seam: only id-jag exchanges are authorized, and only
        /// when the requested JAG scope is a subset of the step-3 grant the validated subject
        /// token carries (ICHAIN-024). A denial returns <see langword="null"/>, which the id-jag
        /// path maps to <c>invalid_grant</c>.
        /// </summary>
        private static ValueTask<TokenExchangeAuthorization?> AuthorizeMint(
            ValidatedSecurityToken subject, TokenExchangeRequest request)
        {
            if(request.RequestedTokenType != TokenType.IdJag)
            {
                return ValueTask.FromResult<TokenExchangeAuthorization?>(null);
            }

            string? requestedScope = request.Scope;
            string? ceiling = subject.Scope;
            if(requestedScope is null || ceiling is null || !IsScopeSubset(requestedScope, ceiling))
            {
                return ValueTask.FromResult<TokenExchangeAuthorization?>(null);
            }

            return ValueTask.FromResult<TokenExchangeAuthorization?>(new TokenExchangeAuthorization
            {
                Subject = subject.Subject,
                Scope = requestedScope,
                IssuedTokenType = TokenType.IdJag
            });
        }


        /// <summary>
        /// The AS2 redeem-side seam (ID-JAG §4.4.1 / §9.3): resolves the JAG's signing key by
        /// <c>kid</c> from the issuing servers' wire-fetched JWKS, verifies the signature, applies
        /// <see cref="IdJagAssertionValidation.Validate"/> with AS2's issuer and the authenticated
        /// client, and surfaces <c>iss</c>/<c>jti</c>/<c>exp</c> so the endpoint's
        /// <see cref="JtiReplayGuard"/> enforces the replay defense. Returns
        /// <see langword="null"/> (→ <c>invalid_grant</c>) on any failure.
        /// </summary>
        private async ValueTask<JwtBearerGrant?> ValidateJagForRedeemAsync(
            string assertion, ClientRecord registration, CancellationToken cancellationToken)
        {
            string[] parts = assertion.Split('.');
            if(parts.Length != 3)
            {
                return null;
            }

            JwtHeader header;
            using(IMemoryOwner<byte> headerBytes = TestSetup.Base64UrlDecoder(parts[0], Pool))
            {
                header = JwsAccessTokenTestSupport.Parser.ParseHeader(headerBytes.Memory);
            }

            if(!header.TryGetValue(WellKnownJwkMemberNames.Kid, out object? kidValue) || kidValue is not string kid)
            {
                return null;
            }

            JwtPayload payload;
            using(IMemoryOwner<byte> payloadBytes = TestSetup.Base64UrlDecoder(parts[1], Pool))
            {
                payload = JwsAccessTokenTestSupport.Parser.ParseClaims(payloadBytes.Memory);
            }

            //ID-JAG §9.5: trust in the grant derives from its own iss, never from a
            //pooled key set — the verification key MUST come from the JWKS the issuer
            //named in iss publishes, so a JAG signed with any other trust domain's key
            //(even one otherwise trusted) is rejected before claim validation.
            if(!TryReadStringClaim(payload, WellKnownJwtClaimNames.Iss, out string? grantIssuer))
            {
                return null;
            }

            Dictionary<string, PublicKeyMemory>? issuerKeys =
                string.Equals(grantIssuer, As1Issuer.OriginalString, StringComparison.Ordinal) ? As1JwksKeys
                : string.Equals(grantIssuer, As2Issuer.OriginalString, StringComparison.Ordinal) ? As2JwksKeys
                : null;
            if(issuerKeys is null || !issuerKeys.TryGetValue(kid, out PublicKeyMemory? verificationKey))
            {
                return null;
            }

            bool isSignatureValid = await Jws.VerifyAsync(
                assertion, TestSetup.Base64UrlDecoder, Pool, verificationKey,
                MicrosoftCryptographicFunctions.VerifyP256Async, cancellationToken).ConfigureAwait(false);
            if(!isSignatureValid)
            {
                return null;
            }

            IdJagAssertionValidationResult result = IdJagAssertionValidation.Validate(
                header, payload, As2Issuer.OriginalString, registration.ClientId,
                Time.GetUtcNow(), TimeSpan.FromSeconds(60));
            if(!result.IsValid)
            {
                return null;
            }

            return new JwtBearerGrant
            {
                Subject = result.Subject!,
                Scope = result.Scope ?? string.Empty,
                Audience = result.Resource,
                AuthorizationDetailsClaim = result.AuthorizationDetails,
                RequiredKeyThumbprint = result.ConfirmationKeyThumbprint,
                Issuer = result.Issuer,
                Jti = result.Jti,
                Expiration = result.Expiration
            };
        }


        /// <summary>
        /// Fetches a tenant's published JWKS over the real wire and materializes the keys into a
        /// kid-indexed map the resolvers and the resource servers consult. The caller owns
        /// disposing the returned <see cref="PublicKeyMemory"/> values.
        /// </summary>
        private static async Task<Dictionary<string, PublicKeyMemory>> FetchJwksKeysAsync(
            HttpClient httpClient, Uri hostBaseAddress, string segment, CancellationToken cancellationToken)
        {
            Uri jwksUrl = new(
                hostBaseAddress, TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.MetadataJwks, segment));
            using HttpResponseMessage response = await httpClient.GetAsync(jwksUrl, cancellationToken)
                .ConfigureAwait(false);
            string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
            Assert.AreEqual(200, (int)response.StatusCode, body);

            Dictionary<string, PublicKeyMemory> keysByKid = new(StringComparer.Ordinal);
            using JsonDocument document = JsonDocument.Parse(body);
            foreach(JsonElement key in document.RootElement.GetProperty(WellKnownJwkMemberNames.Keys).EnumerateArray())
            {
                string kid = key.GetProperty(WellKnownJwkMemberNames.Kid).GetString()!;
                Dictionary<string, string> jwk = new(StringComparer.Ordinal);
                foreach(JsonProperty member in key.EnumerateObject())
                {
                    if(member.Value.ValueKind == JsonValueKind.String)
                    {
                        jwk[member.Name] = member.Value.GetString()!;
                    }
                }

                keysByKid[kid] = DpopJwkUtilities.PublicKeyFromJwk(
                    jwk, WellKnownJwaValues.Es256, TestSetup.Base64UrlDecoder, Pool);
            }

            return keysByKid;
        }


        private static ServerVerificationKeyResolverDelegate BuildMapResolver(
            Dictionary<string, PublicKeyMemory> keysByKid) =>
            (kid, tenantId, context, cancellationToken) =>
                ValueTask.FromResult(keysByKid.GetValueOrDefault(kid.Value));


        /// <summary>
        /// Builds an HTTP-backed <see cref="OAuthClient"/> targeting a NAMED shell host —
        /// <see cref="TestHostShell.CreateOAuthClientAndRegistrationAsync"/> is fixed to the
        /// <c>default</c> host, and the capstone's redeem must dial AS2. Mirrors that factory's
        /// wiring over the named host's pinned <see cref="HostedAuthorizationServer.SharedHttpClient"/>.
        /// </summary>
        private static (OAuthClient Client, ClientRegistration Registration) BuildOAuthClientForHost(
            HostedAuthorizationServer host, ClientRecord alignedRecord, TimeProvider timeProvider)
        {
            Dictionary<string, FlowState> clientFlowStore = [];
            string segment = alignedRecord.TenantId.Value;
            Uri issuerUri = alignedRecord.IssuerUri!;

            AuthorizationServerMetadata metadata = new()
            {
                Issuer = issuerUri,
                TokenEndpoint = new Uri(
                    host.HttpBaseAddress!,
                    TestHostShell.ComposeEndpointPath(WellKnownEndpointNames.AuthCodeToken, segment))
            };

            HttpClient httpClient = host.SharedHttpClient!;

            OAuthClientInfrastructure infrastructure = OAuthClientInfrastructure.Create(
                sendFormPostAsync: (endpoint, fields, headers, _, ct) =>
                    HttpClientTransport.SendFormPostAsync(httpClient, endpoint, fields, headers, ct),
                saveStateAsync: (state, _, ct) =>
                {
                    clientFlowStore[state.FlowId] = state;

                    return ValueTask.CompletedTask;
                },
                loadStateAsync: (flowId, _, ct) =>
                    ValueTask.FromResult(clientFlowStore.GetValueOrDefault(flowId)),
                loadStateByRequestUriAsync: (requestUri, _, ct) =>
                    ValueTask.FromResult<FlowState?>(null),
                parseParResponseAsync: OAuthResponseParsers.ParseParResponse,
                parseTokenResponseAsync: OAuthResponseParsers.ParseTokenResponse,
                parseAuthorizationServerMetadataAsync: (body, ct) =>
                    throw new NotImplementedException("The capstone pre-resolves metadata; the parser is not exercised."),
                parseRegistrationResponseAsync: (body, ct) =>
                    throw new NotImplementedException("The capstone does not exercise dynamic registration."),
                resolveAuthorizationServerMetadataAsync: (issuer, context, ct) =>
                    ValueTask.FromResult(metadata),
                resolveCallbackValidator: ClientPolicyProfiles.DefaultResolveCallbackValidator,
                base64UrlEncoder: TestSetup.Base64UrlEncoder,
                timeProvider: timeProvider);

            ClientRegistration registration = new()
            {
                ClientId = new ClientId(alignedRecord.ClientId),
                AuthorizationServerIssuer = issuerUri,
                RedirectUris = [ClientRedirectUri],
                AuthenticationMethod = ClientAuthenticationMethod.PrivateKeyJwt,
                Profile = PolicyProfile.Rfc6749WithPkce
            };

            return (new OAuthClient(infrastructure), registration);
        }


        private static bool IsAudienceExactly(object? audienceRaw, string expected) => audienceRaw switch
        {
            string single => string.Equals(single, expected, StringComparison.Ordinal),
            IReadOnlyList<object> list when list.Count == 1 && list[0] is string only =>
                string.Equals(only, expected, StringComparison.Ordinal),
            _ => false
        };


        private static bool TryReadStringClaim(JwtPayload payload, string claimName, out string? value)
        {
            if(payload.TryGetValue(claimName, out object? raw) && raw is string text && text.Length > 0)
            {
                value = text;

                return true;
            }

            value = null;

            return false;
        }


        private static DateTimeOffset? ReadUnixSecondsClaim(JwtPayload payload, string claimName)
        {
            if(!payload.TryGetValue(claimName, out object? raw))
            {
                return null;
            }

            long? seconds = raw switch
            {
                long longValue => longValue,
                int intValue => intValue,
                double doubleValue when doubleValue == Math.Floor(doubleValue) => (long)doubleValue,
                _ => null
            };

            return seconds is null ? null : DateTimeOffset.FromUnixTimeSeconds(seconds.Value);
        }
    }
}
