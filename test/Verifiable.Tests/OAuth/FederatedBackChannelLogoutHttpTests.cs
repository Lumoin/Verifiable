using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.OAuth;
using Verifiable.OAuth.Logout;
using Verifiable.OAuth.Pkce;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Slice 5d — federated logout end-to-end over real HTTP. One OP session is shared
/// across two relying parties (SSO: one OP <c>sid</c>, two RP sessions). The user logs
/// out at the OP; the OP terminates the local session and fans a signed
/// <c>logout_token</c> out to <em>every</em> registered RP over a real socket. Each RP
/// reconstructs the token from the wire bytes plus the OP's published public key alone,
/// runs the full OIDC Back-Channel Logout 1.0 §2.6 validation, and drops its session
/// keyed by the <c>sid</c>.
/// </summary>
/// <remarks>
/// <para>
/// Firewalled: the only OP secret an RP ever holds is the OP's <em>public</em>
/// verification key (handed over once, as registration trust would carry it). No private
/// key, salt, or in-memory session object crosses the OP→RP boundary — an RP sees the
/// compact token bytes and nothing else.
/// </para>
/// <para>
/// Scope choice (per the slice's latitude): the OP drives its session setup and the
/// <c>end_session</c> trigger in-process — that path is already covered by
/// <see cref="EndSessionLogoutTests.EndSessionFansOutBackChannelLogoutAfterTerminate"/> —
/// while the security-critical OP→RP <c>logout_token</c> delivery crosses a real Kestrel
/// socket to each RP receiver. This multi-RP HTTP propagation is the new realism the
/// slice adds; a full Federation trust-ring is not a dependency (Back-Channel Logout is
/// OP→RP, not a federation-trust feature).
/// </para>
/// </remarks>
[TestClass]
internal sealed class FederatedBackChannelLogoutHttpTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The memory pool used for all transient signing/verification buffers.</summary>
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>The OP issuer every RP is configured, out of band, to expect on a Logout Token's <c>iss</c>.</summary>
    private const string OpIssuer = "https://op.example/";

    /// <summary>The end-user subject logged out across all RPs.</summary>
    private const string SubjectId = "subject-sso-1";

    /// <summary>The single OP session shared by both RP sessions — the "SSO" session.</summary>
    private const string SsoSessionId = "session-sso";

    /// <summary>The redirect URI every client registered by the host shares.</summary>
    private static readonly Uri RedirectUri = new("https://client.example.com/callback");

    /// <summary>
    /// Auth-code/OIDC defaults plus both logout capabilities. RP-Initiated Logout
    /// activates the <c>end_session</c> endpoint; Back-Channel Logout opens the fan-out
    /// drop-out after the local session is terminated.
    /// </summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> RpCapabilities =
        ImmutableHashSet.Create(
            WellKnownCapabilityIdentifiers.OAuthAuthorizationCode,
            WellKnownCapabilityIdentifiers.OAuthPushedAuthorization,
            WellKnownCapabilityIdentifiers.OidcOpenIdConnect,
            WellKnownCapabilityIdentifiers.OAuthDiscoveryEndpoint,
            WellKnownCapabilityIdentifiers.OAuthJwksEndpoint,
            WellKnownCapabilityIdentifiers.OidcRpInitiatedLogout,
            WellKnownCapabilityIdentifiers.OidcBackChannelLogout);


    /// <summary>
    /// One OP logout propagates the <c>logout_token</c> to both registered RPs over HTTP;
    /// each verifies §2.6 against the OP public key + its own <c>client_id</c> and drops
    /// exactly the shared SSO session.
    /// </summary>
    [TestMethod]
    public async Task FederatedLogoutPropagatesLogoutTokenToEveryRegisteredRpOverHttp()
    {
        //The OP's back-channel signing key. The private half signs Logout Tokens OP-side;
        //the public half is the only OP secret the RPs hold (a published verification key
        //MAY cross to the verifier).
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> opKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PrivateKeyMemory opPrivate = opKeys.PrivateKey;
        using PublicKeyMemory opPublic = opKeys.PublicKey;

        await using TestHostShell op = new(TimeProvider);
        op.SeedTestSubject(subject: SubjectId);

        //Two relying parties, each a real receiver endpoint over loopback Kestrel. Each
        //verifies an incoming Logout Token against the OP public key and its own
        //client_id, and on a valid §2.6 token drops the session keyed by sid.
        await using RelyingPartyReceiver rp1 = await RelyingPartyReceiver.StartAsync(
            "https://rp1.example.com", opPublic, OpIssuer, TestContext.CancellationToken).ConfigureAwait(false);
        await using RelyingPartyReceiver rp2 = await RelyingPartyReceiver.StartAsync(
            "https://rp2.example.com", opPublic, OpIssuer, TestContext.CancellationToken).ConfigureAwait(false);

        using VerifierKeyMaterial rp1Material = op.RegisterBackChannelLogoutClient(
            rp1.ClientId, new Uri(rp1.ClientId), rp1.BackChannelLogoutUri, RpCapabilities);
        using VerifierKeyMaterial rp2Material = op.RegisterBackChannelLogoutClient(
            rp2.ClientId, new Uri(rp2.ClientId), rp2.BackChannelLogoutUri, RpCapabilities);

        //SSO: one OP session, an id_token to each RP carrying sub + the shared sid. As
        //each is issued, record the RP in the OP-side session→RP registry the deliver
        //seam fans out over, sourcing the delivery URL from the registered ClientRecord.
        List<RegisteredRelyingParty> session = [];
        string rp1IdToken = await IssueIdTokenAsync(op, rp1Material, SsoSessionId).ConfigureAwait(false);
        session.Add(new RegisteredRelyingParty(
            rp1Material.Registration.ClientId, rp1Material.Registration.BackchannelLogoutUri!));
        _ = await IssueIdTokenAsync(op, rp2Material, SsoSessionId).ConfigureAwait(false);
        session.Add(new RegisteredRelyingParty(
            rp2Material.Registration.ClientId, rp2Material.Registration.BackchannelLogoutUri!));

        //Each RP now holds a live session keyed by the OP sid.
        rp1.SeedSession(SsoSessionId);
        rp2.SeedSession(SsoSessionId);

        //Wire the OP seams: terminate the local session, then build and POST a Logout
        //Token (aud = that RP's client_id) to every RP in the session over real HTTP.
        using HttpClient deliveryClient = new();
        op.Server.OAuth().TerminateSessionAsync = (_, _, _, _, _) => ValueTask.CompletedTask;
        op.Server.OAuth().DeliverBackChannelLogoutAsync = async (subject, sessionId, _, _, ct) =>
        {
            foreach(RegisteredRelyingParty relyingParty in session)
            {
                string logoutToken = await BackChannelLogout.BuildLogoutTokenAsync(
                    OpIssuer,
                    relyingParty.ClientId,
                    jwtId: Guid.NewGuid().ToString("N"),
                    issuedAt: TimeProvider.GetUtcNow(),
                    subject: subject,
                    sessionId: sessionId,
                    opPrivate,
                    TestSetup.Base64UrlEncoder,
                    SecurityEventTestJson.HeaderSerializer,
                    SecurityEventTestJson.PayloadSerializer,
                    Pool,
                    ct,
                    signingKeyId: "op-key-1").ConfigureAwait(false);

                using FormUrlEncodedContent content = new(
                    [new KeyValuePair<string, string>(WellKnownTokenTypes.LogoutToken, logoutToken)]);
                using HttpResponseMessage delivery = await deliveryClient.PostAsync(
                    relyingParty.BackChannelLogoutUri, content, ct).ConfigureAwait(false);

                Assert.AreEqual(200, (int)delivery.StatusCode,
                    $"RP '{relyingParty.ClientId}' must acknowledge the Logout Token with 200.");
            }
        };

        //The user logs out at the OP (RP1 initiates RP-Initiated Logout). end_session
        //terminates the local session and drops out to the back-channel fan-out.
        ServerHttpResponse response = await op.DispatchAtEndpointAsync(
            rp1Material.Registration.TenantId.Value,
            WellKnownEndpointNames.EndSession,
            "GET",
            new RequestFields { [OAuthRequestParameterNames.IdTokenHint] = rp1IdToken },
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, response.StatusCode, response.Body);

        //Both RPs verified the Logout Token and dropped exactly the shared SSO session.
        Assert.Contains(SsoSessionId, rp1.VerifiedSessionIds, "RP1 must have verified and dropped the SSO session.");
        Assert.Contains(SsoSessionId, rp2.VerifiedSessionIds, "RP2 must have verified and dropped the SSO session.");
        Assert.IsFalse(rp1.HasActiveSession(SsoSessionId), "RP1 must no longer hold the SSO session.");
        Assert.IsFalse(rp2.HasActiveSession(SsoSessionId), "RP2 must no longer hold the SSO session.");
        Assert.AreEqual(SubjectId, rp1.LastSubject, "RP1 must extract the logged-out subject.");
        Assert.AreEqual(SubjectId, rp2.LastSubject, "RP2 must extract the logged-out subject.");
    }


    /// <summary>
    /// Drives PAR → Authorize (stamping subject + session id) → Token for the given RP
    /// and returns the issued ID Token — the value the RP later presents as
    /// <c>id_token_hint</c>. Mirrors <see cref="EndSessionLogoutTests"/>' issuance shape.
    /// </summary>
    /// <param name="host">The OP host.</param>
    /// <param name="material">The RP's registration + key material.</param>
    /// <param name="sessionId">The OP session id to stamp into the ID Token's <c>sid</c>.</param>
    /// <returns>The compact ID Token.</returns>
    private async Task<string> IssueIdTokenAsync(
        TestHostShell host, VerifierKeyMaterial material, string sessionId)
    {
        string clientId = material.Registration.ClientId;
        string tenant = material.Registration.TenantId.Value;

        PkceParameters pkce = PkceGeneration.Generate(TestSetup.Base64UrlEncoder, Pool);

        RequestFields parFields = new()
        {
            [OAuthRequestParameterNames.ClientId] = clientId,
            [OAuthRequestParameterNames.CodeChallenge] = pkce.EncodedChallenge,
            [OAuthRequestParameterNames.CodeChallengeMethod] = OAuthRequestParameterValues.CodeChallengeMethodS256,
            [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString,
            [OAuthRequestParameterNames.Scope] = WellKnownScopes.OpenId
        };
        ServerHttpResponse parResponse = await host.DispatchAtEndpointAsync(
            tenant, WellKnownEndpointNames.AuthCodePar, "POST",
            parFields, new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(201, parResponse.StatusCode, parResponse.Body);
        using JsonDocument parDoc = JsonDocument.Parse(parResponse.Body);
        string requestUri = parDoc.RootElement.GetProperty("request_uri").GetString()!;

        ExchangeContext authorizeContext = new();
        authorizeContext.SetSubjectId(SubjectId);
        authorizeContext.SetSessionId(sessionId);
        ServerHttpResponse authorizeResponse = await host.DispatchAtEndpointAsync(
            tenant, WellKnownEndpointNames.AuthCodeAuthorize, "GET",
            new RequestFields
            {
                [OAuthRequestParameterNames.ClientId] = clientId,
                [OAuthRequestParameterNames.RequestUri] = requestUri
            },
            authorizeContext, TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(302, authorizeResponse.StatusCode, authorizeResponse.Body);
        string code = ExtractCode(authorizeResponse.Location!);

        ServerHttpResponse tokenResponse = await host.DispatchAtEndpointAsync(
            tenant, WellKnownEndpointNames.AuthCodeToken, "POST",
            new RequestFields
            {
                [OAuthRequestParameterNames.GrantType] = OAuthRequestParameterValues.GrantTypeAuthorizationCode,
                [OAuthRequestParameterNames.Code] = code,
                [OAuthRequestParameterNames.CodeVerifier] = pkce.EncodedVerifier,
                [OAuthRequestParameterNames.ClientId] = clientId,
                [OAuthRequestParameterNames.RedirectUri] = RedirectUri.OriginalString
            },
            new ExchangeContext(), TestContext.CancellationToken).ConfigureAwait(false);
        Assert.AreEqual(200, tokenResponse.StatusCode, tokenResponse.Body);

        using JsonDocument tokenDoc = JsonDocument.Parse(tokenResponse.Body);

        return tokenDoc.RootElement.GetProperty("id_token").GetString()!;
    }


    /// <summary>Extracts the <c>code</c> query parameter from an authorize redirect Location.</summary>
    /// <param name="location">The redirect Location header value.</param>
    /// <returns>The decoded authorization code.</returns>
    private static string ExtractCode(string location)
    {
        int q = location.IndexOf('?', StringComparison.Ordinal);
        foreach(string pair in location[(q + 1)..].Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq > 0 && string.Equals(pair[..eq], OAuthRequestParameterNames.Code, StringComparison.Ordinal))
            {
                return Uri.UnescapeDataString(pair[(eq + 1)..]);
            }
        }

        throw new InvalidOperationException(
            $"Authorize redirect did not carry a code parameter: {location}");
    }
}


/// <summary>
/// One relying party as the OP-side fan-out sees it: the <c>client_id</c> the Logout
/// Token's <c>aud</c> must equal, and the absolute receiver URL the OP POSTs it to.
/// </summary>
/// <param name="ClientId">The RP's OAuth client identifier.</param>
/// <param name="BackChannelLogoutUri">The RP's back-channel logout receiver URL.</param>
internal readonly record struct RegisteredRelyingParty(string ClientId, Uri BackChannelLogoutUri);


/// <summary>
/// A relying-party back-channel-logout receiver: a real loopback HTTP endpoint that
/// verifies each delivered Logout Token (OP public key + this RP's <c>client_id</c>, full
/// §2.6) and, on a valid token, drops the session keyed by the token's <c>sid</c>. Holds
/// only per-RP state and the OP's published public key — never anything in-memory from
/// the OP side.
/// </summary>
internal sealed class RelyingPartyReceiver: IAsyncDisposable
{
    /// <summary>The relative path the OP POSTs this RP's <c>logout_token</c> to.</summary>
    private const string BackChannelLogoutPath = "/backchannel-logout";

    private readonly MinimalHttpHost host;
    private readonly PublicKeyMemory opPublic;
    private readonly string expectedIssuer;
    private readonly HashSet<string> activeSessions = new(StringComparer.Ordinal);
    private readonly List<string> verifiedSessionIds = [];


    private RelyingPartyReceiver(
        MinimalHttpHost host, string clientId, PublicKeyMemory opPublic, string expectedIssuer)
    {
        this.host = host;
        ClientId = clientId;
        this.opPublic = opPublic;
        this.expectedIssuer = expectedIssuer;
        BackChannelLogoutUri = new Uri(host.BaseAddress, BackChannelLogoutPath);
    }


    /// <summary>This RP's OAuth client identifier — the Logout Token <c>aud</c> it accepts.</summary>
    public string ClientId { get; }

    /// <summary>The absolute receiver URL the OP delivers this RP's <c>logout_token</c> to.</summary>
    public Uri BackChannelLogoutUri { get; }

    /// <summary>The <c>sid</c> values this RP has verified and dropped, in arrival order.</summary>
    public IReadOnlyList<string> VerifiedSessionIds => verifiedSessionIds;

    /// <summary>The <c>sub</c> of the most recently verified Logout Token, or <see langword="null"/>.</summary>
    public string? LastSubject { get; private set; }


    /// <summary>
    /// Starts a receiver on an ephemeral loopback port and returns it once the host is
    /// listening.
    /// </summary>
    /// <param name="clientId">The RP's OAuth client identifier.</param>
    /// <param name="opPublic">The OP's published public verification key.</param>
    /// <param name="expectedIssuer">The OP issuer the Logout Token's <c>iss</c> must equal.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The started receiver.</returns>
    public static async Task<RelyingPartyReceiver> StartAsync(
        string clientId, PublicKeyMemory opPublic, string expectedIssuer, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(clientId);
        ArgumentNullException.ThrowIfNull(opPublic);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedIssuer);

        //The handler closes over the receiver, assigned immediately after the host starts
        //listening — safe because no delivery arrives until the test POSTs later.
        RelyingPartyReceiver? receiver = null;
        MinimalHttpHost startedHost = await MinimalHttpHost.StartAsync(
            (request, ct) => receiver!.HandleAsync(request, ct), cancellationToken).ConfigureAwait(false);
        receiver = new RelyingPartyReceiver(startedHost, clientId, opPublic, expectedIssuer);

        return receiver;
    }


    /// <summary>Seeds an active session keyed by the OP <c>sid</c> — an RP-side login.</summary>
    /// <param name="sessionId">The OP session id this RP now holds.</param>
    public void SeedSession(string sessionId)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sessionId);
        activeSessions.Add(sessionId);
    }


    /// <summary>Whether this RP still holds an active session for <paramref name="sessionId"/>.</summary>
    /// <param name="sessionId">The OP session id to test.</param>
    /// <returns><see langword="true"/> while the session is live; <see langword="false"/> once dropped.</returns>
    public bool HasActiveSession(string sessionId) => activeSessions.Contains(sessionId);


    /// <summary>
    /// Handles one delivered <c>logout_token</c>: parses the form body, verifies §2.6 over
    /// the wire bytes, and on success drops the named session and records the verified
    /// identifiers. Returns 200 on a processed token, 400 otherwise (OIDC Back-Channel
    /// Logout 1.0 §2.5).
    /// </summary>
    /// <param name="request">The buffered delivery request.</param>
    /// <param name="cancellationToken">Cancellation token.</param>
    /// <returns>The acknowledgement response.</returns>
    private async Task<MinimalHttpResponse> HandleAsync(
        MinimalHttpRequest request, CancellationToken cancellationToken)
    {
        if(request.ContentType is null
            || !request.ContentType.StartsWith(WellKnownMediaTypes.Application.FormUrlEncoded, StringComparison.OrdinalIgnoreCase))
        {
            return new MinimalHttpResponse { StatusCode = 400 };
        }

        if(!TryGetFormValue(request.Body, WellKnownTokenTypes.LogoutToken, out string? logoutToken))
        {
            return new MinimalHttpResponse { StatusCode = 400 };
        }

        BackChannelLogoutVerificationResult result = await BackChannelLogout.VerifyLogoutTokenAsync(
            logoutToken,
            opPublic,
            expectedIssuer,
            ClientId,
            TestSetup.Base64UrlDecoder,
            bytes => SecurityEventTestJson.DeserializePart(bytes),
            BaseMemoryPool.Shared,
            cancellationToken).ConfigureAwait(false);

        if(!result.IsValid)
        {
            return new MinimalHttpResponse { StatusCode = 400 };
        }

        //§2.6 sid: drop the session this Logout Token names.
        if(result.SessionId is not null)
        {
            activeSessions.Remove(result.SessionId);
            verifiedSessionIds.Add(result.SessionId);
        }

        LastSubject = result.Subject;

        return new MinimalHttpResponse { StatusCode = 200 };
    }


    /// <summary>
    /// Reads a single <c>application/x-www-form-urlencoded</c> field value, or
    /// <see langword="null"/> when the key is absent.
    /// </summary>
    /// <param name="body">The form-encoded request body.</param>
    /// <param name="key">The field name to read.</param>
    /// <param name="value">The decoded value when present.</param>
    /// <returns><see langword="true"/> when the field is present.</returns>
    private static bool TryGetFormValue(string body, string key, [NotNullWhen(true)] out string? value)
    {
        foreach(string pair in body.Split('&'))
        {
            int eq = pair.IndexOf('=', StringComparison.Ordinal);
            if(eq > 0 && string.Equals(pair[..eq], key, StringComparison.Ordinal))
            {
                value = Uri.UnescapeDataString(pair[(eq + 1)..].Replace('+', ' '));
                return true;
            }
        }

        value = null;
        return false;
    }


    /// <inheritdoc/>
    public async ValueTask DisposeAsync()
    {
        await host.DisposeAsync().ConfigureAwait(false);
    }
}
