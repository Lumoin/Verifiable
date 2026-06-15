using System;
using System.Buffers;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.OAuth;
using Verifiable.OAuth.Logout;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// A single global-logout trigger fanning out to BOTH generations of global logout at once,
/// over real HTTP: the older OIDC Back-Channel Logout (a signed <c>logout_token</c> to every
/// relying party) AND the newer Shared Signals / CAEP <c>session-revoked</c> signal (a Security
/// Event Token to a Shared Signals Receiver). The application composes both inside the Global
/// Token Revocation revoke-subject seam — the "kill this subject everywhere" deployment policy.
/// </summary>
/// <remarks>
/// <para>
/// Each leg is already proven independently —
/// <see cref="FederatedBackChannelLogoutHttpTests"/> (Back-Channel) and
/// <see cref="GlobalLogoutCaepEmitHttpTests"/> (CAEP). This test proves the two compose from one
/// trigger: choosing which channels to drive is the library user's wiring (the seams are
/// independent), but the end-to-end flow shows how a deployment notifies both its OIDC relying
/// parties and its Shared Signals receivers from a single revocation. There is no library
/// orchestrator; the app fans out inside its own seam.
/// </para>
/// <para>
/// Firewalled: every receiver (RP or SSF) holds only the OP's published public verification key
/// and the compact token bytes — no signing key and no in-memory object cross a boundary.
/// </para>
/// </remarks>
[TestClass]
internal sealed class GlobalLogoutDualChannelHttpTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(
        new DateTimeOffset(2026, 6, 1, 12, 0, 0, TimeSpan.Zero));

    /// <summary>The memory pool used for all transient signing/verification buffers.</summary>
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>The OP issuer every receiver is configured, out of band, to expect.</summary>
    private const string OpIssuer = "https://op.example/";

    /// <summary>The SSF Receiver's audience identifier the SET's <c>aud</c> must carry.</summary>
    private const string ReceiverAudience = "https://receiver.example/ssf";

    /// <summary>The admin client driving the Global Token Revocation request.</summary>
    private const string GtrClientId = "https://gtr.client.test";

    /// <summary>The base URI the GTR client is reachable at.</summary>
    private static readonly Uri GtrClientBaseUri = new("https://gtr.client.test");

    /// <summary>The <c>sub</c> half of the revoked iss_sub subject — the end-user logged out everywhere.</summary>
    private const string RevokedSubject = "subject-123";

    /// <summary>The single OP session both RPs share for the revoked subject.</summary>
    private const string SsoSessionId = "session-global";

    /// <summary>The request body: a global revocation of the iss_sub subject above.</summary>
    private const string SubIdJson =
        /*lang=json,strict*/ "{\"sub_id\":{\"format\":\"iss_sub\",\"iss\":\"https://issuer.test\",\"sub\":\"subject-123\"}}";

    /// <summary>The single capability the Global Token Revocation endpoint requires.</summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> GtrCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation);


    /// <summary>
    /// One Global Token Revocation fans a signed <c>logout_token</c> out to every RP over HTTP
    /// AND pushes a conformant CAEP <c>session-revoked</c> SET to the Shared Signals Receiver over
    /// HTTP — each verified independently from the wire bytes plus the OP public key alone.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationFansOutToBackChannelRpsAndCaepReceiverOverHttp()
    {
        //The OP's signing key: the private half signs Logout Tokens and SETs OP-side; the public
        //half is the only OP secret any receiver ever holds.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> opKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PrivateKeyMemory opPrivate = opKeys.PrivateKey;
        using PublicKeyMemory opPublic = opKeys.PublicKey;

        //Channel 2 — the Shared Signals Receiver: every push is one SET, verified from the wire
        //bytes plus the OP public key alone through the full reception pipeline.
        SecurityEventToken? receivedToken = null;
        HashSet<string> seenJtis = new(StringComparer.Ordinal);
        IsSecurityEventTokenJtiSeenDelegate isSeen =
            (jti, _, _) => ValueTask.FromResult(!seenJtis.Add(jti));

        async Task<MinimalHttpResponse> ReceiverPushHandler(MinimalHttpRequest request, CancellationToken ct)
        {
            if(request.ContentType is null
                || !request.ContentType.StartsWith(WellKnownMediaTypes.Application.SecEventJwt, StringComparison.OrdinalIgnoreCase))
            {
                return new MinimalHttpResponse { StatusCode = 400 };
            }

            SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
                request.Body, opPublic, OpIssuer, ReceiverAudience,
                SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
                TestSetup.Base64UrlDecoder, isSeen, new ExchangeContext(), Pool, ct).ConfigureAwait(false);

            if(decision.Outcome is SsfDeliveryOutcome.Accepted or SsfDeliveryOutcome.AcceptedDuplicate)
            {
                receivedToken = decision.Token;
                return new MinimalHttpResponse { StatusCode = 202 };
            }

            return new MinimalHttpResponse { StatusCode = 400 };
        }

        await using MinimalHttpHost ssfReceiver = await MinimalHttpHost.StartAsync(
            ReceiverPushHandler, TestContext.CancellationToken).ConfigureAwait(false);

        //Channel 1 — two OIDC relying parties, each a real receiver over loopback Kestrel. Each
        //holds a live session keyed by the shared OP sid and drops it on a valid §2.6 Logout Token.
        await using RelyingPartyReceiver rp1 = await RelyingPartyReceiver.StartAsync(
            "https://rp1.example.com", opPublic, OpIssuer, TestContext.CancellationToken).ConfigureAwait(false);
        await using RelyingPartyReceiver rp2 = await RelyingPartyReceiver.StartAsync(
            "https://rp2.example.com", opPublic, OpIssuer, TestContext.CancellationToken).ConfigureAwait(false);
        rp1.SeedSession(SsoSessionId);
        rp2.SeedSession(SsoSessionId);

        //The application's session→RP registry the fan-out walks (what a deployment maintains).
        List<RegisteredRelyingParty> sessionRelyingParties =
        [
            new RegisteredRelyingParty(rp1.ClientId, rp1.BackChannelLogoutUri),
            new RegisteredRelyingParty(rp2.ClientId, rp2.BackChannelLogoutUri)
        ];

        //The OP: a Global Token Revocation endpoint whose revoke-subject seam composes BOTH
        //fan-outs and pushes them over real HTTP.
        await using TestHostShell op = new(TimeProvider);
        using VerifierKeyMaterial gtrMaterial = op.RegisterClient(GtrClientId, GtrClientBaseUri, GtrCapabilities);

        using HttpClient deliveryClient = new();
        using HttpClient transmitterClient = new();
        op.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) => ValueTask.FromResult(true);
        op.Server.OAuth().UseDefaultGlobalTokenRevocationJsonParsing();
        op.Server.OAuth().RevokeSubjectTokensAsync = async (subId, _, _, ct) =>
        {
            //Channel 1 (older — OIDC Back-Channel Logout): tell every RP holding the subject's
            //session to drop it. aud = that RP's client_id; the token carries sub + the shared sid.
            foreach(RegisteredRelyingParty relyingParty in sessionRelyingParties)
            {
                string logoutToken = await BackChannelLogout.BuildLogoutTokenAsync(
                    OpIssuer,
                    relyingParty.ClientId,
                    jwtId: Guid.NewGuid().ToString("N"),
                    issuedAt: TimeProvider.GetUtcNow(),
                    subject: RevokedSubject,
                    sessionId: SsoSessionId,
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

            //Channel 2 (newer — Shared Signals / CAEP session-revoked): signal the SSF Receiver.
            var sessionRevoked = new CaepSessionRevokedEvent
            {
                Common = new CaepEventClaims
                {
                    EventTimestamp = TimeProvider.GetUtcNow(),
                    InitiatingEntity = CaepInitiatingEntityValues.Admin,
                    ReasonAdmin = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["en"] = "Global subject revocation."
                    }
                }
            };

            string set = await SecurityEventTokenIssuance.IssueAsync(
                OpIssuer,
                [ReceiverAudience],
                jwtId: Guid.NewGuid().ToString("N"),
                issuedAt: TimeProvider.GetUtcNow(),
                [sessionRevoked.ToSecurityEvent()],
                opPrivate,
                TestSetup.Base64UrlEncoder,
                SecurityEventTestJson.HeaderSerializer,
                SecurityEventTestJson.PayloadSerializer,
                Pool,
                ct,
                signingKeyId: "op-key-1",
                subjectId: subId).ConfigureAwait(false);

            using StringContent setContent = new(set, Encoding.UTF8, WellKnownMediaTypes.Application.SecEventJwt);
            using HttpResponseMessage push = await transmitterClient.PostAsync(
                new Uri(ssfReceiver.BaseAddress, "/ssf/push"), setContent, ct).ConfigureAwait(false);
            Assert.AreEqual(202, (int)push.StatusCode, "The SSF Receiver must accept the session-revoked SET.");

            return GlobalTokenRevocationOutcome.Initiated;
        };

        //The single trigger: revoke the subject everywhere.
        ServerHttpResponse response = await op.DispatchAtEndpointAsync(
            gtrMaterial.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            SubIdJson,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //§3: revocation initiated → 204; both fan-outs reached and verified at their receivers.
        Assert.AreEqual(204, response.StatusCode, response.Body);

        //Channel 1: both RPs verified the Logout Token and dropped exactly the shared session.
        Assert.Contains(SsoSessionId, rp1.VerifiedSessionIds, "RP1 must have verified and dropped the session.");
        Assert.Contains(SsoSessionId, rp2.VerifiedSessionIds, "RP2 must have verified and dropped the session.");
        Assert.IsFalse(rp1.HasActiveSession(SsoSessionId), "RP1 must no longer hold the session.");
        Assert.IsFalse(rp2.HasActiveSession(SsoSessionId), "RP2 must no longer hold the session.");
        Assert.AreEqual(RevokedSubject, rp1.LastSubject, "RP1 must extract the logged-out subject.");
        Assert.AreEqual(RevokedSubject, rp2.LastSubject, "RP2 must extract the logged-out subject.");

        //Channel 2: the SSF Receiver verified the CAEP session-revoked SET about the same subject.
        Assert.IsNotNull(receivedToken, "The SSF Receiver must have verified the emitted SET.");
        Assert.HasCount(1, receivedToken.Events);
        Assert.IsTrue(CaepEventTypes.IsSessionRevoked(receivedToken.Events[0].EventType),
            "The emitted event must be CAEP session-revoked.");
        Assert.IsTrue(CaepInteropProfile.IsConformantTransmitterEvent(receivedToken.Events[0]),
            "The emitted event must satisfy the CAEP Interop Profile (non-empty reason_admin).");
        Assert.IsNotNull(receivedToken.SubjectId);
        Assert.AreEqual(RevokedSubject, receivedToken.SubjectId.Members[SubjectIdentifierMemberNames.Sub],
            "The SET must be about exactly the revoked subject.");
    }
}
