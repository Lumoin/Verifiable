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
using Verifiable.OAuth.Logout;
using Verifiable.OAuth.Server;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.OAuth;

/// <summary>
/// Slice 7 — the global-logout → CAEP <c>session-revoked</c> emit, end to end over real
/// HTTP. A Global Token Revocation request
/// (<see href="https://drafts.aaronpk.com/draft-parecki-oauth-global-token-revocation/draft-parecki-oauth-global-token-revocation.html">draft-parecki-oauth-global-token-revocation</see>)
/// revokes a subject; its revoke-subject seam then emits a CAEP <c>session-revoked</c>
/// Security Event Token (CAEP 1.0 §3.1) about that subject and pushes it to a Shared
/// Signals Receiver over a real socket. The Receiver reconstructs the SET from the wire
/// bytes plus the OP's published public key alone, runs the full reception pipeline, and
/// confirms a conformant <c>session-revoked</c> event about exactly the revoked subject.
/// </summary>
/// <remarks>
/// <para>
/// This is the flow-level proof of the documented (but until now only asserted in pieces)
/// hook: the §8 Global Token Revocation decision states the revoke-subject seam <em>is</em>
/// the global-logout fan-out and, when the deployment runs an SSF Transmitter, MAY emit a
/// CAEP <c>session-revoked</c> signal. The SET primitives, the typed
/// <see cref="CaepSessionRevokedEvent"/>, the reception pipeline, and the interop-profile
/// conformance are each covered on their own; this ties them to the actual revocation
/// endpoint and proves the best-effort signal crosses a real socket, firewalled.
/// </para>
/// <para>
/// Firewalled: the Receiver holds only the OP's published public verification key and the
/// compact SET bytes — no signing key, no in-memory event object crosses the boundary.
/// There is deliberately no library orchestrator; the application composes the SET from
/// the existing primitives inside its own seam, exactly as the deployment would.
/// </para>
/// </remarks>
[TestClass]
internal sealed class GlobalLogoutCaepEmitHttpTests
{
    /// <summary>The MSTest-supplied per-test context.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>A fixed clock so issued artefacts are reproducible.</summary>
    private FakeTimeProvider TimeProvider { get; } = new(TestClock.CanonicalEpoch);

    /// <summary>The memory pool used for all transient signing/verification buffers.</summary>
    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    /// <summary>The OP / SSF Transmitter issuer the Receiver is configured to expect.</summary>
    private const string OpIssuer = "https://op.example/";

    /// <summary>The Receiver's audience identifier the SET's <c>aud</c> must carry.</summary>
    private const string ReceiverAudience = "https://receiver.example/ssf";

    /// <summary>The client driving the Global Token Revocation request.</summary>
    private const string GtrClientId = "https://gtr.client.test";

    /// <summary>The base URI the GTR client is reachable at.</summary>
    private static readonly Uri GtrClientBaseUri = new("https://gtr.client.test");

    /// <summary>The <c>iss</c> half of the revoked iss_sub Subject Identifier.</summary>
    private const string RevokedIssuer = "https://issuer.test";

    /// <summary>The <c>sub</c> half of the revoked iss_sub Subject Identifier.</summary>
    private const string RevokedSubject = "subject-123";

    /// <summary>The request body: a global revocation of the iss_sub subject above.</summary>
    private const string SubIdJson =
        /*lang=json,strict*/ "{\"sub_id\":{\"format\":\"iss_sub\",\"iss\":\"https://issuer.test\",\"sub\":\"subject-123\"}}";

    /// <summary>The single capability the Global Token Revocation endpoint requires.</summary>
    private static readonly ImmutableHashSet<CapabilityIdentifier> GtrCapabilities =
        ImmutableHashSet.Create(WellKnownCapabilityIdentifiers.OAuthGlobalTokenRevocation);


    /// <summary>
    /// A wired Global Token Revocation that returns 204 also propagates a conformant CAEP
    /// <c>session-revoked</c> SET, about the revoked subject, to the Receiver over HTTP.
    /// </summary>
    [TestMethod]
    public async Task GlobalTokenRevocationEmitsConformantSessionRevokedSetToReceiverOverHttp()
    {
        //The OP's SSF Transmitter signing key. The private half signs the SET OP-side;
        //the public half is the only OP secret the Receiver ever holds.
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> opKeys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PrivateKeyMemory opPrivate = opKeys.PrivateKey;
        using PublicKeyMemory opPublic = opKeys.PublicKey;

        //The Receiver's push endpoint: every request is one SET, verified from the wire
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
                TestSetup.Base64UrlDecoder, isSeen, new ExchangeContext(), Pool, cancellationToken: ct).ConfigureAwait(false);

            if(decision.Outcome is SsfDeliveryOutcome.Accepted or SsfDeliveryOutcome.AcceptedDuplicate)
            {
                receivedToken = decision.Token;
                return new MinimalHttpResponse { StatusCode = 202 };
            }

            return new MinimalHttpResponse { StatusCode = 400 };
        }

        await using MinimalHttpHost receiver = await MinimalHttpHost.StartAsync(
            ReceiverPushHandler, TestContext.CancellationToken).ConfigureAwait(false);

        //The OP: a Global Token Revocation endpoint whose revoke-subject seam, after
        //revoking, composes a CAEP session-revoked SET about the revoked subject and
        //pushes it to the Receiver over real HTTP.
        await using TestHostShell op = new(TimeProvider);
        using VerifierKeyMaterial material = op.RegisterClient(GtrClientId, GtrClientBaseUri, GtrCapabilities);

        using HttpClient transmitterClient = new();
        op.Server.OAuth().ValidateClientCredentialsAsync = static (_, _, _, _, _) => ValueTask.FromResult(true);
        op.Server.OAuth().UseDefaultGlobalTokenRevocationJsonParsing();
        op.Server.OAuth().RevokeSubjectTokensAsync = async (subId, _, _, ct) =>
        {
            //CAEP 1.0 §3.1 + Interop Profile: a session-revoked event carrying a non-empty
            //reason_admin is the conformant transmitter shape.
            var sessionRevoked = new CaepSessionRevokedEvent
            {
                Common = new CaepEventClaims
                {
                    EventTimestamp = TimeProvider.GetUtcNow(),
                    InitiatingEntity = CaepInitiatingEntityValues.Admin,
                    ReasonAdmin = new Dictionary<string, string>(StringComparer.Ordinal)
                    {
                        ["en"] = "Global token revocation."
                    }
                }
            };

            //Compose the SET from the existing primitives — the application's own seam,
            //the SET's sub_id is the very subject the revocation named.
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
                signingKeyId: "op-key-1",
                subjectId: subId,
                cancellationToken: ct).ConfigureAwait(false);

            using StringContent content = new(set, Encoding.UTF8, WellKnownMediaTypes.Application.SecEventJwt);
            using HttpResponseMessage push = await transmitterClient.PostAsync(
                new Uri(receiver.BaseAddress, "/ssf/push"), content, ct).ConfigureAwait(false);
            Assert.AreEqual(202, (int)push.StatusCode, "The Receiver must accept the session-revoked SET.");

            return GlobalTokenRevocationOutcome.Initiated;
        };

        ServerHttpResponse response = await op.DispatchAtEndpointAsync(
            material.Registration.TenantId.Value,
            WellKnownEndpointNames.GlobalTokenRevocation,
            "POST",
            new RequestFields(),
            SubIdJson,
            new ExchangeContext(),
            TestContext.CancellationToken).ConfigureAwait(false);

        //§3: revocation initiated → 204; the SET reached and verified at the Receiver.
        Assert.AreEqual(204, response.StatusCode, response.Body);
        Assert.IsNotNull(receivedToken, "The Receiver must have verified the emitted SET.");

        //The verified SET carries exactly one CAEP session-revoked event, interop-conformant.
        Assert.HasCount(1, receivedToken.Events);
        Assert.IsTrue(CaepEventTypes.IsSessionRevoked(receivedToken.Events[0].EventType),
            "The emitted event must be CAEP session-revoked.");
        Assert.IsTrue(CaepInteropProfile.IsConformantTransmitterEvent(receivedToken.Events[0]),
            "The emitted event must satisfy the CAEP Interop Profile (non-empty reason_admin).");

        //The SET is about exactly the subject the revocation named.
        Assert.IsNotNull(receivedToken.SubjectId);
        Assert.IsTrue(SubjectIdentifierFormats.IsIssuerSubject(receivedToken.SubjectId.Format),
            "The SET's sub_id must carry the revoked iss_sub subject.");
        Assert.AreEqual(RevokedIssuer, receivedToken.SubjectId.Members[SubjectIdentifierMemberNames.Iss]);
        Assert.AreEqual(RevokedSubject, receivedToken.SubjectId.Members[SubjectIdentifierMemberNames.Sub]);
    }
}
