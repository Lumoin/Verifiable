using System;
using System.Buffers;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.Cryptography;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Round-trip tests for the SSF framework SETs
/// (<see cref="SsfFrameworkSetIssuance"/>): the transmitter-issued
/// <c>verification</c> (§8.1.4.1) and <c>stream-updated</c> (§8.1.5) events flow
/// through the receiver's reception pipeline from wire bytes alone, with the
/// stream-identifying <c>opaque</c> <c>sub_id</c> and payload semantics asserted.
/// </summary>
[TestClass]
internal sealed class SsfFrameworkSetIssuanceTests
{
    private const string Issuer = "https://transmitter.example/";
    private const string Audience = "https://receiver.example/ssf";
    private const string StreamId = "f67e39a0a4d34d56b3aa1bc4cff0069f";

    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly IsSecurityEventTokenJtiSeenDelegate NeverSeen =
        static (jti, context, cancellationToken) => ValueTask.FromResult(false);


    [TestMethod]
    public async Task VerificationSetEchoesStateAndIdentifiesTheStream()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await SsfFrameworkSetIssuance.IssueVerificationSetAsync(
            StreamId,
            state: "requested-state-1",
            Issuer,
            [Audience],
            jwtId: Guid.NewGuid().ToString("N"),
            issuedAt: DateTimeOffset.UnixEpoch.AddSeconds(1493856000),
            transmitterPrivate,
            TestSetup.Base64UrlEncoder,
            SecurityEventTestJson.HeaderSerializer,
            SecurityEventTestJson.PayloadSerializer,
            Pool,
            TestContext.CancellationToken,
            signingKeyId: "key-1").ConfigureAwait(false);

        //The receiver's reception pipeline accepts it when the state echoes the
        //outstanding verification request.
        SsfDeliveryDecision decision = await ReceiveAsync(
            compact, transmitterPublic, expectedVerificationState: "requested-state-1").ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Accepted, decision.Outcome);
        SecurityEventToken token = decision.Token!;
        Assert.IsTrue(SsfEventTypes.IsVerification(token.Events[0].EventType));

        //§8.1.4.1: the sub_id MUST be opaque with the stream_id as its id.
        Assert.IsNotNull(token.SubjectId);
        Assert.AreEqual(SubjectIdentifierFormats.Opaque, token.SubjectId!.Format);
        Assert.AreEqual(StreamId, token.SubjectId.Members[SubjectIdentifierMemberNames.Id]);
    }


    [TestMethod]
    public async Task VerificationSetWithWrongStateIsRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await SsfFrameworkSetIssuance.IssueVerificationSetAsync(
            StreamId,
            state: "stale-or-forged",
            Issuer,
            [Audience],
            jwtId: Guid.NewGuid().ToString("N"),
            issuedAt: DateTimeOffset.UnixEpoch.AddSeconds(1493856000),
            transmitterPrivate,
            TestSetup.Base64UrlEncoder,
            SecurityEventTestJson.HeaderSerializer,
            SecurityEventTestJson.PayloadSerializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        SsfDeliveryDecision decision = await ReceiveAsync(
            compact, transmitterPublic, expectedVerificationState: "requested-state-1").ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Rejected, decision.Outcome);
        Assert.IsTrue(SsfDeliveryErrorCodes.IsInvalidState(decision.Error!.Err));
    }


    [TestMethod]
    public async Task StreamUpdatedSetCarriesStatusReasonAndStreamSubject()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await SsfFrameworkSetIssuance.IssueStreamUpdatedSetAsync(
            StreamId,
            SsfStreamStatusValues.Paused,
            reason: "Internal error",
            Issuer,
            [Audience],
            jwtId: Guid.NewGuid().ToString("N"),
            issuedAt: DateTimeOffset.UnixEpoch.AddSeconds(1493856000),
            transmitterPrivate,
            TestSetup.Base64UrlEncoder,
            SecurityEventTestJson.HeaderSerializer,
            SecurityEventTestJson.PayloadSerializer,
            Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        SsfDeliveryDecision decision = await ReceiveAsync(compact, transmitterPublic).ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Accepted, decision.Outcome);
        SecurityEventToken token = decision.Token!;
        SecurityEvent streamUpdated = token.Events[0];
        Assert.IsTrue(SsfEventTypes.IsStreamUpdated(streamUpdated.EventType));

        //§8.1.5: status is REQUIRED, reason OPTIONAL; the subject is the stream.
        Assert.AreEqual(SsfStreamStatusValues.Paused, streamUpdated.Payload[SsfStreamStatusParameterNames.Status]);
        Assert.AreEqual("Internal error", streamUpdated.Payload[SsfStreamStatusParameterNames.Reason]);
        Assert.AreEqual(SubjectIdentifierFormats.Opaque, token.SubjectId!.Format);
        Assert.AreEqual(StreamId, token.SubjectId.Members[SubjectIdentifierMemberNames.Id]);
    }


    private async Task<SsfDeliveryDecision> ReceiveAsync(
        string compact, PublicKeyMemory publicKey, string? expectedVerificationState = null) =>
        await SecurityEventTokenReception.ReceiveAsync(
            compact, publicKey, Issuer, Audience,
            SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
            TestSetup.Base64UrlDecoder, NeverSeen, new ExchangeContext(), Pool,
            TestContext.CancellationToken, expectedVerificationState).ConfigureAwait(false);
}
