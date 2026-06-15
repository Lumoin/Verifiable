using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.Cryptography;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Tests for <see cref="SecurityEventTokenReception"/> — the Receiver's
/// delivery-method-agnostic SET disposition pipeline: accept (ack), accept a
/// replay as a duplicate (re-ack, no action), or reject with the SET error the
/// delivery RFCs put on the wire, including SSF's <c>invalid_state</c> for a
/// failed verification round trip.
/// </summary>
[TestClass]
internal sealed class SecurityEventTokenReceptionTests
{
    private const string Issuer = "https://transmitter.example/";
    private const string Audience = "https://receiver.example/ssf";
    private const string StreamId = "f67e39a0a4d34d56b3aa1bc4cff0069f";

    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly IsSecurityEventTokenJtiSeenDelegate NeverSeen =
        static (jti, context, cancellationToken) => ValueTask.FromResult(false);


    [TestMethod]
    public async Task ValidSetIsAccepted()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(transmitterPrivate, SessionRevoked()).ConfigureAwait(false);

        SsfDeliveryDecision decision = await ReceiveAsync(compact, transmitterPublic).ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Accepted, decision.Outcome);
        Assert.IsNotNull(decision.Token);
        Assert.AreEqual(CaepEventTypes.SessionRevoked, decision.Token.Events[0].EventType);
        Assert.IsNull(decision.Error);
    }


    [TestMethod]
    public async Task ReplayedSetIsAcceptedAsDuplicate()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(transmitterPrivate, SessionRevoked()).ConfigureAwait(false);

        IsSecurityEventTokenJtiSeenDelegate alwaysSeen =
            (jti, context, cancellationToken) => ValueTask.FromResult(true);

        SsfDeliveryDecision decision = await ReceiveAsync(compact, transmitterPublic, isJtiSeen: alwaysSeen).ConfigureAwait(false);

        //At-least-once delivery: a repeat is re-acknowledged, never reported as an error,
        //and carries no token because there is nothing new to act on.
        Assert.AreEqual(SsfDeliveryOutcome.AcceptedDuplicate, decision.Outcome);
        Assert.IsNull(decision.Token);
        Assert.IsNull(decision.Error);
    }


    [TestMethod]
    public async Task TamperedSetIsRejectedWithInvalidKey()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(transmitterPrivate, SessionRevoked()).ConfigureAwait(false);
        string[] parts = compact.Split('.');
        char[] payload = parts[1].ToCharArray();
        payload[3] = payload[3] == 'A' ? 'B' : 'A';
        string tampered = $"{parts[0]}.{new string(payload)}.{parts[2]}";

        SsfDeliveryDecision decision = await ReceiveAsync(tampered, transmitterPublic).ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Rejected, decision.Outcome);
        Assert.IsNotNull(decision.Error);
        Assert.IsTrue(SsfDeliveryErrorCodes.IsInvalidKey(decision.Error.Err));
    }


    [TestMethod]
    public async Task WrongIssuerIsRejectedWithInvalidIssuer()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(transmitterPrivate, SessionRevoked()).ConfigureAwait(false);

        SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
            compact, transmitterPublic,
            expectedIssuer: "https://impostor.example/",
            expectedAudience: Audience,
            SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
            TestSetup.Base64UrlDecoder, NeverSeen, new ExchangeContext(), Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Rejected, decision.Outcome);
        Assert.IsTrue(SsfDeliveryErrorCodes.IsInvalidIssuer(decision.Error!.Err));
    }


    [TestMethod]
    public async Task WrongAudienceIsRejectedWithInvalidAudience()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(transmitterPrivate, SessionRevoked()).ConfigureAwait(false);

        SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
            compact, transmitterPublic,
            expectedIssuer: Issuer,
            expectedAudience: "https://other.example/",
            SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
            TestSetup.Base64UrlDecoder, NeverSeen, new ExchangeContext(), Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Rejected, decision.Outcome);
        Assert.IsTrue(SsfDeliveryErrorCodes.IsInvalidAudience(decision.Error!.Err));
    }


    [TestMethod]
    public async Task VerificationEventWithEchoedStateIsAccepted()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(transmitterPrivate, VerificationEvent("expected-state-1")).ConfigureAwait(false);

        SsfDeliveryDecision decision = await ReceiveAsync(
            compact, transmitterPublic, expectedVerificationState: "expected-state-1").ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Accepted, decision.Outcome);
        Assert.IsNotNull(decision.Token);
        Assert.IsTrue(SsfEventTypes.IsVerification(decision.Token.Events[0].EventType));
    }


    [TestMethod]
    public async Task VerificationEventWithWrongStateIsRejectedWithInvalidState()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(transmitterPrivate, VerificationEvent("attacker-chosen")).ConfigureAwait(false);

        SsfDeliveryDecision decision = await ReceiveAsync(
            compact, transmitterPublic, expectedVerificationState: "expected-state-1").ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Rejected, decision.Outcome);
        Assert.IsTrue(SsfDeliveryErrorCodes.IsInvalidState(decision.Error!.Err));
    }


    private static SecurityEvent SessionRevoked() => new()
    {
        EventType = CaepEventTypes.SessionRevoked,
        Payload = new Dictionary<string, object> { ["event_timestamp"] = 1615304991L }
    };


    private static SecurityEvent VerificationEvent(string state) => new()
    {
        EventType = SsfEventTypes.Verification,
        Payload = new Dictionary<string, object> { [SsfStreamManagementParameterNames.State] = state }
    };


    private async Task<string> IssueAsync(PrivateKeyMemory signingKey, SecurityEvent securityEvent) =>
        await SecurityEventTokenIssuance.IssueAsync(
            Issuer,
            [Audience],
            jwtId: Guid.NewGuid().ToString("N"),
            issuedAt: DateTimeOffset.UnixEpoch.AddSeconds(1615305159),
            [securityEvent],
            signingKey,
            TestSetup.Base64UrlEncoder,
            SecurityEventTestJson.HeaderSerializer,
            SecurityEventTestJson.PayloadSerializer,
            Pool,
            TestContext.CancellationToken,
            signingKeyId: "key-1",
            subjectId: SubjectIdentifier.Opaque(StreamId)).ConfigureAwait(false);


    private async Task<SsfDeliveryDecision> ReceiveAsync(
        string compact,
        PublicKeyMemory publicKey,
        IsSecurityEventTokenJtiSeenDelegate? isJtiSeen = null,
        string? expectedVerificationState = null) =>
        await SecurityEventTokenReception.ReceiveAsync(
            compact, publicKey, Issuer, Audience,
            SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
            TestSetup.Base64UrlDecoder, isJtiSeen ?? NeverSeen, new ExchangeContext(), Pool,
            TestContext.CancellationToken, expectedVerificationState).ConfigureAwait(false);
}
