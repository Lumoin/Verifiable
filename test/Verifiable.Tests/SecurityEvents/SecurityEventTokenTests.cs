using System;
using System.Buffers;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.Cryptography;
using Verifiable.JCose;
using Verifiable.Json;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Firewalled round-trip tests for the Security Event Token core (RFC 8417):
/// a Transmitter issues and signs a SET, and a Receiver reconstructs it from the
/// compact wire string alone (plus the Transmitter's published public key),
/// running full signature + SET-level validation. Nothing in-memory is shared
/// across the boundary.
/// </summary>
[TestClass]
internal sealed class SecurityEventTokenTests
{
    private const string Issuer = "https://transmitter.example/";
    private const string Audience = "https://receiver.example/ssf";

    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    //A receiver that has never seen any jti.
    private static readonly IsSecurityEventTokenJtiSeenDelegate NeverSeen =
        static (jti, context, cancellationToken) => ValueTask.FromResult(false);


    [TestMethod]
    public async Task ValidCaepSetRoundTripsThroughWireString()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        SecurityEvent sessionRevoked = new()
        {
            EventType = CaepEventTypes.SessionRevoked,
            Payload = new Dictionary<string, object> { ["event_timestamp"] = 1615304991L }
        };

        string compact = await IssueAsync(
            transmitterPrivate,
            [sessionRevoked],
            SubjectIdentifier.IssuerSubject(Issuer, "abc-123")).ConfigureAwait(false);

        //Receiver side: only the wire string and the published public key.
        SecurityEventTokenVerificationResult result = await VerifyAsync(compact, transmitterPublic).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"Expected valid SET, got {result.Error}.");
        SecurityEventToken token = result.Token!;
        Assert.AreEqual(Issuer, token.Issuer);
        Assert.IsFalse(string.IsNullOrEmpty(token.JwtId));
        Assert.IsNotNull(token.IssuedAt);
        Assert.HasCount(1, token.Audiences);
        Assert.AreEqual(Audience, token.Audiences[0]);
        Assert.HasCount(1, token.Events);
        Assert.AreEqual(CaepEventTypes.SessionRevoked, token.Events[0].EventType);
        Assert.IsTrue(CaepEventTypes.IsSessionRevoked(token.Events[0].EventType));
        Assert.IsNotNull(token.SubjectId);
        Assert.AreEqual(SubjectIdentifierFormats.IssuerSubject, token.SubjectId!.Format);
        Assert.IsTrue(token.SubjectId.IsValidForKnownFormat());
    }


    [TestMethod]
    public async Task RiscSetRoundTripsThroughWireString()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        SecurityEvent accountDisabled = new()
        {
            EventType = RiscEventTypes.AccountDisabled,
            Payload = new Dictionary<string, object> { ["reason"] = "hijacking" }
        };

        string compact = await IssueAsync(
            transmitterPrivate,
            [accountDisabled],
            SubjectIdentifier.Email("user@example.com")).ConfigureAwait(false);

        SecurityEventTokenVerificationResult result = await VerifyAsync(compact, transmitterPublic).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"Expected valid SET, got {result.Error}.");
        Assert.AreEqual(RiscEventTypes.AccountDisabled, result.Token!.Events[0].EventType);
        Assert.IsTrue(RiscEventTypes.IsRiscEventType(result.Token.Events[0].EventType));
        Assert.AreEqual("hijacking", result.Token.Events[0].Payload["reason"]);
        Assert.AreEqual(SubjectIdentifierFormats.Email, result.Token.SubjectId!.Format);
    }


    [TestMethod]
    public async Task ComplexSubjectRoundTrips()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        SubjectIdentifier complex = SubjectIdentifier.Complex(new Dictionary<string, SubjectIdentifier>
        {
            [ComplexSubjectMemberNames.User] = SubjectIdentifier.IssuerSubject(Issuer, "user-1"),
            [ComplexSubjectMemberNames.Tenant] = SubjectIdentifier.Opaque("tenant-9")
        });

        SecurityEvent revoked = new()
        {
            EventType = CaepEventTypes.SessionRevoked,
            Payload = new Dictionary<string, object>(StringComparer.Ordinal)
        };

        string compact = await IssueAsync(transmitterPrivate, [revoked], complex).ConfigureAwait(false);
        SecurityEventTokenVerificationResult result = await VerifyAsync(compact, transmitterPublic).ConfigureAwait(false);

        Assert.IsTrue(result.IsValid, $"Expected valid SET, got {result.Error}.");
        SubjectIdentifier subject = result.Token!.SubjectId!;
        Assert.AreEqual(SubjectIdentifierFormats.Complex, subject.Format);
        Assert.IsTrue(subject.IsValidForKnownFormat());

        var members = new Dictionary<string, SubjectIdentifier>(StringComparer.Ordinal);
        foreach(KeyValuePair<string, SubjectIdentifier> member in subject.EnumerateComplexMembers())
        {
            members[member.Key] = member.Value;
        }

        Assert.IsTrue(members.ContainsKey(ComplexSubjectMemberNames.User));
        Assert.AreEqual(SubjectIdentifierFormats.IssuerSubject, members[ComplexSubjectMemberNames.User].Format);
        Assert.AreEqual(SubjectIdentifierFormats.Opaque, members[ComplexSubjectMemberNames.Tenant].Format);
    }


    [TestMethod]
    public async Task TamperedPayloadIsRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(
            transmitterPrivate,
            [SimpleEvent()],
            SubjectIdentifier.Opaque("subj-1")).ConfigureAwait(false);

        string[] parts = compact.Split('.');
        //Flip one character of the payload segment without re-signing.
        char[] payload = parts[1].ToCharArray();
        payload[3] = payload[3] == 'A' ? 'B' : 'A';
        string tampered = $"{parts[0]}.{new string(payload)}.{parts[2]}";

        SecurityEventTokenVerificationResult result = await VerifyAsync(tampered, transmitterPublic).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SecurityEventTokenValidationError.SignatureInvalid, result.Error);
    }


    [TestMethod]
    public async Task NonSecEventTypIsRejectedBeforeSignature()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(
            transmitterPrivate,
            [SimpleEvent()],
            SubjectIdentifier.Opaque("subj-1")).ConfigureAwait(false);

        string[] parts = compact.Split('.');
        //Re-type the header to a non-SET typ without re-signing: parse, mutate the
        //typ member, re-serialize. (String replacement on the raw JSON is unsafe —
        //the default encoder escapes '+' in "secevent+jwt" as "+".)
        Dictionary<string, object> forgedHeaderDict = SecurityEventTestJson.DeserializePart(SecurityEventTestJson.DecodeSegment(parts[0], Pool))!;
        forgedHeaderDict[WellKnownJoseHeaderNames.Typ] = WellKnownMediaTypes.Jwt.AtJwt;
        string forgedHeader = TestSetup.Base64UrlEncoder(
            JsonSerializerExtensions.SerializeToUtf8Bytes(forgedHeaderDict, TestSetup.DefaultSerializationOptions));
        string forged = $"{forgedHeader}.{parts[1]}.{parts[2]}";

        SecurityEventTokenVerificationResult result = await VerifyAsync(forged, transmitterPublic).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SecurityEventTokenValidationError.ExplicitTypeMissing, result.Error);
    }


    [TestMethod]
    public async Task ReplayedJtiIsRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(
            transmitterPrivate,
            [SimpleEvent()],
            SubjectIdentifier.Opaque("subj-1")).ConfigureAwait(false);

        //A receiver whose replay store reports every jti as already seen.
        IsSecurityEventTokenJtiSeenDelegate alwaysSeen =
            (jti, context, cancellationToken) => ValueTask.FromResult(true);

        SecurityEventTokenVerificationResult result = await VerifyAsync(compact, transmitterPublic, alwaysSeen).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SecurityEventTokenValidationError.Replayed, result.Error);
    }


    [TestMethod]
    public async Task WrongIssuerIsRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(
            transmitterPrivate,
            [SimpleEvent()],
            SubjectIdentifier.Opaque("subj-1")).ConfigureAwait(false);

        SecurityEventTokenVerificationResult result = await SecurityEventTokenVerification.VerifyAsync(
            compact, transmitterPublic,
            expectedIssuer: "https://impostor.example/",
            expectedAudience: Audience,
            SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart, TestSetup.Base64UrlDecoder, NeverSeen,
            new ExchangeContext(), Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SecurityEventTokenValidationError.IssuerMismatch, result.Error);
    }


    [TestMethod]
    public async Task WrongAudienceIsRejected()
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        string compact = await IssueAsync(
            transmitterPrivate,
            [SimpleEvent()],
            SubjectIdentifier.Opaque("subj-1")).ConfigureAwait(false);

        SecurityEventTokenVerificationResult result = await SecurityEventTokenVerification.VerifyAsync(
            compact, transmitterPublic,
            expectedIssuer: Issuer,
            expectedAudience: "https://other.example/",
            SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart, TestSetup.Base64UrlDecoder, NeverSeen,
            new ExchangeContext(), Pool, TestContext.CancellationToken).ConfigureAwait(false);

        Assert.IsFalse(result.IsValid);
        Assert.AreEqual(SecurityEventTokenValidationError.AudienceMismatch, result.Error);
    }


    private static SecurityEvent SimpleEvent() => new()
    {
        EventType = CaepEventTypes.SessionRevoked,
        Payload = new Dictionary<string, object> { ["event_timestamp"] = 1615304991L }
    };


    private async Task<string> IssueAsync(
        PrivateKeyMemory signingKey, IReadOnlyList<SecurityEvent> events, SubjectIdentifier subjectId) =>
        await SecurityEventTokenIssuance.IssueAsync(
            Issuer,
            [Audience],
            jwtId: Guid.NewGuid().ToString("N"),
            issuedAt: DateTimeOffset.UnixEpoch.AddSeconds(1615305159),
            events,
            signingKey,
            TestSetup.Base64UrlEncoder,
            SecurityEventTestJson.HeaderSerializer,
            SecurityEventTestJson.PayloadSerializer,
            Pool,
            signingKeyId: "key-1",
            subjectId: subjectId,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);


    private async Task<SecurityEventTokenVerificationResult> VerifyAsync(
        string compact, PublicKeyMemory publicKey, IsSecurityEventTokenJtiSeenDelegate? isJtiSeen = null) =>
        await SecurityEventTokenVerification.VerifyAsync(
            compact, publicKey, Issuer, Audience,
            SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart, TestSetup.Base64UrlDecoder,
            isJtiSeen ?? NeverSeen, new ExchangeContext(), Pool, TestContext.CancellationToken).ConfigureAwait(false);
}
