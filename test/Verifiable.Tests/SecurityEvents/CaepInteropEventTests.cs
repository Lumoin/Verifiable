using System;
using System.Buffers;
using System.Collections.Generic;
using System.Threading.Tasks;
using Verifiable.Core;
using Verifiable.Core.SecurityEvents;
using Verifiable.Cryptography;
using Verifiable.Tests.TestDataProviders;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.SecurityEvents;

/// <summary>
/// Round-trip tests for the typed CAEP interop events: each of the three
/// CAEP Interoperability Profile use cases — <c>session-revoked</c> (CAEP 1.0
/// §3.1), <c>credential-change</c> (§3.3), <c>device-compliance-change</c>
/// (§3.5) — is built typed, issued as a SET, received from wire bytes alone
/// through the full reception pipeline, and projected back typed with every
/// field asserted. Strict projections reject values outside the closed sets,
/// and the interop-profile transmitter gate (one event per SET, non-empty
/// <c>reason_admin</c>) is exercised both ways.
/// </summary>
[TestClass]
internal sealed class CaepInteropEventTests
{
    private const string Issuer = "https://transmitter.example/";
    private const string Audience = "https://receiver.example/ssf";

    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => SensitiveMemoryPool<byte>.Shared;

    private static readonly IsSecurityEventTokenJtiSeenDelegate NeverSeen =
        static (jti, context, cancellationToken) => ValueTask.FromResult(false);


    [TestMethod]
    public async Task SessionRevokedRoundTripsWithCommonClaims()
    {
        var revoked = new CaepSessionRevokedEvent
        {
            Common = new CaepEventClaims
            {
                EventTimestamp = DateTimeOffset.FromUnixTimeSeconds(1615304991),
                InitiatingEntity = CaepInitiatingEntityValues.Policy,
                ReasonAdmin = new Dictionary<string, string> { ["en"] = "Landspeed Policy Violation: C076E82F" },
                ReasonUser = new Dictionary<string, string> { ["en"] = "Access attempt from multiple regions.", ["es-410"] = "Intento de acceso desde varias regiones." }
            }
        };

        SecurityEventToken token = await RoundTripAsync(revoked.ToSecurityEvent()).ConfigureAwait(false);
        CaepSessionRevokedEvent? projected = CaepSessionRevokedEvent.From(token.Events[0]);

        Assert.IsNotNull(projected);
        Assert.AreEqual(revoked, projected);
        Assert.IsTrue(CaepInteropProfile.IsConformantTransmitterToken(token));
    }


    [TestMethod]
    public async Task CredentialChangeRoundTripsWithEventSpecificClaims()
    {
        var change = new CaepCredentialChangeEvent
        {
            CredentialType = CaepCredentialTypeValues.Fido2Roaming,
            ChangeType = CaepChangeTypeValues.Create,
            FriendlyName = "Jane's USB authenticator",
            Fido2Aaguid = "accced6a-63f5-490a-9eea-e59bc1896cfc",
            Common = new CaepEventClaims
            {
                EventTimestamp = DateTimeOffset.FromUnixTimeSeconds(1615304991),
                InitiatingEntity = CaepInitiatingEntityValues.User,
                ReasonAdmin = new Dictionary<string, string> { ["en"] = "User self-enrollment" }
            }
        };

        SecurityEventToken token = await RoundTripAsync(change.ToSecurityEvent()).ConfigureAwait(false);
        CaepCredentialChangeEvent? projected = CaepCredentialChangeEvent.From(token.Events[0]);

        Assert.IsNotNull(projected);
        Assert.AreEqual(change, projected);
        Assert.IsNull(projected.X509Issuer);
        Assert.IsTrue(CaepInteropProfile.IsConformantTransmitterToken(token));
    }


    [TestMethod]
    public async Task DeviceComplianceChangeRoundTripsWithStatuses()
    {
        var compliance = new CaepDeviceComplianceChangeEvent
        {
            PreviousStatus = CaepComplianceStatusValues.Compliant,
            CurrentStatus = CaepComplianceStatusValues.NotCompliant,
            Common = new CaepEventClaims
            {
                EventTimestamp = DateTimeOffset.FromUnixTimeSeconds(1615304991),
                InitiatingEntity = CaepInitiatingEntityValues.Policy,
                ReasonAdmin = new Dictionary<string, string> { ["en"] = "Location Policy Violation: C076E822" }
            }
        };

        SecurityEventToken token = await RoundTripAsync(compliance.ToSecurityEvent()).ConfigureAwait(false);
        CaepDeviceComplianceChangeEvent? projected = CaepDeviceComplianceChangeEvent.From(token.Events[0]);

        Assert.IsNotNull(projected);
        Assert.AreEqual(compliance, projected);
        Assert.IsTrue(CaepInteropProfile.IsConformantTransmitterToken(token));
    }


    [TestMethod]
    public void ProjectionsRejectValuesOutsideTheClosedSets()
    {
        //change_type is a closed set (§3.3.1) — an unknown value does not project.
        var badChangeType = new SecurityEvent
        {
            EventType = CaepEventTypes.CredentialChange,
            Payload = new Dictionary<string, object>
            {
                [CaepCredentialChangeClaimNames.CredentialType] = CaepCredentialTypeValues.Password,
                [CaepCredentialChangeClaimNames.ChangeType] = "rotate"
            }
        };
        Assert.IsNull(CaepCredentialChangeEvent.From(badChangeType));

        //credential_type is REQUIRED — absent does not project; the set itself
        //is open, so a mutually-supported non-listed value projects fine.
        var missingCredentialType = new SecurityEvent
        {
            EventType = CaepEventTypes.CredentialChange,
            Payload = new Dictionary<string, object>
            {
                [CaepCredentialChangeClaimNames.ChangeType] = CaepChangeTypeValues.Revoke
            }
        };
        Assert.IsNull(CaepCredentialChangeEvent.From(missingCredentialType));

        var mutuallySupportedType = new SecurityEvent
        {
            EventType = CaepEventTypes.CredentialChange,
            Payload = new Dictionary<string, object>
            {
                [CaepCredentialChangeClaimNames.CredentialType] = "hardware-otp",
                [CaepCredentialChangeClaimNames.ChangeType] = CaepChangeTypeValues.Revoke
            }
        };
        Assert.IsNotNull(CaepCredentialChangeEvent.From(mutuallySupportedType));

        //Compliance statuses are a closed set (§3.5.1).
        var badStatus = new SecurityEvent
        {
            EventType = CaepEventTypes.DeviceComplianceChange,
            Payload = new Dictionary<string, object>
            {
                [CaepDeviceComplianceClaimNames.PreviousStatus] = CaepComplianceStatusValues.Compliant,
                [CaepDeviceComplianceClaimNames.CurrentStatus] = "quarantined"
            }
        };
        Assert.IsNull(CaepDeviceComplianceChangeEvent.From(badStatus));

        //Type mismatch never projects across records.
        Assert.IsNull(CaepSessionRevokedEvent.From(badChangeType));
        Assert.IsNull(CaepCredentialChangeEvent.From(badStatus));
    }


    [TestMethod]
    public void InteropGateRequiresNonEmptyReasonAdminAndOneEvent()
    {
        //The base CAEP spec leaves reason_admin optional; the interop profile
        //makes a non-empty object a transmitter MUST for all three use cases.
        SecurityEvent withoutReason = new CaepSessionRevokedEvent().ToSecurityEvent();
        Assert.IsFalse(CaepInteropProfile.IsConformantTransmitterEvent(withoutReason));

        SecurityEvent withReason = new CaepSessionRevokedEvent
        {
            Common = new CaepEventClaims { ReasonAdmin = new Dictionary<string, string> { ["en"] = "Revoked by admin." } }
        }.ToSecurityEvent();
        Assert.IsTrue(CaepInteropProfile.IsConformantTransmitterEvent(withReason));

        //A non-profile event type fails the gate outright.
        var riscEvent = new SecurityEvent
        {
            EventType = RiscEventTypes.AccountDisabled,
            Payload = new Dictionary<string, object>()
        };
        Assert.IsFalse(CaepInteropProfile.IsConformantTransmitterEvent(riscEvent));

        //The events claim MUST contain only one event.
        var twoEvents = new SecurityEventToken
        {
            Issuer = Issuer,
            JwtId = "jti-1",
            IssuedAt = DateTimeOffset.UnixEpoch,
            Events = [withReason, withReason]
        };
        Assert.IsFalse(CaepInteropProfile.IsConformantTransmitterToken(twoEvents));
    }


    /// <summary>
    /// Issues <paramref name="securityEvent"/> as a one-event SET and receives
    /// it from wire bytes alone through the full reception pipeline.
    /// </summary>
    private async Task<SecurityEventToken> RoundTripAsync(SecurityEvent securityEvent)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

        var subject = SubjectIdentifier.Email("user@example.com");
        string compact = await SecurityEventTokenIssuance.IssueAsync(
            Issuer,
            [Audience],
            jwtId: Guid.NewGuid().ToString("N"),
            issuedAt: DateTimeOffset.FromUnixTimeSeconds(1615305000),
            [securityEvent],
            transmitterPrivate,
            TestSetup.Base64UrlEncoder,
            SecurityEventTestJson.HeaderSerializer,
            SecurityEventTestJson.PayloadSerializer,
            Pool,
            TestContext.CancellationToken,
            signingKeyId: "key-1",
            subjectId: subject).ConfigureAwait(false);

        SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
            compact, transmitterPublic, Issuer, Audience,
            SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
            TestSetup.Base64UrlDecoder, NeverSeen, new ExchangeContext(), Pool,
            TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Accepted, decision.Outcome);

        return decision.Token!;
    }
}
