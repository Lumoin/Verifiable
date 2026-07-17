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
/// Round-trip tests for the rest of the typed event catalog beyond the interop
/// three: the remaining CAEP events — <c>token-claims-change</c> (CAEP 1.0
/// §3.2), <c>assurance-level-change</c> (§3.4), <c>session-established</c>
/// (§3.6), <c>session-presented</c> (§3.7), <c>risk-level-change</c> (§3.8) —
/// and the RISC 1.0 §2 events. Each typed build is issued as a SET, received
/// from wire bytes alone through the full reception pipeline, and projected
/// back typed; strict projections reject values outside the closed sets.
/// </summary>
[TestClass]
internal sealed class CaepRiscEventCatalogTests
{
    private const string Issuer = "https://transmitter.example/";
    private const string Audience = "https://receiver.example/ssf";

    public TestContext TestContext { get; set; } = null!;

    private static MemoryPool<byte> Pool => BaseMemoryPool.Shared;

    private static readonly IsSecurityEventTokenJtiSeenDelegate NeverSeen =
        static (jti, context, cancellationToken) => ValueTask.FromResult(false);


    [TestMethod]
    public async Task TokenClaimsChangeRoundTripsAndRequiresNonEmptyClaims()
    {
        var change = new CaepTokenClaimsChangeEvent
        {
            Claims = new Dictionary<string, object> { ["role"] = "ro-admin", ["trusted_network"] = "false" },
            Common = new CaepEventClaims
            {
                EventTimestamp = DateTimeOffset.FromUnixTimeSeconds(1615304991),
                InitiatingEntity = CaepInitiatingEntityValues.Policy
            }
        };

        SecurityEventToken token = await RoundTripAsync(change.ToSecurityEvent()).ConfigureAwait(false);
        CaepTokenClaimsChangeEvent? projected = CaepTokenClaimsChangeEvent.From(token.Events[0]);

        Assert.IsNotNull(projected);
        Assert.AreEqual(change, projected);

        //§3.2.1: "one or more claims" — an empty claims object does not project.
        var emptyClaims = new SecurityEvent
        {
            EventType = CaepEventTypes.TokenClaimsChange,
            Payload = new Dictionary<string, object>
            {
                [CaepTokenClaimsChangeClaimNames.Claims] = new Dictionary<string, object>()
            }
        };
        Assert.IsNull(CaepTokenClaimsChangeEvent.From(emptyClaims));
    }


    [TestMethod]
    public async Task AssuranceLevelChangeRoundTripsAndClosesChangeDirection()
    {
        var change = new CaepAssuranceLevelChangeEvent
        {
            Namespace = CaepAssuranceNamespaceValues.NistAal,
            CurrentLevel = "nist-aal2",
            PreviousLevel = "nist-aal1",
            ChangeDirection = CaepChangeDirectionValues.Increase,
            Common = new CaepEventClaims { EventTimestamp = DateTimeOffset.FromUnixTimeSeconds(1615304991) }
        };

        SecurityEventToken token = await RoundTripAsync(change.ToSecurityEvent()).ConfigureAwait(false);
        CaepAssuranceLevelChangeEvent? projected = CaepAssuranceLevelChangeEvent.From(token.Events[0]);

        Assert.IsNotNull(projected);
        Assert.AreEqual(change, projected);

        //§3.4.1: a custom namespace alias is valid (open set)…
        var customNamespace = new SecurityEvent
        {
            EventType = CaepEventTypes.AssuranceLevelChange,
            Payload = new Dictionary<string, object>
            {
                [CaepAssuranceLevelChangeClaimNames.Namespace] = "example-corp-levels",
                [CaepAssuranceLevelChangeClaimNames.CurrentLevel] = "gold"
            }
        };
        Assert.IsNotNull(CaepAssuranceLevelChangeEvent.From(customNamespace));

        //…but a present change_direction is closed to increase/decrease.
        var sideways = new SecurityEvent
        {
            EventType = CaepEventTypes.AssuranceLevelChange,
            Payload = new Dictionary<string, object>
            {
                [CaepAssuranceLevelChangeClaimNames.Namespace] = CaepAssuranceNamespaceValues.Rfc8176,
                [CaepAssuranceLevelChangeClaimNames.CurrentLevel] = "otp",
                [CaepAssuranceLevelChangeClaimNames.ChangeDirection] = "sideways"
            }
        };
        Assert.IsNull(CaepAssuranceLevelChangeEvent.From(sideways));
    }


    [TestMethod]
    public async Task SessionEstablishedAndPresentedRoundTrip()
    {
        var established = new CaepSessionEstablishedEvent
        {
            FpUa = "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611",
            Acr = "urn:mace:incommon:iap:silver",
            Amr = new List<string> { "otp", "pwd" },
            ExtId = "12345",
            Common = new CaepEventClaims { EventTimestamp = DateTimeOffset.FromUnixTimeSeconds(1615304991) }
        };

        SecurityEventToken establishedToken = await RoundTripAsync(established.ToSecurityEvent()).ConfigureAwait(false);
        CaepSessionEstablishedEvent? projectedEstablished = CaepSessionEstablishedEvent.From(establishedToken.Events[0]);

        Assert.IsNotNull(projectedEstablished);
        Assert.AreEqual(established, projectedEstablished);

        var presented = new CaepSessionPresentedEvent
        {
            FpUa = "abb0b6e7da81a42233f8f2b1a8ddb1b9a4c81611",
            ExtId = "12345",
            Common = new CaepEventClaims { EventTimestamp = DateTimeOffset.FromUnixTimeSeconds(1615304991) }
        };

        SecurityEventToken presentedToken = await RoundTripAsync(presented.ToSecurityEvent()).ConfigureAwait(false);
        CaepSessionPresentedEvent? projectedPresented = CaepSessionPresentedEvent.From(presentedToken.Events[0]);

        Assert.IsNotNull(projectedPresented);
        Assert.AreEqual(presented, projectedPresented);

        //The two session events do not cross-project.
        Assert.IsNull(CaepSessionEstablishedEvent.From(presentedToken.Events[0]));
        Assert.IsNull(CaepSessionPresentedEvent.From(establishedToken.Events[0]));
    }


    [TestMethod]
    public async Task RiskLevelChangeRoundTripsAndClosesLevels()
    {
        var change = new CaepRiskLevelChangeEvent
        {
            Principal = CaepRiskPrincipalValues.User,
            CurrentLevel = CaepRiskLevelValues.High,
            PreviousLevel = CaepRiskLevelValues.Low,
            RiskReason = "PASSWORD_FOUND_IN_DATA_BREACH",
            Common = new CaepEventClaims
            {
                EventTimestamp = DateTimeOffset.FromUnixTimeSeconds(1615304991),
                InitiatingEntity = CaepInitiatingEntityValues.System
            }
        };

        SecurityEventToken token = await RoundTripAsync(change.ToSecurityEvent()).ConfigureAwait(false);
        CaepRiskLevelChangeEvent? projected = CaepRiskLevelChangeEvent.From(token.Events[0]);

        Assert.IsNotNull(projected);
        Assert.AreEqual(change, projected);

        //§3.8.1: levels are closed to LOW/MEDIUM/HIGH; principal is open.
        var badLevel = new SecurityEvent
        {
            EventType = CaepEventTypes.RiskLevelChange,
            Payload = new Dictionary<string, object>
            {
                [CaepRiskLevelChangeClaimNames.Principal] = "WORKLOAD",
                [CaepRiskLevelChangeClaimNames.CurrentLevel] = "SEVERE"
            }
        };
        Assert.IsNull(CaepRiskLevelChangeEvent.From(badLevel));

        var openPrincipal = new SecurityEvent
        {
            EventType = CaepEventTypes.RiskLevelChange,
            Payload = new Dictionary<string, object>
            {
                [CaepRiskLevelChangeClaimNames.Principal] = "WORKLOAD",
                [CaepRiskLevelChangeClaimNames.CurrentLevel] = CaepRiskLevelValues.Medium
            }
        };
        Assert.IsNotNull(CaepRiskLevelChangeEvent.From(openPrincipal));
    }


    [TestMethod]
    public async Task RiscCredentialCompromiseRoundTripsAndRequiresCredentialType()
    {
        var compromise = new RiscCredentialCompromiseEvent
        {
            CredentialType = CaepCredentialTypeValues.Password,
            EventTimestamp = DateTimeOffset.FromUnixTimeSeconds(1508184845),
            ReasonAdmin = new Dictionary<string, string> { ["en"] = "Credential found in a breach corpus." }
        };

        SecurityEventToken token = await RoundTripAsync(compromise.ToSecurityEvent()).ConfigureAwait(false);
        RiscCredentialCompromiseEvent? projected = RiscCredentialCompromiseEvent.From(token.Events[0]);

        Assert.IsNotNull(projected);
        Assert.AreEqual(compromise, projected);

        //§2.7: credential_type is REQUIRED.
        var missingType = new SecurityEvent
        {
            EventType = RiscEventTypes.CredentialCompromise,
            Payload = new Dictionary<string, object>()
        };
        Assert.IsNull(RiscCredentialCompromiseEvent.From(missingType));
    }


    [TestMethod]
    public async Task RiscAttributedEventsRoundTrip()
    {
        //account-disabled with the §2.3 reason.
        var disabled = new RiscAccountDisabledEvent { Reason = RiscAccountDisabledReasonValues.Hijacking };
        SecurityEventToken disabledToken = await RoundTripAsync(disabled.ToSecurityEvent()).ConfigureAwait(false);
        RiscAccountDisabledEvent? projectedDisabled = RiscAccountDisabledEvent.From(disabledToken.Events[0]);

        Assert.IsNotNull(projectedDisabled);
        Assert.AreEqual(disabled, projectedDisabled);

        //identifier-changed with the §2.5 hyphenated new-value, on an email subject.
        var changed = new RiscIdentifierChangedEvent { NewValue = "john.roe@example.com" };
        SecurityEventToken changedToken = await RoundTripAsync(
            changed.ToSecurityEvent(),
            SubjectIdentifier.Email("john.doe@example.com")).ConfigureAwait(false);
        RiscIdentifierChangedEvent? projectedChanged = RiscIdentifierChangedEvent.From(changedToken.Events[0]);

        Assert.IsNotNull(projectedChanged);
        Assert.AreEqual(changed, projectedChanged);
        Assert.AreEqual(SubjectIdentifierFormats.Email, changedToken.SubjectId!.Format);
    }


    [TestMethod]
    public async Task RiscPayloadlessEventsCoverTheCatalog()
    {
        //Every attribute-less §2 event builds with an empty payload object and
        //its catalogued type URI; one exemplar runs the full wire round trip.
        (SecurityEvent Event, string ExpectedType)[] catalog =
        [
            (RiscPayloadlessEvents.AccountCredentialChangeRequired(), RiscEventTypes.AccountCredentialChangeRequired),
            (RiscPayloadlessEvents.AccountPurged(), RiscEventTypes.AccountPurged),
            (RiscPayloadlessEvents.AccountEnabled(), RiscEventTypes.AccountEnabled),
            (RiscPayloadlessEvents.IdentifierRecycled(), RiscEventTypes.IdentifierRecycled),
            (RiscPayloadlessEvents.OptIn(), RiscEventTypes.OptIn),
            (RiscPayloadlessEvents.OptOutInitiated(), RiscEventTypes.OptOutInitiated),
            (RiscPayloadlessEvents.OptOutCancelled(), RiscEventTypes.OptOutCancelled),
            (RiscPayloadlessEvents.OptOutEffective(), RiscEventTypes.OptOutEffective),
            (RiscPayloadlessEvents.RecoveryActivated(), RiscEventTypes.RecoveryActivated),
            (RiscPayloadlessEvents.RecoveryInformationChanged(), RiscEventTypes.RecoveryInformationChanged),
            (RiscPayloadlessEvents.SessionsRevoked(), RiscEventTypes.SessionsRevoked)
        ];

        foreach((SecurityEvent securityEvent, string expectedType) in catalog)
        {
            Assert.AreEqual(expectedType, securityEvent.EventType);
            Assert.IsEmpty(securityEvent.Payload);
            Assert.IsTrue(RiscEventTypes.IsRiscEventType(securityEvent.EventType));
        }

        SecurityEventToken token = await RoundTripAsync(RiscPayloadlessEvents.AccountPurged()).ConfigureAwait(false);
        Assert.IsTrue(RiscEventTypes.IsAccountPurged(token.Events[0].EventType));
        Assert.IsEmpty(token.Events[0].Payload);
    }


    /// <summary>
    /// Issues <paramref name="securityEvent"/> as a one-event SET and receives
    /// it from wire bytes alone through the full reception pipeline.
    /// </summary>
    private async Task<SecurityEventToken> RoundTripAsync(
        SecurityEvent securityEvent, SubjectIdentifier? subject = null)
    {
        PublicPrivateKeyMaterial<PublicKeyMemory, PrivateKeyMemory> keys =
            TestKeyMaterialProvider.CreateFreshP256KeyMaterial();
        using PublicKeyMemory transmitterPublic = keys.PublicKey;
        using PrivateKeyMemory transmitterPrivate = keys.PrivateKey;

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
            signingKeyId: "key-1",
            subjectId: subject ?? SubjectIdentifier.IssuerSubject(Issuer, "user-1234"),
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        SsfDeliveryDecision decision = await SecurityEventTokenReception.ReceiveAsync(
            compact, transmitterPublic, Issuer, Audience,
            SecurityEventTestJson.DeserializePart, SecurityEventTestJson.DeserializePart,
            TestSetup.Base64UrlDecoder, NeverSeen, new ExchangeContext(), Pool,
            cancellationToken: TestContext.CancellationToken).ConfigureAwait(false);

        Assert.AreEqual(SsfDeliveryOutcome.Accepted, decision.Outcome);

        return decision.Token!;
    }
}
