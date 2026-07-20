using System;
using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for CTAP 2.3's power-cycle state operation (wave-5b PIN/UV contract decision 7): the pure
/// <see cref="CtapAuthenticatorState.PowerCycle"/> transform's exact preserve/refresh/clear sets, and
/// <see cref="CtapAuthenticatorSimulator.PowerCycle"/>'s equivalent simulator-level seam — testable
/// without reconstructing the simulator.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorPowerCycleTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A power cycle preserves the stored PIN hash carrier, its code-point length, both retry
    /// counters, and this wave's four config fields (<c>IsAlwaysUvEnabled</c>,
    /// <c>MinPinCodePointLength</c>, <c>IsForcePinChangeRequired</c>, <c>MinPinLengthRpIds</c> — CTAP
    /// 2.3 §7.2.3/§7.4.3 revert these only "after an authenticator reset",
    /// <see cref="CtapAuthenticatorState.FactoryReset"/>'s own concern) while clearing the
    /// consecutive-mismatch counter and the power-cycle latch, refreshing both PIN/UV auth protocols'
    /// key-agreement key pairs and pinUvAuthTokens, and leaving the AAGUID, <c>firmwareVersion</c> (R7:
    /// device identity, the AAGUID analogy), advertised extensions, resident-credential capacity,
    /// credential store, and credential sequence counter untouched.
    /// </summary>
    [TestMethod]
    public void PowerCyclePreservesPinConfigurationClearsTheLatchAndRefreshesKeyMaterial()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        DateTimeOffset now = TestClock.CanonicalEpoch;
        DigestValue storedPin = BuildFixedDigest(0x77, 16, pool);

        CtapAuthenticatorState before = CtapAuthenticatorState.Initial(
            aaguid, now, supportedExtensions: ["hmac-secret"], residentCredentialCapacity: 5, keyAgreementPool: pool, firmwareVersion: 7) with
        {
            CurrentStoredPin = storedPin,
            PinCodePointLength = 6,
            PinRetries = 3,
            UvRetries = 8,
            ConsecutivePinMismatches = 2,
            IsPowerCycleRequired = true,
            IsAlwaysUvEnabled = true,
            MinPinCodePointLength = 6,
            IsForcePinChangeRequired = true,
            MinPinLengthRpIds = ["example.com"]
        };

        byte[] protocolOnePublicKeyBefore = before.ProtocolOneKeyAgreementKeyPair.PublicKey.AsReadOnlySpan().ToArray();
        byte[] protocolTwoPublicKeyBefore = before.ProtocolTwoKeyAgreementKeyPair.PublicKey.AsReadOnlySpan().ToArray();
        byte[] protocolOneTokenBefore = before.ProtocolOneToken.Token.AsReadOnlySpan().ToArray();
        byte[] protocolTwoTokenBefore = before.ProtocolTwoToken.Token.AsReadOnlySpan().ToArray();

        CtapAuthenticatorState after = before.PowerCycle(now, pool);

        Assert.AreEqual(aaguid, after.Aaguid, "AAGUID must never change across a power cycle.");
        Assert.AreEqual(7, after.FirmwareVersion, "firmwareVersion is device identity, like the AAGUID, and survives a power cycle unchanged.");
        Assert.AreSame(before.SupportedExtensions, after.SupportedExtensions, "Advertised extensions are a personalization knob, unaffected by a power cycle.");
        Assert.AreEqual(5, after.ResidentCredentialCapacity);
        Assert.AreSame(before.CredentialsByCredentialId, after.CredentialsByCredentialId, "The credential store must be untouched by a power cycle.");
        Assert.AreEqual(before.NextCredentialSequence, after.NextCredentialSequence);

        Assert.AreSame(storedPin, after.CurrentStoredPin, "The stored PIN hash carrier must survive a power cycle unchanged.");
        Assert.AreEqual(6, after.PinCodePointLength);
        Assert.AreEqual(3, after.PinRetries, "pinRetries is untouched by a power cycle (only a correct PIN entry or authenticatorReset changes it).");
        Assert.AreEqual(8, after.UvRetries);

        Assert.AreEqual(0, after.ConsecutivePinMismatches, "A power cycle clears the consecutive-mismatch counter.");
        Assert.IsFalse(after.IsPowerCycleRequired, "A power cycle clears its own latch.");

        Assert.IsTrue(after.IsAlwaysUvEnabled, "alwaysUv survives a power cycle; only authenticatorReset reverts it.");
        Assert.AreEqual(6, after.MinPinCodePointLength, "the current minimum PIN length survives a power cycle; only authenticatorReset reverts it.");
        Assert.IsTrue(after.IsForcePinChangeRequired, "forcePINChange survives a power cycle; only authenticatorReset or a successful changePIN clears it.");
        Assert.AreSequenceEqual(
            (string[])[.. before.MinPinLengthRpIds], (string[])[.. after.MinPinLengthRpIds],
            "minPinLengthRPIDs (§7.4.3 line 8424) survives a power cycle; only authenticatorReset clears it.");

        Assert.IsFalse(protocolOnePublicKeyBefore.AsSpan().SequenceEqual(after.ProtocolOneKeyAgreementKeyPair.PublicKey.AsReadOnlySpan()), "Protocol one's key-agreement key pair must be refreshed.");
        Assert.IsFalse(protocolTwoPublicKeyBefore.AsSpan().SequenceEqual(after.ProtocolTwoKeyAgreementKeyPair.PublicKey.AsReadOnlySpan()), "Protocol two's key-agreement key pair must be refreshed.");
        Assert.IsFalse(protocolOneTokenBefore.AsSpan().SequenceEqual(after.ProtocolOneToken.Token.AsReadOnlySpan()), "Protocol one's pinUvAuthToken must be refreshed.");
        Assert.IsFalse(protocolTwoTokenBefore.AsSpan().SequenceEqual(after.ProtocolTwoToken.Token.AsReadOnlySpan()), "Protocol two's pinUvAuthToken must be refreshed.");

        Assert.AreSame(
            before.SerializedLargeBlobArray, after.SerializedLargeBlobArray,
            "The serialized large-blob array (CTAP 2.3 §6.10) is a persistent store, untouched by a power cycle — only authenticatorReset reverts it.");

        after.ProtocolOneKeyAgreementKeyPair.Dispose();
        after.ProtocolTwoKeyAgreementKeyPair.Dispose();
        after.ProtocolOneToken.Dispose();
        after.ProtocolTwoToken.Dispose();
        after.CurrentStoredPin!.Dispose();
        after.SerializedLargeBlobArray.Dispose();
    }


    /// <summary>
    /// A power cycle preserves a credential's CredRandom pair by reference (contract R2's
    /// PowerCycle-preserves half): <see cref="CtapAuthenticatorState.PowerCycle"/> never touches
    /// <see cref="CtapAuthenticatorState.CredentialsByCredentialId"/> in its own <c>with</c> copy (proven
    /// generically above by <see cref="PowerCyclePreservesPinConfigurationClearsTheLatchAndRefreshesKeyMaterial"/>'s
    /// dictionary-reference assertion), so a stored record — and therefore its
    /// <see cref="CtapCredentialRecord.CredRandomWithUV"/>/<see cref="CtapCredentialRecord.CredRandomWithoutUV"/>
    /// pooled owners — survives as the SAME objects, not merely equal ones.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects created by 'CredentialId.Create'/'UserHandle.Create' before all references to it are out of scope",
        Justification = "Ownership of the credential ID and user handle carriers transfers to the CtapCredentialRecord constructed immediately afterward; record.Dispose() releases both once the assertions complete.")]
    public async Task PowerCyclePreservesCredRandomWithUvAndWithoutUvByReference()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        DateTimeOffset now = TestClock.CanonicalEpoch;

        CtapCredentialSigningBackend backend = CtapCredentialSigningBackend.CreateEs256Default();
        CtapCredentialKeyPair keyPair = await backend.GenerateCredentialKeyPair(WellKnownCoseAlgorithms.Es256, pool, TestContext.CancellationToken);
        CredentialId credentialId = CredentialId.Create(BuildFixedBytes(16, 0x92), pool);
        UserHandle userId = UserHandle.Create(BuildFixedBytes(16, 0x93), pool);
        IMemoryOwner<byte> credRandomWithUV = pool.Rent(32);
        IMemoryOwner<byte> credRandomWithoutUV = pool.Rent(32);
        CtapCredentialRecord record = new(
            credentialId, "example.com", userId, "alice", "Alice Example", WellKnownCoseAlgorithms.Es256,
            IsResident: true, keyPair.PrivateKey, SignCount: 0, CreationSequence: 0, PublicKey: keyPair.PublicKey, CredProtectLevel: 1,
            CredRandomWithUV: credRandomWithUV, CredRandomWithoutUV: credRandomWithoutUV);

        string credentialIdHex = Convert.ToHexStringLower(credentialId.AsReadOnlySpan());
        ImmutableDictionary<string, CtapCredentialRecord> store = ImmutableDictionary<string, CtapCredentialRecord>.Empty.Add(credentialIdHex, record);

        CtapAuthenticatorState before = CtapAuthenticatorState.Initial(aaguid, now, keyAgreementPool: pool) with
        {
            CredentialsByCredentialId = store
        };

        CtapAuthenticatorState after = before.PowerCycle(now, pool);

        CtapCredentialRecord survivingRecord = after.CredentialsByCredentialId[credentialIdHex];
        Assert.AreSame(record, survivingRecord, "the credential record itself must be the same object across a power cycle.");
        Assert.AreSame(credRandomWithUV, survivingRecord.CredRandomWithUV, "CredRandomWithUV must survive a power cycle as the same pooled owner.");
        Assert.AreSame(credRandomWithoutUV, survivingRecord.CredRandomWithoutUV, "CredRandomWithoutUV must survive a power cycle as the same pooled owner.");

        record.Dispose();
        after.ProtocolOneKeyAgreementKeyPair.Dispose();
        after.ProtocolTwoKeyAgreementKeyPair.Dispose();
        after.ProtocolOneToken.Dispose();
        after.ProtocolTwoToken.Dispose();
        after.SerializedLargeBlobArray.Dispose();
    }


    /// <summary>
    /// A power cycle preserves BOTH the vendor-burned-in <see cref="CtapAuthenticatorState.EnterpriseAttestationProvisioning"/>
    /// record (the SAME reference, never re-minted) and the runtime-only
    /// <see cref="CtapAuthenticatorState.IsEnterpriseAttestationEnabled"/> flag, whichever value it
    /// holds — R3: CTAP 2.3 §7.1.3/§6.6 name no power-cycle obligation for either, unlike
    /// <see cref="CtapAuthenticatorState.FactoryReset"/>'s own reset-disables-the-feature behavior.
    /// </summary>
    [TestMethod]
    public void PowerCyclePreservesEnterpriseAttestationProvisioningAndEnabledFlag()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        DateTimeOffset now = TestClock.CanonicalEpoch;
        CtapEnterpriseAttestationProvisioning provisioning = CtapWaveEpFixtures.BuildProvisioning(pool);

        CtapAuthenticatorState before = CtapAuthenticatorState.Initial(
            aaguid, now, keyAgreementPool: pool, enterpriseAttestationProvisioning: provisioning) with
        {
            IsEnterpriseAttestationEnabled = true
        };

        CtapAuthenticatorState after = before.PowerCycle(now, pool);

        Assert.IsTrue(after.IsEnterpriseAttestationCapable);
        Assert.AreSame(provisioning, after.EnterpriseAttestationProvisioning, "the provisioning record must survive a power cycle unchanged, never re-minted.");
        Assert.IsTrue(after.IsEnterpriseAttestationEnabled, "the enabled flag must survive a power cycle.");

        after.ProtocolOneKeyAgreementKeyPair.Dispose();
        after.ProtocolTwoKeyAgreementKeyPair.Dispose();
        after.ProtocolOneToken.Dispose();
        after.ProtocolTwoToken.Dispose();
        after.SerializedLargeBlobArray.Dispose();
        provisioning.Dispose();
    }


    /// <summary>
    /// A power cycle discards ALL THREE remembered stateful-command sequences (R10):
    /// <see cref="CtapAuthenticatorState.RememberedGetAssertion"/> dies alongside the two credMgmt
    /// enumeration sequences on the same deliberate basis, CTAP 2.3, section 6, item 1 (line 2869):
    /// "The state SHOULD NOT be maintained across power cycles."
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the DigestValue transfers into the CtapRememberedGetAssertionState installed on the state below, which CtapAuthenticatorState.PowerCycle disposes via its own RememberedGetAssertion?.Dispose() call; the analyzer cannot see this transfer through the with-expression and the method call.")]
    public void PowerCycleDiscardsAllThreeRememberedStatefulSequences()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        DateTimeOffset now = TestClock.CanonicalEpoch;
        DigestValue clientDataHash = BuildFixedDigest(0xA1, 32, pool);
        var rememberedGetAssertion = new CtapRememberedGetAssertionState([], clientDataHash, true, true, 1, now, CtapPinUvAuthProtocolId.Two, LargeBlobKeyRequested: false);
        var rememberedEnumerateRps = new CtapRememberedEnumerateRpsState(["a.example", "b.example"], 1, now, CtapPinUvAuthProtocolId.Two);
        var rememberedEnumerateCredentials = new CtapRememberedEnumerateCredentialsState([], 1, now, CtapPinUvAuthProtocolId.Two);

        CtapAuthenticatorState before = CtapAuthenticatorState.Initial(Guid.NewGuid(), now, keyAgreementPool: pool) with
        {
            RememberedGetAssertion = rememberedGetAssertion,
            RememberedEnumerateRps = rememberedEnumerateRps,
            RememberedEnumerateCredentials = rememberedEnumerateCredentials
        };

        CtapAuthenticatorState after = before.PowerCycle(now, pool);

        Assert.IsNull(after.RememberedGetAssertion, "authenticatorGetNextAssertion's own sequence must not survive a power cycle.");
        Assert.IsNull(after.RememberedEnumerateRps, "enumerateRPsGetNextRP's own sequence must not survive a power cycle.");
        Assert.IsNull(after.RememberedEnumerateCredentials, "enumerateCredentialsGetNextCredential's own sequence must not survive a power cycle.");

        after.ProtocolOneKeyAgreementKeyPair.Dispose();
        after.ProtocolTwoKeyAgreementKeyPair.Dispose();
        after.ProtocolOneToken.Dispose();
        after.ProtocolTwoToken.Dispose();
        after.SerializedLargeBlobArray.Dispose();
    }


    /// <summary>
    /// A power cycle discards an in-progress <c>authenticatorBioEnrollment</c> capture sequence (R7,
    /// joining the existing three-slot discard set), disposing its not-yet-persisted template identifier,
    /// while a provisioned (completed) fingerprint template SURVIVES — the fourth slot's own asymmetry:
    /// <see cref="CtapAuthenticatorState.BioEnrollmentTemplatesByTemplateId"/> is persistent state (the
    /// <see cref="CtapAuthenticatorState.CredentialsByCredentialId"/> analogy), never remembered-sequence-
    /// shaped.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the in-progress capture's template identifier transfers into the CtapRememberedBioEnrollmentState installed on `before`, which CtapAuthenticatorState.PowerCycle disposes via its own RememberedBioEnrollment?.Dispose() call; the provisioned template's identifier transfers into `before`'s BioEnrollmentTemplatesByTemplateId, disposed explicitly below since PowerCycle leaves the store untouched.")]
    public void PowerCyclePreservesProvisionedTemplatesButDiscardsInProgressCapture()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        DateTimeOffset now = TestClock.CanonicalEpoch;

        BioEnrollmentTemplateId provisionedTemplateId = BioEnrollmentTemplateId.Create(BuildFixedBytes(16, 0x60), pool);
        var provisionedRecord = new CtapBioEnrollmentTemplateRecord(provisionedTemplateId, FriendlyName: "right index");
        ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord> populatedStore = ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord>.Empty
            .Add(Convert.ToHexStringLower(provisionedTemplateId.AsReadOnlySpan()), provisionedRecord);
        BioEnrollmentTemplateId inProgressTemplateId = BioEnrollmentTemplateId.Create(BuildFixedBytes(16, 0x61), pool);
        var rememberedBioEnrollment = new CtapRememberedBioEnrollmentState(inProgressTemplateId, RemainingSamples: 1);

        CtapAuthenticatorState before = CtapAuthenticatorState.Initial(Guid.NewGuid(), now, keyAgreementPool: pool) with
        {
            BioEnrollmentTemplatesByTemplateId = populatedStore,
            RememberedBioEnrollment = rememberedBioEnrollment
        };

        CtapAuthenticatorState after = before.PowerCycle(now, pool);

        Assert.AreSame(populatedStore, after.BioEnrollmentTemplatesByTemplateId, "the provisioned template store must survive a power cycle unchanged.");
        Assert.IsTrue(after.HasProvisionedBioEnrollments);
        Assert.IsNull(after.RememberedBioEnrollment, "an in-progress capture sequence must not survive a power cycle (R7).");

        provisionedTemplateId.Dispose();
        after.ProtocolOneKeyAgreementKeyPair.Dispose();
        after.ProtocolTwoKeyAgreementKeyPair.Dispose();
        after.ProtocolOneToken.Dispose();
        after.ProtocolTwoToken.Dispose();
        after.SerializedLargeBlobArray.Dispose();
    }


    /// <summary>
    /// <see cref="CtapAuthenticatorSimulator.PowerCycle"/> is a real, invokable simulator-level seam: a
    /// credential registered beforehand remains fully usable afterward (proving the credential store and
    /// the AAGUID survive), while <c>getKeyAgreement</c> reports different key material for BOTH
    /// protocols afterward (proving the refresh actually happened) — all without reconstructing the
    /// simulator (row 5435's testability goal).
    /// </summary>
    [TestMethod]
    public async Task SimulatorPowerCycleKeepsCredentialsUsableAndRefreshesBothProtocolsKeyAgreement()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulatorWithClientPinAndCredentials("power-cycle-sim");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        Guid aaguidBefore = simulator.Aaguid;

        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0x90), TestContext.CancellationToken);

        CoseKey protocolOneKeyBefore = await GetKeyAgreementAsync(simulator, CtapPinUvAuthProtocolId.One, pool);
        CoseKey protocolTwoKeyBefore = await GetKeyAgreementAsync(simulator, CtapPinUvAuthProtocolId.Two, pool);

        simulator.PowerCycle();

        Assert.AreEqual(aaguidBefore, simulator.Aaguid, "The AAGUID must never change across a power cycle.");

        CredentialId credentialId = CredentialId.Create(credentialIdBytes, pool);
        CtapGetAssertionRequest request = BuildGetAssertionRequest(
            pool, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId }]);
        using(PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0],
                "A credential registered before a power cycle must remain fully usable afterward.");
        }

        CoseKey protocolOneKeyAfter = await GetKeyAgreementAsync(simulator, CtapPinUvAuthProtocolId.One, pool);
        CoseKey protocolTwoKeyAfter = await GetKeyAgreementAsync(simulator, CtapPinUvAuthProtocolId.Two, pool);

        Assert.IsFalse(protocolOneKeyBefore.X!.Value.Span.SequenceEqual(protocolOneKeyAfter.X!.Value.Span), "Protocol one's key-agreement public key must change across a power cycle.");
        Assert.IsFalse(protocolTwoKeyBefore.X!.Value.Span.SequenceEqual(protocolTwoKeyAfter.X!.Value.Span), "Protocol two's key-agreement public key must change across a power cycle.");
    }


    /// <summary>
    /// Builds a simulator wired with both the credential-signing backend and the <c>clientPIN</c>
    /// codecs, so this file can exercise credential registration and <c>getKeyAgreement</c> together —
    /// neither <see cref="TestInfrastructure.CtapWave2AuthenticatorFixtures"/> nor
    /// <see cref="TestInfrastructure.CtapWave5AuthenticatorFixtures"/> combines both.
    /// </summary>
    private static CtapAuthenticatorSimulator CreateSimulatorWithClientPinAndCredentials(string runId) =>
        new(
            runId,
            CtapGetInfoResponseCborWriter.Write,
            CtapMakeCredentialRequestCborReader.Read,
            CtapMakeCredentialResponseCborWriter.Write,
            CtapGetAssertionRequestCborReader.Read,
            CtapGetAssertionResponseCborWriter.Write,
            CredentialPublicKeyCborWriter.Write,
            PackedAttestationStatementCborWriter.Write,
            credentialSigningBackend: CtapCredentialSigningBackend.CreateEs256Default(),
            decodeClientPinRequest: CtapClientPinRequestCborReader.Read,
            encodeClientPinResponse: CtapClientPinResponseCborWriter.Write,
            decodeAuthenticatorConfigRequest: CtapAuthenticatorConfigRequestCborReader.Read,
            decodeCredentialManagementRequest: CtapCredentialManagementRequestCborReader.Read,
            encodeCredentialManagementResponse: CtapCredentialManagementResponseCborWriter.Write,
            decodeBioEnrollmentRequest: CtapBioEnrollmentRequestCborReader.Read,
            encodeBioEnrollmentResponse: CtapBioEnrollmentResponseCborWriter.Write,
            decodeLargeBlobsRequest: CtapLargeBlobsRequestCborReader.Read,
            encodeLargeBlobsResponse: CtapLargeBlobsResponseCborWriter.Write,
            encodeMakeCredentialExtensionOutputs: CtapMakeCredentialExtensionOutputsCborWriter.Write,
            encodeGetAssertionExtensionOutputs: CtapGetAssertionExtensionOutputsCborWriter.Write);


    /// <summary>Sends a <c>getKeyAgreement</c> request for <paramref name="id"/> and returns the reported COSE_Key.</summary>
    private async Task<CoseKey> GetKeyAgreementAsync(CtapAuthenticatorSimulator simulator, CtapPinUvAuthProtocolId id, MemoryPool<byte> pool)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)id);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, TestContext.CancellationToken);

        return response.KeyAgreement!;
    }


    /// <summary>
    /// <see cref="CtapAuthenticatorState.CurrentStoredPin"/>'s chosen carrier type — a
    /// <see cref="DigestValue"/> sized to <c>LEFT(SHA-256(PIN), 16)</c> — zeroes its 16-byte buffer on
    /// dispose, observed through the tracking-pool public seam without any test-only hook in production
    /// code. This test fabricates the digest directly (via <see cref="BuildFixedDigest"/>) so the
    /// carrier's own dispose-time zeroing is proven independently of any one production path that mints
    /// a stored-PIN digest, such as <see cref="CtapAuthenticatorSetPinTests"/>'s <c>setPIN</c> coverage.
    /// </summary>
    [TestMethod]
    public void StoredPinHashCarrierZeroesOnDispose()
    {
        const int PinHashLength = 16;
        using var trackingPool = new ZeroOnDisposeTrackingMemoryPool(PinHashLength);

        DigestValue storedPin = BuildFixedDigest(0x99, PinHashLength, trackingPool);
        storedPin.Dispose();

        Assert.AreEqual(1, trackingPool.TrackedDisposalCount);
        Assert.IsTrue(trackingPool.AllTrackedDisposalsWereZero, "The stored PIN hash carrier must be zeroed before its buffer returns to the pool.");
    }


    /// <summary>
    /// Builds a fixed-pattern digest of <paramref name="length"/> bytes, mirroring the shape of a
    /// <c>LEFT(SHA-256(PIN), 16)</c> pin-hash carrier, to exercise
    /// <see cref="CtapAuthenticatorState.CurrentStoredPin"/>'s chosen carrier type directly rather than
    /// through a full <c>setPIN</c> round trip.
    /// </summary>
    private static DigestValue BuildFixedDigest(byte seed, int length, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(length);
        for(int i = 0; i < length; i++)
        {
            owner.Memory.Span[i] = (byte)(seed + i);
        }

        return new DigestValue(owner, CryptoTags.Sha256Digest);
    }
}
