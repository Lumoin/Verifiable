using System;
using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
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
/// The wave PKG-A unit-test matrix for <c>authenticatorReset</c> (<c>0x07</c>): the 10-second power-up
/// window (fake <see cref="TimeProvider"/>-driven boundary/re-arm matrix), the pure
/// <see cref="CtapAuthenticatorState.FactoryReset"/> transform's exact clear/keep field set (mirroring
/// <see cref="CtapAuthenticatorPowerCycleTests"/>'s own shape, including the wavelb R7 large-blob-array
/// restoration — a grown array reverts byte-exact to <see cref="CtapAuthenticatorState.InitialSerializedLargeBlobArray"/>),
/// wire-visible factory-default proofs (byte-
/// exact <c>getInfo</c> reversion, key/token regeneration, credential-store/PIN/config erasure), PIN-lockout
/// recovery, and idempotence. Driven in-process through <see cref="CtapAuthenticatorSimulator.TransceiveAsync"/>
/// (real-wire capstones are a later package), with platform-side <c>pinUvAuthParam</c> computed the same way
/// the wave-5c/waveconfig/wavecm fixtures compute mc/ga/acfg/cm's own — through
/// <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/> over the actual token bytes, never a test-only
/// crypto reimplementation.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorResetTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN most tests establish, matching this profile's default 4-code-point minimum.</summary>
    private const string DefaultPin = "1234";


    /// <summary>A reset issued strictly less than 10 seconds after power-on succeeds (CTAP 2.3, line 6365's "within").</summary>
    [TestMethod]
    public async Task ResetWithinWindowSucceeds()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-within-window", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        timeProvider.Advance(TimeSpan.FromSeconds(9));

        using PooledMemory response = await SendResetAsync(simulator, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A reset issued at EXACTLY 10 seconds after power-on still succeeds (line 6365's "within 10 seconds" is inclusive).</summary>
    [TestMethod]
    public async Task ResetExactlyAtWindowBoundarySucceeds()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-window-boundary", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        timeProvider.Advance(TimeSpan.FromSeconds(10));

        using PooledMemory response = await SendResetAsync(simulator, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A reset issued strictly more than 10 seconds after power-on fails with <c>CTAP2_ERR_NOT_ALLOWED</c> (line 6374).</summary>
    [TestMethod]
    public async Task ResetJustOverWindowReturnsNotAllowed()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-window-over", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        timeProvider.Advance(TimeSpan.FromSeconds(10) + TimeSpan.FromMilliseconds(1));

        using PooledMemory response = await SendResetAsync(simulator, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A reset rejected by the power-up window leaves the PIN, the credential store, config state
    /// (<c>alwaysUv</c>), <c>pinRetries</c>, and an already-issued <c>pinUvAuthToken</c> all fully intact —
    /// the ONLY effect of a failed reset is the family-standard remembered-<c>authenticatorGetAssertion</c>-
    /// sequence discard every command arm performs. The remembered sequence is established immediately
    /// before the failing reset, with the failing reset itself the ONLY command in between: the 11-second
    /// time advance below lands strictly past the reset's own 10-second power-up window (CTAP 2.3, line
    /// 6374) while staying strictly inside the sequence's own 30-second <c>authenticatorGetNextAssertion</c>
    /// timer (section 6.3), so the post-reset <c>authenticatorGetNextAssertion</c> probe can only observe
    /// <c>CTAP2_ERR_NOT_ALLOWED</c> because the reset arm's own discard ran — not because some earlier
    /// intervening command already discarded the sequence, and not because the sequence's own timer
    /// independently expired.
    /// </summary>
    [TestMethod]
    public async Task FailedResetLeavesStateIntactButDiscardsRememberedSequence()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-failed-intact", timeProvider: timeProvider, residentCredentialCapacity: 4);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        byte[] firstCredentialIdBytes = await RegisterResidentCredentialWithTokenAsync(
            simulator, pool, protocolId, BuildFixedBytes(16, 0xE0), TestContext.CancellationToken);
        _ = await RegisterResidentCredentialWithTokenAsync(
            simulator, pool, protocolId, BuildFixedBytes(16, 0xE1), TestContext.CancellationToken);

        //Only ONE pinUvAuthToken can be live per protocol at a time (issuing one replaces whatever the
        //protocol's current token was): this combined Mc|Ga|Acfg token is issued LAST among the setup
        //steps, after both registrations' own single-purpose tokens are already spent, so it remains the
        //LIVE token (Mc bit unstripped) through the toggle below, through the sequence-establishing
        //GetAssertion further down (issued with up:false, so it never runs the family-standard "up:true
        //clears every pinUvAuthToken permission but lbw" step and never touches this token), and through
        //the "already-issued token" proof at the very end.
        byte[] token = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin,
            WellKnownCtapPinUvAuthTokenPermissions.Mc | WellKnownCtapPinUvAuthTokenPermissions.Ga | WellKnownCtapPinUvAuthTokenPermissions.Acfg,
            rpId: DefaultRpId, TestContext.CancellationToken);

        byte[] toggleMessage = CtapWaveConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] toggleParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, toggleMessage, pool, TestContext.CancellationToken);
        var toggleRequest = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: toggleParam);
        using(PooledMemory toggleResponse = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, toggleRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, toggleResponse.AsReadOnlySpan()[0]);
        }

        using(CtapWave5bPlatformPinSession mismatchSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken))
        {
            byte[] wrongPinHashEnc = await mismatchSession.BuildWrongPinHashEncAsync(TestContext.CancellationToken);
            var mismatchRequest = new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
                KeyAgreement: mismatchSession.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);
            _ = await SendClientPinExpectingErrorAsync(simulator, mismatchRequest, pool, TestContext.CancellationToken);
        }

        Assert.AreEqual(7, await GetPinRetriesAsync(simulator, pool, TestContext.CancellationToken), "the wrong-PIN attempt must have dropped pinRetries before the failed reset.");

        //Established LAST among the setup steps, immediately before the time advance and the failing
        //reset below, with up:false: alwaysUv (toggled on above) gates authenticatorGetAssertion only
        //when the effective "up" option is true (CTAP 2.3, line 3917), so up:false both bypasses that
        //gate without a pinUvAuthParam and skips the "up:true clears every pinUvAuthToken permission but
        //lbw" step, leaving `token`'s Mc permission untouched for the proof at the end.
        CtapGetAssertionRequest multiAccountRequest = BuildGetAssertionRequest(pool, options: new CtapCommandOptions(UserPresence: false));
        using(PooledMemory multiAccountResponse = await SendGetAssertionAsync(simulator, multiAccountRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, multiAccountResponse.AsReadOnlySpan()[0]);
        }

        //11 seconds is simultaneously strictly PAST the reset's own 10-second power-up window (so the
        //reset below is rejected on that ground) and strictly INSIDE the remembered sequence's own
        //30-second GetNextAssertion timer (so, absent the reset arm's own discard, the probe further
        //down would still find the sequence live and return an assertion rather than NotAllowed).
        timeProvider.Advance(TimeSpan.FromSeconds(11));

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, resetResponse.AsReadOnlySpan()[0]);
        }

        using(PooledMemory nextResponse = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(
                WellKnownCtapStatusCodes.NotAllowed, nextResponse.AsReadOnlySpan()[0],
                "the family-standard remembered-sequence discard runs even when the reset itself is rejected.");
        }

        Assert.AreEqual(7, await GetPinRetriesAsync(simulator, pool, TestContext.CancellationToken), "a failed reset must not touch pinRetries.");

        CtapGetInfoResponse infoAfter = await CtapWaveConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(infoAfter.Options!.AlwaysUv!.Value, "a failed reset must not touch config state.");

        CredentialId firstCredentialId = CredentialId.Create(firstCredentialIdBytes, pool);
        CtapGetAssertionRequest allowListRequest = BuildGetAssertionRequest(
            pool, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = firstCredentialId }],
            options: new CtapCommandOptions(UserPresence: false));
        using(PooledMemory allowListResponse = await SendGetAssertionAsync(simulator, allowListRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, allowListResponse.AsReadOnlySpan()[0], "a failed reset must not erase the credential store.");
        }

        byte[] clientDataHashBytes = BuildFixedBytes(32, 0x10);
        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, clientDataHashBytes, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest mcRequest = BuildMakeCredentialRequest(
            pool, userId: BuildFixedBytes(16, 0xE2), pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)protocolId);
        using PooledMemory mcResponse = await SendMakeCredentialAsync(simulator, mcRequest, pool, TestContext.CancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, mcResponse.AsReadOnlySpan()[0], "a failed reset must not invalidate an already-issued pinUvAuthToken.");

        CtapMakeCredentialResponse decodedMc = CtapMakeCredentialResponseCborReader.Read(mcResponse.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decodedMc.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsTrue(authenticatorData.Flags.UserVerified, "the pre-existing pinUvAuthToken must still authenticate with uv=1 after a failed reset.");
    }


    /// <summary>A power cycle re-arms the 10-second power-up window: a reset that would otherwise fail succeeds once issued right after <see cref="CtapAuthenticatorSimulator.PowerCycle"/>.</summary>
    [TestMethod]
    public async Task PowerCycleReArmsResetWindow()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-powercycle-rearms", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        timeProvider.Advance(TimeSpan.FromSeconds(15));

        using(PooledMemory tooLate = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, tooLate.AsReadOnlySpan()[0]);
        }

        simulator.PowerCycle();

        using PooledMemory afterPowerCycle = await SendResetAsync(simulator, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, afterPowerCycle.AsReadOnlySpan()[0], "a power cycle re-arms the 10-second power-up window.");
    }


    /// <summary>
    /// A SUCCESSFUL reset does NOT restamp <see cref="CtapAuthenticatorState.PoweredOnAt"/>: a reset at 5
    /// seconds succeeds, but a second reset once total elapsed time since the ORIGINAL power-on exceeds
    /// 10 seconds fails — a reset is not itself a power-up.
    /// </summary>
    [TestMethod]
    public async Task SuccessfulResetDoesNotReArmWindow()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-success-no-rearm", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        timeProvider.Advance(TimeSpan.FromSeconds(5));

        using(PooledMemory first = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        timeProvider.Advance(TimeSpan.FromSeconds(6));

        using PooledMemory second = await SendResetAsync(simulator, pool, TestContext.CancellationToken);

        Assert.AreEqual(
            WellKnownCtapStatusCodes.NotAllowed, second.AsReadOnlySpan()[0],
            "total elapsed time since the original power-on is now 11 seconds; a successful reset must not have restamped PoweredOnAt.");
    }


    /// <summary>
    /// <see cref="CtapAuthenticatorState.FactoryReset"/>'s exact clear/keep field set, mirroring
    /// <see cref="CtapAuthenticatorPowerCycleTests"/>'s own field-by-field shape: every field the R1
    /// clear table names reverts to its factory value, and every kept field (identity/personalization/boot
    /// facts, plus both PIN/UV auth protocols' key-agreement key pairs and tokens — the effectful
    /// executor's own business, not this pure transform's) survives unchanged. Also proves contract R2's
    /// FactoryReset-disposes half: both records' <see cref="CtapCredentialRecord.CredRandomWithUV"/>/
    /// <see cref="CtapCredentialRecord.CredRandomWithoutUV"/> are rented from a
    /// <see cref="ZeroOnDisposeTrackingMemoryPool"/> at their exact 32-byte length, so the credential-store
    /// walk's own <see cref="CtapCredentialRecord.Dispose"/> call disposing all four is observable through
    /// the existing pool seam, without any test-only hook.
    /// </summary>
    [TestMethod]
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Ownership of the credential ID/user handle/private key carriers, the stored-PIN digest, both bio-enrollment template identifiers, and the grown large-blob array transfers to `before`; `before.FactoryReset(pool)` disposes every one of them as part of its own credential-store/template-store/stored-PIN/large-blob-array walk.")]
    public async Task FactoryResetRevertsEveryClearFieldAndPreservesEveryKeepField()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        DateTimeOffset poweredOnAt = TestClock.CanonicalEpoch;
        DigestValue storedPin = BuildFixedDigest(0x88, 16, pool);
        DigestValue rememberedClientDataHash = BuildFixedDigest(0xA5, 32, pool);

        using var credRandomTrackingPool = new ZeroOnDisposeTrackingMemoryPool(32);

        CtapCredentialSigningBackend backend = CtapCredentialSigningBackend.CreateEs256Default();
        CtapCredentialKeyPair discoverableKeyPair = await backend.GenerateCredentialKeyPair(WellKnownCoseAlgorithms.Es256, pool, TestContext.CancellationToken);
        CredentialId discoverableCredentialId = CredentialId.Create(BuildFixedBytes(16, 0x50), pool);
        UserHandle discoverableUserId = UserHandle.Create(BuildFixedBytes(16, 0x51), pool);
        CtapCredentialRecord discoverableRecord = new(
            discoverableCredentialId, "example.com", discoverableUserId, "alice", "Alice Example", WellKnownCoseAlgorithms.Es256,
            IsResident: true, discoverableKeyPair.PrivateKey, SignCount: 0, CreationSequence: 0, PublicKey: discoverableKeyPair.PublicKey, CredProtectLevel: 1,
            CredRandomWithUV: credRandomTrackingPool.Rent(32), CredRandomWithoutUV: credRandomTrackingPool.Rent(32));

        CtapCredentialKeyPair nonDiscoverableKeyPair = await backend.GenerateCredentialKeyPair(WellKnownCoseAlgorithms.Es256, pool, TestContext.CancellationToken);
        CredentialId nonDiscoverableCredentialId = CredentialId.Create(BuildFixedBytes(16, 0x52), pool);
        UserHandle nonDiscoverableUserId = UserHandle.Create(BuildFixedBytes(16, 0x53), pool);
        CtapCredentialRecord nonDiscoverableRecord = new(
            nonDiscoverableCredentialId, "example.com", nonDiscoverableUserId, "bob", "Bob Example", WellKnownCoseAlgorithms.Es256,
            IsResident: false, nonDiscoverableKeyPair.PrivateKey, SignCount: 0, CreationSequence: 1, PublicKey: nonDiscoverableKeyPair.PublicKey, CredProtectLevel: 1,
            CredRandomWithUV: credRandomTrackingPool.Rent(32), CredRandomWithoutUV: credRandomTrackingPool.Rent(32));

        ImmutableDictionary<string, CtapCredentialRecord> populatedStore = ImmutableDictionary<string, CtapCredentialRecord>.Empty
            .Add(Convert.ToHexStringLower(discoverableCredentialId.AsReadOnlySpan()), discoverableRecord)
            .Add(Convert.ToHexStringLower(nonDiscoverableCredentialId.AsReadOnlySpan()), nonDiscoverableRecord);

        var rememberedGetAssertion = new CtapRememberedGetAssertionState(
            [discoverableCredentialId], rememberedClientDataHash, true, true, 1, poweredOnAt, CtapPinUvAuthProtocolId.Two, LargeBlobKeyRequested: false);
        var rememberedEnumerateRps = new CtapRememberedEnumerateRpsState(["example.com"], 1, poweredOnAt, CtapPinUvAuthProtocolId.Two);
        var rememberedEnumerateCredentials = new CtapRememberedEnumerateCredentialsState([discoverableCredentialId], 1, poweredOnAt, CtapPinUvAuthProtocolId.Two);

        BioEnrollmentTemplateId provisionedTemplateId = BioEnrollmentTemplateId.Create(BuildFixedBytes(16, 0x54), pool);
        var provisionedTemplateRecord = new CtapBioEnrollmentTemplateRecord(provisionedTemplateId, FriendlyName: "left thumb");
        ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord> populatedTemplateStore = ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord>.Empty
            .Add(Convert.ToHexStringLower(provisionedTemplateId.AsReadOnlySpan()), provisionedTemplateRecord);
        BioEnrollmentTemplateId inProgressTemplateId = BioEnrollmentTemplateId.Create(BuildFixedBytes(16, 0x55), pool);
        var rememberedBioEnrollment = new CtapRememberedBioEnrollmentState(inProgressTemplateId, RemainingSamples: 2);

        CtapAuthenticatorState initial = CtapAuthenticatorState.Initial(
            aaguid, poweredOnAt, supportedExtensions: ["hmac-secret"], residentCredentialCapacity: 5, keyAgreementPool: pool);
        initial.SerializedLargeBlobArray.Dispose();
        PooledMemory grownLargeBlobArray = PooledMemory.FromBytes(BuildFixedBytes(40, 0x60), pool, Fido2BufferTags.CtapSerializedLargeBlobArrayPayload);

        CtapAuthenticatorState before = initial with
        {
            CredentialsByCredentialId = populatedStore,
            NextCredentialSequence = 2,
            RememberedGetAssertion = rememberedGetAssertion,
            RememberedEnumerateRps = rememberedEnumerateRps,
            RememberedEnumerateCredentials = rememberedEnumerateCredentials,
            CurrentStoredPin = storedPin,
            PinCodePointLength = 6,
            PinRetries = 3,
            UvRetries = 5,
            ConsecutivePinMismatches = 2,
            IsPowerCycleRequired = true,
            IsAlwaysUvEnabled = true,
            MinPinCodePointLength = 6,
            IsForcePinChangeRequired = true,
            MinPinLengthRpIds = ["example.com"],
            BioEnrollmentTemplatesByTemplateId = populatedTemplateStore,
            RememberedBioEnrollment = rememberedBioEnrollment,
            SerializedLargeBlobArray = grownLargeBlobArray
        };

        byte[] protocolOneKeyBefore = before.ProtocolOneKeyAgreementKeyPair.PublicKey.AsReadOnlySpan().ToArray();
        byte[] protocolTwoKeyBefore = before.ProtocolTwoKeyAgreementKeyPair.PublicKey.AsReadOnlySpan().ToArray();
        byte[] protocolOneTokenBefore = before.ProtocolOneToken.Token.AsReadOnlySpan().ToArray();
        byte[] protocolTwoTokenBefore = before.ProtocolTwoToken.Token.AsReadOnlySpan().ToArray();

        CtapAuthenticatorState after = before.FactoryReset(pool);

        Assert.IsEmpty(after.CredentialsByCredentialId, "bullets 6332/6334: one clearing invalidates and erases every credential.");
        Assert.AreEqual(
            4, credRandomTrackingPool.TrackedDisposalCount,
            "contract R2: the credential-store walk's per-record Dispose() must dispose both CredRandomWithUV and CredRandomWithoutUV for each of the two records.");
        Assert.AreEqual(0UL, after.NextCredentialSequence);
        Assert.IsNull(after.RememberedGetAssertion);
        Assert.IsNull(after.RememberedEnumerateRps);
        Assert.IsNull(after.RememberedEnumerateCredentials);
        Assert.IsNull(after.CurrentStoredPin);
        Assert.AreEqual(0, after.PinCodePointLength);
        Assert.AreEqual(CtapAuthenticatorState.MaxPinRetries, after.PinRetries, "line 5078: reset is the PIN lockout's sole spec-named recovery.");
        Assert.AreEqual(CtapAuthenticatorState.MaxPinRetries, after.UvRetries, "lines 5092-5093: reset is one of two spec-named recoveries for the uvRetries lockout.");
        Assert.AreEqual(0, after.ConsecutivePinMismatches);
        Assert.IsFalse(after.IsPowerCycleRequired);
        Assert.IsFalse(after.IsAlwaysUvEnabled, "§7.2.3, lines 8318-8323.");
        Assert.AreEqual(CtapAuthenticatorState.DefaultMinPinCodePointLength, after.MinPinCodePointLength, "§7.4.3 lines 8419-8422; line 4465.");
        Assert.IsFalse(after.IsForcePinChangeRequired, "§7.4.3, line 8426.");
        Assert.IsEmpty(after.MinPinLengthRpIds, "§7.4.3, line 8424: previously added RP IDs are removed on reset.");
        Assert.IsEmpty(after.BioEnrollmentTemplatesByTemplateId, "R13: a documented profile-security posture over §6.6's own silence on bio enrollment (bio scout Finding 8) — every provisioned template is disposed and erased.");
        Assert.IsFalse(after.HasProvisionedBioEnrollments, "post-reset bioEnroll/uv must derive false from the now-empty template store.");
        Assert.IsNull(after.RememberedBioEnrollment, "R13: the fourth remembered-sequence slot is discarded by a factory reset, joining the other three.");

        ReadOnlySpan<byte> initialLargeBlobArray = CtapAuthenticatorState.InitialSerializedLargeBlobArray;
        Assert.AreEqual(initialLargeBlobArray.Length, after.SerializedLargeBlobArray.Length, "line 7541: the initial serialized large-blob array is 17 bytes.");
        Assert.AreSequenceEqual(
            initialLargeBlobArray.ToArray(), after.SerializedLargeBlobArray.AsReadOnlySpan().ToArray(),
            "line 7705's MUST + line 6336: FactoryReset restores the initial serialized large-blob array byte string, byte-exact, even though `before` carried a grown (40-byte) array.");

        Assert.AreEqual(aaguid, after.Aaguid, "the AAGUID is model identity, never named in the factory-default-state bullet list.");
        Assert.AreSame(before.SupportedExtensions, after.SupportedExtensions);
        Assert.AreEqual(5, after.ResidentCredentialCapacity);
        Assert.AreEqual(poweredOnAt, after.PoweredOnAt, "a reset is not itself a power-up; the power-up window does not re-arm.");

        Assert.AreSame(
            before.ProtocolOneKeyAgreementKeyPair, after.ProtocolOneKeyAgreementKeyPair,
            "key-agreement regeneration is the effectful executor's business, not FactoryReset's own pure clear.");
        Assert.AreSame(before.ProtocolTwoKeyAgreementKeyPair, after.ProtocolTwoKeyAgreementKeyPair);
        Assert.AreSame(before.ProtocolOneToken, after.ProtocolOneToken);
        Assert.AreSame(before.ProtocolTwoToken, after.ProtocolTwoToken);
        Assert.AreSequenceEqual(protocolOneKeyBefore, after.ProtocolOneKeyAgreementKeyPair.PublicKey.AsReadOnlySpan().ToArray());
        Assert.AreSequenceEqual(protocolTwoKeyBefore, after.ProtocolTwoKeyAgreementKeyPair.PublicKey.AsReadOnlySpan().ToArray());
        Assert.AreSequenceEqual(protocolOneTokenBefore, after.ProtocolOneToken.Token.AsReadOnlySpan().ToArray());
        Assert.AreSequenceEqual(protocolTwoTokenBefore, after.ProtocolTwoToken.Token.AsReadOnlySpan().ToArray());

        after.ProtocolOneKeyAgreementKeyPair.Dispose();
        after.ProtocolTwoKeyAgreementKeyPair.Dispose();
        after.ProtocolOneToken.Dispose();
        after.ProtocolTwoToken.Dispose();
        after.SerializedLargeBlobArray.Dispose();
    }


    /// <summary>
    /// A factory reset flips <see cref="CtapAuthenticatorState.IsEnterpriseAttestationEnabled"/> to
    /// <see langword="false"/> (CTAP 2.3 §7.1.3, lines 8276-8278: "MUST disable the enterprise
    /// attestation feature") while PRESERVING <see cref="CtapAuthenticatorState.EnterpriseAttestationProvisioning"/>
    /// completely unchanged — the SAME reference, never disposed or re-minted (line 8256: the vendor's
    /// material is "burned into" the authenticator; a reset disables the FEATURE, never the underlying
    /// capability). <see cref="CtapAuthenticatorState.IsEnterpriseAttestationCapable"/> stays
    /// <see langword="true"/> throughout, proving trap 9's own preserve/disable distinction.
    /// </summary>
    [TestMethod]
    public void FactoryResetDisablesEnterpriseAttestationButPreservesProvisioningRecord()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        DateTimeOffset poweredOnAt = TestClock.CanonicalEpoch;
        CtapEnterpriseAttestationProvisioning provisioning = CtapWaveEpFixtures.BuildProvisioning(pool);

        CtapAuthenticatorState before = CtapAuthenticatorState.Initial(
            aaguid, poweredOnAt, keyAgreementPool: pool, enterpriseAttestationProvisioning: provisioning) with
        {
            IsEnterpriseAttestationEnabled = true
        };

        CtapAuthenticatorState after = before.FactoryReset(pool);

        Assert.IsTrue(after.IsEnterpriseAttestationCapable, "the vendor-burned-in capability survives a factory reset.");
        Assert.AreSame(provisioning, after.EnterpriseAttestationProvisioning, "the provisioning record must survive a factory reset unchanged, never disposed or re-minted.");
        Assert.IsFalse(after.IsEnterpriseAttestationEnabled, "a factory reset must disable the enterprise attestation feature.");

        after.ProtocolOneKeyAgreementKeyPair.Dispose();
        after.ProtocolTwoKeyAgreementKeyPair.Dispose();
        after.ProtocolOneToken.Dispose();
        after.ProtocolTwoToken.Dispose();
        after.SerializedLargeBlobArray.Dispose();
        provisioning.Dispose();
    }


    /// <summary>A reset on a factory-fresh simulator (no PIN, empty store) succeeds.</summary>
    [TestMethod]
    public async Task ResetOnFactoryFreshSimulatorSucceeds()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-factory-fresh");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        using PooledMemory response = await SendResetAsync(simulator, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);
    }


    /// <summary>Two resets both issued within the ORIGINAL power-up window each succeed independently.</summary>
    [TestMethod]
    public async Task DoubleResetWithinWindowSucceedsTwice()
    {
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-double-within-window", timeProvider: timeProvider);
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        timeProvider.Advance(TimeSpan.FromSeconds(3));
        using(PooledMemory first = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        timeProvider.Advance(TimeSpan.FromSeconds(3));
        using PooledMemory second = await SendResetAsync(simulator, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, second.AsReadOnlySpan()[0], "both resets remain within 10 seconds of the ORIGINAL power-on.");
    }


    /// <summary>
    /// Post-reset <c>getInfo</c> bytes are BYTE-IDENTICAL to the same simulator's birth <c>getInfo</c>
    /// bytes (R8), captured before <c>setPIN</c>, <c>toggleAlwaysUv</c>, and a credential registration
    /// drove every state-derived getInfo member away from its factory value.
    /// </summary>
    [TestMethod]
    public async Task PostResetGetInfoBytesEqualBirthGetInfoBytes()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-birth-getinfo");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        byte[] getInfoRequest = [WellKnownCtapCommands.GetInfo];

        byte[] birthBytes;
        using(PooledMemory birth = await simulator.TransceiveAsync(getInfoRequest, pool, TestContext.CancellationToken))
        {
            birthBytes = birth.AsReadOnlySpan().ToArray();
        }

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        _ = await RegisterResidentCredentialWithTokenAsync(simulator, pool, protocolId, BuildFixedBytes(16, 0xE5), TestContext.CancellationToken);

        //Only ONE pinUvAuthToken can be live per protocol at a time: this Acfg token is issued AFTER the
        //registration above's own single-purpose token is already spent, so it remains the LIVE token
        //for the toggle below.
        byte[] acfgToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Acfg, rpId: null, TestContext.CancellationToken);

        byte[] toggleMessage = CtapWaveConfigFixtures.BuildMessage(WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, ReadOnlyMemory<byte>.Empty);
        byte[] toggleParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(acfgToken, protocolId, toggleMessage, pool, TestContext.CancellationToken);
        var toggleRequest = new CtapAuthenticatorConfigRequest(
            SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.ToggleAlwaysUv, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: toggleParam);
        using(PooledMemory toggleResponse = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, toggleRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, toggleResponse.AsReadOnlySpan()[0]);
        }

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        using PooledMemory postReset = await simulator.TransceiveAsync(getInfoRequest, pool, TestContext.CancellationToken);

        Assert.AreSequenceEqual(birthBytes, postReset.AsReadOnlySpan().ToArray());
    }


    /// <summary>Post-reset <c>getPINRetries</c> shows the maximum, even though a wrong-PIN attempt had dropped it beforehand.</summary>
    [TestMethod]
    public async Task PostResetGetPinRetriesShowsMaximum()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-getretries-max");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        using(CtapWave5bPlatformPinSession mismatchSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
            simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken))
        {
            byte[] wrongPinHashEnc = await mismatchSession.BuildWrongPinHashEncAsync(TestContext.CancellationToken);
            var mismatchRequest = new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
                KeyAgreement: mismatchSession.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);
            _ = await SendClientPinExpectingErrorAsync(simulator, mismatchRequest, pool, TestContext.CancellationToken);
        }

        Assert.AreEqual(7, await GetPinRetriesAsync(simulator, pool, TestContext.CancellationToken));

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        Assert.AreEqual(CtapAuthenticatorState.MaxPinRetries, await GetPinRetriesAsync(simulator, pool, TestContext.CancellationToken));
    }


    /// <summary><c>getKeyAgreement</c> returns a DIFFERENT COSE key after a successful reset, proving key-agreement key-pair regeneration.</summary>
    [TestMethod]
    public async Task PostResetGetKeyAgreementDiffersFromPreResetCapture()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-keyagreement-differs");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        CoseKey keyBefore = await GetKeyAgreementAsync(simulator, protocolId, pool, TestContext.CancellationToken);

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        CoseKey keyAfter = await GetKeyAgreementAsync(simulator, protocolId, pool, TestContext.CancellationToken);

        Assert.IsFalse(keyBefore.X!.Value.Span.SequenceEqual(keyAfter.X!.Value.Span));
    }


    /// <summary>
    /// A <c>pinUvAuthToken</c> issued BEFORE a reset fails to authenticate a post-reset
    /// <c>authenticatorMakeCredential</c> with <c>CTAP2_ERR_PIN_AUTH_INVALID</c> — line 6138's "generated
    /// afresh ... at reset" observed on the wire.
    /// </summary>
    [TestMethod]
    public async Task PreResetPinUvAuthTokenOnMakeCredentialPostResetReturnsPinAuthInvalid()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-stale-token-mc");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] staleToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Mc, rpId: DefaultRpId, TestContext.CancellationToken);

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        byte[] clientDataHashBytes = BuildFixedBytes(32, 0x10);
        byte[] staleParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(staleToken, protocolId, clientDataHashBytes, pool, TestContext.CancellationToken);
        CtapMakeCredentialRequest mcRequest = BuildMakeCredentialRequest(pool, pinUvAuthParam: staleParam, pinUvAuthProtocol: (int)protocolId);
        using PooledMemory mcResponse = await SendMakeCredentialAsync(simulator, mcRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthInvalid, mcResponse.AsReadOnlySpan()[0]);
    }


    /// <summary>An <c>authenticatorGetAssertion</c> <c>allowList</c> naming a credential minted BEFORE a reset resolves to no credentials afterward.</summary>
    [TestMethod]
    public async Task GetAssertionAllowListNamingPreResetCredentialReturnsNoCredentials()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-stale-credential-ga");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        byte[] credentialIdBytes = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xD0), TestContext.CancellationToken);

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        CredentialId credentialId = CredentialId.Create(credentialIdBytes, pool);
        CtapGetAssertionRequest request = BuildGetAssertionRequest(
            pool, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId }]);
        using PooledMemory response = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, response.AsReadOnlySpan()[0]);
    }


    /// <summary>A cold <c>authenticatorGetNextAssertion</c> issued after a reset returns <c>CTAP2_ERR_NOT_ALLOWED</c>: a live multi-account sequence does not survive.</summary>
    [TestMethod]
    public async Task ColdGetNextAssertionPostResetReturnsNotAllowed()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-cold-gna");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xD1), TestContext.CancellationToken);
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xD2), TestContext.CancellationToken);

        CtapGetAssertionRequest request = BuildGetAssertionRequest(pool);
        using(PooledMemory first = await SendGetAssertionAsync(simulator, request, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, first.AsReadOnlySpan()[0]);
        }

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        using PooledMemory response = await SendGetNextAssertionAsync(simulator, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, response.AsReadOnlySpan()[0]);
    }


    /// <summary>An <c>enumerateRPsGetNextRP</c> issued after a reset returns <c>CTAP2_ERR_NOT_ALLOWED</c>: a live cm enumeration sequence does not survive.</summary>
    [TestMethod]
    public async Task CredentialManagementGetNextRpPostResetReturnsNotAllowed()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-cold-cm-getnext");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xD3), TestContext.CancellationToken, rpId: "rp-a.example");
        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xD4), TestContext.CancellationToken, rpId: "rp-b.example");

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
        byte[] cmToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Cm, rpId: null, TestContext.CancellationToken);

        using(PooledMemory begin = await SendGatedCmRequestAsync(
            simulator, cmToken, protocolId, WellKnownCtapCredentialManagementSubCommands.EnumerateRpsBegin, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, begin.AsReadOnlySpan()[0]);
        }

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        var nextRequest = new CtapCredentialManagementRequest(SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateRpsGetNextRp);
        using PooledMemory nextResponse = await CtapWaveCmFixtures.SendCredentialManagementAsync(simulator, nextRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, nextResponse.AsReadOnlySpan()[0]);
    }


    /// <summary><c>setPIN</c> succeeds fresh with a 4-code-point PIN after a reset, proving <c>minPINLength</c> reverted from a raised value (line 4465).</summary>
    [TestMethod]
    public async Task SetPinSucceedsFreshWithFourCodePointPinAfterMinPinLengthReverts()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-minpin-reverts");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        var raiseRequest = new CtapAuthenticatorConfigRequest(SubCommand: WellKnownCtapAuthenticatorConfigSubCommands.SetMinPinLength, NewMinPinLength: 6);
        using(PooledMemory raiseResponse = await CtapWaveConfigFixtures.SendAuthenticatorConfigAsync(simulator, raiseRequest, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, raiseResponse.AsReadOnlySpan()[0]);
        }

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        CtapGetInfoResponse info = await CtapWaveConfigFixtures.GetInfoAsync(simulator, pool, TestContext.CancellationToken);
        Assert.IsTrue(info.Options!.ClientPin);
    }


    /// <summary><c>authenticatorMakeCredential</c> and <c>authenticatorGetAssertion</c> both complete factory-fresh once a credential is re-registered after a reset.</summary>
    [TestMethod]
    public async Task MakeCredentialAndGetAssertionSucceedFactoryFreshAfterReset()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-factory-fresh-mcga");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        _ = await RegisterAndCaptureCredentialIdBytesAsync(simulator, pool, BuildFixedBytes(16, 0xE6), TestContext.CancellationToken);

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        CtapWave2RegisteredCredential registered = await RegisterCredentialAsync(simulator, pool, BuildFixedBytes(16, 0xE7), TestContext.CancellationToken);

        CtapGetAssertionRequest gaRequest = BuildGetAssertionRequest(
            pool, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = registered.CredentialId }]);
        using PooledMemory gaResponse = await SendGetAssertionAsync(simulator, gaRequest, pool, TestContext.CancellationToken);

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, gaResponse.AsReadOnlySpan()[0]);
    }


    /// <summary>
    /// A reset recovers from a full <c>pinRetries</c> exhaustion (<c>PinBlocked</c>), interleaving the
    /// required power cycles through the consecutive-mismatch latch exactly as the wave-5b retries-matrix
    /// tests do — line 5078's own promise: clientPIN "can only be enabled if the authenticator is reset".
    /// </summary>
    [TestMethod]
    public async Task ResetRecoversFromPinBlockedLockout()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-recovers-pinblocked");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        for(int attempt = 0; attempt < 8; attempt++)
        {
            using CtapWave5bPlatformPinSession mismatchSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
                simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
            byte[] wrongPinHashEnc = await mismatchSession.BuildWrongPinHashEncAsync(TestContext.CancellationToken);
            var mismatchRequest = new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
                KeyAgreement: mismatchSession.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);
            byte statusCode = await SendClientPinExpectingErrorAsync(simulator, mismatchRequest, pool, TestContext.CancellationToken);

            if(statusCode == WellKnownCtapStatusCodes.PinAuthBlocked)
            {
                simulator.PowerCycle();
            }
        }

        Assert.AreEqual(0, await GetPinRetriesAsync(simulator, pool, TestContext.CancellationToken));

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0]);
        }

        Assert.AreEqual(
            CtapAuthenticatorState.MaxPinRetries, await GetPinRetriesAsync(simulator, pool, TestContext.CancellationToken),
            "line 5078: a reset re-enables clientPIN once pinRetries had reached 0.");

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);
    }


    /// <summary>A reset succeeds WHILE the power-cycle-required latch is set (the latch does not gate reset) and clears the latch.</summary>
    [TestMethod]
    public async Task ResetSucceedsWhilePowerCycleRequiredAndClearsIt()
    {
        using CtapAuthenticatorSimulator simulator = CreateSimulator("reset-clears-powercycle-latch");
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CtapPinUvAuthProtocolId protocolId = CtapPinUvAuthProtocolId.Two;

        await CtapWaveConfigFixtures.EstablishPinAsync(simulator, pool, protocolId, DefaultPin, TestContext.CancellationToken);

        byte statusCode = WellKnownCtapStatusCodes.Ok;
        for(int attempt = 0; attempt < 3 && statusCode != WellKnownCtapStatusCodes.PinAuthBlocked; attempt++)
        {
            using CtapWave5bPlatformPinSession mismatchSession = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(
                simulator.TransceiveAsync, protocolId, pool, TestContext.CancellationToken);
            byte[] wrongPinHashEnc = await mismatchSession.BuildWrongPinHashEncAsync(TestContext.CancellationToken);
            var mismatchRequest = new CtapClientPinRequest(
                SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
                KeyAgreement: mismatchSession.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);
            statusCode = await SendClientPinExpectingErrorAsync(simulator, mismatchRequest, pool, TestContext.CancellationToken);
        }

        Assert.AreEqual(WellKnownCtapStatusCodes.PinAuthBlocked, statusCode, "three consecutive mismatches must latch the power-cycle-recoverable lockout.");
        Assert.IsTrue(await GetPowerCycleRequiredAsync(simulator, pool, TestContext.CancellationToken));

        using(PooledMemory resetResponse = await SendResetAsync(simulator, pool, TestContext.CancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0], "the power-cycle-required latch does not gate authenticatorReset.");
        }

        Assert.IsFalse(await GetPowerCycleRequiredAsync(simulator, pool, TestContext.CancellationToken));
    }


    /// <summary>Sends a bare <c>authenticatorReset</c> request, returning the raw response envelope.</summary>
    private static ValueTask<PooledMemory> SendResetAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.Reset];

        return simulator.TransceiveAsync(request, pool, cancellationToken);
    }


    /// <summary>
    /// Registers one discoverable (<c>rk</c>) credential for <paramref name="userId"/>, driven by a
    /// freshly issued single-use <c>mc</c>-permissioned token: once a PIN is set, resident-credential
    /// creation requires a <c>pinUvAuthToken</c> regardless of <c>alwaysUv</c>
    /// (<c>MakeCredential:ResidentKeyRequiresPinUvAuthToken</c>), and a successful <c>mc</c> strips the
    /// token it consumes of every permission but <c>lbw</c>, so each registration needs its own token.
    /// </summary>
    private static async Task<byte[]> RegisterResidentCredentialWithTokenAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, byte[] userId, CancellationToken cancellationToken)
    {
        byte[] mcToken = await CtapWaveConfigFixtures.IssueTokenAsync(
            simulator, pool, protocolId, DefaultPin, WellKnownCtapPinUvAuthTokenPermissions.Mc, rpId: DefaultRpId, cancellationToken);
        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(mcToken, protocolId, BuildFixedBytes(32, 0x10), pool, cancellationToken);

        CtapMakeCredentialRequest request = BuildMakeCredentialRequest(
            pool, userId: userId, options: new CtapCommandOptions(ResidentKey: true), pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)protocolId);
        using PooledMemory response = await SendMakeCredentialAsync(simulator, request, pool, cancellationToken);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, response.AsReadOnlySpan()[0]);

        CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);

        return authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
    }


    /// <summary>Computes the platform-side <c>pinUvAuthParam</c> and sends one gated credMgmt subcommand carrying no <c>subCommandParams</c> (e.g. <c>enumerateRPsBegin</c>).</summary>
    private static async Task<PooledMemory> SendGatedCmRequestAsync(
        CtapAuthenticatorSimulator simulator, byte[] token, CtapPinUvAuthProtocolId protocolId, int subCommand, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] message = CtapWaveCmFixtures.BuildMessage(subCommand, ReadOnlyMemory<byte>.Empty);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, protocolId, message, pool, cancellationToken);

        var request = new CtapCredentialManagementRequest(SubCommand: subCommand, PinUvAuthProtocol: (int)protocolId, PinUvAuthParam: param);

        return await CtapWaveCmFixtures.SendCredentialManagementAsync(simulator, request, pool, cancellationToken);
    }


    /// <summary>Reads the current <c>pinRetries</c> value via <c>getPINRetries</c>.</summary>
    private static async Task<int> GetPinRetriesAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return response.PinRetries!.Value;
    }


    /// <summary>Reads the current power-cycle-required latch via <c>getPINRetries</c>'s own <c>powerCycleState</c> member.</summary>
    private static async Task<bool> GetPowerCycleRequiredAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return response.PowerCycleState!.Value;
    }


    /// <summary>Reads a protocol's current key-agreement public key via <c>getKeyAgreement</c>.</summary>
    private static async Task<CoseKey> GetKeyAgreementAsync(
        CtapAuthenticatorSimulator simulator, CtapPinUvAuthProtocolId protocolId, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)protocolId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return response.KeyAgreement!;
    }


    /// <summary>Sends an <c>authenticatorClientPIN</c> request expected to fail and returns the CTAP2 status code it failed with.</summary>
    private static async Task<byte> SendClientPinExpectingErrorAsync(
        CtapAuthenticatorSimulator simulator, CtapClientPinRequest request, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).AsTask());

        return exception.StatusCode;
    }


    /// <summary>Builds a fixed-content <see cref="DigestValue"/> standing in for a stored PIN hash or a remembered client data hash, without a full command round trip.</summary>
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
