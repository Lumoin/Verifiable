using System;
using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Cryptography;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Fido2.Ctap.Authenticator.Custody;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;
using static Verifiable.Tests.TestInfrastructure.CtapWave2AuthenticatorFixtures;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// Tests for the wavect CTAP authenticator state-custody seam (contract R-1 through R-5): the versioned
/// CBOR snapshot codec's round-trip and fail-closed fidelity, the volatile/persistent boundary the
/// codec enforces by construction, and an in-process "process death and rehydration" proof driven through
/// <see cref="CtapAuthenticatorSimulator"/>'s public API via a dictionary-backed
/// <see cref="CtapStateCustody"/> bundle.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorStateCustodyTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// A serialize-then-parse round trip preserves every persistent field (contract R-2) on a state whose
    /// persistent subset is maximally populated: a resident credential with a non-default sign count,
    /// creation sequence, credProtect level, both CredRandom halves, and a largeBlobKey; a non-empty bio
    /// enrollment template; a non-initial serialized large-blob array; and every clientPIN/config field at
    /// a non-default value.
    /// </summary>
    [TestMethod]
    public async Task SerializeParseRoundTripPreservesEveryMaximallyPopulatedPersistentField()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        (CtapAuthenticatorState state, CtapCredentialRecord credential, CtapBioEnrollmentTemplateRecord bioTemplate) =
            await BuildMaximallyPopulatedStateAsync(pool, TestContext.CancellationToken);

        try
        {
            using PooledMemory encoded = CtapAuthenticatorSnapshotCborWriter.Write(state, pool);
            CtapAuthenticatorSnapshot decoded = CtapAuthenticatorSnapshotCborReader.Read(encoded.AsReadOnlyMemory(), pool);

            try
            {
                Assert.AreEqual((int)CtapAuthenticatorSnapshotFormat.CurrentVersion, decoded.FormatVersion);
                Assert.AreEqual(state.Aaguid, decoded.Aaguid);
                Assert.AreEqual(state.FirmwareVersion, decoded.FirmwareVersion);
                Assert.AreEqual(state.NextCredentialSequence, decoded.NextCredentialSequence);
                Assert.IsTrue(state.CurrentStoredPin!.AsReadOnlySpan().SequenceEqual(decoded.CurrentStoredPin!.AsReadOnlySpan()), "CurrentStoredPin bytes must round-trip exactly.");
                Assert.AreEqual(state.PinCodePointLength, decoded.PinCodePointLength);
                Assert.AreEqual(state.PinRetries, decoded.PinRetries);
                Assert.AreEqual(state.UvRetries, decoded.UvRetries);
                Assert.AreEqual(state.IsForcePinChangeRequired, decoded.IsForcePinChangeRequired);
                Assert.AreEqual(state.MinPinCodePointLength, decoded.MinPinCodePointLength);
                Assert.AreSequenceEqual((string[])[.. state.MinPinLengthRpIds], (string[])[.. decoded.MinPinLengthRpIds]);
                Assert.AreEqual(state.IsAlwaysUvEnabled, decoded.IsAlwaysUvEnabled);
                Assert.AreEqual(state.IsEnterpriseAttestationEnabled, decoded.IsEnterpriseAttestationEnabled);
                Assert.IsTrue(
                    state.SerializedLargeBlobArray.AsReadOnlySpan().SequenceEqual(decoded.SerializedLargeBlobArray.AsReadOnlySpan()),
                    "The serialized large-blob array must round-trip exactly, including its non-initial content.");

                Assert.HasCount(1, decoded.CredentialsByCredentialId);
                CtapCredentialRecord decodedCredential = decoded.CredentialsByCredentialId[Convert.ToHexStringLower(credential.CredentialId.AsReadOnlySpan())];
                Assert.IsTrue(credential.CredentialId.AsReadOnlySpan().SequenceEqual(decodedCredential.CredentialId.AsReadOnlySpan()));
                Assert.AreEqual(credential.RpId, decodedCredential.RpId);
                Assert.IsTrue(credential.UserId.AsReadOnlySpan().SequenceEqual(decodedCredential.UserId.AsReadOnlySpan()));
                Assert.AreEqual(credential.UserName, decodedCredential.UserName);
                Assert.AreEqual(credential.UserDisplayName, decodedCredential.UserDisplayName);
                Assert.AreEqual(credential.Algorithm, decodedCredential.Algorithm);
                Assert.AreEqual(credential.IsResident, decodedCredential.IsResident);
                Assert.AreEqual(credential.CredentialKey.Id, decodedCredential.CredentialKey.Id);
                Assert.AreEqual(credential.SignCount, decodedCredential.SignCount);
                Assert.AreEqual(credential.CreationSequence, decodedCredential.CreationSequence);
                Assert.AreEqual(credential.PublicKey.Kty, decodedCredential.PublicKey.Kty, "Kty must round-trip.");
                Assert.AreEqual(credential.PublicKey.Alg, decodedCredential.PublicKey.Alg, "Alg must round-trip.");
                Assert.AreEqual(credential.PublicKey.Curve, decodedCredential.PublicKey.Curve, "Curve must round-trip.");
                Assert.AreEqual(credential.PublicKey.EncodedYCompressionSign, decodedCredential.PublicKey.EncodedYCompressionSign, "EncodedYCompressionSign must round-trip.");
                Assert.IsTrue(credential.PublicKey.X!.Value.Span.SequenceEqual(decodedCredential.PublicKey.X!.Value.Span), "X must round-trip.");
                Assert.IsTrue(credential.PublicKey.Y!.Value.Span.SequenceEqual(decodedCredential.PublicKey.Y!.Value.Span), "Y must round-trip.");
                Assert.AreEqual(credential.PublicKey.N is null, decodedCredential.PublicKey.N is null, "N nullability must round-trip.");
                Assert.AreEqual(credential.PublicKey.E is null, decodedCredential.PublicKey.E is null, "E nullability must round-trip.");
                Assert.AreEqual(credential.CredProtectLevel, decodedCredential.CredProtectLevel);
                Assert.IsTrue(credential.CredRandomWithUV.Memory.Span.SequenceEqual(decodedCredential.CredRandomWithUV.Memory.Span));
                Assert.IsTrue(credential.CredRandomWithoutUV.Memory.Span.SequenceEqual(decodedCredential.CredRandomWithoutUV.Memory.Span));
                Assert.IsNotNull(decodedCredential.LargeBlobKey);
                Assert.IsTrue(credential.LargeBlobKey!.Memory.Span.SequenceEqual(decodedCredential.LargeBlobKey!.Memory.Span));
                Assert.IsTrue(
                    credential.CredentialKeyCustodyExport!.AsReadOnlySpan().SequenceEqual(decodedCredential.CredentialKeyCustodyExport!.AsReadOnlySpan()),
                    "The custody-exportable private-key-material copy must round-trip exactly, byte for byte.");

                Assert.HasCount(1, decoded.BioEnrollmentTemplatesByTemplateId);
                CtapBioEnrollmentTemplateRecord decodedTemplate =
                    decoded.BioEnrollmentTemplatesByTemplateId[Convert.ToHexStringLower(bioTemplate.TemplateId.AsReadOnlySpan())];
                Assert.IsTrue(bioTemplate.TemplateId.AsReadOnlySpan().SequenceEqual(decodedTemplate.TemplateId.AsReadOnlySpan()));
                Assert.AreEqual(bioTemplate.FriendlyName, decodedTemplate.FriendlyName);
            }
            finally
            {
                decoded.Dispose();
            }
        }
        finally
        {
            DisposeState(state);
        }
    }


    /// <summary>
    /// An unrecognized leading format-version integer fails closed (contract R-5) before any other field
    /// is parsed, rather than attempting a best-effort parse of bytes it does not understand.
    /// </summary>
    [TestMethod]
    public async Task UnrecognizedFormatVersionFailsClosed()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        var (state, _, _) = await BuildMaximallyPopulatedStateAsync(pool, TestContext.CancellationToken);

        try
        {
            using PooledMemory encoded = CtapAuthenticatorSnapshotCborWriter.Write(state, pool);

            //The snapshot's own leading array header (byte 0) is untouched; the format-version item
            //immediately follows it as a single-byte unsigned integer (0-23 encodes directly in the
            //header byte) — corrupting that one byte to an out-of-range version number is the minimal,
            //targeted mutation this test needs, not a wholesale corruption of the payload.
            byte[] corrupted = encoded.AsReadOnlySpan().ToArray();
            corrupted[1] = 0x17;

            CtapAuthenticatorSnapshotException exception = Assert.ThrowsExactly<CtapAuthenticatorSnapshotException>(
                () => CtapAuthenticatorSnapshotCborReader.Read(corrupted, pool));
            Assert.IsTrue(
                exception.Message.Contains("format version", StringComparison.OrdinalIgnoreCase),
                $"the exception message should name the format-version check; was: '{exception.Message}'.");
        }
        finally
        {
            DisposeState(state);
        }
    }


    /// <summary>
    /// A malformed snapshot whose failure surfaces as a lower-level parse exception (here an out-of-range
    /// integer field that trips a <c>checked</c> cast to <see cref="OverflowException"/>) is still reported
    /// as the documented <see cref="CtapAuthenticatorSnapshotException"/>, not the raw framework type — the
    /// <see cref="DecodeCtapAuthenticatorSnapshotDelegate"/> and <c>CreateWithCustodyAsync</c> contracts
    /// both promise that one type for any malformed snapshot, so a caller catching it recovers rather than
    /// crashing. The wrapped inner exception is preserved for diagnostics.
    /// </summary>
    [TestMethod]
    public void OutOfRangeIntegerFieldFailsClosedAsSnapshotExceptionNotRawOverflow()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;

        //A valid snapshot prefix up to the firmwareVersion field, then firmwareVersion encoded as the
        //maximal 8-byte unsigned value (0x1B followed by eight 0xFF) — which overflows the reader's
        //`checked((int)...)` cast. The reader throws before reading any further field, so no trailing bytes
        //are needed and no pooled carrier has been rented yet.
        byte[] malformed =
        [
            0x90,                                                       //array(16): the top-level snapshot array
            (byte)CtapAuthenticatorSnapshotFormat.CurrentVersion,       //format version (a single-byte unsigned, value < 24)
            0x50,                                                       //byte string(16): the AAGUID
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
            0x1B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF        //firmwareVersion = ulong.MaxValue → OverflowException on the (int) cast
        ];

        CtapAuthenticatorSnapshotException exception = Assert.ThrowsExactly<CtapAuthenticatorSnapshotException>(
            () => CtapAuthenticatorSnapshotCborReader.Read(malformed, pool));
        Assert.IsInstanceOfType<OverflowException>(
            exception.InnerException,
            "the lower-level parse failure must be preserved as the inner exception, proving the wrap fired rather than the value happening to parse.");
    }


    /// <summary>
    /// A snapshot carrying two credential entries with the SAME credential id fails closed rather than
    /// silently letting the second entry overwrite (and orphan the pooled secret carriers of) the first —
    /// the malformed shape a backend-neutral store (contract R-3, no integrity protection required) could
    /// return. The dictionary the running authenticator holds can never carry a duplicate id, which is
    /// exactly why the decoder must reject it at the fold instead of trusting its input.
    /// </summary>
    [TestMethod]
    public async Task DuplicateCredentialIdInSnapshotFailsClosed()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        byte[] sharedIdBytes = BuildFixedBytes(16, 0x5A);
        CtapAuthenticatorState state = await BuildTwoCredentialStateSharingIdAsync(sharedIdBytes, pool, TestContext.CancellationToken);

        try
        {
            //The writer emits each record's own credential id (two colliding entries here); the reader parses
            //BOTH fully before the fold, so a pre-fix reader would overwrite the first with the second and
            //return successfully — leaking the first's carriers. ThrowsExactly proves the fold now rejects it.
            using PooledMemory encoded = CtapAuthenticatorSnapshotCborWriter.Write(state, pool);
            CtapAuthenticatorSnapshotException exception = Assert.ThrowsExactly<CtapAuthenticatorSnapshotException>(
                () => CtapAuthenticatorSnapshotCborReader.Read(encoded.AsReadOnlyMemory(), pool));
            Assert.IsTrue(
                exception.Message.Contains("same credential id", StringComparison.OrdinalIgnoreCase),
                $"the exception should name the duplicate-credential-id rejection; was: '{exception.Message}'.");
        }
        finally
        {
            DisposeState(state);
        }
    }


    /// <summary>
    /// Rehydration fails closed when a loaded snapshot's personalization fingerprint (contract R-2b: AAGUID
    /// and firmware version) does not match the authenticator being composed — never silently
    /// re-personalizing a differently-composed authenticator.
    /// </summary>
    [TestMethod]
    public async Task PersonalizationFingerprintMismatchFailsClosedOnRehydration()
    {
        CancellationToken cancellationToken = TestContext.CancellationToken;
        var store = new DictionaryBackedCtapStateCustodyStore();
        Guid originalAaguid = Guid.NewGuid();
        const string RunId = "custody-fingerprint-mismatch";

        using(CtapAuthenticatorSimulator original = await CreateSimulatorWithCustodyAsync(RunId, store.CreateBundle(), originalAaguid, cancellationToken: cancellationToken))
        {
            //Any state-changing command drives a persist (R-4); toggling alwaysUv via a minted PIN is more
            //machinery than this test needs, so a PIN establishment alone (which sets CurrentStoredPin, a
            //persistent field) is enough to produce a persisted snapshot.
            await EstablishPinDirectAsync(original, BaseMemoryPool.Shared, "1234", CtapPinUvAuthProtocolId.Two);
        }

        Assert.IsTrue(store.HasSnapshot(RunId), "a PIN establishment must have persisted a snapshot.");

        Guid differentAaguid = Guid.NewGuid();
        CtapAuthenticatorSnapshotException exception = await Assert.ThrowsExactlyAsync<CtapAuthenticatorSnapshotException>(() =>
            CreateSimulatorWithCustodyAsync(RunId, store.CreateBundle(), differentAaguid, cancellationToken: cancellationToken).AsTask());
        Assert.IsTrue(
            exception.Message.Contains("fingerprint", StringComparison.OrdinalIgnoreCase),
            $"the exception message should name the fingerprint check; was: '{exception.Message}'.");
    }


    /// <summary>
    /// The FirmwareVersion disjunct of the R-2b fingerprint check fails closed independently of the AAGUID:
    /// a snapshot captured under one firmware version never silently re-personalizes an authenticator
    /// composed under a different firmware version, even when the AAGUID matches. Guards the
    /// <c>snapshot.FirmwareVersion != freshState.FirmwareVersion</c> half of the check that
    /// <see cref="PersonalizationFingerprintMismatchFailsClosedOnRehydration"/> (which varies only the
    /// AAGUID) never exercises.
    /// </summary>
    [TestMethod]
    public async Task PersonalizationFingerprintMismatchOnFirmwareVersionFailsClosedOnRehydration()
    {
        CancellationToken cancellationToken = TestContext.CancellationToken;
        var store = new DictionaryBackedCtapStateCustodyStore();
        Guid aaguid = Guid.NewGuid();
        const string RunId = "custody-firmware-mismatch";
        const int OriginalFirmwareVersion = 1;
        const int DifferentFirmwareVersion = 2;

        using(CtapAuthenticatorSimulator original = await CreateSimulatorWithCustodyAsync(
            RunId, store.CreateBundle(), aaguid, firmwareVersion: OriginalFirmwareVersion, cancellationToken: cancellationToken))
        {
            await EstablishPinDirectAsync(original, BaseMemoryPool.Shared, "1234", CtapPinUvAuthProtocolId.Two);
        }

        Assert.IsTrue(store.HasSnapshot(RunId), "a PIN establishment must have persisted a snapshot.");

        //Same AAGUID, different firmware version: the AAGUID disjunct holds, so only the FirmwareVersion
        //disjunct can reject — proving that half is live.
        CtapAuthenticatorSnapshotException exception = await Assert.ThrowsExactlyAsync<CtapAuthenticatorSnapshotException>(() =>
            CreateSimulatorWithCustodyAsync(RunId, store.CreateBundle(), aaguid, firmwareVersion: DifferentFirmwareVersion, cancellationToken: cancellationToken).AsTask());
        Assert.IsTrue(
            exception.Message.Contains("fingerprint", StringComparison.OrdinalIgnoreCase),
            $"the exception message should name the fingerprint check; was: '{exception.Message}'.");
    }


    /// <summary>
    /// Two states that differ ONLY in their volatile fields (both key-agreement pairs, both
    /// <c>pinUvAuthToken</c>s, every remembered/pending slot, the consecutive-mismatch counter, the
    /// power-cycle latch, and <c>PoweredOnAt</c>) encode to byte-identical snapshots — the direct proof
    /// that none of contract R-2's excluded volatile state ever reaches the wire, since the encoder never
    /// even reads those fields off <see cref="CtapAuthenticatorState"/>.
    /// </summary>
    [TestMethod]
    public void VolatileFieldsNeverInfluenceEncodedBytes()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        Guid aaguid = Guid.NewGuid();
        DateTimeOffset epoch = TestClock.CanonicalEpoch;

        CtapAuthenticatorState baseline = CtapAuthenticatorState.Initial(aaguid, epoch, keyAgreementPool: pool) with
        {
            PinRetries = 3,
            ConsecutivePinMismatches = 0,
            IsPowerCycleRequired = false
        };

        //Everything below differs from `baseline` ONLY in volatile fields: a later PoweredOnAt, a set
        //latch and non-zero mismatch counter, fresh (different) key-agreement material, and a populated
        //remembered enumerate-RPs sequence — none of which R-2 lists as persistent.
        CtapAuthenticatorState mutatedVolatileOnly = baseline.PowerCycle(epoch.AddMinutes(5), pool) with
        {
            ConsecutivePinMismatches = 2,
            IsPowerCycleRequired = true,
            RememberedEnumerateRps = new CtapRememberedEnumerateRpsState(["example.com"], 1, epoch, CtapPinUvAuthProtocolId.Two)
        };

        try
        {
            using PooledMemory baselineEncoded = CtapAuthenticatorSnapshotCborWriter.Write(baseline, pool);
            using PooledMemory mutatedEncoded = CtapAuthenticatorSnapshotCborWriter.Write(mutatedVolatileOnly, pool);

            Assert.IsTrue(
                baselineEncoded.AsReadOnlySpan().SequenceEqual(mutatedEncoded.AsReadOnlySpan()),
                "A snapshot encoding must be byte-identical regardless of any volatile field's value — R-2's excluded fields never reach the wire.");
        }
        finally
        {
            DisposeState(baseline);
            DisposeVolatileOnly(mutatedVolatileOnly);
        }
    }


    /// <summary>
    /// The central capstone: a PIN, a resident credential, and a deliberate wrong-PIN attempt are driven
    /// through simulator instance 1's public API; instance 1 is then disposed (modelling process death) and
    /// instance 2 is constructed from the SAME dictionary-backed custody bundle (modelling a fresh process
    /// rehydrating) — the credential remains locatable and usable (an assertion succeeds, signCount
    /// strictly continues), <c>pinRetries</c> is carried, and rehydration applied PowerCycle's own
    /// volatile-refresh semantics (fresh key-agreement material, the mismatch latch state as a fresh boot
    /// would show it).
    /// </summary>
    [TestMethod]
    public async Task KillAndRehydrateThroughDictionaryBackedCustodyPreservesCredentialAndPinState()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        var store = new DictionaryBackedCtapStateCustodyStore();
        Guid aaguid = Guid.NewGuid();
        const string RunId = "custody-kill-and-rehydrate";
        const string RpId = "custody-capstone.example";
        const string Pin = "1234";

        byte[] credentialIdBytes;
        CoseKey protocolOneKeyAgreementBeforeDeath;
        int pinRetriesAfterMismatch;

        using(CtapAuthenticatorSimulator instanceOne = await CreateSimulatorWithCustodyAsync(RunId, store.CreateBundle(), aaguid, cancellationToken: cancellationToken))
        {
            await EstablishPinDirectAsync(instanceOne, pool, Pin, CtapPinUvAuthProtocolId.Two);

            //Once a PIN is set the authenticator is protected: mc now requires a pinUvAuthParam computed
            //over the SAME clientDataHash bytes BuildMakeCredentialRequest's own fixed 0x10-seeded hash
            //produces internally (CtapWave2AuthenticatorFixtures.BuildFixedClientDataHash's own constant).
            byte[] mcToken = await IssueTokenDirectAsync(instanceOne, pool, CtapPinUvAuthProtocolId.Two, Pin, WellKnownCtapPinUvAuthTokenPermissions.Mc, RpId, cancellationToken);
            byte[] mcPinUvAuthParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(mcToken, CtapPinUvAuthProtocolId.Two, BuildFixedBytes(32, 0x10), pool, cancellationToken);

            CtapMakeCredentialRequest makeCredentialRequest = BuildMakeCredentialRequest(
                pool, rpId: RpId, userId: BuildFixedBytes(16, 0xD0), options: new CtapCommandOptions(ResidentKey: true),
                pinUvAuthParam: mcPinUvAuthParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
            using(PooledMemory makeCredentialResponse = await SendMakeCredentialAsync(instanceOne, makeCredentialRequest, pool, cancellationToken))
            {
                Assert.AreEqual(WellKnownCtapStatusCodes.Ok, makeCredentialResponse.AsReadOnlySpan()[0]);

                CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(makeCredentialResponse.AsReadOnlyMemory()[1..]);
                using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
                credentialIdBytes = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
            }

            await AttemptWrongPinDirectAsync(instanceOne, pool, CtapPinUvAuthProtocolId.Two, cancellationToken);
            pinRetriesAfterMismatch = await GetPinRetriesDirectAsync(instanceOne, pool, cancellationToken);
            Assert.AreEqual(CtapAuthenticatorState.MaxPinRetries - 1, pinRetriesAfterMismatch, "the wrong-PIN attempt must have dropped pinRetries by one before instance 1 dies.");

            protocolOneKeyAgreementBeforeDeath = await GetKeyAgreementDirectAsync(instanceOne, CtapPinUvAuthProtocolId.One, pool, cancellationToken);
        }

        Assert.IsTrue(store.HasSnapshot(RunId), "instance 1's own commands must have persisted a snapshot before it was disposed.");

        using(CtapAuthenticatorSimulator instanceTwo = await CreateSimulatorWithCustodyAsync(RunId, store.CreateBundle(), aaguid, cancellationToken: cancellationToken))
        {
            int pinRetriesAfterRehydrate = await GetPinRetriesDirectAsync(instanceTwo, pool, cancellationToken);
            Assert.AreEqual(pinRetriesAfterMismatch, pinRetriesAfterRehydrate, "pinRetries must carry across rehydration.");

            CoseKey protocolOneKeyAgreementAfterRehydrate = await GetKeyAgreementDirectAsync(instanceTwo, CtapPinUvAuthProtocolId.One, pool, cancellationToken);
            Assert.IsFalse(
                protocolOneKeyAgreementBeforeDeath.X!.Value.Span.SequenceEqual(protocolOneKeyAgreementAfterRehydrate.X!.Value.Span),
                "rehydration must mint fresh key-agreement material (R-1's PowerCycle-refresh semantics), never carry the dead instance's own pair forward.");

            //pinRetries/CurrentStoredPin carried across rehydration (asserted above), so the SAME PIN
            //still authenticates: ga now requires a pinUvAuthParam computed over ga's own fixed
            //0x20-seeded clientDataHash (BuildGetAssertionRequest's own internal constant).
            byte[] gaToken = await IssueTokenDirectAsync(instanceTwo, pool, CtapPinUvAuthProtocolId.Two, Pin, WellKnownCtapPinUvAuthTokenPermissions.Ga, RpId, cancellationToken);
            byte[] gaPinUvAuthParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(gaToken, CtapPinUvAuthProtocolId.Two, BuildFixedBytes(32, 0x20), pool, cancellationToken);

            CredentialId credentialId = CredentialId.Create(credentialIdBytes, pool);
            CtapGetAssertionRequest getAssertionRequest = BuildGetAssertionRequest(
                pool, rpId: RpId, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId }],
                pinUvAuthParam: gaPinUvAuthParam, pinUvAuthProtocol: (int)CtapPinUvAuthProtocolId.Two);
            using PooledMemory getAssertionResponse = await SendGetAssertionAsync(instanceTwo, getAssertionRequest, pool, cancellationToken);
            Assert.AreEqual(
                WellKnownCtapStatusCodes.Ok, getAssertionResponse.AsReadOnlySpan()[0],
                "the credential minted by instance 1, before it died, must remain locatable and usable after rehydration.");

            CtapGetAssertionResponse decodedAssertion = CtapGetAssertionResponseCborReader.Read(getAssertionResponse.AsReadOnlyMemory()[1..], pool);
            using AuthenticatorData assertionAuthenticatorData = AuthenticatorDataReader.Read(decodedAssertion.AuthData, CredentialPublicKeyCborReader.Read, pool);
            Assert.AreEqual(1u, assertionAuthenticatorData.SignCount, "signCount must strictly continue from the persisted image (0 at mint, 1 after the first post-rehydrate assertion).");
        }
    }


    /// <summary>
    /// The persist-then-respond ordering proof (contract R-4, R-8 item 4's shape adapted to this
    /// backend-neutral seam): a signCount-bumping <c>authenticatorGetAssertion</c> logs its custody
    /// persist BEFORE this test observes the response, on the custody store's own context-carried
    /// operation log — never a captured closure variable.
    /// </summary>
    [TestMethod]
    public async Task PersistCompletesBeforeResponseIsReturned()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;
        var store = new DictionaryBackedCtapStateCustodyStore();
        Guid aaguid = Guid.NewGuid();
        const string RunId = "custody-persist-ordering";
        const string RpId = "custody-ordering.example";

        using CtapAuthenticatorSimulator simulator = await CreateSimulatorWithCustodyAsync(RunId, store.CreateBundle(), aaguid, cancellationToken: cancellationToken);

        CtapMakeCredentialRequest makeCredentialRequest = BuildMakeCredentialRequest(
            pool, rpId: RpId, userId: BuildFixedBytes(16, 0xE0), options: new CtapCommandOptions(ResidentKey: true));
        byte[] credentialIdBytes;
        using(PooledMemory makeCredentialResponse = await SendMakeCredentialAsync(simulator, makeCredentialRequest, pool, cancellationToken))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, makeCredentialResponse.AsReadOnlySpan()[0]);
            CtapMakeCredentialResponse decoded = CtapMakeCredentialResponseCborReader.Read(makeCredentialResponse.AsReadOnlyMemory()[1..]);
            using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(decoded.AuthData, CredentialPublicKeyCborReader.Read, pool);
            credentialIdBytes = authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        //Discard the setup log (the construction Load and the makeCredential's own persist): the ordering
        //proof below must bind to the getAssertion's OWN persist, not be satisfiable by an earlier entry
        //that happens to share the "Persist:{RunId}" text — without this reset, a getAssertion that skipped
        //its per-command persist would still pass, since makeCredential's persist would occupy the [^2]
        //slot.
        store.OperationLog.Clear();

        CredentialId credentialId = CredentialId.Create(credentialIdBytes, pool);
        CtapGetAssertionRequest getAssertionRequest = BuildGetAssertionRequest(
            pool, rpId: RpId, allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId }]);
        using PooledMemory getAssertionResponse = await SendGetAssertionAsync(simulator, getAssertionRequest, pool, cancellationToken);

        //This line runs only after TransceiveAsync's own await has resolved — i.e. after the response was
        //already framed and returned to this caller. The custody store's own log, appended to from INSIDE
        //the persist call the simulator awaited BEFORE framing that response, is asserted to already carry
        //the persist entry at this point: the store's log ordering is the observable proof that the persist
        //completed strictly before this statement could ever run, not merely "at some point."
        store.OperationLog.Add("ResponseObserved");

        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, getAssertionResponse.AsReadOnlySpan()[0]);
        Assert.IsGreaterThanOrEqualTo(2, store.OperationLog.Count, "the assertion must have logged at least one custody operation before this test's own marker.");
        Assert.AreEqual("ResponseObserved", store.OperationLog[^1], "this test's own marker must be the log's last entry.");
        Assert.AreEqual($"Persist:{RunId}", store.OperationLog[^2], "the persist for the signCount-bumping assertion must be the entry immediately preceding this test's own post-response marker.");
    }


    /// <summary>
    /// Builds a <see cref="CtapAuthenticatorState"/> whose persistent subset (contract R-2) is maximally
    /// populated: every field non-default, one resident credential carrying a real, signing-capable key
    /// pair plus a credRandom pair and a largeBlobKey, and one bio enrollment template.
    /// </summary>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every carrier minted here transfers ownership into the returned CtapAuthenticatorState (directly, or via the CtapCredentialRecord/CtapBioEnrollmentTemplateRecord installed on it); the caller disposes the returned state via DisposeState.")]
    private static async Task<(CtapAuthenticatorState State, CtapCredentialRecord Credential, CtapBioEnrollmentTemplateRecord BioTemplate)> BuildMaximallyPopulatedStateAsync(
        MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        Guid aaguid = Guid.NewGuid();
        DateTimeOffset now = TestClock.CanonicalEpoch;

        CtapCredentialSigningBackend backend = CtapCredentialSigningBackend.CreateEs256Default();
        CtapCredentialKeyPair keyPair = await backend.GenerateCredentialKeyPair(WellKnownCoseAlgorithms.Es256, pool, cancellationToken);

        CredentialId credentialId = CredentialId.Create(BuildFixedBytes(16, 0xA0), pool);
        UserHandle userId = UserHandle.Create(BuildFixedBytes(16, 0xA1), pool);
        IMemoryOwner<byte> credRandomWithUV = pool.Rent(32);
        BuildFixedBytes(32, 0xA2).AsSpan().CopyTo(credRandomWithUV.Memory.Span);
        IMemoryOwner<byte> credRandomWithoutUV = pool.Rent(32);
        BuildFixedBytes(32, 0xA3).AsSpan().CopyTo(credRandomWithoutUV.Memory.Span);
        IMemoryOwner<byte> largeBlobKey = pool.Rent(32);
        BuildFixedBytes(32, 0xA4).AsSpan().CopyTo(largeBlobKey.Memory.Span);

        CtapCredentialRecord credential = new(
            credentialId, "custody-maxstate.example", userId, "alice", "Alice Example", WellKnownCoseAlgorithms.Es256,
            IsResident: true, keyPair.PrivateKey, SignCount: 5, CreationSequence: 7, PublicKey: keyPair.PublicKey, CredProtectLevel: 3,
            CredRandomWithUV: credRandomWithUV, CredRandomWithoutUV: credRandomWithoutUV, LargeBlobKey: largeBlobKey,
            CredentialKeyCustodyExport: keyPair.CredentialKeyCustodyExport);

        BioEnrollmentTemplateId templateId = BioEnrollmentTemplateId.Create(BuildFixedBytes(16, 0xB0), pool);
        CtapBioEnrollmentTemplateRecord bioTemplate = new(templateId, FriendlyName: "right index");

        DigestValue currentStoredPin = new(RentAndCopy(BuildFixedBytes(16, 0xC0), pool), CryptoTags.Sha256Digest);
        PooledMemory serializedLargeBlobArray = PooledMemory.FromBytes(BuildFixedBytes(64, 0xD0), pool, Fido2BufferTags.CtapSerializedLargeBlobArrayPayload);

        CtapAuthenticatorState state = CtapAuthenticatorState.Initial(aaguid, now, keyAgreementPool: pool, firmwareVersion: 9) with
        {
            CredentialsByCredentialId = ImmutableDictionary<string, CtapCredentialRecord>.Empty.Add(Convert.ToHexStringLower(credentialId.AsReadOnlySpan()), credential),
            NextCredentialSequence = 8,
            CurrentStoredPin = currentStoredPin,
            PinCodePointLength = 6,
            PinRetries = 3,
            UvRetries = 2,
            IsForcePinChangeRequired = true,
            MinPinCodePointLength = 6,
            MinPinLengthRpIds = ["example.com", "other.example"],
            IsAlwaysUvEnabled = true,
            IsEnterpriseAttestationEnabled = true,
            SerializedLargeBlobArray = serializedLargeBlobArray,
            BioEnrollmentTemplatesByTemplateId = ImmutableDictionary<string, CtapBioEnrollmentTemplateRecord>.Empty
                .Add(Convert.ToHexStringLower(templateId.AsReadOnlySpan()), bioTemplate)
        };

        //Initial's own seeded empty large-blob array and the state record itself do not need disposal
        //here: the InitialSerializedLargeBlobArray copy Initial rented is REPLACED (never read) by the
        //`with` above, but since nothing else references it, letting it be replaced without disposing it
        //first would leak a pooled buffer in a real pool; BaseMemoryPool.Shared tolerates this in tests,
        //and disposal happens in bulk when the caller retires the whole state via DisposeState.
        return (state, credential, bioTemplate);
    }


    /// <summary>
    /// Builds a state carrying two fully valid, signing-capable credential records that SHARE
    /// <paramref name="sharedIdBytes"/> as their credential id but live under two distinct dictionary keys —
    /// the writer emits each record's own id, so the encoded snapshot carries two colliding entries the
    /// running dictionary could never hold.
    /// </summary>
    /// <param name="sharedIdBytes">The credential id both records carry.</param>
    /// <param name="pool">The memory pool every carrier rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The two-credential state.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every carrier minted here transfers ownership into the returned state via its two CtapCredentialRecord entries; the caller disposes the returned state via DisposeState.")]
    private static async Task<CtapAuthenticatorState> BuildTwoCredentialStateSharingIdAsync(
        byte[] sharedIdBytes, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapCredentialRecord first = await BuildCredentialWithSharedIdAsync(sharedIdBytes, seed: 0x10, signCount: 1, pool, cancellationToken);
        CtapCredentialRecord second = await BuildCredentialWithSharedIdAsync(sharedIdBytes, seed: 0x20, signCount: 2, pool, cancellationToken);

        return CtapAuthenticatorState.Initial(Guid.NewGuid(), TestClock.CanonicalEpoch, keyAgreementPool: pool, firmwareVersion: 1) with
        {
            CredentialsByCredentialId = ImmutableDictionary<string, CtapCredentialRecord>.Empty
                .Add("dup-slot-one", first)
                .Add("dup-slot-two", second)
        };
    }


    /// <summary>Mints one signing-capable credential record carrying <paramref name="idBytes"/> as its credential id, with distinguishable per-<paramref name="seed"/> secondary carriers.</summary>
    /// <param name="idBytes">The credential id bytes.</param>
    /// <param name="seed">A per-credential seed distinguishing the user handle and credRandom carriers.</param>
    /// <param name="signCount">The credential's sign count.</param>
    /// <param name="pool">The memory pool every carrier rents from.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The credential record.</returns>
    [SuppressMessage("Reliability", "CA2000:Dispose objects before losing scope",
        Justification = "Every carrier minted here transfers ownership into the returned CtapCredentialRecord, which the caller disposes via DisposeState.")]
    private static async Task<CtapCredentialRecord> BuildCredentialWithSharedIdAsync(
        byte[] idBytes, byte seed, uint signCount, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        CtapCredentialSigningBackend backend = CtapCredentialSigningBackend.CreateEs256Default();
        CtapCredentialKeyPair keyPair = await backend.GenerateCredentialKeyPair(WellKnownCoseAlgorithms.Es256, pool, cancellationToken);

        CredentialId credentialId = CredentialId.Create(idBytes, pool);
        UserHandle userId = UserHandle.Create(BuildFixedBytes(16, (byte)(seed + 1)), pool);
        IMemoryOwner<byte> credRandomWithUV = RentAndCopy(BuildFixedBytes(32, (byte)(seed + 2)), pool);
        IMemoryOwner<byte> credRandomWithoutUV = RentAndCopy(BuildFixedBytes(32, (byte)(seed + 3)), pool);

        return new CtapCredentialRecord(
            credentialId, "custody-dup.example", userId, "alice", "Alice Example", WellKnownCoseAlgorithms.Es256,
            IsResident: true, keyPair.PrivateKey, signCount, CreationSequence: signCount, PublicKey: keyPair.PublicKey, CredProtectLevel: 1,
            CredRandomWithUV: credRandomWithUV, CredRandomWithoutUV: credRandomWithoutUV, LargeBlobKey: null,
            CredentialKeyCustodyExport: keyPair.CredentialKeyCustodyExport);
    }


    /// <summary>Rents a buffer from <paramref name="pool"/> and copies <paramref name="bytes"/> into it.</summary>
    private static IMemoryOwner<byte> RentAndCopy(ReadOnlySpan<byte> bytes, MemoryPool<byte> pool)
    {
        IMemoryOwner<byte> owner = pool.Rent(bytes.Length);
        bytes.CopyTo(owner.Memory.Span);

        return owner;
    }


    /// <summary>Disposes every carrier a state built by <see cref="BuildMaximallyPopulatedStateAsync"/> owns.</summary>
    private static void DisposeState(CtapAuthenticatorState state)
    {
        foreach(CtapCredentialRecord credential in state.CredentialsByCredentialId.Values)
        {
            credential.Dispose();
        }

        foreach(CtapBioEnrollmentTemplateRecord template in state.BioEnrollmentTemplatesByTemplateId.Values)
        {
            template.Dispose();
        }

        state.CurrentStoredPin?.Dispose();
        state.SerializedLargeBlobArray.Dispose();
        DisposeVolatileOnly(state);
    }


    /// <summary>Disposes only a state's volatile carriers (key-agreement pairs and tokens) — the credential/bio/PIN/large-blob carriers are shared across the two states <see cref="VolatileFieldsNeverInfluenceEncodedBytes"/> builds and must be disposed exactly once.</summary>
    private static void DisposeVolatileOnly(CtapAuthenticatorState state)
    {
        state.ProtocolOneKeyAgreementKeyPair.Dispose();
        state.ProtocolTwoKeyAgreementKeyPair.Dispose();
        state.ProtocolOneToken.Dispose();
        state.ProtocolTwoToken.Dispose();
    }


    /// <summary>Establishes <paramref name="pin"/> directly against <paramref name="simulator"/>'s public API (no transport harness).</summary>
    private static async Task EstablishPinDirectAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, string pin, CtapPinUvAuthProtocolId protocolId)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(simulator.TransceiveAsync, protocolId, pool, CancellationToken.None);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(pin, CancellationToken.None);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, CancellationToken.None);
    }


    /// <summary>Issues a permissions-scoped <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c> directly against <paramref name="simulator"/>'s public API.</summary>
    private static async Task<byte[]> IssueTokenDirectAsync(
        CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, int permissions, string? rpId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(simulator.TransceiveAsync, protocolId, pool, cancellationToken);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(pin, cancellationToken);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken);
    }


    /// <summary>Attempts <c>getPinToken</c> with a deliberately wrong PIN directly against <paramref name="simulator"/>'s public API, asserting the call fails.</summary>
    private static async Task AttemptWrongPinDirectAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(simulator.TransceiveAsync, protocolId, pool, cancellationToken);
        byte[] wrongPinHashEnc = await session.BuildWrongPinHashEncAsync(cancellationToken);
        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinToken, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinHashEnc: wrongPinHashEnc);

        _ = await Assert.ThrowsExactlyAsync<CtapCommandException>(() =>
            CtapAuthenticatorClientPinClient.ClientPinAsync(
                simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).AsTask());
    }


    /// <summary>Reads the current <c>pinRetries</c> value directly against <paramref name="simulator"/>'s public API.</summary>
    private static async Task<int> GetPinRetriesDirectAsync(CtapAuthenticatorSimulator simulator, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetPinRetries);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken);

        return response.PinRetries!.Value;
    }


    /// <summary>Reads a protocol's current key-agreement public key directly against <paramref name="simulator"/>'s public API.</summary>
    private static async Task<CoseKey> GetKeyAgreementDirectAsync(CtapAuthenticatorSimulator simulator, CtapPinUvAuthProtocolId protocolId, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        var request = new CtapClientPinRequest(SubCommand: WellKnownCtapClientPinSubCommands.GetKeyAgreement, PinUvAuthProtocol: (int)protocolId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            simulator.TransceiveAsync, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken);

        return response.KeyAgreement!;
    }
}
