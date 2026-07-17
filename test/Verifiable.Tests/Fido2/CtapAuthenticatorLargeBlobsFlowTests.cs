using System;
using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The wavelb PKG-D real-wire capstones for <c>authenticatorLargeBlobs</c> (<c>0x0C</c>) and the
/// <c>largeBlobKey</c> extension (CTAP 2.3 §12.3): the same real, unmodified APDU transport stack
/// (<see cref="CtapWave2TransportHarness"/>) every prior wave's capstones use, driving five flows end to
/// end — (A) the fresh-state <c>get</c> plus a tokenless multi-fragment write exercising both discard
/// disciplines, (B) the R5 protection arc and the <c>lbw</c> permission carve-out, (C) the full §12.3
/// story with REAL DEFLATE compression and AES-256-GCM encryption in test code
/// (<see cref="CtapWaveLargeBlobPlatformFixtures"/>), (D) <c>authenticatorReset</c>'s restoration of the
/// initial constant plus the power-cycle discard, and (E) a commit-time integrity failure. Every
/// assertion reads a wire-visible fact only — a raw response status byte, a decoded
/// <c>authenticatorLargeBlobs</c>/<c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>/
/// <c>authenticatorCredentialManagement</c> response, or an independently recomputed SHA-256 digest —
/// never internal simulator state, with <see cref="CtapAuthenticatorSimulator.PowerCycle"/> as the one
/// sanctioned exception (<see cref="CtapAuthenticatorResetFlowTests"/>'s own precedent: CTAP 2.3's own
/// physical-replug seam, not a wire command). Every armed-gate <c>pinUvAuthParam</c> is computed with the
/// real <see cref="CtapPinUvAuthProtocol.AuthenticateAsync"/> over wire-received bytes, through
/// <see cref="CtapWaveLargeBlobsFixtures"/>'s R7 verify-message helper.
/// </summary>
[TestClass]
internal sealed class CtapAuthenticatorLargeBlobsFlowTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;

    /// <summary>The plaintext PIN every capstone that establishes one uses, matching this profile's default 4-code-point minimum.</summary>
    private const string Pin = "1234";

    /// <summary>The single PIN/UV auth protocol every capstone drives.</summary>
    private static CtapPinUvAuthProtocolId ProtocolId => CtapPinUvAuthProtocolId.Two;


    /// <summary>
    /// Capstone A: the fresh-state <c>get</c> is byte-exact against the 17-byte initial constant (trap
    /// 9), then a completely tokenless three-fragment write (960 + 960 + 80 = 2000 bytes, spanning the
    /// <see cref="CtapAuthenticatorState.MaxFragmentLength"/> boundary at least twice, seams trap 12) is
    /// reconstructed from wire bytes only. An <c>InvalidSeq</c> negative injected mid-sequence (a
    /// mismatched continuation offset) leaves the live sequence's own <c>expectedNextOffset</c>
    /// untouched, so the correct continuation still lands; the completed write is read back through the
    /// platform's own read loop (line 7699) with harness-side trailing-hash confirmation and an
    /// exact byte round trip. A second, THROWAWAY pending sequence is then abandoned via an intervening
    /// <c>authenticatorGetInfo</c> (the GLOBAL discard discipline) — its own continuation fails
    /// <c>InvalidSeq</c>, and a fresh read-back proves the abandoned throwaway never touched the
    /// ALREADY COMMITTED array from the first write.
    /// </summary>
    [TestMethod]
    public async Task FreshStateGetAndTokenlessMultiFragmentWriteWithDiscardDisciplinesOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("wavelb-capstone-a");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        (byte freshStatus, CtapLargeBlobsResponse? freshResponse) = await SendGetAsync(
            harness.Transceive, pool, CtapAuthenticatorState.InitialSerializedLargeBlobArray.Length, offset: 0, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, freshStatus);
        CollectionAssert.AreEqual(
            CtapAuthenticatorState.InitialSerializedLargeBlobArray.ToArray(), freshResponse!.Config.ToArray(),
            "a fresh authenticator's get must return the 17-byte initial constant byte-exactly, on the wire.");

        int fragmentLength = CtapAuthenticatorState.MaxFragmentLength;
        byte[] fullArray = CtapWaveLargeBlobPlatformFixtures.BuildValidSerializedArray(pool, payloadLength: (2 * fragmentLength) + 80);

        byte firstStatus = await CtapWaveLargeBlobPlatformFixtures.SendFragmentAsync(
            harness.Transceive, pool, fullArray.AsMemory(0, fragmentLength), offset: 0, length: fullArray.Length, token: null, ProtocolId, cancellationToken)
            .ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, firstStatus, "the sequence-initiating fragment must succeed tokenless on a fresh device.");

        byte wrongOffsetStatus = await CtapWaveLargeBlobPlatformFixtures.SendFragmentAsync(
            harness.Transceive, pool, new byte[] { 0xAA }, offset: 100, length: null, token: null, ProtocolId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSeq, wrongOffsetStatus, "a mismatched continuation offset must fail InvalidSeq, on the wire.");

        byte secondStatus = await CtapWaveLargeBlobPlatformFixtures.SendFragmentAsync(
            harness.Transceive, pool, fullArray.AsMemory(fragmentLength, fragmentLength), offset: fragmentLength, length: null, token: null, ProtocolId,
            cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, secondStatus, "the InvalidSeq negative above must not have disturbed the live sequence's own expectedNextOffset.");

        int thirdOffset = 2 * fragmentLength;
        byte thirdStatus = await CtapWaveLargeBlobPlatformFixtures.SendFragmentAsync(
            harness.Transceive, pool, fullArray.AsMemory(thirdOffset, fullArray.Length - thirdOffset), offset: thirdOffset, length: null, token: null, ProtocolId,
            cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, thirdStatus, "the third and final fragment must commit the whole write.");

        byte[] readBack = await CtapWaveLargeBlobPlatformFixtures.ReadEntireSerializedArrayAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);
        CollectionAssert.AreEqual(fullArray, readBack, "the read-back array must byte-exactly match the committed write.");

        byte throwawayFirstStatus = await CtapWaveLargeBlobPlatformFixtures.SendFragmentAsync(
            harness.Transceive, pool, new byte[] { 0x01, 0x02 }, offset: 0, length: 50, token: null, ProtocolId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, throwawayFirstStatus);

        _ = await GetInfoAsync(harness.Transceive, pool, cancellationToken).ConfigureAwait(false);

        byte throwawayContinuationStatus = await CtapWaveLargeBlobPlatformFixtures.SendFragmentAsync(
            harness.Transceive, pool, new byte[] { 0x03 }, offset: 2, length: null, token: null, ProtocolId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(
            WellKnownCtapStatusCodes.InvalidSeq, throwawayContinuationStatus,
            "an intervening authenticatorGetInfo must discard the pending sequence, on the wire.");

        byte[] readBackAfterDiscard = await CtapWaveLargeBlobPlatformFixtures.ReadEntireSerializedArrayAsync(harness.Transceive, pool, cancellationToken)
            .ConfigureAwait(false);
        CollectionAssert.AreEqual(
            fullArray, readBackAfterDiscard, "the abandoned throwaway sequence must never have overwritten the previously committed array.");
    }


    /// <summary>
    /// Capstone B: <c>setPIN</c> arms the R5 conditional gate — a subsequent tokenless <c>set</c> now
    /// fails <c>PuatRequired</c> on the wire. An <c>lbw|mc</c> token then drives a full write to
    /// completion; the SAME token, after driving an <c>authenticatorMakeCredential</c> call that strips
    /// every permission but <c>lbw</c> (line 5828), still drives a SECOND full write to completion — the
    /// <c>lbw</c> carve-out's own E2E proof, reconstructed over the real wire.
    /// </summary>
    [TestMethod]
    public async Task SetPinArmsGateAndLbwCarveOutSurvivesMakeCredentialOverRealApduTransport()
    {
        const string RpId = "wavelb-capstone-b.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("wavelb-capstone-b");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        await EstablishPinAsync(harness.Transceive, pool, ProtocolId, Pin, cancellationToken).ConfigureAwait(false);

        byte armedTokenlessStatus = await CtapWaveLargeBlobPlatformFixtures.SendFragmentAsync(
            harness.Transceive, pool, new byte[] { 0x80 }, offset: 0, length: 17, token: null, ProtocolId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.PuatRequired, armedTokenlessStatus, "setPIN must arm the R5 gate, observed on the wire.");

        int lbwAndMc = WellKnownCtapPinUvAuthTokenPermissions.Lbw | WellKnownCtapPinUvAuthTokenPermissions.Mc;
        byte[] token = await IssueTokenAsync(harness.Transceive, pool, ProtocolId, Pin, lbwAndMc, RpId, cancellationToken).ConfigureAwait(false);

        byte[] firstEntry = CtapWaveLargeBlobPlatformFixtures.BuildValidSerializedArray(pool, payloadLength: 20);
        await CtapWaveLargeBlobPlatformFixtures.WriteSerializedArrayAsync(
            harness.Transceive, pool, firstEntry, CtapAuthenticatorState.MaxFragmentLength, token, ProtocolId, cancellationToken).ConfigureAwait(false);

        byte[] readBackAfterLbwWrite = await CtapWaveLargeBlobPlatformFixtures.ReadEntireSerializedArrayAsync(harness.Transceive, pool, cancellationToken)
            .ConfigureAwait(false);
        CollectionAssert.AreEqual(firstEntry, readBackAfterLbwWrite, "the lbw-token-driven write must land on the wire exactly as sent.");

        byte[] mcClientDataHash = CtapWave2AuthenticatorFixtures.BuildFixedBytes(32, 0x10);
        byte[] mcParam = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, ProtocolId, mcClientDataHash, pool, cancellationToken).ConfigureAwait(false);
        CtapMakeCredentialRequest mcRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: RpId, pinUvAuthParam: mcParam, pinUvAuthProtocol: (int)ProtocolId);
        CtapMakeCredentialResponse mcResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, mcRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(mcRequest);
        using(AuthenticatorData mcAuthenticatorData = AuthenticatorDataReader.Read(mcResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            Assert.IsTrue(mcAuthenticatorData.Flags.UserVerified, "the mc call itself, authorized by the same token's mc bit, must succeed with uv=1.");
        }

        byte[] secondEntry = CtapWaveLargeBlobPlatformFixtures.BuildValidSerializedArray(pool, payloadLength: 25);
        await CtapWaveLargeBlobPlatformFixtures.WriteSerializedArrayAsync(
            harness.Transceive, pool, secondEntry, CtapAuthenticatorState.MaxFragmentLength, token, ProtocolId, cancellationToken).ConfigureAwait(false);

        byte[] readBackAfterCarveOut = await CtapWaveLargeBlobPlatformFixtures.ReadEntireSerializedArrayAsync(harness.Transceive, pool, cancellationToken)
            .ConfigureAwait(false);
        CollectionAssert.AreEqual(
            secondEntry, readBackAfterCarveOut,
            "the SAME token -- stripped of mc but still carrying lbw (the line 5828 carve-out) -- must still drive a full set to completion, on the wire.");
    }


    /// <summary>
    /// Capstone C: <c>mc(largeBlobKey:true, rk:true)</c> mints a fresh 32-byte key at the TOP-LEVEL
    /// <c>0x05</c> response member; <c>ga(largeBlobKey:true)</c> against the same credential returns the
    /// IDENTICAL key at the TOP-LEVEL <c>0x07</c> member. The platform role then DEFLATE-compresses,
    /// AES-256-GCM-encrypts, CBOR-frames, and writes a real per-credential entry under that key
    /// (<see cref="CtapWaveLargeBlobPlatformFixtures"/>, R9), reads it back, decrypts, and decompresses —
    /// recovering the exact original opaque payload, the full §6.10.4/6.10.5 story with REAL crypto.
    /// Finally, <c>credMgmt</c>'s <c>enumerateCredentialsBegin</c> reports the SAME stored key at its own
    /// <c>0x0B</c> member ("the contents, if any", lines 7312/7341).
    /// </summary>
    [TestMethod]
    public async Task LargeBlobKeyExtensionEndToEndWithRealDeflateAndGcmOverRealApduTransport()
    {
        const string RpId = "wavelb-capstone-c.example";
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("wavelb-capstone-c");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        ReadOnlyMemory<byte> mcExtensions = CtapWave2AuthenticatorFixtures.BuildMakeCredentialExtensionsInput(largeBlobKey: true);
        byte[] userId = CtapWave2AuthenticatorFixtures.BuildFixedBytes(16, 0xF0);
        CtapMakeCredentialRequest mcRequest = CtapWave2AuthenticatorFixtures.BuildMakeCredentialRequest(
            pool, rpId: RpId, userId: userId, options: new CtapCommandOptions(ResidentKey: true), extensions: mcExtensions);
        CtapMakeCredentialResponse mcResponse = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, mcRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeMakeCredentialRequest(mcRequest);

        Assert.IsNotNull(mcResponse.LargeBlobKey, "mc(largeBlobKey:true, rk:true) must emit the TOP-LEVEL 0x05 response member, on the wire.");
        byte[] largeBlobKey = mcResponse.LargeBlobKey!.Value.ToArray();
        Assert.HasCount(32, largeBlobKey);

        byte[] credentialIdBytes;
        using(AuthenticatorData mcAuthenticatorData = AuthenticatorDataReader.Read(mcResponse.AuthData, CredentialPublicKeyCborReader.Read, pool))
        {
            credentialIdBytes = mcAuthenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan().ToArray();
        }

        ReadOnlyMemory<byte> gaExtensions = CtapWave2AuthenticatorFixtures.BuildGetAssertionExtensionsInput(largeBlobKey: true);
        CtapGetAssertionRequest gaRequest = CtapWave2AuthenticatorFixtures.BuildGetAssertionRequest(
            pool, rpId: RpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(credentialIdBytes, pool) }],
            extensions: gaExtensions);
        CtapGetAssertionResponse gaResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, gaRequest, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken)
            .ConfigureAwait(false);
        CtapWave2AuthenticatorFixtures.DisposeGetAssertionRequest(gaRequest);
        gaResponse.Credential.Id.Dispose();
        gaResponse.User?.Id.Dispose();

        Assert.IsNotNull(gaResponse.LargeBlobKey, "ga(largeBlobKey:true) against a keyed credential must emit the TOP-LEVEL 0x07 response member, on the wire.");
        Assert.IsTrue(largeBlobKey.AsSpan().SequenceEqual(gaResponse.LargeBlobKey!.Value.Span), "ga must return the SAME key mc minted.");

        byte[] opaqueData = Encoding.UTF8.GetBytes("wavelb capstone-c opaque payload, encrypted and compressed for real over the wire.");
        await CtapWaveLargeBlobPlatformFixtures.WriteEncryptedEntryAsync(
            harness.Transceive, pool, opaqueData, largeBlobKey, CtapAuthenticatorState.MaxFragmentLength, token: null, ProtocolId, cancellationToken)
            .ConfigureAwait(false);

        byte[] recovered = await CtapWaveLargeBlobPlatformFixtures.ReadAndDecryptEntryAsync(harness.Transceive, pool, largeBlobKey, cancellationToken)
            .ConfigureAwait(false);
        CollectionAssert.AreEqual(opaqueData, recovered, "the real DEFLATE+AES-256-GCM round trip must recover the exact original opaque payload.");

        await EstablishPinAsync(harness.Transceive, pool, ProtocolId, Pin, cancellationToken).ConfigureAwait(false);
        byte[] cmToken = await IssueTokenAsync(
            harness.Transceive, pool, ProtocolId, Pin, WellKnownCtapPinUvAuthTokenPermissions.Cm, rpId: null, cancellationToken).ConfigureAwait(false);

        byte[] rpIdHash = ComputeRpIdHash(RpId);
        ReadOnlyMemory<byte>? enumeratedLargeBlobKey = await EnumerateSingleCredentialLargeBlobKeyAsync(
            harness.Transceive, pool, cmToken, rpIdHash, cancellationToken).ConfigureAwait(false);

        Assert.IsNotNull(enumeratedLargeBlobKey, "credMgmt's enumerateCredentialsBegin must emit 0x0B for a credential carrying a stored largeBlobKey, on the wire.");
        Assert.IsTrue(
            largeBlobKey.AsSpan().SequenceEqual(enumeratedLargeBlobKey!.Value.Span), "credMgmt's 0x0B must carry the SAME key mc minted and ga confirmed.");
    }


    /// <summary>
    /// Capstone D: a committed, non-initial array is written tokenless; <c>authenticatorReset</c> issued
    /// over the wire restores the initial 17-byte constant, wire-visibly confirmed by a post-reset
    /// <c>get</c> (line 7705's MUST, made live this wave). A fresh pending write begun after the reset is
    /// then discarded by a power cycle (line 2869) — the continuation fails <c>InvalidSeq</c> — while the
    /// reset-restored constant itself survives the cycle untouched.
    /// </summary>
    [TestMethod]
    public async Task FactoryResetRestoresConstantAndPowerCycleDiscardsPendingWriteOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("wavelb-capstone-d");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        byte[] committed = CtapWaveLargeBlobPlatformFixtures.BuildValidSerializedArray(pool, payloadLength: 30);
        await CtapWaveLargeBlobPlatformFixtures.WriteSerializedArrayAsync(
            harness.Transceive, pool, committed, CtapAuthenticatorState.MaxFragmentLength, token: null, ProtocolId, cancellationToken).ConfigureAwait(false);

        byte[] readBackBeforeReset = await CtapWaveLargeBlobPlatformFixtures.ReadEntireSerializedArrayAsync(harness.Transceive, pool, cancellationToken)
            .ConfigureAwait(false);
        CollectionAssert.AreEqual(committed, readBackBeforeReset);

        byte[] resetRequest = [WellKnownCtapCommands.Reset];
        using(PooledMemory resetResponse = await harness.Transceive(resetRequest, pool, cancellationToken).ConfigureAwait(false))
        {
            Assert.AreEqual(WellKnownCtapStatusCodes.Ok, resetResponse.AsReadOnlySpan()[0], "authenticatorReset must return CTAP2_OK on the wire.");
        }

        (byte postResetStatus, CtapLargeBlobsResponse? postResetResponse) = await SendGetAsync(
            harness.Transceive, pool, CtapAuthenticatorState.InitialSerializedLargeBlobArray.Length, offset: 0, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, postResetStatus);
        CollectionAssert.AreEqual(
            CtapAuthenticatorState.InitialSerializedLargeBlobArray.ToArray(), postResetResponse!.Config.ToArray(),
            "authenticatorReset must restore the initial serialized large-blob array byte-exactly, on the wire.");

        byte pendingStatus = await CtapWaveLargeBlobPlatformFixtures.SendFragmentAsync(
            harness.Transceive, pool, new byte[] { 0x80 }, offset: 0, length: 17, token: null, ProtocolId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.Ok, pendingStatus);

        simulator.PowerCycle();

        byte continuationAfterCycleStatus = await CtapWaveLargeBlobPlatformFixtures.SendFragmentAsync(
            harness.Transceive, pool, new byte[] { 0x76 }, offset: 1, length: null, token: null, ProtocolId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidSeq, continuationAfterCycleStatus, "a power cycle must discard the pending sequence, on the wire.");

        byte[] readBackAfterCycle = await CtapWaveLargeBlobPlatformFixtures.ReadEntireSerializedArrayAsync(harness.Transceive, pool, cancellationToken)
            .ConfigureAwait(false);
        CollectionAssert.AreEqual(
            CtapAuthenticatorState.InitialSerializedLargeBlobArray.ToArray(), readBackAfterCycle,
            "the power cycle must preserve the reset-restored constant, discarding only the abandoned pending write.");
    }


    /// <summary>
    /// Capstone E: a valid array is committed tokenless; a SECOND single-fragment write whose trailing
    /// hash byte is deliberately flipped fails <c>IntegrityFailure</c> on the wire (line 7666,
    /// exercised on the TOKENLESS path per trap 3), and the FIRST commit's array is still readable,
    /// byte-exact, proving the failed write never touched persistent storage.
    /// </summary>
    [TestMethod]
    public async Task IntegrityFailureOnTheWireLeavesPreviousArrayReadableOverRealApduTransport()
    {
        MemoryPool<byte> pool = BaseMemoryPool.Shared;
        CancellationToken cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapWave2AuthenticatorFixtures.CreateSimulator("wavelb-capstone-e");
        using CtapWave2TransportHarness harness = await CtapWave2TransportHarness.CreateAsync(simulator, pool, cancellationToken).ConfigureAwait(false);

        byte[] committed = CtapWaveLargeBlobPlatformFixtures.BuildValidSerializedArray(pool, payloadLength: 25);
        await CtapWaveLargeBlobPlatformFixtures.WriteSerializedArrayAsync(
            harness.Transceive, pool, committed, CtapAuthenticatorState.MaxFragmentLength, token: null, ProtocolId, cancellationToken).ConfigureAwait(false);

        byte[] corrupted = CtapWaveLargeBlobPlatformFixtures.BuildValidSerializedArray(pool, payloadLength: 25);
        corrupted[^1] ^= 0xFF;

        byte corruptedStatus = await CtapWaveLargeBlobPlatformFixtures.SendFragmentAsync(
            harness.Transceive, pool, corrupted, offset: 0, length: corrupted.Length, token: null, ProtocolId, cancellationToken).ConfigureAwait(false);
        Assert.AreEqual(WellKnownCtapStatusCodes.IntegrityFailure, corruptedStatus, "a corrupted trailing hash must fail with IntegrityFailure, on the wire.");

        byte[] readBackAfterFailure = await CtapWaveLargeBlobPlatformFixtures.ReadEntireSerializedArrayAsync(harness.Transceive, pool, cancellationToken)
            .ConfigureAwait(false);
        CollectionAssert.AreEqual(
            committed, readBackAfterFailure, "a commit-time integrity failure must leave the previously stored array byte-exact and unchanged, on the wire.");
    }


    /// <summary>Sends an <c>authenticatorLargeBlobs</c> <c>get</c> request over <paramref name="transceive"/>'s real transport, decoding a successful response.</summary>
    /// <returns>The raw status byte and, when it is <see cref="WellKnownCtapStatusCodes.Ok"/>, the decoded response.</returns>
    private static async Task<(byte Status, CtapLargeBlobsResponse? Response)> SendGetAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, int get, int offset, CancellationToken cancellationToken)
    {
        var request = new CtapLargeBlobsRequest(Get: get, Offset: offset);
        byte[] envelope = CtapWaveLargeBlobsFixtures.BuildEnvelope(request);
        using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);
        byte status = response.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(status))
        {
            return (status, null);
        }

        return (status, CtapLargeBlobsResponseCborReader.Read(response.AsReadOnlyMemory()[1..]));
    }


    /// <summary>Sends an <c>authenticatorGetInfo</c> request over <paramref name="transceive"/>'s real transport and decodes the response.</summary>
    private static async Task<CtapGetInfoResponse> GetInfoAsync(Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CancellationToken cancellationToken)
    {
        byte[] request = [WellKnownCtapCommands.GetInfo];
        using PooledMemory response = await transceive(request, pool, cancellationToken).ConfigureAwait(false);

        return CtapGetInfoResponseCborReader.Read(response.AsReadOnlyMemory()[1..]);
    }


    /// <summary>Establishes <paramref name="pin"/> as the authenticator's PIN over <paramref name="transceive"/>'s real transport.</summary>
    private static async Task EstablishPinAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        (byte[] newPinEnc, byte[] pinUvAuthParam) = await session.BuildSetPinMessagesAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.SetPin, PinUvAuthProtocol: (int)protocolId,
            KeyAgreement: session.PlatformPublicKeyCose, PinUvAuthParam: pinUvAuthParam, NewPinEnc: newPinEnc);

        _ = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Issues a permissions-scoped <c>pinUvAuthToken</c> via <c>getPinUvAuthTokenUsingPinWithPermissions</c>
    /// (<c>0x09</c>) over <paramref name="transceive"/>'s real transport, decrypting it from wire bytes only.
    /// </summary>
    private static async Task<byte[]> IssueTokenAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, CtapPinUvAuthProtocolId protocolId, string pin, int permissions, string? rpId,
        CancellationToken cancellationToken)
    {
        using CtapWave5bPlatformPinSession session = await CtapWave5bPinCryptoFixtures.EstablishSessionAsync(transceive, protocolId, pool, cancellationToken)
            .ConfigureAwait(false);
        byte[] pinHashEnc = await session.BuildPinHashEncAsync(pin, cancellationToken).ConfigureAwait(false);

        var request = new CtapClientPinRequest(
            SubCommand: WellKnownCtapClientPinSubCommands.GetPinUvAuthTokenUsingPinWithPermissions,
            PinUvAuthProtocol: (int)protocolId, KeyAgreement: session.PlatformPublicKeyCose,
            PinHashEnc: pinHashEnc, Permissions: permissions, RpId: rpId);
        CtapClientPinResponse response = await CtapAuthenticatorClientPinClient.ClientPinAsync(
            transceive, CtapClientPinRequestCborWriter.Write, request, CtapClientPinResponseCborReader.Read, pool, cancellationToken).ConfigureAwait(false);

        return await session.DecryptTokenAsync(response.PinUvAuthToken!.Value, cancellationToken).ConfigureAwait(false);
    }


    /// <summary>
    /// Drives one gated <c>authenticatorCredentialManagement</c> <c>enumerateCredentialsBegin</c> (<c>0x04</c>)
    /// over <paramref name="transceive"/>'s real transport for the single credential registered under
    /// <paramref name="rpIdHash"/>, returning its reported <c>largeBlobKey</c> (<c>0x0B</c>) member.
    /// </summary>
    private static async Task<ReadOnlyMemory<byte>?> EnumerateSingleCredentialLargeBlobKeyAsync(
        Ctap2TransceiveDelegate transceive, MemoryPool<byte> pool, byte[] token, byte[] rpIdHash, CancellationToken cancellationToken)
    {
        byte[] subCommandParams = CtapWaveCmFixtures.BuildSubCommandParams(rpIdHash: rpIdHash);
        byte[] message = CtapWaveCmFixtures.BuildMessage(WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, subCommandParams);
        byte[] param = await CtapWaveConfigFixtures.ComputeSignatureAsync(token, ProtocolId, message, pool, cancellationToken).ConfigureAwait(false);

        var request = new CtapCredentialManagementRequest(
            SubCommand: WellKnownCtapCredentialManagementSubCommands.EnumerateCredentialsBegin, RpIdHash: rpIdHash,
            PinUvAuthProtocol: (int)ProtocolId, PinUvAuthParam: param);
        byte[] envelope = CtapWaveCmFixtures.BuildCredentialManagementEnvelope(request);
        using PooledMemory response = await transceive(envelope, pool, cancellationToken).ConfigureAwait(false);
        byte status = response.AsReadOnlySpan()[0];
        if(!WellKnownCtapStatusCodes.IsOk(status))
        {
            throw new CtapCommandException(status);
        }

        CtapCredentialManagementResponse decoded = CtapCredentialManagementResponseCborReader.Read(response.AsReadOnlyMemory()[1..], pool);
        decoded.User?.Id.Dispose();
        decoded.CredentialId?.Id.Dispose();

        return decoded.LargeBlobKey;
    }


    /// <summary>Independently computes <paramref name="rpId"/>'s SHA-256 digest -- an oracle wholly separate from the authenticator's own <c>ComputeRpIdHash</c> seam, mirroring <see cref="CtapAuthenticatorCredentialManagementFlowTests"/>'s own identical helper.</summary>
    private static byte[] ComputeRpIdHash(string rpId) => SHA256.HashData(Encoding.UTF8.GetBytes(rpId));
}
