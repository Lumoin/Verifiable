using System;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Time.Testing;
using Verifiable.Cbor.Ctap;
using Verifiable.Cbor.Fido2;
using Verifiable.Fido2;
using Verifiable.Fido2.Ctap;
using Verifiable.Fido2.Ctap.Authenticator.Automata;
using Verifiable.JCose;
using Verifiable.Tests.TestInfrastructure;

namespace Verifiable.Tests.Fido2;

/// <summary>
/// The capstone's negative matrix: <c>authenticatorMakeCredential</c>/<c>authenticatorGetAssertion</c>/
/// <c>authenticatorGetNextAssertion</c> error/edge scenarios, each driven by
/// <see cref="CtapAuthenticatorMakeCredentialClient"/>/<see cref="CtapAuthenticatorGetAssertionClient"/>/
/// <see cref="CtapAuthenticatorGetNextAssertionClient"/> over the real, unmodified transport
/// (<see cref="CtapNfcTransportHarness"/>) and asserting the exact CTAP2 status byte the authenticator
/// returned on the wire.
/// </summary>
/// <remarks>
/// Firewalled the same way as <see cref="CtapAuthenticatorCapstoneFlowTests"/>: every request travels
/// through the CBOR wire encoding (never a direct in-process call into the simulator's automaton), and
/// every assertion reads only the decoded response or the thrown <see cref="CtapCommandException"/>'s
/// own <see cref="CtapCommandException.StatusCode"/> — never the simulator's internal state.
/// </remarks>
[TestClass]
internal sealed class CtapAuthenticatorCapstoneNegativeMatrixTests
{
    /// <summary>Gets or sets the test context, supplying the ambient cancellation token.</summary>
    public TestContext TestContext { get; set; } = null!;


    /// <summary>
    /// (a) An <c>excludeList</c> entry naming a credential already registered for the same relying
    /// party fails with <see cref="WellKnownCtapStatusCodes.CredentialExcluded"/>.
    /// </summary>
    [TestMethod]
    public async Task ExcludeListHitReturnsCredentialExcluded()
    {
        const string rpId = "negative-a.example";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-a-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        CredentialId existingCredentialId = await RegisterCredentialAsync(
            harness, pool, rpId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x01), resident: false, cancellationToken);

        CtapMakeCredentialRequest request = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(
            pool,
            rpId: rpId,
            userId: CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x02),
            excludeList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = existingCredentialId }]);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.CredentialExcluded, exception.StatusCode);

        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(request);
    }


    /// <summary>
    /// (b) An <c>allowList</c> naming only unregistered credential identifiers fails with
    /// <see cref="WellKnownCtapStatusCodes.NoCredentials"/>.
    /// </summary>
    [TestMethod]
    public async Task UnknownAllowListIdReturnsNoCredentials()
    {
        const string rpId = "negative-b.example";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-b-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        CredentialId unknownCredentialId = CredentialId.Create(CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(32, 0x9A), pool);
        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool,
            rpId: rpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = unknownCredentialId }]);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                harness.Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, exception.StatusCode);

        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
    }


    /// <summary>
    /// (c) A <c>pubKeyCredParams</c> list naming only algorithms the injected ES256-only backend does
    /// not support fails with <see cref="WellKnownCtapStatusCodes.UnsupportedAlgorithm"/>.
    /// </summary>
    [TestMethod]
    public async Task UnsupportedAlgorithmReturnsUnsupportedAlgorithm()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-c-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        CtapMakeCredentialRequest request = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(pool, alg: WellKnownCoseAlgorithms.Rs256);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.UnsupportedAlgorithm, exception.StatusCode);

        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(request);
    }


    /// <summary>
    /// (d) <c>options.uv = true</c> fails with <see cref="WellKnownCtapStatusCodes.InvalidOption"/>: this
    /// fresh simulator has zero fingerprint enrollments, so its built-in UV method is not yet configured.
    /// </summary>
    [TestMethod]
    public async Task UserVerificationTrueOnMakeCredentialReturnsInvalidOption()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-d-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        CtapMakeCredentialRequest request = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(
            pool, options: new CtapCommandOptions(UserVerification: true));

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.InvalidOption, exception.StatusCode);

        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(request);
    }


    /// <summary>
    /// (e) A <c>pinUvAuthParam</c> present with no accompanying <c>pinUvAuthProtocol</c> fails with
    /// <see cref="WellKnownCtapStatusCodes.MissingParameter"/> — the exact snapshot-mandated code for
    /// that half of the shared pinUvAuth guard's case split.
    /// </summary>
    [TestMethod]
    public async Task PinUvAuthParamWithoutProtocolReturnsMissingParameter()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-e-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        CtapMakeCredentialRequest request = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(
            pool, pinUvAuthParam: new byte[] { 0x01, 0x02, 0x03, 0x04 });

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.MissingParameter, exception.StatusCode);

        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(request);
    }


    /// <summary>
    /// (f) An <c>rk</c> option key present at all on <c>authenticatorGetAssertion</c> fails with
    /// <see cref="WellKnownCtapStatusCodes.UnsupportedOption"/>, unconditionally — a platform MUST NOT
    /// send it here at all, regardless of its value.
    /// </summary>
    [TestMethod]
    public async Task ResidentKeyOptionOnGetAssertionReturnsUnsupportedOption()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-f-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool, options: new CtapCommandOptions(ResidentKey: false));

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                harness.Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.UnsupportedOption, exception.StatusCode);

        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
    }


    /// <summary>
    /// (g) A resident <c>authenticatorMakeCredential</c> for a NEW account at a relying party whose
    /// resident-credential store is already at its configured capacity fails with
    /// <see cref="WellKnownCtapStatusCodes.KeyStoreFull"/> — the store is re-keyed by (rp.id, account),
    /// so a second account at the SAME relying party is otherwise legal; capacity, not the relying party
    /// identifier, is what this negative exercises (a 1-slot authenticator, filled by the first account).
    /// </summary>
    [TestMethod]
    public async Task SecondAccountResidentAtCapacityReturnsKeyStoreFull()
    {
        const string rpId = "negative-g.example";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-g-authenticator", BaseMemoryPool.Shared, residentCredentialCapacity: 1);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        CredentialId firstCredentialId = await RegisterCredentialAsync(
            harness, pool, rpId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x11), resident: true, cancellationToken);

        CtapMakeCredentialRequest secondRequest = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(
            pool,
            rpId: rpId,
            userId: CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x22),
            options: new CtapCommandOptions(ResidentKey: true));

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
                harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, secondRequest, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.KeyStoreFull, exception.StatusCode);

        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(secondRequest);
        firstCredentialId.Dispose();
    }


    /// <summary>
    /// (h) <c>options.up = false</c> on <c>authenticatorGetAssertion</c> is a legitimate silent
    /// pre-flight: the command SUCCEEDS, and the returned <c>authData</c>'s <c>UP</c> flag is clear.
    /// </summary>
    [TestMethod]
    public async Task UserPresenceFalsePreFlightSucceedsWithUserPresentFlagClear()
    {
        const string rpId = "negative-h.example";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-h-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        CredentialId credentialId = await RegisterCredentialAsync(
            harness, pool, rpId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x33), resident: false, cancellationToken);

        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool,
            rpId: rpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = credentialId }],
            options: new CtapCommandOptions(UserPresence: false));

        CtapGetAssertionResponse response = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);
        Assert.IsFalse(authenticatorData.Flags.UserPresent, "options.up = false must clear the UP flag in the returned authData.");

        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
        response.Credential.Id.Dispose();
    }


    /// <summary>
    /// (i) An <c>authenticatorGetNextAssertion</c> with no prior <c>authenticatorGetAssertion</c> at all
    /// fails with <see cref="WellKnownCtapStatusCodes.NotAllowed"/> — the no-remembered-state path.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionWithNoPriorSequenceReturnsNotAllowed()
    {
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-i-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorGetNextAssertionClient.GetNextAssertionAsync(
                harness.Transceive, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, exception.StatusCode);
    }


    /// <summary>
    /// (j) An <c>authenticatorGetInfo</c> issued between a multi-account <c>authenticatorGetAssertion</c>
    /// and the following <c>authenticatorGetNextAssertion</c> discards the remembered sequence outright,
    /// so the <c>authenticatorGetNextAssertion</c> fails with <see cref="WellKnownCtapStatusCodes.NotAllowed"/>.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionAfterInterveningGetInfoReturnsNotAllowed()
    {
        const string rpId = "negative-j.example";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-j-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        using CredentialId firstCredentialId = await RegisterCredentialAsync(
            harness, pool, rpId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x40), resident: true, cancellationToken);
        using CredentialId secondCredentialId = await RegisterCredentialAsync(
            harness, pool, rpId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x41), resident: true, cancellationToken);

        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(pool, rpId: rpId);
        CtapGetAssertionResponse response = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken);
        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
        response.Credential.Id.Dispose();
        response.User?.Id.Dispose();

        _ = await CtapAuthenticatorGetInfoClient.GetInfoAsync(harness.Transceive, CtapGetInfoResponseCborReader.Read, pool, cancellationToken);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorGetNextAssertionClient.GetNextAssertionAsync(
                harness.Transceive, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, exception.StatusCode);
    }


    /// <summary>
    /// (k) An <c>authenticatorGetNextAssertion</c> issued more than 30 seconds after the last stateful
    /// step, measured through a <see cref="FakeTimeProvider"/> injected at the simulator's construction,
    /// fails with <see cref="WellKnownCtapStatusCodes.NotAllowed"/> — the timer-expiry path.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionAfterTimerExpiryReturnsNotAllowed()
    {
        const string rpId = "negative-k.example";
        var timeProvider = new FakeTimeProvider(TestClock.CanonicalEpoch);
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-k-authenticator", BaseMemoryPool.Shared, timeProvider: timeProvider);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        using CredentialId firstCredentialId = await RegisterCredentialAsync(
            harness, pool, rpId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x42), resident: true, cancellationToken);
        using CredentialId secondCredentialId = await RegisterCredentialAsync(
            harness, pool, rpId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x43), resident: true, cancellationToken);

        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(pool, rpId: rpId);
        CtapGetAssertionResponse response = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken);
        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
        response.Credential.Id.Dispose();
        response.User?.Id.Dispose();

        timeProvider.Advance(TimeSpan.FromSeconds(31));

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorGetNextAssertionClient.GetNextAssertionAsync(
                harness.Transceive, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, exception.StatusCode);
    }


    /// <summary>
    /// (l) Once every applicable credential of a two-account sequence has been returned (the initial
    /// <c>authenticatorGetAssertion</c> plus one <c>authenticatorGetNextAssertion</c>), a further
    /// <c>authenticatorGetNextAssertion</c> fails with <see cref="WellKnownCtapStatusCodes.NotAllowed"/> —
    /// the credentialCounter-exhausted path.
    /// </summary>
    [TestMethod]
    public async Task GetNextAssertionAfterCounterExhaustionReturnsNotAllowed()
    {
        const string rpId = "negative-l.example";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-l-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        using CredentialId firstCredentialId = await RegisterCredentialAsync(
            harness, pool, rpId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x44), resident: true, cancellationToken);
        using CredentialId secondCredentialId = await RegisterCredentialAsync(
            harness, pool, rpId, CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x45), resident: true, cancellationToken);

        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(pool, rpId: rpId);
        CtapGetAssertionResponse firstResponse = await CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
            harness.Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken);
        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
        firstResponse.Credential.Id.Dispose();
        firstResponse.User?.Id.Dispose();

        CtapGetAssertionResponse nextResponse = await CtapAuthenticatorGetNextAssertionClient.GetNextAssertionAsync(
            harness.Transceive, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken);
        nextResponse.Credential.Id.Dispose();
        nextResponse.User?.Id.Dispose();

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorGetNextAssertionClient.GetNextAssertionAsync(
                harness.Transceive, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.NotAllowed, exception.StatusCode);
    }


    /// <summary>
    /// (m) A resident registration for the same relying party and user OVERWRITES the existing resident
    /// credential (CTAP 2.3, section 6.1.2, step 16): a direct <c>authenticatorGetAssertion</c> whose
    /// <c>allowList</c> names the now-overwritten (first) credential identifier fails with
    /// <see cref="WellKnownCtapStatusCodes.NoCredentials"/>, since that identifier was removed from the
    /// credential-ID-keyed store entirely — closing a coverage note that only exercised
    /// the overwrite's effect on a subsequent <c>excludeList</c>, never on <c>allowList</c> lookup.
    /// </summary>
    [TestMethod]
    public async Task AllowListNamingOverwrittenCredentialIdReturnsNoCredentials()
    {
        const string rpId = "negative-m.example";
        BaseMemoryPool pool = BaseMemoryPool.Shared;
        var cancellationToken = TestContext.CancellationToken;

        using CtapAuthenticatorSimulator simulator = CtapMakeCredentialGetAssertionFixtures.CreateSimulator("negative-m-authenticator",BaseMemoryPool.Shared);
        using CtapNfcTransportHarness harness = await CtapNfcTransportHarness.CreateAsync(simulator, pool, cancellationToken);

        byte[] userId = CtapMakeCredentialGetAssertionFixtures.BuildFixedBytes(16, 0x46);
        byte[] overwrittenCredentialIdBytes;
        using(CredentialId overwrittenCredentialId = await RegisterCredentialAsync(harness, pool, rpId, userId, resident: true, cancellationToken))
        {
            overwrittenCredentialIdBytes = overwrittenCredentialId.AsReadOnlySpan().ToArray();
        }

        using CredentialId currentCredentialId = await RegisterCredentialAsync(harness, pool, rpId, userId, resident: true, cancellationToken);

        CtapGetAssertionRequest request = CtapMakeCredentialGetAssertionFixtures.BuildGetAssertionRequest(
            pool,
            rpId: rpId,
            allowList: [new PublicKeyCredentialDescriptor { Type = WellKnownPublicKeyCredentialTypes.PublicKey, Id = CredentialId.Create(overwrittenCredentialIdBytes, pool) }]);

        CtapCommandException exception = await Assert.ThrowsExactlyAsync<CtapCommandException>(
            () => CtapAuthenticatorGetAssertionClient.GetAssertionAsync(
                harness.Transceive, CtapGetAssertionRequestCborWriter.Write, request, CtapGetAssertionResponseCborReader.Read, pool, cancellationToken).AsTask());

        Assert.AreEqual(WellKnownCtapStatusCodes.NoCredentials, exception.StatusCode);

        CtapMakeCredentialGetAssertionFixtures.DisposeGetAssertionRequest(request);
    }


    /// <summary>
    /// Registers a credential over the real transport via <see cref="CtapAuthenticatorMakeCredentialClient"/>
    /// and returns a fresh, independently-owned copy of its minted credential identifier — the shared
    /// setup step several negative-matrix cases need to construct a wire vector referencing a real,
    /// already-registered credential.
    /// </summary>
    private static async Task<CredentialId> RegisterCredentialAsync(
        CtapNfcTransportHarness harness, BaseMemoryPool pool, string rpId, byte[] userId, bool resident, CancellationToken cancellationToken)
    {
        CtapMakeCredentialRequest request = CtapMakeCredentialGetAssertionFixtures.BuildMakeCredentialRequest(
            pool, rpId: rpId, userId: userId, options: new CtapCommandOptions(ResidentKey: resident));

        CtapMakeCredentialResponse response = await CtapAuthenticatorMakeCredentialClient.MakeCredentialAsync(
            harness.Transceive, CtapMakeCredentialRequestCborWriter.Write, request, CtapMakeCredentialResponseCborReader.Read, pool, cancellationToken);
        CtapMakeCredentialGetAssertionFixtures.DisposeMakeCredentialRequest(request);

        using AuthenticatorData authenticatorData = AuthenticatorDataReader.Read(response.AuthData, CredentialPublicKeyCborReader.Read, pool);

        return CredentialId.Create(authenticatorData.AttestedCredentialData!.CredentialId.AsReadOnlySpan(), pool);
    }
}
